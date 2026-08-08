# Deterministic, offline replay server for the benign false-positive corpus in
# `scripts/fixtures/replay/`.
#
# Every fixture is a page that genuinely echoes user input and is nonetheless
# not exploitable. Serving them from one process, with the escaping each fixture
# declares for itself, gives `scripts/replay_corpus.cr` a corpus where *any*
# dalfox finding is by construction a false positive.
#
# Flow:
#   1. Load every `*.html` under the fixture directory and parse its leading
#      front-matter comment (see below).
#   2. Bind 127.0.0.1:$REPLAY_PORT and print exactly one line:
#      `listening on http://127.0.0.1:<port>`.
#   3. Serve:
#        GET /health           -> `ok`
#        GET /map/json         -> the fixture catalog (name, url, why, ...)
#        GET /page/<name>?q=.. -> the fixture, with `q` substituted
#   4. Shut down cleanly on SIGINT/SIGTERM.
#
# ---------------------------------------------------------------------------
# Manifest format: front-matter inside each fixture's leading HTML comment.
# ---------------------------------------------------------------------------
# There is no sidecar manifest file. A fixture is one self-contained file, so
# adding one to the corpus is "drop a `.html` in the directory" and nothing
# else. The file starts with:
#
#   <!-- replay-fixture
#   name: escaped_body_text                      # optional, defaults to basename
#   content-type: text/html; charset=utf-8       # optional, this is the default
#   status: 200                                  # optional, default 200
#   escape: html                                 # optional, default html
#   url-decode: false                            # optional, default false
#   query: callback=render                       # optional extra query keys for /map/json
#   header: X-Content-Type-Options: nosniff      # optional, repeatable
#   why: prose explaining why the page is benign
#     continuation lines are indented
#   -->
#
# A line starts a new key only when it begins at column 0 with a known key name
# followed by `:`; anything else continues the previous value. The comment is
# stripped before serving, so the prose never reaches the wire.
#
# Every fixture is a `.html` file whatever it really is: `content-type` decides
# what it is served as (json_api.html is served as application/json). One rule,
# no exceptions.
#
# Placeholders inside the body and inside `header:` values:
#   {input}        the `q` parameter, escaped with the fixture's `escape` mode
#   {input:html}   entity-escape & < > " '
#   {input:url}    percent-encode to the RFC 3986 unreserved set
#   {input:json}   JSON string escaping, plus < > & U+2028 U+2029 as \u00xx
#   {input:raw}    verbatim (only legal where the content type is inert)
#   {callback}     the `callback` parameter, validated to a bare JS identifier
#
# Env vars:
#   REPLAY_PORT       listen port                  (default 4804)
#   REPLAY_FIXTURES   fixture directory            (default scripts/fixtures/replay)
#   REPLAY_SEED       seed `q` value in /map/json  (default replayseed)

require "http/server"
require "json"
require "uri"

PORT         = ENV.fetch("REPLAY_PORT", "4804").to_i
FIXTURE_DIR  = ENV.fetch("REPLAY_FIXTURES", "scripts/fixtures/replay")
SEED         = ENV.fetch("REPLAY_SEED", "replayseed")
HOST         = "127.0.0.1"
DEFAULT_TYPE = "text/html; charset=utf-8"

# JavaScript-only line terminators. They end a string literal in JS but are not
# escaped by JSON, which is why `esc_json` handles them explicitly.
LS = '\u2028'
PS = '\u2029'

# ---------------------------------------------------------------------------
# Escapers. Each one is the whole security argument of the fixtures that use
# it, so they are deliberately conservative rather than minimal.
# ---------------------------------------------------------------------------

# Entity-escape the five characters that matter in element content, in
# double-quoted attributes and in single-quoted attributes alike. `&` goes
# first so the entities it produces are not re-escaped.
def esc_html(s : String) : String
  s.gsub('&', "&amp;")
    .gsub('<', "&lt;")
    .gsub('>', "&gt;")
    .gsub('"', "&quot;")
    .gsub('\'', "&#39;")
end

# Percent-encode everything outside the RFC 3986 unreserved set. The output
# alphabet is [A-Za-z0-9-._~%], which is a strict subset of what `esc_html`
# allows, so it is safe in both element content and quoted attributes — and,
# because `:` and `/` are encoded too, it can never reach a URL's scheme.
def esc_url(s : String) : String
  String.build do |io|
    s.each_byte do |b|
      c = b.unsafe_chr
      if c.ascii_alphanumeric? || "-._~".includes?(c)
        io << c
      else
        io << '%' << b.to_s(16).rjust(2, '0').upcase
      end
    end
  end
end

# JSON string escaping (without the surrounding quotes), extended so that a
# value can never close a `<script>` element (`<`), start markup after a decode
# step (`>` / `&`), or terminate a JS string literal via U+2028 / U+2029.
def esc_json(s : String) : String
  inner = s.to_json
  inner = inner[1...-1]
  inner.gsub('<', "\\u003c")
    .gsub('>', "\\u003e")
    .gsub('&', "\\u0026")
    .gsub(LS, "\\u2028")
    .gsub(PS, "\\u2029")
end

def escape_with(mode : String, value : String) : String
  case mode
  when "html" then esc_html(value)
  when "url"  then esc_url(value)
  when "json" then esc_json(value)
  when "raw"  then value
  else             esc_html(value) # unknown mode: fail closed, never fail open
  end
end

# A JSONP callback is only ever a bare JavaScript identifier. Anything else is
# replaced wholesale rather than sanitised in place — there is no partially
# valid callback name.
CALLBACK_RE = /\A[A-Za-z_$][A-Za-z0-9_$]{0,63}\z/

def safe_callback(value : String?) : String
  v = value || ""
  CALLBACK_RE.matches?(v) ? v : "render"
end

# Header values must not carry control characters: response splitting would
# make an otherwise benign fixture genuinely exploitable, and no fixture should
# be able to opt out of that.
def sanitize_header(value : String) : String
  value.gsub(/[[:cntrl:]]/, "")
end

# ---------------------------------------------------------------------------
# Fixture model + front-matter parsing.
# ---------------------------------------------------------------------------

KNOWN_KEYS = %w[name content-type status escape url-decode query header why]
# The terminator must be `-->` alone at the start of a line. A plain non-greedy
# `.*?-->` would stop at the first `-->` the *prose* mentions — html_comment.html
# has to talk about the comment terminator to explain why it is benign, and that
# leaked front-matter text into the served body.
FRONT_MATTER = /\A\s*<!--\s*replay-fixture\s*?\n(.*?)\n-->[ \t]*\r?\n?/m
PLACEHOLDER  = /\{input(?::(html|url|json|raw))?\}|\{callback\}/

class Fixture
  getter name : String
  getter file : String
  getter content_type : String
  getter status : Int32
  getter escape : String
  getter url_decode : Bool
  getter query : String
  getter headers : Array({String, String})
  getter why : String
  getter body : String

  def initialize(@name, @file, @content_type, @status, @escape,
                 @url_decode, @query, @headers, @why, @body)
  end

  # Catalog path the runner enumerates. `query:` lets a fixture declare extra
  # parameters it wants exercised (the JSONP callback, for instance).
  def url(seed : String) : String
    base = "/page/#{@name}?q=#{esc_url(seed)}"
    @query.empty? ? base : "#{base}&#{@query}"
  end

  # Render one template (the body, or a header value) for one request.
  def render(template : String, raw_input : String, callback : String) : String
    input = @url_decode ? extra_decode(raw_input) : raw_input
    template.gsub(PLACEHOLDER) do |match|
      if match == "{callback}"
        callback
      else
        escape_with($~[1]? || @escape, input)
      end
    end
  end

  # The `url-decode: true` fixtures model a legacy handler that percent-decodes
  # once more than it should. The decode is only ever applied *before* the
  # escaper, which is what keeps those fixtures benign.
  private def extra_decode(value : String) : String
    URI.decode(value)
  rescue
    value
  end
end

def parse_front_matter(text : String) : {Hash(String, String), Array(String), String}
  match = FRONT_MATTER.match(text)
  return {Hash(String, String).new, [] of String, text} unless match

  fields = Hash(String, String).new
  headers = [] of String
  current = ""

  match[1].each_line do |line|
    if (m = line.match(/\A([a-z][a-z-]*):[ \t]?(.*)\z/)) && KNOWN_KEYS.includes?(m[1])
      current = m[1]
      value = m[2].strip
      if current == "header"
        headers << value
      else
        fields[current] = value
      end
    else
      # Continuation of the previous key — joined with a single space so the
      # prose survives re-wrapping in the source file.
      chunk = line.strip
      next if chunk.empty? || current.empty? || current == "header"
      fields[current] = "#{fields[current]?} #{chunk}".strip
    end
  end

  {fields, headers, text[match.end(0)..]}
end

def load_fixture(path : String) : Fixture
  fields, header_lines, body = parse_front_matter(File.read(path))
  basename = File.basename(path, File.extname(path))

  headers = header_lines.compact_map do |raw|
    idx = raw.index(':')
    next nil unless idx
    {raw[0...idx].strip, raw[(idx + 1)..].strip}
  end

  Fixture.new(
    name: fields["name"]? || basename,
    file: path,
    content_type: fields["content-type"]? || DEFAULT_TYPE,
    status: fields["status"]?.try(&.to_i?) || 200,
    escape: fields["escape"]? || "html",
    url_decode: fields["url-decode"]? == "true",
    query: fields["query"]? || "",
    headers: headers,
    why: fields["why"]? || "",
    body: body,
  )
end

def load_fixtures : Hash(String, Fixture)
  unless Dir.exists?(FIXTURE_DIR)
    abort "fixture directory not found: #{FIXTURE_DIR} (run from the repo root)"
  end
  paths = Dir.glob(File.join(FIXTURE_DIR, "*.html")).sort!
  abort "no fixtures in #{FIXTURE_DIR}" if paths.empty?

  fixtures = Hash(String, Fixture).new
  paths.each do |path|
    fixture = load_fixture(path)
    abort "duplicate fixture name #{fixture.name.inspect} (#{path})" if fixtures.has_key?(fixture.name)
    # Two guards worth their weight: front matter that leaked into the body
    # would put unreviewed prose on the wire, and a fixture with no placeholder
    # is not an echo page at all, so a clean scan of it would prove nothing.
    abort "front matter was not stripped from #{path}" if fixture.body.includes?("replay-fixture")
    abort "#{path} has no {input} placeholder — a corpus fixture must echo its input" unless fixture.body.includes?("{input")
    fixtures[fixture.name] = fixture
  end
  fixtures
end

# ---------------------------------------------------------------------------
# HTTP surface.
# ---------------------------------------------------------------------------

FIXTURES = load_fixtures

def catalog_json : String
  {
    count:    FIXTURES.size,
    seed:     SEED,
    fixtures: FIXTURES.values.map do |f|
      {
        name:         f.name,
        url:          f.url(SEED),
        file:         f.file,
        content_type: f.content_type,
        status:       f.status,
        escape:       f.escape,
        url_decode:   f.url_decode,
        why:          f.why,
      }
    end,
  }.to_json
end

def serve_fixture(fixture : Fixture, ctx : HTTP::Server::Context)
  params = ctx.request.query_params
  input = params["q"]? || ""
  callback = safe_callback(params["callback"]?)

  ctx.response.status_code = fixture.status
  ctx.response.content_type = fixture.content_type
  fixture.headers.each do |name, value|
    ctx.response.headers[name] = sanitize_header(fixture.render(value, input, callback))
  end
  # Nothing here is cacheable: two runs of the corpus must see identical bytes,
  # never a 304 from an intermediary.
  ctx.response.headers["Cache-Control"] = "no-store"
  ctx.response.print(fixture.render(fixture.body, input, callback))
end

server = HTTP::Server.new do |ctx|
  path = ctx.request.path
  case
  when path == "/health"
    ctx.response.content_type = "text/plain; charset=utf-8"
    ctx.response.print "ok"
  when path == "/map/json"
    ctx.response.content_type = "application/json; charset=utf-8"
    ctx.response.print catalog_json
  when path.starts_with?("/page/")
    name = path["/page/".size..]
    if fixture = FIXTURES[name]?
      serve_fixture(fixture, ctx)
    else
      ctx.response.status_code = 404
      ctx.response.content_type = "text/plain; charset=utf-8"
      # The unknown name is NOT echoed: this handler is infrastructure, not a
      # fixture, and an echo here would be an untracked reflection surface.
      ctx.response.print "unknown fixture"
    end
  else
    ctx.response.status_code = 404
    ctx.response.content_type = "text/plain; charset=utf-8"
    ctx.response.print "not found"
  end
end

server.bind_tcp(HOST, PORT)

# Diagnostics go to stderr so stdout carries exactly the one contract line.
STDERR.puts "#{FIXTURES.size} fixtures from #{FIXTURE_DIR}"
puts "listening on http://#{HOST}:#{PORT}"
STDOUT.flush

{Signal::INT, Signal::TERM}.each do |sig|
  sig.trap do
    STDERR.puts "shutting down"
    server.close
  end
end

server.listen
