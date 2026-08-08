# Serves the labelled `tests/functional/mock_cases/**/*.toml` corpus over HTTP so
# any harness can point a scanner at it.
#
# The corpus is the repo's only labelled XSS ground truth (943 cases, each one
# declaring `expected_detection`), but until now it was reachable only from
# inside the Rust integration test that embeds `xss_mock_server.rs`. That makes
# "what is dalfox's precision/recall right now?" a question nobody can answer
# without writing a Rust test. This lab exposes the same corpus as a plain
# server, so `scripts/effectiveness_snapshot.cr` — or a curl, or another
# scanner — can measure against it.
#
# Flow:
#   1. Load the corpus through `scripts/lib/mock_cases.cr`, filter to the
#      requested categories/limit, and drop the cases this lab cannot serve
#      faithfully (see FIDELITY below). Report what was dropped.
#   2. Index the survivors by `<category>/<id>` and print the catalog size.
#   3. Serve:
#        GET  /health                      -> "ok"
#        GET  /map/json                    -> catalog, incl. a ready-to-scan URL
#        GET  /case/<category>/<id>        -> query / header / cookie case
#        GET  /case/<category>/<id>/<seg>  -> path case (input is <seg>)
#        POST /case/<category>/<id>        -> body case (urlencoded form)
#   4. Shut down cleanly on SIGINT/SIGTERM.
#
# FIDELITY — the Rust server is the reference implementation; this lab must
# agree with it or the labels stop meaning anything:
#   * Input is read from the same place per `handler_type` as
#     `xss_mock_server.rs` (query key, request header, cookie, form field,
#     path segment), with the same defaults (`X-Test`, `test`, `query`).
#   * `apply_reflection` here mirrors the Rust function of that name, including
#     the six non-template reflection keys (`encoded_html_named`,
#     `encoded_html_hex_lower`, `encoded_html_hex_upper`, `percent_to_entity`,
#     `encoded_base64`, `encoded_url`). `MockCases::Case#render` only does the
#     `{input}` substitution, so those keys must be special-cased before it or
#     six cases would reflect the literal string "encoded_html_named".
#   * Cases carrying a `filter` (server-side sanitizer chain) or a
#     `page_template` (canned real-world page shell) are NOT served: those are
#     behaviours implemented in Rust, and serving such a case unfiltered turns
#     an expected-clean case into a bogus false positive. They are counted and
#     reported at boot instead of being silently dropped.
#   * Every case body is wrapped in the same `<div id=out>` shell the Rust
#     handlers use. The one deviation: `dom_xss` cases (which the Rust server
#     has no route for at all) carry a whole `<html>` document as their
#     "reflection" and are served verbatim, because nesting a document inside a
#     div would be a lab artefact rather than a faithful page.
#
# Environment:
#   CORPUS_PORT        listen port                     (default 4801)
#   CORPUS_HOST        bind address                    (default 127.0.0.1)
#   CORPUS_CATEGORIES  comma-separated category filter (default: all)
#                      one or more of query,header,cookie,path,body,dom_xss,realworld
#   CORPUS_LIMIT       serve only the first N cases    (default: all)
#   CORPUS_ROOT        corpus directory                (default tests/functional/mock_cases)

require "base64"
require "http/server"
require "json"
require "uri"

require "../lib/mock_cases"

PORT       = ENV.fetch("CORPUS_PORT", "4801").to_i
HOST       = ENV.fetch("CORPUS_HOST", "127.0.0.1")
ROOT       = ENV.fetch("CORPUS_ROOT", MockCases::ROOT)
CATEGORIES = ENV["CORPUS_CATEGORIES"]?.try(&.split(',', remove_empty: true).map(&.strip))
LIMIT      = ENV["CORPUS_LIMIT"]?.try(&.to_i?)

# ---------------------------------------------------------------------------
# Reflection — mirror of `xss_mock_server.rs#apply_reflection`.
# ---------------------------------------------------------------------------

# `html_named_encode_all`: the five named entities, nothing else.
def html_named_encode(input : String) : String
  String.build do |io|
    input.each_char do |c|
      case c
      when '<'  then io << "&lt;"
      when '>'  then io << "&gt;"
      when '&'  then io << "&amp;"
      when '"'  then io << "&quot;"
      when '\'' then io << "&apos;"
      else           io << c
      end
    end
  end
end

# `html_numeric_hex_lower` / `_upper_x`. Rust formats with `{:02x}`/`{:02X}`,
# i.e. a *minimum* width of two, so astral chars widen rather than truncate.
def html_hex_encode(input : String, upper : Bool) : String
  String.build do |io|
    input.each_char do |c|
      io << (upper ? "&#X%02X;" % c.ord : "&#x%02x;" % c.ord)
    end
  end
end

# Rust's `urlencoding::encode`: percent-encode everything outside the unreserved
# set, uppercase hex. `URI.encode_www_form` is NOT equivalent (it maps space to
# `+`), which would change what the scanner sees.
def url_encode_strict(input : String) : String
  String.build do |io|
    input.each_byte do |b|
      c = b.unsafe_chr
      if c.ascii_alphanumeric? || c == '-' || c == '_' || c == '.' || c == '~'
        io << c
      else
        io << '%' << "%02X" % b
      end
    end
  end
end

def apply_reflection(kase : MockCases::Case, input : String) : String
  case kase.reflection
  when "encoded_html_named"     then html_named_encode(input)
  when "encoded_html_hex_lower" then html_hex_encode(input, false)
  when "encoded_html_hex_upper" then html_hex_encode(input, true)
  when "percent_to_entity"      then input.gsub("%", "&#37;")
  when "encoded_base64"         then Base64.strict_encode(input)
  when "encoded_url"            then url_encode_strict(input)
  else                               kase.render(input) # plain `{input}` substitution
  end
end

# The page shell every Rust handler wraps its reflection in.
def wrap_page(reflected : String) : String
  "<html><head><title>mock</title></head><body><div id=out>#{reflected}</div></body></html>"
end

# ---------------------------------------------------------------------------
# Catalog.
# ---------------------------------------------------------------------------

# Where the scanner has to inject for this case, in the vocabulary the map
# exposes. `dom_xss` and `realworld` are query-driven in the Rust server too.
def location_of(kase : MockCases::Case) : String
  case kase.handler_type
  when "header" then "Header"
  when "cookie" then "Cookie"
  when "body"   then "Body"
  when "path"   then "Path"
  else               "Query"
  end
end

def method_of(kase : MockCases::Case) : String
  kase.handler_type == "body" ? "POST" : "GET"
end

# Absolute, ready-to-scan URL with the injection point already seeded.
#
# Query-style cases get `?<param>=test` so the scanner has something to
# discover. Header/cookie/body cases deliberately get a bare URL: seeding a
# fake query parameter there would hand the scanner an extra, never-reflected
# parameter to burn requests on. Path cases seed the segment itself, matching
# the Rust route `/path/{case_id}/{param}`.
def scan_url(kase : MockCases::Case, base : String) : String
  path = "#{base}/case/#{kase.category}/#{kase.id}"
  case location_of(kase)
  when "Path"                     then "#{path}/test"
  when "Header", "Cookie", "Body" then path
  else                                 "#{path}?#{URI.encode_path_segment(kase.injection_param)}=test"
  end
end

# ---------------------------------------------------------------------------
# Boot: load, filter, index.
# ---------------------------------------------------------------------------

all_cases = MockCases.load(ROOT, CATEGORIES)
servable = all_cases.select(&.self_contained?)
skipped_unservable = all_cases.size - servable.size
servable = servable.first(LIMIT.not_nil!) if LIMIT

# `id` is only unique per injection type, and a category can span several TOML
# files — so a collision inside one category is possible in principle. The Rust
# loader silently overwrites on collision; here it is reported, because a
# swallowed case quietly changes the denominator of every score.
cases = {} of String => MockCases::Case
duplicates = [] of String
servable.each do |kase|
  key = "#{kase.category}/#{kase.id}"
  if cases.has_key?(key)
    duplicates << key
  else
    cases[key] = kase
  end
end

base_url = "http://#{HOST}:#{PORT}"

catalog = cases.values.map do |kase|
  {
    uid:                kase.uid,
    id:                 kase.id,
    name:               kase.name,
    category:           kase.category,
    handler_type:       kase.handler_type,
    expected_detection: kase.expected_detection,
    method:             method_of(kase),
    url:                scan_url(kase, base_url),
    param:              kase.injection_param,
    location:           location_of(kase),
  }
end
catalog_json = {count: catalog.size, cases: catalog}.to_json

by_category = cases.values.group_by(&.category).transform_values(&.size)

puts "==> corpus: #{all_cases.size} cases loaded from #{ROOT}"
puts "==> skipped #{skipped_unservable} case(s) with a filter/page_template (not self-contained; served by the Rust mock server only)"
puts "==> skipped #{duplicates.size} duplicate id(s): #{duplicates.first(8).join(", ")}" unless duplicates.empty?
puts "==> serving #{cases.size} case(s): #{by_category.to_a.sort_by! { |(c, _)| c }.map { |(c, n)| "#{c}=#{n}" }.join(" ")}"

# ---------------------------------------------------------------------------
# Request handling.
# ---------------------------------------------------------------------------

# Rust reads the cookie header raw: split on `;`, exact `name=` prefix, no
# percent-decoding. Crystal's `HTTP::Cookies` parser would decode, so this is
# hand-rolled to stay byte-identical.
def cookie_value(header : String?, name : String) : String
  return "" unless header
  prefix = "#{name}="
  header.split(';').each do |part|
    part = part.strip
    return part[prefix.size..] if part.starts_with?(prefix)
  end
  ""
end

# Axum's `Form` extractor: urlencoded, `+` is a space, `%XX` decoded.
# `URI::Params.parse` has the same semantics.
def form_value(body : IO?, name : String) : String
  return "" unless body
  URI::Params.parse(body.gets_to_end)[name]? || ""
rescue
  ""
end

def read_input(kase : MockCases::Case, request : HTTP::Request, path_segment : String) : String
  param = kase.injection_param
  case kase.handler_type
  when "header" then request.headers[param]? || "" # HTTP::Headers is case-insensitive
  when "cookie" then cookie_value(request.headers["Cookie"]?, param)
  when "body"   then form_value(request.body, param)
  when "path"   then path_segment.empty? ? "" : URI.decode(path_segment)
  else               request.query_params[param]? || ""
  end
end

def serve_case(context : HTTP::Server::Context, kase : MockCases::Case, path_segment : String)
  input = read_input(kase, context.request, path_segment)
  reflected = apply_reflection(kase, input)
  # See FIDELITY: dom_xss reflections are complete documents.
  body = kase.handler_type == "dom_xss" ? reflected : wrap_page(reflected)

  response = context.response
  response.status_code = kase.status_code
  response.content_type = kase.content_type
  kase.response_headers.each do |raw|
    name, sep, value = raw.partition(':')
    next if sep.empty?
    response.headers[name.strip] = value.strip
  end
  response.print(body)
end

def text(context : HTTP::Server::Context, status : Int32, body : String)
  context.response.status_code = status
  context.response.content_type = "text/plain; charset=utf-8"
  context.response.print(body)
end

server = HTTP::Server.new do |context|
  request = context.request
  path = request.path

  case
  when path == "/health"
    text(context, 200, "ok")
  when path == "/map/json"
    context.response.content_type = "application/json"
    context.response.print(catalog_json)
  when path.starts_with?("/case/")
    # /case/<category>/<id>[/<path segment>]
    parts = path[6..].split('/', 3)
    if parts.size < 2
      text(context, 404, "not found")
    elsif kase = cases["#{parts[0]}/#{parts[1]}"]?
      serve_case(context, kase, parts.size > 2 ? parts[2] : "")
    else
      text(context, 404, "no such case: #{parts[0]}/#{parts[1]}")
    end
  else
    text(context, 404, "not found")
  end
rescue ex
  # A handler crash must not take the lab down mid-measurement; a 500 shows up
  # in the harness as a scan error instead of a silent hang.
  text(context, 500, "handler error: #{ex.message}")
end

address = server.bind_tcp(HOST, PORT)

# Both signals, because the harness sends TERM while a human sends INT.
{Signal::INT, Signal::TERM}.each do |sig|
  sig.trap do
    server.close
  end
end

puts "listening on http://#{address.address}:#{address.port}"
STDOUT.flush
server.listen
