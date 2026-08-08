# Instrumented lab server whose entire job is counting what the scanner does.
#
# dalfox has repeatedly shipped *cost* regressions that no unit test can see:
# an endpoint that reflects every payload once drew ~33k requests for a single
# parameter, and a payload-cap change silently moved scan volume. Nothing in the
# repo measures requests-per-parameter, so this lab makes the cost observable:
# every endpoint is a different *cost profile*, and the counters are the output.
#
# Flow:
#   1. Boot one `HTTP::Server` on 127.0.0.1 and print the listening line so a
#      harness can wait on it deterministically.
#   2. Count every inbound request BEFORE routing it — path, query/body params,
#      distinct injected values, response bytes, first/last timestamps.
#   3. Serve the reflection endpoints (`/echo`, `/reflect-all`, `/many`,
#      `/inert`, `/slow`), each shaped to draw a different amount of scanner work.
#   4. Expose the tally at `/stats` and let a harness zero it at `/reset`
#      between scenarios.
#
# Run with `crystal run scripts/labs/counting_server.cr`. Environment:
#   COUNTING_PORT         listen port                       (default 4802)
#   COUNTING_SLOW_MS      fixed delay of `/slow`, in ms      (default 50)
#   COUNTING_PAYLOAD_CAP  max distinct values retained       (default 200000)
#
# Endpoints:
#   GET /health       -> "ok"
#   GET /stats        -> JSON tally (see `Counters#to_json_string`)
#   GET /reset        -> zeroes every counter, returns the JSON zero state
#   GET /echo?q=      -> raw reflection in one HTML body position
#   GET /reflect-all?q=  raw reflection in attribute + <script> + href at once
#   GET /many?a=..&e=    five independently reflecting params
#   GET /inert?q=     -> HTML-escaped reflection (nothing exploitable)
#   GET /slow?q=      -> raw reflection after a fixed small delay

require "http/server"
require "http/params"
require "html"
require "json"

PORT        = ENV.fetch("COUNTING_PORT", "4802").to_i
SLOW_MS     = ENV.fetch("COUNTING_SLOW_MS", "50").to_i
PAYLOAD_CAP = ENV.fetch("COUNTING_PAYLOAD_CAP", "200000").to_i

# Harness control plane. These are counted separately so a `/stats` poll can
# never inflate the scan-cost numbers the harness is trying to measure.
CONTROL_PATHS = Set{"/health", "/stats", "/reset"}

# ---------------------------------------------------------------------------
# Counters.
# ---------------------------------------------------------------------------

# Per-path tally. `payloads` is the set of distinct values the scanner injected
# into this endpoint — the number that tells amplification (one payload, many
# requests) apart from a large catalog (many payloads, one request each).
class EndpointStat
  property requests = 0_i64
  property bytes = 0_i64
  getter params = Hash(String, Int64).new(0_i64)
  getter payloads = Set(String).new
end

# Every mutation goes through the mutex. Crystal's HTTP::Server interleaves
# fibers at each IO point even without `-Dpreview_mt`, and the harness may run
# scans with 50 workers, so unguarded `+= 1` would drop counts.
class Counters
  def initialize
    @lock = Mutex.new
    @started_at = Time.utc
    @total = 0_i64
    @control = 0_i64
    @bytes = 0_i64
    @endpoints = Hash(String, EndpointStat).new
    @params = Hash(String, Int64).new(0_i64)
    @payloads = Set(String).new
    @payloads_truncated = false
    @first_at = nil.as(Time?)
    @last_at = nil.as(Time?)
  end

  # Record one request and return its parameters (query pairs first, then any
  # urlencoded body pairs) so the caller does not re-parse them.
  #
  # The body is consumed here rather than in the route handlers: counting must
  # happen before anything else, and a handler that never touches the body
  # would otherwise leave POST parameters uncounted.
  def record(request : HTTP::Request) : Hash(String, String)
    path = request.path
    control = CONTROL_PATHS.includes?(path)
    pairs = collect_pairs(request)

    @lock.synchronize do
      now = Time.utc
      if control
        @control += 1
      else
        @total += 1
        @first_at ||= now
        @last_at = now

        stat = (@endpoints[path] ||= EndpointStat.new)
        stat.requests += 1
        pairs.each do |name, value|
          @params[name] += 1
          stat.params[name] += 1
          # Bounded: an amplifying endpoint can draw tens of thousands of
          # distinct values, and this process must not become the bottleneck.
          if @payloads.size < PAYLOAD_CAP
            @payloads << value
            stat.payloads << value
          else
            @payloads_truncated = true
          end
        end
      end
    end

    pairs.to_h
  end

  # Response size, added after the body is rendered. Control-plane responses are
  # excluded for the same reason their requests are.
  def add_bytes(path : String, n : Int32)
    return if CONTROL_PATHS.includes?(path)
    @lock.synchronize do
      @bytes += n
      (@endpoints[path] ||= EndpointStat.new).bytes += n
    end
  end

  def reset
    @lock.synchronize do
      @started_at = Time.utc
      @total = 0_i64
      @control = 0_i64
      @bytes = 0_i64
      @endpoints.clear
      @params.clear
      @payloads.clear
      @payloads_truncated = false
      @first_at = nil
      @last_at = nil
    end
  end

  def to_json_string : String
    @lock.synchronize do
      first = @first_at
      last = @last_at
      # Rate over the *active* window (first -> last request), not over uptime:
      # idle time before the scan starts would otherwise dilute it to nothing.
      window = (first && last) ? (last - first).total_seconds : 0.0
      rps = (window > 0.0) ? (@total / window) : 0.0

      JSON.build do |j|
        j.object do
          j.field "port", PORT
          j.field "uptime_seconds", (Time.utc - @started_at).total_seconds.round(3)
          j.field "total_requests", @total
          j.field "control_requests", @control
          j.field "bytes_sent", @bytes
          j.field "distinct_payloads", @payloads.size
          j.field "payloads_truncated", @payloads_truncated
          j.field "first_request_at", first.try(&.to_rfc3339)
          j.field "last_request_at", last.try(&.to_rfc3339)
          j.field "active_seconds", window.round(3)
          j.field "requests_per_second", rps.round(2)

          j.field "params" do
            j.object do
              @params.to_a.sort_by! { |(name, count)| {-count, name} }.each do |(name, count)|
                j.field name, count
              end
            end
          end

          j.field "endpoints" do
            j.object do
              @endpoints.to_a.sort_by! { |(path, stat)| {-stat.requests, path} }.each do |(path, stat)|
                j.field path do
                  j.object do
                    j.field "requests", stat.requests
                    j.field "bytes_sent", stat.bytes
                    j.field "distinct_payloads", stat.payloads.size
                    j.field "params" do
                      j.object do
                        stat.params.to_a.sort_by! { |(name, count)| {-count, name} }.each do |(name, count)|
                          j.field name, count
                        end
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
  end

  # Query pairs plus urlencoded body pairs, as a flat list so repeated keys
  # (HPP-style duplicates) each count.
  private def collect_pairs(request : HTTP::Request) : Array({String, String})
    pairs = [] of {String, String}
    request.query_params.each { |name, value| pairs << {name, value} }

    if body = request.body
      raw = body.gets_to_end
      ctype = request.headers["Content-Type"]? || ""
      if ctype.includes?("urlencoded") && !raw.empty?
        HTTP::Params.parse(raw).each { |name, value| pairs << {name, value} }
      end
    end
    pairs
  rescue
    # A malformed query/body must not take the lab down; the request still counts.
    pairs || [] of {String, String}
  end
end

COUNTERS = Counters.new

# ---------------------------------------------------------------------------
# Response shapes. Each endpoint is a distinct cost profile for the scanner.
# ---------------------------------------------------------------------------

def page(title : String, body : String) : String
  "<!doctype html><html><head><title>#{title}</title></head><body>#{body}</body></html>"
end

# One raw reflection in HTML body text — the cheapest reflecting shape.
def echo_page(value : String) : String
  page("echo", "<div id=\"out\">#{value}</div>")
end

# The historically expensive shape: the same input lands in an attribute value,
# inside an inline script string, and in an href at once. Every payload family
# reflects somewhere, so nothing prunes the catalog and the scanner keeps going.
def reflect_all_page(value : String) : String
  String.build do |io|
    io << "<!doctype html><html><head>"
    io << "<meta name=\"keywords\" content=\"" << value << "\">"
    io << "<script>var q = \"" << value << "\"; console.log(q);</script>"
    io << "</head><body>"
    io << "<a href=\"" << value << "\">link</a>"
    io << "<div data-q=\"" << value << "\">" << value << "</div>"
    io << "</body></html>"
  end
end

# Several reflecting params, for measuring how per-parameter cost scales.
def many_page(params : Hash(String, String)) : String
  items = MANY_PARAMS.map { |name| "<li data-#{name}>#{params[name]? || ""}</li>" }.join
  page("many", "<ul>#{items}</ul>")
end

MANY_PARAMS = %w[a b c d e]

# HTML-escaped: reflected but never exploitable. Measures how much work the
# scanner spends on a dead end before giving up.
def inert_page(value : String) : String
  page("inert", "<div id=\"out\">#{HTML.escape(value)}</div>")
end

def index_page : String
  links = ["/echo?q=dalfox", "/reflect-all?q=dalfox",
           "/many?a=1&b=2&c=3&d=4&e=5", "/inert?q=dalfox", "/slow?q=dalfox",
           "/stats", "/reset", "/health"]
  page("counting lab", "<h1>counting lab</h1><ul>" +
                       links.map { |l| "<li><a href=\"#{HTML.escape(l)}\">#{HTML.escape(l)}</a></li>" }.join + "</ul>")
end

# ---------------------------------------------------------------------------
# Routing.
# ---------------------------------------------------------------------------

record Rendered, body : String, status : Int32, content_type : String

def html(body : String, status : Int32 = 200) : Rendered
  Rendered.new(body, status, "text/html; charset=utf-8")
end

def route(path : String, params : Hash(String, String)) : Rendered
  q = params["q"]? || ""

  case path
  when "/health"
    Rendered.new("ok", 200, "text/plain; charset=utf-8")
  when "/stats"
    Rendered.new(COUNTERS.to_json_string, 200, "application/json")
  when "/reset"
    COUNTERS.reset
    Rendered.new(COUNTERS.to_json_string, 200, "application/json")
  when "/echo"
    html(echo_page(q))
  when "/reflect-all"
    html(reflect_all_page(q))
  when "/many"
    html(many_page(params))
  when "/inert"
    html(inert_page(q))
  when "/slow"
    # Fixed, small, and deliberately not jittered: this endpoint exists so a
    # wall-clock budget has a scenario whose duration is predictable.
    sleep SLOW_MS.milliseconds
    html(echo_page(q))
  when "/"
    html(index_page)
  else
    html(page("not found", "<p>not found</p>"), 404)
  end
end

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

server = HTTP::Server.new do |context|
  path = context.request.path
  # Counting happens before routing, before the body is rendered, and before
  # any delay: a request that times out client-side still cost the server one.
  params = COUNTERS.record(context.request)

  rendered = route(path, params)
  context.response.status_code = rendered.status
  context.response.content_type = rendered.content_type
  context.response.print rendered.body
  COUNTERS.add_bytes(path, rendered.body.bytesize)
end

shutdown = ->(_signal : Signal) do
  server.close rescue nil
  exit 0
end
Signal::INT.trap(&shutdown)
Signal::TERM.trap(&shutdown)

begin
  address = server.bind_tcp("127.0.0.1", PORT)
rescue ex
  STDERR.puts "counting_server: cannot bind 127.0.0.1:#{PORT}: #{ex.message}"
  exit 1
end

# Exact line the harnesses wait on; flushed so a piped/redirected stdout does
# not hold it in a buffer while the harness polls.
puts "listening on http://127.0.0.1:#{address.port}"
STDOUT.flush
server.listen
