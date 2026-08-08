# Adversarial HTTP lab: a server that answers every request with a *hostile
# response shape* rather than hostile content. dalfox has been hardened against
# these by hand several times (capped body reads after an OOM, reflection
# occurrence/range caps after a hang, a parser recursion guard + a bigger parse
# stack after deeply-nested JavaScript aborted the process) and none of those
# fixes has a standing regression target. This is that target.
#
# Flow:
#   1. Bind a raw `TCPServer` on 127.0.0.1 and print `listening on http://...`.
#   2. Per connection: parse the request line + headers by hand, route on path.
#   3. Each endpoint *streams* its hostility, so the server never allocates the
#      memory it is trying to make the client allocate (64 MB body = one 64 KiB
#      buffer written 1024 times; a 512 MB gzip bomb = the same buffer through a
#      `Compress::Gzip::Writer`).
#   4. Every unbounded shape (never-ends, redirect-loop, slowloris) carries a
#      per-request byte/time/hop cap so a runaway cannot wedge the host; set
#      HOSTILE_UNBOUNDED=1 to lift them.
#   5. SIGINT/SIGTERM close the listener, print a per-endpoint request tally and
#      exit 0.
#
# Why raw TCP instead of `HTTP::Server`: half the point is malformed framing —
# duplicate/conflicting `Content-Length`, a `Content-Length` that lies about the
# body, header values holding NUL / control characters / a bare CRLF. Crystal's
# `HTTP::Headers` (correctly) rejects all of that, so the wire has to be written
# by hand. `GET /` lists every endpoint.
#
# Environment (defaults in parentheses):
#   HOSTILE_PORT          listen port                                    (4803)
#   HOSTILE_HOST          bind address                              (127.0.0.1)
#   HOSTILE_HUGE_MB       /huge body size in MB                            (64)
#   HOSTILE_REFLECTIONS   /many-reflections echo count                 (100000)
#   HOSTILE_JS_DEPTH      /deep-js nesting depth                        (50000)
#   HOSTILE_SLOW_BYTES    /slowloris body bytes, one per delay            (256)
#   HOSTILE_SLOW_DELAY_MS /slowloris delay between bytes                   (60)
#   HOSTILE_REDIRECT_MAX  /redirect-loop hop cap                       (100000)
#   HOSTILE_HEADER_COUNT  /bad-headers junk header count                  (300)
#   HOSTILE_BOMB_MB       /gzip-bomb *decompressed* size in MB            (512)
#   HOSTILE_NEVER_MAX_SEC /never-ends wall-clock cap                      (120)
#   HOSTILE_NEVER_CHUNK_MS  /never-ends delay between chunks              (100)
#   HOSTILE_MAX_RESP_MB   per-response cap on bytes put on the wire       (256)
#   HOSTILE_UNBOUNDED     1 = lift every cap above (do this deliberately)   (0)
#   HOSTILE_VERBOSE       1 = log one line per request                      (0)

require "compress/gzip"
require "socket"
require "uri"
require "../lib/sh"

# ---------------------------------------------------------------------------
# Configuration.
# ---------------------------------------------------------------------------

PORT = ENV.fetch("HOSTILE_PORT", "4803").to_i
HOST = ENV.fetch("HOSTILE_HOST", "127.0.0.1")

HUGE_MB        = ENV.fetch("HOSTILE_HUGE_MB", "64").to_i
REFLECTIONS    = ENV.fetch("HOSTILE_REFLECTIONS", "100000").to_i
JS_DEPTH       = ENV.fetch("HOSTILE_JS_DEPTH", "50000").to_i
SLOW_BYTES     = ENV.fetch("HOSTILE_SLOW_BYTES", "256").to_i
SLOW_DELAY_MS  = ENV.fetch("HOSTILE_SLOW_DELAY_MS", "60").to_i
REDIRECT_MAX   = ENV.fetch("HOSTILE_REDIRECT_MAX", "100000").to_i
HEADER_COUNT   = ENV.fetch("HOSTILE_HEADER_COUNT", "300").to_i
BOMB_MB        = ENV.fetch("HOSTILE_BOMB_MB", "512").to_i
NEVER_MAX_SEC  = ENV.fetch("HOSTILE_NEVER_MAX_SEC", "120").to_i
NEVER_CHUNK_MS = ENV.fetch("HOSTILE_NEVER_CHUNK_MS", "100").to_i
MAX_RESP_MB    = ENV.fetch("HOSTILE_MAX_RESP_MB", "256").to_i
UNBOUNDED      = ENV.fetch("HOSTILE_UNBOUNDED", "0") == "1"
VERBOSE        = ENV.fetch("HOSTILE_VERBOSE", "0") == "1"

# Reusable 64 KiB scratch buffers. Everything large is written by repeating one
# of these; the server's own RSS stays flat no matter how big the response is.
BLOCK_BYTES = 64 * 1024
FILLER      = ("<p>dalfox hostile filler payload padding lorem ipsum dolor sit amet </p>" * 1024)
  .byte_slice(0, BLOCK_BYTES)
ZEROS = Bytes.new(BLOCK_BYTES, 0_u8)

# Per-response wire budget. `/gzip-bomb` is intentionally exempt in effect (its
# compressed stream is ~1/1000th of what the client must inflate).
MAX_RESP_BYTES = UNBOUNDED ? Int64::MAX : MAX_RESP_MB.to_i64 * 1024 * 1024

# ---------------------------------------------------------------------------
# Request model + tally.
# ---------------------------------------------------------------------------

record Req,
  method : String,
  target : String,
  path : String,
  params : URI::Params

class Tally
  @counts = Hash(String, Int32).new(0)
  @lock = Mutex.new

  def hit(path : String)
    @lock.synchronize { @counts[path] += 1 }
  end

  def dump
    @lock.synchronize do
      return if @counts.empty?
      puts "\nrequests served:"
      @counts.to_a.sort_by! { |(_, n)| -n }.each { |(p, n)| puts "  %7d  %s" % {n, p} }
    end
  end
end

TALLY = Tally.new

# ---------------------------------------------------------------------------
# Wire helpers. Everything is written by hand so malformed framing is possible.
# ---------------------------------------------------------------------------

private def head(io, status : String, headers : Array(String))
  io << "HTTP/1.1 " << status << "\r\n"
  headers.each { |h| io << h << "\r\n" }
  io << "Connection: close\r\n\r\n"
  io.flush
end

private def chunked_head(io, content_type = "text/html; charset=utf-8", extra = [] of String)
  head(io, "200 OK", ["Content-Type: #{content_type}", "Transfer-Encoding: chunked"] + extra)
end

private def chunk(io, data : String)
  return if data.bytesize.zero?
  io << data.bytesize.to_s(16) << "\r\n" << data << "\r\n"
end

private def chunk(io, data : Bytes)
  return if data.size.zero?
  io << data.size.to_s(16) << "\r\n"
  io.write(data)
  io << "\r\n"
end

private def end_chunks(io)
  io << "0\r\n\r\n"
  io.flush
end

# Fixed-length response with a correct Content-Length — the boring baseline.
private def plain(io, body : String, status = "200 OK", content_type = "text/html; charset=utf-8")
  head(io, status, ["Content-Type: #{content_type}", "Content-Length: #{body.bytesize}"])
  io << body
  io.flush
end

# ---------------------------------------------------------------------------
# Endpoints.
# ---------------------------------------------------------------------------

INDEX = <<-HTML
  <!doctype html><title>dalfox hostile lab</title><h1>hostile lab</h1><ul>
  <li>/huge?q=            — very large streamed body, reflection near the start
  <li>/deep-js?q=&shape=  — deeply nested JS: paren|bracket|ternary|member|helper|call
  <li>/many-reflections?q= — the input echoed an enormous number of times
  <li>/slowloris?q=       — headers, then the body one byte at a time
  <li>/redirect-loop?q=   — endless redirect chain (&self=1 for a self-redirect)
  <li>/bad-headers?q=&mode=all|retry|ctrl|length — absurd/duplicated/illegal headers
  <li>/chunk-lie?q=&mode=short|long|badchunk — Content-Length that lies
  <li>/gzip-bomb?q=       — small on the wire, enormous once inflated
  <li>/nul-bytes?q=       — NUL bytes around the reflection
  <li>/invalid-utf8?q=    — invalid UTF-8 around the reflection
  <li>/never-ends?q=      — a response that never completes
  <li>/health             — ok
  </ul>
  HTML

# `/huge` — a body far larger than any sane page, with the reflection in the
# first chunk so a client that caps its body read still has something to find.
# Regression target: the 16 MiB `read_body_capped` limit (an uncapped read here
# was an OOM), and whatever the read costs when 50 workers do it at once.
private def ep_huge(io, req)
  q = reflect(req)
  target_bytes = Math.min(HUGE_MB.to_i64 * 1024 * 1024, MAX_RESP_BYTES)
  chunked_head(io)
  chunk(io, "<!doctype html><html><body><h1>echo</h1><div id=r>#{q}</div>\n")
  written = 0_i64
  while written < target_bytes
    chunk(io, FILLER)
    written += FILLER.bytesize
    io.flush if (written // BLOCK_BYTES) % 64 == 0
  end
  chunk(io, "</body></html>")
  end_chunks(io)
end

# `/deep-js` — JavaScript nested `depth` levels. `shape=helper` is the one that
# matters most: a *per-call* recursion limit is defeated by re-entry through a
# helper (`x.a().a().a()…`), which is flat to a depth counter but not to the
# analyser walking it. Everything is emitted token-by-token, never built.
private def ep_deep_js(io, req)
  q = reflect(req)
  shape = req.params["shape"]? || "paren"
  depth = clamp_depth(req.params["depth"]?.try(&.to_i?) || JS_DEPTH)

  open, close = case shape
                when "bracket" then {"[", "]"}
                when "ternary" then {"c?", ":0"}
                when "member"  then {"", ""} # handled below (suffix-only shape)
                when "helper"  then {"", ""}
                when "call"    then {"f(", ")"}
                else                {"(", ")"}
                end

  chunked_head(io)
  chunk(io, "<!doctype html><html><body><div id=r>#{q}</div>\n<script>\n")
  chunk(io, "function f(v){return v} var c=1, obj={a:function(){return obj}};\n")
  chunk(io, "var s = \"#{q}\";\n")

  case shape
  when "member", "helper"
    # Suffix chains: `obj.a.a.a…` / `obj.a().a().a()…`. No nesting depth at all
    # by a naive counter, yet each link is another node to descend into.
    token = shape == "member" ? ".a" : ".a()"
    chunk(io, "var sink = obj")
    repeat(io, token, depth)
    chunk(io, ";\ndocument.write(s);\n")
  else
    chunk(io, "var sink = ")
    repeat(io, open, depth)
    chunk(io, "s")
    repeat(io, close, depth)
    chunk(io, ";\ndocument.write(sink);\n")
  end

  chunk(io, "</script></body></html>")
  end_chunks(io)
end

# `/many-reflections` — the exact shape the occurrence/range caps exist for:
# one input echoed 100k times, so any per-occurrence work in the reflection scan
# is multiplied by 100k.
private def ep_many_reflections(io, req)
  q = reflect(req)
  count = clamp_count(req.params["n"]?.try(&.to_i?) || REFLECTIONS)
  chunked_head(io)
  chunk(io, "<!doctype html><html><body>\n")
  # Batch the echoes into ~64 KiB chunks: 100k separate 20-byte chunks would
  # make this a chunked-encoding torture test instead of a reflection one.
  buf = String::Builder.new
  buf_len = 0
  written = 0_i64
  count.times do |i|
    line = "<div id=\"r#{i}\">#{q}</div>\n"
    buf << line
    buf_len += line.bytesize
    next if buf_len < BLOCK_BYTES
    body = buf.to_s
    written += body.bytesize
    break if written > MAX_RESP_BYTES
    chunk(io, body)
    io.flush
    buf = String::Builder.new
    buf_len = 0
  end
  chunk(io, buf.to_s)
  chunk(io, "</body></html>")
  end_chunks(io)
end

# `/slowloris` — a complete, correct response delivered one byte at a time.
# Nothing is malformed; the only weapon is time. A client without a whole-
# response deadline (as opposed to a per-read one) waits forever.
private def ep_slowloris(io, req)
  q = reflect(req)
  body = "<!doctype html><html><body><div id=r>#{q}</div>" +
         ("<span>slow</span>" * 64) + "</body></html>"
  body = body.byte_slice(0, Math.min(body.bytesize, clamp_slow(SLOW_BYTES)))
  head(io, "200 OK", ["Content-Type: text/html; charset=utf-8", "Content-Length: #{body.bytesize}"])
  body.each_byte do |b|
    io.write_byte(b)
    io.flush
    sleep SLOW_DELAY_MS.milliseconds
  end
end

# `/redirect-loop` — an endless 302 chain. `self=1` redirects to the identical
# URL, which defeats any "have I seen this hop before" set that only remembers
# the previous location but still counts against a hop limit.
private def ep_redirect_loop(io, req)
  q = reflect_raw(req)
  n = (req.params["n"]?.try(&.to_i?) || 0) + 1
  selfish = req.params["self"]? == "1"
  if !UNBOUNDED && n > REDIRECT_MAX
    plain(io, "<html><body>loop ended after #{REDIRECT_MAX} hops: #{q}</body></html>")
    return
  end
  location = selfish ? "/redirect-loop?self=1&q=#{URI.encode_www_form(q)}" : "/redirect-loop?n=#{n}&q=#{URI.encode_www_form(q)}"
  head(io, "302 Found", ["Location: #{location}", "Content-Length: 0"])
end

# `/bad-headers` — the header block itself is the attack.
#   mode=all    (default) everything at once: the `retry` set below *plus*
#               HEADER_COUNT junk headers. Note hyper caps a response at 100
#               headers, so this variant is really a "can a server refuse to be
#               scanned by flooding headers" test — the parsers below are never
#               reached, which is why `retry` exists as its own variant.
#   mode=retry  absurd `Retry-After` values (huge integer, far-future HTTP-date,
#               U+2028 garbage, negative) on a 429, duplicated conflicting
#               `Content-Type`, and a value carrying a bare CRLF (response
#               splitting) — few enough headers that the client parses them.
#   mode=ctrl   NUL and C0 control characters inside header values.
#   mode=length two `Content-Length` headers that disagree.
# 429 is the status whose `Retry-After` is always honoured — the parser at risk
# of being told to sleep until the year 9999.
private def ep_bad_headers(io, req)
  q = reflect(req)
  mode = req.params["mode"]? || "all"
  body = "<!doctype html><html><body><div id=r>#{q}</div></body></html>"

  case mode
  when "ctrl"
    hdrs = [
      "Content-Type: text/html; charset=utf-8",
      "Content-Length: #{body.bytesize}",
      "X-Ctrl-Nul: a\u{0}b",
      "X-Ctrl-Bell: a\u{7}b",
      "X-Ctrl-Del: a\u{7F}b",
      "X-Ctrl-Vt: a\u{B}b",
    ]
    head(io, "200 OK", hdrs)
    io << body
    io.flush
  when "length"
    # Two disagreeing Content-Lengths. RFC 7230 says reject; a client that picks
    # one and reads on is desynchronised for the rest of the connection.
    head(io, "200 OK", [
      "Content-Type: text/html; charset=utf-8",
      "Content-Length: #{body.bytesize}",
      "Content-Length: 999999",
    ])
    io << body
    io.flush
  else
    hdrs = [
      "Content-Type: text/html; charset=utf-8",
      "Content-Type: application/json; charset=x-no-such-charset",
      "Content-Type: ",
      "Retry-After: 99999999999999999999999999",
      "Retry-After: Fri, 31 Dec 9999 23:59:59 GMT",
      "Retry-After: \u{2028}not-a-delay-at-all\u{2029}",
      "Retry-After: -1",
      "X-Sep: line\u{2028}separator\u{2029}here",
      "X-Split: value\r\nX-Injected-By-Splitting: yes",
      "Set-Cookie: a=#{"x" * 4096}; Path=/",
      "Transfer-Encoding: chunked",
    ]
    HEADER_COUNT.times { |i| hdrs << "X-Junk-#{i}: #{"j" * 64}" } unless mode == "retry"
    head(io, "429 Too Many Requests", hdrs)
    chunk(io, body)
    end_chunks(io)
  end
end

# `/chunk-lie` — declared framing that does not match the bytes.
#   mode=short (default) `Content-Length` promises 10x what is sent, then the
#              connection closes: the client is left waiting for a body that
#              will never arrive.
#   mode=long  more bytes are sent than declared, so the surplus looks like the
#              start of a second response on a keep-alive connection.
#   mode=badchunk `Transfer-Encoding: chunked` with a garbage chunk-size line.
private def ep_chunk_lie(io, req)
  q = reflect(req)
  body = "<!doctype html><html><body><div id=r>#{q}</div><p>truncated</p></body></html>"
  case req.params["mode"]? || "short"
  when "long"
    head(io, "200 OK", ["Content-Type: text/html; charset=utf-8", "Content-Length: #{body.bytesize // 4}"])
    io << body << ("<!-- surplus -->" * 256)
    io.flush
  when "badchunk"
    head(io, "200 OK", ["Content-Type: text/html; charset=utf-8", "Transfer-Encoding: chunked"])
    io << "not-a-hex-length\r\n" << body << "\r\n0\r\n\r\n"
    io.flush
  else
    head(io, "200 OK", ["Content-Type: text/html; charset=utf-8", "Content-Length: #{body.bytesize * 10}"])
    io << body
    io.flush
  end
end

# `/gzip-bomb` — a few hundred KB on the wire, BOMB_MB once inflated. The
# reflection sits at the front so a client that stops inflating early still
# behaves as if it found a reflection point.
private def ep_gzip_bomb(io, req)
  q = reflect(req)
  head(io, "200 OK", [
    "Content-Type: text/html; charset=utf-8",
    "Content-Encoding: gzip",
    "Transfer-Encoding: chunked",
  ])
  # A chunk-framing IO so gzip output is streamed rather than buffered whole.
  framed = ChunkedIO.new(io)
  gz = Compress::Gzip::Writer.new(framed, sync_close: false)
  gz << "<!doctype html><html><body><div id=r>#{q}</div>\n"
  blocks = (BOMB_MB.to_i64 * 1024 * 1024) // BLOCK_BYTES
  blocks.times { gz.write(ZEROS) }
  gz << "</body></html>"
  gz.close
  framed.flush
  end_chunks(io)
end

# `/nul-bytes` and `/invalid-utf8` — the reflected region is not text. A body
# read that assumes UTF-8, or a marker search that stops at a NUL, misbehaves
# here; nothing may crash.
private def ep_nul_bytes(io, req)
  q = reflect(req)
  chunked_head(io)
  chunk(io, "<!doctype html><html><body>\n")
  chunk(io, "<div id=r>\u{0}#{q}\u{0}</div>\n")
  # NUL runs before and after, plus NULs interleaved into the echo itself.
  chunk(io, "<!--" + "\u{0}" * 4096 + "-->\n")
  chunk(io, "<div id=r2>" + q.each_char.join("\u{0}") + "</div>\n")
  chunk(io, "</body></html>")
  end_chunks(io)
end

private def ep_invalid_utf8(io, req)
  q = reflect(req)
  chunked_head(io)
  chunk(io, "<!doctype html><html><body>\n<div id=r>")
  chunk(io, q)
  chunk(io, "</div>\n<div id=r2>")
  # Continuation byte without a lead, truncated 3-byte sequence, overlong NUL,
  # a CESU-8 lone surrogate, and the two bytes that can never appear in UTF-8.
  chunk(io, Bytes[0x80_u8, 0xC3_u8, 0x28_u8, 0xE2_u8, 0x82_u8, 0xC0_u8, 0x80_u8,
    0xED_u8, 0xA0_u8, 0x80_u8, 0xFE_u8, 0xFF_u8, 0xF5_u8, 0x90_u8])
  chunk(io, "</div>\n")
  chunk(io, "</body></html>")
  end_chunks(io)
end

# `/never-ends` — a chunked response with no last chunk, dripping forever. The
# per-request wall-clock and byte caps below keep a runaway from wedging the
# host; HOSTILE_UNBOUNDED=1 removes them.
private def ep_never_ends(io, req)
  q = reflect(req)
  chunked_head(io)
  chunk(io, "<!doctype html><html><body><div id=r>#{q}</div>\n")
  io.flush
  deadline = Sh.clock + NEVER_MAX_SEC.seconds
  written = 0_i64
  loop do
    chunk(io, "<p>still going</p>\n")
    io.flush
    written += 20
    break if !UNBOUNDED && (Sh.clock > deadline || written > MAX_RESP_BYTES)
    sleep NEVER_CHUNK_MS.milliseconds
  end
  # Deliberately no `end_chunks`: the client saw a truncated stream, not an end.
end

# ---------------------------------------------------------------------------
# Support.
# ---------------------------------------------------------------------------

# Chunked-transfer framing as an IO, so a streaming writer (gzip) can be piped
# straight onto the wire without materialising its output.
class ChunkedIO < IO
  def initialize(@io : IO)
  end

  def read(slice : Bytes) : Int32
    raise IO::Error.new("write-only")
  end

  def write(slice : Bytes) : Nil
    return if slice.size.zero?
    @io << slice.size.to_s(16) << "\r\n"
    @io.write(slice)
    @io << "\r\n"
  end

  def flush
    @io.flush
    self
  end
end

# The value under test, echoed verbatim — no escaping anywhere in this file.
private def reflect(req : Req) : String
  reflect_raw(req)
end

private def reflect_raw(req : Req) : String
  req.params["q"]? || req.params.first?.try(&.[1]) || ""
end

private def repeat(io, token : String, times : Int32)
  return if token.empty?
  # Emit in ~64 KiB batches so a 50k-deep chain is a handful of writes.
  per_batch = Math.max(1, BLOCK_BYTES // token.bytesize)
  batch = token * per_batch
  full, rest = times // per_batch, times % per_batch
  full.times { chunk(io, batch) }
  chunk(io, token * rest) if rest > 0
end

private def clamp_depth(d : Int32) : Int32
  UNBOUNDED ? d : Math.min(d, 2_000_000)
end

private def clamp_count(n : Int32) : Int32
  UNBOUNDED ? n : Math.min(n, 5_000_000)
end

private def clamp_slow(n : Int32) : Int32
  UNBOUNDED ? n : Math.min(n, 100_000)
end

# ---------------------------------------------------------------------------
# Connection handling.
# ---------------------------------------------------------------------------

private def route(io, req : Req)
  case req.path
  when "/health"           then plain(io, "ok", content_type: "text/plain; charset=utf-8")
  when "/"                 then plain(io, INDEX)
  when "/huge"             then ep_huge(io, req)
  when "/deep-js"          then ep_deep_js(io, req)
  when "/many-reflections" then ep_many_reflections(io, req)
  when "/slowloris"        then ep_slowloris(io, req)
  when "/redirect-loop"    then ep_redirect_loop(io, req)
  when "/bad-headers"      then ep_bad_headers(io, req)
  when "/chunk-lie"        then ep_chunk_lie(io, req)
  when "/gzip-bomb"        then ep_gzip_bomb(io, req)
  when "/nul-bytes"        then ep_nul_bytes(io, req)
  when "/invalid-utf8"     then ep_invalid_utf8(io, req)
  when "/never-ends"       then ep_never_ends(io, req)
  else                          plain(io, "<html><body>no such lab: #{req.path}</body></html>", status: "404 Not Found")
  end
end

private def handle(client : TCPSocket)
  client.read_timeout = 15.seconds
  client.write_timeout = 30.seconds
  client.tcp_nodelay = true # otherwise Nagle batches the slowloris dribble

  line = client.gets(chomp: true)
  return if line.nil? || line.empty?
  parts = line.split(' ')
  method = parts[0]? || "GET"
  target = parts[1]? || "/"

  content_length = 0
  while (h = client.gets(chomp: true)) && !h.empty?
    key, _, value = h.partition(':')
    content_length = value.strip.to_i? || 0 if key.downcase == "content-length"
  end
  # Drain a request body so POST scans parse cleanly. Capped: our own client is
  # trusted, but an accidental huge upload should not be buffered either.
  client.skip(content_length) if content_length > 0 && content_length < 8 * 1024 * 1024

  path, _, query = target.partition('?')
  req = Req.new(method, target, path, URI::Params.parse(query))
  TALLY.hit(path)
  puts "#{method} #{target[0, 120]}" if VERBOSE

  route(client, req)
rescue ex : IO::Error | Socket::Error
  # The client hanging up mid-stream is the expected outcome for most of these
  # endpoints (it capped its read, or timed out); never let it kill the fiber.
  puts "  (client gone: #{ex.class})" if VERBOSE
rescue ex
  puts "  (handler error: #{ex.class}: #{ex.message})" if VERBOSE
ensure
  client.close rescue nil
end

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

server = TCPServer.new(HOST, PORT)
shutting_down = false
stop = ->(_s : Signal) do
  unless shutting_down
    shutting_down = true
    server.close rescue nil
  end
end
Signal::INT.trap(&stop)
Signal::TERM.trap(&stop)

puts "listening on http://#{HOST}:#{PORT}"
puts "caps: huge=#{HUGE_MB}MB reflections=#{REFLECTIONS} js_depth=#{JS_DEPTH} " \
     "bomb=#{BOMB_MB}MB resp_cap=#{UNBOUNDED ? "none" : "#{MAX_RESP_MB}MB"}"
STDOUT.flush

while (client = server.accept?)
  spawn handle(client)
end

TALLY.dump
puts "shutdown"
