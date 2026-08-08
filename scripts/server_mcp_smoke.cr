# End-to-end smoke test for dalfox's two machine-facing surfaces: the REST API
# (`dalfox server`, src/server/**) and the MCP stdio server (`dalfox mcp`,
# src/mcp/**). Both are driven for real — a child process each, a real scan, a
# real cancel — against a scan target this script hosts itself, so the run needs
# neither the internet nor another harness's lab.
#
# Flow:
#   1. Start an in-script HTTP target on SMOKE_TARGET_PORT with two endpoints:
#      `/vuln` (raw, unescaped reflection of `q` into HTML — reliably a `V`
#      finding) and `/inert` (static HTML, params ignored — reliably clean).
#   2. Boot `dalfox server` on 127.0.0.1:SMOKE_REST_PORT, wait for /health, then
#      exercise the lifecycle: health, scan → poll → results, clean scan, cancel
#      + capacity-slot reclamation, input validation, response headers, 404.
#   3. Launch `dalfox mcp` and speak newline-delimited JSON-RPC 2.0 over its
#      pipes: initialize → notifications/initialized → tools/list → tools/call.
#   4. Diff the scan-parameter surface of the two APIs (REST `ScanOptions` in
#      src/server/types.rs vs. the MCP `scan_with_dalfox` input schema) and fail
#      on any name/type divergence outside the intentional allowlist below.
#
# Every child process is torn down in an `ensure` and every wait is bounded, so
# a server that fails to boot produces a failed check carrying its captured
# output rather than a hang or an orphaned process.
#
# Tunable via environment variables:
#   SMOKE_REST_PORT      dalfox server port           (default 4805)
#   SMOKE_TARGET_PORT    in-script scan target port   (default 4815)
#   SMOKE_BOOT_TIMEOUT   seconds to wait for /health  (default 20)
#   SMOKE_SCAN_TIMEOUT   seconds to wait for a scan   (default 90)
#   SMOKE_CANCEL_CYCLES  create/cancel rounds to run  (default 8)
#   SMOKE_MAX_CONCURRENT --max-concurrent-scans value (default 3)
#   SMOKE_MCP_TIMEOUT    seconds per JSON-RPC reply   (default 120)
#   SMOKE_VERBOSE        1 = print detail on passing checks too
#   DALFOX_BIN           dalfox binary (default target/release/dalfox)

require "http/server"
require "http/client"
require "json"
require "./lib/sh"
require "./lib/dalfox"
require "./lib/report"

REST_PORT      = ENV.fetch("SMOKE_REST_PORT", "4805").to_i
TARGET_PORT    = ENV.fetch("SMOKE_TARGET_PORT", "4815").to_i
BOOT_TIMEOUT   = ENV.fetch("SMOKE_BOOT_TIMEOUT", "20").to_i.seconds
SCAN_TIMEOUT   = ENV.fetch("SMOKE_SCAN_TIMEOUT", "90").to_i.seconds
CANCEL_CYCLES  = ENV.fetch("SMOKE_CANCEL_CYCLES", "8").to_i
MAX_CONCURRENT = ENV.fetch("SMOKE_MAX_CONCURRENT", "3").to_i
MCP_TIMEOUT    = ENV.fetch("SMOKE_MCP_TIMEOUT", "120").to_i.seconds
VERBOSE        = ENV["SMOKE_VERBOSE"]? == "1"

# The REST payload struct is the source of truth for the REST parameter surface;
# parsing it beats restating a list that silently rots when a field is added.
REST_TYPES_RS = "src/server/types.rs"

VULN_URL  = "http://127.0.0.1:#{TARGET_PORT}/vuln?q=test"
INERT_URL = "http://127.0.0.1:#{TARGET_PORT}/inert?q=test"

# Option blobs are raw JSON so the harness sends exactly what a client would —
# including the shapes a typed builder would refuse to construct.
#
# `skip_mining` keeps the runtime down (without it dalfox fans a parameter
# dictionary out over the target first). `skip_discovery` is deliberately NOT
# set: on every surface, CLI included, it also drops the URL's own query
# parameters, so the scan would test nothing and report a vacuous clean result.
SMOKE_OPTS = %({"skip_mining":true,"max_payloads_per_param":40})
# Deliberately slow (single worker, 300ms between requests, full catalog) so the
# cancel cycles below always have a genuinely *running* scan to cancel.
SLOW_OPTS = %({"worker":1,"delay":300,"skip_mining":true,"scan_timeout":60})

# ---------------------------------------------------------------------------
# Part 1 — the scan target.
#
# Two endpoints, both deterministic:
#   GET /vuln?q=X   → X spliced raw into the HTML body (always a finding)
#   GET /inert?q=X  → fixed HTML, X never echoed anywhere (never a finding)
# `/vuln` reflects into element content rather than an attribute so the
# injection context is the simplest one dalfox has to verify.
# ---------------------------------------------------------------------------

class TargetServer
  def initialize(@port : Int32)
    @server = HTTP::Server.new do |ctx|
      ctx.response.content_type = "text/html; charset=utf-8"
      case ctx.request.path
      when "/vuln"
        q = ctx.request.query_params["q"]? || ""
        ctx.response.print "<html><head><title>search</title></head><body>" \
                           "<h1>results</h1><div id=\"out\">#{q}</div></body></html>"
      else
        # No reflection at all, not an escaped echo. An escaped echo would be
        # testing dalfox's inert-reflection gates, which is a detection
        # question; this endpoint only has to prove a clean target reads clean.
        ctx.response.print "<html><head><title>inert</title></head><body>" \
                           "<p>nothing to see here</p></body></html>"
      end
    end
  end

  # Binds synchronously (so a port clash surfaces here rather than as a mystery
  # scan failure later) and serves on a fiber. Returns an error message or nil.
  def start : String?
    @server.bind_tcp("127.0.0.1", @port)
    spawn { @server.listen }
    Fiber.yield
    nil
  rescue ex
    "bind 127.0.0.1:#{@port} failed: #{ex.message}"
  end

  def stop
    @server.close
  rescue
    # Already closed or never bound — nothing to undo.
  end
end

# ---------------------------------------------------------------------------
# Shared process helper: wait for a child to exit, but never longer than the
# budget. Used by both teardown paths so neither can wedge the `ensure`.
# ---------------------------------------------------------------------------

def wait_for_exit(process : Process, budget : Time::Span) : Bool
  done = Channel(Nil).new(1)
  spawn do
    process.wait rescue nil
    done.send(nil)
  end
  select
  when done.receive
    true
  when timeout(budget)
    false
  end
end

# ---------------------------------------------------------------------------
# HTTP client helper. Every call is bounded by connect/read timeouts, so a
# wedged server becomes a failed check instead of a hung harness.
# ---------------------------------------------------------------------------

record HttpReply,
  status : Int32,
  body : String,
  headers : HTTP::Headers,
  error : String? do
  def ok? : Bool
    @error.nil?
  end

  # Parsed body, or nil when the body is absent or not JSON.
  def json : JSON::Any?
    return nil if @body.empty?
    JSON.parse(@body)
  rescue
    nil
  end

  # `code` from dalfox's `{code,msg,data}` envelope (src/server/response.rs).
  def envelope_code : Int64?
    json.try(&.["code"]?).try(&.as_i64?)
  end

  def envelope_msg : String
    json.try(&.["msg"]?).try(&.as_s?) || ""
  end

  def data : JSON::Any?
    json.try(&.["data"]?)
  end

  # Compact one-liner for failure details.
  def describe : String
    return "transport error: #{@error}" unless ok?
    "HTTP #{@status} #{@body[0, 300]}"
  end
end

def rest_request(method : String,
                 path : String,
                 body : String? = nil,
                 timeout : Time::Span = 15.seconds) : HttpReply
  client = HTTP::Client.new("127.0.0.1", REST_PORT)
  client.connect_timeout = 3.seconds
  client.read_timeout = timeout
  headers = HTTP::Headers{"Accept" => "application/json"}
  headers["Content-Type"] = "application/json" if body
  resp = client.exec(method, path, headers, body)
  HttpReply.new(resp.status_code, resp.body, resp.headers, nil)
rescue ex
  HttpReply.new(0, "", HTTP::Headers.new, ex.message || ex.class.name)
ensure
  client.close if client
end

def rest_post_scan(target : String, options_json : String) : HttpReply
  rest_request("POST", "/scan", %({"target":#{target.to_json},"options":#{options_json}}))
end

# Poll a scan id to a terminal status, or give up with a note explaining where
# it got stuck.
record ScanOutcome, status : String, payload : JSON::Any?, note : String

def poll_until_terminal(scan_id : String, budget : Time::Span) : ScanOutcome
  deadline = Sh.clock + budget
  last = ScanOutcome.new("", nil, "never polled")
  while Sh.clock < deadline
    reply = rest_request("GET", "/scan/#{scan_id}")
    return ScanOutcome.new("", nil, reply.describe) unless reply.ok? && reply.status == 200
    data = reply.data
    status = data.try(&.["status"]?).try(&.as_s?) || ""
    last = ScanOutcome.new(status, data, "")
    return last if {"done", "error", "cancelled"}.includes?(status)
    sleep 200.milliseconds
  end
  stuck = last.status.empty? ? "unknown" : last.status
  ScanOutcome.new(last.status, last.payload, "still #{stuck} after #{budget.total_seconds.round}s")
end

# Findings array from a `/scan/{id}` payload. `results` is
# `skip_serializing_if = "Option::is_none"`, so an in-flight scan simply has no
# such key — that is not an error, it is zero findings so far.
def findings_of(payload : JSON::Any?) : Array(JSON::Any)
  payload.try(&.["results"]?).try(&.as_a?) || [] of JSON::Any
end

# ---------------------------------------------------------------------------
# Part 2 — `dalfox server` lifecycle.
#
# stdout and stderr are captured into one buffer so a boot failure can be
# reported verbatim. Teardown is TERM → bounded wait → KILL, and is idempotent
# so the `ensure` at the bottom can call it unconditionally.
# ---------------------------------------------------------------------------

class RestServer
  getter log = IO::Memory.new
  @process : Process? = nil

  def initialize(@bin : String, @args : Array(String))
  end

  def start : String?
    @process = Process.new(@bin, @args,
      input: Process::Redirect::Close,
      output: @log,
      error: @log)
    nil
  rescue ex
    "spawn failed: #{ex.message}"
  end

  # Poll /health until the server answers or the budget runs out. Bails out
  # early when the child has already exited (bad flag, port in use, panic).
  def wait_ready(budget : Time::Span) : String?
    deadline = Sh.clock + budget
    while Sh.clock < deadline
      if (p = @process) && p.terminated?
        return "server exited during boot; captured output:\n#{tail}"
      end
      reply = rest_request("GET", "/health", timeout: 2.seconds)
      return nil if reply.ok? && reply.status == 200
      sleep 200.milliseconds
    end
    "no /health response within #{budget.total_seconds.round}s; captured output:\n#{tail}"
  end

  def stop
    p = @process
    return unless p
    @process = nil
    return if p.terminated?
    p.signal(Signal::TERM) rescue nil
    return if wait_for_exit(p, 5.seconds)
    p.signal(Signal::KILL) rescue nil
    wait_for_exit(p, 5.seconds)
  end

  # Last few lines of the captured server output, for failure details.
  def tail(lines : Int32 = 12) : String
    @log.to_s.lines.last(lines).join("\n")
  end
end

# ---------------------------------------------------------------------------
# Part 3 — MCP over stdio.
#
# `dalfox mcp` speaks newline-delimited JSON-RPC 2.0 on stdin/stdout. A reader
# fiber drains stdout into a channel so every wait can be a `select` with a
# timeout — a missing, malformed, or out-of-order reply must never block the
# harness.
# ---------------------------------------------------------------------------

class McpClient
  getter stderr = IO::Memory.new
  @process : Process? = nil

  def initialize(@bin : String)
    @lines = Channel(String).new(64)
    @next_id = 0
  end

  def start : String?
    p = Process.new(@bin, ["mcp"],
      input: Process::Redirect::Pipe,
      output: Process::Redirect::Pipe,
      error: @stderr)
    @process = p
    spawn do
      while line = p.output.gets
        @lines.send(line)
      end
    rescue
      # Pipe torn down while the child was going away; closing the channel
      # below turns any pending read into a clean nil for the caller.
    ensure
      @lines.close rescue nil
    end
    nil
  rescue ex
    "spawn failed: #{ex.message}"
  end

  # Send a request and wait for the reply carrying the matching id, skipping
  # notifications and out-of-order messages. Returns nil on timeout or EOF.
  def call(method : String,
           params_json : String,
           timeout : Time::Span = MCP_TIMEOUT) : JSON::Any?
    id = (@next_id += 1)
    request = %({"jsonrpc":"2.0","id":#{id},"method":#{method.to_json},"params":#{params_json}})
    return nil unless write(request)
    deadline = Sh.clock + timeout
    while Sh.clock < deadline
      msg = read_message(deadline - Sh.clock)
      return nil unless msg
      obj = msg.as_h?
      next unless obj
      next unless obj["id"]?.try(&.as_i64?) == id.to_i64
      return msg
    end
    nil
  end

  # Fire-and-forget notification (no id, so no reply is expected).
  def notify(method : String) : Bool
    write(%({"jsonrpc":"2.0","method":#{method.to_json}}))
  end

  # `tools/call` unwraps the MCP content envelope: dalfox returns tool payloads
  # as a JSON document inside a text content block, not as structured data.
  # Returns {payload, error}; exactly one is non-nil on a completed call, both
  # are nil when the server never answered.
  def call_tool(name : String,
                arguments_json : String,
                timeout : Time::Span = MCP_TIMEOUT) : {JSON::Any?, JSON::Any?}
    msg = call("tools/call", %({"name":#{name.to_json},"arguments":#{arguments_json}}), timeout)
    return {nil, nil} unless msg
    if err = msg["error"]?
      return {nil, err}
    end
    text = msg.dig?("result", "content", 0, "text").try(&.as_s?)
    return {msg, nil} unless text
    parsed = (JSON.parse(text) rescue nil)
    {parsed || msg, nil}
  end

  def stop
    p = @process
    return unless p
    @process = nil
    # Closing stdin is the protocol-level shutdown: rmcp's stdio transport ends
    # its serve loop on EOF, so the child normally exits on its own.
    p.input.close rescue nil
    return if wait_for_exit(p, 5.seconds)
    p.signal(Signal::TERM) rescue nil
    return if wait_for_exit(p, 3.seconds)
    p.signal(Signal::KILL) rescue nil
    wait_for_exit(p, 3.seconds)
  end

  private def write(line : String) : Bool
    p = @process
    return false unless p
    p.input.puts(line)
    p.input.flush
    true
  rescue
    false
  end

  private def read_message(budget : Time::Span) : JSON::Any?
    return nil if budget <= Time::Span.zero
    select
    when line = @lines.receive?
      return nil unless line
      JSON.parse(line) rescue JSON::Any.new(nil)
    when timeout(budget)
      nil
    end
  end
end

# ---------------------------------------------------------------------------
# Part 4 — parity between the two scan-parameter surfaces.
# ---------------------------------------------------------------------------

# Rust field type → the JSON Schema `type` an equivalent MCP field would carry.
def rust_type_to_json(rust : String) : String
  inner = rust.gsub(/\AOption<(.*)>\z/, "\\1")
  case inner
  when "String"
    "string"
  when "bool"
    "boolean"
  when "Vec<String>"
    "array"
  when "f32", "f64"
    "number"
  when /\A[ui](8|16|32|64|size)\z/
    "integer"
  else
    inner
  end
end

# Parse `struct ScanOptions { ... }` out of src/server/types.rs. Reading the
# struct instead of restating it means a newly added REST option shows up as a
# divergence here automatically.
#
# `#[serde(alias = "...")]` counts: an alias is a name the REST API genuinely
# accepts on the wire, which is the only thing parity is about. The four MCP
# spellings (`cookies`, `headers`, `workers`, `blind_callback_url`) are carried
# as aliases rather than renamed fields so existing REST clients keep working,
# and a checker that read only the field names would report them as divergent
# forever. The alias's declared type is taken from the field it feeds, except
# where the deserializer widens it — see `ALIAS_WIRE_TYPES`.
def rest_scan_option_fields : Hash(String, String)
  fields = {} of String => String
  src = File.read(REST_TYPES_RS)
  struct_body = src.match(/struct\s+ScanOptions\s*\{(.*?)^\}/m)
  return fields unless struct_body

  pending_aliases = [] of String
  struct_body[1].each_line do |line|
    line.scan(/alias\s*=\s*"([a-z0-9_]+)"/) { |m| pending_aliases << m[1] }
    if m = line.match(/^\s*pub\(crate\)\s+([a-z0-9_]+)\s*:\s*(.+?)\s*,\s*$/)
      type = rust_type_to_json(m[2])
      fields[m[1]] = type
      pending_aliases.each { |a| fields[a] = ALIAS_WIRE_TYPES[a]? || type }
      pending_aliases.clear
    end
  end
  fields
end

# Aliases whose accepted wire type is wider than the field they land on.
# `cookies` takes MCP's list form and joins it into the single `Cookie` header
# string `ScanOptions#cookie` holds (`string_or_seq_cookie` in types.rs), so on
# the wire it is an array even though the field is a String.
ALIAS_WIRE_TYPES = {"cookies" => "array"}

# `type` from a JSON Schema property, collapsing the `["string","null"]` form
# schemars emits for `Option<T>` down to its non-null member.
def schema_type_of(prop : JSON::Any) : String
  t = prop["type"]?
  return "unknown" unless t
  if arr = t.as_a?
    return arr.compact_map(&.as_s?).reject!("null").first? || "null"
  end
  t.as_s? || "unknown"
end

# Divergences that are deliberate, with the reason. Anything not listed here is
# reported as a real parity bug.
#
#   url               REST keeps `url` as a serde alias for `target` so pre-3.x
#                     REST clients keep working (src/server/types.rs:141). It
#                     lives on ScanRequest, not ScanOptions, so it never reaches
#                     the diff below — recorded here for completeness.
#   callback_url      REST-only: the server POSTs a completion webhook. MCP has
#                     no out-of-band channel; the agent polls or uses wait=true.
#   wait,             MCP-only: collapses submit+poll into one tool call for
#   wait_timeout_sec  agents. REST clients poll GET /scan/{id} instead.
#   cookie, header,   REST-only *legacy spellings*. These four diverged from
#   worker, blind     MCP (`cookies`, `headers`, `workers`,
#                     `blind_callback_url`) and, before
#                     `deny_unknown_fields`, an MCP-spelled request was
#                     accepted by REST with 200 and silently discarded — a scan
#                     with no cookies reported as clean. REST now accepts the
#                     MCP spelling as a serde alias, so the canonical name
#                     works on both surfaces and an unknown one 400s. The old
#                     names stay accepted so pre-3.x REST clients keep working,
#                     which is what makes them REST-only rather than a
#                     divergence: nothing is silently dropped in either
#                     direction. Adding them to MCP would advertise a legacy
#                     spelling on the newer surface, so they are not mirrored.
INTENTIONAL_REST_ONLY = Set{"callback_url", "cookie", "header", "worker", "blind"}
INTENTIONAL_MCP_ONLY  = Set{"wait", "wait_timeout_sec"}

# ---------------------------------------------------------------------------
# Run.
# ---------------------------------------------------------------------------

report = Report.new("server + MCP smoke", verbose: VERBOSE)

unless Dalfox.available?
  report.fail("dalfox binary", "not found at #{Dalfox.bin} (build it, or set DALFOX_BIN)")
  exit report.finish
end

target = TargetServer.new(TARGET_PORT)
rest = RestServer.new(Dalfox.bin, [
  "server",
  "--host", "127.0.0.1",
  "--port", REST_PORT.to_s,
  # A small cap makes a leaked capacity slot show up within a few cycles
  # instead of needing 100 create/cancel rounds to reach the default.
  "--max-concurrent-scans", MAX_CONCURRENT.to_s,
  # Backstop: nothing this harness starts may outlive the run by more than
  # this, even if a cancel somehow fails to take effect.
  "--scan-timeout", "120",
  "--no-color",
])
mcp = McpClient.new(Dalfox.bin)

begin
  # -- Part 1: scan target --------------------------------------------------
  report.group("target server (port #{TARGET_PORT})")

  if target_error = target.start
    report.fail("bind scan target", target_error)
    exit report.finish
  end
  report.pass("bind scan target", "127.0.0.1:#{TARGET_PORT}")

  vuln_probe = (HTTP::Client.get("#{VULN_URL}&probe=1").body rescue "")
  report.check("vulnerable endpoint reflects raw", "GET /vuln did not echo the marker") do
    vuln_probe.includes?(%(<div id="out">test</div>))
  end
  inert_probe = (HTTP::Client.get(INERT_URL).body rescue "")
  report.check("inert endpoint echoes nothing", "GET /inert leaked the parameter") do
    !inert_probe.includes?("test")
  end

  # -- Part 2: REST lifecycle -----------------------------------------------
  report.group("REST server (port #{REST_PORT})")

  if spawn_error = rest.start
    report.fail("boot dalfox server", spawn_error)
    exit report.finish
  end
  if boot_error = rest.wait_ready(BOOT_TIMEOUT)
    report.fail("boot dalfox server", boot_error)
    exit report.finish
  end
  report.pass("boot dalfox server", "ready within #{BOOT_TIMEOUT.total_seconds.round}s")

  health = rest_request("GET", "/health")
  report.check("GET /health answers 200", health.describe) do
    health.ok? && health.status == 200 && health.envelope_code == 200
  end
  report.check_eq("GET /health version matches binary",
    Dalfox.version, health.data.try(&.["version"]?).try(&.as_s?) || "(absent)")
  report.check("GET /health advertises endpoints", "no endpoints array in data") do
    (health.data.try(&.["endpoints"]?).try(&.as_a?) || [] of JSON::Any).size > 0
  end
  report.check("Content-Type is JSON", health.headers["Content-Type"]? || "(absent)") do
    (health.headers["Content-Type"]? || "").starts_with?("application/json")
  end
  report.check("X-Content-Type-Options: nosniff", health.headers["X-Content-Type-Options"]? || "(absent)") do
    health.headers["X-Content-Type-Options"]? == "nosniff"
  end

  # Vulnerable target: submit → poll → results.
  vuln_reply = rest_post_scan(VULN_URL, SMOKE_OPTS)
  vuln_id = vuln_reply.data.try(&.["scan_id"]?).try(&.as_s?)
  report.check("POST /scan accepts the vulnerable target", vuln_reply.describe) do
    vuln_reply.ok? && vuln_reply.status == 200 && !vuln_id.nil?
  end

  if vuln_id
    outcome = poll_until_terminal(vuln_id, SCAN_TIMEOUT)
    report.check_eq("vulnerable scan reaches done", "done",
      outcome.status.empty? ? outcome.note : outcome.status)
    findings = findings_of(outcome.payload)
    report.check("vulnerable scan reports a finding on `q`",
      "#{findings.size} findings; note=#{outcome.note}") do
      findings.any? { |f| f["param"]?.try(&.as_s?) == "q" }
    end
    report.check("finding is verified (type V)",
      findings.compact_map { |f| f["type"]?.try(&.as_s?) }.join(",")) do
      findings.any? { |f| f["type"]?.try(&.as_s?) == "V" }
    end
    done_pct = outcome.payload.try(&.dig?("progress", "estimated_completion_pct")).try(&.as_i64?)
    report.check_eq("done scan reports 100%", 100_i64, done_pct)
  end

  # Inert target: same pipeline, must come back clean.
  inert_reply = rest_post_scan(INERT_URL, SMOKE_OPTS)
  if inert_id = inert_reply.data.try(&.["scan_id"]?).try(&.as_s?)
    outcome = poll_until_terminal(inert_id, SCAN_TIMEOUT)
    report.check_eq("inert scan reaches done", "done",
      outcome.status.empty? ? outcome.note : outcome.status)
    report.check_empty("inert scan reports no findings",
      findings_of(outcome.payload).map { |f| "#{f["type"]?}/#{f["param"]?}" })
  else
    report.fail("POST /scan accepts the inert target", inert_reply.describe)
  end

  # Cancel + capacity-slot reclamation. Each cycle submits a slow scan, waits
  # for it to actually be running, cancels it, and re-reads the status. With
  # --max-concurrent-scans set to MAX_CONCURRENT, a slot that is not released
  # on cancel makes cycle MAX_CONCURRENT+1 fail with a 503.
  report.group("REST cancel + capacity")

  cancel_failures = [] of String
  bogus_pct = [] of String
  cycles_admitted = 0
  CANCEL_CYCLES.times do |i|
    submit = rest_post_scan(VULN_URL, SLOW_OPTS)
    id = submit.data.try(&.["scan_id"]?).try(&.as_s?)
    unless submit.ok? && submit.status == 200 && id
      cancel_failures << "cycle #{i + 1}: submit → #{submit.describe}"
      next
    end
    cycles_admitted += 1

    # Wait for the job to leave `queued` so this cancels a *running* scan
    # rather than dequeuing one that never started.
    deadline = Sh.clock + 15.seconds
    while Sh.clock < deadline
      s = rest_request("GET", "/scan/#{id}").data.try(&.["status"]?).try(&.as_s?)
      break if s.nil? || s == "running" || {"done", "error", "cancelled"}.includes?(s)
      sleep 100.milliseconds
    end

    cancel = rest_request("DELETE", "/scan/#{id}")
    unless cancel.ok? && cancel.status == 200 && cancel.data.try(&.["cancelled"]?).try(&.as_bool?)
      cancel_failures << "cycle #{i + 1}: cancel → #{cancel.describe}"
      next
    end
    after = rest_request("GET", "/scan/#{id}").data
    status = after.try(&.["status"]?).try(&.as_s?) || "(none)"
    cancel_failures << "cycle #{i + 1}: post-cancel status #{status}" unless status == "cancelled"
    pct = after.try(&.dig?("progress", "estimated_completion_pct")).try(&.as_i64?)
    bogus_pct << "cycle #{i + 1}: #{pct}%" if pct == 100_i64
  end
  report.check_empty("#{CANCEL_CYCLES} sequential create/cancel cycles (cap #{MAX_CONCURRENT})", cancel_failures)
  report.check_empty("cancelled scans never report 100%", bogus_pct)
  report.check_eq("every cancel cycle was admitted", CANCEL_CYCLES, cycles_admitted)

  # A create after all that cancelling must still be admitted — the direct
  # test that the capacity slot was released and not merely counted down.
  after_cancels = rest_post_scan(INERT_URL, SMOKE_OPTS)
  report.check("create succeeds after the cancel cycles", after_cancels.describe) do
    after_cancels.ok? && after_cancels.status == 200
  end
  if trailing_id = after_cancels.data.try(&.["scan_id"]?).try(&.as_s?)
    poll_until_terminal(trailing_id, SCAN_TIMEOUT)
  end

  # -- REST input validation ------------------------------------------------
  report.group("REST input validation")

  bad_inputs = [
    {"non-http scheme", %({"target":"ftp://example.com/x"})},
    {"bare host, no scheme", %({"target":"example.com"})},
    {"empty target", %({"target":"   "})},
    {"missing target field", %({"options":{}})},
    {"body is not an object", %(["not","an","object"])},
    {"unknown method verb", %({"target":#{VULN_URL.to_json},"options":{"method":"FETCH"}})},
    {"method with trailing junk", %({"target":#{VULN_URL.to_json},"options":{"method":"GET junk"}})},
    {"negative worker", %({"target":#{VULN_URL.to_json},"options":{"worker":-1}})},
    {"zero worker", %({"target":#{VULN_URL.to_json},"options":{"worker":0}})},
    {"huge worker", %({"target":#{VULN_URL.to_json},"options":{"worker":100000}})},
    {"huge timeout", %({"target":#{VULN_URL.to_json},"options":{"timeout":999999}})},
    {"timeout overflows u64", %({"target":#{VULN_URL.to_json},"options":{"timeout":99999999999999999999}})},
    {"negative delay", %({"target":#{VULN_URL.to_json},"options":{"delay":-5}})},
    {"unknown waf_bypass value", %({"target":#{VULN_URL.to_json},"options":{"waf_bypass":"maybe"}})},
    {"waf_min_confidence out of range", %({"target":#{VULN_URL.to_json},"options":{"waf_min_confidence":7.5}})},
    {"unknown encoder", %({"target":#{VULN_URL.to_json},"options":{"encoders":["rot13"]}})},
    {"scan_timeout past ceiling", %({"target":#{VULN_URL.to_json},"options":{"scan_timeout":999999999}})},
  ]
  rejected_badly = [] of String
  bad_inputs.each do |name, body|
    reply = rest_request("POST", "/scan", body)
    unless reply.ok?
      rejected_badly << "#{name}: #{reply.describe}"
      next
    end
    unless (400..499).includes?(reply.status)
      rejected_badly << "#{name}: expected 4xx, got #{reply.status} #{reply.body[0, 160]}"
      next
    end
    rejected_badly << "#{name}: 4xx with an empty msg" if reply.envelope_msg.empty?
  end
  report.check_empty("#{bad_inputs.size} malformed submissions rejected with 4xx", rejected_badly)

  # The counterpart: a lowercase method is *valid* — it must be normalized, not
  # rejected and not put on the wire verbatim (see src/server/util.rs:17).
  lower_method = rest_post_scan(VULN_URL,
    %({"method":"post","data":"q=test","skip_mining":true,"max_payloads_per_param":5}))
  report.check("lowercase method \"post\" is normalized, not rejected", lower_method.describe) do
    lower_method.ok? && lower_method.status == 200
  end
  if lm_id = lower_method.data.try(&.["scan_id"]?).try(&.as_s?)
    poll_until_terminal(lm_id, SCAN_TIMEOUT)
  end

  report.check("server survived the malformed-input barrage", rest.tail) do
    rest_request("GET", "/health").status == 200
  end

  # -- REST error surfaces --------------------------------------------------
  report.group("REST error surfaces")

  missing = rest_request("GET", "/scan/does-not-exist-#{Time.utc.to_unix_ms}")
  report.check("unknown scan id → 404", missing.describe) do
    missing.ok? && missing.status == 404 && missing.envelope_code == 404
  end
  missing_alias = rest_request("GET", "/result/does-not-exist")
  report.check("unknown id on the /result alias → 404", missing_alias.describe) do
    missing_alias.ok? && missing_alias.status == 404
  end
  missing_cancel = rest_request("DELETE", "/scan/does-not-exist")
  report.check("cancel of an unknown id → 404", missing_cancel.describe) do
    missing_cancel.ok? && missing_cancel.status == 404
  end
  report.check("404 body carries nosniff + JSON content type", missing.headers.to_s) do
    missing.headers["X-Content-Type-Options"]? == "nosniff" &&
      (missing.headers["Content-Type"]? || "").starts_with?("application/json")
  end

  # -- Part 3: MCP over stdio -----------------------------------------------
  report.group("MCP stdio server")

  tools = [] of JSON::Any

  if mcp_error = mcp.start
    report.fail("launch dalfox mcp", mcp_error)
  else
    init = mcp.call("initialize",
      %({"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"dalfox-smoke","version":"1"}}),
      30.seconds)

    if init.nil?
      report.fail("initialize handshake", "no reply within 30s; stderr: #{mcp.stderr.to_s[0, 400]}")
    else
      proto = init.dig?("result", "protocolVersion").try(&.as_s?)
      report.check("initialize reports a protocol version", init.to_json[0, 300]) do
        !(proto.nil? || proto.empty?)
      end
      report.check("initialize advertises a tools capability", init.to_json[0, 300]) do
        !init.dig?("result", "capabilities", "tools").nil?
      end
      mcp.notify("notifications/initialized")

      listing = mcp.call("tools/list", "{}", 30.seconds)
      tools = listing.try(&.dig?("result", "tools")).try(&.as_a?) || [] of JSON::Any
      report.check("tools/list returns tools", listing.nil? ? "no reply" : listing.to_json[0, 200]) do
        tools.size >= 6
      end

      documented = %w[scan_with_dalfox get_results_dalfox list_scans_dalfox
        cancel_scan_dalfox delete_scan_dalfox preflight_dalfox]
      listed = tools.compact_map { |t| t["name"]?.try(&.as_s?) }
      report.check_empty("all documented tools present", documented - listed)

      bad_tool_meta = [] of String
      tools.each do |t|
        name = t["name"]?.try(&.as_s?) || "(unnamed)"
        bad_tool_meta << "#{name}: empty description" if (t["description"]?.try(&.as_s?) || "").strip.empty?
        schema = t["inputSchema"]?
        if schema.nil? || schema.as_h?.nil?
          bad_tool_meta << "#{name}: no inputSchema object"
          next
        end
        bad_tool_meta << "#{name}: inputSchema is not type=object" unless schema["type"]?.try(&.as_s?) == "object"
        bad_tool_meta << "#{name}: inputSchema has no properties" if schema["properties"]?.try(&.as_h?).nil?
      end
      report.check_empty("every tool has a description and an object input schema", bad_tool_meta)

      # A real scan through the tool. wait=true puts submit + poll + retrieve
      # into one call, which is also the path agents are told to prefer.
      scan_args = %({"target":#{VULN_URL.to_json},"wait":true,) +
                  %("wait_timeout_sec":#{SCAN_TIMEOUT.total_seconds.to_i},) +
                  %("skip_mining":true,"max_payloads_per_param":40})
      payload, tool_err = mcp.call_tool("scan_with_dalfox", scan_args, SCAN_TIMEOUT + 30.seconds)
      if tool_err
        report.fail("scan_with_dalfox(wait) returns the finding", "JSON-RPC error: #{tool_err.to_json}")
      elsif payload.nil?
        report.fail("scan_with_dalfox(wait) returns the finding",
          "no reply; stderr: #{mcp.stderr.to_s[0, 400]}")
      else
        report.check_eq("MCP scan reaches done", "done",
          payload["status"]?.try(&.as_s?) || payload.to_json[0, 200])
        mcp_findings = payload["results"]?.try(&.as_a?) || [] of JSON::Any
        report.check("MCP scan reports the finding on `q`",
          "#{mcp_findings.size} findings: #{payload.to_json[0, 300]}") do
          mcp_findings.any? { |f| f["param"]?.try(&.as_s?) == "q" && f["type"]?.try(&.as_s?) == "V" }
        end
        if sid = payload["scan_id"]?.try(&.as_s?)
          again, again_err = mcp.call_tool("get_results_dalfox", %({"scan_id":#{sid.to_json}}), 30.seconds)
          report.check("get_results_dalfox re-reads the same scan",
            again_err.try(&.to_json) || (again.try(&.to_json) || "no reply")[0, 200]) do
            again.try(&.["scan_id"]?).try(&.as_s?) == sid
          end
        end
      end

      # Invalid arguments must come back as JSON-RPC errors — not a crash, not
      # a silently accepted scan, and above all not a hang.
      mcp_bad = [
        {"scan_with_dalfox", "non-http target", %({"target":"ftp://example.com"})},
        {"scan_with_dalfox", "empty target", %({"target":"   "})},
        {"scan_with_dalfox", "missing target", %({})},
        {"scan_with_dalfox", "zero timeout", %({"target":#{VULN_URL.to_json},"timeout":0})},
        {"scan_with_dalfox", "workers past ceiling", %({"target":#{VULN_URL.to_json},"workers":100000})},
        {"scan_with_dalfox", "unknown waf_bypass", %({"target":#{VULN_URL.to_json},"waf_bypass":"maybe"})},
        {"scan_with_dalfox", "unknown method verb", %({"target":#{VULN_URL.to_json},"method":"FETCH"})},
        {"scan_with_dalfox", "target is not a string", %({"target":42})},
        {"get_results_dalfox", "unknown scan_id", %({"scan_id":"nope-#{Time.utc.to_unix_ms}"})},
        {"cancel_scan_dalfox", "unknown scan_id", %({"scan_id":"nope-#{Time.utc.to_unix_ms}"})},
      ]
      # Two distinct questions, deliberately kept apart:
      #   (a) is the call rejected at all — never accepted, never a hang?
      #   (b) is it rejected through the same channel every time? dalfox's own
      #       validation raises JSON-RPC errors (ErrorData::invalid_params,
      #       e.g. src/mcp/mod.rs:1184), but arguments that fail rmcp's schema
      #       deserialization come back as a *successful* result carrying
      #       isError:true — so a client that only inspects `error` reads them
      #       as a started scan.
      mcp_unhandled = [] of String
      mcp_channel_split = [] of String
      mcp_bad.each do |tool, name, args|
        msg = mcp.call("tools/call", %({"name":#{tool.to_json},"arguments":#{args}}), 30.seconds)
        if msg.nil?
          mcp_unhandled << "#{tool}/#{name}: no reply (hang or crash)"
          next
        end
        if err = msg["error"]?
          if err["code"]?.try(&.as_i64?).nil?
            mcp_unhandled << "#{tool}/#{name}: error without a numeric code: #{err.to_json}"
          end
          next
        end
        if msg.dig?("result", "isError").try(&.as_bool?)
          text = msg.dig?("result", "content", 0, "text").try(&.as_s?) || ""
          mcp_channel_split << "#{tool}/#{name}: rejected via result.isError instead of a JSON-RPC error — #{text[0, 110]}"
          next
        end
        mcp_unhandled << "#{tool}/#{name}: accepted, returned #{msg.to_json[0, 160]}"
      end
      report.check_empty("#{mcp_bad.size} invalid tool calls are rejected, never accepted or hung", mcp_unhandled)
      report.check_empty("invalid tool calls all use the JSON-RPC error channel", mcp_channel_split)

      report.check("MCP server still answers after bad input",
        "stderr: #{mcp.stderr.to_s[0, 300]}") do
        !mcp.call("tools/list", "{}", 20.seconds).nil?
      end
    end
  end

  # -- Part 4: REST ↔ MCP parity --------------------------------------------
  report.group("REST ↔ MCP scan-parameter parity")

  rest_fields = rest_scan_option_fields
  report.check("parsed REST ScanOptions from #{REST_TYPES_RS}", "found #{rest_fields.size} fields") do
    rest_fields.size >= 20
  end

  scan_tool = tools.find { |t| t["name"]?.try(&.as_s?) == "scan_with_dalfox" }
  mcp_props = scan_tool.try(&.dig?("inputSchema", "properties")).try(&.as_h?) || {} of String => JSON::Any
  mcp_fields = {} of String => String
  # `target` is the scan target itself, top-level on both surfaces (REST carries
  # it on ScanRequest, MCP on the tool params) — it is not a scan *option*.
  mcp_props.each { |k, v| mcp_fields[k] = schema_type_of(v) unless k == "target" }
  report.check("read the MCP scan_with_dalfox schema", "found #{mcp_fields.size} fields") do
    mcp_fields.size >= 20
  end

  if rest_fields.empty? || mcp_fields.empty?
    report.skip("scan-parameter diff", "one of the two surfaces could not be read")
  else
    rest_only = (rest_fields.keys.to_set - mcp_fields.keys.to_set) - INTENTIONAL_REST_ONLY
    mcp_only = (mcp_fields.keys.to_set - rest_fields.keys.to_set) - INTENTIONAL_MCP_ONLY
    report.check_empty("no unexplained REST-only scan options",
      rest_only.to_a.sort!.map { |k| "#{k} (#{rest_fields[k]}) missing from MCP" }, limit: 20)
    report.check_empty("no unexplained MCP-only scan options",
      mcp_only.to_a.sort!.map { |k| "#{k} (#{mcp_fields[k]}) missing from REST" }, limit: 20)

    shared = (rest_fields.keys.to_set & mcp_fields.keys.to_set).to_a.sort!
    type_mismatches = shared.compact_map do |k|
      rest_fields[k] == mcp_fields[k] ? nil : "#{k}: REST #{rest_fields[k]} vs MCP #{mcp_fields[k]}"
    end
    report.check_empty("shared options agree on type", type_mismatches, limit: 20)
  end

  # Names that differ only by spelling are the worst case: `ScanOptions` has no
  # `deny_unknown_fields`, so an MCP-shaped body is accepted with a 200 and the
  # option is silently dropped. Prove that on the wire rather than inferring it.
  silently_ignored = [] of String
  rest_spelling = rest_post_scan(VULN_URL, %({"worker":0}))
  if rest_spelling.status != 400
    silently_ignored << "options.worker=0 should be 400, got #{rest_spelling.describe}"
  end
  mcp_spelling = rest_post_scan(VULN_URL, %({"workers":0}))
  if mcp_spelling.status == 200
    silently_ignored << "options.workers=0 (MCP spelling) accepted with HTTP 200 — the value is discarded"
    if ignored_id = mcp_spelling.data.try(&.["scan_id"]?).try(&.as_s?)
      rest_request("DELETE", "/scan/#{ignored_id}")
    end
  end
  report.check_empty("MCP-spelled options are not silently swallowed by REST", silently_ignored)
ensure
  # Teardown order mirrors dependency order: the scanners first, then the target
  # they were pointed at.
  mcp.stop
  rest.stop
  target.stop
end

exit report.finish
