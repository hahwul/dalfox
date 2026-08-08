# Request-and-wall-clock budget for dalfox, measured server-side.
#
# dalfox's cost regressions have all been invisible to unit tests: an endpoint
# that reflects every payload once drew ~33k requests for a single parameter,
# and the payload-cap change silently moved scan volume. This harness pins the
# cost down by scanning a lab that counts every request it receives, then gates
# the numbers against a committed snapshot.
#
# Flow:
#   1. Boot `scripts/labs/counting_server.cr` (or reuse a running one via
#      PERF_URL) and tear down whatever this process started.
#   2. For each scenario — one per lab endpoint — zero the counters via
#      `/reset`, run a scan with a fixed arg set under a hard timeout, and read
#      `/stats` back.
#   3. Record requests, requests-per-parameter, wall-clock, findings, and
#      whether the scan was cut short.
#   4. Write the snapshot to `docs/data/perf-budget.json`.
#   5. Gate against the committed snapshot: fail when requests or duration grow
#      past tolerance, when a scenario newly times out, or when a scenario's
#      finding count drops — a cost win that costs detection is not a win.
#
# Run with `crystal run scripts/perf_budget.cr`. Environment:
#   PERF_URL                reuse a lab already listening here (skips spawning)
#   PERF_PORT               port for the spawned lab            (default 4802)
#   PERF_TOLERANCE_PCT      allowed growth in requests/duration (default 25)
#   PERF_TIMEOUT            hard per-scenario scan timeout, s   (default 180)
#   PERF_ARGS               replace the fixed dalfox arg set (space-separated)
#   PERF_DATA_PATH          snapshot path (default docs/data/perf-budget.json)
#   PERF_UPDATE_BASELINE=1  write the snapshot and skip gating
#   DALFOX_BIN              binary under test (default target/release/dalfox)

require "http/client"
require "json"
require "./lib/dalfox"
require "./lib/sh"
require "./lib/snapshot"
require "./lib/report"

SERVER_SRC = "scripts/labs/counting_server.cr"
DATA_PATH  = ENV.fetch("PERF_DATA_PATH", "docs/data/perf-budget.json")

PERF_URL        = ENV["PERF_URL"]?.try(&.rstrip("/"))
PERF_PORT       = ENV.fetch("PERF_PORT", "4802").to_i
TOLERANCE_PCT   = ENV.fetch("PERF_TOLERANCE_PCT", "25").to_f
SCAN_TIMEOUT    = ENV.fetch("PERF_TIMEOUT", "180").to_f.seconds
UPDATE_BASELINE = ENV["PERF_UPDATE_BASELINE"]? == "1"

# Fixed arg set. Mining is skipped on purpose: the built-in dictionary fires a
# large fixed wordlist at every endpoint, which swamps the payload-injection
# volume this budget exists to watch. Override with PERF_ARGS to budget mining.
DEFAULT_ARGS = ["--skip-mining", "--timeout", "5"]
SCAN_ARGS    = ENV["PERF_ARGS"]?.try(&.split(' ', remove_empty: true)) || DEFAULT_ARGS

# Jitter floors. A 25% tolerance on a scenario that legitimately costs 22
# requests and 0.02s would flag noise as a regression, so every metric also
# gets an absolute floor and the larger of the two wins.
MIN_REQUEST_DELTA  = ENV.fetch("PERF_MIN_REQUEST_DELTA", "10").to_f
MIN_DURATION_DELTA = ENV.fetch("PERF_MIN_DURATION_DELTA", "1.0").to_f

# ---------------------------------------------------------------------------
# Scenarios — one per lab endpoint, each a different cost profile.
# ---------------------------------------------------------------------------

# `params` is the number of injection points the URL declares; it is the
# denominator for requests-per-parameter, the number that actually moved in the
# amplification and payload-cap incidents.
record Scenario,
  name : String,
  path : String,
  query : String,
  params : Int32,
  note : String

SCENARIOS = [
  Scenario.new("echo", "/echo", "q=dalfox", 1,
    "plain reflection in HTML body"),
  Scenario.new("reflect_all", "/reflect-all", "q=dalfox", 1,
    "attribute + script + href at once (amplification shape)"),
  Scenario.new("many", "/many", "a=1&b=2&c=3&d=4&e=5", 5,
    "five reflecting params (per-param cost scaling)"),
  Scenario.new("inert", "/inert", "q=dalfox", 1,
    "HTML-escaped, nothing exploitable (wasted work)"),
  Scenario.new("slow", "/slow", "q=dalfox", 1,
    "fixed small delay (timing sanity)"),
]

# One scenario's measurement. Serialized straight into the snapshot, so any
# field added here becomes gateable by dotted path.
struct Measurement
  include JSON::Serializable

  getter path : String
  getter note : String
  getter params : Int32
  getter requests : Int64          # counted by the lab: authoritative
  getter reported_requests : Int64 # dalfox's own meta.total_requests
  getter requests_per_param : Float64
  getter duration_s : Float64
  getter findings : Int32
  getter verified : Int32
  getter timed_out : Bool
  getter bytes_sent : Int64
  getter distinct_payloads : Int32
  getter requests_per_second : Float64

  def initialize(@path, @note, @params, @requests, @reported_requests,
                 @requests_per_param, @duration_s, @findings, @verified,
                 @timed_out, @bytes_sent, @distinct_payloads, @requests_per_second)
  end
end

# ---------------------------------------------------------------------------
# Lab lifecycle.
# ---------------------------------------------------------------------------

def http_get(url : String, timeout : Time::Span = 10.seconds) : String?
  uri = URI.parse(url)
  # Block form so the socket is always closed, and explicit timeouts so a wedged
  # lab surfaces as "not healthy" instead of hanging the harness forever.
  HTTP::Client.new(uri) do |client|
    client.connect_timeout = timeout
    client.read_timeout = timeout
    resp = client.get(uri.request_target)
    return resp.success? ? resp.body : nil
  end
rescue
  nil
end

def healthy?(base : String) : Bool
  http_get("#{base}/health", 2.seconds) == "ok"
end

# Compile the lab to a throwaway binary rather than using `crystal run`:
# `crystal run` leaves the compiled child behind when the parent is signalled,
# and this harness must not orphan a process holding the port.
def build_server : String
  bin = File.tempname("counting-server")
  puts "==> building #{SERVER_SRC}"
  out = Sh.run("crystal", ["build", SERVER_SRC, "-o", bin], timeout: 300.seconds)
  abort "crystal build failed: #{out.error_line}" unless out.success?
  bin
end

# Returns {base_url, process?, binary?}. A nil process means "reused, do not
# tear down".
def start_server : {String, Process?, String?}
  if url = PERF_URL
    abort "PERF_URL=#{url} is not serving /health" unless healthy?(url)
    puts "==> reusing lab at #{url}"
    return {url, nil, nil}
  end

  base = "http://127.0.0.1:#{PERF_PORT}"
  if healthy?(base)
    puts "==> reusing lab already listening on #{base}"
    return {base, nil, nil}
  end

  bin = build_server
  log = File.tempname("counting-server", ".log")
  process = Process.new(bin,
    env: {"COUNTING_PORT" => PERF_PORT.to_s},
    output: File.open(log, "w"),
    error: File.open(log, "a"))

  60.times do
    return {base, process, bin} if healthy?(base)
    unless process.exists?
      abort "lab exited during startup:\n#{File.read(log)}"
    end
    sleep 250.milliseconds
  end

  process.signal(Signal::KILL) rescue nil
  abort "lab did not become healthy on #{base}:\n#{File.read(log)}"
ensure
  File.delete(log) if log && File.exists?(log)
end

def stop_server(process : Process?, bin : String?)
  if process
    puts "==> stopping lab (pid #{process.pid})"
    process.signal(Signal::TERM) rescue nil
    process.wait rescue nil
  end
  File.delete(bin) if bin && File.exists?(bin)
end

# ---------------------------------------------------------------------------
# Measurement.
# ---------------------------------------------------------------------------

def stats(base : String) : JSON::Any
  body = http_get("#{base}/stats") || abort "could not read #{base}/stats"
  JSON.parse(body)
end

def json_i(node : JSON::Any, key : String) : Int64
  node[key]?.try { |v| v.as_i64? || v.as_i?.try(&.to_i64) || v.as_f?.try(&.to_i64) } || 0_i64
end

def json_f(node : JSON::Any, key : String) : Float64
  node[key]?.try { |v| v.as_f? || v.as_i?.try(&.to_f) } || 0.0
end

def measure(base : String, scenario : Scenario) : Measurement
  # Zero first: the previous scenario's traffic must not leak into this one.
  abort "could not reset counters" unless http_get("#{base}/reset")

  target = "#{base}#{scenario.path}?#{scenario.query}"
  result = Dalfox.scan(target, SCAN_ARGS, timeout: SCAN_TIMEOUT)
  s = stats(base)

  requests = json_i(s, "total_requests")
  # dalfox's own count, straight off the report envelope, to cross-check the
  # server-side counter above.
  reported = result.total_requests || 0_i64

  Measurement.new(
    path: scenario.path,
    note: scenario.note,
    params: scenario.params,
    requests: requests,
    reported_requests: reported,
    requests_per_param: (requests.to_f / scenario.params).round(1),
    duration_s: result.elapsed.total_seconds.round(3),
    findings: result.findings.size,
    verified: result.verified.size,
    timed_out: result.timed_out?,
    bytes_sent: json_i(s, "bytes_sent"),
    distinct_payloads: json_i(s, "distinct_payloads").to_i,
    requests_per_second: json_f(s, "requests_per_second"),
  )
end

# ---------------------------------------------------------------------------
# Reporting.
# ---------------------------------------------------------------------------

def print_table(measurements : Hash(String, Measurement))
  puts ""
  puts "  %-12s %9s %9s %9s %8s %7s  %s" % ["scenario", "requests", "req/param", "wall(s)", "findings", "V", "note"]
  puts "  " + "-" * 92
  measurements.each do |name, m|
    puts "  %-12s %9d %9.1f %9.2f %8d %7d  %s" % [
      name + (m.timed_out ? "*" : ""),
      m.requests, m.requests_per_param, m.duration_s,
      m.findings, m.verified, m.note,
    ]
  end
  puts "  (* = scan hit the #{SCAN_TIMEOUT.total_seconds.round}s hard timeout)" if measurements.any? { |_, m| m.timed_out }
  puts ""
end

# Tolerance for a metric: a percentage of the baseline, floored so that cheap
# scenarios do not flap on scheduler noise.
def tolerance(baseline : Float64?, pct : Float64, floor : Float64) : Float64
  return floor unless baseline
  Math.max(baseline.abs * pct / 100.0, floor)
end

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

abort "dalfox binary not found: #{Dalfox.bin}" unless Dalfox.available?
abort "missing lab: #{SERVER_SRC}" unless File.exists?(SERVER_SRC) || PERF_URL

base, process, bin = start_server

measurements = Hash(String, Measurement).new
begin
  puts "==> dalfox #{Dalfox.version} (#{Dalfox.bin}), args: #{SCAN_ARGS.join(' ')}"
  SCENARIOS.each do |scenario|
    print "==> #{scenario.name} "
    m = measure(base, scenario)
    measurements[scenario.name] = m
    puts "#{m.requests} requests, #{m.duration_s}s, #{m.findings} findings"
  end
ensure
  stop_server(process, bin)
end

print_table(measurements)

total_requests = measurements.sum { |_, m| m.requests }
total_duration = measurements.sum { |_, m| m.duration_s }
total_findings = measurements.sum { |_, m| m.findings }

payload = Snapshot.stamp("perf_budget", Dalfox.version, {
  scan_args: SCAN_ARGS,
  scenarios: measurements,
  total:     {
    requests:   total_requests,
    duration_s: total_duration.round(3),
    findings:   total_findings,
  },
})
after = JSON.parse(payload.to_json)
before = Snapshot.load(DATA_PATH)

if UPDATE_BASELINE
  Snapshot.write(DATA_PATH, payload)
  puts "==> baseline updated (PERF_UPDATE_BASELINE=1); no gating"
  exit 0
end

unless before
  Snapshot.write(DATA_PATH, payload)
  puts "==> no baseline at #{DATA_PATH}; wrote the first one. Nothing to gate."
  exit 0
end

# Build the metric map from the baseline so tolerances scale per scenario.
metrics = Hash(String, {Float64, Bool}).new
SCENARIOS.each do |s|
  req_path = "scenarios.#{s.name}.requests"
  dur_path = "scenarios.#{s.name}.duration_s"
  fnd_path = "scenarios.#{s.name}.findings"
  metrics[req_path] = {tolerance(Snapshot.dig_f(before, req_path), TOLERANCE_PCT, MIN_REQUEST_DELTA), false}
  metrics[dur_path] = {tolerance(Snapshot.dig_f(before, dur_path), TOLERANCE_PCT, MIN_DURATION_DELTA), false}
  # Detection is not a budget: any drop is a regression, hence tolerance 0.
  metrics[fnd_path] = {0.0, true}
end
metrics["total.requests"] = {tolerance(Snapshot.dig_f(before, "total.requests"), TOLERANCE_PCT, MIN_REQUEST_DELTA), false}

report = Report.new("perf budget (tolerance #{TOLERANCE_PCT.round}%, floors #{MIN_REQUEST_DELTA.round} req / #{MIN_DURATION_DELTA}s)")

# One check per scenario rather than per metric: the deltas are printed in full
# anyway, and a scenario is the unit a reader acts on.
index = Snapshot.compare(before, after, metrics).to_h { |d| {d.name, d} }

report.group("cost + detection deltas")
SCENARIOS.each do |s|
  names = %w[requests duration_s findings].map { |m| "scenarios.#{s.name}.#{m}" }
  names.each { |n| puts index[n].to_s }
  report.check_empty("#{s.name} within budget", names.select { |n| index[n].regressed? })
end

total = index["total.requests"]
puts total.to_s
report.check_empty("total requests within budget", total.regressed? ? [total.name] : [] of String)

report.group("liveness")
SCENARIOS.each do |s|
  m = measurements[s.name]
  was_timeout = before.dig?("scenarios", s.name, "timed_out").try(&.as_bool?) || false
  if m.timed_out && !was_timeout
    report.fail("#{s.name} timed out", "newly exceeds the #{SCAN_TIMEOUT.total_seconds.round}s budget")
  elsif m.timed_out
    report.skip("#{s.name} timed out", "already timing out in the baseline")
  else
    report.pass("#{s.name} completed")
  end
end

Snapshot.write(DATA_PATH, payload)
puts "==> refresh the baseline with PERF_UPDATE_BASELINE=1 once a change is understood"
exit report.finish
