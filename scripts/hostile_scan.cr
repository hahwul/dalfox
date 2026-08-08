# Hostile-response regression gate: point dalfox at every endpoint of the
# adversarial lab (`scripts/labs/hostile_server.cr`) and assert only one thing —
# **the scanner terminates, without crashing, inside a wall-clock budget and
# under a memory ceiling**. Detecting nothing is a pass; surviving is the point.
#
# dalfox has been hardened against hostile *responses* several times (capped
# body reads after an OOM, reflection occurrence/range caps after a hang, a
# parser recursion guard + a bigger parse stack after deeply-nested JavaScript
# aborted the process). Each of those was found by hand and none had a standing
# regression harness. This is it.
#
# Flow:
#   1. Boot the lab (or reuse HOSTILE_URL) and wait for /health.
#   2. For each scenario, run the real binary under `/usr/bin/time` so peak RSS
#      is measured, with a hard per-endpoint budget.
#   3. PASS  = a controlled exit within budget and under the ceiling: 0 (clean),
#              1 (findings) or 2 (dalfox declared the target unscannable).
#      FAIL  = signal death (SIGSEGV/SIGABRT), a Rust panic, a timeout kill, or
#              peak RSS above HOSTILE_MAX_RSS_MB.
#   4. Print a scenario / outcome / elapsed / peak RSS / findings table, verify
#      the lab itself is still alive, and exit non-zero on any failure.
#
# A failure here is a real bug in dalfox. Do not "fix" it by raising the budget,
# shrinking the payload, or dropping the scenario — report the endpoint, the
# repro command, and the signal.
#
# Environment (defaults in parentheses):
#   HOSTILE_URL          scan an already-running lab instead of booting one  (—)
#   HOSTILE_PORT         port for the lab this script boots               (4803)
#   HOSTILE_BUDGET_SEC   hard wall-clock budget per endpoint                (45)
#   HOSTILE_MAX_RSS_MB   peak-RSS ceiling per scan                        (1024)
#   HOSTILE_ONLY         run a single scenario by name (debugging)          (—)
#   HOSTILE_REQ_TIMEOUT  dalfox --timeout, per request, seconds              (2)
#   HOSTILE_MAX_PAYLOADS dalfox --max-payloads-per-param                    (30)
#   HOSTILE_BOOT_SEC     how long to wait for the lab to compile+listen    (180)
#   DALFOX_BIN           binary under test          (target/release/dalfox)
# Every HOSTILE_* knob of the lab itself (HOSTILE_HUGE_MB, HOSTILE_JS_DEPTH, …)
# is inherited by the child, so `HOSTILE_HUGE_MB=256 crystal run …` works.

require "http/client"
require "./lib/sh"
require "./lib/dalfox"
require "./lib/report"

PORT       = ENV.fetch("HOSTILE_PORT", "4803")
BASE_URL   = ENV.fetch("HOSTILE_URL", "http://127.0.0.1:#{PORT}").rstrip("/")
BUDGET     = ENV.fetch("HOSTILE_BUDGET_SEC", "45").to_i.seconds
MAX_RSS_MB = ENV.fetch("HOSTILE_MAX_RSS_MB", "1024").to_i
ONLY       = ENV["HOSTILE_ONLY"]?

# BUDGET and REQ_TIMEOUT are coupled, and the coupling is the whole reason this
# default is 2 and not 10. On a drip-feed endpoint (`/slowloris`, `/never-ends`)
# every phase pays the full per-request timeout, and the measured worst case is
# ~13 sequential timeouts before the scan ends: 3s → 40s, 5s → 60s, linearly.
# That is bounded, correct behaviour, not a hang — so REQ_TIMEOUT × ~15 must fit
# inside BUDGET, or the gate cries wolf on its own configuration. Raise BUDGET
# alongside REQ_TIMEOUT if you raise it, and never the other way round: BUDGET is
# what catches a genuine hang.
REQ_TIMEOUT  = ENV.fetch("HOSTILE_REQ_TIMEOUT", "2")
MAX_PAYLOADS = ENV.fetch("HOSTILE_MAX_PAYLOADS", "30")
BOOT_SEC     = ENV.fetch("HOSTILE_BOOT_SEC", "180").to_i
SERVER_PATH  = "scripts/labs/hostile_server.cr"

# ---------------------------------------------------------------------------
# Scenarios. `path` is appended to the lab base URL; `args` are extra dalfox
# flags for that shape only. `why` is what breaks if the scenario regresses.
# ---------------------------------------------------------------------------

record Scenario,
  name : String,
  path : String,
  why : String,
  args : Array(String) = [] of String

SCENARIOS = [
  Scenario.new("huge", "/huge?q=dalfox",
    "64 MB body — the capped body read (16 MiB) that replaced an OOM"),
  Scenario.new("deep-js-paren", "/deep-js?q=dalfox&shape=paren",
    "50k nested parens — oxc has no parser depth guard"),
  Scenario.new("deep-js-bracket", "/deep-js?q=dalfox&shape=bracket",
    "50k nested array literals"),
  Scenario.new("deep-js-ternary", "/deep-js?q=dalfox&shape=ternary",
    "50k nested conditionals — a different recursion path than parens"),
  Scenario.new("deep-js-call", "/deep-js?q=dalfox&shape=call",
    "50k nested call expressions"),
  Scenario.new("deep-js-member", "/deep-js?q=dalfox&shape=member",
    "50k-link member chain — flat to a per-call depth counter"),
  Scenario.new("deep-js-helper", "/deep-js?q=dalfox&shape=helper",
    "x.a().a().a()… re-entry — the shape that defeats per-call depth limits"),
  Scenario.new("many-reflections", "/many-reflections?q=dalfox",
    "100k echoes — what the reflection occurrence/range caps exist for"),
  Scenario.new("slowloris", "/slowloris?q=dalfox",
    "one body byte per delay — the scan must stay bounded by --timeout (measured: " \
    "~12 sequential per-request timeouts), not stall on the drip"),
  Scenario.new("redirect-loop", "/redirect-loop?q=dalfox",
    "endless 302 chain", ["-F"]),
  Scenario.new("redirect-self", "/redirect-loop?self=1&q=dalfox",
    "302 to the identical URL forever", ["-F"]),
  Scenario.new("bad-headers", "/bad-headers?q=dalfox",
    "300+ headers on a 429 — hyper caps a response at 100, so this is the " \
    "\"server refuses to be scanned\" shape; it must fail gracefully, not hang"),
  Scenario.new("bad-headers-retry", "/bad-headers?q=dalfox&mode=retry",
    "absurd Retry-After (huge int / year-9999 HTTP-date / U+2028 garbage / -1) on a 429"),
  Scenario.new("bad-headers-ctrl", "/bad-headers?q=dalfox&mode=ctrl",
    "NUL and C0 control characters inside header values"),
  Scenario.new("bad-headers-length", "/bad-headers?q=dalfox&mode=length",
    "two disagreeing Content-Length headers"),
  Scenario.new("chunk-lie-short", "/chunk-lie?q=dalfox&mode=short",
    "Content-Length promises 10x the bytes sent, then the socket closes"),
  Scenario.new("chunk-lie-long", "/chunk-lie?q=dalfox&mode=long",
    "more body bytes than Content-Length declares"),
  Scenario.new("chunk-lie-badchunk", "/chunk-lie?q=dalfox&mode=badchunk",
    "chunked framing with a non-hex chunk-size line"),
  Scenario.new("gzip-bomb", "/gzip-bomb?q=dalfox",
    "~500 KB on the wire, 512 MB inflated. Measured 2026-08: a single such " \
    "response costs ~2.1 GB RSS. The 16 MiB body cap holds, but processing a " \
    "capped body amplifies ~130x for NUL/'<'-dense content (8 MB of NUL = 1068 MB, " \
    "8 MB of '<' = 613 MB, 8 MB of HTML = 206 MB, 8 MB of 'A' = 58 MB), so 16 MiB " \
    "× 130 ≈ 2.1 GB per response × concurrency. gzip is only the cheap delivery " \
    "vehicle; plain 16 MiB of NULs buys the same"),
  Scenario.new("nul-bytes", "/nul-bytes?q=dalfox",
    "NUL bytes around and inside the reflected region"),
  Scenario.new("invalid-utf8", "/invalid-utf8?q=dalfox",
    "invalid UTF-8 (bad continuations, overlongs, surrogates) in the body"),
  Scenario.new("never-ends", "/never-ends?q=dalfox",
    "a chunked response that never sends its last chunk"),
]

# ---------------------------------------------------------------------------
# Process control.
#
# `Sh.run` SIGKILLs only the process it spawned. Here dalfox runs *under*
# `/usr/bin/time`, so killing the wrapper would leave an orphaned scanner
# hammering the lab for the rest of the run — hence a local runner that keeps
# the pid and kills the whole subtree.
# ---------------------------------------------------------------------------

def kill_tree(pid : Int64)
  Sh.capture("pgrep", ["-P", pid.to_s]).split(/\s+/, remove_empty: true).each do |child|
    child.to_i64?.try { |c| kill_tree(c) }
  end
  Process.signal(Signal::KILL, pid.to_i) rescue nil
end

def run_capped(cmd : String, args : Array(String), budget : Time::Span) : Sh::Output
  out_io, err_io = IO::Memory.new, IO::Memory.new
  started = Sh.clock
  process = Process.new(cmd, args,
    input: Process::Redirect::Close, output: out_io, error: err_io)
  status_ch = Channel(Process::Status).new(1)
  spawn { status_ch.send(process.wait) }

  timed_out = false
  status = select
  when s = status_ch.receive
    s
  when timeout(budget)
    timed_out = true
    kill_tree(process.pid)
    status_ch.receive
  end

  code = begin
    status.exit_code
  rescue
    -1
  end
  Sh::Output.new(code, out_io.to_s, err_io.to_s, timed_out, Sh.clock - started)
rescue ex
  Sh::Output.new(127, "", ex.message || "spawn failed", false, Time::Span.zero)
end

# ---------------------------------------------------------------------------
# Peak RSS. BSD `/usr/bin/time -l` (macOS) reports bytes, GNU `-v` reports KB.
# When neither exists the memory assertion is skipped, loudly.
# ---------------------------------------------------------------------------

enum RssStyle
  Bsd  # /usr/bin/time -l
  Gnu  # /usr/bin/time -v
  None # unavailable — assertion skipped
end

def detect_rss_style : RssStyle
  probe = Sh.which("true") || "/usr/bin/true"
  return RssStyle::None unless File.exists?("/usr/bin/time")
  bsd = Sh.run("/usr/bin/time", ["-l", probe], timeout: 10.seconds)
  return RssStyle::Bsd if bsd.stderr.includes?("maximum resident set size")
  gnu = Sh.run("/usr/bin/time", ["-v", probe], timeout: 10.seconds)
  return RssStyle::Gnu if gnu.stderr.includes?("Maximum resident set size")
  RssStyle::None
end

RSS_STYLE = detect_rss_style

def rss_mb(stderr : String) : Float64?
  case RSS_STYLE
  in RssStyle::Bsd
    stderr.match(/^\s*(\d+)\s+maximum resident set size/m).try { |m| m[1].to_f / (1024 * 1024) }
  in RssStyle::Gnu
    stderr.match(/Maximum resident set size \(kbytes\):\s*(\d+)/).try { |m| m[1].to_f / 1024 }
  in RssStyle::None
    nil
  end
end

def time_prefix : {String, Array(String)}
  case RSS_STYLE
  in RssStyle::Bsd  then {"/usr/bin/time", ["-l"]}
  in RssStyle::Gnu  then {"/usr/bin/time", ["-v"]}
  in RssStyle::None then {Dalfox.bin, [] of String}
  end
end

# ---------------------------------------------------------------------------
# Lab lifecycle.
# ---------------------------------------------------------------------------

def health? : Bool
  HTTP::Client.get("#{BASE_URL}/health") { |r| r.status_code == 200 }
rescue
  false
end

# Returns the lab process (nil when HOSTILE_URL pointed at an existing one).
def boot_lab(log_path : String) : Process?
  if health?
    puts "==> reusing lab already listening at #{BASE_URL}"
    return nil
  end
  if ENV["HOSTILE_URL"]?
    abort "HOSTILE_URL=#{BASE_URL} is set but /health does not answer"
  end

  puts "==> booting #{SERVER_PATH} (compiles first; up to #{BOOT_SEC}s)"
  log = File.open(log_path, "w")
  process = Process.new("crystal", ["run", "--no-debug", SERVER_PATH],
    env: {"HOSTILE_PORT" => PORT},
    input: Process::Redirect::Close, output: log, error: log)

  BOOT_SEC.times do
    if health?
      puts "==> lab up at #{BASE_URL}"
      return process
    end
    unless process.exists?
      abort "lab exited during boot; log:\n#{File.read(log_path)}"
    end
    sleep 1.second
  end
  kill_tree(process.pid)
  abort "lab did not answer /health within #{BOOT_SEC}s; log:\n#{File.read(log_path)}"
end

# ---------------------------------------------------------------------------
# Scanning.
# ---------------------------------------------------------------------------

record Outcome,
  scenario : Scenario,
  ok : Bool,
  label : String,
  detail : String,
  elapsed : Time::Span,
  rss : Float64?,
  findings : Int32

# Rust/abort signatures worth surfacing even when the exit code alone would
# already fail the check — the message is what makes a report actionable.
CRASH_MARKERS = [
  "panicked at",
  "fatal runtime error",
  "stack overflow",
  "Abort trap",
  "Segmentation fault",
  "core dumped",
  "terminated abnormally",
  "memory allocation of",
]

def scan(scenario : Scenario) : Outcome
  out_file = File.tempname("dalfox-hostile", ".json")
  dalfox_args = ["scan", BASE_URL + scenario.path,
                 "--format", "json", "-o", out_file,
                 "--no-color", "-S",
                 "--skip-mining",
                 "--timeout", REQ_TIMEOUT,
                 "--max-payloads-per-param", MAX_PAYLOADS] + scenario.args
  cmd, prefix = time_prefix
  argv = RSS_STYLE.none? ? dalfox_args : prefix + [Dalfox.bin] + dalfox_args

  output = run_capped(cmd, argv, BUDGET)
  findings = Dalfox.parse_report(out_file)
  rss = rss_mb(output.stderr)
  marker = CRASH_MARKERS.find { |m| output.stderr.includes?(m) }

  # Exit codes are `ScanOutcome` (src/main.rs): 0 clean, 1 findings, 2 a
  # deliberate error exit (e.g. the target was declared UNREACHABLE because the
  # client rejected the response). All three are controlled terminations, so all
  # three survive — 2 is labelled separately because "dalfox refused to scan
  # this endpoint at all" is a materially different result from a clean scan.
  ok, label, detail =
    if output.timed_out
      {false, "TIMEOUT", "still running after #{BUDGET.total_seconds.round}s — killed"}
    elsif marker
      {false, "CRASH", "exit #{output.status}, stderr says #{marker.inspect}: #{output.error_line}"}
    elsif output.status < 0 || output.status > 2
      sig = output.status > 128 ? " (signal #{output.status - 128})" : ""
      {false, "CRASH", "exit #{output.status}#{sig}: #{output.error_line}"}
    elsif rss && rss > MAX_RSS_MB
      {false, "MEMORY", "peak RSS #{rss.round(1)} MB > ceiling #{MAX_RSS_MB} MB"}
    elsif output.status == 2
      {true, "errored", "exit 2 (dalfox reported the target as unscannable — a controlled exit)"}
    else
      {true, "survived", ""}
    end

  Outcome.new(scenario, ok, label, detail, output.elapsed, rss, findings.size)
ensure
  File.delete(out_file) if out_file && File.exists?(out_file)
end

# ---------------------------------------------------------------------------
# Reporting.
# ---------------------------------------------------------------------------

def print_table(outcomes : Array(Outcome))
  name_w = Math.max(8, outcomes.map(&.scenario.name.size).max)
  puts ""
  puts "%-#{name_w}s  %-9s  %8s  %10s  %8s" % {"scenario", "outcome", "elapsed", "peak RSS", "findings"}
  puts "-" * (name_w + 43)
  outcomes.each do |o|
    rss = o.rss ? "#{o.rss.not_nil!.round(1)} MB" : "n/a"
    puts "%-#{name_w}s  %-9s  %7.1fs  %10s  %8d" % {
      o.scenario.name, o.label, o.elapsed.total_seconds, rss, o.findings,
    }
  end
end

def repro(scenario : Scenario) : String
  ([Dalfox.bin, "scan", BASE_URL + scenario.path,
    "--skip-mining", "--timeout", REQ_TIMEOUT,
    "--max-payloads-per-param", MAX_PAYLOADS] + scenario.args)
    .map { |a| Process.quote(a) }.join(" ")
end

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

abort "dalfox binary not found: #{Dalfox.bin} (build it first)" unless Dalfox.available?

scenarios = ONLY ? SCENARIOS.select { |s| s.name == ONLY } : SCENARIOS
abort "no scenario named #{ONLY} (have: #{SCENARIOS.map(&.name).join(", ")})" if scenarios.empty?

log_path = File.tempname("hostile-lab", ".log")
lab = boot_lab(log_path)
exit_code = 0

begin
  report = Report.new("hostile responses — dalfox #{Dalfox.version}")
  puts "    budget #{BUDGET.total_seconds.round}s/endpoint · RSS ceiling #{MAX_RSS_MB} MB · " \
       "#{scenarios.size} scenarios"
  report.group("survival")

  if RSS_STYLE.none?
    report.skip("peak RSS measurement",
      "no usable /usr/bin/time (-l on BSD/macOS, -v on GNU) — memory ceiling not enforced")
  end

  outcomes = scenarios.map do |scenario|
    outcome = scan(scenario)
    if outcome.ok
      note = outcome.detail.empty? ? "" : " — #{outcome.detail}"
      report.pass(scenario.name, "#{outcome.label} in #{outcome.elapsed.total_seconds.round(1)}s#{note}")
    else
      report.fail(scenario.name, "#{outcome.label}: #{outcome.detail} | #{scenario.why} | repro: #{repro(scenario)}")
    end
    outcome
  end

  print_table(outcomes)

  # The lab streaming its own hostility must not have killed the lab: a dead
  # server would silently turn every later scenario into a trivial pass.
  report.group("lab")
  report.check("lab still serving after the run", "GET #{BASE_URL}/health did not answer") { health? }

  # NOT `exit report.finish`: Crystal's `exit` does not unwind the stack, so an
  # `exit` here would skip the `ensure` below and leave the lab listening on
  # PORT after the run — which then makes the *next* run silently reuse a stale
  # server. Record the code, tear down, exit last.
  exit_code = report.finish
ensure
  if lab
    puts "==> stopping lab"
    kill_tree(lab.pid)
    lab.wait rescue nil
  end
  File.delete(log_path) if File.exists?(log_path)
end

exit exit_code
