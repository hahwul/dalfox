# Measures dalfox's precision and recall against the labelled mock-case corpus
# in one pass, and gates on regressions.
#
# The corpus under `tests/functional/mock_cases/` labels every case with
# `expected_detection`, which is exactly the ground truth an FP/FN measurement
# needs — but nothing in the repo turns it into a number. "Did my fix cost
# recall?" therefore gets re-derived by hand every time, with a different ad-hoc
# script each time. This harness is that measurement, committed.
#
# Flow:
#   1. Start `scripts/labs/corpus_server.cr` as a child process (or reuse an
#      already-running lab via EFFECTIVENESS_URL) and wait for `/health`.
#   2. Read `/map/json` — the lab's catalog of scannable cases, each with the
#      absolute URL, the declared injection point, and the expected verdict.
#   3. Scan every case with the release binary in parallel, targeting the
#      declared injection point (`-p name:header`, `--cookies`, `-d`, …).
#   4. Classify: expected && detected = TP, expected && !detected = FN,
#      !expected && detected = FP, !expected && !detected = TN. Tallied twice —
#      once for any finding, once for `V`-only, because an `R` on a case the
#      corpus labels clean is a much weaker claim than a `V`.
#   5. Write `docs/data/effectiveness.json`, including every FP and FN with the
#      payload and evidence so the failures are actionable.
#   6. Compare against the committed snapshot and exit non-zero when recall
#      drops or the FP count rises. No committed snapshot yet = "no baseline",
#      exit 0.
#
# Environment:
#   EFFECTIVENESS_URL          scan an already-running lab instead of starting one
#   EFFECTIVENESS_PORT         port for the lab this script starts   (default 4801)
#   EFFECTIVENESS_CATEGORIES   comma-separated category filter passed to the lab
#   EFFECTIVENESS_LIMIT        scan only the first N cases (smoke runs)
#   EFFECTIVENESS_CONCURRENCY  parallel scans                        (default 8)
#   EFFECTIVENESS_RETRIES      retries for a scan that errored out   (default 1)
#   EFFECTIVENESS_TIMEOUT      per-scan wall-clock budget, seconds   (default 120)
#   EFFECTIVENESS_TOLERANCE    recall/precision regression slack, pp (default 0.5)
#   EFFECTIVENESS_FP_TOLERANCE extra false positives tolerated       (default 0)
#   EFFECTIVENESS_RENDER_ONLY  1 = skip scanning, re-report the committed snapshot
#   EFFECTIVENESS_DATA_PATH    snapshot path        (default docs/data/effectiveness.json)
#   DALFOX_BIN                 binary under test    (default target/release/dalfox)

require "http/client"
require "json"

require "./lib/dalfox"
require "./lib/report"
require "./lib/sh"
require "./lib/snapshot"

SERVER_SRC = "scripts/labs/corpus_server.cr"

LAB_URL        = ENV["EFFECTIVENESS_URL"]?.try(&.rstrip("/"))
PORT           = ENV.fetch("EFFECTIVENESS_PORT", "4801").to_i
CATEGORIES     = ENV["EFFECTIVENESS_CATEGORIES"]?
LIMIT          = ENV["EFFECTIVENESS_LIMIT"]?.try(&.to_i?)
CONCURRENCY    = ENV.fetch("EFFECTIVENESS_CONCURRENCY", "8").to_i
RETRIES        = ENV.fetch("EFFECTIVENESS_RETRIES", "1").to_i
SCAN_TIMEOUT   = ENV.fetch("EFFECTIVENESS_TIMEOUT", "120").to_i
TOLERANCE      = ENV.fetch("EFFECTIVENESS_TOLERANCE", "0.5").to_f
FP_TOLERANCE   = ENV.fetch("EFFECTIVENESS_FP_TOLERANCE", "0").to_f
RENDER_ONLY    = ENV["EFFECTIVENESS_RENDER_ONLY"]? == "1"
DATA_PATH      = ENV.fetch("EFFECTIVENESS_DATA_PATH", "docs/data/effectiveness.json")
REQUEST_BUDGET = ENV.fetch("EFFECTIVENESS_REQUEST_TIMEOUT", "7")

# ---------------------------------------------------------------------------
# Lab catalog (shape of /map/json — see scripts/labs/corpus_server.cr).
# ---------------------------------------------------------------------------

struct LabCase
  include JSON::Serializable
  getter uid : String
  getter id : Int32
  getter name : String
  getter category : String
  getter handler_type : String
  getter expected_detection : Bool
  getter method : String
  getter url : String
  getter param : String
  getter location : String
end

struct LabMap
  include JSON::Serializable
  getter count : Int32
  getter cases : Array(LabCase)
end

# ---------------------------------------------------------------------------
# Lab lifecycle.
# ---------------------------------------------------------------------------

def health?(url : String) : Bool
  HTTP::Client.get("#{url}/health") { |r| r.success? }
rescue
  false
end

def wait_health(url : String, attempts : Int32) : Bool
  attempts.times do
    return true if health?(url)
    sleep 250.milliseconds
  end
  false
end

# The lab this run is responsible for. `process` is nil when we attached to an
# instance somebody else started — in that case tearing it down is not ours to
# do.
class Lab
  getter url : String

  def initialize(@url : String, @process : Process? = nil, @binary : String? = nil)
  end

  def self.start : Lab
    if url = LAB_URL
      abort "no lab at #{url} (EFFECTIVENESS_URL is set, so none was started)" unless wait_health(url, 8)
      puts "==> using the lab already running at #{url}"
      return Lab.new(url)
    end

    # Compile first rather than `crystal run`: that spawns the built binary as a
    # grandchild, so the PID we hold would not be the server and SIGTERM would
    # leave the lab listening after this script exits.
    binary = File.tempname("corpus-server")
    puts "==> building #{SERVER_SRC}"
    build = Sh.run("crystal", ["build", "-o", binary, SERVER_SRC], timeout: 300.seconds)
    abort "crystal build failed:\n#{build.stderr}" unless build.success?

    env = {"CORPUS_PORT" => PORT.to_s}
    if categories = CATEGORIES
      env["CORPUS_CATEGORIES"] = categories
    end
    process = Process.new(binary, [] of String, env: env,
      output: Process::Redirect::Inherit,
      error: Process::Redirect::Inherit)

    url = "http://127.0.0.1:#{PORT}"
    unless wait_health(url, 60)
      process.signal(Signal::KILL) rescue nil
      abort "lab did not become healthy on port #{PORT}"
    end
    Lab.new(url, process, binary)
  end

  # Idempotent: called from an `ensure`, which can run after a partial start.
  def stop
    if process = @process
      puts "==> stopping the lab"
      process.signal(Signal::TERM) rescue nil
      # SIGTERM closes the listener and `listen` returns; escalate if it does
      # not, so a wedged lab cannot hang the harness forever.
      done = Channel(Nil).new(1)
      spawn do
        process.wait rescue nil
        done.send(nil)
      end
      select
      when done.receive
      when timeout(5.seconds)
        process.signal(Signal::KILL) rescue nil
      end
      @process = nil
    end
    if binary = @binary
      File.delete(binary) if File.exists?(binary)
      @binary = nil
    end
  end
end

# ---------------------------------------------------------------------------
# Scanning.
# ---------------------------------------------------------------------------

# Argument list targeting the injection point the catalog declares.
#
# Every case turns off the reflection-discovery phases it does not need, both to
# keep the request budget sane and so a finding can only be attributed to the
# declared injection point. Two per-location quirks, both verified against the
# binary rather than assumed:
#
#   * Header — an explicitly named `-p name:header` is probed even under
#     `--skip-reflection-header`, so the blanket common-header sweep can be
#     switched off without losing the case's own header.
#   * Cookie — cookie discovery only walks cookies actually supplied, so the
#     cookie has to be seeded with `--cookies`; `-p name:cookie` alone probes
#     nothing. It also files the result under the param name `Cookie` with
#     `Location::Header`, so `--skip-reflection-header` silently suppresses
#     every cookie finding. Hence: seed the cookie, leave header discovery on.
def build_args(lab_case : LabCase) : Array(String)
  args = ["--skip-mining", "--timeout", REQUEST_BUDGET, "--scan-timeout", SCAN_TIMEOUT.to_s]

  case lab_case.location
  when "Header"
    args.concat(["-p", "#{lab_case.param}:header",
                 "--skip-reflection-header", "--skip-reflection-cookie", "--skip-reflection-path"])
  when "Cookie"
    args.concat(["--cookies", "#{lab_case.param}=seed", "--skip-reflection-path"])
  when "Body"
    args.concat(["-X", lab_case.method, "-d", "#{lab_case.param}=seed",
                 "--skip-reflection-header", "--skip-reflection-cookie", "--skip-reflection-path"])
  when "Path"
    args.concat(["--skip-reflection-header", "--skip-reflection-cookie"])
  else # Query
    args.concat(["--skip-reflection-header", "--skip-reflection-cookie", "--skip-reflection-path"])
  end

  args
end

def scan(lab_case : LabCase) : Dalfox::ScanResult
  out_file = File.tempname("dalfox-effectiveness", ".json")
  args = ["scan", lab_case.url,
          "--format", "json", "-o", out_file,
          "--no-color", "-S"] + build_args(lab_case)
  output = Sh.run(Dalfox.bin, args, timeout: (SCAN_TIMEOUT + 30).seconds)
  Dalfox::ScanResult.new(Dalfox.parse_report(out_file), output, args,
    Dalfox.parse_meta(out_file))
ensure
  File.delete(out_file) if out_file && File.exists?(out_file)
end

# One scanned case, reduced to what the tallies and the snapshot need.
struct Outcome
  getter lab_case : LabCase
  getter detected : Bool
  getter verified : Bool
  getter findings : Array(Dalfox::Finding)
  getter seconds : Float64
  getter error : String?

  def initialize(@lab_case, @detected, @verified, @findings, @seconds, @error)
  end

  def expected : Bool
    @lab_case.expected_detection
  end

  # The finding that best explains the verdict: a `V` if there is one, so the
  # snapshot shows the strongest claim dalfox made about the case.
  def lead : Dalfox::Finding?
    @findings.find(&.verified?) || @findings.first?
  end
end

def measure_once(lab_case : LabCase) : Outcome
  result = scan(lab_case)
  # Informational findings (outdated libraries and friends) are not XSS claims
  # and must not count as a detection on a case labelled clean.
  xss = result.xss
  detected = !xss.empty? || (result.findings.empty? && result.output.status == 1)
  error = if result.timed_out?
            "timeout after #{result.elapsed.total_seconds.round(1)}s"
          elsif result.crashed?
            "exit #{result.output.status}: #{result.output.error_line}"
          end
  Outcome.new(lab_case, detected, xss.any?(&.verified?), xss,
    result.elapsed.total_seconds, error)
end

# Retry a case whose scan errored out.
#
# dalfox exits 2 when a target fails preflight, and a run right after another
# one reliably produced a burst of those: 100k+ localhost connections leave
# enough sockets in TIME_WAIT that the lab starts refusing connects. A refused
# connection is a missing measurement, not a missed detection — left alone it
# would show up as a false negative and make the recall number a lie. A
# detection result (found or not found) is never retried, so this cannot paper
# over a real miss.
def measure(lab_case : LabCase) : Outcome
  attempt = 0
  loop do
    outcome = measure_once(lab_case)
    return outcome if outcome.error.nil? || attempt >= RETRIES
    attempt += 1
    sleep 500.milliseconds
  end
end

# ---------------------------------------------------------------------------
# Tallies.
# ---------------------------------------------------------------------------

# Confusion matrix plus the derived rates. Used once for "any finding" and once
# for "`V` findings only".
class Tally
  property tp = 0
  property fp = 0
  property fn = 0
  property tn = 0

  def add(expected : Bool, detected : Bool)
    if expected
      detected ? (@tp += 1) : (@fn += 1)
    else
      detected ? (@fp += 1) : (@tn += 1)
    end
  end

  def cases : Int32
    @tp + @fp + @fn + @tn
  end

  def expected : Int32
    @tp + @fn
  end

  def precision : Float64
    ratio(@tp, @tp + @fp)
  end

  def recall : Float64
    ratio(@tp, @tp + @fn)
  end

  def f1 : Float64
    p = precision
    r = recall
    (p + r).zero? ? 0.0 : (2 * p * r / (p + r)).round(2)
  end

  private def ratio(num : Int32, den : Int32) : Float64
    den.zero? ? 0.0 : (num.to_f * 100 / den).round(2)
  end

  def to_json_object
    {
      cases:     cases,
      expected:  expected,
      tp:        @tp,
      fp:        @fp,
      fn:        @fn,
      tn:        @tn,
      precision: precision,
      recall:    recall,
      f1:        f1,
    }
  end
end

def median(values : Array(Float64)) : Float64
  return 0.0 if values.empty?
  sorted = values.sort
  mid = sorted.size // 2
  (sorted.size.odd? ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2).round(3)
end

# ---------------------------------------------------------------------------
# Snapshot assembly.
# ---------------------------------------------------------------------------

def build_snapshot(outcomes : Array(Outcome), wall_clock : Float64, lab_count : Int32) : JSON::Any
  overall = Tally.new
  verified_overall = Tally.new
  by_category = Hash(String, Tally).new { |h, k| h[k] = Tally.new }
  verified_by_category = Hash(String, Tally).new { |h, k| h[k] = Tally.new }

  outcomes.each do |o|
    overall.add(o.expected, o.detected)
    verified_overall.add(o.expected, o.verified)
    by_category[o.lab_case.category].add(o.expected, o.detected)
    verified_by_category[o.lab_case.category].add(o.expected, o.verified)
  end

  categories = by_category.keys.sort!.map do |name|
    t = by_category[name]
    v = verified_by_category[name]
    {
      category:  name,
      cases:     t.cases,
      expected:  t.expected,
      tp:        t.tp,
      fp:        t.fp,
      fn:        t.fn,
      tn:        t.tn,
      precision: t.precision,
      recall:    t.recall,
      f1:        t.f1,
      verified:  {tp: v.tp, fp: v.fp, recall: v.recall, precision: v.precision},
    }
  end

  # Every failure, with enough context to act on it without re-running.
  failures = outcomes.compact_map do |o|
    kind = if o.error
             "ERROR"
           elsif o.expected && !o.detected
             "FN"
           elsif !o.expected && o.detected
             "FP"
           end
    next unless kind
    lead = o.lead
    {
      kind:              kind,
      uid:               o.lab_case.uid,
      name:              o.lab_case.name,
      category:          o.lab_case.category,
      param:             o.lab_case.param,
      location:          o.lab_case.location,
      url:               o.lab_case.url,
      result_type:       lead.try(&.result_type) || "",
      detection_method:  lead.try(&.detection_method) || "",
      confidence:        lead.try(&.confidence) || "",
      payload:           lead.try(&.payload) || "",
      evidence:          lead.try(&.evidence) || "",
      findings:          o.findings.size,
      verified_findings: o.findings.count(&.verified?),
      seconds:           o.seconds.round(2),
      error:             o.error,
    }
  end.sort_by! { |f| {f[:kind], f[:category], f[:uid]} }

  seconds = outcomes.map(&.seconds)
  payload = {
    corpus: {
      lab_cases: lab_count,
      scanned:   outcomes.size,
      source:    "tests/functional/mock_cases",
    },
    total:      overall.to_json_object,
    verified:   verified_overall.to_json_object,
    categories: categories,
    timing:     {
      wall_clock_seconds: wall_clock.round(1),
      median_seconds:     median(seconds),
      slowest_seconds:    (seconds.max? || 0.0).round(2),
      concurrency:        CONCURRENCY,
    },
    # Cases whose only evidence is a static-analysis `[A]` finding. They can
    # never be `V` (no payload is ever sent), so they are a floor on the
    # `V`-only miss count rather than a detection gap — worth stating next to
    # the number so nobody reads it as one.
    ast_only: outcomes.count { |o| o.detected && o.findings.all?(&.ast?) && !o.findings.empty? },
    errors:   outcomes.count { |o| o.error },
    cases:    failures,
  }

  JSON.parse(Snapshot.stamp("effectiveness", Dalfox.version, payload).to_json)
end

# ---------------------------------------------------------------------------
# Reporting.
# ---------------------------------------------------------------------------

def pct(value : JSON::Any?) : String
  value.try(&.as_f?).try { |f| "#{f}%" } || "-"
end

def print_summary(data : JSON::Any)
  total = data["total"]
  ver = data["verified"]
  timing = data["timing"]?

  puts ""
  puts "==> detection (any finding)"
  puts "    precision #{pct(total["precision"]?)}  recall #{pct(total["recall"]?)}  F1 #{pct(total["f1"]?)}"
  puts "    TP #{total["tp"]}  FP #{total["fp"]}  FN #{total["fn"]}  TN #{total["tn"]}  (#{total["cases"]} cases, #{total["expected"]} labelled vulnerable)"
  puts "==> detection (V findings only)"
  puts "    precision #{pct(ver["precision"]?)}  recall #{pct(ver["recall"]?)}  F1 #{pct(ver["f1"]?)}"
  puts "    TP #{ver["tp"]}  FP #{ver["fp"]}  FN #{ver["fn"]}  TN #{ver["tn"]}"
  if ast_only = data["ast_only"]?
    puts "    (#{ast_only} of those V-misses are cases detected only by static [A] analysis, which never emits V)"
  end
  if timing
    puts "==> #{timing["wall_clock_seconds"]}s wall clock, #{timing["median_seconds"]}s median per case, #{timing["concurrency"]} workers"
  end

  puts ""
  puts "| Category | Cases | Vuln | TP | FP | FN | TN | Precision | Recall |"
  puts "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
  data["categories"].as_a.each do |c|
    puts "| #{c["category"]} | #{c["cases"]} | #{c["expected"]} | #{c["tp"]} | #{c["fp"]} | #{c["fn"]} | #{c["tn"]} | #{c["precision"]}% | #{c["recall"]}% |"
  end

  cases = data["cases"].as_a
  {"FP", "FN", "ERROR"}.each do |kind|
    listed = cases.select { |c| c["kind"].as_s == kind }
    next if listed.empty?
    puts ""
    puts "==> #{kind} (#{listed.size})"
    listed.first(15).each do |c|
      detail = kind == "FN" ? "no finding" : "#{c["result_type"].as_s.presence || "?"} #{c["payload"].as_s[0, 60]}"
      detail = c["error"].to_s if kind == "ERROR"
      puts "    #{c["uid"]} #{c["name"]} (#{c["param"]}/#{c["location"]}) — #{detail}"
    end
    puts "    … +#{listed.size - 15} more (see #{DATA_PATH})" if listed.size > 15
  end
end

# ---------------------------------------------------------------------------
# Gating.
# ---------------------------------------------------------------------------

def gate(data : JSON::Any) : Int32
  baseline = Snapshot.load(DATA_PATH)
  report = Report.new("effectiveness gate")

  # `Snapshot.load` reads the path this run is about to overwrite, so the
  # caller must load the baseline *before* writing — see main.
  unless baseline
    report.skip("baseline", "no committed snapshot at #{DATA_PATH}; recorded this run as the first one")
    return report.finish
  end

  deltas = Snapshot.compare(baseline, data, {
    "total.recall"       => {TOLERANCE, true},
    "total.precision"    => {TOLERANCE, true},
    "total.fp"           => {FP_TOLERANCE, false},
    "verified.recall"    => {TOLERANCE, true},
    "verified.precision" => {TOLERANCE, true},
  })

  deltas.each do |d|
    if d.regressed?
      report.fail(d.name, d.to_s.strip)
    else
      report.pass(d.name, d.to_s.strip)
    end
  end
  report.finish
end

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

if RENDER_ONLY
  snapshot = Snapshot.load(DATA_PATH)
  abort "no snapshot at #{DATA_PATH}; run a full measurement first" unless snapshot
  print_summary(snapshot)
  exit 0
end

abort "dalfox binary not found: #{Dalfox.bin}" unless Dalfox.available?

exit_code = 0
lab = Lab.start
begin
  body = HTTP::Client.get("#{lab.url}/map/json").body
  map = LabMap.from_json(body)
  cases = map.cases
  cases = cases.first(LIMIT.not_nil!) if LIMIT

  puts "==> scanning #{cases.size}/#{map.count} case(s) with #{CONCURRENCY} workers (#{Dalfox.bin} v#{Dalfox.version})"
  started = Sh.clock
  outcomes = Sh.parallel_map_progress(cases, CONCURRENCY, "scanned") { |c| measure(c) }
  wall_clock = (Sh.clock - started).total_seconds

  data = build_snapshot(outcomes, wall_clock, map.count)
  print_summary(data)
  # Gate before writing: the gate compares against the committed snapshot, and
  # `Snapshot.write` would replace it with this run's numbers first.
  exit_code = gate(data)
  Snapshot.write(DATA_PATH, data)
ensure
  # `exit` does not unwind, so the code is carried out of the block instead.
  lab.stop
end

exit exit_code
