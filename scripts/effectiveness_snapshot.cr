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
#      !expected && detected = FP, !expected && !detected = TN. Tallied for
#      any finding, V-only, high-confidence, and each (method, confidence) bucket.
#      Each bucket counts a case once, regardless of duplicate findings.
#   5. Write `docs/data/effectiveness.json`, including every FP and FN with the
#      payload and evidence so the failures are actionable, and a `verdicts`
#      map with one grade per case (`V/high`, `R/low`, `-`, …).
#   6. Compare against the committed snapshot, case by case, and exit non-zero
#      when any case got worse: an expected case lost its finding, its `V`, or
#      its high-confidence grade; a safe case gained a finding; a scan errored;
#      a case vanished from the corpus. The aggregate rates are compared too,
#      but with their tolerance three lost cases out of 730 would pass, which
#      is why they are not the gate on their own. No committed snapshot yet =
#      "no baseline", exit 0.
#
# The snapshot on disk is the baseline (in CI: the committed one). A run that
# passes rewrites it, so gained detections and new cases get recorded. A run
# that fails leaves it alone — otherwise running twice would accept the
# regression — and so does a filtered run, whose numbers describe a subset.
# To accept an intended change that the gate rejects (a relabelled case, a
# detection knowingly traded away), re-run with EFFECTIVENESS_ACCEPT=1 and
# commit the file; its diff is the reviewable record of which cases moved.
#
# Environment:
#   EFFECTIVENESS_URL          scan an already-running lab instead of starting one
#   EFFECTIVENESS_PORT         port for the lab this script starts   (default 4801)
#   EFFECTIVENESS_CATEGORIES   comma-separated category filter passed to the lab
#   EFFECTIVENESS_LIMIT        scan only the first N cases (smoke runs)
#   EFFECTIVENESS_CONCURRENCY  parallel scans                        (default 8)
#   EFFECTIVENESS_RETRIES      retries for a scan that errored out   (default 2)
#   EFFECTIVENESS_TIMEOUT      per-scan wall-clock budget, seconds   (default 120)
#   EFFECTIVENESS_TOLERANCE    recall/precision regression slack, pp (default 0.5)
#   EFFECTIVENESS_FP_TOLERANCE extra false positives tolerated       (default 0)
#   EFFECTIVENESS_ACCEPT       1 = record this run as the baseline even if the gate fails
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
RETRIES        = ENV.fetch("EFFECTIVENESS_RETRIES", "2").to_i
SCAN_TIMEOUT   = ENV.fetch("EFFECTIVENESS_TIMEOUT", "120").to_i
TOLERANCE      = ENV.fetch("EFFECTIVENESS_TOLERANCE", "0.5").to_f
FP_TOLERANCE   = ENV.fetch("EFFECTIVENESS_FP_TOLERANCE", "0").to_f
ACCEPT         = ENV["EFFECTIVENESS_ACCEPT"]? == "1"
RENDER_ONLY    = ENV["EFFECTIVENESS_RENDER_ONLY"]? == "1"
# A run over part of the corpus (or over a lab somebody else started, whose
# contents this script cannot vouch for). Its totals and verdicts are not
# comparable with the snapshot's, and it must not replace it.
FILTERED = !(LIMIT.nil? && CATEGORIES.nil? && LAB_URL.nil?)
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
  # None of these is a verdict about the case. A scan that lost requests can
  # report a weaker tier than it would have (the verification request is the
  # one that went missing), and exit 1 with nothing parseable in the report
  # says "found something" without saying what. Both are retried like a crash
  # and fail the gate if they persist.
  incomplete = result.meta.try(&.["incomplete"]?).try(&.as_bool?) == true
  error = if result.timed_out?
            "timeout after #{result.elapsed.total_seconds.round(1)}s"
          elsif result.crashed?
            "exit #{result.output.status}: #{result.output.error_line}"
          elsif result.findings.empty? && result.output.status == 1
            "exit 1 but the report has no parseable findings"
          elsif incomplete
            "the scan reported itself incomplete (requests were lost)"
          end
  Outcome.new(lab_case, !xss.empty?, xss.any?(&.verified?), xss,
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
    # An errored case fails the per-case gate, so give a refused connection
    # room to clear: 0.5 s, then 2 s.
    sleep (attempt == 1 ? 500 : 2000).milliseconds
  end
end

# ---------------------------------------------------------------------------
# Per-case verdicts.
# ---------------------------------------------------------------------------

# One case's result reduced to what the gate compares: the strongest tier
# dalfox reported for it (`V` > `A` > `R`) and whether any finding is graded
# high confidence. `-` is "no finding", `error` a scan that produced no
# measurement.
def grade(o : Outcome) : String
  return "error" if o.error
  return "-" unless o.detected
  tier = if o.findings.any?(&.verified?)
           "V"
         elsif o.findings.any?(&.ast?)
           "A"
         else
           "R"
         end
  confidence = o.findings.any? { |f| f.confidence == "high" } ? "high" : "low"
  "#{tier}/#{confidence}"
end

def grade_detected?(grade : String) : Bool
  grade != "-" && grade != "error"
end

def grade_verified?(grade : String) : Bool
  grade.starts_with?("V/")
end

def grade_high?(grade : String) : Bool
  grade.ends_with?("/high")
end

# Places where the committed snapshot disagrees with itself: a case listed as
# a miss whose verdict is a detection, a listed false positive whose verdict is
# "no finding", or a listed mismatch with no verdict at all. `case_transitions`
# trusts both, so a hand-edited or half-merged snapshot has to be rejected
# before it is used.
def baseline_contradictions(before : Hash(String, String), known : Hash(String, String)) : Array(String)
  known.compact_map do |uid, kind|
    verdict = before[uid]?
    if verdict.nil?
      "#{uid}: listed as #{kind} but has no verdict"
    elsif (kind == "FN") == grade_detected?(verdict)
      "#{uid}: listed as #{kind} but its verdict is #{verdict}"
    end
  end
end

# Compare this run with the committed snapshot, case by case.
#
# `before` is the committed `verdicts` map; `known` maps the uid of every
# mismatch the committed snapshot already lists to its kind (`FN` / `FP`).
#
# Returns `{regressions, notes}`. A regression fails the gate; a note is a
# change that is not worse (a gained detection, a new case that behaves as
# labelled) but means the committed snapshot no longer describes the corpus
# and should be re-recorded.
#
# The rule for a miss or a false positive is "it must already be a recorded
# one", not "the verdict must not have changed": that also catches a case
# relabelled without re-recording, where the verdict is the same and only its
# meaning moved.
#
# `full_corpus` is false for a filtered run (`EFFECTIVENESS_LIMIT`,
# `EFFECTIVENESS_CATEGORIES`): a case that was simply not scanned must not be
# reported as removed.
def case_transitions(before : Hash(String, String), known : Hash(String, String),
                     outcomes : Array(Outcome), full_corpus : Bool) : {Array(String), Array(String)}
  regressions = [] of String
  notes = [] of String
  seen = Set(String).new

  outcomes.each do |o|
    uid = o.lab_case.uid
    seen << uid
    now = grade(o)
    was = before[uid]?
    label = "#{uid} #{o.lab_case.name}"

    if err = o.error
      regressions << "#{label}: scan error (#{err}), no measurement"
      next
    end

    mismatch = if o.expected && !o.detected
                 "FN"
               elsif !o.expected && o.detected
                 "FP"
               end

    if mismatch && known[uid]? != mismatch
      regressions << "#{label}: " + if was.nil?
        "new case does not match its label (#{o.expected ? "labelled vulnerable, no finding" : "labelled safe, got #{now}"})"
      elsif mismatch == "FN" && grade_detected?(was)
        "lost detection (#{was} -> #{now})"
      elsif mismatch == "FP" && !grade_detected?(was)
        "new false positive (#{now})"
      elsif mismatch == "FN"
        "labelled vulnerable with no finding, and not a recorded miss"
      else
        "labelled safe but reported (#{now}), and not a recorded false positive"
      end
      next
    end

    if was.nil?
      notes << "#{label}: new case (#{now})"
    elsif was != now
      if o.expected && grade_verified?(was) && !grade_verified?(now)
        regressions << "#{label}: lost verification (#{was} -> #{now})"
      elsif o.expected && grade_high?(was) && !grade_high?(now)
        regressions << "#{label}: lost high confidence (#{was} -> #{now})"
      else
        notes << "#{label}: #{was} -> #{now}"
      end
    end
  end

  if full_corpus
    (before.keys - seen.to_a).each do |uid|
      regressions << "#{uid}: in the committed snapshot but no longer served by the corpus"
    end
  end

  {regressions, notes}
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
  high_overall = Tally.new
  high_by_category = Hash(String, Tally).new { |h, k| h[k] = Tally.new }
  by_method_confidence = Hash({String, String}, Tally).new { |h, k| h[k] = Tally.new }
  buckets = outcomes.flat_map(&.findings).map { |f| {f.detection_method, f.confidence || "ungraded"} }.uniq.sort
  by_category = Hash(String, Tally).new { |h, k| h[k] = Tally.new }
  verified_by_category = Hash(String, Tally).new { |h, k| h[k] = Tally.new }

  outcomes.each do |o|
    overall.add(o.expected, o.detected)
    verified_overall.add(o.expected, o.verified)
    high = o.findings.any? { |f| f.confidence == "high" }
    high_overall.add(o.expected, high)
    high_by_category[o.lab_case.category].add(o.expected, high)
    found_buckets = o.findings.map { |f| {f.detection_method, f.confidence || "ungraded"} }.to_set
    buckets.each { |bucket| by_method_confidence[bucket].add(o.expected, found_buckets.includes?(bucket)) }
    by_category[o.lab_case.category].add(o.expected, o.detected)
    verified_by_category[o.lab_case.category].add(o.expected, o.verified)
  end

  categories = by_category.keys.sort!.map do |name|
    t = by_category[name]
    v = verified_by_category[name]
    h = high_by_category[name]
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
      high_confidence: {tp: h.tp, fp: h.fp, recall: h.recall, precision: h.precision},
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
    high_confidence: high_overall.to_json_object,
    by_method_confidence: buckets.map do |method, confidence|
      {detection_method: method, confidence: confidence, metrics: by_method_confidence[{method, confidence}].to_json_object}
    end,
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
    # One grade per case, in corpus order. This is what the gate compares, and
    # what makes a snapshot diff show exactly which cases a change moved.
    verdicts: outcomes.sort_by { |o| {o.lab_case.category, o.lab_case.id} }
      .map { |o| {o.lab_case.uid, grade(o)} }.to_h,
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
  if high = data["high_confidence"]?
    puts "==> detection (high confidence only)"
    puts "    precision #{pct(high["precision"]?)}  recall #{pct(high["recall"]?)}  FP #{high["fp"]}"
  end
  if buckets = data["by_method_confidence"]?
    puts "==> precision by detection method / confidence"
    buckets.as_a.each do |bucket|
      m = bucket["metrics"]
      puts "    #{bucket["detection_method"]}/#{bucket["confidence"]}: #{pct(m["precision"]?)} (TP #{m["tp"]}, FP #{m["fp"]})"
    end
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

def gate(data : JSON::Any, outcomes : Array(Outcome)) : Int32
  baseline = Snapshot.load(DATA_PATH)
  report = Report.new("effectiveness gate")

  high = data["high_confidence"]
  verified = data["verified"]
  report.check("high-confidence precision >= V-only precision",
    "high #{high["precision"]}% vs V #{verified["precision"]}%") do
    high["precision"].as_f >= verified["precision"].as_f
  end

  # `Snapshot.load` reads the path this run is about to overwrite, so the
  # caller must load the baseline *before* writing — see main.
  unless baseline
    report.skip("baseline", "no committed snapshot at #{DATA_PATH}; recorded this run as the first one")
    return report.finish
  end

  if FILTERED
    report.skip("aggregate rates and per-case verdicts",
      "filtered run: its population is not the snapshot's, so nothing is compared")
    return report.finish
  end

  deltas = Snapshot.compare(baseline, data, {
    "total.recall"       => {TOLERANCE, true},
    "total.precision"    => {TOLERANCE, true},
    "total.fp"           => {FP_TOLERANCE, false},
    "verified.recall"    => {TOLERANCE, true},
    "verified.precision" => {TOLERANCE, true},
    "high_confidence.recall" => {TOLERANCE, true},
    "high_confidence.precision" => {TOLERANCE, true},
    "high_confidence.fp" => {FP_TOLERANCE, false},
  })

  deltas.each do |d|
    if d.regressed?
      report.fail(d.name, d.to_s.strip)
    else
      report.pass(d.name, d.to_s.strip)
    end
  end

  if before = baseline["verdicts"]?.try(&.as_h?)
    committed = before.transform_values(&.to_s)
    known = {} of String => String
    baseline["cases"]?.try(&.as_a?).try &.each do |c|
      kind = c["kind"]?.try(&.as_s?)
      uid = c["uid"]?.try(&.as_s?)
      known[uid] = kind if uid && kind && kind.in?("FN", "FP")
    end
    contradictions = baseline_contradictions(committed, known)
    contradictions.each { |c| report.fail("snapshot consistency", c) }
    regressions, notes = case_transitions(committed, known, outcomes, true)
    if regressions.empty?
      report.pass("per-case verdicts", "no case got worse (#{committed.size} in the committed snapshot)")
    else
      regressions.each { |r| report.fail("per-case verdicts", r) }
    end
    unless notes.empty?
      puts ""
      puts "==> #{notes.size} case(s) changed without getting worse. A passing run records them in"
      puts "    #{DATA_PATH}; commit it so the baseline keeps up:"
      notes.first(20).each { |n| puts "    #{n}" }
      puts "    … +#{notes.size - 20} more" if notes.size > 20
    end
  else
    report.skip("per-case verdicts", "the committed snapshot has no `verdicts` map yet; this run records one")
  end
  report.finish
end

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

if ENV["EFFECTIVENESS_SELF_TEST"]? == "1"
  make_case = ->(id : Int32, expected : Bool) {
    LabCase.from_json({uid: id.to_s, id: id, name: "test", category: "test", handler_type: "test", expected_detection: expected, method: "GET", url: "http://localhost/", param: "q", location: "Query"}.to_json)
  }
  finding = ->(tier : String, method : String, confidence : String) {
    Dalfox::Finding.from_json({type: tier, detection_method: method, confidence: confidence}.to_json)
  }
  high = finding.call("A", "ast", "high")
  low = finding.call("V", "reflection", "low")
  outcomes = [
    Outcome.new(make_case.call(1, true), true, false, [high, high], 0.0, nil),
    Outcome.new(make_case.call(2, false), true, true, [low], 0.0, nil),
    Outcome.new(make_case.call(3, true), false, false, [] of Dalfox::Finding, 0.0, nil),
  ]
  data = build_snapshot(outcomes, 0.0, 3)
  h = data["high_confidence"]
  raise "high bucket must count cases once" unless h["tp"].as_i == 1 && h["fp"].as_i == 0 && h["fn"].as_i == 1 && h["tn"].as_i == 1
  buckets = data["by_method_confidence"].as_a
  raise "method buckets missing" unless buckets.size == 2
  ast = buckets.find { |b| b["detection_method"].as_s == "ast" }.not_nil!["metrics"]
  raise "AST copies inflated precision" unless ast["tp"].as_i == 1 && ast["fp"].as_i == 0

  # Per-case gate. `outcomes` grades as 1 => A/high, 2 => V/low (a false
  # positive), 3 => "-" (a miss).
  verdicts = data["verdicts"].as_h.transform_values(&.to_s)
  raise "verdicts not recorded per case: #{verdicts}" unless verdicts == {"1" => "A/high", "2" => "V/low", "3" => "-"}
  recorded = {"2" => "FP", "3" => "FN"}
  same, same_notes = case_transitions(verdicts, recorded, outcomes, true)
  raise "an unchanged run must not regress: #{same}" unless same.empty? && same_notes.empty?

  none = {} of String => String
  verified = finding.call("V", "reflection", "high")
  reflected = finding.call("R", "reflection", "low")
  no_findings = [] of Dalfox::Finding
  expect_regression = ->(name : String, before : Hash(String, String), known : Hash(String, String), now : Array(Outcome), needle : String) {
    found, _ = case_transitions(before, known, now, true)
    raise "#{name}: expected one regression mentioning #{needle.inspect}, got #{found}" unless found.size == 1 && found[0].includes?(needle)
  }
  expect_regression.call("lost detection", {"1" => "R/low"}, none,
    [Outcome.new(make_case.call(1, true), false, false, no_findings, 0.0, nil)], "lost detection")
  expect_regression.call("lost verification", {"1" => "V/high"}, none,
    [Outcome.new(make_case.call(1, true), true, false, [reflected], 0.0, nil)], "lost verification")
  expect_regression.call("lost high confidence", {"1" => "A/high"}, none,
    [Outcome.new(make_case.call(1, true), true, false, [finding.call("A", "ast", "low")], 0.0, nil)], "lost high confidence")
  expect_regression.call("new false positive", {"1" => "-"}, none,
    [Outcome.new(make_case.call(1, false), true, false, [reflected], 0.0, nil)], "new false positive")
  expect_regression.call("scan error", {"1" => "V/high"}, none,
    [Outcome.new(make_case.call(1, true), false, false, no_findings, 0.0, "timeout")], "scan error")
  expect_regression.call("removed case", {"1" => "V/high", "9" => "V/high"}, none,
    [Outcome.new(make_case.call(1, true), true, true, [verified], 0.0, nil)], "no longer served")
  expect_regression.call("mislabelled new case", none, none,
    [Outcome.new(make_case.call(1, true), false, false, no_findings, 0.0, nil)], "does not match its label")
  # Same verdict as before, but the case was relabelled without re-recording.
  expect_regression.call("relabelled to safe", {"1" => "V/high"}, none,
    [Outcome.new(make_case.call(1, false), true, true, [verified], 0.0, nil)], "not a recorded false positive")
  expect_regression.call("relabelled to vulnerable", {"1" => "-"}, none,
    [Outcome.new(make_case.call(1, true), false, false, no_findings, 0.0, nil)], "not a recorded miss")
  # A recorded false positive does not excuse a different kind of mismatch.
  expect_regression.call("recorded as the other kind", {"1" => "-"}, {"1" => "FP"},
    [Outcome.new(make_case.call(1, true), false, false, no_findings, 0.0, nil)], "not a recorded miss")

  # Not regressions: a recorded miss that is still a miss, a gained detection,
  # a new case that behaves as labelled, and a case a filtered run skipped.
  still, still_notes = case_transitions({"1" => "-"}, {"1" => "FN"},
    [Outcome.new(make_case.call(1, true), false, false, no_findings, 0.0, nil)], true)
  raise "a recorded miss must stay accepted: #{still}" unless still.empty? && still_notes.empty?
  gained, gained_notes = case_transitions({"1" => "-"}, {"1" => "FN"},
    [Outcome.new(make_case.call(1, true), true, true, [verified], 0.0, nil)], true)
  raise "a gained detection must be a note, not a regression: #{gained}" unless gained.empty? && gained_notes.size == 1
  fresh, fresh_notes = case_transitions(none, none,
    [Outcome.new(make_case.call(1, true), true, true, [verified], 0.0, nil)], true)
  raise "a well-behaved new case must be a note: #{fresh}" unless fresh.empty? && fresh_notes.size == 1
  bad = baseline_contradictions({"1" => "V/high", "2" => "-", "3" => "-"}, {"1" => "FN", "2" => "FP", "3" => "FN", "4" => "FP"})
  raise "contradictory snapshot records must be reported: #{bad}" unless bad.size == 3 && bad.none?(&.starts_with?("3:"))
  partial, _ = case_transitions({"1" => "V/high", "9" => "V/high"}, none,
    [Outcome.new(make_case.call(1, true), true, true, [verified], 0.0, nil)], false)
  raise "a filtered run must not report unscanned cases as removed: #{partial}" unless partial.empty?

  puts "effectiveness accounting self-test passed"
  exit 0
end

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
  duplicates = cases.map(&.uid).tally.select { |_, n| n > 1 }.keys
  abort "the lab lists these case uids more than once: #{duplicates.join(", ")}" unless duplicates.empty?
  cases = cases.first(LIMIT.not_nil!) if LIMIT

  puts "==> scanning #{cases.size}/#{map.count} case(s) with #{CONCURRENCY} workers (#{Dalfox.bin} v#{Dalfox.version})"
  started = Sh.clock
  outcomes = Sh.parallel_map_progress(cases, CONCURRENCY, "scanned") { |c| measure(c) }
  wall_clock = (Sh.clock - started).total_seconds

  data = build_snapshot(outcomes, wall_clock, map.count)
  print_summary(data)
  # Gate before writing: the gate compares against the snapshot on disk, and
  # `Snapshot.write` would replace it with this run's numbers first.
  exit_code = gate(data, outcomes)
  if FILTERED
    puts "==> filtered run: #{DATA_PATH} left as it was"
  elsif exit_code == 0
    Snapshot.write(DATA_PATH, data)
  elsif ACCEPT
    puts "==> EFFECTIVENESS_ACCEPT=1: recording this run as the baseline despite the failures above"
    Snapshot.write(DATA_PATH, data)
    exit_code = 0
  else
    puts "==> gate failed: #{DATA_PATH} left as it was. If the change is intended, re-run with"
    puts "    EFFECTIVENESS_ACCEPT=1 to record it, then commit the file."
  end
ensure
  # `exit` does not unwind, so the code is carried out of the block instead.
  lab.stop
end

exit exit_code
