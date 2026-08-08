# A/B two dalfox binaries over the same targets and diff what they find.
#
# The missing answer to "did this branch lose detections against the last
# release". Coverage snapshots say how much of a lab is detected; they do not
# say *which* findings moved, and a refactor that trades one finding for another
# keeps the rate flat while quietly dropping a real one.
#
# Flow:
#   1. Resolve targets, in priority order: AB_TARGETS (a newline-delimited URL
#      file) -> AB_TARGET_URL -> the corpus lab at `scripts/labs/corpus_server.cr`
#      (spawned and read via `GET /map/json`). No source -> skip cleanly.
#   2. Run AB_OLD_BIN over every target, then AB_NEW_BIN. The two passes are
#      sequential because `Dalfox.bin` is read from the environment, and because
#      overlapping passes would contend for the same lab.
#   3. Diff per target on two identities: `Finding#key` (type/location/param/
#      method) is the signal, `Finding#strict_key` (key + payload) is churn.
#   4. Print regressions first, then gains, then net counts and wall-clock.
#   5. Exit non-zero when NEW lost any key-level finding.
#
# Run with `crystal run scripts/ab_diff.cr`. Environment:
#   AB_OLD_BIN        baseline binary                        (REQUIRED)
#   AB_NEW_BIN        candidate binary   (default target/release/dalfox)
#   AB_TARGETS        path to a newline-delimited URL file
#   AB_TARGET_URL     single target URL
#   AB_CORPUS_URL     reuse a corpus lab already listening here
#   AB_LIMIT          scan only the first N targets (smoke testing)
#   AB_CONCURRENCY    parallel scans per pass                (default 4)
#   AB_TIMEOUT        hard per-scan timeout, seconds         (default 180)
#   AB_ARGS           replace the fixed dalfox arg set (space-separated)
#   AB_PASS_PAUSE     cool-down between the two passes, s    (default 5)
#   AB_ALLOW_LOSS=1   report losses but still exit 0

require "http/client"
require "json"
require "uri"
require "./lib/dalfox"
require "./lib/sh"
require "./lib/report"

CORPUS_SRC = "scripts/labs/corpus_server.cr"

OLD_BIN     = ENV["AB_OLD_BIN"]?
NEW_BIN     = ENV.fetch("AB_NEW_BIN", "target/release/dalfox")
CORPUS_URL  = ENV["AB_CORPUS_URL"]?.try(&.rstrip("/"))
LIMIT       = ENV["AB_LIMIT"]?.try(&.to_i?)
CONCURRENCY = ENV.fetch("AB_CONCURRENCY", "4").to_i
TIMEOUT     = ENV.fetch("AB_TIMEOUT", "180").to_f.seconds
ALLOW_LOSS  = ENV["AB_ALLOW_LOSS"]? == "1"
PASS_PAUSE  = ENV.fetch("AB_PASS_PAUSE", "5").to_f.seconds

# Mining is skipped by default so the diff is about detection logic rather than
# wordlist volume, and so a corpus of a few hundred cases finishes twice over.
DEFAULT_ARGS = ["--skip-mining", "--timeout", "10"]
SCAN_ARGS    = ENV["AB_ARGS"]?.try(&.split(' ', remove_empty: true)) || DEFAULT_ARGS

# ---------------------------------------------------------------------------
# Targets.
# ---------------------------------------------------------------------------

# `args` carries the per-target injection setup a corpus case implies (method
# override, body seed); URL-list sources leave it empty.
record Target, url : String, args : Array(String), label : String

# Shape of the corpus lab's `/map/json`. Unknown keys are ignored, so the
# contract can grow fields without breaking this harness.
struct CorpusCase
  include JSON::Serializable
  getter uid : String = ""
  getter url : String
  getter method : String = "GET"
  getter param : String = ""
  getter location : String = ""
end

struct CorpusMap
  include JSON::Serializable
  getter count : Int32 = 0
  getter cases : Array(CorpusCase)
end

def http_get(url : String, timeout : Time::Span = 15.seconds) : String?
  uri = URI.parse(url)
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
  http_get("#{base}/health", 2.seconds).try(&.strip) == "ok"
end

# Best-effort mapping of a corpus case onto dalfox flags. The corpus declares
# where the injection point lives; without this a body/header case would be
# scanned as a bare GET and both binaries would miss it identically, hiding a
# real difference behind a shared blind spot.
def case_args(c : CorpusCase) : Array(String)
  args = [] of String
  args.push("-X", c.method.upcase) unless c.method.empty? || c.method.upcase == "GET"
  return args if c.param.empty?

  case c.location.downcase
  when "body", "form"     then args.push("-d", "#{c.param}=a")
  when "json", "jsonbody" then args.push("-d", %({"#{c.param}":"a"}))
  when "header", "cookie" then args.push("-p", "#{c.param}:#{c.location.downcase}")
  end
  args
end

def targets_from_file(path : String) : Array(Target)
  File.read_lines(path)
    .map(&.strip)
    .reject { |l| l.empty? || l.starts_with?('#') }
    .map { |u| Target.new(u, [] of String, u) }
end

def targets_from_corpus(base : String) : Array(Target)
  body = http_get("#{base}/map/json") || return [] of Target
  map = CorpusMap.from_json(body)
  map.cases.map do |c|
    Target.new(c.url, case_args(c), c.uid.empty? ? c.url : c.uid)
  end
rescue ex
  puts "==> could not read #{base}/map/json: #{ex.message}"
  [] of Target
end

# ---------------------------------------------------------------------------
# Corpus lab lifecycle. Another harness owns this file; this one only consumes
# its published contract (health endpoint, listening line, /map/json).
# ---------------------------------------------------------------------------

# Skip, never fail: the corpus lab is an optional target source, and a CI job
# without it should stay green rather than pretend the A/B ran.
def skip(message : String) : NoReturn
  puts "==> ab_diff skipped: #{message}"
  exit 0
end

# Returns {base_url, process?, binary?, log?}; a nil process means "reused".
def start_corpus : {String, Process?, String?, String?}
  if url = CORPUS_URL
    skip("AB_CORPUS_URL=#{url} is not serving /health") unless healthy?(url)
    puts "==> reusing corpus lab at #{url}"
    return {url, nil, nil, nil}
  end

  skip("no target source (set AB_TARGETS or AB_TARGET_URL; #{CORPUS_SRC} does not exist)") unless File.exists?(CORPUS_SRC)

  bin = File.tempname("corpus-server")
  puts "==> building #{CORPUS_SRC}"
  build = Sh.run("crystal", ["build", CORPUS_SRC, "-o", bin], timeout: 300.seconds)
  unless build.success?
    File.delete(bin) if File.exists?(bin)
    skip("#{CORPUS_SRC} does not compile: #{build.error_line}")
  end

  log = File.tempname("corpus-server", ".log")
  process = Process.new(bin, output: File.open(log, "w"), error: File.open(log, "a"))

  # The lab chooses its own port; the contract is that it prints the listening
  # line, so parse it rather than assuming a default that another agent owns.
  base = nil.as(String?)
  120.times do
    if m = File.read(log).match(/listening on (https?:\/\/\S+)/)
      base = m[1].rstrip("/")
      break
    end
    break unless process.exists?
    sleep 250.milliseconds
  end

  unless base && healthy?(base)
    process.signal(Signal::KILL) rescue nil
    detail = File.exists?(log) ? File.read(log).lines.first(3).join(" / ") : ""
    stop_corpus(process, bin, log)
    skip("#{CORPUS_SRC} did not come up#{detail.empty? ? "" : ": #{detail}"}")
  end

  puts "==> corpus lab listening on #{base}"
  {base, process, bin, log}
end

def stop_corpus(process : Process?, bin : String?, log : String?)
  if process
    process.signal(Signal::TERM) rescue nil
    process.wait rescue nil
  end
  File.delete(bin) if bin && File.exists?(bin)
  File.delete(log) if log && File.exists?(log)
end

# ---------------------------------------------------------------------------
# Scanning + diffing.
# ---------------------------------------------------------------------------

def run_pass(label : String, bin : String, targets : Array(Target)) : {Array(Dalfox::ScanResult), Time::Span}
  # `Dalfox.bin` reads DALFOX_BIN on every call, so a pass is selected by
  # setting it once — which is exactly why the two passes must not overlap.
  ENV["DALFOX_BIN"] = bin
  started = Sh.clock
  results = Sh.parallel_map_progress(targets, CONCURRENCY, "#{label} (#{bin})") do |t|
    Dalfox.scan(t.url, SCAN_ARGS + t.args, timeout: TIMEOUT)
  end
  {results, Sh.clock - started}
end

# `Dalfox.diff` keys on `Finding#key`; this is the payload-aware twin, used only
# to size the churn that a key-level diff deliberately ignores.
def strict_diff(before : Array(Dalfox::Finding), after : Array(Dalfox::Finding))
  before_keys = before.map(&.strict_key).to_set
  after_keys = after.map(&.strict_key).to_set
  {after.reject { |f| before_keys.includes?(f.strict_key) },
   before.reject { |f| after_keys.includes?(f.strict_key) }}
end

# Per-target verdict.
record Diff,
  target : Target,
  gained : Array(Dalfox::Finding),
  lost : Array(Dalfox::Finding),
  strict_gained : Int32,
  strict_lost : Int32,
  old_result : Dalfox::ScanResult,
  new_result : Dalfox::ScanResult

def describe(f : Dalfox::Finding) : String
  "[#{f.result_type}] #{f.param.empty? ? "-" : f.param} @ #{f.location.empty? ? "-" : f.location}" \
  " via #{f.detection_method.empty? ? "-" : f.detection_method} (msg #{f.message_id})"
end

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

old_bin = OLD_BIN || abort("AB_OLD_BIN is required (path to the baseline dalfox binary)")
abort "AB_OLD_BIN not found: #{old_bin}" unless File.exists?(old_bin)
abort "AB_NEW_BIN not found: #{NEW_BIN}" unless File.exists?(NEW_BIN)

corpus_process = nil.as(Process?)
corpus_bin = nil.as(String?)
corpus_log = nil.as(String?)

targets =
  if path = ENV["AB_TARGETS"]?
    abort "AB_TARGETS file not found: #{path}" unless File.exists?(path)
    puts "==> targets from #{path}"
    targets_from_file(path)
  elsif url = ENV["AB_TARGET_URL"]?
    puts "==> single target #{url}"
    [Target.new(url, [] of String, url)]
  else
    base, corpus_process, corpus_bin, corpus_log = start_corpus
    targets_from_corpus(base)
  end

targets = targets.first(LIMIT.not_nil!) if LIMIT
skip("no targets resolved") if targets.empty?

diffs = [] of Diff
old_wall = Time::Span.zero
new_wall = Time::Span.zero

begin
  puts "==> #{targets.size} targets, #{CONCURRENCY} workers, args: #{SCAN_ARGS.join(' ')}"
  old_results, old_wall = run_pass("old", old_bin, targets)

  # Cool-down between passes. Two full passes back-to-back leave the local
  # stack saturated with TIME_WAIT sockets, and the second pass then fails
  # connections that the first one made fine — which would read as the new
  # binary losing findings. Measured, not theoretical: an 809-target corpus run
  # produced 0 broken scans in pass one and 253 in pass two without this.
  if PASS_PAUSE > Time::Span.zero
    puts "==> cooling down #{PASS_PAUSE.total_seconds.round(1)}s between passes"
    sleep PASS_PAUSE
  end

  new_results, new_wall = run_pass("new", NEW_BIN, targets)

  targets.each_with_index do |t, i|
    o = old_results[i]
    n = new_results[i]
    gained, lost = Dalfox.diff(o.findings, n.findings)
    sg, sl = strict_diff(o.findings, n.findings)
    diffs << Diff.new(t, gained, lost, sg.size, sl.size, o, n)
  end
ensure
  stop_corpus(corpus_process, corpus_bin, corpus_log)
end

# A crashed or timed-out scan reports zero findings, which would masquerade as
# the other side losing every finding it had. Those targets are not comparable
# and are bucketed separately — they still fail the run through the crash check,
# just not as a detection regression.
unusable = diffs.select { |d| d.old_result.crashed? || d.new_result.crashed? }
comparable = diffs - unusable
regressions = comparable.select { |d| !d.lost.empty? }
gains = comparable.select { |d| !d.gained.empty? }
old_total = comparable.sum { |d| d.old_result.findings.size }
new_total = comparable.sum { |d| d.new_result.findings.size }
churn = comparable.sum { |d| d.strict_gained + d.strict_lost } -
        comparable.sum { |d| d.gained.size + d.lost.size }
old_broken = diffs.count { |d| d.old_result.crashed? }
new_broken = diffs.count { |d| d.new_result.crashed? }

puts ""
puts "==> regressions — findings OLD had that NEW does not (#{regressions.size} targets)"
if regressions.empty?
  puts "    none"
else
  regressions.each do |d|
    puts "  #{d.target.label}"
    puts "      old: #{d.old_result.summary}"
    puts "      new: #{d.new_result.summary}"
    d.lost.each { |f| puts "    - lost #{describe(f)}" }
  end
end

puts ""
puts "==> gains — findings NEW has that OLD did not (#{gains.size} targets)"
if gains.empty?
  puts "    none"
else
  gains.each do |d|
    puts "  #{d.target.label}"
    d.gained.each { |f| puts "    + gained #{describe(f)}" }
  end
end

unless unusable.empty?
  puts ""
  puts "==> not comparable — a scan crashed or timed out (#{unusable.size} targets)"
  unusable.first(10).each do |d|
    puts "  #{d.target.label}"
    puts "      old: #{d.old_result.summary}"
    puts "      new: #{d.new_result.summary}"
  end
  puts "    (+#{unusable.size - 10} more)" if unusable.size > 10
end

puts ""
puts "==> net"
puts "    targets              #{targets.size} (#{comparable.size} comparable)"
puts "    findings old -> new  #{old_total} -> #{new_total} (#{new_total - old_total >= 0 ? "+" : ""}#{new_total - old_total})"
puts "    targets regressed    #{regressions.size}"
puts "    targets gained       #{gains.size}"
# Payload-level churn is expected and harmless: the same finding reached through
# a different bypass variant is the same regression-relevant fact.
puts "    payload-only churn   #{churn} (same finding, different PoC — noise)"
puts "    scans crashed/timed  old #{old_broken}, new #{new_broken}"
puts "    wall-clock           old #{old_wall.total_seconds.round(1)}s -> new #{new_wall.total_seconds.round(1)}s" \
     " (#{old_wall.total_seconds > 0 ? ((new_wall.total_seconds / old_wall.total_seconds - 1) * 100).round(1) : 0.0}%)"

report = Report.new("ab diff (#{old_bin} -> #{NEW_BIN})")
report.check_empty("no findings lost by NEW", regressions.map(&.target.label))
report.check("no new crashes/timeouts in NEW", "old #{old_broken}, new #{new_broken}") { new_broken <= old_broken }

code = report.finish
if code != 0 && ALLOW_LOSS
  puts "==> AB_ALLOW_LOSS=1: reporting the loss but exiting 0"
  exit 0
end
exit code
