# Replays the benign false-positive corpus (`scripts/fixtures/replay/`) against
# the release binary and fails when dalfox reports anything at all.
#
# Every fixture is a page that really does echo its input and is nonetheless not
# exploitable — the reasoning is written into each fixture's leading comment, so
# a finding here is a false positive by construction, not by opinion. The known
# FP classes dalfox has already shipped fixes for (javascript:-scheme self-link,
# server-escaped quote/scheme echoes, HTML-marker verdicts on JSON/JSONP bodies,
# entity-escaped echoes inside <script>, reflections in inert content types) all
# have a fixture here so they cannot come back unnoticed.
#
# Flow:
#   1. Reuse the replay server at REPLAY_URL, or build + boot
#      `scripts/labs/replay_server.cr` on REPLAY_PORT and tear it down after.
#   2. Read the fixture catalog from `/map/json`.
#   3. Scan every fixture URL with the release binary, in parallel.
#   4. Grade each fixture: V/A findings fail, R/I findings warn. `REPLAY_STRICT`
#      moves the line. A crashed or timed-out scan is its own failure.
#   5. Print a per-fixture table, write the JSON snapshot, `exit report.finish`.
#
# Invoked by `just replay-corpus`. Tunable via environment variables:
#   REPLAY_URL          scan an already-running server instead of booting one
#   REPLAY_PORT         port for the server this script boots  (default 4804)
#   REPLAY_STRICT       `va` = fail on V/A, warn on R/I (default)
#                       `all` = every finding fails
#   REPLAY_CONCURRENCY  parallel fixture scans                 (default 4)
#   REPLAY_LIMIT        scan only the first N fixtures (smoke testing)
#   REPLAY_MINING       1 = leave parameter mining on (default: --skip-mining;
#                       no fixture echoes a dictionary parameter, so mining is
#                       pure request noise here)
#   REPLAY_TIMEOUT      per-fixture scan budget in seconds     (default 180)
#   REPLAY_DATA_PATH    snapshot path (empty string = do not write)
#   DALFOX_BIN          dalfox binary          (default target/release/dalfox)

require "json"
require "http/client"
require "./lib/dalfox"
require "./lib/report"
require "./lib/sh"
require "./lib/snapshot"

SERVER_SRC  = "scripts/labs/replay_server.cr"
PORT        = ENV.fetch("REPLAY_PORT", "4804")
BASE_URL    = ENV.fetch("REPLAY_URL", "http://127.0.0.1:#{PORT}").rstrip("/")
STRICT      = ENV.fetch("REPLAY_STRICT", "va").downcase
CONCURRENCY = ENV.fetch("REPLAY_CONCURRENCY", "4").to_i
LIMIT       = ENV["REPLAY_LIMIT"]?.try(&.to_i?)
MINING      = ENV["REPLAY_MINING"]? == "1"
BUDGET      = ENV.fetch("REPLAY_TIMEOUT", "180").to_i.seconds
DATA_PATH   = ENV.fetch("REPLAY_DATA_PATH", "docs/data/replay-corpus.json")

# ---------------------------------------------------------------------------
# Catalog model — the shape of /map/json (see labs/replay_server.cr#catalog_json).
# ---------------------------------------------------------------------------

struct FixtureInfo
  include JSON::Serializable
  getter name : String
  getter url : String
  getter file : String = ""
  getter content_type : String = ""
  getter status : Int32 = 200
  getter escape : String = ""
  getter url_decode : Bool = false
  getter why : String = ""
end

struct Catalog
  include JSON::Serializable
  getter count : Int32
  getter seed : String = ""
  getter fixtures : Array(FixtureInfo)
end

# ---------------------------------------------------------------------------
# Server lifecycle.
# ---------------------------------------------------------------------------

def health? : Bool
  HTTP::Client.get("#{BASE_URL}/health").success?
rescue
  false
end

# Compiles the server to a tempfile and runs *that* rather than shelling out to
# `crystal run`: killing `crystal run` leaves the compiled child orphaned on the
# port, which would poison the next run.
record BootedServer, process : Process, binary : String

def boot_server : BootedServer?
  return nil if health? # someone already owns the port; scan it as-is

  abort "missing #{SERVER_SRC} (run from the repo root)" unless File.exists?(SERVER_SRC)
  binary = File.tempname("replay-server")
  puts "==> building #{SERVER_SRC}"
  build = Sh.run("crystal", ["build", SERVER_SRC, "-o", binary], timeout: 300.seconds)
  unless build.success?
    abort "crystal build failed:\n#{build.stderr}"
  end

  puts "==> starting replay server on port #{PORT}"
  process = Process.new(binary, [] of String,
    env: {"REPLAY_PORT" => PORT},
    output: Process::Redirect::Close,
    error: Process::Redirect::Inherit)

  60.times do
    return BootedServer.new(process, binary) if health?
    abort "replay server exited before becoming healthy" if process.terminated?
    sleep 0.25.seconds
  end
  process.signal(Signal::KILL) rescue nil
  abort "replay server did not become healthy on port #{PORT}"
end

def stop_server(booted : BootedServer?)
  return unless booted
  puts "==> stopping replay server"
  booted.process.signal(Signal::TERM) rescue nil
  booted.process.wait rescue nil
  File.delete(booted.binary) if File.exists?(booted.binary)
end

# ---------------------------------------------------------------------------
# Scanning + grading.
# ---------------------------------------------------------------------------

# Fixtures are benign, so mining only adds requests for parameters no fixture
# reflects. Everything else stays at dalfox's defaults on purpose: the corpus is
# a regression test for the shipping configuration, not for a tuned one.
def scan_args : Array(String)
  args = ["--timeout", "10", "--scan-timeout", "120"]
  args << "--skip-mining" unless MINING
  args
end

# Under the default gate a `V`/`A` is a hard failure (dalfox asserted a
# vulnerability) while an `R` is a weaker signal: the payload was reflected,
# which on an escaped echo is true but not an exploitability claim. `all`
# promotes everything, including informational findings.
def blocking?(finding : Dalfox::Finding) : Bool
  return true if STRICT == "all"
  finding.verified? || finding.ast?
end

def clip(value : String, limit : Int32 = 90) : String
  flat = value.gsub(/\s+/, " ").strip
  flat.size > limit ? "#{flat[0, limit]}…" : flat
end

def describe(finding : Dalfox::Finding) : String
  parts = ["[#{finding.result_type}]"]
  parts << "param=#{finding.param}" unless finding.param.empty?
  parts << "method=#{finding.detection_method}" unless finding.detection_method.empty?
  parts << "payload=#{clip(finding.payload, 70).inspect}" unless finding.payload.empty?
  parts << "evidence=#{clip(finding.evidence, 70).inspect}" unless finding.evidence.empty?
  parts.join(" ")
end

record Outcome,
  info : FixtureInfo,
  target : String,
  result : Dalfox::ScanResult do
  def counts : Hash(String, Int32)
    tally = {"V" => 0, "A" => 0, "R" => 0, "I" => 0}
    result.findings.each do |f|
      key = f.result_type
      tally[key] = (tally[key]? || 0) + 1
    end
    tally
  end

  def blocking : Array(Dalfox::Finding)
    result.findings.select { |f| blocking?(f) }
  end

  def warning : Array(Dalfox::Finding)
    result.findings.reject { |f| blocking?(f) }
  end

  # dalfox exits 1 exactly when it reported at least one finding. Parsing zero
  # out of that report means the harness lost them, not that the page is clean.
  # That is not hypothetical: `Dalfox.parse_report` used to assume a bare JSON
  # array while dalfox 3.2.0 writes a `{"meta": …, "findings": […]}` envelope,
  # and the mismatch was rescued to an empty array — every fixture looked clean
  # and this gate was a rubber stamp. The library is fixed; this check is what
  # makes the next such regression loud instead of silent.
  def report_lost? : Bool
    result.output.status == 1 && result.findings.empty?
  end

  def verdict : String
    return "error" if result.crashed? || report_lost?
    return "FAIL" unless blocking.empty?
    warning.empty? ? "clean" : "warn"
  end
end

# ---------------------------------------------------------------------------
# The run itself. Kept in a method returning the exit code because `exit` does
# not unwind the stack in Crystal: exiting from inside the begin/ensure below
# would skip the teardown and leave the server holding the port.
# ---------------------------------------------------------------------------

def run : Int32
  body = begin
    HTTP::Client.get("#{BASE_URL}/map/json").body
  rescue ex
    STDERR.puts "could not read #{BASE_URL}/map/json: #{ex.message}"
    return 1
  end
  catalog = Catalog.from_json(body)
  fixtures = catalog.fixtures
  fixtures = fixtures.first(LIMIT.not_nil!) if LIMIT
  if fixtures.empty?
    STDERR.puts "the catalog at #{BASE_URL}/map/json is empty"
    return 1
  end

  puts "==> dalfox #{Dalfox.version} (#{Dalfox.bin}) vs #{fixtures.size} benign fixtures at #{BASE_URL}"
  puts "==> gate: #{STRICT == "all" ? "every finding fails" : "V/A fail, R/I warn"} (REPLAY_STRICT=#{STRICT})"

  outcomes = Sh.parallel_map_progress(fixtures, CONCURRENCY, "scanned") do |info|
    target = BASE_URL + info.url
    Outcome.new(info, target, Dalfox.scan(target, scan_args, timeout: BUDGET))
  end

  # --- per-fixture table -----------------------------------------------------
  name_w = Math.max(7, outcomes.max_of { |o| o.info.name.size })
  esc_w = Math.max(6, outcomes.max_of { |o| o.info.escape.size })
  puts ""
  puts "  #{"fixture".ljust(name_w)}  #{"escape".ljust(esc_w)}  #{"st".rjust(3)}  #{"V".rjust(2)} #{"A".rjust(2)} #{"R".rjust(2)} #{"I".rjust(2)}  verdict"
  puts "  #{"-" * name_w}  #{"-" * esc_w}  ---  -- -- -- --  -------"
  outcomes.each do |o|
    c = o.counts
    puts "  #{o.info.name.ljust(name_w)}  #{o.info.escape.ljust(esc_w)}  " \
         "#{o.info.status.to_s.rjust(3)}  " \
         "#{c["V"].to_s.rjust(2)} #{c["A"].to_s.rjust(2)} #{c["R"].to_s.rjust(2)} #{c["I"].to_s.rjust(2)}  #{o.verdict}"
  end
  puts ""

  # --- gate ------------------------------------------------------------------
  report = Report.new("replay corpus — benign pages must yield zero findings",
    verbose: ENV["REPLAY_VERBOSE"]? == "1")
  report.group("scans completed")
  outcomes.each do |o|
    if o.result.crashed?
      report.fail(o.info.name, "scan did not complete: #{o.result.summary} (#{o.target})")
    elsif o.report_lost?
      report.fail(o.info.name, "dalfox exited 1 (findings reported) but the JSON " \
                               "report parsed to 0 findings — the harness lost them (#{o.target})")
    else
      report.pass(o.info.name, o.result.summary)
    end
  end

  report.group("no false positives")
  outcomes.each do |o|
    next if o.result.crashed? || o.report_lost? # findings are not trustworthy
    hits = o.blocking
    if hits.empty?
      report.pass(o.info.name)
    else
      detail = String.build do |io|
        io << hits.size << " finding(s) on a fixture documented as benign — "
        io << o.target << "\n"
        hits.each { |f| io << "        " << describe(f) << "\n" }
        io << "        why benign: " << clip(o.info.why, 220)
      end
      report.fail(o.info.name, detail)
    end
  end

  warned = outcomes.reject { |o| o.warning.empty? }
  unless warned.empty?
    puts ""
    puts "warnings (not gated at REPLAY_STRICT=#{STRICT}; re-run with REPLAY_STRICT=all to gate them)"
    warned.each do |o|
      puts "  #{o.info.name} — #{o.target}"
      o.warning.each { |f| puts "      #{describe(f)}" }
    end
  end

  # --- snapshot --------------------------------------------------------------
  unless DATA_PATH.empty?
    payload = Snapshot.stamp("replay_corpus", Dalfox.version, {
      "strict"   => STRICT,
      "base_url" => BASE_URL,
      "total"    => {
        "fixtures" => outcomes.size,
        "clean"    => outcomes.count { |o| o.verdict == "clean" },
        "warn"     => outcomes.count { |o| o.verdict == "warn" },
        "failed"   => outcomes.count { |o| o.verdict == "FAIL" },
        "errored"  => outcomes.count { |o| o.verdict == "error" },
        "findings" => outcomes.sum { |o| o.result.findings.size },
      },
      "fixtures" => outcomes.map do |o|
        {
          "name"         => o.info.name,
          "file"         => o.info.file,
          "url"          => o.info.url,
          "content_type" => o.info.content_type,
          "status"       => o.info.status,
          "escape"       => o.info.escape,
          "url_decode"   => o.info.url_decode,
          "verdict"      => o.verdict,
          "counts"       => o.counts,
          "findings"     => o.result.findings.map { |f|
            {
              "type"             => f.result_type,
              "param"            => f.param,
              "payload"          => f.payload,
              "evidence"         => clip(f.evidence, 200),
              "detection_method" => f.detection_method,
            }
          },
        }
      end,
    })
    Snapshot.write(DATA_PATH, payload)
  end

  report.finish
end

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

unless Dalfox.available?
  abort "dalfox binary not found at #{Dalfox.bin} (build it, or set DALFOX_BIN)"
end
unless STRICT.in?("va", "all")
  abort "REPLAY_STRICT must be `va` or `all`, got #{STRICT.inspect}"
end

booted = boot_server
code = 1
begin
  code = run
ensure
  stop_server(booted)
end
exit code
