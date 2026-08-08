# dalfox binary driver shared by the Crystal harnesses under `scripts/`.
#
# Wraps "run a scan, get typed findings back" so each harness stops hand-rolling
# tempfile plumbing and `JSON::Any` digging. The `Finding` shape mirrors
# `src/scanning/result.rs#Result` — keep the two in step when fields move.

require "json"
require "./sh"

module Dalfox
  # Binary under test. Override for A/B runs against another build.
  def self.bin : String
    ENV.fetch("DALFOX_BIN", "target/release/dalfox")
  end

  # One finding from `--format json`. Every field carries a default so a
  # skipped/optional key (`location`, `confidence`, `new`, …) never breaks
  # deserialization.
  struct Finding
    include JSON::Serializable

    @[JSON::Field(key: "type")]
    getter result_type : String = ""
    getter inject_type : String = ""
    getter method : String = ""
    getter data : String = ""
    getter param : String = ""
    getter payload : String = ""
    getter evidence : String = ""
    getter cwe : String = ""
    getter severity : String = ""
    getter message_id : UInt32 = 0_u32
    getter message_str : String = ""
    getter location : String = ""
    getter detection_method : String = ""
    getter confidence : String? = nil
    getter confidence_reason : String = ""
    @[JSON::Field(key: "new")]
    getter new_since_baseline : Bool? = nil

    # `V` — dalfox asserts exploitability.
    def verified? : Bool
      result_type == "V"
    end

    # `A` — static JavaScript analysis (DOM XSS), no payload sent.
    def ast? : Bool
      result_type == "A"
    end

    # `R` — payload reflected, position unconfirmed.
    def reflected? : Bool
      result_type == "R"
    end

    # `I` — informational (outdated library, …), not an XSS claim.
    def informational? : Bool
      result_type == "I"
    end

    # Stable identity for set-diffing two runs. Deliberately excludes the
    # payload: an equivalent finding reached through a different bypass variant
    # is the same finding for regression purposes.
    def key : String
      "#{result_type}|#{location}|#{param}|#{detection_method}|#{message_id}"
    end

    # Identity including the payload, for "did the exact PoC change" diffs.
    def strict_key : String
      "#{key}|#{payload}"
    end
  end

  # A completed scan: the process outcome plus the parsed report.
  struct ScanResult
    getter findings : Array(Finding)
    getter output : Sh::Output
    getter args : Array(String)
    # The report's `meta` object (`dalfox_version`, `total_requests`,
    # `params_total`, `findings_count`, …). Kept raw: it grows new keys often
    # and a harness that wants one should not be gated on the lib modelling it.
    getter meta : JSON::Any?

    def initialize(@findings, @output, @args, @meta = nil)
    end

    # dalfox's own request count for the run — the number to cross-check a
    # lab's server-side counter against.
    def total_requests : Int64?
      @meta.try(&.["total_requests"]?).try { |v| v.as_i64? || v.as_i?.try(&.to_i64) }
    end

    def elapsed : Time::Span
      @output.elapsed
    end

    def timed_out? : Bool
      @output.timed_out
    end

    # dalfox exits 1 when it reported at least one finding, so a non-empty
    # report and exit 1 both mean "detected". Anything else is a real failure.
    def crashed? : Bool
      @output.timed_out || (@output.status != 0 && @output.status != 1)
    end

    def detected? : Bool
      !@findings.empty? || @output.status == 1
    end

    def verified : Array(Finding)
      @findings.select(&.verified?)
    end

    def xss : Array(Finding)
      @findings.reject(&.informational?)
    end

    def keys : Set(String)
      @findings.map(&.key).to_set
    end

    # Compact one-line summary for failure messages.
    def summary : String
      return "timeout after #{elapsed.total_seconds.round(1)}s" if timed_out?
      return "exit #{@output.status}: #{@output.error_line}" if crashed?
      "#{@findings.size} findings (#{verified.size} V) in #{elapsed.total_seconds.round(1)}s"
    end
  end

  def self.available? : Bool
    File.exists?(bin) || Sh.which(bin) != nil
  end

  def self.version : String
    Sh.capture(bin, ["--version"]).match(/(\d+\.\d+\.\d+\S*)/).try(&.[1]) || "unknown"
  end

  # Run the binary directly (no report parsing) — for `--help`, `server`,
  # `payload`, and other non-scan subcommands.
  def self.run(args : Array(String), timeout : Time::Span? = 60.seconds, input : String? = nil) : Sh::Output
    Sh.run(bin, args, input: input, timeout: timeout)
  end

  # Scan `target` and parse the JSON report.
  #
  # `args` is appended verbatim, so a caller can add `-p`, `-d`, `-H`, mining
  # switches, and so on. The report always goes to a tempfile rather than
  # stdout so banner/progress noise can never corrupt it.
  def self.scan(target : String,
                args : Array(String) = [] of String,
                timeout : Time::Span = 120.seconds,
                subcommand : String = "scan") : ScanResult
    out_file = File.tempname("dalfox-harness", ".json")
    full = [subcommand, target,
            "--format", "json", "-o", out_file,
            "--no-color", "-S"] + args
    output = Sh.run(bin, full, timeout: timeout)
    ScanResult.new(parse_report(out_file), output, full, parse_meta(out_file))
  ensure
    File.delete(out_file) if out_file && File.exists?(out_file)
  end

  # The `meta` object of a JSON report, or nil for any other shape.
  def self.parse_meta(path : String) : JSON::Any?
    return nil unless File.exists?(path)
    body = File.read(path).strip
    return nil unless body.starts_with?('{')
    JSON.parse(body).as_h?.try(&.["meta"]?)
  rescue
    nil
  end

  # Parse a `--format json` (or `jsonl`) report file. Tolerates an absent /
  # empty / garbled file — the caller decides whether that is a failure by
  # looking at the process status.
  #
  # Three shapes are accepted, because getting this wrong is silent and
  # expensive: the current `{"meta": …, "findings": […]}` envelope
  # (`src/cmd/scan/output.rs`), a bare `[…]` array (what an older dalfox wrote,
  # and what `scripts/xssmaze_score.cr` assumed for long enough to publish a
  # permanently-zero "Verified" column to the docs), and JSONL, whose first
  # line is the meta object followed by one finding per line.
  def self.parse_report(path : String) : Array(Finding)
    return [] of Finding unless File.exists?(path)
    body = File.read(path).strip
    return [] of Finding if body.empty?

    if body.starts_with?('[')
      return Array(Finding).from_json(body)
    end

    if body.starts_with?('{')
      # Envelope, or JSONL whose first line happens to be an object.
      if parsed = (JSON.parse(body) rescue nil)
        if arr = parsed.as_h?.try(&.["findings"]?)
          return Array(Finding).from_json(arr.to_json)
        end
        # A lone object with no `findings` key is the meta-only report of a
        # clean scan, not a parse failure.
        return [] of Finding if parsed.as_h?
      end

      # Not one JSON document: treat it as JSONL and keep the lines that look
      # like findings (the meta line has no `type`).
      return body.lines.compact_map do |line|
        line = line.strip
        next if line.empty?
        obj = JSON.parse(line) rescue nil
        next unless obj && obj.as_h?.try(&.has_key?("type"))
        Finding.from_json(line) rescue nil
      end
    end

    [] of Finding
  rescue
    [] of Finding
  end

  # Findings present in `after` but not `before`, and vice versa, keyed by
  # `Finding#key`. Used by the A/B and baseline harnesses.
  def self.diff(before : Array(Finding), after : Array(Finding)) : {Array(Finding), Array(Finding)}
    before_keys = before.map(&.key).to_set
    after_keys = after.map(&.key).to_set
    gained = after.reject { |f| before_keys.includes?(f.key) }
    lost = before.reject { |f| after_keys.includes?(f.key) }
    {gained, lost}
  end
end
