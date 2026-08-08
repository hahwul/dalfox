# Gate for dalfox's **output contract**: the promise that `dalfox … | jq` never
# breaks. Findings and normal output go to stdout, diagnostics go to stderr, and
# every `--format` renders a well-formed document — with findings and without.
#
# The contract this asserts was read out of the source, not assumed:
#   * `src/main.rs:148-160,332-349` — the banner is suppressed for the formats
#     listed as "machine-readable" and under `--silence`.
#   * `src/cmd/scan/logging.rs:16-29` — `log_info` / `log_warn` (the `INF` /
#     `WRN` lines) are gated on `format == "plain" && !silence`, so they are
#     *content* in plain mode and must never appear in any other format.
#   * `src/utils/log.rs` + `crate::dbg_log!` — debug output always goes to
#     stderr, regardless of format.
#   * `src/cmd/scan/logging.rs:47-53` — the spinner needs a TTY *and* no
#     `--silence`, and repaints with `\r`.
#   * `src/cmd/scan/output.rs:684-707` — `--output` writes the rendered document
#     to the file; without `-o` the same string goes to stdout through
#     `cprintln!`, which strips ANSI under `--no-color` / `NO_COLOR`.
#   * `src/main.rs:434-435` + `docs/content/guide/output.md:313-325` — exit 0
#     clean, 1 findings (any tier), 2 input/config/runtime error.
#
# Flow:
#   1. Start an in-process HTTP server on port 4806 with two endpoints: `/vuln`
#      reflects `q` raw into the HTML body, `/inert` reflects it HTML-escaped.
#   2. For every `--format` value, run three scans capturing stdout and stderr
#      separately: findings→stdout, findings→`-o` file, and no-findings→stdout.
#   3. Assert the document parses, carries no banner/log/spinner/ANSI leak, that
#      the `-o` file and the stdout render agree on the findings, and that the
#      zero-finding document is still well-formed.
#   4. Assert the cross-cutting rules: `--silence`, `--no-color`, `NO_COLOR=1`,
#      debug-goes-to-stderr, and the three exit codes.
#
# There is no SARIF JSON schema vendored in this repo (only the hand-written
# assertions in `tests/integration/sarif_validation_test.rs`), so the SARIF
# checks below are structural: `version`, `$schema`, `runs[].tool.driver.name`,
# and per-result `ruleId` + non-empty `locations`.
#
# Environment:
#   OUTPUT_CONFORMANCE_PORT     listen port                (default 4806)
#   OUTPUT_CONFORMANCE_FORMATS  comma list of formats      (default all six)
#   OUTPUT_CONFORMANCE_TIMEOUT  per-scan wall clock budget (default 120 s)
#   OUTPUT_CONFORMANCE_SKIP_PTY 1 = skip the `script(1)` pseudo-terminal checks
#   DALFOX_BIN                  binary under test          (default target/release/dalfox)

require "json"
require "http/server"
require "./lib/sh"
require "./lib/dalfox"
require "./lib/report"

PORT     = ENV.fetch("OUTPUT_CONFORMANCE_PORT", "4806").to_i
HOST     = "127.0.0.1"
TIMEOUT  = ENV.fetch("OUTPUT_CONFORMANCE_TIMEOUT", "120").to_i.seconds
SKIP_PTY = ENV["OUTPUT_CONFORMANCE_SKIP_PTY"]? == "1"

# Every value clap accepts for `-f` (src/cmd/scan/args.rs:218-220).
ALL_FORMATS = %w[plain json jsonl markdown sarif toml]
FORMATS     = ENV.fetch("OUTPUT_CONFORMANCE_FORMATS", ALL_FORMATS.join(","))
  .split(',', remove_empty: true).map(&.strip)

VULN_URL  = "http://#{HOST}:#{PORT}/vuln?q=xx"
INERT_URL = "http://#{HOST}:#{PORT}/inert?q=xx"

# `plain` is the only human format; everything else must be machine-clean.
# main.rs treats markdown as human too (it is absent from `is_machine_format`),
# which is exactly what the banner check below is here to surface.
def machine_format?(format : String) : Bool
  format != "plain"
end

# ---------------------------------------------------------------------------
# Fixture server. `/vuln` is a textbook reflected sink; `/inert` reflects the
# same parameter but entity-encodes it, so dalfox exercises the full reflection
# pipeline and still finds nothing — the "zero findings" case has to be a real
# scan, not a target that was never reachable.
# ---------------------------------------------------------------------------

ESCAPES = {'<' => "&lt;", '>' => "&gt;", '"' => "&quot;", '\'' => "&#39;", '&' => "&amp;"}

def html_escape(s : String) : String
  String.build { |io| s.each_char { |c| io << (ESCAPES[c]? || c) } }
end

def start_fixture_server : HTTP::Server
  server = HTTP::Server.new do |ctx|
    q = ctx.request.query_params["q"]? || ""
    ctx.response.content_type = "text/html; charset=utf-8"
    if ctx.request.path == "/vuln"
      ctx.response.print "<html><head><title>search</title></head><body>" \
                         "<h1>Results</h1><div id=\"out\">#{q}</div></body></html>"
    else
      ctx.response.print "<html><head><title>search</title></head><body>" \
                         "<h1>Results</h1><div id=\"out\">#{html_escape(q)}</div></body></html>"
    end
  end
  server.bind_tcp HOST, PORT
  spawn { server.listen }
  # Poll rather than sleep: bind_tcp has already reserved the port, so one
  # successful request is proof the accept loop is scheduled.
  50.times do
    begin
      HTTP::Client.get("http://#{HOST}:#{PORT}/inert?q=probe")
      return server
    rescue
      sleep 100.milliseconds
    end
  end
  abort "fixture server never answered on #{HOST}:#{PORT}"
end

# ---------------------------------------------------------------------------
# Stream inspection helpers.
# ---------------------------------------------------------------------------

# CSI / OSC escape sequences. A single one of these on stdout is what turns a
# `| jq` into a parse error, so the check is "contains any", not "looks colored".
ANSI_RE = /\e\[[0-9;?]*[ -\/]*[@-~]|\e\][^\a\e]*(?:\a|\e\\)/

# The ASCII-art banner from src/utils/banner.rs — four block-drawing glyphs no
# scan document has any reason to contain.
BANNER_RE = /[░▒▓█]/

# `HH:MMAM INF …` / `WRN` / `DBG` — the plain-mode log line shape from
# src/cmd/scan/logging.rs and src/utils/log.rs.
LOG_LINE_RE = /^\s*\d{1,2}:\d{2}(?:AM|PM)\s+(?:INF|WRN|DBG|ERR)\b/m

# Braille frames from src/utils/shimmer.rs:21, plus the `\r` redraw they ride on.
SPINNER_RE = /[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]|\r/

def strip_ansi(s : String) : String
  s.gsub(ANSI_RE, "")
end

# First offending line, quoted, so a failure names the exact text to grep for.
def first_match_line(text : String, re : Regex) : String
  text.each_line.with_index(1) do |line, n|
    return "line #{n}: #{line.chomp.inspect}" if line.matches?(re)
  end
  ""
end

# ---------------------------------------------------------------------------
# Findings extraction. Every format is compared only against *itself* (stdout
# render vs `-o` file), so each extractor can use whatever fields its format
# exposes. Payloads embed a per-process random marker (`dlx…`), so two runs of
# the same scan differ byte-for-byte until it is normalized away.
# ---------------------------------------------------------------------------

def normalize_marker(s : String) : String
  s.gsub(/dlx[0-9a-fA-F]{4,}/, "dlxMARK")
end

def sig(type : String, param : String, payload : String) : String
  "#{type}|#{param}|#{normalize_marker(payload)}"
end

def findings_json(text : String) : Array(String)
  JSON.parse(text)["findings"].as_a.map do |f|
    sig(f["type"].as_s, f["param"].as_s, f["payload"].as_s)
  end
end

def findings_jsonl(text : String) : Array(String)
  text.each_line.compact_map do |line|
    next if line.strip.empty?
    obj = JSON.parse(line)
    next if obj.as_h?.try(&.has_key?("meta"))
    sig(obj["type"].as_s, obj["param"].as_s, obj["payload"].as_s)
  end.to_a
end

def findings_sarif(text : String) : Array(String)
  JSON.parse(text)["runs"].as_a.flat_map do |run|
    (run["results"]?.try(&.as_a) || [] of JSON::Any).map do |r|
      props = r["properties"]
      snippet = r["locations"].as_a.first["physicalLocation"]["region"]["snippet"]["text"].as_s
      sig(props["type"].as_s, props["param"].as_s, snippet)
    end
  end
end

# No TOML parser in the Crystal stdlib, so the `[[results]]` array of tables is
# split by its header and each chunk read with line-anchored key regexes.
# `[^"\n]` rather than `.` on purpose: Crystal's `m` flag is DOTALL *and*
# MULTILINE, so a `.*` here silently swallows the rest of the table.
def findings_toml(text : String) : Array(String)
  text.split(/^\[\[results\]\]\s*$/m).skip(1).map do |chunk|
    grab = ->(key : String) { chunk.match(/^#{key} = "([^"\n]*)"$/m).try(&.[1]) || "" }
    sig(grab.call("type"), grab.call("param"), grab.call("payload"))
  end
end

# `### 1. Vulnerability - q (inHTML)` blocks, each holding a `| Field | Value |`
# table (src/scanning/result.rs#results_to_markdown_with_meta).
def findings_markdown(text : String) : Array(String)
  text.split(/^### \d+\. /m).skip(1).map do |chunk|
    grab = ->(key : String) {
      chunk.match(/^\| \*\*#{key}\*\* \| `?([^|`\n]*)`? \|$/m).try(&.[1].strip) || ""
    }
    sig(grab.call("Type"), grab.call("Parameter"), grab.call("Payload"))
  end
end

# `[POC][V][GET][inHTML] url` followed by a `Payload:` branch line
# (src/cmd/scan/poc.rs#render_finding_block). The param is not on the block, so
# it stays empty — harmless, both sides of the comparison are plain.
def findings_plain(text : String) : Array(String)
  clean = strip_ansi(text)
  out = [] of String
  type = ""
  clean.each_line do |line|
    if m = line.match(/^\[POC\]\[([VARI])\]/)
      type = m[1]
    elsif (m = line.match(/Payload:\s*(.*)$/)) && !type.empty?
      out << sig(type, "", m[1].strip)
      type = ""
    end
  end
  out
end

def findings_of(format : String, text : String) : Array(String)
  case format
  when "json"     then findings_json(text)
  when "jsonl"    then findings_jsonl(text)
  when "sarif"    then findings_sarif(text)
  when "toml"     then findings_toml(text)
  when "markdown" then findings_markdown(text)
  else                 findings_plain(text)
  end
end

# ---------------------------------------------------------------------------
# Per-format document validation. Returns "" when well-formed, else the reason.
# ---------------------------------------------------------------------------

def validate_document(format : String, text : String) : String
  case format
  when "json"     then validate_json(text)
  when "jsonl"    then validate_jsonl(text)
  when "sarif"    then validate_sarif(text)
  when "toml"     then validate_toml(text)
  when "markdown" then validate_markdown(text)
  else                 validate_plain(text)
  end
rescue ex
  "#{format} parse raised: #{ex.message}"
end

def validate_json(text : String) : String
  root = JSON.parse(text).as_h? || return "top level is not a JSON object"
  return "no `findings` key" unless root.has_key?("findings")
  return "`findings` is not an array" unless root["findings"].as_a?
  return "no `meta` key" unless root.has_key?("meta")
  ""
end

def validate_jsonl(text : String) : String
  lines = text.lines.reject(&.strip.empty?)
  return "empty document" if lines.empty?
  lines.each_with_index do |line, i|
    obj = JSON.parse(line).as_h? || return "line #{i + 1} is not a JSON object"
    return "line 1 is not the meta envelope" if i.zero? && !obj.has_key?("meta")
  end
  ""
end

def validate_sarif(text : String) : String
  root = JSON.parse(text).as_h? || return "top level is not a JSON object"
  return "missing `version`" unless root["version"]?.try(&.as_s?)
  return "missing `$schema`" unless root["$schema"]?.try(&.as_s?)
  runs = root["runs"]?.try(&.as_a?) || return "missing/!array `runs`"
  return "`runs` is empty" if runs.empty?
  runs.each_with_index do |run, i|
    name = run.dig?("tool", "driver", "name").try(&.as_s?)
    return "runs[#{i}].tool.driver.name missing" unless name
    results = run["results"]?.try(&.as_a?) || return "runs[#{i}].results missing/!array"
    results.each_with_index do |r, j|
      return "runs[#{i}].results[#{j}].ruleId missing" unless r["ruleId"]?.try(&.as_s?)
      locs = r["locations"]?.try(&.as_a?) || return "runs[#{i}].results[#{j}].locations missing"
      return "runs[#{i}].results[#{j}].locations is empty" if locs.empty?
    end
  end
  ""
end

# Structural, not a real TOML parse (no stdlib parser): the `[meta]` envelope
# and a `results` array must both be present, and every non-blank line must be
# a table header or a `key = value` pair.
def validate_toml(text : String) : String
  return "no `[meta]` table" unless text.matches?(/^\[meta\]\s*$/m)
  unless text.matches?(/^\[\[results\]\]\s*$/m) || text.matches?(/^results = \[\]\s*$/m)
    return "neither `[[results]]` nor an empty `results = []`"
  end
  text.each_line.with_index(1) do |line, n|
    s = line.strip
    next if s.empty? || s.starts_with?('#')
    next if s.matches?(/^\[{1,2}[A-Za-z0-9_.\-]+\]{1,2}$/)
    next if s.matches?(/^[A-Za-z0-9_\-]+ = /)
    return "line #{n} is not a TOML table/pair: #{s.inspect}"
  end
  ""
end

def validate_markdown(text : String) : String
  unless text.starts_with?("# Dalfox Scan Results")
    lead = text.lines.first?.try(&.chomp) || ""
    return text.includes?("# Dalfox Scan Results") ? "document has junk before its `# Dalfox Scan Results` heading, starting #{lead.inspect}" : "no `# Dalfox Scan Results` heading"
  end
  return "no table header row" unless text.matches?(/^\| *Field *\| *Value *\|$/m)
  return "no table delimiter row" unless text.matches?(/^\|[-\s|]+\|$/m)
  ""
end

# Plain is line-oriented by contract: no raw control characters (which would
# mean a spinner frame or a stray `\r` landed in captured output), and every
# POC header keeps its four-bracket shape so `grep '\[POC\]'` keeps working.
def validate_plain(text : String) : String
  strip_ansi(text).each_line.with_index(1) do |line, n|
    body = line.chomp
    if body.each_char.any? { |c| c.ord < 0x20 && c != '\t' }
      return "line #{n} carries a control character: #{body.inspect}"
    end
    if body.starts_with?("[POC]") && !body.matches?(/^\[POC\]\[[VARI]\]\[[A-Z]+\]\[[^\]]+\] \S/)
      return "malformed POC header at line #{n}: #{body.inspect}"
    end
  end
  ""
end

# ---------------------------------------------------------------------------
# Scan driver.
# ---------------------------------------------------------------------------

# `--skip-mining` keeps the fixture scan to the reflection pipeline (the part
# that produces output), and the two timeouts keep a wedged run from hanging the
# gate instead of failing it.
def scan(target : String, format : String, extra : Array(String) = [] of String,
         env : Process::Env = nil) : Sh::Output
  args = ["scan", target, "-f", format,
          "--skip-mining", "--timeout", "5", "--scan-timeout", "60"] + extra
  Sh.run(Dalfox.bin, args, env: env, timeout: TIMEOUT)
end

# ---------------------------------------------------------------------------
# Pseudo-terminal support. Colour auto-disables when stdout is not a TTY
# (src/main.rs:120-131), so a piped capture can never distinguish "--no-color
# works" from "there was never any colour". `script(1)` supplies a real pty.
# ---------------------------------------------------------------------------

enum Pty
  Bsd   # macOS:      script -q /dev/null cmd args...
  Linux # util-linux: script -qec "cmd args" /dev/null
  None
end

def detect_pty : Pty
  return Pty::None if SKIP_PTY
  if Sh.run("script", ["-q", "/dev/null", "/bin/echo", "probe"], timeout: 10.seconds)
       .stdout.includes?("probe")
    return Pty::Bsd
  end
  if Sh.run("script", ["-qec", "/bin/echo probe", "/dev/null"], timeout: 10.seconds)
       .stdout.includes?("probe")
    return Pty::Linux
  end
  Pty::None
end

# Runs dalfox attached to a pty. `script` merges stderr into the pty stream, so
# the result is only useful for "is there any ANSI here", which is all we ask.
def pty_scan(flavor : Pty, target : String, extra : Array(String), env : Process::Env = nil) : String
  args = [Dalfox.bin, "scan", target, "--skip-mining", "--timeout", "5", "--scan-timeout", "60"] + extra
  case flavor
  in Pty::Bsd
    Sh.run("script", ["-q", "/dev/null"] + args, env: env, timeout: TIMEOUT).stdout
  in Pty::Linux
    cmd = args.map { |a| Process.quote(a) }.join(' ')
    Sh.run("script", ["-qec", cmd, "/dev/null"], env: env, timeout: TIMEOUT).stdout
  in Pty::None
    ""
  end
end

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

unless Dalfox.available?
  abort "dalfox binary not found at #{Dalfox.bin} (set DALFOX_BIN)"
end

report = Report.new("output conformance — dalfox #{Dalfox.version} @ #{Dalfox.bin}")
server = start_fixture_server

begin
  FORMATS.each do |format|
    report.group("format: #{format}")

    unless ALL_FORMATS.includes?(format)
      report.fail("known format", "#{format} is not one of #{ALL_FORMATS.join(", ")}")
      next
    end

    out_file = File.tempname("dalfox-conformance", ".#{format}")
    with_findings = scan(VULN_URL, format)
    # `-o` runs use `--silence` so the only thing on stdout is whatever the
    # renderer leaks: without it, output.rs:687 legitimately prints one
    # `Results written to …` status line (checked separately below).
    to_file = scan(VULN_URL, format, ["-o", out_file, "-S"])
    no_findings = scan(INERT_URL, format)

    if with_findings.timed_out || no_findings.timed_out || to_file.timed_out
      report.fail("scans complete", "a scan hit the #{TIMEOUT} budget")
      File.delete(out_file) if File.exists?(out_file)
      next
    end

    stdout = with_findings.stdout
    file_body = File.exists?(out_file) ? File.read(out_file) : ""

    # --- the document itself -------------------------------------------------
    err = validate_document(format, stdout)
    err.empty? ? report.pass("stdout is a well-formed #{format} document") : report.fail("stdout is a well-formed #{format} document", err)

    err = validate_document(format, file_body)
    err.empty? ? report.pass("-o file is a well-formed #{format} document") : report.fail("-o file is a well-formed #{format} document", err)

    err = validate_document(format, no_findings.stdout)
    err.empty? ? report.pass("zero-finding stdout is still well-formed") : report.fail("zero-finding stdout is still well-formed", err)

    if (n = findings_of(format, no_findings.stdout).size) == 0
      report.pass("zero-finding document reports no findings")
    else
      report.fail("zero-finding document reports no findings", "extracted #{n}")
    end

    # --- nothing but the document on stdout ----------------------------------
    if stdout.matches?(ANSI_RE)
      report.fail("stdout carries no ANSI escape", first_match_line(stdout, ANSI_RE))
    else
      report.pass("stdout carries no ANSI escape")
    end

    if stdout.matches?(SPINNER_RE)
      report.fail("stdout carries no spinner frame / CR repaint", first_match_line(stdout, SPINNER_RE))
    else
      report.pass("stdout carries no spinner frame / CR repaint")
    end

    if machine_format?(format)
      if stdout.matches?(BANNER_RE)
        report.fail("stdout carries no ASCII banner", first_match_line(stdout, BANNER_RE))
      else
        report.pass("stdout carries no ASCII banner")
      end

      if stdout.matches?(LOG_LINE_RE)
        report.fail("stdout carries no INF/WRN/DBG log line", first_match_line(stdout, LOG_LINE_RE))
      else
        report.pass("stdout carries no INF/WRN/DBG log line")
      end
    else
      # plain's INF/WRN lines *are* its content; the banner still has to go
      # under --silence, which is what `plain --silence` asserts below.
      report.pass("plain: log lines are content, not a leak", "banner/log checked under --silence")
    end

    # --- the -o file ---------------------------------------------------------
    if file_body.matches?(ANSI_RE)
      report.fail("-o file carries no ANSI escape", first_match_line(file_body, ANSI_RE))
    else
      report.pass("-o file carries no ANSI escape")
    end

    stdout_sigs = findings_of(format, stdout)
    file_sigs = findings_of(format, file_body)
    if stdout_sigs.empty?
      report.fail("-o file and stdout agree on findings",
        "the stdout render produced no findings at all")
    elsif stdout_sigs.sort! == file_sigs.sort!
      report.pass("-o file and stdout agree on findings", "#{stdout_sigs.size} finding(s)")
    else
      report.fail("-o file and stdout agree on findings",
        "stdout=#{stdout_sigs.sort.inspect} file=#{file_sigs.sort.inspect}")
    end

    # --- --silence -----------------------------------------------------------
    silenced = scan(VULN_URL, format, ["-S"])
    if silenced.stdout.matches?(BANNER_RE) || silenced.stdout.matches?(LOG_LINE_RE)
      report.fail("--silence leaves findings-only stdout",
        first_match_line(silenced.stdout, /#{BANNER_RE.source}|#{LOG_LINE_RE.source}/))
    elsif findings_of(format, silenced.stdout).empty?
      report.fail("--silence leaves findings-only stdout", "no findings survived --silence")
    else
      report.pass("--silence leaves findings-only stdout")
    end

    silent_clean = scan(INERT_URL, format, ["-S"])
    if machine_format?(format)
      err = validate_document(format, silent_clean.stdout)
      if err.empty? && findings_of(format, silent_clean.stdout).empty?
        report.pass("--silence + no findings emits a valid empty document")
      else
        report.fail("--silence + no findings emits a valid empty document",
          err.empty? ? "document reported findings" : err)
      end
    else
      # plain has no envelope, so "findings-only" with zero findings means
      # literally nothing (output.rs prints the empty render through cprintln,
      # which contributes a single trailing newline).
      if silent_clean.stdout.strip.empty?
        report.pass("--silence + no findings leaves stdout empty")
      else
        report.fail("--silence + no findings leaves stdout empty",
          silent_clean.stdout.inspect[0, 200])
      end
    end

    # --- --no-color / NO_COLOR ------------------------------------------------
    nocolor = scan(VULN_URL, format, ["-S", "-o", out_file, "--no-color"])
    nocolor_file = File.exists?(out_file) ? File.read(out_file) : ""
    leaks = [] of String
    leaks << "stdout: #{first_match_line(nocolor.stdout, ANSI_RE)}" if nocolor.stdout.matches?(ANSI_RE)
    leaks << "stderr: #{first_match_line(nocolor.stderr, ANSI_RE)}" if nocolor.stderr.matches?(ANSI_RE)
    leaks << "-o file: #{first_match_line(nocolor_file, ANSI_RE)}" if nocolor_file.matches?(ANSI_RE)
    report.check_empty("--no-color leaves no ANSI on stdout/stderr/-o", leaks)

    env_nocolor = scan(VULN_URL, format, ["-S", "-o", out_file], {"NO_COLOR" => "1"})
    envfile = File.exists?(out_file) ? File.read(out_file) : ""
    env_leaks = [] of String
    env_leaks << "stdout: #{first_match_line(env_nocolor.stdout, ANSI_RE)}" if env_nocolor.stdout.matches?(ANSI_RE)
    env_leaks << "stderr: #{first_match_line(env_nocolor.stderr, ANSI_RE)}" if env_nocolor.stderr.matches?(ANSI_RE)
    env_leaks << "-o file: #{first_match_line(envfile, ANSI_RE)}" if envfile.matches?(ANSI_RE)
    report.check_empty("NO_COLOR=1 behaves like --no-color", env_leaks)

    # --- `-o` without --silence prints the status line ------------------------
    # output.rs:687 prints `Results written to <path>` unless silenced. For a
    # machine format that single line is the *whole* of stdout; plain also has
    # its INF/WRN log, which is that format's normal content.
    noisy = scan(VULN_URL, format, ["-o", out_file])
    lines = noisy.stdout.lines.reject(&.strip.empty?)
    status_lines = lines.select(&.starts_with?("Results written to "))
    if machine_format?(format)
      if lines.size == 1 && status_lines.size == 1
        report.pass("-o without --silence prints only the status line")
      else
        report.fail("-o without --silence prints only the status line",
          "#{lines.size} line(s): #{lines.first(3).inspect}")
      end
    else
      report.check_eq("-o without --silence prints the status line", 1, status_lines.size)
    end

    # --- exit codes -----------------------------------------------------------
    report.check_eq("exit 1 when findings are reported", 1, with_findings.status)
    report.check_eq("exit 0 when the scan is clean", 0, no_findings.status)

    File.delete(out_file) if File.exists?(out_file)
  end

  # -------------------------------------------------------------------------
  # Cross-cutting: streams, exit codes, and the TTY colour path.
  # -------------------------------------------------------------------------
  report.group("streams")

  debug_run = scan(VULN_URL, "json", ["--debug"])
  err = validate_document("json", debug_run.stdout)
  if err.empty?
    report.pass("--debug keeps stdout parseable")
  else
    report.fail("--debug keeps stdout parseable", err)
  end
  if debug_run.stdout.includes?("DBG")
    report.fail("--debug writes DBG to stderr only", first_match_line(debug_run.stdout, /DBG/))
  elsif !debug_run.stderr.includes?("DBG")
    report.fail("--debug writes DBG to stderr only", "no DBG line reached stderr either")
  else
    report.pass("--debug writes DBG to stderr only")
  end

  report.group("exit codes")

  unreachable = scan("http://#{HOST}:#{PORT + 1}/dead", "json", ["-S"])
  report.check_eq("exit 2 when every target is unreachable", 2, unreachable.status)
  if validate_document("json", unreachable.stdout).empty?
    report.pass("unreachable run still emits a valid JSON envelope")
  else
    report.fail("unreachable run still emits a valid JSON envelope",
      unreachable.stdout.inspect[0, 200])
  end

  bad_flag = Sh.run(Dalfox.bin, ["scan", "--format", "not-a-format", VULN_URL], timeout: TIMEOUT)
  report.check_eq("exit 2 on an invalid --format", 2, bad_flag.status)
  report.check("invalid --format writes nothing to stdout",
    bad_flag.stdout.inspect[0, 200]) { bad_flag.stdout.strip.empty? }

  unwritable = File.join(Dir.tempdir, "dalfox-conformance-missing-#{Random.rand(1_000_000)}", "out.json")
  bad_out = scan(VULN_URL, "json", ["-S", "-o", unwritable])
  report.check_eq("exit 2 when --output cannot be written", 2, bad_out.status)

  report.group("colour under a real TTY")

  case flavor = detect_pty
  in Pty::None
    report.skip("pty checks", SKIP_PTY ? "OUTPUT_CONFORMANCE_SKIP_PTY=1" : "no usable script(1)")
  in Pty::Bsd, Pty::Linux
    tty_default = pty_scan(flavor, VULN_URL, ["-S"])
    # Control check: without it the two assertions below pass vacuously.
    if tty_default.matches?(ANSI_RE)
      report.pass("pty probe really is a terminal (default run is coloured)")

      tty_flag = pty_scan(flavor, VULN_URL, ["-S", "--no-color"])
      if tty_flag.matches?(ANSI_RE)
        report.fail("--no-color suppresses colour on a TTY", first_match_line(tty_flag, ANSI_RE))
      else
        report.pass("--no-color suppresses colour on a TTY")
      end

      tty_env = pty_scan(flavor, VULN_URL, ["-S"], {"NO_COLOR" => "1"})
      if tty_env.matches?(ANSI_RE)
        report.fail("NO_COLOR=1 suppresses colour on a TTY", first_match_line(tty_env, ANSI_RE))
      else
        report.pass("NO_COLOR=1 suppresses colour on a TTY")
      end
    else
      report.skip("pty checks", "script(1) produced no colour; probe is not a real terminal")
    end
  end
ensure
  server.close rescue nil
end

exit report.finish
