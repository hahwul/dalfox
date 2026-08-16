# Gate that keeps dalfox's five scanning surfaces in lockstep.
#
# The same scan engine is exposed through the CLI (clap), the config file
# (`src/config.rs`), the REST server (`src/server/types.rs`), the MCP tool
# schema (`src/mcp/mod.rs`), and the agent-facing skill bundle (`skills/**` +
# the published `.well-known` copy). Each of those is hand-maintained, and they
# have repeatedly drifted: a config key that exists in the struct but is never
# read by `apply_to_scan_args_if_default` silently does nothing, a REST option
# lands without its MCP twin, a SKILL.md is edited without refreshing the
# digest recorded next to it. This script re-derives every surface from the
# source of truth and fails the build when they disagree.
#
# Flow:
#   1. Interrogate the built binary (`dalfox scan|server --help`) for the real
#      clap surface — long flags, short flags, aliases, defaults, and
#      `[possible values]` sets. Parsing `--help` beats regexing the `#[arg]`
#      macros: it is what users actually see, and it survives macro refactors.
#   2. Parse the narrow Rust structures that have no runtime representation:
#      `ScanConfig`'s fields, the body of `apply_to_scan_args_if_default`, the
#      body of `ScanConfig::normalize_and_validate`, the shared `*_VALUES` /
#      `DEFAULT_*` consts, REST `ScanOptions`, and MCP `ScanWithDalfoxParams`.
#      Every parser is asserted non-empty first (group "parsers"), so a
#      refactor that breaks a regex turns the gate red instead of green.
#   3. Cross-check the surfaces:
#        - CLI <-> config file  (key exists, key is actually applied)
#        - enum value sets      (clap and the config validator share one const)
#        - REST <-> MCP         (modulo a documented compat-alias list)
#        - agent surfaces       (skills/ == .well-known copy, digest, tool list)
#        - docs key reference   (EN + KO, read-only)
#   4. Print one line per check and exit non-zero on any drift.
#
# Legitimate asymmetries live in the small allowlists below, each with a
# comment saying why — never by weakening a check.
#
# Run from the repo root: `crystal run scripts/surface_parity.cr`
#
# Environment tunables:
#   PARITY_DALFOX_BIN   dalfox binary to interrogate (default: $DALFOX_BIN or
#                       target/release/dalfox). It must be built from the tree
#                       being checked, otherwise the CLI half is stale.
#   PARITY_VERBOSE      1 = also print the detail line for passing checks
#                       (default 0)
#   PARITY_MAX_LIST     how many offenders to name per failing check
#                       (default 12)

require "digest/sha256"
require "json"
require "./lib/sh"
require "./lib/dalfox"
require "./lib/report"

# ---------------------------------------------------------------------------
# Tunables & source-of-truth paths.
# ---------------------------------------------------------------------------

DALFOX_BIN = ENV.fetch("PARITY_DALFOX_BIN", Dalfox.bin)
VERBOSE    = ENV.fetch("PARITY_VERBOSE", "0") == "1"
MAX_LIST   = ENV.fetch("PARITY_MAX_LIST", "12").to_i

CONFIG_RS       = "src/config.rs"
ARGS_RS         = "src/cmd/scan/args.rs"
SESSION_RS      = "src/cmd/scan/session.rs"
SERVER_TYPES_RS = "src/server/types.rs"
MCP_RS          = "src/mcp/mod.rs"

SKILL_MD           = "skills/dalfox/SKILL.md"
SKILL_CLI_REF      = "skills/dalfox/references/cli.md"
SKILL_MCP_REF      = "skills/dalfox/references/mcp.md"
WELLKNOWN_SKILL_MD = "docs/static/.well-known/agent-skills/dalfox/SKILL.md"
WELLKNOWN_INDEX    = "docs/static/.well-known/agent-skills/index.json"

DOC_CLI     = {"docs/content/reference/cli.md", "docs/content/reference/cli.ko.md"}
DOC_CONFIG  = {"docs/content/reference/config.md", "docs/content/reference/config.ko.md"}
DOC_SERVER  = {"docs/content/integrations/server.md", "docs/content/integrations/server.ko.md"}
DOC_MCP_INT = {"docs/content/integrations/mcp.md", "docs/content/integrations/mcp.ko.md"}

# ---------------------------------------------------------------------------
# Allowlists — every entry is a *documented* asymmetry, not a silenced bug.
# ---------------------------------------------------------------------------

# Config keys whose CLI flag is not simply the key with underscores swapped for
# dashes. Resolved before the generic kebab / value-placeholder matching so the
# mapping is explicit rather than inferred.
CONFIG_KEY_TO_FLAG = {
  # `-b, --blind <BLIND_CALLBACK_URL>`: the flag is short-named, the struct
  # field (and therefore the config key) carries the descriptive name.
  "blind_callback_url" => "blind",
}

# Global flags that exist on every subcommand and deliberately have no config
# key: they either select the config file itself or are clap built-ins.
CLI_FLAGS_WITHOUT_CONFIG_KEY = %w[config help version]

# `dalfox server` flags that are the process-global set rather than part of the
# server's own documented surface, so the server docs do not repeat them.
SERVER_GLOBAL_FLAGS = %w[config debug help no-color silence version]

# REST `ScanOptions` field -> MCP `ScanWithDalfoxParams` field, for the options
# the REST API kept under their v2-era names when MCP was added with the
# CLI-aligned spelling. Renaming the REST side would break existing clients, so
# the divergence is intentional; the mapping is what must stay true.
REST_TO_MCP_ALIASES = {
  "cookie" => "cookies",            # REST takes one cookie string, MCP a list
  "header" => "headers",            # ditto for headers
  "worker" => "workers",            # v2 spelling of --workers
  "blind"  => "blind_callback_url", # v2 spelling of -b/--blind
}

# REST-only scan options. `callback_url` is the completion webhook: MCP is a
# stdio session where the agent polls `get_results_dalfox`, so there is nothing
# to POST a result to.
REST_ONLY_OPTIONS = %w[callback_url]

# MCP-only scan params.
#   target              REST carries it on `ScanRequest`, one level above
#                       `ScanOptions`, so it is not an option there.
#   wait/wait_timeout_sec  MCP-only convenience that blocks the tool call until
#                       the job settles; the REST equivalent is polling GET
#                       /scan/{id}, which needs no request field.
MCP_ONLY_PARAMS = %w[target wait wait_timeout_sec]

# Server/MCP scan options that intentionally have no CLI flag or config key —
# they configure the request/response protocol, not the scan.
TRANSPORT_ONLY_OPTIONS = %w[target callback_url wait wait_timeout_sec]

# Flags whose `[possible values]` come from a clap built-in parser rather than a
# shared `*_VALUES` const, so there is no const for them to agree with.
FLAGS_WITHOUT_VALUE_CONST = {
  "insecure" => "clap BoolishValueParser (true/false), not an enum",
}

# ---------------------------------------------------------------------------
# clap surface, read back out of the built binary.
# ---------------------------------------------------------------------------

# One option as `--help` renders it. `possible` / `default` are empty when clap
# printed no such annotation for the flag.
class ClapFlag
  getter long : String
  getter short : String?
  getter value_name : String?
  property possible = [] of String
  property default = [] of String
  property aliases = [] of String

  def initialize(@long, @short, @value_name)
  end

  # True when `text` refers to this flag by any of its spellings. Short flags
  # are matched with explicit boundaries so `-S` does not hit inside `-Sx`.
  def mentioned_in?(text : String) : Bool
    return true if text.includes?("--#{@long}")
    return true if @aliases.any? { |a| text.includes?("--#{a}") }
    if s = @short
      return true if text.matches?(/(?<![\w-])-#{Regex.escape(s)}(?![\w-])/)
    end
    false
  end

  def to_s(io : IO)
    io << "--" << @long
  end
end

# `[  -x, ]--long[ <VALUE>]` at the indentation clap uses for option entries.
# Anchored on the leading `--` so prose lines that happen to mention a flag are
# never mistaken for a declaration. The value placeholder has three renderings
# depending on the arg's arity: ` <V>`, `[=<V>]` (optional value, `--insecure`)
# and `[=<V>...]` (optional multi-value, `--blind-oob`); all three must match,
# otherwise the flag is dropped *and* its `[possible values]` line is
# mis-attributed to the previous flag.
OPT_RE = /^\s{2,10}(?:-(?<short>[A-Za-z]), )?--(?<long>[a-z0-9][a-z0-9-]*)(?:\[?=?<(?<value>[A-Z0-9_]+)>\.{0,3}\]?)?(?:\s|$)/

# Run `dalfox <sub> --help` and turn it back into structured flags. The banner
# and any warnings can land on either stream, so both are scanned.
def parse_help(sub : Array(String)) : Array(ClapFlag)
  out = Sh.run(DALFOX_BIN, sub + ["--help"], timeout: 30.seconds)
  text = out.stdout + "\n" + out.stderr
  flags = [] of ClapFlag
  current : ClapFlag? = nil

  text.each_line do |line|
    if m = OPT_RE.match(line)
      current = ClapFlag.new(m["long"], m["short"]?, m["value"]?)
      flags << current
      next
    end
    # Annotations clap prints on their own line under the option's help text.
    cur = current
    next unless cur
    if m = line.match(/\[possible values:\s*(.+?)\]\s*$/)
      cur.possible = m[1].split(',').map(&.strip)
    elsif m = line.match(/^\s*\[default:\s*(.*?)\]\s*$/)
      cur.default = m[1].split(' ').map(&.strip).reject(&.empty?)
    elsif m = line.match(/\[alias(?:es)?:\s*(.+?)\]\s*$/)
      cur.aliases = m[1].split(',').map { |a| a.strip.lchop("--") }
    end
  end
  flags
end

# ---------------------------------------------------------------------------
# Rust source parsing. Deliberately narrow regexes; every extraction is
# asserted non-empty in the "parsers" group so a silent zero-match cannot make
# the gate pass.
# ---------------------------------------------------------------------------

def read(path : String) : String
  File.exists?(path) ? File.read(path) : ""
end

# Field names of a `struct Name { .. }` block, whatever the visibility keyword.
# The closing brace is matched at column 0, which is where rustfmt puts it for
# a top-level item.
def struct_fields(src : String, name : String) : Array(String)
  m = src.match(/^(?:pub(?:\(crate\))? )?struct #{Regex.escape(name)}[^\{]*\{(.*?)^\}/m)
  return [] of String unless m
  m[1].scan(/^\s*pub(?:\(crate\))? ([a-z_][a-z_0-9]*):/m).map { |f| f[1] }
end

# Body of a function, from its signature to the start of `stop_at`. Used for
# "is this field ever read here?" checks, where an exact brace match is
# unnecessary and fragile.
def slice_between(src : String, start_at : String, stop_at : String) : String
  a = src.index(start_at)
  return "" unless a
  b = src.index(stop_at, a)
  b ? src[a...b] : src[a..]
end

# `pub const NAME: &[&str] = &["a", "b"];` — including the multi-line form and
# entries that reference another `&str` const (e.g. BASELINE_MODE_VALUES).
def value_consts(sources : Array(String)) : Hash(String, Array(String))
  joined = sources.join("\n")
  strings = {} of String => String
  joined.scan(/^pub(?:\(crate\))? const ([A-Z0-9_]+): &str = "([^"]*)";/m) { |m| strings[m[1]] = m[2] }

  out = {} of String => Array(String)
  joined.scan(/^pub(?:\(crate\))? const ([A-Z0-9_]+): &\[&str\] = &\[(.*?)\];/m) do |m|
    items = [] of String
    m[2].scan(/"([^"]*)"|([A-Z][A-Z0-9_]+)/) do |item|
      if lit = item[1]?
        items << lit
      elsif ref = item[2]?
        items << (strings[ref]? || "<unresolved:#{ref}>")
      end
    end
    out[m[1]] = items
  end
  out
end

# `pub const NAME: <numeric> = 10;` / `pub const NAME: &str = "GET";`, returned
# as the literal text so it can be compared with clap's `[default: ...]`.
def scalar_consts(sources : Array(String)) : Hash(String, String)
  joined = sources.join("\n")
  out = {} of String => String
  joined.scan(/^pub(?:\(crate\))? const ([A-Z0-9_]+): (?:u8|u16|u32|u64|usize|f32|f64) = ([0-9_.]+);/m) do |m|
    out[m[1]] = m[2].gsub('_', "")
  end
  joined.scan(/^pub(?:\(crate\))? const ([A-Z0-9_]+): &str = "([^"]*)";/m) { |m| out[m[1]] = m[2] }
  out
end

# ---------------------------------------------------------------------------
# Load every surface up front so the checks below are pure comparisons.
# ---------------------------------------------------------------------------

config_src = read(CONFIG_RS)
args_src = read(ARGS_RS)
session_src = read(SESSION_RS)
server_src = read(SERVER_TYPES_RS)
mcp_src = read(MCP_RS)

scan_flags = parse_help(["scan"])
server_flags = parse_help(["server"])
flag_by_long = scan_flags.to_h { |f| {f.long, f} }

config_keys = struct_fields(config_src, "ScanConfig")
# `apply_to_scan_args_if_default` is the only place config values reach
# `ScanArgs`; a key absent from it is dead weight the user cannot tell apart
# from a working one.
apply_body = slice_between(config_src, "fn apply_to_scan_args_if_default", "    /// Normalize and validate config values")
normalize_body = slice_between(config_src, "impl ScanConfig {", "\npub fn load_or_init")

rest_options = struct_fields(server_src, "ScanOptions")
mcp_params = struct_fields(mcp_src, "ScanWithDalfoxParams")
mcp_tools = mcp_src.scan(/#\[tool\(\s*name = "([a-z_0-9]+)"/m).map { |m| m[1] }

consts = value_consts([args_src, session_src])
scalars = scalar_consts([args_src, session_src])

# Config key -> CLI flag. Explicit override first, then the kebab-case form,
# then clap's value placeholder (`--blind <BLIND_CALLBACK_URL>`), which is how
# a descriptively-named struct field ends up behind a short flag name.
placeholder_to_flag = {} of String => String
scan_flags.each do |f|
  if v = f.value_name
    placeholder_to_flag[v.downcase] = f.long
  end
end

config_flag = {} of String => String
config_keys.each do |key|
  if mapped = CONFIG_KEY_TO_FLAG[key]?
    config_flag[key] = mapped if flag_by_long.has_key?(mapped)
  elsif flag_by_long.has_key?(key.tr("_", "-"))
    config_flag[key] = key.tr("_", "-")
  elsif mapped = placeholder_to_flag[key]?
    config_flag[key] = mapped
  end
end
flag_config = config_flag.invert

report = Report.new("surface parity", verbose: VERBOSE)

# ---------------------------------------------------------------------------
# 0. Parser sanity. Every later check compares extracted sets, so an extraction
#    that silently returns nothing would make the whole gate vacuously green.
#    These floors are deliberately far below the current counts: they catch a
#    broken regex, not a legitimate removal.
# ---------------------------------------------------------------------------

report.group("parsers (fail loud on a broken extraction)")

report.check("dalfox binary present", "not found: #{DALFOX_BIN} (build it first)") do
  File.exists?(DALFOX_BIN) || Sh.which(DALFOX_BIN) != nil
end
report.check("dalfox scan --help parsed", "got #{scan_flags.size} flags from #{DALFOX_BIN}") { scan_flags.size >= 50 }
report.check("dalfox server --help parsed", "got #{server_flags.size} flags") { server_flags.size >= 10 }
report.check("ScanConfig fields parsed", "got #{config_keys.size} from #{CONFIG_RS}") { config_keys.size >= 50 }
report.check("apply_to_scan_args_if_default body located", "empty slice from #{CONFIG_RS}") { apply_body.size > 1000 }
report.check("normalize_and_validate body located", "empty slice from #{CONFIG_RS}") { normalize_body.size > 1000 }
report.check("REST ScanOptions parsed", "got #{rest_options.size} from #{SERVER_TYPES_RS}") { rest_options.size >= 20 }
report.check("MCP ScanWithDalfoxParams parsed", "got #{mcp_params.size} from #{MCP_RS}") { mcp_params.size >= 20 }
report.check("MCP tool list parsed", "got #{mcp_tools.size} from #{MCP_RS}") { mcp_tools.size >= 5 }
report.check("shared *_VALUES consts parsed", "got #{consts.size} from #{ARGS_RS}") { consts.size >= 8 }
report.check_empty("no unresolved const references", consts.flat_map { |name, v| v.select(&.starts_with?("<unresolved")).map { |u| "#{name}#{u}" } }, MAX_LIST)

# ---------------------------------------------------------------------------
# 1. CLI <-> config file.
# ---------------------------------------------------------------------------

report.group("CLI <-> config file")

report.check_empty("every config key maps to a CLI flag",
  config_keys.reject { |k| config_flag.has_key?(k) }, MAX_LIST)

# The recurring silent-no-op bug: the key deserializes fine, `--help` shows the
# matching flag, but nothing ever copies the value into ScanArgs.
report.check_empty("every config key is read by apply_to_scan_args_if_default",
  config_keys.reject { |k| apply_body.matches?(/scan\.#{Regex.escape(k)}\b/) }, MAX_LIST)

report.check_empty("every scan CLI flag has a config key",
  scan_flags.map(&.long)
    .reject { |l| CLI_FLAGS_WITHOUT_CONFIG_KEY.includes?(l) }
    .reject { |l| flag_config.has_key?(l) }, MAX_LIST)

# ---------------------------------------------------------------------------
# 2. Enum value sets: one source of truth for clap and the config validator.
#    A config file never passes through clap, so if the config validator uses a
#    different list (or none), an invalid value reaches ScanArgs verbatim.
# ---------------------------------------------------------------------------

report.group("enum value sets (single source of truth)")

enum_flags = scan_flags.reject { |f| f.possible.empty? }
report.check("flags with [possible values] found", "none in --help output") { enum_flags.size >= 8 }

# clap's rendered possible-values must equal the const the config validator
# uses; that is what makes them literally the same list.
const_mismatch = [] of String
unvalidated = [] of String
enum_flags.each do |f|
  key = flag_config[f.long]?
  next unless key
  next if FLAGS_WITHOUT_VALUE_CONST.has_key?(f.long)
  m = normalize_body.match(/&mut self\.#{Regex.escape(key)},\s*crate::cmd::scan::([A-Z0-9_]+),/m)
  unless m
    unvalidated << "#{f.long} (scan.#{key})"
    next
  end
  const_name = m[1]
  expected = consts[const_name]?
  if expected.nil?
    const_mismatch << "#{f.long}: #{const_name} not found in #{ARGS_RS}"
  elsif expected != f.possible
    const_mismatch << "#{f.long}: clap #{f.possible.inspect} != #{const_name} #{expected.inspect}"
  end
end

report.check_empty("every enum flag's config key is validated against a shared const", unvalidated, MAX_LIST)
report.check_empty("clap possible-values == the const the config validator uses", const_mismatch, MAX_LIST)

# Numeric/string defaults clap prints must equal the centralized DEFAULT_*
# consts the config precedence logic compares against — if they diverge, a
# config value silently loses (or wins) against a CLI default it should not.
DEFAULT_CONST_FOR_FLAG = {
  "timeout"                => "DEFAULT_TIMEOUT_SECS",
  "delay"                  => "DEFAULT_DELAY_MS",
  "workers"                => "DEFAULT_WORKERS",
  "max-concurrent-targets" => "DEFAULT_MAX_CONCURRENT_TARGETS",
  "max-targets-per-host"   => "DEFAULT_MAX_TARGETS_PER_HOST",
  "rate-limit"             => "DEFAULT_RATE_LIMIT",
  "retries"                => "DEFAULT_RETRIES",
  "retry-delay"            => "DEFAULT_RETRY_DELAY_MS",
  "waf-min-confidence"     => "DEFAULT_WAF_MIN_CONFIDENCE",
  "method"                 => "DEFAULT_METHOD",
}

default_drift = [] of String
DEFAULT_CONST_FOR_FLAG.each do |long, const_name|
  flag = flag_by_long[long]?
  unless flag
    default_drift << "#{long}: flag gone from --help (stale mapping)"
    next
  end
  want = scalars[const_name]?
  unless want
    default_drift << "#{long}: #{const_name} not found in #{ARGS_RS}"
    next
  end
  got = flag.default.join(" ")
  # Numeric consts render as `0.3`/`10`; compare as floats when both parse so
  # `0.3` vs `0.30` is not reported as drift.
  same = got == want || (got.to_f?.try { |g| want.to_f?.try { |w| g == w } } == true)
  default_drift << "--#{long}: clap default #{got.inspect} != #{const_name} #{want.inspect}" unless same
end
# `--encoders` is a list default; compare it against DEFAULT_ENCODERS, whose
# doc comment claims to be the canonical source (clap currently repeats the
# literal instead of referencing it, so this is the only thing tying them).
if enc = flag_by_long["encoders"]?
  want = consts["DEFAULT_ENCODERS"]? || [] of String
  default_drift << "--encoders: clap default #{enc.default.inspect} != DEFAULT_ENCODERS #{want.inspect}" if enc.default != want
end
report.check_empty("clap defaults == centralized DEFAULT_* consts", default_drift, MAX_LIST)

# ---------------------------------------------------------------------------
# 3. REST <-> MCP scan surface.
# ---------------------------------------------------------------------------

report.group("REST <-> MCP scan surface")

mcp_set = mcp_params.to_set
rest_mapped = rest_options.map { |o| REST_TO_MCP_ALIASES[o]? || o }

report.check_empty("every REST scan option exists on the MCP tool",
  rest_options.reject { |o| REST_ONLY_OPTIONS.includes?(o) }
    .reject { |o| mcp_set.includes?(REST_TO_MCP_ALIASES[o]? || o) }, MAX_LIST)

report.check_empty("every MCP scan param exists on the REST API",
  mcp_params.reject { |p| MCP_ONLY_PARAMS.includes?(p) }
    .reject { |p| rest_mapped.includes?(p) }, MAX_LIST)

# Stale allowlist entries are as bad as missing ones: they hide a re-introduced
# asymmetry behind a comment that is no longer true.
report.check_empty("REST->MCP alias list has no stale entries",
  REST_TO_MCP_ALIASES.keys.reject { |k| rest_options.includes?(k) }, MAX_LIST)
report.check_empty("REST-only allowlist has no stale entries",
  REST_ONLY_OPTIONS.reject { |k| rest_options.includes?(k) }, MAX_LIST)
report.check_empty("MCP-only allowlist has no stale entries",
  MCP_ONLY_PARAMS.reject { |k| mcp_params.includes?(k) }, MAX_LIST)

# A server/MCP option that maps to neither a CLI flag nor a config key is an
# option the engine cannot actually honour end-to-end.
config_key_set = config_keys.to_set
orphans = (rest_mapped + mcp_params).uniq
  .reject { |p| TRANSPORT_ONLY_OPTIONS.includes?(p) }
  .reject { |p| config_key_set.includes?(p) || flag_by_long.has_key?(p.tr("_", "-")) }
report.check_empty("every REST/MCP option maps to a CLI flag or config key", orphans, MAX_LIST)

# The MCP schema hard-codes a few defaults as literals (schemars renders them
# into the published tool schema); they must still equal the CLI's.
mcp_default_drift = [] of String
if m = mcp_src.match(/fn default_waf_min_confidence\(\) -> f64 \{\s*([0-9.]+)\s*\}/m)
  want = scalars["DEFAULT_WAF_MIN_CONFIDENCE"]?
  mcp_default_drift << "waf_min_confidence: MCP #{m[1]} != DEFAULT_WAF_MIN_CONFIDENCE #{want}" if want && m[1].to_f? != want.to_f?
else
  mcp_default_drift << "default_waf_min_confidence(): not found in #{MCP_RS}"
end
if m = mcp_src.match(/fn default_waf_bypass\(\) -> String \{\s*"([a-z]+)"/m)
  cli_default = flag_by_long["waf-bypass"]?.try(&.default.join(" "))
  mcp_default_drift << "waf_bypass: MCP #{m[1].inspect} != clap #{cli_default.inspect}" if cli_default && m[1] != cli_default
else
  mcp_default_drift << "default_waf_bypass(): not found in #{MCP_RS}"
end
report.check_empty("MCP literal defaults == CLI defaults", mcp_default_drift, MAX_LIST)

# ---------------------------------------------------------------------------
# 4. Agent surfaces: skills/ and the published .well-known copy.
#    The digest in index.json is the classic drift trap — SKILL.md gets edited
#    and the recorded hash is not refreshed, so clients keep the stale copy.
# ---------------------------------------------------------------------------

report.group("agent surfaces (skills/ + .well-known)")

skill_body = read(SKILL_MD)
published_body = read(WELLKNOWN_SKILL_MD)
index_raw = read(WELLKNOWN_INDEX)

report.check("skills/ SKILL.md exists", SKILL_MD) { !skill_body.empty? }
report.check("published SKILL.md exists", WELLKNOWN_SKILL_MD) { !published_body.empty? }
report.check_eq("skills/ SKILL.md == published .well-known copy",
  Digest::SHA256.hexdigest(skill_body), Digest::SHA256.hexdigest(published_body))

index = begin
  JSON.parse(index_raw)
rescue
  nil
end

if index
  entry = index["skills"].as_a.find { |s| s["name"]?.try(&.as_s?) == "dalfox" }
  if entry
    recorded = entry["digest"]?.try(&.as_s?) || ""
    actual = "sha256:" + Digest::SHA256.hexdigest(published_body)
    report.check_eq("index.json digest matches SKILL.md content", actual, recorded)

    # The discovery description and the SKILL.md frontmatter description are
    # two copies of one sentence; agents pick a skill off the former and act on
    # the latter, so a drift changes when the skill gets selected.
    # Crystal's `m` turns on BOTH line-anchored `^` and dot-matches-newline, so
    # the repeated line is spelled `[^\n]*` — with a bare `.` the indented-line
    # repetition swallows the whole document past the `---` terminator.
    fm = skill_body.match(/^description: >\n((?:[ ]{2}[^\n]*\n)+)/m)
    if fm
      folded = fm[1].lines.map(&.strip).join(" ").strip
      report.check_eq("index.json description == SKILL.md frontmatter description",
        folded, entry["description"]?.try(&.as_s?) || "")
    else
      report.fail("SKILL.md frontmatter description parsed", "no folded `description: >` block in #{SKILL_MD}")
    end
  else
    report.fail("index.json lists the dalfox skill", "no entry with name=dalfox in #{WELLKNOWN_INDEX}")
  end
else
  report.fail("index.json parses", "invalid JSON in #{WELLKNOWN_INDEX}")
end

# The skill bundle advertises a fixed tool count in prose ("6 tools" / "six
# tools"); adding or removing an MCP tool must update it.
NUMBER_WORDS = {1 => "one", 2 => "two", 3 => "three", 4 => "four", 5 => "five",
                6 => "six", 7 => "seven", 8 => "eight", 9 => "nine", 10 => "ten"}
tool_count = mcp_tools.size
count_forms = [tool_count.to_s, NUMBER_WORDS[tool_count]? || tool_count.to_s]
tool_count_drift = [] of String
# Only quantity words count as a claim — "MCP tools" / "external tools" are
# prose, not a count, and must not be read as one.
count_re = /\b(\d{1,2}|#{NUMBER_WORDS.values.join("|")})\s+tools\b/i
{SKILL_MD => skill_body, SKILL_MCP_REF => read(SKILL_MCP_REF), DOC_MCP_INT[0] => read(DOC_MCP_INT[0])}.each do |path, body|
  claims = body.scan(count_re).map { |m| m[1].downcase }
  bad = claims.reject { |c| count_forms.includes?(c) }
  tool_count_drift << "#{path}: claims #{bad.uniq.inspect} tools, code has #{tool_count}" unless bad.empty?
end
report.check_empty("tool-count claims match the #[tool] definitions (#{tool_count})", tool_count_drift, MAX_LIST)

skill_mcp_ref = read(SKILL_MCP_REF)
report.check_empty("every MCP tool is named in #{SKILL_MCP_REF}",
  mcp_tools.reject { |t| skill_mcp_ref.includes?(t) }, MAX_LIST)
# The reference bills this section as "scan_with_dalfox — Full Parameters", so
# it is a complete list by its own contract, not a curated sample.
report.check_empty("every MCP scan param is in #{SKILL_MCP_REF}",
  mcp_params.reject { |p| skill_mcp_ref.matches?(/\b#{Regex.escape(p)}\b/) }, MAX_LIST)

# skills/references/cli.md opens with "All flags are defined in ScanArgs" and
# tabulates them, so it too claims completeness. (server-and-payload.md says
# "Key Flags" — an explicit subset — and is therefore not checked.)
skill_cli_ref = read(SKILL_CLI_REF)
report.check_empty("every scan CLI flag is in #{SKILL_CLI_REF}",
  scan_flags.reject { |f| CLI_FLAGS_WITHOUT_CONFIG_KEY.includes?(f.long) }
    .reject(&.mentioned_in?(skill_cli_ref)), MAX_LIST)

# ---------------------------------------------------------------------------
# 5. Docs key reference (read-only; this script never edits docs/).
#    Both language variants are checked: a flag added to the EN reference but
#    not the KO one leaves half the site describing a different scanner.
# ---------------------------------------------------------------------------

report.group("docs key reference (EN + KO)")

DOC_CLI.each do |path|
  body = read(path)
  if body.empty?
    report.fail("#{path} readable", "missing")
    next
  end
  report.check_empty("every scan CLI flag in #{path}",
    scan_flags.reject { |f| CLI_FLAGS_WITHOUT_CONFIG_KEY.includes?(f.long) }
      .reject(&.mentioned_in?(body)), MAX_LIST)
end

DOC_CONFIG.each do |path|
  body = read(path)
  if body.empty?
    report.fail("#{path} readable", "missing")
    next
  end
  report.check_empty("every config key in #{path}",
    config_keys.reject { |k| body.matches?(/\b#{Regex.escape(k)}\b/) }, MAX_LIST)
end

DOC_SERVER.each do |path|
  body = read(path)
  if body.empty?
    report.fail("#{path} readable", "missing")
    next
  end
  report.check_empty("every server flag in #{path}",
    server_flags.reject { |f| SERVER_GLOBAL_FLAGS.includes?(f.long) }
      .reject(&.mentioned_in?(body)), MAX_LIST)
  report.check_empty("every REST scan option in #{path}",
    rest_options.reject { |o| body.matches?(/\b#{Regex.escape(o)}\b/) }, MAX_LIST)
end

DOC_MCP_INT.each do |path|
  body = read(path)
  if body.empty?
    report.fail("#{path} readable", "missing")
    next
  end
  report.check_empty("every MCP tool in #{path}",
    mcp_tools.reject { |t| body.includes?(t) }, MAX_LIST)
  report.check_empty("every MCP scan param in #{path}",
    mcp_params.reject { |p| body.matches?(/\b#{Regex.escape(p)}\b/) }, MAX_LIST)
end

exit report.finish
