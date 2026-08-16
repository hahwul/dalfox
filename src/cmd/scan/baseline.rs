//! `--baseline`: diff this run against a previous dalfox report so CI gates on
//! what is *new*, not on the whole backlog.
//!
//! Every run before this re-reported the same findings, which left no honest
//! failure threshold to set — `--limit` / `--only-poc` filter by *shape*, not by
//! *novelty*, so a pipeline gate was either permanently red or switched off.
//!
//! The baseline is an ordinary `--format json` / `--format jsonl` report: there
//! is no separate writer, and refreshing it is "accept the new findings, replace
//! the file".
//!
//! Failure is soft by design. An unreadable, malformed, or foreign-schema
//! baseline warns and disables the diff rather than failing the scan — a stale
//! path in a pipeline should not turn a working security scan into a red build
//! with no findings reported at all.

use crate::scanning::result::Result;
use serde::Deserialize;
use std::collections::HashSet;

use super::args::BASELINE_MODE_ANNOTATE;

/// Upper bound on a baseline report we will read into memory. Reports are
/// JSON/JSONL text; 64 MiB is far past any realistic backlog while still
/// failing fast on a path that resolves to something unbounded.
pub(crate) const MAX_BASELINE_BYTES: u64 = 64 << 20;

/// A loaded baseline, or a disabled one carrying the reason it was disabled.
///
/// Both cases are represented by the same type so the output path always has a
/// `baseline` block to report: an operator who passed `--baseline` and got no
/// suppression needs to see *why* in the same envelope as the findings.
pub(crate) struct Baseline {
    /// The `--baseline` path exactly as the operator typed it.
    pub(crate) path: String,
    /// `filter` or `annotate` (already validated by clap / config).
    pub(crate) mode: String,
    /// Identity keys of the findings recorded in the baseline report. Fewer
    /// than [`entries`] when the report holds several findings that share one
    /// identity (e.g. an `R` and a `V` for the same parameter and context).
    ///
    /// [`entries`]: Baseline::entries
    pub(crate) keys: HashSet<String>,
    /// How many finding entries the report actually contained. Reported as
    /// `meta.baseline.baseline_findings` so it lines up with the baseline
    /// file's own `findings_count` instead of the smaller deduplicated total.
    pub(crate) entries: usize,
    /// `Some` when the diff is disabled; the message is surfaced on stderr and
    /// in the structured `meta.baseline` block.
    pub(crate) warning: Option<String>,
}

impl Baseline {
    pub(crate) fn is_active(&self) -> bool {
        self.warning.is_none()
    }

    pub(crate) fn annotates(&self) -> bool {
        self.mode == BASELINE_MODE_ANNOTATE
    }

    /// True when this finding is absent from the baseline.
    pub(crate) fn is_new(&self, r: &Result) -> bool {
        !self.keys.contains(&key_for_result(r))
    }
}

/// The fields a finding's identity is derived from.
///
/// Named rather than positional: [`finding_key`] used to take these as nine
/// consecutive `&str` parameters, so any two could be swapped and still
/// compile. That is not a cosmetic risk here. The key is derived on two
/// independent paths — from a live [`Result`] and from a loaded
/// [`BaselineFinding`], whose field declaration orders differ — and both must
/// produce byte-identical keys. Transpose one and every finding either reads
/// as new (noise) or, under `filter` mode, collides with an unrelated one and
/// is suppressed: the silent false-clean this module exists to avoid.
struct FindingIdentity<'a> {
    data: &'a str,
    param: &'a str,
    location: &'a str,
    inject_type: &'a str,
    cwe: &'a str,
    tier: &'a str,
    evidence: &'a str,
    detection_method: &'a str,
    payload: &'a str,
}

/// Stable cross-run identity of a finding.
///
/// Deliberately built from *what the finding is* and not *how this particular
/// run happened to surface it*: the payload (and therefore the query string of
/// `data`), the payload index, the AST line/column, request/response captures,
/// timings and ordering are all excluded, so cosmetic scan-to-scan variation
/// does not read as a new finding.
///
/// Included:
///   - **host + path** via [`identity_path`],
///   - **parameter name** and its **wire location** (a `q` in the query and a
///     `q` in a cookie are different findings),
///   - **injection context** (`inject_type`) and **CWE**,
///   - **tier**, so an `R` that becomes a `V` on a later run is reported as new
///     — an escalation is exactly the thing a gate should catch,
///   - **evidence family**: the `Source: … , Sink: …` pair for AST findings
///     (two distinct DOM flows through the same parameter are two findings),
///     falling back to the detection method for everything else. The raw
///     evidence string is *not* used — it carries line/column numbers and
///     payload text that shift for unrelated reasons.
fn finding_key(id: FindingIdentity<'_>) -> String {
    format!(
        "v1|{}|{}|{}|{}|{}|{}|{}",
        identity_path(id.data, id.location, id.payload),
        id.param,
        id.location,
        id.inject_type,
        id.cwe,
        id.tier,
        evidence_family(id.evidence, id.detection_method),
    )
}

pub(crate) fn key_for_result(r: &Result) -> String {
    finding_key(FindingIdentity {
        data: &r.data,
        param: &r.param,
        location: &r.location,
        inject_type: &r.inject_type,
        cwe: &r.cwe,
        tier: r.result_type.short(),
        evidence: &r.evidence,
        detection_method: r.detection_method.as_str(),
        payload: &r.payload,
    })
}

/// The payload-invariant part of a finding URL: scheme + host + path, with the
/// query and fragment dropped and a payload-carrying trailing path segment
/// replaced by `*`.
///
/// Deliberately **not** `utils::target_identity_key` (the SARIF fingerprint
/// helper), which drops the whole last path segment for any URL without a
/// query. That is fine as the *containment* test it was written for, but as an
/// *identity* key it collapses sibling endpoints: a header/cookie/body finding
/// on `/api/v1/users` and one on `/api/v1/orders` would hash the same, and
/// under `filter` mode the second would be suppressed as already-known — a
/// silent false-clean, the one failure mode a gate must not have.
///
/// The trailing segment is only dropped when the payload actually lives there:
///   - `location == "Path"` — path-parameter injection replaces a segment,
///   - or the segment decodes to something containing the payload, which is how
///     `build_dom_xss_poc_url` renders a `location.pathname` DOM finding.
///
/// Anything we can't prove is payload-carrying keeps its full path. That errs
/// toward reporting a known finding as new (noise) rather than hiding a new one
/// (a missed vulnerability), which is the right direction for a CI gate.
fn identity_path(data: &str, location: &str, payload: &str) -> String {
    let no_fragment = data.split('#').next().unwrap_or(data);
    let path = no_fragment.split('?').next().unwrap_or(no_fragment);

    let Some(slash) = path.rfind('/') else {
        return path.to_string();
    };
    let (parent, last) = path.split_at(slash + 1);
    if last.is_empty() {
        return path.to_string();
    }

    if location == "Path" || segment_carries_payload(last, payload) {
        return format!("{}*", parent);
    }
    path.to_string()
}

/// Whether a path segment holds the payload — directly, or percent-encoded as
/// the `url` crate writes it when a DOM-XSS POC pushes the payload onto the path.
fn segment_carries_payload(segment: &str, payload: &str) -> bool {
    if payload.is_empty() {
        return false;
    }
    segment.contains(payload)
        || urlencoding::decode(segment)
            .map(|d| d.contains(payload))
            .unwrap_or(false)
}

/// Reduce an evidence string to the part that is stable across runs.
///
/// AST evidence looks like `"<url>:<line>:<col> - <desc> (Source: <s>, Sink:
/// <k>)"`. The line/column and URL move whenever the page's JavaScript is
/// re-bundled; the source→sink pair is the actual identity of the flow, and it
/// is what distinguishes two AST findings that share a parameter label. Every
/// other producer gets its detection method, which is constant per finding.
fn evidence_family(evidence: &str, detection_method: &str) -> String {
    if let Some((_, rest)) = evidence.split_once("(Source: ")
        && let Some((source, tail)) = rest.split_once(", Sink: ")
    {
        let sink = tail.strip_suffix(')').unwrap_or(tail);
        return format!("src={};sink={}", source.trim(), sink.trim());
    }
    detection_method.to_string()
}

/// The subset of a serialized finding needed to rebuild its identity key.
/// Every field defaults so an older report missing `location` or
/// `detection_method` still yields a usable key instead of being rejected.
#[derive(Deserialize)]
struct BaselineFinding {
    #[serde(rename = "type", default)]
    tier: String,
    #[serde(default)]
    inject_type: String,
    #[serde(default)]
    data: String,
    #[serde(default)]
    param: String,
    #[serde(default)]
    evidence: String,
    #[serde(default)]
    cwe: String,
    #[serde(default)]
    location: String,
    #[serde(default)]
    detection_method: String,
    #[serde(default)]
    payload: String,
}

/// Load `path`, returning a [`Baseline`] that is either active or carries the
/// reason the diff was disabled. Never fails the scan.
pub(crate) fn load(path: &str, mode: &str) -> Baseline {
    let disabled = |warning: String| Baseline {
        path: path.to_string(),
        mode: mode.to_string(),
        keys: HashSet::new(),
        entries: 0,
        warning: Some(warning),
    };

    let raw = match crate::utils::fs::read_bounded(
        std::path::Path::new(path),
        MAX_BASELINE_BYTES,
        "baseline report",
    ) {
        Ok(s) => s,
        Err(e) => return disabled(format!("--baseline '{}' could not be read: {}", path, e)),
    };

    let (meta, findings) = match parse_report(&raw) {
        Ok(v) => v,
        Err(e) => {
            return disabled(format!(
                "--baseline '{}' is not a dalfox JSON/JSONL report: {}",
                path, e
            ));
        }
    };

    // Reject a report written by a different major version rather than diffing
    // against a schema whose field meanings we can't vouch for. Missing version
    // metadata is tolerated (hand-assembled baselines are a legitimate use).
    if let Some(v) = meta
        .as_ref()
        .and_then(|m| m.get("dalfox_version"))
        .and_then(|v| v.as_str())
    {
        let current = env!("CARGO_PKG_VERSION");
        if major_of(v) != major_of(current) {
            return disabled(format!(
                "--baseline '{}' was written by dalfox {} but this is {} (incompatible report schema)",
                path, v, current
            ));
        }
    }

    let total = findings.len();
    let mut keys = HashSet::with_capacity(total);
    for value in findings {
        let Ok(f) = serde_json::from_value::<BaselineFinding>(value) else {
            continue;
        };
        // A finding with no target URL and no parameter carries no identity —
        // it is either not a finding object or a schema we don't understand.
        if f.data.is_empty() && f.param.is_empty() {
            continue;
        }
        keys.insert(finding_key(FindingIdentity {
            data: &f.data,
            param: &f.param,
            location: &f.location,
            inject_type: &f.inject_type,
            cwe: &f.cwe,
            tier: &f.tier,
            evidence: &f.evidence,
            detection_method: &f.detection_method,
            payload: &f.payload,
        }));
    }

    // Entries were present but none of them looked like findings: the file
    // parses as JSON but isn't a report we can diff against.
    if total > 0 && keys.is_empty() {
        return disabled(format!(
            "--baseline '{}' has {} entries but none carry a recognizable finding schema",
            path, total
        ));
    }

    Baseline {
        path: path.to_string(),
        mode: mode.to_string(),
        keys,
        entries: total,
        warning: None,
    }
}

/// Major-version component of a semver-ish string (`"3.1.0"` → `"3"`).
fn major_of(v: &str) -> &str {
    v.split('.').next().unwrap_or(v)
}

/// Accept both report shapes dalfox emits, plus the bare findings array the
/// `results_to_json` helper produces:
///   - `--format json`  → `{ "meta": {...}, "findings": [...] }`
///   - `--format jsonl` → a `{"meta": {...}}` line followed by one finding/line
///   - bare `[ {...}, ... ]`
fn parse_report(
    raw: &str,
) -> std::result::Result<(Option<serde_json::Value>, Vec<serde_json::Value>), String> {
    if raw.trim().is_empty() {
        return Err("file is empty".to_string());
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) {
        return match value {
            serde_json::Value::Object(mut map) => match map.remove("findings") {
                Some(serde_json::Value::Array(findings)) => Ok((map.remove("meta"), findings)),
                // A clean `--format jsonl` run writes exactly one line — the
                // meta envelope — which whole-file JSON parsing happily accepts
                // as an object with no `findings`. Rejecting it would break the
                // documented "record the backlog once, diff every run after"
                // flow for any repo whose first scan is clean: the baseline
                // would be permanently unreadable and every later run would
                // report its whole backlog as new.
                //
                // Matched on `{"meta": …}` and nothing else, so the `--dry-run`
                // and `--only-discovery` envelopes — which also carry a `meta`
                // but describe a plan, not findings — are still rejected rather
                // than silently read as an empty backlog.
                _ if map.len() == 1 && map.contains_key("meta") => {
                    Ok((map.remove("meta"), Vec::new()))
                }
                _ => Err("top-level object has no `findings` array".to_string()),
            },
            serde_json::Value::Array(findings) => Ok((None, findings)),
            _ => Err("top-level value is neither an object nor an array".to_string()),
        };
    }

    // JSONL. A single malformed line is a corrupt report, not a partial one —
    // silently diffing against half a baseline would suppress real findings.
    let mut meta = None;
    let mut findings = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("line {}: {}", i + 1, e))?;
        match value {
            serde_json::Value::Object(mut map) => {
                if let Some(m) = map.remove("meta") {
                    meta = Some(m);
                } else {
                    findings.push(serde_json::Value::Object(map));
                }
            }
            _ => return Err(format!("line {}: not a JSON object", i + 1)),
        }
    }
    if meta.is_none() && findings.is_empty() {
        return Err("no JSON objects found".to_string());
    }
    Ok((meta, findings))
}

#[cfg(test)]
mod tests;

/// Load `--baseline` before any request goes out.
///
/// Up front on purpose: a stale or malformed baseline path is exactly what a
/// pipeline gets wrong, and finding out after a 20-minute scan is too late.
/// The warnings go to stderr for every format (stdout stays a clean machine
/// payload) rather than through `log_warn`, which only speaks in `plain`.
pub(crate) fn load_from_args(args: &super::args::ScanArgs) -> Option<Baseline> {
    args.baseline.as_ref().map(|path| {
        // `--output` pointed at the baseline overwrites it with this run's
        // report. Under the default `filter` mode that report holds only the
        // NEW findings, so the recorded backlog is destroyed and the next run
        // re-reports all of it. Refreshing a baseline means re-running WITHOUT
        // `--baseline`; warn rather than refuse, since `annotate` mode writes a
        // complete report and is a legitimate way to do it.
        if args.output.as_deref() == Some(path.as_str()) {
            eprintln!(
                "Warning: --output and --baseline are the same path ('{}'); under --baseline-mode filter this overwrites the baseline with new findings only. Re-run without --baseline to refresh it.",
                path
            );
        }
        // `--limit` stops the scan once N findings accrue, and that count is
        // taken before the baseline diff runs. A target whose first N findings
        // are all already known therefore halts early and reports zero new
        // findings without having tested the rest of its parameters.
        if args.limit.is_some() {
            eprintln!(
                "Warning: --limit counts findings before the --baseline diff, so a run whose first {} findings are all in the baseline stops early and reports 0 new. Drop --limit when gating on new findings.",
                args.limit.unwrap_or(0)
            );
        }
        let loaded = load(path, args.baseline_mode());
        match &loaded.warning {
            Some(w) => eprintln!("Warning: {} — baseline diff disabled", w),
            None => super::logging::log_info(
                args,
                &format!(
                    "baseline loaded: {} known findings from {}",
                    loaded.entries, path
                ),
            ),
        }
        loaded
    })
}
