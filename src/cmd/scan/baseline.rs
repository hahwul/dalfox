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
    /// Identity keys of the findings recorded in the baseline report.
    pub(crate) keys: HashSet<String>,
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

/// Stable cross-run identity of a finding.
///
/// Deliberately built from *what the finding is* and not *how this particular
/// run happened to surface it*: the payload (and therefore the query string of
/// `data`), the payload index, the AST line/column, request/response captures,
/// timings and ordering are all excluded, so cosmetic scan-to-scan variation
/// does not read as a new finding.
///
/// Included:
///   - **host + path** via [`crate::utils::target_identity_key`], the same
///     payload-invariant key SARIF `partialFingerprints` use,
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
#[allow(clippy::too_many_arguments)]
fn finding_key(
    data: &str,
    param: &str,
    location: &str,
    inject_type: &str,
    cwe: &str,
    tier: &str,
    evidence: &str,
    detection_method: &str,
) -> String {
    format!(
        "v1|{}|{}|{}|{}|{}|{}|{}",
        crate::utils::target_identity_key(data),
        param,
        location,
        inject_type,
        cwe,
        tier,
        evidence_family(evidence, detection_method),
    )
}

pub(crate) fn key_for_result(r: &Result) -> String {
    finding_key(
        &r.data,
        &r.param,
        &r.location,
        &r.inject_type,
        &r.cwe,
        r.result_type.short(),
        &r.evidence,
        r.detection_method.as_str(),
    )
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
}

/// Load `path`, returning a [`Baseline`] that is either active or carries the
/// reason the diff was disabled. Never fails the scan.
pub(crate) fn load(path: &str, mode: &str) -> Baseline {
    let disabled = |warning: String| Baseline {
        path: path.to_string(),
        mode: mode.to_string(),
        keys: HashSet::new(),
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
        keys.insert(finding_key(
            &f.data,
            &f.param,
            &f.location,
            &f.inject_type,
            &f.cwe,
            &f.tier,
            &f.evidence,
            &f.detection_method,
        ));
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
