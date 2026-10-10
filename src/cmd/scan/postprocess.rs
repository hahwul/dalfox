//! Result post-processing: context extraction, priority scoring, and
//! AST-finding deduplication. Split out of the monolithic `scan.rs` so the
//! scan orchestrator only orchestrates.

use crate::scanning::result::{Confidence, FindingType, Result};
use std::collections::HashMap;

pub(crate) fn extract_context(response: &str, payload: &str) -> Option<(usize, String)> {
    for (line_num, line) in response.lines().enumerate() {
        if let Some(pos) = line.find(payload) {
            let context = if line.len() > 40 {
                let mut start = pos.saturating_sub(20);
                let mut end = (pos + payload.len() + 20).min(line.len());
                // `pos` and the payload end are boundaries; only the ±20
                // padding can land inside a multibyte char. Snap outward
                // (`len()` is always a boundary, so both loops terminate)
                // rather than falling back to the whole — possibly 64 KiB — line.
                while !line.is_char_boundary(start) {
                    start -= 1;
                }
                while !line.is_char_boundary(end) {
                    end += 1;
                }
                line[start..end].to_string()
            } else {
                line.to_string()
            };
            return Some((line_num + 1, context));
        }
    }
    None
}

/// Dedup rank: type, then severity, then confidence (`high` > `low` >
/// ungraded). Compared as a tuple so each axis only breaks ties in the one
/// before it.
fn result_priority(result: &Result) -> (u8, u8, u8) {
    let type_score = match result.result_type {
        FindingType::Verified => 3,
        FindingType::AstDetected => 2,
        FindingType::Reflected => 1,
        // Informational findings never enter the AST-dedup path (message_id != 0);
        // this arm exists only for match exhaustiveness.
        FindingType::Informational => 0,
    };
    let severity_score = match result.severity.as_str() {
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0,
    };
    let confidence_score = match result.confidence {
        Some(Confidence::High) => 2,
        Some(Confidence::Low) => 1,
        None => 0,
    };
    (type_score, severity_score, confidence_score)
}

/// Evidence-centric fingerprint [`dedupe_ast_results`] collapses AST findings
/// on, so duplicates across stages (initial pass, and once per parameter in the
/// scan loop) fold into one. `None` for non-AST findings, which are never
/// merged. Shared with the `--stream-findings` printer so the live output folds
/// the same duplicates the final report does.
pub(crate) fn ast_dedup_key(result: &Result) -> Option<String> {
    ast_dedup_parts(result).map(|(t, m, e)| format!("{t}|{m}|{e}"))
}

/// [`ast_dedup_key`]'s fields, borrowed, for hot paths that must not allocate
/// per result.
pub(crate) fn ast_dedup_parts(result: &Result) -> Option<(&str, &str, &str)> {
    (result.message_id == 0).then_some((&result.inject_type, &result.method, &result.evidence))
}

// AST findings can be produced in multiple scan stages (preflight/probe/reflection loop).
// Keep one strongest result per equivalent AST fingerprint to reduce duplicate noise.
pub(crate) fn dedupe_ast_results(results: Vec<Result>) -> Vec<Result> {
    let mut out: Vec<Result> = Vec::with_capacity(results.len());
    let mut ast_index_by_key: HashMap<String, usize> = HashMap::new();

    for result in results {
        let Some(key) = ast_dedup_key(&result) else {
            out.push(result);
            continue;
        };

        if let Some(existing_idx) = ast_index_by_key.get(&key).copied() {
            if result_priority(&result) > result_priority(&out[existing_idx]) {
                out[existing_idx] = result;
            }
        } else {
            ast_index_by_key.insert(key, out.len());
            out.push(result);
        }
    }

    out
}
