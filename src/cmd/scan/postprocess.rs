//! Result post-processing: context extraction, priority scoring, and
//! AST-finding deduplication. Split out of the monolithic `scan.rs` so the
//! scan orchestrator only orchestrates.

use crate::scanning::result::{FindingType, Result};
use std::collections::HashMap;

pub(crate) fn extract_context(response: &str, payload: &str) -> Option<(usize, String)> {
    for (line_num, line) in response.lines().enumerate() {
        if let Some(pos) = line.find(payload) {
            let context = if line.len() > 40 {
                let start = pos.saturating_sub(20);
                let end = (pos + payload.len() + 20).min(line.len());
                // Use get to avoid panic on multibyte boundaries
                line.get(start..end).unwrap_or(line).to_string()
            } else {
                line.to_string()
            };
            return Some((line_num + 1, context));
        }
    }
    None
}

fn result_priority(result: &Result) -> u8 {
    let type_score = match result.result_type {
        FindingType::Verified => 3,
        FindingType::AstDetected => 2,
        FindingType::Reflected => 1,
    };
    let severity_score = match result.severity.as_str() {
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0,
    };
    type_score * 10 + severity_score
}

// AST findings can be produced in multiple scan stages (preflight/probe/reflection loop).
// Keep one strongest result per equivalent AST fingerprint to reduce duplicate noise.
pub(crate) fn dedupe_ast_results(results: Vec<Result>) -> Vec<Result> {
    let mut out: Vec<Result> = Vec::with_capacity(results.len());
    let mut ast_index_by_key: HashMap<String, usize> = HashMap::new();

    for result in results {
        if result.message_id != 0 {
            out.push(result);
            continue;
        }

        // Use evidence-centric fingerprint so duplicates across stages
        // (preflight/probe/reflection loop) collapse into one.
        let key = format!(
            "{}|{}|{}",
            result.inject_type, result.method, result.evidence
        );

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
