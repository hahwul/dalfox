//! # Stage 1: Discovery
//!
//! Identifies which parameters reflect user input in the HTTP response.
//!
//! **Input:** `Target` (URL, method, headers, cookies) + `ScanArgs` flags.
//!
//! **Output:** Appends `Param` entries to the shared `reflection_params` list.
//! Each `Param` carries:
//! - `name`, `value`, `location` (Query/Body/Header/Path/Fragment)
//! - `valid_specials` / `invalid_specials` — **naive** classification based on
//!   whether the character already appears in the response body (not yet
//!   actively probed).
//! - `injection_context` — **naive** guess from surrounding HTML/JS context.
//! - `pre_encoding` — `None` at this stage (set later in Stage 3).
//!
//! **Side effects:** HTTP requests (one per parameter per location type).
//! Respects `--skip-discovery`, `--skip-reflection-header`, etc.

use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::{Location, Param, ReflectionAnalysis};
use crate::scanning::url_inject::build_injected_url;
use crate::target_parser::Target;
use std::sync::{Arc, OnceLock};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{Duration, sleep};

use crate::scanning::selectors;

/// Cached regex for detecting JSON.stringify patterns in JavaScript source.
fn json_stringify_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r#"JSON\.stringify\(\s*\{([^}]+)\}\s*\)"#)
            .expect("json_stringify_regex is a valid pattern")
    })
}

/// Cached regex for extracting key names from JSON-like object literals.
fn json_key_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r#"["']?(\w+)["']?\s*:"#).expect("json_key_regex is a valid pattern")
    })
}

/// Names the operator explicitly targeted with `-p name:<wanted>` (e.g.
/// `-p Referer:header`, `-p sid:cookie`, `-p file:multipart`). These are
/// explicit injection points, so callers probe them even when the matching
/// `--skip-reflection-*` sweep (or the mining phase) is disabled — mirroring
/// how `-d` body params are honored under `--skip-mining`.
pub(crate) fn explicit_param_names(param_specs: &[String], wanted: &str) -> Vec<String> {
    param_specs
        .iter()
        .filter_map(|spec| {
            // Parse "name:type" the same way `filter_params` does (parts[0] /
            // parts[1]) so the two never disagree on what was targeted.
            let parts: Vec<&str> = spec.split(':').collect();
            match parts.as_slice() {
                [name, ty, ..] if *ty == wanted && !name.is_empty() => Some(name.to_string()),
                _ => None,
            }
        })
        .collect()
}

pub async fn check_discovery(
    target: &mut Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    if !args.skip_discovery {
        check_query_discovery(target, reflection_params.clone(), semaphore.clone()).await;
        // The header/cookie reflection *sweeps* are gated by
        // `--skip-reflection-header` / `--skip-reflection-cookie`, but a
        // header/cookie named explicitly via `-p name:header` / `:cookie` is an
        // explicit injection point and is probed regardless. That gating now
        // lives inside each function (see `explicit_param_names`).
        check_header_discovery(target, args, reflection_params.clone(), semaphore.clone()).await;
        check_cookie_discovery(target, args, reflection_params.clone(), semaphore.clone()).await;
        // Path discovery (respects --skip-reflection-path)
        if !args.skip_reflection_path {
            check_path_discovery(target, reflection_params.clone(), semaphore.clone()).await;
        }
        // Form discovery: parse HTML forms and test POST parameters
        check_form_discovery(target, reflection_params.clone(), semaphore.clone()).await;
        // Fragment discovery: extract params from URL hash fragments (client-side only)
        check_fragment_discovery(target, reflection_params.clone()).await;
    }
    // Each `check_*_discovery` extends `reflection_params` independently,
    // so a URL like `/search.jsp?query=…` whose response also embeds
    // `<form><input name="query">` lands the same (name, location) twice
    // — once from `check_query_discovery`, once from
    // `check_form_discovery`. Without dedup we'd double the scan cost
    // and double every POC line. Collapse here before handing the list
    // to the scanner.
    {
        let mut guard = reflection_params.lock().await;
        dedupe_reflection_params(&mut guard);
    }
    target.reflection_params = reflection_params.lock().await.clone();
}

/// Collapse duplicate `Param` entries that share the same identity
/// (name, location, effective wire name, pre-encoding pipeline). When
/// two entries describe the same wire slot, merge their metadata in
/// place: keep the entry with the richer `injection_context` /
/// `valid_specials` / `invalid_specials` / `framework_sink`, and union
/// the special-character sets so later payload generation sees the
/// widest valid surface either probe observed.
///
/// `(name, location, effective_wire_name, pre_encoding_pipeline)` is
/// the smallest set of fields that meaningfully distinguishes one
/// injection point from another at scan time — same name in a query
/// vs body slot is two different sinks, but two pushes of `?query=`
/// from the URL and from a `<form>` echo are not.
pub(crate) fn dedupe_reflection_params(params: &mut Vec<Param>) {
    use std::collections::HashSet;

    if params.len() <= 1 {
        return;
    }

    let key_of = |p: &Param| -> String {
        let pipe = p
            .pre_encoding_pipeline
            .as_ref()
            .map(|p| format!("{:?}", p))
            .unwrap_or_default();
        format!(
            "{}|{:?}|{}|{}",
            p.name,
            p.location,
            p.effective_wire_name(),
            pipe
        )
    };

    // First pass: collect indexes per key so we can merge metadata into
    // the canonical entry (the first occurrence) before discarding the
    // rest. Using stable ordering by index keeps deterministic output.
    let mut seen: HashSet<String> = HashSet::with_capacity(params.len());
    let mut keep: Vec<usize> = Vec::with_capacity(params.len());
    let mut merge_into: Vec<Vec<usize>> = Vec::with_capacity(params.len());

    for (idx, p) in params.iter().enumerate() {
        let key = key_of(p);
        if seen.insert(key.clone()) {
            keep.push(idx);
            merge_into.push(Vec::new());
        } else {
            // Find the canonical slot for this key.
            let canonical = keep
                .iter()
                .position(|&i| key_of(&params[i]) == key)
                .expect("key was inserted above");
            merge_into[canonical].push(idx);
        }
    }

    if keep.len() == params.len() {
        return; // no duplicates
    }

    // Materialise the merged set out-of-place to keep borrow scopes
    // simple while we touch multiple indexes.
    let mut merged: Vec<Param> = Vec::with_capacity(keep.len());
    for (slot, &canonical_idx) in keep.iter().enumerate() {
        let mut base = params[canonical_idx].clone();
        for &dup_idx in &merge_into[slot] {
            let other = &params[dup_idx];
            if base.injection_context.is_none() && other.injection_context.is_some() {
                base.injection_context = other.injection_context.clone();
            }
            // Keep the observed-prefix JS breakout (#1073) when only one probe
            // landed inside a `<script>`, mirroring the injection_context merge
            // above so the per-parameter carrier survives dedup.
            if base.js_breakout.is_none() && other.js_breakout.is_some() {
                base.js_breakout = other.js_breakout.clone();
            }
            if base.framework_sink.is_none() && other.framework_sink.is_some() {
                base.framework_sink = other.framework_sink.clone();
            }
            if base.pre_encoding.is_none() && other.pre_encoding.is_some() {
                base.pre_encoding = other.pre_encoding.clone();
            }
            if base.form_action_url.is_none() && other.form_action_url.is_some() {
                base.form_action_url = other.form_action_url.clone();
            }
            if base.form_origin_url.is_none() && other.form_origin_url.is_some() {
                base.form_origin_url = other.form_origin_url.clone();
            }
            // Union the special-char sets: a char marked valid by
            // either probe should stay valid; a char marked invalid by
            // both stays invalid. The discovery probes are noisy so
            // taking the wider valid set lets the payload generator
            // exercise everything either run could land.
            base.valid_specials =
                merge_char_sets(base.valid_specials.take(), other.valid_specials.clone());
            base.invalid_specials =
                intersect_char_sets(base.invalid_specials.take(), other.invalid_specials.clone());
        }
        merged.push(base);
    }
    *params = merged;
}

fn merge_char_sets(a: Option<Vec<char>>, b: Option<Vec<char>>) -> Option<Vec<char>> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(mut a), Some(b)) => {
            for c in b {
                if !a.contains(&c) {
                    a.push(c);
                }
            }
            Some(a)
        }
    }
}

fn intersect_char_sets(a: Option<Vec<char>>, b: Option<Vec<char>>) -> Option<Vec<char>> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(a), Some(b)) => Some(a.into_iter().filter(|c| b.contains(c)).collect()),
    }
}

mod cookie;
mod form;
mod fragment;
mod header;
mod path;
mod query;

use cookie::*;
use form::*;
use fragment::*;
use header::*;
use path::*;
use query::*;

#[cfg(test)]
mod tests;
