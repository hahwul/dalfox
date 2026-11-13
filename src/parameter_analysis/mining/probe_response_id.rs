//! Mining: probe response ids/names. See module docs in `mod.rs`.

use super::*;
use std::sync::OnceLock;

/// A plausible parameter name: ASCII identifier start, then the characters
/// real query keys use (`user.name`, `items[]`, `utm-source`). Capped at 64 so
/// a minified blob cannot hand the miner a kilobyte "name".
const JS_PARAM_NAME: &str = r"[A-Za-z_][A-Za-z0-9_.\-\[\]]{0,63}";

/// Most bundle-derived names DOM mining probes for one target. A bundle
/// carries other servers' URLs and minifier noise along with the app's own
/// keys: on a 142-site corpus of real homepages, the same-origin bundles gave
/// a median of 11 distinct names per site, p90 53, max 280. This holds what
/// `--analyze-external-js` adds to mining to one canary bucket.
pub(super) const MAX_BUNDLE_MINING_PARAMS: usize = 64;

/// `?name=` / `&name=`. The caller keeps a match only when the byte after it
/// is not another `=` (`a&&b==c`, checked without consuming it, so `?a=&b=`
/// keeps `b`) and when [`in_url_string`] places the `?`/`&` inside a string.
fn js_query_key_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(&format!(r"[?&]({JS_PARAM_NAME})="))
            .expect("js_query_key_regex is a valid pattern")
    })
}

/// The string argument of a `URLSearchParams` read: `.get('q')`,
/// `.getAll("q")`, `.has(`q`)`. A template literal with `${` cannot match.
fn js_param_getter_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(&format!(
            r#"\.(?:get|getAll|has)\(\s*["'`]({JS_PARAM_NAME})["'`]\s*\)"#
        ))
        .expect("js_param_getter_regex is a valid pattern")
    })
}

/// Bytes that can sit between the start of a URL string and one of its
/// `?` / `&` separators.
fn is_url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"_-./:%~=&?#@".contains(&b)
}

/// Whether the `?`/`&` at `at` sits inside a string literal: walking back over
/// URL bytes reaches a quote, or the `}` closing a template `${…}`. Minified
/// code is full of ternary assignments (`c?t=1:2`, `(e?n.x=…`) that the
/// query-key regex also matches. Walking back from those reaches code
/// instead, and a string comparison in front of one (`"x"==e?t=`) is caught
/// by its `==`.
fn in_url_string(js: &[u8], at: usize) -> bool {
    let floor = at.saturating_sub(256);
    let mut start = at;
    while start > floor && is_url_byte(js[start - 1]) {
        start -= 1;
    }
    start > 0
        && matches!(js[start - 1], b'"' | b'\'' | b'`' | b'}')
        && !js[start..at].windows(2).any(|w| w == b"==")
}

/// Query-parameter names a page's own JavaScript references: URL query keys,
/// then getter arguments, each in source order (deterministic, so the
/// `cap_dom_params` cut is stable across runs). May repeat; the caller dedups.
///
/// Text-level on purpose, not an oxc parse: every name here is only a mining
/// candidate, confirmed by a reflection probe, so a stray match costs one
/// bucket slot and never a finding. A text scan also keeps working on the
/// minified or unparseable bundles an AST parse would drop, and the `regex`
/// crate runs in linear time, so hostile page JS cannot stall it.
pub(crate) fn js_param_candidates(js: &str) -> Vec<String> {
    let bytes = js.as_bytes();
    let query_keys = js_query_key_regex().captures_iter(js).filter(|caps| {
        caps.get(0)
            .is_some_and(|m| bytes.get(m.end()) != Some(&b'=') && in_url_string(bytes, m.start()))
    });
    let getters = js_param_getter_regex().captures_iter(js);
    query_keys
        .chain(getters)
        .filter_map(|caps| caps.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

/// A name shaped like a real query key (`page`, `utm-source`, `items[]`), as
/// opposed to the dotted or indexed expressions minified bundles leak
/// (`r.src`, `t[e]`).
fn is_plain_param_name(name: &str) -> bool {
    name.trim_end_matches("[]")
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Append the bundle names (recorded on the target by the external-JS pass)
/// that `names` does not hold yet: plain names first, then the rest, cut at
/// [`MAX_BUNDLE_MINING_PARAMS`]. The sort is stable, so the cut is the same
/// on every run. Appending after the page's own names keeps `cap_dom_params`
/// from ever evicting an input or inline-script name for a bundle one.
pub(super) fn append_bundle_names(names: &mut Vec<String>, bundle: &[String]) {
    let existing: HashSet<&str> = names.iter().map(String::as_str).collect();
    let mut seen = HashSet::new();
    let mut fresh: Vec<&String> = bundle
        .iter()
        .filter(|n| !existing.contains(n.as_str()) && seen.insert(n.as_str()))
        .collect();
    fresh.sort_by_key(|n| !is_plain_param_name(n));
    let add: Vec<String> = fresh
        .into_iter()
        .take(MAX_BUNDLE_MINING_PARAMS)
        .cloned()
        .collect();
    names.extend(add);
}

/// Distinct candidate names in document order: `<input>` id/name values
/// first, then names the page's JavaScript references (see
/// [`js_param_candidates`]). Order matters: the result is truncated by
/// `cap_dom_params`, which keeps the front, so a JS-heavy page can never evict
/// an input name; and a hash-order set made the kept subset differ from run to
/// run. The `scraper::Html` (which is `!Send`) stays inside this function.
pub(super) fn dom_candidate_names(text: &str) -> Vec<String> {
    let document = crate::utils::html::parse_document_bounded(text);
    let selector = selectors::input_with_id_or_name();
    let mut seen: HashSet<String> = HashSet::new();
    let mut names = Vec::new();
    for element in document.select(selector) {
        for attr in [element.value().attr("id"), element.value().attr("name")]
            .into_iter()
            .flatten()
        {
            if seen.insert(attr.to_string()) {
                names.push(attr.to_string());
            }
        }
    }
    for js in crate::scanning::ast_integration::js_blocks_from_document(&document) {
        for name in js_param_candidates(&js) {
            if seen.insert(name.clone()) {
                names.push(name);
            }
        }
    }
    names
}

pub async fn probe_response_id_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ShimmerSpinner>,
) {
    let client = target.build_client_or_default();
    let preexisting = snapshot_param_slots(&reflection_params).await;

    // The base HTML. The copy form discovery shared is fine for candidate
    // names, but it predates the dictionary miner's whole bucket run, so it is
    // not used as this miner's baseline sample: calibration takes fresh ones.
    // Without a usable shared copy, fetch it here and keep the old shortcut —
    // that response is a free first baseline sample for the bucket engine.
    let (base, fresh) = match crate::parameter_analysis::cached_base_response() {
        Some(base) if !base.is_server_error() => (base, false),
        _ => match crate::parameter_analysis::fetch_base_response(target).await {
            Some(base) => (base, true),
            None => return,
        },
    };
    if base.is_server_error() {
        return;
    }
    let status = base.status;
    let location = base.location.clone();
    let text = base.body.as_str();

    // Scope the scraper::Html (which is !Send) strictly to this block so the
    // owned candidate list is all that crosses the subsequent async engine.
    let mut params_to_check = dom_candidate_names(text);
    append_bundle_names(&mut params_to_check, &target.bundle_param_names);

    // Cap the DOM candidate set so a hostile/huge response body cannot fan
    // out into one task/request per attribute. Bucketing then bounds the live
    // task count again while retaining the full capped candidate surface.
    let (params_to_check, capped_from) = cap_dom_params(params_to_check);
    if let Some(original) = capped_from
        && !args.silence
    {
        eprintln!(
            "[mining] DOM candidate params capped to {} (from {}); reduce reflected fields or use --skip-mining",
            MAX_DOM_MINING_PARAMS, original
        );
    }

    let baseline = fresh.then(|| QueryBaseline::from_response(status, text, location.as_deref()));
    let query_ctx = QueryMiningContext {
        target,
        args,
        reflection_params,
        semaphore,
        pb,
        client,
    };
    probe_query_candidates(&query_ctx, params_to_check, preexisting, "DOM", baseline).await;
}
