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
use crate::parameter_analysis::{
    Location, Param, classify_special_chars, detect_injection_context,
};
use crate::scanning::url_inject::build_injected_url;
use crate::target_parser::Target;
use scraper;
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

/// Extract parameters from URL hash fragments for AST DOM-XSS analysis
/// correlation.
///
/// Handles two formats:
/// - SPA routing: `#/path?key=value&key2=value2`
/// - Simple fragments: `#key=value&key2=value2`
///
/// No HTTP requests are needed — fragments are client-side only — and
/// the run_scanning loop now skips `Location::Fragment` params for
/// reflection probes (HTTP servers never see the fragment) to avoid the
/// "discovered but never fuzzed" phantom that dogfood surfaced. The
/// params still get registered so the AST DOM analyzer can correlate a
/// `location.hash`-source finding with the user-supplied key.
pub async fn check_fragment_discovery(target: &Target, reflection_params: Arc<Mutex<Vec<Param>>>) {
    let frag = match target.url.fragment() {
        Some(f) if !f.is_empty() => f,
        _ => return,
    };

    // Split fragment into optional route prefix and query portion.
    // e.g. "/redir?url=value" => route prefix "/redir", query "url=value"
    // e.g. "key=value" => route prefix "", query "key=value"
    let query_part = if let Some(q_pos) = frag.find('?') {
        &frag[q_pos + 1..]
    } else {
        frag
    };

    if query_part.is_empty() {
        return;
    }

    let mut params = reflection_params.lock().await;
    for pair in query_part.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = if let Some((k, v)) = pair.split_once('=') {
            (k.to_string(), v.to_string())
        } else {
            (pair.to_string(), String::new())
        };
        if key.is_empty() {
            continue;
        }
        // Avoid duplicates
        if params
            .iter()
            .any(|p| p.name == key && p.location == Location::Fragment)
        {
            continue;
        }
        params.push(Param {
            name: key,
            value,
            location: Location::Fragment,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            pre_encoding_pipeline: None,
            wire_name: None,
            form_action_url: None,
            form_origin_url: None,
            framework_sink: None,
        });
    }
}

pub async fn check_query_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let arc_target = Arc::new(target.clone());
    let client = target.build_client_or_default();
    let test_value = crate::scanning::markers::bracketed_marker();

    let mut handles = vec![];

    // Check existing query params for reflection
    for (name, value) in target.url.query_pairs() {
        let tmp_param = Param {
            name: name.to_string(),
            value: String::new(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
            pre_encoding: None,
            pre_encoding_pipeline: None,
            wire_name: None,
            form_action_url: None,
            form_origin_url: None,
            framework_sink: None,
        };
        let url_str = build_injected_url(&target.url, &tmp_param, test_value);
        let url = url::Url::parse(&url_str).expect("build_injected_url produces valid URL");
        let client_clone = client.clone();
        let data = target.data.clone();
        let parsed_method = target.parse_method();
        let delay = target.delay;
        let semaphore_clone = semaphore.clone();
        let name = name.to_string();
        let value = value.to_string();
        let target_clone = arc_target.clone();

        // Spawn a task that returns Option<Param> instead of locking per discovery.
        let handle = tokio::spawn(async move {
            let permit = semaphore_clone
                .acquire()
                .await
                .expect("acquire semaphore permit");
            let m = parsed_method;
            let request =
                crate::utils::build_request(&client_clone, &target_clone, m, url, data.clone());
            crate::tick_request_count();
            let mut discovered: Option<Param> = None;
            if let Ok(resp) = request.send().await {
                // Check for redirect reflection: if the response is a 3xx redirect,
                // the Location header may contain the reflected marker value.
                let is_redirect = resp.status().is_redirection();
                let location_reflection = if is_redirect {
                    resp.headers()
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|loc| {
                            crate::scanning::markers::classify_probe_reflection(loc).detected()
                        })
                } else {
                    false
                };

                if location_reflection {
                    // Redirect context: marker reflected in Location header.
                    // Use Attribute context since the value is placed in a URI attribute.
                    discovered = Some(Param {
                        name,
                        value,
                        location: crate::parameter_analysis::Location::Query,
                        injection_context: Some(
                            crate::parameter_analysis::InjectionContext::AttributeUrl(None),
                        ),
                        valid_specials: None,
                        invalid_specials: None,
                        pre_encoding: None,
                        pre_encoding_pipeline: None,
                        wire_name: None,
                        form_action_url: None,
                        form_origin_url: None,
                        framework_sink: None,
                    });
                } else if let Ok(text) = resp.text().await
                    && crate::scanning::markers::classify_probe_reflection(&text).detected()
                {
                    let (valid, invalid) = classify_special_chars(&text);
                    let framework_sink = crate::parameter_analysis::detect_framework_html_sink(
                        &text,
                        crate::scanning::markers::bracketed_marker(),
                    )
                    .map(ToString::to_string);
                    discovered = Some(Param {
                        name,
                        value,
                        location: crate::parameter_analysis::Location::Query,
                        injection_context: Some(detect_injection_context(&text)),
                        valid_specials: Some(valid),
                        invalid_specials: Some(invalid),
                        pre_encoding: None,
                        pre_encoding_pipeline: None,
                        wire_name: None,
                        form_action_url: None,
                        form_origin_url: None,
                        framework_sink,
                    });
                }
            }
            if delay > 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            drop(permit);
            discovered
        });
        handles.push(handle);
    }

    // Batch collect results to reduce mutex contention
    let mut batch: Vec<Param> = Vec::new();
    let mut discovered_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    for handle in handles {
        if let Ok(opt_param) = handle.await
            && let Some(p) = opt_param
        {
            discovered_names.insert(p.name.clone());
            batch.push(p);
        }
    }

    // Encoding probe: for params not yet discovered, try base64-encoded markers
    let encoding_probes = crate::encoding::pre_encoding::encoding_probes();
    for (name, value) in target.url.query_pairs() {
        let name = name.to_string();
        if discovered_names.contains(&name) {
            continue;
        }
        for (enc_type, encode_fn) in encoding_probes {
            let enc_name = enc_type.as_str();
            let encoded_marker = encode_fn(test_value);
            let mut url = target.url.clone();
            url.query_pairs_mut().clear();
            for (n, v) in target.url.query_pairs() {
                if n.as_ref() == name.as_str() {
                    url.query_pairs_mut().append_pair(&n, &encoded_marker);
                } else {
                    url.query_pairs_mut().append_pair(&n, &v);
                }
            }
            let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
            let m = target.parse_method();
            let request = crate::utils::build_request(&client, target, m, url, target.data.clone());
            crate::tick_request_count();
            if let Ok(resp) = request.send().await
                && let Ok(text) = resp.text().await
                && crate::scanning::markers::classify_probe_reflection(&text).detected()
            {
                // For pre-encoded params (base64/2base64), skip special char
                // classification. The encoding bypasses HTTP-level filtering,
                // and leaving specials as None ensures all payload types are tried
                // without adaptive filtering that would incorrectly block payloads.
                discovered_names.insert(name.clone());
                batch.push(Param {
                    name: name.clone(),
                    value: value.to_string(),
                    location: crate::parameter_analysis::Location::Query,
                    injection_context: Some(detect_injection_context(&text)),
                    valid_specials: None,
                    invalid_specials: None,
                    pre_encoding: Some(enc_name.to_string()),
                    pre_encoding_pipeline: None,
                    wire_name: None,
                    form_action_url: None,
                    form_origin_url: None,
                    framework_sink: None,
                });
                break; // Found working encoding, no need to try more
            }
            if target.delay > 0 {
                sleep(Duration::from_millis(target.delay)).await;
            }
        }
    }

    // Nested-pipeline probe: when a parameter's existing value decodes as
    // base64-of-JSON, treat each leaf string field as its own injection
    // point. The wire-level parameter name stays the parent (`qs`); each
    // virtual sub-param carries an `EncodingPipeline` that wraps the
    // payload back into the original structure (JSON-stringify with
    // payload at the leaf pointer, then base64).
    for (name, value) in target.url.query_pairs() {
        let name = name.to_string();
        let value = value.to_string();
        if discovered_names.contains(&name) {
            continue;
        }
        let nested = crate::encoding::pipeline::infer_nested_pipelines(&value);
        if nested.is_empty() {
            continue;
        }
        for nf in nested {
            // Bracket-style naming so dotted JSON keys (and parent param
            // names that already contain `.`) don't collide with each
            // other: `qs[move_url]`, `qs[items][0][name]`, `qs[a.b]`.
            let display_name = if nf.path.is_empty() {
                name.clone()
            } else {
                let mut s = name.clone();
                for seg in &nf.path {
                    s.push('[');
                    s.push_str(seg);
                    s.push(']');
                }
                s
            };
            // Skip if this synthetic name was already registered.
            if discovered_names.contains(&display_name) {
                continue;
            }
            let Ok(wire_value) = nf.pipeline.apply(test_value) else {
                continue;
            };
            let mut url = target.url.clone();
            url.query_pairs_mut().clear();
            for (n, v) in target.url.query_pairs() {
                if n.as_ref() == name.as_str() {
                    url.query_pairs_mut().append_pair(&n, &wire_value);
                } else {
                    url.query_pairs_mut().append_pair(&n, &v);
                }
            }
            let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
            let m = target.parse_method();
            let request = crate::utils::build_request(&client, target, m, url, target.data.clone());
            crate::tick_request_count();
            if let Ok(resp) = request.send().await
                && let Ok(text) = resp.text().await
                && crate::scanning::markers::classify_probe_reflection(&text).detected()
            {
                discovered_names.insert(display_name.clone());
                batch.push(Param {
                    name: display_name,
                    value: nf.original_value.clone(),
                    location: crate::parameter_analysis::Location::Query,
                    injection_context: Some(detect_injection_context(&text)),
                    valid_specials: None,
                    invalid_specials: None,
                    pre_encoding: None,
                    pre_encoding_pipeline: Some(nf.pipeline.clone()),
                    wire_name: Some(name.clone()),
                    form_action_url: None,
                    form_origin_url: None,
                    framework_sink: None,
                });
            }
            if target.delay > 0 {
                sleep(Duration::from_millis(target.delay)).await;
            }
        }
    }

    // Letter-stripped reflection probe: for params not yet discovered,
    // send a purely numeric marker to detect filters that strip a-zA-Z.
    // This catches injection points like `<script>#{input.gsub(/[a-zA-Z]/, "")}</script>`.
    {
        let numeric_marker = crate::scanning::check_reflection::NUMERIC_PROBE_MARKER;
        for (name, value) in target.url.query_pairs() {
            let name = name.to_string();
            if discovered_names.contains(&name) {
                continue;
            }
            let tmp_param = Param {
                name: name.clone(),
                value: String::new(),
                location: Location::Query,
                injection_context: None,
                valid_specials: None,
                invalid_specials: None,
                pre_encoding: None,
                pre_encoding_pipeline: None,
                wire_name: None,
                form_action_url: None,
                form_origin_url: None,
                framework_sink: None,
            };
            let url_str = build_injected_url(&target.url, &tmp_param, numeric_marker);
            let url = url::Url::parse(&url_str).expect("valid URL");
            let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
            let m = target.parse_method();
            let request = crate::utils::build_request(&client, target, m, url, target.data.clone());
            crate::tick_request_count();
            if let Ok(resp) = request.send().await
                && let Ok(text) = resp.text().await
                && text.contains(numeric_marker)
            {
                discovered_names.insert(name.clone());
                batch.push(Param {
                    name: name.clone(),
                    value: value.to_string(),
                    location: crate::parameter_analysis::Location::Query,
                    injection_context: Some(
                        crate::parameter_analysis::mining::detect_injection_context_with_marker(
                            &text,
                            numeric_marker,
                        ),
                    ),
                    valid_specials: None,
                    invalid_specials: None,
                    pre_encoding: None,
                    pre_encoding_pipeline: None,
                    wire_name: None,
                    form_action_url: None,
                    form_origin_url: None,
                    framework_sink: None,
                });
            }
            if target.delay > 0 {
                sleep(Duration::from_millis(target.delay)).await;
            }
        }
    }

    // Parameter key reflection: test if parameter NAMES are reflected in the
    // response body (e.g., ?<script>=a shows key in output).  We append an
    // extra query parameter whose key is the marker and check if the marker
    // appears in the response.
    {
        let mut url = target.url.clone();
        url.query_pairs_mut().append_pair(test_value, "1");
        let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
        let m = target.parse_method();
        let request = crate::utils::build_request(&client, target, m, url, target.data.clone());
        crate::tick_request_count();
        if let Ok(resp) = request.send().await
            && let Ok(text) = resp.text().await
            && crate::scanning::markers::classify_probe_reflection(&text).detected()
        {
            let (valid, invalid) = classify_special_chars(&text);
            batch.push(Param {
                name: "__dalfox_key_inject__".to_string(),
                value: String::new(),
                location: crate::parameter_analysis::Location::Query,
                injection_context: Some(detect_injection_context(&text)),
                valid_specials: Some(valid),
                invalid_specials: Some(invalid),
                pre_encoding: None,
                pre_encoding_pipeline: None,
                wire_name: None,
                form_action_url: None,
                form_origin_url: None,
                framework_sink: None,
            });
        }
        if target.delay > 0 {
            sleep(Duration::from_millis(target.delay)).await;
        }
    }

    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }
}

/// Common HTTP headers to proactively test for reflection,
/// even when they are not explicitly provided by the user.
const COMMON_PROBE_HEADERS: &[&str] = &[
    "Referer",
    "User-Agent",
    "Accept",
    "Accept-Language",
    "Authorization",
    "Cookie",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Custom-Header",
    "X-Debug",
    "Origin",
];

/// Differential probe to detect "blanket header echo" sites — printenv /
/// phpinfo-style endpoints (e.g. xss-quiz.int21h.jp) that render every
/// incoming header value back into the response. Without this guard,
/// each entry in [`COMMON_PROBE_HEADERS`] turns into an independent
/// reflection finding with identical payloads, drowning out actual
/// signal. We send one request with a header whose name is
/// guaranteed-unused (so no legitimate code path looks for it): if the
/// marker still reflects, the site echoes everything header-shaped,
/// and we should skip the default probe list.
///
/// User-supplied headers (`target.headers`) are NOT suppressed — the
/// user explicitly opted into testing those, and their findings remain
/// useful for narrowing a stored-XSS / cookie-injection vector.
async fn detect_blanket_header_echo(target: &Target) -> bool {
    let client = target.build_client_or_default();
    let arc_target = Arc::new(target.clone());
    let test_value = crate::scanning::markers::bracketed_marker();
    let guard_name = format!(
        "X-Dalfox-Probe-{}",
        crate::utils::short_scan_id(&crate::utils::make_scan_id(test_value))
    );
    let parsed_method = target.parse_method();
    let base = crate::utils::build_request(
        &client,
        &arc_target,
        parsed_method,
        target.url.clone(),
        target.data.clone(),
    );
    let overrides = vec![(guard_name, test_value.to_string())];
    let request = crate::utils::apply_header_overrides(base, &overrides);
    crate::tick_request_count();
    match request.send().await {
        Ok(resp) => match resp.text().await {
            Ok(text) => crate::scanning::markers::classify_probe_reflection(&text).detected(),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

pub async fn check_header_discovery(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let arc_target = Arc::new(target.clone());
    let client = target.build_client_or_default();
    let test_value = crate::scanning::markers::bracketed_marker();

    let mut handles = vec![];

    // Headers to test, in priority order of "explicitness":
    //   1. `-H` headers the user supplied (always)
    //   2. headers the user named via `-p name:header` (always — explicit
    //      injection points, honored even under --skip-reflection-header)
    //   3. the common-probe sweep (only when reflection-header discovery is on)
    let mut headers_to_test: Vec<(String, String)> = target
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let mut existing_names: std::collections::HashSet<String> = headers_to_test
        .iter()
        .map(|(k, _)| k.to_ascii_lowercase())
        .collect();

    for name in explicit_param_names(&args.param, "header") {
        if existing_names.insert(name.to_ascii_lowercase()) {
            headers_to_test.push((name, String::new()));
        }
    }

    // The blanket common-header sweep is the only part gated by
    // `--skip-reflection-header`. Explicitly-named headers above are not.
    if !args.skip_reflection_header {
        // Differential check: skip the default probe list when the target
        // echoes any header name. User-supplied headers still get probed
        // because the operator explicitly asked for them.
        let blanket_echo = detect_blanket_header_echo(target).await;
        if blanket_echo {
            if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!(
                    "[DBG] blanket header echo detected (guard reflected); skipping {} common header probes",
                    COMMON_PROBE_HEADERS.len()
                );
            }
        } else {
            for &hdr in COMMON_PROBE_HEADERS {
                if existing_names.insert(hdr.to_ascii_lowercase()) {
                    headers_to_test.push((hdr.to_string(), String::new()));
                }
            }
        }
    }

    if headers_to_test.is_empty() {
        return;
    }

    for (header_name, header_value) in &headers_to_test {
        let client_clone = client.clone();
        let url = target.url.clone();
        let data = target.data.clone();
        let parsed_method = target.parse_method();
        let delay = target.delay;
        let semaphore_clone = semaphore.clone();
        let header_name = header_name.clone();
        let header_value = header_value.clone();
        let target_clone = arc_target.clone();

        // Spawn task returning Option<Param> to batch reduce mutex contention
        let handle = tokio::spawn(async move {
            let permit = semaphore_clone
                .acquire()
                .await
                .expect("acquire semaphore permit");
            let m = parsed_method;
            let base =
                crate::utils::build_request(&client_clone, &target_clone, m, url, data.clone());
            let overrides = vec![(header_name.clone(), test_value.to_string())];
            let request = crate::utils::apply_header_overrides(base, &overrides);
            crate::tick_request_count();
            let mut discovered: Option<Param> = None;
            if let Ok(resp) = request.send().await
                && let Ok(text) = resp.text().await
                && crate::scanning::markers::classify_probe_reflection(&text).detected()
            {
                let (valid, invalid) = classify_special_chars(&text);
                let framework_sink = crate::parameter_analysis::detect_framework_html_sink(
                    &text,
                    crate::scanning::markers::bracketed_marker(),
                )
                .map(ToString::to_string);
                discovered = Some(Param {
                    name: header_name,
                    value: header_value,
                    location: crate::parameter_analysis::Location::Header,
                    injection_context: Some(detect_injection_context(&text)),
                    valid_specials: Some(valid),
                    invalid_specials: Some(invalid),
                    pre_encoding: None,
                    pre_encoding_pipeline: None,
                    wire_name: None,
                    form_action_url: None,
                    form_origin_url: None,
                    framework_sink,
                });
            }
            if delay > 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            drop(permit);
            discovered
        });
        handles.push(handle);
    }

    // Batch collect
    let mut batch: Vec<Param> = Vec::new();
    for handle in handles {
        if let Ok(opt) = handle.await
            && let Some(p) = opt
        {
            batch.push(p);
        }
    }
    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }
}

/// Discover reflections in path segments by replacing each segment with the test marker
pub async fn check_path_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let arc_target = Arc::new(target.clone());
    let test_value = crate::scanning::markers::bracketed_marker();
    let path = target.url.path();
    // Split non-empty segments
    let segments: Vec<&str> = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if segments.is_empty() {
        return;
    }

    let client = target.build_client_or_default();

    let mut handles = Vec::new();

    let mut new_segments: Vec<String> = segments.iter().map(ToString::to_string).collect();
    for (idx, original) in segments.iter().enumerate() {
        let saved = std::mem::replace(&mut new_segments[idx], test_value.to_string());
        let new_path = format!("/{}", new_segments.join("/"));

        let mut new_url = target.url.clone();
        new_url.set_path(&new_path);

        // For non-2xx responses, the URL-attr-only filter above keeps any path
        // reflection that lands in text content — including 404 templates like
        // `<span class='path'>/{uri}/</span>` where the server HTML-escapes
        // every `<` and `>` before echoing. Treating those as scannable made
        // path-segment params dominate the wall time on real benchmarks (xssmaze:
        // ~99% of requests with zero true positives). The bracket-wrapped
        // probe below is sent only when the first probe says non-2xx +
        // exploitable_context, and we keep the path-segment registration only
        // if the response contains the literal `<MARKER>` substring — i.e. `<`
        // and `>` both survived reflection without entity-escaping.
        let bracket_path = new_path.replace(test_value, &format!("%3C{}%3E", test_value));
        let mut bracket_url = target.url.clone();
        bracket_url.set_path(&bracket_path);

        let client_clone = client.clone();
        let data = target.data.clone();
        let parsed_method = target.parse_method();
        let target_clone = arc_target.clone();
        let delay = target.delay;
        let semaphore_clone = semaphore.clone();
        let param_name = format!("path_segment_{}", idx);
        let original_value = original.to_string();

        // Skip if already discovered (e.g., duplicate path pattern)
        {
            let guard = reflection_params.lock().await;
            if guard.iter().any(|p| {
                p.name == param_name && p.location == crate::parameter_analysis::Location::Path
            }) {
                new_segments[idx] = saved;
                continue;
            }
        }

        // Spawn task returning Option<Param> for batched collection
        let handle = tokio::spawn(async move {
            let permit = semaphore_clone
                .acquire()
                .await
                .expect("acquire semaphore permit");
            let m = parsed_method;
            let request = crate::utils::build_request(
                &client_clone,
                &target_clone,
                m.clone(),
                new_url,
                data.clone(),
            );

            crate::tick_request_count();
            let mut discovered: Option<Param> = None;
            if let Ok(resp) = request.send().await {
                // Pair discovery with the scan-time `should_suppress_path_*`
                // policy so we don't pay payload-set requests for path
                // segments the scanner would later throw away. Concretely:
                //   * 2xx                              → always honor
                //   * 3xx                              → drop (Location-only
                //                                       echo, not a rendered
                //                                       HTML sink)
                //   * 4xx/5xx + marker only in URL attrs → drop (canonical
                //                                       link / `<a href>`
                //                                       echo noise)
                //   * 4xx/5xx + marker outside URL attrs → keep
                //                                       (genuine error-page
                //                                       XSS — e.g. a 404
                //                                       template that emits
                //                                       `<td>{uri}</td>`).
                let status = resp.status().as_u16();
                if !(300..400).contains(&status)
                    && let Ok(text) = resp.text().await
                    && crate::scanning::markers::classify_probe_reflection(&text).detected()
                {
                    let exploitable_context = (200..300).contains(&status)
                        || !crate::scanning::check_reflection::marker_reflects_in_url_attr_only(
                            &text,
                            crate::scanning::markers::bracketed_marker(),
                        );
                    // For 4xx/5xx error pages whose templates echo the URL
                    // path into text content, require the second probe
                    // (`<MARKER>`) to come back with raw `<` and `>` before
                    // declaring the segment scannable. If the server
                    // entity-escapes either bracket, no HTML-tag payload
                    // will ever reflect — keeping the segment would burn
                    // thousands of requests on guaranteed-negative payloads.
                    //
                    // Known limitation: `t.contains(&needle)` is case-sensitive,
                    // so a server that ASCII-uppercases / -lowercases reflected
                    // path bytes (e.g. xssmaze's `obfuscation/level2` shape, but
                    // applied to a 4xx path-echo) would slip past this gate and
                    // get treated as inert. Real-world servers rarely case-fold
                    // URL paths, so the trade-off is acceptable; if it surfaces
                    // in benchmarks, swap to the `ascii_ci_contains` helper used
                    // by `check_reflection::marker_case_fold_reflected`.
                    let bracket_survives = if exploitable_context && !(200..300).contains(&status) {
                        let needle = format!("<{}>", crate::scanning::markers::bracketed_marker());
                        let probe = crate::utils::build_request(
                            &client_clone,
                            &target_clone,
                            m.clone(),
                            bracket_url,
                            data.clone(),
                        );
                        crate::tick_request_count();
                        match probe.send().await {
                            Ok(r) => match r.text().await {
                                Ok(t) => t.contains(&needle),
                                Err(_) => false,
                            },
                            Err(_) => false,
                        }
                    } else {
                        true
                    };
                    if exploitable_context && bracket_survives {
                        let (valid, invalid) = classify_special_chars(&text);
                        discovered = Some(Param {
                            name: param_name,
                            value: original_value,
                            location: crate::parameter_analysis::Location::Path,
                            injection_context: Some(detect_injection_context(&text)),
                            valid_specials: Some(valid),
                            invalid_specials: Some(invalid),
                            pre_encoding: None,
                            pre_encoding_pipeline: None,
                            wire_name: None,
                            form_action_url: None,
                            form_origin_url: None,
                            framework_sink: None,
                        });
                    }
                }
            }
            if delay > 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            drop(permit);
            discovered
        });
        handles.push(handle);
        new_segments[idx] = saved;
    }

    // Batch collect discovered path params
    let mut batch: Vec<Param> = Vec::new();
    for h in handles {
        if let Ok(opt) = h.await
            && let Some(p) = opt
        {
            batch.push(p);
        }
    }
    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }
}

pub async fn check_cookie_discovery(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let arc_target = Arc::new(target.clone());
    let client = target.build_client_or_default();
    let test_value = crate::scanning::markers::bracketed_marker();

    let mut handles = vec![];

    // Under `--skip-reflection-cookie` the blanket sweep over supplied cookies
    // is off, but cookies named explicitly via `-p name:cookie` are explicit
    // injection points and still get probed.
    let explicit_only: Option<Vec<String>> = if args.skip_reflection_cookie {
        Some(explicit_param_names(&args.param, "cookie"))
    } else {
        None
    };

    for (cookie_name, cookie_value) in &target.cookies {
        if let Some(ref allow) = explicit_only
            && !allow.iter().any(|n| n == cookie_name)
        {
            continue;
        }
        let client_clone = client.clone();
        let url = target.url.clone();
        let cookies = target.cookies.clone();
        let data = target.data.clone();
        let parsed_method = target.parse_method();
        let delay = target.delay;
        let semaphore_clone = semaphore.clone();
        let cookie_name = cookie_name.clone();
        let cookie_value = cookie_value.clone();
        let target_clone = arc_target.clone();

        // Spawn task returning Option<Param> for batched collection
        let handle = tokio::spawn(async move {
            let permit = semaphore_clone
                .acquire()
                .await
                .expect("acquire semaphore permit");
            let m = parsed_method;
            // Compose cookie header overriding the probed cookie while preserving others
            let others =
                crate::utils::compose_cookie_header_excluding(&cookies, Some(&cookie_name));
            let cookie_header = match others {
                Some(s) => format!("{}; {}={}", s, cookie_name, test_value),
                None => format!("{}={}", cookie_name, test_value),
            };
            let request = crate::utils::build_request_with_cookie(
                &client_clone,
                &target_clone,
                m,
                url,
                data.clone(),
                Some(cookie_header),
            );
            crate::tick_request_count();
            let mut discovered: Option<Param> = None;
            if let Ok(resp) = request.send().await
                && let Ok(text) = resp.text().await
                && crate::scanning::markers::classify_probe_reflection(&text).detected()
            {
                let (valid, invalid) = classify_special_chars(&text);
                discovered = Some(Param {
                    name: cookie_name,
                    value: cookie_value,
                    location: crate::parameter_analysis::Location::Header,
                    injection_context: Some(detect_injection_context(&text)),
                    valid_specials: Some(valid),
                    invalid_specials: Some(invalid),
                    pre_encoding: None,
                    pre_encoding_pipeline: None,
                    wire_name: None,
                    form_action_url: None,
                    form_origin_url: None,
                    framework_sink: None,
                });
            }
            if delay > 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            drop(permit);
            discovered
        });
        handles.push(handle);
    }

    // Batch collect cookie params
    let mut batch: Vec<Param> = Vec::new();
    for handle in handles {
        if let Ok(opt) = handle.await
            && let Some(p) = opt
        {
            batch.push(p);
        }
    }
    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }
}

/// Discover POST form parameters by parsing HTML forms from the GET response.
pub async fn check_form_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    // Only discover forms when the target doesn't already have POST data
    if target.data.is_some() || target.method.eq_ignore_ascii_case("POST") {
        return;
    }

    let client = target.build_client_or_default();
    let test_value = crate::scanning::markers::bracketed_marker();

    // Fetch the page via GET to find forms
    let method = reqwest::Method::GET;
    let request = crate::utils::build_request(&client, target, method, target.url.clone(), None);
    crate::tick_request_count();
    let html = match request.send().await {
        Ok(resp) => match resp.text().await {
            Ok(text) => text,
            Err(_) => return,
        },
        Err(_) => return,
    };

    // Fully-owned form descriptor extracted from the HTML. Keeping these as
    // Send-safe `String` / `Url` lets the scraper document get dropped before
    // the async probing loop below, which is a prerequisite for ever moving
    // this function off the current_thread runtime.
    struct FormInfo {
        url: url::Url,
        is_post: bool,
        is_multipart: bool,
        fields: Vec<(String, String)>,
    }

    // Parse forms in a tight scope so `scraper::Html` (which is !Send) never
    // escapes. Collect into `Vec<FormInfo>` before touching any await.
    let forms: Vec<FormInfo> = {
        let document = scraper::Html::parse_document(&html);
        let form_sel = selectors::form();
        let input_sel = selectors::input_textarea_select();

        let mut out = Vec::new();
        for form in document.select(form_sel) {
            let form_method = form.value().attr("method").unwrap_or("get");
            let is_post = form_method.eq_ignore_ascii_case("post");
            let enctype = form.value().attr("enctype").unwrap_or("");
            let is_multipart = enctype.eq_ignore_ascii_case("multipart/form-data");

            let action = form.value().attr("action").unwrap_or("");
            let form_url = if action.is_empty() || action == "#" {
                target.url.clone()
            } else if let Ok(resolved) = target.url.join(action) {
                resolved
            } else {
                continue;
            };

            let mut fields: Vec<(String, String)> = Vec::new();
            for input in form.select(input_sel) {
                let name = input.value().attr("name").unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let value = input.value().attr("value").unwrap_or("").to_string();
                fields.push((name, value));
            }
            if fields.is_empty() {
                continue;
            }

            out.push(FormInfo {
                url: form_url,
                is_post,
                is_multipart,
                fields,
            });
        }
        out
    };

    let mut batch: Vec<Param> = Vec::new();

    for FormInfo {
        url: form_url,
        is_post,
        is_multipart,
        fields,
    } in forms
    {
        if is_post && is_multipart {
            // Multipart form: test each field via multipart/form-data POST
            for (field_idx, (field_name, field_value)) in fields.iter().enumerate() {
                let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
                let mut form = reqwest::multipart::Form::new();
                for (i, (n, v)) in fields.iter().enumerate() {
                    if i == field_idx {
                        form = form.text(n.clone(), test_value.to_string());
                    } else {
                        form = form.text(n.clone(), v.clone());
                    }
                }
                let rb = crate::utils::build_request(
                    &client,
                    target,
                    reqwest::Method::POST,
                    form_url.clone(),
                    None,
                )
                .multipart(form);
                crate::tick_request_count();
                if let Ok(resp) = rb.send().await
                    && let Ok(text) = resp.text().await
                    && crate::scanning::markers::classify_probe_reflection(&text).detected()
                {
                    let (valid, invalid) = classify_special_chars(&text);
                    batch.push(Param {
                        name: field_name.clone(),
                        value: field_value.clone(),
                        location: crate::parameter_analysis::Location::MultipartBody,
                        injection_context: Some(detect_injection_context(&text)),
                        valid_specials: Some(valid),
                        invalid_specials: Some(invalid),
                        pre_encoding: None,
                        pre_encoding_pipeline: None,
                        wire_name: None,
                        form_action_url: Some(form_url.to_string()),
                        form_origin_url: Some(target.url.to_string()),
                        framework_sink: None,
                    });
                }
                if target.delay > 0 {
                    sleep(Duration::from_millis(target.delay)).await;
                }
            }
        } else if is_post {
            // Pre-encode field names and values once for form body construction
            let encoded_fields: Vec<(String, String)> = fields
                .iter()
                .map(|(n, v)| {
                    let enc_n =
                        url::form_urlencoded::byte_serialize(n.as_bytes()).collect::<String>();
                    let enc_v =
                        url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>();
                    (enc_n, enc_v)
                })
                .collect();
            let encoded_test_value: String =
                url::form_urlencoded::byte_serialize(test_value.as_bytes()).collect();

            // Test each field for reflection via POST
            for (field_idx, (field_name, field_value)) in fields.iter().enumerate() {
                let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
                // Build body by joining pre-encoded pairs, substituting the target field
                let body = encoded_fields.iter().enumerate().fold(
                    String::new(),
                    |mut acc, (i, (enc_n, enc_v))| {
                        if !acc.is_empty() {
                            acc.push('&');
                        }
                        acc.push_str(enc_n);
                        acc.push('=');
                        if i == field_idx {
                            acc.push_str(&encoded_test_value);
                        } else {
                            acc.push_str(enc_v);
                        }
                        acc
                    },
                );
                let m = reqwest::Method::POST;
                let rb =
                    crate::utils::build_request(&client, target, m, form_url.clone(), Some(body));
                let rb = crate::utils::apply_header_overrides(
                    rb,
                    &[(
                        "Content-Type".to_string(),
                        "application/x-www-form-urlencoded".to_string(),
                    )],
                );
                crate::tick_request_count();
                if let Ok(resp) = rb.send().await
                    && let Ok(text) = resp.text().await
                    && crate::scanning::markers::classify_probe_reflection(&text).detected()
                {
                    let (valid, invalid) = classify_special_chars(&text);
                    batch.push(Param {
                        name: field_name.clone(),
                        value: field_value.clone(),
                        location: crate::parameter_analysis::Location::Body,
                        injection_context: Some(detect_injection_context(&text)),
                        valid_specials: Some(valid),
                        invalid_specials: Some(invalid),
                        pre_encoding: None,
                        pre_encoding_pipeline: None,
                        wire_name: None,
                        form_action_url: Some(form_url.to_string()),
                        form_origin_url: Some(target.url.to_string()),
                        framework_sink: None,
                    });
                }
                if target.delay > 0 {
                    sleep(Duration::from_millis(target.delay)).await;
                }
            }
        } else {
            // GET form: test each field as query parameter on the form action URL
            for (field_name, field_value) in &fields {
                let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
                let mut test_url = form_url.clone();
                // Build query: set all fields, replace target field with test value
                {
                    let mut pairs = test_url.query_pairs_mut();
                    pairs.clear();
                    for (n, v) in &fields {
                        if n == field_name {
                            pairs.append_pair(n, test_value);
                        } else {
                            pairs.append_pair(n, v);
                        }
                    }
                }
                let m = reqwest::Method::GET;
                let rb = crate::utils::build_request(&client, target, m, test_url.clone(), None);
                crate::tick_request_count();
                if let Ok(resp) = rb.send().await
                    && let Ok(text) = resp.text().await
                    && crate::scanning::markers::classify_probe_reflection(&text).detected()
                {
                    let (valid, invalid) = classify_special_chars(&text);
                    batch.push(Param {
                        name: field_name.clone(),
                        value: field_value.clone(),
                        location: crate::parameter_analysis::Location::Query,
                        injection_context: Some(detect_injection_context(&text)),
                        valid_specials: Some(valid),
                        invalid_specials: Some(invalid),
                        pre_encoding: None,
                        pre_encoding_pipeline: None,
                        wire_name: None,
                        form_action_url: Some(form_url.to_string()),
                        form_origin_url: Some(target.url.to_string()),
                        framework_sink: None,
                    });
                }
                if target.delay > 0 {
                    sleep(Duration::from_millis(target.delay)).await;
                }
            }
        }

        // Also try JSON body if the form has a single text-like field
        if fields.len() <= 3 {
            let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
            let json_body = {
                let mut map = serde_json::Map::new();
                for (n, _) in &fields {
                    map.insert(n.clone(), serde_json::Value::String(test_value.to_string()));
                }
                serde_json::Value::Object(map).to_string()
            };
            let m = reqwest::Method::POST;
            let rb =
                crate::utils::build_request(&client, target, m, form_url.clone(), Some(json_body));
            let rb = crate::utils::apply_header_overrides(
                rb,
                &[("Content-Type".to_string(), "application/json".to_string())],
            );
            crate::tick_request_count();
            if let Ok(resp) = rb.send().await
                && let Ok(text) = resp.text().await
                && crate::scanning::markers::classify_probe_reflection(&text).detected()
            {
                let (valid, invalid) = classify_special_chars(&text);
                for (field_name, field_value) in &fields {
                    batch.push(Param {
                        name: field_name.clone(),
                        value: field_value.clone(),
                        location: crate::parameter_analysis::Location::JsonBody,
                        injection_context: Some(detect_injection_context(&text)),
                        valid_specials: Some(valid.clone()),
                        invalid_specials: Some(invalid.clone()),
                        pre_encoding: None,
                        pre_encoding_pipeline: None,
                        wire_name: None,
                        form_action_url: Some(form_url.to_string()),
                        form_origin_url: Some(target.url.to_string()),
                        framework_sink: None,
                    });
                }
            }
        }
    }

    // Detect inline JSON object hints in page body (e.g., {"name":"value"} in text or code).
    // This catches cases where the page documents a JSON API without using JSON.stringify.
    {
        static JSON_INLINE_RE: OnceLock<regex::Regex> = OnceLock::new();
        let inline_re = JSON_INLINE_RE.get_or_init(|| {
            regex::Regex::new(r#"\{["\s]*"(\w+)"["\s]*:["\s]*"[^"]*"[^}]*\}"#)
                .expect("inline JSON regex is valid")
        });
        for caps in inline_re.captures_iter(&html) {
            let full = caps.get(0).map_or("", |m| m.as_str());
            // Try to parse as JSON
            if let Ok(serde_json::Value::Object(obj)) =
                serde_json::from_str::<serde_json::Value>(full)
            {
                let keys: Vec<String> = obj.keys().cloned().collect();
                if keys.is_empty() {
                    continue;
                }
                // Skip if all keys are already known
                let all_known = {
                    let guard = reflection_params.lock().await;
                    keys.iter().all(|k| {
                        guard
                            .iter()
                            .any(|p| p.name == *k && matches!(p.location, Location::JsonBody))
                    })
                };
                if all_known {
                    continue;
                }

                for key in &keys {
                    let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
                    let mut map = serde_json::Map::new();
                    for (k, v) in &obj {
                        if k == key {
                            map.insert(
                                k.clone(),
                                serde_json::Value::String(test_value.to_string()),
                            );
                        } else {
                            map.insert(k.clone(), v.clone());
                        }
                    }
                    let json_body = serde_json::Value::Object(map).to_string();
                    let m = reqwest::Method::POST;
                    let rb = crate::utils::build_request(
                        &client,
                        target,
                        m,
                        target.url.clone(),
                        Some(json_body),
                    );
                    let rb = crate::utils::apply_header_overrides(
                        rb,
                        &[("Content-Type".to_string(), "application/json".to_string())],
                    );
                    crate::tick_request_count();
                    if let Ok(resp) = rb.send().await
                        && let Ok(text) = resp.text().await
                        && crate::scanning::markers::classify_probe_reflection(&text).detected()
                    {
                        let (valid, invalid) = classify_special_chars(&text);
                        batch.push(Param {
                            name: key.clone(),
                            value: "a".to_string(),
                            location: crate::parameter_analysis::Location::JsonBody,
                            injection_context: Some(detect_injection_context(&text)),
                            valid_specials: Some(valid),
                            invalid_specials: Some(invalid),
                            pre_encoding: None,
                            pre_encoding_pipeline: None,
                            wire_name: None,
                            form_action_url: Some(target.url.to_string()),
                            form_origin_url: Some(target.url.to_string()),
                            framework_sink: None,
                        });
                    }
                    if target.delay > 0 {
                        sleep(Duration::from_millis(target.delay)).await;
                    }
                }
            }
        }
    }

    // Also detect JSON POST endpoints from JavaScript (XHR / fetch with JSON.stringify)
    // Look for patterns like: JSON.stringify({"key":"value",...})
    {
        let re = json_stringify_regex();
        for caps in re.captures_iter(&html) {
            if let Some(inner) = caps.get(1) {
                // Parse key names from the JSON-like object literal
                let key_re = json_key_regex();
                let mut json_fields: Vec<(String, String)> = Vec::new();
                for kcap in key_re.captures_iter(inner.as_str()) {
                    if let Some(k) = kcap.get(1) {
                        json_fields.push((k.as_str().to_string(), "a".to_string()));
                    }
                }
                if json_fields.is_empty() {
                    continue;
                }

                // Try JSON body with each field replaced by test_value
                for (field_name, field_value) in &json_fields {
                    let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
                    let mut map = serde_json::Map::new();
                    for (n, v) in &json_fields {
                        if n == field_name {
                            map.insert(
                                n.clone(),
                                serde_json::Value::String(test_value.to_string()),
                            );
                        } else {
                            map.insert(n.clone(), serde_json::Value::String(v.clone()));
                        }
                    }
                    let json_body = serde_json::Value::Object(map).to_string();
                    let m = reqwest::Method::POST;
                    let rb = crate::utils::build_request(
                        &client,
                        target,
                        m,
                        target.url.clone(),
                        Some(json_body),
                    );
                    let rb = crate::utils::apply_header_overrides(
                        rb,
                        &[("Content-Type".to_string(), "application/json".to_string())],
                    );
                    crate::tick_request_count();
                    if let Ok(resp) = rb.send().await
                        && let Ok(text) = resp.text().await
                        && crate::scanning::markers::classify_probe_reflection(&text).detected()
                    {
                        let (valid, invalid) = classify_special_chars(&text);
                        batch.push(Param {
                            name: field_name.clone(),
                            value: field_value.clone(),
                            location: crate::parameter_analysis::Location::JsonBody,
                            injection_context: Some(detect_injection_context(&text)),
                            valid_specials: Some(valid),
                            invalid_specials: Some(invalid),
                            pre_encoding: None,
                            pre_encoding_pipeline: None,
                            wire_name: None,
                            form_action_url: Some(target.url.to_string()),
                            form_origin_url: Some(target.url.to_string()),
                            framework_sink: None,
                        });
                    }
                    if target.delay > 0 {
                        sleep(Duration::from_millis(target.delay)).await;
                    }
                }
            }
        }
    }

    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }
}

#[cfg(test)]
mod tests;
