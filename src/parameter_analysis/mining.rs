//! # Stage 2: Mining
//!
//! Discovers additional parameters by analyzing HTML forms, JavaScript source,
//! dictionary wordlists, and GF-pattern lists — then probes each for reflection.
//!
//! **Input:** `Target` + `ScanArgs` + the initial `reflection_params` from Stage 1.
//!
//! **Output:** Extends the shared `reflection_params` list with newly discovered
//! `Param` entries that reflect. Each carries the same naive `valid_specials`,
//! `invalid_specials`, and `injection_context` as Stage 1 output.
//!
//! **Side effects:** HTTP requests for DOM/dict/GF mining probes. Uses EWMA-based
//! collapse detection to short-circuit when a target reflects everything
//! (sustained ≥85% reflection rate after ≥15 attempts). Filters out 5xx
//! responses to avoid false positives from debug/error pages.
//!
//! **Skippable via:** `--skip-mining`, `--skip-mining-dict`, `--skip-mining-dom`.

use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::{DelimiterType, InjectionContext, Location, Param};
use crate::payload::mining::GF_PATTERNS_PARAMS;
use crate::target_parser::Target;
use indicatif::ProgressBar;
use scraper;
use std::sync::{Arc, atomic::Ordering};

use tokio::sync::{Mutex, Semaphore};
use tokio::time::{Duration, sleep};
use url::form_urlencoded;

use crate::scanning::selectors;

const EWMA_ALPHA: f64 = 0.30; // smoothing factor for exponential weighted moving average
const EWMA_START_VALUE: f64 = 0.0;
const COLLAPSE_EWMA_THRESHOLD: f64 = 0.85; // if sustained EWMA reflection ratio >= 85%
const COLLAPSE_MIN_ATTEMPTS: usize = 15; // need at least this many attempts before collapsing
const COLLAPSE_MIN_REFLECTIONS: usize = 5; // and at least this many reflections

#[derive(Debug)]
struct MiningSampleStats {
    attempts: usize,
    reflections: usize,
    ewma_ratio: f64,
    collapsed: bool,
}

impl MiningSampleStats {
    fn new() -> Self {
        Self {
            attempts: 0,
            reflections: 0,
            ewma_ratio: EWMA_START_VALUE,
            collapsed: false,
        }
    }
    fn record_attempt(&mut self) {
        self.attempts += 1;
    }
    fn record_reflection(&mut self) {
        self.reflections += 1;
        let instant = 1.0; // this attempt reflected
        self.update_ewma(instant);
    }
    fn record_non_reflection(&mut self) {
        let instant = 0.0;
        self.update_ewma(instant);
    }
    fn update_ewma(&mut self, instant: f64) {
        self.ewma_ratio = EWMA_ALPHA * instant + (1.0 - EWMA_ALPHA) * self.ewma_ratio;
    }
    fn should_collapse(&self) -> bool {
        !self.collapsed
            && self.attempts >= COLLAPSE_MIN_ATTEMPTS
            && self.reflections >= COLLAPSE_MIN_REFLECTIONS
            && self.ewma_ratio >= COLLAPSE_EWMA_THRESHOLD
    }
}

pub fn detect_injection_context(text: &str) -> InjectionContext {
    let marker = crate::scanning::markers::open_marker();
    detect_injection_context_with_marker(text, marker)
}

/// Like `detect_injection_context` but uses a caller-supplied marker string.
/// Useful for probes that don't use the standard alphanumeric marker (e.g. numeric-only probes).
pub fn detect_injection_context_with_marker(text: &str, marker: &str) -> InjectionContext {
    if !text.contains(marker) {
        return InjectionContext::Html(None);
    }

    // Fast comment check using raw HTML when available
    if let (Some(cs), Some(ce)) = (text.find("<!--"), text.find("-->"))
        && let Some(mp) = text.find(marker)
        && cs < mp
        && mp < ce
    {
        return InjectionContext::Html(Some(DelimiterType::Comment));
    }

    // Parse HTML and locate marker via element text/attributes/script
    let document = scraper::Html::parse_document(text);

    // Heuristic to infer surrounding quote delimiter around the first marker
    fn infer_quote_delimiter(text: &str, marker: &str) -> Option<DelimiterType> {
        let pos = text.find(marker)?;
        let before = &text[..pos];
        let after = &text[pos + marker.len()..];
        let prev_dq = before.rfind('"');
        let prev_sq = before.rfind('\'');
        let (qch, _qpos) = match (prev_dq, prev_sq) {
            (Some(dq), Some(sq)) => {
                if dq > sq {
                    ('"', dq)
                } else {
                    ('\'', sq)
                }
            }
            (Some(dq), None) => ('"', dq),
            (None, Some(sq)) => ('\'', sq),
            (None, None) => return None,
        };
        let next = after.find(qch);
        if next.is_some() {
            return Some(match qch {
                '"' => DelimiterType::DoubleQuote,
                '\'' => DelimiterType::SingleQuote,
                _ => return None,
            });
        }
        None
    }

    fn is_url_like_attribute(name: &str) -> bool {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "src" | "href" | "xlink:href" | "data" | "action" | "formaction" | "poster"
        )
    }

    // 1) JavaScript context: marker appears in any <script> text
    {
        let sel = selectors::script();
        for el in document.select(sel) {
            let s = el.text().fold(String::new(), |mut acc, t| { acc.push_str(t); acc });
            if s.contains(marker) {
                let delim = infer_quote_delimiter(text, marker);
                return InjectionContext::Javascript(delim);
            }
        }
    }

    // 1b) CSS context: marker appears in any <style> text
    {
        let sel = selectors::style();
        for el in document.select(sel) {
            let s = el.text().fold(String::new(), |mut acc, t| { acc.push_str(t); acc });
            if s.contains(marker) {
                let delim = infer_quote_delimiter(text, marker);
                return InjectionContext::Css(delim);
            }
        }
    }

    // 2) Attribute context: marker in any attribute value
    {
        let any = selectors::universal();
        for el in document.select(any) {
            for (name, v) in el.value().attrs() {
                if v.contains(marker) {
                    let delim = infer_quote_delimiter(text, marker);
                    return if is_url_like_attribute(name) {
                        InjectionContext::AttributeUrl(delim)
                    } else {
                        InjectionContext::Attribute(delim)
                    };
                }
            }
        }
    }

    // 3) HTML text context: marker in non-script, non-style text nodes
    {
        let any = selectors::universal();
        for el in document.select(any) {
            let tag = el.value().name();
            if tag.eq_ignore_ascii_case("script") || tag.eq_ignore_ascii_case("style") {
                continue;
            }
            let s = el.text().fold(String::new(), |mut acc, t| { acc.push_str(t); acc });
            if s.contains(marker) {
                return InjectionContext::Html(None);
            }
        }
    }

    // Fallback to HTML
    InjectionContext::Html(None)
}

pub async fn probe_dictionary_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ProgressBar>,
) {
    let arc_target = Arc::new(target.clone());
    let silence = args.silence;
    let client = target.build_client_or_default();

    // Resolve candidate parameter names (remote, file, or built-ins)
    let mut params: Vec<String> = Vec::new();
    let mut loaded = false;

    if !args.remote_wordlists.is_empty() {
        if let Err(e) = crate::payload::init_remote_wordlists(&args.remote_wordlists).await
            && !silence
        {
            eprintln!("Error initializing remote wordlists: {}", e);
        }
        if let Some(words) = crate::payload::get_remote_words()
            && !words.is_empty()
        {
            params = words.as_ref().clone();
            loaded = true;
        }
    }

    if !loaded && let Some(wordlist_path) = &args.mining_dict_word {
        match std::fs::read_to_string(wordlist_path) {
            Ok(content) => {
                params = content
                    .lines()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                loaded = true;
            }
            Err(e) => {
                if !silence {
                    eprintln!("Error reading wordlist file {}: {}", wordlist_path, e);
                }
                return;
            }
        }
    }

    if !loaded {
        params = GF_PATTERNS_PARAMS.iter().map(|s| s.to_string()).collect();
    }

    if let Some(ref pb) = pb {
        pb.set_length(params.len() as u64);
        pb.set_message("Mining dictionary parameters");
    }

    // EWMA adaptive stats shared across tasks
    let stats = Arc::new(Mutex::new(MiningSampleStats::new()));

    // Each task returns Option<Param>; batch flush later
    let mut handles: Vec<tokio::task::JoinHandle<Option<Param>>> = Vec::new();

    // Chunked processing to reduce memory and allow early collapse exit
    const CHUNK_SIZE: usize = 500;
    'outer: for param_chunk in params.chunks(CHUNK_SIZE) {
        {
            let st = stats.lock().await;
            if st.collapsed {
                break 'outer;
            }
        }
        for param in param_chunk {
            {
                let st = stats.lock().await;
                if st.collapsed {
                    break 'outer;
                }
            }
            // original body below
            // Early collapse stop
            {
                let st = stats.lock().await;
                if st.collapsed {
                    break;
                }
            }
            // Skip if already discovered
            let exists = reflection_params
                .lock()
                .await
                .iter()
                .any(|p| p.name == *param);
            if exists {
                continue;
            }

            let mut url = target.url.clone();
            url.query_pairs_mut()
                .append_pair(param, crate::scanning::markers::open_marker());

            let client_clone = client.clone();

            let data = target.data.clone();
            let parsed_method = target.parse_method();
            let target_clone = arc_target.clone();
            let delay = target.delay;
            let semaphore_clone = semaphore.clone();
            let param_name = param.clone();
            let pb_clone = pb.clone();
            let stats_clone = stats.clone();

            let handle = tokio::spawn(async move {
                let permit = semaphore_clone.acquire().await.expect("acquire semaphore permit");
                let request =
                    crate::utils::build_request(&client_clone, &target_clone, parsed_method, url, data.clone());

                let resp = request.send().await;
                crate::REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);

                let mut discovered: Option<Param> = None;
                if let Ok(r) = resp {
                    // Skip server error responses (5xx) — debug error pages often
                    // reflect query params in stack traces, causing false positives.
                    let status = r.status();
                    if status.is_server_error() {
                        let mut st = stats_clone.lock().await;
                        st.record_attempt();
                        drop(permit);
                        if delay > 0 {
                            sleep(Duration::from_millis(delay)).await;
                        }
                        if let Some(ref pb) = pb_clone {
                            pb.inc(1);
                        }
                        return discovered;
                    }
                    // Check for redirect reflection: if the response is a 3xx redirect,
                    // the Location header may contain the reflected marker value.
                    let is_redirect = status.is_redirection();
                    let location_has_marker = if is_redirect {
                        r.headers()
                            .get("location")
                            .and_then(|v| v.to_str().ok())
                            .map(|loc| loc.contains(crate::scanning::markers::open_marker()))
                            .unwrap_or(false)
                    } else {
                        false
                    };

                    if location_has_marker {
                        // Redirect context: marker reflected in Location header.
                        let mut st = stats_clone.lock().await;
                        st.record_attempt();
                        st.record_reflection();
                        if !st.collapsed {
                            discovered = Some(Param {
                                name: param_name.clone(),
                                value: crate::scanning::markers::open_marker().to_string(),
                                location: crate::parameter_analysis::Location::Query,
                                injection_context: Some(
                                    crate::parameter_analysis::InjectionContext::AttributeUrl(None),
                                ),
                                valid_specials: None,
                                invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
                            });
                            if !silence {
                                eprintln!(
                                    "Discovered parameter (redirect): {} (EWMA {:.2}, {}/{})",
                                    param_name, st.ewma_ratio, st.reflections, st.attempts
                                );
                            }
                            if st.should_collapse() {
                                st.collapsed = true;
                                if !silence {
                                    eprintln!(
                                        "[mining-collapse] High reflection EWMA {:.2} after {} attempts ({} reflections)",
                                        st.ewma_ratio, st.attempts, st.reflections
                                    );
                                }
                            }
                        }
                    } else if let Ok(text) = r.text().await {
                        let mut st = stats_clone.lock().await;
                        st.record_attempt();
                        if text.contains(crate::scanning::markers::open_marker()) {
                            st.record_reflection();
                            if !st.collapsed {
                                let context = detect_injection_context(&text);
                                let (valid, invalid) =
                                    crate::parameter_analysis::classify_special_chars(&text);
                                discovered = Some(Param {
                                    name: param_name.clone(),
                                    value: crate::scanning::markers::open_marker().to_string(),
                                    location: crate::parameter_analysis::Location::Query,
                                    injection_context: Some(context),
                                    valid_specials: Some(valid),
                                    invalid_specials: Some(invalid),
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
                                });
                                if !silence {
                                    eprintln!(
                                        "Discovered parameter: {} (EWMA {:.2}, {}/{})",
                                        param_name, st.ewma_ratio, st.reflections, st.attempts
                                    );
                                }
                                if st.should_collapse() {
                                    st.collapsed = true;
                                    if !silence {
                                        eprintln!(
                                            "[mining-collapse] High reflection EWMA {:.2} after {} attempts ({} reflections)",
                                            st.ewma_ratio, st.attempts, st.reflections
                                        );
                                    }
                                }
                            }
                        } else {
                            st.record_non_reflection();
                        }
                    }
                }

                if delay > 0 {
                    sleep(Duration::from_millis(delay)).await;
                }
                drop(permit);
                if let Some(ref pb) = pb_clone {
                    pb.inc(1);
                }
                discovered
            });

            handles.push(handle);
        }
    } // end chunk loop

    // Batch collect discovered parameters
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

    // Apply collapse post-processing once (instead of inside tasks mutating aggressively).
    // Only collapse Query params — preserve params discovered via other channels
    // (Body from form discovery, Header from header discovery, Path, etc.).
    let st_final = stats.lock().await;
    if st_final.collapsed {
        let mut guard = reflection_params.lock().await;
        // Preserve non-Query params (Body, Header, Path, JsonBody, Cookie, etc.)
        let non_query: Vec<Param> = guard
            .iter()
            .filter(|p| !matches!(p.location, crate::parameter_analysis::Location::Query))
            .cloned()
            .collect();
        let preserved = guard
            .iter()
            .find(|p| matches!(p.location, crate::parameter_analysis::Location::Query))
            .cloned();
        guard.clear();
        guard.extend(non_query);
        if let Some(orig) = preserved {
            guard.push(Param {
                name: "any".to_string(),
                value: orig.value.clone(),
                location: crate::parameter_analysis::Location::Query,
                injection_context: orig.injection_context.clone(),
                valid_specials: orig.valid_specials.clone(),
                invalid_specials: orig.invalid_specials.clone(),
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
            });
        } else {
            guard.push(Param {
                name: "any".to_string(),
                value: crate::scanning::markers::open_marker().to_string(),
                location: crate::parameter_analysis::Location::Query,
                injection_context: Some(crate::parameter_analysis::InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
            });
        }
    }
}

pub async fn probe_body_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ProgressBar>,
) {
    let arc_target = Arc::new(target.clone());
    let silence = args.silence;
    let client = target.build_client_or_default();

    if let Some(data) = &args.data {
        // Assume form data for now (application/x-www-form-urlencoded)
        let params: Vec<(String, String)> = form_urlencoded::parse(data.as_bytes())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        if let Some(ref pb) = pb {
            pb.set_length(params.len() as u64);
            pb.set_message("Mining body parameters");
        }

        // Adaptive EWMA stats shared across tasks
        let stats = Arc::new(Mutex::new(MiningSampleStats::new()));

        // Spawn tasks returning Option<Param> for batching
        let mut handles: Vec<tokio::task::JoinHandle<Option<Param>>> = Vec::new();

        for (param_name, _) in params {
            // Early stop if collapsed
            {
                let st = stats.lock().await;
                if st.collapsed {
                    break;
                }
            }
            // Skip already discovered params
            let exists = reflection_params
                .lock()
                .await
                .iter()
                .any(|p| p.name == param_name);
            if exists {
                continue;
            }

            // Build mutated body with this param set to marker
            let new_data = form_urlencoded::parse(data.as_bytes())
                .map(|(k, v)| {
                    if k == param_name {
                        (k, crate::scanning::markers::open_marker().to_string())
                    } else {
                        (k, v.to_string())
                    }
                })
                .collect::<Vec<_>>();
            let body = form_urlencoded::Serializer::new(String::new())
                .extend_pairs(new_data)
                .finish();

            let client_clone = client.clone();
            let url = target.url.clone();

            let parsed_method = reqwest::Method::POST;
            let target_clone = arc_target.clone();
            let delay = target.delay;
            let semaphore_clone = semaphore.clone();
            let param_name_cloned = param_name.clone();
            let pb_clone = pb.clone();
            let stats_clone = stats.clone();

            let handle = tokio::spawn(async move {
                let permit = semaphore_clone.acquire().await.expect("acquire semaphore permit");
                let m = parsed_method;
                let base =
                    crate::utils::build_request(&client_clone, &target_clone, m, url, Some(body));
                let overrides = vec![(
                    "Content-Type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                )];
                let request = crate::utils::apply_header_overrides(base, &overrides);

                let resp = request.send().await;
                crate::REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);

                let mut discovered: Option<Param> = None;
                if let Ok(r) = resp
                    && let Ok(text) = r.text().await
                {
                    let mut st = stats_clone.lock().await;
                    st.record_attempt();
                    if text.contains(crate::scanning::markers::open_marker()) {
                        st.record_reflection();
                        if !st.collapsed {
                            let context = detect_injection_context(&text);
                            let (valid, invalid) =
                                crate::parameter_analysis::classify_special_chars(&text);
                            discovered = Some(Param {
                                name: param_name_cloned.clone(),
                                value: crate::scanning::markers::open_marker().to_string(),
                                location: Location::Body,
                                injection_context: Some(context),
                                valid_specials: Some(valid),
                                invalid_specials: Some(invalid),
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
                            });
                            if !silence {
                                eprintln!(
                                    "Discovered body param: {} (EWMA {:.2}, {}/{})",
                                    param_name_cloned, st.ewma_ratio, st.reflections, st.attempts
                                );
                            }
                            if st.should_collapse() {
                                st.collapsed = true;
                                if !silence {
                                    eprintln!(
                                        "[mining-collapse] Body mining collapsed at EWMA {:.2} after {} attempts ({} reflections)",
                                        st.ewma_ratio, st.attempts, st.reflections
                                    );
                                }
                            }
                        }
                    } else {
                        st.record_non_reflection();
                    }
                }

                if delay > 0 {
                    sleep(Duration::from_millis(delay)).await;
                }
                drop(permit);
                if let Some(ref pb) = pb_clone {
                    pb.inc(1);
                }
                discovered
            });

            handles.push(handle);
        }

        // Batch collect discovered params
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

        // If collapsed after attempts, normalize Body params to single 'any' param.
        // Preserve non-Body params discovered via other channels.
        let st_final = stats.lock().await;
        if st_final.collapsed {
            let mut guard = reflection_params.lock().await;
            let non_body: Vec<Param> = guard
                .iter()
                .filter(|p| !matches!(p.location, Location::Body))
                .cloned()
                .collect();
            let preserved = guard
                .iter()
                .find(|p| matches!(p.location, Location::Body))
                .cloned();
            guard.clear();
            guard.extend(non_body);
            if let Some(orig) = preserved {
                guard.push(Param {
                    name: "any".to_string(),
                    value: orig.value.clone(),
                    location: Location::Body,
                    injection_context: orig.injection_context.clone(),
                    valid_specials: orig.valid_specials.clone(),
                    invalid_specials: orig.invalid_specials.clone(),
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
                });
            } else {
                guard.push(Param {
                    name: "any".to_string(),
                    value: crate::scanning::markers::open_marker().to_string(),
                    location: Location::Body,
                    injection_context: Some(crate::parameter_analysis::InjectionContext::Html(
                        None,
                    )),
                    valid_specials: None,
                    invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
                });
            }
        }
    }
}

pub async fn probe_response_id_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ProgressBar>,
) {
    let arc_target = Arc::new(target.clone());
    let silence = args.silence;
    let client = target.build_client_or_default();

    // First, get the HTML to find input ids and names
    let base_request = crate::utils::build_request(
        &client,
        target,
        target.parse_method(),
        target.url.clone(),
        target.data.clone(),
    );

    let __resp = base_request.send().await;
    crate::REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
    if let Ok(resp) = __resp
        && !resp.status().is_server_error()
        && let Ok(text) = resp.text().await
    {
        let document = scraper::Html::parse_document(&text);

        // Collect unique ids and names
        let mut params_to_check = std::collections::HashSet::new();
        let selector = selectors::input_with_id_or_name();
        for element in document.select(selector) {
            if let Some(id) = element.value().attr("id") {
                params_to_check.insert(id.to_string());
            }
            if let Some(name) = element.value().attr("name") {
                params_to_check.insert(name.to_string());
            }
        }

        if let Some(ref pb) = pb {
            pb.set_length(params_to_check.len() as u64);
            pb.set_message("Mining DOM parameters");
        }

        // Spawn tasks returning Option<Param> for batched collection
        let mut handles: Vec<tokio::task::JoinHandle<Option<Param>>> = Vec::new();
        let stats = Arc::new(Mutex::new(MiningSampleStats::new()));

        // Check each param for reflection
        for param in params_to_check {
            {
                let st = stats.lock().await;
                if st.collapsed {
                    break;
                }
            }
            let existing = reflection_params
                .lock()
                .await
                .iter()
                .any(|p| p.name == param);
            if existing {
                continue;
            }
            let mut url = target.url.clone();
            url.query_pairs_mut()
                .append_pair(&param, crate::scanning::markers::open_marker());
            let client_clone = client.clone();

            let data = target.data.clone();
            let parsed_method = target.parse_method();
            let target_clone = arc_target.clone();
            let delay = target.delay;
            let semaphore_clone = semaphore.clone();
            let param = param.clone();
            let pb_clone = pb.clone();
            let stats_clone = stats.clone();

            let handle = tokio::spawn(async move {
                let permit = semaphore_clone.acquire().await.expect("acquire semaphore permit");
                let m = parsed_method;
                let request =
                    crate::utils::build_request(&client_clone, &target_clone, m, url, data.clone());
                // Prepare optional discovered Param container for batched return
                let mut discovered: Option<Param> = None;
                let __resp = request.send().await;
                crate::REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
                if let Ok(resp) = __resp {
                    // Skip 5xx error responses — debug pages often reflect params
                    if resp.status().is_server_error() {
                        let mut st = stats_clone.lock().await;
                        st.record_attempt();
                        drop(permit);
                        if delay > 0 {
                            sleep(Duration::from_millis(delay)).await;
                        }
                        if let Some(ref pb) = pb_clone {
                            pb.inc(1);
                        }
                        return discovered;
                    }
                    if let Ok(text) = resp.text().await {
                    let mut st = stats_clone.lock().await;
                    st.record_attempt();
                    if text.contains(crate::scanning::markers::open_marker()) {
                        st.record_reflection();
                        if !st.collapsed {
                            let context = detect_injection_context(&text);
                            let (valid, invalid) =
                                crate::parameter_analysis::classify_special_chars(&text);
                            // Store discovered Param for return (batched later)
                            discovered = Some(Param {
                                name: param.clone(),
                                value: crate::scanning::markers::open_marker().to_string(),
                                location: crate::parameter_analysis::Location::Query,
                                injection_context: Some(context),
                                valid_specials: Some(valid),
                                invalid_specials: Some(invalid),
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
                            });
                            if !silence {
                                eprintln!(
                                    "Discovered DOM param: {} (EWMA {:.2}, {}/{})",
                                    param, st.ewma_ratio, st.reflections, st.attempts
                                );
                            }
                            if st.should_collapse() {
                                st.collapsed = true;
                                if !silence {
                                    eprintln!(
                                        "[mining-collapse] DOM mining collapsed at EWMA {:.2} after {} attempts ({} reflections)",
                                        st.ewma_ratio, st.attempts, st.reflections
                                    );
                                }
                            }
                        }
                    } else {
                        st.record_non_reflection();
                    }
                    }
                }
                if delay > 0 {
                    sleep(Duration::from_millis(delay)).await;
                }
                drop(permit);
                if let Some(ref pb) = pb_clone {
                    pb.inc(1);
                }
                // Return discovered Param (if any) for batch processing
                discovered
            });
            handles.push(handle);
        }

        // Batch collect discovered DOM params
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
        // Collapse post-processing (single 'any' param) if adaptive stats triggered it.
        // Preserve non-Query params discovered via other channels.
        let st_final = stats.lock().await;
        if st_final.collapsed {
            let mut guard = reflection_params.lock().await;
            let non_query: Vec<Param> = guard
                .iter()
                .filter(|p| !matches!(p.location, crate::parameter_analysis::Location::Query))
                .cloned()
                .collect();
            let preserved = guard
                .iter()
                .find(|p| matches!(p.location, crate::parameter_analysis::Location::Query))
                .cloned();
            guard.clear();
            guard.extend(non_query);
            if let Some(orig) = preserved {
                guard.push(Param {
                    name: "any".to_string(),
                    value: orig.value.clone(),
                    location: crate::parameter_analysis::Location::Query,
                    injection_context: orig.injection_context.clone(),
                    valid_specials: orig.valid_specials.clone(),
                    invalid_specials: orig.invalid_specials.clone(),
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
                });
            } else {
                guard.push(Param {
                    name: "any".to_string(),
                    value: crate::scanning::markers::open_marker().to_string(),
                    location: crate::parameter_analysis::Location::Query,
                    injection_context: Some(crate::parameter_analysis::InjectionContext::Html(
                        None,
                    )),
                    valid_specials: None,
                    invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
                });
            }
        }
    }
}

pub async fn probe_json_body_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ProgressBar>,
) {
    let arc_target = Arc::new(target.clone());
    let silence = args.silence;
    let client = target.build_client_or_default();

    // Detect JSON body from args.data; only proceed if it's a JSON object
    let base_json: serde_json::Value = match &args.data {
        Some(d) => match serde_json::from_str::<serde_json::Value>(d) {
            Ok(v) => v,
            Err(_) => return, // not JSON
        },
        None => return,
    };
    if !base_json.is_object() {
        return;
    }

    // Collect top-level keys to mutate
    let Some(obj) = base_json.as_object() else {
        return;
    };
    let keys: Vec<String> = obj.keys().cloned().collect();

    if let Some(ref pb) = pb {
        pb.set_length(keys.len() as u64);
        pb.set_message("Mining JSON body parameters");
    }

    // Adaptive EWMA stats shared across tasks
    let stats = Arc::new(Mutex::new(MiningSampleStats::new()));

    // Spawn tasks returning Option<Param> for batching
    let mut handles: Vec<tokio::task::JoinHandle<Option<Param>>> = Vec::new();

    for param_name in keys {
        {
            // Early collapse stop
            let st = stats.lock().await;
            if st.collapsed {
                break;
            }
        }
        // Skip if already discovered
        let exists = reflection_params
            .lock()
            .await
            .iter()
            .any(|p| p.name == param_name);
        if exists {
            continue;
        }

        let client_clone = client.clone();
        let url = target.url.clone();

        let parsed_method = reqwest::Method::POST;
        let target_clone = arc_target.clone();
        let delay = target.delay;
        let semaphore_clone = semaphore.clone();
        let param_name_cloned = param_name.clone();
        let pb_clone = pb.clone();
        let stats_clone = stats.clone();
        let base_json_clone = base_json.clone();

        let handle = tokio::spawn(async move {
            let permit = semaphore_clone.acquire().await.expect("acquire semaphore permit");

            // Build mutated JSON with this key set to marker
            let mut root = base_json_clone;
            if let Some(map) = root.as_object_mut() {
                map.insert(
                    param_name_cloned.clone(),
                    serde_json::Value::String(crate::scanning::markers::open_marker().to_string()),
                );
            } else {
                let mut map = serde_json::Map::new();
                map.insert(
                    param_name_cloned.clone(),
                    serde_json::Value::String(crate::scanning::markers::open_marker().to_string()),
                );
                root = serde_json::Value::Object(map);
            }
            let body = serde_json::to_string(&root).unwrap_or_else(|_| {
                format!(
                    "{{\"{}\":\"{}\"}}",
                    param_name_cloned,
                    crate::scanning::markers::open_marker()
                )
            });

            let base =
                crate::utils::build_request(&client_clone, &target_clone, parsed_method, url, Some(body));
            let overrides = vec![("Content-Type".to_string(), "application/json".to_string())];
            let request = crate::utils::apply_header_overrides(base, &overrides);

            let resp = request.send().await;
            crate::REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);

            let mut discovered: Option<Param> = None;
            if let Ok(r) = resp
                && let Ok(text) = r.text().await
            {
                let mut st = stats_clone.lock().await;
                st.record_attempt();
                if text.contains(crate::scanning::markers::open_marker()) {
                    st.record_reflection();
                    if !st.collapsed {
                        let context = detect_injection_context(&text);
                        let (valid, invalid) =
                            crate::parameter_analysis::classify_special_chars(&text);
                        discovered = Some(Param {
                            name: param_name_cloned.clone(),
                            value: crate::scanning::markers::open_marker().to_string(),
                            location: Location::JsonBody,
                            injection_context: Some(context),
                            valid_specials: Some(valid),
                            invalid_specials: Some(invalid),
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
                        });
                        if !silence {
                            eprintln!(
                                "Discovered JSON body param: {} (EWMA {:.2}, {}/{})",
                                param_name_cloned, st.ewma_ratio, st.reflections, st.attempts
                            );
                        }
                        if st.should_collapse() {
                            st.collapsed = true;
                            if !silence {
                                eprintln!(
                                    "[mining-collapse] JSON mining collapsed at EWMA {:.2} after {} attempts ({} reflections)",
                                    st.ewma_ratio, st.attempts, st.reflections
                                );
                            }
                        }
                    }
                } else {
                    st.record_non_reflection();
                }
            }

            if delay > 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            drop(permit);
            if let Some(ref pb) = pb_clone {
                pb.inc(1);
            }
            discovered
        });

        handles.push(handle);
    }

    // Batch collect discovered params
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

    // Collapse normalization to single 'any' JSON param if triggered.
    // Preserve non-JsonBody params discovered via other channels.
    let st_final = stats.lock().await;
    if st_final.collapsed {
        let mut guard = reflection_params.lock().await;
        let non_json: Vec<Param> = guard
            .iter()
            .filter(|p| !matches!(p.location, Location::JsonBody))
            .cloned()
            .collect();
        let preserved = guard
            .iter()
            .find(|p| matches!(p.location, Location::JsonBody))
            .cloned();
        guard.clear();
        guard.extend(non_json);
        if let Some(orig) = preserved {
            guard.push(Param {
                name: "any".to_string(),
                value: orig.value.clone(),
                location: Location::JsonBody,
                injection_context: orig.injection_context.clone(),
                valid_specials: orig.valid_specials.clone(),
                invalid_specials: orig.invalid_specials.clone(),
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
            });
        } else {
            guard.push(Param {
                name: "any".to_string(),
                value: crate::scanning::markers::open_marker().to_string(),
                location: Location::JsonBody,
                injection_context: Some(crate::parameter_analysis::InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
                    pre_encoding: None,
                    form_action_url: None,
                    form_origin_url: None,
            });
        }
    }
}

pub async fn mine_parameters(
    target: &mut Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ProgressBar>,
) {
    if !args.skip_mining {
        if !args.skip_mining_dict {
            probe_dictionary_params(
                target,
                args,
                reflection_params.clone(),
                semaphore.clone(),
                pb.clone(),
            )
            .await;
            probe_body_params(
                target,
                args,
                reflection_params.clone(),
                semaphore.clone(),
                pb.clone(),
            )
            .await;

            // JSON body mining (top-level keys)
            probe_json_body_params(
                target,
                args,
                reflection_params.clone(),
                semaphore.clone(),
                pb.clone(),
            )
            .await;
        }
        if !args.skip_mining_dom {
            probe_response_id_params(
                target,
                args,
                reflection_params.clone(),
                semaphore.clone(),
                pb.clone(),
            )
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target_parser::parse_target;
    use axum::{Router, extract::Query, response::Html, routing::get};
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::time::{Duration, sleep};

    fn default_scan_args() -> ScanArgs {
        ScanArgs {
            input_type: "url".to_string(),
            format: "json".to_string(),
            targets: vec!["http://127.0.0.1:1".to_string()],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            include_url: vec![],
            exclude_url: vec![],
            ignore_param: vec![],
            out_of_scope: vec![],
            out_of_scope_file: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            only_discovery: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 1,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            ignore_return: vec![],
            output: None,
            include_request: false,
            include_response: false,
            include_all: false,
            no_color: false,
            silence: true,
            poc_type: "plain".to_string(),
            limit: None,
            only_poc: vec![],
            workers: 1,
            max_concurrent_targets: 1,
            max_targets_per_host: 1,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            inject_marker: None,
            custom_alert_value: "1".to_string(),
            custom_alert_type: "none".to_string(),
            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        }
    }

    #[test]
    fn test_mining_sample_stats_collapses_after_sustained_reflection() {
        let mut stats = MiningSampleStats::new();
        assert!(!stats.should_collapse());

        for _ in 0..15 {
            stats.record_attempt();
            stats.record_reflection();
        }

        assert!(stats.reflections >= 5);
        assert!(stats.attempts >= 15);
        assert!(stats.ewma_ratio >= COLLAPSE_EWMA_THRESHOLD);
        assert!(stats.should_collapse());
    }

    #[test]
    fn test_mining_sample_stats_non_reflection_keeps_low_ewma() {
        let mut stats = MiningSampleStats::new();
        for _ in 0..20 {
            stats.record_attempt();
            stats.record_non_reflection();
        }
        assert_eq!(stats.reflections, 0);
        assert!(!stats.should_collapse());
    }

    #[test]
    fn test_detect_injection_context_without_marker_is_html() {
        let ctx = detect_injection_context("<html><body>plain</body></html>");
        assert_eq!(ctx, InjectionContext::Html(None));
    }

    #[test]
    fn test_detect_injection_context_comment_delimiter() {
        let marker = crate::scanning::markers::open_marker();
        let body = format!("<!-- {} -->", marker);
        let ctx = detect_injection_context(&body);
        assert_eq!(ctx, InjectionContext::Html(Some(DelimiterType::Comment)));
    }

    #[test]
    fn test_detect_injection_context_script_single_quote() {
        let marker = crate::scanning::markers::open_marker();
        let body = format!("<script>var x='{}';</script>", marker);
        let ctx = detect_injection_context(&body);
        assert_eq!(
            ctx,
            InjectionContext::Javascript(Some(DelimiterType::SingleQuote))
        );
    }

    #[test]
    fn test_detect_injection_context_attribute_double_quote() {
        let marker = crate::scanning::markers::open_marker();
        let body = format!("<img alt=\"{}\">", marker);
        let ctx = detect_injection_context(&body);
        assert_eq!(
            ctx,
            InjectionContext::Attribute(Some(DelimiterType::DoubleQuote))
        );
    }

    #[test]
    fn test_detect_injection_context_url_attribute_double_quote() {
        let marker = crate::scanning::markers::open_marker();
        let body = format!("<iframe src=\"{}\"></iframe>", marker);
        let ctx = detect_injection_context(&body);
        assert_eq!(
            ctx,
            InjectionContext::AttributeUrl(Some(DelimiterType::DoubleQuote))
        );
    }

    #[tokio::test]
    async fn test_probe_dictionary_params_returns_when_wordlist_file_missing() {
        let target = parse_target("http://127.0.0.1:1").expect("parse target");
        let mut args = default_scan_args();
        args.mining_dict_word = Some("/definitely/not/found/dalfox-wordlist.txt".to_string());

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        probe_dictionary_params(&target, &args, reflection_params.clone(), semaphore, None).await;

        assert!(reflection_params.lock().await.is_empty());
    }

    #[tokio::test]
    async fn test_probe_body_params_without_data_is_noop() {
        let target = parse_target("http://127.0.0.1:1").expect("parse target");
        let args = default_scan_args();
        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));

        probe_body_params(&target, &args, reflection_params.clone(), semaphore, None).await;
        assert!(reflection_params.lock().await.is_empty());
    }

    #[tokio::test]
    async fn test_probe_json_body_params_returns_for_invalid_or_non_object_data() {
        let target = parse_target("http://127.0.0.1:1").expect("parse target");
        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));

        let mut invalid_json_args = default_scan_args();
        invalid_json_args.data = Some("{not-json".to_string());
        probe_json_body_params(
            &target,
            &invalid_json_args,
            reflection_params.clone(),
            semaphore.clone(),
            None,
        )
        .await;
        assert!(reflection_params.lock().await.is_empty());

        let mut non_object_json_args = default_scan_args();
        non_object_json_args.data = Some("[1,2,3]".to_string());
        probe_json_body_params(
            &target,
            &non_object_json_args,
            reflection_params.clone(),
            semaphore,
            None,
        )
        .await;
        assert!(reflection_params.lock().await.is_empty());
    }

    #[tokio::test]
    async fn test_mine_parameters_skip_mining_leaves_params_untouched() {
        let mut target = parse_target("http://127.0.0.1:1").expect("parse target");
        let mut args = default_scan_args();
        args.skip_mining = true;

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        mine_parameters(
            &mut target,
            &args,
            reflection_params.clone(),
            semaphore,
            None,
        )
        .await;

        assert!(reflection_params.lock().await.is_empty());
    }

    #[tokio::test]
    async fn test_mine_parameters_dom_only_on_unreachable_target_does_not_panic() {
        let mut target = parse_target("http://127.0.0.1:1").expect("parse target");
        let mut args = default_scan_args();
        args.skip_mining = false;
        args.skip_mining_dict = true;
        args.skip_mining_dom = false;

        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        mine_parameters(
            &mut target,
            &args,
            reflection_params.clone(),
            semaphore,
            None,
        )
        .await;

        assert!(reflection_params.lock().await.is_empty());
    }

    async fn dom_mining_handler(Query(params): Query<HashMap<String, String>>) -> Html<String> {
        let marker = params.get("search").cloned().unwrap_or_default();
        Html(format!(
            "<form><input id=\"search\" name=\"search\" value=\"seed\"></form><div>{}</div>",
            marker
        ))
    }

    async fn start_dom_mining_server() -> SocketAddr {
        let app = Router::new().route("/dom-mining", get(dom_mining_handler));
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        sleep(Duration::from_millis(20)).await;
        addr
    }

    #[tokio::test]
    async fn test_probe_response_id_params_discovers_reflected_input_name() {
        let addr = start_dom_mining_server().await;
        let target = parse_target(&format!("http://{}:{}/dom-mining", addr.ip(), addr.port()))
            .expect("parse target");
        let args = default_scan_args();
        let reflection_params = Arc::new(Mutex::new(Vec::<Param>::new()));
        let semaphore = Arc::new(tokio::sync::Semaphore::new(2));

        probe_response_id_params(&target, &args, reflection_params.clone(), semaphore, None).await;

        let params = reflection_params.lock().await.clone();
        assert!(params.iter().any(|p| {
            p.name == "search"
                && p.location == Location::Query
                && p.value == crate::scanning::markers::open_marker()
        }));
    }
}
