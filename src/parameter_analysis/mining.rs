use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::{DelimiterType, InjectionContext, Location, Param};
use crate::payload::mining::GF_PATTERNS_PARAMS;
use crate::target_parser::Target;
use indicatif::ProgressBar;
use reqwest::Client;
use scraper;
use std::sync::{Arc, atomic::Ordering};

use tokio::sync::{Mutex, Semaphore};
use tokio::time::{Duration, sleep};
use url::form_urlencoded;

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
    if !text.contains(marker) {
        return InjectionContext::Html(None);
    }

    // Fast comment check using raw HTML when available
    if let (Some(cs), Some(ce)) = (text.find("<!--"), text.find("-->")) {
        if let Some(mp) = text.find(marker) {
            if cs < mp && mp < ce {
                return InjectionContext::Html(Some(DelimiterType::Comment));
            }
        }
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
            (Some(dq), Some(sq)) => if dq > sq { ('"', dq) } else { ('\'', sq) },
            (Some(dq), None) => ('"', dq),
            (None, Some(sq)) => ('\'', sq),
        (None, None) => return None,
        };
        let next = after.find(qch);
        if next.is_some() {
            return Some(match qch { '"' => DelimiterType::DoubleQuote, '\'' => DelimiterType::SingleQuote, _ => return None });
        }
        None
    }

    // 1) JavaScript context: marker appears in any <script> text
    if let Ok(sel) = scraper::Selector::parse("script") {
        for el in document.select(&sel) {
            let s = el.text().collect::<Vec<_>>().join("");
            if s.contains(marker) {
                let delim = infer_quote_delimiter(text, marker);
                return InjectionContext::Javascript(delim);
            }
        }
    }

    // 2) Attribute context: marker in any attribute value
    if let Ok(any) = scraper::Selector::parse("*") {
        for el in document.select(&any) {
            for (_name, v) in el.value().attrs() {
                if v.contains(marker) {
                    let delim = infer_quote_delimiter(text, marker);
                    return InjectionContext::Attribute(delim);
                }
            }
        }
    }

    // 3) HTML text context: marker in non-script text nodes
    if let Ok(any) = scraper::Selector::parse("*") {
        for el in document.select(&any) {
            if el.value().name().eq_ignore_ascii_case("script") {
                continue;
            }
            let s = el.text().collect::<Vec<_>>().join("");
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
    let client = target.build_client().unwrap_or_else(|_| Client::new());

    // Resolve candidate parameter names (remote, file, or built-ins)
    let mut params: Vec<String> = Vec::new();
    let mut loaded = false;

    if !args.remote_wordlists.is_empty() {
        if let Err(e) = crate::payload::init_remote_wordlists(&args.remote_wordlists).await {
            if !silence {
                eprintln!("Error initializing remote wordlists: {}", e);
            }
        }
        if let Some(words) = crate::payload::get_remote_words() {
            if !words.is_empty() {
                params = words.as_ref().clone();
                loaded = true;
            }
        }
    }

    if !loaded {
        if let Some(wordlist_path) = &args.mining_dict_word {
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
                .append_pair(&param, crate::scanning::markers::open_marker());

            let client_clone = client.clone();

            let data = target.data.clone();
            let method = target.method.clone();
            let target_clone = arc_target.clone();
            let delay = target.delay;
            let semaphore_clone = semaphore.clone();
            let param_name = param.clone();
            let pb_clone = pb.clone();
            let stats_clone = stats.clone();

            let handle = tokio::spawn(async move {
                let permit = semaphore_clone.acquire().await.unwrap();
                let m = method.parse().unwrap_or(reqwest::Method::GET);
                let request =
                    crate::utils::build_request(&client_clone, &target_clone, m, url, data.clone());

                let resp = request.send().await;
                crate::REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);

                let mut discovered: Option<Param> = None;
                if let Ok(r) = resp {
                    if let Ok(text) = r.text().await {
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
        if let Ok(opt) = h.await {
            if let Some(p) = opt {
                batch.push(p);
            }
        }
    }

    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }

    // Apply collapse post-processing once (instead of inside tasks mutating aggressively)
    let st_final = stats.lock().await;
    if st_final.collapsed {
        let mut guard = reflection_params.lock().await;
        let preserved = guard.first().cloned();
        guard.clear();
        if let Some(orig) = preserved {
            guard.push(Param {
                name: "any".to_string(),
                value: orig.value.clone(),
                location: crate::parameter_analysis::Location::Query,
                injection_context: orig.injection_context.clone(),
                valid_specials: orig.valid_specials.clone(),
                invalid_specials: orig.invalid_specials.clone(),
            });
        } else {
            guard.push(Param {
                name: "any".to_string(),
                value: crate::scanning::markers::open_marker().to_string(),
                location: crate::parameter_analysis::Location::Query,
                injection_context: Some(crate::parameter_analysis::InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
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
    let client = target.build_client().unwrap_or_else(|_| Client::new());

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

            let method = target.method.clone();
            let target_clone = arc_target.clone();
            let delay = target.delay;
            let semaphore_clone = semaphore.clone();
            let param_name_cloned = param_name.clone();
            let pb_clone = pb.clone();
            let stats_clone = stats.clone();

            let handle = tokio::spawn(async move {
                let permit = semaphore_clone.acquire().await.unwrap();
                let m = method.parse().unwrap_or(reqwest::Method::POST);
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
                if let Ok(r) = resp {
                    if let Ok(text) = r.text().await {
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
                                });
                                if !silence {
                                    eprintln!(
                                        "Discovered body param: {} (EWMA {:.2}, {}/{})",
                                        param_name_cloned,
                                        st.ewma_ratio,
                                        st.reflections,
                                        st.attempts
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
            if let Ok(opt) = h.await {
                if let Some(p) = opt {
                    batch.push(p);
                }
            }
        }
        if !batch.is_empty() {
            let mut guard = reflection_params.lock().await;
            guard.extend(batch);
        }

        // If collapsed after attempts, normalize to single 'any' param
        let st_final = stats.lock().await;
        if st_final.collapsed {
            let mut guard = reflection_params.lock().await;
            let preserved = guard.first().cloned();
            guard.clear();
            if let Some(orig) = preserved {
                guard.push(Param {
                    name: "any".to_string(),
                    value: orig.value.clone(),
                    location: Location::Body,
                    injection_context: orig.injection_context.clone(),
                    valid_specials: orig.valid_specials.clone(),
                    invalid_specials: orig.invalid_specials.clone(),
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
    let client = target.build_client().unwrap_or_else(|_| Client::new());

    // First, get the HTML to find input ids and names
    let base_request = crate::utils::build_request(
        &client,
        target,
        target.method.parse().unwrap_or(reqwest::Method::GET),
        target.url.clone(),
        target.data.clone(),
    );

    let __resp = base_request.send().await;
    crate::REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
    if let Ok(resp) = __resp {
        if let Ok(text) = resp.text().await {
            let document = scraper::Html::parse_document(&text);

            // Collect unique ids and names
            let mut params_to_check = std::collections::HashSet::new();
            let selector = scraper::Selector::parse("input[id], input[name]").unwrap();
            for element in document.select(&selector) {
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
                url.query_pairs_mut().append_pair(&param, "dalfox");
                let client_clone = client.clone();

                let data = target.data.clone();
                let method = target.method.clone();
                let target_clone = arc_target.clone();
                let delay = target.delay;
                // removed unused variable reflection_params_clone
                let semaphore_clone = semaphore.clone();
                let param = param.clone();
                let pb_clone = pb.clone();
                let stats_clone = stats.clone();

                let handle = tokio::spawn(async move {
                    let permit = semaphore_clone.acquire().await.unwrap();
                    let m = method.parse().unwrap_or(reqwest::Method::GET);
                    let request = crate::utils::build_request(
                        &client_clone,
                        &target_clone,
                        m,
                        url,
                        data.clone(),
                    );
                    // Prepare optional discovered Param container for batched return
                    let mut discovered: Option<Param> = None;
                    let __resp = request.send().await;
                    crate::REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
                    if let Ok(resp) = __resp {
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
                if let Ok(opt) = handle.await {
                    if let Some(p) = opt {
                        batch.push(p);
                    }
                }
            }
            if !batch.is_empty() {
                let mut guard = reflection_params.lock().await;
                guard.extend(batch);
            }
            // Collapse post-processing (single 'any' param) if adaptive stats triggered it
            let st_final = stats.lock().await;
            if st_final.collapsed {
                let mut guard = reflection_params.lock().await;
                let preserved = guard.first().cloned();
                guard.clear();
                if let Some(orig) = preserved {
                    guard.push(Param {
                        name: "any".to_string(),
                        value: orig.value.clone(),
                        location: crate::parameter_analysis::Location::Query,
                        injection_context: orig.injection_context.clone(),
                        valid_specials: orig.valid_specials.clone(),
                        invalid_specials: orig.invalid_specials.clone(),
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
                    });
                }
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
    let client = target.build_client().unwrap_or_else(|_| Client::new());

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
    let keys: Vec<String> = base_json.as_object().unwrap().keys().cloned().collect();

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

        let method = target.method.clone();
        let target_clone = arc_target.clone();
        let delay = target.delay;
        let semaphore_clone = semaphore.clone();
        let param_name_cloned = param_name.clone();
        let pb_clone = pb.clone();
        let stats_clone = stats.clone();
        let base_json_clone = base_json.clone();

        let handle = tokio::spawn(async move {
            let permit = semaphore_clone.acquire().await.unwrap();

            // Build mutated JSON with this key set to marker
            let mut root = base_json_clone;
            if let Some(map) = root.as_object_mut() {
                map.insert(
                    param_name_cloned.clone(),
                    serde_json::Value::String(
                        crate::scanning::markers::open_marker().to_string(),
                    ),
                );
            } else {
                let mut map = serde_json::Map::new();
                map.insert(
                    param_name_cloned.clone(),
                    serde_json::Value::String(
                        crate::scanning::markers::open_marker().to_string(),
                    ),
                );
                root = serde_json::Value::Object(map);
            }
            let body = serde_json::to_string(&root)
                .unwrap_or_else(|_| {
                    format!(
                        "{{\"{}\":\"{}\"}}",
                        param_name_cloned,
                        crate::scanning::markers::open_marker()
                    )
                });

            let m = method.parse().unwrap_or(reqwest::Method::POST);
            let base =
                crate::utils::build_request(&client_clone, &target_clone, m, url, Some(body));
            let overrides = vec![("Content-Type".to_string(), "application/json".to_string())];
            let request = crate::utils::apply_header_overrides(base, &overrides);

            let resp = request.send().await;
            crate::REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);

            let mut discovered: Option<Param> = None;
            if let Ok(r) = resp {
                if let Ok(text) = r.text().await {
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
        if let Ok(opt) = h.await {
            if let Some(p) = opt {
                batch.push(p);
            }
        }
    }
    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }

    // Collapse normalization to single 'any' JSON param if triggered
    let st_final = stats.lock().await;
    if st_final.collapsed {
        let mut guard = reflection_params.lock().await;
        let preserved = guard.first().cloned();
        guard.clear();
        if let Some(orig) = preserved {
            guard.push(Param {
                name: "any".to_string(),
                value: orig.value.clone(),
                location: Location::JsonBody,
                injection_context: orig.injection_context.clone(),
                valid_specials: orig.valid_specials.clone(),
                invalid_specials: orig.invalid_specials.clone(),
            });
        } else {
            guard.push(Param {
                name: "any".to_string(),
                value: crate::scanning::markers::open_marker().to_string(),
                location: Location::JsonBody,
                injection_context: Some(crate::parameter_analysis::InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
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
