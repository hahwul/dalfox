use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::{InjectionContext, Location, Param};
use crate::payload::mining::GF_PATTERNS_PARAMS;
use crate::target_parser::Target;
use indicatif::ProgressBar;
use reqwest::Client;
use scraper;
use std::sync::Arc;

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
    let dalfox_pos = match text.find("dalfox") {
        Some(pos) => pos,
        None => return InjectionContext::Html(None),
    };

    // Check for JavaScript context
    if let Some(script_start) = text.find("<script") {
        if let Some(script_end) = text.find("</script>") {
            if script_start < dalfox_pos && dalfox_pos < script_end {
                // Check for delimiter type in JavaScript
                if text.contains("\"dalfox\"") {
                    return InjectionContext::Javascript(Some(
                        crate::parameter_analysis::DelimiterType::DoubleQuote,
                    ));
                } else if text.contains("'dalfox'") {
                    return InjectionContext::Javascript(Some(
                        crate::parameter_analysis::DelimiterType::SingleQuote,
                    ));
                } else {
                    return InjectionContext::Javascript(None);
                }
            }
        }
    }

    // Check for comment context
    if let Some(comment_start) = text.find("<!--") {
        if let Some(comment_end) = text.find("-->") {
            if comment_start < dalfox_pos && dalfox_pos < comment_end {
                // Check for delimiter type in comment
                if text.contains("\"dalfox\"") {
                    return InjectionContext::Html(Some(
                        crate::parameter_analysis::DelimiterType::Comment,
                    ));
                } else if text.contains("'dalfox'") {
                    return InjectionContext::Html(Some(
                        crate::parameter_analysis::DelimiterType::Comment,
                    ));
                } else {
                    return InjectionContext::Html(Some(
                        crate::parameter_analysis::DelimiterType::Comment,
                    ));
                }
            }
        }
    }

    // Check for attribute context
    if text.contains("=\"dalfox\"") {
        return InjectionContext::Attribute(Some(
            crate::parameter_analysis::DelimiterType::DoubleQuote,
        ));
    } else if text.contains("='dalfox'") {
        return InjectionContext::Attribute(Some(
            crate::parameter_analysis::DelimiterType::SingleQuote,
        ));
    }

    // Check for string contexts (fallback)
    if text.contains("\"dalfox\"") {
        return InjectionContext::Attribute(Some(
            crate::parameter_analysis::DelimiterType::DoubleQuote,
        ));
    }
    if text.contains("'dalfox'") {
        return InjectionContext::Attribute(Some(
            crate::parameter_analysis::DelimiterType::SingleQuote,
        ));
    }

    // Default to HTML
    InjectionContext::Html(None)
}

pub async fn probe_dictionary_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ProgressBar>,
) {
    let silence = args.silence;
    let mut client_builder = Client::builder().timeout(Duration::from_secs(target.timeout));
    if let Some(proxy_url) = &target.proxy {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            client_builder = client_builder.proxy(proxy);
        }
    }
    let client = client_builder.build().unwrap_or_else(|_| Client::new());

    // Get parameters from wordlist or default
    let params: Vec<String> = if let Some(wordlist_path) = &args.mining_dict_word {
        match std::fs::read_to_string(wordlist_path) {
            Ok(content) => content
                .lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            Err(e) => {
                if !silence {
                    eprintln!("Error reading wordlist file {}: {}", wordlist_path, e);
                }
                return;
            }
        }
    } else {
        GF_PATTERNS_PARAMS.iter().map(|s| s.to_string()).collect()
    };

    if let Some(ref pb) = pb {
        pb.set_length(params.len() as u64);
        pb.set_message("Mining dictionary parameters");
    }

    let mut handles: Vec<tokio::task::JoinHandle<()>> = vec![];

    // Adaptive sampling stats (EWMA-based)
    let stats = Arc::new(Mutex::new(MiningSampleStats::new()));

    // Check for additional valid parameters
    for param in params {
        // Collapse check (after previous updates possibly set collapsed)
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
        let headers = target.headers.clone();
        let user_agent = target.user_agent.clone();
        let cookies = target.cookies.clone();
        let data = target.data.clone();
        let method = target.method.clone();
        let delay = target.delay;
        let reflection_params_clone = reflection_params.clone();
        let semaphore_clone = semaphore.clone();
        let param = param.clone();
        let pb_clone = pb.clone();
        let stats_clone = stats.clone();

        let handle = tokio::spawn(async move {
            let permit = semaphore_clone.acquire().await.unwrap();
            let mut request =
                client_clone.request(method.parse().unwrap_or(reqwest::Method::GET), url);
            for (k, v) in &headers {
                request = request.header(k, v);
            }
            if let Some(ua) = &user_agent {
                request = request.header("User-Agent", ua);
            }
            for (k, v) in &cookies {
                request = request.header("Cookie", format!("{}={}", k, v));
            }
            if let Some(data) = &data {
                request = request.body(data.clone());
            }
            if let Ok(resp) = request.send().await {
                if let Ok(text) = resp.text().await {
                    let mut st = stats_clone.lock().await;
                    st.record_attempt();
                    if text.contains("dalfox") {
                        st.record_reflection();
                        if !st.collapsed {
                            let context = detect_injection_context(&text);
                            let (valid, invalid) =
                                crate::parameter_analysis::classify_special_chars(&text);
                            let param_struct = Param {
                                name: param.clone(),
                                value: "dalfox".to_string(),
                                location: crate::parameter_analysis::Location::Query,
                                injection_context: Some(context),
                                valid_specials: Some(valid),
                                invalid_specials: Some(invalid),
                            };
                            reflection_params_clone.lock().await.push(param_struct);
                            if !silence {
                                eprintln!(
                                    "Discovered parameter: {} (EWMA {:.2}, {}/{})",
                                    param, st.ewma_ratio, st.reflections, st.attempts
                                );
                            }
                            if st.should_collapse() {
                                st.collapsed = true;
                                // Collapse existing discovered params into single synthetic 'any'
                                let mut guard = reflection_params_clone.lock().await;
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
                                        value: "dalfox".to_string(),
                                        location: crate::parameter_analysis::Location::Query,
                                        injection_context: Some(
                                            crate::parameter_analysis::InjectionContext::Html(None),
                                        ),
                                        valid_specials: None,
                                        invalid_specials: None,
                                    });
                                }
                                if !silence {
                                    eprintln!(
                                        "[mining-collapse] High reflection EWMA {:.2} after {} attempts ({} reflections) -> collapsing to single 'any' param",
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
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

pub async fn probe_body_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ProgressBar>,
) {
    let silence = args.silence;
    let mut client_builder = Client::builder().timeout(Duration::from_secs(target.timeout));
    if let Some(proxy_url) = &target.proxy {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            client_builder = client_builder.proxy(proxy);
        }
    }
    let client = client_builder.build().unwrap_or_else(|_| Client::new());

    if let Some(data) = &args.data {
        // Assume form data for now (application/x-www-form-urlencoded)
        let params: Vec<(String, String)> = form_urlencoded::parse(data.as_bytes())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        if let Some(ref pb) = pb {
            pb.set_length(params.len() as u64);
            pb.set_message("Mining body parameters");
        }

        let mut handles: Vec<tokio::task::JoinHandle<()>> = vec![];
        let stats = Arc::new(Mutex::new(MiningSampleStats::new()));

        for (param_name, _) in params {
            // Sampling stop for body parameters
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
                .any(|p| p.name == param_name);
            if existing {
                continue;
            }
            let new_data = form_urlencoded::parse(data.as_bytes())
                .map(|(k, v)| {
                    if k == param_name {
                        (k, "dalfox".to_string())
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
            let headers = target.headers.clone();
            let user_agent = target.user_agent.clone();
            let cookies = target.cookies.clone();
            let method = target.method.clone();
            let delay = target.delay;
            let reflection_params_clone = reflection_params.clone();
            let semaphore_clone = semaphore.clone();
            let param_name = param_name.clone();
            let pb_clone = pb.clone();
            let stats_clone = stats.clone();

            let handle = tokio::spawn(async move {
                let permit = semaphore_clone.acquire().await.unwrap();
                let mut request =
                    client_clone.request(method.parse().unwrap_or(reqwest::Method::POST), url);
                for (k, v) in &headers {
                    request = request.header(k, v);
                }
                if let Some(ua) = &user_agent {
                    request = request.header("User-Agent", ua);
                }
                for (k, v) in &cookies {
                    request = request.header("Cookie", format!("{}={}", k, v));
                }
                request = request.header("Content-Type", "application/x-www-form-urlencoded");
                request = request.body(body);

                if let Ok(resp) = request.send().await {
                    if let Ok(text) = resp.text().await {
                        let mut st = stats_clone.lock().await;
                        st.record_attempt();
                        if text.contains("dalfox") {
                            st.record_reflection();
                            if !st.collapsed {
                                let context = detect_injection_context(&text);
                                let (valid, invalid) =
                                    crate::parameter_analysis::classify_special_chars(&text);
                                let param = Param {
                                    name: param_name.clone(),
                                    value: "dalfox".to_string(),
                                    location: Location::Body,
                                    injection_context: Some(context),
                                    valid_specials: Some(valid),
                                    invalid_specials: Some(invalid),
                                };
                                let mut guard = reflection_params_clone.lock().await;
                                guard.push(param);
                                if !silence {
                                    eprintln!(
                                        "Discovered body param: {} (EWMA {:.2}, {}/{})",
                                        param_name, st.ewma_ratio, st.reflections, st.attempts
                                    );
                                }
                                if st.should_collapse() {
                                    st.collapsed = true;
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
                                            value: "dalfox".to_string(),
                                            location: Location::Body,
                                            injection_context: Some(
                                                crate::parameter_analysis::InjectionContext::Html(
                                                    None,
                                                ),
                                            ),
                                            valid_specials: None,
                                            invalid_specials: None,
                                        });
                                    }
                                    if !silence {
                                        eprintln!(
                                            "[mining-collapse] Body mining collapsed at EWMA {:.2} after {} attempts",
                                            st.ewma_ratio, st.attempts
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
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
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
    let silence = args.silence;
    let mut client_builder = Client::builder().timeout(Duration::from_secs(target.timeout));
    if let Some(proxy_url) = &target.proxy {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            client_builder = client_builder.proxy(proxy);
        }
    }
    let client = client_builder.build().unwrap_or_else(|_| Client::new());

    // First, get the HTML to find input ids and names
    let mut base_request = client.request(
        target.method.parse().unwrap_or(reqwest::Method::GET),
        target.url.clone(),
    );
    for (k, v) in &target.headers {
        base_request = base_request.header(k, v);
    }
    if let Some(ua) = &target.user_agent {
        base_request = base_request.header("User-Agent", ua);
    }
    for (k, v) in &target.cookies {
        base_request = base_request.header("Cookie", format!("{}={}", k, v));
    }
    if let Some(data) = &target.data {
        base_request = base_request.body(data.clone());
    }

    if let Ok(resp) = base_request.send().await {
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

            let mut handles: Vec<tokio::task::JoinHandle<()>> = vec![];
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
                let headers = target.headers.clone();
                let user_agent = target.user_agent.clone();
                let cookies = target.cookies.clone();
                let data = target.data.clone();
                let method = target.method.clone();
                let delay = target.delay;
                let reflection_params_clone = reflection_params.clone();
                let semaphore_clone = semaphore.clone();
                let param = param.clone();
                let pb_clone = pb.clone();
                let stats_clone = stats.clone();

                let handle = tokio::spawn(async move {
                    let permit = semaphore_clone.acquire().await.unwrap();
                    let mut request =
                        client_clone.request(method.parse().unwrap_or(reqwest::Method::GET), url);
                    for (k, v) in &headers {
                        request = request.header(k, v);
                    }
                    if let Some(ua) = &user_agent {
                        request = request.header("User-Agent", ua);
                    }
                    for (k, v) in &cookies {
                        request = request.header("Cookie", format!("{}={}", k, v));
                    }
                    if let Some(data) = &data {
                        request = request.body(data.clone());
                    }
                    if let Ok(resp) = request.send().await {
                        if let Ok(text) = resp.text().await {
                            let mut st = stats_clone.lock().await;
                            st.record_attempt();
                            if text.contains("dalfox") {
                                st.record_reflection();
                                if !st.collapsed {
                                    let context = detect_injection_context(&text);
                                    let (valid, invalid) =
                                        crate::parameter_analysis::classify_special_chars(&text);
                                    let param_struct = Param {
                                        name: param.clone(),
                                        value: "dalfox".to_string(),
                                        location: crate::parameter_analysis::Location::Query,
                                        injection_context: Some(context),
                                        valid_specials: Some(valid),
                                        invalid_specials: Some(invalid),
                                    };
                                    let mut guard = reflection_params_clone.lock().await;
                                    guard.push(param_struct);
                                    if !silence {
                                        eprintln!(
                                            "Discovered DOM param: {} (EWMA {:.2}, {}/{})",
                                            param, st.ewma_ratio, st.reflections, st.attempts
                                        );
                                    }
                                    if st.should_collapse() {
                                        st.collapsed = true;
                                        let preserved = guard.first().cloned();
                                        guard.clear();
                                        if let Some(orig) = preserved {
                                            guard.push(Param {
                                                name: "any".to_string(),
                                                value: orig.value.clone(),
                                                location:
                                                    crate::parameter_analysis::Location::Query,
                                                injection_context: orig.injection_context.clone(),
                                                valid_specials: orig.valid_specials.clone(),
                                                invalid_specials: orig.invalid_specials.clone(),
                                            });
                                        } else {
                                            guard.push(Param {
                                                name: "any".to_string(),
                                                value: "dalfox".to_string(),
                                                location: crate::parameter_analysis::Location::Query,
                                                injection_context: Some(
                                                    crate::parameter_analysis::InjectionContext::Html(
                                                        None,
                                                    ),
                                                ),
                                                valid_specials: None,
                                                invalid_specials: None,
                                            });
                                        }
                                        if !silence {
                                            eprintln!(
                                                "[mining-collapse] DOM mining collapsed at EWMA {:.2} after {} attempts",
                                                st.ewma_ratio, st.attempts
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
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.await.unwrap();
            }
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
