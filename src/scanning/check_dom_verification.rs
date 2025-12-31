use crate::parameter_analysis::Param;
use crate::target_parser::Target;
use reqwest::Client;
use scraper;
use std::sync::OnceLock;

use tokio::time::{Duration, sleep};

#[allow(dead_code)]
static DALFOX_SELECTOR: OnceLock<scraper::Selector> = OnceLock::new();

pub async fn check_dom_verification(
    target: &Target,
    param: &Param,
    payload: &str,
    args: &crate::cmd::scan::ScanArgs,
) -> (bool, Option<String>) {
    if args.skip_xss_scanning {
        return (false, None);
    }
    let client = target.build_client().unwrap_or_else(|_| Client::new());

    // Build URL or body based on param location for injection
    let inject_url_str =
        crate::scanning::url_inject::build_injected_url(&target.url, param, payload);
    let inject_url = url::Url::parse(&inject_url_str).unwrap_or_else(|_| target.url.clone());

    // Send injection request (centralized builder)
    let method = target.method.parse().unwrap_or(reqwest::Method::GET);
    let inject_request =
        crate::utils::build_request(&client, target, method, inject_url, target.data.clone());

    // Send the injection request
    crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let inject_resp = inject_request.send().await;

    if target.delay > 0 {
        sleep(Duration::from_millis(target.delay)).await;
    }

    if args.sxss {
        // For Stored XSS, check DOM on sxss_url
        if let Some(sxss_url_str) = &args.sxss_url
            && let Ok(sxss_url) = url::Url::parse(sxss_url_str) {
                let method = args.sxss_method.parse().unwrap_or(reqwest::Method::GET);
                let check_request =
                    crate::utils::build_request(&client, target, method, sxss_url, None);

                crate::REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Ok(resp) = check_request.send().await {
                    let headers = resp.headers().clone();
                    let ct = headers
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    if let Ok(text) = resp.text().await
                        && crate::utils::is_htmlish_content_type(ct) && text.contains(payload) {
                            return (true, Some(text));
                        }
                }
            }
    } else {
        // Normal DOM verification
        if let Ok(resp) = inject_resp {
            let headers = resp.headers().clone();
            let ct = headers
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if let Ok(text) = resp.text().await
                && crate::utils::is_htmlish_content_type(ct) && text.contains(payload) {
                    return (true, Some(text));
                }
        }
    }

    (false, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameter_analysis::{Location, Param};
    use crate::target_parser::parse_target;

    #[tokio::test]
    async fn test_check_dom_verification_early_return_when_skip() {
        let target = parse_target("https://example.com/?q=1").unwrap();
        let param = Param {
            name: "q".to_string(),
            value: "1".to_string(),
            location: Location::Query,
            injection_context: None,
            valid_specials: None,
            invalid_specials: None,
        };
        let args = crate::cmd::scan::ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec![],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            output: None,
            include_request: false,
            include_response: false,
            silence: false,
            poc_type: "plain".to_string(),
            limit: None,
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            skip_xss_scanning: true,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };
        let res = check_dom_verification(&target, &param, "PAY", &args).await;
        assert_eq!(res, (false, None));
    }
}
