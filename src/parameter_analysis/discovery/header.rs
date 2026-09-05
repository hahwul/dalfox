//! Discovery surface: header. See the module docs in `mod.rs`.

use super::*;

/// Common HTTP headers to proactively test for reflection,
/// even when they are not explicitly provided by the user.
pub(super) const COMMON_PROBE_HEADERS: &[&str] = &[
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
    crate::record_outbound_request().await;
    match crate::utils::http::send_counted(request).await {
        Ok(resp) => match crate::utils::http::read_body(resp).await {
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
            crate::dbg_log!(
                "blanket header echo detected (guard reflected); skipping {} common header probes",
                COMMON_PROBE_HEADERS.len()
            );
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
        let handle = tokio::spawn(crate::with_job_scopes(
            crate::JobScopes::capture(),
            async move {
                let permit = semaphore_clone
                    .acquire()
                    .await
                    .expect("acquire semaphore permit");
                let m = parsed_method;
                let base =
                    crate::utils::build_request(&client_clone, &target_clone, m, url, data.clone());
                let overrides = vec![(header_name.clone(), test_value.to_string())];
                let request = crate::utils::apply_header_overrides(base, &overrides);
                crate::record_outbound_request().await;
                let mut discovered: Option<Param> = None;
                if let Ok(resp) = crate::utils::http::send_counted(request).await
                    && let Ok(text) = crate::utils::http::read_body(resp).await
                    && crate::scanning::markers::classify_probe_reflection(&text).detected()
                {
                    discovered = Some(
                        Param::new(
                            header_name,
                            header_value,
                            crate::parameter_analysis::Location::Header,
                        )
                        .with_reflection_analysis(&text)
                        .with_framework_sink(&text),
                    );
                }
                if delay > 0 {
                    sleep(Duration::from_millis(delay)).await;
                }
                drop(permit);
                discovered
            },
        ));
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
