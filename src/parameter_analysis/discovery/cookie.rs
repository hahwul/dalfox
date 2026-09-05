//! Discovery surface: cookie. See the module docs in `mod.rs`.

use super::*;

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
        let handle = tokio::spawn(crate::with_job_scopes(
            crate::JobScopes::capture(),
            async move {
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
                crate::record_outbound_request().await;
                let mut discovered: Option<Param> = None;
                if let Ok(resp) = crate::utils::http::send_counted(request).await
                    && let Ok(text) = crate::utils::http::read_body(resp).await
                    && crate::scanning::markers::classify_probe_reflection(&text).detected()
                {
                    discovered = Some(
                        Param::new(
                            cookie_name,
                            cookie_value,
                            crate::parameter_analysis::Location::Header,
                        )
                        .with_reflection_analysis(&text),
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
