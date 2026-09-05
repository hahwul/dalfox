//! Discovery surface: path. See the module docs in `mod.rs`.

use super::*;

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
        let handle = tokio::spawn(crate::with_job_scopes(
            crate::JobScopes::capture(),
            async move {
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

                crate::record_outbound_request().await;
                let mut discovered: Option<Param> = None;
                if let Ok(resp) = crate::utils::http::send_counted(request).await {
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
                        && let Ok(text) = crate::utils::http::read_body(resp).await
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
                        let bracket_survives =
                            if exploitable_context && !(200..300).contains(&status) {
                                let needle =
                                    format!("<{}>", crate::scanning::markers::bracketed_marker());
                                let probe = crate::utils::build_request(
                                    &client_clone,
                                    &target_clone,
                                    m.clone(),
                                    bracket_url,
                                    data.clone(),
                                );
                                crate::record_outbound_request().await;
                                match crate::utils::http::send_counted(probe).await {
                                    Ok(r) => match crate::utils::http::read_body(r).await {
                                        Ok(t) => t.contains(&needle),
                                        Err(_) => false,
                                    },
                                    Err(_) => false,
                                }
                            } else {
                                true
                            };
                        if exploitable_context && bracket_survives {
                            discovered = Some(
                                Param::new(
                                    param_name,
                                    original_value,
                                    crate::parameter_analysis::Location::Path,
                                )
                                .with_reflection_analysis(&text),
                            );
                        }
                    }
                }
                if delay > 0 {
                    sleep(Duration::from_millis(delay)).await;
                }
                drop(permit);
                discovered
            },
        ));
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
