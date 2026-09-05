//! Discovery surface: query. See the module docs in `mod.rs`.

use super::*;

/// Await a chunk of in-flight query-discovery probe tasks, folding any
/// discovered params into `batch` / `discovered_names`. Factored out so the
/// main pass can drain each chunk before spawning the next (see
/// `QUERY_DISCOVERY_CHUNK`).
async fn drain_query_discovery_handles(
    handles: Vec<tokio::task::JoinHandle<Option<Param>>>,
    batch: &mut Vec<Param>,
    discovered_names: &mut std::collections::HashSet<String>,
) {
    for handle in handles {
        if let Ok(Some(p)) = handle.await {
            discovered_names.insert(p.name.clone());
            batch.push(p);
        }
    }
}

/// Spawn-and-drain the query-discovery reflection pass this many tasks at a
/// time. Each task captures an injected URL whose construction re-serializes
/// the entire N-parameter query (O(N) bytes), so accumulating all N handles up
/// front held O(N²) resident heap (4000 params ≈ 180 MB). Bounding the live
/// task count caps that to O(CHUNK) without changing which params are probed —
/// the main pass doesn't gate on `discovered_names`, so chunk boundaries are
/// invisible to the result. Mirrors the `CHUNK_SIZE` guard in `mining.rs`.
const QUERY_DISCOVERY_CHUNK: usize = 500;

pub async fn check_query_discovery(
    target: &Target,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
) {
    let arc_target = Arc::new(target.clone());
    let client = target.build_client_or_default();
    let test_value = crate::scanning::markers::bracketed_marker();

    let mut handles = vec![];
    // Batch collect results to reduce mutex contention.
    let mut batch: Vec<Param> = Vec::new();
    let mut discovered_names: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Check existing query params for reflection
    for (name, value) in target.url.query_pairs() {
        let tmp_param = Param::new(name.to_string(), String::new(), Location::Query);
        let url_str = build_injected_url(&target.url, &tmp_param, test_value);
        // `build_injected_url` reassembles the query by hand, so a pathological
        // param name/value in the *target's own* URL can yield a string the URL
        // parser rejects. That is one unprobeable parameter, not a reason to
        // abort every target in the run — skip it (same fallback posture as
        // `url_inject::build_inject_request` and `check_reflection`).
        let Ok(url) = url::Url::parse(&url_str) else {
            if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!("[discovery] skipping param {name}: unparseable probe URL {url_str}");
            }
            continue;
        };
        let client_clone = client.clone();
        let data = target.data.clone();
        let parsed_method = target.parse_method();
        let delay = target.delay;
        let semaphore_clone = semaphore.clone();
        let name = name.to_string();
        let value = value.to_string();
        let target_clone = arc_target.clone();

        // Spawn a task that returns Option<Param> instead of locking per discovery.
        let handle = tokio::spawn(crate::with_job_scopes(
            crate::JobScopes::capture(),
            async move {
                let permit = semaphore_clone
                    .acquire()
                    .await
                    .expect("acquire semaphore permit");
                let m = parsed_method;
                let request =
                    crate::utils::build_request(&client_clone, &target_clone, m, url, data.clone());
                crate::record_outbound_request().await;
                let mut discovered: Option<Param> = None;
                if let Ok(resp) = crate::utils::http::send_counted(request).await {
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
                            injection_context: Some(
                                crate::parameter_analysis::InjectionContext::AttributeUrl(None),
                            ),
                            ..Param::new(name, value, crate::parameter_analysis::Location::Query)
                        });
                    } else if let Ok(text) = crate::utils::http::read_body(resp).await
                        && crate::scanning::markers::classify_probe_reflection(&text).detected()
                    {
                        discovered = Some(
                            Param::new(name, value, crate::parameter_analysis::Location::Query)
                                .with_reflection_analysis(&text)
                                .with_framework_sink(&text),
                        );
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

        // Drain this chunk before spawning more so the live task count (and the
        // O(N)-sized injected URL each task holds) never exceeds the chunk size.
        if handles.len() >= QUERY_DISCOVERY_CHUNK {
            drain_query_discovery_handles(
                std::mem::take(&mut handles),
                &mut batch,
                &mut discovered_names,
            )
            .await;
        }
    }

    // Drain the final partial chunk.
    drain_query_discovery_handles(handles, &mut batch, &mut discovered_names).await;

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
            crate::record_outbound_request().await;
            if let Ok(resp) = crate::utils::http::send_counted(request).await
                && let Ok(text) = crate::utils::http::read_body(resp).await
                && crate::scanning::markers::classify_probe_reflection(&text).detected()
            {
                // For pre-encoded params (base64/2base64), skip special char
                // classification. The encoding bypasses HTTP-level filtering,
                // and leaving specials as None ensures all payload types are tried
                // without adaptive filtering that would incorrectly block payloads.
                discovered_names.insert(name.clone());
                batch.push(
                    Param {
                        pre_encoding: Some(enc_name.to_string()),
                        ..Param::new(
                            name.clone(),
                            value.to_string(),
                            crate::parameter_analysis::Location::Query,
                        )
                    }
                    .with_reflection_context(&text),
                );
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
            crate::record_outbound_request().await;
            if let Ok(resp) = crate::utils::http::send_counted(request).await
                && let Ok(text) = crate::utils::http::read_body(resp).await
                && crate::scanning::markers::classify_probe_reflection(&text).detected()
            {
                discovered_names.insert(display_name.clone());
                batch.push(
                    Param {
                        pre_encoding_pipeline: Some(nf.pipeline.clone()),
                        wire_name: Some(name.clone()),
                        ..Param::new(
                            display_name,
                            nf.original_value.clone(),
                            crate::parameter_analysis::Location::Query,
                        )
                    }
                    .with_reflection_context(&text),
                );
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
            let tmp_param = Param::new(name.clone(), String::new(), Location::Query);
            let url_str = build_injected_url(&target.url, &tmp_param, numeric_marker);
            let Ok(url) = url::Url::parse(&url_str) else {
                if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                    eprintln!(
                        "[discovery] skipping numeric probe for {name}: unparseable probe URL {url_str}"
                    );
                }
                continue;
            };
            let _permit = semaphore.acquire().await.expect("acquire semaphore permit");
            let m = target.parse_method();
            let request = crate::utils::build_request(&client, target, m, url, target.data.clone());
            crate::record_outbound_request().await;
            if let Ok(resp) = crate::utils::http::send_counted(request).await
                && let Ok(text) = crate::utils::http::read_body(resp).await
                && text.contains(numeric_marker)
            {
                discovered_names.insert(name.clone());
                batch.push(Param {
                    injection_context: Some(
                        crate::parameter_analysis::mining::detect_injection_context_with_marker(
                            &text,
                            numeric_marker,
                        ),
                    ),
                    js_breakout: crate::parameter_analysis::mining::detect_js_breakout_with_marker(
                        &text,
                        numeric_marker,
                    ),
                    ..Param::new(
                        name.clone(),
                        value.to_string(),
                        crate::parameter_analysis::Location::Query,
                    )
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
        crate::record_outbound_request().await;
        if let Ok(resp) = crate::utils::http::send_counted(request).await
            && let Ok(text) = crate::utils::http::read_body(resp).await
            && crate::scanning::markers::classify_probe_reflection(&text).detected()
        {
            batch.push(
                Param::new(
                    "__dalfox_key_inject__".to_string(),
                    String::new(),
                    crate::parameter_analysis::Location::Query,
                )
                .with_reflection_analysis(&text),
            );
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
