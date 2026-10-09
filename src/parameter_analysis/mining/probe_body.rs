//! Mining: probe body. See module docs in `mod.rs`.

use super::*;

pub async fn probe_body_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ShimmerSpinner>,
) {
    let arc_target = Arc::new(target.clone());
    let silence = args.silence;
    let client = target.build_client_or_default();

    // A declared-multipart body is mined as multipart fields
    // (`probe_multipart_params`); probing it urlencoded too would only add
    // requests the endpoint can't parse and duplicate every field's slot.
    if let Some(data) = args.data.as_ref().filter(|_| !target.multipart) {
        // JSON (GraphQL included) / XML bodies have their own probes.
        // Form-parsing one yields a single pair keyed by the whole body, which
        // an echoing endpoint reflects, registering a junk Body param that then
        // eats the full payload catalog.
        if serde_json::from_str::<serde_json::Value>(data)
            .is_ok_and(|v| v.is_object() || v.is_array())
            || request_is_xml(target, data)
        {
            return;
        }
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

        // Slot keys already present, collected once rather than re-scanned
        // under the lock for every body key.
        let already_found: HashSet<String> = reflection_params
            .lock()
            .await
            .iter()
            .filter(|p| p.location == Location::Body)
            .map(|p| p.name.clone())
            .collect();
        // Shared by every task; each one builds its mutated body only after
        // it holds a permit. Building all N bodies up front kept N full-size
        // copies of the request body alive at once (quadratic memory).
        let shared_data: Arc<str> = Arc::from(data.as_str());

        for (param_name, _) in params {
            // Skip already discovered params — but only at *this* wire slot.
            // Keying on the name alone meant an ordinary
            // `dalfox scan '…?q=x' -d 'q=y'` never mined the body `q` at all,
            // because Stage 1 had already discovered the query `q`: a
            // vulnerable body parameter was not just unreported, it was never
            // probed. See `param_slot_key`.
            if already_found.contains(&param_name) {
                continue;
            }

            let data_clone = shared_data.clone();
            let client_clone = client.clone();
            let url = target.url.clone();

            let parsed_method = crate::scanning::url_inject::body_location_method(&target.method);
            let target_clone = arc_target.clone();
            let delay = target.delay;
            let semaphore_clone = semaphore.clone();
            let param_name_cloned = param_name.clone();
            let pb_clone = pb.clone();
            let stats_clone = stats.clone();

            let handle = tokio::spawn(crate::with_job_scopes(
                crate::JobScopes::capture(),
                async move {
                    let permit = semaphore_clone
                        .acquire()
                        .await
                        .expect("acquire semaphore permit");
                    // Build mutated body with this param set to marker
                    let new_data = form_urlencoded::parse(data_clone.as_bytes())
                        .map(|(k, v)| {
                            if k == param_name_cloned {
                                (k, crate::scanning::markers::bracketed_marker().to_string())
                            } else {
                                (k, v.to_string())
                            }
                        })
                        .collect::<Vec<_>>();
                    let body = form_urlencoded::Serializer::new(String::new())
                        .extend_pairs(new_data)
                        .finish();
                    let m = parsed_method;
                    let base = crate::utils::build_body_request_base(
                        &client_clone,
                        &target_clone,
                        m,
                        url,
                        Some(body),
                    );
                    let overrides = vec![(
                        "Content-Type".to_string(),
                        "application/x-www-form-urlencoded".to_string(),
                    )];
                    let request = crate::utils::apply_header_overrides(base, &overrides);

                    crate::record_outbound_request().await;
                    let resp = crate::utils::http::send_counted(request).await;

                    let mut discovered: Option<Param> = None;
                    if let Ok(r) = resp
                        && let Ok(text) = crate::utils::http::read_body(r).await
                    {
                        let mut st = stats_clone.lock().await;
                        st.record_attempt();
                        if crate::scanning::markers::probe_reflected(&text) {
                            st.record_reflection();
                            // No EWMA fold: these names are the user's own `-d`
                            // keys (bounded by the body), not wordlist guesses,
                            // so an echoing page must not replace them with `any`.
                            discovered = Some(
                                Param::new(
                                    param_name_cloned.clone(),
                                    crate::scanning::markers::bracketed_marker().to_string(),
                                    Location::Body,
                                )
                                .with_reflection_analysis(&text),
                            );
                            if !silence {
                                eprintln!(
                                    "Discovered body param: {} (EWMA {:.2}, {}/{})",
                                    param_name_cloned, st.ewma_ratio, st.reflections, st.attempts
                                );
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
                },
            ));

            handles.push(handle);
        }

        extend_with_joined(&reflection_params, handles).await;
    }
}
