//! Mining: probe json. See module docs in `mod.rs`.

use super::*;

pub async fn probe_json_body_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ShimmerSpinner>,
) {
    let arc_target = Arc::new(target.clone());
    let silence = args.silence;
    let client = target.build_client_or_default();
    let preexisting = snapshot_param_slots(&reflection_params).await;

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
    // A GraphQL request is JSON too, but its injection points live inside the
    // `variables` object (handled by `probe_graphql_params`, which rebuilds the
    // whole request per variable). Mining the top-level `query`/`variables`
    // keys here would replace the `variables` object with a bare marker string
    // and garble the request, so hand GraphQL bodies off entirely.
    if let Some(data) = &args.data
        && !crate::encoding::pipeline::infer_graphql_variable_fields(data).is_empty()
    {
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
        // Slot-scoped, not name-scoped: a query or form `q` must not suppress
        // mining of the JSON body's `q`. See `param_slot_key`.
        let exists = reflection_params
            .lock()
            .await
            .iter()
            .any(|p| p.name == param_name && p.location == Location::JsonBody);
        if exists {
            continue;
        }

        let client_clone = client.clone();
        let url = target.url.clone();

        let parsed_method = crate::scanning::url_inject::body_location_method(&target.method);
        let target_clone = arc_target.clone();
        let delay = target.delay;
        let semaphore_clone = semaphore.clone();
        let param_name_cloned = param_name.clone();
        let pb_clone = pb.clone();
        let stats_clone = stats.clone();
        let base_json_clone = base_json.clone();

        let handle = tokio::spawn(crate::with_job_scopes(
            crate::JobScopes::capture(),
            async move {
                let permit = semaphore_clone
                    .acquire()
                    .await
                    .expect("acquire semaphore permit");

                // Build mutated JSON with this key set to marker
                let mut root = base_json_clone;
                if let Some(map) = root.as_object_mut() {
                    map.insert(
                        param_name_cloned.clone(),
                        serde_json::Value::String(
                            crate::scanning::markers::bracketed_marker().to_string(),
                        ),
                    );
                } else {
                    let mut map = serde_json::Map::new();
                    map.insert(
                        param_name_cloned.clone(),
                        serde_json::Value::String(
                            crate::scanning::markers::bracketed_marker().to_string(),
                        ),
                    );
                    root = serde_json::Value::Object(map);
                }
                let body = serde_json::to_string(&root).unwrap_or_else(|_| {
                    format!(
                        "{{\"{}\":\"{}\"}}",
                        param_name_cloned,
                        crate::scanning::markers::bracketed_marker()
                    )
                });

                let base = crate::utils::build_body_request_base(
                    &client_clone,
                    &target_clone,
                    parsed_method,
                    url,
                    Some(body),
                );
                let overrides = vec![("Content-Type".to_string(), "application/json".to_string())];
                let request = crate::utils::apply_header_overrides(base, &overrides);

                crate::record_outbound_request().await;
                let resp = crate::utils::http::send_counted(request).await;

                let mut discovered: Option<Param> = None;
                if let Ok(r) = resp
                    && let Ok(text) = crate::utils::http::read_body(r).await
                {
                    let mut st = stats_clone.lock().await;
                    st.record_attempt();
                    if crate::scanning::markers::classify_probe_reflection(&text).detected() {
                        st.record_reflection();
                        if !st.collapsed {
                            discovered = Some(
                                Param::new(
                                    param_name_cloned.clone(),
                                    crate::scanning::markers::bracketed_marker().to_string(),
                                    Location::JsonBody,
                                )
                                .with_reflection_analysis(&text),
                            );
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
            },
        ));

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

    // Collapse normalization to single 'any' JSON param if triggered. Only the
    // JsonBody params this stage mined fold in; everything else is preserved.
    let st_final = stats.lock().await;
    if st_final.collapsed {
        collapse_mined_params(&reflection_params, &preexisting, Location::JsonBody, None).await;
    }
}
