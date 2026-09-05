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
    let preexisting = snapshot_param_slots(&reflection_params).await;

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
            // Skip already discovered params — but only at *this* wire slot.
            // Keying on the name alone meant an ordinary
            // `dalfox scan '…?q=x' -d 'q=y'` never mined the body `q` at all,
            // because Stage 1 had already discovered the query `q`: a
            // vulnerable body parameter was not just unreported, it was never
            // probed. See `param_slot_key`.
            let exists = reflection_params
                .lock()
                .await
                .iter()
                .any(|p| p.name == param_name && p.location == Location::Body);
            if exists {
                continue;
            }

            // Build mutated body with this param set to marker
            let new_data = form_urlencoded::parse(data.as_bytes())
                .map(|(k, v)| {
                    if k == param_name {
                        (k, crate::scanning::markers::bracketed_marker().to_string())
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
                        if crate::scanning::markers::classify_probe_reflection(&text).detected() {
                            st.record_reflection();
                            if !st.collapsed {
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

        // If collapsed after attempts, normalize the Body params this stage
        // mined to a single 'any' param. Params discovered via other channels
        // — and the Body params that were already known — are preserved.
        let st_final = stats.lock().await;
        if st_final.collapsed {
            collapse_mined_params(&reflection_params, &preexisting, Location::Body, None).await;
        }
    }
}
