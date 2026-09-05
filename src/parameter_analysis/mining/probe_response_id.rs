//! Mining: probe response id. See module docs in `mod.rs`.

use super::*;

pub async fn probe_response_id_params(
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

    // First, get the HTML to find input ids and names
    let base_request = crate::utils::build_request(
        &client,
        target,
        target.parse_method(),
        target.url.clone(),
        target.data.clone(),
    );

    crate::record_outbound_request().await;
    let __resp = crate::utils::http::send_counted(base_request).await;
    if let Ok(resp) = __resp
        && !resp.status().is_server_error()
        && let Ok(text) = crate::utils::http::read_body(resp).await
    {
        // Scope the scraper::Html (which is !Send) strictly to the owning
        // block so the compiler can prove it never crosses any of the
        // subsequent .await points. Extract owned String data, then drop
        // the document before hitting the async code below.
        let params_to_check: std::collections::HashSet<String> = {
            let document = crate::utils::html::parse_document_bounded(&text);
            let selector = selectors::input_with_id_or_name();
            let mut set = std::collections::HashSet::new();
            for element in document.select(selector) {
                if let Some(id) = element.value().attr("id") {
                    set.insert(id.to_string());
                }
                if let Some(name) = element.value().attr("name") {
                    set.insert(name.to_string());
                }
            }
            set
        };

        // Cap the DOM candidate set so a hostile/huge response body (up to the
        // 16 MiB read_body cap) packed with distinct `id`/`name` attributes
        // can't fan out into ~10^6 probe tasks + outbound requests. HashSet
        // iteration order is arbitrary, which is fine for a safety ceiling:
        // real pages stay far under it. Probing then consumes this Vec one
        // owned name at a time exactly as it did the set.
        let (params_to_check, capped_from) = cap_dom_params(params_to_check.into_iter().collect());
        if let Some(original) = capped_from
            && !silence
        {
            eprintln!(
                "[mining] DOM candidate params capped to {} (from {}); reduce reflected fields or use --skip-mining",
                MAX_DOM_MINING_PARAMS, original
            );
        }

        // Sentinel pre-probe — same rationale as Query mining: a
        // reflect-everything page would mark every DOM-extracted name as
        // reflected and balloon downstream cost. Threshold matches Query
        // mining: only run when the candidate set exceeds the pre-probe
        // ceiling.
        if params_to_check.len() > SENTINEL_PROBE_COUNT * 5
            && let Some(text) = pre_collapse_query_probe(&client, target).await
        {
            if !silence {
                eprintln!(
                    "[mining-collapse] sentinel pre-probe collapsed DOM mining: \
                     every random param name reflected; adding single 'any' param"
                );
            }
            collapse_mined_params(
                &reflection_params,
                &preexisting,
                Location::Query,
                Some(&text),
            )
            .await;
            if let Some(ref pb) = pb {
                pb.finish_and_clear();
            }
            return;
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
            // Slot-scoped, not name-scoped: see `param_slot_key`.
            let existing = reflection_params
                .lock()
                .await
                .iter()
                .any(|p| p.name == param && p.location == Location::Query);
            if existing {
                continue;
            }
            let mut url = target.url.clone();
            url.query_pairs_mut()
                .append_pair(&param, crate::scanning::markers::bracketed_marker());
            let client_clone = client.clone();

            let data = target.data.clone();
            let parsed_method = target.parse_method();
            let target_clone = arc_target.clone();
            let delay = target.delay;
            let semaphore_clone = semaphore.clone();
            let param = param.clone();
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
                    let request = crate::utils::build_request(
                        &client_clone,
                        &target_clone,
                        m,
                        url,
                        data.clone(),
                    );
                    // Prepare optional discovered Param container for batched return
                    let mut discovered: Option<Param> = None;
                    crate::record_outbound_request().await;
                    let __resp = crate::utils::http::send_counted(request).await;
                    if let Ok(resp) = __resp {
                        // Skip 5xx error responses — debug pages often reflect params
                        if resp.status().is_server_error() {
                            let mut st = stats_clone.lock().await;
                            st.record_attempt();
                            drop(permit);
                            if delay > 0 {
                                sleep(Duration::from_millis(delay)).await;
                            }
                            if let Some(ref pb) = pb_clone {
                                pb.inc(1);
                            }
                            return discovered;
                        }
                        if let Ok(text) = crate::utils::http::read_body(resp).await {
                            let mut st = stats_clone.lock().await;
                            st.record_attempt();
                            if crate::scanning::markers::classify_probe_reflection(&text).detected()
                            {
                                st.record_reflection();
                                if !st.collapsed {
                                    // Store discovered Param for return (batched later)
                                    discovered = Some(
                                        Param::new(
                                            param.clone(),
                                            crate::scanning::markers::bracketed_marker()
                                                .to_string(),
                                            crate::parameter_analysis::Location::Query,
                                        )
                                        .with_reflection_analysis(&text),
                                    );
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
                },
            ));
            handles.push(handle);
        }

        // Batch collect discovered DOM params
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
        // Collapse post-processing (single 'any' param) if adaptive stats
        // triggered it. Only the Query params this stage mined are folded in;
        // params discovered via other channels — and the ones discovery already
        // confirmed — survive.
        let st_final = stats.lock().await;
        if st_final.collapsed {
            collapse_mined_params(&reflection_params, &preexisting, Location::Query, None).await;
        }
    }
}
