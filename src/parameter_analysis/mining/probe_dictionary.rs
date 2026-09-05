//! Mining: probe dictionary. See module docs in `mod.rs`.

use super::*;

pub async fn probe_dictionary_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ShimmerSpinner>,
) {
    let arc_target = Arc::new(target.clone());
    let silence = args.silence;
    let client = target.build_client_or_default();
    // Taken before this stage pushes anything, so a collapse below can drop
    // what the wordlist mined without touching what discovery already found.
    let preexisting = snapshot_param_slots(&reflection_params).await;

    // Resolve candidate parameter names (remote, file, or built-ins)
    let mut params: Vec<String> = Vec::new();
    let mut loaded = false;

    if !args.remote_wordlists.is_empty() {
        if let Err(e) = crate::payload::init_remote_wordlists(&args.remote_wordlists).await
            && !silence
        {
            eprintln!("Error initializing remote wordlists: {}", e);
        }
        // Keyed by this scan's provider set: the cache is process-global, so a
        // provider-less lookup in the server/MCP daemon could return whatever
        // wordlist an earlier job with different providers had fetched.
        if let Some(words) = crate::payload::get_remote_words_for(&args.remote_wordlists)
            && !words.is_empty()
        {
            params = words.as_ref().clone();
            loaded = true;
        }
    }

    if !loaded && let Some(wordlist_path) = &args.mining_dict_word {
        match crate::utils::fs::read_bounded(
            std::path::Path::new(wordlist_path),
            crate::utils::fs::MAX_FILE_READ_BYTES,
            "parameter wordlist",
        ) {
            Ok(content) => {
                params = content
                    .lines()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                loaded = true;
            }
            Err(e) => {
                // Always surface on stderr — an unreadable
                // `--mining-dict-word` is a user-supplied input error and
                // silencing it (because server/MCP pass silence=true to
                // analyze_parameters) means the operator can't tell why
                // their custom dictionary did nothing. stderr never
                // pollutes the stdout JSON/JSONL payload anyway.
                eprintln!("Error reading wordlist file {}: {}", wordlist_path, e);
                let _ = silence; // intentionally unused now
                return;
            }
        }
    }

    if !loaded {
        params = GF_PATTERNS_PARAMS.iter().map(ToString::to_string).collect();
    }

    // Sentinel pre-probe: 3 unique random param names. If every one reflects,
    // the page echoes arbitrary input and the wordlist would just balloon
    // into Stage 3-6 cost. Skip the wordlist and add a single "any" param
    // instead — the params discovered before this stage are kept and still
    // scanned. Skip when the wordlist is small enough that the pre-probe is
    // more expensive than just running it.
    if params.len() > SENTINEL_PROBE_COUNT * 5
        && let Some(text) = pre_collapse_query_probe(&client, target).await
    {
        if !silence {
            eprintln!(
                "[mining-collapse] sentinel pre-probe collapsed Query mining: \
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
        pb.set_length(params.len() as u64);
        pb.set_message("Mining dictionary parameters");
    }

    // EWMA adaptive stats shared across tasks
    let stats = Arc::new(Mutex::new(MiningSampleStats::new()));

    // Chunked processing bounds memory and allows early collapse exit. Tasks
    // are spawned AND drained one chunk at a time (see the per-chunk join below)
    // so the live task count never exceeds CHUNK_SIZE. Accumulating handles for
    // the whole wordlist (joined only after every chunk) let a multi-million-line
    // `--mining-dict-word` / `--remote-wordlists` spawn one task per entry up
    // front — each holding cloned Url/String/Arc state — and blow resident
    // memory into the tens of GB before any task was awaited.
    const CHUNK_SIZE: usize = 500;
    'outer: for param_chunk in params.chunks(CHUNK_SIZE) {
        {
            let st = stats.lock().await;
            if st.collapsed {
                break 'outer;
            }
        }
        // Per-chunk handles, drained at the end of this chunk (see below).
        let mut handles: Vec<tokio::task::JoinHandle<Option<Param>>> = Vec::new();
        for param in param_chunk {
            // Early collapse stop. (A second identical `collapsed` check used to
            // follow immediately with no await in between — dead code, since
            // this `break 'outer` already fires first when collapsed is set.)
            {
                let st = stats.lock().await;
                if st.collapsed {
                    break 'outer;
                }
            }
            // Skip only when this *slot* was already discovered. Matching on
            // the name alone let a param found at another wire location (a
            // query `q`, a header `q`) suppress mining of the same name here,
            // so the slot was never probed at all. See `param_slot_key`.
            let exists = reflection_params
                .lock()
                .await
                .iter()
                .any(|p| p.name == *param && p.location == Location::Query);
            if exists {
                continue;
            }

            let mut url = target.url.clone();
            url.query_pairs_mut()
                .append_pair(param, crate::scanning::markers::bracketed_marker());

            let client_clone = client.clone();

            let data = target.data.clone();
            let parsed_method = target.parse_method();
            let target_clone = arc_target.clone();
            let delay = target.delay;
            let semaphore_clone = semaphore.clone();
            let param_name = param.clone();
            let pb_clone = pb.clone();
            let stats_clone = stats.clone();

            let handle = tokio::spawn(crate::with_job_scopes(
                crate::JobScopes::capture(),
                async move {
                    let permit = semaphore_clone
                        .acquire()
                        .await
                        .expect("acquire semaphore permit");
                    let request = crate::utils::build_request(
                        &client_clone,
                        &target_clone,
                        parsed_method,
                        url,
                        data.clone(),
                    );

                    crate::record_outbound_request().await;
                    let resp = crate::utils::http::send_counted(request).await;

                    let mut discovered: Option<Param> = None;
                    if let Ok(r) = resp {
                        // Skip server error responses (5xx) — debug error pages often
                        // reflect query params in stack traces, causing false positives.
                        let status = r.status();
                        if status.is_server_error() {
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
                        // Check for redirect reflection: if the response is a 3xx redirect,
                        // the Location header may contain the reflected marker value.
                        let is_redirect = status.is_redirection();
                        let location_has_marker = if is_redirect {
                            r.headers()
                                .get("location")
                                .and_then(|v| v.to_str().ok())
                                .is_some_and(|loc| {
                                    crate::scanning::markers::classify_probe_reflection(loc)
                                        .detected()
                                })
                        } else {
                            false
                        };

                        if location_has_marker {
                            // Redirect context: marker reflected in Location header.
                            let mut st = stats_clone.lock().await;
                            st.record_attempt();
                            st.record_reflection();
                            if !st.collapsed {
                                discovered = Some(Param {
                                    injection_context: Some(
                                        crate::parameter_analysis::InjectionContext::AttributeUrl(
                                            None,
                                        ),
                                    ),
                                    ..Param::new(
                                        param_name.clone(),
                                        crate::scanning::markers::bracketed_marker().to_string(),
                                        crate::parameter_analysis::Location::Query,
                                    )
                                });
                                if !silence {
                                    eprintln!(
                                        "Discovered parameter (redirect): {} (EWMA {:.2}, {}/{})",
                                        param_name, st.ewma_ratio, st.reflections, st.attempts
                                    );
                                }
                                if st.should_collapse() {
                                    st.collapsed = true;
                                    if !silence {
                                        eprintln!(
                                            "[mining-collapse] High reflection EWMA {:.2} after {} attempts ({} reflections)",
                                            st.ewma_ratio, st.attempts, st.reflections
                                        );
                                    }
                                }
                            }
                        } else if let Ok(text) = crate::utils::http::read_body(r).await {
                            let mut st = stats_clone.lock().await;
                            st.record_attempt();
                            if crate::scanning::markers::classify_probe_reflection(&text).detected()
                            {
                                st.record_reflection();
                                if !st.collapsed {
                                    discovered = Some(
                                        Param::new(
                                            param_name.clone(),
                                            crate::scanning::markers::bracketed_marker()
                                                .to_string(),
                                            crate::parameter_analysis::Location::Query,
                                        )
                                        .with_reflection_analysis(&text),
                                    );
                                    if !silence {
                                        eprintln!(
                                            "Discovered parameter: {} (EWMA {:.2}, {}/{})",
                                            param_name, st.ewma_ratio, st.reflections, st.attempts
                                        );
                                    }
                                    if st.should_collapse() {
                                        st.collapsed = true;
                                        if !silence {
                                            eprintln!(
                                                "[mining-collapse] High reflection EWMA {:.2} after {} attempts ({} reflections)",
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
                    discovered
                },
            ));

            handles.push(handle);
        }

        // Drain THIS chunk's tasks (and flush discovered params) before the next
        // chunk spawns, keeping the live task/handle count bounded by CHUNK_SIZE.
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
    } // end chunk loop

    // Apply collapse post-processing once (instead of inside tasks mutating aggressively).
    // Only the Query params *this stage mined* collapse — params discovered via
    // other channels (Body, Header, Path, JsonBody, …) and the Query params
    // Stage 1 discovery already confirmed are left alone.
    let st_final = stats.lock().await;
    if st_final.collapsed {
        collapse_mined_params(&reflection_params, &preexisting, Location::Query, None).await;
    }
}
