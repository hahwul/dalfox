//! Mining: probe multipart. See module docs in `mod.rs`.

use super::*;

/// Seed multipart form-field params the operator named via `-p name:multipart`.
///
/// Like [`probe_body_params`], these come from explicit `-d` input rather than
/// discovery — without this, `MultipartBody` params were only ever seeded from
/// HTML `<form enctype=multipart/form-data>` discovery, so `-p file:multipart`
/// (a known multipart sink) had no entry point and was silently never tested.
/// Sends a real `multipart/form-data` probe and seeds the field as a
/// `MultipartBody` param when the marker reflects. No-op without both `-d` and
/// at least one `-p :multipart` spec.
pub async fn probe_multipart_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ShimmerSpinner>,
) {
    let Some(data) = &args.data else {
        return;
    };
    let wanted =
        crate::parameter_analysis::discovery::explicit_param_names(&args.param, "multipart");
    if wanted.is_empty() {
        return;
    }

    if let Some(ref pb) = pb {
        pb.set_length(wanted.len() as u64);
        pb.set_message("Probing multipart fields");
    }

    let pairs: Vec<(String, String)> = form_urlencoded::parse(data.as_bytes())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let client = target.build_client_or_default();
    let marker = crate::scanning::markers::bracketed_marker();
    let silence = args.silence;

    let mut handles: Vec<tokio::task::JoinHandle<Option<Param>>> = Vec::new();
    for field in wanted {
        // Skip only if this name is already registered *as a multipart field*.
        // A same-named body/query param (e.g. `probe_body_params` seeding
        // `file` from the same `-d`) must not block the multipart slot —
        // `-p file:multipart` filters by location, so the body entry would be
        // dropped and we'd be left with nothing.
        let exists = reflection_params
            .lock()
            .await
            .iter()
            .any(|p| p.name == field && p.location == Location::MultipartBody);
        if exists {
            continue;
        }

        let client_clone = client.clone();
        let url = target.url.clone();
        let target_clone = Arc::new(target.clone());
        let semaphore_clone = semaphore.clone();
        let pairs_clone = pairs.clone();
        let field_name = field.clone();

        let handle = tokio::spawn(crate::with_job_scopes(
            crate::JobScopes::capture(),
            async move {
                let permit = semaphore_clone
                    .acquire()
                    .await
                    .expect("acquire semaphore permit");
                let mut form = reqwest::multipart::Form::new();
                let mut placed = false;
                for (k, v) in &pairs_clone {
                    if *k == field_name {
                        form = form.text(k.clone(), marker.to_string());
                        placed = true;
                    } else {
                        form = form.text(k.clone(), v.clone());
                    }
                }
                if !placed {
                    form = form.text(field_name.clone(), marker.to_string());
                }

                let method =
                    crate::scanning::url_inject::body_location_method(&target_clone.method);
                let request = crate::utils::build_body_request_base(
                    &client_clone,
                    &target_clone,
                    method,
                    url,
                    None,
                )
                .multipart(form);
                crate::record_outbound_request().await;

                let mut discovered: Option<Param> = None;
                if let Ok(r) = crate::utils::http::send_counted(request).await
                    && let Ok(text) = crate::utils::http::read_body(r).await
                    && crate::scanning::markers::classify_probe_reflection(&text).detected()
                {
                    if !silence {
                        eprintln!("Discovered multipart field: {}", field_name);
                    }
                    discovered = Some(
                        Param::new(field_name, marker.to_string(), Location::MultipartBody)
                            .with_reflection_analysis(&text),
                    );
                }
                drop(permit);
                discovered
            },
        ));
        handles.push(handle);
    }

    let mut batch: Vec<Param> = Vec::new();
    for handle in handles {
        if let Ok(Some(p)) = handle.await {
            batch.push(p);
        }
    }
    if !batch.is_empty() {
        reflection_params.lock().await.extend(batch);
    }
}
