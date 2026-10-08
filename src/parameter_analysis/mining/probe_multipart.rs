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
    /// Imported multipart fields probed per target. One task per field is
    /// spawned up front, so an imported body with thousands of fields must
    /// not turn into thousands of tasks; real forms are far smaller.
    const MAX_IMPORTED_MULTIPART_FIELDS: usize = 256;

    let mut wanted =
        crate::parameter_analysis::discovery::explicit_param_names(&args.param, "multipart");
    let mut seen: HashSet<String> = wanted.iter().cloned().collect();
    if target.multipart {
        // An imported spec/collection declared this body multipart: every
        // field of it is a multipart field, named or not.
        for (k, _) in form_urlencoded::parse(data.as_bytes()) {
            if seen.len() >= MAX_IMPORTED_MULTIPART_FIELDS {
                break;
            }
            if seen.insert(k.to_string()) {
                wanted.push(k.into_owned());
            }
        }
    }
    if wanted.is_empty() {
        return;
    }

    if let Some(ref pb) = pb {
        pb.set_length(wanted.len() as u64);
        pb.set_message("Probing multipart fields");
    }

    let pairs: Arc<Vec<(String, String)>> = Arc::new(
        form_urlencoded::parse(data.as_bytes())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    );
    let client = target.build_client_or_default();
    let marker = crate::scanning::markers::bracketed_marker();
    let silence = args.silence;
    let delay = target.delay;
    let shared_target = Arc::new(target.clone());
    // Skip only names already registered *as a multipart field*. A
    // same-named body/query param (e.g. `probe_body_params` seeding `file`
    // from the same `-d`) must not block the multipart slot — `-p
    // file:multipart` filters by location, so the body entry would be
    // dropped and we'd be left with nothing.
    let existing: HashSet<String> = reflection_params
        .lock()
        .await
        .iter()
        .filter(|p| p.location == Location::MultipartBody)
        .map(|p| p.name.clone())
        .collect();

    let mut handles: Vec<tokio::task::JoinHandle<Option<Param>>> = Vec::new();
    for field in wanted {
        if existing.contains(&field) {
            continue;
        }

        let client_clone = client.clone();
        let url = target.url.clone();
        let target_clone = shared_target.clone();
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
                for (k, v) in pairs_clone.iter() {
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
                    && crate::scanning::markers::probe_reflected(&text)
                {
                    if !silence {
                        eprintln!("Discovered multipart field: {}", field_name);
                    }
                    discovered = Some(
                        Param::new(field_name, marker.to_string(), Location::MultipartBody)
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

    extend_with_joined(&reflection_params, handles).await;
}
