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

    // A captured multipart body keeps its wire framing; an imported spec's is
    // urlencoded (see `Target::multipart`).
    let pairs: Arc<Vec<(String, String)>> = Arc::new(
        crate::target_parser::raw_multipart_fields(data).unwrap_or_else(|| {
            form_urlencoded::parse(data.as_bytes())
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        }),
    );
    let mut wanted =
        crate::parameter_analysis::discovery::explicit_param_names(&args.param, "multipart");
    let mut seen: HashSet<String> = wanted.iter().cloned().collect();
    if target.multipart {
        // An imported spec/collection declared this body multipart: every
        // field of it is a multipart field, named or not.
        // A file part is two injection points: its content, and its upload
        // filename (`<field>[filename]`), which upload listings echo back.
        let filename_slots = crate::target_parser::raw_multipart_parts(data)
            .unwrap_or_default()
            .into_iter()
            .filter(|p| p.filename.is_some())
            .map(|p| crate::scanning::url_inject::multipart_filename_slot(&p.name));
        let names: Vec<String> = pairs
            .iter()
            .map(|(k, _)| k.clone())
            .chain(filename_slots)
            .collect();
        for k in names {
            if seen.len() >= MAX_IMPORTED_MULTIPART_FIELDS {
                break;
            }
            if seen.insert(k.clone()) {
                wanted.push(k);
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
        // Only a captured (raw) multipart body has file parts, so only it needs
        // the file-aware builder. A non-raw `-d` body keeps the plain text-field
        // form built from `pairs` (form_urlencoded semantics: `+`→space, bare
        // keys), so a sibling field is sent exactly as the old probe sent it.
        let raw_data = target.multipart.then(|| data.clone());
        let pairs_clone = pairs.clone();
        let field_name = field.clone();

        // No `pb` tick: this probe never advanced the spinner.
        let handle = crate::parameter_analysis::spawn_reflection_probe(
            semaphore.clone(),
            delay,
            None,
            move || {
                // Captured multipart: the shared builder the injection uses, so a
                // file part goes out as a file (an upload endpoint rejects a
                // text-only body) and `<field>[filename]` lands in the filename.
                let form = if let Some(data) = raw_data.as_deref() {
                    crate::scanning::url_inject::multipart_form(Some(data), &field, marker)
                } else {
                    let mut form = reqwest::multipart::Form::new();
                    let mut placed = false;
                    for (k, v) in pairs_clone.iter() {
                        if *k == field {
                            form = form.text(k.clone(), marker.to_string());
                            placed = true;
                        } else {
                            form = form.text(k.clone(), v.clone());
                        }
                    }
                    if !placed {
                        form = form.text(field.clone(), marker.to_string());
                    }
                    form
                };

                let method =
                    crate::scanning::url_inject::body_location_method(&target_clone.method);
                Some(
                    crate::utils::build_body_request_base(
                        &client_clone,
                        &target_clone,
                        method,
                        url,
                        None,
                    )
                    .multipart(form),
                )
            },
            move |text| {
                if !silence {
                    eprintln!("Discovered multipart field: {}", field_name);
                }
                Param::new(field_name, marker.to_string(), Location::MultipartBody)
                    .with_reflection_analysis(text)
            },
        );
        handles.push(handle);
    }

    extend_with_joined(&reflection_params, handles).await;
}
