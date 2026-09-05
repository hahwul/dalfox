//! Mining: probe xml. See module docs in `mod.rs`.

use super::*;

/// Whether the target's request body should be treated as XML for injection:
/// its declared `Content-Type` is an XML-family type, or the body opens with an
/// `<?xml` prolog. Deliberately strict so JSON / form / HTML bodies are not
/// mistaken for XML.
fn request_is_xml(target: &Target, data: &str) -> bool {
    let ct_is_xml = target
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| {
            matches!(
                crate::utils::content_type_primary(v).as_deref(),
                Some("text/xml")
                    | Some("application/xml")
                    | Some("application/soap+xml")
                    | Some("application/xhtml+xml")
            )
        })
        .unwrap_or(false);
    ct_is_xml || data.trim_start().starts_with("<?xml")
}

/// Seed XML / SOAP injection points from an `-d` XML body.
///
/// Runs only when the request body is XML (see [`request_is_xml`]). Tokenizes
/// the document into element text nodes and attribute values (see
/// [`crate::parameter_analysis::xml_inject::xml_injection_points`]) and probes
/// each by splicing a marker into that one leaf — the rest of the document
/// survives byte-for-byte. A leaf is seeded as a [`Location::XmlBody`] param,
/// carrying the exact-byte-range `Splice` pipeline, only when the marker
/// reflects, so a benign XML body that echoes nothing produces no params.
///
/// No-op on JSON / form / GET targets. Bounded by the tokenizer's point cap.
pub async fn probe_xml_body_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ShimmerSpinner>,
) {
    let Some(data) = &args.data else {
        return;
    };
    if !request_is_xml(target, data) {
        return;
    }
    let points = crate::parameter_analysis::xml_inject::xml_injection_points(data);
    if points.is_empty() {
        return;
    }

    if let Some(ref pb) = pb {
        pb.set_length(points.len() as u64);
        pb.set_message("Probing XML body");
    }

    let arc_target = Arc::new(target.clone());
    let client = target.build_client_or_default();
    let silence = args.silence;
    let marker = crate::scanning::markers::bracketed_marker();
    let content_type = crate::scanning::url_inject::xml_request_content_type(target);

    let mut handles: Vec<tokio::task::JoinHandle<Option<Param>>> = Vec::new();
    for point in points {
        let name = point.name.clone();
        let exists = reflection_params
            .lock()
            .await
            .iter()
            .any(|p| p.name == name && p.location == Location::XmlBody);
        if exists {
            continue;
        }

        // Exact-byte-range splice: prefix + payload + suffix rebuilds the whole
        // document with only this leaf replaced.
        let pipeline = crate::encoding::pipeline::EncodingPipeline::new(vec![
            crate::encoding::pipeline::EncodingStep::Splice {
                prefix: data[..point.start].to_string(),
                suffix: data[point.end..].to_string(),
            },
        ]);

        let client_clone = client.clone();
        let url = target.url.clone();
        let target_clone = arc_target.clone();
        let semaphore_clone = semaphore.clone();
        let delay = target.delay;
        let pb_clone = pb.clone();
        let ct = content_type.clone();
        let original_value = point.value.clone();
        let name_for_task = name.clone();
        let pipeline_for_task = pipeline.clone();

        let handle = tokio::spawn(crate::with_job_scopes(
            crate::JobScopes::capture(),
            async move {
                let permit = semaphore_clone
                    .acquire()
                    .await
                    .expect("acquire semaphore permit");

                let body = match pipeline_for_task.apply(marker) {
                    Ok(b) => b,
                    Err(_) => {
                        drop(permit);
                        return None;
                    }
                };

                let base = crate::utils::build_body_request_base(
                    &client_clone,
                    &target_clone,
                    crate::scanning::url_inject::body_location_method(&target_clone.method),
                    url,
                    Some(body),
                );
                let request =
                    crate::utils::apply_header_overrides(base, &[("Content-Type".to_string(), ct)]);

                crate::record_outbound_request().await;
                let mut discovered: Option<Param> = None;
                if let Ok(r) = crate::utils::http::send_counted(request).await
                    && let Ok(text) = crate::utils::http::read_body(r).await
                    && crate::scanning::markers::classify_probe_reflection(&text).detected()
                {
                    if !silence {
                        eprintln!("Discovered XML injection point: {}", name_for_task);
                    }
                    discovered = Some(
                        Param {
                            pre_encoding_pipeline: Some(pipeline_for_task),
                            ..Param::new(name_for_task, original_value, Location::XmlBody)
                        }
                        .with_reflection_analysis(&text),
                    );
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

    let mut batch: Vec<Param> = Vec::new();
    for h in handles {
        if let Ok(Some(p)) = h.await {
            batch.push(p);
        }
    }
    if !batch.is_empty() {
        reflection_params.lock().await.extend(batch);
    }
}
