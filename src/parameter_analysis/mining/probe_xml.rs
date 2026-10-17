//! Mining: probe xml. See module docs in `mod.rs`.

use super::*;

/// Whether the target's request body should be treated as XML for injection:
/// its declared `Content-Type` is an XML-family type, or the body opens with an
/// `<?xml` prolog. Deliberately strict so JSON / form / HTML bodies are not
/// mistaken for XML.
pub(super) fn request_is_xml(target: &Target, data: &str) -> bool {
    let ct_is_xml = target
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .is_some_and(|(_, v)| crate::utils::is_xml_content_type(v));
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
        let ct = content_type.clone();
        let original_value = point.value.clone();
        let pipeline_for_request = pipeline.clone();

        let handle = crate::parameter_analysis::spawn_reflection_probe(
            semaphore.clone(),
            target.delay,
            pb.clone(),
            move || {
                let body = pipeline_for_request.apply(marker).ok()?;
                let base = crate::utils::build_body_request_base(
                    &client_clone,
                    &target_clone,
                    crate::scanning::url_inject::body_location_method(&target_clone.method),
                    url,
                    Some(body),
                );
                Some(crate::utils::apply_header_overrides(
                    base,
                    &[("Content-Type".to_string(), ct)],
                ))
            },
            move |text| {
                if !silence {
                    eprintln!("Discovered XML injection point: {}", name);
                }
                Param {
                    pre_encoding_pipeline: Some(pipeline),
                    ..Param::new(name, original_value, Location::XmlBody)
                }
                .with_reflection_analysis(text)
            },
        );
        handles.push(handle);
    }

    extend_with_joined(&reflection_params, handles).await;
}
