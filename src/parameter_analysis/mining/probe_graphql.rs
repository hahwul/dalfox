//! Mining: probe graphql. See module docs in `mod.rs`.

use super::*;

/// Seed GraphQL injection points from an `-d` GraphQL-over-JSON body.
///
/// Detects the GraphQL request shape (see
/// [`crate::encoding::pipeline::infer_graphql_variable_fields`]) and probes each
/// string value inside the `variables` object by rebuilding the whole request
/// with a marker in that one slot. A field is seeded as a
/// [`Location::GraphqlBody`] param — carrying the whole-request rebuild
/// pipeline — only when the marker reflects, so an ordinary JSON API can never
/// produce GraphQL params.
///
/// No-op unless `-d` parses as a GraphQL request, so REST/JSON/GET targets are
/// unaffected. Bounded by the pipeline walker's leaf cap (≤32 fields).
pub async fn probe_graphql_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ShimmerSpinner>,
) {
    let Some(data) = &args.data else {
        return;
    };
    let fields = crate::encoding::pipeline::infer_graphql_variable_fields(data);
    if fields.is_empty() {
        return;
    }

    if let Some(ref pb) = pb {
        pb.set_length(fields.len() as u64);
        pb.set_message("Probing GraphQL variables");
    }

    let arc_target = Arc::new(target.clone());
    let client = target.build_client_or_default();
    let silence = args.silence;
    let marker = crate::scanning::markers::bracketed_marker();

    let mut handles: Vec<tokio::task::JoinHandle<Option<Param>>> = Vec::new();
    for nf in fields {
        // Display name: `variables.<path>` (e.g. `variables.input.title`).
        let name = nf.path.join(".");
        // Slot-scoped skip: only suppress a GraphQL field already seeded here.
        let exists = reflection_params
            .lock()
            .await
            .iter()
            .any(|p| p.name == name && p.location == Location::GraphqlBody);
        if exists {
            continue;
        }

        let client_clone = client.clone();
        let url = target.url.clone();
        let target_clone = arc_target.clone();
        let pipeline = nf.pipeline.clone();
        let pipeline_for_request = pipeline.clone();
        let original_value = nf.original_value.clone();

        let handle = crate::parameter_analysis::spawn_reflection_probe(
            semaphore.clone(),
            target.delay,
            pb.clone(),
            move || {
                // Rebuild the full request with the marker in this one variable.
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
                    &[("Content-Type".to_string(), "application/json".to_string())],
                ))
            },
            move |text| {
                if !silence {
                    eprintln!("Discovered GraphQL variable: {}", name);
                }
                Param {
                    pre_encoding_pipeline: Some(pipeline),
                    ..Param::new(name, original_value, Location::GraphqlBody)
                }
                .with_reflection_analysis(text)
            },
        );
        handles.push(handle);
    }

    extend_with_joined(&reflection_params, handles).await;
}
