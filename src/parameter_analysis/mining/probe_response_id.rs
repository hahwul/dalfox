//! Mining: probe response ids/names. See module docs in `mod.rs`.

use super::*;

/// Distinct `<input>` id/name values in document order. Order matters: the
/// result is truncated by `cap_dom_params`, and a hash-order set made the kept
/// subset differ from run to run. The `scraper::Html` (which is `!Send`) stays
/// inside this function.
pub(super) fn dom_candidate_names(text: &str) -> Vec<String> {
    let document = crate::utils::html::parse_document_bounded(text);
    let selector = selectors::input_with_id_or_name();
    let mut seen = HashSet::new();
    let mut names = Vec::new();
    for element in document.select(selector) {
        for attr in [element.value().attr("id"), element.value().attr("name")]
            .into_iter()
            .flatten()
        {
            if seen.insert(attr) {
                names.push(attr.to_string());
            }
        }
    }
    names
}

pub async fn probe_response_id_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ShimmerSpinner>,
) {
    let client = target.build_client_or_default();
    let preexisting = snapshot_param_slots(&reflection_params).await;

    // Fetch the HTML once. Besides yielding candidate names, this response is
    // a free baseline sample for the bucket engine, so DOM mining does not
    // pay for a second clean request before it starts.
    let base_request = crate::utils::build_request(
        &client,
        target,
        target.parse_method(),
        target.url.clone(),
        target.data.clone(),
    );

    crate::record_outbound_request().await;
    let response = match crate::utils::http::send_counted(base_request).await {
        Ok(response) if !response.status().is_server_error() => response,
        _ => return,
    };
    let status = response.status().as_u16();
    let location = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let Ok(text) = crate::utils::http::read_body_counted(response).await else {
        return;
    };

    // Scope the scraper::Html (which is !Send) strictly to this block so the
    // owned candidate list is all that crosses the subsequent async engine.
    let params_to_check = dom_candidate_names(&text);

    // Cap the DOM candidate set so a hostile/huge response body cannot fan
    // out into one task/request per attribute. Bucketing then bounds the live
    // task count again while retaining the full capped candidate surface.
    let (params_to_check, capped_from) = cap_dom_params(params_to_check);
    if let Some(original) = capped_from
        && !args.silence
    {
        eprintln!(
            "[mining] DOM candidate params capped to {} (from {}); reduce reflected fields or use --skip-mining",
            MAX_DOM_MINING_PARAMS, original
        );
    }

    let baseline = QueryBaseline::from_response(status, &text, location.as_deref());
    let query_ctx = QueryMiningContext {
        target,
        args,
        reflection_params,
        semaphore,
        pb,
        client,
    };
    probe_query_candidates(
        &query_ctx,
        params_to_check,
        preexisting,
        "DOM",
        Some(baseline),
    )
    .await;
}
