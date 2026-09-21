//! Mining: probe response ids/names. See module docs in `mod.rs`.

use super::*;

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
    let Ok(text) = crate::utils::http::read_body(response).await else {
        return;
    };

    // Scope the scraper::Html (which is !Send) strictly to this block so the
    // owned candidate list is all that crosses the subsequent async engine.
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

    // Cap the DOM candidate set so a hostile/huge response body cannot fan
    // out into one task/request per attribute. Bucketing then bounds the live
    // task count again while retaining the full capped candidate surface.
    let (params_to_check, capped_from) = cap_dom_params(params_to_check.into_iter().collect());
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
