//! # Stage 2: Mining
//!
//! Discovers additional parameters by analyzing HTML forms, JavaScript source,
//! dictionary wordlists, and GF-pattern lists — then probes each for reflection.
//!
//! **Input:** `Target` + `ScanArgs` + the initial `reflection_params` from Stage 1.
//!
//! **Output:** Extends the shared `reflection_params` list with newly discovered
//! `Param` entries that reflect. Each carries the same naive `valid_specials`,
//! `invalid_specials`, and `injection_context` as Stage 1 output.
//!
//! **Side effects:** HTTP requests for DOM/dict/GF mining probes. Uses EWMA-based
//! collapse detection to short-circuit when a target reflects everything
//! (sustained ≥85% reflection rate after ≥15 attempts). Filters out 5xx
//! responses to avoid false positives from debug/error pages.
//!
//! **Skippable via:** `--skip-mining`, `--skip-mining-dict`, `--skip-mining-dom`.

use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::{DelimiterType, InjectionContext, Location, Param};
use crate::payload::mining::GF_PATTERNS_PARAMS;
use crate::target_parser::Target;
use crate::utils::shimmer::ShimmerSpinner;
use std::sync::Arc;

use tokio::sync::{Mutex, Semaphore};
use tokio::time::{Duration, sleep};
use url::form_urlencoded;

use crate::scanning::selectors;

mod collapse;
mod context_detect;
mod probe_body;
mod probe_dictionary;
mod probe_graphql;
mod probe_json;
mod probe_multipart;
mod probe_response_id;
mod probe_xml;

// Cross-module injection-context detectors: `mining::detect_*` resolves here
// and the parent's `pub use mining::*` re-exports them crate-wide.
pub(crate) use context_detect::*;

// Intra-module helpers reached by `mine_parameters` and the test module.
use collapse::*;
use probe_body::*;
use probe_dictionary::*;
use probe_graphql::*;
use probe_json::*;
use probe_multipart::*;
use probe_response_id::*;
use probe_xml::*;

pub async fn mine_parameters(
    target: &mut Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ShimmerSpinner>,
) {
    // Body/JSON parameters supplied via `-d` are explicit user input, not
    // discovery. Seed them independent of the mining flags: query params are
    // seeded from the URL during the discovery stage, but body params have no
    // other entry point, so gating them behind mining drops the entire
    // POST/JSON body surface — even when `-p name:body` is given and even
    // under `--skip-mining` / `--skip-mining-dict`. (Both probes are no-ops
    // when `args.data` is None, so GET targets are unaffected.)
    probe_body_params(
        target,
        args,
        reflection_params.clone(),
        semaphore.clone(),
        pb.clone(),
    )
    .await;
    probe_json_body_params(
        target,
        args,
        reflection_params.clone(),
        semaphore.clone(),
        pb.clone(),
    )
    .await;
    // GraphQL variables: own path for GraphQL-over-JSON bodies (no-op on plain
    // JSON, which `probe_json_body_params` already handled).
    probe_graphql_params(
        target,
        args,
        reflection_params.clone(),
        semaphore.clone(),
        pb.clone(),
    )
    .await;
    // XML / SOAP element text + attribute values (no-op on non-XML bodies).
    probe_xml_body_params(
        target,
        args,
        reflection_params.clone(),
        semaphore.clone(),
        pb.clone(),
    )
    .await;
    probe_multipart_params(
        target,
        args,
        reflection_params.clone(),
        semaphore.clone(),
        pb.clone(),
    )
    .await;

    // Mining proper: discover parameters the user did NOT name.
    if !args.skip_mining {
        if !args.skip_mining_dict {
            probe_dictionary_params(
                target,
                args,
                reflection_params.clone(),
                semaphore.clone(),
                pb.clone(),
            )
            .await;
        }
        if !args.skip_mining_dom {
            probe_response_id_params(
                target,
                args,
                reflection_params.clone(),
                semaphore.clone(),
                pb.clone(),
            )
            .await;
        }
    }
}

#[cfg(test)]
mod tests;
