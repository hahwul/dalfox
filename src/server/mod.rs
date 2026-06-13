//! HTTP API server for dalfox. The module is split into focused submodules:
//!
//! - [`types`] — request/response payloads and [`ServerArgs`]/`AppState`.
//! - [`auth`] — API-key authentication.
//! - [`cors`] — CORS response-header construction.
//! - [`response`] — the shared `{code,msg,data}` envelope + JSONP wrapping.
//! - [`util`] — logging, scan-id, cookie parsing, option validation, purge.
//! - [`job_runner`] — background scan execution and completion webhooks.
//! - [`handlers`] — the axum route handlers.
//!
//! The imports below are re-exported (`pub(crate) use`) so every submodule can
//! pull a single consistent name set in via `use super::*`, and the test module
//! keeps resolving everything through `use super::*` unchanged.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Router,
    routing::{get, options, post},
};

use tokio::sync::Mutex;

// Shared name surface re-exported for submodules (`use super::*`) and tests.
pub(crate) use axum::{
    Json,
    extract::{Path, Query, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
pub(crate) use clap::Args;
pub(crate) use serde::{Deserialize, Serialize};

pub(crate) use crate::cmd::scan::ScanArgs;
pub(crate) use crate::job::{
    AbortOnDrop, JOB_RETENTION_SECS, Job, JobProgress, JobStatus, MAX_DELAY_MS,
    MAX_DISCOVERED_PARAMS, MAX_SCAN_TIMEOUT_SECS, MAX_TIMEOUT_SECS, MAX_WORKERS,
    cap_reflection_params, effective_rate_limit, effective_scan_timeout, has_http_scheme, now_ms,
    parse_job_status, purge_expired_jobs as purge_jobs_map, run_within_scan_budget,
    send_reachability_probe, split_cookie_pairs, unreachable_error_message,
};
pub(crate) use crate::parameter_analysis::analyze_parameters;
pub(crate) use crate::scanning::result::{Result as ScanResult, SanitizedResult};
pub(crate) use crate::target_parser::parse_target;

mod auth;
mod cors;
mod handlers;
mod job_runner;
mod response;
mod types;
mod util;

pub use types::ServerArgs;

pub(crate) use auth::*;
pub(crate) use cors::*;
pub(crate) use handlers::*;
pub(crate) use job_runner::*;
pub(crate) use response::*;
pub(crate) use types::*;
pub(crate) use util::*;

pub async fn run_server(args: ServerArgs) {
    let addr_str = format!("{}:{}", args.host, args.port);
    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Invalid bind address {}: {}", addr_str, e);
            return;
        }
    };

    let mut api_key = args.api_key.clone();
    if api_key.is_none()
        && let Ok(v) = std::env::var("DALFOX_API_KEY")
        && !v.is_empty()
    {
        api_key = Some(v);
    }

    // Parse allowed origins, build regex list and wildcard flag
    let allowed_origins_vec = args.allowed_origins.as_ref().map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()
    });

    let mut allowed_origin_regexes = Vec::new();
    let mut allow_all_origins = false;
    if let Some(list) = &allowed_origins_vec {
        for item in list {
            if item == "*" {
                allow_all_origins = true;
            } else if let Some(pat) = item.strip_prefix("regex:") {
                match regex::Regex::new(pat) {
                    Ok(re) => allowed_origin_regexes.push(re),
                    Err(e) => eprintln!(
                        "[WRN] ignoring invalid allowed-origins regex '{}': {}",
                        pat, e
                    ),
                }
            } else if item.contains('*') {
                // Convert simple wildcard to regex
                let mut pattern = regex::escape(item);
                pattern = pattern.replace("\\*", ".*");
                let anchored = format!("^{}$", pattern);
                match regex::Regex::new(&anchored) {
                    Ok(re) => allowed_origin_regexes.push(re),
                    Err(e) => eprintln!(
                        "[WRN] ignoring invalid allowed-origins wildcard '{}': {}",
                        item, e
                    ),
                }
            }
        }
    }

    let allow_methods = args
        .cors_allow_methods
        .clone()
        .unwrap_or_else(|| "GET,POST,OPTIONS,PUT,PATCH,DELETE".to_string());
    let allow_headers = args
        .cors_allow_headers
        .clone()
        .unwrap_or_else(|| "Content-Type,X-API-KEY,Authorization".to_string());

    let state = AppState {
        api_key,
        jobs: Arc::new(Mutex::new(HashMap::new())),
        log_file: args.log_file.clone(),
        allowed_origins: allowed_origins_vec,
        allowed_origin_regexes,
        allow_all_origins,
        allow_methods,
        allow_headers,
        jsonp_enabled: args.jsonp,
        callback_param_name: args.callback_param_name.clone(),
        rate_limit: args.rate_limit,
        scan_timeout: args.scan_timeout,
        max_concurrent_scans: args.max_concurrent_scans,
        last_purge_ms: Arc::new(std::sync::atomic::AtomicI64::new(0)),
        preflight_sem: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PREFLIGHT)),
    };

    let app = Router::new()
        .route("/scan", post(start_scan_handler))
        .route("/scan", get(get_scan_handler))
        .route("/scan", options(options_scan_handler))
        .route("/scans", get(list_scans_handler))
        .route("/scans", options(options_scan_handler))
        .route("/preflight", post(preflight_handler))
        .route("/preflight", options(options_scan_handler))
        .route("/result/{id}", get(get_result_handler))
        .route("/result/{id}", options(options_result_handler))
        .route("/scan/{id}", get(get_result_handler))
        .route("/scan/{id}", axum::routing::delete(cancel_scan_handler))
        .route("/scan/{id}", options(options_result_handler))
        .route("/health", get(health_handler))
        .route("/health", options(options_scan_handler))
        // Explicit request-body cap for every route. Replaces axum's implicit
        // 2 MiB default so the bound is documented and operator-tunable; a
        // body over the limit is rejected with 413 before handler code runs.
        .layer(axum::extract::DefaultBodyLimit::max(args.max_body_bytes))
        .with_state(state.clone());

    log(
        &state,
        "SERVER",
        &format!("listening on http://{}", addr_str),
    );

    // Loud warning for the most dangerous misconfiguration: a network-reachable
    // bind with auth disabled. The API scans any submitted URL and POSTs results
    // to any callback_url, so an unauthenticated non-loopback instance is an open
    // SSRF / scan-launch relay into whatever network it can reach (cloud metadata
    // at 169.254.169.254, RFC1918 hosts, etc.). We warn rather than refuse so a
    // deployment that fronts the server with its own auth/egress controls still
    // starts. `auth_disabled` mirrors `check_api_key`: an empty key string is
    // treated as no auth, same as `--api-key` help ("Leave empty to disable").
    let auth_disabled = state.api_key.as_deref().is_none_or(|s| s.is_empty());
    if auth_disabled && !addr.ip().is_loopback() {
        log(
            &state,
            "WRN",
            &format!(
                "bound to non-loopback address {} with NO API key — the API is an \
                 unauthenticated SSRF / scan-launch relay reachable by anyone on this \
                 network. Set --api-key (or DALFOX_API_KEY), or bind to 127.0.0.1.",
                addr_str
            ),
        );
    }

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            log(
                &state,
                "ERR",
                &format!("Failed to bind {}: {}", addr_str, e),
            );
            return;
        }
    };
    // Graceful shutdown on SIGINT / SIGTERM. axum drains in-flight
    // requests before returning; previously the server ignored Ctrl-C
    // outright and required SIGKILL, leaking any in-flight scans and
    // their webhook subscribers' terminal callbacks.
    let shutdown_signal = async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
            let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
            tokio::select! {
                _ = sigint.recv() => {}
                _ = sigterm.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        eprintln!("[server] shutdown signal received — draining in-flight requests");
    };
    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await
    {
        eprintln!("server error: {}", e);
    }
}

#[cfg(test)]
mod tests;
