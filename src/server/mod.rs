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
    JOB_RETENTION_SECS, Job, JobProgress, JobStatus, MAX_DELAY_MS, MAX_SCAN_TIMEOUT_SECS,
    MAX_TIMEOUT_SECS, MAX_WORKERS, WorkerLease, cap_reflection_params, effective_rate_limit,
    effective_scan_timeout, enforce_retention_cap, has_http_scheme, now_ms, parse_job_status,
    purge_expired_jobs as purge_jobs_map, send_reachability_probe, split_cookie_pairs,
    unreachable_error_message,
};
pub(crate) use crate::parameter_analysis::analyze_parameters;
pub(crate) use crate::scanning::result::SanitizedResult;
pub(crate) use crate::target_parser::parse_target;

mod auth;
mod cors;
mod handlers;
mod job_runner;
mod response;
pub(crate) mod types;
mod util;

pub use types::ServerArgs;

pub(crate) use auth::*;
pub(crate) use cors::*;
pub(crate) use handlers::*;
pub(crate) use job_runner::*;
pub(crate) use response::*;
pub(crate) use types::*;
pub(crate) use util::*;

/// Shortest `--api-key` the server will not warn about. The API-key check has
/// no throttle or lockout, so key length is the entire cost of a brute-force
/// attempt; 24 random characters is comfortably past what an attacker can walk
/// over a network.
const MIN_RECOMMENDED_API_KEY_LEN: usize = 24;

/// Run the REST API server until it shuts down gracefully.
///
/// Returns `Err` when the server never came up (an unparseable bind address, a
/// port already in use) or when `axum::serve` itself failed. A supervisor —
/// systemd, a container runtime, `dalfox server || alert` — reads the exit
/// status, not stderr, so a failed start that exits 0 is indistinguishable from
/// a clean shutdown.
pub async fn run_server(args: ServerArgs) -> Result<(), String> {
    let addr_str = format!("{}:{}", args.host, args.port);
    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            let msg = format!("Invalid bind address {}: {}", addr_str, e);
            eprintln!("{}", msg);
            return Err(msg);
        }
    };

    let mut api_key = args.api_key.clone();
    if api_key.is_none()
        && let Ok(v) = std::env::var("DALFOX_API_KEY")
        && !v.is_empty()
    {
        api_key = Some(v);
    }

    // Parse allowed origins into the exact list, the compiled (anchored)
    // patterns, and the `*` opt-in. See `cors::compile_allowed_origins`.
    let origin_rules = compile_allowed_origins(args.allowed_origins.as_deref());
    let origin_rejections = origin_rules.rejected;

    let allow_methods = args
        .cors_allow_methods
        .clone()
        .unwrap_or_else(|| "GET,POST,OPTIONS,PUT,PATCH,DELETE".to_string());
    let allow_headers = args
        .cors_allow_headers
        .clone()
        .unwrap_or_else(|| "Content-Type,X-API-KEY,Authorization".to_string());

    // Hostnames accepted in the `Host` header. The bind host is always one of
    // them (an operator who ran `--host dalfox.internal` means it), and
    // `auth::check_host` additionally accepts IP literals and `localhost`.
    let mut allowed_hosts: Vec<String> = args
        .allowed_hosts
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let bind_host = args.host.trim().to_ascii_lowercase();
    if !bind_host.is_empty() && !allowed_hosts.contains(&bind_host) {
        allowed_hosts.push(bind_host);
    }

    // Prove `--log-file` is writable before serving anything. Every later write
    // is a best-effort `let _ =` inside the log helper (a logging failure must
    // not take a request down), so without this check a bad path — a typo, a
    // missing directory, a read-only mount — made the flag a silent no-op for
    // the whole process lifetime: logs still scrolled past on stdout, and the
    // operator only discovered the empty file after the incident they wanted it
    // for. Creating it up front also means the file exists immediately, so
    // `tail -F` works from before the first request.
    if let Some(path) = &args.log_file
        && let Err(e) = open_log_file(path)
    {
        let msg = format!("Cannot open --log-file {}: {}", path, e);
        eprintln!("{}", msg);
        return Err(msg);
    }

    let state = AppState {
        api_key,
        jobs: Arc::new(Mutex::new(HashMap::new())),
        log_file: args.log_file.clone(),
        allowed_origins: origin_rules.origins,
        allowed_origin_regexes: origin_rules.regexes,
        allow_all_origins: origin_rules.allow_all,
        allow_methods,
        allow_headers,
        jsonp_enabled: args.jsonp,
        callback_param_name: args.callback_param_name.clone(),
        rate_limit: args.rate_limit,
        scan_timeout: args.scan_timeout,
        max_concurrent_scans: args.max_concurrent_scans,
        allowed_hosts,
        max_retained_scans: args.max_retained_scans,
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

    // Loud warning for the most dangerous misconfiguration: a network-reachable
    // bind with auth disabled. The API scans any submitted URL and POSTs results
    // to any callback_url, so an unauthenticated non-loopback instance is an open
    // SSRF / scan-launch relay into whatever network it can reach (cloud metadata
    // at 169.254.169.254, RFC1918 hosts, etc.). We warn rather than refuse so a
    // deployment that fronts the server with its own auth/egress controls still
    // starts. `auth_disabled` mirrors `check_api_key`: an empty key string is
    // treated as no auth, same as `--api-key` help ("Leave empty to disable").
    //
    // Note this warning is about *network* reach only. Binding to loopback is
    // not by itself a security boundary: a web page the operator visits can
    // drive a loopback API through their browser, which is what the
    // origin/Host gate in `auth.rs` exists to stop.
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

    // A short key is not a boundary. Nothing here throttles or locks out a
    // wrong `X-API-KEY`, so the only cost of a guess is one request — an
    // attacker who can reach the port walks a small keyspace at line rate.
    // Warn rather than refuse: the key may be a deployment-generated value the
    // operator cannot lengthen, and refusing to start would be worse than
    // running with a weak one they were told about.
    //
    // Counted in characters, matching what the message and the docs promise —
    // `len()` would let a 12-character non-ASCII key past a byte comparison.
    // The exact count stays out of the message: `constant_time_eq` deliberately
    // confines key length to a timing difference, and this line is written to
    // stdout and to `--log-file`, where it would become a durable one.
    if !auth_disabled
        && let Some(key) = state.api_key.as_deref()
        && key.chars().count() < MIN_RECOMMENDED_API_KEY_LEN
    {
        log(
            &state,
            "WRN",
            &format!(
                "--api-key is shorter than the recommended {} characters — nothing \
                 rate-limits a wrong key, so a short one is guessable at line rate.",
                MIN_RECOMMENDED_API_KEY_LEN
            ),
        );
    }

    // Two flags switch the cross-site gate off outright — `check_cross_site`
    // returns `Ok` for `jsonp_enabled || allow_all_origins` before it looks at
    // anything. JSONP is served to `<script src>` loads, which carry no Origin
    // to validate; `--allowed-origins '*'` says every origin is allowed, which
    // is the same statement spelled differently. Combined with no API key,
    // either one means any page the operator visits can launch scans through
    // this API and read the results.
    let gate_disabled_by = match (state.jsonp_enabled, state.allow_all_origins) {
        (true, true) => Some("--jsonp and --allowed-origins '*' are"),
        (true, false) => Some("--jsonp is"),
        (false, true) => Some("--allowed-origins '*' is"),
        (false, false) => None,
    };
    if let Some(flags) = gate_disabled_by
        && auth_disabled
    {
        log(
            &state,
            "WRN",
            &format!(
                "{} enabled with NO API key — the cross-site gate is off, so any website \
                 the operator visits can launch scans through this API and read the \
                 results. Set --api-key (or DALFOX_API_KEY), or name the specific web UI \
                 with --allowed-origins.",
                flags
            ),
        );
    }

    // An origin pattern that could not be compiled is dropped, which fails
    // closed: the web UI it described starts getting 403s from the cross-site
    // gate. Reported here rather than at compile time so it lands in
    // `--log-file` alongside the other startup warnings — under systemd a bare
    // stderr line is exactly what nobody reads.
    for rejection in &origin_rejections {
        log(&state, "WRN", &format!("ignoring {}", rejection));
    }

    // `open_log_file` creates the file 0600, but the mode only applies at
    // creation — a server upgraded in place keeps the world-readable file the
    // previous version made, and every target URL in it (with whatever token
    // made the target worth scanning) stays readable by every local account.
    // Chmod-ing a file the operator may deliberately have opened up to a log
    // group would be worse than saying so.
    #[cfg(unix)]
    if let Some(path) = &state.log_file {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                log(
                    &state,
                    "WRN",
                    &format!(
                        "--log-file {} is mode {:o} — it records every submitted target \
                         URL, so any local account can read them. New log files are \
                         created 0600; run `chmod 600 {}` on this one.",
                        path, mode, path
                    ),
                );
            }
        }
    }

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            let msg = format!("Failed to bind {}: {}", addr_str, e);
            log(&state, "ERR", &msg);
            return Err(msg);
        }
    };
    // Announced only now: this line is the operator's "it came up" signal, and
    // logging it before the bind made the last line before a bind error claim
    // success.
    log(
        &state,
        "SERVER",
        &format!("listening on http://{}", addr_str),
    );
    // Graceful shutdown on SIGINT / SIGTERM. axum drains in-flight
    // requests before returning; previously the server ignored Ctrl-C
    // outright and required SIGKILL, leaking any in-flight scans and
    // their webhook subscribers' terminal callbacks.
    // Clone for the shutdown future: `state` is borrowed again below for the
    // serve-error log, so the future can't take it by reference (it outlives
    // this point) or by move.
    let shutdown_state = state.clone();
    let shutdown_signal = async move {
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
        log(
            &shutdown_state,
            "SERVER",
            "shutdown signal received — draining in-flight requests",
        );
    };
    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await
    {
        let msg = format!("server error: {}", e);
        log(&state, "ERR", &msg);
        return Err(msg);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
