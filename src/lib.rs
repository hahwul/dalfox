//! Dalfox XSS Scanner Library
//!
//! This library provides XSS scanning capabilities including:
//! - Parameter analysis and discovery
//! - XSS payload generation and encoding
//! - Reflection and DOM-based XSS detection
//! - AST-based JavaScript analysis
//!
//! # Scan Pipeline Overview
//!
//! A single target URL flows through six stages. Each stage enriches the
//! `Param` list or produces scan results. The table below shows the data
//! contract between stages:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │ Stage │ Module                          │ Input → Output           │
//! ├───────┼─────────────────────────────────┼──────────────────────────┤
//! │  1    │ parameter_analysis::discovery   │ Target                   │
//! │       │                                 │   → DiscoveredParams     │
//! │       │                                 │     (naive specials)     │
//! ├───────┼─────────────────────────────────┼──────────────────────────┤
//! │  2    │ parameter_analysis::mining      │ Target + HTML/JS         │
//! │       │                                 │   → DiscoveredParams     │
//! │       │                                 │     (extended via DOM/   │
//! │       │                                 │      dict/gf mining)     │
//! ├───────┼─────────────────────────────────┼──────────────────────────┤
//! │  3    │ parameter_analysis (mod)        │ DiscoveredParams         │
//! │       │   active_probe_param()          │   → ProbedParams         │
//! │       │                                 │     (finalized specials, │
//! │       │                                 │      injection_context,  │
//! │       │                                 │      pre_encoding)       │
//! ├───────┼─────────────────────────────────┼──────────────────────────┤
//! │  4    │ scanning (mod)                  │ ProbedParams             │
//! │       │   run_scanning() payload gen    │   → ParamPayloadJob[]    │
//! │       │                                 │     (param, reflection   │
//! │       │                                 │      payloads, dom       │
//! │       │                                 │      payloads)           │
//! ├───────┼─────────────────────────────────┼──────────────────────────┤
//! │  5    │ scanning::check_reflection      │ (Param, payload)         │
//! │       │                                 │   → ReflectionKind?      │
//! │       │                                 │     + response body      │
//! ├───────┼─────────────────────────────────┼──────────────────────────┤
//! │  6    │ scanning::check_dom_verification│ (Param, payload)         │
//! │       │                                 │   → (bool, Option<HTML>) │
//! │       │                                 │     DOM evidence check   │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! **Data enrichment flow on `Param`:**
//!
//! ```text
//! Discovery (Stage 1-2)          Active Probing (Stage 3)
//! ─────────────────────          ────────────────────────
//! name, value, location    →     + valid_specials (confirmed)
//! valid_specials (naive)         + invalid_specials (confirmed)
//! injection_context (naive)      + injection_context (refined)
//!                                + pre_encoding (auto-detected)
//! ```

pub mod cmd;
pub mod config;
pub mod encoding;
pub mod job;
pub mod mcp;
pub mod parameter_analysis;
pub mod payload;
pub mod scanning;
pub mod server;
pub mod target_parser;
pub mod utils;
pub mod waf;

pub use std::sync::atomic::AtomicBool;
pub use std::sync::atomic::AtomicU64;

pub static DEBUG: AtomicBool = AtomicBool::new(false);
pub static REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);
pub static WAF_BLOCK_COUNT: AtomicU64 = AtomicU64::new(0);
pub static WAF_CONSECUTIVE_BLOCKS: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);
pub static NO_COLOR: AtomicBool = AtomicBool::new(false);

/// Install the process-wide rustls crypto provider (ring).
///
/// reqwest is built with the `rustls-no-provider` feature so it bundles no
/// crypto backend; we supply ring's instead of the default aws-lc-rs because
/// aws-lc-sys fails to link on several distros (AUR, musl, …; see #1061).
/// reqwest resolves the provider via `CryptoProvider::get_default()` when a
/// `Client` is built, so this must run before the first client is constructed
/// — it is called from `main()` and from every pooled client builder.
///
/// Idempotent and thread-safe: the first caller installs the provider, the
/// rest are no-ops. If a downstream library consumer already installed a
/// provider of their own, `install_default` returns `Err` and we leave their
/// choice untouched.
pub fn ensure_crypto_provider() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Process-wide request rate limiter installed from `--rate-limit`
/// (req/sec; `None` once set means "unlimited"). Written once at scan
/// startup via [`install_rate_limiter`] and read on every send through
/// [`rate_limit_acquire`]. The default (no limiter) keeps the hot path free
/// of any locking.
static RATE_LIMITER: std::sync::OnceLock<Option<std::sync::Arc<utils::rate_limit::RateLimiter>>> =
    std::sync::OnceLock::new();

tokio::task_local! {
    /// Per-scan request counter, set by the MCP runner so concurrent scans
    /// don't pollute each other's progress tallies. Callers use
    /// `tick_request_count` which bumps both the global counter and this
    /// task-local when it is bound.
    pub static REQUEST_COUNT_JOB: std::sync::Arc<AtomicU64>;

    /// Per-scan consecutive-WAF-block counter. Bound by MCP and REST runners
    /// so concurrent scans don't trigger each other's adaptive backoff.
    /// Callers use `tick_waf_block` / `reset_waf_consecutive`.
    pub static WAF_CONSECUTIVE_BLOCKS_JOB: std::sync::Arc<std::sync::atomic::AtomicU32>;

    /// Per-scan request rate limiter, bound by the MCP / REST runners (see
    /// [`with_job_rate_limiter`]) so concurrent jobs get independent request
    /// budgets instead of sharing the process-wide one. Preferred over
    /// `RATE_LIMITER` by [`rate_limit_acquire`] when bound.
    pub static RATE_LIMITER_JOB: std::sync::Arc<utils::rate_limit::RateLimiter>;
}

/// Install the process-wide request rate limiter from `--rate-limit`
/// (requests/second; `0` = unlimited). Called once from the CLI scan entry
/// point before any requests go out. Idempotent: only the first call wins,
/// matching the once-per-process CLI lifecycle.
pub fn install_rate_limiter(rate: u32) {
    let _ = RATE_LIMITER.set(utils::rate_limit::RateLimiter::per_second(rate));
}

/// Run `fut` with a per-job rate limiter bound for `rate` requests/second.
/// When `rate == 0` no limiter is installed and `fut` runs unchanged, so the
/// no-rate-limit path stays a plain await. Used by the MCP and REST runners
/// to give each concurrent scan its own budget.
pub async fn with_job_rate_limiter<F>(rate: u32, fut: F) -> F::Output
where
    F: std::future::Future,
{
    match utils::rate_limit::RateLimiter::per_second(rate) {
        Some(limiter) => RATE_LIMITER_JOB.scope(limiter, fut).await,
        None => fut.await,
    }
}

/// Acquire one permit from the active request rate limiter before sending a
/// request. Prefers the per-job task-local limiter (bound by MCP / REST
/// runners) and falls back to the process-wide one installed from the CLI.
/// When no limiter is configured — the default — this is a cheap no-op (a
/// failed task-local lookup plus an empty `OnceLock` read), so callers can
/// place it before every send unconditionally.
#[inline]
pub async fn rate_limit_acquire() {
    if let Ok(limiter) = RATE_LIMITER_JOB.try_with(std::sync::Arc::clone) {
        limiter.acquire().await;
        return;
    }
    if let Some(Some(limiter)) = RATE_LIMITER.get() {
        limiter.acquire().await;
    }
}

/// Acquire a rate-limit permit (see [`rate_limit_acquire`]) and then record
/// the request in the counters (see [`tick_request_count`]). Call this
/// immediately before a direct `.send().await` so the request is both
/// throttled and tallied in one step. Sends that go through
/// `utils::send_with_retry` are already throttled internally and should keep
/// calling `tick_request_count` directly.
#[inline]
pub async fn record_outbound_request() {
    rate_limit_acquire().await;
    tick_request_count();
}

/// Record a single outbound HTTP request. Always increments the process-wide
/// `REQUEST_COUNT`; additionally increments the task-local `REQUEST_COUNT_JOB`
/// counter when one is bound (see MCP `run_job`). Prefer this over calling
/// `REQUEST_COUNT.fetch_add` directly so concurrent scans get accurate
/// per-job numbers.
#[inline]
pub fn tick_request_count() {
    REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let _ = REQUEST_COUNT_JOB.try_with(|c| c.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
}

/// Record a WAF-block response (403/406/429/503 on an injection request).
/// Returns the per-scan consecutive block count used for adaptive backoff.
///
/// - Always bumps the process-wide `WAF_BLOCK_COUNT` for CLI totals.
/// - When a per-job task-local is bound, increments that and returns its new
///   value, isolating concurrent scans. Otherwise falls back to the global
///   `WAF_CONSECUTIVE_BLOCKS` atomic.
#[inline]
pub fn tick_waf_block() -> u32 {
    WAF_BLOCK_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    match WAF_CONSECUTIVE_BLOCKS_JOB
        .try_with(|c| c.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1)
    {
        Ok(v) => v,
        Err(_) => WAF_CONSECUTIVE_BLOCKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    }
}

/// Reset the consecutive-WAF-block counter after a non-blocking response.
/// Prefers the per-job counter when bound; falls back to the global one.
#[inline]
pub fn reset_waf_consecutive() {
    match WAF_CONSECUTIVE_BLOCKS_JOB.try_with(|c| c.store(0, std::sync::atomic::Ordering::Relaxed))
    {
        Ok(_) => {}
        Err(_) => WAF_CONSECUTIVE_BLOCKS.store(0, std::sync::atomic::Ordering::Relaxed),
    }
}
