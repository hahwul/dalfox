//! Dalfox XSS Scanner
//!
//! The engine behind the `dalfox` binary: parameter discovery and mining,
//! payload generation and encoding, reflection and DOM-based detection, and
//! AST-backed JavaScript analysis.
//!
//! # Public surface
//!
//! This crate ships as a binary; the library target exists to hold the engine
//! and to let `tests/` drive it. Most of it is `pub(crate)` for that reason —
//! what stays `pub` is what `main.rs` dispatches through plus what the
//! integration tests reach for, not a curated API. Treat anything here as
//! internal unless the binary or a test in `tests/` actually uses it.
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
pub(crate) mod job;
pub mod mcp;
pub(crate) mod oob;
pub mod parameter_analysis;
pub mod payload;
pub mod scanning;
pub mod server;
pub mod target_parser;
pub mod utils;
pub(crate) mod waf;

pub use std::sync::atomic::AtomicBool;
pub use std::sync::atomic::AtomicU64;

pub static DEBUG: AtomicBool = AtomicBool::new(false);
pub static REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);
/// Outbound requests that never produced a response — connection reset,
/// refused, timed out, TLS failure — counted *after* `send_with_retry` has
/// exhausted its budget. See [`tick_request_failure`].
pub static REQUEST_FAILURE_COUNT: AtomicU64 = AtomicU64::new(0);
pub(crate) static WAF_BLOCK_COUNT: AtomicU64 = AtomicU64::new(0);
pub(crate) static WAF_CONSECUTIVE_BLOCKS: std::sync::atomic::AtomicU32 =
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
    pub(crate) static REQUEST_COUNT_JOB: std::sync::Arc<AtomicU64>;

    /// Per-scan failed-request counter, the sibling of [`REQUEST_COUNT_JOB`].
    /// Bound alongside it by `job::runner` (to `progress.requests_failed`) so a
    /// daemon's concurrent jobs don't inherit each other's transport failures —
    /// the same process-global trap the remote payload cache had. Callers use
    /// `tick_request_failure`, which bumps the global tally as well.
    pub(crate) static REQUEST_FAILURE_COUNT_JOB: std::sync::Arc<AtomicU64>;

    /// Per-scan consecutive-WAF-block counter. Bound by MCP and REST runners
    /// so concurrent scans don't trigger each other's adaptive backoff.
    /// Callers use `tick_waf_block` / `reset_waf_consecutive`.
    pub(crate) static WAF_CONSECUTIVE_BLOCKS_JOB: std::sync::Arc<std::sync::atomic::AtomicU32>;

    /// Per-scan request rate limiter, bound by the MCP / REST runners (see
    /// [`with_job_rate_limiter`]) so concurrent jobs get independent request
    /// budgets instead of sharing the process-wide one. Preferred over
    /// `RATE_LIMITER` by [`rate_limit_acquire`] when bound.
    pub(crate) static RATE_LIMITER_JOB: std::sync::Arc<utils::rate_limit::RateLimiter>;
}

/// Install the process-wide request rate limiter from `--rate-limit`
/// (requests/second; `0` = unlimited). Called once from the CLI scan entry
/// point before any requests go out. Idempotent: only the first call wins,
/// matching the once-per-process CLI lifecycle.
pub(crate) fn install_rate_limiter(rate: u32) {
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

/// Snapshot of the per-job task-local scopes (request counter, WAF-backoff
/// counter, rate limiter) captured from the currently-executing task.
///
/// The REST server and MCP runner bind these task-locals on the *parent* scan
/// future so concurrent scans stay isolated. But `run_scanning` fans work out
/// to per-parameter workers via `tokio::spawn`, and tokio task-locals are NOT
/// inherited across `spawn`. Without re-binding, those workers — which send the
/// bulk of a scan's requests — silently fall back to the process-wide globals:
/// the per-job `requests_sent` under-counts the whole injection phase, and one
/// scan's WAF backoff bleeds into unrelated concurrent scans. Capture the
/// scopes in the parent task, then re-enter them inside each spawned worker via
/// [`with_job_scopes`].
///
/// All three are `None` on the CLI path (it binds no per-job scope and uses the
/// process-wide globals by design), so capture + re-enter is a no-op there.
#[derive(Clone, Default)]
pub struct JobScopes {
    requests: Option<std::sync::Arc<AtomicU64>>,
    request_failures: Option<std::sync::Arc<AtomicU64>>,
    waf: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
    limiter: Option<std::sync::Arc<utils::rate_limit::RateLimiter>>,
}

impl JobScopes {
    /// Capture whatever per-job task-locals are currently bound in the calling
    /// task. Returns all-`None` when called outside any per-job scope (the CLI).
    pub(crate) fn capture() -> Self {
        Self {
            requests: REQUEST_COUNT_JOB.try_with(std::sync::Arc::clone).ok(),
            request_failures: REQUEST_FAILURE_COUNT_JOB
                .try_with(std::sync::Arc::clone)
                .ok(),
            waf: WAF_CONSECUTIVE_BLOCKS_JOB
                .try_with(std::sync::Arc::clone)
                .ok(),
            limiter: RATE_LIMITER_JOB.try_with(std::sync::Arc::clone).ok(),
        }
    }

    /// True when no per-job scope was captured (the CLI path).
    pub(crate) fn is_empty(&self) -> bool {
        self.requests.is_none()
            && self.request_failures.is_none()
            && self.waf.is_none()
            && self.limiter.is_none()
    }
}

/// Run `fut` with the captured per-job task-local scopes re-bound, so work
/// spawned via `tokio::spawn` writes through to the per-job counters/limiter
/// instead of the process-wide globals. A plain `fut.await` (no boxing) when no
/// scope was captured — the CLI path — so it adds nothing there.
pub async fn with_job_scopes<F>(scopes: JobScopes, fut: F) -> F::Output
where
    F: std::future::Future + Send + 'static,
    F::Output: 'static,
{
    if scopes.is_empty() {
        return fut.await;
    }
    // Each present scope re-binds via `.scope()`, which yields a distinct future
    // type, so build the (0–3 deep) chain with boxed futures. `Box<dyn Future +
    // Send>` carries an implicit `+ 'static`, keeping the result spawn-safe.
    let mut f: std::pin::Pin<Box<dyn std::future::Future<Output = F::Output> + Send>> =
        Box::pin(fut);
    if let Some(limiter) = scopes.limiter {
        f = Box::pin(RATE_LIMITER_JOB.scope(limiter, f));
    }
    if let Some(waf) = scopes.waf {
        f = Box::pin(WAF_CONSECUTIVE_BLOCKS_JOB.scope(waf, f));
    }
    if let Some(failures) = scopes.request_failures {
        f = Box::pin(REQUEST_FAILURE_COUNT_JOB.scope(failures, f));
    }
    if let Some(requests) = scopes.requests {
        f = Box::pin(REQUEST_COUNT_JOB.scope(requests, f));
    }
    f.await
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
pub(crate) fn tick_request_count() {
    REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let _ = REQUEST_COUNT_JOB.try_with(|c| c.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
}

/// Record an outbound request that never produced a response.
///
/// A transport error in the injection phase means a payload was *sent but never
/// tested*. Every send site swallowed those (`if let Ok(resp) = …`), and nothing
/// counted them, so a target that drops or resets injection requests produced a
/// scan indistinguishable from a genuinely clean one: `status: clean`,
/// `incomplete: false`, exit 0, with a plausible `total_requests`.
///
/// Mirrors [`tick_request_count`]: always bumps the process-wide counter, and
/// additionally the task-local one when a per-job scope is bound.
#[inline]
pub(crate) fn tick_request_failure() {
    REQUEST_FAILURE_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let _ = REQUEST_FAILURE_COUNT_JOB
        .try_with(|c| c.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
}

/// Record a WAF-block response (403/406/429/503 on an injection request).
/// Returns the per-scan consecutive block count used for adaptive backoff.
///
/// - Always bumps the process-wide `WAF_BLOCK_COUNT` for CLI totals.
/// - When a per-job task-local is bound, increments that and returns its new
///   value, isolating concurrent scans. Otherwise falls back to the global
///   `WAF_CONSECUTIVE_BLOCKS` atomic.
#[inline]
pub(crate) fn tick_waf_block() -> u32 {
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
pub(crate) fn reset_waf_consecutive() {
    match WAF_CONSECUTIVE_BLOCKS_JOB.try_with(|c| c.store(0, std::sync::atomic::Ordering::Relaxed))
    {
        Ok(_) => {}
        Err(_) => WAF_CONSECUTIVE_BLOCKS.store(0, std::sync::atomic::Ordering::Relaxed),
    }
}

#[cfg(test)]
mod job_scope_tests {
    //! Regression tests for [`JobScopes`] / [`with_job_scopes`]: the per-job
    //! task-local scopes (`requests_sent`, `requests_failed`, WAF backoff) that
    //! `run_scanning`'s
    //! `tokio::spawn`'d workers must re-enter. Assertions are on per-job
    //! counters (fresh `Arc`s), never the process-wide globals, so they don't
    //! flake under parallel test runs that also bump those globals.
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    #[tokio::test]
    async fn with_job_scopes_rebinds_the_failure_counter_across_spawn() {
        // `job::runner` binds this alongside `REQUEST_COUNT_JOB`. Nothing did
        // for a while, which made `capture()` always yield `None` here and left
        // every job's transport failures landing only on the process-global
        // tally — the cross-job leak this scope exists to prevent.
        let job_failures = Arc::new(AtomicU64::new(0));
        REQUEST_FAILURE_COUNT_JOB
            .scope(job_failures.clone(), async {
                let scopes = JobScopes::capture();
                assert!(
                    !scopes.is_empty(),
                    "a bound failure scope must be captured, not dropped"
                );
                tokio::spawn(with_job_scopes(scopes, async {
                    tick_request_failure();
                    tick_request_failure();
                }))
                .await
                .unwrap();
            })
            .await;
        assert_eq!(
            job_failures.load(Ordering::Relaxed),
            2,
            "failures raised in a spawned worker must reach the job's own counter"
        );
    }

    #[tokio::test]
    async fn two_jobs_do_not_inherit_each_others_transport_failures() {
        let job_a = Arc::new(AtomicU64::new(0));
        let job_b = Arc::new(AtomicU64::new(0));

        REQUEST_FAILURE_COUNT_JOB
            .scope(job_a.clone(), async {
                tick_request_failure();
            })
            .await;
        REQUEST_FAILURE_COUNT_JOB
            .scope(job_b.clone(), async {
                tick_request_failure();
                tick_request_failure();
            })
            .await;

        assert_eq!(job_a.load(Ordering::Relaxed), 1);
        assert_eq!(job_b.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn with_job_scopes_rebinds_request_counter_across_spawn() {
        let job_counter = Arc::new(AtomicU64::new(0));
        REQUEST_COUNT_JOB
            .scope(job_counter.clone(), async {
                let scopes = JobScopes::capture();
                tokio::spawn(with_job_scopes(scopes, async {
                    tick_request_count();
                    tick_request_count();
                }))
                .await
                .unwrap();
            })
            .await;
        assert_eq!(
            job_counter.load(Ordering::Relaxed),
            2,
            "with_job_scopes must route spawned-worker ticks to the per-job counter"
        );
    }

    #[tokio::test]
    async fn bare_spawn_loses_per_job_request_scope() {
        // Negative control: this is the F1 bug. A bare tokio::spawn does NOT
        // inherit the task-local, so the per-job counter is never touched —
        // which is exactly why workers need with_job_scopes.
        let job_counter = Arc::new(AtomicU64::new(0));
        REQUEST_COUNT_JOB
            .scope(job_counter.clone(), async {
                tokio::spawn(async {
                    tick_request_count();
                })
                .await
                .unwrap();
            })
            .await;
        assert_eq!(
            job_counter.load(Ordering::Relaxed),
            0,
            "tokio::spawn does not inherit task-locals; the per-job counter is missed without with_job_scopes"
        );
    }

    #[tokio::test]
    async fn with_job_scopes_rebinds_waf_counter_across_spawn() {
        let job_waf = Arc::new(AtomicU32::new(0));
        let observed = WAF_CONSECUTIVE_BLOCKS_JOB
            .scope(job_waf.clone(), async {
                let scopes = JobScopes::capture();
                tokio::spawn(with_job_scopes(scopes, async { tick_waf_block() }))
                    .await
                    .unwrap()
            })
            .await;
        assert_eq!(
            observed, 1,
            "tick_waf_block must see the per-job counter inside the re-scoped worker"
        );
        assert_eq!(job_waf.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn with_job_scopes_rebinds_rate_limiter_across_spawn() {
        // The limiter arm: a per-job rate limiter bound via with_job_rate_limiter
        // must be visible inside the re-scoped worker (so rate_limit_acquire
        // throttles against the job budget), while a bare spawn loses it.
        // Deterministic — checks scope presence, not throttling timing.
        let (with, without) = with_job_rate_limiter(5, async {
            let scopes = JobScopes::capture();
            let with = tokio::spawn(with_job_scopes(scopes, async {
                RATE_LIMITER_JOB.try_with(|_| ()).is_ok()
            }))
            .await
            .unwrap();
            let without = tokio::spawn(async { RATE_LIMITER_JOB.try_with(|_| ()).is_ok() })
                .await
                .unwrap();
            (with, without)
        })
        .await;
        assert!(with, "re-scoped worker must see the per-job rate limiter");
        assert!(
            !without,
            "bare spawn must not inherit the rate-limiter scope"
        );
    }

    #[tokio::test]
    async fn capture_is_empty_and_passes_through_outside_any_job_scope() {
        // The CLI path: no per-job scope bound, so capture() is empty and
        // with_job_scopes is a transparent pass-through (no boxing).
        let scopes = JobScopes::capture();
        assert!(scopes.is_empty(), "no per-job scope bound should be empty");
        let out = with_job_scopes(scopes, async { 7u8 }).await;
        assert_eq!(out, 7);
    }
}
