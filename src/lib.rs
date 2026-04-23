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
pub mod mcp;
pub mod parameter_analysis;
pub mod payload;
pub mod scanning;
pub mod target_parser;
pub mod utils;
pub mod waf;

pub use std::sync::atomic::AtomicBool;
pub use std::sync::atomic::AtomicU64;

pub static DEBUG: AtomicBool = AtomicBool::new(false);
pub static REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);
pub static WAF_BLOCK_COUNT: AtomicU64 = AtomicU64::new(0);
pub static WAF_CONSECUTIVE_BLOCKS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
pub static NO_COLOR: AtomicBool = AtomicBool::new(false);

tokio::task_local! {
    /// Per-scan request counter, set by the MCP runner so concurrent scans
    /// don't pollute each other's progress tallies. Callers use
    /// `tick_request_count` which bumps both the global counter and this
    /// task-local when it is bound.
    pub static REQUEST_COUNT_JOB: std::sync::Arc<AtomicU64>;
}

/// Record a single outbound HTTP request. Always increments the process-wide
/// `REQUEST_COUNT`; additionally increments the task-local `REQUEST_COUNT_JOB`
/// counter when one is bound (see MCP `run_job`). Prefer this over calling
/// `REQUEST_COUNT.fetch_add` directly so concurrent scans get accurate
/// per-job numbers.
#[inline]
pub fn tick_request_count() {
    REQUEST_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let _ = REQUEST_COUNT_JOB
        .try_with(|c| c.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
}
