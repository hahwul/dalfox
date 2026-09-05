//! # Scanning (Stages 4–6)
//!
//! Drives payload generation, reflection checking, and DOM verification for
//! each probed parameter. [`run_scanning`] is the orchestrator: it builds the
//! per-parameter jobs (`generate_param_jobs`) and fans them out across
//! `ScanWorkerCtx::scan_param` workers.
//!
//! ## Stage 4: Payload Generation (`generate_param_jobs`)
//! Builds per-parameter payload sets based on `injection_context`, CSP bypass,
//! technology-specific payloads, and WAF bypass mutations/encoders.
//! Output: `ParamPayloadJob` tuples fed into the concurrent scan loop.
//!
//! ## Stage 5: Reflection Check (`ScanWorkerCtx::run_reflection_phase`, see
//! also the `check_reflection` module)
//! Each payload is injected and the response is checked for reflection.
//!
//! ## Stage 6: DOM Verification (`ScanWorkerCtx::run_dom_phase`, see also
//! the `check_dom_verification` module)
//! Reflected payloads are verified for actual DOM evidence to upgrade
//! findings from "R" (Reflected) to "V" (DOM-verified).
//!
//! ## Per-parameter request fan-out (issue #1156)
//! The total requests sent per parameter is, roughly:
//!
//! ```text
//!   probe (1–2)
//! + reflection phase: short-circuits on the first detected reflection, so ~1
//!     request on a reflecting param; up to `min(reflection_set, cap)` on a
//!     non-reflecting / safe-context one
//! + DOM phase: 1 request per DOM payload until a payload verifies (`V`) OR the
//!     recall-preserving early exit fires (see `INERT_ECHO_BUDGET` /
//!     `BLOCKED_STREAK_LIMIT`) OR the per-param cap is hit
//! + HPP (only with `--hpp`, ≤ 5 payloads × 3 positions)
//! ```
//!
//! The DOM/reflection payload-set size is `base × encoder_factor`, then a WAF
//! multiplier only when a WAF is detected (or `--force-waf`):
//!
//! | axis              | factor                                              |
//! |-------------------|-----------------------------------------------------|
//! | `--encoders`      | `1 + count(active encoders)` (default `url,html` → 3)|
//! | WAF bypass        | `expand_waf_payloads`: structural mutations + encoder variants are added **orthogonally** (no `encode(mutate(p))` cross-product), so it is additive, not multiplicative — and is paid **only on WAF targets** |
//! | `--deep-scan`     | disables the per-param cap **and** the DOM early exit (exhaustive) |
//! | `--max-payloads-per-param N` | hard-caps each set at `N` (default `0` = unlimited) |
//!
//! Note: `--max-payloads-per-param` defaults to unlimited, so the DOM early exit
//! is the only *default-on* bound on the DOM phase. Net effect on a
//! self-/canonical-link echo (the issue's worst case): the DOM phase used to
//! send the entire set (measured ~thousands/param); the early exit now caps it
//! at roughly one diverse pass once the endpoint proves inert.

pub mod ast_dom_analysis;
pub mod ast_integration;
pub mod check_dom_verification;
pub mod check_reflection;
pub(crate) use check_reflection::decode_html_entities;
/// Shared test-only fixtures modelling server-side reflection transforms.
#[cfg(test)]
pub(crate) mod dom_evidence_fixtures;
pub mod js_context_verify;
pub mod light_verify;
pub mod markers;
pub mod result;
pub mod selectors;
pub mod tech_detect;
pub mod url_inject;
pub mod vuln_libs;
pub mod xss_blind;
pub mod xss_common;

// Scan-hub helper modules (extracted for parallel work / navigability).
mod ast_dom_phase;
mod param_jobs;
mod payload_families;
mod progress;
mod request_render;
mod waf_strategy;

pub(crate) use ast_dom_phase::*;
pub(crate) use param_jobs::*;
pub(crate) use payload_families::*;
pub(crate) use progress::*;
pub(crate) use request_render::*;
pub(crate) use waf_strategy::*;

use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::Param;
use crate::scanning::check_dom_verification::check_dom_verification_with_client_outcome;
use crate::scanning::check_reflection::check_reflection_with_response_tracked;
use crate::scanning::result::FindingType;
use crate::target_parser::Target;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, RwLock, Semaphore};

/// A per-parameter work unit for the scan loop: the parameter, its reflection
/// payloads (checked in Stage 5), and its DOM payloads (verified in Stage 6).
pub type ParamPayloadJob = (Param, Vec<String>, Vec<String>);

/// Count how many results in `results` match the `--limit-result-type` filter.
/// Returns `results.len()` when filter is `"all"` (default).
/// `filter` must already be uppercased (normalised once at scan start).
pub(crate) fn count_matching_results(
    results: &[crate::scanning::result::Result],
    filter: &str,
) -> usize {
    if filter == "ALL" {
        return results.len();
    }
    results
        .iter()
        .filter(|r| r.result_type.short() == filter)
        .count()
}

/// Per-target "a finding already landed for this injection point" sets, keyed
/// by [`found_param_key`].
struct FoundParams {
    reflection: HashSet<String>,
    dom: HashSet<String>,
}

/// Identity of a parameter *slot* for the [`FoundParams`] sets.
///
/// Keyed on the wire location and the wire-level name, not just the display
/// name: the same name routinely names two independent injection points on one
/// request — `?q=` in the query string *and* `q` in the POST body, or a `q`
/// cookie — and a finding at one says nothing about the other. Keying on
/// `Param::name` alone let the first slot that produced a finding suppress
/// every sibling slot: the reflection/DOM phases short-circuited and the
/// dispatch loop skipped the sibling's worker outright, so a vulnerable body
/// parameter was silently never reported (false negative).
///
/// `wire_name` is part of the key so nested-field synthetic params
/// (`qs[move_url]`, whose wire name is the parent `qs`) stay distinct from one
/// another exactly as they were under the old name-only key.
fn found_param_key(param: &Param) -> String {
    // `\u{1}` separator: not producible by a URL/header parameter name, so
    // concatenation cannot alias two different slots onto one key.
    format!(
        "{:?}\u{1}{}\u{1}{}",
        param.location,
        param.name,
        param.effective_wire_name()
    )
}

/// Collapse this target's R findings that are already proven by one of its
/// own V findings on the same `(param, location, inject_type)`, adjusting
/// `findings_count` for any dropped duplicates. Multiple per-param payload
/// variants typically surface the same logical issue twice — keep the
/// strongest evidence and drop weaker R duplicates. See
/// [`collapse_redundant_reflected`] for the target-scoping rationale.
async fn collapse_target_results(
    results: &Arc<Mutex<Vec<crate::scanning::result::Result>>>,
    findings_count: &Arc<AtomicUsize>,
    limit_result_type: &str,
    target: &Target,
) {
    let mut guard = results.lock().await;
    let original = std::mem::take(&mut *guard);
    let target_url_str = target.url.to_string();
    // Decrement by the drop in *filter-matching* findings, mirroring the add
    // path (`count_matching_results` in `accumulate`/`record_results`). Using
    // the raw length delta (`before - after`) would over-decrement whenever the
    // collapsed entries — always `R` duplicates — don't match
    // `--limit-result-type` (e.g. `V`/`A`): `findings_count` never counted them,
    // so subtracting them underflows the unsigned counter to ~usize::MAX and
    // poisons `limit_reached()` for the rest of a multi-target run (a silent,
    // hard-to-diagnose scan truncation).
    let before_matching = count_matching_results(&original, limit_result_type);
    let collapsed = collapse_redundant_reflected(original, &target_url_str);
    let after_matching = count_matching_results(&collapsed, limit_result_type);
    *guard = collapsed;
    if after_matching < before_matching {
        findings_count.fetch_sub(before_matching - after_matching, Ordering::Relaxed);
    }
}

/// Outcome of a per-parameter scan phase. `Abort` means a global `--limit` was
/// reached mid-phase, so the worker stops immediately without running the
/// remaining phases. A `break`-style early exit (cancellation) instead yields
/// `Continue`, so later phases run their own cancellation checks.
///
/// Either way the caller flushes whatever the worker already batched. The
/// pre-refactor `return` discarded that batch instead, on the reasoning that
/// "the limit is already hit, the scan is winding down" — but `--limit` is a
/// *stop condition*, not an instruction to destroy evidence already confirmed
/// against the target, and the worker that aborts is rarely the one that
/// reached the cap. The discard is observable whenever the surviving tally
/// falls back under the limit before rendering, which `collapse_target_results`
/// does routinely (it decrements `findings_count` for every `R` a `V` covers):
/// the report then has room for the findings the abort threw away. Flushing
/// cannot overshoot the cap either, because `--limit` truncation is applied
/// once more at render time (`cmd::scan::output`).
enum PhaseFlow {
    Continue,
    Abort,
}

/// Issue #1156 — recall-preserving DOM-phase early-exit budgets.
///
/// `run_dom_phase` only short-circuits when a payload actually *verifies* (`V`).
/// On a self-/canonical-link echo endpoint — one that reflects every payload but
/// in an inert (non-executable) context — that means the *entire* DOM payload
/// set is sent (measured at tens of thousands of requests for a single
/// parameter; see the issue). These budgets curtail that fan-out once the
/// endpoint has produced overwhelming evidence it will never verify, without
/// trimming the high-signal shapes.
///
/// `INERT_ECHO_BUDGET` is the cumulative count of payloads that were reflected
/// but inert (`reflected && !verified`).
///
/// Recall safety rests on two properties:
///
/// 1. **The budget only accrues on raw-reflecting endpoints.**
///    `check_reflection::classify_reflection` returns `None` for reflections the
///    server escaped/encoded (entity, percent, fullwidth) — see its FP guards —
///    so a *sanitizing* endpoint (DOMPurify, `&lt;IMG&gt;`-emitting templates,
///    …) never advances `inert_echo_count` and is never cut. The early exit
///    therefore fires only on endpoints that echo our bytes verbatim yet never
///    execute them.
///
/// 2. **Every DOM-evidence kind is sampled before the budget can trip.** For the
///    unknown-context catalog the families are round-robin interleaved (see
///    `interleave_payload_families`), so any prefix — including the first
///    `INERT_ECHO_BUDGET` echoes — contains a representative of each evidence
///    kind: HTML-tag injection, event-handler/attribute breakout, mXSS,
///    DOM-clobbering, and `javascript:`/`data:` protocol-URL (the sole verifier
///    for URL-attribute sinks). Without the interleave the protocol/mXSS
///    families are appended last and would sit thousands of payloads past the
///    budget. Context-specific catalogs are already shape-diverse up front.
///
/// Given (1) and (2), 256 reflected-but-inert echoes with zero verifications is
/// overwhelming evidence of a uniformly-inert echo; the remaining payloads are
/// redundant sink-variations (`alert` vs `prompt`) and encoder-variants of
/// shapes that already failed, so cutting them is recall-neutral.
const INERT_ECHO_BUDGET: u32 = 256;

/// Issue #1156 — *consecutive* dead-server responses that end the DOM phase.
///
/// Scoped to **server errors (`status >= 500`) only**, deliberately *excluding*
/// 4xx WAF blocks (`403`/`406`/`429`): a payload *variant* can bypass a WAF
/// filter, so early-exiting on a 4xx block would risk cutting a working bypass
/// (those are handled by the reflection-path WAF backoff instead). A 5xx that
/// tells us nothing back is the server failing — no payload variant "bypasses"
/// it — so a long consecutive run is a safe, recall-neutral stop. A single
/// response that does not qualify resets the streak, so a transient blip cannot
/// abandon a recoverable parameter.
///
/// A 5xx that **echoes the payload** is explicitly *not* counted. That
/// combination is a framework development error page (Kemal, Werkzeug, Rails,
/// Symfony …), which renders the request path, query string, or an exception
/// message built from user input — one of the most common reflected-XSS sinks
/// there is, and a 500 by construction. Counting it lost the entire class:
/// after 64 payloads dalfox abandoned DOM verification and could only ever
/// report `[R]` for a parameter that `--deep-scan` verifies as `[V]`. Fan-out
/// on such an endpoint stays bounded by [`INERT_ECHO_BUDGET`], which is the
/// budget designed for "reflects everything, verifies nothing".
const BLOCKED_STREAK_LIMIT: u32 = 64;

/// True for statuses that signal the endpoint will not yield a DOM verification
/// *and* that no payload variant could turn around: any 5xx server error. 4xx
/// WAF blocks are intentionally excluded (see [`BLOCKED_STREAK_LIMIT`]); `0`
/// (request error) is likewise not blocking — a transient network error should
/// not, on its own, end the phase.
///
/// Status alone is not the whole test: see [`next_blocked_streak`], which
/// additionally spares a 5xx that reflected the payload.
fn is_blocking_dom_status(status: u16) -> bool {
    status >= 500
}

/// Fold one DOM response's `reflected` flag into the cumulative inert-echo
/// count. Cumulative (never resets on a non-reflecting response) so an endpoint
/// that reflects most-but-not-all payloads still converges on the budget. Pure
/// for unit testing.
fn next_inert_echo_count(prev: u32, reflected: bool) -> u32 {
    if reflected { prev + 1 } else { prev }
}

/// Fold one DOM response's status into the consecutive blocked streak: increment
/// on a blocking status, reset to 0 otherwise. The reset is what makes the
/// streak *consecutive* (one good response clears it), preserving recall on
/// intermittently-failing endpoints.
///
/// `reflected` spares the responses a 5xx status alone would condemn: a server
/// error that hands our payload back is a rendered error page, not a dead
/// server, and error pages are a first-class XSS sink (see
/// [`BLOCKED_STREAK_LIMIT`]). Pure for unit testing.
fn next_blocked_streak(prev: u32, status: u16, reflected: bool) -> u32 {
    if is_blocking_dom_status(status) && !reflected {
        prev + 1
    } else {
        0
    }
}

/// Decide whether the DOM phase should stop early given the signals accumulated
/// so far. Pure so it can be unit-tested without a live server. Disabled under
/// `--deep-scan` (the exhaustive mode that opts out of all fan-out trimming).
fn dom_phase_should_early_exit(
    deep_scan: bool,
    inert_echo_count: u32,
    blocked_streak: u32,
) -> bool {
    !deep_scan && (inert_echo_count >= INERT_ECHO_BUDGET || blocked_streak >= BLOCKED_STREAK_LIMIT)
}

/// Mutable per-parameter state shared across a single worker's probe,
/// reflection, DOM, and HPP phases.
#[derive(Default)]
struct ParamScanState {
    /// Findings batched locally, flushed to the shared vector once at the
    /// end of the worker (one lock acquisition instead of one per finding).
    local_results: Vec<crate::scanning::result::Result>,
    /// AST findings already recorded for this param (dedup key set).
    ast_seen: HashSet<String>,
    /// AST DOM analysis runs at most once per param.
    ast_analysis_done: bool,
    /// Reflection already confirmed for this param locally — skip the
    /// remaining reflection payloads.
    reflection_found_locally: bool,
    /// DOM XSS already confirmed for this param locally — skip the
    /// remaining DOM payloads.
    dom_found_locally: bool,
    /// Per-worker consecutive-WAF-block streak driving the `--waf-evasion`
    /// backoff escalation. Lives on the per-param scan state (one per worker)
    /// so a single scan's ~50 concurrent workers don't reset each other's
    /// streak — which previously kept the escalation from ever firing. Threaded
    /// into `check_reflection_with_response_tracked`.
    waf_streak: std::sync::atomic::AtomicU32,
}

/// Shared, cheaply-clonable context handed to each spawned worker. Every
/// field is an `Arc`/handle, so `clone()` per worker is just a refcount
/// bump (plus a `ProgressBar` clone, itself an `Arc` internally).
#[derive(Clone)]
struct ScanWorkerCtx {
    args: Arc<ScanArgs>,
    target: Arc<Target>,
    client: Arc<reqwest::Client>,
    results: Arc<Mutex<Vec<crate::scanning::result::Result>>>,
    found_params: Arc<RwLock<FoundParams>>,
    findings_count: Arc<AtomicUsize>,
    pb: Option<ProgressBar>,
    overall_pb: Option<Arc<indicatif::ProgressBar>>,
    limit_result_type: Arc<str>,
    cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
    finding_tx: Option<tokio::sync::mpsc::UnboundedSender<crate::scanning::result::Result>>,
    semaphore: Arc<Semaphore>,
    /// Live per-parameter completion counter (see `run_scanning`'s
    /// `params_done`). Bumped once per finished parameter worker.
    params_done: Option<Arc<AtomicU32>>,
}

impl ScanWorkerCtx {
    /// True when a cancellation flag was supplied and is now set.
    fn cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|c| c.load(Ordering::Relaxed))
    }

    /// True when a global `--limit` was supplied and the running findings
    /// tally has reached it.
    fn limit_reached(&self) -> bool {
        self.args
            .limit
            .is_some_and(|lim| self.findings_count.load(Ordering::Relaxed) >= lim)
    }

    /// Stream a new finding through the channel (if provided) before it is
    /// batched into the shared results — so the CLI can print the full
    /// finding block (POC + Issue + Payload + Line) while the scan is still
    /// running instead of waiting for the end-of-scan flush. The response
    /// body is forwarded so the CLI's `L13:` context line can be extracted
    /// from the actual response; it's dropped from the clone at the receiver
    /// after use. Channel is unbounded but the total payload is bounded by
    /// the (small) finding count.
    fn stream_finding(&self, r: &crate::scanning::result::Result) {
        if let Some(tx) = self.finding_tx.as_ref() {
            let _ = tx.send(r.clone());
        }
    }

    /// Flush locally-batched findings into the shared results vector with a
    /// single lock acquisition, bumping `findings_count` by the number that
    /// match `--limit-result-type`.
    async fn flush_results(&self, local_results: &mut Vec<crate::scanning::result::Result>) {
        if local_results.is_empty() {
            return;
        }
        let batch = std::mem::take(local_results);
        let added = count_matching_results(&batch, &self.limit_result_type);
        let mut guard = self.results.lock().await;
        guard.extend(batch);
        self.findings_count.fetch_add(added, Ordering::Relaxed);
    }

    /// Scan a single parameter end-to-end: acquire a worker permit, probe
    /// for reflection (running a one-shot AST analysis on the probe
    /// response), then run the reflection, DOM, and HPP phases before
    /// flushing the batched findings.
    async fn scan_param(
        &self,
        param: Param,
        reflection_payloads: Vec<String>,
        dom_payloads: Vec<String>,
    ) {
        // `acquire()` only errors if the semaphore has been closed. Nothing
        // closes this one today (it lives for the whole scan), so the error
        // path is currently unreachable — but `expect` would turn any future
        // cooperative-shutdown change into a panic across every waiting
        // worker, which is especially bad when dalfox runs embedded as a
        // library / server / MCP backend. A closed semaphore means there is
        // no work left to do, so wind the worker down cleanly (results are
        // batched into the shared vector, so there is nothing to return).
        let Ok(_permit) = self.semaphore.acquire().await else {
            return;
        };

        let mut state = ParamScanState::default();

        // Every parameter's worker is spawned up front (the dispatch loop only
        // gates *spawning* on cancellation), so on a cancelled scan the workers
        // still queued behind this semaphore would each go on to fire the Stage-0
        // probe and the HPP phase — thousands of requests at a target the user
        // already asked us to stop hitting. Bail before the first request.
        if self.cancelled() {
            return;
        }

        // Stage 0: fast probe to avoid large payload blasts on non-reflective
        // params (also runs one-shot AST DOM analysis on the probe response).
        let probe_reflected = self.probe_param(&param, &mut state).await;

        // If probe found no reflection and not in deep_scan, skip heavy
        // payload loops for this param.
        if !probe_reflected && !self.args.deep_scan {
            self.flush_results(&mut state.local_results).await;
            return;
        }

        // Save a reference copy for the HPP phase (only first 5 payloads)
        // before the reflection phase consumes `reflection_payloads`. Gate on
        // the same condition `run_hpp_phase` checks (Query location) so we don't
        // clone payloads for params whose HPP phase would immediately return.
        let hpp_payloads: Vec<String> =
            if self.args.hpp && param.location == crate::parameter_analysis::Location::Query {
                reflection_payloads.iter().take(5).cloned().collect()
            } else {
                vec![]
            };

        if let PhaseFlow::Abort = self
            .run_reflection_phase(&param, reflection_payloads, &mut state)
            .await
        {
            self.flush_results(&mut state.local_results).await;
            return;
        }
        if let PhaseFlow::Abort = self.run_dom_phase(&param, dom_payloads, &mut state).await {
            self.flush_results(&mut state.local_results).await;
            return;
        }
        self.run_hpp_phase(&param, hpp_payloads, &mut state).await;

        self.flush_results(&mut state.local_results).await;
    }

    /// Stage 0 fast probe: detect whether the param reflects at all before
    /// blasting the full payload set. Runs the sandwich marker probe, a
    /// one-shot AST DOM analysis on the probe response, and a numeric-only
    /// fallback probe (to catch letter-stripping filters). Returns whether
    /// any reflection was observed; AST findings are pushed into `state`.
    async fn probe_param(&self, param: &Param, state: &mut ParamScanState) -> bool {
        let client = self.client.as_ref();

        // Sandwich probe (OPEN+INNER+CLOSE) so the response check picks up
        // partial reflections (PrefixOnly / SuffixOnly / InnerOnly) where a
        // server-side filter strips a prefix or suffix off the input before
        // echoing — those cases would slip past a single-token contains().
        let probe_payloads: [&str; 1] = [crate::scanning::markers::bracketed_marker()];
        let mut probe_reflected = false;
        let mut probe_response_text: Option<String> = None;
        for pp in probe_payloads {
            if self.cancelled() {
                break;
            }
            let (kind, response_text) = check_reflection_with_response_tracked(
                Some(client),
                &self.target,
                param,
                pp,
                &self.args,
                &state.waf_streak,
            )
            .await;
            // Only a browser-rendered body may seed AST analysis / probe
            // classification; the 3xx `Location:` stand-in is not a document.
            let response_text = response_text.and_then(|b| b.renderable.then_some(b.text));
            if kind.is_some() {
                probe_reflected = true;
                probe_response_text = response_text;
                break;
            } else if let Some(ref text) = response_text {
                // Even if safe-context suppressed the reflection kind,
                // check if the probe marker actually appears in the response.
                // This ensures breakout payloads get a chance to be tried
                // for params reflected inside safe tags (title, textarea, etc.).
                if crate::scanning::markers::classify_probe_reflection(text).detected() {
                    probe_reflected = true;
                    probe_response_text = response_text;
                    break;
                }
                // Keep one response for AST analysis below.
                probe_response_text = response_text;
            }
        }

        // Run AST-based DOM XSS static analysis once using the probe response (if available)
        if !self.args.skip_ast_analysis
            && let Some(ref response_text) = probe_response_text
        {
            state.ast_analysis_done = true;
            let ast_findings = run_ast_dom_analysis(
                client,
                &self.target,
                param,
                response_text,
                &mut state.ast_seen,
            )
            .await;
            for f in &ast_findings {
                self.stream_finding(f);
            }
            state.local_results.extend(ast_findings);
        }

        // If probe found no reflection, try a numeric-only probe to detect
        // letter-stripping filters (e.g., /[a-zA-Z]/ removal). Skipped once the
        // scan is cancelled — it is a second HTTP request per parameter.
        if !probe_reflected && !self.cancelled() {
            let numeric_probe = crate::scanning::check_reflection::NUMERIC_PROBE_MARKER;
            let (kind, _) = check_reflection_with_response_tracked(
                Some(client),
                &self.target,
                param,
                numeric_probe,
                &self.args,
                &state.waf_streak,
            )
            .await;
            if kind.is_some() {
                probe_reflected = true;
            }
        }

        probe_reflected
    }

    /// === Stage 5: Reflection Check ===
    ///
    /// Inject each reflection payload, recording an R (Reflected) finding —
    /// or upgrading to a V (Verified) finding when the reflection response
    /// itself already carries browser-executable DOM evidence (the static V
    /// upgrade). Lazily runs AST analysis if the probe had no usable
    /// response. Returns `Abort` when the global limit was reached mid-loop.
    async fn run_reflection_phase(
        &self,
        param: &Param,
        reflection_payloads: Vec<String>,
        state: &mut ParamScanState,
    ) -> PhaseFlow {
        for reflection_payload in reflection_payloads {
            // Check cancellation
            if self.cancelled() {
                break;
            }
            // Early stop if global limit reached
            if self.limit_reached() {
                return PhaseFlow::Abort;
            }
            // Skip reflection if already found for this param
            let reflection_tuple = if state.reflection_found_locally {
                (None, None)
            } else if self.args.deep_scan {
                // deep_scan never records into `found_params.reflection` (the
                // write path short-circuits to `should_add = true` below), so
                // the shared read would always return false. Skip the awaited
                // lock and run the reflection check directly on every payload.
                check_reflection_with_response_tracked(
                    Some(self.client.as_ref()),
                    &self.target,
                    param,
                    &reflection_payload,
                    &self.args,
                    &state.waf_streak,
                )
                .await
            } else {
                let already = self
                    .found_params
                    .read()
                    .await
                    .reflection
                    .contains(&found_param_key(param));
                if already {
                    state.reflection_found_locally = true;
                    (None, None)
                } else {
                    check_reflection_with_response_tracked(
                        Some(self.client.as_ref()),
                        &self.target,
                        param,
                        &reflection_payload,
                        &self.args,
                        &state.waf_streak,
                    )
                    .await
                }
            };
            let reflected_kind = reflection_tuple.0;
            let reflection_body = reflection_tuple.1;
            // Everything downstream of here infers execution from the body
            // (AST sinks, the static V upgrade), so it may only ever see a
            // body a browser would actually render. The 3xx `Location:`
            // stand-in is withheld: it contains the payload for R
            // classification but was never a document. Borrowed rather than
            // cloned — a response body runs up to 16 MiB and this is the
            // per-payload hot loop.
            let renderable_text: Option<&str> =
                reflection_body.as_ref().and_then(|b| b.renderable_text());
            // A body served as executable JavaScript (JSONP) is run as script,
            // never HTML-parsed, so HTML-parse-derived DOM evidence found in it
            // is inert — an `<svg onload=…>` echo is a JS syntax error, not a
            // rendered element. Only JS-context evidence upgrades R→V there.
            let body_is_javascript = reflection_body.as_ref().is_some_and(|b| b.js_content_type);

            // AST-based DOM XSS analysis (enabled by default unless skipped)
            if !self.args.skip_ast_analysis
                && !state.ast_analysis_done
                && let Some(response_text) = renderable_text
            {
                state.ast_analysis_done = true;
                let ast_findings = run_ast_dom_analysis(
                    self.client.as_ref(),
                    &self.target,
                    param,
                    response_text,
                    &mut state.ast_seen,
                )
                .await;
                for f in &ast_findings {
                    self.stream_finding(f);
                }
                state.local_results.extend(ast_findings);
            }

            if let Some(ref pb) = self.pb {
                pb.inc(1);
            }
            if let Some(ref opb) = self.overall_pb {
                opb.inc(1);
            }
            if let Some(kind) = reflected_kind {
                // Static V upgrade: reuse the reflection response body to look
                // for browser-executable DOM evidence (marker, executable URL in
                // a dangerous attribute, HTML element with a sink handler,
                // JS-context sink call). Computed *before* the reflection lock so
                // an inert JS-body echo can be handled without emitting a bogus
                // finding.
                //
                // On a body served as executable JavaScript (JSONP), drop
                // HTML-parse-derived evidence: the browser runs the body as
                // script and never HTML-parses it, so a `<svg onload=…>` echo is
                // a JS syntax error, not a rendered element. Only JS-context
                // evidence (the payload runs as JavaScript) confirms XSS there;
                // the dedicated DOM phase supplies JSONP-callable payloads that
                // can prove that genuine V.
                let dom_evidence_kind = renderable_text
                    .and_then(|body| {
                        crate::scanning::check_dom_verification::classify_dom_evidence(
                            &reflection_payload,
                            body,
                        )
                    })
                    .filter(|kind| !(body_is_javascript && kind.requires_html_rendering()));

                // An inert HTML echo into a JS body is not a finding. Lock the
                // param's reflection slot (so the reflection phase stops here
                // instead of hammering an endpoint that echoes every payload)
                // but emit nothing, and leave `found.dom` unset so the DOM phase
                // still runs — a JSONP-callable payload there can prove V.
                if body_is_javascript && dom_evidence_kind.is_none() {
                    if !self.args.deep_scan {
                        let mut found = self.found_params.write().await;
                        found.reflection.insert(found_param_key(param));
                        state.reflection_found_locally = true;
                    }
                    continue;
                }

                let should_add = if self.args.deep_scan {
                    true
                } else {
                    let mut found = self.found_params.write().await;
                    let key = found_param_key(param);
                    if !found.reflection.contains(&key) {
                        found.reflection.insert(key);
                        state.reflection_found_locally = true;
                        true
                    } else {
                        false
                    }
                };

                if should_add {
                    // Build result URL with the reflected payload (via helper).
                    // Use the form action URL when the param came from form
                    // discovery, so the PoC URL points at the actual sink.
                    let base =
                        crate::scanning::url_inject::effective_query_base(&self.target.url, param);
                    // Build the PoC URL from the *as-sent* payload (pre-encoding
                    // applied — base64 / multi-URL / WAF window-pad) so the
                    // reported URL actually reproduces the finding.
                    // `build_injected_url` preserves existing %-encoding, matching
                    // the dedicated reflection-check PoC path. No-op for the common
                    // case (no pre-encoding → payload unchanged).
                    let poc_payload = crate::encoding::pre_encoding::apply_param_encoding(
                        &reflection_payload,
                        param,
                    );
                    let result_url =
                        crate::scanning::url_inject::build_injected_url(&base, param, &poc_payload);

                    let reflection_note = reflection_kind_note(kind);

                    // Static V upgrade: re-use the reflection response body
                    // to look for browser-executable DOM evidence. Saves one
                    // HTTP request relative to running a separate
                    // `check_dom_verification` request. The four evidence
                    // kinds (marker, executable URL in dangerous attribute,
                    // HTML element with sink handler, JS-context sink call)
                    // are the same set DOM verification ultimately uses, so
                    // the static path is consistent with the dedicated path.
                    //
                    // Without this broader check, multi-site reflections where
                    // the reflection-phase payload already contains the
                    // structurally exploitable bytes (e.g. xssmaze
                    // /realworld/level1 reflecting `<svg onload=alert(1)>`
                    // raw into <h2>, and xssmaze /hpp/level1 where the
                    // first-value reflection renders the unfiltered payload)
                    // surfaced as R-only despite being trivially V — the
                    // adaptive DOM payload generator drops HTML-tag payloads
                    // when angles are reported "invalid" at one of the
                    // reflection sites, and the prior `has_js_context_evidence`
                    // check only covered the `<script>`-block case.
                    // (`dom_evidence_kind` is computed above, before the lock,
                    // so a JS-body echo can be filtered without emitting an R.)

                    // Both arms come from the reflection phase, so the tier-derived
                    // default (`dom-verification` for V) would misattribute the
                    // upgrade — it reuses the reflection response rather than
                    // issuing the dedicated verification request.
                    let (finding_type, severity, summary, poc_msg) =
                        if let Some(kind) = dom_evidence_kind {
                            // Mark dom_found so we skip redundant DOM verification
                            {
                                let mut found = self.found_params.write().await;
                                found.dom.insert(found_param_key(param));
                            }
                            state.dom_found_locally = true;
                            let evidence_label = kind.label();
                            (
                                FindingType::Verified,
                                "High".to_string(),
                                format!(
                                    "DOM verification successful for param {} ({})",
                                    param.name, evidence_label
                                ),
                                format!(
                                    "Triggered XSS Payload ({}): {}={}",
                                    evidence_label, param.name, reflection_payload
                                ),
                            )
                        } else {
                            (
                                FindingType::Reflected,
                                "Info".to_string(),
                                format!(
                                    "Reflected XSS detected for param {} ({})",
                                    param.name, reflection_note
                                ),
                                format!(
                                    "[R] Triggered XSS Payload ({}): {}={}",
                                    reflection_note, param.name, reflection_payload
                                ),
                            )
                        };

                    // Record reflected/verified XSS finding (fallback path).
                    // In SXSS mode, prefix inject_type so downstream output
                    // (JSON, markdown, plain) makes the stored route visible.
                    // Template-shaped payloads (`{{…}}`) further refine the
                    // label to `*-CSTI` so users can tell client-side
                    // template injection apart from generic HTML reflection.
                    let (confidence, confidence_reason) = if dom_evidence_kind.is_some() {
                        (
                            crate::scanning::result::Confidence::High,
                            "payload reached an executable position in the parsed response",
                        )
                    } else {
                        (
                            crate::scanning::result::Confidence::Low,
                            "payload echoed in the response; no executable position confirmed",
                        )
                    };
                    let mut result = crate::scanning::result::Result::builder(finding_type)
                        .inject_type(inject_type_for_payload_with_sink(
                            self.args.sxss,
                            &reflection_payload,
                            param.framework_sink.as_deref(),
                        ))
                        .method(crate::scanning::url_inject::effective_method(
                            &self.target.method,
                            param,
                        ))
                        .detection_method(crate::scanning::result::FindingMethod::Reflection)
                        .confidence(confidence, confidence_reason)
                        .data(result_url)
                        .param(param.name.clone())
                        .payload(reflection_payload.clone())
                        .evidence(summary)
                        .cwe("CWE-79")
                        .severity(severity)
                        .message_id(606)
                        .message_str(poc_msg)
                        .build();
                    result.location = format!("{:?}", param.location);
                    result.request =
                        Some(build_request_text(&self.target, param, &reflection_payload));
                    // Report the observed text even when it isn't renderable:
                    // the redirect stand-in is an honest `HTTP 302 Location: …`
                    // line, which is the real evidence for that vector. Only
                    // execution-inferring consumers above are gated on
                    // `renderable`.
                    result.response = reflection_body.map(|b| {
                        crate::scanning::result::bound_evidence_body(b.text, &reflection_payload)
                    });

                    self.stream_finding(&result);
                    // Defer pushing to shared results (batched)
                    state.local_results.push(result);
                }
            }
        }
        PhaseFlow::Continue
    }

    /// === Stage 6: DOM Verification ===
    ///
    /// Inject each DOM payload and verify actual DOM evidence, recording a V
    /// (Verified) finding on the first hit (one per param). Returns `Abort`
    /// when the global limit was reached mid-loop.
    async fn run_dom_phase(
        &self,
        param: &Param,
        dom_payloads: Vec<String>,
        state: &mut ParamScanState,
    ) -> PhaseFlow {
        // Issue #1156 — recall-preserving early-exit signals. `inert_echo_count`
        // is cumulative (an echo endpoint reflects consistently, so the count
        // accrues across the whole phase); `blocked_streak` is consecutive (a
        // single response that gets through resets it, preserving WAF-bypass
        // recall). Both are disabled under `--deep-scan`.
        let mut inert_echo_count: u32 = 0;
        let mut blocked_streak: u32 = 0;

        for dom_payload in dom_payloads {
            // Check cancellation
            if self.cancelled() {
                break;
            }
            // Early stop if global limit reached
            if self.limit_reached() {
                return PhaseFlow::Abort;
            }
            // Skip DOM verification if already found for this param
            let already_dom_found = if state.dom_found_locally {
                true
            } else {
                let is_found = self
                    .found_params
                    .read()
                    .await
                    .dom
                    .contains(&found_param_key(param));
                if is_found {
                    state.dom_found_locally = true;
                }
                is_found
            };
            if already_dom_found {
                if let Some(ref pb) = self.pb {
                    pb.inc(1);
                }
                if let Some(ref opb) = self.overall_pb {
                    opb.inc(1);
                }
                continue;
            }
            let crate::scanning::check_dom_verification::DomVerifyOutcome {
                verified: dom_verified,
                response_text,
                reflected,
                status,
            } = check_dom_verification_with_client_outcome(
                self.client.as_ref(),
                &self.target,
                param,
                &dom_payload,
                &self.args,
            )
            .await;
            if dom_verified {
                let should_add = if self.args.deep_scan {
                    true
                } else {
                    let mut found = self.found_params.write().await;
                    let key = found_param_key(param);
                    if !found.dom.contains(&key) {
                        found.dom.insert(key);
                        state.dom_found_locally = true;
                        true
                    } else {
                        false
                    }
                };

                if should_add {
                    // Create result (via helper). Use the form action URL
                    // when the param came from form discovery.
                    let base =
                        crate::scanning::url_inject::effective_query_base(&self.target.url, param);
                    // PoC URL from the as-sent payload (see reflection path above)
                    // so window-pad / base64 / multi-URL findings reproduce.
                    let poc_payload =
                        crate::encoding::pre_encoding::apply_param_encoding(&dom_payload, param);
                    let result_url =
                        crate::scanning::url_inject::build_injected_url(&base, param, &poc_payload);

                    // Determine which evidence path proved exploitability
                    // so the V finding's message reflects the route.
                    let evidence_label = response_text
                        .as_deref()
                        .and_then(|body| {
                            crate::scanning::check_dom_verification::classify_dom_evidence(
                                &dom_payload,
                                body,
                            )
                        })
                        .map_or("DOM evidence", |k| k.label());

                    // DOM-verified => Vulnerability
                    let mut result =
                        crate::scanning::result::Result::builder(FindingType::Verified)
                            .confidence(
                                crate::scanning::result::Confidence::High,
                                format!(
                                    "DOM verification confirmed an executable position ({})",
                                    evidence_label
                                ),
                            )
                            .inject_type(inject_type_for_payload_with_sink(
                                self.args.sxss,
                                &dom_payload,
                                param.framework_sink.as_deref(),
                            ))
                            .method(crate::scanning::url_inject::effective_method(
                                &self.target.method,
                                param,
                            ))
                            .data(result_url)
                            .param(param.name.clone())
                            .payload(dom_payload.clone())
                            .evidence(format!(
                                "DOM verification successful for param {} ({})",
                                param.name, evidence_label
                            ))
                            .cwe("CWE-79")
                            .severity("High")
                            .message_id(606)
                            .message_str(format!(
                                "Triggered XSS Payload ({}): {}={}",
                                evidence_label, param.name, dom_payload
                            ))
                            .build();
                    result.location = format!("{:?}", param.location);
                    result.request = Some(build_request_text(&self.target, param, &dom_payload));
                    result.response = response_text
                        .map(|t| crate::scanning::result::bound_evidence_body(t, &dom_payload));

                    self.stream_finding(&result);
                    // Defer pushing to shared results (batched)
                    state.local_results.push(result);
                    break;
                }
            }

            // Issue #1156 — accumulate the recall-preserving early-exit signals
            // for this response, then stop the phase once the endpoint has shown
            // overwhelming evidence it will never verify. Only non-verifying
            // responses feed the signals: a `dom_verified` response that did not
            // `break` above (another worker recorded it first, `should_add ==
            // false`) must not be miscounted as an inert echo.
            if !dom_verified {
                inert_echo_count = next_inert_echo_count(inert_echo_count, reflected);
                blocked_streak = next_blocked_streak(blocked_streak, status, reflected);
            }
            if let Some(ref pb) = self.pb {
                pb.inc(1);
            }
            if let Some(ref opb) = self.overall_pb {
                opb.inc(1);
            }
            if dom_phase_should_early_exit(self.args.deep_scan, inert_echo_count, blocked_streak) {
                crate::dbg_log!(
                    "dom phase early-exit (param={}): inert_echo={}, blocked_streak={} — endpoint shows no path to DOM verification, skipping remaining payloads",
                    param.name,
                    inert_echo_count,
                    blocked_streak,
                );
                break;
            }
        }
        PhaseFlow::Continue
    }

    /// HPP (HTTP Parameter Pollution) phase: re-test the param with
    /// duplicate-parameter URLs. Only runs for query params under `--hpp`,
    /// uses a small subset of reflection payloads to avoid request
    /// explosion, and records at most one finding per param.
    async fn run_hpp_phase(
        &self,
        param: &Param,
        hpp_payloads: Vec<String>,
        state: &mut ParamScanState,
    ) {
        if !(self.args.hpp && param.location == crate::parameter_analysis::Location::Query) {
            return;
        }
        use crate::scanning::url_inject::{HppPosition, build_hpp_url};

        // `hpp_payloads` is already the small reflection-payload subset capped
        // by the caller (see `scan_param`), which bounds the request fan-out.
        let hpp_positions = [HppPosition::Last, HppPosition::First, HppPosition::Both];

        'hpp_outer: for hpp_payload in &hpp_payloads {
            // Cancellation is checked here *and* in the inner position loop:
            // this phase runs after the reflection/DOM phases have already
            // broken out on cancel, and without its own check a cancelled
            // `--hpp` scan kept firing up to `payloads x positions` requests
            // per parameter after the user stopped it.
            if self.limit_reached() || self.cancelled() {
                break;
            }
            for &position in &hpp_positions {
                if self.cancelled() {
                    break 'hpp_outer;
                }
                if let Some(hpp_url) = build_hpp_url(&self.target.url, param, hpp_payload, position)
                {
                    let (kind, response_text) =
                        crate::scanning::check_reflection::check_reflection_with_hpp_url(
                            self.client.as_ref(),
                            &self.target,
                            param,
                            hpp_payload,
                            &hpp_url,
                            &self.args,
                        )
                        .await;

                    if let Some(kind) = kind {
                        let pos_label = match position {
                            HppPosition::Last => "last",
                            HppPosition::First => "first",
                            HppPosition::Both => "both",
                        };
                        let reflection_note = reflection_kind_note(kind);

                        let mut result =
                            crate::scanning::result::Result::builder(FindingType::Reflected)
                                .confidence(
                                    crate::scanning::result::Confidence::Low,
                                    "duplicated-parameter echo; no executable position confirmed",
                                )
                                .inject_type("inHTML-HPP")
                                .method(self.target.method.clone())
                                .data(hpp_url.clone())
                                .param(param.name.clone())
                                .payload(hpp_payload.clone())
                                .evidence(format!(
                                    "HPP bypass: reflected XSS for param {} (position={}, {})",
                                    param.name, pos_label, reflection_note
                                ))
                                .cwe("CWE-79")
                                // Same severity as any other `R`: the
                                // duplicate-parameter echo proves the payload
                                // survives HPP handling, not that it reached an
                                // executable position. Emitting `Medium` here
                                // while a plain reflection emits `Info` made the
                                // severity of a tier depend on which phase found
                                // it (#1238).
                                .severity("Info")
                                .message_id(606)
                                .message_str(format!(
                                    "[R] HPP Bypass ({}): {}={} (position={})",
                                    reflection_note, param.name, hpp_payload, pos_label
                                ))
                                .build();
                        result.location = format!("{:?}", param.location);
                        result.response = response_text
                            .map(|t| crate::scanning::result::bound_evidence_body(t, hpp_payload));
                        self.stream_finding(&result);
                        state.local_results.push(result);
                        break 'hpp_outer; // One HPP finding per param is enough
                    }
                }
            }
        }
    }
}

/// Outcome of a `run_scanning` call. The REST server and MCP runners inspect
/// `worker_panics` so a scan that lost workers to a panic can be surfaced as a
/// partial/failed result instead of being silently reported `done` — a worker
/// panic means the param's findings are incomplete, indistinguishable from
/// "scanned, found nothing" otherwise. The CLI additionally uses
/// `limit_stopped` to decide a target's `--state-file` terminal state.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScanRunReport {
    pub worker_panics: usize,
    /// The dispatch loop stopped early because `--limit` was reached, so this
    /// target's remaining parameters were never tested. Distinguishing this
    /// from a clean finish matters for `--state-file`: a target recorded
    /// `completed` is skipped on every later run of the same command, which
    /// would make those parameters permanently unscanned.
    pub limit_stopped: bool,
}

/// The shared handles a [`run_scanning`] call needs beyond its target and args.
///
/// Grouped into a struct because the positional form took nine parameters, and
/// the interchangeable ones sat next to each other: two `Option<Arc<..>>`
/// progress bars in a row, then two *different* atomic counters
/// (`findings_count`, a running findings tally, and `params_done`, a
/// per-parameter completion counter) separated only by more `Option`s.
/// Transposing any of them compiled fine and failed silently at runtime —
/// which already happened once, when a caller stored the findings tally into
/// `params_tested` (see the note in `server/job_runner.rs`).
///
/// Deliberately **not** `Default`. The two shared handles below are required,
/// and defaulting them would be its own silent failure: a defaulted `results`
/// is a private `Vec` nobody reads (every finding discarded), and a defaulted
/// `findings_count` is a private counter nobody else writes (so `--limit`
/// never fires). Trading "transpose two arguments" for "forget a field" would
/// not have been an improvement — construct via [`ScanRunHandles::new`] and
/// add the optional front-end handles with the `with_*` methods.
#[derive(Clone)]
pub struct ScanRunHandles {
    /// Accumulates findings across every target in the run.
    pub results: Arc<Mutex<Vec<crate::scanning::result::Result>>>,
    /// Running findings tally, shared run-wide so `--limit` can stop the scan.
    pub findings_count: Arc<AtomicUsize>,
    /// CLI progress container; `None` for the REST/MCP front-ends.
    pub multi_pb: Option<Arc<MultiProgress>>,
    /// The run-wide bar this target ticks; `None` when no bar is drawn.
    pub overall_pb: Option<Arc<indicatif::ProgressBar>>,
    /// Cooperative cancellation, checked at per-parameter checkpoints.
    pub cancel: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Mid-scan finding stream; `None` disables streaming output.
    pub finding_tx: Option<tokio::sync::mpsc::UnboundedSender<crate::scanning::result::Result>>,
    /// Live "parameters finished" counter for async front-ends (REST server,
    /// MCP). Each per-parameter worker bumps it on completion so pollers see
    /// `params_tested` climb during the scan instead of staying pinned at 0
    /// until the very end. `None` for the CLI, which renders its own
    /// indicatif progress bar from `total_tasks` instead.
    pub params_done: Option<Arc<AtomicU32>>,
}

impl ScanRunHandles {
    /// The two run-wide handles every caller must share; all optional
    /// front-end handles start disabled.
    pub fn new(
        results: Arc<Mutex<Vec<crate::scanning::result::Result>>>,
        findings_count: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            results,
            findings_count,
            multi_pb: None,
            overall_pb: None,
            cancel: None,
            finding_tx: None,
            params_done: None,
        }
    }

    /// Attach the CLI's indicatif bars.
    pub fn with_progress(
        mut self,
        multi_pb: Option<Arc<MultiProgress>>,
        overall_pb: Option<Arc<indicatif::ProgressBar>>,
    ) -> Self {
        self.multi_pb = multi_pb;
        self.overall_pb = overall_pb;
        self
    }

    /// Attach the cooperative cancellation flag.
    pub fn with_cancel(mut self, cancel: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// Stream findings as they are confirmed instead of only at end-of-scan.
    pub fn with_finding_tx(
        mut self,
        tx: Option<tokio::sync::mpsc::UnboundedSender<crate::scanning::result::Result>>,
    ) -> Self {
        self.finding_tx = tx;
        self
    }

    /// Feed an async front-end's live `params_tested` counter.
    pub fn with_params_done(mut self, params_done: Arc<AtomicU32>) -> Self {
        self.params_done = Some(params_done);
        self
    }
}

pub async fn run_scanning(
    target: &Target,
    args: Arc<ScanArgs>,
    handles: ScanRunHandles,
) -> ScanRunReport {
    let ScanRunHandles {
        results,
        multi_pb,
        overall_pb,
        findings_count,
        cancel,
        finding_tx,
        params_done,
    } = handles;
    // Short-circuit scanning when skip_xss_scanning is enabled (e.g., in unit tests)
    if args.skip_xss_scanning {
        return ScanRunReport::default();
    }
    let arc_target = Arc::new(target.clone());
    let shared_client = Arc::new(arc_target.build_client_or_default());
    let semaphore = Arc::new(Semaphore::new(crate::utils::semaphore_permits(
        if args.sxss { 1 } else { target.workers },
    )));
    let limit_result_type: Arc<str> = Arc::from(args.limit_result_type.to_uppercase());

    // Reset WAF block counters for this scan
    crate::WAF_BLOCK_COUNT.store(0, Ordering::Relaxed);
    crate::WAF_CONSECUTIVE_BLOCKS.store(0, Ordering::Relaxed);

    // Compute WAF bypass strategy + pre-merge the payloads shared across all
    // parameters (CSP bypass + tech-specific).
    let waf_strategy = compute_waf_strategy(target, &args);
    let shared_payloads = build_shared_payloads(target);

    // === Stage 4: Payload Generation — build per-parameter payload sets ===
    let (param_jobs, total_tasks) =
        generate_param_jobs(target, &args, waf_strategy.as_ref(), &shared_payloads);

    let pb = build_scan_progress_bar(&multi_pb, total_tasks, target);

    let found_params = Arc::new(RwLock::new(FoundParams {
        reflection: HashSet::new(),
        dom: HashSet::new(),
    }));

    let ctx = ScanWorkerCtx {
        args: args.clone(),
        target: arc_target.clone(),
        client: shared_client.clone(),
        results: results.clone(),
        found_params: found_params.clone(),
        findings_count: findings_count.clone(),
        pb: pb.clone(),
        overall_pb: overall_pb.clone(),
        limit_result_type: limit_result_type.clone(),
        cancel: cancel.clone(),
        finding_tx: finding_tx.clone(),
        semaphore: semaphore.clone(),
        params_done: params_done.clone(),
    };

    // === Stage 5 & 6: spawn one worker per parameter (Reflection + DOM) ===
    // A `JoinSet` (not a bare `Vec<JoinHandle>`) so that if this scan future is
    // dropped mid-flight — which happens when an async front-end's `scan_timeout`
    // budget expires and `run_within_scan_budget` drops the wrapped future — the
    // in-flight workers are ABORTED on drop rather than detached. A dropped
    // `JoinHandle` does not abort its task, so the old `Vec` left timed-out
    // workers parked on the runtime; on MCP's cached current_thread runtime they
    // would resume during a later, unrelated scan and fire residual probes at
    // the stale target. The normal-completion path below still drains every
    // worker to completion, so partial/complete results and the panic tally are
    // unchanged.
    let mut handles = tokio::task::JoinSet::new();
    // Set when the `--limit` cap cuts the dispatch loop short, so the caller
    // can tell "finished this target" from "stopped part-way through it".
    let mut limit_stopped = false;
    // Capture the per-job task-local scopes (request counter, WAF backoff, rate
    // limiter) bound by the REST/MCP runners. `tokio::spawn` does NOT inherit
    // task-locals, so each worker re-enters them via `with_job_scopes`;
    // otherwise the injection-phase requests (the bulk of the scan) would bump
    // only the process-wide globals — under-counting per-job `requests_sent`
    // and leaking one scan's WAF backoff into unrelated concurrent scans. No-op
    // on the CLI, which binds no per-job scope.
    let job_scopes = crate::JobScopes::capture();
    for (param_clone, reflection_payloads, dom_payloads) in param_jobs {
        // Check cancellation before spawning next param task
        if ctx.cancelled() {
            if let Some(ref pb) = pb {
                finish_scan_bar(
                    pb,
                    console::style("⚠").yellow().to_string(),
                    format!("Cancelled scanning {}", target.url),
                );
            }
            break;
        }
        let already_found = {
            let key = found_param_key(&param_clone);
            let fp = found_params.read().await;
            fp.reflection.contains(&key) || fp.dom.contains(&key)
        };
        if already_found && !args.deep_scan {
            // Skip further testing for this param if reflection or DOM XSS
            // already found and not deep scanning. This param *was* exercised
            // (the finding came from its probe/AST pass), so count it toward
            // the live progress counter — otherwise `params_tested` would
            // permanently under-report it on a cancelled scan.
            if let Some(done) = &ctx.params_done {
                done.fetch_add(1, Ordering::Relaxed);
            }
            continue;
        }
        // Early stop if global limit reached. Use `break` (not an early
        // `return`) so the join-drain loop below awaits the already-spawned
        // workers instead of detaching them: a dropped JoinHandle does NOT
        // abort its task, so an early return left workers hitting the target
        // past the stop point, skipped `collapse_target_results` and the
        // worker-panic tally, and let late findings race the server's result
        // snapshot. The tail finishes the progress bar with "Completed scanning".
        if ctx.limit_reached() {
            limit_stopped = true;
            break;
        }

        let ctx = ctx.clone();
        // Re-enter the per-job scopes inside the spawned worker so the requests
        // it sends are tallied and rate-limited against THIS job, not the
        // process-wide globals (see `JobScopes`). Cheap no-op on the CLI.
        handles.spawn(crate::with_job_scopes(job_scopes.clone(), async move {
            ctx.scan_param(param_clone, reflection_payloads, dom_payloads)
                .await;
            // Bump the live completion counter after this parameter is fully
            // processed (covers every `scan_param` exit path, including the
            // non-reflective early return), so async front-ends observe
            // `params_tested` advancing as each worker finishes.
            if let Some(done) = &ctx.params_done {
                done.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    let mut worker_panics = 0usize;
    while let Some(res) = handles.join_next().await {
        if let Err(e) = res {
            // A JoinError from a worker is almost always a panic inside
            // scan_param (a scanning-pipeline bug). Count it so the caller can
            // mark the scan as partial/failed instead of reporting a clean
            // `done`; the param's findings are incomplete either way. (Aborts
            // are not counted: they only occur when the whole scan future is
            // being dropped on scan_timeout, which the caller already records.)
            if e.is_panic() {
                worker_panics += 1;
            }
            // Sanitized for the same reason as the sibling sites: the panic
            // message can embed response bytes.
            eprintln!(
                "[!] scanning task failed: {}",
                crate::utils::log::sanitize_log_message(&e.to_string())
            );
        }
    }

    log_waf_block_stats(target);

    // Collapse this target's R findings that are already proven by one of
    // its own V findings on the same (param, location, inject_type), scoped
    // to the current target so other targets' findings are never affected.
    collapse_target_results(&results, &findings_count, &limit_result_type, target).await;

    if let Some(pb) = pb {
        finish_scan_bar(
            &pb,
            console::style("✓").green().to_string(),
            format!("Completed scanning {}", target.url),
        );
    }

    ScanRunReport {
        worker_panics,
        limit_stopped,
    }
}

/// Drop Reflected findings on the *current target* that are already covered
/// by a Verified finding on the same `(param, location, inject_type)` for
/// that same target. Verified and AST findings are preserved.
///
/// Scope is critical: this runs at the end of each target's scan against
/// the shared cross-target results vector. Without scoping, a V finding on
/// one target would silently drop every later R finding on different
/// targets that share the same reflection shape (param + inject_type) —
/// which on benchmarks like xssmaze is the common case.
///
/// `location` is part of the key for the same reason it is part of
/// [`found_param_key`]: a `q` in the query string and a `q` in the request
/// body are different injection points, so proving one exploitable says
/// nothing about the other and must not delete the other's evidence.
fn collapse_redundant_reflected(
    results: Vec<crate::scanning::result::Result>,
    target_url: &str,
) -> Vec<crate::scanning::result::Result> {
    use std::collections::HashSet;
    let belongs = |data: &str| crate::utils::finding_belongs_to_target(target_url, data);
    let key = |r: &crate::scanning::result::Result| {
        (r.param.clone(), r.location.clone(), r.inject_type.clone())
    };
    let verified_keys: HashSet<(String, String, String)> = results
        .iter()
        .filter(|r| r.result_type == FindingType::Verified && belongs(&r.data))
        .map(key)
        .collect();
    if verified_keys.is_empty() {
        return results;
    }
    results
        .into_iter()
        .filter(|r| {
            !(r.result_type == FindingType::Reflected
                && belongs(&r.data)
                && verified_keys.contains(&key(r)))
        })
        .collect()
}

pub(crate) use xss_blind::{
    CallbackSource, blind_scan_forms_with, blind_scanning, blind_scanning_with,
};

#[cfg(test)]
mod tests;
