//! `notifications/progress` for the two tools that block on real work.
//!
//! MCP lets a client attach a `progressToken` to any request's `_meta`; the
//! server may then stream `notifications/progress` against that token while the
//! request is still in flight. dalfox has exactly the shape that utility exists
//! for — `scan_with_dalfox` with `wait=true` holds the call open for up to
//! `wait_timeout_sec` (300s by default), and `preflight_dalfox` blocks for the
//! whole discovery + mining pass — and it published nothing at all. A host
//! showed a spinner with no text, and an agent had no way to tell a scan that
//! was working from one that was wedged short of cancelling it.
//!
//! **The value is `requests_sent`, not a percentage.** The spec requires the
//! progress number to *increase* on every notification, and the obvious
//! candidates do not: `params_tested` sits at zero for the whole discovery and
//! mining phase (often the longest part of a scan), and a percentage derived
//! from it sits at zero with it — so the second notification would repeat the
//! first's value. Outbound requests are the one counter that moves in every
//! phase and never goes backwards. `total` is therefore left unset: the number
//! of requests a scan will send is not known until it has sent them, and the
//! spec's own guidance is to omit an unknown total rather than invent one. The
//! human-readable detail — phase, parameters tested, findings so far — rides in
//! `message`, which is what a client actually renders next to an
//! indeterminate bar.
//!
//! **A stalled counter still gets a heartbeat.** Dropping a tick whose counter
//! had not moved would have made this feature silent in precisely the case it
//! exists for: every worker blocked on a tarpit target bumps `requests_sent`
//! *before* the send, so it can sit still for a whole `timeout` window while
//! the scan is at its least obviously alive. It would also have swallowed the
//! phase transitions — "discovering parameters" to "testing 3/12" — which are
//! the informative half of a notification. So every poll publishes, and
//! [`MonotonicGate`] nudges a value that did not beat the last one by a hair.
//! `progress` is a JSON number, not an integer, so the nudge keeps the spec's
//! increase rule without lying about the count: it stays the request total to
//! three decimal places.
//!
//! **The sink is asked for, not passed in.** It rides the per-call scope that
//! `DalfoxMcp::call_tool` binds (see [`super::call_scope`]), so a handler
//! called directly — every unit test, and every tool that does not report —
//! takes a `try_with` miss and nothing else.

use std::sync::atomic::{AtomicU64, Ordering};

use rmcp::model::{ProgressNotificationParam, ProgressToken};
use rmcp::{Peer, RoleServer};

use super::call_scope;

/// Enforces the spec's "the progress value MUST increase with each
/// notification" rule for one token.
///
/// The counters here are sampled on a timer, so a tick that lands between two
/// requests finds the same number as the last one — and a scan stuck on a
/// tarpit target produces a long run of those. Repeating the value is not
/// allowed and dropping the tick would make the feature silent exactly when it
/// is needed, so the value is nudged instead: the next notification goes out at
/// one [`STALL_NUDGE`] above the last. Separated from the sink so the rule is
/// testable without a live peer to send through.
#[derive(Default)]
pub(super) struct MonotonicGate {
    /// Last `progress` published on this token, as `f64` bits — `f64` has no
    /// atomic of its own, and the value has to be read-modify-written by
    /// whichever reporter gets there first.
    last_sent: AtomicU64,
    /// Set once something has been published, so the opening tick goes out at
    /// its true value even when that is `0`.
    started: std::sync::atomic::AtomicBool,
}

/// How far a stalled counter is nudged so the published value still rises.
/// Small enough that `progress` remains the request count to three decimals.
const STALL_NUDGE: f64 = 0.001;

impl MonotonicGate {
    /// The value to publish for `progress`: itself when it beats the last one,
    /// otherwise the smallest number that does.
    pub(super) fn next_value(&self, progress: u64) -> f64 {
        let mut current = self.last_sent.load(Ordering::Relaxed);
        loop {
            let previous = f64::from_bits(current);
            let first = !self.started.load(Ordering::Relaxed);
            let candidate = if first || progress as f64 > previous {
                progress as f64
            } else {
                previous + STALL_NUDGE
            };
            // CAS rather than a plain store: two reporters racing must not
            // both publish the same nudged value.
            match self.last_sent.compare_exchange_weak(
                current,
                candidate.to_bits(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.started.store(true, Ordering::Relaxed);
                    return candidate;
                }
                Err(observed) => current = observed,
            }
        }
    }
}

/// Where a reporting tool sends its progress, plus the last value it sent.
pub(super) struct ProgressSink {
    peer: Peer<RoleServer>,
    token: ProgressToken,
    gate: MonotonicGate,
}

impl ProgressSink {
    pub(super) fn new(peer: Peer<RoleServer>, token: ProgressToken) -> Self {
        Self {
            peer,
            token,
            gate: MonotonicGate::default(),
        }
    }
}

/// Publish one progress notification, if this call carries a token.
///
/// Errors are swallowed on purpose: a client that has gone away, or a transport
/// that has closed, must not turn into a failed scan — the tool's own result is
/// the contract, and progress is an optional courtesy on top of it.
pub(super) async fn report(progress: u64, message: impl Into<String>) {
    let Some(sink) = call_scope::progress_sink() else {
        return;
    };
    let value = sink.gate.next_value(progress);
    let mut param = ProgressNotificationParam::new(sink.token.clone(), value);
    param.message = Some(message.into());
    if let Err(e) = sink.peer.notify_progress(param).await {
        // A client that has gone away, or a transport already closing, is not
        // a failed scan. The tool's own result is the contract.
        crate::dbg_log!("mcp: progress notification dropped: {e}");
    }
}

/// True when the current tool call asked for progress. Lets a caller skip
/// building a status line nobody will read.
pub(super) fn wanted() -> bool {
    call_scope::progress_sink().is_some()
}

/// Publish one tick for a scan, derived from the body
/// `results_json_for_scan` just built.
///
/// No notification is sent for the terminal state: the tool's own result is
/// the completion signal.
pub(super) async fn report_scan_status(body: &serde_json::Value) {
    if !wanted() {
        return;
    }
    if let Some((progress, message)) = scan_status_line(body) {
        report(progress, message).await;
    }
}

/// The `(progress, message)` pair describing a scan mid-flight, or `None` once
/// it is terminal.
pub(super) fn scan_status_line(body: &serde_json::Value) -> Option<(u64, String)> {
    let status = body.get("status").and_then(|v| v.as_str()).unwrap_or("");
    if matches!(status, "done" | "error" | "cancelled") {
        return None;
    }
    let counter = |key: &str| -> u64 {
        body.get("progress")
            .and_then(|p| p.get(key))
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    };
    let sent = counter("requests_sent");
    let failed = counter("requests_failed");
    let tested = counter("params_tested");
    let total = counter("params_total");
    let findings = counter("findings_so_far");

    // `params_total` is only published once discovery and mining have settled
    // on the parameter set, so its absence is itself the phase indicator.
    let requests = |n: u64| format!("{n} request{}", if n == 1 { "" } else { "s" });
    let mut message = if status == "queued" {
        "queued".to_string()
    } else if total == 0 {
        format!("discovering parameters — {} sent", requests(sent))
    } else {
        format!(
            "testing {tested}/{total} parameters — {} sent",
            requests(sent)
        )
    };
    if findings > 0 {
        message.push_str(&format!(", {findings} findings so far"));
    }
    if failed > 0 {
        // The counter that decides whether "no findings" means anything.
        message.push_str(&format!(", {} never reached the target", requests(failed)));
    }
    Some((sent, message))
}

/// Await `fut`, publishing a heartbeat every couple of seconds while it runs.
///
/// For work that exposes no counter of its own — preflight runs discovery and
/// mining behind one blocking call — the only honest thing to report is that
/// the server is still on it. The tick number is the progress value, which
/// satisfies the spec's increase rule; the elapsed seconds ride in the message.
pub(super) async fn tick_while<F: std::future::Future>(label: &str, fut: F) -> F::Output {
    if !wanted() {
        return fut.await;
    }
    const HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(2);
    let started = std::time::Instant::now();
    let mut ticks: u64 = 0;
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    // `interval` fires immediately on its first tick; spend it here so the
    // first heartbeat lands one period in rather than at once.
    heartbeat.tick().await;
    let mut fut = std::pin::pin!(fut);
    loop {
        tokio::select! {
            // Bias toward the work: when both are ready the result wins, so a
            // future that completes on the same poll as a tick does not pay
            // for a notification nobody will see.
            biased;
            out = &mut fut => return out,
            _ = heartbeat.tick() => {
                ticks += 1;
                report(
                    ticks,
                    format!("{label} ({}s elapsed)", started.elapsed().as_secs()),
                )
                .await;
            }
        }
    }
}
