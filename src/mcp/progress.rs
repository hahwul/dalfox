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
//! **The sink is a task-local, not an argument.** rmcp can inject
//! `RequestContext` straight into a `#[tool]` handler, but every one of those
//! handlers is also called directly by the unit tests, so threading it through
//! would have rewritten ~40 call sites to say "no progress here". Binding it
//! around the router call in `DalfoxMcp::call_tool` instead means an unbound
//! caller — every test, and every tool that does not report — takes a
//! `try_with` miss and nothing else, the same no-op shape
//! [`crate::rate_limit_acquire`] already uses for the per-job rate limiter.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rmcp::model::{ProgressNotificationParam, ProgressToken};
use rmcp::service::RequestContext;
use rmcp::{Peer, RoleServer};

/// Enforces the spec's "the progress value MUST increase with each
/// notification" rule for one token.
///
/// The counters here are sampled on a timer, so a tick that lands between two
/// requests finds the same number as the last one — and a scan waiting on a
/// slow target produces a long run of those. They are dropped rather than
/// repeated. Separated from the sink so the rule is testable without a live
/// peer to send through.
#[derive(Default)]
pub(super) struct MonotonicGate {
    /// Highest `progress` already published on this token.
    last_sent: AtomicU64,
    /// Set once something has been published, so the opening tick is allowed
    /// through at `0` while later repeats of `0` are not.
    started: std::sync::atomic::AtomicBool,
}

impl MonotonicGate {
    /// Claim `progress` as the next value to publish, or refuse it.
    pub(super) fn admits(&self, progress: u64) -> bool {
        // `fetch_max` both records the new high-water mark and reveals the old
        // one, in one atomic — two concurrent reporters cannot both decide
        // they are the increase.
        let previous = self.last_sent.fetch_max(progress, Ordering::Relaxed);
        let first = !self.started.swap(true, Ordering::Relaxed);
        first || progress > previous
    }
}

/// Where a reporting tool sends its progress, plus the last value it sent.
pub(super) struct ProgressSink {
    peer: Peer<RoleServer>,
    token: ProgressToken,
    gate: MonotonicGate,
}

tokio::task_local! {
    /// Bound for the duration of one `tools/call` that carried a progress
    /// token. Absent everywhere else, which is what makes [`report`] free.
    static PROGRESS: Arc<ProgressSink>;
}

/// Run `fut` with a progress sink bound, when the request asked for one.
///
/// A request without `_meta.progressToken` — the common case, and every unit
/// test — gets the future back unchanged, so nothing is allocated and nothing
/// is sent.
pub(super) async fn with_progress<F: std::future::Future>(
    context: &RequestContext<RoleServer>,
    fut: F,
) -> F::Output {
    let Some(token) = context.meta.get_progress_token() else {
        return fut.await;
    };
    let sink = Arc::new(ProgressSink {
        peer: context.peer.clone(),
        token,
        gate: MonotonicGate::default(),
    });
    PROGRESS.scope(sink, fut).await
}

/// Publish one progress notification, if this call carries a token and the
/// value has actually moved.
///
/// Errors are swallowed on purpose: a client that has gone away, or a transport
/// that has closed, must not turn into a failed scan — the tool's own result is
/// the contract, and progress is an optional courtesy on top of it.
pub(super) async fn report(progress: u64, message: impl Into<String>) {
    let Ok(sink) = PROGRESS.try_with(Arc::clone) else {
        return;
    };
    if !sink.gate.admits(progress) {
        return;
    }
    let mut param = ProgressNotificationParam::new(sink.token.clone(), progress as f64);
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
    PROGRESS.try_with(|_| ()).is_ok()
}

/// Publish one tick for a scan, derived from the body
/// `results_json_for_scan` just built.
///
/// No notification is sent for the terminal state: the tool's own result is
/// the completion signal, and repeating the final counters would either
/// duplicate the last value (which the spec forbids) or inflate it.
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
