//! What a handler knows about the `tools/call` it is running inside.
//!
//! rmcp can inject `RequestContext` straight into a `#[tool]` handler, but
//! every handler here is also called directly by the unit tests, so taking it
//! as an argument would have rewritten ~40 call sites to say "no client here".
//! Instead `DalfoxMcp::call_tool` binds this scope around the dispatch, and a
//! handler that wants any of it asks. Nothing is bound when a handler is called
//! directly, which is exactly the shape [`crate::rate_limit_acquire`] already
//! uses for the per-job rate limiter: a `try_with` miss and a sane default.
//!
//! Three things live here because all three are properties of *this call*, and
//! keeping them in one scope means one binding site rather than three nested
//! ones:
//!
//! - the progress sink, when the client attached a `progressToken`;
//! - whether the client's protocol revision can parse a `resource_link`;
//! - the request's cancellation token, so a `wait=true` scan can stop when the
//!   client says it no longer wants the answer.

use std::sync::Arc;

use rmcp::RoleServer;
use rmcp::service::RequestContext;

use super::progress::ProgressSink;

/// First protocol revision that defines the `resource_link` content block.
const RESOURCE_LINK_SINCE: &str = "2025-06-18";

pub(super) struct CallScope {
    progress: Option<Arc<ProgressSink>>,
    links_supported: bool,
    /// Kept whole rather than pulling out its `ct`: the cancellation token is
    /// `tokio_util::sync::CancellationToken`, which rmcp owns and does not
    /// re-export, and holding the context costs one clone per call instead of
    /// a direct dependency taken to name a field.
    request: RequestContext<RoleServer>,
}

tokio::task_local! {
    /// Bound for the duration of one `tools/call`; absent everywhere else.
    static CALL: Arc<CallScope>;
}

/// Run `fut` with this request's call scope bound.
pub(super) async fn bind<F: std::future::Future>(
    context: &RequestContext<RoleServer>,
    fut: F,
) -> F::Output {
    // A tool result's content array is a *closed union* on the client side:
    // the TypeScript and Python SDKs validate every block against the revision
    // they speak, and a block type they do not know fails the whole result —
    // not just that block. `resource_link` arrived in 2025-06-18 and rmcp still
    // serves clients that negotiated 2024-11-05, so the link is attached only
    // where it can be read. ISO `YYYY-MM-DD` revisions compare lexically the
    // same as chronologically, which is how rmcp itself gates on them.
    let links_supported = context
        .protocol_version()
        .is_none_or(|v| v.as_str() >= RESOURCE_LINK_SINCE);
    let scope = Arc::new(CallScope {
        progress: context
            .meta
            .get_progress_token()
            .map(|token| Arc::new(ProgressSink::new(context.peer.clone(), token))),
        links_supported,
        request: context.clone(),
    });
    CALL.scope(scope, fut).await
}

/// The progress sink for this call, if the client asked for progress.
pub(super) fn progress_sink() -> Option<Arc<ProgressSink>> {
    CALL.try_with(|scope| scope.progress.clone()).ok().flatten()
}

/// Whether to attach a `resource_link` to the result being built. An unbound
/// caller — the unit tests — gets the link.
pub(super) fn links_supported() -> bool {
    CALL.try_with(|scope| scope.links_supported).unwrap_or(true)
}

/// Resolves when the client cancels this request.
///
/// rmcp does not drop a cancelled handler's future; it cancels the request's
/// token and discards whatever the handler eventually returns. So the token is
/// the only way to notice, and noticing matters: a `wait=true` scan that nobody
/// is waiting for any more would otherwise keep sending attack traffic at a
/// third-party host for as long as its budget allows.
///
/// Pends forever when nothing is bound, so a `select!` on it is a no-op outside
/// a real call.
pub(super) async fn cancelled() {
    let Ok(ct) = CALL.try_with(|scope| scope.request.ct.clone()) else {
        std::future::pending::<()>().await;
        return;
    };
    ct.cancelled().await;
}
