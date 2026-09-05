//! MCP job-runtime helpers: current-thread runtime bridge, sync error
//! marking, and job -> JSON snapshotting.

use super::*;

/// Run `f` on a current_thread runtime and return its result. The closure
/// receives a borrow of the runtime so callers can issue `block_on`. Returns
/// `None` if runtime construction fails — extremely rare; `tag` is logged to
/// identify the call site.
///
/// The runtime is a plain local, built and dropped inside the caller's
/// `spawn_blocking` closure, and it has to stay that way. Caching it in a
/// `thread_local!` — which this did, to save the ~ms of `Builder::build()` on
/// the second scan scheduled onto the same blocking-pool slot — deadlocks the
/// whole process on Windows. Windows runs TLS destructors from
/// `ntdll!LdrShutdownThread`, with the loader lock held; dropping a runtime
/// there joins that runtime's own blocking threads (hyper resolves DNS on
/// `spawn_blocking`, so they exist), and those threads cannot finish exiting
/// without the same lock. Every thread that tries to exit afterwards parks in
/// `LdrpDrainWorkQueue` and the process wedges — `cargo test` on the Windows
/// CI leg stopped dead after 501 of 2308 tests and burned the 6-hour job limit.
/// The REST server's `spawn_scan_task` has always built the runtime as a local;
/// this matches it.
pub(super) fn run_on_scan_runtime<F, R>(tag: &str, f: F) -> Option<R>
where
    F: FnOnce(&tokio::runtime::Runtime) -> R,
{
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => Some(f(&rt)),
        Err(e) => {
            DalfoxMcp::log(
                "ERR",
                &format!("runtime build failed for tag={}: {}", tag, e),
            );
            None
        }
    }
}

/// Transition a non-terminal job into `Error` with the supplied message.
/// Safe to call after panic or runtime-build failure: gated on
/// `!is_terminal()` so it won't clobber a real outcome, and recovers from
/// mutex poisoning by taking the inner guard rather than re-panicking.
pub(super) fn mark_job_error_sync(
    jobs: &Arc<StdMutex<HashMap<String, Job>>>,
    job_id: &str,
    msg: String,
) {
    let mut guard = match jobs.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(job) = guard.get_mut(job_id)
        && !job.is_terminal()
    {
        job.status = JobStatus::Error;
        job.error_message = Some(msg);
        if job.finished_at_ms.is_none() {
            job.finished_at_ms = Some(now_ms());
        }
    }
}

/// Cheap view of a `Job` containing only what a tool response needs. Built
/// while holding the jobs lock so the lock can be released before any
/// JSON serialization or computation runs.
pub(super) struct JobSnapshot {
    pub(super) status: JobStatus,
    pub(super) target_url: String,
    pub(super) results: Option<Arc<Vec<SanitizedResult>>>,
    pub(super) progress: crate::job::JobProgress,
    pub(super) error_message: Option<String>,
    pub(super) queued_at_ms: i64,
    pub(super) started_at_ms: Option<i64>,
    pub(super) finished_at_ms: Option<i64>,
}

/// Render timestamp/duration fields into the given JSON object.
pub(super) fn write_timestamps(job: &Job, out: &mut serde_json::Map<String, serde_json::Value>) {
    out.insert("queued_at_ms".into(), serde_json::json!(job.queued_at_ms));
    out.insert("started_at_ms".into(), serde_json::json!(job.started_at_ms));
    out.insert(
        "finished_at_ms".into(),
        serde_json::json!(job.finished_at_ms),
    );
    out.insert("duration_ms".into(), serde_json::json!(job.duration_ms()));
}
