//! Shared job-lifecycle domain for the REST server and MCP runtime.
//!
//! Both interfaces track asynchronous scans in an in-memory `HashMap<String, Job>`
//! with identical requirements: status transitions, progress counters, retention
//! TTL, reachability probing that respects the scan's HTTP config, and bounds
//! validation on scan options. This module owns those pieces so the two
//! interfaces stay in lockstep. It lives at the crate root (rather than under
//! `cmd`) because it is a subsystem shared by `server` and `mcp`, not a command.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};

use serde::{Deserialize, Serialize};

use crate::scanning::result::SanitizedResult;
use crate::target_parser::Target;

pub(crate) mod runner;
pub(crate) mod spec;

/// Status of an asynchronous scan job (used by both REST server and MCP).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum JobStatus {
    Queued,
    Running,
    Done,
    Error,
    Cancelled,
}

impl fmt::Display for JobStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queued => write!(f, "queued"),
            Self::Running => write!(f, "running"),
            Self::Done => write!(f, "done"),
            Self::Error => write!(f, "error"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// How long terminal jobs (done/error/cancelled) are retained in memory before
/// being auto-purged. Prevents unbounded growth in long-running processes.
pub(crate) const JOB_RETENTION_SECS: i64 = 3600;

/// Maximum HTTP request timeout accepted via scan options (inclusive).
pub(crate) const MAX_TIMEOUT_SECS: u64 = 299;
/// Maximum delay-between-requests accepted via scan options (inclusive).
pub(crate) const MAX_DELAY_MS: u64 = 9999;
/// Maximum worker count accepted via scan options (inclusive).
pub(crate) const MAX_WORKERS: usize = 500;
/// Maximum whole-scan wall-clock budget accepted via scan options (inclusive,
/// 24h). `0` always means "no budget" (unbounded). The ceiling only exists to
/// reject obvious typos; a real long-running deep scan can still set hours.
pub(crate) const MAX_SCAN_TIMEOUT_SECS: u64 = 86_400;

/// Cap on the number of distinct parameters a single async (server/MCP) scan
/// will test. `analyze_parameters` can discover/mine a very large parameter set
/// on a hostile or sprawling target, and scanning fans out O(params × payloads)
/// worker tasks — so an uncapped count amplifies CPU / memory / outbound load
/// from one submission. Beyond this the candidate set is truncated with a log.
pub(crate) const MAX_DISCOVERED_PARAMS: usize = 512;

/// Upper bound for the per-parameter payload cap accepted via scan options.
/// `0` means "no explicit cap" (the built-in payload safety cap still applies).
/// Purely a typo guard — a real scan never needs six figures of payloads per
/// parameter. Shared by the REST server and MCP so the bound is identical.
pub(crate) const MAX_PAYLOADS_PER_PARAM: usize = 100_000;

/// Default ceiling on concurrently active (queued + running) scans for the MCP
/// runtime, which — unlike the REST server's `--max-concurrent-scans` — has no
/// config surface. Submissions past this are rejected so an agent loop can't
/// grow the job map / blocking pool without bound.
pub(crate) const MAX_ACTIVE_SCANS_MCP: usize = 100;

/// Ceiling on retained *finished* scans for the MCP runtime, mirroring the REST
/// server's `--max-retained-scans` (which MCP has no config surface for).
pub(crate) const MAX_RETAINED_SCANS_MCP: usize = 1000;

/// Resolve the effective per-scan request-rate limit (requests/second) from a
/// per-request value and an optional server-side cap.
///
/// - `0` means "no limit" (unlimited), matching the CLI's `--rate-limit 0`.
/// - When the server sets a cap (`Some(c)` with `c > 0`) it is an *upper bound*
///   on outbound RPS: a request may ask for a lower rate but cannot raise it
///   past the cap or disable it (a requested `0` is clamped down to the cap).
///   This lets an operator bound the load every submitted scan can put on a
///   target, regardless of what an (authenticated) client requests.
pub(crate) fn effective_rate_limit(requested: Option<u32>, server_cap: Option<u32>) -> u32 {
    match (requested, server_cap.filter(|c| *c > 0)) {
        (Some(r), Some(cap)) => {
            if r == 0 {
                cap
            } else {
                r.min(cap)
            }
        }
        (Some(r), None) => r,
        (None, Some(cap)) => cap,
        (None, None) => 0,
    }
}

/// Validate a caller-supplied payload-encoder list against the canonical set
/// the CLI's `--encoders` accepts.
///
/// The CLI enforces this with clap's `PossibleValuesParser` and the config-file
/// path re-checks it in `ScanConfig::normalize_and_validate` — but the REST and
/// MCP request bodies bypass both, so an unknown name (`"urlencode"`,
/// `"double-url"`, a typo) used to flow straight into `ScanArgs::encoders`,
/// where the payload builder simply matches nothing for it. The scan then ran
/// with silently reduced payload coverage and reported "done, 0 findings",
/// which a caller cannot tell apart from a genuinely clean target.
pub(crate) fn validate_encoders(encoders: &[String]) -> Result<(), String> {
    for e in encoders {
        if !crate::cmd::scan::ENCODER_VALUES.contains(&e.as_str()) {
            return Err(format!(
                "unknown encoder '{}' (expected one of: {})",
                e,
                crate::cmd::scan::ENCODER_VALUES.join(", ")
            ));
        }
    }
    Ok(())
}

/// Validate a list of `Name: value` header strings, rejecting anything reqwest
/// cannot put on the wire.
///
/// Shared by the REST server and MCP so the two front ends agree. Catching this
/// at the boundary matters because reqwest fails on the *builder*, for every
/// request in the job: the reachability probe then fails and the scan settles
/// `unreachable` / `CONNECTION_FAILED`, blaming a perfectly live target for
/// what is really malformed input. Note obs-text is legal in a value, so
/// `X-Note: café` passes.
pub(crate) fn validate_header_list(headers: &[String]) -> Result<(), String> {
    for h in headers {
        let Some((name, value)) = h.split_once(':') else {
            return Err(format!(
                "header must be in 'Name: value' form (got '{}')",
                crate::utils::log::sanitize_log_message(h)
            ));
        };
        if reqwest::header::HeaderName::try_from(name.trim()).is_err() {
            return Err(format!(
                "invalid header name '{}'",
                crate::utils::log::sanitize_log_message(name.trim())
            ));
        }
        if reqwest::header::HeaderValue::try_from(value.trim()).is_err() {
            return Err(format!(
                "invalid header value for '{}'",
                crate::utils::log::sanitize_log_message(name.trim())
            ));
        }
    }
    Ok(())
}

/// Reject a `User-Agent` or cookie value reqwest cannot put on the wire.
///
/// Same rationale as [`validate_header_list`]: both a supplied `user_agent`
/// (pushed on as a `User-Agent` header by `hydrate_target` / the reachability
/// probe) and each cookie value (composed into the `Cookie` header) become
/// header values, and a control byte in one fails reqwest on the *builder* for
/// every request in the job — so the reachability probe fails and the scan
/// settles `unreachable` / `CONNECTION_FAILED`, blaming a live target for what
/// is really malformed input. Validating here turns that into a precise 400 at
/// submission. `HeaderValue::try_from(&str)` is exactly what reqwest's
/// `.header()` applies, so obs-text stays legal (a UTF-8 UA passes).
pub(crate) fn validate_header_value(field: &str, value: &str) -> Result<(), String> {
    if reqwest::header::HeaderValue::try_from(value).is_err() {
        return Err(format!(
            "invalid {} value '{}'",
            field,
            crate::utils::log::sanitize_log_message(value)
        ));
    }
    Ok(())
}

/// Validate and normalize a caller-supplied proxy URL, rejecting anything
/// reqwest cannot actually route through (unparseable, or a scheme like
/// `ftp://` / `socks6://` that `Proxy::all` accepts then silently drops).
/// Returns the value to store: `None` when the field was empty (which already
/// meant "no proxy"), else the trimmed URL.
///
/// This matters more than a normal input check because the failure is silent
/// and inverts the caller's intent: `Target::build_client` resolves the proxy
/// with `reqwest::Proxy::all(..).ok()` and falls back to *no proxy* when that
/// fails. A submitted scan whose `proxy` was a typo therefore connected
/// **directly** to the target — bypassing the intercept proxy / SOCKS tunnel
/// the caller asked for, sending traffic down a path they did not intend — and
/// still settled `done`, reporting a perfectly successful scan.
///
/// Returning the normalized string rather than just `Ok(())` is load-bearing:
/// the caller stores what `build_client` will later resolve, and the two must
/// be the same bytes. `str::trim` strips all Unicode whitespace while
/// `url::Url` strips only ASCII, so validating the trimmed form and storing the
/// raw one would let `"\u{a0}http://127.0.0.1:8080"` — an ordinary
/// copy-paste artifact — pass the check and still resolve away to no proxy,
/// reopening the exact hole this function exists to close.
///
/// An empty value is normalized to `None` rather than refused: it carries no
/// silent-bypass risk (nothing was asked for, nothing is skipped), and query
/// strings are routinely templated with empty optional parameters
/// (`?proxy=&callback_url=`), which used to scan fine.
///
/// Shared by the REST server and MCP so both front ends treat it identically.
pub(crate) fn normalize_proxy(proxy: &str) -> Result<Option<String>, String> {
    let trimmed = proxy.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    // Same scheme + `Proxy::all` gate the CLI uses. `reqwest::Proxy::all`
    // accepts any URL-with-host, including `ftp://` / `socks6://`, which
    // hyper-util then silently drops — the scan would go DIRECT. Empty was
    // already handled above: on REST/MCP it means "no proxy", which is the
    // opposite of the CLI (`--proxy ""` is an operator mistake).
    crate::cmd::scan::check_routable_proxy(trimmed, "proxy")?;
    Ok(Some(trimmed.to_string()))
}

/// Validate and normalize a caller-supplied blind-XSS callback URL, rejecting
/// anything that can never receive a callback. Returns the value to store:
/// `None` when the field was empty, else the trimmed URL.
///
/// This is not cosmetic, because arming the channel is what *sends* the
/// payloads. `job::runner::execute_scan` starts blind injection on
/// `blind_callback_url.is_some()` alone, and blind payloads are **stored**
/// attack payloads: `"'><script src={}></script>` is written into every query,
/// body, header and cookie parameter of the target and persists there. With an
/// empty or scheme-less value the template renders as `<script src=>` — traffic
/// that permanently modifies the target and cannot possibly call back, on a job
/// that still settles `done`. Same silent-uselessness class already closed for
/// [`normalize_proxy`] and the REST `callback_url`.
///
/// Normalizing (trim) rather than only checking is load-bearing for the same
/// reason as `normalize_proxy`: the stored string is what gets interpolated
/// into the payload, so validating a trimmed form and storing the raw one would
/// still emit `<script src= https://cb/ >`.
///
/// An empty value is accepted as `None` rather than refused: it already meant
/// "no blind XSS", and query strings are routinely templated with empty
/// optional parameters (`?proxy=&blind=`).
///
/// Shared by the REST server and MCP so both front ends treat it identically.
/// `field` names the offending field in the message, because the two surfaces
/// spell it differently — REST's query parameter is `blind`, MCP's tool
/// argument is `blind_callback_url` — the same way `check_routable_proxy` and
/// `validate_header_value` take theirs.
pub(crate) fn normalize_blind_callback(value: &str, field: &str) -> Result<Option<String>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    // Parsed, not prefix-tested. `has_http_scheme` only looks at the first
    // seven bytes, so a hostless `http://` (or `https://a b`) would pass and
    // render as `<script src=http://>`: the stored payloads still land in every
    // parameter of the target and the callback still cannot fire, which is
    // precisely what this function exists to refuse. `url::Url` rejects a
    // special scheme with no host (`EmptyHost`) and an invalid host character,
    // the same parse `cmd::scan::validation::validate_http_url` uses for
    // `--sxss-url` / `--session-check-url`.
    let parsed = url::Url::parse(trimmed).map_err(|_| {
        format!(
            "{field} is not a valid absolute http:// or https:// URL (got '{}')",
            crate::utils::log::sanitize_log_message(trimmed)
        )
    })?;
    // Belt-and-suspenders on top of the parse. `Url::parse` already rejects a
    // hostless special scheme (`http://` → `EmptyHost`), so this cannot fire
    // for the schemes accepted below — but `has_host()` alone would not say
    // that, since a special scheme always reports *a* host, and the check costs
    // nothing next to the payloads a false accept would leave in the target.
    let has_real_host = parsed.host_str().is_some_and(|h| !h.is_empty());
    if !matches!(parsed.scheme(), "http" | "https") || !has_real_host {
        return Err(format!(
            "{field} must be an absolute http:// or https:// URL with a host (got '{}')",
            crate::utils::log::sanitize_log_message(trimmed)
        ));
    }
    Ok(Some(trimmed.to_string()))
}

/// Reject a remote payload/wordlist provider name that is not in the registry.
///
/// Same rationale as [`validate_encoders`]: an unrecognized name is a silent
/// no-op inside `init_remote_*`, which caches an empty list for that provider
/// set and returns `Ok`. The scan then runs with the built-in catalog only —
/// missing exactly the payloads or wordlist the caller asked for — and still
/// reports `done` with whatever it found, which a caller cannot tell apart from
/// a genuinely clean target. The CLI already warns about this at startup
/// (`cmd::scan::startup::init_remote_providers`); REST and MCP bypass that path
/// entirely, so they check here instead and fail the submission outright.
///
/// The known set is read from the live registry (not a literal) so a provider
/// added via `register_payload_provider` / `register_wordlist_provider` is
/// accepted, and so the error can list what is actually available.
pub(crate) fn validate_remote_providers(
    payloads: &[String],
    wordlists: &[String],
) -> Result<(), String> {
    // `known` is a closure, not a `Vec`: naming no providers is the common case
    // by far, and each registry lookup seeds the defaults, takes a global lock
    // and clones its key set. Nothing should pay for that on every submission.
    fn check(
        field: &str,
        requested: &[String],
        known: impl FnOnce() -> Vec<String>,
    ) -> Result<(), String> {
        if requested.is_empty() {
            return Ok(());
        }
        let mut known = known();
        // Registry iteration order is a HashMap's; sort before the set is built
        // so the error message lists providers in a stable order.
        known.sort();
        // Registry keys are already lowercased on insert, which is the same
        // normalization `collect_*_provider_urls` applies on lookup.
        let set: std::collections::HashSet<&str> = known.iter().map(String::as_str).collect();
        for p in requested {
            if !set.contains(p.to_ascii_lowercase().as_str()) {
                return Err(format!(
                    "unknown {} provider '{}' (expected one of: {})",
                    field,
                    crate::utils::log::sanitize_log_message(p),
                    known.join(", ")
                ));
            }
        }
        Ok(())
    }

    check(
        "remote_payloads",
        payloads,
        crate::payload::list_payload_providers,
    )?;
    check(
        "remote_wordlists",
        wordlists,
        crate::payload::list_wordlist_providers,
    )
}

/// Truncate a target's discovered parameter set to [`MAX_DISCOVERED_PARAMS`],
/// returning how many were dropped (0 if already under the cap). Shared by the
/// REST server, MCP, and both preflight paths so every async front-end bounds
/// the per-scan fan-out identically. Callers should log when the return is > 0.
pub(crate) fn cap_reflection_params(target: &mut Target) -> usize {
    let n = target.reflection_params.len();
    if n > MAX_DISCOVERED_PARAMS {
        target.reflection_params.truncate(MAX_DISCOVERED_PARAMS);
        n - MAX_DISCOVERED_PARAMS
    } else {
        0
    }
}

/// Split an HTTP-style `Cookie` header value (`a=b; c=d`) into `(name, value)`
/// pairs, trimming whitespace around each pair and around the `=`. Shared by the
/// CLI (`--cookies`, `--cookie-from-raw`), the REST server and the MCP
/// scan/preflight paths so a multi-cookie value parses identically everywhere
/// (a single `split_once('=')` would fold `; c=d` into the first value and
/// leave `=`-adjacent whitespace in).
///
/// Nameless segments (`=orphan`, or a stray `;;`) are dropped: they cannot be
/// re-serialized into a valid `Cookie` header, and keeping them burned a probe
/// per scan on a cookie that can never exist. The raw-request and HAR parsers
/// already apply the same rule.
pub(crate) fn split_cookie_pairs(raw: &str) -> Vec<(String, String)> {
    raw.split(';')
        .filter_map(|p| p.trim().split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

/// Current unix time in milliseconds (UTC).
pub(crate) fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Non-negative elapsed-ms duration from optional start/finish wall-clock
/// samples, falling back to `now` when not yet finished. Returns `None` when the
/// scan never started.
///
/// Both endpoints are wall-clock (`now_ms`) samples, so an NTP/VM clock
/// step-back between them could otherwise yield a negative duration in the
/// serialized API output; clamp to non-negative. The timestamps themselves stay
/// wall-clock because they are API-exposed as unix-ms fields. Shared by
/// [`Job::duration_ms`] and the MCP poll path (which reads a snapshot, not a
/// `Job`) so the clamp policy has a single source of truth.
pub(crate) fn duration_ms_between(
    started_at_ms: Option<i64>,
    finished_at_ms: Option<i64>,
) -> Option<i64> {
    match (started_at_ms, finished_at_ms) {
        (Some(s), Some(f)) => Some((f - s).max(0)),
        (Some(s), None) => Some((now_ms() - s).max(0)),
        _ => None,
    }
}

/// Parse a lowercase status string back into `JobStatus`. Returns `None` for
/// unknown values so callers can surface a precise error instead of silently
/// matching nothing.
pub(crate) fn parse_job_status(s: &str) -> Option<JobStatus> {
    match s {
        "queued" => Some(JobStatus::Queued),
        "running" => Some(JobStatus::Running),
        "done" => Some(JobStatus::Done),
        "error" => Some(JobStatus::Error),
        "cancelled" => Some(JobStatus::Cancelled),
        _ => None,
    }
}

/// Progress counters shared with a running scan task.
#[derive(Clone, Default)]
pub(crate) struct JobProgress {
    pub requests_sent: Arc<AtomicU64>,
    /// Requests that never reached the target (connect/TLS/timeout/transport),
    /// the sibling of `requests_sent`. Scoped per job by the runner so one
    /// scan's transport failures are not attributed to another's.
    pub requests_failed: Arc<AtomicU64>,
    pub findings_so_far: Arc<AtomicU64>,
    pub params_total: Arc<AtomicU32>,
    pub params_tested: Arc<AtomicU32>,
}

/// Single in-memory representation of an asynchronous scan used by both the
/// REST server and the MCP runtime. `callback_url` is only populated by the
/// REST server's webhook feature; MCP leaves it `None`.
#[derive(Clone)]
pub(crate) struct Job {
    pub status: JobStatus,
    /// Sanitized findings, wrapped in `Arc` so cloning a Job for outbound
    /// responses is a pointer bump rather than a deep copy of potentially
    /// large raw request/response bodies.
    pub results: Option<Arc<Vec<SanitizedResult>>>,
    pub progress: JobProgress,
    pub cancelled: Arc<AtomicBool>,
    pub error_message: Option<String>,
    /// The original target URL submitted for scanning.
    pub target_url: String,
    /// Optional webhook URL to POST results to. REST-server only.
    pub callback_url: Option<String>,
    /// Unix ms when the scan was enqueued.
    pub queued_at_ms: i64,
    /// Unix ms when the scan transitioned to Running.
    pub started_at_ms: Option<i64>,
    /// Unix ms when the scan reached a terminal state (done/error/cancelled).
    pub finished_at_ms: Option<i64>,
    /// Liveness handle for the worker that owns this job, if one was spawned.
    ///
    /// Held as a `Weak` so the job record never keeps the worker's side alive
    /// and cloning a `Job` for an outbound response does not look like another
    /// worker. `strong_count() > 0` means the worker task is still running, and
    /// therefore may still write results, a final status, or a webhook into
    /// this entry. See [`Job::is_evictable`].
    pub worker_lease: Option<std::sync::Weak<()>>,
}

/// The worker's half of a job's liveness handle: an `Arc` moved into the
/// spawned task. Dropping it — on completion, on panic, or because the task was
/// never polled — is what makes [`Job::worker_alive`] go false, so there is no
/// "clear the flag" path to forget on an error branch.
pub(crate) type WorkerLease = Arc<()>;

/// How long a terminal job may keep its concurrency slot and its map entry
/// while its worker is still draining.
///
/// Cancelling stamps a terminal status immediately and the worker winds down at
/// its next cancellation checkpoint — bounded in practice by one in-flight
/// request, i.e. `--timeout` (default 10s). Holding the slot across that window
/// is deliberate: releasing it at cancel time let a client submit-then-cancel in
/// a loop and keep unbounded workers alive against `--max-concurrent-scans`.
///
/// But "until the lease drops" is not a bound. `effective_scan_timeout` returns
/// `0` (unbounded) when neither the request nor `--scan-timeout` sets one, so a
/// worker wedged past its checkpoints would otherwise pin one slot and one map
/// entry *forever*, and repeating that drives `/scan` to a permanent 503. This
/// grace is the outer bound: far longer than any healthy drain, so only a stuck
/// worker is ever force-reclaimed.
pub(crate) const WORKER_DRAIN_GRACE_SECS: i64 = 300;

impl Job {
    /// Construct a freshly-queued Job for `target_url`, with timestamps and
    /// flags set to their initial "just enqueued" state.
    pub(crate) fn new_queued(target_url: String) -> Self {
        Self {
            status: JobStatus::Queued,
            results: None,
            progress: JobProgress::default(),
            cancelled: Arc::new(AtomicBool::new(false)),
            error_message: None,
            target_url,
            callback_url: None,
            queued_at_ms: now_ms(),
            started_at_ms: None,
            finished_at_ms: None,
            worker_lease: None,
        }
    }

    /// Mint the liveness handle for the worker about to run this job and record
    /// its `Weak` side on the job. The returned [`WorkerLease`] must be moved
    /// into the spawned task; retention will not evict this entry until it
    /// drops.
    pub(crate) fn issue_worker_lease(&mut self) -> WorkerLease {
        let lease: WorkerLease = Arc::new(());
        self.worker_lease = Some(Arc::downgrade(&lease));
        lease
    }

    /// True while the worker spawned for this job is still running.
    pub(crate) fn worker_alive(&self) -> bool {
        self.worker_lease
            .as_ref()
            .is_some_and(|w| w.strong_count() > 0)
    }

    pub(crate) fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            JobStatus::Done | JobStatus::Error | JobStatus::Cancelled
        )
    }

    /// Terminal **and** nobody is still writing to it.
    ///
    /// `is_terminal` alone is not a safe eviction test: cancelling stamps
    /// `status = Cancelled` and `finished_at_ms` the moment the user asks, but
    /// the worker keeps draining — it still has partial results to store, a
    /// final status to reconcile, and (REST) a terminal webhook to fire. Evict
    /// the entry in that window and `jobs.get_mut(&id)` comes back `None`: the
    /// results are dropped on the floor, the webhook never fires, and a `GET`
    /// on the scan_id the client is holding 404s. Automatic retention therefore
    /// waits for the lease; an explicit `DELETE ?purge=1` still wins, because
    /// that is the caller asking for exactly this.
    pub(crate) fn is_evictable(&self) -> bool {
        self.is_terminal() && (!self.worker_alive() || self.drain_window_expired())
    }

    /// True when this job went terminal more than [`WORKER_DRAIN_GRACE_SECS`]
    /// ago and its worker *still* holds the lease — i.e. the worker is wedged,
    /// not draining. Only meaningful for a terminal job; a running one legitimately
    /// holds its slot for as long as it runs.
    ///
    /// `finished_at_ms` is stamped whenever a status goes terminal, but fall
    /// back through the earlier timestamps so a missing one cannot make the
    /// window unbounded again — `queued_at_ms` is always set.
    pub(crate) fn drain_window_expired(&self) -> bool {
        if !self.is_terminal() {
            return false;
        }
        let since = self
            .finished_at_ms
            .or(self.started_at_ms)
            .unwrap_or(self.queued_at_ms);
        now_ms() - since > WORKER_DRAIN_GRACE_SECS * 1000
    }

    /// Whether this job still occupies a concurrency slot.
    ///
    /// Not the same question as `!is_terminal()`. `cancel_scan_handler` stamps
    /// a terminal status the moment the user asks, but the worker keeps running
    /// until it notices the flag — still holding a blocking-pool thread and
    /// still sending requests. Counting only non-terminal jobs let a client
    /// submit-then-cancel in a loop and keep an unbounded number of workers
    /// alive against `--max-concurrent-scans` of 1, because every one of them
    /// had already stopped counting.
    ///
    /// The slot is released when the worker's [`WorkerLease`] drops, which is
    /// the same signal [`Job::is_evictable`] uses — so admission and retention
    /// agree on what "still running" means, and after
    /// [`WORKER_DRAIN_GRACE_SECS`] a wedged worker's slot is reclaimed anyway
    /// so the cap cannot be exhausted permanently.
    pub(crate) fn occupies_capacity(&self) -> bool {
        !self.is_terminal() || (self.worker_alive() && !self.drain_window_expired())
    }

    /// Total elapsed ms from `started_at_ms` to `finished_at_ms` (or now, for
    /// still-running jobs). `None` if the scan never started.
    pub(crate) fn duration_ms(&self) -> Option<i64> {
        duration_ms_between(self.started_at_ms, self.finished_at_ms)
    }
}

/// Remove terminal jobs whose `finished_at_ms` is older than `retention_secs`
/// seconds ago. The caller is expected to hold the jobs map's lock.
pub(crate) fn purge_expired_jobs(jobs: &mut HashMap<String, Job>, retention_secs: i64) {
    let cutoff = now_ms() - retention_secs * 1000;
    jobs.retain(|_, job| {
        // A cancelled job is stamped terminal (status + finished_at_ms) the
        // moment the user asks, while its worker keeps draining. Retention must
        // not collect it out from under that worker — see `Job::is_evictable`.
        // Bounded by `WORKER_DRAIN_GRACE_SECS` so a wedged worker cannot pin the
        // entry (and its concurrency slot) forever.
        if job.worker_alive() && !job.drain_window_expired() {
            return true;
        }
        match job.finished_at_ms {
            Some(finished) => finished >= cutoff,
            None => true,
        }
    });
}

/// Drop the oldest finished jobs until the map holds at most `cap` entries.
/// `cap == 0` disables the cap.
///
/// The admission caps (`--max-concurrent-scans`, [`MAX_ACTIVE_SCANS_MCP`])
/// count only *active* jobs, and [`purge_expired_jobs`] only collects entries
/// past the retention TTL — so a flood of quick scans retains every result
/// (including raw response bodies when `include_response` was set) for an hour
/// with nothing bounding the total. This is the bound. Callers apply it while
/// admitting a new scan, since that is where the jobs lock is already held.
///
/// Only *settled* jobs are evicted: a queued/running job still has a worker
/// writing to it, and dropping its entry would strand that worker and lose the
/// caller's scan_id. Terminal-but-draining jobs (a cancel stamps the terminal
/// state immediately while the worker winds down) are held back the same way —
/// see [`Job::is_evictable`]. If every job is active, the map simply stays over
/// the cap until they settle.
pub(crate) fn enforce_retention_cap(jobs: &mut HashMap<String, Job>, cap: usize) {
    if cap == 0 || jobs.len() <= cap {
        return;
    }
    let mut finished: Vec<(String, i64)> = jobs
        .iter()
        .filter(|(_, job)| job.is_evictable())
        .map(|(id, job)| (id.clone(), job.finished_at_ms.unwrap_or(job.queued_at_ms)))
        .collect();
    // Oldest first, then by id so two jobs finishing in the same millisecond
    // evict deterministically rather than in HashMap iteration order.
    finished.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));

    let mut excess = jobs.len() - cap;
    for (id, _) in finished {
        if excess == 0 {
            break;
        }
        jobs.remove(&id);
        excess -= 1;
    }
}

/// RAII guard that aborts a background `JoinHandle` on drop, including the
/// panic path. Both the REST server and MCP spawn a small progress-mirroring
/// task that must not outlive `run_scan_job` — without this guard, a panic
/// between the spawn and the manual `abort()` call would leak the task.
pub(crate) struct AbortOnDrop<T>(pub tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Send one request mirroring the scan's HTTP configuration (method, headers,
/// cookies, User-Agent, body, proxy, timeout, redirects). Returns true iff a
/// response came back — content/status are not inspected.
///
/// Used by preflight reachability probes so the result reflects what a real
/// scan would see, not what a default reqwest client sees.
/// True when `url` (after trimming) carries an `http`/`https` scheme. The
/// scheme is matched case-insensitively because URI schemes are
/// case-insensitive (RFC 3986 §3.1) and `parse_target` already lowercases the
/// scheme — so `HTTP://x` is a valid target the scanner would otherwise dial.
/// Shared by the REST server (`/scan`, `/preflight`) and the MCP scan/preflight
/// tools so the accepted-target contract is identical everywhere. Allocation-
/// and panic-free (byte-prefix compare, never slices on a char boundary).
pub(crate) fn has_http_scheme(url: &str) -> bool {
    let b = url.trim().as_bytes();
    let starts_with = |p: &[u8]| b.len() >= p.len() && b[..p.len()].eq_ignore_ascii_case(p);
    starts_with(b"http://") || starts_with(b"https://")
}

/// The `error_message` recorded when a scan target can't be connected to.
/// Shared by the REST server and MCP so the client-facing string — which
/// callers grep to tell "unreachable" apart from "scanned, no findings" —
/// has a single source of truth. Carries the `CONNECTION_FAILED` code that
/// `/preflight` already returns in its `error_code` field.
pub(crate) fn unreachable_error_message() -> String {
    format!(
        "target unreachable: connection failed ({})",
        crate::cmd::error_codes::CONNECTION_FAILED
    )
}

/// Resolve the effective whole-scan wall-clock budget (seconds) for a job from
/// a per-request value and an optional server-side cap.
///
/// - `0` means "no budget" (unbounded), matching the CLI's `--scan-timeout 0`.
/// - When the server sets a cap (`Some(c)` with `c > 0`) it is an *upper bound*:
///   a request may ask for a shorter budget but cannot raise it past the cap or
///   disable it (a requested `0` is clamped up to the cap). This lets an
///   operator bound every submitted scan regardless of what an (authenticated)
///   client requests, without breaking the unbounded default when no cap is set.
///
/// Shared by the REST server (per-request option + `--scan-timeout` cap) and the
/// MCP scan tool (per-call value, no server cap) so the budget semantics match.
pub(crate) fn effective_scan_timeout(requested: Option<u64>, server_cap: Option<u64>) -> u64 {
    match (requested, server_cap.filter(|c| *c > 0)) {
        (Some(r), Some(cap)) => {
            if r == 0 {
                cap
            } else {
                r.min(cap)
            }
        }
        (Some(r), None) => r,
        (None, Some(cap)) => cap,
        (None, None) => 0,
    }
}

/// Drive `fut` to completion, but abort it after `budget_secs` of wall-clock
/// time when `budget_secs > 0`. On expiry the shared `cancel` flag is set — so
/// any scan workers still in flight wind down at their next cancellation
/// checkpoint, exactly as a user-initiated cancel would — and `true` is
/// returned. `budget_secs == 0` disables the cap and always returns `false`.
///
/// Used by the REST server and MCP runners to bound a single scan's total
/// runtime; the CLI enforces the same `--scan-timeout` budget in its scan loop.
/// Wrapping (rather than only setting the cancel flag from a watchdog) is what
/// bounds phases that don't poll the flag — discovery, mining, and the initial
/// AST fetch — so a slow target can't keep a scan alive past its budget there.
pub async fn run_within_scan_budget<F>(budget_secs: u64, cancel: &Arc<AtomicBool>, fut: F) -> bool
where
    F: std::future::Future<Output = ()>,
{
    if budget_secs == 0 {
        fut.await;
        return false;
    }
    let budget = std::time::Duration::from_secs(budget_secs);
    match tokio::time::timeout(budget, fut).await {
        Ok(()) => false,
        Err(_elapsed) => {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            true
        }
    }
}

pub async fn send_reachability_probe(target: &Target) -> bool {
    let client = target.build_client_or_default();
    let mut req = client.request(target.parse_method(), target.url.clone());
    for (k, v) in &target.headers {
        req = req.header(k, v);
    }
    if !target.cookies.is_empty() {
        let cookie_header = target
            .cookies
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("; ");
        req = req.header("Cookie", cookie_header);
    }
    if let Some(ua) = target.effective_user_agent() {
        req = req.header("User-Agent", ua);
    }
    if let Some(body) = &target.data {
        req = req.body(body.clone());
    }
    req.send().await.is_ok()
}

#[cfg(test)]
mod tests;
