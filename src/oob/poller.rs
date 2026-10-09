//! Background OOB poller: drives [`OobSession::poll`], correlates each callback
//! back to the request that caused it, and merges a finding into the shared
//! results vector. Poll requests go to the OAST server (not the target), so they
//! deliberately never touch the request counter or the target rate limiter.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::Mutex as TokioMutex;
use tokio::task::JoinHandle;

use crate::oob::{InjectionRecord, OobInteraction, OobSession};
use crate::scanning::result::{FindingType, Result as ScanResult};

/// How often the background task polls the OAST server.
const POLL_INTERVAL_SECS: u64 = 5;

/// Ceiling on findings from callbacks whose nonce is not in the registry.
/// The correlation id is embedded in every injected URL, so anyone who can read
/// a stored payload can mint `<corr-id><any 13 chars>.<server>` hosts at will;
/// each distinct suffix is otherwise a new Verified/High finding plus a `seen`
/// entry. Registered nonces are bounded by the payloads we injected and stay
/// uncapped.
pub(crate) const MAX_UNATTRIBUTED_FINDINGS: usize = 1000;

type Results = Arc<TokioMutex<Vec<ScanResult>>>;
type Seen = Arc<StdMutex<HashSet<String>>>;

/// What the poll loop has observed, shared by the background task and the
/// final sweep so a dead OAST server can be reported once instead of reading as
/// a clean scan.
#[derive(Default)]
struct PollState {
    ok: AtomicUsize,
    failed: AtomicUsize,
    consecutive_failed: AtomicUsize,
    last_error: StdMutex<String>,
    warned_poll: AtomicBool,
    unattributed: AtomicUsize,
    warned_cap: AtomicBool,
}

/// One WRN line on stderr (stdout stays clean for json/sarif), at most once per
/// `flag`, and never under `--silence`.
fn warn_once(silence: bool, flag: &AtomicBool, msg: &str) {
    if !silence && !flag.swap(true, Ordering::Relaxed) {
        crate::ceprintln!("{} {}", crate::utils::log::log_prefix("33", "WRN"), msg);
    }
}

/// Short, secret-free cause for a poll failure. A `reqwest::Error` displays the
/// request URL, which carries the session's `secret=` query value, so it is
/// reduced to its kind; the remaining errors are our own messages.
fn summarize_poll_error(e: &(dyn std::error::Error + Send + Sync + 'static)) -> String {
    let s = match e.downcast_ref::<reqwest::Error>() {
        Some(r) if r.is_timeout() => "request timed out".to_string(),
        Some(r) if r.is_connect() => "connection failed".to_string(),
        Some(_) => "request failed".to_string(),
        None => e.to_string(),
    };
    crate::utils::term::sanitize_display(&s).to_string()
}

fn warn_poll_failure(silence: bool, state: &PollState) {
    let last = state
        .last_error
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    warn_once(
        silence,
        &state.warned_poll,
        &format!(
            "OOB polling is failing ({last}); blind callbacks are not being collected, so a clean result does not rule out blind XSS"
        ),
    );
}

/// Handle to a running poller. Hold it for the scan's lifetime, then call
/// [`finish`](PollerHandle::finish) to drain the grace window and deregister.
pub(crate) struct PollerHandle {
    session: Arc<OobSession>,
    results: Results,
    findings_count: Arc<AtomicUsize>,
    cancel: Arc<AtomicBool>,
    seen: Seen,
    stop: Arc<AtomicBool>,
    /// `Option` so [`finish`](PollerHandle::finish) can take the handle to await
    /// it, while [`Drop`] still aborts a handle dropped without `finish` (panic,
    /// early return) — the background poll loop must never outlive its job.
    task: Option<JoinHandle<()>>,
    state: Arc<PollState>,
    silence: bool,
}

impl Drop for PollerHandle {
    fn drop(&mut self) {
        // `finish` already took the handle and awaited it; only a handle
        // dropped *without* `finish` still owns a live task to abort.
        self.stop.store(true, Ordering::Relaxed);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Spawn the background poll loop. It runs until `stop`/`cancel` is set.
pub(crate) fn spawn_poller(
    session: Arc<OobSession>,
    results: Results,
    findings_count: Arc<AtomicUsize>,
    cancel: Arc<AtomicBool>,
    silence: bool,
) -> PollerHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let seen: Seen = Arc::new(StdMutex::new(HashSet::new()));
    let state = Arc::new(PollState::default());

    let task = {
        let state = state.clone();
        let session = session.clone();
        let results = results.clone();
        let findings_count = findings_count.clone();
        let cancel = cancel.clone();
        let stop = stop.clone();
        let seen = seen.clone();
        tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) && !cancel.load(Ordering::Relaxed) {
                poll_once(&session, &results, &findings_count, &seen, &state, silence).await;
                // Sleep in 1s slices so a stop/cancel cuts the wait short.
                for _ in 0..POLL_INTERVAL_SECS {
                    if stop.load(Ordering::Relaxed) || cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        })
    };

    PollerHandle {
        session,
        results,
        findings_count,
        cancel,
        seen,
        stop,
        task: Some(task),
        state,
        silence,
    }
}

impl PollerHandle {
    /// `(poll-failure warning emitted, unattributed findings kept)`, readable
    /// after `finish` has consumed the handle.
    #[cfg(test)]
    pub(crate) fn probe(&self) -> impl Fn() -> (bool, usize) + use<> {
        let s = self.state.clone();
        move || {
            (
                s.warned_poll.load(Ordering::Relaxed),
                s.unattributed.load(Ordering::Relaxed),
            )
        }
    }

    /// Keep the background poller draining for up to `grace`, then stop it, do a
    /// final poll for anything that landed in the last interval, and deregister.
    /// A pending cancel (Ctrl-C) cuts the grace window short.
    pub async fn finish(mut self, grace: Duration) {
        let start = Instant::now();
        while start.elapsed() < grace && !self.cancel.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        self.stop.store(true, Ordering::Relaxed);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        // Final sweep to catch interactions queued during the last poll gap.
        poll_once(
            &self.session,
            &self.results,
            &self.findings_count,
            &self.seen,
            &self.state,
            self.silence,
        )
        .await;
        // A short `--blind-oob-wait` may only ever see one poll, which is below
        // the in-loop threshold; never having succeeded is enough to say so.
        if self.state.ok.load(Ordering::Relaxed) == 0
            && self.state.failed.load(Ordering::Relaxed) > 0
        {
            warn_poll_failure(self.silence, &self.state);
        }
        self.session.deregister().await;
    }
}

/// Key used to collapse repeated callbacks into one finding. A correlated hit
/// (a recovered nonce) de-dupes per `(nonce, protocol)`: one finding per payload
/// per channel even if the callback fires repeatedly. An UNcorrelated hit has no
/// nonce, so it de-dupes on the interaction's own identity (host + remote
/// address + protocol) — keying it on the empty nonce alone would collapse every
/// distinct uncorrelated hit of a protocol into a single finding, dropping real
/// out-of-band evidence.
fn dedup_key(nonce: &str, it: &OobInteraction) -> String {
    if nonce.is_empty() {
        format!(
            "uncorrelated:{}:{}:{}",
            it.full_id, it.remote_address, it.protocol
        )
    } else {
        format!("{}:{}", nonce, it.protocol)
    }
}

/// Poll once and merge any new, correlated callbacks into `results`.
async fn poll_once(
    session: &OobSession,
    results: &Results,
    findings_count: &Arc<AtomicUsize>,
    seen: &Seen,
    state: &PollState,
    silence: bool,
) {
    let interactions = match session.poll().await {
        Ok(v) => {
            state.ok.fetch_add(1, Ordering::Relaxed);
            state.consecutive_failed.store(0, Ordering::Relaxed);
            v
        }
        Err(e) => {
            crate::dbg_log!("OOB poll failed: {e}");
            *state
                .last_error
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = summarize_poll_error(&*e);
            state.failed.fetch_add(1, Ordering::Relaxed);
            // Two in a row: a single dropped poll is noise, a dead server is not.
            if state.consecutive_failed.fetch_add(1, Ordering::Relaxed) + 1 >= 2 {
                warn_poll_failure(silence, state);
            }
            return;
        }
    };

    let mut batch: Vec<ScanResult> = Vec::new();
    for it in interactions {
        let nonce = session.extract_nonce(&it.full_id).unwrap_or_default();
        let record = session.registry().lookup(&nonce);
        if record.is_none() {
            // Bound the forgeable path before it can grow `seen` or `results`.
            if state.unattributed.load(Ordering::Relaxed) >= MAX_UNATTRIBUTED_FINDINGS {
                warn_once(
                    silence,
                    &state.warned_cap,
                    &format!(
                        "OOB: more than {MAX_UNATTRIBUTED_FINDINGS} callbacks matched no injected payload; ignoring the rest (the correlation id is visible to the target)"
                    ),
                );
                continue;
            }
        }
        let dedup_key = dedup_key(&nonce, &it);
        {
            let mut guard = seen.lock().unwrap_or_else(PoisonError::into_inner);
            if !guard.insert(dedup_key) {
                continue;
            }
        }
        if record.is_none() {
            state.unattributed.fetch_add(1, Ordering::Relaxed);
        }
        if !silence {
            crate::ceprintln!("{}", live_line(&it, record.as_ref()));
        }
        batch.push(build_finding(&it, record.as_ref(), session.server_domain()));
    }

    if !batch.is_empty() {
        let added = batch.len();
        results.lock().await.extend(batch);
        findings_count.fetch_add(added, Ordering::Relaxed);
    }
}

/// One-line stderr notice when a callback lands (kept off stdout so JSON/SARIF
/// output stays clean). Formatted like the rest of dalfox's plain log lines —
/// gray `{ts}` + a red `OOB` level token (a fired blind callback is a Verified
/// finding) — and routed through `ceprintln!` so the ANSI is stripped under
/// `--no-color` / `NO_COLOR`.
fn live_line(it: &OobInteraction, record: Option<&InjectionRecord>) -> String {
    // Every field is target- or callback-derived; escape control bytes.
    use crate::utils::term::sanitize_display as clean;
    let proto = if it.protocol.is_empty() {
        "oob"
    } else {
        &it.protocol
    };
    let head = crate::utils::log::log_prefix("31", "OOB");
    match record {
        Some(r) => format!(
            "{} {} callback: param '{}' ({}) on {} — payload {}",
            head,
            clean(proto),
            clean(&r.param),
            if r.location.is_empty() {
                "?"
            } else {
                &r.location
            },
            clean(&r.target_url),
            clean(&r.payload),
        ),
        None => format!(
            "{} {} callback to {} (no correlated payload)",
            head,
            clean(proto),
            clean(&it.full_id)
        ),
    }
}

/// Build a `Verified` finding for a correlated OOB callback. Falls back to a
/// minimally-attributed finding when the nonce isn't in the registry (still a
/// real signal — the callback hit our session-scoped correlation domain).
fn build_finding(
    it: &OobInteraction,
    record: Option<&InjectionRecord>,
    server: &str,
) -> ScanResult {
    let proto = if it.protocol.is_empty() {
        "oob".to_string()
    } else {
        it.protocol.clone()
    };
    let (data, param, payload, location, method) = match record {
        Some(r) => (
            r.target_url.clone(),
            r.param.clone(),
            r.payload.clone(),
            r.location.clone(),
            if r.method.is_empty() {
                "GET".to_string()
            } else {
                r.method.clone()
            },
        ),
        None => (
            format!("https://{}", it.full_id),
            String::new(),
            String::new(),
            String::new(),
            "GET".to_string(),
        ),
    };

    let loc_label = if location.is_empty() {
        "Unknown"
    } else {
        location.as_str()
    };
    let host = if it.full_id.is_empty() {
        server
    } else {
        &it.full_id
    };
    let remote = if it.remote_address.is_empty() {
        "?"
    } else {
        &it.remote_address
    };
    let ts = if it.timestamp.is_empty() {
        "?"
    } else {
        &it.timestamp
    };
    let evidence = format!("OOB {proto} callback from {remote} at {ts} (host {host})");

    let mut result = ScanResult::builder(FindingType::Verified)
        // The one path where dalfox observes real execution: the payload called
        // home. Not `dom-verification`, which the tier would otherwise imply.
        .detection_method(crate::scanning::result::FindingMethod::Oob)
        .confidence(
            crate::scanning::result::Confidence::High,
            "out-of-band callback received from the injected payload",
        )
        .inject_type(format!("blind-oob-{loc_label}-{proto}"))
        .method(method)
        .data(data)
        .param(param)
        .payload(payload)
        .evidence(evidence)
        .cwe("CWE-79")
        .severity("High")
        .message_str("Triggered Blind XSS via out-of-band (interactsh) callback")
        .build();
    result.location = location;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_line_escapes_terminal_controls() {
        let it = OobInteraction {
            protocol: "http\x1b]0;P\x07".to_string(),
            full_id: "x\x1b]52;c;SEFDSw==\x07.oast.fun".to_string(),
            remote_address: String::new(),
            timestamp: String::new(),
        };
        let rec = InjectionRecord {
            target_url: "https://t/\u{9d}".to_string(),
            param: "q\x1b]8;;https://evil/\x07".to_string(),
            location: "Query".to_string(),
            payload: "<x>\r".to_string(),
            method: "GET".to_string(),
        };
        for line in [live_line(&it, Some(&rec)), live_line(&it, None)] {
            // Only the line's own SGR head may carry ESC.
            let tail = line.split_once("OOB\x1b[0m").map_or(&*line, |(_, t)| t);
            assert!(
                !tail.contains(['\x1b', '\x07', '\r', '\u{9d}']),
                "raw control in {line:?}"
            );
        }
    }

    #[test]
    fn finding_uses_record_attribution() {
        let it = OobInteraction {
            protocol: "http".to_string(),
            full_id: "corrnonce.oast.fun".to_string(),
            remote_address: "203.0.113.5".to_string(),
            timestamp: "2026-06-12T00:00:00Z".to_string(),
        };
        let rec = InjectionRecord {
            target_url: "https://t/?q=1".to_string(),
            param: "q".to_string(),
            location: "Query".to_string(),
            payload: "\"'><script src=//x></script>".to_string(),
            method: "GET".to_string(),
        };
        let r = build_finding(&it, Some(&rec), "oast.fun");
        assert_eq!(r.result_type, FindingType::Verified);
        assert_eq!(r.param, "q");
        assert_eq!(r.location, "Query");
        assert_eq!(r.inject_type, "blind-oob-Query-http");
        assert!(r.evidence.contains("203.0.113.5"));
        assert!(r.evidence.contains("oast.fun"));
    }

    #[test]
    fn dedup_key_correlated_collapses_per_nonce_protocol() {
        let it = OobInteraction {
            protocol: "http".to_string(),
            full_id: "abc123.oast.fun".to_string(),
            remote_address: "203.0.113.5".to_string(),
            timestamp: String::new(),
        };
        // Same nonce + protocol => same key (repeat callbacks collapse to one).
        assert_eq!(dedup_key("abc123", &it), dedup_key("abc123", &it));
        // Different protocols of the same nonce stay distinct (one per channel).
        let mut dns = it.clone();
        dns.protocol = "dns".to_string();
        assert_ne!(dedup_key("abc123", &it), dedup_key("abc123", &dns));
    }

    #[test]
    fn dedup_key_uncorrelated_does_not_collapse_distinct_hits() {
        // Two uncorrelated callbacks (empty nonce) from different sources must
        // NOT share a key — otherwise only the first surfaces and the rest of
        // the blind-XSS evidence is silently dropped.
        let a = OobInteraction {
            protocol: "http".to_string(),
            full_id: "aaa.oast.fun".to_string(),
            remote_address: "203.0.113.5".to_string(),
            timestamp: String::new(),
        };
        let mut b = a.clone();
        b.full_id = "bbb.oast.fun".to_string();
        b.remote_address = "198.51.100.9".to_string();
        assert_ne!(dedup_key("", &a), dedup_key("", &b));
        // But an identical uncorrelated hit (same host+addr+proto) still dedupes.
        assert_eq!(dedup_key("", &a), dedup_key("", &a.clone()));
    }

    #[test]
    fn finding_without_record_is_still_emitted() {
        let it = OobInteraction {
            protocol: "dns".to_string(),
            full_id: "abc.oast.fun".to_string(),
            remote_address: String::new(),
            timestamp: String::new(),
        };
        let r = build_finding(&it, None, "oast.fun");
        assert_eq!(r.result_type, FindingType::Verified);
        assert_eq!(r.inject_type, "blind-oob-Unknown-dns");
        assert!(r.param.is_empty());
        assert!(r.data.contains("abc.oast.fun"));
    }
}
