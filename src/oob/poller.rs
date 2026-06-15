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

type Results = Arc<TokioMutex<Vec<ScanResult>>>;
type Seen = Arc<StdMutex<HashSet<String>>>;

/// Handle to a running poller. Hold it for the scan's lifetime, then call
/// [`finish`](PollerHandle::finish) to drain the grace window and deregister.
pub struct PollerHandle {
    session: Arc<OobSession>,
    results: Results,
    findings_count: Arc<AtomicUsize>,
    cancel: Arc<AtomicBool>,
    seen: Seen,
    stop: Arc<AtomicBool>,
    task: JoinHandle<()>,
    silence: bool,
}

/// Spawn the background poll loop. It runs until `stop`/`cancel` is set.
pub fn spawn_poller(
    session: Arc<OobSession>,
    results: Results,
    findings_count: Arc<AtomicUsize>,
    cancel: Arc<AtomicBool>,
    silence: bool,
) -> PollerHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let seen: Seen = Arc::new(StdMutex::new(HashSet::new()));

    let task = {
        let session = session.clone();
        let results = results.clone();
        let findings_count = findings_count.clone();
        let cancel = cancel.clone();
        let stop = stop.clone();
        let seen = seen.clone();
        tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) && !cancel.load(Ordering::Relaxed) {
                poll_once(&session, &results, &findings_count, &seen, silence).await;
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
        task,
        silence,
    }
}

impl PollerHandle {
    /// Keep the background poller draining for up to `grace`, then stop it, do a
    /// final poll for anything that landed in the last interval, and deregister.
    /// A pending cancel (Ctrl-C) cuts the grace window short.
    pub async fn finish(self, grace: Duration) {
        let start = Instant::now();
        while start.elapsed() < grace && !self.cancel.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.task.await;
        // Final sweep to catch interactions queued during the last poll gap.
        poll_once(
            &self.session,
            &self.results,
            &self.findings_count,
            &self.seen,
            self.silence,
        )
        .await;
        self.session.deregister().await;
    }
}

/// Poll once and merge any new, correlated callbacks into `results`.
async fn poll_once(
    session: &OobSession,
    results: &Results,
    findings_count: &Arc<AtomicUsize>,
    seen: &Seen,
    silence: bool,
) {
    let interactions = match session.poll().await {
        Ok(v) => v,
        Err(e) => {
            if crate::DEBUG.load(Ordering::Relaxed) {
                eprintln!("[DBG] OOB poll failed: {e}");
            }
            return;
        }
    };

    let mut batch: Vec<ScanResult> = Vec::new();
    for it in interactions {
        let nonce = session.extract_nonce(&it.full_id).unwrap_or_default();
        // De-dupe per (nonce, protocol): one finding per payload per channel,
        // even if the callback fires repeatedly.
        let dedup_key = format!("{}:{}", nonce, it.protocol);
        {
            let mut guard = seen.lock().unwrap_or_else(PoisonError::into_inner);
            if !guard.insert(dedup_key) {
                continue;
            }
        }
        let record = session.registry().lookup(&nonce);
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
    let proto = if it.protocol.is_empty() {
        "oob"
    } else {
        &it.protocol
    };
    let ts = chrono::Local::now().format("%-I:%M%p").to_string();
    match record {
        Some(r) => format!(
            "\x1b[90m{}\x1b[0m \x1b[31mOOB\x1b[0m {} callback: param '{}' ({}) on {} — payload {}",
            ts,
            proto,
            r.param,
            if r.location.is_empty() {
                "?"
            } else {
                &r.location
            },
            r.target_url,
            r.payload,
        ),
        None => format!(
            "\x1b[90m{}\x1b[0m \x1b[31mOOB\x1b[0m {} callback to {} (no correlated payload)",
            ts, proto, it.full_id
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
    fn finding_uses_record_attribution() {
        let it = OobInteraction {
            protocol: "http".to_string(),
            full_id: "corrnonce.oast.fun".to_string(),
            remote_address: "203.0.113.5".to_string(),
            timestamp: "2026-06-12T00:00:00Z".to_string(),
            raw_request: "GET / HTTP/1.1".to_string(),
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
    fn finding_without_record_is_still_emitted() {
        let it = OobInteraction {
            protocol: "dns".to_string(),
            full_id: "abc.oast.fun".to_string(),
            remote_address: String::new(),
            timestamp: String::new(),
            raw_request: String::new(),
        };
        let r = build_finding(&it, None, "oast.fun");
        assert_eq!(r.result_type, FindingType::Verified);
        assert_eq!(r.inject_type, "blind-oob-Unknown-dns");
        assert!(r.param.is_empty());
        assert!(r.data.contains("abc.oast.fun"));
    }
}
