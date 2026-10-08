//! Blind-XSS arming and dispatch: the static `-b/--blind` callback and the
//! OOB/OAST (interactsh) channel.
//!
//! Split out of `run_scan` because the gating is subtle and easy to get wrong
//! in either direction — these are *stored* attack payloads, so a run that was
//! told not to attack must not send them, while a registration outage must not
//! abort a scan that would otherwise proceed.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::args::ScanArgs;
use super::logging::{log_info, log_warn};
use crate::target_parser::Target;

/// Arm the configured blind-XSS channels and inject over them, returning the
/// OOB session (if one registered) for the poller to drain later.
pub(crate) async fn arm_and_dispatch(
    args: &ScanArgs,
    host_groups: &BTreeMap<String, Vec<Target>>,
    cancel_flag: &AtomicBool,
) -> Option<Arc<crate::oob::OobSession>> {
    // Blind XSS: the static `-b/--blind` callback and/or OOB/OAST (interactsh)
    // callbacks. Skipped in preview-only modes — `--dry-run` (which advertises
    // "without sending attack payloads") and `--only-discovery` — because blind
    // payloads are real attack traffic and OOB registration is an outbound side
    // effect to a third-party server.
    //
    // Start an OOB session first — it fails soft (warn + continue), so a
    // registration outage never aborts the scan. Injection then runs over
    // whichever channel(s) are configured; the OOB poller is spawned once
    // `stream_findings_enabled` is known (below) and drained before rendering.
    // `--skip-xss-scanning` means "send no attack payloads". Blind XSS payloads
    // are attack payloads — stored ones, at that: they persist in the target
    // after the run. Only the per-target injection stage used to honour the
    // flag (scan_loop.rs), so `--skip-xss-scanning -b <callback>` (with `-b`
    // commonly living in a shared config file) still wrote live stored-XSS
    // payloads into every parameter and form of a production system the
    // operator had explicitly asked not to attack. This also skips OOB session
    // registration, which is correct: there is nothing left to call back.
    let blind_active = !args.dry_run && !args.only_discovery && !args.skip_xss_scanning;
    let oob_session: Option<Arc<crate::oob::OobSession>> =
        if blind_active && args.blind_oob_enabled() {
            match crate::oob::OobSession::start(&args.oob_config()).await {
                Ok(session) => {
                    log_info(
                        args,
                        &format!(
                            "OOB blind XSS armed via interactsh server: {}",
                            session.server_domain()
                        ),
                    );
                    Some(Arc::new(session))
                }
                Err(e) => {
                    log_warn(
                        args,
                        &format!("--blind-oob disabled (could not register with any server): {e}"),
                    );
                    None
                }
            }
        } else {
            None
        };

    if blind_active && (args.blind_callback_url.is_some() || oob_session.is_some()) {
        if let Some(callback_url) = &args.blind_callback_url {
            log_info(
                args,
                &format!(
                    "Performing blind XSS scanning with callback URL: {}",
                    callback_url
                ),
            );
        }
        let custom = args.custom_blind_xss_payload.as_deref();
        // Serial by design, but Ctrl-C must not wait out the whole phase: the
        // flag is checked per target and also races the in-flight requests,
        // so the first SIGINT drops the current target's request and moves on
        // to the graceful drain.
        'dispatch: for group in host_groups.values() {
            for target in group {
                if cancel_flag.load(Ordering::Relaxed) {
                    break 'dispatch;
                }
                let source = match (&args.blind_callback_url, &oob_session) {
                    (Some(url), Some(session)) => crate::scanning::CallbackSource::Both {
                        url: url.as_str(),
                        session: session.as_ref(),
                    },
                    (Some(url), None) => crate::scanning::CallbackSource::Static(url.as_str()),
                    (None, Some(session)) => crate::scanning::CallbackSource::Oob(session.as_ref()),
                    // Guarded by the enclosing `if`: at least one is Some.
                    (None, None) => continue,
                };
                tokio::select! {
                    _ = async {
                        crate::scanning::blind_scanning_with(target, source, custom).await;
                        crate::scanning::blind_scan_forms_with(target, source, custom).await;
                    } => {}
                    _ = super::scan_loop::poll_cancel(cancel_flag) => break 'dispatch,
                }
            }
        }
    }

    oob_session
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::routing::any;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    /// Server that counts requests and optionally stalls each one.
    async fn spawn_counting_server(stall: Duration) -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let app = Router::new().fallback(any(move || {
            let h = h.clone();
            async move {
                h.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(stall).await;
                "ok"
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}/?q=1"), hits)
    }

    fn setup(url: &str) -> (ScanArgs, BTreeMap<String, Vec<Target>>) {
        let args = ScanArgs {
            blind_callback_url: Some("https://cb.example/x".to_string()),
            silence: true,
            insecure: Some(true),
            ..Default::default()
        };
        let mut groups = BTreeMap::new();
        groups.insert(
            "h".to_string(),
            vec![crate::target_parser::parse_target(url).unwrap()],
        );
        (args, groups)
    }

    #[tokio::test]
    async fn cancelled_flag_stops_blind_dispatch() {
        let _serial = crate::REQUEST_COUNTER_TEST_LOCK.lock().await;
        let (url, hits) = spawn_counting_server(Duration::ZERO).await;
        let (args, groups) = setup(&url);

        arm_and_dispatch(&args, &groups, &AtomicBool::new(false)).await;
        assert!(hits.load(Ordering::SeqCst) > 0, "control: dispatch sends");

        hits.store(0, Ordering::SeqCst);
        arm_and_dispatch(&args, &groups, &AtomicBool::new(true)).await;
        assert_eq!(hits.load(Ordering::SeqCst), 0, "cancelled before dispatch");
    }

    #[tokio::test]
    async fn cancel_interrupts_an_in_flight_blind_request() {
        let _serial = crate::REQUEST_COUNTER_TEST_LOCK.lock().await;
        let (url, hits) = spawn_counting_server(Duration::from_secs(30)).await;
        let (args, groups) = setup(&url);
        let flag = Arc::new(AtomicBool::new(false));
        let f = flag.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            f.store(true, Ordering::Relaxed);
        });
        let started = std::time::Instant::now();
        arm_and_dispatch(&args, &groups, &flag).await;
        assert!(hits.load(Ordering::SeqCst) >= 1);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "first Ctrl-C must not wait out the stalled request: {:?}",
            started.elapsed()
        );
    }
}
