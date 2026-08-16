//! Blind-XSS arming and dispatch: the static `-b/--blind` callback and the
//! OOB/OAST (interactsh) channel.
//!
//! Split out of `run_scan` because the gating is subtle and easy to get wrong
//! in either direction — these are *stored* attack payloads, so a run that was
//! told not to attack must not send them, while a registration outage must not
//! abort a scan that would otherwise proceed.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::args::ScanArgs;
use super::logging::{log_info, log_warn};
use crate::target_parser::Target;

/// Arm the configured blind-XSS channels and inject over them, returning the
/// OOB session (if one registered) for the poller to drain later.
pub(crate) async fn arm_and_dispatch(
    args: &ScanArgs,
    host_groups: &BTreeMap<String, Vec<Target>>,
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
        for group in host_groups.values() {
            for target in group {
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
                crate::scanning::blind_scanning_with(target, source, custom).await;
                crate::scanning::blind_scan_forms_with(target, source, custom).await;
            }
        }
    }

    oob_session
}
