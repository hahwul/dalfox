//! Session-state detection (issue #1273).
//!
//! Authentication in dalfox is static: `--headers` / `--cookies` /
//! `--cookie-from-raw` are attached to every request and never revisited.
//! When the session behind them expires mid-scan, every subsequent request is
//! answered by a login page, nothing reflects, and the run exits `0` with an
//! empty report — indistinguishable from a genuinely clean target. That is a
//! silent total-false-negative mode, and it bites hardest on exactly the long
//! authenticated scans where it is most expensive.
//!
//! This module makes it loud. During preflight we capture a
//! [`SessionBaseline`] of the *authenticated* landing response (no extra
//! request — it reuses the body the preflight GET already fetched). The scan
//! loop then re-probes at the per-target dispatch boundary and once more after
//! the target's injection stage, and [`classify`] compares the two. On loss the
//! target is marked `SESSION_LOST` in the scan-meta envelope and — under the
//! default `--on-session-loss abort` — the remaining targets for that host are
//! skipped rather than spent against a login page.
//!
//! The REST server and MCP runtime run their own scan loop, so they do not use
//! [`SessionMonitor`] — one job is one target, asked once. They call
//! [`session_lost_after_scan`] instead and settle the job as `error` with a
//! `SESSION_LOST:` message, which is the same claim their surfaces can express.
//! Everything that decides *whether* the session died ([`classify`],
//! [`baseline_warning`], [`monitoring_enabled`]) is shared, so the three
//! front-ends cannot drift on the actual detection rules.
//!
//! Non-goal: automated login. Detection only.

use super::args::ScanArgs;
use crate::target_parser::Target;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// Allowed values for `--on-session-loss`. Shared with the config-file
/// validator: a config file bypasses clap entirely, so both must agree.
pub const ON_SESSION_LOSS_VALUES: &[&str] = &["abort", "continue"];

/// Policy when neither the CLI nor a config file says otherwise: stop spending
/// requests on a login page.
pub const DEFAULT_ON_SESSION_LOSS: &str = "abort";

/// Minimum age a baseline must have before the *pre-dispatch* re-probe is worth
/// spending a request on. The baseline is captured during preflight, and on a
/// single-target run dispatch follows within milliseconds — re-probing there
/// would only re-confirm what we just measured. The post-scan probe is never
/// throttled: that is the one that actually catches a session dying mid-run.
const PRE_DISPATCH_MIN_AGE_SECS: u64 = 30;

/// Cap on the probe response body we read. Only the login-form heuristic and
/// `--session-check` look at the body, and neither needs megabytes; the cap
/// keeps a hostile or merely enormous response from turning a cheap liveness
/// check into a memory event.
const PROBE_BODY_CAP_BYTES: usize = 64 * 1024;

/// Fingerprint of the authenticated state, captured once per target from the
/// preflight GET. Deliberately coarse: the only job is to tell "this is still
/// the app" from "this is the login wall", and a tight fingerprint would
/// false-positive on every dynamic page.
#[derive(Debug, Clone)]
pub(crate) struct SessionBaseline {
    /// Status of the authenticated preflight response.
    pub(crate) status: u16,
    /// Where the request actually landed: the post-redirect URL, or the
    /// resolved `Location` when redirects aren't being followed.
    pub(crate) landing: String,
    /// Did the authenticated page *already* show a login form? Some apps render
    /// one in a header/modal even when signed in, so "a password field appeared"
    /// is only a loss signal if the baseline had none.
    pub(crate) has_login_form: bool,
    /// How many bytes of the response this baseline actually saw.
    ///
    /// This is a **decision input**, not a diagnostic: the preflight GET asks
    /// for `Range: bytes=0-8191` while a probe reads up to
    /// [`PROBE_BODY_CAP_BYTES`], so against an origin that honors Range the two
    /// bodies cover different spans of the same page. A `type="password"` at
    /// byte 20000 would then be invisible to the baseline and visible to every
    /// probe — a permanent false `SESSION_LOST`. [`classify`] compares the
    /// login-form signal over this many bytes of the probe body so both sides
    /// look at the same region.
    pub(crate) body_len: usize,
    /// Whether `--session-check` matched the baseline. `None` when the flag
    /// wasn't given. `Some(false)` means the marker is wrong or on a different
    /// page — every later probe would report a loss, so this is caught up front
    /// (see [`baseline_warning`]) instead of aborting the scan at the first
    /// probe.
    pub(crate) check_marker_present: Option<bool>,
    /// When this baseline was captured, for [`PRE_DISPATCH_MIN_AGE_SECS`].
    ///
    /// (There is deliberately no "came from `--session-check-url`" flag. A
    /// login-shaped check URL like `/auth/session` needs no special-casing:
    /// [`classify`]'s login-URL rule already requires the *baseline* not to be
    /// login-shaped, and [`baseline_warning`] only flags a login URL reached by
    /// redirect. An operator-chosen 200 at `/auth/session` therefore trips
    /// neither.)
    pub(crate) captured_at: Instant,
}

/// A re-probe of the same endpoint, later in the scan.
#[derive(Debug, Clone)]
pub(crate) struct SessionProbe {
    pub(crate) status: u16,
    pub(crate) landing: String,
    pub(crate) body: String,
}

/// Verdict from comparing a [`SessionProbe`] against its [`SessionBaseline`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionState {
    /// Still authenticated, as far as we can tell.
    Alive,
    /// The session is gone; the payload explains which signal fired, verbatim
    /// into the stderr warning and the `error_message` of the meta envelope.
    Lost(String),
}

/// When a target's session is monitored at all.
///
/// Monitoring is opt-in-by-context: it costs requests, and on a target with no
/// credentials there is no session to lose. So it runs only when the operator
/// either supplied auth material (cookies, a `Cookie`/`Authorization` header)
/// or explicitly asked for a check via `--session-check` / `--session-check-url`.
pub(crate) fn monitoring_enabled(args: &ScanArgs, target: &Target) -> bool {
    if args.session_check.is_some() || args.session_check_url.is_some() {
        return true;
    }
    if !target.cookies.is_empty() {
        return true;
    }
    target
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("cookie") || k.eq_ignore_ascii_case("authorization"))
}

/// Compile `--session-check` once, up front, so a bad pattern is a startup
/// error instead of a per-probe surprise. Returns `Ok(None)` when the flag
/// wasn't given.
pub(crate) fn compile_session_check(args: &ScanArgs) -> Result<Option<regex::Regex>, regex::Error> {
    match &args.session_check {
        Some(p) => regex::Regex::new(p).map(Some),
        None => Ok(None),
    }
}

/// Should this run abort the affected target on loss (`--on-session-loss abort`,
/// the default) rather than keep spending requests against a login page?
pub(crate) fn aborts_on_loss(args: &ScanArgs) -> bool {
    !args.on_session_loss_mode().eq_ignore_ascii_case("continue")
}

/// Is the pre-dispatch re-probe worth a request yet? See
/// [`PRE_DISPATCH_MIN_AGE_SECS`].
pub(crate) fn pre_dispatch_probe_due(baseline: &SessionBaseline) -> bool {
    baseline.captured_at.elapsed().as_secs() >= PRE_DISPATCH_MIN_AGE_SECS
}

/// Build the baseline from the preflight GET's own response. Called from
/// `preflight_content_type`, which has all of it in hand — capturing the
/// authenticated fingerprint therefore costs zero extra requests.
///
/// `final_url` must be the response's own URL (`resp.url()`), not the request
/// URL. Under `--follow-redirects` reqwest has already walked the chain, so an
/// app that serves `/` by redirecting an authenticated user to `/auth/home`
/// lands somewhere the request URL never mentions. Passing the request URL here
/// made every probe compare `/?q=1` against `/auth/home` and read the `auth`
/// segment as a login redirect — a guaranteed false `SESSION_LOST`.
pub(crate) fn baseline_from_preflight(
    request_url: &url::Url,
    final_url: &url::Url,
    status: u16,
    headers: &reqwest::header::HeaderMap,
    body: &str,
    check_re: Option<&regex::Regex>,
) -> SessionBaseline {
    SessionBaseline {
        status,
        landing: resolve_landing(request_url, Some(final_url), status, headers),
        has_login_form: has_login_form(body),
        body_len: body.len(),
        check_marker_present: check_re.map(|re| re.is_match(body)),
        captured_at: Instant::now(),
    }
}

/// Capture the baseline from `--session-check-url` rather than from the
/// preflight response.
///
/// Necessary because every later probe will ask *that* endpoint: baselining
/// `/dashboard` and then probing `/api/me` compares two different pages, and
/// `/dashboard` never tells us what an authenticated `/api/me` looks like. The
/// sharpest edge is the login-URL signal — a perfectly reasonable check URL
/// like `/auth/session` reads as a login page against a `/dashboard` baseline
/// and would abort the scan on the first probe.
///
/// Costs one request per target, and only when the operator explicitly asked
/// for a check URL.
pub(crate) async fn baseline_from_check_url(
    target: &Target,
    check_url: &str,
    check_re: Option<&regex::Regex>,
) -> Option<SessionBaseline> {
    let probe = probe_session(target, Some(check_url)).await?;
    Some(SessionBaseline {
        status: probe.status,
        landing: probe.landing,
        has_login_form: has_login_form(&probe.body),
        body_len: probe.body.len(),
        check_marker_present: check_re.map(|re| re.is_match(&probe.body)),
        captured_at: Instant::now(),
    })
}

/// Is this baseline unusable as a reference for "authenticated"? Returns the
/// operator-facing explanation, or `None` when it looks fine.
///
/// Two ways it can be unusable, and both are silent catastrophes without this
/// check:
///
/// - **The credentials were already stale.** The login page becomes the
///   baseline, so no later probe can ever detect a *change* and the run reports
///   a clean bill of health for a target that was never tested — the worst
///   version of the bug this module exists to kill.
/// - **`--session-check` never matched.** A typo (`'Sign Out'` for
///   `'Sign out'`), or a marker that lives on a different page than the scan
///   target, makes the pattern miss on every probe. Since the pattern is
///   authoritative, that is an unconditional `Lost` verdict — and under the
///   default `abort` it would skip the whole host and exit 2 for no reason.
///
/// The caller records this as `SESSION_LOST` rather than only logging it, so
/// the structured output and exit code agree with the warning.
pub(crate) fn baseline_warning(baseline: &SessionBaseline) -> Option<String> {
    if baseline.check_marker_present == Some(false) {
        return Some(format!(
            "--session-check pattern did not match the baseline response (HTTP {}, {} bytes from {}) — the marker is wrong, is on a different page, or the credentials are already invalid",
            baseline.status, baseline.body_len, baseline.landing
        ));
    }
    // A *redirect* onto an unambiguous login URL, not merely living at one, and
    // not merely one whose path contains an auth-ish word.
    //
    // Two narrowings, both because this verdict costs the operator an exit code
    // and there is no second signal to corroborate it: every other rule in this
    // module compares a probe against a baseline and fires on a *change*, which
    // is what makes a weak token safe there. Here there is nothing to compare —
    // the baseline IS the evidence — so the token has to carry the claim alone.
    //
    // 1. Redirect only. `/auth/home` served with 200 is an ordinary
    //    authenticated landing page.
    // 2. [`is_login_endpoint_url`], not [`is_login_url`]. An app that serves its
    //    authenticated home by redirecting `/` to `/auth/home` — the example
    //    this module's own docs use for "ordinary authenticated landing page" —
    //    otherwise reported SESSION_LOST, `incomplete: true`, and exit 2 on a
    //    session nobody had been logged out of, whenever the scan ran without
    //    `--follow-redirects` (the default). Reproduced end-to-end.
    let redirected_to_login =
        (300..400).contains(&baseline.status) && is_login_endpoint_url(&baseline.landing);
    if baseline.status == 401 || baseline.has_login_form || redirected_to_login {
        return Some(format!(
            "preflight response already looks unauthenticated (HTTP {}, landed on {}) — no later probe can detect a change from this baseline, so check the supplied credentials",
            baseline.status, baseline.landing
        ));
    }
    None
}

/// A baseline that *might* be a login wall, stated as a heads-up rather than a
/// verdict. Returns the operator-facing text, or `None` when there is nothing
/// ambiguous about it.
///
/// This is the half [`baseline_warning`] gave up when it narrowed to
/// [`is_login_endpoint_url`]. A preflight that redirects to `/oauth2/authorize`
/// or `/sso/` really can be a dead SSO session — and if it is, no later probe
/// can detect a change, so the run would end `"clean"`. But it is just as
/// likely an authenticated app whose home lives behind an auth-shaped redirect,
/// and that case must not cost an exit code (see [`baseline_warning`]).
///
/// So it is printed and nothing else: no `SESSION_LOST` entry, no effect on
/// `meta.incomplete` or the exit code. The operator gets the one thing dalfox
/// genuinely knows — "your credentials may already be stale here, and I cannot
/// tell" — and `--session-check` settles it definitively.
pub(crate) fn baseline_advisory(baseline: &SessionBaseline) -> Option<String> {
    if baseline_warning(baseline).is_some() {
        return None; // Already reported, and far more definitely.
    }
    let ambiguous_redirect = (300..400).contains(&baseline.status)
        && is_login_url(&baseline.landing)
        && !is_login_endpoint_url(&baseline.landing);
    ambiguous_redirect.then(|| {
        format!(
            "preflight redirects to an auth-shaped URL ({}) — normal for an app whose authenticated home lives there, but it is also what an expired SSO session looks like, and dalfox cannot tell the two apart. If the credentials are stale this run cannot detect it; pass --session-check '<marker>' to make the check exact",
            baseline.landing
        )
    })
}

/// Re-probe the session with a single plain GET carrying the same
/// headers/UA/cookies the scan uses. `--session-check-url` overrides the
/// endpoint (useful when the scan target itself is a public page but the app
/// has a cheap authenticated endpoint to ask).
///
/// Returns `None` when the probe itself failed. That is deliberate: a network
/// blip must not be reported as a dead session, so an unanswered probe leaves
/// the previous verdict standing.
pub(crate) async fn probe_session(
    target: &Target,
    check_url: Option<&str>,
) -> Option<SessionProbe> {
    let client = target.build_client().ok()?;
    let probe_url = match check_url {
        Some(u) => url::Url::parse(u).ok()?,
        None => target.url.clone(),
    };
    let rb =
        crate::utils::http::apply_headers_ua_cookies(client.get(probe_url.clone()), target, None);
    crate::record_outbound_request().await;
    let resp = rb.send().await.ok()?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let final_url = resp.url().clone();
    let body = crate::utils::http::read_body_capped(resp, PROBE_BODY_CAP_BYTES)
        .await
        .unwrap_or_default();
    Some(SessionProbe {
        status,
        landing: resolve_landing(&probe_url, Some(&final_url), status, &headers),
        body,
    })
}

/// Where a response "landed". With `--follow-redirects` reqwest already walked
/// the chain, so `final_url` is the answer. Without it a session-expiry 302 is
/// the *whole* signal, and the only record of the login page is the `Location`
/// header — resolve it against the request URL so both modes produce a
/// comparable value.
fn resolve_landing(
    request_url: &url::Url,
    final_url: Option<&url::Url>,
    status: u16,
    headers: &reqwest::header::HeaderMap,
) -> String {
    if (300..400).contains(&status)
        && let Some(loc) = headers.get(reqwest::header::LOCATION)
        && let Ok(loc) = loc.to_str()
        && let Ok(abs) = request_url.join(loc)
    {
        return abs.to_string();
    }
    final_url.unwrap_or(request_url).to_string()
}

/// Compare a probe against its baseline.
///
/// `check_re` (`--session-check`) is authoritative when present: the operator
/// told us exactly what an authenticated response looks like, so nothing is
/// inferred on top of it. Otherwise three signals are consulted, each chosen
/// because it is hard to trip accidentally on a normal page:
///
/// 1. the status moved into 401/403 from something else,
/// 2. the request now lands on a login-shaped URL it didn't land on before,
/// 3. a password field appeared where the authenticated page had none.
///
/// Everything softer — body length, title, generic content drift — is left out
/// on purpose. `abort` is the default, so a false positive costs the operator a
/// whole scan; the signals have to be worth that.
///
/// `waf_detected` suppresses the 403 branch. A bare GET returning 403 after a
/// heavy injection run is one of the most common outcomes of scanning a
/// WAF-fronted origin, and monitoring auto-enables for anyone passing
/// `--cookies` — including cookies that carry no session at all (consent, A/B).
/// Calling that "session lost" would abort the host group and flip the exit
/// code on a target that was never logged out. When a WAF was fingerprinted we
/// have a better explanation than a guess, so we take it; operators who need
/// 403-as-expiry on a WAF-fronted origin have `--session-check`.
pub(crate) fn classify(
    baseline: &SessionBaseline,
    probe: &SessionProbe,
    check_re: Option<&regex::Regex>,
    waf_detected: bool,
) -> SessionState {
    if let Some(re) = check_re {
        return if re.is_match(&probe.body) {
            SessionState::Alive
        } else {
            SessionState::Lost(format!(
                "--session-check pattern /{}/ no longer matches the response body (HTTP {})",
                re.as_str(),
                probe.status
            ))
        };
    }

    let status_flipped = probe.status != baseline.status;
    if probe.status == 401 && status_flipped {
        return SessionState::Lost(format!(
            "HTTP 401 on the unmodified target request (baseline was HTTP {})",
            baseline.status
        ));
    }
    if probe.status == 403 && status_flipped {
        if waf_detected {
            crate::dbg_log!(
                "session: ignoring HTTP 403 on {} — a WAF is fingerprinted on this target, so a block is the likelier cause than an expired session",
                probe.landing
            );
        } else {
            return SessionState::Lost(format!(
                "HTTP 403 on the unmodified target request (baseline was HTTP {}) (session expired, or the origin is now blocking this client)",
                baseline.status
            ));
        }
    }

    if probe.landing != baseline.landing
        && is_login_url(&probe.landing)
        && !is_login_url(&baseline.landing)
    {
        return SessionState::Lost(format!(
            "request now lands on a login URL ({}); baseline landed on {}",
            probe.landing, baseline.landing
        ));
    }

    // Compared over the span the baseline actually saw, not the whole probe
    // body: the preflight GET asks for `Range: bytes=0-8191` while a probe reads
    // up to PROBE_BODY_CAP_BYTES, so on a Range-honoring origin a password field
    // past byte 8192 is invisible to the baseline and visible to every probe.
    // That asymmetry was a permanent false SESSION_LOST on any SPA shell big
    // enough to have its login markup below the fold. Truncating errs toward a
    // missed signal, never a fabricated one.
    let comparable = prefix_bytes(&probe.body, baseline.body_len);
    if !baseline.has_login_form && has_login_form(comparable) {
        return SessionState::Lost(format!(
            "response now contains a login form (password field); baseline had none (HTTP {}, compared over the first {} bytes)",
            probe.status,
            comparable.len()
        ));
    }

    SessionState::Alive
}

/// The longest prefix of `s` that is at most `n` bytes and ends on a `char`
/// boundary. (`str::floor_char_boundary` is still unstable.)
fn prefix_bytes(s: &str, n: usize) -> &str {
    if s.len() <= n {
        return s;
    }
    let mut end = n;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Which of the two re-probe points a check is running from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbePhase {
    /// Just before a target's injection stage starts. Throttled by
    /// [`PRE_DISPATCH_MIN_AGE_SECS`] — on a short run this is the baseline
    /// request again, for nothing.
    PreDispatch,
    /// Right after a target's injection stage finishes. Never throttled: this
    /// is the probe that catches a session that died *during* the scan, which
    /// is the whole failure mode.
    PostScan,
}

/// The live half of session monitoring: owns the compiled `--session-check`,
/// the per-target baselines captured during preflight, and the loss ledger the
/// meta envelope reads. Constructed once per run by the scan loop, then shared
/// across the per-target tasks.
pub(crate) struct SessionMonitor {
    check_re: Option<regex::Regex>,
    check_url: Option<String>,
    /// `--on-session-loss abort`: stop the affected target and skip the rest
    /// of its host group rather than spend requests on a login page.
    pub(crate) abort_on_loss: bool,
    silence: bool,
    baselines: Arc<Mutex<HashMap<String, SessionBaseline>>>,
    lost: Arc<Mutex<HashMap<String, String>>>,
}

impl SessionMonitor {
    /// Build a monitor, or `None` when this run has nothing to monitor —
    /// no target carried credentials, so preflight captured no baselines and
    /// every probe would be a wasted request. The scan loop keeps its
    /// zero-overhead path for that (overwhelmingly common) case.
    ///
    /// The regex is already known to compile: `run_scan` validates it before
    /// any request goes out, so a pattern that fails here can only mean the
    /// two call sites drifted — fall back to the heuristics rather than
    /// silently treating every probe as a loss.
    pub(crate) async fn new(
        args: &ScanArgs,
        baselines: Arc<Mutex<HashMap<String, SessionBaseline>>>,
        lost: Arc<Mutex<HashMap<String, String>>>,
    ) -> Option<Arc<Self>> {
        if baselines.lock().await.is_empty() {
            return None;
        }
        Some(Arc::new(Self {
            check_re: compile_session_check(args).ok().flatten(),
            check_url: args.session_check_url.clone(),
            abort_on_loss: aborts_on_loss(args),
            silence: args.silence,
            baselines,
            lost,
        }))
    }

    /// Re-probe `target` and report whether its session is gone, recording the
    /// loss (once) and warning on stderr. `None` means "keep scanning": either
    /// still authenticated, not monitored, throttled, or the probe itself
    /// failed — a network blip must never be reported as a dead session.
    ///
    /// stderr, not stdout, so the warning reaches the operator without
    /// corrupting the JSON/JSONL/SARIF payload a script is parsing.
    pub(crate) async fn check(&self, target: &Target, phase: ProbePhase) -> Option<String> {
        let key = target.url.to_string();
        let baseline = self.baselines.lock().await.get(&key).cloned()?;
        if phase == ProbePhase::PreDispatch && !pre_dispatch_probe_due(&baseline) {
            return None;
        }
        // Already reported for this target — don't re-probe or duplicate the
        // warning when the post-scan check follows a pre-dispatch `continue`.
        if self.lost.lock().await.contains_key(&key) {
            return None;
        }

        let probe = probe_session(target, self.check_url.as_deref()).await?;
        // A fingerprinted WAF changes what a 403 means — see `classify`.
        let waf_detected = target.waf_info.as_ref().is_some_and(|w| !w.is_empty());
        match classify(&baseline, &probe, self.check_re.as_ref(), waf_detected) {
            SessionState::Alive => {
                crate::dbg_log!("session alive ({:?}): {}", phase, key);
                None
            }
            SessionState::Lost(reason) => {
                self.lost.lock().await.insert(key.clone(), reason.clone());
                if !self.silence {
                    report_loss(&key, &reason, self.abort_on_loss);
                }
                Some(reason)
            }
        }
    }
}

/// One-shot session verdict for the single-target async front-ends (REST
/// server, MCP), which have no [`SessionMonitor`].
///
/// The CLI needs a monitor because it juggles a map of baselines, a 30s
/// pre-dispatch throttle, and a host-group abort policy. A server job is one
/// target with one baseline and one question, asked once when the scan ends:
/// *was the session still alive?* Everything else — which signals count, how a
/// WAF changes the meaning of 403, `--session-check` being authoritative —
/// comes from the same [`classify`] the CLI uses.
///
/// It exists as one shared function rather than two copies precisely because
/// these two front-ends have drifted before: the multipart and JSON body
/// injection fixes (#1260, #1261, #1263) each had to be applied again after
/// landing in only one of them.
///
/// `None` means "keep trusting this run" — still authenticated, or the probe
/// itself failed. A network blip must never be reported as a dead session.
pub(crate) async fn session_lost_after_scan(
    target: &Target,
    baseline: &SessionBaseline,
    args: &ScanArgs,
) -> Option<String> {
    let probe = probe_session(target, args.session_check_url.as_deref()).await?;
    let check_re = compile_session_check(args).ok().flatten();
    // A fingerprinted WAF changes what a 403 means — see `classify`.
    let waf_detected = target.waf_info.as_ref().is_some_and(|w| !w.is_empty());
    match classify(baseline, &probe, check_re.as_ref(), waf_detected) {
        SessionState::Alive => None,
        SessionState::Lost(reason) => Some(reason),
    }
}

/// Capture a baseline for a front-end that has no preflight response to reuse
/// (`skip_ast_analysis`, or a `--session-check-url` pointing elsewhere).
///
/// Costs one request, and only when the job actually carries credentials — see
/// [`monitoring_enabled`]. Returns `None` when the probe failed, which leaves
/// monitoring off for that job rather than inventing a baseline.
pub(crate) async fn capture_baseline(target: &Target, args: &ScanArgs) -> Option<SessionBaseline> {
    let check_re = compile_session_check(args).ok().flatten();
    baseline_from_check_url(
        target,
        args.session_check_url
            .as_deref()
            .unwrap_or(target.url.as_str()),
        check_re.as_ref(),
    )
    .await
}

/// The single `SESSION LOST` stderr line, shared by the mid-scan probes and the
/// preflight baseline check so both read identically.
///
/// stderr, not stdout, so the warning reaches the operator without corrupting
/// the JSON/JSONL/SARIF payload a script is parsing. Both interpolations are
/// sanitized: `reason` embeds a `Location` header the origin controls, and the
/// URL can come from a target list of arbitrary provenance.
pub(crate) fn report_loss(target_url: &str, reason: &str, abort_on_loss: bool) {
    let ts = chrono::Local::now().format("%-I:%M%p").to_string();
    let action = if abort_on_loss {
        "aborting this target and the rest of this host (--on-session-loss abort)"
    } else {
        "continuing; results for this target are incomplete (--on-session-loss continue)"
    };
    crate::ceprintln!(
        "\x1b[90m{}\x1b[0m \x1b[31mSESSION LOST\x1b[0m {} — {}; {}",
        ts,
        crate::utils::log::sanitize_log_message(target_url),
        crate::utils::log::sanitize_log_message(reason),
        action
    );
}

/// The advisory counterpart of [`report_loss`]: same stream and sanitizing,
/// deliberately not the same word. `SESSION LOST` is a verdict that costs an
/// exit code; this one is `SESSION?` — a thing to look at, not a failure.
pub(crate) fn report_baseline_advisory(target_url: &str, note: &str) {
    let ts = chrono::Local::now().format("%-I:%M%p").to_string();
    crate::ceprintln!(
        "\x1b[90m{}\x1b[0m \x1b[33mSESSION?\x1b[0m {} — {}",
        ts,
        crate::utils::log::sanitize_log_message(target_url),
        crate::utils::log::sanitize_log_message(note)
    );
}

/// Does this URL look like a login endpoint?
///
/// Matched on whole path *tokens*, not substrings: a substring test for "auth"
/// flags `/authors/42` and one for "sso" flags `/lessons`. Each path segment is
/// tested twice — as-is split on punctuation (`/oauth2/authorize`), and with
/// punctuation squeezed out, so the Rails-style `/users/sign_in` and its
/// `sign-in` spelling collapse onto the same `signin` token without a substring
/// test's collateral damage (`/single-sign-on-explained` squeezes to
/// `singlesignonexplained`, which matches nothing).
///
/// Query strings are ignored — `?next=/login` appears on plenty of pages that
/// are perfectly authenticated.
///
/// Used by [`classify`], where the verdict additionally requires the landing to
/// have *changed* from the baseline's. That corroboration is what makes the
/// weak half of the token list (`auth`, `sso`, `oauth`, …) safe here: moving
/// from `/dashboard` to `/oauth2/authorize` mid-scan really is a logout.
/// A rule with no such comparison must use [`is_login_endpoint_url`].
fn is_login_url(raw: &str) -> bool {
    const LOGIN_TOKENS: &[&str] = &[
        "login",
        "signin",
        "logon",
        "sso",
        "oauth",
        "auth",
        "authenticate",
        "authorize",
    ];
    path_has_token(raw, LOGIN_TOKENS)
}

/// Does this URL name a login endpoint *by itself*, with no corroborating
/// signal?
///
/// The strict half of [`is_login_url`]: only tokens that name the sign-in page
/// itself. `auth`, `sso`, `oauth`, `authorize` and `authenticate` are dropped
/// because they are every bit as common in *authenticated* areas —
/// `/auth/home`, `/sso/dashboard`, `/authorize-payment` — and the rules that
/// call this have no "it changed" evidence to lean on. A real logout redirect
/// still lands on `/login`, `/signin`, `/users/sign_in`, `/auth/login` or
/// `/sso/login`, all of which keep matching; what stops matching is the app
/// whose authenticated home merely *lives* under an auth-shaped prefix.
fn is_login_endpoint_url(raw: &str) -> bool {
    const LOGIN_ENDPOINT_TOKENS: &[&str] = &["login", "signin", "logon"];
    path_has_token(raw, LOGIN_ENDPOINT_TOKENS)
}

/// Whole-token path match shared by the two rules above. Each segment is tested
/// twice — split on punctuation (`/oauth2/authorize`), and with punctuation
/// squeezed out, so `sign_in` and `sign-in` collapse onto `signin`.
fn path_has_token(raw: &str, tokens: &[&str]) -> bool {
    let path = match url::Url::parse(raw) {
        Ok(u) => u.path().to_ascii_lowercase(),
        // Not absolute (shouldn't happen — `resolve_landing` always joins
        // against an absolute URL — but a caller could pass anything).
        Err(_) => raw.to_ascii_lowercase(),
    };
    path.split('/').any(|segment| {
        let squeezed: String = segment
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect();
        tokens.contains(&squeezed.as_str())
            || segment
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|tok| tokens.contains(&tok))
    })
}

/// Does this body contain a password input?
///
/// A deliberately literal scan for the three ways `type=password` is actually
/// written in HTML. Parsing the document would catch exotic spacing
/// (`type = "password"`), but that spelling is vanishingly rare in real output
/// and a full parse on every probe is not worth it. The cost of missing one is
/// a missed signal, not a false alarm.
fn has_login_form(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("type=\"password\"")
        || lower.contains("type='password'")
        || lower.contains("type=password")
}

#[cfg(test)]
mod tests;
