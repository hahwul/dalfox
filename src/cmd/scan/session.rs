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

/// Minimum age a baseline must have before the *pre-dispatch* re-probe is worth
/// spending a request on. The baseline is captured during preflight, and on a
/// single-target run dispatch follows within milliseconds — re-probing there
/// would only re-confirm what we just measured. The post-scan probe is never
/// throttled: that is the one that actually catches a session dying mid-run.
const PRE_DISPATCH_MIN_AGE_SECS: u64 = 30;

/// Cap on the probe response body we read. Only the login-form heuristic looks
/// at the body, and a login page's `<input type="password">` is never megabytes
/// deep; the cap keeps a hostile or merely enormous response from turning a
/// cheap liveness check into a memory event.
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
    /// Coarse body-shape signal. Not a decision input (page sizes swing wildly
    /// between renders); carried so the debug line can show the before/after.
    pub(crate) body_len: usize,
    /// When this baseline was captured, for [`PRE_DISPATCH_MIN_AGE_SECS`].
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
    !args.on_session_loss.eq_ignore_ascii_case("continue")
}

/// Is the pre-dispatch re-probe worth a request yet? See
/// [`PRE_DISPATCH_MIN_AGE_SECS`].
pub(crate) fn pre_dispatch_probe_due(baseline: &SessionBaseline) -> bool {
    baseline.captured_at.elapsed().as_secs() >= PRE_DISPATCH_MIN_AGE_SECS
}

/// Build the baseline from the preflight GET's own status/headers/body. Called
/// from `preflight_content_type`, which has all three in hand — capturing the
/// authenticated fingerprint therefore costs zero extra requests.
pub(crate) fn baseline_from_preflight(
    request_url: &url::Url,
    status: u16,
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> SessionBaseline {
    SessionBaseline {
        status,
        landing: resolve_landing(request_url, None, status, headers),
        has_login_form: has_login_form(body),
        body_len: body.len(),
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
) -> Option<SessionBaseline> {
    let probe = probe_session(target, Some(check_url)).await?;
    Some(SessionBaseline {
        status: probe.status,
        landing: probe.landing,
        has_login_form: has_login_form(&probe.body),
        body_len: probe.body.len(),
        captured_at: Instant::now(),
    })
}

/// Did the *baseline itself* already look unauthenticated?
///
/// If the credentials were stale before the first payload went out, no later
/// probe can ever report a "loss" — the login page is the baseline, so every
/// comparison matches. That is the worst version of the bug this module exists
/// to kill, so it gets its own up-front warning instead of a silent clean run.
pub(crate) fn baseline_looks_unauthenticated(baseline: &SessionBaseline) -> bool {
    baseline.status == 401 || baseline.has_login_form || is_login_url(&baseline.landing)
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
pub(crate) fn classify(
    baseline: &SessionBaseline,
    probe: &SessionProbe,
    check_re: Option<&regex::Regex>,
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

    if (probe.status == 401 || probe.status == 403) && probe.status != baseline.status {
        // 403 is included because plenty of apps answer an expired session with
        // it, but it is also what an origin/WAF returns once it decides to block
        // the scanner — say so rather than assert a cause we can't distinguish.
        let hint = if probe.status == 403 {
            " (session expired, or the origin/WAF is now blocking this client)"
        } else {
            ""
        };
        return SessionState::Lost(format!(
            "HTTP {} on the unmodified target request (baseline was HTTP {}){}",
            probe.status, baseline.status, hint
        ));
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

    if !baseline.has_login_form && has_login_form(&probe.body) {
        return SessionState::Lost(format!(
            "response now contains a login form (password field); baseline had none (HTTP {}, {} bytes vs {} at baseline)",
            probe.status,
            probe.body.len(),
            baseline.body_len
        ));
    }

    SessionState::Alive
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
        match classify(&baseline, &probe, self.check_re.as_ref()) {
            SessionState::Alive => {
                crate::dbg_log!("session alive ({:?}): {}", phase, key);
                None
            }
            SessionState::Lost(reason) => {
                self.lost.lock().await.insert(key.clone(), reason.clone());
                if !self.silence {
                    let ts = chrono::Local::now().format("%-I:%M%p").to_string();
                    let action = if self.abort_on_loss {
                        "aborting this target and the rest of this host (--on-session-loss abort)"
                    } else {
                        "continuing; results for this target are incomplete (--on-session-loss continue)"
                    };
                    crate::ceprintln!(
                        "\x1b[90m{}\x1b[0m \x1b[31mSESSION LOST\x1b[0m {} — {}; {}",
                        ts,
                        key,
                        crate::utils::log::sanitize_log_message(&reason),
                        action
                    );
                }
                Some(reason)
            }
        }
    }
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
        LOGIN_TOKENS.contains(&squeezed.as_str())
            || segment
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|tok| LOGIN_TOKENS.contains(&tok))
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
mod tests {
    use super::*;

    fn baseline(status: u16, landing: &str, has_login_form: bool) -> SessionBaseline {
        SessionBaseline {
            status,
            landing: landing.to_string(),
            has_login_form,
            body_len: 1024,
            captured_at: Instant::now(),
        }
    }

    fn probe(status: u16, landing: &str, body: &str) -> SessionProbe {
        SessionProbe {
            status,
            landing: landing.to_string(),
            body: body.to_string(),
        }
    }

    fn lost_reason(state: &SessionState) -> &str {
        match state {
            SessionState::Lost(r) => r,
            SessionState::Alive => panic!("expected Lost, got Alive"),
        }
    }

    #[test]
    fn unchanged_response_is_alive() {
        let b = baseline(200, "https://app.test/dashboard", false);
        let p = probe(200, "https://app.test/dashboard", "<h1>Dashboard</h1>");
        assert_eq!(classify(&b, &p, None), SessionState::Alive);
    }

    #[test]
    fn status_flip_to_401_is_loss() {
        let b = baseline(200, "https://app.test/dashboard", false);
        let p = probe(401, "https://app.test/dashboard", "");
        assert!(lost_reason(&classify(&b, &p, None)).contains("HTTP 401"));
    }

    #[test]
    fn status_flip_to_403_is_loss_but_names_the_waf_alternative() {
        let b = baseline(200, "https://app.test/dashboard", false);
        let p = probe(403, "https://app.test/dashboard", "");
        assert!(lost_reason(&classify(&b, &p, None)).contains("WAF"));
    }

    // A target that answered 403 from the start (e.g. an endpoint the
    // credentials never had access to) must not be re-reported as a *loss* on
    // every probe — nothing changed.
    #[test]
    fn baseline_that_was_already_401_does_not_report_loss() {
        let b = baseline(401, "https://app.test/api", false);
        let p = probe(401, "https://app.test/api", "");
        assert_eq!(classify(&b, &p, None), SessionState::Alive);
    }

    #[test]
    fn redirect_to_login_url_is_loss() {
        let b = baseline(200, "https://app.test/dashboard", false);
        let p = probe(302, "https://app.test/login?next=/dashboard", "");
        assert!(lost_reason(&classify(&b, &p, None)).contains("login URL"));
    }

    // The whole point of token matching: `/authors/42` and `/lessons` are not
    // login pages, and flagging them would abort a scan by default.
    #[test]
    fn login_lookalike_paths_are_not_login_urls() {
        assert!(!is_login_url("https://app.test/authors/42"));
        assert!(!is_login_url("https://app.test/lessons"));
        assert!(!is_login_url(
            "https://app.test/blog/single-sign-on-explained"
        ));
        assert!(!is_login_url("https://app.test/dashboard?next=/login"));
    }

    #[test]
    fn real_login_paths_are_login_urls() {
        assert!(is_login_url("https://app.test/login"));
        assert!(is_login_url("https://app.test/users/sign_in"));
        assert!(is_login_url("https://app.test/users/sign-in"));
        assert!(is_login_url("https://app.test/log-in"));
        assert!(is_login_url("https://app.test/auth/callback"));
        assert!(is_login_url("https://app.test/SSO/redirect"));
        assert!(is_login_url("https://app.test/oauth2/authorize"));
    }

    #[test]
    fn appearing_login_form_is_loss() {
        let b = baseline(200, "https://app.test/dashboard", false);
        let p = probe(
            200,
            "https://app.test/dashboard",
            "<form><input type=\"password\" name=\"pw\"></form>",
        );
        assert!(lost_reason(&classify(&b, &p, None)).contains("login form"));
    }

    // Apps that render a sign-in modal in the header while authenticated would
    // otherwise trip the login-form signal on the very first probe.
    #[test]
    fn login_form_present_at_baseline_is_not_a_loss_signal() {
        let b = baseline(200, "https://app.test/dashboard", true);
        let p = probe(
            200,
            "https://app.test/dashboard",
            "<input type='password' id='pw'>",
        );
        assert_eq!(classify(&b, &p, None), SessionState::Alive);
    }

    #[test]
    fn session_check_regex_is_authoritative_when_it_matches() {
        let re = regex::Regex::new("Signed in as").unwrap();
        // Every heuristic signal fires — 401, a login URL, a password field —
        // yet the operator's own marker is present, so the session is alive.
        let b = baseline(200, "https://app.test/dashboard", false);
        let p = probe(
            401,
            "https://app.test/login",
            "Signed in as alice <input type=password>",
        );
        assert_eq!(classify(&b, &p, Some(&re)), SessionState::Alive);
    }

    #[test]
    fn session_check_regex_miss_is_loss_even_when_page_looks_normal() {
        let re = regex::Regex::new("Signed in as").unwrap();
        let b = baseline(200, "https://app.test/dashboard", false);
        let p = probe(200, "https://app.test/dashboard", "<h1>Dashboard</h1>");
        assert!(lost_reason(&classify(&b, &p, Some(&re))).contains("--session-check"));
    }

    #[test]
    fn password_field_detected_across_quoting_styles() {
        assert!(has_login_form("<input TYPE=\"PASSWORD\">"));
        assert!(has_login_form("<input type='password'>"));
        assert!(has_login_form("<input type=password required>"));
        assert!(!has_login_form("<input type=text name=password>"));
    }

    #[test]
    fn monitoring_is_off_without_credentials_and_on_with_them() {
        let url = url::Url::parse("https://app.test/").unwrap();
        let args = ScanArgs::default();
        let bare = Target::for_url(url.clone());
        assert!(!monitoring_enabled(&args, &bare));

        let with_cookie = Target {
            cookies: vec![("sid".to_string(), "abc".to_string())],
            ..Target::for_url(url.clone())
        };
        assert!(monitoring_enabled(&args, &with_cookie));

        let with_bearer = Target {
            headers: vec![("Authorization".to_string(), "Bearer x".to_string())],
            ..Target::for_url(url.clone())
        };
        assert!(monitoring_enabled(&args, &with_bearer));

        // Explicitly asked for, with no credentials of its own.
        let explicit = ScanArgs {
            session_check: Some("Sign out".to_string()),
            ..ScanArgs::default()
        };
        assert!(monitoring_enabled(&explicit, &bare));
    }

    #[test]
    fn abort_is_the_default_and_continue_opts_out() {
        assert!(aborts_on_loss(&ScanArgs::default()));
        assert!(!aborts_on_loss(&ScanArgs {
            on_session_loss: "continue".to_string(),
            ..ScanArgs::default()
        }));
    }

    // A freshly captured baseline must not trigger the pre-dispatch probe:
    // on a single-target run dispatch happens milliseconds after preflight.
    #[test]
    fn fresh_baseline_does_not_owe_a_pre_dispatch_probe() {
        let b = baseline(200, "https://app.test/", false);
        assert!(!pre_dispatch_probe_due(&b));
        let stale = SessionBaseline {
            captured_at: Instant::now()
                - std::time::Duration::from_secs(PRE_DISPATCH_MIN_AGE_SECS + 1),
            ..b
        };
        assert!(pre_dispatch_probe_due(&stale));
    }

    #[test]
    fn a_login_page_baseline_is_flagged_as_already_unauthenticated() {
        assert!(baseline_looks_unauthenticated(&baseline(
            302,
            "https://app.test/login",
            false
        )));
        assert!(baseline_looks_unauthenticated(&baseline(
            401,
            "https://app.test/dashboard",
            false
        )));
        assert!(baseline_looks_unauthenticated(&baseline(
            200,
            "https://app.test/dashboard",
            true
        )));
        assert!(!baseline_looks_unauthenticated(&baseline(
            200,
            "https://app.test/dashboard",
            false
        )));
    }

    #[test]
    fn landing_resolves_a_relative_location_when_redirects_are_not_followed() {
        let req = url::Url::parse("https://app.test/dashboard").unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::LOCATION,
            "/login?next=%2Fdashboard".parse().unwrap(),
        );
        assert_eq!(
            resolve_landing(&req, None, 302, &headers),
            "https://app.test/login?next=%2Fdashboard"
        );
        // Non-redirect statuses ignore any stray Location header.
        assert_eq!(
            resolve_landing(&req, None, 200, &headers),
            "https://app.test/dashboard"
        );
    }

    #[test]
    fn baseline_from_preflight_captures_the_landing_and_form_state() {
        let req = url::Url::parse("https://app.test/dashboard").unwrap();
        let headers = reqwest::header::HeaderMap::new();
        let b = baseline_from_preflight(&req, 200, &headers, "<h1>hi</h1>");
        assert_eq!(b.status, 200);
        assert_eq!(b.landing, "https://app.test/dashboard");
        assert!(!b.has_login_form);
        assert_eq!(b.body_len, 11);
    }
}
