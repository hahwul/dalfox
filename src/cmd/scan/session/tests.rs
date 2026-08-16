use super::*;

/// Baseline with a generous `body_len` so the login-form comparison isn't
/// truncated unless a test deliberately sets a small budget.
fn baseline(status: u16, landing: &str, has_login_form: bool) -> SessionBaseline {
    SessionBaseline {
        status,
        landing: landing.to_string(),
        has_login_form,
        body_len: 8192,
        check_marker_present: None,
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

/// `classify` with no `--session-check` and no WAF fingerprinted — the
/// plain heuristic path most tests exercise.
fn verdict(b: &SessionBaseline, p: &SessionProbe) -> SessionState {
    classify(b, p, None, false)
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
    assert_eq!(verdict(&b, &p), SessionState::Alive);
}

#[test]
fn status_flip_to_401_is_loss() {
    let b = baseline(200, "https://app.test/dashboard", false);
    let p = probe(401, "https://app.test/dashboard", "");
    assert!(lost_reason(&verdict(&b, &p)).contains("HTTP 401"));
}

#[test]
fn status_flip_to_403_is_loss_when_no_waf_is_in_play() {
    let b = baseline(200, "https://app.test/dashboard", false);
    let p = probe(403, "https://app.test/dashboard", "");
    assert!(lost_reason(&verdict(&b, &p)).contains("HTTP 403"));
}

// A WAF that starts blocking after a heavy injection run answers a bare GET
// with 403 too. Calling that "session lost" would abort the whole host
// group and flip the exit code on a target nobody logged out of — so once a
// WAF is fingerprinted, 403 stops being a session signal.
#[test]
fn status_flip_to_403_is_not_a_loss_when_a_waf_is_fingerprinted() {
    let b = baseline(200, "https://app.test/dashboard", false);
    let p = probe(403, "https://app.test/dashboard", "");
    assert_eq!(classify(&b, &p, None, true), SessionState::Alive);
    // 401 is unambiguous and survives the WAF carve-out.
    let p401 = probe(401, "https://app.test/dashboard", "");
    assert!(lost_reason(&classify(&b, &p401, None, true)).contains("HTTP 401"));
}

// A target that answered 403 from the start (e.g. an endpoint the
// credentials never had access to) must not be re-reported as a *loss* on
// every probe — nothing changed.
#[test]
fn baseline_that_was_already_401_does_not_report_loss() {
    let b = baseline(401, "https://app.test/api", false);
    let p = probe(401, "https://app.test/api", "");
    assert_eq!(verdict(&b, &p), SessionState::Alive);
}

#[test]
fn redirect_to_login_url_is_loss() {
    let b = baseline(200, "https://app.test/dashboard", false);
    let p = probe(302, "https://app.test/login?next=/dashboard", "");
    assert!(lost_reason(&verdict(&b, &p)).contains("login URL"));
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

// The strict variant keeps only the tokens that name the sign-in page
// itself, for the one rule that has no baseline-vs-probe change to lean on.
#[test]
fn login_endpoint_urls_exclude_the_ambiguous_auth_tokens() {
    for named in [
        "https://app.test/login",
        "https://app.test/auth/login",
        "https://app.test/users/sign-in",
        "https://app.test/logon",
    ] {
        assert!(is_login_endpoint_url(named), "{named}");
    }
    for ambiguous in [
        "https://app.test/auth/home",
        "https://app.test/sso/dashboard",
        "https://app.test/oauth2/authorize",
        "https://app.test/authenticate-device",
    ] {
        assert!(!is_login_endpoint_url(ambiguous), "{ambiguous}");
        // …all of which the wider rule still matches, by design.
        assert!(is_login_url(ambiguous), "{ambiguous}");
    }
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
    assert!(lost_reason(&verdict(&b, &p)).contains("login form"));
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
    assert_eq!(verdict(&b, &p), SessionState::Alive);
}

// The preflight GET asks for `Range: bytes=0-8191`; a probe reads up to
// 64 KiB. On a Range-honoring origin that means a password field deep in a
// large SPA shell is invisible to the baseline and visible to every probe —
// a permanent false SESSION_LOST. The comparison is bounded by what the
// baseline could actually see.
#[test]
fn login_form_past_the_baseline_byte_budget_is_not_a_loss() {
    let mut b = baseline(200, "https://app.test/dashboard", false);
    b.body_len = 64;
    let body = format!("{}<input type=\"password\">", "x".repeat(200));
    let p = probe(200, "https://app.test/dashboard", &body);
    assert_eq!(
        verdict(&b, &p),
        SessionState::Alive,
        "a password field the baseline's byte budget never covered is not evidence of anything"
    );
    // Inside the budget it still fires.
    b.body_len = 4096;
    assert!(lost_reason(&verdict(&b, &p)).contains("login form"));
}

#[test]
fn prefix_bytes_never_splits_a_char() {
    // 'é' is two bytes; asking for 2 must not slice it in half.
    assert_eq!(prefix_bytes("aé", 2), "a");
    assert_eq!(prefix_bytes("aé", 3), "aé");
    assert_eq!(prefix_bytes("abc", 99), "abc");
    assert_eq!(prefix_bytes("abc", 0), "");
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
    assert_eq!(classify(&b, &p, Some(&re), false), SessionState::Alive);
}

#[test]
fn session_check_regex_miss_is_loss_even_when_page_looks_normal() {
    let re = regex::Regex::new("Signed in as").unwrap();
    let b = baseline(200, "https://app.test/dashboard", false);
    let p = probe(200, "https://app.test/dashboard", "<h1>Dashboard</h1>");
    assert!(lost_reason(&classify(&b, &p, Some(&re), false)).contains("--session-check"));
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
        on_session_loss_arg: Some("continue".to_string()),
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
        captured_at: Instant::now() - std::time::Duration::from_secs(PRE_DISPATCH_MIN_AGE_SECS + 1),
        ..b
    };
    assert!(pre_dispatch_probe_due(&stale));
}

#[test]
fn a_login_page_baseline_is_flagged_as_already_unauthenticated() {
    for b in [
        // Redirected to the login wall…
        baseline(302, "https://app.test/login", false),
        // …rejected outright…
        baseline(401, "https://app.test/dashboard", false),
        // …or rendering the login form inline.
        baseline(200, "https://app.test/dashboard", true),
    ] {
        assert!(
            baseline_warning(&b)
                .expect("unusable baseline")
                .contains("already looks unauthenticated")
        );
    }
    assert!(baseline_warning(&baseline(200, "https://app.test/dashboard", false)).is_none());
}

// A path that merely *contains* an auth-ish word is not evidence of
// anything: `/auth/home` and `/sso/dashboard` are ordinary authenticated
// landing pages, and this verdict costs the operator exit code 2.
//
// Neither the status nor the token alone is enough — it takes both. The
// 302 case is a reproduced false positive: an app that serves its
// authenticated home by redirecting `/` to `/auth/home` (no
// `--follow-redirects`, the default) reported SESSION_LOST,
// `incomplete: true` and exit 2 with a perfectly live session.
#[test]
fn a_login_shaped_path_is_not_flagged_without_a_login_endpoint_token() {
    assert!(baseline_warning(&baseline(200, "https://app.test/auth/home", false)).is_none());
    assert!(baseline_warning(&baseline(200, "https://app.test/sso/dashboard", false)).is_none());
    assert!(
        baseline_warning(&baseline(302, "https://app.test/auth/home", false)).is_none(),
        "an authenticated app that redirects / to /auth/home is not a logged-out session"
    );
    assert!(baseline_warning(&baseline(302, "https://app.test/sso/dashboard", false)).is_none());
    assert!(baseline_warning(&baseline(302, "https://app.test/oauth2/authorize", false)).is_none());
    // …while a redirect onto the sign-in page itself still is.
    for landing in [
        "https://app.test/login",
        "https://app.test/auth/login",
        "https://app.test/sso/login",
        "https://app.test/users/sign_in",
    ] {
        assert!(
            baseline_warning(&baseline(302, landing, false))
                .expect("a redirect onto the login page is still flagged")
                .contains("already looks unauthenticated"),
            "{landing}"
        );
    }
    // The mid-scan rule keeps the wider token list: there the landing must
    // have *changed*, which is the corroboration this rule lacks.
    let b = baseline(200, "https://app.test/dashboard", false);
    let p = probe(302, "https://app.test/oauth2/authorize", "");
    assert!(lost_reason(&verdict(&b, &p)).contains("login URL"));
}

// What the narrowed rule gives up is not dropped, only demoted: the
// ambiguous redirect is still surfaced, as a heads-up with no
// SESSION_LOST entry, no `incomplete`, and no exit code attached.
#[test]
fn an_ambiguous_auth_redirect_is_advised_but_not_condemned() {
    for landing in [
        "https://app.test/auth/home",
        "https://app.test/sso/dashboard",
        "https://app.test/oauth2/authorize",
    ] {
        let b = baseline(302, landing, false);
        assert!(baseline_warning(&b).is_none(), "{landing}");
        assert!(
            baseline_advisory(&b)
                .expect("ambiguous redirect is advised")
                .contains("--session-check"),
            "{landing}"
        );
    }

    // Nothing ambiguous about these, so no advisory noise.
    assert!(baseline_advisory(&baseline(200, "https://app.test/auth/home", false)).is_none());
    assert!(baseline_advisory(&baseline(200, "https://app.test/dashboard", false)).is_none());
    assert!(baseline_advisory(&baseline(302, "https://app.test/home", false)).is_none());
    // A baseline already condemned by `baseline_warning` is not also
    // advised — one line per target, and the verdict is the louder one.
    assert!(baseline_advisory(&baseline(302, "https://app.test/login", false)).is_none());
}

// A `--session-check` marker that isn't on the baseline page (a typo, or a
// marker that lives elsewhere) makes every probe report a loss. Caught here
// instead of aborting the host at the first probe with no explanation.
#[test]
fn a_session_check_marker_missing_from_the_baseline_is_flagged_up_front() {
    let mut b = baseline(200, "https://app.test/dashboard", false);
    b.check_marker_present = Some(false);
    assert!(
        baseline_warning(&b)
            .expect("unusable baseline")
            .contains("--session-check")
    );

    b.check_marker_present = Some(true);
    assert!(baseline_warning(&b).is_none());
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
    let b = baseline_from_preflight(&req, &req, 200, &headers, "<h1>hi</h1>", None);
    assert_eq!(b.status, 200);
    assert_eq!(b.landing, "https://app.test/dashboard");
    assert!(!b.has_login_form);
    assert_eq!(b.body_len, 11);
    assert_eq!(b.check_marker_present, None);
}

// Under `--follow-redirects` reqwest has already walked the chain, so the
// baseline has to record where the response actually came from. Recording
// the *request* URL instead meant an app that redirects an authenticated
// user to `/auth/home` compared `/?q=1` against `/auth/home` on every
// probe, read the `auth` segment as a login redirect, and aborted the scan.
#[test]
fn baseline_records_the_post_redirect_landing_url() {
    let req = url::Url::parse("https://app.test/?q=1").unwrap();
    let landed = url::Url::parse("https://app.test/auth/home").unwrap();
    let headers = reqwest::header::HeaderMap::new();
    let b = baseline_from_preflight(&req, &landed, 200, &headers, "<h1>hi</h1>", None);
    assert_eq!(b.landing, "https://app.test/auth/home");

    // …and a probe landing in the same place is therefore unremarkable.
    let p = probe(200, "https://app.test/auth/home", "<h1>hi</h1>");
    assert_eq!(verdict(&b, &p), SessionState::Alive);
}

#[test]
fn baseline_from_preflight_records_whether_the_check_marker_matched() {
    let req = url::Url::parse("https://app.test/dashboard").unwrap();
    let headers = reqwest::header::HeaderMap::new();
    let re = regex::Regex::new("Sign out").unwrap();
    let hit = baseline_from_preflight(&req, &req, 200, &headers, "Sign out", Some(&re));
    assert_eq!(hit.check_marker_present, Some(true));
    let miss = baseline_from_preflight(&req, &req, 200, &headers, "Welcome", Some(&re));
    assert_eq!(miss.check_marker_present, Some(false));
}
