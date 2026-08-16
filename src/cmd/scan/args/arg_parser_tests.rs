use super::*;
use crate::cmd::scan::DEFAULT_TIMEOUT_SECS;

/// Build the `ArgMatches` for a `ScanArgs`-flattened command line, the way
/// `main.rs` does for the `scan` subcommand.
#[cfg(test)]
fn matches_for(argv: &[&str]) -> clap::ArgMatches {
    use clap::{Args as _, CommandFactory, Parser};

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        scan: ScanArgs,
    }
    let _ = ScanArgs::augment_args; // keep the trait import honest
    TestCli::command()
        .try_get_matches_from(argv)
        .expect("parse should succeed")
}

/// The load-bearing property: a flag typed with its *default* value is
/// still recorded as explicit. Comparing `args.timeout` against
/// `DEFAULT_TIMEOUT_SECS` cannot tell these apart — that is the whole bug
/// `ExplicitArgs` exists to fix — so it has to come from clap's
/// `ValueSource`.
#[test]
fn explicit_args_records_flags_typed_with_their_default_value() {
    let m = matches_for(&[
        "dalfox",
        "--timeout",
        &DEFAULT_TIMEOUT_SECS.to_string(),
        "--method",
        "GET",
        "http://example.com",
    ]);
    let explicit = ExplicitArgs::from_matches(&m);

    assert!(
        explicit.contains("timeout"),
        "--timeout <default> must count as explicit"
    );
    assert!(
        explicit.contains("method"),
        "--method GET must count as explicit even though GET is the default"
    );
}

/// The other half: flags the operator never typed must not be recorded,
/// or a config file would become unreachable for every flag at once.
#[test]
fn explicit_args_omits_untyped_flags() {
    let m = matches_for(&["dalfox", "--workers", "10", "http://example.com"]);
    let explicit = ExplicitArgs::from_matches(&m);

    assert!(explicit.contains("workers"));
    for untyped in ["timeout", "method", "format", "delay", "encoders"] {
        assert!(
            !explicit.contains(untyped),
            "{untyped} was never typed, so it must stay config-overridable"
        );
    }
}

/// A bare run records nothing — the state every non-CLI construction
/// (`Default::default()`, REST, MCP) is in.
#[test]
fn explicit_args_is_empty_for_a_bare_command_line() {
    let explicit = ExplicitArgs::from_matches(&matches_for(&["dalfox"]));
    assert!(explicit.is_empty());
    assert!(ScanArgs::default().explicit.is_empty());
}

/// `ScanArgs::default()` must equal what clap produces for a bare run with
/// no flags. Construction sites use `..Default::default()` to stand in for
/// "whatever the CLI default is", so any drift between the two silently
/// changes behaviour at every one of those sites — most of which are
/// non-CLI entry points (preflight, REST, MCP) that never go through clap
/// and would not notice. Adding a field with a `default_value` but no
/// matching entry in the `Default` impl fails here.
#[test]
fn scanargs_default_matches_clap_defaults() {
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        scan: ScanArgs,
    }

    let parsed = TestCli::try_parse_from(["dalfox"])
        .expect("no-flag parse should succeed")
        .scan;

    assert_eq!(
        parsed,
        ScanArgs::default(),
        "ScanArgs::default() drifted from the clap-declared defaults; \
             update the Default impl in args.rs to match"
    );
}

#[test]
fn encoders_arg_accepts_all_implemented_encoders() {
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        scan: ScanArgs,
    }

    // Regression for #1069: the clap allowlist must accept every encoder the
    // engine implements, including htmlpad, unicode, and zwsp.
    let cli = TestCli::try_parse_from([
        "dalfox",
        "https://example.com",
        "-e",
        "htmlpad,unicode,zwsp",
    ])
    .expect("encoders htmlpad,unicode,zwsp should be accepted");
    assert_eq!(cli.scan.encoders, vec!["htmlpad", "unicode", "zwsp"]);
}

#[test]
fn blind_oob_flag_off_bare_and_list() {
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        scan: ScanArgs,
    }

    // Omitted → disabled.
    let off = TestCli::try_parse_from(["dalfox", "https://e.com"]).unwrap();
    assert!(!off.scan.blind_oob_enabled());
    assert_eq!(off.scan.blind_oob_wait(), DEFAULT_BLIND_OOB_WAIT_SECS);
    assert_eq!(off.scan.blind_oob_servers(), crate::oob::DEFAULT_SERVERS);

    // Bare `--blind-oob` → enabled, default public mesh.
    let bare = TestCli::try_parse_from(["dalfox", "https://e.com", "--blind-oob"]).unwrap();
    assert!(bare.scan.blind_oob_enabled());
    assert_eq!(bare.scan.oob.blind_oob.as_deref(), Some(&[][..]));
    assert_eq!(bare.scan.blind_oob_servers(), crate::oob::DEFAULT_SERVERS);

    // Explicit comma-separated servers (the `=` form is required) + secret
    // + wait.
    let full = TestCli::try_parse_from([
        "dalfox",
        "https://e.com",
        "--blind-oob=oast.fun,oast.me",
        "--blind-oob-secret",
        "tok",
        "--blind-oob-wait",
        "12",
    ])
    .unwrap();
    assert!(full.scan.blind_oob_enabled());
    assert_eq!(full.scan.blind_oob_servers(), vec!["oast.fun", "oast.me"]);
    assert_eq!(full.scan.blind_oob_secret(), Some("tok"));
    assert_eq!(full.scan.blind_oob_wait(), 12);
}

#[test]
fn blind_oob_never_swallows_positional_target() {
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        scan: ScanArgs,
    }

    // Regression: `--blind-oob` before the target must NOT eat the URL.
    // Without `require_equals` a bare `num_args = 0..` greedily consumes the
    // following positional, leaving the scan with no target.
    let bare_before = TestCli::try_parse_from(["dalfox", "--blind-oob", "https://e.com"])
        .expect("bare --blind-oob before target");
    assert!(bare_before.scan.blind_oob_enabled());
    assert_eq!(bare_before.scan.targets, vec!["https://e.com".to_string()]);
    assert_eq!(
        bare_before.scan.blind_oob_servers(),
        crate::oob::DEFAULT_SERVERS
    );

    // Same with an explicit `=` server list before the target.
    let list_before =
        TestCli::try_parse_from(["dalfox", "--blind-oob=oast.fun,oast.me", "https://e.com"])
            .expect("--blind-oob=list before target");
    assert_eq!(list_before.scan.targets, vec!["https://e.com".to_string()]);
    assert_eq!(
        list_before.scan.blind_oob_servers(),
        vec!["oast.fun", "oast.me"]
    );
}

#[test]
fn blind_oob_blank_server_list_falls_back_to_mesh() {
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        scan: ScanArgs,
    }

    // `--blind-oob=` / `--blind-oob=,,` / stray whitespace must still enable
    // OOB but degrade to the public mesh rather than registering an empty
    // host. Enabled is keyed on presence, so each is still "on".
    for arg in ["--blind-oob=", "--blind-oob=,,", "--blind-oob= , "] {
        let cli = TestCli::try_parse_from(["dalfox", "https://e.com", arg])
            .unwrap_or_else(|e| panic!("parse {arg}: {e}"));
        assert!(cli.scan.blind_oob_enabled(), "{arg} should enable OOB");
        assert_eq!(
            cli.scan.blind_oob_servers(),
            crate::oob::DEFAULT_SERVERS,
            "{arg} should fall back to the default mesh"
        );
    }

    // A list with one real entry and surrounding blanks keeps just the real
    // one, trimmed.
    let mixed = TestCli::try_parse_from(["dalfox", "https://e.com", "--blind-oob= oast.fun ,,"])
        .expect("mixed blank/real list");
    assert_eq!(mixed.scan.blind_oob_servers(), vec!["oast.fun"]);
}

#[test]
fn insecure_defaults_true_and_accepts_explicit_values() {
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        scan: ScanArgs,
    }

    // Omitted: None (unspecified). The effective value is unwrap_or(true)
    // at the consumption points, but presence must be distinguishable so
    // config / CLI precedence can be resolved correctly.
    let cli = TestCli::try_parse_from(["dalfox", "https://example.com"])
        .expect("parse without --insecure");
    assert_eq!(cli.scan.insecure, None, "omitted --insecure should be None");

    // Bare `--insecure` => Some(true) (and does NOT swallow the positional).
    let cli = TestCli::try_parse_from(["dalfox", "--insecure", "https://example.com"])
        .expect("parse with bare --insecure");
    assert_eq!(cli.scan.insecure, Some(true));
    assert_eq!(cli.scan.targets, vec!["https://example.com".to_string()]);

    // `--insecure=false` opts into TLS certificate validation.
    let cli = TestCli::try_parse_from(["dalfox", "https://example.com", "--insecure=false"])
        .expect("parse with --insecure=false");
    assert_eq!(
        cli.scan.insecure,
        Some(false),
        "insecure=false should be Some(false)"
    );

    // Boolish values are accepted on the `=` form.
    let cli = TestCli::try_parse_from(["dalfox", "https://example.com", "--insecure=true"])
        .expect("parse with --insecure=true");
    assert_eq!(cli.scan.insecure, Some(true));
    let cli = TestCli::try_parse_from(["dalfox", "https://example.com", "--insecure=0"])
        .expect("parse with --insecure=0");
    assert_eq!(cli.scan.insecure, Some(false));
}

#[test]
fn force_waf_arg_normalizes_known_alias() {
    assert_eq!(parse_force_waf_arg("  CloudFlare ").unwrap(), "cloudflare");
    assert_eq!(parse_force_waf_arg("MODSEC").unwrap(), "modsec");
    assert_eq!(parse_force_waf_arg("cloud-armor").unwrap(), "cloud-armor");
    assert_eq!(parse_force_waf_arg("NetScaler").unwrap(), "netscaler");
    assert_eq!(parse_force_waf_arg("citrix").unwrap(), "citrix");
}

#[test]
fn force_waf_arg_rejects_unknown() {
    let err = parse_force_waf_arg("notawaf").unwrap_err();
    assert!(err.contains("unknown WAF"), "got: {}", err);
}

#[test]
fn limit_arg_accepts_positive() {
    assert_eq!(parse_limit_arg("5").unwrap(), 5);
    assert_eq!(parse_limit_arg("1").unwrap(), 1);
}

#[test]
fn limit_arg_rejects_zero() {
    let err = parse_limit_arg("0").unwrap_err();
    assert!(err.contains("at least 1"), "got: {}", err);
}

#[test]
fn limit_arg_rejects_non_numeric() {
    let err = parse_limit_arg("abc").unwrap_err();
    assert!(err.contains("positive integer"), "got: {}", err);
}

#[test]
fn http_method_arg_uppercases_and_accepts_known() {
    for (input, expected) in [
        ("get", "GET"),
        ("Post", "POST"),
        ("  put ", "PUT"),
        ("delete", "DELETE"),
        ("head", "HEAD"),
        ("options", "OPTIONS"),
        ("patch", "PATCH"),
        ("query", "QUERY"),
        ("  Query ", "QUERY"),
    ] {
        assert_eq!(parse_http_method_arg(input).unwrap(), expected);
    }
}

#[test]
fn http_method_arg_rejects_empty_and_unknown() {
    assert!(
        parse_http_method_arg("   ")
            .unwrap_err()
            .contains("must not be empty")
    );
    let err = parse_http_method_arg("TRACE").unwrap_err();
    assert!(err.contains("unsupported HTTP method"), "got: {}", err);
}

#[test]
fn for_preflight_sets_discovery_only_shape() {
    let args = ScanArgs::for_preflight(PreflightOptions {
        insecure: true,
        target: "https://example.com".to_string(),
        param: vec!["q".to_string()],
        method: "GET".to_string(),
        data: None,
        headers: vec![],
        cookies: vec![],
        user_agent: None,
        timeout: 15,
        proxy: None,
        follow_redirects: false,
        skip_mining: true,
        skip_discovery: false,
        encoders: vec!["none".to_string()],
    });
    assert_eq!(args.targets, vec!["https://example.com".to_string()]);
    assert_eq!(args.timeout, 15);
    assert!(args.dry_run);
    assert!(args.skip_xss_scanning);
    assert!(args.skip_ast_analysis);
    assert!(args.silence);
    assert_eq!(args.insecure, Some(true));
    // skip_mining fans out to all three mining toggles.
    assert!(args.skip_mining && args.skip_mining_dict && args.skip_mining_dom);
}

#[test]
fn for_preflight_threads_insecure_choice() {
    // The caller's insecure choice must flow into the preflight ScanArgs,
    // not be silently forced to true.
    let validate = ScanArgs::for_preflight(PreflightOptions {
        insecure: false,
        target: "https://example.com".to_string(),
        param: vec![],
        method: "GET".to_string(),
        data: None,
        headers: vec![],
        cookies: vec![],
        user_agent: None,
        timeout: 10,
        proxy: None,
        follow_redirects: false,
        skip_mining: false,
        skip_discovery: false,
        encoders: vec![],
    });
    assert_eq!(
        validate.insecure,
        Some(false),
        "insecure=false must thread through for_preflight"
    );
}

#[test]
fn for_preflight_clamps_out_of_range_timeout_to_default() {
    // 0 and >=300 both fall back to the default timeout.
    let zero = ScanArgs::for_preflight(PreflightOptions {
        insecure: true,
        target: "https://example.com".to_string(),
        param: vec![],
        method: "GET".to_string(),
        data: None,
        headers: vec![],
        cookies: vec![],
        user_agent: None,
        timeout: 0,
        proxy: None,
        follow_redirects: false,
        skip_mining: false,
        skip_discovery: false,
        encoders: vec![],
    });
    assert_eq!(zero.timeout, DEFAULT_TIMEOUT_SECS);

    let huge = ScanArgs::for_preflight(PreflightOptions {
        insecure: true,
        target: "https://example.com".to_string(),
        param: vec![],
        method: "GET".to_string(),
        data: None,
        headers: vec![],
        cookies: vec![],
        user_agent: None,
        timeout: 5000,
        proxy: None,
        follow_redirects: false,
        skip_mining: false,
        skip_discovery: false,
        encoders: vec![],
    });
    assert_eq!(huge.timeout, DEFAULT_TIMEOUT_SECS);
}
