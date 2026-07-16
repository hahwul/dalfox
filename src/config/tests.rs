use super::*;
use std::sync::atomic::Ordering;

fn default_scan_args() -> crate::cmd::scan::ScanArgs {
    crate::cmd::scan::ScanArgs {
        insecure: Some(true),
        detect_outdated_libs: false,
        input_type: "auto".to_string(),
        format: "plain".to_string(),
        output: None,
        include_request: false,
        include_response: false,
        include_all: false,
        no_color: false,
        silence: false,
        dry_run: false,
        stream_findings: false,
        poc_type: "plain".to_string(),
        limit: None,
        limit_result_type: "all".to_string(),
        only_poc: vec![],
        param: vec![],
        data: None,
        headers: vec![],
        cookies: vec![],
        method: "GET".to_string(),
        user_agent: None,
        cookie_from_raw: None,
        include_url: vec![],
        exclude_url: vec![],
        ignore_param: vec![],
        out_of_scope: vec![],
        out_of_scope_file: None,
        only_discovery: false,
        skip_discovery: false,
        skip_reflection_header: false,
        skip_reflection_cookie: false,
        skip_reflection_path: false,
        mining_dict_word: None,
        remote_wordlists: vec![],
        skip_mining: false,
        skip_mining_dict: false,
        skip_mining_dom: false,
        timeout: crate::cmd::scan::DEFAULT_TIMEOUT_SECS,
        scan_timeout: 0,
        delay: crate::cmd::scan::DEFAULT_DELAY_MS,
        proxy: None,
        follow_redirects: false,
        ignore_return: vec![],
        workers: crate::cmd::scan::DEFAULT_WORKERS,
        max_concurrent_targets: crate::cmd::scan::DEFAULT_MAX_CONCURRENT_TARGETS,
        max_targets_per_host: crate::cmd::scan::DEFAULT_MAX_TARGETS_PER_HOST,
        encoders: crate::cmd::scan::DEFAULT_ENCODERS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        remote_payloads: vec![],
        custom_blind_xss_payload: None,
        blind_callback_url: None,
        oob: Default::default(),
        custom_payload: None,
        only_custom_payload: false,
        inject_marker: None,
        custom_alert_value: "1".to_string(),
        custom_alert_type: "none".to_string(),
        skip_xss_scanning: false,
        max_payloads_per_param: 0,
        deep_scan: false,
        sxss: false,
        sxss_url: None,
        sxss_method: "GET".to_string(),
        sxss_retries: 3,
        skip_ast_analysis: false,
        analyze_external_js: false,
        hpp: false,
        waf_bypass: "auto".to_string(),
        skip_waf_probe: false,
        force_waf: None,
        waf_evasion: false,
        rate_limit: 0,
        retries: 0,
        retry_delay: 1000,
        waf_min_confidence: 0.0,
        targets: vec![],
    }
}

fn full_scan_config() -> ScanConfig {
    ScanConfig {
        insecure: None,
        input_type: Some("file".to_string()),
        format: Some("jsonl".to_string()),
        output: Some("result.jsonl".to_string()),
        include_request: Some(true),
        include_response: Some(true),
        include_all: Some(false),
        silence: Some(true),
        dry_run: Some(false),
        stream_findings: Some(false),
        poc_type: Some("curl".to_string()),
        limit: Some(42),
        limit_result_type: Some("v".to_string()),
        only_poc: Some(vec!["v".to_string()]),
        no_color: Some(false),
        param: Some(vec!["q".to_string(), "id:query".to_string()]),
        data: Some("name=test".to_string()),
        headers: Some(vec!["X-Test: 1".to_string()]),
        cookies: Some(vec!["sid=abc".to_string()]),
        method: Some("POST".to_string()),
        user_agent: Some("DalfoxTest/1.0".to_string()),
        cookie_from_raw: Some("request.txt".to_string()),
        include_url: Some(vec!["https://example.com/.*".to_string()]),
        exclude_url: Some(vec!["https://example.com/exclude".to_string()]),
        ignore_param: Some(vec![]),
        out_of_scope: Some(vec![]),
        out_of_scope_file: None,
        only_discovery: Some(false),
        skip_discovery: Some(true),
        skip_reflection_header: Some(true),
        skip_reflection_cookie: Some(true),
        skip_reflection_path: Some(true),
        mining_dict_word: Some("words.txt".to_string()),
        remote_wordlists: Some(vec!["burp".to_string(), "assetnote".to_string()]),
        skip_mining: Some(true),
        skip_mining_dict: Some(true),
        skip_mining_dom: Some(true),
        timeout: Some(21),
        scan_timeout: Some(45),
        delay: Some(123),
        rate_limit: Some(25),
        retries: Some(4),
        retry_delay: Some(750),
        proxy: Some("http://127.0.0.1:8080".to_string()),
        follow_redirects: Some(true),
        ignore_return: Some(vec![403, 404]),
        workers: Some(7),
        max_concurrent_targets: Some(8),
        max_targets_per_host: Some(9),
        encoders: Some(vec!["none".to_string(), "base64".to_string()]),
        remote_payloads: Some(vec!["payloadbox".to_string(), "portswigger".to_string()]),
        custom_blind_xss_payload: Some("blind.txt".to_string()),
        blind_callback_url: Some("https://bxss.example/callback".to_string()),
        blind_oob: Some(vec!["oast.fun".to_string()]),
        blind_oob_secret: Some("secret-token".to_string()),
        blind_oob_wait: Some(45),
        custom_payload: Some("custom.txt".to_string()),
        only_custom_payload: Some(true),
        inject_marker: None,
        custom_alert_value: Some("1".to_string()),
        custom_alert_type: Some("none".to_string()),
        skip_xss_scanning: Some(true),
        max_payloads_per_param: Some(0),
        deep_scan: Some(true),
        sxss: Some(true),
        sxss_url: Some("https://example.com/sxss".to_string()),
        sxss_method: Some("POST".to_string()),
        sxss_retries: Some(12),
        skip_ast_analysis: Some(true),
        analyze_external_js: Some(true),
        detect_outdated_libs: Some(true),
        hpp: Some(false),
        waf_bypass: Some("auto".to_string()),
        skip_waf_probe: Some(false),
        force_waf: None,
        waf_evasion: Some(true),
        waf_min_confidence: Some(0.7),
        debug: Some(true),
    }
}

#[test]
fn test_resolve_config_dir_returns_dalfox_path() {
    let dir = resolve_config_dir().expect("should resolve config dir");
    assert!(dir.ends_with("dalfox"));
}

#[test]
fn test_default_toml_parses() {
    let s = default_toml_template();
    let cfg: Config = toml::from_str(&s).expect("template must parse");
    // Empty or partial config is fine; ensure not panicking
    let _ = cfg.scan.as_ref().and_then(|s| s.format.clone());
}

#[test]
fn test_default_json_parses() {
    let s = default_json_template();
    let cfg: Config = serde_json::from_str(&s).expect("json template must parse");
    // Touch a field to avoid unused variable warning
    let _ = cfg.scan.as_ref().and_then(|scan| scan.format.clone());
}

#[test]
fn test_default_numeric_constants_alignment() {
    assert_eq!(crate::cmd::scan::DEFAULT_TIMEOUT_SECS, 10);
    assert_eq!(crate::cmd::scan::DEFAULT_DELAY_MS, 0);
    assert_eq!(crate::cmd::scan::DEFAULT_WORKERS, 50);
    assert_eq!(crate::cmd::scan::DEFAULT_MAX_CONCURRENT_TARGETS, 50);
    assert_eq!(crate::cmd::scan::DEFAULT_MAX_TARGETS_PER_HOST, 100);
    // DEFAULT_ENCODERS canonical defaults
    assert_eq!(crate::cmd::scan::DEFAULT_ENCODERS, &["url", "html"]);
}

#[test]
fn test_encoders_override_when_default() {
    // Prepare config with custom encoders
    let cfg = Config {
        scan: Some(ScanConfig {
            encoders: Some(vec![
                "url".to_string(),
                "2url".to_string(),
                "html".to_string(),
                "base64".to_string(),
            ]),
            ..Default::default()
        }),
    };

    // Prepare ScanArgs with canonical defaults (["url","html"])
    let mut args = default_scan_args();

    // Apply config only-if-default logic
    cfg.apply_to_scan_args_if_default(&mut args);
    // Expect override to occur
    assert_eq!(
        args.encoders,
        vec!["url", "2url", "html", "base64"],
        "Encoders should be overridden when starting from canonical defaults"
    );
}

#[test]
fn test_encoders_not_override_when_custom_cli() {
    // Config wants to set encoders, but CLI already customized
    let cfg = Config {
        scan: Some(ScanConfig {
            encoders: Some(vec![
                "url".to_string(),
                "html".to_string(),
                "base64".to_string(),
            ]),
            ..Default::default()
        }),
    };

    // CLI provided non-default encoders (e.g., includes 'none')
    let mut args = default_scan_args();
    args.encoders = vec!["none".to_string(), "url".to_string()]; // Custom CLI setting

    cfg.apply_to_scan_args_if_default(&mut args);
    // Should NOT override because starting encoders != canonical defaults
    assert_eq!(
        args.encoders,
        vec!["none", "url"],
        "Encoders should remain as custom CLI-provided set"
    );
}

#[test]
fn test_apply_to_scan_args_overwrites_present_fields() {
    let cfg = Config {
        scan: Some(full_scan_config()),
    };
    let mut args = default_scan_args();

    // Seed a few non-default values to verify unconditional overwrite behavior.
    args.input_type = "url".to_string();
    args.method = "GET".to_string();
    args.encoders = vec!["url".to_string()];
    args.sxss_method = "GET".to_string();

    cfg.apply_to_scan_args(&mut args);

    assert_eq!(args.input_type, "file");
    assert_eq!(args.format, "jsonl");
    assert_eq!(args.output.as_deref(), Some("result.jsonl"));
    assert!(args.include_request);
    assert!(args.include_response);
    assert!(args.silence);
    assert_eq!(args.poc_type, "curl");
    assert_eq!(args.limit, Some(42));
    assert_eq!(args.limit_result_type, "v");
    assert_eq!(args.param, vec!["q".to_string(), "id:query".to_string()]);
    assert_eq!(args.data.as_deref(), Some("name=test"));
    assert_eq!(args.headers, vec!["X-Test: 1".to_string()]);
    assert_eq!(args.cookies, vec!["sid=abc".to_string()]);
    assert_eq!(args.method, "POST");
    assert_eq!(args.user_agent.as_deref(), Some("DalfoxTest/1.0"));
    assert_eq!(args.cookie_from_raw.as_deref(), Some("request.txt"));
    assert!(args.skip_discovery);
    assert!(args.skip_reflection_header);
    assert!(args.skip_reflection_cookie);
    assert!(args.skip_reflection_path);
    assert_eq!(args.mining_dict_word.as_deref(), Some("words.txt"));
    assert_eq!(
        args.remote_wordlists,
        vec!["burp".to_string(), "assetnote".to_string()]
    );
    assert!(args.skip_mining);
    assert!(args.skip_mining_dict);
    assert!(args.skip_mining_dom);
    assert_eq!(args.timeout, 21);
    assert_eq!(args.delay, 123);
    assert_eq!(args.rate_limit, 25);
    assert_eq!(args.retries, 4);
    assert_eq!(args.retry_delay, 750);
    assert_eq!(args.proxy.as_deref(), Some("http://127.0.0.1:8080"));
    assert!(args.follow_redirects);
    assert_eq!(args.workers, 7);
    assert_eq!(args.max_concurrent_targets, 8);
    assert_eq!(args.max_targets_per_host, 9);
    assert_eq!(
        args.encoders,
        vec!["none".to_string(), "base64".to_string()]
    );
    assert_eq!(
        args.remote_payloads,
        vec!["payloadbox".to_string(), "portswigger".to_string()]
    );
    assert_eq!(args.custom_blind_xss_payload.as_deref(), Some("blind.txt"));
    assert_eq!(
        args.blind_callback_url.as_deref(),
        Some("https://bxss.example/callback")
    );
    assert_eq!(args.custom_payload.as_deref(), Some("custom.txt"));
    assert!(args.only_custom_payload);
    assert!(args.skip_xss_scanning);
    assert!(args.deep_scan);
    assert!(args.sxss);
    assert_eq!(args.sxss_url.as_deref(), Some("https://example.com/sxss"));
    assert_eq!(args.sxss_method, "POST");
    // Fields added after this method's first draft (AST / external-JS / HPP /
    // WAF suite) must be overwritten too — regression guard for the drift bug
    // where new ScanConfig fields were only wired into the if_default overlay.
    assert!(args.skip_ast_analysis);
    assert!(args.analyze_external_js);
    assert!(args.detect_outdated_libs);
    assert_eq!(args.sxss_retries, 12);
    // full_scan_config sets waf_evasion=true / waf_min_confidence=0.7, both
    // distinct from default_scan_args (false / 0.0), so these prove overwrite.
    assert!(args.waf_evasion);
    assert!((args.waf_min_confidence - 0.7).abs() < f32::EPSILON);
}

#[test]
fn test_apply_to_scan_args_unconditional_applies_waf_and_hpp_fields() {
    // Distinct-from-default values for the fields where full_scan_config()
    // happens to match the default (waf_bypass/skip_waf_probe/hpp/force_waf),
    // seeded opposite in args to prove the unconditional apply overwrites them.
    let cfg = Config {
        scan: Some(ScanConfig {
            waf_bypass: Some("force".to_string()),
            skip_waf_probe: Some(true),
            force_waf: Some("cloudflare".to_string()),
            hpp: Some(true),
            ..Default::default()
        }),
    };
    let mut args = default_scan_args();
    args.waf_bypass = "auto".to_string();
    args.skip_waf_probe = false;
    args.force_waf = None;
    args.hpp = false;

    cfg.apply_to_scan_args(&mut args);

    assert_eq!(args.waf_bypass, "force");
    assert!(args.skip_waf_probe);
    assert_eq!(args.force_waf.as_deref(), Some("cloudflare"));
    assert!(args.hpp);
}

#[test]
fn test_apply_to_scan_args_conservative_fills_missing_values() {
    let cfg = Config {
        scan: Some(full_scan_config()),
    };
    let mut args = default_scan_args();

    cfg.apply_to_scan_args_conservative(&mut args);

    assert_eq!(args.output.as_deref(), Some("result.jsonl"));
    assert_eq!(args.limit, Some(42));
    assert_eq!(args.limit_result_type, "v");
    assert_eq!(args.data.as_deref(), Some("name=test"));
    assert_eq!(args.user_agent.as_deref(), Some("DalfoxTest/1.0"));
    assert_eq!(args.cookie_from_raw.as_deref(), Some("request.txt"));
    assert_eq!(args.mining_dict_word.as_deref(), Some("words.txt"));
    assert_eq!(
        args.remote_wordlists,
        vec!["burp".to_string(), "assetnote".to_string()]
    );
    assert_eq!(args.proxy.as_deref(), Some("http://127.0.0.1:8080"));
    assert_eq!(args.custom_blind_xss_payload.as_deref(), Some("blind.txt"));
    assert_eq!(
        args.blind_callback_url.as_deref(),
        Some("https://bxss.example/callback")
    );
    assert_eq!(args.custom_payload.as_deref(), Some("custom.txt"));
    assert_eq!(
        args.remote_payloads,
        vec!["payloadbox".to_string(), "portswigger".to_string()]
    );
    assert_eq!(args.sxss_url.as_deref(), Some("https://example.com/sxss"));
    assert!(args.skip_reflection_path);
}

#[test]
fn test_apply_to_scan_args_conservative_preserves_existing_values() {
    let cfg = Config {
        scan: Some(full_scan_config()),
    };
    let mut args = default_scan_args();

    args.output = Some("cli-output.txt".to_string());
    args.limit = Some(7);
    args.data = Some("cli=1".to_string());
    args.user_agent = Some("CliUA/1.0".to_string());
    args.cookie_from_raw = Some("cli-request.txt".to_string());
    args.mining_dict_word = Some("cli-words.txt".to_string());
    args.remote_wordlists = vec!["cliwordlist".to_string()];
    args.proxy = Some("http://127.0.0.1:8888".to_string());
    args.custom_blind_xss_payload = Some("cli-blind.txt".to_string());
    args.blind_callback_url = Some("https://cli.example/cb".to_string());
    args.custom_payload = Some("cli-custom.txt".to_string());
    args.remote_payloads = vec!["cliremote".to_string()];
    args.sxss_url = Some("https://cli.example/sxss".to_string());
    args.skip_reflection_path = true;

    cfg.apply_to_scan_args_conservative(&mut args);

    assert_eq!(args.output.as_deref(), Some("cli-output.txt"));
    assert_eq!(args.limit, Some(7));
    assert_eq!(args.data.as_deref(), Some("cli=1"));
    assert_eq!(args.user_agent.as_deref(), Some("CliUA/1.0"));
    assert_eq!(args.cookie_from_raw.as_deref(), Some("cli-request.txt"));
    assert_eq!(args.mining_dict_word.as_deref(), Some("cli-words.txt"));
    assert_eq!(args.remote_wordlists, vec!["cliwordlist".to_string()]);
    assert_eq!(args.proxy.as_deref(), Some("http://127.0.0.1:8888"));
    assert_eq!(
        args.custom_blind_xss_payload.as_deref(),
        Some("cli-blind.txt")
    );
    assert_eq!(
        args.blind_callback_url.as_deref(),
        Some("https://cli.example/cb")
    );
    assert_eq!(args.custom_payload.as_deref(), Some("cli-custom.txt"));
    assert_eq!(args.remote_payloads, vec!["cliremote".to_string()]);
    assert_eq!(args.sxss_url.as_deref(), Some("https://cli.example/sxss"));
    assert!(args.skip_reflection_path);
}

#[test]
fn test_apply_to_scan_args_if_default_waf_precedence() {
    // Config carries non-default WAF settings.
    let mut scan = full_scan_config();
    scan.waf_bypass = Some("off".to_string());
    scan.force_waf = Some("cloudflare".to_string());
    let cfg = Config { scan: Some(scan) };

    // Case 1: CLI left both at their clap defaults ("auto" / None) -> config fills them.
    let mut args = default_scan_args();
    cfg.apply_to_scan_args_if_default(&mut args);
    assert_eq!(args.waf_bypass, "off");
    assert_eq!(args.force_waf.as_deref(), Some("cloudflare"));

    // Case 2: CLI explicitly set both -> CLI wins, config is ignored.
    let mut args = default_scan_args();
    args.waf_bypass = "force".to_string();
    args.force_waf = Some("akamai".to_string());
    cfg.apply_to_scan_args_if_default(&mut args);
    assert_eq!(args.waf_bypass, "force");
    assert_eq!(args.force_waf.as_deref(), Some("akamai"));
}

#[test]
fn test_apply_to_scan_args_if_default_insecure_precedence() {
    // `insecure` defaults to true, so config can only flip it to false while
    // the user left the flag untouched; an explicit `--insecure=false` wins.
    let mut scan = full_scan_config();
    scan.insecure = Some(false);
    let cfg = Config { scan: Some(scan) };

    // Case 1: CLI left --insecure unspecified (None) -> config flips it off.
    let mut args = default_scan_args();
    args.insecure = None;
    cfg.apply_to_scan_args_if_default(&mut args);
    assert_eq!(
        args.insecure,
        Some(false),
        "config insecure=false should apply when CLI left it unspecified"
    );

    // Case 2: CLI explicitly disabled it (Some(false)) -> a config of Some(true)
    // must NOT re-enable it; the explicit CLI choice wins.
    let mut scan_on = full_scan_config();
    scan_on.insecure = Some(true);
    let cfg_on = Config {
        scan: Some(scan_on),
    };
    let mut args = default_scan_args();
    args.insecure = Some(false); // user passed --insecure=false
    cfg_on.apply_to_scan_args_if_default(&mut args);
    assert_eq!(
        args.insecure,
        Some(false),
        "CLI --insecure=false must win over config insecure=true"
    );

    // Case 3 (the precedence gap Copilot flagged): CLI explicitly *enabled* it
    // (Some(true)) while config sets false -> CLI must win and stay insecure.
    // A plain bool couldn't express this; Option<bool> can.
    let mut scan_off = full_scan_config();
    scan_off.insecure = Some(false);
    let cfg_off = Config {
        scan: Some(scan_off),
    };
    let mut args = default_scan_args();
    args.insecure = Some(true); // user passed --insecure / --insecure=true
    cfg_off.apply_to_scan_args_if_default(&mut args);
    assert_eq!(
        args.insecure,
        Some(true),
        "CLI --insecure=true must win over config insecure=false"
    );

    // Case 4: config omits insecure (None) + CLI unspecified -> stays None,
    // and the effective value defaults to insecure (true).
    let cfg_none = Config {
        scan: Some(full_scan_config()),
    };
    let mut args = default_scan_args();
    args.insecure = None;
    cfg_none.apply_to_scan_args_if_default(&mut args);
    assert_eq!(args.insecure, None);
    assert!(
        args.insecure.unwrap_or(true),
        "omitted config + CLI keeps the scanner default (true)"
    );
}

#[test]
fn test_apply_to_scan_args_unconditional_overrides_insecure() {
    // The unconditional apply always honors a present config value.
    let mut scan = full_scan_config();
    scan.insecure = Some(false);
    let cfg = Config { scan: Some(scan) };
    let mut args = default_scan_args();
    cfg.apply_to_scan_args(&mut args);
    assert_eq!(args.insecure, Some(false));
}

#[test]
fn test_apply_to_scan_args_if_default_maps_all_supported_fields() {
    struct DebugGuard(bool);
    impl Drop for DebugGuard {
        fn drop(&mut self) {
            crate::DEBUG.store(self.0, Ordering::Relaxed);
        }
    }

    let original_debug = crate::DEBUG.load(Ordering::Relaxed);
    let _debug_guard = DebugGuard(original_debug);
    crate::DEBUG.store(false, Ordering::Relaxed);

    let cfg = Config {
        scan: Some(full_scan_config()),
    };
    let mut args = default_scan_args();

    cfg.apply_to_scan_args_if_default(&mut args);

    assert_eq!(args.input_type, "file");
    assert_eq!(args.format, "jsonl");
    assert_eq!(args.output.as_deref(), Some("result.jsonl"));
    assert!(args.include_request);
    assert!(args.include_response);
    assert!(args.silence);
    assert_eq!(args.poc_type, "curl");
    assert_eq!(args.limit, Some(42));
    assert!(crate::DEBUG.load(Ordering::Relaxed));
    assert_eq!(args.param, vec!["q".to_string(), "id:query".to_string()]);
    assert_eq!(args.data.as_deref(), Some("name=test"));
    assert_eq!(args.headers, vec!["X-Test: 1".to_string()]);
    assert_eq!(args.cookies, vec!["sid=abc".to_string()]);
    assert_eq!(args.method, "POST");
    assert_eq!(args.user_agent.as_deref(), Some("DalfoxTest/1.0"));
    assert_eq!(args.include_url, vec!["https://example.com/.*".to_string()]);
    assert_eq!(
        args.exclude_url,
        vec!["https://example.com/exclude".to_string()]
    );
    assert!(args.skip_reflection_path);
    assert_eq!(args.cookie_from_raw.as_deref(), Some("request.txt"));
    assert!(args.skip_discovery);
    assert!(args.skip_reflection_header);
    assert!(args.skip_reflection_cookie);
    assert_eq!(args.mining_dict_word.as_deref(), Some("words.txt"));
    assert_eq!(
        args.remote_wordlists,
        vec!["burp".to_string(), "assetnote".to_string()]
    );
    assert!(args.skip_mining);
    assert!(args.skip_mining_dict);
    assert!(args.skip_mining_dom);
    assert_eq!(args.timeout, 21);
    assert_eq!(args.scan_timeout, 45);
    assert_eq!(args.delay, 123);
    assert_eq!(args.rate_limit, 25);
    assert_eq!(args.retries, 4);
    assert_eq!(args.retry_delay, 750);
    assert_eq!(args.proxy.as_deref(), Some("http://127.0.0.1:8080"));
    assert!(args.follow_redirects);
    assert_eq!(args.workers, 7);
    assert_eq!(args.max_concurrent_targets, 8);
    assert_eq!(args.max_targets_per_host, 9);
    assert_eq!(
        args.encoders,
        vec!["none".to_string(), "base64".to_string()]
    );
    assert_eq!(
        args.remote_payloads,
        vec!["payloadbox".to_string(), "portswigger".to_string()]
    );
    assert_eq!(args.custom_blind_xss_payload.as_deref(), Some("blind.txt"));
    assert_eq!(
        args.blind_callback_url.as_deref(),
        Some("https://bxss.example/callback")
    );
    assert_eq!(args.custom_payload.as_deref(), Some("custom.txt"));
    assert!(args.only_custom_payload);
    assert!(args.skip_xss_scanning);
    assert!(args.deep_scan);
    assert!(args.sxss);
    assert_eq!(args.sxss_url.as_deref(), Some("https://example.com/sxss"));
    assert_eq!(args.sxss_method, "POST");
    assert_eq!(args.sxss_retries, 12);
    assert!(args.skip_ast_analysis);
    assert!(args.analyze_external_js);
    assert!(args.detect_outdated_libs);
}

#[test]
fn test_save_writes_toml_and_json_formats() {
    let cfg = Config {
        scan: Some(ScanConfig {
            format: Some("json".to_string()),
            timeout: Some(3),
            ..Default::default()
        }),
    };

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time moved backwards")
        .as_nanos();
    let base = std::env::temp_dir().join(format!("dalfox-config-save-{nonce}"));
    std::fs::create_dir_all(&base).expect("create temp directory");

    let toml_path = base.join("config.toml");
    save(&cfg, &toml_path, ConfigFormat::Toml).expect("save toml config");
    let toml_content = std::fs::read_to_string(&toml_path).expect("read toml file");
    let loaded_toml: Config = toml::from_str(&toml_content).expect("parse saved toml");
    assert_eq!(
        loaded_toml
            .scan
            .as_ref()
            .and_then(|s| s.format.as_deref())
            .expect("saved toml should keep scan.format"),
        "json"
    );

    let json_path = base.join("config.json");
    save(&cfg, &json_path, ConfigFormat::Json).expect("save json config");
    let json_content = std::fs::read_to_string(&json_path).expect("read json file");
    let loaded_json: Config = serde_json::from_str(&json_content).expect("parse saved json");
    assert_eq!(
        loaded_json
            .scan
            .as_ref()
            .and_then(|s| s.timeout)
            .expect("saved json should keep scan.timeout"),
        3
    );

    let _ = std::fs::remove_dir_all(base);
}

// --- normalize_and_validate -------------------------------------------------

#[test]
fn test_normalize_and_validate_accepts_full_valid_config() {
    // full_scan_config() uses only valid values, so validation must be a no-op
    // (no warnings, no field cleared).
    let mut cfg = Config {
        scan: Some(full_scan_config()),
    };
    let warnings = cfg.normalize_and_validate();
    assert!(
        warnings.is_empty(),
        "expected no warnings, got: {warnings:?}"
    );
    let scan = cfg.scan.as_ref().unwrap();
    assert_eq!(scan.format.as_deref(), Some("jsonl"));
    assert_eq!(scan.method.as_deref(), Some("POST"));
    assert_eq!(scan.limit, Some(42));
}

#[test]
fn test_normalize_and_validate_none_scan_is_noop() {
    let mut cfg = Config { scan: None };
    assert!(cfg.normalize_and_validate().is_empty());
}

#[test]
fn test_normalize_and_validate_uppercases_method() {
    // A lowercase config method must be normalized to uppercase (mirroring the
    // CLI's `--method` parser) instead of silently breaking `== "POST"`.
    let mut scan = ScanConfig {
        method: Some("post".to_string()),
        ..Default::default()
    };
    let warnings = scan.normalize_and_validate();
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    assert_eq!(scan.method.as_deref(), Some("POST"));
}

#[test]
fn test_normalize_and_validate_rejects_invalid_method() {
    let mut scan = ScanConfig {
        method: Some("banana".to_string()),
        ..Default::default()
    };
    let warnings = scan.normalize_and_validate();
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("scan.method"));
    assert_eq!(
        scan.method, None,
        "invalid method must fall back to default"
    );
}

#[test]
fn test_normalize_and_validate_rejects_invalid_enums() {
    let mut scan = ScanConfig {
        format: Some("xml".to_string()),
        poc_type: Some("nc".to_string()),
        limit_result_type: Some("z".to_string()),
        custom_alert_type: Some("bogus".to_string()),
        waf_bypass: Some("always".to_string()),
        ..Default::default()
    };
    let warnings = scan.normalize_and_validate();
    assert_eq!(
        warnings.len(),
        5,
        "one warning per invalid field: {warnings:?}"
    );
    assert_eq!(scan.format, None);
    assert_eq!(scan.poc_type, None);
    assert_eq!(scan.limit_result_type, None);
    assert_eq!(scan.custom_alert_type, None);
    assert_eq!(scan.waf_bypass, None);
}

#[test]
fn test_normalize_and_validate_rejects_invalid_list_values() {
    // A single bad element drops the whole list back to the default.
    let mut scan = ScanConfig {
        only_poc: Some(vec!["v".to_string(), "bogus".to_string()]),
        encoders: Some(vec!["url".to_string(), "rot13".to_string()]),
        ..Default::default()
    };
    let warnings = scan.normalize_and_validate();
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("scan.only_poc") && w.contains("bogus"))
    );
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("scan.encoders") && w.contains("rot13"))
    );
    assert_eq!(scan.only_poc, None);
    assert_eq!(scan.encoders, None);
}

#[test]
fn test_normalize_and_validate_keeps_valid_list_values() {
    let mut scan = ScanConfig {
        only_poc: Some(vec!["v".to_string(), "r".to_string()]),
        encoders: Some(vec!["url".to_string(), "base64".to_string()]),
        ..Default::default()
    };
    let warnings = scan.normalize_and_validate();
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(scan.only_poc, Some(vec!["v".to_string(), "r".to_string()]));
    assert_eq!(
        scan.encoders,
        Some(vec!["url".to_string(), "base64".to_string()])
    );
}

#[test]
fn test_normalize_and_validate_normalizes_force_waf() {
    // Mixed-case alias normalizes to lowercase; a typo is rejected.
    let mut ok = ScanConfig {
        force_waf: Some("CloudFlare".to_string()),
        ..Default::default()
    };
    assert!(ok.normalize_and_validate().is_empty());
    assert_eq!(ok.force_waf.as_deref(), Some("cloudflare"));

    let mut bad = ScanConfig {
        force_waf: Some("cloudflair".to_string()),
        ..Default::default()
    };
    let warnings = bad.normalize_and_validate();
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("scan.force_waf"));
    assert_eq!(bad.force_waf, None);
}

#[test]
fn test_normalize_and_validate_rejects_zero_limit() {
    // clap rejects `--limit 0`; a config `limit = 0` must be treated as "no
    // cap" (None) with a warning rather than resurrecting "show no findings".
    let mut scan = ScanConfig {
        limit: Some(0),
        ..Default::default()
    };
    let warnings = scan.normalize_and_validate();
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("scan.limit"));
    assert_eq!(scan.limit, None);

    // A positive cap is preserved.
    let mut ok = ScanConfig {
        limit: Some(5),
        ..Default::default()
    };
    assert!(ok.normalize_and_validate().is_empty());
    assert_eq!(ok.limit, Some(5));
}

#[test]
fn test_normalize_and_validate_accepts_every_allowed_enum_value() {
    // Guard that the validator is wired to the same value sets clap enforces:
    // every canonical value round-trips without a warning.
    for &f in crate::cmd::scan::FORMAT_VALUES {
        let mut scan = ScanConfig {
            format: Some(f.to_string()),
            ..Default::default()
        };
        assert!(
            scan.normalize_and_validate().is_empty(),
            "format {f} should be accepted"
        );
        assert_eq!(scan.format.as_deref(), Some(f));
    }
    for &p in crate::cmd::scan::POC_TYPE_VALUES {
        let mut scan = ScanConfig {
            poc_type: Some(p.to_string()),
            ..Default::default()
        };
        assert!(
            scan.normalize_and_validate().is_empty(),
            "poc_type {p} should be accepted"
        );
    }
    for &e in crate::cmd::scan::ENCODER_VALUES {
        let mut scan = ScanConfig {
            encoders: Some(vec![e.to_string()]),
            ..Default::default()
        };
        assert!(
            scan.normalize_and_validate().is_empty(),
            "encoder {e} should be accepted"
        );
    }
}
