/*
Code by @hahwul
Happy hacking :D
*/

use clap::{Parser, Subcommand};

use dalfox::cmd::scan::ScanOutcome;
use dalfox::{DEBUG, cmd, config, mcp, server, utils};

#[derive(Parser)]
#[command(name = "dalfox")]
#[command(about = "Powerful open-source XSS scanner")]
#[command(version, short_flag = 'V')]
#[command(
    override_usage = "dalfox [COMMAND] [TARGET] <FLAGS>\ne.g., dalfox scan https://dalfox.hahwul.com"
)]
#[command(help_template = r#"
{about-with-newline}
Usage: {usage}

{all-args}
"#)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to a config file (TOML or JSON). Overrides default search path.
    #[arg(long = "config", global = true, value_name = "FILE")]
    config: Option<String>,

    /// Enable debug logging (show DBG lines)
    #[arg(long = "debug", global = true)]
    debug: bool,

    // `--no-color` and `--silence` (`-S`) are accepted at the root level
    // so `dalfox <TARGET> --no-color` (no subcommand) works, *and* with
    // `global = true` they're also accepted on every subcommand
    // (`payload`, `server`, `mcp`, hidden compat). They are still
    // declared on `ScanArgs` separately so `dalfox scan URL --no-color`
    // (flag *after* the scan subcommand) keeps working — the derive
    // macro doesn't always propagate `global = true` to the parent
    // struct, so main.rs OR-merges both locations when dispatching scan.
    /// Disable colored output (also respects NO_COLOR env var)
    #[arg(long = "no-color", global = true)]
    no_color: bool,

    /// Silence all logs except POC output to STDOUT
    #[arg(short = 'S', long = "silence", global = true)]
    silence: bool,

    /// Targets (when no subcommand is provided, defaults to scan)
    #[arg(value_name = "TARGET")]
    targets: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan targets for XSS
    Scan(cmd::scan::ScanArgs),
    /// Run API/server mode
    Server(server::ServerArgs),
    /// Manage or enumerate payloads
    Payload(cmd::payload::PayloadArgs),
    /// Run MCP stdio server (Model Context Protocol) exposing Dalfox tools
    Mcp,

    #[clap(hide = true)]
    Url(cmd::url::UrlArgs),
    #[clap(hide = true)]
    File(cmd::file::FileArgs),
    #[clap(hide = true)]
    Pipe(cmd::pipe::PipeArgs),
}

// Bounded file/stdin readers moved to `crate::utils::fs` so the
// auto-detect / target-list / pipe paths can share the same cap (a
// 5 MB config and a 256 MB target list have very different ceilings,
// but the safety model — refuse non-regular files, enforce a hard
// byte budget — is identical).
use dalfox::utils::fs::read_bounded;

#[tokio::main]
async fn main() {
    // Install the rustls crypto provider (ring) before anything builds a
    // reqwest Client. reqwest uses `rustls-no-provider`, so without this the
    // first Client::build() panics with "no crypto provider configured".
    dalfox::ensure_crypto_provider();

    // Exit cleanly when a downstream consumer (e.g. `head`, `grep -q`) closes
    // the pipe. Rust ignores SIGPIPE by default, so the next `println!` panics
    // inside the stdio shim with `failed printing to stdout: Broken pipe` and
    // exits 101 with a stack trace — surprising for `dalfox payload payloadbox
    // | head -10`. Override the panic hook to swallow only that specific
    // payload and exit 0; any other panic still flows through the default hook.
    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload_str = info
            .payload()
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| info.payload().downcast_ref::<&str>().copied());
        if matches!(payload_str, Some(s) if s.contains("Broken pipe")) {
            std::process::exit(0);
        }
        default_panic_hook(info);
    }));

    // Determine color policy from TTY + `NO_COLOR` env var. The CLI
    // `--no-color` / `-S` flags are inspected via raw argv because clap
    // hasn't parsed yet — the banner is emitted before `Cli::parse()`.
    // We need the color decision before `Cli::parse()` so the -h/--help
    // banner can pick the right palette — clap's auto-help writes to
    // stdout and exits before our normal post-parse banner block runs.
    let __args: Vec<String> = std::env::args().collect();
    let has_flag =
        |needles: &[&str]| -> bool { __args.iter().any(|a| needles.iter().any(|n| a == n)) };
    let no_color_env = std::env::var("NO_COLOR").is_ok();
    let no_color_flag = has_flag(&["--no-color"]);
    let stdout_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let color_enabled = stdout_is_tty && !no_color_env && !no_color_flag;
    // Wire the *global* color decision now so every downstream module
    // (scan, server logger, payload subcommand) honours it consistently.
    // Previously only ScanArgs.no_color drove `crate::NO_COLOR`, leaving
    // `dalfox scan URL | cat` (non-TTY pipe) emitting raw ANSI through
    // the POC line, and `dalfox server` writing escape codes to a
    // redirected log file. Auto-disable when stdout isn't a TTY.
    if !color_enabled {
        dalfox::NO_COLOR.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    if __args.iter().any(|a| a == "-h" || a == "--help") {
        utils::print_banner_once(env!("CARGO_PKG_VERSION"), color_enabled);
    }

    let cli = Cli::parse();
    // Set global debug toggle for downstream modules
    DEBUG.store(cli.debug, std::sync::atomic::Ordering::Relaxed);
    // Skip banner for MCP subcommand (stdout is JSON-RPC) and for
    // machine-readable output formats (json, jsonl, sarif, toml) to keep stdout parseable.
    let is_mcp = matches!(cli.command, Some(Commands::Mcp));
    // Suppress banner when `payload <selector>` is invoked: the selector path
    // emits one-line-per-item output that users routinely pipe into grep/jq.
    // The argless `payload` summary stays human-readable and keeps the banner.
    let is_payload_selector = matches!(
        &cli.command,
        Some(Commands::Payload(args)) if args.selector.is_some()
    );
    let is_machine_format = {
        let scan_format = match &cli.command {
            Some(Commands::Scan(args)) => Some(args.format.as_str()),
            _ => None,
        };
        // Also check raw args for the default-scan path (no subcommand)
        let raw_format = __args
            .windows(2)
            .find(|w| w[0] == "--format" || w[0] == "-f")
            .map(|w| w[1].as_str());
        matches!(
            scan_format.or(raw_format),
            Some("json" | "jsonl" | "sarif" | "toml")
        )
    };
    // Banner emission is deferred until after the config file has been
    // loaded (further down) so a `silence = true` in the config file
    // suppresses it the same way the `--silence` CLI flag does.

    // Load configuration with optional --config override
    let config_load = if let Some(cfg_path) = &cli.config {
        let p = std::path::Path::new(cfg_path);
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if !p.exists() {
            let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
            if ext.eq_ignore_ascii_case("json") {
                let s = config::default_json_template();
                let _ = std::fs::write(p, &s);
                match serde_json::from_str::<config::Config>(&s) {
                    Ok(cfg) => Ok(config::LoadResult {
                        config: cfg,
                        path: p.to_path_buf(),
                        format: config::ConfigFormat::Json,
                        created: true,
                    }),
                    Err(e) => Err(Box::<dyn std::error::Error>::from(e)),
                }
            } else {
                let s = config::default_toml_template();
                let _ = std::fs::write(p, &s);
                match toml::from_str::<config::Config>(&s) {
                    Ok(cfg) => Ok(config::LoadResult {
                        config: cfg,
                        path: p.to_path_buf(),
                        format: config::ConfigFormat::Toml,
                        created: true,
                    }),
                    Err(e) => Err(Box::<dyn std::error::Error>::from(e)),
                }
            }
        } else {
            // Bound the read so `--config /dev/zero` (or any other
            // non-regular file that streams forever) can't hang dalfox
            // indefinitely. Config files are TOML/JSON — 1 MiB is more
            // than two orders of magnitude over what any real
            // operator-curated config will ever be.
            const MAX_CONFIG_BYTES: u64 = 1 << 20; // 1 MiB
            match read_bounded(p, MAX_CONFIG_BYTES, "config file") {
                Ok(content) => {
                    let is_json_ext = p
                        .extension()
                        .and_then(|s| s.to_str())
                        .map(|e| e.eq_ignore_ascii_case("json"))
                        .unwrap_or(false);
                    if is_json_ext {
                        if let Ok(cfg) = serde_json::from_str::<config::Config>(&content) {
                            Ok(config::LoadResult {
                                config: cfg,
                                path: p.to_path_buf(),
                                format: config::ConfigFormat::Json,
                                created: false,
                            })
                        } else if let Ok(cfg) = toml::from_str::<config::Config>(&content) {
                            Ok(config::LoadResult {
                                config: cfg,
                                path: p.to_path_buf(),
                                format: config::ConfigFormat::Toml,
                                created: false,
                            })
                        } else {
                            Err(Box::<dyn std::error::Error>::from(
                                "Failed to parse config as JSON or TOML",
                            ))
                        }
                    } else if let Ok(cfg) = toml::from_str::<config::Config>(&content) {
                        Ok(config::LoadResult {
                            config: cfg,
                            path: p.to_path_buf(),
                            format: config::ConfigFormat::Toml,
                            created: false,
                        })
                    } else if let Ok(cfg) = serde_json::from_str::<config::Config>(&content) {
                        Ok(config::LoadResult {
                            config: cfg,
                            path: p.to_path_buf(),
                            format: config::ConfigFormat::Json,
                            created: false,
                        })
                    } else {
                        Err(Box::<dyn std::error::Error>::from(
                            "Failed to parse config as TOML or JSON",
                        ))
                    }
                }
                Err(e) => Err(Box::<dyn std::error::Error>::from(e)),
            }
        }
    } else {
        // Default path behavior: $XDG_CONFIG_HOME/dalfox/config.* or $HOME/.config/dalfox/config.*
        config::load_or_init()
    };

    // When the user explicitly passes `--config <path>`, a parse failure
    // must be visible — silently falling back to defaults masks typos
    // like an unclosed brace in `my-scan.toml` and leaves the operator
    // wondering why their `silence = true` / `format = "jsonl"` /
    // `encoders = […]` settings had no effect. Implicit default-path
    // loading still stays quiet because most users never create that
    // file and a missing-or-malformed default isn't actionable.
    if let (Some(cfg_path), Err(e)) = (&cli.config, &config_load) {
        eprintln!("Warning: failed to load --config {}: {}", cfg_path, e);
    }

    // Emit the banner now that the config file (if any) has been parsed.
    // `effective_silence` folds three places `--silence` can land:
    //   - `cli.silence` — the root-level flag (`dalfox --silence …`)
    //   - `scan_silence` — the same flag parsed under `Commands::Scan`
    //     because clap stores it on the subcommand's `ArgMatches`, not
    //     the parent, when the user writes `dalfox scan --silence URL`
    //     (the derive macro doesn't auto-propagate to the root struct
    //     even with `global = true`, so we read both places explicitly)
    //   - `config_silence` — the TOML config value, so a config-only
    //     `silence = true` suppresses the banner just like the flag.
    let scan_silence = match &cli.command {
        Some(Commands::Scan(args)) => args.silence,
        _ => false,
    };
    let config_silence = config_load
        .as_ref()
        .ok()
        .and_then(|r| r.config.scan.as_ref())
        .and_then(|s| s.silence)
        .unwrap_or(false);
    let effective_silence = cli.silence || scan_silence || config_silence;
    if !is_mcp && !is_machine_format && !effective_silence && !is_payload_selector {
        utils::print_banner_once(env!("CARGO_PKG_VERSION"), color_enabled);
    }

    // Exit codes:
    //   0 = success, no findings
    //   1 = success, findings found
    //   2 = input/configuration/runtime error
    let outcome;

    if let Some(command) = cli.command {
        match command {
            Commands::Scan(args) => {
                let mut args = args;
                // `--no-color` and `--silence` are global flags on `Cli`
                // so users can write `dalfox scan URL --silence` or
                // `dalfox URL --silence` without clap rejecting them.
                // Mirror the parsed values into `ScanArgs` before the
                // config layer runs so `apply_to_scan_args_if_default`
                // sees them as already-set when deciding precedence.
                args.no_color = args.no_color || cli.no_color;
                args.silence = args.silence || cli.silence;
                if let Ok(res) = &config_load {
                    res.config.apply_to_scan_args_if_default(&mut args);
                }
                if args.include_all {
                    args.include_request = true;
                    args.include_response = true;
                }
                outcome = cmd::scan::run_scan(&args).await;
            }
            Commands::Server(args) => {
                server::run_server(args).await;
                outcome = ScanOutcome::Clean;
            }
            Commands::Payload(args) => {
                outcome = cmd::payload::run_payload(args);
            }
            Commands::Mcp => {
                // Run MCP stdio server (no banner already)
                if let Err(e) = mcp::run_mcp_server().await {
                    eprintln!("MCP server error: {e}");
                }
                outcome = ScanOutcome::Clean;
            }

            Commands::Url(args) => {
                outcome = cmd::url::run_url(args).await;
            }
            Commands::File(args) => {
                outcome = cmd::file::run_file(args).await;
            }
            Commands::Pipe(args) => {
                outcome = cmd::pipe::run_pipe(args).await;
            }
        }
    } else {
        // Default to scan
        let mut args = cmd::scan::ScanArgs {
            detect_outdated_libs: false,
            input_type: "auto".to_string(),
            format: "plain".to_string(),
            targets: cli.targets,
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
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            only_discovery: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: cmd::scan::DEFAULT_TIMEOUT_SECS,
            scan_timeout: 0,
            delay: cmd::scan::DEFAULT_DELAY_MS,
            proxy: None,
            // Scanner default: skip TLS verification. The bare `dalfox <TARGET>`
            // path takes no `--insecure` flag (only global flags are accepted
            // here), so config can still flip this via apply_to_scan_args_if_default.
            insecure: true,
            follow_redirects: false,
            ignore_return: vec![],
            output: None,
            include_request: false,
            include_response: false,
            include_all: false,
            // No-subcommand path (`dalfox <TARGET>`); read the global
            // flags from `Cli` so `dalfox URL --silence` and
            // `dalfox URL --no-color` flow through to scan.
            no_color: cli.no_color,
            silence: cli.silence,
            dry_run: false,
            stream_findings: false,
            poc_type: "plain".to_string(),
            limit: None,
            limit_result_type: "all".to_string(),
            only_poc: vec![],
            workers: cmd::scan::DEFAULT_WORKERS,
            max_concurrent_targets: cmd::scan::DEFAULT_MAX_CONCURRENT_TARGETS,
            max_targets_per_host: cmd::scan::DEFAULT_MAX_TARGETS_PER_HOST,
            encoders: cmd::scan::DEFAULT_ENCODERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            custom_blind_xss_payload: None,
            blind_callback_url: None,
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
            waf_min_confidence: cmd::scan::DEFAULT_WAF_MIN_CONFIDENCE,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };
        if let Ok(res) = &config_load {
            res.config.apply_to_scan_args_if_default(&mut args);
        }
        if args.include_all {
            args.include_request = true;
            args.include_response = true;
        }

        // No redundant banner emission here — the earlier
        // post-config-load block already called `print_banner_once`
        // with the full `effective_silence` decision (CLI, scan
        // subcommand, and config-file silence all OR-folded).
        outcome = cmd::scan::run_scan(&args).await;
    }

    match outcome {
        ScanOutcome::Clean => {} // exit 0
        ScanOutcome::Findings => std::process::exit(1),
        ScanOutcome::Error => std::process::exit(2),
    }
}
