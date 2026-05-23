use clap::{Parser, Subcommand};

use dalfox::cmd::scan::ScanOutcome;
use dalfox::{DEBUG, cmd, config, mcp, utils};

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

    /// Targets (when no subcommand is provided, defaults to scan)
    #[arg(value_name = "TARGET")]
    targets: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan targets for XSS
    Scan(cmd::scan::ScanArgs),
    /// Run API/server mode
    Server(cmd::server::ServerArgs),
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

#[tokio::main]
async fn main() {
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
    let __args: Vec<String> = std::env::args().collect();
    let has_flag =
        |needles: &[&str]| -> bool { __args.iter().any(|a| needles.iter().any(|n| a == n)) };
    let no_color_env = std::env::var("NO_COLOR").is_ok();
    let no_color_flag = has_flag(&["--no-color"]);
    let silence_flag = has_flag(&["-S", "--silence"]);
    let color_enabled =
        std::io::IsTerminal::is_terminal(&std::io::stdout()) && !no_color_env && !no_color_flag;
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
    // Suppress the banner for pipelines/CI: machine formats, MCP stdio,
    // and any `--silence` / `-S` invocation. The ASCII art is large enough
    // that it dominates `| head` output otherwise.
    if !is_mcp && !is_machine_format && !silence_flag && !is_payload_selector {
        utils::print_banner_once(env!("CARGO_PKG_VERSION"), color_enabled);
    }

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
            match std::fs::read_to_string(p) {
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

    // Exit codes:
    //   0 = success, no findings
    //   1 = success, findings found
    //   2 = input/configuration/runtime error
    let outcome;

    if let Some(command) = cli.command {
        match command {
            Commands::Scan(args) => {
                let mut args = args;
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
                cmd::server::run_server(args).await;
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
            delay: cmd::scan::DEFAULT_DELAY_MS,
            proxy: None,
            follow_redirects: false,
            ignore_return: vec![],
            output: None,
            include_request: false,
            include_response: false,
            include_all: false,
            no_color: false,
            silence: false,
            dry_run: false,
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
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
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

        if !is_machine_format {
            utils::print_banner_once(env!("CARGO_PKG_VERSION"), color_enabled);
        }
        outcome = cmd::scan::run_scan(&args).await;
    }

    match outcome {
        ScanOutcome::Clean => {} // exit 0
        ScanOutcome::Findings => std::process::exit(1),
        ScanOutcome::Error => std::process::exit(2),
    }
}
