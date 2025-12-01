use clap::{Parser, Subcommand};

use dalfox::{cmd, config, mcp, utils, DEBUG};

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
    // Determine color policy from TTY and print banner early for help
    let __args: Vec<String> = std::env::args().collect();
    let color_enabled = atty::is(atty::Stream::Stdout);
    if __args.iter().any(|a| a == "-h" || a == "--help") {
        utils::print_banner_once(env!("CARGO_PKG_VERSION"), color_enabled);
    }

    let cli = Cli::parse();
    // Set global debug toggle for downstream modules
    DEBUG.store(cli.debug, std::sync::atomic::Ordering::Relaxed);
    // Skip banner for MCP subcommand to keep stdout clean for JSON-RPC
    let is_mcp = matches!(cli.command, Some(Commands::Mcp));
    if !is_mcp {
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

    if let Some(command) = cli.command {
        match command {
            Commands::Scan(args) => {
                let mut args = args;
                if let Ok(res) = &config_load {
                    res.config.apply_to_scan_args_if_default(&mut args);
                }
                cmd::scan::run_scan(&args).await
            }
            Commands::Server(args) => cmd::server::run_server(args).await,
            Commands::Payload(args) => cmd::payload::run_payload(args),
            Commands::Mcp => {
                // Run MCP stdio server (no banner already)
                if let Err(e) = mcp::run_mcp_server().await {
                    eprintln!("MCP server error: {e}");
                }
            }

            Commands::Url(args) => cmd::url::run_url(args).await,
            Commands::File(args) => cmd::file::run_file(args).await,
            Commands::Pipe(args) => cmd::pipe::run_pipe(args).await,
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
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: cmd::scan::DEFAULT_TIMEOUT_SECS,
            delay: cmd::scan::DEFAULT_DELAY_MS,
            proxy: None,
            follow_redirects: false,
            output: None,
            include_request: false,
            include_response: false,
            silence: false,
            poc_type: "plain".to_string(),
            limit: None,
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

            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };
        if let Ok(res) = &config_load {
            res.config.apply_to_scan_args_if_default(&mut args);
        }

        utils::print_banner_once(env!("CARGO_PKG_VERSION"), color_enabled);
        cmd::scan::run_scan(&args).await;
    }
}
