/*
Code by @hahwul
Happy hacking :D
*/

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use clap_complete::{Shell, generate};
use dalfox::cmd::scan::ScanOutcome;
use dalfox::{DEBUG, cmd, config, mcp, server, utils};

/// Binary name, shared by the clap definition, the completion command tree and
/// the `bin_name` the generated scripts key off, so the three cannot drift.
const BIN_NAME: &str = "dalfox";

#[derive(Parser)]
#[command(name = BIN_NAME)]
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
    /// Generate shell completion scripts
    Completion {
        /// Shell to generate completions for
        shell: Shell,
    },
    /// Generate a roff man page and print it to stdout
    #[clap(hide = true)]
    Man,

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

/// Render the top-level `dalfox` man page from the Clap command definition.
fn print_man_page() {
    use std::io::Write;

    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buf = Vec::new();

    if let Err(e) = man.render(&mut buf) {
        eprintln!("dalfox: failed to render man page: {e}");
        std::process::exit(2);
    }

    if let Err(e) = std::io::stdout().write_all(&buf) {
        eprintln!("dalfox: failed to write man page: {e}");
        std::process::exit(2);
    }
}

/// The command tree the shell-completion scripts are generated from: `Cli`
/// minus every `hide = true` subcommand.
///
/// `clap_mangen` drops hidden subcommands on its own, but `clap_complete`'s
/// generators walk `Command::get_subcommands()` unfiltered, so `dalfox <TAB>`
/// would offer the deprecated compat commands (`url` / `file` / `pipe`) and the
/// packaging helper (`man`) that `--help` and the man page both hide — and
/// carry four copies of the flattened `ScanArgs` while doing it.
///
/// `clap::Command` has no `remove_subcommand`, so the root is re-assembled from
/// the real definition's own arguments and its visible subcommands instead. No
/// part of the CLI surface is restated here — the flags and subcommands are
/// `Cli`'s own — and the two root fields that are come from the same constants
/// the derive reads. Only cosmetic root settings the completion scripts never
/// render (usage string, help template) are left behind.
///
/// The subcommand tree is one level deep, so filtering the root's children is
/// the whole job; a nested hidden subcommand would need this to recurse.
fn completion_command() -> clap::Command {
    let full = Cli::command();
    let mut cmd = clap::Command::new(BIN_NAME)
        .version(env!("CARGO_PKG_VERSION"))
        .args(full.get_arguments().cloned())
        .subcommands(
            full.get_subcommands()
                .filter(|sc| !sc.is_hide_set())
                .cloned(),
        );
    if let Some(about) = full.get_about() {
        cmd = cmd.about(about.clone());
    }
    cmd
}

/// Which of `name`'s flags the operator actually typed, for the scan-bearing
/// subcommands (`scan`, and the compat `url` / `file` / `pipe`, which all carry
/// a flattened `ScanArgs`).
///
/// Empty when the subcommand is absent — which is also the correct answer for
/// the no-subcommand path (`dalfox <TARGET>`), since the root `Cli` declares no
/// scan flags of its own for a config file to contend with.
fn explicit_args_for(matches: &clap::ArgMatches, name: &str) -> cmd::scan::ExplicitArgs {
    matches
        .subcommand_matches(name)
        .map(cmd::scan::ExplicitArgs::from_matches)
        .unwrap_or_default()
}

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

    // Parsed via `ArgMatches` rather than `Cli::parse()` so the raw matches
    // survive: they are the only record of *which* flags the operator actually
    // typed, which `ExplicitArgs` needs to keep a config file from overriding
    // an explicit choice that happens to equal the built-in default.
    //
    // `parse()` is these two steps plus `format_error`, which attaches the
    // command so a failure prints usage instead of a bare message; it is
    // mirrored here rather than dropped. (Only the `get_matches` half can fail
    // on user input — everything reachable from `from_arg_matches` is a
    // definition/access mismatch — but the two must not diverge in how they
    // report.)
    let matches = Cli::command().get_matches();
    let cli =
        Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.format(&mut Cli::command()).exit());

    // Keep man-page output as pure roff by handling it before the
    // banner/config machinery writes anything else to stdout.
    if let Some(command) = &cli.command {
        match command {
            Commands::Man => {
                print_man_page();
                return;
            }
            Commands::Completion { shell } => {
                let mut cmd = completion_command();
                generate(*shell, &mut cmd, BIN_NAME, &mut std::io::stdout());
                return;
            }
            _ => {}
        }
    }

    // Set global debug toggle for downstream modules
    DEBUG.store(cli.debug, std::sync::atomic::Ordering::Relaxed);
    // Skip banner for MCP subcommand (stdout is JSON-RPC) and for every
    // document format (see `format_is_machine` — everything but `plain`) to
    // keep stdout parseable.
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
        scan_format
            .or(raw_format)
            .is_some_and(dalfox::cmd::scan::format_is_machine)
    };
    // Banner emission is deferred until after the config file has been
    // loaded (further down) so a `silence = true` in the config file
    // suppresses it the same way the `--silence` CLI flag does.

    // Load configuration with optional --config override
    let mut config_load = if let Some(cfg_path) = &cli.config {
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
            match read_bounded(p, dalfox::config::MAX_CONFIG_BYTES, "config file") {
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

    // A missing explicit `--config <path>` is scaffolded with a default template
    // (see the create-if-missing branch above) and the scan proceeds on built-in
    // defaults. That convenience is fine, but doing it *silently* reproduces the
    // exact footgun the warning above guards against: a typo in the path (or a
    // wrong directory) then runs with defaults while the operator believes their
    // `encoders` / `method` / `format` settings applied — and writes an
    // unsolicited file at the mistyped location. Surface it on stderr so the
    // creation is visible; stdout stays clean for machine formats. Scoped to the
    // explicit-`--config` path only — the implicit default-path init
    // (`load_or_init`, `cli.config == None`) stays quiet on purpose so a
    // first-time user isn't nagged about their bootstrapped config.
    if let (Some(cfg_path), Ok(lr)) = (&cli.config, &config_load)
        && lr.created
    {
        eprintln!(
            "Notice: --config {} did not exist — created it with a default template and ran with built-in defaults (check the path if you meant to load an existing config)",
            cfg_path
        );
    }

    // Config values are deserialized straight into `Config` and never pass
    // through clap's value-parsers, so an invalid `format`, a lowercase
    // `method`, or a `limit = 0` would be copied verbatim into `ScanArgs` and
    // silently misbehave. Normalize/validate once here — before the config
    // drives any banner/format decision or overlays onto scan args — so every
    // downstream entry point (scan / default / url / file / pipe) sees a clean
    // config. Invalid fields fall back to their built-in defaults and each
    // emits an actionable stderr warning (stdout stays clean for machine
    // formats). The default `~/.config/dalfox/config.toml` is all-commented, so
    // this is silent unless the operator set a real value.
    if let Ok(lr) = config_load.as_mut() {
        for warning in lr.config.normalize_and_validate() {
            eprintln!("Warning: {warning}");
        }
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
    // A machine-readable `format` set *only* in the config file (not on the CLI)
    // must also suppress the banner — otherwise the ASCII banner is prepended to
    // the machine-format document on stdout and breaks any pipeline that
    // configures the format via file rather than `--format`. `is_machine_format`
    // above only sees CLI args, so fold the config value in the same way
    // `config_silence` folds the config `silence`.
    let config_machine_format = config_load
        .as_ref()
        .ok()
        .and_then(|r| r.config.scan.as_ref())
        .and_then(|s| s.format.as_deref())
        .map(dalfox::cmd::scan::format_is_machine)
        .unwrap_or(false);
    let effective_silence = cli.silence || scan_silence || config_silence;
    if !is_mcp
        && !is_machine_format
        && !config_machine_format
        && !effective_silence
        && !is_payload_selector
    {
        utils::print_banner_once(env!("CARGO_PKG_VERSION"), color_enabled);
    }

    // Exit codes:
    //   0 = success, no findings
    //   1 = success, findings found
    //   2 = input/configuration/runtime error
    let outcome;

    if let Some(command) = cli.command {
        match command {
            Commands::Scan(mut args) => {
                args.explicit = explicit_args_for(&matches, "scan");
                // `--no-color`/`--silence` are global on `Cli`, config defaults
                // overlay, and `--include-all` expands — all folded in one shared
                // helper so this path and `url`/`file`/`pipe` stay identical.
                let args = cmd::scan::finalize_scan_args(
                    args,
                    cli.no_color,
                    cli.silence,
                    config_load.as_ref().ok().map(|r| &r.config),
                );
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

            Commands::Completion { .. } => unreachable!(),

            // `dalfox man` is handled immediately after parsing so this arm
            // should never execute. It exists only for match exhaustiveness.
            Commands::Man => unreachable!(),

            // The compat subcommands flatten `ScanArgs`, so their own matches
            // carry the same argument ids the `scan` arm reads above.
            Commands::Url(mut args) => {
                args.scan_args.explicit = explicit_args_for(&matches, "url");
                let config = config_load.as_ref().ok().map(|r| &r.config);
                outcome = cmd::url::run_url(args, cli.no_color, cli.silence, config).await;
            }
            Commands::File(mut args) => {
                args.scan_args.explicit = explicit_args_for(&matches, "file");
                let config = config_load.as_ref().ok().map(|r| &r.config);
                outcome = cmd::file::run_file(args, cli.no_color, cli.silence, config).await;
            }
            Commands::Pipe(mut args) => {
                args.scan_args.explicit = explicit_args_for(&matches, "pipe");
                let config = config_load.as_ref().ok().map(|r| &r.config);
                outcome = cmd::pipe::run_pipe(args, cli.no_color, cli.silence, config).await;
            }
        }
    } else {
        // Default to scan
        let args = cmd::scan::ScanArgs {
            targets: cli.targets,
            // No-subcommand path (`dalfox <TARGET>`); read the global
            // flags from `Cli` so `dalfox URL --silence` and
            // `dalfox URL --no-color` flow through to scan.
            no_color: cli.no_color,
            silence: cli.silence,
            // Everything else is the plain CLI default. Note `insecure` stays
            // `None`: this path accepts no `--insecure` flag, so leaving it
            // unspecified lets config set it via apply_to_scan_args_if_default,
            // and the effective value falls back to insecure (true) when
            // targets are built.
            ..Default::default()
        };
        // Same config-overlay + `--include-all` expansion as every other entry
        // point. `no_color`/`silence` were already set from `cli` above, so the
        // helper's fold is a no-op here.
        let args = cmd::scan::finalize_scan_args(
            args,
            cli.no_color,
            cli.silence,
            config_load.as_ref().ok().map(|r| &r.config),
        );

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
