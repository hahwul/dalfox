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
    Url(cmd::compat::UrlArgs),
    #[clap(hide = true)]
    File(cmd::compat::FileArgs),
    #[clap(hide = true)]
    Pipe(cmd::compat::PipeArgs),
}

/// Hand a fully rendered artifact (man page, completion script) to stdout.
///
/// Rendering into a buffer first and writing it here keeps the generators off
/// the real stdout handle: `clap_complete::generate` writes with `expect`, so
/// pointing it at stdout turns any write failure — a full disk, a closed pipe —
/// into a panic from inside the crate. A `Vec<u8>` cannot fail, which leaves
/// exactly one place to report a write error, the way `dalfox man` already did.
fn write_to_stdout(artifact: &str, bytes: &[u8]) {
    use std::io::Write;

    let mut out = std::io::stdout().lock();
    if let Err(e) = out.write_all(bytes).and_then(|()| out.flush()) {
        // A downstream `head` closing the pipe is not a failure — the panic
        // hook installed in `main` already treats `Broken pipe` as a clean exit
        // for the scanning paths, and these one-shot generators get the same
        // treatment rather than a diagnostic nobody can act on.
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            return;
        }
        eprintln!("dalfox: failed to write {artifact}: {e}");
        std::process::exit(2);
    }
}

/// Render the top-level `dalfox` man page from the Clap command definition.
fn print_man_page() {
    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buf = Vec::new();

    if let Err(e) = man.render(&mut buf) {
        eprintln!("dalfox: failed to render man page: {e}");
        std::process::exit(2);
    }

    write_to_stdout("man page", &buf);
}

/// Render the completion script for `shell` from the completion command tree.
fn print_completion_script(shell: Shell) {
    let mut cmd = completion_command();
    let mut buf = Vec::new();

    generate(shell, &mut cmd, BIN_NAME, &mut buf);

    write_to_stdout("completion script", &buf);
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

/// Exit a daemon (`server` / `mcp`) once it has stopped serving.
///
/// Scans run on `spawn_blocking` threads, and returning from `main` drops the
/// runtime, which waits for every blocking thread to finish. So after SIGTERM
/// (or MCP stdin EOF) the process lingered until each in-flight scan ended —
/// forever under the default `scan_timeout` of 0 — still firing payloads at
/// targets with no client attached, and a second Ctrl-C could not stop it.
/// Jobs live only in memory, so nothing is lost by not waiting for them.
fn exit_daemon(outcome: ScanOutcome) -> ! {
    std::process::exit(outcome.exit_code())
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

    // `man` and `completion` each write one generated artifact to stdout and
    // nothing else — the roff has to stay pure roff, the completion script has
    // to stay sourceable — so both are dispatched here, before the
    // banner/config machinery gets a chance to add to that stream.
    match &cli.command {
        Some(Commands::Man) => {
            print_man_page();
            return;
        }
        Some(Commands::Completion { shell }) => {
            print_completion_script(*shell);
            return;
        }
        _ => {}
    }

    // Set global debug toggle for downstream modules
    DEBUG.store(cli.debug, std::sync::atomic::Ordering::Relaxed);
    // Skip banner for MCP subcommand (stdout is JSON-RPC) and for every
    // document format (see `format_is_machine` — everything but `plain`) to
    // keep stdout parseable.
    let is_mcp = matches!(cli.command, Some(Commands::Mcp));
    // Suppress banner for `payload` whenever its stdout is meant to be parsed:
    // a selector emits one-line-per-item output users pipe into grep/jq, and
    // `--json` emits a document. The argless *prose* summary stays
    // human-readable and keeps the banner. Missing the `--json` half left the
    // ASCII banner prepended to the summary document, so `dalfox payload --json`
    // could not be parsed at all.
    let is_payload_machine_output = matches!(
        &cli.command,
        Some(Commands::Payload(args)) if args.selector.is_some() || args.json
    );
    // Read `--format` from the parsed args of *every* scan-bearing subcommand.
    // All four flatten a `ScanArgs`, so the value is already there; only `scan`
    // used to be consulted, and the compat subcommands fell back to a raw-argv
    // `["--format", "json"]` window scan. That window only ever matched the
    // space-separated spelling, so `dalfox url -u URL --format=json` (and
    // `-f=json`, and `-fjson`) prepended the ASCII banner to the JSON document
    // on stdout while `-f json` came out clean. The no-subcommand path needs no
    // fallback: the root `Cli` declares no `--format`/`-f` at all, so
    // `dalfox URL -f json` is a clap parse error, not a scan.
    let cli_scan_format = match &cli.command {
        Some(Commands::Scan(args)) => Some(args.format.as_str()),
        Some(Commands::Url(args)) => Some(args.scan_args.format.as_str()),
        Some(Commands::File(args)) => Some(args.scan_args.format.as_str()),
        Some(Commands::Pipe(args)) => Some(args.scan_args.format.as_str()),
        _ => None,
    };
    let is_machine_format = cli_scan_format.is_some_and(dalfox::cmd::scan::format_is_machine);
    // Banner emission is deferred until after the config file has been
    // loaded (further down) so a `silence = true` in the config file
    // suppresses it the same way the `--silence` CLI flag does.

    // Load configuration with optional --config override
    let mut config_load = match &cli.config {
        Some(cfg_path) => config::load_path(std::path::Path::new(cfg_path)),
        // Default path behavior: $XDG_CONFIG_HOME/dalfox/config.* or $HOME/.config/dalfox/config.*
        None => config::load_or_init(),
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
    //
    // The write itself is best-effort (`let _ = std::fs::write(..)`), so the
    // notice checks the path instead of assuming success: `--config` pointing
    // into a directory that does not exist, or one the process cannot write,
    // used to report "created it with a default template" for a file that was
    // never written — sending the operator to look at a path with nothing in
    // it. Report what actually happened on disk.
    if let (Some(cfg_path), Ok(lr)) = (&cli.config, &config_load)
        && lr.created
    {
        if lr.path.exists() {
            eprintln!(
                "Notice: --config {} did not exist — created it with a default template and ran with built-in defaults (check the path if you meant to load an existing config)",
                cfg_path
            );
        } else {
            eprintln!(
                "Warning: --config {} did not exist and could not be created — ran with built-in defaults (check the path if you meant to load an existing config)",
                cfg_path
            );
        }
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
        for key in &lr.unknown_keys {
            eprintln!(
                "Warning: config {}: unknown key `{key}` ignored",
                lr.path.display()
            );
        }
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
    // A config-file `no_color` must decolour the banner the same way the CLI
    // flag does. `color_enabled` is computed from raw argv before `Cli::parse()`
    // (the banner has to be ready for `-h`), so it cannot see the config file;
    // fold it in here, the same way `config_silence` and `config_machine_format`
    // are folded above. Everything after the banner was already correct —
    // `run_scan` sets the global `NO_COLOR` from the merged args.
    let config_no_color = config_load
        .as_ref()
        .ok()
        .and_then(|r| r.config.scan.as_ref())
        .and_then(|s| s.no_color)
        .unwrap_or(false);
    let banner_color = color_enabled && !config_no_color;
    if config_no_color {
        dalfox::NO_COLOR.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    if !is_mcp
        && !is_machine_format
        && !config_machine_format
        && !effective_silence
        && !is_payload_machine_output
    {
        utils::print_banner_once(env!("CARGO_PKG_VERSION"), banner_color);
    }

    // Exit codes (`ScanOutcome::exit_code`):
    //   0 = success, no findings
    //   1 = success, findings found
    //   2 = input/configuration/runtime error
    //
    // The compat subcommands flatten `ScanArgs`, so their own matches carry
    // the same argument ids the `scan` arm reads; the explicit set is recorded
    // before `into_scan_args` adds the subcommand's own `input_type` to it.
    let compat = |mut scan_args: cmd::scan::ScanArgs, name: &str, targets| {
        scan_args.explicit = explicit_args_for(&matches, name);
        cmd::compat::into_scan_args(scan_args, name, targets)
    };
    let outcome = match cli.command {
        Some(Commands::Server(args)) => {
            // A server that never bound — or whose `axum::serve` failed —
            // has to reach the exit code. A supervisor reads status, not
            // stderr, so the hard-coded `Clean` made "the port was already
            // in use" indistinguishable from a clean shutdown.
            exit_daemon(match server::run_server(args).await {
                Ok(()) => ScanOutcome::Clean,
                Err(_) => ScanOutcome::Error,
            })
        }
        Some(Commands::Mcp) => {
            // Run MCP stdio server (no banner already). A failed handshake
            // or transport error has to reach the exit code: an MCP host or
            // a supervisor (systemd, a process manager, `dalfox mcp || …`)
            // reads status, not stderr, and a hard-coded `Clean` made "the
            // server never came up" indistinguishable from a clean
            // shutdown.
            exit_daemon(match mcp::run_mcp_server().await {
                Ok(()) => ScanOutcome::Clean,
                Err(e) => {
                    eprintln!("MCP server error: {e}");
                    ScanOutcome::Error
                }
            })
        }
        Some(Commands::Payload(args)) => cmd::payload::run_payload(args).await,
        // `man` and `completion` are handled immediately after parsing, so
        // this arm exists only for match exhaustiveness.
        Some(Commands::Completion { .. } | Commands::Man) => unreachable!(),
        command => {
            let args = match command {
                Some(Commands::Scan(mut args)) => {
                    args.explicit = explicit_args_for(&matches, "scan");
                    args
                }
                Some(Commands::Url(a)) => compat(a.scan_args, "url", vec![a.url]),
                Some(Commands::File(a)) => compat(a.scan_args, "file", vec![a.file]),
                Some(Commands::Pipe(a)) => compat(a.scan_args, "pipe", vec![]),
                // Default to scan (`dalfox <TARGET>`); read the global flags
                // from `Cli` so `dalfox URL --silence` and `dalfox URL
                // --no-color` flow through to scan. Everything else is the
                // plain CLI default. Note `insecure` stays `None`: this path
                // accepts no `--insecure` flag, so leaving it unspecified lets
                // config set it via apply_to_scan_args_if_default, and the
                // effective value falls back to insecure (true) when targets
                // are built.
                None => cmd::scan::ScanArgs {
                    targets: cli.targets,
                    no_color: cli.no_color,
                    silence: cli.silence,
                    ..Default::default()
                },
                Some(_) => unreachable!("dispatched above"),
            };
            // `--no-color`/`--silence` are global on `Cli`, config defaults
            // overlay, and `--include-all` expands — all folded in one shared
            // helper so every scan entry point (scan / default / url / file /
            // pipe) stays identical. No banner here — the post-config-load
            // block above already made the full `effective_silence` decision.
            let args = cmd::scan::finalize_scan_args(
                args,
                cli.no_color,
                cli.silence,
                config_load.as_ref().ok().map(|r| &r.config),
            );
            cmd::scan::run_scan(&args).await
        }
    };

    if outcome != ScanOutcome::Clean {
        std::process::exit(outcome.exit_code());
    }
}
