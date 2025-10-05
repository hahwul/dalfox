use clap::{Parser, Subcommand};

mod cmd;
mod target_parser;

#[derive(Parser)]
#[command(name = "dalfox")]
#[command(about = "Powerful open-source XSS scanner")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Targets (when no subcommand is provided, defaults to scan)
    #[arg(value_name = "TARGET")]
    targets: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    Scan(cmd::scan::ScanArgs),
    Server(cmd::server::ServerArgs),
    Payload(cmd::payload::PayloadArgs),
    #[clap(hide = true)]
    Url(cmd::url::UrlArgs),
    #[clap(hide = true)]
    File(cmd::file::FileArgs),
    Pipe(cmd::pipe::PipeArgs),
}

fn main() {
    let cli = Cli::parse();

    if let Some(command) = cli.command {
        match command {
            Commands::Scan(args) => cmd::scan::run_scan(args),
            Commands::Server(args) => cmd::server::run_server(args),
            Commands::Payload(args) => cmd::payload::run_payload(args),
            Commands::Url(args) => cmd::url::run_url(args),
            Commands::File(args) => cmd::file::run_file(args),
            Commands::Pipe(args) => cmd::pipe::run_pipe(args),
        }
    } else {
        // Default to scan
        let args = cmd::scan::ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: cli.targets,
        };
        cmd::scan::run_scan(args);
    }
}
