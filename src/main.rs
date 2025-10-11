use clap::{Parser, Subcommand};
use tokio;

mod cmd;
mod encoding;
mod parameter_analysis;
mod payload;
mod scanning;
mod target_parser;

#[derive(Parser)]
#[command(name = "dalfox")]
#[command(about = "Powerful open-source XSS scanner")]
#[command(version, short_flag = 'V')]
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
    #[clap(hide = true)]
    Pipe(cmd::pipe::PipeArgs),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Some(command) = cli.command {
        match command {
            Commands::Scan(args) => cmd::scan::run_scan(&args).await,
            Commands::Server(args) => cmd::server::run_server(args),
            Commands::Payload(args) => cmd::payload::run_payload(args),
            Commands::Url(args) => cmd::url::run_url(args).await,
            Commands::File(args) => cmd::file::run_file(args).await,
            Commands::Pipe(args) => cmd::pipe::run_pipe(args).await,
        }
    } else {
        // Default to scan
        let args = cmd::scan::ScanArgs {
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
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            output: None,
            include_request: false,
            include_response: false,
            silence: false,
            workers: 50,
            max_concurrent_targets: 50,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            fast_scan: false,
            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
        };
        cmd::scan::run_scan(&args).await;
    }
}
