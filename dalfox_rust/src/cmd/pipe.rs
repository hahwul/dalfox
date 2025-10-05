use clap::Args;

#[derive(Args)]
pub struct PipeArgs {
    /// Output format
    #[arg(short, long, default_value = "json")]
    pub format: String,
}

pub fn run_pipe(args: PipeArgs) {
    // Redirect to scan with input-type=pipe
    let scan_args = crate::cmd::scan::ScanArgs {
        input_type: "pipe".to_string(),
        format: args.format,
        targets: vec![], // No targets needed for pipe
    };
    crate::cmd::scan::run_scan(scan_args);
}
