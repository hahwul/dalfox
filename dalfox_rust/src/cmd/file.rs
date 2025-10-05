use clap::Args;

#[derive(Args)]
pub struct FileArgs {
    /// Target file containing URLs to scan
    #[arg(value_name = "FILE")]
    pub file: String,

    /// Output format
    #[arg(short, long, default_value = "json")]
    pub format: String,
}

pub fn run_file(args: FileArgs) {
    // Redirect to scan with input-type=file
    let scan_args = crate::cmd::scan::ScanArgs {
        input_type: "file".to_string(),
        format: args.format,
        targets: vec![args.file],
    };
    crate::cmd::scan::run_scan(scan_args);
}
