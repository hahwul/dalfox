use clap::Args;

#[derive(Args)]
pub struct UrlArgs {
    /// Target URL to scan
    #[arg(short = 'u', hide = true)]
    pub url: String,

    /// Output format
    #[arg(short, long, default_value = "json")]
    pub format: String,
}

pub fn run_url(args: UrlArgs) {
    // Redirect to scan with input-type=url
    let scan_args = crate::cmd::scan::ScanArgs {
        input_type: "url".to_string(),
        format: args.format,
        targets: vec![args.url],
        data: None,
        headers: vec![],
        cookies: vec![],
        method: "GET".to_string(),
        user_agent: None,
        mining_dict_word: None,
        skip_mining: false,
        skip_mining_dict: false,
        skip_mining_dom: false,
        skip_discovery: false,
        skip_reflection_header: false,
        skip_reflection_cookie: false,
    };
    crate::cmd::scan::run_scan(&scan_args);
}
