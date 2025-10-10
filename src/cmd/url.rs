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

pub async fn run_url(args: UrlArgs) {
    // Redirect to scan with input-type=url
    let scan_args = crate::cmd::scan::ScanArgs {
        input_type: "url".to_string(),
        format: args.format,
        targets: vec![args.url],
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
        workers: 10,
        custom_blind_xss_payload: None,
        custom_payload: None,
        only_custom_payload: false,
        fast_scan: false,
        skip_xss_scanning: false,
    };
    crate::cmd::scan::run_scan(&scan_args).await;
}
