use super::*;
use clap::Parser;

#[derive(Parser)]
struct TestCli {
    #[command(flatten)]
    args: UrlArgs,
}

#[test]
fn test_into_scan_args_sets_url_mode_and_target() {
    let cli = TestCli::parse_from(["dalfox-test", "--url", "https://example.com"]);
    let scan_args = into_scan_args(cli.args);
    assert_eq!(scan_args.input_type, "url");
    assert_eq!(scan_args.targets, vec!["https://example.com".to_string()]);
}

#[test]
fn test_into_scan_args_respects_explicit_input_type() {
    // An explicit `-i` survives instead of being silently overwritten with
    // `url`, keeping the entry subcommands consistent.
    let cli = TestCli::parse_from([
        "dalfox-test",
        "--url",
        "https://example.com",
        "-i",
        "raw-http",
    ]);
    let scan_args = into_scan_args(cli.args);
    assert_eq!(scan_args.input_type, "raw-http");
    assert_eq!(scan_args.targets, vec!["https://example.com".to_string()]);
}

#[tokio::test]
async fn test_run_url_executes_scan_path_without_panic() {
    let cli = TestCli::parse_from([
        "dalfox-test",
        "--url",
        "http://[::1",
        "--format",
        "json",
        "-S",
    ]);
    run_url(cli.args).await;
}
