use super::*;
use clap::Parser;

#[derive(Parser)]
struct TestCli {
    #[command(flatten)]
    args: FileArgs,
}

#[test]
fn test_into_scan_args_sets_file_mode_and_target() {
    let cli = TestCli::parse_from(["dalfox-test", "targets.txt"]);
    let scan_args = into_scan_args(cli.args);
    assert_eq!(scan_args.input_type, "file");
    assert_eq!(scan_args.targets, vec!["targets.txt".to_string()]);
}

#[test]
fn test_into_scan_args_respects_explicit_input_type() {
    // `-i har` / `-i raw-http` must survive: the file is then parsed as a HAR /
    // raw-HTTP document rather than a line-based URL list. The file path still
    // becomes the sole target.
    for it in ["har", "raw-http"] {
        let cli = TestCli::parse_from(["dalfox-test", "capture.har", "-i", it]);
        let scan_args = into_scan_args(cli.args);
        assert_eq!(scan_args.input_type, it);
        assert_eq!(scan_args.targets, vec!["capture.har".to_string()]);
    }
}

#[tokio::test]
async fn test_run_file_executes_scan_path_without_panic() {
    let path = std::env::temp_dir().join(format!(
        "dalfox-file-test-{}.txt",
        crate::utils::make_scan_id("file-run")
    ));
    std::fs::write(&path, "http://[::1").expect("write test target file");

    let cli = TestCli::parse_from([
        "dalfox-test",
        path.to_str().expect("utf8 path"),
        "--format",
        "json",
        "-S",
    ]);
    run_file(cli.args).await;

    let _ = std::fs::remove_file(path);
}
