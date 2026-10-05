use super::*;
use clap::Parser;

#[derive(Parser)]
enum TestCli {
    Url(UrlArgs),
    File(FileArgs),
    Pipe(PipeArgs),
}

/// Parse `argv` as one of the compat subcommands and convert it the way
/// `main` does.
fn convert(argv: &[&str]) -> ScanArgs {
    match TestCli::parse_from(std::iter::once("dalfox-test").chain(argv.iter().copied())) {
        TestCli::Url(a) => into_scan_args(a.scan_args, "url", a.url.into_iter().collect()),
        TestCli::File(a) => into_scan_args(a.scan_args, "file", vec![a.file]),
        TestCli::Pipe(a) => into_scan_args(a.scan_args, "pipe", vec![]),
    }
}

#[test]
fn test_into_scan_args_sets_mode_and_target() {
    let url = convert(&["url", "--url", "https://example.com"]);
    assert_eq!(url.input_type, "url");
    assert_eq!(url.targets, vec!["https://example.com".to_string()]);

    let file = convert(&["file", "targets.txt"]);
    assert_eq!(file.input_type, "file");
    assert_eq!(file.targets, vec!["targets.txt".to_string()]);

    let pipe = convert(&["pipe"]);
    assert_eq!(pipe.input_type, "pipe");
    assert!(pipe.targets.is_empty());
}

#[test]
fn test_into_scan_args_respects_explicit_input_type() {
    // An explicit `-i` survives instead of being silently overwritten: `-i har`
    // / `-i raw-http` parse the file (or stdin) as a HAR / raw-HTTP document
    // rather than a line-based URL list. The target is unchanged.
    let url = convert(&["url", "--url", "https://example.com", "-i", "raw-http"]);
    assert_eq!(url.input_type, "raw-http");
    assert_eq!(url.targets, vec!["https://example.com".to_string()]);

    for it in ["har", "raw-http"] {
        let file = convert(&["file", "capture.har", "-i", it]);
        assert_eq!(file.input_type, it);
        assert_eq!(file.targets, vec!["capture.har".to_string()]);
    }

    let pipe = convert(&["pipe", "-i", "har"]);
    assert_eq!(pipe.input_type, "har");
    assert!(pipe.targets.is_empty());
}

#[test]
fn test_compat_keeps_positional_targets() {
    // The v2 form `dalfox url <URL>` (no `-u`) must work.
    let url = convert(&["url", "https://example.com"]);
    assert_eq!(url.targets, vec!["https://example.com".to_string()]);
    // Extra positional targets are kept, after the subcommand's own.
    let url = convert(&["url", "-u", "https://a.example", "https://b.example"]);
    assert_eq!(url.targets, ["https://a.example", "https://b.example"]);
    let file = convert(&["file", "a.txt", "b.txt"]);
    assert_eq!(file.targets, ["a.txt", "b.txt"]);
}
