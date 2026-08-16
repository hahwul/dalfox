use super::*;

#[test]
fn test_format_is_machine_covers_every_non_plain_format() {
    // Every format but `plain` produces a document on stdout, so the
    // banner must be suppressed for all of them. `markdown` is the one
    // that was missing from the hand-written list this replaced, which
    // put seventeen lines of ASCII art at the top of `-f markdown` output.
    for format in FORMAT_VALUES {
        assert_eq!(
            format_is_machine(format),
            *format != "plain",
            "{format} classified wrongly"
        );
    }
    assert!(format_is_machine("markdown"));
    assert!(!format_is_machine("plain"));
}
