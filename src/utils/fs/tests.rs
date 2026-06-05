use super::*;
use std::io::Write;

fn tmp(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let mut p = std::env::temp_dir();
    p.push(format!(
        "dalfox-fs-test-{}-{}-{}",
        std::process::id(),
        nanos,
        name
    ));
    p
}

#[test]
fn read_bounded_accepts_small_regular_file() {
    let p = tmp("small");
    std::fs::write(&p, b"hello\nworld\n").unwrap();
    let s = read_bounded(&p, 1024, "target list").unwrap();
    assert_eq!(s, "hello\nworld\n");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn read_bounded_rejects_directory() {
    let p = std::env::temp_dir();
    let err = read_bounded(&p, 1024, "target list").unwrap_err();
    assert!(err.to_string().contains("not a regular file"));
}

#[test]
fn read_bounded_rejects_oversized_file_before_open() {
    let p = tmp("too-big");
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(&vec![b'x'; 1024]).unwrap();
    drop(f);
    let err = read_bounded(&p, 100, "target list").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("too large"), "got: {msg}");
    assert!(msg.contains("target list"), "label must appear: {msg}");
    let _ = std::fs::remove_file(&p);
}

#[cfg(unix)]
#[test]
fn read_bounded_rejects_dev_zero() {
    // The whole point of this helper — `/dev/zero` lies about size (0
    // bytes per metadata) but streams forever. The `take(N+1)` guard
    // must trip and the read must return Err instead of OOMing.
    let p = std::path::Path::new("/dev/zero");
    let err = read_bounded(p, 1024, "target list").unwrap_err();
    // `/dev/zero` is a character device, so the regular-file gate
    // catches it before the read even starts.
    assert!(err.to_string().contains("not a regular file"), "got: {err}");
}

#[test]
fn read_bounded_rejects_non_utf8() {
    let p = tmp("non-utf8");
    std::fs::write(&p, vec![0x80, 0x81]).unwrap();
    let err = read_bounded(&p, 1024, "target list").unwrap_err();
    assert!(err.to_string().contains("read failed (or non-UTF8)"));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn read_bounded_accepts_file_at_exact_cap() {
    let p = tmp("exact");
    std::fs::write(&p, b"0123456789").unwrap(); // 10 bytes
    let s = read_bounded(&p, 10, "config file").unwrap();
    assert_eq!(s, "0123456789");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn read_bounded_accepts_empty_file_with_zero_cap() {
    let p = tmp("empty-zero");
    std::fs::write(&p, b"").unwrap();
    let s = read_bounded(&p, 0, "config file").unwrap();
    assert!(s.is_empty());
    let _ = std::fs::remove_file(&p);
}

#[test]
fn read_prefix_lossy_truncates_instead_of_erroring() {
    // Unlike read_bounded, an oversized file is truncated to the prefix so
    // auto-detection can sniff a huge input cheaply.
    let p = tmp("prefix-big");
    std::fs::write(&p, b"0123456789ABCDEF").unwrap(); // 16 bytes
    let s = read_prefix_lossy(&p, 8).unwrap();
    assert_eq!(s, "01234567", "should return only the first 8 bytes");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn read_prefix_lossy_returns_whole_small_file() {
    let p = tmp("prefix-small");
    std::fs::write(&p, b"{\"log\":{\"entries\":[]}}").unwrap();
    let s = read_prefix_lossy(&p, 8192).unwrap();
    assert_eq!(s, "{\"log\":{\"entries\":[]}}");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn read_prefix_lossy_rejects_directory() {
    let err = read_prefix_lossy(&std::env::temp_dir(), 8192).unwrap_err();
    assert!(err.to_string().contains("not a regular file"));
}

#[test]
fn read_prefix_lossy_tolerates_split_multibyte_char() {
    // A 3-byte '…' (U+2026) cut after 1 byte must not error — the partial
    // byte becomes U+FFFD, which the ASCII-only sniff markers ignore.
    let p = tmp("prefix-utf8");
    std::fs::write(&p, "a…b".as_bytes()).unwrap(); // 'a' + 3 bytes + 'b'
    let s = read_prefix_lossy(&p, 2).unwrap();
    assert!(
        s.starts_with('a'),
        "prefix should start with the ASCII byte: {s:?}"
    );
    let _ = std::fs::remove_file(&p);
}
