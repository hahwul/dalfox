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
    assert!(
        err.to_string().contains("not a regular file"),
        "got: {err}"
    );
}
