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

// ── read_bounded_within: grace window on the *first* byte ───────────
//
// The real stdin can't be swapped out inside a test process, so these
// drive the reader-generic core with readers that reproduce the shapes
// that matter: a live-but-silent pipe, a normal producer, and a producer
// that keeps the stream open long after its first byte (#1239).

/// Blocks on every read for `hold`, then reports EOF — an open pipe whose
/// writer never sends anything.
struct SilentReader {
    hold: std::time::Duration,
}

impl std::io::Read for SilentReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        std::thread::sleep(self.hold);
        Ok(0)
    }
}

/// Emits `head` immediately, then holds the stream open for `hold` before
/// delivering `tail` and EOF — a slow producer that has already started.
struct SlowTailReader {
    head: Vec<u8>,
    tail: Vec<u8>,
    hold: std::time::Duration,
    sent_head: bool,
}

impl std::io::Read for SlowTailReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.sent_head {
            self.sent_head = true;
            let n = self.head.len().min(buf.len());
            buf[..n].copy_from_slice(&self.head[..n]);
            return Ok(n);
        }
        if !self.tail.is_empty() {
            std::thread::sleep(self.hold);
            let n = self.tail.len().min(buf.len());
            buf[..n].copy_from_slice(&self.tail[..n]);
            self.tail.drain(..n);
            return Ok(n);
        }
        Ok(0)
    }
}

#[test]
fn read_bounded_within_reports_idle_when_nothing_arrives() {
    let reader = SilentReader {
        hold: std::time::Duration::from_secs(30),
    };
    let started = std::time::Instant::now();
    let out = read_bounded_within(
        reader,
        1024,
        "stdin pipe",
        std::time::Duration::from_millis(100),
    )
    .unwrap();
    assert!(
        matches!(out, StdinRead::Idle),
        "a silent pipe must not block the caller: {out:?}"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "should have returned right after the grace window"
    );
}

#[test]
fn read_bounded_within_returns_data_that_is_ready() {
    let out = read_bounded_within(
        std::io::Cursor::new(b"http://a.example\nhttp://b.example\n".to_vec()),
        1024,
        "stdin pipe",
        std::time::Duration::from_secs(5),
    )
    .unwrap();
    match out {
        StdinRead::Data(s) => assert_eq!(s.lines().count(), 2),
        StdinRead::Idle => panic!("buffered input must not be reported as idle"),
    }
}

#[test]
fn read_bounded_within_treats_immediate_eof_as_empty_data() {
    // `echo -n "" | dalfox scan <URL>`: stdin answered, it just had nothing.
    // That's not the idle case — there is no producer to wait for.
    let out = read_bounded_within(
        std::io::Cursor::new(Vec::new()),
        1024,
        "stdin pipe",
        std::time::Duration::from_millis(100),
    )
    .unwrap();
    match out {
        StdinRead::Data(s) => assert!(s.is_empty()),
        StdinRead::Idle => panic!("a closed empty stream is data, not idle"),
    }
}

#[test]
fn read_bounded_within_bounds_only_the_first_byte_not_the_whole_read() {
    // Once the stream talks we're committed: a list still being written when
    // the grace window expires must arrive whole, never truncated.
    let out = read_bounded_within(
        SlowTailReader {
            head: b"http://first.example\n".to_vec(),
            tail: b"http://second.example\n".to_vec(),
            hold: std::time::Duration::from_millis(300),
            sent_head: false,
        },
        1024,
        "stdin pipe",
        std::time::Duration::from_millis(50),
    )
    .unwrap();
    match out {
        StdinRead::Data(s) => assert_eq!(
            s, "http://first.example\nhttp://second.example\n",
            "the tail written after the grace window must still be read"
        ),
        StdinRead::Idle => panic!("stream had data before the window expired"),
    }
}

#[test]
fn read_bounded_within_enforces_the_byte_cap() {
    let err = read_bounded_within(
        std::io::Cursor::new(vec![b'x'; 64]),
        16,
        "stdin pipe",
        std::time::Duration::from_secs(5),
    )
    .unwrap_err();
    assert!(err.to_string().contains("exceeded 16-byte cap"));
}

#[test]
fn read_bounded_within_rejects_non_utf8() {
    let err = read_bounded_within(
        std::io::Cursor::new(vec![0x80, 0x81]),
        1024,
        "stdin pipe",
        std::time::Duration::from_secs(5),
    )
    .unwrap_err();
    assert!(err.to_string().contains("read failed (or non-UTF8)"));
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
