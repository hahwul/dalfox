//! Bounded file / stdin readers.
//!
//! Plain `std::fs::read_to_string` and `io::stdin().read_to_string` slurp
//! input with no upper bound — pointing them at `/dev/zero`, a runaway
//! pipe, or a multi-GB list silently exhausts memory. These helpers cap
//! the read at a caller-chosen byte budget and refuse non-regular files
//! up front, so the auto-detect / target-list / config paths can't be
//! turned into a DoS by misclassified input.

use std::io::Read;
use std::path::Path;

/// Default hard cap for bounded file/stdin reads: 256 MiB. Generous enough
/// for legitimate target lists, wordlists, and custom-payload files, while
/// cutting `/dev/zero`, runaway pipes, and gigabyte misclassified blobs to a
/// fast, clear error instead of OOM-ing the process. Shared by the
/// target-list, mining-wordlist, and custom-payload read paths so the limit
/// has a single source of truth. See [`read_bounded`] / [`read_stdin_bounded`].
pub const MAX_FILE_READ_BYTES: u64 = 256 << 20;

/// Read a UTF-8 file with a hard byte cap. Refuses non-regular files
/// (a symlink that resolves to a regular file is fine, since
/// `metadata()` follows symlinks). Returns `Err` when the cap is hit
/// or the file isn't readable as UTF-8.
///
/// `label` is the kind of file being read ("target list", "config
/// file", …). It appears verbatim in the error message so users see
/// which limit they tripped without parsing the source.
pub fn read_bounded(path: &Path, max_bytes: u64, label: &str) -> std::io::Result<String> {
    let md = std::fs::metadata(path)?;
    if !md.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    // metadata() reports a real size for regular files; reject early
    // when it's already over the cap so we don't even open the handle.
    if md.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} too large: {} bytes (cap {})",
                label,
                md.len(),
                max_bytes
            ),
        ));
    }
    let mut f = std::fs::File::open(path)?;
    let mut buf = String::new();
    // `take(N)` enforces the cap during the read itself — even when
    // metadata lied (pseudo-files like `/dev/zero` report size 0 but
    // stream forever).
    f.by_ref()
        .take(max_bytes + 1)
        .read_to_string(&mut buf)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("read failed (or non-UTF8): {}", e),
            )
        })?;
    if buf.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} exceeded {}-byte cap during read (likely a streaming device)",
                label, max_bytes
            ),
        ));
    }
    Ok(buf)
}

/// Read up to `max_bytes` from the start of `path` for cheap content sniffing,
/// returning a lossy-UTF-8 string. Unlike [`read_bounded`], an oversized file
/// is *truncated* to the prefix rather than rejected, so auto-detection can
/// classify a (possibly huge) input from its first few KiB without slurping it
/// in full — the committed input mode reads the whole file afterwards. Refuses
/// non-regular files. The text may end on a U+FFFD replacement if the cut falls
/// mid-multibyte-char, which is harmless for the ASCII markers callers sniff.
pub fn read_prefix_lossy(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    let md = std::fs::metadata(path)?;
    if !md.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    let mut f = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    // `take` bounds the read even for a pseudo-file that streams forever.
    f.by_ref().take(max_bytes).read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Read STDIN into a String with a hard byte cap. Same intent as
/// `read_bounded` but for the streaming side — `cat /dev/zero | dalfox`
/// would otherwise OOM the process.
pub fn read_stdin_bounded(max_bytes: u64, label: &str) -> std::io::Result<String> {
    let mut buf = String::new();
    std::io::stdin()
        .lock()
        .take(max_bytes + 1)
        .read_to_string(&mut buf)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("read failed (or non-UTF8): {}", e),
            )
        })?;
    if buf.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} exceeded {}-byte cap (likely a streaming source)",
                label, max_bytes
            ),
        ));
    }
    Ok(buf)
}

/// Outcome of [`read_stdin_bounded_within`].
#[derive(Debug)]
pub enum StdinRead {
    /// stdin answered within the grace window — it either delivered bytes or
    /// hit an immediate EOF. The payload is the whole stream, read to EOF.
    Data(String),
    /// The grace window elapsed with stdin silent: an open pipe nobody is
    /// writing to. Nothing was consumed that the caller could have used.
    Idle,
}

/// [`read_stdin_bounded`] with a bound on how long we wait for the *first*
/// byte.
///
/// `is_terminal()` cannot tell a pipe that is about to deliver a URL list
/// apart from one a parent process left open and idle (CI harnesses, job
/// runners, wrappers) — both are simply "not a TTY". Blocking on the latter
/// hangs the whole run (#1239). Waiting a short grace window for the first
/// byte separates them: a real producer (`cat urls.txt | dalfox …`) has bytes
/// buffered in the pipe long before we look, while an idle pipe stays silent
/// and the caller can carry on without it.
///
/// Only the first byte is time-bounded. Once the stream starts talking we are
/// committed and read it to EOF like [`read_stdin_bounded`] would, so a large
/// or slowly-written list is never silently truncated.
///
/// The read runs on a detached thread that outlives a timeout — a blocking
/// `read()` on a pipe cannot be cancelled portably. That thread only ever
/// touches stdin and its own buffer, and it is reaped at process exit.
pub fn read_stdin_bounded_within(
    max_bytes: u64,
    label: &str,
    grace: std::time::Duration,
) -> std::io::Result<StdinRead> {
    read_bounded_within(std::io::stdin(), max_bytes, label, grace)
}

/// Reader-generic core of [`read_stdin_bounded_within`], so the timing
/// behaviour can be tested without hijacking the process's real stdin.
fn read_bounded_within<R: Read + Send + 'static>(
    reader: R,
    max_bytes: u64,
    label: &str,
    grace: std::time::Duration,
) -> std::io::Result<StdinRead> {
    use std::sync::mpsc;

    let label = label.to_string();
    // `first_byte` fires as soon as the stream commits to an answer (a byte,
    // EOF, or an error); `done` carries the fully-read result afterwards.
    let (first_byte_tx, first_byte_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<std::io::Result<String>>();

    std::thread::spawn(move || {
        // `take(max + 1)` bounds the read itself, so a stream that never ends
        // stops one byte past the cap and is rejected below.
        let mut reader = reader.take(max_bytes + 1);
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
        let mut announced = false;
        let read_result = loop {
            match reader.read(&mut chunk) {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    if !announced {
                        announced = true;
                        let _ = first_byte_tx.send(());
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                // A signal interrupted the read; the stream is still fine.
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    break Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("read failed (or non-UTF8): {}", e),
                    ));
                }
            }
        };
        // Empty stream or an error on the very first read: still an answer, so
        // release the waiter rather than letting it time out as "idle".
        if !announced {
            let _ = first_byte_tx.send(());
        }
        let result = read_result.and_then(|()| {
            if buf.len() as u64 > max_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "{} exceeded {}-byte cap (likely a streaming source)",
                        label, max_bytes
                    ),
                ));
            }
            String::from_utf8(buf).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("read failed (or non-UTF8): {}", e),
                )
            })
        });
        let _ = done_tx.send(result);
    });

    match first_byte_rx.recv_timeout(grace) {
        // The stream answered — now wait for all of it.
        Ok(()) => done_rx
            .recv()
            .unwrap_or_else(|_| Err(std::io::Error::other("stdin reader ended without a result")))
            .map(StdinRead::Data),
        // Timeout: an open pipe with nothing in it. Disconnected: the reader
        // thread died without answering. Neither yields usable input, and
        // neither is worth failing the run over.
        Err(_) => Ok(StdinRead::Idle),
    }
}

#[cfg(test)]
mod tests;
