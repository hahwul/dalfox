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

#[cfg(test)]
mod tests;
