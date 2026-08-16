//! `--state-file`: an opt-in, append-only record of which targets reached a
//! terminal state, so an interrupted mass scan resumes instead of restarting.
//!
//! Ctrl-C already stops cleanly and still prints what was found, but nothing
//! recorded *which targets finished* — so on a 50k-URL list, stopping at 80%
//! and re-running redid the 80%. The same applies to a crash, a lost SSH
//! session, or an OOM on a shared box.
//!
//! Shape of the file (JSONL, one object per line):
//!
//! ```text
//! {"dalfox_state":1,"version":"3.1.0","config_hash":"…","created":"…"}
//! {"target":"https://x/?a=1","method":"GET","outcome":"completed","at":"…"}
//! ```
//!
//! Design notes:
//!
//! - **Append-only.** One line is written per target as it finishes, so a hard
//!   kill can at worst tear the final line — which [`load`] skips. Nothing is
//!   ever rewritten in place, so there is no window where the file is invalid.
//!   Lines are flushed but not `fsync`ed: that survives `kill -9` (the page
//!   cache outlives the process), not a machine crash, which is the right
//!   trade for a progress log written once per target.
//! - **Only `completed` is skipped.** `cancelled` (SIGINT / `--scan-timeout`)
//!   and `error` (preflight skip) targets are retried on the next run, because
//!   how much of them was actually covered is unknown.
//! - **A configuration change starts fresh.** The header carries a hash of the
//!   scan-affecting configuration; when it does not match, the prior results
//!   are not comparable, so the file is reset rather than silently skipping
//!   targets under settings that never tested them (see [`config_hash`]).

use super::args::ScanArgs;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Bumped only if the record schema changes incompatibly. A file written by a
/// newer format is treated like a mismatched config hash: reset, never
/// misread.
pub(crate) const STATE_FORMAT_VERSION: u32 = 1;

/// Upper bound on a state file we will read back. One record is ~120 bytes, so
/// 256 MiB is past two million targets while still failing fast on a path that
/// resolves to something unbounded.
pub(crate) const MAX_STATE_FILE_BYTES: u64 = 256 << 20;

/// Terminal state of one target, as recorded in the state file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TargetOutcome {
    /// Scanned to the end. The only outcome a later run skips.
    Completed,
    /// Cut short — Ctrl-C, `--scan-timeout`, or a dead session — so coverage
    /// is unknown and the target is retried.
    Cancelled,
    /// Never scanned: dropped during preflight (unreachable, content-type
    /// mismatch, per-host cap). Also retried.
    Error,
}

impl TargetOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            TargetOutcome::Completed => "completed",
            TargetOutcome::Cancelled => "cancelled",
            TargetOutcome::Error => "error",
        }
    }
}

/// Cross-run identity of a target: the same `url|method` pair the `exact`
/// dedup mode keys on (`input::dedup_targets`), so "one target" means the same
/// thing to resume as it does to dedup.
pub(crate) fn target_key(url: &str, method: &str) -> String {
    format!("{}|{}", url, method)
}

/// Hash of the configuration that decides *what a completed target was tested
/// with*. A run whose hash differs cannot reuse the prior file's completions.
///
/// Built as a denylist over the whole of [`ScanArgs`] — every field counts
/// unless it is explicitly neutralized below — so a flag added later is
/// included automatically. That direction matters: a forgotten *exclusion*
/// costs an over-cautious fresh start, while a forgotten *inclusion* would
/// silently skip targets that were never tested under the new settings.
///
/// Neutralized, with the reason each cannot change what a completed target
/// covered:
///
/// - **Input source** (`targets`, `input_type`) — the same campaign is
///   legitimately driven as `dalfox file list.txt`, as a pipe, or as a shell
///   loop of `dalfox url <one>` invocations sharing one state file. Hashing
///   the target list would reset the file on every iteration of that loop,
///   which is precisely the workflow resume exists for.
/// - **Reporting** (`format`, `output`, `poc_type`, `include_*`, `no_color`,
///   `silence`, `stream_findings`, `only_poc`, `baseline*`, `state_file`,
///   `dry_run`, `only_discovery`) — presentation and post-processing of
///   findings already made. The two preview modes never write records at all.
///   `limit` and `limit_result_type` are deliberately *not* here: `--limit`
///   stops the scan early, so it decides coverage.
/// - **Pacing** (`timeout`, `scan_timeout`, `delay`, `rate_limit`, `retries`,
///   `retry_delay`, `workers`, `max_concurrent_targets`) — how fast requests
///   go out and how long one is waited on, not which are sent. Raising these
///   after a timeout-heavy run is the normal reaction to an interrupted scan;
///   the targets that suffered are recorded `cancelled`/`error` and retried
///   regardless.
///
/// The major version is mixed in for the same reason `--baseline` refuses a
/// report from another major: payload sets and detection change between them,
/// so completions are not comparable even with identical flags.
pub(crate) fn config_hash(args: &ScanArgs) -> String {
    use sha2::{Digest, Sha256};

    let d = ScanArgs::default();
    let mut a = args.clone();

    // Input source.
    a.targets = d.targets.clone();
    a.input_type = d.input_type.clone();
    // Reporting / post-processing.
    a.format = d.format.clone();
    a.output = d.output.clone();
    a.poc_type = d.poc_type.clone();
    a.include_request = d.include_request;
    a.include_response = d.include_response;
    a.include_all = d.include_all;
    a.no_color = d.no_color;
    a.silence = d.silence;
    a.stream_findings = d.stream_findings;
    a.only_poc = d.only_poc.clone();
    a.baseline = d.baseline.clone();
    a.baseline_mode_arg = d.baseline_mode_arg.clone();
    a.state_file = d.state_file.clone();
    a.dry_run = d.dry_run;
    a.only_discovery = d.only_discovery;
    // Pacing.
    a.timeout = d.timeout;
    a.scan_timeout = d.scan_timeout;
    a.delay = d.delay;
    a.rate_limit = d.rate_limit;
    a.retries = d.retries;
    a.retry_delay = d.retry_delay;
    a.workers = d.workers;
    a.max_concurrent_targets = d.max_concurrent_targets;

    // Provenance, not configuration: `explicit` records *which* flags were
    // typed, and every value it could influence is already hashed on its own
    // above. Hashing it too would mean `dalfox scan --workers 50` and a config
    // file supplying the same 50 produce different hashes for an identical
    // scan, so the state file would reset whenever a setting moved between the
    // two — a difference that changes nothing about what a target was tested
    // with.
    //
    // Note this neutralization does not make the *upgrade* free: the field
    // still widens `ScanArgs: Debug`, so every state file written before it
    // existed hashes differently and resets once on first run after upgrading.
    // That is the direction this function deliberately errs in (see the
    // denylist rationale above) — a needless re-scan, never a silent skip.
    a.explicit = d.explicit.clone();

    // `ScanArgs: Debug` is the whole struct by construction, which is what
    // makes the denylist above self-maintaining.
    let mut hasher = Sha256::new();
    hasher.update(major_of(env!("CARGO_PKG_VERSION")).as_bytes());
    hasher.update([0u8]);
    hasher.update(format!("{:?}", a).as_bytes());
    hex::encode(&hasher.finalize()[..8])
}

/// Major-version component of a semver-ish string (`"3.1.0"` → `"3"`).
fn major_of(v: &str) -> &str {
    v.split('.').next().unwrap_or(v)
}

#[derive(Serialize, Deserialize)]
struct Header {
    dalfox_state: u32,
    version: String,
    config_hash: String,
    created: String,
}

#[derive(Serialize, Deserialize)]
struct Record {
    target: String,
    method: String,
    outcome: String,
    at: String,
}

/// What reading an existing state file produced.
struct Loaded {
    completed: HashSet<String>,
    /// Terminal state already on record per target key, including the
    /// non-reusable ones. Used to suppress a re-record of an outcome the file
    /// already carries, which is what bounds the file's growth: without it a
    /// permanently unreachable host adds one `error` line per run until the
    /// file crosses the read cap and the campaign can no longer be resumed.
    prior: std::collections::HashMap<String, String>,
    /// Set when the file could not be resumed from and has to be started over;
    /// carries the operator-facing reason.
    reset: Option<String>,
    /// Lines that did not parse — a torn final line after a hard kill, in the
    /// normal case. Reported so a *systematically* unreadable file is visible
    /// rather than looking like an empty one.
    corrupt_lines: usize,
}

/// Read `path` and decide whether its completions can be reused under `hash`.
///
/// Three outcomes, and which one applies is decided by how much we can vouch
/// for the file's contents:
///
/// - **Reusable** — a dalfox state file whose header matches this run.
/// - **Reset** — a dalfox state file we understand but cannot reuse (older
///   format version, foreign config hash). Its records are known to describe
///   scans under other settings, so [`StateFile::open`] moves it aside and
///   starts a new one.
/// - **`Err`** — anything else: a file we cannot read at all, or one whose
///   first line is not a dalfox header. Both are files whose contents we
///   cannot judge, and the reset path would destroy them. A single typo
///   (`--state-file urls.txt`) must not eat the target list, so the run stops
///   and says so instead.
fn load(path: &str, hash: &str) -> Result<Loaded, String> {
    let fresh = |reset: Option<String>| {
        Ok(Loaded {
            completed: HashSet::new(),
            prior: std::collections::HashMap::new(),
            reset,
            corrupt_lines: 0,
        })
    };

    let raw = match std::fs::metadata(path) {
        // No file yet is the ordinary first run, not a reset.
        Err(_) => return fresh(None),
        Ok(_) => match crate::utils::fs::read_bounded(
            std::path::Path::new(path),
            MAX_STATE_FILE_BYTES,
            "state file",
        ) {
            Ok(s) => s,
            Err(e) => {
                return Err(format!(
                    "--state-file '{}' exists but could not be read ({}); move it aside or point --state-file elsewhere",
                    path, e
                ));
            }
        },
    };

    if raw.trim().is_empty() {
        return fresh(None);
    }

    let mut lines = raw.lines().filter(|l| !l.trim().is_empty());
    let header: Header = match lines.next().map(serde_json::from_str::<Header>) {
        Some(Ok(h)) => h,
        _ => {
            return Err(format!(
                "--state-file '{}' is not a dalfox state file (no state header on its first line); move it aside or point --state-file elsewhere",
                path
            ));
        }
    };
    if header.dalfox_state != STATE_FORMAT_VERSION {
        return fresh(Some(format!(
            "'{}' is state format v{} but this build writes v{}",
            path, header.dalfox_state, STATE_FORMAT_VERSION
        )));
    }
    if header.config_hash != hash {
        return fresh(Some(format!(
            "scan configuration changed since '{}' was written (recorded {}, now {})",
            path, header.config_hash, hash
        )));
    }

    let mut completed = HashSet::new();
    let mut prior = std::collections::HashMap::new();
    let mut corrupt_lines = 0usize;
    for line in lines {
        match serde_json::from_str::<Record>(line) {
            Ok(r) => {
                let key = target_key(&r.target, &r.method);
                // Only completions are reusable; `cancelled` / `error` targets
                // are retried. Both go into `prior` — the later runs need to
                // know a target's recorded outcome to avoid re-appending it.
                if r.outcome == TargetOutcome::Completed.as_str() {
                    completed.insert(key.clone());
                }
                prior.insert(key, r.outcome);
            }
            Err(_) => corrupt_lines += 1,
        }
    }

    Ok(Loaded {
        completed,
        prior,
        reset: None,
        corrupt_lines,
    })
}

/// An open state file: the completions carried over from previous runs, plus
/// the append handle this run records into.
pub(crate) struct StateFile {
    path: String,
    completed: HashSet<String>,
    prior: std::collections::HashMap<String, String>,
    /// `None` when this run must not write — a preview mode, or once a write
    /// has failed (the warning is emitted once and the scan continues, rather
    /// than repeating per target).
    handle: Mutex<Option<std::fs::File>>,
    write_failed: AtomicBool,
    silence: bool,
    /// Why the prior file was set aside, if it was. Surfaced by the caller.
    pub(crate) reset_reason: Option<String>,
    /// Unparseable lines skipped while reading.
    pub(crate) corrupt_lines: usize,
    /// Where a reset moved the previous file, when one was moved.
    pub(crate) reset_backup: Option<String>,
}

impl StateFile {
    /// Open `path` for a scanning run: read what previous runs completed under
    /// the same configuration, then position the file for appends.
    ///
    /// Fails when the file cannot be written, or when it exists and cannot be
    /// read or recognized (see [`load`]). The operator asked for a resumable
    /// run; finding out after a two-hour scan that nothing was recorded is the
    /// failure this whole feature exists to prevent, so both are reported up
    /// front, before any request goes out.
    pub(crate) fn open(path: &str, args: &ScanArgs) -> Result<Self, String> {
        Self::open_inner(path, args, false)
    }

    /// Open `path` for a run that must not touch it: `--dry-run` and
    /// `--only-discovery` filter their plan through the recorded completions,
    /// but they send no attack traffic and complete nothing, so they have no
    /// business creating the file, writing a header, or setting it aside on a
    /// hash mismatch. Pricing out `--deep-scan` with a `--dry-run` must not
    /// disturb a campaign's recorded progress.
    pub(crate) fn open_read_only(path: &str, args: &ScanArgs) -> Result<Self, String> {
        Self::open_inner(path, args, true)
    }

    fn open_inner(path: &str, args: &ScanArgs, read_only: bool) -> Result<Self, String> {
        let hash = config_hash(args);
        let loaded = load(path, &hash)?;

        let mut state = StateFile {
            path: path.to_string(),
            completed: loaded.completed,
            prior: loaded.prior,
            handle: Mutex::new(None),
            write_failed: AtomicBool::new(false),
            silence: args.silence,
            reset_reason: loaded.reset,
            corrupt_lines: loaded.corrupt_lines,
            reset_backup: None,
        };

        if read_only {
            // A reset is a *write* decision; with nothing to write there is
            // nothing to reset, and the completions were already dropped by
            // `load`. Keep the reason (the caller still warns) but do not
            // touch the file.
            return Ok(state);
        }

        // A reset starts a new file, and the old one is moved aside rather
        // than truncated. It is a legitimate record of real work — an
        // authenticated campaign resumed with a rotated `--cookies` value hits
        // this path — and "your progress is in scan.state.bak" is recoverable
        // where an in-place truncate is not.
        if state.reset_reason.is_some() {
            let backup = format!("{}.bak", path);
            match std::fs::rename(path, &backup) {
                Ok(()) => state.reset_backup = Some(backup),
                Err(e) => {
                    return Err(format!(
                        "--state-file '{}' has to be started over but could not be moved to '{}': {}",
                        path, backup, e
                    ));
                }
            }
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("--state-file '{}' could not be opened: {}", path, e))?;

        // Header goes in when the file is new or was just moved aside. Judged
        // by length so a zero-byte file left behind by an earlier failure gets
        // one too.
        let needs_header = file.metadata().map(|m| m.len() == 0).unwrap_or(true);
        if needs_header {
            let header = Header {
                dalfox_state: STATE_FORMAT_VERSION,
                version: env!("CARGO_PKG_VERSION").to_string(),
                config_hash: hash,
                created: chrono::Local::now().to_rfc3339(),
            };
            let line = serde_json::to_string(&header)
                .map_err(|e| format!("--state-file header could not be encoded: {}", e))?;
            writeln!(file, "{}", line)
                .and_then(|_| file.flush())
                .map_err(|e| format!("--state-file '{}' could not be written: {}", path, e))?;
        }

        *state.handle.get_mut().expect("fresh mutex") = Some(file);
        Ok(state)
    }

    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    /// How many targets previous runs finished — the number this run will skip
    /// if the input list is unchanged.
    pub(crate) fn completed_count(&self) -> usize {
        self.completed.len()
    }

    pub(crate) fn is_completed(&self, url: &str, method: &str) -> bool {
        self.completed.contains(&target_key(url, method))
    }

    /// Append one terminal-state record. Best-effort by design: a scan that is
    /// producing findings must not be aborted because the progress log hit a
    /// full disk, so the first failure warns and the rest are silent.
    pub(crate) fn record(&self, url: &str, method: &str, outcome: TargetOutcome) {
        // Nothing to say when the file already records this exact outcome for
        // this target. Retried targets are the common case — a host that is
        // down stays down — and re-appending an identical `error` line every
        // run is what would eventually push the file past the read cap and
        // strand the campaign.
        if self.prior.get(&target_key(url, method)).map(String::as_str) == Some(outcome.as_str()) {
            return;
        }
        let record = Record {
            target: url.to_string(),
            method: method.to_string(),
            outcome: outcome.as_str().to_string(),
            at: chrono::Local::now().to_rfc3339(),
        };
        let Ok(line) = serde_json::to_string(&record) else {
            return;
        };

        let mut guard = match self.handle.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(file) = guard.as_mut() else {
            return;
        };
        // One `writeln!` of a sub-4KiB line on an O_APPEND handle, under this
        // lock, so concurrent per-target tasks cannot interleave a record.
        if let Err(e) = writeln!(file, "{}", line).and_then(|_| file.flush()) {
            *guard = None;
            if !self.write_failed.swap(true, Ordering::Relaxed) && !self.silence {
                eprintln!(
                    "Warning: --state-file '{}' stopped recording ({}); the scan continues but is no longer resumable from this point",
                    self.path, e
                );
            }
        }
    }
}

#[cfg(test)]
mod tests;
