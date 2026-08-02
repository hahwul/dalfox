//! `--state-file` resume behavior. The contract these pin down: a completed
//! target is skipped exactly once the configuration still matches, and every
//! other outcome (cancelled, error, torn line, changed config) is retried.

use super::*;
use std::io::Read;

/// Unique scratch path per test. `Instant`-derived names collide when two
/// tests land in the same tick (see the HAR-fixture fix in #1284), so the name
/// is derived from a per-process counter plus the test-supplied label.
fn scratch(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static N: AtomicUsize = AtomicUsize::new(0);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "dalfox_state_{}_{}_{}.jsonl",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed),
        label
    ));
    let _ = std::fs::remove_file(&p);
    p
}

fn read(path: &std::path::Path) -> String {
    let mut s = String::new();
    std::fs::File::open(path)
        .expect("state file exists")
        .read_to_string(&mut s)
        .expect("state file is utf-8");
    s
}

fn args_with(path: &std::path::Path) -> ScanArgs {
    ScanArgs {
        state_file: Some(path.to_string_lossy().to_string()),
        silence: true,
        ..Default::default()
    }
}

#[test]
fn new_file_gets_a_header_and_no_completions() {
    let path = scratch("new");
    let args = args_with(&path);
    let sf = StateFile::open(path.to_str().unwrap(), &args).expect("opens");

    assert_eq!(sf.completed_count(), 0);
    assert!(sf.reset_reason.is_none(), "a first run is not a reset");

    let contents = read(&path);
    let header: serde_json::Value =
        serde_json::from_str(contents.lines().next().unwrap()).expect("header is JSON");
    assert_eq!(header["dalfox_state"], STATE_FORMAT_VERSION);
    assert_eq!(header["config_hash"], config_hash(&args));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn completed_targets_are_skipped_on_the_next_run() {
    let path = scratch("resume");
    let args = args_with(&path);

    {
        let sf = StateFile::open(path.to_str().unwrap(), &args).expect("opens");
        sf.record("https://a.test/?q=1", "GET", TargetOutcome::Completed);
        sf.record("https://b.test/?q=1", "POST", TargetOutcome::Completed);
    }

    let sf = StateFile::open(path.to_str().unwrap(), &args).expect("reopens");
    assert_eq!(sf.completed_count(), 2);
    assert!(sf.is_completed("https://a.test/?q=1", "GET"));
    assert!(sf.is_completed("https://b.test/?q=1", "POST"));
    // The method is part of the identity: the same URL under another method is
    // a different target and must still be scanned.
    assert!(!sf.is_completed("https://a.test/?q=1", "POST"));
    assert!(!sf.is_completed("https://c.test/?q=1", "GET"));

    let _ = std::fs::remove_file(&path);
}

// The core safety rule of the feature: only `completed` may be skipped.
// A target cut short by Ctrl-C / --scan-timeout, or dropped in preflight, has
// unknown coverage — skipping it would silently drop it from the campaign.
#[test]
fn cancelled_and_error_targets_are_retried() {
    let path = scratch("retry");
    let args = args_with(&path);

    {
        let sf = StateFile::open(path.to_str().unwrap(), &args).expect("opens");
        sf.record("https://a.test/", "GET", TargetOutcome::Cancelled);
        sf.record("https://b.test/", "GET", TargetOutcome::Error);
        sf.record("https://c.test/", "GET", TargetOutcome::Completed);
    }

    let sf = StateFile::open(path.to_str().unwrap(), &args).expect("reopens");
    assert_eq!(sf.completed_count(), 1);
    assert!(!sf.is_completed("https://a.test/", "GET"));
    assert!(!sf.is_completed("https://b.test/", "GET"));
    assert!(sf.is_completed("https://c.test/", "GET"));

    let _ = std::fs::remove_file(&path);
}

// A hard kill can leave the final line half-written. That line is skipped, and
// every complete record before it still counts — losing the whole file to one
// torn tail would defeat the point of an append-only log.
#[test]
fn a_torn_final_line_is_skipped_and_earlier_records_survive() {
    let path = scratch("torn");
    let args = args_with(&path);

    {
        let sf = StateFile::open(path.to_str().unwrap(), &args).expect("opens");
        sf.record("https://a.test/", "GET", TargetOutcome::Completed);
    }
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append");
        write!(f, "{{\"target\":\"https://b.test/\",\"meth").expect("torn write");
    }

    let sf = StateFile::open(path.to_str().unwrap(), &args).expect("reopens");
    assert_eq!(sf.corrupt_lines, 1);
    assert!(sf.is_completed("https://a.test/", "GET"));
    assert!(sf.reset_reason.is_none(), "a torn tail is not a reset");

    let _ = std::fs::remove_file(&path);
}

// Changing a scan-affecting flag means the recorded targets were tested under
// different settings, so they are not comparable: the file resets rather than
// skipping targets the new configuration has never covered.
#[test]
fn a_changed_configuration_resets_the_file() {
    let path = scratch("rehash");
    let args = args_with(&path);

    {
        let sf = StateFile::open(path.to_str().unwrap(), &args).expect("opens");
        sf.record("https://a.test/", "GET", TargetOutcome::Completed);
    }

    let changed = ScanArgs {
        deep_scan: true,
        ..args_with(&path)
    };
    let sf = StateFile::open(path.to_str().unwrap(), &changed).expect("reopens");
    assert!(sf.reset_reason.is_some(), "a config change must reset");
    assert_eq!(sf.completed_count(), 0);

    // Reset starts a *new* file, and the header carries the new hash so the
    // next run matches this one.
    let contents = read(&path);
    assert_eq!(
        contents.lines().count(),
        1,
        "the fresh file holds only its header: {contents}"
    );
    let header: serde_json::Value = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
    assert_eq!(header["config_hash"], config_hash(&changed));

    // The prior file is real work — an authenticated campaign resumed with a
    // rotated cookie lands here — so it is moved aside, never destroyed.
    let backup = sf.reset_backup.clone().expect("the old file is kept");
    let kept = read(std::path::Path::new(&backup));
    assert!(
        kept.contains("https://a.test/"),
        "the discarded completions must still be recoverable: {kept}"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&backup);
}

// A readable file that is not a state file is refused, not overwritten. One
// typo (`--state-file urls.txt`) would otherwise eat the target list.
#[test]
fn a_file_that_is_not_a_state_file_is_refused_not_overwritten() {
    let path = scratch("foreign");
    let original = "https://a.test/?q=1\nhttps://b.test/?q=1\n";
    std::fs::write(&path, original).expect("write");
    let args = args_with(&path);

    let Err(err) = StateFile::open(path.to_str().unwrap(), &args) else {
        panic!("a foreign file must not be adopted as a state file");
    };
    assert!(
        err.contains("not a dalfox state file"),
        "the message has to name the problem: {err}"
    );
    assert_eq!(read(&path), original, "the file must be left untouched");

    let _ = std::fs::remove_file(&path);
}

// The preview modes filter their plan through the recorded completions but
// scan nothing, so they must not create, extend, or set aside the file.
// Pricing out a different flag set with `--dry-run` is exactly when an
// operator would otherwise lose a campaign to a hash mismatch.
#[test]
fn a_read_only_open_never_touches_the_file() {
    let path = scratch("readonly");
    let args = args_with(&path);
    {
        let sf = StateFile::open(path.to_str().unwrap(), &args).expect("opens");
        sf.record("https://a.test/", "GET", TargetOutcome::Completed);
    }
    let before = read(&path);

    // Same configuration: completions are still visible to the preview.
    let sf = StateFile::open_read_only(path.to_str().unwrap(), &args).expect("opens read-only");
    assert!(sf.is_completed("https://a.test/", "GET"));
    sf.record("https://b.test/", "GET", TargetOutcome::Completed);
    drop(sf);
    assert_eq!(read(&path), before, "a preview may not write records");

    // Changed configuration: the preview reports the mismatch but leaves both
    // the file and any `.bak` sibling alone.
    let changed = ScanArgs {
        deep_scan: true,
        ..args_with(&path)
    };
    let sf = StateFile::open_read_only(path.to_str().unwrap(), &changed).expect("opens read-only");
    assert!(sf.reset_reason.is_some(), "the mismatch is still reported");
    assert!(sf.reset_backup.is_none(), "a preview resets nothing");
    drop(sf);
    assert_eq!(read(&path), before, "a preview may not reset the file");
    assert!(!std::path::Path::new(&format!("{}.bak", path.display())).exists());

    let _ = std::fs::remove_file(&path);
}

// A target that keeps failing must not add a line per run: the file would grow
// until it crossed the read cap, and then the campaign could not be resumed at
// all — the failure this feature exists to prevent, arrived at slowly.
#[test]
fn a_repeated_outcome_is_not_appended_again() {
    let path = scratch("bounded");
    let args = args_with(&path);

    for _ in 0..5 {
        let sf = StateFile::open(path.to_str().unwrap(), &args).expect("opens");
        sf.record("https://down.test/", "GET", TargetOutcome::Error);
        sf.record("https://slow.test/", "GET", TargetOutcome::Cancelled);
    }

    let contents = read(&path);
    assert_eq!(
        contents.lines().count(),
        3,
        "header + one line per (target, outcome), not per run: {contents}"
    );

    // A target whose outcome *changes* is still recorded, or resume would
    // never learn that a retried target finally completed.
    {
        let sf = StateFile::open(path.to_str().unwrap(), &args).expect("opens");
        sf.record("https://slow.test/", "GET", TargetOutcome::Completed);
    }
    let sf = StateFile::open(path.to_str().unwrap(), &args).expect("reopens");
    assert!(sf.is_completed("https://slow.test/", "GET"));
    assert!(!sf.is_completed("https://down.test/", "GET"));

    let _ = std::fs::remove_file(&path);
}

// An existing file we cannot read is *not* reset: truncating it would destroy
// a campaign's recorded progress sight unseen. The run stops and says so.
#[test]
fn an_unreadable_existing_file_fails_instead_of_being_truncated() {
    let path = scratch("unreadable");
    // A file over the read cap stands in for "exists, cannot be read back".
    std::fs::write(&path, "x").expect("write");
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open");
    f.set_len(MAX_STATE_FILE_BYTES + 1).expect("grow past cap");
    drop(f);

    let args = args_with(&path);
    let Err(err) = StateFile::open(path.to_str().unwrap(), &args) else {
        panic!("an unreadable state file must fail the run, not be overwritten");
    };
    assert!(err.contains("move it aside"), "actionable message: {err}");
    assert!(
        std::fs::metadata(&path).expect("still there").len() > MAX_STATE_FILE_BYTES,
        "the file must be left exactly as it was"
    );

    let _ = std::fs::remove_file(&path);
}

// Output and pacing flags cannot change what a completed target covered, so
// they must not invalidate progress — an operator who resumes with a longer
// --scan-timeout or a different --format would otherwise redo the whole run.
#[test]
fn reporting_and_pacing_flags_do_not_change_the_hash() {
    let base = ScanArgs::default();
    let hash = config_hash(&base);

    for tweak in [
        ScanArgs {
            format: "json".to_string(),
            ..Default::default()
        },
        ScanArgs {
            output: Some("out.json".to_string()),
            ..Default::default()
        },
        ScanArgs {
            silence: true,
            ..Default::default()
        },
        ScanArgs {
            baseline: Some("baseline.json".to_string()),
            ..Default::default()
        },
        ScanArgs {
            state_file: Some("other.state".to_string()),
            ..Default::default()
        },
        ScanArgs {
            scan_timeout: 600,
            ..Default::default()
        },
        ScanArgs {
            workers: 4,
            ..Default::default()
        },
        ScanArgs {
            delay: 250,
            ..Default::default()
        },
        // The target list itself: one state file legitimately covers a shell
        // loop of per-URL invocations.
        ScanArgs {
            targets: vec!["https://a.test/".to_string()],
            ..Default::default()
        },
    ] {
        assert_eq!(
            config_hash(&tweak),
            hash,
            "this flag must not invalidate recorded progress: {:?}",
            tweak
        );
    }
}

// The other direction: anything that changes which payloads are sent, which
// parameters are found, or what counts as a finding must invalidate progress.
#[test]
fn scan_affecting_flags_change_the_hash() {
    let base = config_hash(&ScanArgs::default());

    for tweak in [
        ScanArgs {
            deep_scan: true,
            ..Default::default()
        },
        ScanArgs {
            encoders: vec!["base64".to_string()],
            ..Default::default()
        },
        ScanArgs {
            skip_mining: true,
            ..Default::default()
        },
        ScanArgs {
            skip_discovery: true,
            ..Default::default()
        },
        ScanArgs {
            waf_evasion: true,
            ..Default::default()
        },
        ScanArgs {
            custom_payload: Some("payloads.txt".to_string()),
            ..Default::default()
        },
        ScanArgs {
            max_payloads_per_param: 100,
            ..Default::default()
        },
        ScanArgs {
            cookies: vec!["session=abc".to_string()],
            ..Default::default()
        },
        ScanArgs {
            limit: Some(10),
            ..Default::default()
        },
        ScanArgs {
            max_targets_per_host: 5,
            ..Default::default()
        },
    ] {
        assert_ne!(
            config_hash(&tweak),
            base,
            "this flag changes coverage and must reset progress: {:?}",
            tweak
        );
    }
}

// Records are appended, never rewritten, so a resumed run keeps the history of
// every run before it in one file.
#[test]
fn records_from_later_runs_are_appended_to_the_same_file() {
    let path = scratch("append");
    let args = args_with(&path);

    {
        let sf = StateFile::open(path.to_str().unwrap(), &args).expect("opens");
        sf.record("https://a.test/", "GET", TargetOutcome::Completed);
    }
    {
        let sf = StateFile::open(path.to_str().unwrap(), &args).expect("reopens");
        sf.record("https://b.test/", "GET", TargetOutcome::Completed);
    }

    let contents = read(&path);
    assert_eq!(
        contents.lines().count(),
        3,
        "one header + two records: {contents}"
    );

    let sf = StateFile::open(path.to_str().unwrap(), &args).expect("reopens");
    assert_eq!(sf.completed_count(), 2);

    let _ = std::fs::remove_file(&path);
}

// A path that cannot be opened for writing fails the run up front. Discovering
// after a two-hour scan that nothing was recorded is the exact failure the
// feature exists to prevent.
#[test]
fn an_unwritable_path_is_an_error_not_a_silent_no_op() {
    let mut dir = std::env::temp_dir();
    dir.push(format!("dalfox_state_dir_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    // A directory can never be opened for writing.
    let args = args_with(&dir);
    let Err(err) = StateFile::open(dir.to_str().unwrap(), &args) else {
        panic!("opening a directory as a state file must fail");
    };
    assert!(
        err.contains("--state-file"),
        "operator-facing message: {err}"
    );

    let _ = std::fs::remove_dir(&dir);
}
