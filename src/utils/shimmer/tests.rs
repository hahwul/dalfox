use super::*;

#[test]
fn smoothstep_clamps_and_hits_key_points() {
    assert_eq!(smoothstep(0.0), 0.0);
    assert_eq!(smoothstep(0.5), 0.5);
    assert_eq!(smoothstep(1.0), 1.0);
    assert_eq!(smoothstep(-1.0), 0.0);
    assert_eq!(smoothstep(2.0), 1.0);
}

#[test]
fn smoothstep_is_monotonic() {
    let mut previous = smoothstep(0.0);
    for step in 1..=10 {
        let current = smoothstep(step as f64 / 10.0);
        assert!(current >= previous);
        previous = current;
    }
}

#[test]
fn gray_code_spans_the_ramp() {
    assert_eq!(gray_code(0.0), GRAY_MIN);
    assert_eq!(gray_code(1.0), GRAY_MAX);
    // Clamps out-of-range input rather than wrapping.
    assert_eq!(gray_code(-1.0), GRAY_MIN);
    assert_eq!(gray_code(2.0), GRAY_MAX);
}

#[test]
fn cell_at_band_center_is_brightest() {
    // A cell directly under the head is full brightness; far away it
    // rests at the base level.
    assert!((cell_level(10.0, 10.0) - 1.0).abs() < 1e-9);
    assert!((cell_level(100.0, 10.0) - BASE_LEVEL).abs() < 1e-9);
}

#[test]
fn shimmer_preserves_visible_text() {
    // Stripping the ANSI must recover the original text exactly — this is
    // what keeps the rendered width correct and avoids wrap/newline bugs.
    let painted = shimmer_at("scanning: https://example.com/x", 5.0);
    assert_eq!(
        crate::utils::term::strip_ansi(&painted),
        "scanning: https://example.com/x"
    );
}

#[test]
fn shimmer_empty_is_empty() {
    assert_eq!(shimmer("", 3), "");
    assert_eq!(shimmer_at("", 0.0), "");
}

#[test]
fn shimmer_visible_width_is_stable_across_frames() {
    // The whole point of keeping width correct: every frame strips back
    // to the same text, so the `\r` redraw never wraps or leaves debris.
    let text = "analyzing: https://xss-game.appspot.com/level1/frame";
    for phase in 0..40 {
        assert_eq!(crate::utils::term::strip_ansi(&shimmer(text, phase)), text);
    }
}

#[test]
fn shimmer_spinner_set_message_updates_shared_cell() {
    // The whole analyzer-shimmer feature rests on `set_message` writing
    // through to the cell that `{wave}` reads. `ProgressBar::hidden()`
    // needs no TTY, so this stays a pure unit test.
    let sp = ShimmerSpinner::new(
        indicatif::ProgressBar::hidden(),
        Arc::new(Mutex::new("Analyzing…".to_string())),
    );
    assert_eq!(&*sp.label_cell().lock().unwrap(), "Analyzing…");
    sp.set_message("Mining dictionary parameters");
    assert_eq!(
        &*sp.label_cell().lock().unwrap(),
        "Mining dictionary parameters"
    );
}

#[test]
fn spin_glyph_always_contains_its_frame() {
    // Color-state agnostic (avoids mutating the global NO_COLOR toggle,
    // which would flake other tests run in parallel): the glyph char is
    // present whether or not ANSI wraps it.
    for i in 0..SPIN_FRAMES.len() * 2 {
        assert!(spin_glyph(i).contains(SPIN_FRAMES[i % SPIN_FRAMES.len()]));
    }
}

// ---- ShimmerSpinner delegate methods --------------------------------

fn hidden_spinner() -> ShimmerSpinner {
    ShimmerSpinner::new(
        indicatif::ProgressBar::hidden(),
        Arc::new(Mutex::new(String::new())),
    )
}

#[test]
fn shimmer_spinner_inc_advances_wrapped_bar() {
    // `inc` and `set_length` must reach the wrapped bar so callers that
    // swapped `Option<ProgressBar>` for `Option<ShimmerSpinner>` keep the
    // same progress semantics. A hidden bar needs no TTY.
    let sp = hidden_spinner();
    sp.set_length(10);
    assert_eq!(sp.bar().length(), Some(10));
    sp.inc(3);
    sp.inc(2);
    assert_eq!(sp.bar().position(), 5);
}

#[test]
fn shimmer_spinner_finish_and_clear_marks_finished() {
    let sp = hidden_spinner();
    assert!(!sp.bar().is_finished());
    sp.finish_and_clear();
    assert!(sp.bar().is_finished());
}

#[test]
fn shimmer_spinner_println_does_not_panic() {
    // `println` prints above the live redraw; on a hidden bar it is a
    // no-op, but it must not panic so mining progress logs stay safe.
    let sp = hidden_spinner();
    sp.println("discovered 3 parameters");
}

// ---- wave_tracker rendering -----------------------------------------

/// Capture draw target so we can drive the `{wave}` closure through a real
/// indicatif render and inspect what it emitted. indicatif never hands a
/// `ProgressState` to test code directly, so rendering through a bar is the
/// only way to exercise the tracker closures.
#[derive(Debug, Default)]
struct CaptureTerm {
    buf: Arc<Mutex<String>>,
}

impl indicatif::TermLike for CaptureTerm {
    fn width(&self) -> u16 {
        120
    }
    fn move_cursor_up(&self, _n: usize) -> std::io::Result<()> {
        Ok(())
    }
    fn move_cursor_down(&self, _n: usize) -> std::io::Result<()> {
        Ok(())
    }
    fn move_cursor_right(&self, _n: usize) -> std::io::Result<()> {
        Ok(())
    }
    fn move_cursor_left(&self, _n: usize) -> std::io::Result<()> {
        Ok(())
    }
    fn write_line(&self, s: &str) -> std::io::Result<()> {
        self.buf.lock().unwrap().push_str(s);
        Ok(())
    }
    fn write_str(&self, s: &str) -> std::io::Result<()> {
        self.buf.lock().unwrap().push_str(s);
        Ok(())
    }
    fn clear_line(&self) -> std::io::Result<()> {
        Ok(())
    }
    fn flush(&self) -> std::io::Result<()> {
        Ok(())
    }
}

fn render_with_wave(
    key: impl Fn(&indicatif::ProgressState, &mut dyn std::fmt::Write) + Send + Sync + Clone + 'static,
) -> String {
    let buf = Arc::new(Mutex::new(String::new()));
    let term = CaptureTerm {
        buf: Arc::clone(&buf),
    };
    let style = indicatif::ProgressStyle::default_spinner()
        .template("{wave}")
        .unwrap()
        .with_key("wave", key);
    let bar = indicatif::ProgressBar::with_draw_target(
        None,
        indicatif::ProgressDrawTarget::term_like(Box::new(term)),
    )
    .with_style(style);
    bar.tick();
    bar.finish();
    buf.lock().unwrap().clone()
}

#[test]
fn wave_tracker_renders_label_through_a_bar() {
    // The shimmered label must survive a real render: stripped of any ANSI
    // the rendered text contains the original label, which is exactly what
    // keeps the bar from wrapping.
    let out = render_with_wave(wave_tracker("scanning-target".to_string(), 0));
    let plain = crate::utils::term::strip_ansi(&out);
    assert!(
        plain.contains("scanning-target"),
        "rendered output missing label: {plain:?}"
    );
}

#[test]
fn wave_tracker_truncates_label_to_available_width() {
    // A reserve that swallows almost the whole 120-col width forces the
    // label to be trimmed with the ellipsis rather than spilling onto a
    // second line. `max(6)` guarantees at least a few cells remain.
    let long = "a".repeat(200);
    let out = render_with_wave(wave_tracker(long, 10_000));
    let plain = crate::utils::term::strip_ansi(&out);
    assert!(plain.contains('…'), "expected ellipsis marker: {plain:?}");
    // The 200-char run must have been cut to the small floor width — the
    // longest surviving run of the label char is short, never the original.
    let longest_run = plain.split(|c| c != 'a').map(str::len).max().unwrap_or(0);
    assert!(
        longest_run < 20,
        "label run not trimmed (got {longest_run} chars): {plain:?}"
    );
}

#[test]
fn wave_tracker_shared_reads_live_cell() {
    // The shared variant reads its text from the cell on every render, so
    // updating the cell before the render is reflected in the output.
    let cell = Arc::new(Mutex::new("phase-one".to_string()));
    *cell.lock().unwrap() = "mining-dictionary".to_string();
    let out = render_with_wave(wave_tracker_shared(cell, 0));
    let plain = crate::utils::term::strip_ansi(&out);
    assert!(
        plain.contains("mining-dictionary"),
        "shared tracker missing live text: {plain:?}"
    );
}
