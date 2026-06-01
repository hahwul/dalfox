//! Animated "metallic shimmer" text coloring plus the shared spinner glyph
//! palette.
//!
//! The shimmer paints text in a 256-color grayscale ramp with a bright
//! highlight band that sweeps left→right and loops — like light traveling
//! across brushed metal. Every live indicator (the hand-rolled scan spinner,
//! the multi-target overall ticker, and the indicatif progress messages)
//! pulls its glyph and its text coloring from here so the whole CLI animates
//! with one consistent look.
//!
//! All coloring honors the global `--no-color` / `NO_COLOR` toggle: when
//! color is disabled every helper returns the input text verbatim, and the
//! `cprint!` family additionally strips any escape that slips through.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

/// Smooth 10-frame braille spinner. Shared by the hand-rolled spinner
/// (`start_spinner`, the overall ticker) and the indicatif bars (as
/// `tick_chars`) so every spinner in the app rotates identically.
pub const SPIN_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// `tick_chars` string for indicatif bars: the 10 running frames followed by
/// the finished frame (indicatif shows the last entry once a bar completes).
pub const TICK_CHARS: &str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏✓";

/// Safe upper bound (in columns) of the fixed furniture on the shared scan-bar
/// template — everything before the trailing `{wave}`: spinner, `[elapsed]`,
/// `[bar:28]`, `pos/len`, and the `· req/s ·`. Passed to [`wave_tracker`] as
/// the `reserve` so the shimmering target label is trimmed to the leftover
/// width and the bar stays on one line (fits standard 80-column terminals).
/// Keep this in sync (a little high) if the bar template changes width.
pub const BAR_WAVE_RESERVE: usize = 80;

/// Accent color (xterm-256) for the spinner glyph — a bright steel cyan that
/// reads as "active" against the silver shimmer text.
const ACCENT: u8 = 45;

/// Milliseconds per animation frame. Used to derive a frame counter from a
/// bar's elapsed time so the indicatif shimmer advances at the same cadence
/// as the hand-rolled spinner's steady tick.
pub const FRAME_MS: u128 = 80;

/// Per-frame advance of the highlight band, in character cells. A touch
/// faster than one cell so the shine visibly travels.
const SWEEP_SPEED: f64 = 1.5;
/// Half-width of the highlight band, in cells.
const BAND_HALF: f64 = 4.5;
/// Resting (base) brightness along the gray ramp, 0.0..=1.0. The band rises
/// from here to full white at its center.
const BASE_LEVEL: f64 = 0.42;
/// Padding past each end so the band fully exits before the sweep loops.
const SWEEP_PAD: f64 = BAND_HALF + 2.0;

/// xterm-256 grayscale ramp endpoints: 232 (near-black) … 255 (near-white).
const GRAY_MIN: u8 = 232;
const GRAY_MAX: u8 = 255;

/// Smoothstep easing for a soft band edge (no hard cutoff at the rim).
#[inline]
fn smoothstep(t: f64) -> f64 {
    let t = t.clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

/// Map a 0.0..=1.0 brightness to an xterm-256 grayscale code.
#[inline]
fn gray_code(level: f64) -> u8 {
    let span = (GRAY_MAX - GRAY_MIN) as f64;
    GRAY_MIN + (level.clamp(0.0, 1.0) * span).round() as u8
}

/// Brightness (0..1) of the cell at `idx` given the highlight centered at
/// `head`. Cells inside the band ramp up toward full white; cells outside
/// sit at the resting base level.
#[inline]
fn cell_level(idx: f64, head: f64) -> f64 {
    let dist = (idx - head).abs();
    let t = (1.0 - dist / BAND_HALF).max(0.0);
    BASE_LEVEL + (1.0 - BASE_LEVEL) * smoothstep(t)
}

/// Paint `text` with the highlight band centered at cell `head`. Runs of
/// equal color are coalesced into a single escape (one `\x1b[38;5;Nm` per
/// color change, not per character) so the rendered line stays compact.
///
/// Returns `text` unchanged when color output is disabled.
pub fn shimmer_at(text: &str, head: f64) -> String {
    if !crate::utils::term::color_enabled() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len() + 24);
    let mut cur: Option<u8> = None;
    for (i, ch) in text.chars().enumerate() {
        let code = gray_code(cell_level(i as f64, head));
        if cur != Some(code) {
            let _ = write!(out, "\x1b[38;5;{code}m");
            cur = Some(code);
        }
        out.push(ch);
    }
    if cur.is_some() {
        out.push_str("\x1b[0m");
    }
    out
}

/// Paint `text` for animation frame `phase`. The highlight sweeps left→right
/// and loops; `phase` is a monotonically increasing frame counter. Returns
/// `text` unchanged when color output is disabled or the text is empty.
pub fn shimmer(text: &str, phase: usize) -> String {
    let n = text.chars().count();
    if n == 0 {
        return String::new();
    }
    if !crate::utils::term::color_enabled() {
        return text.to_string();
    }
    let period = n as f64 + 2.0 * SWEEP_PAD;
    let head = (phase as f64 * SWEEP_SPEED) % period - SWEEP_PAD;
    shimmer_at(text, head)
}

/// The spinner glyph for animation frame `phase`, painted in the steel accent
/// (or plain when color is disabled).
pub fn spin_glyph(phase: usize) -> String {
    let frame = SPIN_FRAMES[phase % SPIN_FRAMES.len()];
    if crate::utils::term::color_enabled() {
        format!("\x1b[38;5;{ACCENT}m{frame}\x1b[0m")
    } else {
        frame.to_string()
    }
}

/// Build a `with_key("wave", …)` tracker that renders `label` with the
/// metallic shimmer. The animation phase is derived from the bar's elapsed
/// time, so the effect advances on every steady-tick redraw without spawning
/// a separate timer task.
///
/// `reserve` is the column count consumed by the rest of the bar (every
/// template element except `{wave}`, which sits last). The label is truncated
/// to the leftover terminal width so the line never wraps — indicatif renders
/// fixed-width bars at full length regardless of terminal size, so a long URL
/// in an untruncated message is exactly what would spill onto a second row.
/// Pass `reserve` as a safe *upper bound* of the furniture: over-estimating
/// only trims a few extra characters off the label, while under-estimating is
/// what risks a wrap.
pub fn wave_tracker(
    label: String,
    reserve: usize,
) -> impl Fn(&indicatif::ProgressState, &mut dyn std::fmt::Write) + Send + Sync + Clone + 'static {
    move |state, w| {
        let phase = (state.elapsed().as_millis() / FRAME_MS) as usize;
        // indicatif draws to stderr, so measure stderr (see `term_cols_stderr`).
        let avail = crate::utils::term::term_cols_stderr()
            .saturating_sub(reserve)
            .max(6);
        let shown = console::truncate_str(&label, avail, "…");
        let _ = write!(w, "{}", shimmer(shown.as_ref(), phase));
    }
}

/// Like [`wave_tracker`] but reads its text from a shared cell on every render
/// instead of a fixed string — for spinners whose message changes over time
/// (e.g. the parameter analyzer moving "Analyzing…" → "Mining dictionary…" →
/// "Mining DOM…"). indicatif's `ProgressState` can't expose the live `{msg}`
/// to a custom key, so the displayed text is funneled through `label` (updated
/// via [`ShimmerSpinner::set_message`]) and shimmered here.
pub fn wave_tracker_shared(
    label: Arc<Mutex<String>>,
    reserve: usize,
) -> impl Fn(&indicatif::ProgressState, &mut dyn std::fmt::Write) + Send + Sync + Clone + 'static {
    move |state, w| {
        let phase = (state.elapsed().as_millis() / FRAME_MS) as usize;
        let text = label.lock().map(|g| g.clone()).unwrap_or_default();
        // indicatif draws to stderr, so measure stderr (see `term_cols_stderr`).
        let avail = crate::utils::term::term_cols_stderr()
            .saturating_sub(reserve)
            .max(6);
        let shown = console::truncate_str(&text, avail, "…");
        let _ = write!(w, "{}", shimmer(shown.as_ref(), phase));
    }
}

/// A progress spinner whose message is painted with the metallic shimmer.
///
/// indicatif's `ProgressState` can't hand the live message to a `{wave}` key,
/// so the displayed text lives in a shared cell here. Callers update it via
/// [`set_message`](Self::set_message) — same name and shape as
/// `ProgressBar::set_message`, so the parameter-mining code keeps working
/// verbatim after swapping `Option<ProgressBar>` for `Option<ShimmerSpinner>`
/// — and the `{wave}` key built by [`wave_tracker_shared`] over the same cell
/// (see [`label_cell`](Self::label_cell)) shimmers whatever it holds. The
/// remaining methods just delegate to the wrapped bar.
#[derive(Clone)]
pub struct ShimmerSpinner {
    bar: indicatif::ProgressBar,
    label: Arc<Mutex<String>>,
}

impl ShimmerSpinner {
    /// Wrap `bar` with a shared `label` cell. The bar's style should reference
    /// `{wave}` via [`wave_tracker_shared`] over this same cell.
    pub fn new(bar: indicatif::ProgressBar, label: Arc<Mutex<String>>) -> Self {
        Self { bar, label }
    }

    /// The shared label cell, for wiring the `{wave}` tracker to this spinner.
    pub fn label_cell(&self) -> Arc<Mutex<String>> {
        self.label.clone()
    }

    /// The wrapped bar, e.g. to finish it via `scanning::finish_scan_bar`.
    pub fn bar(&self) -> &indicatif::ProgressBar {
        &self.bar
    }

    /// Update the shimmered message (mirrors `ProgressBar::set_message`).
    pub fn set_message(&self, msg: impl Into<String>) {
        if let Ok(mut g) = self.label.lock() {
            *g = msg.into();
        }
    }

    /// Delegate to the wrapped bar (drives a redraw, refreshing the shimmer).
    pub fn inc(&self, delta: u64) {
        self.bar.inc(delta);
    }

    /// Delegate to the wrapped bar.
    pub fn set_length(&self, len: u64) {
        self.bar.set_length(len);
    }

    /// Delegate to the wrapped bar.
    pub fn finish_and_clear(&self) {
        self.bar.finish_and_clear();
    }

    /// Print a line above the spinner without shredding the live redraw.
    pub fn println(&self, msg: impl AsRef<str>) {
        self.bar.println(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
