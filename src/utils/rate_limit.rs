//! Request-rate limiting and adaptive WAF-evasion timing.
//!
//! Two independent timing controls live here:
//!
//! * [`RateLimiter`] — a token-bucket / GCRA limiter shared across **all**
//!   scan workers so the aggregate outbound request rate stays under
//!   `--rate-limit` requests/second, regardless of how many
//!   `workers × max_concurrent_targets` futures fan out at once. Before this
//!   existed the only pacing was a fixed per-request `--delay` sleep, which
//!   does nothing to cap the *burst* of in-flight requests; a shared-IP edge
//!   WAF would see thousands of requests arrive at once.
//!
//! * [`inter_request_pause`] — the per-request pause applied after an
//!   injection send. It folds the user's `--delay`, the per-WAF
//!   `extra_delay_hint_ms` (consumed here instead of only appearing in JSON
//!   meta), and, under `--waf-evasion`, randomized jitter so a WAF can't
//!   fingerprint a fixed inter-request cadence.
//!
//! The limiter is installed process-wide from the CLI
//! (`crate::install_rate_limiter`) and/or bound per-job by the MCP / REST
//! runners (`crate::RATE_LIMITER_JOB`); `crate::rate_limit_acquire` picks
//! whichever applies before every send.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Floor applied to the per-request pause when `--waf-evasion` is active, so
/// evasion always throttles even when the user passed no `--delay` and the
/// detected WAF advertised no pacing hint. Randomized jitter is layered on
/// top of this floor.
pub const EVASION_FLOOR_MS: u64 = 150;

/// A process-wide / per-job request rate limiter.
///
/// Implemented as a GCRA (Generic Cell Rate Algorithm) limiter: it tracks a
/// single "theoretical arrival time" (TAT) for the next conforming request
/// and spaces grants by `interval = 1 / rate`. A configurable `tolerance`
/// allows a short initial burst before steady-state pacing applies; the
/// default ([`per_second`](RateLimiter::per_second)) uses a burst of one,
/// i.e. strict even spacing — the safest choice for shared-IP WAF thresholds
/// and the whole reason this type exists.
///
/// `acquire` is `async` and safe to call from many tasks at once: each call
/// reserves a distinct future slot, so concurrent workers wake staggered by
/// `interval` rather than in a thundering herd.
#[derive(Debug)]
pub struct RateLimiter {
    /// Minimum spacing between grants (`1 / rate`).
    interval: Duration,
    /// Burst tolerance: a request may be admitted up to this far ahead of the
    /// theoretical schedule. Zero means strict even spacing.
    tolerance: Duration,
    /// GCRA theoretical arrival time of the next request.
    tat: Mutex<Instant>,
}

impl RateLimiter {
    /// Build a limiter for `rate` requests/second with strict even spacing
    /// (burst of one). Returns `None` when `rate == 0` so callers can treat
    /// "unlimited" as "no limiter installed" and pay zero overhead on the
    /// hot path.
    pub fn per_second(rate: u32) -> Option<Arc<Self>> {
        Self::with_burst(rate, 1)
    }

    /// Build a limiter for `rate` requests/second allowing up to `burst`
    /// requests to fire back-to-back before steady-state pacing applies.
    /// `burst` is clamped to at least 1. Returns `None` when `rate == 0`.
    pub fn with_burst(rate: u32, burst: u32) -> Option<Arc<Self>> {
        if rate == 0 {
            return None;
        }
        // nanos-per-request; rate >= 1 so this never divides by zero and is
        // at most 1e9 (1 req/s) — well within Duration's range.
        let interval = Duration::from_nanos(1_000_000_000u64 / rate as u64);
        let tolerance = interval.saturating_mul(burst.max(1) - 1);
        Some(Arc::new(Self {
            interval,
            tolerance,
            tat: Mutex::new(Instant::now()),
        }))
    }

    /// Block until the caller may issue one request under the configured
    /// rate, then return. A no-op-ish fast path when the limiter happens to
    /// be idle (no sleep is awaited).
    pub async fn acquire(&self) {
        let wait = self.reserve(Instant::now());
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }

    /// Reserve the next slot for a request arriving at `now`, returning how
    /// long the caller must wait before sending. Pure (no sleeping) so the
    /// GCRA bookkeeping can be unit-tested with a synthetic clock.
    fn reserve(&self, now: Instant) -> Duration {
        // Poisoning only happens if a holder panicked mid-update; the state
        // is a single Instant, so recovering the inner value is safe.
        let mut tat = self.tat.lock().unwrap_or_else(|p| p.into_inner());

        // A request conforms when it arrives at or after `tat - tolerance`.
        let earliest = tat.checked_sub(self.tolerance).unwrap_or(now);
        if now >= earliest {
            // Conforming: advance TAT from whichever is later of the stored
            // TAT and now (an idle gap collapses back to `now`, so idle time
            // never accumulates burst credit beyond `tolerance`).
            let base = if *tat > now { *tat } else { now };
            *tat = base + self.interval;
            Duration::ZERO
        } else {
            // Too early: wait until the slot opens and reserve it.
            let wait = earliest.saturating_duration_since(now);
            *tat += self.interval;
            wait
        }
    }
}

/// Cheap, dependency-free pseudo-random value in `[0, modulo)` for timing
/// jitter. Returns 0 for `modulo <= 1`. Not cryptographically secure — it is
/// only used to scatter inter-request timing so a WAF cannot lock onto a
/// fixed cadence, which does not need real randomness.
pub fn fast_jitter(modulo: u64) -> u64 {
    if modulo <= 1 {
        return 0;
    }
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEED: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

    // Mix in sub-second wall-clock nanos so separate processes (and the very
    // first call) diverge instead of replaying the same xorshift stream.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let mut x = SEED.load(Ordering::Relaxed) ^ nanos.wrapping_mul(0x2545_F491_4F6C_DD1D);
    // xorshift64
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    SEED.store(x, Ordering::Relaxed);
    x % modulo
}

/// Compute the pause to apply after an injection request.
///
/// * `base_delay_ms` — the user's `--delay`.
/// * `waf_extra_ms` — the per-WAF `extra_delay_hint_ms` (0 when no WAF was
///   detected or `--waf-bypass off`); paces requests at the cadence the WAF
///   tolerates.
/// * `evasion` — `--waf-evasion`: randomize the cadence (uniform jitter in
///   `[center/2, center*3/2]` around a floor of [`EVASION_FLOOR_MS`]) so a
///   WAF cannot fingerprint a constant inter-request interval. Without it the
///   pause is simply `base_delay_ms + waf_extra_ms`.
pub fn inter_request_pause(base_delay_ms: u64, waf_extra_ms: u64, evasion: bool) -> Duration {
    let base = base_delay_ms.saturating_add(waf_extra_ms);
    if !evasion {
        return Duration::from_millis(base);
    }
    // Center the jitter window on at least the evasion floor so evasion still
    // throttles when both --delay and the WAF hint are zero.
    let center = base.max(EVASION_FLOOR_MS);
    let low = center / 2;
    // Window width == center, so the result lands in [center/2, center*3/2]
    // and averages ~center.
    let jittered = low.saturating_add(fast_jitter(center.saturating_add(1)));
    Duration::from_millis(jittered)
}

#[cfg(test)]
mod tests;
