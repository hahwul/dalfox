use super::*;
use std::time::{Duration, Instant};

#[test]
fn per_second_zero_is_unlimited() {
    assert!(
        RateLimiter::per_second(0).is_none(),
        "rate 0 must mean unlimited (no limiter installed)"
    );
    assert!(RateLimiter::per_second(10).is_some());
}

#[test]
fn interval_matches_rate() {
    // 10 req/s => 100ms spacing.
    let limiter = RateLimiter::per_second(10).unwrap();
    assert_eq!(limiter.interval, Duration::from_millis(100));
    // strict spacing by default (burst of 1) => no tolerance window.
    assert_eq!(limiter.tolerance, Duration::ZERO);
}

#[test]
fn strict_spacing_serializes_requests() {
    // With burst 1, N requests reserved at the same instant must be spaced
    // exactly `interval` apart: the first is immediate, each subsequent one
    // waits one more interval.
    let limiter = RateLimiter::per_second(10).unwrap(); // 100ms interval
    let now = Instant::now();

    let w0 = limiter.reserve(now);
    let w1 = limiter.reserve(now);
    let w2 = limiter.reserve(now);
    let w3 = limiter.reserve(now);

    assert_eq!(w0, Duration::ZERO, "first request is immediate");
    assert_eq!(w1, Duration::from_millis(100));
    assert_eq!(w2, Duration::from_millis(200));
    assert_eq!(w3, Duration::from_millis(300));
}

#[test]
fn idle_does_not_accumulate_burst_credit() {
    // After a long idle gap a single request is immediate, but the one right
    // after it is still spaced by a full interval (no saved-up burst).
    let limiter = RateLimiter::per_second(5).unwrap(); // 200ms interval
    let t0 = Instant::now();

    assert_eq!(limiter.reserve(t0), Duration::ZERO);

    // Jump far past the reserved slot: the limiter "catches up" to now.
    let later = t0 + Duration::from_secs(10);
    assert_eq!(
        limiter.reserve(later),
        Duration::ZERO,
        "request after idle gap should be immediate"
    );
    // The next back-to-back request still pays a full interval.
    assert_eq!(limiter.reserve(later), Duration::from_millis(200));
}

#[test]
fn burst_tolerance_allows_initial_burst_then_paces() {
    // burst=3 lets three requests through immediately, then steady pacing.
    let limiter = RateLimiter::with_burst(10, 3).unwrap(); // 100ms interval, 200ms tolerance
    let now = Instant::now();

    assert_eq!(limiter.reserve(now), Duration::ZERO);
    assert_eq!(limiter.reserve(now), Duration::ZERO);
    assert_eq!(limiter.reserve(now), Duration::ZERO);
    // Fourth request must wait: the burst window is exhausted.
    assert_eq!(limiter.reserve(now), Duration::from_millis(100));
    assert_eq!(limiter.reserve(now), Duration::from_millis(200));
}

#[tokio::test]
async fn acquire_paces_concurrent_workers() {
    // End-to-end: many concurrent acquirers against a shared limiter must
    // take at least the expected wall-clock time. 20 req/s => 50ms apart;
    // 6 requests => >= 5 intervals == 250ms.
    let limiter = RateLimiter::per_second(20).unwrap();
    let start = Instant::now();

    let mut handles = Vec::new();
    for _ in 0..6 {
        let l = limiter.clone();
        handles.push(tokio::spawn(async move { l.acquire().await }));
    }
    for h in handles {
        h.await.unwrap();
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(240),
        "6 requests at 20/s should take >= ~250ms, took {:?}",
        elapsed
    );
}

#[tokio::test]
async fn job_rate_limiter_throttles_acquire() {
    // A per-job limiter bound via with_job_rate_limiter must throttle
    // rate_limit_acquire: 5 sequential acquires at 20/s (50ms apart) span
    // ~4 intervals == ~200ms.
    let start = Instant::now();
    crate::with_job_rate_limiter(20, async {
        for _ in 0..5 {
            crate::rate_limit_acquire().await;
        }
    })
    .await;
    assert!(
        start.elapsed() >= Duration::from_millis(180),
        "per-job limiter should pace acquires, took {:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn job_rate_limiter_zero_is_unthrottled() {
    // rate 0 binds no limiter, so acquires fall through to a no-op.
    let start = Instant::now();
    crate::with_job_rate_limiter(0, async {
        for _ in 0..200 {
            crate::rate_limit_acquire().await;
        }
    })
    .await;
    assert!(
        start.elapsed() < Duration::from_millis(150),
        "rate 0 must not throttle, took {:?}",
        start.elapsed()
    );
}

#[test]
fn fast_jitter_bounds() {
    assert_eq!(fast_jitter(0), 0);
    assert_eq!(fast_jitter(1), 0);
    for _ in 0..1000 {
        let v = fast_jitter(100);
        assert!(v < 100, "jitter {} out of range", v);
    }
}

#[test]
fn fast_jitter_varies() {
    // The xorshift state advances each call, so a batch should not be a
    // single repeated value.
    let mut seen = std::collections::HashSet::new();
    for _ in 0..50 {
        seen.insert(fast_jitter(1_000_000));
    }
    assert!(
        seen.len() > 1,
        "jitter should produce more than one distinct value"
    );
}

#[test]
fn inter_request_pause_without_evasion_is_sum() {
    assert_eq!(
        inter_request_pause(0, 0, false),
        Duration::from_millis(0),
        "no delay, no waf, no evasion => no pause"
    );
    assert_eq!(
        inter_request_pause(100, 0, false),
        Duration::from_millis(100)
    );
    // WAF pacing hint is added to the user delay.
    assert_eq!(
        inter_request_pause(100, 50, false),
        Duration::from_millis(150)
    );
}

#[test]
fn inter_request_pause_with_evasion_jitters_within_window() {
    // Center = max(base+extra, floor). With base+extra=0, center=floor=150,
    // so the window is [75, 225].
    for _ in 0..1000 {
        let p = inter_request_pause(0, 0, true).as_millis() as u64;
        assert!(
            (75..=225).contains(&p),
            "evasion jitter {} outside [75,225]",
            p
        );
    }
    // With a larger base the window scales with it: base=400 => center=400 =>
    // [200, 600].
    for _ in 0..1000 {
        let p = inter_request_pause(300, 100, true).as_millis() as u64;
        assert!(
            (200..=600).contains(&p),
            "evasion jitter {} outside [200,600]",
            p
        );
    }
}
