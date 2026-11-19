//! Discovery memory must stay linear in what the caller supplied.
//!
//! Every discovery surface spawns one probe task per item up front and gates
//! the *sending* on a semaphore. Whatever a task captures at spawn time is
//! therefore alive once per item, all at once: the cookie sweep captured a
//! copy of the whole cookie jar per cookie (N² — 8,000 cookies took a
//! `dalfox server` past 4 GiB in two seconds, one request), and every sweep
//! captured a copy of the request body per item (2,000 headers × a 500 KiB
//! body ≈ 1 GiB). The probes now read both from the shared target when they
//! get their permit, so the peak is bounded by `workers`.
//!
//! Measured with a counting allocator rather than RSS so the bound is exact
//! and the test is not at the mercy of the system allocator. One `#[test]`,
//! cases in sequence: the counter is process-wide.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use dalfox::cmd::scan::ScanArgs;
use dalfox::parameter_analysis::analyze_parameters;
use dalfox::target_parser::parse_target;

struct PeakAlloc;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// `realloc` is left to the trait's default, which goes through `alloc` and
// `dealloc`, so the two counters see every byte.
unsafe impl GlobalAlloc for PeakAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let live = LIVE.fetch_add(layout.size(), Relaxed) + layout.size();
            PEAK.fetch_max(live, Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: PeakAlloc = PeakAlloc;

const MIB: usize = 1024 * 1024;

/// Peak bytes allocated above the starting level while discovery runs.
async fn discovery_peak(url: &str, cookies: usize, body_bytes: usize) -> usize {
    let mut target = parse_target(url).expect("valid target");
    target.workers = 4;
    target.cookies = (0..cookies)
        .map(|i| (format!("c{i}"), "v".to_string()))
        .collect();
    if body_bytes > 0 {
        target.method = "POST".to_string();
        target.data = Some("x".repeat(body_bytes));
    }
    let args = ScanArgs {
        skip_mining: true,
        silence: true,
        ..Default::default()
    };
    let before = LIVE.load(Relaxed);
    PEAK.store(before, Relaxed);
    analyze_parameters(&mut target, &args, None).await;
    PEAK.load(Relaxed).saturating_sub(before)
}

#[tokio::test]
async fn discovery_memory_is_bounded_by_workers_not_by_item_count() {
    // Answers everything and reflects nothing: only the probes' own state is
    // measured, not what a discovered parameter goes on to cost.
    let app = axum::Router::new().fallback(|| async { "ok" });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let query = (0..200)
        .map(|i| format!("p{i}=1"))
        .collect::<Vec<_>>()
        .join("&");
    let path = (0..200)
        .map(|i| format!("s{i}"))
        .collect::<Vec<_>>()
        .join("/");
    // (label, url, cookies, body bytes, peak before the fix)
    let cases = [
        ("3000 cookies", format!("{base}/?q=1"), 3000, 0, "470 MiB"),
        (
            "200 query params x 1 MiB body",
            format!("{base}/?{query}"),
            0,
            MIB,
            "207 MiB",
        ),
        (
            "200 path segments x 1 MiB body",
            format!("{base}/{path}"),
            0,
            MIB,
            "207 MiB",
        ),
        (
            "40 cookies x 1 MiB body",
            format!("{base}/?q=1"),
            40,
            MIB,
            "42 MiB",
        ),
    ];
    for (label, url, cookies, body_bytes, before_fix) in cases {
        let peak = discovery_peak(&url, cookies, body_bytes).await;
        assert!(
            peak < 32 * MIB,
            "{label}: discovery peaked at {} MiB (was {before_fix} when every probe task \
             captured its own copy at spawn time)",
            peak / MIB
        );
    }
}
