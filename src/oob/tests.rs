//! End-to-end OOB test against a mock interactsh server (axum). Exercises the
//! full path: register → mint+record a payload → server fires an AES-256-CTR /
//! RSA-OAEP encrypted callback → poller decrypts, correlates, and emits a
//! `Verified` finding → deregister.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use tokio::sync::Mutex as TokioMutex;

use crate::oob::{InjectionRecord, OobConfig, OobSession, spawn_poller};

#[derive(Default)]
struct MockState {
    public_key_b64: Option<String>,
    correlation_id: Option<String>,
    /// Set by the test to make the next poll fire a callback for this nonce.
    pending_nonce: Option<String>,
    /// Bare host[:port] the client embeds in callback hosts.
    host: String,
    deregistered: bool,
    /// Make `/poll` answer HTTP 500.
    poll_fails: bool,
    /// Make the next poll return this many callbacks with distinct, unregistered nonces.
    flood: usize,
    /// How many times the poller hit `/poll` — proves it ran.
    poll_count: usize,
}

type Shared = Arc<StdMutex<MockState>>;

async fn register(State(s): State<Shared>, Json(body): Json<Value>) -> Json<Value> {
    let mut st = s.lock().unwrap();
    st.public_key_b64 = body
        .get("public-key")
        .and_then(Value::as_str)
        .map(str::to_string);
    st.correlation_id = body
        .get("correlation-id")
        .and_then(Value::as_str)
        .map(str::to_string);
    Json(json!({ "message": "registration successful" }))
}

async fn deregister(State(s): State<Shared>, Json(_body): Json<Value>) -> Json<Value> {
    s.lock().unwrap().deregistered = true;
    Json(json!({ "message": "deregistration successful" }))
}

async fn poll(
    State(s): State<Shared>,
    Query(_q): Query<HashMap<String, String>>,
) -> (axum::http::StatusCode, Json<Value>) {
    let (fails, flood) = {
        let mut st = s.lock().unwrap();
        st.poll_count += 1;
        (st.poll_fails, std::mem::take(&mut st.flood))
    };
    if fails {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({})),
        );
    }
    if flood > 0 {
        let (pubkey, corr, host) = {
            let st = s.lock().unwrap();
            (
                st.public_key_b64.clone().unwrap(),
                st.correlation_id.clone().unwrap(),
                st.host.clone(),
            )
        };
        // One RSA wrap (the slow part in a debug build) for the whole batch;
        // every entry shares the AES key it wraps.
        let (_, aes_key_b64) = server_encrypt(&pubkey, b"");
        let data: Vec<String> = (0..flood)
            .map(|i| {
                let interaction = json!({
                    "protocol": "dns",
                    "full-id": format!("{corr}forged{i:07}.{host}"),
                    "remote-address": "198.51.100.1",
                });
                aes_blob(interaction.to_string().as_bytes())
            })
            .collect();
        return (
            axum::http::StatusCode::OK,
            Json(json!({ "data": data, "aes_key": aes_key_b64 })),
        );
    }
    (axum::http::StatusCode::OK, poll_one(s).await)
}

async fn poll_one(s: Shared) -> Json<Value> {
    let (pubkey, corr, nonce, host) = {
        let mut st = s.lock().unwrap();
        (
            st.public_key_b64.clone(),
            st.correlation_id.clone(),
            st.pending_nonce.take(),
            st.host.clone(),
        )
    };
    let (Some(pubkey), Some(corr), Some(nonce)) = (pubkey, corr, nonce) else {
        return Json(json!({ "data": [], "aes_key": "" }));
    };

    let full_id = format!("{corr}{nonce}.{host}");
    let interaction = json!({
        "protocol": "http",
        "unique-id": format!("{corr}{nonce}"),
        "full-id": full_id,
        "remote-address": "203.0.113.9",
        "timestamp": "2026-06-12T00:00:00Z",
        "raw-request": "GET / HTTP/1.1\r\n\r\n",
    });
    let (data_b64, aes_key_b64) = server_encrypt(&pubkey, interaction.to_string().as_bytes());
    Json(json!({ "data": [data_b64], "aes_key": aes_key_b64 }))
}

/// `base64(IV ‖ AES-256-CTR(plaintext))` under the fixed key `server_encrypt` wraps.
fn aes_blob(plaintext: &[u8]) -> String {
    use ctr::cipher::{KeyIvInit, StreamCipher};
    type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;
    let iv = [3u8; 16];
    let mut buf = plaintext.to_vec();
    Aes256Ctr::new_from_slices(&[0x11u8; 32], &iv)
        .unwrap()
        .apply_keystream(&mut buf);
    let mut blob = iv.to_vec();
    blob.extend_from_slice(&buf);
    B64.encode(&blob)
}

/// Mirror the interactsh server: RSA-OAEP(SHA-256)-wrap a random AES key to the
/// client's public key, then AES-256-CTR encrypt the interaction as
/// `base64(IV ‖ ciphertext)`. Returns `(data, aes_key)`.
fn server_encrypt(public_key_pem_b64: &str, plaintext: &[u8]) -> (String, String) {
    use ctr::cipher::{KeyIvInit, StreamCipher};
    use rand::rngs::OsRng;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::{Oaep, RsaPublicKey};
    use sha2_oaep::Sha256;
    type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

    let pem = String::from_utf8(B64.decode(public_key_pem_b64).unwrap()).unwrap();
    let pubkey = RsaPublicKey::from_public_key_pem(&pem).unwrap();

    let aes_key = [0x11u8; 32];
    let mut rng = OsRng;
    let wrapped = pubkey
        .encrypt(&mut rng, Oaep::new::<Sha256>(), &aes_key)
        .unwrap();
    let aes_key_b64 = B64.encode(&wrapped);

    let iv = [3u8; 16];
    let mut buf = plaintext.to_vec();
    let mut cipher = Aes256Ctr::new_from_slices(&aes_key, &iv).unwrap();
    cipher.apply_keystream(&mut buf);
    let mut blob = iv.to_vec();
    blob.extend_from_slice(&buf);
    (B64.encode(&blob), aes_key_b64)
}

#[tokio::test]
async fn oob_end_to_end_register_poll_correlate_deregister() {
    let state: Shared = Arc::new(StdMutex::new(MockState::default()));
    let app = Router::new()
        .route("/register", post(register))
        .route("/poll", get(poll))
        .route("/deregister", post(deregister))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind mock interactsh");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(Duration::from_millis(30)).await;

    // The client derives host = "127.0.0.1:PORT" from this; the mock must use the
    // same host when building full-id so correlation matches.
    state.lock().unwrap().host = addr.to_string();

    let config = OobConfig {
        servers: vec![format!("http://{addr}")],
        secret: None,
        wait_secs: 1,
        timeout: 5,
        proxy: None,
        insecure: true,
    };
    let session = OobSession::start(&config)
        .await
        .expect("register with mock");

    // Arm a payload: mint a URL and record what we "injected" under its nonce.
    let (url, nonce) = session.mint_url();
    assert!(url.contains(&nonce));
    session.registry().record(
        nonce.clone(),
        InjectionRecord {
            target_url: "https://victim/?q=1".to_string(),
            param: "q".to_string(),
            location: "Query".to_string(),
            payload: format!("\"'><script src={url}></script>"),
            method: "GET".to_string(),
        },
    );
    // Make the next poll fire a callback for that nonce.
    state.lock().unwrap().pending_nonce = Some(nonce.clone());

    let results = Arc::new(TokioMutex::new(Vec::new()));
    let findings_count = Arc::new(AtomicUsize::new(0));
    let cancel = Arc::new(AtomicBool::new(false));
    let poller = spawn_poller(
        Arc::new(session),
        results.clone(),
        findings_count.clone(),
        cancel,
        /* silence */ true,
    );
    poller.finish(Duration::from_millis(400)).await;

    let found = results.lock().await;
    assert_eq!(
        found.len(),
        1,
        "expected exactly one correlated OOB finding"
    );
    let f = &found[0];
    assert_eq!(f.param, "q");
    assert_eq!(f.location, "Query");
    assert_eq!(f.severity, "High");
    assert_eq!(f.inject_type, "blind-oob-Query-http");
    assert!(f.payload.contains("script src="));
    assert!(f.evidence.contains("203.0.113.9"));
    assert_eq!(findings_count.load(Ordering::Relaxed), 1);
    assert!(
        state.lock().unwrap().deregistered,
        "session must deregister on finish"
    );
}

#[tokio::test]
async fn oob_session_start_fails_soft_when_no_server_registers() {
    // Unroutable / closed port → registration fails → start() errors (caller
    // turns this into a warning and continues with the static -b path).
    let config = OobConfig {
        servers: vec!["http://127.0.0.1:1".to_string()],
        secret: None,
        wait_secs: 1,
        timeout: 1,
        proxy: None,
        insecure: true,
    };
    assert!(OobSession::start(&config).await.is_err());
}

#[test]
fn interaction_reads_null_and_missing_fields_as_empty() {
    let it: crate::oob::OobInteraction =
        serde_json::from_str(r#"{"protocol":"dns","full-id":"abc.oast.fun","timestamp":null}"#)
            .expect("lenient interaction parse");
    assert_eq!(it.protocol, "dns");
    assert_eq!(it.full_id, "abc.oast.fun");
    assert!(it.remote_address.is_empty() && it.timestamp.is_empty());
}

/// Start the mock and a session registered against it.
async fn mock_session() -> (Shared, OobSession) {
    let state: Shared = Arc::new(StdMutex::new(MockState::default()));
    let app = Router::new()
        .route("/register", post(register))
        .route("/poll", get(poll))
        .route("/deregister", post(deregister))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind mock interactsh");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    state.lock().unwrap().host = addr.to_string();
    crate::ensure_crypto_provider();
    let session = OobSession::start(&OobConfig {
        servers: vec![format!("http://{addr}")],
        secret: None,
        wait_secs: 1,
        timeout: 5,
        proxy: None,
        insecure: true,
    })
    .await
    .expect("register with mock");
    (state, session)
}

#[tokio::test]
async fn oob_poll_failures_are_reported_not_swallowed() {
    let (state, session) = mock_session().await;
    state.lock().unwrap().poll_fails = true;
    let poller = spawn_poller(
        Arc::new(session),
        Arc::new(TokioMutex::new(Vec::new())),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicBool::new(false)),
        /* silence */ false,
    );
    let probe = poller.probe();
    poller.finish(Duration::from_millis(300)).await;
    assert!(
        probe().0,
        "a server that registers fine but fails every poll must produce a warning"
    );
}

#[tokio::test]
async fn oob_unregistered_nonce_findings_are_capped() {
    let (state, session) = mock_session().await;
    let extra = 50;
    state.lock().unwrap().flood = super::poller::MAX_UNATTRIBUTED_FINDINGS + extra;
    let results = Arc::new(TokioMutex::new(Vec::new()));
    let poller = spawn_poller(
        Arc::new(session),
        results.clone(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicBool::new(false)),
        /* silence */ true,
    );
    let probe = poller.probe();
    poller.finish(Duration::from_millis(400)).await;
    assert_eq!(
        results.lock().await.len(),
        super::poller::MAX_UNATTRIBUTED_FINDINGS,
        "forgeable unregistered-nonce hits must stop at the cap"
    );
    assert_eq!(probe().1, super::poller::MAX_UNATTRIBUTED_FINDINGS);
}

/// A server/MCP job that enables `blind_oob` must start the OOB poller bound to
/// the job and stop it when the scan ends — no process-global state, no leaked
/// task. Drives the real `job::runner::execute_scan` against a mock target and
/// a mock interactsh server, then asserts the session was polled (started) and
/// deregistered (stopped) by the time the job returned.
#[tokio::test]
async fn execute_scan_starts_and_stops_the_job_oob_poller() {
    let state: Shared = Arc::new(StdMutex::new(MockState::default()));
    let app = Router::new()
        .route("/register", post(register))
        .route("/poll", get(poll))
        .route("/deregister", post(deregister))
        .with_state(state.clone());
    let oob_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind mock interactsh");
    let oob_addr = oob_listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(oob_listener, app).await;
    });
    state.lock().unwrap().host = oob_addr.to_string();

    // Mock scan target.
    let tgt_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind mock target");
    let tgt_addr = tgt_listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(
            tgt_listener,
            Router::new().route("/", get(|| async { "<html>ok</html>" })),
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(30)).await;

    // `?q=1` gives the blind injector a query param to arm over OOB, so the
    // correlation registry is non-empty and the drain actually polls (rather
    // than short-circuiting its wait).
    let mut target =
        crate::target_parser::parse_target(&format!("http://{tgt_addr}/?q=1")).expect("target");
    let args = Arc::new(crate::cmd::scan::ScanArgs {
        skip_discovery: true,
        skip_mining: true,
        skip_waf_probe: true,
        silence: true,
        oob: crate::cmd::scan::BlindOobArgs {
            blind_oob: Some(vec![format!("http://{oob_addr}")]),
            blind_oob_secret: None,
            // Short drain so the background poller runs at least once (proving
            // it was started) without sleeping the default 30s.
            blind_oob_wait: Some(1),
        },
        ..Default::default()
    });
    let progress = crate::job::JobProgress::default();
    let cancel = Arc::new(AtomicBool::new(false));

    let run =
        crate::job::runner::execute_scan(&mut target, &args, &progress, &cancel, &|_| {}).await;
    assert!(!run.reachability_failed, "mock target must be reachable");
    assert!(
        !run.was_cancelled,
        "a completed scan must not read as cancelled"
    );

    let st = state.lock().unwrap();
    // The background poll loop polls immediately on spawn, and `finish` does a
    // final sweep — so a running-then-stopped poller shows at least two polls,
    // which a final-sweep-only poller (never started) could not.
    assert!(
        st.poll_count >= 2,
        "the background poller must have run (polls={})",
        st.poll_count
    );
    assert!(
        st.deregistered,
        "the job must have stopped the poller and deregistered the session"
    );
}

/// The drain must always deregister, even when the job is cancelled mid-flight
/// — the timeout/cancel path for the OOB poller. `finish` under a tripped
/// cancel flag returns promptly and still runs its final sweep + deregister, so
/// a cancelled scan does not leave the session armed on the server.
#[tokio::test]
async fn poller_finish_under_cancel_still_deregisters() {
    let state: Shared = Arc::new(StdMutex::new(MockState::default()));
    let app = Router::new()
        .route("/register", post(register))
        .route("/poll", get(poll))
        .route("/deregister", post(deregister))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    state.lock().unwrap().host = addr.to_string();

    let config = OobConfig {
        servers: vec![format!("http://{addr}")],
        secret: None,
        wait_secs: 1,
        timeout: 5,
        proxy: None,
        insecure: true,
    };
    let session = OobSession::start(&config).await.expect("register");

    let results = Arc::new(TokioMutex::new(Vec::new()));
    let findings_count = Arc::new(AtomicUsize::new(0));
    // Cancel is already set — the budget/user cancel case.
    let cancel = Arc::new(AtomicBool::new(true));
    let poller = spawn_poller(
        Arc::new(session),
        results,
        findings_count,
        cancel,
        /* silence */ true,
    );
    // A 30s grace would hang if cancel were ignored; cancel must cut it short.
    let start = std::time::Instant::now();
    poller.finish(Duration::from_secs(30)).await;
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "a tripped cancel must cut the grace window short"
    );
    assert!(
        state.lock().unwrap().deregistered,
        "a cancelled drain must still deregister the session"
    );
}

/// Serve the mock interactsh API on an ephemeral port.
async fn serve_mock_oob(state: Shared) -> std::net::SocketAddr {
    let app = Router::new()
        .route("/register", post(register))
        .route("/poll", get(poll))
        .route("/deregister", post(deregister))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind mock interactsh");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    state.lock().unwrap().host = addr.to_string();
    addr
}

/// A reachable scan target plus job args that arm OOB against `oob_addr`.
async fn oob_job(
    oob_addr: std::net::SocketAddr,
    wait: u64,
    scan_timeout: u64,
) -> (
    crate::target_parser::Target,
    Arc<crate::cmd::scan::ScanArgs>,
) {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind mock target");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            Router::new().route("/", get(|| async { "<html>ok</html>" })),
        )
        .await;
    });
    let mut target =
        crate::target_parser::parse_target(&format!("http://{addr}/?q=1")).expect("target");
    target.timeout = 30;
    let args = Arc::new(crate::cmd::scan::ScanArgs {
        skip_discovery: true,
        skip_mining: true,
        skip_waf_probe: true,
        silence: true,
        timeout: 30,
        scan_timeout,
        oob: crate::cmd::scan::BlindOobArgs {
            blind_oob: Some(vec![format!("http://{oob_addr}")]),
            blind_oob_secret: None,
            blind_oob_wait: Some(wait),
        },
        ..Default::default()
    });
    (target, args)
}

/// A server/MCP job runs its poller silenced, so an OAST server that registers
/// but fails every poll must still reach the job's warnings — otherwise the
/// job settles a clean `done` although no callback could ever be collected.
#[tokio::test]
async fn execute_scan_surfaces_oob_poll_failure_as_job_warning() {
    let state: Shared = Arc::new(StdMutex::new(MockState::default()));
    let oob_addr = serve_mock_oob(state.clone()).await;
    state.lock().unwrap().poll_fails = true;
    let (mut target, args) = oob_job(oob_addr, 0, 0).await;
    let progress = crate::job::JobProgress::default();
    let cancel = Arc::new(AtomicBool::new(false));
    let run =
        crate::job::runner::execute_scan(&mut target, &args, &progress, &cancel, &|_| {}).await;
    assert!(
        state.lock().unwrap().poll_count > 0,
        "the poller must have run"
    );
    assert!(
        run.warnings
            .iter()
            .any(|w| w.contains("OOB polling is failing")),
        "poll failure must reach the job warnings: {:?}",
        run.warnings
    );
}

/// `blind_oob_wait` counts against `scan_timeout` (the documented contract, and
/// what keeps a request from outliving the server-wide `--scan-timeout` cap):
/// the drain window is clipped to what is left of the budget.
#[tokio::test]
async fn execute_scan_oob_drain_is_bounded_by_scan_timeout() {
    let state: Shared = Arc::new(StdMutex::new(MockState::default()));
    let oob_addr = serve_mock_oob(state.clone()).await;
    let (mut target, args) = oob_job(oob_addr, 600, 10).await;
    let progress = crate::job::JobProgress::default();
    let cancel = Arc::new(AtomicBool::new(false));
    // Not asserting `!timed_out`: a debug-build RSA keygen under parallel test
    // load can eat the budget, which ends the drain early too.
    tokio::time::timeout(
        Duration::from_secs(40),
        crate::job::runner::execute_scan(&mut target, &args, &progress, &cancel, &|_| {}),
    )
    .await
    .expect("a 600s drain must not outlive a 10s scan_timeout");
    assert!(
        state.lock().unwrap().deregistered,
        "drain must still deregister"
    );
}
