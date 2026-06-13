//! interactsh OAST client: RSA-armed registration, per-payload callback URLs,
//! polling with decrypt, and best-effort deregistration. One client == one
//! session bound to a single server domain and correlation-id.

mod crypto;
mod wire;

use std::time::Duration;

use rand::Rng;
use reqwest::Client;

use crate::oob::{OobConfig, OobInteraction};
use crypto::SessionKeys;

type ClientResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// interactsh fixes the correlation-id length at 20; the per-payload nonce fills
/// the rest of the 33-char subdomain label.
const CORRELATION_ID_LEN: usize = 20;
const NONCE_LEN: usize = 13;
/// Cap on the OAST poll/register response body we buffer. Legitimate interactsh
/// poll JSON is tiny; this bounds memory if a hostile/compromised OAST node
/// streams an oversized body, consistent with the project's capped-body policy
/// for scanned targets. A truncated body just yields a parse error the poller
/// already swallows.
const OOB_MAX_BODY_BYTES: usize = 4 << 20; // 4 MiB
/// Upper bound on the pre-allocation hint for the decrypted-interaction buffer,
/// so a large advertised entry count can't drive an oversized reservation.
const OOB_MAX_ENTRIES_HINT: usize = 4096;
const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

pub struct InteractshClient {
    /// Bare host[:port] embedded in payload callback hosts and matched against
    /// interaction `full-id`s.
    server: String,
    /// Full base URL (`scheme://host[:port]`) for register/poll/deregister.
    base: String,
    /// Scheme to use for minted callback URLs (honors user-provided scheme for
    /// self-hosted OAST so that e.g. `http://my-collab:8080` produces
    /// `http://<corr><nonce>.my-collab:8080` in blind payloads rather than
    /// hard-coded https).
    callback_scheme: String,
    correlation_id: String,
    secret_key: String,
    token: Option<String>,
    keys: SessionKeys,
    http: Client,
}

/// Generate one keypair, then try each configured server in order until one
/// registers. Returns the first live client, or the last error if all fail
/// (the caller turns that into a soft warning). The RSA-2048 keypair is
/// generated once and reused across attempts rather than per server.
pub async fn register_first(config: &OobConfig) -> ClientResult<InteractshClient> {
    // RSA-2048 keygen is a 50-300ms CPU burst. Run it on the blocking pool so it
    // does not stall an async runtime worker (and any other tasks scheduled on
    // it) for the duration.
    let keys = tokio::task::spawn_blocking(SessionKeys::generate)
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("OOB keygen task panicked: {e}").into()
        })??;
    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    for server in &config.servers {
        let client = match InteractshClient::new(server, config, keys.clone()) {
            Ok(c) => c,
            Err(e) => {
                last_err = Some(format!("init {server}: {e}").into());
                continue;
            }
        };
        match client.register().await {
            Ok(()) => return Ok(client),
            Err(e) => last_err = Some(format!("register {server}: {e}").into()),
        }
    }
    Err(last_err.unwrap_or_else(|| "no OOB servers configured".into()))
}

impl InteractshClient {
    /// Build a client for `server` from a pre-generated keypair (does no network
    /// I/O — call [`register`] next).
    ///
    /// [`register`]: InteractshClient::register
    fn new(server: &str, config: &OobConfig, keys: SessionKeys) -> ClientResult<Self> {
        crate::ensure_crypto_provider();
        let correlation_id = rand_label(CORRELATION_ID_LEN);
        let secret_key = uuid::Uuid::new_v4().to_string();

        let mut builder = Client::builder()
            .timeout(Duration::from_secs(config.timeout.max(1)))
            .danger_accept_invalid_certs(config.insecure);
        if let Some(pxy) = config.proxy.as_ref()
            && let Ok(proxy) = reqwest::Proxy::all(pxy)
        {
            builder = builder.proxy(proxy);
        }
        let http = builder.build()?;

        let (base, host) = split_server(server);
        let callback_scheme = if base.starts_with("http://") {
            "http".to_string()
        } else {
            "https".to_string()
        };
        Ok(Self {
            server: host,
            base,
            callback_scheme,
            correlation_id,
            secret_key,
            token: config.secret.clone(),
            keys,
            http,
        })
    }

    pub fn server_domain(&self) -> &str {
        &self.server
    }

    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    fn base_url(&self) -> &str {
        &self.base
    }

    /// Register the public key + correlation-id with the server.
    pub async fn register(&self) -> ClientResult<()> {
        let body = wire::RegisterRequest {
            public_key: self.keys.public_key_b64.clone(),
            secret_key: self.secret_key.clone(),
            correlation_id: self.correlation_id.clone(),
        };
        let mut req = self
            .http
            .post(format!("{}/register", self.base_url()))
            .json(&body);
        if let Some(t) = &self.token {
            req = req.header(reqwest::header::AUTHORIZATION, t);
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(format!("register returned HTTP {}", resp.status()).into());
        }
        Ok(())
    }

    /// Mint a fresh `<scheme>://<corr><nonce>.<server>` callback URL (scheme
    /// matches the one used for the OAST API server) and return it alongside
    /// the `nonce` used to correlate the eventual callback.
    pub fn new_payload_url(&self) -> (String, String) {
        let nonce = rand_label(NONCE_LEN);
        let host = format!("{}{}.{}", self.correlation_id, nonce, self.server);
        (format!("{}://{host}", self.callback_scheme), nonce)
    }

    /// Recover the 13-char nonce from an interaction's `full-id`
    /// (`<corr><nonce>.<server>`), or `None` if it isn't one of ours.
    pub fn extract_nonce(&self, full_id: &str) -> Option<String> {
        let label = full_id.split('.').next()?;
        let rest = label.strip_prefix(&self.correlation_id)?;
        if rest.is_empty() {
            return None;
        }
        Some(rest.chars().take(NONCE_LEN).collect())
    }

    /// Poll once, returning every decrypted interaction the server had queued.
    pub async fn poll(&self) -> ClientResult<Vec<OobInteraction>> {
        let url = format!(
            "{}/poll?id={}&secret={}",
            self.base_url(),
            self.correlation_id,
            self.secret_key
        );
        let mut req = self.http.get(url);
        if let Some(t) = &self.token {
            req = req.header(reqwest::header::AUTHORIZATION, t);
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Err(format!("poll returned HTTP {}", resp.status()).into());
        }
        // Cap the buffered body instead of `resp.json()` (which reads without
        // bound) so a hostile OAST node can't drive an OOM through the poller.
        let body = crate::utils::http::read_body_capped(resp, OOB_MAX_BODY_BYTES).await?;
        let parsed: wire::PollResponse = serde_json::from_str(&body)?;

        let aes_key_b64 = parsed.aes_key.as_deref().filter(|s| !s.is_empty());
        let Some(aes_key_b64) = aes_key_b64 else {
            return Ok(Vec::new());
        };
        let mut entries: Vec<String> = parsed.data.unwrap_or_default();
        entries.extend(parsed.extra.unwrap_or_default());
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        let aes_key = self.keys.decrypt_aes_key(aes_key_b64)?;

        let mut out = Vec::with_capacity(entries.len().min(OOB_MAX_ENTRIES_HINT));
        for item in &entries {
            let Ok(plain) = crypto::decrypt_interaction(&aes_key, item) else {
                continue;
            };
            let Ok(inter) = serde_json::from_slice::<wire::Interaction>(&plain) else {
                continue;
            };
            out.push(OobInteraction {
                protocol: inter.protocol.unwrap_or_default(),
                full_id: inter.full_id.unwrap_or_default(),
                remote_address: inter.remote_address.unwrap_or_default(),
                timestamp: inter.timestamp.unwrap_or_default(),
                raw_request: inter.raw_request.unwrap_or_default(),
            });
        }
        Ok(out)
    }

    /// Best-effort deregistration; failures are ignored (the session is ending).
    pub async fn deregister(&self) {
        let body = wire::DeregisterRequest {
            correlation_id: self.correlation_id.clone(),
            secret_key: self.secret_key.clone(),
        };
        let mut req = self
            .http
            .post(format!("{}/deregister", self.base_url()))
            .json(&body);
        if let Some(t) = &self.token {
            req = req.header(reqwest::header::AUTHORIZATION, t);
        }
        let _ = req.send().await;
    }
}

/// Split a user-supplied server value into `(base_url, host)`. The scheme
/// defaults to `https` (public interactsh) but an explicit `http://` is honored
/// for self-hosted servers behind a TLS-terminating proxy (and for tests). The
/// returned host (no scheme/path, trailing dot stripped, lowercased) is what
/// gets embedded in payload callback hosts.
fn split_server(server: &str) -> (String, String) {
    let s = server.trim();
    let (scheme, rest) = if let Some(r) = s.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = s.strip_prefix("http://") {
        ("http", r)
    } else {
        ("https", s)
    };
    let host = rest
        .split('/')
        .next()
        .unwrap_or(rest)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (format!("{scheme}://{host}"), host)
}

/// Random lowercase-alphanumeric DNS label component of length `n`.
fn rand_label(n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> OobConfig {
        OobConfig {
            servers: vec!["oast.fun".to_string()],
            secret: None,
            wait_secs: 5,
            timeout: 10,
            proxy: None,
            insecure: false,
        }
    }

    #[test]
    fn split_server_handles_scheme_and_path() {
        assert_eq!(
            split_server("https://OAST.fun/"),
            ("https://oast.fun".to_string(), "oast.fun".to_string())
        );
        assert_eq!(
            split_server("oast.me."),
            ("https://oast.me".to_string(), "oast.me".to_string())
        );
        assert_eq!(
            split_server("  http://my.collab:1/x "),
            ("http://my.collab:1".to_string(), "my.collab:1".to_string())
        );
    }

    #[test]
    fn payload_url_is_33_char_host_and_correlates() {
        let keys = SessionKeys::generate().expect("keygen");
        let client = InteractshClient::new("oast.fun", &test_config(), keys).expect("client");
        let (url, nonce) = client.new_payload_url();
        assert_eq!(nonce.len(), NONCE_LEN);
        let host = url.strip_prefix("https://").unwrap();
        let label = host.split('.').next().unwrap();
        assert_eq!(label.len(), CORRELATION_ID_LEN + NONCE_LEN);
        assert!(host.ends_with(".oast.fun"));
        assert!(
            label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        );

        // Round-trip: the full-id from a callback recovers the same nonce.
        let full_id = format!("{}{}.oast.fun", client.correlation_id(), nonce);
        assert_eq!(
            client.extract_nonce(&full_id).as_deref(),
            Some(nonce.as_str())
        );
        assert!(client.extract_nonce("someoneelses.oast.fun").is_none());
    }
}
