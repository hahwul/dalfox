//! Out-of-band (OAST) blind-XSS support.
//!
//! Extends `-b/--blind` so dalfox can register with an OAST server
//! (projectdiscovery interactsh — the public `oast.*` mesh or a self-hosted
//! instance), mint a unique callback host per injected payload, poll the server,
//! decrypt the interactions, and correlate each callback back to the exact
//! (target, param, payload) that triggered it.
//!
//! The backend is pluggable via [`OobBackend`]; interactsh is the first and only
//! backend today. Adding another OAST provider is a new enum variant plus its
//! match arms — no changes to the injection or reporting paths.

pub mod interactsh;
mod poller;
mod registry;

#[cfg(test)]
mod tests;

pub use poller::{PollerHandle, spawn_poller};
pub use registry::{CorrelationRegistry, InjectionRecord};

use std::sync::Arc;

/// Default public interactsh server mesh, tried in order when the user enables
/// `--blind-oob` without naming a server.
pub const DEFAULT_SERVERS: &[&str] = &[
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "oast.me",
];

/// Static configuration for an OOB session, derived from CLI/config.
#[derive(Debug, Clone)]
pub struct OobConfig {
    /// Candidate server domains, tried in order until one registers.
    pub servers: Vec<String>,
    /// Optional auth token (secret) for a self-hosted interactsh server.
    pub secret: Option<String>,
    /// Seconds to keep draining callbacks after the scan's last request.
    pub wait_secs: u64,
    /// HTTP knobs mirrored from the scan so the OOB client behaves like the scanner.
    pub timeout: u64,
    pub proxy: Option<String>,
    pub insecure: bool,
}

/// One decrypted OAST interaction.
#[derive(Debug, Clone)]
pub struct OobInteraction {
    /// `"http"`, `"dns"`, `"smtp"`, …
    pub protocol: String,
    /// The 33-char host that was hit (`<corr><nonce>.<server>`).
    pub full_id: String,
    pub remote_address: String,
    pub timestamp: String,
    pub raw_request: String,
}

/// Pluggable OAST backend. Dispatch is a `match`; add a variant per provider.
pub enum OobBackend {
    Interactsh(interactsh::InteractshClient),
}

impl OobBackend {
    async fn register(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self {
            OobBackend::Interactsh(c) => c.register().await,
        }
    }
    fn new_payload_url(&self) -> (String, String) {
        match self {
            OobBackend::Interactsh(c) => c.new_payload_url(),
        }
    }
    fn extract_nonce(&self, full_id: &str) -> Option<String> {
        match self {
            OobBackend::Interactsh(c) => c.extract_nonce(full_id),
        }
    }
    async fn poll(&self) -> Result<Vec<OobInteraction>, Box<dyn std::error::Error + Send + Sync>> {
        match self {
            OobBackend::Interactsh(c) => c.poll().await,
        }
    }
    async fn deregister(&self) {
        match self {
            OobBackend::Interactsh(c) => c.deregister().await,
        }
    }
    fn server_domain(&self) -> &str {
        match self {
            OobBackend::Interactsh(c) => c.server_domain(),
        }
    }
}

/// A live OOB session: a registered backend plus the correlation registry that
/// maps per-payload nonces back to what was injected.
pub struct OobSession {
    backend: OobBackend,
    registry: Arc<CorrelationRegistry>,
}

impl OobSession {
    /// Build a session, trying each configured server until one registers.
    /// Returns an error only if *every* candidate fails — callers fail soft and
    /// fall back to the static `-b` path (if any).
    pub async fn start(
        config: &OobConfig,
    ) -> Result<OobSession, Box<dyn std::error::Error + Send + Sync>> {
        let registry = Arc::new(CorrelationRegistry::new());
        let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
        for server in &config.servers {
            match interactsh::InteractshClient::new(server, config) {
                Ok(client) => {
                    let backend = OobBackend::Interactsh(client);
                    match backend.register().await {
                        Ok(()) => return Ok(OobSession { backend, registry }),
                        Err(e) => {
                            last_err = Some(format!("register {server}: {e}").into());
                        }
                    }
                }
                Err(e) => last_err = Some(format!("init {server}: {e}").into()),
            }
        }
        Err(last_err.unwrap_or_else(|| "no OOB servers configured".into()))
    }

    /// Mint a fresh per-payload callback URL, returning `(https URL, nonce)`.
    /// The caller substitutes the URL into the payload, then records the final
    /// payload against `nonce` via [`registry`](Self::registry).
    pub fn mint_url(&self) -> (String, String) {
        self.backend.new_payload_url()
    }

    pub fn registry(&self) -> &Arc<CorrelationRegistry> {
        &self.registry
    }

    pub fn server_domain(&self) -> &str {
        self.backend.server_domain()
    }

    pub fn extract_nonce(&self, full_id: &str) -> Option<String> {
        self.backend.extract_nonce(full_id)
    }

    pub async fn poll(
        &self,
    ) -> Result<Vec<OobInteraction>, Box<dyn std::error::Error + Send + Sync>> {
        self.backend.poll().await
    }

    pub async fn deregister(&self) {
        self.backend.deregister().await
    }
}
