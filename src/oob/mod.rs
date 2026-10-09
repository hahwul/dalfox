//! Out-of-band (OAST) blind-XSS support.
//!
//! Extends `-b/--blind` so dalfox can register with an OAST server
//! (projectdiscovery interactsh — the public `oast.*` mesh or a self-hosted
//! instance), mint a unique callback host per injected payload, poll the server,
//! decrypt the interactions, and correlate each callback back to the exact
//! (target, param, payload) that triggered it.
//!
//! interactsh is the only backend; a second OAST provider would wrap the
//! client in [`OobSession`] behind an enum — no changes to the injection or
//! reporting paths.

pub mod interactsh;
mod poller;
mod registry;

#[cfg(test)]
mod tests;

pub(crate) use poller::{PollerHandle, spawn_poller};
pub(crate) use registry::{CorrelationRegistry, InjectionRecord};

use std::sync::Arc;

use serde::Deserialize;

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

/// Is `host` one of the public [`DEFAULT_SERVERS`]?
///
/// `host` is the bare `host[:port]` produced by the interactsh client's own
/// server parsing (scheme and path stripped, lowercased), so a bare domain, a
/// `https://` URL and a trailing-dot FQDN for the same mesh node all answer the
/// same. An explicit `:443` is stripped first: the mesh is https, so
/// `oast.pro:443` is the same endpoint as `oast.pro` and must not be able to
/// spell its way out of certificate verification. Anything else — a self-hosted
/// instance, or a mesh domain on some other port — is a server the operator
/// named, not one dalfox picked.
pub(crate) fn is_default_server(host: &str) -> bool {
    let host = host.strip_suffix(":443").unwrap_or(host);
    DEFAULT_SERVERS.iter().any(|d| d.eq_ignore_ascii_case(host))
}

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
    /// The scan's `--insecure` posture. Applied only to a server the operator
    /// named themselves — see `interactsh::accept_invalid_certs`, which is
    /// where this becomes an actual TLS decision.
    pub insecure: bool,
}

/// One decrypted OAST interaction, deserialized straight from interactsh's
/// JSON. interactsh always sets `protocol`, `full-id`, and `remote-address`;
/// the rest are best-effort, so absent or `null` fields read as empty.
/// (`unique-id` / `raw-request` are on the wire too but unused here —
/// callbacks are de-duped per (nonce, protocol).)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct OobInteraction {
    /// `"http"`, `"dns"`, `"smtp"`, …
    #[serde(deserialize_with = "null_as_empty")]
    pub protocol: String,
    /// The 33-char host that was hit (`<corr><nonce>.<server>`).
    #[serde(deserialize_with = "null_as_empty")]
    pub full_id: String,
    #[serde(deserialize_with = "null_as_empty")]
    pub remote_address: String,
    #[serde(deserialize_with = "null_as_empty")]
    pub timestamp: String,
}

fn null_as_empty<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
}

/// A live OOB session: a registered interactsh client plus the correlation
/// registry that maps per-payload nonces back to what was injected.
pub struct OobSession {
    client: interactsh::InteractshClient,
    registry: Arc<CorrelationRegistry>,
}

impl OobSession {
    /// Build a session, trying each configured server until one registers.
    /// Returns an error only if *every* candidate fails — callers fail soft and
    /// fall back to the static `-b` path (if any).
    pub async fn start(
        config: &OobConfig,
    ) -> Result<OobSession, Box<dyn std::error::Error + Send + Sync>> {
        Ok(OobSession {
            client: interactsh::register_first(config).await?,
            registry: Arc::new(CorrelationRegistry::new()),
        })
    }

    /// Mint a fresh per-payload callback URL, returning `(https URL, nonce)`.
    /// The caller substitutes the URL into the payload, then records the final
    /// payload against `nonce` via [`registry`](Self::registry).
    pub fn mint_url(&self) -> (String, String) {
        self.client.new_payload_url()
    }

    pub fn registry(&self) -> &Arc<CorrelationRegistry> {
        &self.registry
    }

    pub fn server_domain(&self) -> &str {
        self.client.server_domain()
    }

    pub fn extract_nonce(&self, full_id: &str) -> Option<String> {
        self.client.extract_nonce(full_id)
    }

    pub async fn poll(
        &self,
    ) -> Result<Vec<OobInteraction>, Box<dyn std::error::Error + Send + Sync>> {
        self.client.poll().await
    }

    pub async fn deregister(&self) {
        self.client.deregister().await
    }
}
