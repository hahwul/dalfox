//! Wire structs for the interactsh register/poll/deregister JSON, plus the
//! decrypted interaction payload. Field names match the Go server's tags.

use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct RegisterRequest {
    #[serde(rename = "public-key")]
    pub public_key: String,
    #[serde(rename = "secret-key")]
    pub secret_key: String,
    #[serde(rename = "correlation-id")]
    pub correlation_id: String,
}

#[derive(Serialize)]
pub struct DeregisterRequest {
    #[serde(rename = "correlation-id")]
    pub correlation_id: String,
    #[serde(rename = "secret-key")]
    pub secret_key: String,
}

#[derive(Deserialize, Default)]
pub struct PollResponse {
    #[serde(default)]
    pub data: Option<Vec<String>>,
    #[serde(default)]
    pub extra: Option<Vec<String>>,
    #[serde(rename = "aes_key", default)]
    pub aes_key: Option<String>,
}

/// One decrypted interaction. interactsh always sets `protocol`, `full-id`, and
/// `remote-address`; the rest are best-effort. (`unique-id` is on the wire too
/// but unused here — callbacks are de-duped per (nonce, protocol).)
#[derive(Deserialize, Default)]
pub struct Interaction {
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(rename = "full-id", default)]
    pub full_id: Option<String>,
    #[serde(rename = "remote-address", default)]
    pub remote_address: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(rename = "raw-request", default)]
    pub raw_request: Option<String>,
}
