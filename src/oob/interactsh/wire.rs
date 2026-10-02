//! Wire structs for the interactsh register/poll/deregister JSON. Field names
//! match the Go server's tags. The decrypted interaction deserializes straight
//! into [`crate::oob::OobInteraction`].

use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub(crate) struct RegisterRequest {
    #[serde(rename = "public-key")]
    pub public_key: String,
    #[serde(rename = "secret-key")]
    pub secret_key: String,
    #[serde(rename = "correlation-id")]
    pub correlation_id: String,
}

#[derive(Serialize)]
pub(crate) struct DeregisterRequest {
    #[serde(rename = "correlation-id")]
    pub correlation_id: String,
    #[serde(rename = "secret-key")]
    pub secret_key: String,
}

#[derive(Deserialize)]
pub(crate) struct PollResponse {
    pub data: Option<Vec<String>>,
    pub extra: Option<Vec<String>>,
    pub aes_key: Option<String>,
}
