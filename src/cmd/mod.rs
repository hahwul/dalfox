pub mod file;
pub mod job;
pub mod payload;
pub mod pipe;
pub mod scan;
pub mod server;
pub mod url;

use serde::{Deserialize, Serialize};
use std::fmt;

/// Application-level error codes shared across CLI, REST API, and MCP interfaces.
/// These codes appear in JSON output (`error.code`, `target_summary.error_code`,
/// `error_message`) and should be used consistently across all interfaces.
pub mod error_codes {
    // Input validation
    pub const NO_TARGETS: &str = "NO_TARGETS";
    pub const NO_FILE: &str = "NO_FILE";
    pub const INVALID_INPUT_TYPE: &str = "INVALID_INPUT_TYPE";

    // Parsing
    pub const PARSE_ERROR: &str = "PARSE_ERROR";

    // I/O
    pub const FILE_READ_ERROR: &str = "FILE_READ_ERROR";
    pub const STDIN_ERROR: &str = "STDIN_ERROR";
    /// Input source (target list file or stdin pipe) exceeded the
    /// configured byte cap. Distinct from generic FILE_READ_ERROR so
    /// users see *why* the read was refused — most often a non-regular
    /// file like `/dev/zero` or an unintended huge file.
    pub const INPUT_TOO_LARGE: &str = "INPUT_TOO_LARGE";
    /// `--input-type pipe` was set, but stdin is a terminal (no pipe
    /// attached). Reading would block forever waiting for Ctrl-D —
    /// fail fast with a clear message instead.
    pub const STDIN_NOT_PIPED: &str = "STDIN_NOT_PIPED";
    pub const CONNECTION_FAILED: &str = "CONNECTION_FAILED";
    pub const DNS_RESOLUTION_FAILED: &str = "DNS_RESOLUTION_FAILED";
    pub const TLS_HANDSHAKE_FAILED: &str = "TLS_HANDSHAKE_FAILED";
    pub const REQUEST_TIMEOUT: &str = "REQUEST_TIMEOUT";

    // Scan filtering
    pub const CONTENT_TYPE_MISMATCH: &str = "CONTENT_TYPE_MISMATCH";
    pub const TRUNCATED_PER_HOST_CAP: &str = "TRUNCATED_PER_HOST_CAP";
}

/// Status of an asynchronous scan job (used by both REST server and MCP).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Done,
    Error,
    Cancelled,
}

impl fmt::Display for JobStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queued => write!(f, "queued"),
            Self::Running => write!(f, "running"),
            Self::Done => write!(f, "done"),
            Self::Error => write!(f, "error"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_status_display_matches_lowercase_variant_name() {
        assert_eq!(JobStatus::Queued.to_string(), "queued");
        assert_eq!(JobStatus::Running.to_string(), "running");
        assert_eq!(JobStatus::Done.to_string(), "done");
        assert_eq!(JobStatus::Error.to_string(), "error");
        assert_eq!(JobStatus::Cancelled.to_string(), "cancelled");
    }

    /// The Display impl and the `#[serde(rename_all = "lowercase")]`
    /// representation must agree — REST and MCP clients parse the JSON
    /// form, and CLI logs print the Display form. Drift between them
    /// would silently break consumers that compare the two strings.
    #[test]
    fn job_status_serde_matches_display() {
        let variants = [
            JobStatus::Queued,
            JobStatus::Running,
            JobStatus::Done,
            JobStatus::Error,
            JobStatus::Cancelled,
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            // serde_json wraps the variant name in quotes.
            assert_eq!(json, format!("\"{}\"", v));
            let round: JobStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(round, v);
        }
    }

    #[test]
    fn job_status_deserializes_from_lowercase_string() {
        let s: JobStatus = serde_json::from_str("\"queued\"").unwrap();
        assert_eq!(s, JobStatus::Queued);
        let s: JobStatus = serde_json::from_str("\"cancelled\"").unwrap();
        assert_eq!(s, JobStatus::Cancelled);
    }

    #[test]
    fn job_status_rejects_unknown_variant() {
        assert!(serde_json::from_str::<JobStatus>("\"finished\"").is_err());
    }

    /// Error code string values are part of the wire contract (JSON
    /// output reaches CLI scripts, REST clients, and MCP). Lock the
    /// exact strings so an accidental rename causes a test failure
    /// rather than a silent break.
    #[test]
    fn error_code_constants_have_stable_string_values() {
        assert_eq!(error_codes::NO_TARGETS, "NO_TARGETS");
        assert_eq!(error_codes::NO_FILE, "NO_FILE");
        assert_eq!(error_codes::INVALID_INPUT_TYPE, "INVALID_INPUT_TYPE");
        assert_eq!(error_codes::PARSE_ERROR, "PARSE_ERROR");
        assert_eq!(error_codes::FILE_READ_ERROR, "FILE_READ_ERROR");
        assert_eq!(error_codes::STDIN_ERROR, "STDIN_ERROR");
        assert_eq!(error_codes::CONNECTION_FAILED, "CONNECTION_FAILED");
        assert_eq!(error_codes::CONTENT_TYPE_MISMATCH, "CONTENT_TYPE_MISMATCH");
        assert_eq!(
            error_codes::TRUNCATED_PER_HOST_CAP,
            "TRUNCATED_PER_HOST_CAP"
        );
    }
}
