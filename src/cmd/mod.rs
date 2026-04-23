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
    pub const CONNECTION_FAILED: &str = "CONNECTION_FAILED";

    // Scan filtering
    pub const CONTENT_TYPE_MISMATCH: &str = "CONTENT_TYPE_MISMATCH";
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
