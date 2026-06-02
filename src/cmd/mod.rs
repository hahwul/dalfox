pub mod file;
pub mod payload;
pub mod pipe;
pub mod scan;
pub mod url;

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

#[cfg(test)]
mod tests {
    use super::*;

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
