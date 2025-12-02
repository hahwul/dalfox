//! Functional tests for CLI flags and basic operations

mod version_and_help {
    use std::process::Command;

    #[test]
    fn test_version_flag() {
        let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
            .arg("--version")
            .output()
            .expect("Failed to execute command");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("dalfox") || stdout.contains("3.0"),
            "Version output should contain dalfox name or version number: {}",
            stdout
        );
    }

    #[test]
    fn test_short_version_flag() {
        let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
            .arg("-V")
            .output()
            .expect("Failed to execute command");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("dalfox") || stdout.contains("3.0"),
            "Short version output should contain dalfox name or version number: {}",
            stdout
        );
    }

    #[test]
    fn test_help_flag() {
        let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
            .arg("--help")
            .output()
            .expect("Failed to execute command");

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Help output should contain usage information
        assert!(
            stdout.contains("Usage:") || stdout.contains("usage"),
            "Help output should contain usage information: {}",
            stdout
        );
    }

    #[test]
    fn test_short_help_flag() {
        let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
            .arg("-h")
            .output()
            .expect("Failed to execute command");

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Help output should contain usage information
        assert!(
            stdout.contains("Usage:") || stdout.contains("usage"),
            "Short help output should contain usage information: {}",
            stdout
        );
    }
}

mod subcommand_help {
    use std::process::Command;

    #[test]
    fn test_scan_help() {
        let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
            .args(["scan", "--help"])
            .output()
            .expect("Failed to execute command");

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Scan help should contain scan-specific options
        assert!(
            stdout.contains("scan") || stdout.contains("Scan"),
            "Scan help should contain 'scan': {}",
            stdout
        );
    }

    #[test]
    fn test_server_help() {
        let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
            .args(["server", "--help"])
            .output()
            .expect("Failed to execute command");

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Server help should contain server-specific options
        assert!(
            stdout.contains("server") || stdout.contains("Server") || stdout.contains("API"),
            "Server help should contain 'server' or 'API': {}",
            stdout
        );
    }

    #[test]
    fn test_payload_help() {
        let output = Command::new(env!("CARGO_BIN_EXE_dalfox"))
            .args(["payload", "--help"])
            .output()
            .expect("Failed to execute command");

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Payload help should contain payload-specific options
        assert!(
            stdout.contains("payload") || stdout.contains("Payload"),
            "Payload help should contain 'payload': {}",
            stdout
        );
    }
}
