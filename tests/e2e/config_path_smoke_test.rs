//! E2E smoke tests for explicit --config path handling.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time moved backwards")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("dalfox-{label}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create test temp directory");
    dir
}

fn run_payload_with_config(path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args([
            "--config",
            path.to_str().expect("utf8 path"),
            "payload",
            "event-handlers",
        ])
        .output()
        .expect("run dalfox with explicit --config")
}

fn run_payload_with_xdg_config_home(xdg_home: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dalfox"))
        .args(["payload", "event-handlers"])
        .env("XDG_CONFIG_HOME", xdg_home)
        .output()
        .expect("run dalfox with explicit XDG_CONFIG_HOME")
}

#[test]
fn test_missing_json_config_path_is_created() {
    let dir = unique_temp_dir("cfg-create-json");
    let config_path = dir.join("config.json");
    assert!(!config_path.exists());

    let output = run_payload_with_config(&config_path);
    assert!(
        output.status.success(),
        "expected success for missing json config path"
    );
    assert!(config_path.exists(), "json config file should be created");
}

#[test]
fn test_missing_toml_config_path_is_created() {
    let dir = unique_temp_dir("cfg-create-toml");
    let config_path = dir.join("config.toml");
    assert!(!config_path.exists());

    let output = run_payload_with_config(&config_path);
    assert!(
        output.status.success(),
        "expected success for missing toml config path"
    );
    assert!(config_path.exists(), "toml config file should be created");
}

#[test]
fn test_existing_valid_json_config_path_is_parsed() {
    let dir = unique_temp_dir("cfg-existing-json");
    let config_path = dir.join("config.json");
    std::fs::write(&config_path, "{\n  \"scan\": {\"format\": \"json\"}\n}\n")
        .expect("write valid json config");

    let output = run_payload_with_config(&config_path);
    assert!(
        output.status.success(),
        "valid existing .json config should parse successfully"
    );
}

#[test]
fn test_existing_valid_toml_config_path_is_parsed() {
    let dir = unique_temp_dir("cfg-existing-toml");
    let config_path = dir.join("config.toml");
    std::fs::write(&config_path, "[scan]\nformat = \"json\"\n").expect("write valid toml config");

    let output = run_payload_with_config(&config_path);
    assert!(
        output.status.success(),
        "valid existing .toml config should parse successfully"
    );
}

#[test]
fn test_json_extension_falls_back_to_toml_content() {
    let dir = unique_temp_dir("cfg-json-fallback");
    let config_path = dir.join("config.json");
    std::fs::write(&config_path, "[scan]\nformat = \"json\"\n").expect("write toml-as-json-ext");

    let output = run_payload_with_config(&config_path);
    assert!(
        output.status.success(),
        "toml fallback for .json extension should not fail"
    );
}

#[test]
fn test_toml_extension_falls_back_to_json_content() {
    let dir = unique_temp_dir("cfg-toml-fallback");
    let config_path = dir.join("config.toml");
    std::fs::write(&config_path, "{\"scan\":{\"format\":\"json\"}}\n")
        .expect("write json-as-toml-ext");

    let output = run_payload_with_config(&config_path);
    assert!(
        output.status.success(),
        "json fallback for .toml extension should not fail"
    );
}

#[test]
fn test_broken_config_content_is_non_fatal_for_payload_command() {
    let dir = unique_temp_dir("cfg-broken-content");

    let broken_json = dir.join("broken.json");
    std::fs::write(&broken_json, "{\n").expect("write invalid json/toml");
    let json_output = run_payload_with_config(&broken_json);
    assert!(
        json_output.status.success(),
        "broken .json config should not abort payload command"
    );

    let broken_toml = dir.join("broken.toml");
    std::fs::write(&broken_toml, "{\n").expect("write invalid toml/json");
    let toml_output = run_payload_with_config(&broken_toml);
    assert!(
        toml_output.status.success(),
        "broken .toml config should not abort payload command"
    );
}

#[test]
fn test_unreadable_config_path_is_non_fatal_for_payload_command() {
    let dir = unique_temp_dir("cfg-read-error-dir");
    let output = run_payload_with_config(&dir);
    assert!(
        output.status.success(),
        "directory-as-config read error should not abort payload command"
    );
}

#[test]
fn test_default_load_or_init_creates_toml_under_xdg_config_home() {
    let xdg_home = unique_temp_dir("xdg-create");
    let output = run_payload_with_xdg_config_home(&xdg_home);
    assert!(
        output.status.success(),
        "default config init should succeed when no config exists"
    );
    assert!(
        xdg_home.join("dalfox").join("config.toml").exists(),
        "default config.toml should be created under XDG_CONFIG_HOME"
    );
}

#[test]
fn test_default_load_or_init_reads_json_when_toml_missing() {
    let xdg_home = unique_temp_dir("xdg-json-only");
    let dalfox_dir = xdg_home.join("dalfox");
    std::fs::create_dir_all(&dalfox_dir).expect("create dalfox config dir");
    std::fs::write(
        dalfox_dir.join("config.json"),
        "{\n  \"scan\": {\"format\": \"json\"}\n}\n",
    )
    .expect("write json config");

    let output = run_payload_with_xdg_config_home(&xdg_home);
    assert!(
        output.status.success(),
        "json config should be read when toml is missing"
    );
}

#[test]
fn test_default_load_or_init_prefers_toml_over_json() {
    let xdg_home = unique_temp_dir("xdg-toml-priority");
    let dalfox_dir = xdg_home.join("dalfox");
    std::fs::create_dir_all(&dalfox_dir).expect("create dalfox config dir");
    std::fs::write(
        dalfox_dir.join("config.toml"),
        "[scan]\nformat = \"jsonl\"\n",
    )
    .expect("write toml config");
    std::fs::write(
        dalfox_dir.join("config.json"),
        "{\n  \"scan\": {\"format\": \"json\"}\n}\n",
    )
    .expect("write json config");

    let output = run_payload_with_xdg_config_home(&xdg_home);
    assert!(
        output.status.success(),
        "toml config should be preferred over json when both exist"
    );
}
