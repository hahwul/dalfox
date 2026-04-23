alias b := build
alias d := dev
alias t := test

# List available tasks.
default:
    @just --list

# Build release binary.
[group('build')]
build:
    cargo build --release

# Build debug binary.
[group('build')]
dev:
    cargo build

# Update Nix flake lock.
[group('build')]
nix-update:
    nix flake update

#[group('development')]
#fix:
#    cargo fmt
#    cargo clippy --fix --allow-dirty

# Run unit tests.
[group('test')]
test:
    cargo test

# Run all tests including ignored ones.
[group('test')]
test_all:
    cargo test -- --include-ignored

# Smoke test against xssmaze JSON endpoint.
[group('test')]
xssmaze_smoke:
    cargo test test_cli_scans_xssmaze_json_endpoint_without_deep_scan -- --ignored --nocapture

# Compare v3 against local v2 on xssmaze subset.
[group('test')]
compare_v2_xssmaze:
    cargo test test_v3_is_not_worse_than_local_v2_on_xssmaze_subset -- --ignored --nocapture

# Scan every xssmaze level with the debug binary.
[group('scan')]
xss_maze:
    # Install and Run xssmaze
    # git clone https://github.com/hahwul/xssmaze
    # cd xssmaze
    # shards build
    # ./bin/xssmaze

    # Basic
    ./target/debug/dalfox scan "http://localhost:3000/basic/level1/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/basic/level2/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/basic/level3/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/basic/level4/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/basic/level5/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/basic/level6/?query=a"

    # DOM
    ./target/debug/dalfox scan "http://localhost:3000/dom/level1/"
    ./target/debug/dalfox scan "http://localhost:3000/dom/level2/"
    ./target/debug/dalfox scan "http://localhost:3000/dom/level3/"
    ./target/debug/dalfox scan "http://localhost:3000/dom/level4/"
    ./target/debug/dalfox scan "http://localhost:3000/dom/level5/"
    ./target/debug/dalfox scan "http://localhost:3000/dom/level6/"

    # Decode
    ./target/debug/dalfox scan "http://localhost:3000/decode/level1/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/decode/level2/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/decode/level3/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/decode/level4/?query=a"

    # Hidden
    ./target/debug/dalfox scan "http://localhost:3000/hidden/level1/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/hidden/level2/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/hidden/level3/?query=a"

    # Path
    ./target/debug/dalfox scan "http://localhost:3000/path/level1/a"
    ./target/debug/dalfox scan "http://localhost:3000/path/level2/a"
    ./target/debug/dalfox scan "http://localhost:3000/path/level3/a"
    ./target/debug/dalfox scan "http://localhost:3000/path/level4/a"
