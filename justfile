alias b := build
alias d := dev
alias ds := docs-serve
alias f := fix
alias t := test
alias vc := version-check
alias vu := version-update
alias xs := xssmaze-score

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

# Serve docs site locally.
[group('documents')]
docs-serve:
    hwaro serve -i docs --base-url="http://localhost:3000"

# Install docs dependencies (macOS).
[group('documents')]
docs-dependencies:
    brew install hahwul/hwaro/hwaro

# Format code and apply clippy suggestions.
[group('build')]
fix:
    cargo fmt
    cargo clippy --fix --allow-dirty

# Report dalfox version across Cargo.toml, Cargo.lock, flake.nix, snap.
[group('release')]
version-check:
    crystal run scripts/version_check.cr

# Bump dalfox version in lockstep across all version-bearing files.
[group('release')]
version-update:
    crystal run scripts/version_update.cr

# Run unit tests.
[group('test')]
test:
    cargo test

# Run all tests including ignored ones.
[group('test')]
test_all:
    cargo test -- --include-ignored

# Benchmark detection against XSSMaze (main) and record the score in docs.
[group('benchmark')]
xssmaze-score: build
    crystal run scripts/xssmaze_score.cr

# Re-render the XSSMaze score page from the committed snapshot (no scanning).
[group('benchmark')]
xssmaze-render:
    XSSMAZE_RENDER_ONLY=1 crystal run scripts/xssmaze_score.cr
