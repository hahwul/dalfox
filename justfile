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

# Report dalfox version across all version-bearing files.
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

# ---------------------------------------------------------------------------
# Crystal harnesses (scripts/). Shared helpers live in scripts/lib; the
# disposable labs each harness scans live in scripts/labs. See scripts/README.md.
# ---------------------------------------------------------------------------

# Assert the five scanning surfaces (CLI, config, REST, MCP, skills+docs) agree.
[group('harness')]
surface-parity: build
    crystal run scripts/surface_parity.cr

# Assert the output contract: every --format parses and nothing else reaches stdout.
[group('harness')]
output-conformance: build
    crystal run scripts/output_conformance.cr

# Read-only docs lint: EN/KO pairing, front matter, links, CSP, generated markers.
[group('harness')]
docs-lint:
    crystal run scripts/docs_lint.cr

# End-to-end smoke test of the REST and MCP servers, including their parity.
[group('harness')]
server-mcp-smoke: build
    crystal run scripts/server_mcp_smoke.cr

# Assert dalfox survives hostile responses (crash / hang / memory gate).
[group('harness')]
hostile-scan: build
    crystal run scripts/hostile_scan.cr

# Replay the benign corpus; any finding on these pages is a false positive.
[group('harness')]
replay-corpus: build
    crystal run scripts/replay_corpus.cr

# Run every gate above, continuing past failures (exit non-zero if any failed).
[group('harness')]
harness: build
    #!/usr/bin/env bash
    rc=0
    for h in docs_lint surface_parity output_conformance replay_corpus server_mcp_smoke hostile_scan; do
        echo "::: $h"
        crystal run "scripts/$h.cr" || rc=1
    done
    exit $rc

# Measure precision/recall against the labelled mock-case corpus (~10s).
[group('benchmark')]
effectiveness: build
    crystal run scripts/effectiveness_snapshot.cr

# Re-report the committed effectiveness snapshot without scanning.
[group('benchmark')]
effectiveness-report:
    EFFECTIVENESS_RENDER_ONLY=1 crystal run scripts/effectiveness_snapshot.cr

# Measure request volume and wall-clock per scenario, gated against the snapshot.
[group('benchmark')]
perf-budget: build
    crystal run scripts/perf_budget.cr

# Accept the current cost numbers as the new baseline.
[group('benchmark')]
perf-budget-update: build
    PERF_UPDATE_BASELINE=1 crystal run scripts/perf_budget.cr

# Diff findings between a baseline binary and the working build.
[group('benchmark')]
ab-diff old: build
    AB_OLD_BIN={{old}} crystal run scripts/ab_diff.cr

# Serve the labelled mock-case corpus (Ctrl-C to stop).
[group('lab')]
lab-corpus:
    crystal run scripts/labs/corpus_server.cr

# Serve the request-counting lab.
[group('lab')]
lab-counting:
    crystal run scripts/labs/counting_server.cr

# Serve the adversarial-response lab.
[group('lab')]
lab-hostile:
    crystal run scripts/labs/hostile_server.cr

# Serve the benign false-positive corpus.
[group('lab')]
lab-replay:
    crystal run scripts/labs/replay_server.cr
