# Copilot Instructions for Dalfox (v3/Rust)
Updated guidance for the current Rust v3 codebase of Dalfox, a fast, concurrent XSS scanner and utility.

This document helps GitHub Copilot understand the actual project shape, conventions, and how to extend features safely.

## Project Overview

Dalfox is an open-source XSS scanner focused on automation, parameter analysis, and flexible payload generation.

Key capabilities:
- Multiple scanning inputs: auto, url, file, pipe (raw-http is stubbed)
- Parameter discovery: query, header, cookie, and path-segment reflections
- Parameter mining: dictionary, body probing, response-id heuristics, remote wordlists
- XSS scanning: reflection/DOM verification, context-aware payload generation
- Blind XSS callback workflows and Stored XSS (sxss)
- JSON, JSONL, and enhanced plain POC output with optional request/response inclusion
- Concurrency with host grouping and global concurrency limits
- Server/API mode for remote orchestration + MCP (Model Context Protocol) stdio server

## Technology Stack

- Language: Rust (edition 2024)
- Async runtime: tokio (full features)
- HTTP client: reqwest 0.11
- Web server: axum 0.7
- CLI: clap 4 (derive, env)
- HTML parsing: scraper
- Serialization: serde / serde_json
- URL handling: url + urlencoding
- Regex: regex
- TTY detection: atty
- MCP: rmcp 0.8
- JSON schema (server/MCP tooling): schemars
- Misc: indicatif, base64, chrono, toml, sha2, hex

Crate versions (Cargo.toml):
- clap = 4.0 (features: derive, env)
- tokio = 1 (features: full)
- reqwest = 0.11
- scraper = 0.18
- serde = 1.0 (features: derive)
- serde_json = 1.0
- url = 2.0
- urlencoding = 2.1
- indicatif = 0.17
- base64 = 0.21
- chrono = 0.4
- toml = 0.8
- axum = 0.7
- regex = 1
- atty = 0.2
- rmcp = 0.8.0 (features: server, macros)
- schemars = 0.8 (features: derive)
- sha2 = 0.10
- hex = 0.4

## Project Structure (current)

src/
- main.rs                          Entry point + CLI
- config.rs                        Config loading, defaults, and apply helpers
- utils/                           Common helpers (banner, http builders, scan_id, remote init)
  - mod.rs
  - banner.rs
  - http.rs
  - scan_id.rs
- encoding/
  - mod.rs                         Encoders: url, 2url, html-entity (hex), base64
- cmd/
  - mod.rs
  - scan.rs                        Scan orchestration (inputs, analysis, scanning, output)
  - url.rs                         Legacy/specific URL mode (hidden subcommand)
  - file.rs                        Legacy file mode (hidden subcommand)
  - pipe.rs                        Legacy pipe mode (hidden subcommand)
  - server.rs                      Server/API mode (Axum-based JSON/JSONP + CORS, API key)
  - payload.rs                     Payload management (list/generate)
- parameter_analysis/
  - mod.rs                         Core param types, filtering, active probing, orchestrator
  - discovery.rs                   Reflection discovery: query, header, cookie, path segments
  - mining.rs                      Mining: dictionary, body, heuristic response-id probing
- payload/
  - mod.rs
  - remote.rs                      Remote payload/wordlist registry and fetchers
  - xss_javascript.rs              Canonical JS execution primitives
  - xss_html.rs                    Dynamic HTML payloads derived from JS primitives
  - xss_event.rs                   Dynamic attribute payloads (onerror/onload) from JS primitives
  - xss_blind.rs                   Blind XSS templates
  - mining.rs                      Payload mining helpers (if any)
- scanning/
  - mod.rs                         Scanning driver, request builder, payload selection
  - url_inject.rs                  URL builder helpers for injection
  - xss_common.rs                  Context-aware payload generation + encoder expansion
  - xss_blind.rs                   Blind XSS dispatcher using callback URL
  - check_reflection.rs            Reflection detector with response capture
  - check_dom_verification.rs      DOM verification via presence of .dalfox elements
  - result.rs                      Result model (JSON-compatible shape)
- target_parser/
  - mod.rs                         URL parsing, default target settings
- mcp/
  - mod.rs                         MCP stdio server exposing scan tools

## Commands and CLI

Top-level subcommands:
- scan        Scan targets for XSS
- server      Run Axum API/server mode (CORS/JSONP/API key supported)
- payload     Manage or enumerate payloads
- mcp         Run MCP stdio server exposing Dalfox tools
- url,file,pipe are present as hidden subcommands for compatibility

When no subcommand is given, the CLI defaults to scan with positional targets.

Scan flags (as of src/cmd/scan.rs):
- INPUT
  - -i, --input-type: auto | url | file | pipe | raw-http (raw-http is not implemented yet)
- OUTPUT
  - -f, --format: plain | json | jsonl (default: plain)
  - -o, --output: file path to write results
  - --include-request: include HTTP request in JSON/plain details
  - --include-response: include HTTP response in JSON/plain details
  - -S, --silence: suppress logs except POC output
  - --poc-type: plain | curl | httpie | http-request (default: plain)
  - --limit: cap number of results
- TARGETS
  - -p, --param: param filters; support type qualifiers (e.g., id:query, token:header)
  - -d, --data: body data
  - -H, --headers: header lines "Key: Value"
  - --cookies: cookie assignments "k=v"
  - -X, --method: override HTTP method (default: GET)
  - --user-agent: custom UA
  - --cookie-from-raw: load cookies from raw HTTP file (parses "Cookie: ..." line)
- PARAMETER DISCOVERY
  - --skip-discovery
  - --skip-reflection-header
  - --skip-reflection-cookie
- PARAMETER MINING
  - -W, --mining-dict-word: wordlist file for dictionary probing
  - --remote-wordlists: comma-separated providers; options: burp, assetnote
  - --skip-mining
  - --skip-mining-dict
  - --skip-mining-dom
- NETWORK
  - --timeout: seconds (default: 10)
  - --delay: ms between requests (default: 0)
  - --proxy: proxy URL
  - -F, --follow-redirects
- ENGINE
  - --workers: async concurrency for analysis (default: 50)
  - --max-concurrent-targets: global target concurrency (default: 50)
  - --max-targets-per-host: per-host cap (default: 100)
- XSS SCANNING
  - -e, --encoders: comma-separated; options: none, url, 2url, html, base64
    - Note: if list contains "none", only original payloads are used (no encoder variants).
  - --remote-payloads: comma-separated providers; options: portswigger, payloadbox
  - --custom-blind-xss-payload: file with blind payload templates
  - -b, --blind: blind XSS callback URL (enables blind scanning pass)
  - --custom-payload: file with additional payloads
  - --only-custom-payload: only test custom payloads
  - --skip-xss-scanning: perform discovery/mining but skip XSS checks
  - --deep-scan: do not skip on preflight Content-Type denylist; test all payloads
  - --sxss: enable Stored XSS workflow
  - --sxss-url: URL to check for stored reflection (required with --sxss)
  - --sxss-method: method for stored check (default: GET)
- TARGETS (positional)
  - URLs or file paths depending on input-type

Behavioral notes:
- Input auto: each target is interpreted as URL, or file path containing URLs when readable. If STDIN is piped and no targets are passed, treat input as lines (pipe mode).
- Preflight: a fast HEAD request (with Range) reads Content-Type to skip denylisted types (e.g., application/json, text/plain, images) unless --deep-scan is set. Also detects CSP from response headers or <meta http-equiv="Content-Security-Policy">, and surfaces it in plain logs for single-target scans.
- Grouping: targets grouped by host; capped by --max-targets-per-host; global concurrent scanning gated by --max-concurrent-targets.
- Remote resources: when --remote-payloads/--remote-wordlists are provided, remote lists are fetched once per run (honoring --timeout and --proxy) and cached in-process.
- Blind XSS: when --blind is supplied, a blind scanning pass injects a template payload across all param types; responses are not analyzed (out-of-band validation assumed).
- Stored XSS (sxss): inject on the target, then check sxss-url with sxss-method to detect reflection/DOM markers.

## Server/API Mode (Axum)

- Command: dalfox server
- Endpoints:
  - POST /scan: body { url: string, options?: ScanOptions } -> { code, msg: scan_id }
  - GET  /scan?url=...&... -> same behavior as POST but query-driven (JSONP-friendly)
  - GET  /result/:id        -> { code, msg, data: { status, results? } }
  - GET  /scan/:id          -> alias to /result/:id
  - OPTIONS handlers for CORS preflight
- Auth: optional API key via X-API-KEY header (or DALFOX_API_KEY env)
- CORS: configurable allowed origins (exact, wildcard, regex), allow-methods/headers
- JSONP: optional; wraps JSON as callback(payload)
- Logging: plain stdout with optional log file (no ANSI)
- ScanOptions (subset of ScanArgs):
  - cookie, worker, delay, blind, header[], method, data, user_agent, encoders[],
    remote_payloads[], remote_wordlists[], include_request, include_response

## MCP Integration (Model Context Protocol)

- Command: dalfox mcp
- Exposes two tools over stdio via rmcp:
  - scan_with_dalfox(target, include_request?, include_response?, …args) -> { scan_id, status: queued }
    - Optional additional args: param[], data, headers[], cookies[], cookie_from_raw, method,
      user_agent, encoders (string or array), timeout, delay, follow_redirects, proxy
  - get_results_dalfox(scan_id) -> { scan_id, status: queued|running|done|error, results?: [...] }
- Jobs are in-memory only; non-blocking (tokio runtime per spawned thread)

## Configuration

- Command-line flag --config allows explicit config path. If missing, Dalfox searches $XDG_CONFIG_HOME/dalfox/config.* or $HOME/.config/dalfox/config.* and initializes defaults when absent.
- Supported formats: TOML, JSON (auto-detected). Default templates are generated on first use.
- Config is applied via apply_to_scan_args_if_default, which only fills defaults when CLI hasn’t provided explicit values. See src/config.rs for all fields mirrored from ScanArgs.
- Config fields include debug, remote_payloads, remote_wordlists, and all scan flags.

## Parameter Analysis

- Discovery (src/parameter_analysis/discovery.rs):
  - Query: replace parameter value with marker and detect reflection
  - Header: mutate single header at a time for reflection
  - Cookie: mutate single cookie at a time; sent via Cookie header
  - Path: replace each path segment with marker and check reflection
- Mining (src/parameter_analysis/mining.rs):
  - Dictionary probing of common parameter names (-W)
  - Body parameter probing
  - Heuristic response-id probing
  - Adaptive collapse via EWMA to stop unproductive probes
- Active probing (src/parameter_analysis/mod.rs: active_probe_param):
  - Sends per-character probes around “dalfox{c}dlafox”
  - Classifies valid_specials/invalid_specials
  - Falls back to encoded variants using user-selected encoders (url, html, 2url, base64)

Each discovered Param records:
- location: query, body, json, header, path
- injection_context: Html | Javascript | Attribute and optional delimiter hints (single/double quote, comment)
- valid_specials / invalid_specials: which special characters reflect cleanly

Filtering:
- -p supports name and type filters (e.g., -p id:query, -p auth:header). See filter_params in parameter_analysis/mod.rs.

## Payload System

- Canonical JS payloads: src/payload/xss_javascript.rs (add here to expand the universe)
- Dynamic HTML payloads: xss_html.rs renders templates with JS payloads; includes class/id variants and obfuscated tag variants
- Dynamic attribute payloads: xss_event.rs renders common event handlers (onerror/onload) with JS payloads
- Encoders (src/encoding/mod.rs): url, 2url, html-entity (hex), base64
  - scan.rs uses a global encoder set (GLOBAL_ENCODERS) to influence PoC generation for path-segment injections
- Blind payload templates: xss_blind.rs (string templates using "{}" for callback URLs)
- Remote payloads/wordlists: src/payload/remote.rs
  - Providers: payloads (payloadbox, portswigger), wordlists (burp, assetnote)
  - Fetchers: init_remote_payloads_with/init_remote_wordlists_with (honor --timeout/--proxy)
  - Provider registration: register_payload_provider, register_wordlist_provider

Context-aware payload generation (scanning/xss_common.rs):
- The scanning engine chooses payloads per InjectionContext with delimiter hints (Attribute, Javascript, Html, with optional SingleQuote, DoubleQuote, Comment).
- Encoders are applied in scanning/xss_common.rs to produce variants unless encoders include "none".
- Remote payloads and custom payload files are appended then de-duplicated.

## Scanning Engine

- Reflection (scanning/check_reflection.rs): inject per discovered param and check if payload appears in response; supports sxss check on post-injection page
- DOM verification (scanning/check_dom_verification.rs): inject and parse HTML for presence of .dalfox element(s); supports sxss check URL
- Orchestrator (scanning/mod.rs): builds request text (for optional inclusion), iterates params and payloads, and pushes results to shared vector
- Blind scanning (scanning/xss_blind.rs): dispatches callback-based payloads across all known locations
- POC generation (cmd/scan.rs: generate_poc): supports plain|curl|httpie|http-request; for path injections, applies user-selected path encoders

Result model (scanning/result.rs):
- Fields: type, inject_type, method, data, param, payload, evidence, cwe, severity, message_id, message_str
- Optional: request, response (controlled by flags)
- JSON and JSONL outputs omit null request/response; plain output prints colorized POC lines and detail sections (Issue, Payload, L#, Request, Response)

## Development Workflow

Build
- Development: cargo build
- Release: cargo build --release
- justfile exists; common aliases are available (e.g., just dev, just build, just test)

Test
- Run all: cargo test
- With output: cargo test -- --nocapture
- Specific: cargo test test_name

Quality
- Format: cargo fmt
- Check: cargo fmt --check
- Lint: cargo clippy -- --deny warnings
- Auto-fix: cargo clippy --fix --allow-dirty

## Code Conventions

Rust style
- Standard naming (snake_case for functions/variables, PascalCase for types)
- Use cargo fmt
- Resolve all clippy warnings
- Use Result<T, E> with ? for propagation over panics

Async
- All I/O is async under tokio
- Spawn concurrent tasks with tokio::spawn
- Use Arc<Mutex<_>> / Arc<RwLock<_>> for shared state

Error handling
- Prefer descriptive errors; Box<dyn std::error::Error> or custom errors where helpful
- Keep user-facing messages clear in CLI paths

Concurrency and performance
- Minimize clones; prefer borrowing
- Use Arc for shared immutable collections
- Rate-limit concurrently via semaphores; honor workers, max-concurrent-targets, and per-host caps
- Preflight skip avoids non-HTML-ish content unless deep-scan is enabled

Output format
- JSON/JSONL: machine-readable; include request/response only when flags are set
- Plain: colorized POC lines and a detail tree per finding; includes optional request/response blocks

## Adding or Modifying Features

Add a new JavaScript payload
- Edit src/payload/xss_javascript.rs (append to XSS_JAVASCRIPT_PAYLOADS)
- HTML and attribute payloads auto-derive expanded variants
- Add/adjust tests under scanning/xss_common.rs or payload modules

Add a new encoder
- Implement in src/encoding/mod.rs
- Update encoder handling in scanning/xss_common.rs (for scanning variants)
- Consider PoC path-encoder in cmd/scan.rs (GLOBAL_ENCODERS handling)
- Update CLI help and documentation of -e, --encoders

Enhance discovery/mining
- Discovery: src/parameter_analysis/discovery.rs
- Mining: src/parameter_analysis/mining.rs
- Wire into analyze_parameters in parameter_analysis/mod.rs
- Add tests for each new probing routine; mock reqwest as needed

Add or customize remote providers
- Register new providers via payload::register_payload_provider / register_wordlist_provider
- Ensure network fetch options (timeout/proxy) are honored
- Keep outputs sanitized, deduplicated, and sorted

Add a new command
- Create src/cmd/new_command.rs
- Define Args struct with clap derives
- Implement run function
- Add to Commands enum in src/main.rs and match in main()

Update config fields
- Mirror new ScanArgs fields into config.rs ScanConfig
- Ensure default TOML/JSON templates updated
- Implement apply_to_scan_args_if_default mapping

## Testing Guidelines

Unit tests live alongside modules using #[cfg(test)] with a tests module.
- Ensure coverage on:
  - encoding (url/html/2url/base64 correctness)
  - parameter discovery/mining behavior
  - xss_common payload generation per injection context
  - preflight content-type/CSP filtering logic
  - result serialization/deserialization
  - server API behaviors (CORS/JSONP/auth), MCP flows when practical
- CI policy: cargo fmt, cargo clippy -- --deny warnings, cargo test pass before merging

## CLI Examples

- Basic scan
  - dalfox scan https://example.com
- File mode
  - dalfox -i file urls.txt
- Include request/response in JSON
  - dalfox scan https://example.com -f json --include-request --include-response
- Blind XSS
  - dalfox scan https://example.com -b https://collab.example/x/callback
- Stored XSS flow
  - dalfox scan https://example.com --sxss --sxss-url https://example.com/profile --sxss-method GET
- Remote payloads/wordlists
  - dalfox scan https://example.com --remote-payloads portswigger,payloadbox --remote-wordlists burp,assetnote
- Custom payloads only (no encoders)
  - dalfox scan https://example.com --custom-payload p.txt --only-custom-payload -e none
- Skip discovery, deep scan
  - dalfox scan https://example.com --skip-discovery --deep-scan
- Server mode
  - dalfox server --host 0.0.0.0 --port 6664 --api-key secret --allowed-origins "regex:^https?://localhost(:\\d+)?$"
- MCP stdio
  - dalfox mcp

## Tooling Notes for Copilot

When generating code:
- Respect existing module boundaries (encoding, parameter_analysis, payload, scanning, cmd, config, utils, mcp)
- Prefer adding new encoders/payloads/providers in their dedicated modules; avoid duplicating logic in scan.rs
- For concurrency, use semaphores and spawned tasks; don’t block the runtime
- Preserve CLI help strings and defaults; align new fields across ScanArgs and ScanConfig
- Avoid introducing panics in the CLI and scanning paths; propagate errors where reasonable
- For server: keep handlers slim, return explicit status codes, and honor CORS/JSONP settings
- For MCP: keep tools minimal in schema and return JSON strings

When drafting tests:
- Co-locate tests with modules
- Mock HTTP calls for deterministic behavior
- Favor small, descriptive test functions prefixed with test_

## Migration Notes (v2 Go → v3 Rust)

- goroutines → tokio tasks
- interfaces → traits
- error handling → Result/Option
- defer → Drop/RAII
- Channel and concurrency patterns use tokio primitives; prefer explicit limits with semaphores
- Payload system is more dynamic; HTML/attribute payloads derive from canonical JS payloads

## Known Gaps / TODOs

- raw-http input-type is stubbed (prints not implemented)
- Blind XSS scanning is fire-and-forget; verification is up to external callback monitoring

Keeping these in mind will help generate consistent and maintainable contributions aligned with the current codebase.