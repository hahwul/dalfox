# Crystal harnesses

Test, benchmark, and release tooling that does not fit in `cargo test`: anything
that needs to drive the built binary end to end, stand up a hostile or labelled
HTTP lab, or compare a run against a committed baseline.

Crystal, stdlib only — no `shard.yml`, nothing to install beyond the compiler.
Every script is run from the repo root and every path inside one is
repo-root-relative:

```
crystal run scripts/<name>.cr        # or: just <recipe>
```

## Layout

```
scripts/
  lib/           shared helpers — the only place to add cross-harness code
  labs/          disposable HTTP servers the harnesses scan
  fixtures/      committed corpora (replay/*.html)
  *.cr           the harnesses themselves
```

### `lib/`

| module | what it gives you |
| --- | --- |
| `sh.cr` | `Sh.run` (captures both streams, SIGKILLs on `timeout:`, never raises), `Sh.parallel_map(_progress)`, `Sh.which`, `Sh.clock` |
| `dalfox.cr` | `Dalfox.scan` → `ScanResult` (`findings`, `verified`, `detected?`, `crashed?`, `meta`), `Dalfox.parse_report`, `Dalfox.diff` |
| `docker.cr` | `Docker::Lab` — health-polls a container and only tears down what it started |
| `snapshot.cr` | `Snapshot.write`/`stamp`, `Snapshot.compare` → `Delta#regressed?`, docs marker-block rendering |
| `report.cr` | `Report` — the pass/fail checklist every gate prints; finish with `exit report.finish` |
| `mock_cases.cr` | loads `tests/functional/mock_cases/**/*.toml` (Crystal has no stdlib TOML parser) |

Two traps are documented in the source and worth repeating here:

- **The JSON report is an envelope**, `{"meta": …, "findings": […]}`. Parsing it
  as a bare array yields zero findings *silently*, which makes any harness that
  counts findings vacuously green. `Dalfox.parse_report` handles the envelope, a
  bare array, a meta-only clean report, and JSONL.
- **`MockCases::Case#render` must not "fix" doubled braces.** `{{` is literal in
  that corpus, matching `xss_mock_server.rs#apply_reflection`. Cases carrying a
  `filter` or `page_template` are Rust-server behaviours and are not
  `self_contained?`; serving them unfiltered manufactures false positives.

### `labs/`

Standalone servers, each on its own port, each printing
`listening on http://127.0.0.1:<port>` and shutting down cleanly on SIGINT and
SIGTERM. Run one on its own with `just lab-<name>` to drive dalfox by hand.

| lab | port | serves |
| --- | --- | --- |
| `corpus_server.cr` | 4801 | the 809 self-contained labelled mock cases, with `/map/json` |
| `counting_server.cr` | 4802 | reflection endpoints plus `/stats` request counters |
| `hostile_server.cr` | 4803 | adversarial responses (huge, deep JS, gzip bomb, slowloris, lying framing) |
| `replay_server.cr` | 4804 | benign pages that must yield zero findings |

## Harnesses

Gates exit non-zero on failure and print a `Report` checklist.

| harness | `just` | asserts |
| --- | --- | --- |
| `surface_parity.cr` | `surface-parity` | CLI ↔ config ↔ REST ↔ MCP ↔ skills/docs describe the same options |
| `output_conformance.cr` | `output-conformance` | every `--format` parses; only the document reaches stdout; exit codes hold |
| `docs_lint.cr` | `docs-lint` | EN/KO pairing, front matter, links and anchors, CSP, generated markers (read-only) |
| `server_mcp_smoke.cr` | `server-mcp-smoke` | REST lifecycle, MCP JSON-RPC, and parity between the two |
| `hostile_scan.cr` | `hostile-scan` | dalfox terminates within budget, without crashing or exceeding a memory ceiling |
| `replay_corpus.cr` | `replay-corpus` | benign pages yield no findings (every finding is a false positive) |

Measurements write a JSON snapshot under `docs/data/` and fail when the new run
regresses against the committed one.

| harness | `just` | measures |
| --- | --- | --- |
| `effectiveness_snapshot.cr` | `effectiveness` | precision / recall / FP / FN against the labelled corpus |
| `perf_budget.cr` | `perf-budget` | requests and wall-clock per scenario |
| `ab_diff.cr` | `ab-diff <old-bin>` | findings gained and lost between two binaries |
| `xssmaze_score.cr` | `xssmaze-score` | detection rate against the XSSMaze lab (needs Docker) |

`just harness` runs every gate, continuing past failures.

## Adding one

1. Put shared behaviour in `lib/`, never a second copy in a harness.
2. Open with a comment block: what it does, the flow as numbered steps, and
   every env-var tunable with its default. Namespace the env vars.
3. Gates use `Report` and `exit report.finish`. Measurements use
   `Snapshot.write` + `Snapshot.compare`.
4. Own a port if you need a lab, and register it in the table above.
5. Keep a default run under a couple of minutes; put the expensive mode behind
   an env var.
6. Prove the check has teeth before trusting it green — break the thing it
   watches on purpose and confirm it goes red. A gate that cannot fail is worse
   than no gate, because it reads as coverage.
