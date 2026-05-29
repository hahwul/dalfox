# AGENTS.md - AI Agent Instructions for Hwaro Site

This document provides instructions for AI agents working on this Hwaro-generated website.

## Project Overview

This is a static website built with [Hwaro](https://github.com/hahwul/hwaro), a fast and lightweight static site generator written in Crystal.

## Essential Commands

| Command | Description |
|---------|-------------|
| `hwaro build` | Build the site to `public/` directory |
| `hwaro serve` | Start development server with live reload |
| `hwaro new <path>` | Create new content from archetype |
| `hwaro deploy` | Deploy the site (requires configuration) |
| `hwaro build --drafts` | Include draft content |
| `hwaro serve -p 8080` | Serve on custom port (default: 3000) |
| `hwaro build --base-url "https://example.com"` | Set base URL for production |

## Directory Structure

```
.
├── config.toml          # Site configuration
├── content/             # Markdown content files
│   ├── _index.md        # Homepage content
│   └── blog/            # Blog section
│       ├── _index.md    # Section listing page
│       └── *.md         # Individual pages
├── templates/           # Jinja2 templates (Crinja)
│   ├── base.html        # Base layout (optional)
│   ├── page.html        # Page template
│   ├── section.html     # Section listing template
│   └── shortcodes/      # Shortcode templates
├── static/              # Static assets (copied as-is)
└── archetypes/          # Content templates for `hwaro new`
```

## Notes for AI Agents

1. **Front matter is TOML** (`+++`), not YAML (`---`).
2. **Rendered content** is `{{ content | safe }}`, not `{{ page.content }}`.
3. **Custom metadata** is `page.extra.field`, not `page.params.field`.
4. **Always preview** with `hwaro serve` before committing.
5. **Validate TOML syntax** in config.toml and front matter after edits.
6. **Use `{{ base_url }}` prefix** for URLs in templates.
7. **Escape user content** with `{{ value | escape }}` in templates.

## Full Reference

For detailed documentation on content, templates, configuration, and more:

- [Hwaro Documentation](https://hwaro.hahwul.com)
- [Configuration Guide](https://hwaro.hahwul.com/start/config/)
- [Full LLM Reference](https://hwaro.hahwul.com/llms-full.txt) — comprehensive reference optimized for AI agents

To generate the full embedded AGENTS.md locally, run:
```
hwaro tool agents-md --local --write
```

## Site-Specific Instructions

This site documents [Dalfox](https://github.com/hahwul/dalfox), a Rust XSS scanner. Updates to these docs land alongside code changes in the same repo, so the docs and the binary should never disagree about flags, defaults, or stage names.

### Source of truth for flags and defaults

- **CLI flags / default values**: `src/cmd/scan.rs` (look for `pub struct ScanArgs` and `DEFAULT_*` constants). When you add or change a flag in code, update `docs/content/reference/cli.md` *in the same commit*.
- **Agent skill surface**: `skills/dalfox/` (SKILL.md + `references/*.md`). The published agent skill must stay in sync with flag names, defaults, error codes, MCP tool schemas, and the invariants in the repo-root `AGENTS.md`. Treat it as a fourth interface alongside CLI / server / MCP.
- **Output formats**: `src/scanning/result.rs` and `src/cmd/scan.rs` (output routing). Keep `docs/content/guide/output.md` aligned.
- **Stage names**: see `src/lib.rs` doc-comment (authoritative 6-stage table) and `src/parameter_analysis/mining.rs` / `src/scanning/mod.rs` headers. Don't invent stage numbers — read what the code already labels.

### Stage model (current)

The canonical high-level contract is documented in `src/lib.rs` (6 stages, Stages 1–6). The runtime flow has one important nuance:

1. Discovery (Stage 1) — query / body / cookie / header / path / fragment / form / parameter-key probes. Bracketed sandwich marker.
2. Mining (Stage 2) — DOM-input names, dictionary wordlist, JSON body keys. Sentinel pre-probe + EWMA collapse for reflect-everything pages.
3. Active probing (Stage 3) — per-special-character probes; sets `valid_specials` / `invalid_specials`.
4. Payload generation (Stage 4) — inside `scanning::run_scanning`.
5. **Stage 0 fast probe** (inside Stage 4) — single bracketed-marker request that gates whether full payload reflection + DOM verification run for a parameter. Non-reflective params are short-circuited here.
6. Reflection check (Stage 5) — payload sent, body matched against payload + decoded variants.
7. DOM verification (Stage 6) — full DOM evidence: CSS marker, executable URL attribute, HTML structural sink, or JS-context AST.

When writing user-facing docs, refer to the 6-stage model from `src/lib.rs`. When explaining performance characteristics or "why some params cost almost nothing," surface the Stage 0 fast-probe gate that lives inside the scanning loop.

### Recently-shipped surfaces that often need doc updates

When working on docs, double-check that these are reflected:

- **Bracketed sandwich marker** — discovery/mining probes inject `OPEN+INNER+CLOSE`, response classified as Full / PrefixOnly / SuffixOnly / InnerOnly. See `src/scanning/markers.rs::classify_probe_reflection`.
- **Composable EncodingPipeline** — `src/encoding/pipeline.rs`. Supports `JsonField{pointer}`, `Base64`, `Base64Url`, `Url`, `JwtAssemble`. Inferred automatically from existing parameter values.
- **Nested sub-param naming** — bracket style (`qs[move_url]`, `qs[items][0]`). The `Param.wire_name` field carries the parent param when this kicks in.
- **Sentinel pre-probe** — `src/parameter_analysis/mining.rs::pre_collapse_query_probe`. Mining's first defence against reflect-everything pages.

### Verifying flags before you write about them

```bash
cargo run -- --help                    # global help
cargo run -- scan --help               # full scan flags
cargo run -- payload --help            # payload selectors
```

If `--help` and the docs disagree, the code wins; update the docs.

### Avoid

- Speculative documentation. If a feature doesn't exist in code yet, don't pre-announce it here.
- Duplicating code-block content from `cli.md` into the guides — link to the reference instead.
- Marketing copy in the guide pages. The landing page (`content/index.md`) carries the pitch; everything under `content/guide/` should be operational.
- Forgetting the agent skill bundle: changes to CLI surfaces, MCP tools, or core invariants must also land in `skills/dalfox/references/` (and the root `AGENTS.md`) in the same change.