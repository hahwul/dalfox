+++
title = "Agent Skill"
description = "Drop-in `SKILL.md` for Claude Code, Cursor, OpenCode, Codex, and other skill-aware agents."
weight = 3
+++

Dalfox ships a [**SKILL.md**](https://github.com/hahwul/dalfox/blob/main/skills/dalfox/SKILL.md) that teaches any skill-aware agent how to drive Dalfox correctly — authorization gate first, MCP over CLI, preflight before heavy scans, `V > A > R` finding prioritization. Point your agent at it and the model stops guessing flags.

## Install with `npx skills`

The easiest way is the [open agent-skills CLI](https://github.com/vercel-labs/skills):

```bash
# Install to the current project (committed, shared with the team)
npx skills add hahwul/dalfox

# Or install globally (~/<agent>/skills/, available everywhere)
npx skills add hahwul/dalfox -g
```

The CLI auto-detects which agents you use (Claude Code, Cursor, Codex, OpenCode, and [~45 others](https://github.com/vercel-labs/skills#available-agents)) and links the skill for each. Pick a specific agent if you only want one:

```bash
# Only Claude Code
npx skills add hahwul/dalfox -a claude-code

# Non-interactive (CI-friendly)
npx skills add hahwul/dalfox -g -a claude-code -y
```

To update later:

```bash
npx skills update dalfox
```

To remove:

```bash
npx skills remove dalfox
```

## Install manually

If you prefer not to run `npx`, clone the skill file into the location your agent expects. For Claude Code that's `~/.claude/skills/dalfox/SKILL.md`:

```bash
mkdir -p ~/.claude/skills/dalfox
curl -o ~/.claude/skills/dalfox/SKILL.md \
  https://raw.githubusercontent.com/hahwul/dalfox/main/skills/dalfox/SKILL.md
```

Other clients read from their own skills directory — see your agent's docs for the exact path.

## What the skill covers

- **Trigger conditions** — fires when the user asks to scan a URL for XSS, enumerate reflected parameters, or mentions "dalfox" explicitly. Skips non-XSS vulnerabilities.
- **Authorization gate** — the skill refuses to scan until the user confirms they're authorized to send payloads to the target.
- **Mode detection** — prefers MCP tools when available, falls back to the `dalfox` CLI, and tells the user how to install if neither is present.
- **MCP playbook** — `preflight_dalfox` → `scan_with_dalfox` → poll `get_results_dalfox` (honoring `suggested_poll_interval_ms`) → `delete_scan_dalfox` when done. Includes the validated input bounds (timeout 1–299 s, delay 0–9999 ms) so the agent doesn't send values Dalfox will reject.
- **CLI scenarios** — POST bodies, authenticated sessions, proxy-through-Burp, blind XSS with a callback URL, stored XSS, pipe input, fast smoke tests, maximum-coverage runs, and machine-readable output.
- **Result interpretation** — finding type legend (`V` verified DOM execution > `A` AST-detected > `R` reflected-only) so the agent leads with confirmed hits.
- **Failure modes** — what `reachable: false`, all-R findings, a stuck scan, or an `invalid_params` response actually mean, and how to recover.

## Prerequisite

The skill assumes the `dalfox` binary or [MCP server](./mcp/) is reachable from the agent's environment. Install Dalfox first ([installation guide](../../getting-started/installation/)), then install the skill.

## Authoring tips

The skill file lives at [`skills/dalfox/SKILL.md`](https://github.com/hahwul/dalfox/tree/main/skills/dalfox) in the repository. Contributions are welcome — keep it focused on *how an agent should drive Dalfox*, not on restating CLI reference material that already lives in the [CLI reference](../../reference/cli/).
