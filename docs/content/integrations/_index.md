+++
title = "Integrations"
description = "Drive Dalfox from your pipeline, your dashboard, or your AI assistant."
weight = 3
+++

Dalfox is great on the command line, but it also speaks REST and MCP, and ships a SKILL.md for skill-aware agents — so you can drive it from almost anywhere.

## Pick your integration

- **[REST API Server](./server/)** — Long-lived HTTP service. Submit scans, poll status, cancel jobs, integrate with Slack, dashboards, CI/CD, and custom tooling.
- **[MCP Server](./mcp/)** — A [Model Context Protocol](https://modelcontextprotocol.io) stdio server. Exposes Dalfox as a tool for Claude, Cursor, and any MCP-compatible client.
- **[Agent Skill](./skills/)** — A drop-in `SKILL.md` that teaches Claude Code, Cursor, OpenCode, Codex, and other skill-aware agents how to drive Dalfox safely. Install with `npx skills add hahwul/dalfox`.

All three share the exact same scanning engine as the CLI. Results are identical — only the plumbing differs.
