+++
title = "Caido Workflows"
description = "Run Dalfox automatically from Caido Active Workflows and Findings to catch XSS in real time."
weight = 4
toc = true
aliases = ["/page/running/caido/"]
+++

Dalfox works great inside [Caido](https://caido.io) workflows. You can feed every interesting request (or selected traffic) straight into Dalfox's engine and turn findings into Caido Findings with one click.

This page covers the current recommended pattern (v3) and the common "bool gotcha" that trips up workflow authors.

## The Core Pattern

Caido Workflows can execute a shell step. The step receives the current request (usually as JSON) on stdin. Extract the raw HTTP, hand it to Dalfox via `--input-type raw-http`, then decide whether to create a Finding.

### Minimal Workflow Step (bash/zsh)

```bash
#!/bin/bash
set -euo pipefail

DALFOX="${DALFOX_PATH:-/usr/local/bin/dalfox}"

# Caido usually sends { "request": "<raw HTTP>", ... }
RAW=$(cat - | jq -r '.request // .raw // .data.request // empty')

if [[ -z "$RAW" ]]; then
    echo "No request payload" >&2
    exit 0
fi

# Write to temp file (robust for multiline + special chars)
TMP=$(mktemp)
printf '%s' "$RAW" > "$TMP"

# Run Dalfox (tune flags to taste)
"$DALFOX" scan --input-type raw-http "$TMP" \
    -S \
    --no-color \
    --poc-type curl \
    --timeout 8

FOUND=$?

rm -f "$TMP"

# Exit code 1 from Dalfox means "findings existed"
if [[ $FOUND -eq 1 ]]; then
    # Caido If/Else: route this to the "finding" branch
    echo "XSS detected"
else
    # Clean – emit a truthy value so Caido treats it as "no finding"
    echo "1"
fi
```

### The Caido Boolean Gotcha (Important)

Caido's Workflow If/Else node evaluates step output using its own [bool rules](https://docs.caido.io/app/reference/workflow_data_types.html#bool). Many strings that look "truthy" to a human (or a normal shell) become `false` inside Caido.

**The reliable community pattern** (shared by [@m4dni5 in this comment](https://github.com/hahwul/dalfox/discussions/992#discussion-10115370)):

- When you have a finding, emit the actual Dalfox output (or a non-empty marker). Caido will see it as the "False" branch.
- When clean, explicitly emit a simple truthy token such as `1` or `true`. This goes to the "True" branch.

Then wire:
- `False` → **Create Finding**
- `True` → (optional) Set Color / Tag / Continue

This is why the examples above deliberately echo a result only on the finding path.

## Recommended Flags for Caido

| Flag              | Why |
|-------------------|-----|
| `-S` / `--silence` | Only POC / finding lines go to stdout (less noise in Caido logs) |
| `--no-color`      | Clean text for findings, search, and exports (suggested in the community workflow example) |
| `--poc-type curl` (or `httpie`, `http-request`) | Ready-to-use repro in the Caido Finding |
| `--timeout 6-10`  | Per-request budget; keeps workflows snappy |
| `--waf-bypass auto` | Still worth it even inside a proxy |

You can also add `--report --report-format md` if you want the full markdown report captured in the Finding evidence.

**Note on silence:** `-S` suppresses most logs but the verified POC lines still appear when findings exist. (Community feedback in the linked discussion also requested that `-S` fully suppress POC output for even cleaner workflow results.) If you want zero output on clean runs, the pattern above (only emit on finding path) already achieves that.

## Full Example: If/Else + Create Finding

Typical Caido workflow graph:

1. **Trigger** (Manual / Proxy / Intercept / Scope filter)
2. **Shell / Execute** step running the script above → output stored in `$RESULT`
3. **If/Else**
   - Condition: previous step output is falsy / "False" path
   - **False branch (finding)**: Create Finding
     - Title: `XSS via Dalfox`
     - Request: original
     - Evidence / Description: `$RESULT` (or the PoC lines)
     - Severity: High / Medium depending on your rules
   - **True branch (clean)**: Set Color (green) or Add Tag `dalfox-clean`

You can enrich the Finding with more context from Caido (host, method, parameter names, etc.).

## Alternative: Using a File Step First

Some authors prefer two steps:

1. Write the raw request to a temp file (Caido has file-system nodes or you can do it in shell).
2. Run `dalfox scan --input-type raw-http /path/to/req.txt ...`

This is slightly more visible in the workflow graph but easier to debug.

## Tips & Gotchas

- **Binary location**: Caido's PATH may not include brew, asdf, or linuxbrew. Use a full path or set `DALFOX_PATH` env in the workflow / Caido settings and reference `$DALFOX_PATH`.
- **Performance**: On busy browsing, add a Content-Type or in-scope filter *before* the Dalfox step. Dalfox is fast but you don't need to scan every image/stylesheet.
- **Blind XSS**: Add `--blind https://your.collaborator/` when you want out-of-band detection from Caido-driven traffic.
- **DOM XSS**: Works out of the box (AST analysis runs on responses).
- **JSON output**: For more advanced post-processing in later workflow nodes you can use `--format jsonl` and parse the stream.

## Updating from v2 Guides

Older Dalfox v2 documentation used `dalfox pipe --rawdata`. In v3 the equivalent is `dalfox scan --input-type raw-http` (or the hidden `dalfox pipe` compatibility command with adjusted input handling). The temp-file or process-substitution approach shown above is the most portable.

See the [Scanning Modes](../guide/scanning-modes/#raw-http-mode) page for the canonical raw-http usage.

## See Also

- [Scanning Modes – Raw HTTP](../guide/scanning-modes/#raw-http-mode)
- [Output & Reports](../guide/output/)
- [WAF Bypass](../guide/waf-bypass/)
- GitHub Discussion [#992 (comment)](https://github.com/hahwul/dalfox/discussions/992#discussion-10115370) — original community report with the Caido If/Else boolean workaround script and `--no-color` suggestion
