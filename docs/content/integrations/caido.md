+++
title = "Caido Workflows"
description = "Run Dalfox automatically from Caido Active Workflows and Findings to catch XSS in real time."
weight = 4
toc = true
aliases = ["/page/running/caido/"]
+++

Dalfox works well inside [Caido](https://caido.io) workflows. You can feed every interesting request (or selected traffic) straight into Dalfox's engine and turn findings into Caido Findings with one click.

This page covers the current recommended pattern (v3) and the common "bool gotcha" that trips up workflow authors.

## The core pattern

Caido Workflows can execute a shell step. The step receives the current request (usually as JSON) on stdin. Extract the raw HTTP, hand it to Dalfox via `--input-type raw-http`, then decide whether to create a Finding.

### Minimal workflow step (bash/zsh)

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

# raw-http reads a regular file (not stdin or a process substitution),
# so write the request to a temp file first.
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
printf '%s' "$RAW" > "$TMP"

# Run Dalfox (tune flags to taste) and capture its stdout.
# Dalfox exits 1 when it has findings, so capture the status with `|| FOUND=$?`
# instead of letting `set -e` abort the script on the case we care about.
FOUND=0
OUT=$("$DALFOX" scan --input-type raw-http "$TMP" \
    -S \
    --no-color \
    --poc-type curl \
    --timeout 8) || FOUND=$?

# Exit codes: 0 = clean, 1 = findings, 2 = error (bad input, unreachable
# target, or too many requests lost for the scan to count as clean)
if [[ $FOUND -eq 1 ]]; then
    # Caido If/Else: the PoC lines are not a truthy string -> "False" branch
    printf '%s\n' "$OUT"
else
    # An error is not a clean result; leave a trace in the workflow log
    if [[ $FOUND -ne 0 ]]; then echo "dalfox failed (exit $FOUND)" >&2; fi
    # Emit exactly one truthy token so Caido treats it as "no finding"
    echo "1"
fi
```

### The Caido boolean gotcha (important)

Caido's Workflow If/Else node evaluates step output using its own [bool rules](https://docs.caido.io/app/reference/workflow_data_types.html#bool). Many strings that look "truthy" to a human (or a normal shell) become `false` inside Caido.

**The reliable community pattern** (shared by [@m4dni5 in this comment](https://github.com/hahwul/dalfox/discussions/992#discussion-10115370)):

- When you have a finding, emit the actual Dalfox output (or a non-empty marker). Caido will see it as the "False" branch.
- When clean, explicitly emit a simple truthy token such as `1` or `true`. This goes to the "True" branch.

Then wire:
- `False` → **Create Finding**
- `True` → (optional) Set Color / Tag / Continue

This is why the script above captures Dalfox's stdout and prints it only on the
finding path: on the clean path the step's whole output is the single token `1`.

## Recommended flags for Caido

| Flag              | Why |
|-------------------|-----|
| `-S` / `--silence` | Only POC / finding lines go to stdout (less noise in Caido logs) |
| `--no-color`      | Clean text for findings, search, and exports (suggested in the community workflow example) |
| `--poc-type curl` (or `httpie`, `http-request`) | Ready-to-use repro in the Caido Finding |
| `--timeout 6-10`  | Per-request budget; keeps workflows snappy |
| `--waf-bypass auto` | The default already; don't turn it `off` just because traffic comes through a proxy |

You can also add `-f markdown` if you want the full markdown report captured in the Finding evidence.

**Note on silence:** `-S` suppresses the logs, but the PoC lines still go to
stdout when there are findings, and a clean run still prints one empty line.
That empty line is enough to turn a bare `1` into something Caido no longer
reads as `true`, which is why the script captures Dalfox's output instead of
letting it stream into the step result.

## Full example: If/Else + Create Finding

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

## Alternative: using a file step first

Some authors prefer two steps:

1. Write the raw request to a temp file (Caido has file-system nodes or you can do it in shell).
2. Run `dalfox scan --input-type raw-http /path/to/req.txt ...`

This adds a step to the workflow graph but is easier to debug.

## Tips & gotchas

- **Binary location**: Caido's PATH may not include brew, asdf, or linuxbrew. Use a full path or set `DALFOX_PATH` env in the workflow / Caido settings and reference `$DALFOX_PATH`.
- **Performance**: On busy browsing, add a Content-Type or in-scope filter *before* the Dalfox step. Dalfox is fast but you don't need to scan every image/stylesheet.
- **Blind XSS**: Add `--blind https://your.collaborator/` when you want out-of-band detection from Caido-driven traffic.
- **DOM XSS**: Works out of the box (AST analysis runs on responses).
- **JSON output**: For more advanced post-processing in later workflow nodes you can use `--format jsonl` and parse the stream.

## Updating from v2 guides

Older Dalfox v2 documentation used `dalfox pipe --rawdata`. In v3 the equivalent is `dalfox scan --input-type raw-http <file>`. It takes a regular file path: a raw request on stdin (`dalfox pipe -i raw-http`) finds no targets, and a process substitution (`<(...)`) is refused as "not a regular file". That is why the script above writes a temp file.

See the [Scanning Modes](../../guide/scanning-modes/#raw-http-mode) page for the canonical raw-http usage.

## See also

- [Scanning Modes: Raw HTTP](../../guide/scanning-modes/#raw-http-mode)
- [Output & Reports](../../guide/output/)
- [WAF Bypass](../../guide/waf-bypass/)
- GitHub Discussion [#992 (comment)](https://github.com/hahwul/dalfox/discussions/992#discussion-10115370): original community report with the Caido If/Else boolean workaround script and `--no-color` suggestion
