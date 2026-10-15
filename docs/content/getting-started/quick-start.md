+++
title = "Quick Start"
description = "Run your first Dalfox XSS scan in five minutes, then try files, pipelines, JSON output, authentication, and blind XSS."
weight = 3
toc = true
+++

This page walks you from install to a verified finding. We'll use an intentionally vulnerable demo target so you can see real output.

{{ alert(type="warning", body="Only scan targets you're authorized to test. Dalfox fires real XSS payloads.") }}

## 1. Scan a single URL

```bash
dalfox 'https://xss-game.appspot.com/level1/frame?query=test'
```

The first argument is the target. Dalfox auto-detects that it's a URL and runs the `scan` subcommand implicitly. Quote any URL that contains `?` or `&`: the shell treats them as special characters, and zsh aborts an unquoted `?` with `no matches found`. You'll see:

- A banner with the version.
- `INF` lines as Dalfox discovers parameters and probes contexts.
- A `WRN XSS found N XSS` summary, then a `[POC][V]…` (vulnerable) or `[POC][R]…` (reflected) line for each finding. Under it come the issue, the exact payload that worked, and the response line it landed in.
- A closing `INF scan completed in … seconds`.

The bare form accepts only the global flags (`--config`, `--debug`, `--no-color`, `-S`). Any other scan flag needs `dalfox scan <target> …`, the form the rest of this page uses.

## 2. Scan from a file

Feed a list of URLs from your crawler:

```bash
# urls.txt, one target per line
dalfox scan urls.txt
```

Each URL runs through the same pipeline. Findings are printed after the end-of-scan `WRN XSS found N XSS` summary; add `--stream-findings` to print each one the moment it is verified.

## 3. Scan from a pipeline

Dalfox reads from `stdin` when you pipe:

```bash
cat urls.txt | dalfox
# or combined with your recon tools:
waybackurls example.com | gf xss | dalfox
```

## 4. Get JSON output

Pair Dalfox with `jq`, a dashboard, or CI:

```bash
dalfox scan 'https://target.app/search?q=test' -f json -o report.json
```

Every format except `plain` (so `json`, `jsonl`, `markdown`, `sarif`, `toml`) suppresses the banner, so the file stays clean.

The exit code is CI-friendly too: `0` means no findings, `1` means findings, and `2` means an error or a result you can't trust (every target unreachable, too many lost requests, an expired login). See [Exit codes](../../guide/output/#exit-codes).

## 5. Authenticated scans

Pass cookies, headers, or a custom method:

```bash
dalfox scan https://api.target.app/v1/users \
  -X POST \
  -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{"name":"test"}' \
  --cookies "session=abc123"
```

Or point Dalfox at a raw HTTP request file you saved from your proxy:

```bash
dalfox scan --input-type raw-http request.txt
```

Or replay a whole HAR export from browser DevTools or a proxy. Dalfox scans every request in it and keeps each one's method, headers, cookies, and body:

```bash
dalfox scan capture.har            # auto-detected
dalfox scan --input-type har capture.har
```

## 6. Catch Blind XSS

Use an out-of-band callback (Interactsh, Burp Collaborator, XSS Hunter, etc.):

```bash
dalfox scan https://target.app \
  -b https://your-callback.interact.sh
```

Blind payloads go into the parameters the request already carries (query, a form-encoded `-d` body, `-H` headers, cookies) and into the same-origin POST forms on the page. Parameters found later by discovery or mining get none. If a payload fires later in an admin panel, your callback server records it.

Or let Dalfox run the [interactsh](https://github.com/projectdiscovery/interactsh) (OAST) side for you. It registers a session, polls for callbacks, and matches each callback to the payload that sent it:

```bash
dalfox scan https://target.app --blind-oob             # public interactsh mesh
dalfox scan https://target.app --blind-oob=oast.fun    # pick servers
```

A callback that arrives becomes a `V` finding with `detection_method: oob`. Use `--blind-oob-secret` for a self-hosted server and `--blind-oob-wait` to control how long Dalfox keeps polling after the scan finishes. See [Blind XSS](../../guide/scanning-modes/#blind-xss) for the details.

On the OAST channel, `--insecure` (on by default) only reaches a server you named with `--blind-oob=`, such as a self-hosted one behind a self-signed certificate. The public interactsh servers are always TLS-verified.

## 7. Dry-run first

Use `--dry-run` to preview what Dalfox would scan:

```bash
dalfox scan https://target.app --dry-run
```

It discovers parameters and estimates request volume without firing any payloads.

## Reading the output

Each finding is tagged:

| Tag | Meaning |
|-----|---------|
| `[V]` | **Vulnerable**: Dalfox claims the input is exploitable. The payload reached an executable position in the parsed response (for example a DOM element carrying Dalfox's marker), or an out-of-band callback fired |
| `[A]` | **AST-detected**: static JS analysis found a source→sink flow |
| `[R]` | **Reflected**: payload appeared in the response, but no DOM evidence |
| `[I]` | **Informational**: not an XSS claim, e.g. a known-vulnerable JS library from the opt-in `--detect-outdated-libs` |

`V` and `A` findings are actionable. `R` findings are worth a look but may be filtered further downstream.

`[V]` does not mean the payload ran in a browser. Dalfox does not drive a browser, by design. A purely client-side DOM XSS is reported as `[A]`, so confirm it in a browser. Each finding also carries `detection_method` (how it was found) and `confidence` (how strongly the evidence supports the claim). See [Detection Model](../../guide/detection-model/).

## Next steps

- Learn the different [scanning modes](../../guide/scanning-modes/).
- Understand how [parameters are discovered](../../guide/parameters/).
- Tune [payloads and encoders](../../guide/payloads/) for harder targets.
- Save your favorite flags in a [config file](../configuration/).
