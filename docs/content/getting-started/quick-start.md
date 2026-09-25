+++
title = "Quick Start"
description = "Your first Dalfox scan in five minutes."
weight = 3
toc = true
+++

This page walks you from install to a verified finding. We'll use an intentionally vulnerable demo target so you can see real output.

{{ alert(type="warning", body="Only scan targets you're authorized to test. Dalfox fires real XSS payloads.") }}

## 1. Scan a single URL

```bash
dalfox https://xss-game.appspot.com/level1/frame?query=test
```

The first argument is the target. Dalfox auto-detects that it's a URL and runs the `scan` subcommand implicitly. You'll see:

- A banner with the version.
- `INF` lines as Dalfox discovers parameters and probes contexts.
- A `WRN XSS found N XSS` summary, then a `[POC][V]…` (vulnerable) or `[POC][R]…` (reflected) line for each finding. Under it come the issue, the exact payload that worked, and the response line it landed in.
- A closing `INF scan completed in … seconds`.

The bare form only takes a target plus the global flags (`--config`, `--debug`, `--no-color`, `-S`). Every other scan flag needs the explicit subcommand — `dalfox scan <target> …` — which is the form the rest of this page uses.

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
dalfox scan https://target.app/search?q=test -f json -o report.json
```

Machine-readable formats (`json`, `jsonl`, `sarif`, `toml`) auto-suppress the banner so the file stays clean.

The exit code is CI-friendly too: `0` means the scan finished with no findings, `1` means it found something, and `2` means there is no result to trust: an input, configuration, or runtime error, every target unreachable, or a no-finding run that lost too many requests to count as clean (Dalfox prints a `WRN INCOMPLETE` line when that happens).

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

Or point Dalfox at a **raw HTTP request** file you captured from your proxy:

```bash
dalfox scan --input-type raw-http request.txt
```

Or replay an entire **HAR** export (from browser DevTools or a proxy) — Dalfox scans every request in it, preserving each one's method, headers, cookies, and body:

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

Blind payloads go out before parameter discovery runs, so they reach only what the request already carries: its query parameters, a form-encoded `-d` body, the `-H` headers and the cookies. Dalfox also fetches the target page and submits the payload into the text fields of each same-origin POST form on it. Parameters found later by discovery or mining get no blind payloads. If a payload fires later in an admin panel, your callback server records it.

Or let Dalfox manage an [interactsh](https://github.com/projectdiscovery/interactsh) (OAST) server for you — it registers a session, correlates callbacks to the originating payload, and polls automatically:

```bash
dalfox scan https://target.app --blind-oob             # public interactsh mesh
dalfox scan https://target.app --blind-oob=oast.fun    # pick servers
```

Use `--blind-oob-secret` for a self-hosted server and `--blind-oob-wait` to control how long Dalfox keeps polling after the scan finishes.

`--insecure` (on by default) does **not** reach the public mesh. It is a statement about the scan target, which you do not control; the OAST server is infrastructure Dalfox picked, and that channel carries your `--blind-oob-secret` and the session key that reads your callbacks. The public servers present valid certificates, so they are always verified. `--insecure` still applies to a server you named yourself with `--blind-oob=`, which is the case it exists for — a self-hosted interactsh behind a self-signed or hostname-mismatched certificate.

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
| `[V]` | **Vulnerable**: Dalfox asserts the input is exploitable — the payload reached an executable position in the parsed response (for example a DOM element carrying Dalfox's marker), or an out-of-band callback fired |
| `[A]` | **AST-detected**: static JS analysis found a source→sink flow |
| `[R]` | **Reflected**: payload appeared in the response, but no DOM evidence |
| `[I]` | **Informational**: not an XSS claim, e.g. a known-vulnerable JS library from the opt-in `--detect-outdated-libs` |

`V` and `A` findings are actionable. `R` findings are worth a look but may be filtered further downstream.

`[V]` is not browser execution. Dalfox drives no browser, by design. A pure client-side DOM-XSS reports as `[A]` today and is worth confirming in a browser. Each finding also carries `detection_method` (how it was found) and `confidence` (whether Dalfox can claim a vulnerability) — see [Detection Model](../../guide/detection-model/).

## Next steps

- Learn the different [scanning modes](../../guide/scanning-modes/).
- Understand how [parameters are discovered](../../guide/parameters/).
- Tune [payloads and encoders](../../guide/payloads/) for harder targets.
- Save your favorite flags in a [config file](../configuration/).
