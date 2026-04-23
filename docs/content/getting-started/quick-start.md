+++
title = "Quick Start"
description = "Your first Dalfox scan in five minutes."
weight = 3
+++

This page walks you from install to a verified finding. We'll use an intentionally vulnerable demo target so you can see real output.

{{ alert(type="warning", body="Only scan targets you're authorized to test. Dalfox is a powerful tool — it fires real XSS payloads.") }}

## 1. Scan a single URL

```bash
dalfox https://xss-game.appspot.com/level1/frame?query=test
```

The first argument is the target. Dalfox auto-detects that it's a URL and runs the `scan` subcommand implicitly. You'll see:

- A banner with the version.
- `INFO` lines as Dalfox discovers parameters and probes contexts.
- `[V]` (verified) and `[R]` (reflected) lines for each finding, with the exact payload that worked.

## 2. Scan from a file

Got a list of URLs from your crawler? Feed them in:

```bash
# urls.txt — one target per line
dalfox file urls.txt
```

Each URL runs through the same pipeline. Results stream as they're found.

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
dalfox https://target.app/search?q=test -f json -o report.json
```

Machine-readable formats (`json`, `jsonl`, `sarif`, `toml`) auto-suppress the banner so the file stays clean.

## 5. Authenticated scans

Pass cookies, headers, or a custom method:

```bash
dalfox https://api.target.app/v1/users \
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

## 6. Catch Blind XSS

Use an out-of-band callback (Interactsh, Burp Collaborator, XSS Hunter, etc.):

```bash
dalfox https://target.app \
  -b https://your-callback.interact.sh
```

Dalfox sends blind-XSS payloads across every discovered parameter; if the payload fires later in an admin panel, your callback server records it.

## 7. Peek before you poke

Not ready to attack? Use `--dry-run` to see what Dalfox **would** scan:

```bash
dalfox https://target.app --dry-run
```

It discovers parameters and estimates request volume without firing any payloads.

## Reading the output

Each finding is tagged:

| Tag | Meaning |
|-----|---------|
| `[V]` | **Verified** — payload produced a real DOM element (via AST/CSS-selector match) |
| `[A]` | **AST-detected** — static JS analysis found a source→sink flow |
| `[R]` | **Reflected** — payload appeared in the response, but no DOM evidence |

`V` and `A` findings are actionable. `R` findings are worth a look but may be filtered further downstream.

## Next steps

- Learn the different [scanning modes](../../guide/scanning-modes/).
- Understand how [parameters are discovered](../../guide/parameters/).
- Tune [payloads and encoders](../../guide/payloads/) for harder targets.
- Save your favorite flags in a [config file](../configuration/).
