+++
title = "Stored XSS"
description = "Inject on one URL, verify the payload fires on another."
weight = 5
toc = true
+++

A Stored XSS lives on the server: you submit it once (a comment, a profile field, a chat message) and it triggers every time someone views that page. Dalfox has a dedicated mode for this pattern.

## The basic flow

```bash
dalfox scan https://target.app/post-comment \
  --sxss \
  --sxss-url https://target.app/comments
```

Dalfox will:

1. **Inject** each payload into the first URL (`post-comment`).
2. **Retrieve** the second URL (`comments`) with a GET (configurable via `--sxss-method`).
3. **Verify** whether the payload reflects in the retrieval response, and whether it produced a real DOM element.

A payload that comes back on a retrieval page is reported as `R`; one that also forms a real DOM element there is `V`. Stored findings carry an `inject_type` prefixed with `sxss-` (`sxss-inHTML`), so reports keep them apart from reflected ones.

Stored mode is strictly serial: one parameter at a time, one request at a time, because write ordering and the retrieval retries assume it. `--workers` does not speed it up.

The write endpoint does not need to echo what you submit. Dalfox keeps a stored
field even when the submit response just says "saved", and it does not use that
non-rendering response to decide which characters the sink filters — so a
form-backed stored sink is tested with the full payload set rather than skipped.

Every parameter is sent the same payloads, and a stored sink keeps whatever it
is given, so once one field has stored a payload the retrieval page shows it for
the rest of the scan. To keep findings on the right field, before a parameter
injects anything Dalfox snapshots the retrieval page(s) once; a payload is
credited to that parameter only when its injection makes the payload appear
*more* often than the snapshot already showed. A copy another field stored
earlier is already in the snapshot, so it is never mis-credited. The snapshot
costs one extra GET per retrieval URL per parameter.

Right after the snapshot, Dalfox re-probes the field once: if that probe's own
injection does not raise the marker count on the retrieval page (or in the write
response), the field does not store here and its payload catalog is skipped. This
stops a form's non-storing fields — which would otherwise pass the reflection
probe on the marker a sibling field stored — from running the whole catalog. The
probe tries both a long and a short marker, so a sink that only keeps short
values is not mistaken for a non-storing one.

The probe also observes *when* the store becomes visible. A synchronous sink
(visible immediately) lets Dalfox skip re-fetching a payload that does not
appear, keeping the request count low. A write-behind sink (visible only after a
delay) keeps the full per-payload retrieval retries so a delayed payload is not
missed; if your target stores slower than the default retry window, raise
`--sxss-retries` (default `3`, maximum `20`). Retry *n* waits 500 ms × *n*,
capped at 5 s per wait. `--deep-scan` skips the store probe and runs the full
catalog on every field.

## Choosing the retrieval URL

Pick the page the stored value **reads** from. Examples:

| Injection URL | Retrieval URL |
|---------------|---------------|
| `POST /comments/new` | `GET /post/123/comments` |
| `PATCH /profile` | `GET /u/myself` |
| `POST /support/ticket` | `GET /admin/tickets` (if you have admin access) |

Dalfox reads every candidate retrieval page, in this order: `--sxss-url` (when set), the page the
form was found on, the form's `action` endpoint (only when it is on the target's origin, or the
same host upgraded to HTTPS), and the injection target itself. Duplicates are fetched once. Without
`--sxss-url` the last three are all it has, so set it whenever the stored value is rendered
somewhere they don't cover. `--sxss-url` does nothing without `--sxss`; Dalfox warns when you pass
it alone.

## Retrieval method

```bash
dalfox scan https://target.app/form --sxss \
  --sxss-url https://target.app/list \
  --sxss-method GET
```

`GET` is the default. Use `POST` or others if the retrieval endpoint needs it.

## Authentication

Stored-XSS often requires two sessions: one that writes (user), and one that reads (admin). Use headers/cookies that grant enough access for the retrieval GET to see what you wrote.

```bash
dalfox scan https://target.app/profile \
  --sxss --sxss-url https://target.app/admin/users \
  -H "Cookie: admin_session=abc; role=admin"
```

## Blind + stored

If the retrieval page is behind a login you don't have, switch to blind XSS. The payload fires on the admin's browser, and your callback server records it:

```bash
dalfox scan https://target.app/support/ticket \
  -b https://callback.interact.sh
```

You still need to wait for someone to view the page; the callback tells you when it happens.

## Tips

- **Scope narrowly.** Use `-p` to name the field(s) you know are rendered on the retrieval URL. That way Dalfox isn't testing every cookie.
- **Watch for sanitisation-then-render.** Stored XSS often survives an HTML sanitizer on write but breaks on a second sanitization on read. Dalfox's mXSS payloads are tuned for this.
- **Slow down.** Some apps debounce or batch writes. A small `--delay` helps the retrieval see your payload.

## Next

- [Payloads &amp; Encoding](../payloads/) for tuning the injected payloads.
- [Output &amp; Reports](../output/) for shipping findings.
