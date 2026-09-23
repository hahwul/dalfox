+++
title = "Stored XSS"
description = "Inject on one URL, verify the payload fires on another."
weight = 5
toc = true
+++

A Stored XSS lives on the server: you submit it once (a comment, a profile field, a chat message) and it triggers every time someone views that page. Dalfox has a dedicated mode for this pattern.

## The basic flow

```bash
dalfox https://target.app/post-comment \
  --sxss \
  --sxss-url https://target.app/comments
```

Dalfox will:

1. **Inject** each payload into the first URL (`post-comment`).
2. **Retrieve** the second URL (`comments`) with a GET (configurable via `--sxss-method`).
3. **Verify** whether the payload reflects in the retrieval response, and whether it produced a real DOM element.

Only findings that survive both steps are reported as SXSS.

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
injection does not raise the marker count on the retrieval page, the field does
not store here and its payload catalog is skipped. This stops a form's
non-storing fields — which would otherwise pass the reflection probe on the
marker a sibling field stored — from running the whole catalog. Because that
probe already absorbs any write-to-read propagation delay, the per-payload
retrieval is not retried again for payloads that do not appear.

## Choosing the retrieval URL

Pick the page the stored value **reads** from. Examples:

| Injection URL | Retrieval URL |
|---------------|---------------|
| `POST /comments/new` | `GET /post/123/comments` |
| `PATCH /profile` | `GET /u/myself` |
| `POST /support/ticket` | `GET /admin/tickets` (if you have admin access) |

If you omit `--sxss-url`, Dalfox falls back to the form-discovery context: the page the form was
found on, then the form's `action` endpoint, then the injection target itself. Set it explicitly
whenever the stored value is rendered somewhere those three don't cover.

## Retrieval method

```bash
dalfox https://target.app/form --sxss \
  --sxss-url https://target.app/list \
  --sxss-method GET
```

`GET` is the default. Use `POST` or others if the retrieval endpoint needs it.

## Authentication

Stored-XSS often requires two sessions: one that writes (user), and one that reads (admin). Use headers/cookies that grant enough access for the retrieval GET to see what you wrote.

```bash
dalfox https://target.app/profile \
  --sxss --sxss-url https://target.app/admin/users \
  -H "Cookie: admin_session=abc; role=admin"
```

## Blind + stored

If the retrieval page is behind a login you don't have, switch to blind XSS. The payload fires on the admin's browser, and your callback server records it:

```bash
dalfox https://target.app/support/ticket \
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
