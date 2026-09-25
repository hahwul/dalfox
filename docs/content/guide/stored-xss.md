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

The write endpoint does not need to echo what you submit. A submit response that
just says "saved" is fine, and Dalfox does not use it to decide which characters
the sink filters.

Every field gets the same payloads, and a stored value stays on the page, so
before a parameter sends its payloads Dalfox does two things:

- **Snapshot.** It fetches each retrieval page once. A payload is credited to the
  parameter only when that parameter's injection makes it appear *more* often
  than the snapshot showed, so a copy another field stored earlier is never
  mis-credited. This costs one GET per retrieval URL per parameter.
- **Store probe.** It injects a marker, a long one and then a short one for sinks
  that keep only short values. If neither raises the count on a retrieval page
  (or in the write response), the field does not store and its payloads are
  skipped.

The probe also shows *when* the store becomes visible. If it is visible at once,
Dalfox checks each payload with a single retrieval pass. If it shows up only
after a delay (a write-behind store), every payload keeps the full retrieval
retries. For a target that stores slower than that, raise `--sxss-retries`
(default `3`, maximum `20`); retry *n* waits 500 ms × *n*, at most 5 s per wait.
`--deep-scan` skips the store probe and runs every payload on every field.

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
