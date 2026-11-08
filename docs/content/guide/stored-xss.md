+++
title = "Stored XSS"
description = "Use Dalfox to inject stored XSS on one URL and verify execution on a different retrieval URL."
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

The write endpoint does not need to echo what you submit. A submit response that only says "saved" is fine, and Dalfox does not use it to decide which characters the sink filters.

Every field gets the same payloads, and a stored value stays on the page, so before a parameter sends its payloads Dalfox does two things:

- **Snapshot.** It fetches each retrieval page once. A payload is credited to the parameter only when that parameter's injection makes it appear *more* often than the snapshot showed, so a copy another field stored earlier is never credited to the wrong field. This costs one GET per retrieval URL per parameter.
- **Store probe.** It injects a marker: a long one, then a short one for sinks that keep only short values. If neither raises the count on a retrieval page (or in the write response), the field does not store and its payloads are skipped.

The probe also shows *when* the store becomes visible. If it is visible at once, Dalfox checks each payload with a single retrieval pass. If it shows up only after a delay (a write-behind store), every payload keeps the full retrieval retries. For a target that stores slower than that, raise `--sxss-retries` (default `3`, maximum `20`); retry *n* waits 500 ms × *n*, at most 5 s per wait. `--deep-scan` skips the store probe and runs every payload on every field.

## Choosing the retrieval URL

Pick the page the stored value **reads** from. Examples:

| Injection URL | Retrieval URL |
|---------------|---------------|
| `POST /comments/new` | `GET /post/123/comments` |
| `PATCH /profile` | `GET /u/myself` |
| `POST /support/ticket` | `GET /admin/tickets` (if you have admin access) |

Dalfox reads every candidate retrieval page, in this order: each `--sxss-url` (when set), the page the form was found on, the form's `action` endpoint (only when it is on the target's origin, or the same host upgraded to HTTPS), and the injection target itself. Duplicates are fetched once. Without `--sxss-url` the last three are all it has, so set it whenever the stored value is rendered somewhere they don't cover. `--sxss-url` does nothing without `--sxss`; Dalfox warns when you pass it alone.

Repeat `--sxss-url` when the value shows up in more than one place, such as a list view and a detail view:

```bash
dalfox scan https://target.app/post-comment --sxss \
  --sxss-url https://target.app/comments \
  --sxss-url https://target.app/post/123
```

In a config file, `sxss_url` takes one URL or a list.

## File uploads

Give Dalfox a captured upload request (`-i raw-http`, a HAR, or a multipart `-d` body) and each file part becomes two injection points:

- `<field>`: the file's content. The part is still sent as a file, with its captured filename and `Content-Type`.
- `<field>[filename]`: the upload filename, which file listings often print without escaping.

```bash
dalfox scan -i raw-http upload.req --sxss \
  --sxss-url https://target.app/files
```

Under `--sxss`, Dalfox also follows the upload's own response to the stored file: a `Location` header, or a same-origin URL ending in the uploaded filename (an HTML link or a JSON field such as `"url": "/uploads/a.html"`). That page is checked like any other retrieval page. A file served as an image or other non-HTML type, or as a download (`Content-Disposition: attachment`), is never reported, so content injection only pays off when the captured upload is HTML or SVG, or when the server trusts the extension you send.

If the server renames uploads (a hash or ID instead of your filename), Dalfox cannot find the file from the response; pass its URL with `--sxss-url` if it is predictable.

The curl PoC for an upload pipes the file content through stdin (`printf '%s' … | curl -F 'field=@-;filename=…'`), since `--form-string` cannot send a file. When the filename holds a `"` or `\`, which curl `-F` would rewrite (`"` becomes `%22`), the PoC sends the recorded body as is with `--data-binary` instead. httpie names an upload after its local path, so an httpie PoC prints the curl command instead.

## Retrieval method

```bash
dalfox scan https://target.app/form --sxss \
  --sxss-url https://target.app/list \
  --sxss-method GET
```

`GET` is the default. Use `POST` or another method if the retrieval endpoint needs it.

## Authentication

Stored XSS often involves two sessions: one that writes (a user) and one that reads (an admin). Dalfox sends the same headers and cookies on the write and the retrieval requests, so use credentials that can both submit the value and see it on the retrieval page.

```bash
dalfox scan https://target.app/profile \
  --sxss --sxss-url https://target.app/admin/users \
  -H "Cookie: admin_session=abc; role=admin"
```

## Blind + stored

If the retrieval page is behind a login you don't have, switch to blind XSS. The payload fires on the admin's browser, and your callback server records it:

```bash
dalfox scan https://target.app/support/ticket \
  -b https://your-callback.example
```

You still need to wait for someone to view the page; the callback tells you when it happens. `--blind-oob` instead of `-b` has Dalfox poll an interactsh session and report a callback as a `V` finding, but only one that arrives before `--blind-oob-wait` runs out; a view hours later reaches only a listener you run yourself. See [Blind XSS](../scanning-modes/#blind-xss).

## Tips

- **Scope narrowly.** Use `-p` to name the fields you know are rendered on the retrieval URL, so Dalfox does not test every input it finds.
- **Watch for sanitize-then-render.** A stored value can pass an HTML sanitizer on write and still turn into live markup when the page parses it again on read. Dalfox's mXSS payloads target this case.
- **Slow down.** Some apps debounce or batch writes. A small `--delay` gives the retrieval a better chance to see your payload.

## Next

- [Payloads &amp; Encoding](../payloads/) for tuning the injected payloads.
- [Output &amp; Reports](../output/) for shipping findings.
