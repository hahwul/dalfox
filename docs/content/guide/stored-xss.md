+++
title = "Stored XSS"
description = "Inject on one URL, verify the payload fires on another."
weight = 5
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
3. **Verify** whether the payload reflects in the retrieval response — and whether it produced a real DOM element.

Only findings that survive both steps are reported as SXSS.

## Choosing the retrieval URL

Pick the page the stored value **reads** from. Examples:

| Injection URL | Retrieval URL |
|---------------|---------------|
| `POST /comments/new` | `GET /post/123/comments` |
| `PATCH /profile` | `GET /u/myself` |
| `POST /support/ticket` | `GET /admin/tickets` (if you have admin access) |

If you omit `--sxss-url`, Dalfox tries to auto-detect it from the response headers (e.g., a `Location` redirect after a POST).

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
- **Watch for sanitisation-then-render.** Stored XSS often survives a HTML sanitizer on write but breaks on a second sanitization on read. Dalfox's mXSS payloads are tuned for this.
- **Slow down.** Some apps debounce or batch writes. A small `--delay` helps the retrieval see your payload.

## Next

- [Payloads &amp; Encoding](../payloads/) for tuning the injected payloads.
- [Output &amp; Reports](../output/) for shipping findings.
