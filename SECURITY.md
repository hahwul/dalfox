# Security Policy

## Supported Versions

| Version | Status |
|---|---|
| **v3.x** (Rust, current) | Fully supported — security and bug fixes land here. |
| **v2.13.x** (Go, legacy) | Critical security backports only, on a best-effort basis. v2 will not receive new features or non-critical fixes. |
| < v2.13 | Unsupported. Please upgrade. |

The Go (v2.x) sources live on the [`v2` branch](https://github.com/hahwul/dalfox/tree/v2). All v3 development happens on `main`.

## Security Model

Dalfox is an offensive tool. It exists to send requests you tell it to send, so some behavior that looks like a vulnerability from the outside is the product working as designed. Please read this section before filing a report.

### Who is trusted

Whoever can run the CLI, submit a scan to the REST API, or call the MCP tools is trusted to make dalfox request arbitrary URLs. There is no privilege boundary below that line — the entire point of the tool is to fetch a target you chose.

### The scanner reaches whatever the host can reach

`dalfox scan`, `POST /scan`, `POST /preflight`, and the MCP scan tools all take a target URL and fetch it directly, and the response is returned to the caller. That includes loopback, RFC1918 hosts, and cloud metadata endpoints such as `169.254.169.254`. Related options — `callback_url` on the server, `--blind`, `--blind-oob`, remote payload and wordlist URLs, webhook delivery — send requests to hosts you supply and are covered by the same rule.

We deliberately do not filter target or callback hosts. A scanner that refuses to scan internal ranges is broken for the people who need it most, and any such filter is trivially bypassed by DNS anyway. Restricting where dalfox can reach is the deployment's job: run it where its network access is appropriate, and use egress controls if that matters to you.

### Running the server safely

`dalfox server` binds `127.0.0.1:6664` and runs without authentication unless you set one. If you expose it:

* Set `--api-key` (or `DALFOX_API_KEY`). Without a key, anyone who can reach the port can launch scans from your host and have the results POSTed anywhere. The server prints a warning at startup when it is bound to a non-loopback address with no key.
* Put egress controls around the host if it sits somewhere sensitive.

Loopback is not a security boundary on its own: a web page the operator visits can drive a `127.0.0.1` API through their browser. The server rejects browser-driven cross-site requests to close that path. Enabling `--jsonp` turns that check off by design, since `<script src>` loads carry no `Origin` — do not combine `--jsonp` with an unauthenticated server.

### Out of scope

Reports resting on the following will be closed as informative:

* Dalfox requesting an internal, loopback, or metadata URL that the caller supplied, through any option — target, callback, blind, or remote payload source.
* An unauthenticated server reachable over the network, when no API key was configured.
* Scan results being delivered to a callback URL chosen by the same caller who submitted the scan.
* Payloads, wordlists, or crafted requests that dalfox sends to a target you pointed it at.

In scope, and always worth reporting: anything that crosses a boundary the operator did not choose. Memory-safety bugs and crashes on hostile input, a scan target influencing the dalfox host beyond the requests it was told to make, one API caller reading or cancelling another's scan, secrets leaking into logs or output, or a browser page driving the local server past the cross-site gate.

## Reporting a Vulnerability

Found a security issue? Let us know so we can fix it.

### How to Report

* **For general security concerns**, please open a [GitHub issue](https://github.com/hahwul/dalfox/issues). Use the `security` label and describe the issue in as much detail as you can. This helps us to understand and address the problem more effectively.
* **For sensitive matters**, please report privately via [GitHub Security Advisories](https://github.com/hahwul/dalfox/security) or email [me](mailto:hahwul@gmail.com) directly. Handling these issues discreetly is vital for everyone's safety.

## Conclusion
Your vigilance and willingness to report security issues are what help keep our project robust and secure. We appreciate the time and effort you put into making our community a safer place. Remember, no concern is too small; we're here to listen and act. Together, we can ensure a secure environment for all our users and contributors. Thank you for being an essential part of our project's security.

Thank you for your support in maintaining the security and integrity of our project!