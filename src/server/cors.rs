//! CORS response-header construction driven by the configured allow-lists,
//! plus the compilation of `--allowed-origins` into the matchers `AppState`
//! carries.

use super::*;

/// The `--allowed-origins` list, compiled into the three fields `AppState`
/// holds — the raw entries (exact compares), the compiled patterns, and the
/// `*` opt-in — plus any entry that had to be dropped.
pub(crate) struct OriginRules {
    pub(crate) origins: Option<Vec<String>>,
    pub(crate) regexes: Vec<regex::Regex>,
    pub(crate) allow_all: bool,
    /// Entries that could not be compiled, already rendered for the operator.
    /// Returned rather than printed because this runs before `AppState` exists
    /// and a bare `eprintln!` never reaches `--log-file` — which is the one
    /// place an operator running under systemd would look after their web UI
    /// started getting 403s from a silently dropped pattern.
    pub(crate) rejected: Vec<String>,
}

/// Anchor an origin pattern so it must match the **whole** `Origin` value.
///
/// `Regex::is_match` searches anywhere in the subject, and an origin has no
/// delimiter to stop it at: an unanchored `https://app\.example\.com` is a
/// substring of `https://app.example.com.evil.com`, a host an attacker can
/// simply register. That is not a CORS-only leak — [`origin_allowed`] is also
/// what `auth::check_cross_site` consults, so a matching origin lets an
/// attacker's page drive the whole API (start scans, read results) from the
/// operator's browser.
///
/// Operators write these patterns as if they described the entire origin —
/// the wildcard form has always been anchored, and every doc example spells
/// `^…$` — so anchoring is what makes the two forms agree instead of one
/// silently accepting suffixes. The non-capturing group matters for
/// alternation (`a|b` must become `^(?:a|b)$`, not `^a|b$`), and a pattern
/// that already carries `^…$` is unaffected: the added anchors are zero-width
/// assertions asserting the same positions.
fn anchored_origin_pattern(pattern: &str) -> String {
    format!("^(?:{})$", pattern)
}

/// Compile the comma-separated `--allowed-origins` value.
///
/// Entries are trimmed and empties dropped. `*` sets the allow-all opt-in;
/// a `regex:` prefix supplies a pattern verbatim; anything containing `*` is
/// a shell-style wildcard escaped into one. Both pattern forms go through
/// [`anchored_origin_pattern`]. A pattern that fails to compile — or names no
/// origin at all — is dropped and reported through `rejected`, which fails
/// closed.
pub(crate) fn compile_allowed_origins(raw: Option<&str>) -> OriginRules {
    let origins = raw.map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()
    });

    let mut regexes = Vec::new();
    let mut allow_all = false;
    let mut rejected = Vec::new();
    if let Some(list) = &origins {
        for item in list {
            if item == "*" {
                allow_all = true;
                continue;
            }
            // `regex:` is the operator's own pattern; a bare `*` inside an
            // otherwise literal origin is the shell-style wildcard form, which
            // is escaped first so only the `*` stays meta.
            let (pattern, label) = if let Some(pat) = item.strip_prefix("regex:") {
                if pat.trim().is_empty() {
                    // `^(?:)$` matches the empty string, so a stray `regex:`
                    // left behind while editing the list would quietly admit a
                    // request carrying an empty `Origin` header — and admitting
                    // it skips the `Sec-Fetch-Site` fallback entirely. An entry
                    // that describes no origin is a typo, not a rule.
                    rejected.push(format!("empty allowed-origins regex '{}'", item));
                    continue;
                }
                (anchored_origin_pattern(pat), "regex")
            } else if item.contains('*') {
                let escaped = regex::escape(item).replace("\\*", ".*");
                (anchored_origin_pattern(&escaped), "wildcard")
            } else {
                continue;
            };
            match regex::Regex::new(&pattern) {
                Ok(re) => regexes.push(re),
                Err(e) => rejected.push(format!(
                    "invalid allowed-origins {} '{}': {}",
                    label, item, e
                )),
            }
        }
    }

    OriginRules {
        origins,
        regexes,
        allow_all,
        rejected,
    }
}

/// Does `origin` match the configured allow-list (exact entry, compiled
/// wildcard/regex, or the `*` opt-in)?
///
/// Shared with the request gate in `auth.rs` so "this origin may read our
/// responses" and "this origin may drive our API" can never drift apart.
pub(crate) fn origin_allowed(state: &AppState, origin: &str) -> bool {
    if state.allow_all_origins {
        return true;
    }
    // Compared case-insensitively: scheme and host are case-insensitive per
    // RFC 6454, and `auth::check_host` already normalizes the sibling `Host`
    // value the same way. A byte-exact compare made an allow-list entry the
    // operator typed as `https://App.Corp.Local` silently dead — browsers
    // always send the lowercased form, so their web UI got a
    // `refused: cross-site browser request` 403 with nothing pointing at the
    // capitalization.
    let exact = state.allowed_origins.as_ref().is_some_and(|v| {
        v.iter()
            .any(|o| !o.starts_with("regex:") && o != "*" && o.eq_ignore_ascii_case(origin))
    });
    exact
        || state
            .allowed_origin_regexes
            .iter()
            .any(|re| re.is_match(origin))
}

pub(crate) fn build_cors_headers(state: &AppState, req_headers: &HeaderMap) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if state.allowed_origins.is_none() {
        return headers;
    }

    // Methods/Headers (configured or defaults)
    let allow_methods = state.allow_methods.parse().unwrap_or_else(|_| {
        "GET,POST,OPTIONS,PUT,PATCH,DELETE"
            .parse()
            .expect("static CORS methods header")
    });
    let allow_headers = state.allow_headers.parse().unwrap_or_else(|_| {
        "Content-Type,X-API-KEY,Authorization"
            .parse()
            .expect("static CORS headers header")
    });

    // Wildcard
    if state.allow_all_origins {
        headers.insert(
            "Access-Control-Allow-Origin",
            "*".parse().expect("static wildcard origin"),
        );
        headers.insert("Access-Control-Allow-Methods", allow_methods);
        headers.insert("Access-Control-Allow-Headers", allow_headers);
        return headers;
    }

    // Past the wildcard branch the response depends on the request's `Origin`
    // header, so `Vary: Origin` must be set whether or not this particular
    // origin matched. Setting it only on a match let a shared/CDN cache store
    // the no-ACAO response produced for a disallowed origin and replay it to an
    // allowed one (and vice versa), breaking CORS for legitimate callers.
    headers.insert("Vary", "Origin".parse().expect("static Vary header"));

    // Reflect allowed origins
    if let Some(origin_val) = req_headers.get("Origin")
        && let Ok(origin_str) = origin_val.to_str()
    {
        // `allow_all_origins` is handled by the early return above, so this
        // only ever decides the exact/regex cases here.
        if origin_allowed(state, origin_str) {
            headers.insert("Access-Control-Allow-Origin", origin_val.clone());
        }
    }

    headers.insert("Access-Control-Allow-Methods", allow_methods);
    headers.insert("Access-Control-Allow-Headers", allow_headers);
    headers
}
