//! Request authorization for the HTTP API: API-key authentication plus the
//! browser-origin / `Host` gate.
//!
//! Both controls live here so a new route picks up all of them through a
//! single [`authorize_request`] call rather than remembering to copy two
//! separate checks.

use super::*;

/// Constant-time byte comparison. Returns false for differing lengths
/// without iterating, which leaks length only — never the contents. Used
/// for the API-key check so an attacker can't recover the key byte-by-byte
/// from response-time differences.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub(crate) fn check_api_key(state: &AppState, headers: &HeaderMap) -> bool {
    match &state.api_key {
        Some(required) if !required.is_empty() => {
            if let Some(h) = headers.get("X-API-KEY")
                && let Ok(v) = h.to_str()
            {
                return constant_time_eq(v.as_bytes(), required.as_bytes());
            }
            false
        }
        _ => true, // no API key set -> allow all
    }
}

/// Why a request was refused. Kept as a value so the handler can derive the
/// status code, the client-facing message, and the log line from one place
/// instead of each route spelling out its own 401 body.
pub(crate) enum Denied {
    /// API key missing or wrong.
    Unauthorized,
    /// A browser issued this request from another site. Carries the signal
    /// that fired (the `Origin` value, or the `Sec-Fetch-Site` token).
    CrossSite(String),
    /// The `Host` header names something that isn't this server, which is what
    /// a DNS-rebinding attack looks like. Carries the offending host.
    UntrustedHost(String),
}

impl Denied {
    pub(crate) fn status(&self) -> StatusCode {
        match self {
            Denied::Unauthorized => StatusCode::UNAUTHORIZED,
            Denied::CrossSite(_) | Denied::UntrustedHost(_) => StatusCode::FORBIDDEN,
        }
    }

    /// Client-facing message. The cross-site and untrusted-host cases name the
    /// flag that permits the request, because the legitimate hits are an
    /// operator wiring up a web UI or fronting the server with a reverse proxy
    /// — both need to know which knob to turn.
    fn message(&self) -> String {
        match self {
            Denied::Unauthorized => "unauthorized".to_string(),
            Denied::CrossSite(signal) => format!(
                "refused: cross-site browser request ({}). This API can start scans and POST \
                 their results to any callback_url, so requests driven by another web page are \
                 rejected. Allow a specific web UI with --allowed-origins.",
                signal
            ),
            Denied::UntrustedHost(host) => format!(
                "refused: request Host '{}' is not this server. This blocks DNS rebinding, \
                 where a hostname the attacker controls resolves to this machine. Add the \
                 hostname with --allowed-hosts if you front this server with a proxy.",
                host
            ),
        }
    }

    pub(crate) fn api_response(&self) -> ApiResponse<serde_json::Value> {
        ApiResponse::<serde_json::Value> {
            code: self.status().as_u16() as i32,
            msg: self.message(),
            data: None,
        }
    }

    pub(crate) fn log_message(&self, route: &str) -> String {
        match self {
            Denied::Unauthorized => format!("Unauthorized access to {}", route),
            Denied::CrossSite(signal) => {
                format!("blocked cross-site browser request to {} ({})", route, signal)
            }
            Denied::UntrustedHost(host) => {
                format!("blocked request to {} with untrusted Host '{}'", route, host)
            }
        }
    }
}

/// Fetch-metadata + `Origin` gate. Only browsers send these headers, so a
/// curl / CLI / agent client (which sends neither) is unaffected.
///
/// The threat is a web page the operator merely *visits*: `GET /scan` starts a
/// scan from query parameters alone, and `callback_url` ships the results
/// straight to the attacker, so the same-origin policy never gets a say — the
/// attacker never needs to read our response. Binding to loopback does not
/// help, because the victim's browser is already inside that boundary.
fn check_cross_site(state: &AppState, headers: &HeaderMap) -> Result<(), Denied> {
    // JSONP exists to be loaded cross-origin by `<script src>`, which carries
    // no `Origin` to validate — enforcing the gate would make the flag inert.
    // Enabling it is therefore an explicit decision to let any site read this
    // API, and `run_server` warns loudly at startup when it is on without auth.
    // `--allowed-origins '*'` is the same kind of explicit opt-in.
    if state.jsonp_enabled || state.allow_all_origins {
        return Ok(());
    }

    // `Origin` first: a configured web UI is cross-site by definition, and must
    // keep working even though the fetch-metadata check below would reject it.
    if let Some(origin) = headers.get("Origin").and_then(|v| v.to_str().ok()) {
        return if origin_allowed(state, origin) {
            Ok(())
        } else {
            Err(Denied::CrossSite(format!("Origin: {}", origin)))
        };
    }

    // No `Origin` (a `<img>` / `<script>` / form GET sends none), so fall back
    // to fetch metadata. `same-origin` is a page served by us — we serve no
    // HTML, but it costs nothing to allow. `none` is a user-initiated
    // navigation, i.e. the operator typing the URL or opening a bookmark.
    if let Some(site) = headers.get("Sec-Fetch-Site").and_then(|v| v.to_str().ok()) {
        let site = site.trim();
        if !(site.eq_ignore_ascii_case("same-origin") || site.eq_ignore_ascii_case("none")) {
            return Err(Denied::CrossSite(format!("Sec-Fetch-Site: {}", site)));
        }
    }

    Ok(())
}

/// Extract the host portion of an authority, dropping the port and the
/// brackets around an IPv6 literal (`[::1]:6664` -> `::1`).
fn host_name_of(authority: &str) -> &str {
    match authority.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => authority.split(':').next().unwrap_or(authority),
    }
}

/// `Host` allow-list, which is what stops DNS rebinding. Rebinding needs a
/// *name* the attacker controls (evil.com re-resolved to 127.0.0.1) — after
/// which the browser considers the request same-origin and sends no `Origin`,
/// slipping past [`check_cross_site`]. An IP-literal `Host` cannot be rebound,
/// so it is always accepted; a name must be `localhost` or explicitly allowed.
fn check_host(state: &AppState, headers: &HeaderMap) -> Result<(), Denied> {
    let Some(authority) = headers.get("Host").and_then(|v| v.to_str().ok()) else {
        // Absent `Host` can't be evaluated: HTTP/2 carries the authority in the
        // pseudo-header instead, and non-browser clients may omit it entirely.
        return Ok(());
    };
    let authority = authority.trim();
    if authority.is_empty() {
        return Ok(());
    }
    let name = host_name_of(authority);
    if name.parse::<std::net::IpAddr>().is_ok()
        || name.eq_ignore_ascii_case("localhost")
        || state
            .allowed_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(name))
    {
        return Ok(());
    }
    Err(Denied::UntrustedHost(authority.to_string()))
}

/// Source checks that apply to every route, including the ones that need no
/// API key. `/health` uses this directly: it stays open to unauthenticated
/// callers by design, but a malicious page must not be able to use it to probe
/// whether a dalfox server is running on the operator's machine.
pub(crate) fn check_request_source(state: &AppState, headers: &HeaderMap) -> Result<(), Denied> {
    check_host(state, headers)?;
    check_cross_site(state, headers)
}

/// Full authorization for a route: request source, then the API key.
pub(crate) fn authorize_request(state: &AppState, headers: &HeaderMap) -> Result<(), Denied> {
    check_request_source(state, headers)?;
    if check_api_key(state, headers) {
        Ok(())
    } else {
        Err(Denied::Unauthorized)
    }
}
