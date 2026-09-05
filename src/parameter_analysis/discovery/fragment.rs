//! Discovery surface: fragment. See the module docs in `mod.rs`.

use super::*;

/// Extract parameters from URL hash fragments for AST DOM-XSS analysis
/// correlation.
///
/// Handles two formats:
/// - SPA routing: `#/path?key=value&key2=value2`
/// - Simple fragments: `#key=value&key2=value2`
///
/// No HTTP requests are needed — fragments are client-side only — and
/// the run_scanning loop now skips `Location::Fragment` params for
/// reflection probes (HTTP servers never see the fragment) to avoid the
/// "discovered but never fuzzed" phantom that dogfood surfaced. The
/// params still get registered so the AST DOM analyzer can correlate a
/// `location.hash`-source finding with the user-supplied key.
pub async fn check_fragment_discovery(target: &Target, reflection_params: Arc<Mutex<Vec<Param>>>) {
    let frag = match target.url.fragment() {
        Some(f) if !f.is_empty() => f,
        _ => return,
    };

    // Split fragment into optional route prefix and query portion.
    // e.g. "/redir?url=value" => route prefix "/redir", query "url=value"
    // e.g. "key=value" => route prefix "", query "key=value"
    let query_part = if let Some(q_pos) = frag.find('?') {
        &frag[q_pos + 1..]
    } else {
        frag
    };

    if query_part.is_empty() {
        return;
    }

    let mut params = reflection_params.lock().await;
    for pair in query_part.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = if let Some((k, v)) = pair.split_once('=') {
            (k.to_string(), v.to_string())
        } else {
            (pair.to_string(), String::new())
        };
        if key.is_empty() {
            continue;
        }
        // Avoid duplicates
        if params
            .iter()
            .any(|p| p.name == key && p.location == Location::Fragment)
        {
            continue;
        }
        params.push(Param::new(key, value, Location::Fragment));
    }
}
