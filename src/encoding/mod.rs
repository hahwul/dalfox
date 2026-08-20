pub mod pipeline;
pub mod pre_encoding;

use base64::{Engine, engine::general_purpose::STANDARD};

/// Apply encoder policy to a list of base payloads and return expanded, de-duplicated variants.
/// Policy:
/// - If encoders contains "none", return only the original payloads (deduplicated), no variants.
/// - Otherwise, include original payload and, for each encoder present, append its variant(s).
/// - Encoder application order is fixed to: url, html, htmlpad, 2url, 3url, 4url, base64, unicode, zwsp
/// - Results are de-duplicated while preserving the first occurrence order.
pub fn apply_encoders_to_payloads(base_payloads: &[String], encoders: &[String]) -> Vec<String> {
    // Dedup base first while preserving order
    let mut seen = std::collections::HashSet::new();
    let mut bases: Vec<&String> = Vec::with_capacity(base_payloads.len());
    for p in base_payloads {
        if seen.insert(p) {
            bases.push(p);
        }
    }

    // If "none" is selected, only originals should be used
    if encoders.iter().any(|e| e == "none") {
        return bases.into_iter().cloned().collect();
    }

    // Use a HashSet for O(1) encoder lookup instead of O(n) linear scan
    let encoder_set: std::collections::HashSet<&str> =
        encoders.iter().map(String::as_str).collect();

    // Expansion order
    let prio = [
        "url", "html", "htmlpad", "2url", "3url", "4url", "base64", "unicode", "zwsp",
    ];

    // Pre-calculate active encoders using set lookup
    let active_encoders: Vec<&str> = prio
        .iter()
        .filter(|&&e| encoder_set.contains(e))
        .copied()
        .collect();

    let estimated_cap = bases.len() * (1 + active_encoders.len());
    let mut out: Vec<String> = Vec::with_capacity(estimated_cap);
    let mut out_seen = std::collections::HashSet::with_capacity(estimated_cap);

    for p in bases {
        // Always include original first
        if out_seen.insert(p.clone()) {
            out.push(p.clone());
        }
        // Then encoder variants in fixed order gated by encoders set
        for &e in &active_encoders {
            let v = match e {
                "url" => url_encode(p),
                "html" => html_entity_encode(p),
                "htmlpad" => html_entity_zero_padded_encode(p),
                "2url" => double_url_encode(p),
                "3url" => triple_url_encode(p),
                "4url" => quadruple_url_encode(p),
                "base64" => base64_encode(p),
                "unicode" => unicode_fullwidth_encode(p),
                "zwsp" => zero_width_encode(p),
                _ => continue,
            };
            if out_seen.insert(v.clone()) {
                out.push(v);
            }
        }
    }
    out
}

/// Convenience helper to expand a single payload with encoders using the same policy.
pub fn expand_payload_with_encoders(payload: &str, encoders: &[String]) -> Vec<String> {
    apply_encoders_to_payloads(&[payload.to_string()], encoders)
}

#[cfg(test)]
mod encoder_policy_tests;

/// URL-encodes the given payload string.
/// Example: "<" becomes "%3C"
pub fn url_encode(payload: &str) -> String {
    urlencoding::encode(payload).to_string()
}

fn repeat_url_encode(payload: &str, rounds: usize) -> String {
    let mut encoded = payload.to_string();
    for _ in 0..rounds {
        encoded = url_encode(&encoded);
    }
    encoded
}

/// Base64-encodes the given payload string.
/// Example: "<" becomes "PA=="
pub fn base64_encode(payload: &str) -> String {
    STANDARD.encode(payload)
}

/// HTML entity-encodes the given payload string using hex entities.
/// Example: "<" becomes "&#x003c;"
pub fn html_entity_encode(payload: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(payload.len() * 8);
    for c in payload.chars() {
        let _ = write!(out, "&#x{:04x};", c as u32);
    }
    out
}

/// Double URL-encodes the given payload string.
/// First encodes, then encodes the result again.
/// Example: "<" becomes "%253C"
pub fn double_url_encode(payload: &str) -> String {
    repeat_url_encode(payload, 2)
}

/// Triple URL-encodes the given payload string.
/// Useful when the target or framework decodes percent-encoding more than twice.
pub fn triple_url_encode(payload: &str) -> String {
    repeat_url_encode(payload, 3)
}

/// Quadruple URL-encodes the given payload string.
/// Useful when one decode happens in request parsing before application logic.
pub fn quadruple_url_encode(payload: &str) -> String {
    repeat_url_encode(payload, 4)
}

/// Unicode fullwidth encoding: maps ASCII 0x21-0x7E to fullwidth equivalents
/// (U+FF01-U+FF5E). Useful for bypassing WAFs that only check ASCII characters.
/// Example: "<" (0x3C) becomes "＜" (U+FF1C)
pub fn unicode_fullwidth_encode(payload: &str) -> String {
    payload
        .chars()
        .map(|c| {
            let code = c as u32;
            if (0x21..=0x7E).contains(&code) {
                // Map ASCII printable range to fullwidth: 0x21 -> 0xFF01
                char::from_u32(code - 0x21 + 0xFF01).unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

/// HTML entity encoding with zero-padded hex codes.
/// Bypasses WAF regex patterns that expect exactly `&#xNN;` format.
/// Example: "<" becomes "&#x000003c;" (7-digit zero-padded hex)
pub fn html_entity_zero_padded_encode(payload: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(payload.len() * 12);
    for c in payload.chars() {
        if c.is_ascii_alphanumeric() || c == ' ' {
            out.push(c);
        } else {
            // Use 7-digit zero-padded hex for special chars
            let _ = write!(out, "&#x{:07x};", c as u32);
        }
    }
    out
}

/// Zero-width space encoding: inserts U+200B after key characters commonly
/// filtered by WAFs (<, >, ", ', (, ), /, ;). The zero-width space is invisible
/// but may bypass simple string matching.
pub fn zero_width_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 2);
    for c in payload.chars() {
        out.push(c);
        if matches!(c, '<' | '>' | '"' | '\'' | '(' | ')' | '/' | ';') {
            out.push('\u{200B}');
        }
    }
    out
}

/// Selectively HTML-entity-encode only the specified characters in a payload.
fn selective_html_encode(payload: &str, chars_to_encode: &[char]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(payload.len() * 4);
    for c in payload.chars() {
        if chars_to_encode.contains(&c) {
            let _ = write!(out, "&#x{:04x};", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

/// Generate adaptive encoding variants based on which special characters are
/// filtered vs. allowed by the target.  Returns a list of encoding function names
/// that should be applied to payloads.
///
/// * `invalid_specials` – characters that the server filters/blocks (e.g. `<`, `>`)
/// * `valid_specials`   – characters that pass through unmodified
pub fn generate_adaptive_encodings(
    invalid_specials: &[char],
    _valid_specials: &[char],
) -> Vec<String> {
    let mut encoders: Vec<String> = Vec::new();

    let angle_blocked = invalid_specials.contains(&'<') || invalid_specials.contains(&'>');
    let quote_blocked = invalid_specials.contains(&'"') || invalid_specials.contains(&'\'');
    let paren_blocked = invalid_specials.contains(&'(') || invalid_specials.contains(&')');

    if angle_blocked {
        encoders.push("html".to_string());
        encoders.push("url".to_string());
        encoders.push("2url".to_string());
        encoders.push("3url".to_string());
        encoders.push("4url".to_string());
        encoders.push("unicode".to_string());
    }

    if quote_blocked && !angle_blocked {
        encoders.push("html".to_string());
    }

    if paren_blocked && !angle_blocked {
        encoders.push("html".to_string());
    }

    // Always include url as a baseline
    if !encoders.contains(&"url".to_string()) {
        encoders.push("url".to_string());
    }

    encoders
}

/// Apply adaptive encoding to a single payload based on which chars are blocked.
pub fn apply_adaptive_encoding(payload: &str, invalid_specials: &[char]) -> Vec<String> {
    let mut variants = vec![payload.to_string()];

    let angle_blocked = invalid_specials.contains(&'<') || invalid_specials.contains(&'>');
    let quote_blocked = invalid_specials.contains(&'"') || invalid_specials.contains(&'\'');
    let paren_blocked = invalid_specials.contains(&'(') || invalid_specials.contains(&')');

    if angle_blocked {
        // Encode only angle brackets
        variants.push(selective_html_encode(payload, &['<', '>']));
        variants.push(url_encode(payload));
        variants.push(double_url_encode(payload));
        variants.push(triple_url_encode(payload));
        variants.push(quadruple_url_encode(payload));
        variants.push(unicode_fullwidth_encode(payload));
        // Combo: url(html)
        variants.push(url_encode(&selective_html_encode(payload, &['<', '>'])));
        // Combo: html(url)
        variants.push(html_entity_encode(&url_encode(payload)));
    }

    if quote_blocked {
        // Encode only quotes
        variants.push(selective_html_encode(payload, &['"', '\'']));
    }

    if paren_blocked {
        // Encode only parens
        variants.push(selective_html_encode(payload, &['(', ')']));
    }

    // Dedup
    let mut seen = std::collections::HashSet::new();
    variants.retain(|v| seen.insert(v.clone()));
    variants
}

#[cfg(test)]
mod tests;
