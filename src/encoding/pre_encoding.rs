//! Centralized pre-encoding logic for parameters that require encoding
//! before injection (e.g., base64, double-base64, double/triple URL encoding).
//!
//! All pre-encoding application and probe generation lives here so that
//! discovery, active probing, reflection checking, and DOM verification
//! share a single source of truth.

use super::{base64_encode, url_encode};

/// Length of the benign prefix prepended to overflow a size-limited WAF
/// inspection window (the `WafWindowPad` transform). Must exceed the WAF's
/// inspected-byte count for the real vector — which trails the pad — to escape
/// inspection. Sized for the common "first N bytes of the value" query
/// inspectors; a WAF inspecting a larger window simply won't be detected as
/// window-limited (the detection probe in `active_probe_param` won't reflect),
/// so this never produces a false bypass.
pub(crate) const WAF_WINDOW_PAD_LEN: usize = 256;

/// The benign prefix used by the `WafWindowPad` transform. A run of a single
/// inert character (no HTML/JS metacharacters, so it can't change the
/// reflection context) — its only job is to push the real payload past the
/// WAF's inspection window. Shared by the encoder and the detection probe so
/// both agree on the exact prefix.
pub(crate) fn waf_window_pad() -> String {
    "A".repeat(WAF_WINDOW_PAD_LEN)
}

/// Known pre-encoding types.
/// Using an enum prevents typo bugs from stringly-typed matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreEncodingType {
    Base64,
    DoubleBase64,
    DoubleUrl,
    TripleUrl,
    /// Not an encoding, but a pre-injection payload transform that rides the
    /// same "transform before sending, match reflection against the original
    /// payload" rail: prepend a benign filler prefix so the real vector lands
    /// past a size-limited WAF inspection window (e.g. AWS WAF-style "only the
    /// first N bytes are scanned"). Set by `active_probe_param` when a
    /// window-overflow probe shows that special chars blocked at the value
    /// start reflect raw once pushed past the window. The prefix is inert
    /// (`waf_window_pad`), so the original payload still reflects unchanged and
    /// reflection/DOM matching is unaffected.
    WafWindowPad,
}

impl PreEncodingType {
    /// Parse from the string representation stored in `Param.pre_encoding`.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "base64" => Some(Self::Base64),
            "2base64" => Some(Self::DoubleBase64),
            "2url" => Some(Self::DoubleUrl),
            "3url" => Some(Self::TripleUrl),
            "wafpad" => Some(Self::WafWindowPad),
            _ => None,
        }
    }

    /// The canonical string name (for storing in `Param.pre_encoding`).
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Base64 => "base64",
            Self::DoubleBase64 => "2base64",
            Self::DoubleUrl => "2url",
            Self::TripleUrl => "3url",
            Self::WafWindowPad => "wafpad",
        }
    }

    /// Encode a payload according to this pre-encoding type.
    pub(crate) fn encode(&self, payload: &str) -> String {
        match self {
            Self::Base64 => base64_encode(payload),
            Self::DoubleBase64 => base64_encode(&base64_encode(payload)),
            Self::DoubleUrl => url_encode(&url_encode(payload)),
            Self::TripleUrl => url_encode(&url_encode(&url_encode(payload))),
            Self::WafWindowPad => format!("{}{}", waf_window_pad(), payload),
        }
    }
}

/// Apply pre-encoding to a payload based on the optional encoding string
/// stored in `Param.pre_encoding`.
///
/// Returns the encoded payload, or the original if no encoding is needed.
pub(crate) fn apply_pre_encoding(payload: &str, pre_encoding: &Option<String>) -> String {
    match pre_encoding.as_deref().and_then(PreEncodingType::parse) {
        Some(enc) => enc.encode(payload),
        None => payload.to_string(),
    }
}

/// Apply per-`Param` pre-encoding. Prefers the composable
/// `pre_encoding_pipeline` when set; otherwise falls back to the legacy
/// single-step `pre_encoding`. Pipeline failures (e.g. a stale JSON pointer)
/// degrade to the raw payload so probing can still attempt an injection.
pub(crate) fn apply_param_encoding(
    payload: &str,
    param: &crate::parameter_analysis::Param,
) -> String {
    if let Some(pipeline) = &param.pre_encoding_pipeline
        && !pipeline.is_empty()
    {
        return pipeline
            .apply(payload)
            .unwrap_or_else(|_| payload.to_string());
    }
    // A path segment gets one more percent-encoding layer on the wire than the
    // multi-URL encoding itself carries: `build_injected_url` escapes every
    // `%` in the segment to `%25`. Detection accounts for that (the path
    // probe URL-encodes N-1 times, then escapes `%`), so a `2url` path param is
    // one that decodes *two* layers in total. Applying the full N rounds here
    // and letting the segment escape add another sent N+1 layers — the app
    // then reflected `%3C…` instead of `<…`, and every payload for a param
    // just classified as multi-decoding missed.
    if param.location == crate::parameter_analysis::Location::Path
        && let Some(rounds) = match pre_encoding_type(&param.pre_encoding) {
            Some(PreEncodingType::DoubleUrl) => Some(1),
            Some(PreEncodingType::TripleUrl) => Some(2),
            _ => None,
        }
    {
        let mut encoded = payload.to_string();
        for _ in 0..rounds {
            encoded = url_encode(&encoded);
        }
        return encoded;
    }
    apply_pre_encoding(payload, &param.pre_encoding)
}

fn pre_encoding_type(pre_encoding: &Option<String>) -> Option<PreEncodingType> {
    pre_encoding.as_deref().and_then(PreEncodingType::parse)
}

/// A single pre-encoding probe: the encoding type and a function that
/// applies it to a raw payload.
pub(crate) type EncodingProbe = (PreEncodingType, fn(&str) -> String);

/// Encoding probes used during discovery to detect parameters that require
/// pre-encoding. Each probe has a type and its corresponding encode function.
///
/// Returns all known pre-encoding types in probe order (base64 variants first,
/// then URL variants).
pub(crate) fn encoding_probes() -> &'static [EncodingProbe] {
    &[
        (PreEncodingType::Base64, |s: &str| {
            PreEncodingType::Base64.encode(s)
        }),
        (PreEncodingType::DoubleBase64, |s: &str| {
            PreEncodingType::DoubleBase64.encode(s)
        }),
        (PreEncodingType::DoubleUrl, |s: &str| {
            PreEncodingType::DoubleUrl.encode(s)
        }),
        (PreEncodingType::TripleUrl, |s: &str| {
            PreEncodingType::TripleUrl.encode(s)
        }),
    ]
}

/// Multi-URL-decode probes used during active probing when `<` is invalid.
/// Returns (encoding type, number of extra URL-encode rounds needed).
///
/// For Query params: `append_pair()` adds one URL-encoding layer automatically,
/// so we encode (N-1) times for N-decode detection.
/// For Path params: `selective_path_segment_encode()` encodes `%` to `%25`
/// (one layer), so we also encode (N-1) extra times.
pub(crate) fn multi_url_decode_probes() -> &'static [(PreEncodingType, u8)] {
    &[
        (PreEncodingType::DoubleUrl, 1),
        (PreEncodingType::TripleUrl, 2),
    ]
}

#[cfg(test)]
mod tests;
