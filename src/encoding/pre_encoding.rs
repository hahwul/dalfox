//! Centralized pre-encoding logic for parameters that require encoding
//! before injection (e.g., base64, double-base64, double/triple URL encoding).
//!
//! All pre-encoding application and probe generation lives here so that
//! discovery, active probing, reflection checking, and DOM verification
//! share a single source of truth.

use super::{base64_encode, url_encode};

/// Known pre-encoding types.
/// Using an enum prevents typo bugs from stringly-typed matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreEncodingType {
    Base64,
    DoubleBase64,
    DoubleUrl,
    TripleUrl,
}

impl PreEncodingType {
    /// Parse from the string representation stored in `Param.pre_encoding`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "base64" => Some(Self::Base64),
            "2base64" => Some(Self::DoubleBase64),
            "2url" => Some(Self::DoubleUrl),
            "3url" => Some(Self::TripleUrl),
            _ => None,
        }
    }

    /// The canonical string name (for storing in `Param.pre_encoding`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Base64 => "base64",
            Self::DoubleBase64 => "2base64",
            Self::DoubleUrl => "2url",
            Self::TripleUrl => "3url",
        }
    }

    /// Encode a payload according to this pre-encoding type.
    pub fn encode(&self, payload: &str) -> String {
        match self {
            Self::Base64 => base64_encode(payload),
            Self::DoubleBase64 => base64_encode(&base64_encode(payload)),
            Self::DoubleUrl => url_encode(&url_encode(payload)),
            Self::TripleUrl => url_encode(&url_encode(&url_encode(payload))),
        }
    }
}

/// Apply pre-encoding to a payload based on the optional encoding string
/// stored in `Param.pre_encoding`.
///
/// Returns the encoded payload, or the original if no encoding is needed.
pub fn apply_pre_encoding(payload: &str, pre_encoding: &Option<String>) -> String {
    match pre_encoding.as_deref().and_then(PreEncodingType::parse) {
        Some(enc) => enc.encode(payload),
        None => payload.to_string(),
    }
}

/// Encoding probes used during discovery to detect parameters that require
/// pre-encoding. Each probe has a type and its corresponding encode function.
///
/// Returns all known pre-encoding types in probe order (base64 variants first,
/// then URL variants).
pub fn encoding_probes() -> &'static [(PreEncodingType, fn(&str) -> String)] {
    &[
        (PreEncodingType::Base64, |s: &str| PreEncodingType::Base64.encode(s)),
        (PreEncodingType::DoubleBase64, |s: &str| PreEncodingType::DoubleBase64.encode(s)),
        (PreEncodingType::DoubleUrl, |s: &str| PreEncodingType::DoubleUrl.encode(s)),
        (PreEncodingType::TripleUrl, |s: &str| PreEncodingType::TripleUrl.encode(s)),
    ]
}

/// Multi-URL-decode probes used during active probing when `<` is invalid.
/// Returns (encoding type, number of extra URL-encode rounds needed).
///
/// For Query params: `append_pair()` adds one URL-encoding layer automatically,
/// so we encode (N-1) times for N-decode detection.
/// For Path params: `selective_path_segment_encode()` encodes `%` to `%25`
/// (one layer), so we also encode (N-1) extra times.
pub fn multi_url_decode_probes() -> &'static [(PreEncodingType, u8)] {
    &[
        (PreEncodingType::DoubleUrl, 1),
        (PreEncodingType::TripleUrl, 2),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_pre_encoding_none() {
        assert_eq!(apply_pre_encoding("test", &None), "test");
        assert_eq!(apply_pre_encoding("test", &Some("unknown".to_string())), "test");
    }

    #[test]
    fn test_apply_pre_encoding_base64() {
        assert_eq!(
            apply_pre_encoding("<script>", &Some("base64".to_string())),
            base64_encode("<script>")
        );
    }

    #[test]
    fn test_apply_pre_encoding_2base64() {
        let expected = base64_encode(&base64_encode("<script>"));
        assert_eq!(
            apply_pre_encoding("<script>", &Some("2base64".to_string())),
            expected
        );
    }

    #[test]
    fn test_apply_pre_encoding_2url() {
        let expected = url_encode(&url_encode("<"));
        assert_eq!(
            apply_pre_encoding("<", &Some("2url".to_string())),
            expected
        );
    }

    #[test]
    fn test_apply_pre_encoding_3url() {
        let expected = url_encode(&url_encode(&url_encode("<")));
        assert_eq!(
            apply_pre_encoding("<", &Some("3url".to_string())),
            expected
        );
    }

    #[test]
    fn test_pre_encoding_type_roundtrip() {
        for enc in &[
            PreEncodingType::Base64,
            PreEncodingType::DoubleBase64,
            PreEncodingType::DoubleUrl,
            PreEncodingType::TripleUrl,
        ] {
            let s = enc.as_str();
            let parsed = PreEncodingType::parse(s).unwrap();
            assert_eq!(&parsed, enc);
        }
    }

    #[test]
    fn test_encoding_probes_cover_all_types() {
        let probes = encoding_probes();
        assert_eq!(probes.len(), 4);

        // Verify each probe encodes correctly
        let payload = "<test>";
        for (enc_type, encode_fn) in probes {
            assert_eq!(encode_fn(payload), enc_type.encode(payload));
        }
    }

    #[test]
    fn test_multi_url_decode_probes() {
        let probes = multi_url_decode_probes();
        assert_eq!(probes.len(), 2);
        assert_eq!(probes[0], (PreEncodingType::DoubleUrl, 1));
        assert_eq!(probes[1], (PreEncodingType::TripleUrl, 2));
    }

    #[test]
    fn test_encode_consistency() {
        // Ensure apply_pre_encoding matches PreEncodingType::encode
        let payload = "<script>alert(1)</script>";
        for enc in &[
            PreEncodingType::Base64,
            PreEncodingType::DoubleBase64,
            PreEncodingType::DoubleUrl,
            PreEncodingType::TripleUrl,
        ] {
            assert_eq!(
                apply_pre_encoding(payload, &Some(enc.as_str().to_string())),
                enc.encode(payload)
            );
        }
    }
}
