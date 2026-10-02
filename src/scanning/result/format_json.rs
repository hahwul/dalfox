//! `format_json` output serialization for [`Result`].
//!
//! One `impl Result` block per output format keeps format-specific work
//! isolated; the shared model and helpers live in the parent module.

use super::*;

impl Result {
    /// Convert this Result into a serde_json::Value honoring include_request/include_response flags.
    pub(crate) fn to_json_value(
        &self,
        include_request: bool,
        include_response: bool,
    ) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "type": self.result_type,
            "type_description": self.result_type.long_description(),
            "inject_type": self.inject_type,
            "method": self.method,
            "data": self.data,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence,
            "cwe": self.cwe,
            "severity": self.severity,
            "message_id": self.message_id,
            "message_str": self.message_str,
            "detection_method": self.detection_method.as_str()
        });
        if !self.location.is_empty()
            && let serde_json::Value::Object(ref mut map) = obj
        {
            map.insert(
                "location".to_string(),
                serde_json::Value::String(self.location.clone()),
            );
        }
        if let Some(is_new) = self.new_since_baseline
            && let serde_json::Value::Object(ref mut map) = obj
        {
            map.insert("new".to_string(), serde_json::Value::Bool(is_new));
        }
        if let Some(grade) = self.confidence
            && let serde_json::Value::Object(ref mut map) = obj
        {
            map.insert(
                "confidence".to_string(),
                serde_json::Value::String(grade.as_str().to_string()),
            );
            if !self.confidence_reason.is_empty() {
                map.insert(
                    "confidence_reason".to_string(),
                    serde_json::Value::String(self.confidence_reason.clone()),
                );
            }
        }
        if include_request
            && let Some(req) = &self.request
            && let serde_json::Value::Object(ref mut map) = obj
        {
            map.insert(
                "request".to_string(),
                serde_json::Value::String(req.clone()),
            );
        }
        if include_response
            && let Some(resp) = &self.response
            && let serde_json::Value::Object(ref mut map) = obj
        {
            map.insert(
                "response".to_string(),
                serde_json::Value::String(resp.clone()),
            );
        }
        obj
    }
}
