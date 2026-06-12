//! Correlation registry: maps a per-payload nonce (the 13 chars after the
//! 20-char correlation-id) back to the exact request that embedded it, so a
//! later out-of-band callback can be reported against its origin.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// What was injected for a given correlation nonce.
#[derive(Debug, Clone, Default)]
pub struct InjectionRecord {
    pub target_url: String,
    pub param: String,
    /// Wire location understood by `generate_poc`: `"Query"`, `"Body"`,
    /// `"Header"` (cookies fold here too). Empty when unknown.
    pub location: String,
    pub payload: String,
    pub method: String,
}

/// Thread-safe `nonce -> InjectionRecord` map shared between the injection
/// passes (writers) and the OOB poller (reader).
#[derive(Default)]
pub struct CorrelationRegistry {
    inner: Mutex<HashMap<String, InjectionRecord>>,
}

impl CorrelationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, nonce: String, rec: InjectionRecord) {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(nonce, rec);
    }

    pub fn lookup(&self, nonce: &str) -> Option<InjectionRecord> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(nonce)
            .cloned()
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_lookup() {
        let reg = CorrelationRegistry::new();
        assert!(reg.is_empty());
        reg.record(
            "abc1234567890".to_string(),
            InjectionRecord {
                target_url: "https://t/?q=1".to_string(),
                param: "q".to_string(),
                location: "Query".to_string(),
                payload: "\"'><script src=//x></script>".to_string(),
                method: "GET".to_string(),
            },
        );
        assert_eq!(reg.len(), 1);
        let got = reg.lookup("abc1234567890").expect("present");
        assert_eq!(got.param, "q");
        assert_eq!(got.location, "Query");
        assert!(reg.lookup("missing").is_none());
    }
}
