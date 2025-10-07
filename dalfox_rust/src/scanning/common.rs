use crate::payload::XSS_PAYLOADS;

pub fn get_xss_payloads() -> &'static [&'static str] {
    XSS_PAYLOADS
}
