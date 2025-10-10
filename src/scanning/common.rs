use crate::cmd::scan::ScanArgs;
use crate::encoding::{double_url_encode, html_entity_encode, url_encode};
use crate::payload::XSS_PAYLOADS;

pub fn get_xss_payloads() -> &'static [&'static str] {
    XSS_PAYLOADS
}

pub fn load_custom_payloads(path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    Ok(content.lines().map(|s| s.to_string()).collect())
}

pub fn get_payloads(args: &ScanArgs) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut base_payloads = vec![];

    if args.only_custom_payload {
        if let Some(path) = &args.custom_payload {
            base_payloads.extend(load_custom_payloads(path)?);
        }
    } else {
        base_payloads.extend(XSS_PAYLOADS.iter().map(|s| s.to_string()));
        if !args.fast_scan {
            if let Some(path) = &args.custom_payload {
                base_payloads.extend(load_custom_payloads(path)?);
            }
        }
    }

    let mut payloads = vec![];
    for payload in base_payloads {
        payloads.push(payload.clone()); // Original
        payloads.push(url_encode(&payload)); // URL encoded
        payloads.push(html_entity_encode(&payload)); // HTML entity encoded
        payloads.push(double_url_encode(&payload)); // Double URL encoded
    }

    Ok(payloads)
}
