use crate::cmd::scan::ScanArgs;
use crate::payload::XSS_PAYLOADS;

pub fn get_xss_payloads() -> &'static [&'static str] {
    XSS_PAYLOADS
}

pub fn load_custom_payloads(path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    Ok(content.lines().map(|s| s.to_string()).collect())
}

pub fn get_payloads(args: &ScanArgs) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut payloads = vec![];

    if args.only_custom_payload {
        if let Some(path) = &args.custom_payload {
            payloads.extend(load_custom_payloads(path)?);
        }
    } else {
        payloads.extend(XSS_PAYLOADS.iter().map(|s| s.to_string()));
        if !args.fast_scan {
            if let Some(path) = &args.custom_payload {
                payloads.extend(load_custom_payloads(path)?);
            }
        }
    }

    Ok(payloads)
}
