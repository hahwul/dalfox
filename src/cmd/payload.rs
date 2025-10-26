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
    long_about = "Selectors:\n  - event-handlers: list all DOM event handler attribute names (e.g., onclick, onmouseover)\n  - useful-tags: list useful HTML tag names often used in XSS contexts (e.g., script, img, svg)\n  - payloadbox: fetch and print remote XSS payloads from PayloadBox\n  - portswigger: fetch and print remote XSS payloads from PortSwigger"
)]
pub struct PayloadArgs {
    #[arg(
        value_name = "SELECTOR",
        help = "Payload selector\nAvailable selectors:\n  - event-handlers\n  - useful-tags\n  - payloadbox\n  - portswigger",
        long_help = "Selector to enumerate payload resources.\nSupported selectors:\n  - event-handlers: print all DOM event handler attribute names (e.g., onclick, onmouseover)\n  - useful-tags: print useful HTML tag names used for XSS payloads (e.g., script, img, svg)\n  - payloadbox: fetch and print remote XSS payloads from PayloadBox\n  - portswigger: fetch and print remote XSS payloads from PortSwigger"
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
            println!("  dalfox payload portswigger\n");

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
