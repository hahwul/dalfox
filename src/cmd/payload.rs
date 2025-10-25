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
    long_about = "Selectors:\n  - event-handlers: list all DOM event handler attribute names (e.g., onclick, onmouseover)\n  - useful-tags: list useful HTML tag names often used in XSS contexts (e.g., script, img, svg)"
)]
pub struct PayloadArgs {
    #[arg(
        value_name = "SELECTOR",
        help = "Payload selector\nAvailable selectors:\n  - event-handlers\n  - useful-tags",
        long_help = "Selector to enumerate payload resources.\nSupported selectors:\n  - event-handlers: print all DOM event handler attribute names (e.g., onclick, onmouseover)\n  - useful-tags: print useful HTML tag names used for XSS payloads (e.g., script, img, svg)."
    )]
    pub selector: Option<String>,
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
        Some(other) => {
            eprintln!("Unknown selector: {}", other);
        }
        None => {
            // Provide a small, helpful summary rather than a no-op.
            let js_count = crate::payload::XSS_JAVASCRIPT_PAYLOADS.len();

            println!("Dalfox payload");
            println!("----------------");
            println!("Provide a selector to list payloads. Example:");
            println!("  dalfox payload event-handlers\n");

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
