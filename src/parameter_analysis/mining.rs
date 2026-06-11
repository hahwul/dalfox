//! # Stage 2: Mining
//!
//! Discovers additional parameters by analyzing HTML forms, JavaScript source,
//! dictionary wordlists, and GF-pattern lists — then probes each for reflection.
//!
//! **Input:** `Target` + `ScanArgs` + the initial `reflection_params` from Stage 1.
//!
//! **Output:** Extends the shared `reflection_params` list with newly discovered
//! `Param` entries that reflect. Each carries the same naive `valid_specials`,
//! `invalid_specials`, and `injection_context` as Stage 1 output.
//!
//! **Side effects:** HTTP requests for DOM/dict/GF mining probes. Uses EWMA-based
//! collapse detection to short-circuit when a target reflects everything
//! (sustained ≥85% reflection rate after ≥15 attempts). Filters out 5xx
//! responses to avoid false positives from debug/error pages.
//!
//! **Skippable via:** `--skip-mining`, `--skip-mining-dict`, `--skip-mining-dom`.

use crate::cmd::scan::ScanArgs;
use crate::parameter_analysis::{DelimiterType, InjectionContext, Location, Param};
use crate::payload::mining::GF_PATTERNS_PARAMS;
use crate::target_parser::Target;
use crate::utils::shimmer::ShimmerSpinner;
use scraper;
use std::sync::Arc;

use tokio::sync::{Mutex, Semaphore};
use tokio::time::{Duration, sleep};
use url::form_urlencoded;

use crate::scanning::selectors;

const EWMA_ALPHA: f64 = 0.30; // smoothing factor for exponential weighted moving average
const EWMA_START_VALUE: f64 = 0.0;
const COLLAPSE_EWMA_THRESHOLD: f64 = 0.85; // if sustained EWMA reflection ratio >= 85%
const COLLAPSE_MIN_ATTEMPTS: usize = 15; // need at least this many attempts before collapsing
const COLLAPSE_MIN_REFLECTIONS: usize = 5; // and at least this many reflections

/// Number of random sentinel param names probed up-front to detect
/// "reflect-everything" pages. Three is enough to make the false-positive
/// rate negligible while keeping the ceiling cost low (≤ 3 wasted requests).
const SENTINEL_PROBE_COUNT: usize = 3;

/// Sentinel parameter names — random-looking, namespace-prefixed strings
/// that should never collide with real params on a normal application.
/// If every one of these reflects, the page is echoing arbitrary input
/// and there's no point iterating a wordlist.
const SENTINEL_QUERY_NAMES: &[&str] = &[
    "dlfx_sentinel_q_8a3f",
    "dlfx_canary_b27z_p1",
    "dlfx_probe_xx9k_z2",
];

/// Run sentinel probes against the target by injecting the marker into a
/// query parameter named `name` and checking whether the response body
/// (or redirect Location header) echoes the marker. Returns the first
/// response body when every sentinel reflects, or `None` as soon as any
/// sentinel fails to reflect — `None` is the "this page is fine, run the
/// wordlist normally" signal.
async fn pre_collapse_query_probe(client: &reqwest::Client, target: &Target) -> Option<String> {
    let marker = crate::scanning::markers::bracketed_marker();
    let mut first_text: Option<String> = None;
    for name in SENTINEL_QUERY_NAMES.iter().take(SENTINEL_PROBE_COUNT) {
        let mut url = target.url.clone();
        url.query_pairs_mut().append_pair(name, marker);
        let req = crate::utils::build_request(
            client,
            target,
            target.parse_method(),
            url,
            target.data.clone(),
        );
        crate::record_outbound_request().await;
        let resp = req.send().await.ok()?;
        let location_has_marker = resp.status().is_redirection()
            && resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|loc| loc.contains(marker));
        let text = crate::utils::http::read_body(resp).await.ok()?;
        if !location_has_marker && !text.contains(marker) {
            return None;
        }
        if first_text.is_none() {
            first_text = Some(text);
        }
    }
    first_text
}

/// Build the synthetic "any" Query param used as the lone discovered
/// param when sentinel collapse fires. Mirrors the post-collapse path
/// at the end of `probe_dictionary_params`.
fn make_any_query_param(text: &str) -> Param {
    let context = detect_injection_context(text);
    let (valid, invalid) = crate::parameter_analysis::classify_special_chars(text);
    Param {
        name: "any".to_string(),
        value: crate::scanning::markers::bracketed_marker().to_string(),
        location: Location::Query,
        injection_context: Some(context),
        valid_specials: Some(valid),
        invalid_specials: Some(invalid),
        pre_encoding: None,
        pre_encoding_pipeline: None,
        wire_name: None,
        form_action_url: None,
        form_origin_url: None,
        framework_sink: None,
        escaped_specials: None,
        js_breakout: detect_js_breakout(text),
    }
}

/// Replace every `Query`-located param in `reflection_params` with a single
/// synthetic `any` param. Non-Query params (Body, Header, Path, JsonBody,
/// Cookie, Fragment) are preserved. Mirrors the EWMA post-processing path
/// so sentinel collapse and EWMA collapse produce identical downstream
/// state — Stage 3-6 sees one Query injection point regardless of which
/// route triggered the collapse.
async fn collapse_to_any_query_param(
    reflection_params: Arc<Mutex<Vec<Param>>>,
    response_text: &str,
) {
    let mut guard = reflection_params.lock().await;
    let non_query: Vec<Param> = guard
        .iter()
        .filter(|p| !matches!(p.location, Location::Query))
        .cloned()
        .collect();
    guard.clear();
    guard.extend(non_query);
    guard.push(make_any_query_param(response_text));
}

#[derive(Debug)]
struct MiningSampleStats {
    attempts: usize,
    reflections: usize,
    ewma_ratio: f64,
    collapsed: bool,
}

impl MiningSampleStats {
    fn new() -> Self {
        Self {
            attempts: 0,
            reflections: 0,
            ewma_ratio: EWMA_START_VALUE,
            collapsed: false,
        }
    }
    fn record_attempt(&mut self) {
        self.attempts += 1;
    }
    fn record_reflection(&mut self) {
        self.reflections += 1;
        let instant = 1.0; // this attempt reflected
        self.update_ewma(instant);
    }
    fn record_non_reflection(&mut self) {
        let instant = 0.0;
        self.update_ewma(instant);
    }
    fn update_ewma(&mut self, instant: f64) {
        self.ewma_ratio = EWMA_ALPHA * instant + (1.0 - EWMA_ALPHA) * self.ewma_ratio;
    }
    fn should_collapse(&self) -> bool {
        !self.collapsed
            && self.attempts >= COLLAPSE_MIN_ATTEMPTS
            && self.reflections >= COLLAPSE_MIN_REFLECTIONS
            && self.ewma_ratio >= COLLAPSE_EWMA_THRESHOLD
    }
}

pub fn detect_injection_context(text: &str) -> InjectionContext {
    // Inner marker survives every reflection form classified by
    // `classify_probe_reflection` (Full / PrefixOnly / SuffixOnly /
    // InnerOnly), so it's the most reliable anchor for context inference
    // on bracketed probes. Fall back to the open marker for callers that
    // still inject it directly (older tests, legacy probe sites).
    let inner = crate::scanning::markers::inner_marker();
    if text.contains(inner) {
        return detect_injection_context_with_marker(text, inner);
    }
    let open = crate::scanning::markers::open_marker();
    detect_injection_context_with_marker(text, open)
}

/// Compute the exact JS breakout closer (issue #1073 follow-up) from the
/// *observed* response when a probe marker reflects inside an inline `<script>`
/// body. Returns the minimal closer sequence — produced by
/// [`crate::payload::js_breakout::compute_js_breakout`] over the real script
/// source from the enclosing `<script>` content start up to the reflection
/// point — that escapes the open string and every unbalanced `([{` so a
/// following `;<payload>//` reaches executable statement position.
///
/// This is the per-parameter carrier the synthesis layer consumes to emit a
/// breakout matched to the *site's actual nesting* rather than only the fixed
/// depth-0–3 catalog. Returns `None` when the marker is not inside an inline
/// `<script>` body (the script-tag requirement scopes this to script contexts,
/// not event-handler/attribute JS), when no marker is present, or when the
/// observed prefix already sits at statement position (empty closer) — every
/// such case falls back to the fixed catalog, so the result is strictly
/// additive and never removes coverage.
///
/// Mirrors `detect_injection_context`'s marker selection (inner marker
/// preferred, open marker fallback) so the closer is computed for the same
/// reflection the context classifier anchored on. Uses raw response slicing
/// (inline `<script>` content is CDATA-like, not HTML-entity-decoded by the
/// browser), so the prefix matches the JS source the browser actually parses.
pub fn detect_js_breakout(text: &str) -> Option<String> {
    let inner = crate::scanning::markers::inner_marker();
    let marker = if text.contains(inner) {
        inner
    } else {
        crate::scanning::markers::open_marker()
    };
    detect_js_breakout_with_marker(text, marker)
}

/// `detect_js_breakout` with a caller-supplied marker string (mirrors
/// `detect_injection_context_with_marker`). Used by probes that inject a
/// non-standard marker, e.g. the numeric-only discovery probe.
pub fn detect_js_breakout_with_marker(text: &str, marker: &str) -> Option<String> {
    let mp = text.find(marker)?;
    // Find the enclosing inline `<script …>` opening tag before the reflection.
    // `<script` (case-insensitive) never matches a closing `</script>` tag (the
    // char after `<` is `/`, not `s`), so `rfind` lands on a real opener.
    let lower_before = text[..mp].to_ascii_lowercase();
    let open_tag = lower_before.rfind("<script")?;
    // Script content begins just after the `>` that ends the opening tag.
    let gt = text[open_tag..mp].find('>')?;
    let content_start = open_tag + gt + 1;
    let prefix = &text[content_start..mp];
    // Guard the multi-`<script>` edge: if a `</script>` closes between this
    // opener and the marker, the marker isn't inside this script body — bail to
    // the fixed catalog rather than computing a bogus closer.
    if prefix.to_ascii_lowercase().contains("</script") {
        return None;
    }
    let closer = crate::payload::js_breakout::compute_js_breakout(prefix);
    // An empty closer means the prefix already sits at statement position; the
    // raw-JS catalog templates handle that, so carry nothing.
    if closer.is_empty() {
        None
    } else {
        Some(closer)
    }
}

/// Like `detect_injection_context` but uses a caller-supplied marker string.
/// Useful for probes that don't use the standard alphanumeric marker (e.g. numeric-only probes).
pub fn detect_injection_context_with_marker(text: &str, marker: &str) -> InjectionContext {
    if !text.contains(marker) {
        return InjectionContext::Html(None);
    }

    // Fast comment check using raw HTML when available
    if let (Some(cs), Some(ce)) = (text.find("<!--"), text.find("-->"))
        && let Some(mp) = text.find(marker)
        && cs < mp
        && mp < ce
    {
        return InjectionContext::Html(Some(DelimiterType::Comment));
    }

    // Parse HTML and locate marker via element text/attributes/script
    let document = scraper::Html::parse_document(text);

    // Heuristic to infer surrounding quote delimiter around the first marker.
    // Picks the *closest* opening quote before the marker (the one that
    // actually contains it). Includes backtick template literals so a marker
    // reflected inside `` `…` `` is reported as Backtick rather than falling
    // back to None — the breakout payload (`${…}`) is different from `'/`"`.
    fn infer_quote_delimiter(text: &str, marker: &str) -> Option<DelimiterType> {
        let pos = text.find(marker)?;
        let before = &text[..pos];
        let after = &text[pos + marker.len()..];

        let candidates: [(char, DelimiterType); 3] = [
            ('"', DelimiterType::DoubleQuote),
            ('\'', DelimiterType::SingleQuote),
            ('`', DelimiterType::Backtick),
        ];

        let (qch, delim) = candidates
            .iter()
            .filter_map(|(c, d)| before.rfind(*c).map(|p| (*c, d.clone(), p)))
            .max_by_key(|(_, _, p)| *p)
            .map(|(c, d, _)| (c, d))?;

        if after.find(qch).is_some() {
            return Some(delim);
        }
        None
    }

    fn is_url_like_attribute(name: &str) -> bool {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "src" | "href" | "xlink:href" | "data" | "action" | "formaction" | "poster"
        )
    }

    // 1) JavaScript context: marker appears in any <script> text
    {
        let sel = selectors::script();
        for el in document.select(sel) {
            let s = el.text().fold(String::new(), |mut acc, t| {
                acc.push_str(t);
                acc
            });
            if s.contains(marker) {
                let delim = infer_quote_delimiter(text, marker);
                return InjectionContext::Javascript(delim);
            }
        }
    }

    // 1b) CSS context: marker appears in any <style> text
    {
        let sel = selectors::style();
        for el in document.select(sel) {
            let s = el.text().fold(String::new(), |mut acc, t| {
                acc.push_str(t);
                acc
            });
            if s.contains(marker) {
                let delim = infer_quote_delimiter(text, marker);
                return InjectionContext::Css(delim);
            }
        }
    }

    // 2) Attribute context: marker in any attribute value.
    //
    // Event-handler attributes (`onload`, `onerror`, `onclick`, …) hold
    // JavaScript source that the browser feeds into an event handler
    // function — escaping out of the surrounding string literal yields
    // a JS-context XSS, not an HTML one. Classifying these as plain
    // `Attribute(delim)` makes the payload generator emit HTML tag
    // breakouts (`'><svg…>`) that get serialised as inert HTML inside
    // the handler's string. JS-breakout payloads (`',alert(1),'`) are
    // the right strategy, so route on*-attributes through the
    // `Javascript(delim)` branch.
    fn is_event_handler_attribute(name: &str) -> bool {
        let n = name.to_ascii_lowercase();
        n.starts_with("on") && n.len() > 2
    }
    {
        let any = selectors::universal();
        for el in document.select(any) {
            for (name, v) in el.value().attrs() {
                if v.contains(marker) {
                    let delim = infer_quote_delimiter(text, marker);
                    if is_event_handler_attribute(name) {
                        return InjectionContext::Javascript(delim);
                    }
                    return if is_url_like_attribute(name) {
                        InjectionContext::AttributeUrl(delim)
                    } else {
                        InjectionContext::Attribute(delim)
                    };
                }
            }
            // Marker landed *as* an attribute name (not a value). Example:
            //   <div id='x' MARKER>
            // Scraper parses MARKER as a boolean attribute with empty value,
            // so the value-side scan above misses it. This is the "free
            // attribute slot inside an existing tag" position — HTML-tag
            // breakouts (`<svg…>`) just become more attribute names, but
            // bare event handlers (`onmouseover=alert(1)`) execute as-is.
            // Classify as Attribute(None) so the payload generator emits
            // the unquoted-attribute branch (event handlers + protocols).
            for (name, _v) in el.value().attrs() {
                if name.contains(marker) {
                    return InjectionContext::Attribute(None);
                }
            }
        }
    }

    // 3) HTML text context: marker in non-script, non-style text nodes
    {
        let any = selectors::universal();
        for el in document.select(any) {
            let tag = el.value().name();
            if tag.eq_ignore_ascii_case("script") || tag.eq_ignore_ascii_case("style") {
                continue;
            }
            let s = el.text().fold(String::new(), |mut acc, t| {
                acc.push_str(t);
                acc
            });
            if s.contains(marker) {
                return InjectionContext::Html(None);
            }
        }
    }

    // Fallback to HTML
    InjectionContext::Html(None)
}

/// Identify a framework innerHTML-style sink the marker landed inside,
/// if any. Returns the directive/attribute name (`"v-html"`,
/// `"data-bind"`, `"ng-bind-html"`, …) so scanning can:
///   1. Upgrade the finding's `inject_type` to surface the sink class.
///   2. Treat HTML-entity-encoded reflections as exploitable — the
///      framework hands the entity-decoded value to `innerHTML` at
///      runtime, so `&lt;img onerror=…&gt;` still executes.
///
/// Conservative: only returns `Some(_)` when *every* marker occurrence
/// sits inside one of the recognised attributes. A single occurrence in
/// plain text content is enough to fall back to generic HTML payloads —
/// the regular `detect_injection_context` already covers that path.
///
/// Returns `None` when:
///   * the marker isn't present at all,
///   * any occurrence lives outside an HTML attribute (text node,
///     `<script>`, `<style>`), or
///   * the attribute name isn't in the recognised innerHTML-sink set.
pub fn detect_framework_html_sink(text: &str, marker: &str) -> Option<&'static str> {
    if marker.is_empty() || !text.contains(marker) {
        return None;
    }
    let document = scraper::Html::parse_document(text);
    let any = selectors::universal();
    let mut found: Option<&'static str> = None;
    for el in document.select(any) {
        for (name, value) in el.value().attrs() {
            if !value.contains(marker) {
                continue;
            }
            let sink = match name.to_ascii_lowercase().as_str() {
                "v-html" => Some("v-html"),
                "ng-bind-html" | "[innerhtml]" | "innerhtml" => Some("ng-bind-html"),
                // Knockout `data-bind` carries multiple clauses
                // (e.g. `data-bind="text: foo, html: bar"`). Only the
                // `html:` clause is an innerHTML sink, so require the
                // clause to live at a real binding boundary — start of
                // the attribute or after `,` / `;` / whitespace. A bare
                // `value.contains("html:")` false-positives on
                // `data-bind="text: 'html: link'"` and on any string
                // literal that happens to contain `html:`.
                "data-bind" if has_knockout_html_clause(value) => Some("data-bind"),
                _ => None,
            };
            match sink {
                Some(s) => match found {
                    Some(prev) if prev != s => return None,
                    _ => found = Some(s),
                },
                None => return None,
            }
        }
    }
    found
}

/// True when `value` (a Knockout `data-bind` attribute) has an `html:`
/// clause at a real binding boundary — start of the value, or after
/// `,` / `;` / whitespace that separates clauses. Skipping inside
/// quoted strings prevents the dominant false-positive shape:
/// `data-bind="text: 'html: link'"` where `html:` is just data.
fn has_knockout_html_clause(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    let mut at_clause_start = true;
    while i < bytes.len() {
        let b = bytes[i];
        // Track string literal context so an `html:` substring inside a
        // quoted clause value doesn't trigger.
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if b == b'"' || b == b'\'' {
            quote = Some(b);
            at_clause_start = false;
            i += 1;
            continue;
        }
        if b == b',' || b == b';' {
            at_clause_start = true;
            i += 1;
            continue;
        }
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if at_clause_start {
            // Check for `html` followed by whitespace + `:`. ASCII-only
            // attribute name, so direct byte comparison is fine.
            let remaining = &bytes[i..];
            if remaining.len() >= 4 && remaining[..4].eq_ignore_ascii_case(b"html") {
                let mut j = i + 4;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b':' {
                    return true;
                }
            }
            at_clause_start = false;
        }
        i += 1;
    }
    false
}

pub async fn probe_dictionary_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ShimmerSpinner>,
) {
    let arc_target = Arc::new(target.clone());
    let silence = args.silence;
    let client = target.build_client_or_default();

    // Resolve candidate parameter names (remote, file, or built-ins)
    let mut params: Vec<String> = Vec::new();
    let mut loaded = false;

    if !args.remote_wordlists.is_empty() {
        if let Err(e) = crate::payload::init_remote_wordlists(&args.remote_wordlists).await
            && !silence
        {
            eprintln!("Error initializing remote wordlists: {}", e);
        }
        if let Some(words) = crate::payload::get_remote_words()
            && !words.is_empty()
        {
            params = words.as_ref().clone();
            loaded = true;
        }
    }

    if !loaded && let Some(wordlist_path) = &args.mining_dict_word {
        match crate::utils::fs::read_bounded(
            std::path::Path::new(wordlist_path),
            crate::utils::fs::MAX_FILE_READ_BYTES,
            "parameter wordlist",
        ) {
            Ok(content) => {
                params = content
                    .lines()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                loaded = true;
            }
            Err(e) => {
                // Always surface on stderr — an unreadable
                // `--mining-dict-word` is a user-supplied input error and
                // silencing it (because server/MCP pass silence=true to
                // analyze_parameters) means the operator can't tell why
                // their custom dictionary did nothing. stderr never
                // pollutes the stdout JSON/JSONL payload anyway.
                eprintln!("Error reading wordlist file {}: {}", wordlist_path, e);
                let _ = silence; // intentionally unused now
                return;
            }
        }
    }

    if !loaded {
        params = GF_PATTERNS_PARAMS.iter().map(ToString::to_string).collect();
    }

    // Sentinel pre-probe: 3 unique random param names. If every one reflects,
    // the page echoes arbitrary input and the wordlist would just balloon
    // into Stage 3-6 cost. Replace it with a single "any" param and bail.
    // Skip when the wordlist is small enough that the pre-probe is more
    // expensive than just running it.
    if params.len() > SENTINEL_PROBE_COUNT * 5
        && let Some(text) = pre_collapse_query_probe(&client, target).await
    {
        if !silence {
            eprintln!(
                "[mining-collapse] sentinel pre-probe collapsed Query mining: \
                 every random param name reflected; using single 'any' param"
            );
        }
        collapse_to_any_query_param(reflection_params.clone(), &text).await;
        if let Some(ref pb) = pb {
            pb.finish_and_clear();
        }
        return;
    }

    if let Some(ref pb) = pb {
        pb.set_length(params.len() as u64);
        pb.set_message("Mining dictionary parameters");
    }

    // EWMA adaptive stats shared across tasks
    let stats = Arc::new(Mutex::new(MiningSampleStats::new()));

    // Each task returns Option<Param>; batch flush later
    let mut handles: Vec<tokio::task::JoinHandle<Option<Param>>> = Vec::new();

    // Chunked processing to reduce memory and allow early collapse exit
    const CHUNK_SIZE: usize = 500;
    'outer: for param_chunk in params.chunks(CHUNK_SIZE) {
        {
            let st = stats.lock().await;
            if st.collapsed {
                break 'outer;
            }
        }
        for param in param_chunk {
            {
                let st = stats.lock().await;
                if st.collapsed {
                    break 'outer;
                }
            }
            // original body below
            // Early collapse stop
            {
                let st = stats.lock().await;
                if st.collapsed {
                    break;
                }
            }
            // Skip if already discovered
            let exists = reflection_params
                .lock()
                .await
                .iter()
                .any(|p| p.name == *param);
            if exists {
                continue;
            }

            let mut url = target.url.clone();
            url.query_pairs_mut()
                .append_pair(param, crate::scanning::markers::bracketed_marker());

            let client_clone = client.clone();

            let data = target.data.clone();
            let parsed_method = target.parse_method();
            let target_clone = arc_target.clone();
            let delay = target.delay;
            let semaphore_clone = semaphore.clone();
            let param_name = param.clone();
            let pb_clone = pb.clone();
            let stats_clone = stats.clone();

            let handle = tokio::spawn(async move {
                let permit = semaphore_clone
                    .acquire()
                    .await
                    .expect("acquire semaphore permit");
                let request = crate::utils::build_request(
                    &client_clone,
                    &target_clone,
                    parsed_method,
                    url,
                    data.clone(),
                );

                crate::record_outbound_request().await;
                let resp = request.send().await;

                let mut discovered: Option<Param> = None;
                if let Ok(r) = resp {
                    // Skip server error responses (5xx) — debug error pages often
                    // reflect query params in stack traces, causing false positives.
                    let status = r.status();
                    if status.is_server_error() {
                        let mut st = stats_clone.lock().await;
                        st.record_attempt();
                        drop(permit);
                        if delay > 0 {
                            sleep(Duration::from_millis(delay)).await;
                        }
                        if let Some(ref pb) = pb_clone {
                            pb.inc(1);
                        }
                        return discovered;
                    }
                    // Check for redirect reflection: if the response is a 3xx redirect,
                    // the Location header may contain the reflected marker value.
                    let is_redirect = status.is_redirection();
                    let location_has_marker = if is_redirect {
                        r.headers()
                            .get("location")
                            .and_then(|v| v.to_str().ok())
                            .is_some_and(|loc| {
                                crate::scanning::markers::classify_probe_reflection(loc).detected()
                            })
                    } else {
                        false
                    };

                    if location_has_marker {
                        // Redirect context: marker reflected in Location header.
                        let mut st = stats_clone.lock().await;
                        st.record_attempt();
                        st.record_reflection();
                        if !st.collapsed {
                            discovered = Some(Param {
                                name: param_name.clone(),
                                value: crate::scanning::markers::bracketed_marker().to_string(),
                                location: crate::parameter_analysis::Location::Query,
                                injection_context: Some(
                                    crate::parameter_analysis::InjectionContext::AttributeUrl(None),
                                ),
                                valid_specials: None,
                                invalid_specials: None,
                                pre_encoding: None,
                                pre_encoding_pipeline: None,
                                wire_name: None,
                                form_action_url: None,
                                form_origin_url: None,
                                framework_sink: None,
                                escaped_specials: None,
                                js_breakout: None,
                            });
                            if !silence {
                                eprintln!(
                                    "Discovered parameter (redirect): {} (EWMA {:.2}, {}/{})",
                                    param_name, st.ewma_ratio, st.reflections, st.attempts
                                );
                            }
                            if st.should_collapse() {
                                st.collapsed = true;
                                if !silence {
                                    eprintln!(
                                        "[mining-collapse] High reflection EWMA {:.2} after {} attempts ({} reflections)",
                                        st.ewma_ratio, st.attempts, st.reflections
                                    );
                                }
                            }
                        }
                    } else if let Ok(text) = crate::utils::http::read_body(r).await {
                        let mut st = stats_clone.lock().await;
                        st.record_attempt();
                        if crate::scanning::markers::classify_probe_reflection(&text).detected() {
                            st.record_reflection();
                            if !st.collapsed {
                                let context = detect_injection_context(&text);
                                let (valid, invalid) =
                                    crate::parameter_analysis::classify_special_chars(&text);
                                discovered = Some(Param {
                                    name: param_name.clone(),
                                    value: crate::scanning::markers::bracketed_marker().to_string(),
                                    location: crate::parameter_analysis::Location::Query,
                                    injection_context: Some(context),
                                    valid_specials: Some(valid),
                                    invalid_specials: Some(invalid),
                                    pre_encoding: None,
                                    pre_encoding_pipeline: None,
                                    wire_name: None,
                                    form_action_url: None,
                                    form_origin_url: None,
                                    framework_sink: None,
                                    escaped_specials: None,
                                    js_breakout: detect_js_breakout(&text),
                                });
                                if !silence {
                                    eprintln!(
                                        "Discovered parameter: {} (EWMA {:.2}, {}/{})",
                                        param_name, st.ewma_ratio, st.reflections, st.attempts
                                    );
                                }
                                if st.should_collapse() {
                                    st.collapsed = true;
                                    if !silence {
                                        eprintln!(
                                            "[mining-collapse] High reflection EWMA {:.2} after {} attempts ({} reflections)",
                                            st.ewma_ratio, st.attempts, st.reflections
                                        );
                                    }
                                }
                            }
                        } else {
                            st.record_non_reflection();
                        }
                    }
                }

                if delay > 0 {
                    sleep(Duration::from_millis(delay)).await;
                }
                drop(permit);
                if let Some(ref pb) = pb_clone {
                    pb.inc(1);
                }
                discovered
            });

            handles.push(handle);
        }
    } // end chunk loop

    // Batch collect discovered parameters
    let mut batch: Vec<Param> = Vec::new();
    for h in handles {
        if let Ok(opt) = h.await
            && let Some(p) = opt
        {
            batch.push(p);
        }
    }

    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }

    // Apply collapse post-processing once (instead of inside tasks mutating aggressively).
    // Only collapse Query params — preserve params discovered via other channels
    // (Body from form discovery, Header from header discovery, Path, etc.).
    let st_final = stats.lock().await;
    if st_final.collapsed {
        let mut guard = reflection_params.lock().await;
        // Preserve non-Query params (Body, Header, Path, JsonBody, Cookie, etc.)
        let non_query: Vec<Param> = guard
            .iter()
            .filter(|p| !matches!(p.location, crate::parameter_analysis::Location::Query))
            .cloned()
            .collect();
        let preserved = guard
            .iter()
            .find(|p| matches!(p.location, crate::parameter_analysis::Location::Query))
            .cloned();
        guard.clear();
        guard.extend(non_query);
        if let Some(orig) = preserved {
            guard.push(Param {
                name: "any".to_string(),
                value: orig.value.clone(),
                location: crate::parameter_analysis::Location::Query,
                injection_context: orig.injection_context.clone(),
                valid_specials: orig.valid_specials.clone(),
                invalid_specials: orig.invalid_specials.clone(),
                pre_encoding: None,
                pre_encoding_pipeline: None,
                wire_name: None,
                form_action_url: None,
                form_origin_url: None,
                framework_sink: None,
                escaped_specials: None,
                js_breakout: orig.js_breakout.clone(),
            });
        } else {
            guard.push(Param {
                name: "any".to_string(),
                value: crate::scanning::markers::bracketed_marker().to_string(),
                location: crate::parameter_analysis::Location::Query,
                injection_context: Some(crate::parameter_analysis::InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
                pre_encoding: None,
                pre_encoding_pipeline: None,
                wire_name: None,
                form_action_url: None,
                form_origin_url: None,
                framework_sink: None,
                escaped_specials: None,
                js_breakout: None,
            });
        }
    }
}

pub async fn probe_body_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ShimmerSpinner>,
) {
    let arc_target = Arc::new(target.clone());
    let silence = args.silence;
    let client = target.build_client_or_default();

    if let Some(data) = &args.data {
        // Assume form data for now (application/x-www-form-urlencoded)
        let params: Vec<(String, String)> = form_urlencoded::parse(data.as_bytes())
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        if let Some(ref pb) = pb {
            pb.set_length(params.len() as u64);
            pb.set_message("Mining body parameters");
        }

        // Adaptive EWMA stats shared across tasks
        let stats = Arc::new(Mutex::new(MiningSampleStats::new()));

        // Spawn tasks returning Option<Param> for batching
        let mut handles: Vec<tokio::task::JoinHandle<Option<Param>>> = Vec::new();

        for (param_name, _) in params {
            // Early stop if collapsed
            {
                let st = stats.lock().await;
                if st.collapsed {
                    break;
                }
            }
            // Skip already discovered params
            let exists = reflection_params
                .lock()
                .await
                .iter()
                .any(|p| p.name == param_name);
            if exists {
                continue;
            }

            // Build mutated body with this param set to marker
            let new_data = form_urlencoded::parse(data.as_bytes())
                .map(|(k, v)| {
                    if k == param_name {
                        (k, crate::scanning::markers::bracketed_marker().to_string())
                    } else {
                        (k, v.to_string())
                    }
                })
                .collect::<Vec<_>>();
            let body = form_urlencoded::Serializer::new(String::new())
                .extend_pairs(new_data)
                .finish();

            let client_clone = client.clone();
            let url = target.url.clone();

            let parsed_method = reqwest::Method::POST;
            let target_clone = arc_target.clone();
            let delay = target.delay;
            let semaphore_clone = semaphore.clone();
            let param_name_cloned = param_name.clone();
            let pb_clone = pb.clone();
            let stats_clone = stats.clone();

            let handle = tokio::spawn(async move {
                let permit = semaphore_clone
                    .acquire()
                    .await
                    .expect("acquire semaphore permit");
                let m = parsed_method;
                let base =
                    crate::utils::build_request(&client_clone, &target_clone, m, url, Some(body));
                let overrides = vec![(
                    "Content-Type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                )];
                let request = crate::utils::apply_header_overrides(base, &overrides);

                crate::record_outbound_request().await;
                let resp = request.send().await;

                let mut discovered: Option<Param> = None;
                if let Ok(r) = resp
                    && let Ok(text) = crate::utils::http::read_body(r).await
                {
                    let mut st = stats_clone.lock().await;
                    st.record_attempt();
                    if crate::scanning::markers::classify_probe_reflection(&text).detected() {
                        st.record_reflection();
                        if !st.collapsed {
                            let context = detect_injection_context(&text);
                            let (valid, invalid) =
                                crate::parameter_analysis::classify_special_chars(&text);
                            discovered = Some(Param {
                                name: param_name_cloned.clone(),
                                value: crate::scanning::markers::bracketed_marker().to_string(),
                                location: Location::Body,
                                injection_context: Some(context),
                                valid_specials: Some(valid),
                                invalid_specials: Some(invalid),
                                pre_encoding: None,
                                pre_encoding_pipeline: None,
                                wire_name: None,
                                form_action_url: None,
                                form_origin_url: None,
                                framework_sink: None,
                                escaped_specials: None,
                                js_breakout: detect_js_breakout(&text),
                            });
                            if !silence {
                                eprintln!(
                                    "Discovered body param: {} (EWMA {:.2}, {}/{})",
                                    param_name_cloned, st.ewma_ratio, st.reflections, st.attempts
                                );
                            }
                            if st.should_collapse() {
                                st.collapsed = true;
                                if !silence {
                                    eprintln!(
                                        "[mining-collapse] Body mining collapsed at EWMA {:.2} after {} attempts ({} reflections)",
                                        st.ewma_ratio, st.attempts, st.reflections
                                    );
                                }
                            }
                        }
                    } else {
                        st.record_non_reflection();
                    }
                }

                if delay > 0 {
                    sleep(Duration::from_millis(delay)).await;
                }
                drop(permit);
                if let Some(ref pb) = pb_clone {
                    pb.inc(1);
                }
                discovered
            });

            handles.push(handle);
        }

        // Batch collect discovered params
        let mut batch: Vec<Param> = Vec::new();
        for h in handles {
            if let Ok(opt) = h.await
                && let Some(p) = opt
            {
                batch.push(p);
            }
        }
        if !batch.is_empty() {
            let mut guard = reflection_params.lock().await;
            guard.extend(batch);
        }

        // If collapsed after attempts, normalize Body params to single 'any' param.
        // Preserve non-Body params discovered via other channels.
        let st_final = stats.lock().await;
        if st_final.collapsed {
            let mut guard = reflection_params.lock().await;
            let non_body: Vec<Param> = guard
                .iter()
                .filter(|p| !matches!(p.location, Location::Body))
                .cloned()
                .collect();
            let preserved = guard
                .iter()
                .find(|p| matches!(p.location, Location::Body))
                .cloned();
            guard.clear();
            guard.extend(non_body);
            if let Some(orig) = preserved {
                guard.push(Param {
                    name: "any".to_string(),
                    value: orig.value.clone(),
                    location: Location::Body,
                    injection_context: orig.injection_context.clone(),
                    valid_specials: orig.valid_specials.clone(),
                    invalid_specials: orig.invalid_specials.clone(),
                    pre_encoding: None,
                    pre_encoding_pipeline: None,
                    wire_name: None,
                    form_action_url: None,
                    form_origin_url: None,
                    framework_sink: None,
                    escaped_specials: None,
                    js_breakout: orig.js_breakout.clone(),
                });
            } else {
                guard.push(Param {
                    name: "any".to_string(),
                    value: crate::scanning::markers::bracketed_marker().to_string(),
                    location: Location::Body,
                    injection_context: Some(crate::parameter_analysis::InjectionContext::Html(
                        None,
                    )),
                    valid_specials: None,
                    invalid_specials: None,
                    pre_encoding: None,
                    pre_encoding_pipeline: None,
                    wire_name: None,
                    form_action_url: None,
                    form_origin_url: None,
                    framework_sink: None,
                    escaped_specials: None,
                    js_breakout: None,
                });
            }
        }
    }
}

pub async fn probe_response_id_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ShimmerSpinner>,
) {
    let arc_target = Arc::new(target.clone());
    let silence = args.silence;
    let client = target.build_client_or_default();

    // First, get the HTML to find input ids and names
    let base_request = crate::utils::build_request(
        &client,
        target,
        target.parse_method(),
        target.url.clone(),
        target.data.clone(),
    );

    crate::record_outbound_request().await;
    let __resp = base_request.send().await;
    if let Ok(resp) = __resp
        && !resp.status().is_server_error()
        && let Ok(text) = crate::utils::http::read_body(resp).await
    {
        // Scope the scraper::Html (which is !Send) strictly to the owning
        // block so the compiler can prove it never crosses any of the
        // subsequent .await points. Extract owned String data, then drop
        // the document before hitting the async code below.
        let params_to_check: std::collections::HashSet<String> = {
            let document = scraper::Html::parse_document(&text);
            let selector = selectors::input_with_id_or_name();
            let mut set = std::collections::HashSet::new();
            for element in document.select(selector) {
                if let Some(id) = element.value().attr("id") {
                    set.insert(id.to_string());
                }
                if let Some(name) = element.value().attr("name") {
                    set.insert(name.to_string());
                }
            }
            set
        };

        // Sentinel pre-probe — same rationale as Query mining: a
        // reflect-everything page would mark every DOM-extracted name as
        // reflected and balloon downstream cost. Threshold matches Query
        // mining: only run when the candidate set exceeds the pre-probe
        // ceiling.
        if params_to_check.len() > SENTINEL_PROBE_COUNT * 5
            && let Some(text) = pre_collapse_query_probe(&client, target).await
        {
            if !silence {
                eprintln!(
                    "[mining-collapse] sentinel pre-probe collapsed DOM mining: \
                     every random param name reflected; using single 'any' param"
                );
            }
            collapse_to_any_query_param(reflection_params.clone(), &text).await;
            if let Some(ref pb) = pb {
                pb.finish_and_clear();
            }
            return;
        }

        if let Some(ref pb) = pb {
            pb.set_length(params_to_check.len() as u64);
            pb.set_message("Mining DOM parameters");
        }

        // Spawn tasks returning Option<Param> for batched collection
        let mut handles: Vec<tokio::task::JoinHandle<Option<Param>>> = Vec::new();
        let stats = Arc::new(Mutex::new(MiningSampleStats::new()));

        // Check each param for reflection
        for param in params_to_check {
            {
                let st = stats.lock().await;
                if st.collapsed {
                    break;
                }
            }
            let existing = reflection_params
                .lock()
                .await
                .iter()
                .any(|p| p.name == param);
            if existing {
                continue;
            }
            let mut url = target.url.clone();
            url.query_pairs_mut()
                .append_pair(&param, crate::scanning::markers::bracketed_marker());
            let client_clone = client.clone();

            let data = target.data.clone();
            let parsed_method = target.parse_method();
            let target_clone = arc_target.clone();
            let delay = target.delay;
            let semaphore_clone = semaphore.clone();
            let param = param.clone();
            let pb_clone = pb.clone();
            let stats_clone = stats.clone();

            let handle = tokio::spawn(async move {
                let permit = semaphore_clone
                    .acquire()
                    .await
                    .expect("acquire semaphore permit");
                let m = parsed_method;
                let request =
                    crate::utils::build_request(&client_clone, &target_clone, m, url, data.clone());
                // Prepare optional discovered Param container for batched return
                let mut discovered: Option<Param> = None;
                crate::record_outbound_request().await;
                let __resp = request.send().await;
                if let Ok(resp) = __resp {
                    // Skip 5xx error responses — debug pages often reflect params
                    if resp.status().is_server_error() {
                        let mut st = stats_clone.lock().await;
                        st.record_attempt();
                        drop(permit);
                        if delay > 0 {
                            sleep(Duration::from_millis(delay)).await;
                        }
                        if let Some(ref pb) = pb_clone {
                            pb.inc(1);
                        }
                        return discovered;
                    }
                    if let Ok(text) = crate::utils::http::read_body(resp).await {
                        let mut st = stats_clone.lock().await;
                        st.record_attempt();
                        if crate::scanning::markers::classify_probe_reflection(&text).detected() {
                            st.record_reflection();
                            if !st.collapsed {
                                let context = detect_injection_context(&text);
                                let (valid, invalid) =
                                    crate::parameter_analysis::classify_special_chars(&text);
                                // Store discovered Param for return (batched later)
                                discovered = Some(Param {
                                    name: param.clone(),
                                    value: crate::scanning::markers::bracketed_marker().to_string(),
                                    location: crate::parameter_analysis::Location::Query,
                                    injection_context: Some(context),
                                    valid_specials: Some(valid),
                                    invalid_specials: Some(invalid),
                                    pre_encoding: None,
                                    pre_encoding_pipeline: None,
                                    wire_name: None,
                                    form_action_url: None,
                                    form_origin_url: None,
                                    framework_sink: None,
                                    escaped_specials: None,
                                    js_breakout: detect_js_breakout(&text),
                                });
                                if !silence {
                                    eprintln!(
                                        "Discovered DOM param: {} (EWMA {:.2}, {}/{})",
                                        param, st.ewma_ratio, st.reflections, st.attempts
                                    );
                                }
                                if st.should_collapse() {
                                    st.collapsed = true;
                                    if !silence {
                                        eprintln!(
                                            "[mining-collapse] DOM mining collapsed at EWMA {:.2} after {} attempts ({} reflections)",
                                            st.ewma_ratio, st.attempts, st.reflections
                                        );
                                    }
                                }
                            }
                        } else {
                            st.record_non_reflection();
                        }
                    }
                }
                if delay > 0 {
                    sleep(Duration::from_millis(delay)).await;
                }
                drop(permit);
                if let Some(ref pb) = pb_clone {
                    pb.inc(1);
                }
                // Return discovered Param (if any) for batch processing
                discovered
            });
            handles.push(handle);
        }

        // Batch collect discovered DOM params
        let mut batch: Vec<Param> = Vec::new();
        for handle in handles {
            if let Ok(opt) = handle.await
                && let Some(p) = opt
            {
                batch.push(p);
            }
        }
        if !batch.is_empty() {
            let mut guard = reflection_params.lock().await;
            guard.extend(batch);
        }
        // Collapse post-processing (single 'any' param) if adaptive stats triggered it.
        // Preserve non-Query params discovered via other channels.
        let st_final = stats.lock().await;
        if st_final.collapsed {
            let mut guard = reflection_params.lock().await;
            let non_query: Vec<Param> = guard
                .iter()
                .filter(|p| !matches!(p.location, crate::parameter_analysis::Location::Query))
                .cloned()
                .collect();
            let preserved = guard
                .iter()
                .find(|p| matches!(p.location, crate::parameter_analysis::Location::Query))
                .cloned();
            guard.clear();
            guard.extend(non_query);
            if let Some(orig) = preserved {
                guard.push(Param {
                    name: "any".to_string(),
                    value: orig.value.clone(),
                    location: crate::parameter_analysis::Location::Query,
                    injection_context: orig.injection_context.clone(),
                    valid_specials: orig.valid_specials.clone(),
                    invalid_specials: orig.invalid_specials.clone(),
                    pre_encoding: None,
                    pre_encoding_pipeline: None,
                    wire_name: None,
                    form_action_url: None,
                    form_origin_url: None,
                    framework_sink: None,
                    escaped_specials: None,
                    js_breakout: orig.js_breakout.clone(),
                });
            } else {
                guard.push(Param {
                    name: "any".to_string(),
                    value: crate::scanning::markers::bracketed_marker().to_string(),
                    location: crate::parameter_analysis::Location::Query,
                    injection_context: Some(crate::parameter_analysis::InjectionContext::Html(
                        None,
                    )),
                    valid_specials: None,
                    invalid_specials: None,
                    pre_encoding: None,
                    pre_encoding_pipeline: None,
                    wire_name: None,
                    form_action_url: None,
                    form_origin_url: None,
                    framework_sink: None,
                    escaped_specials: None,
                    js_breakout: None,
                });
            }
        }
    }
}

pub async fn probe_json_body_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ShimmerSpinner>,
) {
    let arc_target = Arc::new(target.clone());
    let silence = args.silence;
    let client = target.build_client_or_default();

    // Detect JSON body from args.data; only proceed if it's a JSON object
    let base_json: serde_json::Value = match &args.data {
        Some(d) => match serde_json::from_str::<serde_json::Value>(d) {
            Ok(v) => v,
            Err(_) => return, // not JSON
        },
        None => return,
    };
    if !base_json.is_object() {
        return;
    }

    // Collect top-level keys to mutate
    let Some(obj) = base_json.as_object() else {
        return;
    };
    let keys: Vec<String> = obj.keys().cloned().collect();

    if let Some(ref pb) = pb {
        pb.set_length(keys.len() as u64);
        pb.set_message("Mining JSON body parameters");
    }

    // Adaptive EWMA stats shared across tasks
    let stats = Arc::new(Mutex::new(MiningSampleStats::new()));

    // Spawn tasks returning Option<Param> for batching
    let mut handles: Vec<tokio::task::JoinHandle<Option<Param>>> = Vec::new();

    for param_name in keys {
        {
            // Early collapse stop
            let st = stats.lock().await;
            if st.collapsed {
                break;
            }
        }
        // Skip if already discovered
        let exists = reflection_params
            .lock()
            .await
            .iter()
            .any(|p| p.name == param_name);
        if exists {
            continue;
        }

        let client_clone = client.clone();
        let url = target.url.clone();

        let parsed_method = reqwest::Method::POST;
        let target_clone = arc_target.clone();
        let delay = target.delay;
        let semaphore_clone = semaphore.clone();
        let param_name_cloned = param_name.clone();
        let pb_clone = pb.clone();
        let stats_clone = stats.clone();
        let base_json_clone = base_json.clone();

        let handle = tokio::spawn(async move {
            let permit = semaphore_clone
                .acquire()
                .await
                .expect("acquire semaphore permit");

            // Build mutated JSON with this key set to marker
            let mut root = base_json_clone;
            if let Some(map) = root.as_object_mut() {
                map.insert(
                    param_name_cloned.clone(),
                    serde_json::Value::String(
                        crate::scanning::markers::bracketed_marker().to_string(),
                    ),
                );
            } else {
                let mut map = serde_json::Map::new();
                map.insert(
                    param_name_cloned.clone(),
                    serde_json::Value::String(
                        crate::scanning::markers::bracketed_marker().to_string(),
                    ),
                );
                root = serde_json::Value::Object(map);
            }
            let body = serde_json::to_string(&root).unwrap_or_else(|_| {
                format!(
                    "{{\"{}\":\"{}\"}}",
                    param_name_cloned,
                    crate::scanning::markers::bracketed_marker()
                )
            });

            let base = crate::utils::build_request(
                &client_clone,
                &target_clone,
                parsed_method,
                url,
                Some(body),
            );
            let overrides = vec![("Content-Type".to_string(), "application/json".to_string())];
            let request = crate::utils::apply_header_overrides(base, &overrides);

            crate::record_outbound_request().await;
            let resp = request.send().await;

            let mut discovered: Option<Param> = None;
            if let Ok(r) = resp
                && let Ok(text) = crate::utils::http::read_body(r).await
            {
                let mut st = stats_clone.lock().await;
                st.record_attempt();
                if crate::scanning::markers::classify_probe_reflection(&text).detected() {
                    st.record_reflection();
                    if !st.collapsed {
                        let context = detect_injection_context(&text);
                        let (valid, invalid) =
                            crate::parameter_analysis::classify_special_chars(&text);
                        discovered = Some(Param {
                            name: param_name_cloned.clone(),
                            value: crate::scanning::markers::bracketed_marker().to_string(),
                            location: Location::JsonBody,
                            injection_context: Some(context),
                            valid_specials: Some(valid),
                            invalid_specials: Some(invalid),
                            pre_encoding: None,
                            pre_encoding_pipeline: None,
                            wire_name: None,
                            form_action_url: None,
                            form_origin_url: None,
                            framework_sink: None,
                            escaped_specials: None,
                            js_breakout: detect_js_breakout(&text),
                        });
                        if !silence {
                            eprintln!(
                                "Discovered JSON body param: {} (EWMA {:.2}, {}/{})",
                                param_name_cloned, st.ewma_ratio, st.reflections, st.attempts
                            );
                        }
                        if st.should_collapse() {
                            st.collapsed = true;
                            if !silence {
                                eprintln!(
                                    "[mining-collapse] JSON mining collapsed at EWMA {:.2} after {} attempts ({} reflections)",
                                    st.ewma_ratio, st.attempts, st.reflections
                                );
                            }
                        }
                    }
                } else {
                    st.record_non_reflection();
                }
            }

            if delay > 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            drop(permit);
            if let Some(ref pb) = pb_clone {
                pb.inc(1);
            }
            discovered
        });

        handles.push(handle);
    }

    // Batch collect discovered params
    let mut batch: Vec<Param> = Vec::new();
    for h in handles {
        if let Ok(opt) = h.await
            && let Some(p) = opt
        {
            batch.push(p);
        }
    }
    if !batch.is_empty() {
        let mut guard = reflection_params.lock().await;
        guard.extend(batch);
    }

    // Collapse normalization to single 'any' JSON param if triggered.
    // Preserve non-JsonBody params discovered via other channels.
    let st_final = stats.lock().await;
    if st_final.collapsed {
        let mut guard = reflection_params.lock().await;
        let non_json: Vec<Param> = guard
            .iter()
            .filter(|p| !matches!(p.location, Location::JsonBody))
            .cloned()
            .collect();
        let preserved = guard
            .iter()
            .find(|p| matches!(p.location, Location::JsonBody))
            .cloned();
        guard.clear();
        guard.extend(non_json);
        if let Some(orig) = preserved {
            guard.push(Param {
                name: "any".to_string(),
                value: orig.value.clone(),
                location: Location::JsonBody,
                injection_context: orig.injection_context.clone(),
                valid_specials: orig.valid_specials.clone(),
                invalid_specials: orig.invalid_specials.clone(),
                pre_encoding: None,
                pre_encoding_pipeline: None,
                wire_name: None,
                form_action_url: None,
                form_origin_url: None,
                framework_sink: None,
                escaped_specials: None,
                js_breakout: orig.js_breakout.clone(),
            });
        } else {
            guard.push(Param {
                name: "any".to_string(),
                value: crate::scanning::markers::bracketed_marker().to_string(),
                location: Location::JsonBody,
                injection_context: Some(crate::parameter_analysis::InjectionContext::Html(None)),
                valid_specials: None,
                invalid_specials: None,
                pre_encoding: None,
                pre_encoding_pipeline: None,
                wire_name: None,
                form_action_url: None,
                form_origin_url: None,
                framework_sink: None,
                escaped_specials: None,
                js_breakout: None,
            });
        }
    }
}

/// Seed multipart form-field params the operator named via `-p name:multipart`.
///
/// Like [`probe_body_params`], these come from explicit `-d` input rather than
/// discovery — without this, `MultipartBody` params were only ever seeded from
/// HTML `<form enctype=multipart/form-data>` discovery, so `-p file:multipart`
/// (a known multipart sink) had no entry point and was silently never tested.
/// Sends a real `multipart/form-data` probe and seeds the field as a
/// `MultipartBody` param when the marker reflects. No-op without both `-d` and
/// at least one `-p :multipart` spec.
pub async fn probe_multipart_params(
    target: &Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ShimmerSpinner>,
) {
    let Some(data) = &args.data else {
        return;
    };
    let wanted =
        crate::parameter_analysis::discovery::explicit_param_names(&args.param, "multipart");
    if wanted.is_empty() {
        return;
    }

    if let Some(ref pb) = pb {
        pb.set_length(wanted.len() as u64);
        pb.set_message("Probing multipart fields");
    }

    let pairs: Vec<(String, String)> = form_urlencoded::parse(data.as_bytes())
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let client = target.build_client_or_default();
    let marker = crate::scanning::markers::bracketed_marker();
    let silence = args.silence;

    let mut handles: Vec<tokio::task::JoinHandle<Option<Param>>> = Vec::new();
    for field in wanted {
        // Skip only if this name is already registered *as a multipart field*.
        // A same-named body/query param (e.g. `probe_body_params` seeding
        // `file` from the same `-d`) must not block the multipart slot —
        // `-p file:multipart` filters by location, so the body entry would be
        // dropped and we'd be left with nothing.
        let exists = reflection_params
            .lock()
            .await
            .iter()
            .any(|p| p.name == field && p.location == Location::MultipartBody);
        if exists {
            continue;
        }

        let client_clone = client.clone();
        let url = target.url.clone();
        let target_clone = Arc::new(target.clone());
        let semaphore_clone = semaphore.clone();
        let pairs_clone = pairs.clone();
        let field_name = field.clone();

        let handle = tokio::spawn(async move {
            let permit = semaphore_clone
                .acquire()
                .await
                .expect("acquire semaphore permit");
            let mut form = reqwest::multipart::Form::new();
            let mut placed = false;
            for (k, v) in &pairs_clone {
                if *k == field_name {
                    form = form.text(k.clone(), marker.to_string());
                    placed = true;
                } else {
                    form = form.text(k.clone(), v.clone());
                }
            }
            if !placed {
                form = form.text(field_name.clone(), marker.to_string());
            }

            let request = crate::utils::build_request(
                &client_clone,
                &target_clone,
                reqwest::Method::POST,
                url,
                None,
            )
            .multipart(form);
            crate::record_outbound_request().await;

            let mut discovered: Option<Param> = None;
            if let Ok(r) = request.send().await
                && let Ok(text) = crate::utils::http::read_body(r).await
                && crate::scanning::markers::classify_probe_reflection(&text).detected()
            {
                let context = detect_injection_context(&text);
                let (valid, invalid) = crate::parameter_analysis::classify_special_chars(&text);
                if !silence {
                    eprintln!("Discovered multipart field: {}", field_name);
                }
                discovered = Some(Param {
                    name: field_name,
                    value: marker.to_string(),
                    location: Location::MultipartBody,
                    injection_context: Some(context),
                    valid_specials: Some(valid),
                    invalid_specials: Some(invalid),
                    pre_encoding: None,
                    pre_encoding_pipeline: None,
                    wire_name: None,
                    form_action_url: None,
                    form_origin_url: None,
                    framework_sink: None,
                    escaped_specials: None,
                    js_breakout: detect_js_breakout(&text),
                });
            }
            drop(permit);
            discovered
        });
        handles.push(handle);
    }

    let mut batch: Vec<Param> = Vec::new();
    for handle in handles {
        if let Ok(Some(p)) = handle.await {
            batch.push(p);
        }
    }
    if !batch.is_empty() {
        reflection_params.lock().await.extend(batch);
    }
}

pub async fn mine_parameters(
    target: &mut Target,
    args: &ScanArgs,
    reflection_params: Arc<Mutex<Vec<Param>>>,
    semaphore: Arc<Semaphore>,
    pb: Option<ShimmerSpinner>,
) {
    // Body/JSON parameters supplied via `-d` are explicit user input, not
    // discovery. Seed them independent of the mining flags: query params are
    // seeded from the URL during the discovery stage, but body params have no
    // other entry point, so gating them behind mining drops the entire
    // POST/JSON body surface — even when `-p name:body` is given and even
    // under `--skip-mining` / `--skip-mining-dict`. (Both probes are no-ops
    // when `args.data` is None, so GET targets are unaffected.)
    probe_body_params(
        target,
        args,
        reflection_params.clone(),
        semaphore.clone(),
        pb.clone(),
    )
    .await;
    probe_json_body_params(
        target,
        args,
        reflection_params.clone(),
        semaphore.clone(),
        pb.clone(),
    )
    .await;
    probe_multipart_params(
        target,
        args,
        reflection_params.clone(),
        semaphore.clone(),
        pb.clone(),
    )
    .await;

    // Mining proper: discover parameters the user did NOT name.
    if !args.skip_mining {
        if !args.skip_mining_dict {
            probe_dictionary_params(
                target,
                args,
                reflection_params.clone(),
                semaphore.clone(),
                pb.clone(),
            )
            .await;
        }
        if !args.skip_mining_dom {
            probe_response_id_params(
                target,
                args,
                reflection_params.clone(),
                semaphore.clone(),
                pb.clone(),
            )
            .await;
        }
    }
}

#[cfg(test)]
mod tests;
