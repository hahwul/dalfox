//! Mining: collapse. See module docs in `mod.rs`.

use super::*;

const EWMA_ALPHA: f64 = 0.30; // smoothing factor for exponential weighted moving average
const EWMA_START_VALUE: f64 = 0.0;
pub(super) const COLLAPSE_EWMA_THRESHOLD: f64 = 0.85; // if sustained EWMA reflection ratio >= 85%
const COLLAPSE_MIN_ATTEMPTS: usize = 15; // need at least this many attempts before collapsing
const COLLAPSE_MIN_REFLECTIONS: usize = 5; // and at least this many reflections

/// Number of random sentinel param names probed up-front to detect
/// "reflect-everything" pages. Three is enough to make the false-positive
/// rate negligible while keeping the ceiling cost low (≤ 3 wasted requests).
pub(super) const SENTINEL_PROBE_COUNT: usize = 3;

/// Safety cap on DOM-extracted candidate parameter names probed by
/// [`probe_response_id_params`]. A hostile/huge response body (up to the 16 MiB
/// `read_body` cap) packed with distinct `<input id=…>` / `name=…` attributes
/// can yield ~10^6 unique candidates; without a cap each became a spawned probe
/// task (and an outbound request), scaling memory and request fan-out with the
/// attacker-controlled body. Real pages have at most a few hundred distinct
/// field names, so this ceiling is generous; truncation is surfaced as a warning.
pub(super) const MAX_DOM_MINING_PARAMS: usize = 4096;

/// Cap a DOM-extracted candidate-name set to [`MAX_DOM_MINING_PARAMS`]. Returns
/// the (possibly truncated) names plus `Some(original_len)` when truncation
/// occurred (so the caller can warn), or `None` when already under the cap.
/// Extracted so the boundary (`len == cap` not truncated, `len == cap + 1`
/// truncated) is unit-testable without standing up a giant HTML body.
pub(super) fn cap_dom_params(mut names: Vec<String>) -> (Vec<String>, Option<usize>) {
    let original = names.len();
    if original > MAX_DOM_MINING_PARAMS {
        names.truncate(MAX_DOM_MINING_PARAMS);
        (names, Some(original))
    } else {
        (names, None)
    }
}

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
pub(super) async fn pre_collapse_query_probe(client: &reqwest::Client, target: &Target) -> Option<String> {
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
        let resp = crate::utils::http::send_counted(req).await.ok()?;
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

/// Identity of a parameter *slot*, used to tell the params a mining stage
/// inherited apart from the ones it mined itself. `Location` is not `Hash`, so
/// the key is built from its `Debug` rendering — the same shape
/// `discovery::dedupe_reflection_params` uses.
fn param_slot_key(p: &Param) -> String {
    format!("{}|{:?}", p.name, p.location)
}

/// Snapshot the parameter slots already present before a mining stage starts.
///
/// Mining stages run sequentially (see [`mine_parameters`]), so this is a
/// stable "everything Stage 1 discovery — or an earlier mining stage — already
/// found" set, and a later collapse can subtract from it safely.
pub(super) async fn snapshot_param_slots(
    reflection_params: &Arc<Mutex<Vec<Param>>>,
) -> std::collections::HashSet<String> {
    reflection_params
        .lock()
        .await
        .iter()
        .map(param_slot_key)
        .collect()
}

/// Build the synthetic `any` param standing in for "this target echoes
/// arbitrary parameter names at `location`".
///
/// Metadata comes from whichever sample the caller has: the response body that
/// proved arbitrary names reflect (sentinel path), or one of the params the
/// stage mined before collapsing (EWMA path). Both describe how an *arbitrary*
/// name behaves here, which is what `any` represents. The params the target
/// actually carries are deliberately not used as the sample — their measured
/// specials belong to them, and copying those onto `any` produced findings that
/// reported one parameter's evidence under another's name.
pub(super) fn make_any_param(
    location: Location,
    response_text: Option<&str>,
    mined_sample: Option<&Param>,
) -> Param {
    let mut param = Param {
        injection_context: Some(InjectionContext::Html(None)),
        ..Param::new(
            "any".to_string(),
            crate::scanning::markers::bracketed_marker().to_string(),
            location,
        )
    };
    if let Some(text) = response_text {
        param = param.with_reflection_analysis(text);
    } else if let Some(sample) = mined_sample {
        param.value = sample.value.clone();
        param.injection_context = sample.injection_context.clone();
        param.valid_specials = sample.valid_specials.clone();
        param.invalid_specials = sample.invalid_specials.clone();
        param.js_breakout = sample.js_breakout.clone();
    }
    param
}

/// Collapse the params *this mining stage itself discovered* at `location`
/// into the single synthetic `any` param, leaving everything else untouched.
///
/// Collapse is a cost control. Once a target is known to echo arbitrary
/// parameter names, walking the rest of the wordlist only manufactures
/// injection points that all behave identically, and each one costs a full
/// Stage 3-6 payload run. Dropping *those* is the point of the mechanism.
///
/// Dropping the parameters the target actually carries is not. Those come from
/// Stage 1 discovery — the URL query string, form fields, headers — and were
/// confirmed to reflect before mining ever ran. Earlier revisions cleared every
/// param at `location` regardless of origin, so on any page that echoes its
/// whole query string (a debug endpoint, a framework error page that dumps
/// `request.query_params`) the genuinely vulnerable parameter was deleted
/// before Stage 3 ever saw it: the scan then reported a POC against `any` — a
/// parameter the application does not have — and missed the real one entirely.
/// `preexisting` is the guard against that, and it is why every caller must
/// snapshot with [`snapshot_param_slots`] before it starts pushing.
pub(super) async fn collapse_mined_params(
    reflection_params: &Arc<Mutex<Vec<Param>>>,
    preexisting: &std::collections::HashSet<String>,
    location: Location,
    response_text: Option<&str>,
) {
    let mut guard = reflection_params.lock().await;
    let mut mined_sample: Option<Param> = None;
    guard.retain(|p| {
        if p.location != location || preexisting.contains(&param_slot_key(p)) {
            return true;
        }
        if mined_sample.is_none() {
            mined_sample = Some(p.clone());
        }
        false
    });
    // Don't add a second `any` to a slot that already has one. That covers the
    // synthetic left by an earlier stage collapsing the same location, and —
    // more importantly — a target that genuinely carries a parameter called
    // `any`: it is a real, discovered param and overwriting it with the
    // synthetic stand-in would reintroduce exactly the data loss this function
    // exists to prevent.
    if !guard
        .iter()
        .any(|p| p.location == location && p.name == "any")
    {
        guard.push(make_any_param(
            location,
            response_text,
            mined_sample.as_ref(),
        ));
    }
}

#[derive(Debug)]
pub(super) struct MiningSampleStats {
    pub(super) attempts: usize,
    pub(super) reflections: usize,
    pub(super) ewma_ratio: f64,
    pub(super) collapsed: bool,
}

impl MiningSampleStats {
    pub(super) fn new() -> Self {
        Self {
            attempts: 0,
            reflections: 0,
            ewma_ratio: EWMA_START_VALUE,
            collapsed: false,
        }
    }
    pub(super) fn record_attempt(&mut self) {
        self.attempts += 1;
    }
    pub(super) fn record_reflection(&mut self) {
        self.reflections += 1;
        let instant = 1.0; // this attempt reflected
        self.update_ewma(instant);
    }
    pub(super) fn record_non_reflection(&mut self) {
        let instant = 0.0;
        self.update_ewma(instant);
    }
    fn update_ewma(&mut self, instant: f64) {
        self.ewma_ratio = EWMA_ALPHA * instant + (1.0 - EWMA_ALPHA) * self.ewma_ratio;
    }
    pub(super) fn should_collapse(&self) -> bool {
        !self.collapsed
            && self.attempts >= COLLAPSE_MIN_ATTEMPTS
            && self.reflections >= COLLAPSE_MIN_REFLECTIONS
            && self.ewma_ratio >= COLLAPSE_EWMA_THRESHOLD
    }
}
