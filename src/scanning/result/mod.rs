use serde::{Deserialize, Serialize};
use std::fmt;

/// How much dalfox is willing to claim about a finding.
///
/// This is a **confidence** axis, not a detection-method one: `V` means "we
/// assert this is a vulnerability", `R` means "a signal we could not raise to
/// that claim — confirm it yourself". How a finding was produced is carried
/// separately by [`FindingMethod`], and its impact by `Result::severity`.
///
/// `A` predates that split and still answers the *method* question, which is
/// why users cannot tell where it sits on this scale (issue #1238). It is
/// scheduled to be absorbed: graded high-confidence AST findings become `V`,
/// the rest `R`, with `method == "ast"` preserving the distinction. Until then
/// [`Result::confidence`] reports the grade alongside the legacy tier.
///
/// Internal code uses descriptive variant names; serialization produces the
/// single-letter abbreviation for compact user-facing output and backward-
/// compatible JSON (`"V"`, `"A"`, `"R"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingType {
    /// Vulnerable — dalfox asserts the input is exploitable.
    #[serde(rename = "V")]
    Verified,
    /// AST-detected DOM XSS — identified via static JavaScript analysis.
    /// Method label, pending migration to the confidence axis.
    #[serde(rename = "A")]
    AstDetected,
    /// Reflected — the payload came back in the response, but its position was
    /// not confirmed exploitable. A signal, not a claim.
    #[serde(rename = "R")]
    Reflected,
    /// Informational — a non-exploitable observation, e.g. an outdated or
    /// known-vulnerable JavaScript library (CWE-1104). Not an XSS finding;
    /// excluded from XSS-only dedup/collapse logic.
    #[serde(rename = "I")]
    Informational,
}

impl FindingType {
    /// Short single-letter label used in compact output (POC lines, etc.).
    pub(crate) fn short(&self) -> &'static str {
        match self {
            FindingType::Verified => "V",
            FindingType::AstDetected => "A",
            FindingType::Reflected => "R",
            FindingType::Informational => "I",
        }
    }

    /// Human-readable descriptive name for logs and verbose output.
    ///
    /// `Verified` became `Vulnerable`: "verify" names an *act*, which is what
    /// made readers ask what dalfox had verified and with what — the answer
    /// ("we parsed the response") was never what the word implied. The new word
    /// states the claim instead.
    ///
    /// `Reflected` is deliberately left alone. It is still literally accurate:
    /// today `R` holds exactly the findings whose payload came back in the
    /// response. It stops being accurate only when the tier migration moves
    /// low-confidence AST flows into `R`, so the rename belongs to that release,
    /// not this one.
    #[cfg(test)]
    pub(crate) fn description(&self) -> &'static str {
        match self {
            FindingType::Verified => "Vulnerable",
            FindingType::AstDetected => "AST-Detected",
            FindingType::Reflected => "Reflected",
            FindingType::Informational => "Informational",
        }
    }

    /// Detailed description suitable for agents and structured output.
    pub(crate) fn long_description(&self) -> &'static str {
        match self {
            // NOT "confirmed executed": dalfox has no browser and never
            // observes execution. The claim it can make is that the payload
            // reached an executable position in a response it parsed.
            FindingType::Verified => {
                "Vulnerable - dalfox asserts this input is exploitable; act on it"
            }
            FindingType::AstDetected => {
                "AST-detected DOM XSS - detection method label, pending migration to the confidence axis"
            }
            FindingType::Reflected => {
                "Reflected - payload appears in the response, but its position was not confirmed exploitable; confirm manually"
            }
            FindingType::Informational => {
                "Informational - outdated or known-vulnerable component, not an exploitable XSS"
            }
        }
    }
}

impl fmt::Display for FindingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.short())
    }
}

/// Which subsystem produced a finding — the "how", kept separate from the
/// confidence axis in [`FindingType`].
///
/// Named `detection_method` on the wire because `Result::method` already means
/// the HTTP method. This is the stable selector for "AST-detected findings":
/// prefer it over `type == "A"`, which is being absorbed into the confidence
/// axis (issue #1238).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingMethod {
    /// Payload injected and its bytes located in the response.
    #[serde(rename = "reflection")]
    Reflection,
    /// Payload injected and confirmed as parsed DOM structure by the dedicated
    /// DOM-verification request.
    #[serde(rename = "dom-verification")]
    DomVerification,
    /// Static source→sink analysis of the page's JavaScript. No payload sent.
    #[serde(rename = "ast")]
    Ast,
    /// Out-of-band callback (blind XSS) — the only path on which dalfox
    /// observes real execution.
    #[serde(rename = "oob")]
    Oob,
    /// Known-vulnerable / outdated library detection.
    #[serde(rename = "library")]
    Library,
}

impl FindingMethod {
    /// The method implied by a tier, used when a producer does not set one.
    ///
    /// Correct for every producer whose tier and subsystem line up. The two
    /// that don't — the reflection phase's static `V` upgrade (`Reflection`)
    /// and the out-of-band poller (`Oob`) — set it explicitly.
    ///
    /// Resolved once in [`Result::builder`], which is what keeps the legacy AST
    /// promotions honest: they flip `result_type` to `Verified` *after* the
    /// finding is built, so the method stays `Ast`.
    pub(crate) fn default_for(tier: &FindingType) -> Self {
        match tier {
            FindingType::Verified => FindingMethod::DomVerification,
            FindingType::AstDetected => FindingMethod::Ast,
            FindingType::Reflected => FindingMethod::Reflection,
            FindingType::Informational => FindingMethod::Library,
        }
    }

    /// `serde` default for deserializing older records that predate the field.
    fn default_serde() -> Self {
        FindingMethod::Reflection
    }

    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            FindingMethod::Reflection => "reflection",
            FindingMethod::DomVerification => "dom-verification",
            FindingMethod::Ast => "ast",
            FindingMethod::Oob => "oob",
            FindingMethod::Library => "library",
        }
    }
}

impl fmt::Display for FindingMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether dalfox can claim a finding is a vulnerability.
///
/// Two levels on purpose: the tier migration derives `type` from this
/// directly (`high` → `V`, `low` → `R`), so a third level would only defer the
/// same decision. Ambiguous cases grade `Low` — the conservative direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    #[serde(rename = "high")]
    High,
    #[serde(rename = "low")]
    Low,
}

impl Confidence {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Low => "low",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Result {
    #[serde(rename = "type")]
    pub result_type: FindingType,
    pub inject_type: String,
    pub method: String,
    pub data: String,
    pub param: String,
    pub payload: String,
    pub evidence: String,
    pub cwe: String,
    pub severity: String,
    pub message_id: u32,
    pub message_str: String,
    /// Where the parameter lives on the wire: `"Query"`, `"Header"`,
    /// `"Body"`, `"JsonBody"`, `"MultipartBody"`, `"Path"`, or `"Fragment"`.
    /// Empty when the producer didn't set it (older call sites). Consumed
    /// by `generate_poc` to avoid synthesizing a misleading `?name=payload`
    /// query for header/cookie/body findings, and to tag the plain POC
    /// line with a short location hint.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub location: String,
    /// Which subsystem produced this finding. Defaults from `result_type` (see
    /// [`FindingMethod::default_for`]) and is overridden by the producers whose
    /// tier does not imply their method — the reflection phase's static `V`
    /// upgrade and the out-of-band poller.
    #[serde(default = "FindingMethod::default_serde")]
    pub detection_method: FindingMethod,
    /// Whether dalfox can claim this finding is a vulnerability, independent of
    /// the legacy tier in `result_type`. `None` for informational findings and
    /// for any AST finding that was not graded (which would be a bug — the
    /// grade is absent rather than wrong).
    ///
    /// During the tier migration this may disagree with `result_type`: the two
    /// legacy AST promotions can produce `type=V, confidence=low`. That
    /// disagreement is the preview signal, not an inconsistency to normalize.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    /// Short `;`-joined justification for `confidence`, e.g.
    /// `"URL-carried source; inline script permitted"` for a `High` grade or
    /// `"CSP does not permit inline script"` for a `Low` one. The two never
    /// mix: `ast_integration::grade_ast_finding` joins the supporting reasons
    /// when nothing blocks, and the blockers otherwise.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub confidence_reason: String,
    /// Whether this finding is absent from the `--baseline` report, serialized
    /// as `new`. Only populated under `--baseline-mode annotate`; `None` (and
    /// omitted from output) otherwise, including under `filter`, where every
    /// reported finding is new by construction.
    #[serde(rename = "new", default, skip_serializing_if = "Option::is_none")]
    pub new_since_baseline: Option<bool>,
    /// True when `data` already holds a complete, reproducible POC URL and the
    /// renderer must not append `?param=payload` on top of it. Set by the AST
    /// DOM-XSS producers, which place the payload in the fragment / query /
    /// path themselves according to the detected DOM source. Internal
    /// rendering hint — never serialized.
    #[serde(skip)]
    pub poc_url_complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
}

/// Largest response body kept on a finding as evidence.
///
/// Findings accumulate in one in-memory `Vec` for the whole run, and each one
/// used to carry its response body in full — up to the 16 MiB `read_body_capped`
/// ceiling. That is fine for a handful of findings and fatal for a scan that
/// produces thousands: `--deep-scan` lifts the first-hit-wins reflection lock,
/// so a reflect-everything endpoint emits a finding **per payload**, and a
/// 1 MiB page × a 3000-payload catalog is ~3 GB resident before anything is
/// rendered. In the server that vector is submitter-controlled and takes the
/// whole daemon — every concurrent scan and every retained result — with it.
pub(crate) const MAX_EVIDENCE_BODY_BYTES: usize = 64 * 1024;

/// Bound a response body kept as finding evidence, keeping the window around
/// the payload rather than a blind prefix.
///
/// Centering on the payload is what makes the truncation safe: the body is read
/// back by `extract_context` to render the `L1:` evidence line, which searches
/// for the payload, so a prefix cut would silently blank that line whenever the
/// reflection sat past the cap. Bodies within the cap — effectively all of them
/// — are returned untouched. Only the reported line *number* degrades for
/// oversized bodies, since it is counted within the retained window.
pub(crate) fn bound_evidence_body(body: String, payload: &str) -> String {
    if body.len() <= MAX_EVIDENCE_BODY_BYTES {
        return body;
    }
    let half = MAX_EVIDENCE_BODY_BYTES / 2;
    let center = body.find(payload).unwrap_or(0);
    let mut start = center.saturating_sub(half);
    while start > 0 && !body.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = (start + MAX_EVIDENCE_BODY_BYTES).min(body.len());
    while end > start && !body.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end - start + 32);
    if start > 0 {
        out.push_str("…[truncated]…");
    }
    out.push_str(&body[start..end]);
    if end < body.len() {
        out.push_str("…[truncated]…");
    }
    out
}

impl Result {
    /// Start building a finding. `result_type` is the only required field;
    /// every other field starts empty (`""` / `0` / `None`) and is filled in
    /// with the chained setters on [`ResultBuilder`], finishing with
    /// [`ResultBuilder::build`].
    ///
    /// Replaces the former 11-argument `Result::new`, which tripped
    /// `clippy::too_many_arguments`. The `location` / `request` / `response`
    /// fields remain public and are set directly on the built value when a
    /// caller needs them (often conditionally).
    ///
    /// `detection_method` starts at [`FindingMethod::default_for`] the tier;
    /// producers whose subsystem differs from that default override it with
    /// [`ResultBuilder::detection_method`].
    pub fn builder(result_type: FindingType) -> ResultBuilder {
        ResultBuilder {
            inner: Result {
                detection_method: FindingMethod::default_for(&result_type),
                confidence: None,
                confidence_reason: String::new(),
                result_type,
                inject_type: String::new(),
                method: String::new(),
                data: String::new(),
                param: String::new(),
                payload: String::new(),
                evidence: String::new(),
                cwe: String::new(),
                severity: String::new(),
                message_id: 0,
                message_str: String::new(),
                location: String::new(),
                new_since_baseline: None,
                poc_url_complete: false,
                request: None,
                response: None,
            },
        }
    }
}

/// Fluent builder for [`Result`]. Each setter consumes and returns `self` so
/// calls chain; setters take `impl Into<String>` so both `&str` and `String`
/// work at the call site.
#[derive(Debug, Clone)]
pub struct ResultBuilder {
    inner: Result,
}

impl ResultBuilder {
    /// Injection technique label (e.g. `"inHTML-URL"`, `"DOM-XSS"`).
    pub fn inject_type(mut self, v: impl Into<String>) -> Self {
        self.inner.inject_type = v.into();
        self
    }

    /// HTTP method used for the request that produced the finding.
    pub fn method(mut self, v: impl Into<String>) -> Self {
        self.inner.method = v.into();
        self
    }

    /// Override the subsystem label derived from the tier — see
    /// [`FindingMethod::default_for`].
    pub(crate) fn detection_method(mut self, v: FindingMethod) -> Self {
        self.inner.detection_method = v;
        self
    }

    /// Record the confidence grade and the signals behind it.
    pub(crate) fn confidence(mut self, grade: Confidence, reason: impl Into<String>) -> Self {
        self.inner.confidence = Some(grade);
        self.inner.confidence_reason = reason.into();
        self
    }

    /// Request data / URL associated with the finding.
    pub fn data(mut self, v: impl Into<String>) -> Self {
        self.inner.data = v.into();
        self
    }

    /// Name of the affected parameter.
    pub fn param(mut self, v: impl Into<String>) -> Self {
        self.inner.param = v.into();
        self
    }

    /// The payload that triggered the finding.
    pub fn payload(mut self, v: impl Into<String>) -> Self {
        self.inner.payload = v.into();
        self
    }

    /// Human-readable evidence string.
    pub fn evidence(mut self, v: impl Into<String>) -> Self {
        self.inner.evidence = v.into();
        self
    }

    /// CWE identifier (e.g. `"CWE-79"`).
    pub fn cwe(mut self, v: impl Into<String>) -> Self {
        self.inner.cwe = v.into();
        self
    }

    /// Severity label (e.g. `"High"`, `"Medium"`).
    pub fn severity(mut self, v: impl Into<String>) -> Self {
        self.inner.severity = v.into();
        self
    }

    /// Numeric message identifier.
    pub fn message_id(mut self, v: u32) -> Self {
        self.inner.message_id = v;
        self
    }

    /// Message string shown to the user.
    pub fn message_str(mut self, v: impl Into<String>) -> Self {
        self.inner.message_str = v.into();
        self
    }

    /// Finalize the builder into a [`Result`].
    pub fn build(self) -> Result {
        self.inner
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SanitizedResult {
    #[serde(rename = "type")]
    pub result_type: FindingType,
    pub type_description: String,
    pub inject_type: String,
    pub method: String,
    pub data: String,
    pub param: String,
    pub payload: String,
    pub evidence: String,
    pub cwe: String,
    pub severity: String,
    pub message_id: u32,
    pub message_str: String,
    /// Wire location of the parameter (Query / Header / Body / …). See
    /// [`Result::location`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub location: String,
    /// Producing subsystem. See [`Result::detection_method`].
    #[serde(default = "FindingMethod::default_serde")]
    pub detection_method: FindingMethod,
    /// Confidence grade. See [`Result::confidence`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    /// Signals behind `confidence`. See [`Result::confidence_reason`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub confidence_reason: String,
    /// New relative to `--baseline`. See [`Result::new_since_baseline`].
    #[serde(rename = "new", default, skip_serializing_if = "Option::is_none")]
    pub new_since_baseline: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
}

/// Scan-level metadata envelope, previously only surfaced for JSON/JSONL.
/// Now also threaded into SARIF (run.properties + driver.properties),
/// Markdown (as additional summary tables), and TOML (as `[meta]` table).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct ScanMetadata {
    pub dalfox_version: String,
    pub targets: Vec<String>,
    pub scan_duration_ms: u64,
    pub total_requests: u64,
    /// Outbound requests that never produced a response (connection reset,
    /// refused, timed out) after their retry budget was spent. Reported
    /// alongside `total_requests` because a payload that never reached the
    /// target was never tested: a scan that sent 176 requests and lost 160 of
    /// them is not the same scan as one that sent 176 and got 176 answers,
    /// even though both can finish with zero findings.
    #[serde(default)]
    pub failed_requests: u64,
    pub findings_count: usize,
    pub target_summary: Vec<serde_json::Value>,
    /// Target-dedup mode in effect (`exact`, `signature`, or `off`).
    #[serde(default)]
    pub dedup_mode: String,
    /// Duplicate targets dropped by that mode before scanning. Reported so a
    /// run that collapsed part of its input list is never read as full
    /// coverage of that list.
    #[serde(default)]
    pub targets_deduplicated: usize,
    /// `--baseline` diff summary (path, mode, new/known counts, or the reason
    /// the diff was disabled). `None` when `--baseline` was not used, and then
    /// omitted from every rendered envelope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<serde_json::Value>,
    /// `--state-file` resume summary (path, and how many targets this run
    /// skipped because a previous run completed them). Present only when
    /// `--state-file` was used. A consumer that sees `targets` describing a
    /// 50k-URL list and a report covering 300 of them needs this field to tell
    /// a resumed run from a scan that mostly found nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resumed: Option<serde_json::Value>,
    /// At least one target was not fully tested: its authenticated session
    /// died mid-scan (see `error_codes::SESSION_LOST`), or a significant share
    /// of this run's requests never reached the target at all.
    /// Hoisted out of `target_summary` so a consumer can answer "are these
    /// results trustworthy?" with one field read instead of a scan over every
    /// entry's status. `false` on a normal run.
    #[serde(default)]
    pub incomplete: bool,
}

impl Result {
    pub(crate) fn to_sanitized(
        &self,
        include_request: bool,
        include_response: bool,
    ) -> SanitizedResult {
        SanitizedResult {
            type_description: self.result_type.long_description().to_string(),
            result_type: self.result_type.clone(),
            inject_type: self.inject_type.clone(),
            method: self.method.clone(),
            data: self.data.clone(),
            param: self.param.clone(),
            payload: self.payload.clone(),
            evidence: self.evidence.clone(),
            cwe: self.cwe.clone(),
            severity: self.severity.clone(),
            message_id: self.message_id,
            message_str: self.message_str.clone(),
            location: self.location.clone(),
            detection_method: self.detection_method,
            confidence: self.confidence,
            confidence_reason: self.confidence_reason.clone(),
            new_since_baseline: self.new_since_baseline,
            request: if include_request {
                self.request.clone()
            } else {
                None
            },
            response: if include_response {
                self.response.clone()
            } else {
                None
            },
        }
    }

    /// Convert this Result into a serde_json::Value honoring include_request/include_response flags.
    pub(crate) fn to_json_value(
        &self,
        include_request: bool,
        include_response: bool,
    ) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "type": self.result_type,
            "type_description": self.result_type.long_description(),
            "inject_type": self.inject_type,
            "method": self.method,
            "data": self.data,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence,
            "cwe": self.cwe,
            "severity": self.severity,
            "message_id": self.message_id,
            "message_str": self.message_str,
            "detection_method": self.detection_method.as_str()
        });
        if !self.location.is_empty()
            && let serde_json::Value::Object(ref mut map) = obj
        {
            map.insert(
                "location".to_string(),
                serde_json::Value::String(self.location.clone()),
            );
        }
        if let Some(is_new) = self.new_since_baseline
            && let serde_json::Value::Object(ref mut map) = obj
        {
            map.insert("new".to_string(), serde_json::Value::Bool(is_new));
        }
        if let Some(grade) = self.confidence
            && let serde_json::Value::Object(ref mut map) = obj
        {
            map.insert(
                "confidence".to_string(),
                serde_json::Value::String(grade.as_str().to_string()),
            );
            if !self.confidence_reason.is_empty() {
                map.insert(
                    "confidence_reason".to_string(),
                    serde_json::Value::String(self.confidence_reason.clone()),
                );
            }
        }
        if include_request
            && let Some(req) = &self.request
            && let serde_json::Value::Object(ref mut map) = obj
        {
            map.insert(
                "request".to_string(),
                serde_json::Value::String(req.clone()),
            );
        }
        if include_response
            && let Some(resp) = &self.response
            && let serde_json::Value::Object(ref mut map) = obj
        {
            map.insert(
                "response".to_string(),
                serde_json::Value::String(resp.clone()),
            );
        }
        obj
    }

    /// The scan-meta envelope as JSON, shared by every format that emits one.
    ///
    /// `pub(crate)` so the CLI's `json` / `jsonl` renderers go through it too.
    /// They used to inline their own `json!` literal, which meant a new meta
    /// field had to be added in five places (here plus two inline literals plus
    /// the two `ScanMetadata` construction sites) and silently appeared in only
    /// some formats when it wasn't. `incomplete` and `baseline` — both added on
    /// the same day — each had to touch all of them.
    pub(crate) fn make_scan_meta_value(meta: &ScanMetadata) -> serde_json::Value {
        let mut value = serde_json::json!({
            "dalfox_version": &meta.dalfox_version,
            "targets": &meta.targets,
            "scan_duration_ms": meta.scan_duration_ms,
            "total_requests": meta.total_requests,
            "failed_requests": meta.failed_requests,
            "findings_count": meta.findings_count,
            "incomplete": meta.incomplete,
            "target_summary": &meta.target_summary,
            "dedup_mode": &meta.dedup_mode,
            "targets_deduplicated": meta.targets_deduplicated,
        });
        if let Some(baseline) = &meta.baseline
            && let serde_json::Value::Object(ref mut map) = value
        {
            map.insert("baseline".to_string(), baseline.clone());
        }
        if let Some(resumed) = &meta.resumed
            && let serde_json::Value::Object(ref mut map) = value
        {
            map.insert("resumed".to_string(), resumed.clone());
        }
        value
    }
}

mod format_json;
mod format_markdown;
mod format_sarif;
mod format_toml;

#[cfg(test)]
mod tests;
