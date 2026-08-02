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
    pub fn short(&self) -> &'static str {
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
    pub fn description(&self) -> &'static str {
        match self {
            FindingType::Verified => "Vulnerable",
            FindingType::AstDetected => "AST-Detected",
            FindingType::Reflected => "Reflected",
            FindingType::Informational => "Informational",
        }
    }

    /// Detailed description suitable for agents and structured output.
    pub fn long_description(&self) -> &'static str {
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
    pub fn default_for(tier: &FindingType) -> Self {
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

    pub fn as_str(&self) -> &'static str {
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
    pub fn as_str(&self) -> &'static str {
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
    pub fn detection_method(mut self, v: FindingMethod) -> Self {
        self.inner.detection_method = v;
        self
    }

    /// Record the confidence grade and the signals behind it.
    pub fn confidence(mut self, grade: Confidence, reason: impl Into<String>) -> Self {
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
pub struct SanitizedResult {
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
pub struct ScanMetadata {
    pub dalfox_version: String,
    pub targets: Vec<String>,
    pub scan_duration_ms: u64,
    pub total_requests: u64,
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
    /// At least one target was not fully tested — today that means its
    /// authenticated session died mid-scan (see `error_codes::SESSION_LOST`).
    /// Hoisted out of `target_summary` so a consumer can answer "are these
    /// results trustworthy?" with one field read instead of a scan over every
    /// entry's status. `false` on a normal run.
    #[serde(default)]
    pub incomplete: bool,
}

impl Result {
    pub fn to_sanitized(&self, include_request: bool, include_response: bool) -> SanitizedResult {
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
    pub fn to_json_value(
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

    /// Serialize a slice of Result into JSON array string. Set pretty=true for pretty-printed JSON.
    pub fn results_to_json(
        results: &[Result],
        include_request: bool,
        include_response: bool,
        pretty: bool,
    ) -> String {
        let vals: Vec<serde_json::Value> = results
            .iter()
            .map(|r| r.to_json_value(include_request, include_response))
            .collect();
        if pretty {
            serde_json::to_string_pretty(&vals).unwrap_or_else(|_| "[]".to_string())
        } else {
            serde_json::to_string(&vals).unwrap_or_else(|_| "[]".to_string())
        }
    }

    /// Serialize a slice of Result into JSON Lines (JSONL) string.
    pub fn results_to_jsonl(
        results: &[Result],
        include_request: bool,
        include_response: bool,
    ) -> String {
        let mut out = String::new();
        for r in results {
            let v = r.to_json_value(include_request, include_response);
            if let Ok(s) = serde_json::to_string(&v) {
                out.push_str(&s);
                out.push('\n');
            }
        }
        out
    }

    /// Serialize a slice of Result into TOML string.
    ///
    /// For backward compatibility (public API surface under `dalfox::scanning::result`),
    /// the 3-argument form omits the scan metadata envelope (equivalent to `meta=None`).
    /// Use the `_with_meta` variant to carry `ScanMetadata` (targets, duration, WAF in
    /// `target_summary`, etc.) for parity with the JSON/JSONL render path.
    pub fn results_to_toml(
        results: &[Result],
        include_request: bool,
        include_response: bool,
    ) -> String {
        Self::results_to_toml_with_meta(results, include_request, include_response, None)
    }

    /// Serialize ... with optional scan metadata (see `results_to_toml`).
    pub fn results_to_toml_with_meta(
        results: &[Result],
        include_request: bool,
        include_response: bool,
        meta: Option<&ScanMetadata>,
    ) -> String {
        #[derive(Serialize)]
        struct TomlWrapper {
            #[serde(skip_serializing_if = "Option::is_none")]
            meta: Option<serde_json::Value>,
            results: Vec<SanitizedResult>,
        }

        let sanitized: Vec<SanitizedResult> = results
            .iter()
            .map(|r| r.to_sanitized(include_request, include_response))
            .collect();

        let meta_val = meta.map(Self::make_scan_meta_value);
        let wrapper = TomlWrapper {
            meta: meta_val,
            results: sanitized,
        };
        toml::to_string(&wrapper).unwrap_or_else(|_| "".to_string())
    }

    /// Serialize a slice of Result into Markdown string.
    ///
    /// For backward compatibility (public API surface under `dalfox::scanning::result`),
    /// the 3-argument form omits the scan metadata envelope (equivalent to `meta=None`).
    /// Use the `_with_meta` variant to include `## Scan Metadata` + target summary tables.
    pub fn results_to_markdown(
        results: &[Result],
        include_request: bool,
        include_response: bool,
    ) -> String {
        Self::results_to_markdown_with_meta(results, include_request, include_response, None)
    }

    /// Serialize ... with optional scan metadata (see `results_to_markdown`).
    pub fn results_to_markdown_with_meta(
        results: &[Result],
        include_request: bool,
        include_response: bool,
        meta: Option<&ScanMetadata>,
    ) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(results.len() * 512 + 256);

        // Add header
        out.push_str("# Dalfox Scan Results\n\n");

        // Inject scan metadata envelope when provided (for parity with JSON/JSONL)
        if let Some(m) = meta {
            out.push_str("## Scan Metadata\n\n");
            out.push_str("| Field | Value |\n");
            out.push_str("|-------|-------|\n");
            let _ = writeln!(out, "| **Dalfox Version** | {} |", m.dalfox_version);
            let _ = writeln!(
                out,
                "| **Targets** | {} |",
                m.targets.join(", ").replace('|', "\\|")
            );
            let _ = writeln!(out, "| **Scan Duration** | {} ms |", m.scan_duration_ms);
            let _ = writeln!(out, "| **Total Requests** | {} |", m.total_requests);
            let _ = writeln!(out, "| **Findings Count** | {} |", m.findings_count);
            // Only shown when dedup actually dropped something: a collapsed
            // input list must be visible in the report, but the common
            // "nothing collapsed" case doesn't need a row.
            if m.targets_deduplicated > 0 {
                let _ = writeln!(
                    out,
                    "| **Targets Deduplicated** | {} ({} mode) |",
                    m.targets_deduplicated, m.dedup_mode
                );
            }
            if let Some(b) = &m.baseline {
                let cell = if let Some(w) = b.get("warning").and_then(|v| v.as_str()) {
                    format!("disabled — {}", w)
                } else {
                    format!(
                        "{} (mode: {}, new: {}, known: {})",
                        b.get("path").and_then(|v| v.as_str()).unwrap_or("?"),
                        b.get("mode").and_then(|v| v.as_str()).unwrap_or("?"),
                        b.get("new").and_then(|v| v.as_u64()).unwrap_or(0),
                        b.get("known").and_then(|v| v.as_u64()).unwrap_or(0),
                    )
                };
                let _ = writeln!(out, "| **Baseline** | {} |", cell.replace('|', "\\|"));
            }
            // Same rule as the dedup row: a report covering a fraction of the
            // input list because the rest was already done must say so.
            if let Some(r) = &m.resumed
                && r.get("targets_skipped_completed")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
                    > 0
            {
                let _ = writeln!(
                    out,
                    "| **Resumed** | {} target(s) skipped as already completed (state file: {}) |",
                    r.get("targets_skipped_completed")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    r.get("state_file")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?")
                        .replace('|', "\\|")
                );
            }
            // Only rendered when true — a "Complete: yes" row on every clean
            // report is noise, but its absence must never be what signals a
            // truncated run, so the true case is spelled out loudly.
            if m.incomplete {
                let _ = writeln!(
                    out,
                    "| **Incomplete** | ⚠️ yes — at least one target was not fully tested (see Target Summary) |"
                );
            }
            out.push('\n');

            // Per-target summary table (includes status, findings_count, WAF when present)
            if !m.target_summary.is_empty() {
                out.push_str("### Target Summary\n\n");
                out.push_str("| Target | Status | Findings | WAF |\n");
                out.push_str("|--------|--------|----------|-----|\n");
                for t in &m.target_summary {
                    let tgt = t.get("target").and_then(|v| v.as_str()).unwrap_or("?");
                    let st = t.get("status").and_then(|v| v.as_str()).unwrap_or("?");
                    let fc = t
                        .get("findings_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let status_cell = if let Some(ec) = t.get("error_code").and_then(|e| e.as_str())
                    {
                        format!("{} ({})", st, ec)
                    } else {
                        st.to_string()
                    };
                    let waf_str = if let Some(w) = t.get("waf") {
                        // Real shape (from analysis.rs + render_results): "detected": [{ "type": "..", "confidence": N, ...}, ...]
                        // plus optional "bypass". Support legacy test mock shape {detected: bool, name} too.
                        if let Some(dets) = w.get("detected").and_then(|d| d.as_array()) {
                            if !dets.is_empty() {
                                dets[0]
                                    .get("type")
                                    .and_then(|ty| ty.as_str())
                                    .unwrap_or("detected")
                                    .to_string()
                            } else {
                                "none".to_string()
                            }
                        } else if w.get("detected").and_then(|d| d.as_bool()).unwrap_or(false) {
                            w.get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("detected")
                                .to_string()
                        } else {
                            "none".to_string()
                        }
                    } else {
                        "none".to_string()
                    };
                    let _ = writeln!(
                        out,
                        "| {} | {} | {} | {} |",
                        tgt.replace('|', "\\|"),
                        status_cell.replace('|', "\\|"),
                        fc,
                        waf_str.replace('|', "\\|")
                    );
                }
                out.push('\n');
            }
        }

        // Add summary
        let v_count = results
            .iter()
            .filter(|r| r.result_type == FindingType::Verified)
            .count();
        let r_count = results
            .iter()
            .filter(|r| r.result_type == FindingType::Reflected)
            .count();
        out.push_str("## Summary\n\n");
        let _ = writeln!(out, "- **Total Findings**: {}", results.len());
        let _ = writeln!(out, "- **Vulnerabilities (V)**: {}", v_count);
        let _ = write!(out, "- **Reflections (R)**: {}\n\n", r_count); // double newline intentional

        // Add findings table
        if !results.is_empty() {
            out.push_str("## Findings\n\n");

            for (idx, result) in results.iter().enumerate() {
                let _ = write!(
                    out,
                    "### {}. {} - {} ({})\n\n", // double newline intentional
                    idx + 1,
                    if result.result_type == FindingType::Verified {
                        "Vulnerability"
                    } else {
                        "Reflection"
                    },
                    result.param,
                    result.inject_type
                );

                out.push_str("| Field | Value |\n");
                out.push_str("|-------|-------|\n");
                let _ = writeln!(out, "| **Type** | {} |", result.result_type);
                let _ = writeln!(out, "| **Parameter** | `{}` |", result.param);
                let _ = writeln!(out, "| **Method** | {} |", result.method);
                let _ = writeln!(out, "| **Injection Type** | {} |", result.inject_type);
                let _ = writeln!(
                    out,
                    "| **Detected By** | {} |",
                    result.detection_method.as_str()
                );
                if let Some(grade) = result.confidence {
                    let cell = if result.confidence_reason.is_empty() {
                        grade.as_str().to_string()
                    } else {
                        format!(
                            "{} ({})",
                            grade.as_str(),
                            result.confidence_reason.replace('|', "\\|")
                        )
                    };
                    let _ = writeln!(out, "| **Confidence** | {} |", cell);
                }
                if let Some(is_new) = result.new_since_baseline {
                    let _ = writeln!(
                        out,
                        "| **New** | {} |",
                        if is_new { "yes" } else { "no (in baseline)" }
                    );
                }
                let _ = writeln!(out, "| **Severity** | {} |", result.severity);
                let _ = writeln!(out, "| **CWE** | {} |", result.cwe);
                let _ = writeln!(out, "| **URL** | {} |", result.data);
                let _ = writeln!(
                    out,
                    "| **Payload** | `{}` |",
                    result.payload.replace('|', "\\|")
                );

                if !result.evidence.is_empty() {
                    let _ = writeln!(
                        out,
                        "| **Evidence** | {} |",
                        result.evidence.replace('|', "\\|")
                    );
                }

                out.push('\n');

                // Include request if requested
                if include_request && let Some(req) = &result.request {
                    out.push_str("**Request:**\n\n```http\n");
                    out.push_str(req);
                    out.push_str("\n```\n\n");
                }

                // Include response if requested
                if include_response && let Some(resp) = &result.response {
                    out.push_str("**Response:**\n\n```http\n");
                    out.push_str(resp);
                    out.push_str("\n```\n\n");
                }

                out.push_str("---\n\n");
            }
        }

        out
    }

    /// Serialize a slice of Result into SARIF v2.1.0 format string.
    /// SARIF (Static Analysis Results Interchange Format) is a standard format for static analysis tools.
    ///
    /// For backward compatibility (public API surface under `dalfox::scanning::result`),
    /// the 3-argument form omits the scan metadata envelope. Use the `_with_meta` variant
    /// to populate `run.properties` + `tool.driver.properties` (recommended for CI/code-scanning).
    pub fn results_to_sarif(
        results: &[Result],
        include_request: bool,
        include_response: bool,
    ) -> String {
        Self::results_to_sarif_with_meta(results, include_request, include_response, None)
    }

    /// Serialize ... with optional scan metadata (see `results_to_sarif`).
    pub fn results_to_sarif_with_meta(
        results: &[Result],
        include_request: bool,
        include_response: bool,
        meta: Option<&ScanMetadata>,
    ) -> String {
        use serde_json::json;

        // Convert severity to SARIF level
        let severity_to_level = |severity: &str| -> &str {
            match severity.to_lowercase().as_str() {
                "high" | "critical" => "error",
                "medium" => "warning",
                "low" | "info" => "note",
                _ => "warning",
            }
        };

        // SARIF requires that a result's `ruleId` reference a rule defined in
        // `driver.rules`, and that a present `ruleIndex` point at THAT rule.
        // Findings carry different CWEs (XSS is CWE-79; outdated-library
        // findings are CWE-1104), so a single hardcoded rule + `ruleIndex: 0`
        // emitted an id with no matching rule and an inconsistent index, which
        // GitHub code scanning rejects. Build the rule table from the distinct
        // CWEs actually present, in first-seen order, and index each result
        // into it.
        let mut rule_ids: Vec<String> = Vec::new();
        for r in results {
            let id = sarif_rule_id(&r.cwe);
            if !rule_ids.contains(&id) {
                rule_ids.push(id);
            }
        }
        // Never emit an empty `rules` array — keep the XSS rule as the default
        // so an empty result set still describes the tool's primary rule.
        if rule_ids.is_empty() {
            rule_ids.push(sarif_rule_id("CWE-79"));
        }
        let rules: Vec<serde_json::Value> =
            rule_ids.iter().map(|id| sarif_rule_for_id(id)).collect();

        // Convert results to SARIF result objects
        let sarif_results: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                // Build message with additional context
                let mut message_parts = vec![r.message_str.clone()];
                if !r.evidence.is_empty() {
                    message_parts.push(format!("Evidence: {}", r.evidence));
                }
                if include_request && r.request.is_some() {
                    message_parts.push("HTTP request included in properties".to_string());
                }
                if include_response && r.response.is_some() {
                    message_parts.push("HTTP response included in properties".to_string());
                }
                let full_message = message_parts.join(". ");

                // Build properties bag
                let mut properties = json!({
                    "type": r.result_type,
                    "inject_type": r.inject_type,
                    "method": r.method,
                    "param": r.param,
                    "payload": r.payload,
                    "severity": r.severity,
                    "detection_method": r.detection_method.as_str(),
                });
                if let Some(grade) = r.confidence {
                    properties["confidence"] = json!(grade.as_str());
                    if !r.confidence_reason.is_empty() {
                        properties["confidence_reason"] = json!(r.confidence_reason);
                    }
                }

                if let Some(is_new) = r.new_since_baseline {
                    properties["new"] = json!(is_new);
                }

                if include_request && let Some(req) = &r.request {
                    properties["request"] = json!(req);
                }
                if include_response && let Some(resp) = &r.response {
                    properties["response"] = json!(resp);
                }

                // Stable, vulnerability-identity fingerprint so SARIF
                // consumers (e.g. GitHub code scanning) can dedupe the
                // same finding across rescans. Previously this was the
                // catalog `message_id`, which is hardcoded per finding
                // type (e.g. 606 for every reflected XSS) and therefore
                // useless for dedup.
                let stable_fp = crate::utils::stable_finding_fingerprint(
                    &r.data,
                    &r.param,
                    &r.inject_type,
                    &r.cwe,
                );
                let rule_id = sarif_rule_id(&r.cwe);
                let rule_index = rule_ids.iter().position(|id| *id == rule_id).unwrap_or(0);
                json!({
                    "ruleId": rule_id,
                    "ruleIndex": rule_index,
                    "level": severity_to_level(&r.severity),
                    "message": {
                        "text": full_message
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": r.data.clone()
                            },
                            "region": {
                                "snippet": {
                                    "text": r.payload.clone()
                                }
                            }
                        }
                    }],
                    "partialFingerprints": {
                        // SARIF spec: keys are arbitrary identifiers, values
                        // are stable hashes. v1 versions the scheme so we can
                        // evolve the input tuple later without re-mapping
                        // historical findings.
                        "vulnIdentity/v1": stable_fp,
                        // Preserve the catalog id under a clearly non-
                        // fingerprint name — useful for human triage but
                        // not used by consumers for dedup.
                        "dalfoxMessageId": r.message_id.to_string(),
                    },
                    "properties": properties
                })
            })
            .collect();

        // Build driver, optionally with scan meta under its properties (per issue #1093)
        let mut driver = json!({
            "name": "Dalfox",
            "informationUri": "https://github.com/hahwul/dalfox",
            "version": env!("CARGO_PKG_VERSION"),
            "rules": rules,
        });
        if let Some(m) = meta {
            driver["properties"] = Self::make_scan_meta_value(m);
        }

        // Build run object, optionally with scan meta under run.properties
        let mut run = json!({
            "tool": {
                "driver": driver
            },
            "results": sarif_results
        });
        if let Some(m) = meta {
            run["properties"] = Self::make_scan_meta_value(m);
        }

        // Build SARIF document
        let sarif = json!({
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [run]
        });

        serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
    }
}

/// SARIF `ruleId` / `driver.rules[].id` for a finding's CWE. Empty or unknown
/// CWEs fall back to the XSS rule so the id is always a well-formed
/// `dalfox/cwe-<n>` rather than a bare `dalfox/`.
fn sarif_rule_id(cwe: &str) -> String {
    let trimmed = cwe.trim();
    if trimmed.is_empty() {
        return "dalfox/cwe-79".to_string();
    }
    format!("dalfox/{}", trimmed.to_ascii_lowercase())
}

/// Build a `driver.rules[]` entry for a `dalfox/cwe-<n>` rule id. CWE-79 (the
/// scanner's primary finding class) keeps its rich description; other CWEs get
/// a minimal-but-valid rule so every emitted `ruleId` resolves to a defined
/// rule (SARIF requirement for GitHub code scanning ingestion).
fn sarif_rule_for_id(id: &str) -> serde_json::Value {
    use serde_json::json;
    match id {
        "dalfox/cwe-1104" => json!({
            "id": id,
            "name": "UseOfUnmaintainedThirdPartyComponents",
            "shortDescription": {
                "text": "Use of a component with known vulnerabilities (CWE-1104)"
            },
            "fullDescription": {
                "text": "The application loads a third-party JavaScript component whose version is known to be outdated or vulnerable."
            },
            "help": {
                "text": "Upgrade the flagged component to a maintained, non-vulnerable release and track dependency advisories."
            },
            "defaultConfiguration": { "level": "warning" },
            "properties": { "tags": ["security", "dependencies"], "precision": "high" }
        }),
        "dalfox/cwe-79" => json!({
            "id": id,
            "name": "CrossSiteScripting",
            "shortDescription": {
                "text": "Cross-site Scripting (XSS)"
            },
            "fullDescription": {
                "text": "The application reflects user input in HTML responses without proper encoding, allowing attackers to inject malicious scripts."
            },
            "help": {
                "text": "Ensure all user input is properly encoded before being rendered in HTML context. Use context-aware output encoding based on where the data is placed (HTML body, attributes, JavaScript, CSS, or URL)."
            },
            "defaultConfiguration": {
                "level": "error"
            },
            "properties": {
                "tags": ["security", "xss", "injection"],
                "precision": "high"
            }
        }),
        // Any other CWE: emit a valid, generic rule so the id resolves.
        other => json!({
            "id": other,
            "name": "SecurityFinding",
            "shortDescription": { "text": format!("Security finding ({})", other) },
            "defaultConfiguration": { "level": "warning" },
            "properties": { "tags": ["security"] }
        }),
    }
}

#[cfg(test)]
mod tests;
