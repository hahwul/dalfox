//! `format_markdown` output serialization for [`Result`].
//!
//! One `impl Result` block per output format keeps format-specific work
//! isolated; the shared model and helpers live in the parent module.

use super::*;

/// Neutralize the Markdown structure characters in a value that came off the
/// target — a parameter name (page forms / parameter mining apply no filter),
/// a URL, an evidence string.
///
/// `|` ends a table cell, and a newline ends the whole table: a name like
/// `q| forged |\n\n## FORGED HEADING\n\nx` used to close the row and open a
/// real heading, so the report's own structure could be written by the page
/// it was reporting on. Control bytes go through the same
/// [`sanitize_display`](crate::utils::term::sanitize_display) rule the
/// terminal renderer uses — so `cat report.md` is covered too, and the
/// payload whitespace dalfox's own WAF bypasses rely on (`\x0b`, `\x0c`)
/// still round-trips out of the Payload cell.
fn md_cell(value: &str) -> String {
    crate::utils::term::sanitize_display(value).replace('|', "\\|")
}

/// Pick a fence long enough to contain `body`. A response echoed under
/// `--include-response` can contain ``` and would otherwise close the fence
/// early, spilling the rest of the body into the document as Markdown.
fn code_fence_for(body: &str) -> String {
    let mut longest = 0usize;
    let mut run = 0usize;
    for ch in body.chars() {
        if ch == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    "`".repeat(longest.max(2) + 1)
}

impl Result {
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
    pub(crate) fn results_to_markdown_with_meta(
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
            let _ = writeln!(out, "| **Targets** | {} |", md_cell(&m.targets.join(", ")));
            let _ = writeln!(out, "| **Scan Duration** | {} ms |", m.scan_duration_ms);
            let _ = writeln!(out, "| **Total Requests** | {} |", m.total_requests);
            if m.failed_requests > 0 {
                let _ = writeln!(out, "| **Failed Requests** | {} |", m.failed_requests);
            }
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
            // Same rule as the dedup row: shown only when part of the input
            // list was actually thrown away.
            if m.targets_unparsable > 0 {
                let _ = writeln!(
                    out,
                    "| **Targets Unparsable** | {} list line(s) skipped |",
                    m.targets_unparsable
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
                let _ = writeln!(out, "| **Baseline** | {} |", md_cell(&cell));
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
                    md_cell(r.get("state_file").and_then(|v| v.as_str()).unwrap_or("?"))
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
                        md_cell(tgt),
                        md_cell(&status_cell),
                        fc,
                        md_cell(&waf_str)
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
                    md_cell(&result.param),
                    md_cell(&result.inject_type)
                );

                out.push_str("| Field | Value |\n");
                out.push_str("|-------|-------|\n");
                let _ = writeln!(out, "| **Type** | {} |", result.result_type);
                let _ = writeln!(out, "| **Parameter** | `{}` |", md_cell(&result.param));
                let _ = writeln!(out, "| **Method** | {} |", md_cell(&result.method));
                let _ = writeln!(
                    out,
                    "| **Injection Type** | {} |",
                    md_cell(&result.inject_type)
                );
                let _ = writeln!(
                    out,
                    "| **Detected By** | {} |",
                    md_cell(result.detection_method.as_str())
                );
                if let Some(grade) = result.confidence {
                    let cell = if result.confidence_reason.is_empty() {
                        grade.as_str().to_string()
                    } else {
                        format!(
                            "{} ({})",
                            grade.as_str(),
                            md_cell(&result.confidence_reason)
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
                let _ = writeln!(out, "| **Severity** | {} |", md_cell(&result.severity));
                let _ = writeln!(out, "| **CWE** | {} |", md_cell(&result.cwe));
                let _ = writeln!(out, "| **URL** | {} |", md_cell(&result.data));
                let _ = writeln!(out, "| **Payload** | `{}` |", md_cell(&result.payload));

                if !result.evidence.is_empty() {
                    let _ = writeln!(out, "| **Evidence** | {} |", md_cell(&result.evidence));
                }

                out.push('\n');

                // Include request if requested
                if include_request && let Some(req) = &result.request {
                    let fence = code_fence_for(req);
                    let _ = write!(out, "**Request:**\n\n{}http\n", fence);
                    out.push_str(req);
                    let _ = write!(out, "\n{}\n\n", fence);
                }

                // Include response if requested
                if include_response && let Some(resp) = &result.response {
                    let fence = code_fence_for(resp);
                    let _ = write!(out, "**Response:**\n\n{}http\n", fence);
                    out.push_str(resp);
                    let _ = write!(out, "\n{}\n\n", fence);
                }

                out.push_str("---\n\n");
            }
        }

        out
    }
}
