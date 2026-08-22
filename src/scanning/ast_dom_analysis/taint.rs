//! The taint decision itself: is this expression attacker-controlled, and if
//! so, which DOM source is behind it.
//!
//! Also holds reporting, because a finding is only ever raised from a positive
//! taint verdict and carries the source name that verdict produced.

use super::*;

impl<'a> DomXssVisitor<'a> {
    /// Check taint/source hint for a call argument
    pub(super) fn argument_taint_and_source(&self, arg: &Argument<'a>) -> (bool, Option<String>) {
        match arg {
            Argument::SpreadElement(spread) => {
                let tainted = self.is_tainted(&spread.argument);
                (
                    tainted,
                    if tainted {
                        self.find_source_in_expr(&spread.argument)
                    } else {
                        None
                    },
                )
            }
            _ => {
                if let Some(expr) = arg.as_expression() {
                    let tainted = self.is_tainted(expr);
                    (
                        tainted,
                        if tainted {
                            self.find_source_in_expr(expr)
                        } else {
                            None
                        },
                    )
                } else {
                    (false, None)
                }
            }
        }
    }
    /// Determine whether a call expression yields tainted data and provide source hint.
    pub(super) fn call_taint_and_source(
        &self,
        call: &CallExpression<'a>,
    ) -> (bool, Option<String>) {
        // `responseVar.text()` / `responseVar.json()` on a `fetch()` Response
        // reads untrusted network data (issue #1024). The receiver is bound by
        // the promise-chain driver; the resolved string is the DOM-XSS source.
        if let Expression::StaticMemberExpression(member) = &call.callee
            && let Expression::Identifier(id) = &member.object
            && self.response_object_vars.contains(id.name.as_str())
        {
            match member.property.name.as_str() {
                "text" => return (true, Some("Response.text".to_string())),
                "json" => return (true, Some("Response.json".to_string())),
                _ => {}
            }
        }

        // Trusted Types policy wrapper: `policy.createHTML(x)` / `.createScript`
        // / `.createScriptURL`. A *strict* callback neutralizes its input like a
        // sanitizer (taint cleared); a *permissive* one (`x => x`) does not, so
        // we fall through and the argument's taint propagates — correctly
        // flagging a `createPolicy('default', {createHTML: x=>x})` no-op.
        if self.tt_wrapper_call_strictness(call) == Some(TtStrictness::Strict) {
            return (false, None);
        }

        // Sanitizers produce de-tainted values
        if let Some(func_name) = self.get_expr_string(&call.callee)
            && (self.sanitizers.contains(func_name.as_str())
                || Self::is_likely_sanitizer_name(&func_name))
        {
            return (false, None);
        }

        // Reflect.apply(targetFn, thisArg, argsArray) return propagation
        if let Some(callee_name) = self.get_expr_string(&call.callee)
            && callee_name == "Reflect.apply"
            && call.arguments.len() >= 3
        {
            let target_alias = call
                .arguments
                .first()
                .and_then(|arg0| self.get_callable_target_alias_from_argument(arg0));
            let target_key = call
                .arguments
                .first()
                .and_then(|arg0| self.get_callable_target_key_from_argument(arg0));

            if let Some(target_name) = target_key.as_ref()
                && (self.sanitizers.contains(target_name.as_str())
                    || Self::is_likely_sanitizer_name(target_name))
            {
                return (false, None);
            }

            if let Some(summary_key) = target_key.clone()
                && let Some(summary) = self.function_summaries.get(&summary_key)
            {
                if let Some(source) = &summary.return_without_tainted_params {
                    return (true, Some(source.clone()));
                }
                for (idx, fallback_source) in &summary.tainted_param_returns {
                    let (tainted, source_hint) =
                        self.resolve_reflect_apply_param_argument_taint(call, target_alias, *idx);
                    if tainted {
                        return (true, source_hint.or_else(|| Some(fallback_source.clone())));
                    }
                }
            }

            if let Some(target_name) = target_key
                && self.sources.contains(target_name.as_str())
            {
                return (true, Some(target_name));
            }
        }

        // Wrapper return propagation (fn.call / fn.apply)
        if let Some(wrapper_name) = self.get_callee_property_name(&call.callee)
            && (wrapper_name == "call" || wrapper_name == "apply")
            && let Some(target_expr) = self.get_callee_object_expr(&call.callee)
        {
            let target_alias = self.get_alias_for_expr(target_expr);
            let mut target_summary_key = self.get_summary_key_for_callee_expr(target_expr);
            if target_summary_key
                .as_ref()
                .and_then(|k| self.function_summaries.get(k))
                .is_none()
                && let Some(alias) = target_alias
            {
                target_summary_key = Some(alias.target.clone());
            }

            if let Some(summary_key) = target_summary_key
                && let Some(summary) = self.function_summaries.get(&summary_key)
            {
                if let Some(source) = &summary.return_without_tainted_params {
                    return (true, Some(source.clone()));
                }
                for (idx, fallback_source) in &summary.tainted_param_returns {
                    let (tainted, source_hint) = self.resolve_wrapper_param_argument_taint(
                        call,
                        &wrapper_name,
                        target_alias,
                        *idx,
                    );
                    if tainted {
                        return (true, source_hint.or_else(|| Some(fallback_source.clone())));
                    }
                }
            }

            let mut target_name = self.get_expr_string(target_expr);
            if target_name
                .as_ref()
                .is_none_or(|name| !self.sources.contains(name.as_str()))
                && let Some(alias) = target_alias
            {
                target_name = Some(alias.target.clone());
            }
            if let Some(target_name) = target_name
                && self.sources.contains(target_name.as_str())
            {
                return (true, Some(target_name));
            }
        }

        // Function summary-based return taint
        let mut summary_key = self.get_summary_key_for_callee_expr(&call.callee);
        if let Expression::Identifier(id) = &call.callee
            && (summary_key.is_none()
                || summary_key
                    .as_ref()
                    .and_then(|k| self.function_summaries.get(k))
                    .is_none())
        {
            summary_key = self
                .bound_function_aliases
                .get(id.name.as_str())
                .map(|alias| alias.target.clone())
                .or(summary_key);
        }
        let alias = self.get_alias_for_callee_identifier(call);
        if let Some(fn_key) = summary_key
            && let Some(summary) = self.function_summaries.get(&fn_key)
        {
            if let Some(source) = &summary.return_without_tainted_params {
                return (true, Some(source.clone()));
            }

            for (idx, fallback_source) in &summary.tainted_param_returns {
                let (tainted, source_hint) = self.resolve_param_argument_taint(call, alias, *idx);
                if tainted {
                    return (true, source_hint.or_else(|| Some(fallback_source.clone())));
                }
            }
        }
        if let Expression::Identifier(id) = &call.callee
            && let Some(bound_target) = self
                .bound_function_aliases
                .get(id.name.as_str())
                .map(|alias| alias.target.clone())
            && self.sources.contains(bound_target.as_str())
        {
            return (true, Some(bound_target));
        }

        // Direct source calls (e.g., localStorage.getItem(...))
        if let Expression::StaticMemberExpression(member) = &call.callee {
            if member.property.name.as_str() == "get"
                && let Some(source) = self.url_search_params_get_source(call, &member.object)
            {
                return (true, Some(source));
            }

            if let Some(callee_str) = self.get_member_string(member) {
                if let Some(storage_source) = self.storage_get_source(call, &callee_str) {
                    return (true, Some(storage_source));
                }
                if self.sources.contains(callee_str.as_str()) {
                    return (true, Some(callee_str));
                }
            }

            // Method call on tainted object (e.g., tainted.slice())
            if self.is_tainted(&member.object) {
                return (true, self.find_source_in_expr(&member.object));
            }
        }
        if let Expression::ComputedMemberExpression(member) = &call.callee {
            if let Some(callee_str) = self.get_computed_member_string(member)
                && self.sources.contains(callee_str.as_str())
            {
                return (true, Some(callee_str));
            }

            if self.is_tainted(&member.object) {
                return (true, self.find_source_in_expr(&member.object));
            }
        }

        // Conservative fallback: tainted argument taints call result.
        for arg in &call.arguments {
            let (tainted, source_hint) = self.argument_taint_and_source(arg);
            if tainted {
                return (true, source_hint);
            }
        }

        (false, None)
    }
    /// Source label when `member` reads an `XMLHttpRequest` response body
    /// (`xhr.responseText` / `xhr.response`) on a variable known to hold a
    /// `new XMLHttpRequest()` instance (issue #1024). The Ajax response is
    /// server/network-controlled and routinely echoes a reflected/stored
    /// param, so reading it is an untrusted DOM-XSS source.
    pub(super) fn xhr_response_source_for_member(
        &self,
        member: &StaticMemberExpression<'a>,
    ) -> Option<String> {
        let Expression::Identifier(id) = &member.object else {
            return None;
        };
        if self
            .instance_classes
            .get(id.name.as_str())
            .map(String::as_str)
            != Some("XMLHttpRequest")
        {
            return None;
        }
        match member.property.name.as_str() {
            "responseText" => Some("XMLHttpRequest.responseText".to_string()),
            "response" => Some("XMLHttpRequest.response".to_string()),
            _ => None,
        }
    }
    /// Source label when `member` reads the decoded bytes of a file the user
    /// supplied (`reader.result`) on a variable known to hold a
    /// `new FileReader()` instance. The file arrives by drag-and-drop or an
    /// `<input type=file>` picker, so its contents are attacker-influenced in
    /// exactly the same way as the `dataTransfer.getData` / `clipboardData`
    /// reads above — the canonical shape is a "preview the dropped file"
    /// widget that pushes `reader.result` straight into `innerHTML`.
    ///
    /// Only `result` is a source: `error` / `readyState` are status metadata.
    pub(super) fn file_reader_source_for_member(
        &self,
        member: &StaticMemberExpression<'a>,
    ) -> Option<String> {
        let Expression::Identifier(id) = &member.object else {
            return None;
        };
        if self
            .instance_classes
            .get(id.name.as_str())
            .map(String::as_str)
            != Some("FileReader")
        {
            return None;
        }
        (member.property.name.as_str() == "result").then(|| "FileReader.result".to_string())
    }
    /// Check if expression is tainted.
    ///
    /// Hostile JavaScript can nest expressions arbitrarily deep (`a.b.c.d…`,
    /// `a+a+a+…`, a flat call chain `x.a().a()…`, deeply nested arrays/objects),
    /// and oxc parses left-leaning member/binary chains iteratively, so the
    /// recursion here — not the parser — is what would overflow the stack and
    /// abort the whole scanner (an uncatchable SIGABRT). The shared recursion
    /// guard bails out as "not tainted" once depth reaches [`MAX_AST_VISIT_DEPTH`],
    /// far beyond any real-world code, and (unlike a per-call depth argument)
    /// keeps counting across the `call_taint_and_source` helper this delegates to
    /// for call expressions.
    pub(super) fn is_tainted(&self, expr: &Expression) -> bool {
        let Some(_guard) = self.enter_recursion() else {
            return false;
        };
        match expr {
            Expression::Identifier(id) => {
                self.tainted_vars.contains(id.name.as_str())
                    || self.global_taints.contains(id.name.as_str())
            }
            Expression::StaticMemberExpression(member) => {
                if self.url_search_params_source_for_member(member).is_some() {
                    return true;
                }
                if self.xhr_response_source_for_member(member).is_some() {
                    return true;
                }
                if self.file_reader_source_for_member(member).is_some() {
                    return true;
                }
                if let Some(full_path) = self.get_member_string(member) {
                    // Check field-level taint first for precise tracking
                    if self.field_taints.contains_key(&full_path) {
                        return true;
                    }
                    // Check if the full path is a known source
                    if self.sources.contains(full_path.as_str()) {
                        return true;
                    }
                }
                // Also check if the base object is a tainted variable
                // e.g., if 'data' is tainted, then 'data.field' is also tainted
                self.is_tainted(&member.object)
            }
            Expression::TemplateLiteral(template) => {
                template.expressions.iter().any(|e| self.is_tainted(e))
            }
            Expression::BinaryExpression(binary) => {
                self.is_tainted(&binary.left) || self.is_tainted(&binary.right)
            }
            Expression::LogicalExpression(logical) => {
                self.is_tainted(&logical.left) || self.is_tainted(&logical.right)
            }
            Expression::ConditionalExpression(cond) => {
                self.is_tainted(&cond.consequent) || self.is_tainted(&cond.alternate)
            }
            Expression::CallExpression(call) => self.call_taint_and_source(call).0,
            Expression::ArrayExpression(array) => {
                // Array is tainted if any element is tainted
                array.elements.iter().any(|elem| {
                    match elem {
                        oxc_ast::ast::ArrayExpressionElement::Elision(_) => false,
                        oxc_ast::ast::ArrayExpressionElement::SpreadElement(spread) => {
                            self.is_tainted(&spread.argument)
                        }
                        // All other variants are Expression variants (inherited)
                        _ => {
                            // Cast to Expression to check if tainted
                            if let Some(expr) = elem.as_expression() {
                                self.is_tainted(expr)
                            } else {
                                false
                            }
                        }
                    }
                })
            }
            Expression::ObjectExpression(obj) => {
                // Object is tainted if any property value is tainted
                obj.properties.iter().any(|prop| match prop {
                    oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) => {
                        self.is_tainted(&p.value)
                    }
                    oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                        self.is_tainted(&spread.argument)
                    }
                })
            }
            Expression::ComputedMemberExpression(member) => {
                if let Some(full_path) = self.get_computed_member_string(member)
                    && self.sources.contains(full_path.as_str())
                {
                    return true;
                }
                // Check if base object is tainted (e.g., arr[0] where arr is tainted)
                self.is_tainted(&member.object)
            }
            Expression::ParenthesizedExpression(paren) => {
                // Parentheses don't affect taint
                self.is_tainted(&paren.expression)
            }
            Expression::SequenceExpression(seq) => {
                // Sequence expression returns the last expression's value
                if let Some(last) = seq.expressions.last() {
                    self.is_tainted(last)
                } else {
                    false
                }
            }
            // `await taintedPromise` yields the resolved tainted value — e.g.
            // `await r.text()` on a fetch Response (issue #1024).
            Expression::AwaitExpression(await_expr) => self.is_tainted(&await_expr.argument),
            _ => false,
        }
    }
    /// Report a vulnerability with an optional explicit source
    pub(super) fn report_vulnerability_with_source(
        &mut self,
        span: oxc_span::Span,
        sink: &str,
        description: &str,
        explicit_source: Option<String>,
    ) {
        // An enforced, strict `'default'` Trusted Types policy auto-sanitizes
        // every TrustedHTML sink, so such a finding is a false positive.
        if self.default_policy_suppresses_sink(sink) {
            return;
        }

        let offset = span.start as usize;
        // Binary search for the line containing this byte offset
        let line_idx = match self.line_starts.binary_search(&offset) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        let line = (line_idx + 1) as u32;
        let column = (offset - self.line_starts[line_idx] + 1) as u32;

        let snippet = {
            let start = self.line_starts[line_idx];
            let end = self
                .line_starts
                .get(line_idx + 1)
                .copied()
                .unwrap_or(self.source_code.len());
            // Trim trailing newline from line slice
            let line_slice = &self.source_code[start..end];
            line_slice.trim().to_string()
        };

        // Find the source that led to this
        let source = explicit_source
            .or_else(|| {
                self.tainted_vars
                    .iter()
                    .next()
                    .and_then(|var| self.var_aliases.get(var))
                    .cloned()
            })
            .unwrap_or_else(|| "unknown source".to_string());

        self.vulnerabilities.push(DomXssVulnerability {
            line,
            column,
            source,
            sink: sink.to_string(),
            snippet,
            description: description.to_string(),
            // Reported from inside a conditional / loop / try body, so the flow
            // is only taken on some paths. Consumed as a confidence signal by
            // `ast_integration::grade_ast_finding`; the analysis itself stays
            // flow-insensitive and still reports the finding.
            guarded: self.branch_depth > 0,
        });
    }
}
