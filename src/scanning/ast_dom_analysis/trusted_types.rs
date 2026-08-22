//! Trusted Types policy analysis.
//!
//! A `trustedTypes.createPolicy` whose `createHTML` actually sanitizes turns its
//! sinks inert; one that returns its input unchanged does not. Classifying the
//! callback is what separates a real finding from a page that already defends
//! itself, so the strictness verdict is derived from the callback body rather
//! than from the policy's existence.

use super::*;

impl<'a> DomXssVisitor<'a> {
    // --- Trusted Types policy recognition ---------------------------------
    //
    // A `trustedTypes.createPolicy(name, { createHTML, createScript,
    // createScriptURL })` registers conversion callbacks. Two shapes matter:
    //   * an *explicit* wrapper call `policy.createHTML(x)` whose result feeds a
    //     sink — a strict callback sanitizes `x` (taint cleared), a permissive
    //     one (`x => x`) does not (taint kept, finding flagged);
    //   * the `'default'` policy, which the browser auto-applies to every
    //     TrustedHTML sink *when `require-trusted-types-for` is enforced* — a
    //     strict default `createHTML` neutralizes those sinks (see
    //     [`default_policy_suppresses_sink`]).
    //
    // [`default_policy_suppresses_sink`]: DomXssVisitor::default_policy_suppresses_sink

    /// If `call` is `trustedTypes.createPolicy(name, {...})` (bare or via
    /// `window`/`self`/`globalThis`), return the static policy name (when
    /// determinable) and its config object literal.
    pub(super) fn tt_create_policy_config<'b>(
        &self,
        call: &'b CallExpression<'a>,
    ) -> Option<(Option<String>, &'b ObjectExpression<'a>)> {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return None;
        };
        if member.property.name.as_str() != "createPolicy" {
            return None;
        }
        let is_trusted_types = matches!(
            self.get_expr_string(&member.object).as_deref(),
            Some(
                "trustedTypes"
                    | "window.trustedTypes"
                    | "self.trustedTypes"
                    | "globalThis.trustedTypes"
            )
        );
        if !is_trusted_types {
            return None;
        }
        let name = call
            .arguments
            .first()
            .and_then(|a| a.as_expression())
            .and_then(|e| self.eval_static_string_expr(e));
        let config = call
            .arguments
            .get(1)
            .and_then(|a| a.as_expression())
            .and_then(|e| match e {
                Expression::ObjectExpression(o) => Some(&**o),
                _ => None,
            });
        config.map(|c| (name, c))
    }
    /// Same as [`tt_create_policy_config`] but accepts any expression (unwraps
    /// parentheses), used for the inline `createPolicy(...).createHTML(x)` chain.
    ///
    /// [`tt_create_policy_config`]: DomXssVisitor::tt_create_policy_config
    pub(super) fn tt_create_policy_call<'b>(
        &self,
        expr: &'b Expression<'a>,
    ) -> Option<(Option<String>, &'b ObjectExpression<'a>)> {
        match expr {
            Expression::CallExpression(call) => self.tt_create_policy_config(call),
            Expression::ParenthesizedExpression(p) => self.tt_create_policy_call(&p.expression),
            _ => None,
        }
    }
    /// First parameter of a `create*` callback, classified for the strictness
    /// analysis. A default/destructured/rest param is [`TtParam::Complex`]
    /// (reachable input we can't name-track → conservatively permissive); only a
    /// plain identifier is trackable, and only a genuinely empty parameter list
    /// is [`TtParam::None`].
    pub(super) fn tt_callback_param(params: &FormalParameters<'a>) -> TtParam {
        match params.items.first() {
            Some(p) => match &p.pattern {
                BindingPattern::BindingIdentifier(id) => TtParam::Named(id.name.to_string()),
                _ => TtParam::Complex,
            },
            None if params.rest.is_some() => TtParam::Complex,
            None => TtParam::None,
        }
    }
    /// Classify a policy `create*` callback as strict (genuinely sanitizing) or
    /// permissive. Conservative by construction: anything not *provably* safe is
    /// permissive, so the taint is kept and no false negative is introduced.
    ///
    /// A callback is strict only when:
    ///   * it has no trackable parameter at all (can't pass the input through); or
    ///   * its return expression is a recognised sanitizer call **and** the
    ///     parameter is referenced *only* inside that call — i.e. no other
    ///     statement (a guarded `return s`, a `'<b>'+s` concat, …) leaks the raw
    ///     input. The reference test is textual over the whole body source, so
    ///     it catches passthrough at any nesting depth and in any return path,
    ///     and only ever errs toward permissive.
    pub(super) fn classify_tt_create_method(&self, fn_expr: &Expression<'a>) -> TtStrictness {
        let (params, stmts): (
            &FormalParameters<'a>,
            &oxc_allocator::Vec<'a, Statement<'a>>,
        ) = match fn_expr {
            Expression::ArrowFunctionExpression(arrow) => (&arrow.params, &arrow.body.statements),
            Expression::FunctionExpression(func) => match &func.body {
                Some(body) => (&func.params, &body.statements),
                None => return TtStrictness::Permissive,
            },
            // Not a callback we can analyze (e.g. a bare identifier reference)
            // — assume the worst: permissive, so the finding is kept.
            _ => return TtStrictness::Permissive,
        };

        let param = Self::tt_callback_param(params);
        // A default/destructured/rest param routes the input through in a way we
        // can't name-track — keep the finding.
        let param_name = match &param {
            TtParam::None => None,
            TtParam::Named(name) => Some(name.as_str()),
            TtParam::Complex => return TtStrictness::Permissive,
        };

        // The "result" expression used for sanitizer detection: an arrow concise
        // body's expression, otherwise the first `return`.
        let result = match fn_expr {
            Expression::ArrowFunctionExpression(arrow) if arrow.expression => match stmts.first() {
                Some(Statement::ExpressionStatement(stmt)) => Some(&stmt.expression),
                _ => None,
            },
            _ => Self::first_return_expr(stmts),
        };
        let result = result.map(|mut r| {
            while let Expression::ParenthesizedExpression(p) = r {
                r = &p.expression;
            }
            r
        });

        // Body source (statements only — excludes the parameter list, so the
        // parameter declaration itself never counts as a reference).
        let body_src = self.stmts_source(stmts);

        // (1) Result is a recognised sanitizer call. Grant strict only when the
        //     parameter is referenced nowhere *outside* that call — otherwise
        //     another path (e.g. `if (c) return s;`) could leak the raw input.
        if let Some(Expression::CallExpression(call)) = result
            && let Some(name) = self.get_expr_string(&call.callee)
            && (self.sanitizers.contains(name.as_str()) || Self::is_likely_sanitizer_name(&name))
        {
            let Some(p) = param_name else {
                return TtStrictness::Strict;
            };
            let call_src = self.expr_source(result.unwrap());
            let rest = body_src.replacen(call_src, "", 1);
            if Self::identifier_referenced(&rest, p) {
                return TtStrictness::Permissive;
            }
            return TtStrictness::Strict;
        }

        // (2) No sanitizer: strict only when the parameter is never referenced in
        //     the body (input isn't passed through). The token check only ever
        //     errs toward permissive, so it never mislabels a passthrough.
        match param_name {
            Some(p) => {
                if Self::identifier_referenced(body_src, p) {
                    TtStrictness::Permissive
                } else {
                    TtStrictness::Strict
                }
            }
            None => TtStrictness::Strict,
        }
    }
    /// Whether `name` appears in `src` as a standalone identifier token — i.e.
    /// not as a substring inside a longer identifier/keyword. Bounded on both
    /// sides by a non-identifier byte (`[A-Za-z0-9_$]`).
    ///
    /// A deliberately text-based (rather than AST-based) reference check: it
    /// catches every real identifier reference (a JS identifier is always
    /// delimited by non-identifier characters), so it never mislabels a genuine
    /// passthrough as strict — preserving the no-false-negative guarantee. It is
    /// stricter than a raw `contains`, so `param "s"` no longer matches inside
    /// `sanitize` / `console` / `"processing"`, recovering the intended
    /// false-positive suppression. (It does not strip string/comment contents;
    /// a bare token there still matches, which only over-keeps a finding.)
    pub(super) fn identifier_referenced(src: &str, name: &str) -> bool {
        if name.is_empty() {
            return false;
        }
        let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$';
        let bytes = src.as_bytes();
        let mut from = 0;
        while let Some(rel) = src[from..].find(name) {
            let start = from + rel;
            let end = start + name.len();
            let before_ok = start == 0 || !is_ident(bytes[start - 1]);
            let after_ok = end == bytes.len() || !is_ident(bytes[end]);
            if before_ok && after_ok {
                return true;
            }
            // Advance past the whole match, never by one byte: `start` is a
            // char boundary and the match spans exactly `name.len()` bytes, so
            // `start + name.len()` is one too. `start + 1` lands *inside* the
            // needle's first codepoint whenever that codepoint is multi-byte
            // (JS identifiers may start with any ID_Start char, and a Trusted
            // Types callback parameter name comes straight off the scanned
            // page), and the next `src[from..]` then panics with "byte index N
            // is not a char boundary". Skipping the match is also correct:
            // an overlapping later occurrence starts inside `name`, so it is
            // preceded by an identifier byte and could never pass `before_ok`.
            from = start + name.len();
        }
        false
    }
    /// Source text spanning a list of statements (first start .. last end),
    /// empty when the list is empty. Used to inspect a callback body without
    /// the surrounding braces or parameter list.
    pub(super) fn stmts_source(&self, stmts: &[Statement<'a>]) -> &'a str {
        match (stmts.first(), stmts.last()) {
            (Some(first), Some(last)) => self
                .source_code
                .get(first.span().start as usize..last.span().end as usize)
                .unwrap_or(""),
            _ => "",
        }
    }
    /// Source text of a single expression.
    pub(super) fn expr_source(&self, expr: &Expression<'a>) -> &'a str {
        let span = expr.span();
        self.source_code
            .get(span.start as usize..span.end as usize)
            .unwrap_or("")
    }
    /// Build a [`TtPolicyInfo`] from a `createPolicy` config object literal.
    pub(super) fn build_tt_policy_info(&self, config: &ObjectExpression<'a>) -> TtPolicyInfo {
        let mut info = TtPolicyInfo {
            create_html: TtStrictness::Permissive,
            create_script: TtStrictness::Permissive,
            create_script_url: TtStrictness::Permissive,
        };
        for prop in &config.properties {
            let oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) = prop else {
                continue;
            };
            let Some(key) = self.get_property_key_name(&p.key) else {
                continue;
            };
            match key.as_str() {
                "createHTML" => info.create_html = self.classify_tt_create_method(&p.value),
                "createScript" => info.create_script = self.classify_tt_create_method(&p.value),
                "createScriptURL" => {
                    info.create_script_url = self.classify_tt_create_method(&p.value)
                }
                _ => {}
            }
        }
        info
    }
    /// Record a `var p = trustedTypes.createPolicy(name, {...})` binding so a
    /// later `p.createHTML(x)` resolves, and remember the `'default'` policy.
    /// Reassigning `p` to a non-policy clears the stale entry.
    pub(super) fn record_tt_policy_binding(&mut self, var_name: &str, init: &Expression<'a>) {
        if let Some((name, config)) = self.tt_create_policy_call(init) {
            let info = self.build_tt_policy_info(config);
            self.tt_policies.insert(var_name.to_string(), info);
            if name.as_deref() == Some("default") {
                self.default_tt_policy = Some(info);
            }
        } else {
            self.tt_policies.remove(var_name);
        }
    }
    /// If `call` is a Trusted Types `create*` wrapper (`policy.createHTML(x)`,
    /// `.createScript`, `.createScriptURL`) — either on a tracked policy
    /// variable or an inline `createPolicy(...).createHTML(x)` chain — return
    /// the strictness of the corresponding callback.
    pub(super) fn tt_wrapper_call_strictness(
        &self,
        call: &CallExpression<'a>,
    ) -> Option<TtStrictness> {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return None;
        };
        let pick = |info: &TtPolicyInfo| match member.property.name.as_str() {
            "createHTML" => Some(info.create_html),
            "createScript" => Some(info.create_script),
            "createScriptURL" => Some(info.create_script_url),
            _ => None,
        };
        if let Expression::Identifier(id) = &member.object
            && let Some(info) = self.tt_policies.get(id.name.as_str())
        {
            return pick(info);
        }
        if let Some((_, config)) = self.tt_create_policy_call(&member.object) {
            return pick(&self.build_tt_policy_info(config));
        }
        None
    }
    /// TrustedHTML-family sinks: the ones the browser routes through a Trusted
    /// Types `createHTML` policy (including the default policy) under
    /// enforcement. Script / ScriptURL sinks are intentionally excluded — they
    /// use `createScript` / `createScriptURL`, which the default-policy
    /// suppression does not model.
    pub(super) fn is_trusted_html_sink(sink: &str) -> bool {
        matches!(
            sink,
            "innerHTML"
                | "outerHTML"
                | "insertAdjacentHTML"
                | "createContextualFragment"
                | "document.write"
                | "document.writeln"
                | "setHTMLUnsafe"
                | "parseHTMLUnsafe"
                | "srcdoc"
                | "html"
        )
    }
    /// Whether an enforced, strict `'default'` Trusted Types policy neutralizes
    /// this TrustedHTML sink, making the finding a false positive.
    ///
    /// FN guard: if *any* explicit policy in this block has a permissive
    /// `createHTML`, a value could reach the sink as an already-`TrustedHTML`
    /// (but unsanitized) object the default policy never re-checks — so we do
    /// not suppress, keeping the finding.
    ///
    /// Scope note: analysis is per-`<script>` block, so `default_tt_policy` only
    /// reflects a `'default'` policy defined in the *same* block as the sink. A
    /// policy created in a separate block leaves this `None` here, so the
    /// finding is kept — the safe (no-false-negative) direction.
    pub(super) fn default_policy_suppresses_sink(&self, sink: &str) -> bool {
        if !self.trusted_types_enforced {
            return false;
        }
        let Some(policy) = &self.default_tt_policy else {
            return false;
        };
        if policy.create_html != TtStrictness::Strict || !Self::is_trusted_html_sink(sink) {
            return false;
        }
        self.tt_policies
            .values()
            .all(|p| p.create_html == TtStrictness::Strict)
    }
}
