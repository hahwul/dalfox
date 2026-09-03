//! Taint that travels through `fetch`, `await`, and promise chains.
//!
//! A response body reached through `.then(r => r.text())` is as untrusted as
//! `location.hash`, and the value arrives one callback removed from the call
//! that produced it — so promise-returning calls carry a kind through the chain.

use super::*;

impl<'a> DomXssVisitor<'a> {
    /// Recognise the `fetch(...)` global call (bare, or via `window`/`self`/
    /// `globalThis`). Its returned Promise resolves to a `Response`.
    pub(super) fn is_fetch_call(&self, call: &CallExpression<'a>) -> bool {
        match &call.callee {
            Expression::Identifier(id) => id.name == "fetch",
            Expression::StaticMemberExpression(_) => matches!(
                self.get_expr_string(&call.callee).as_deref(),
                Some("window.fetch" | "self.fetch" | "globalThis.fetch")
            ),
            _ => false,
        }
    }
    /// True when `expr` is `await fetch(...)` (through parentheses) — the
    /// awaited value is a `Response`, so a variable bound to it has
    /// `.text()`/`.json()` reads that are tainted network data (issue #1024).
    pub(super) fn awaited_fetch_var(&self, expr: &Expression<'a>) -> bool {
        let inner = match expr {
            Expression::AwaitExpression(a) => &a.argument,
            Expression::ParenthesizedExpression(p) => return self.awaited_fetch_var(&p.expression),
            _ => return false,
        };
        let mut current = inner;
        loop {
            match current {
                Expression::ParenthesizedExpression(p) => current = &p.expression,
                Expression::CallExpression(call) => return self.is_fetch_call(call),
                _ => return false,
            }
        }
    }
    /// Resolve the indirect-eval idiom `(0, eval)(code)` to its sink name.
    ///
    /// Wrapping a bare `eval` reference in a comma expression detaches it from
    /// the *direct* eval reference, so the code runs in global scope instead of
    /// the caller's. Only the last element of the sequence is the callee;
    /// earlier operands are evaluated and discarded. `get_expr_string` sees a
    /// parenthesized `SequenceExpression` and yields nothing, so without this
    /// the sink lookup misses the call entirely.
    ///
    /// Returns a name only when it resolves to an already-known sink — this
    /// never invents one.
    pub(super) fn indirect_call_sink_name(&self, call: &CallExpression<'a>) -> Option<String> {
        let mut current = &call.callee;
        loop {
            match current {
                Expression::ParenthesizedExpression(p) => current = &p.expression,
                Expression::SequenceExpression(seq) => current = seq.expressions.last()?,
                _ => break,
            }
        }
        let name = self.get_expr_string(current)?;
        self.sinks.contains(name.as_str()).then_some(name)
    }
    /// Recognise a call that returns a Promise resolving to attacker-controlled
    /// data. Unlike `fetch(...)` — whose Promise resolves to a `Response` whose
    /// `.text()`/`.json()` reads are the tainted part — these resolve *directly*
    /// to the untrusted string, so the chain kind is `Tainted` at the root.
    ///
    /// Returns the source label to report.
    ///
    /// Kept as an explicit list rather than reusing the whole `DOM_SOURCES` set:
    /// most sources are synchronous reads (`localStorage.getItem(...)` returns a
    /// string, not a Promise), and treating those as Promise roots would attach
    /// chain semantics to values that never have a `.then`.
    pub(super) fn async_tainted_source_call(&self, call: &CallExpression<'a>) -> Option<String> {
        const ASYNC_TAINTED_SOURCE_CALLS: &[&str] = &[
            // `navigator.clipboard.readText()` resolves to the clipboard text —
            // the async counterpart of the `event.clipboardData.getData` read
            // already modeled as a source.
            "navigator.clipboard.readText",
            "window.navigator.clipboard.readText",
        ];
        let callee = self.get_expr_string(&call.callee)?;
        ASYNC_TAINTED_SOURCE_CALLS
            .contains(&callee.as_str())
            .then_some(callee)
    }
    /// Recognise a `Promise` *static* combinator whose settled value carries
    /// taint from its argument — `Promise.resolve(x)`, and the array
    /// combinators `Promise.all/allSettled/race/any([… x …])`.
    ///
    /// These are not sources of their own: the taint has to already be in the
    /// argument, so a `Promise.resolve('static')` chain stays clean. What they
    /// add is the *link*, so the value survives the microtask hop into the
    /// `.then` callback's parameter — the `Promise.all([a, tainted, b])
    /// .then(parts => sink(parts.join('')))` shape, where the tainted element is
    /// identified only by its index in the settled array.
    ///
    /// The array combinators resolve to a container (an array, or for
    /// `allSettled` an array of result wrappers) rather than the value itself;
    /// treating the container as tainted is the same over-approximation the
    /// analysis already makes for `arr.push(tainted)` and object literals.
    pub(super) fn promise_combinator_source(&self, call: &CallExpression<'a>) -> Option<String> {
        const PROMISE_COMBINATORS: &[&str] = &[
            "Promise.resolve",
            "Promise.all",
            "Promise.allSettled",
            "Promise.race",
            "Promise.any",
        ];
        let callee = self.get_expr_string(&call.callee)?;
        if !PROMISE_COMBINATORS.contains(&callee.as_str()) {
            return None;
        }
        let arg = call.arguments.first()?;
        let (tainted, source) = self.argument_taint_and_source(arg);
        tainted.then(|| source.unwrap_or(callee))
    }
    /// If `call` invokes a Promise combinator (`.then` / `.catch` / `.finally`),
    /// return the method name.
    pub(super) fn promise_method_name(call: &CallExpression<'a>) -> Option<&'static str> {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return None;
        };
        match member.property.name.as_str() {
            "then" => Some("then"),
            "catch" => Some("catch"),
            "finally" => Some("finally"),
            _ => None,
        }
    }
    /// True when this `.then`/`.catch`/`.finally` call sits on a Promise chain
    /// whose root produces untrusted data — a `fetch(...)` call, or an async
    /// source call such as `navigator.clipboard.readText()`. Walks the receiver
    /// chain down through nested combinators.
    pub(super) fn promise_chain_roots_at_untrusted_source(
        &self,
        call: &CallExpression<'a>,
    ) -> bool {
        let mut current: &Expression<'a> = match &call.callee {
            Expression::StaticMemberExpression(m) => &m.object,
            _ => return false,
        };
        loop {
            match current {
                Expression::ParenthesizedExpression(p) => current = &p.expression,
                Expression::CallExpression(inner) => {
                    if self.is_fetch_call(inner)
                        || self.async_tainted_source_call(inner).is_some()
                        || self.promise_combinator_source(inner).is_some()
                    {
                        return true;
                    }
                    if Self::promise_method_name(inner).is_some()
                        && let Expression::StaticMemberExpression(m) = &inner.callee
                    {
                        current = &m.object;
                        continue;
                    }
                    return false;
                }
                _ => return false,
            }
        }
    }
    /// First `return <expr>;` argument in a callback's block body, used to
    /// thread the resolved value of one `.then` callback into the next.
    pub(super) fn first_return_expr<'b>(stmts: &'b [Statement<'a>]) -> Option<&'b Expression<'a>> {
        for stmt in stmts {
            if let Statement::ReturnStatement(ret) = stmt {
                return ret.argument.as_ref();
            }
        }
        None
    }
    /// Drive a `fetch().then(...)…` Promise chain (issue #1024): walk each
    /// callback body so nested sinks fire, threading the resolved value
    /// (`Response`, then the awaited text/json) from one callback's return
    /// into the next callback's parameter. Returns the kind the chain
    /// ultimately resolves to (unused at the top level).
    pub(super) fn promise_kind_of_call(&mut self, call: &CallExpression<'a>) -> PromiseValueKind {
        // A long `fetch(u).then(f).then(f)…` chain recurses through this driver
        // once per link, outside the expression/statement walkers, so it carries
        // the shared recursion guard itself (bail = "unknown promise value").
        let Some(_guard) = self.enter_recursion() else {
            return PromiseValueKind::Unknown;
        };
        if self.is_fetch_call(call) {
            // The URL argument is rarely a sink, but walk it so any nested
            // source/sink inside the request expression is still visited.
            for arg in &call.arguments {
                if let Some(expr) = arg.as_expression() {
                    self.walk_expression(expr);
                }
            }
            return PromiseValueKind::Response;
        }

        // An async source call (`navigator.clipboard.readText()`) resolves
        // straight to the untrusted string, so the chain is tainted at its root.
        if let Some(source) = self.async_tainted_source_call(call) {
            for arg in &call.arguments {
                if let Some(expr) = arg.as_expression() {
                    self.walk_expression(expr);
                }
            }
            return PromiseValueKind::Tainted(source);
        }

        // `Promise.resolve(tainted)` / `Promise.all([… tainted …])` settle to a
        // value that carries the argument's taint into the next `.then`.
        if let Some(source) = self.promise_combinator_source(call) {
            for arg in &call.arguments {
                if let Some(expr) = arg.as_expression() {
                    self.walk_expression(expr);
                }
            }
            return PromiseValueKind::Tainted(source);
        }

        let Some(method) = Self::promise_method_name(call) else {
            return PromiseValueKind::Unknown;
        };
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return PromiseValueKind::Unknown;
        };
        let receiver_kind = self.promise_kind_of_expr(&member.object);

        match method {
            "then" => {
                // arg0 = onFulfilled (the resolved value); arg1 = onRejected
                // (an error — never the tainted response body).
                if let Some(on_rejected) = call.arguments.get(1) {
                    self.process_promise_callback(on_rejected, PromiseValueKind::Unknown);
                }
                match call.arguments.first() {
                    Some(on_fulfilled) => {
                        self.process_promise_callback(on_fulfilled, receiver_kind)
                    }
                    None => receiver_kind,
                }
            }
            // `.catch` / `.finally`: still walk the callback, but on the
            // success path the resolved value flows through unchanged.
            _ => {
                if let Some(cb) = call.arguments.first() {
                    self.process_promise_callback(cb, PromiseValueKind::Unknown);
                }
                receiver_kind
            }
        }
    }
    pub(super) fn promise_kind_of_expr(&mut self, expr: &Expression<'a>) -> PromiseValueKind {
        let Some(_guard) = self.enter_recursion() else {
            return PromiseValueKind::Unknown;
        };
        match expr {
            Expression::ParenthesizedExpression(p) => self.promise_kind_of_expr(&p.expression),
            Expression::CallExpression(call) => self.promise_kind_of_call(call),
            _ => PromiseValueKind::Unknown,
        }
    }
    /// Walk a `.then`/`.catch`/`.finally` callback with its first parameter
    /// bound to the incoming Promise value, then report the value its body
    /// returns so the next `.then` in the chain sees it.
    pub(super) fn process_promise_callback(
        &mut self,
        cb_arg: &Argument<'a>,
        incoming: PromiseValueKind,
    ) -> PromiseValueKind {
        let Some(expr) = cb_arg.as_expression() else {
            return PromiseValueKind::Unknown;
        };

        let (param_name, statements, return_expr): (
            Option<String>,
            &oxc_allocator::Vec<'a, Statement<'a>>,
            Option<&Expression<'a>>,
        ) = match expr {
            Expression::FunctionExpression(func) => {
                let Some(body) = &func.body else {
                    return PromiseValueKind::Unknown;
                };
                let pname = Self::first_param_name(&func.params);
                let ret = Self::first_return_expr(&body.statements);
                (pname, &body.statements, ret)
            }
            Expression::ArrowFunctionExpression(arrow) => {
                let pname = Self::first_param_name(&arrow.params);
                let ret = if arrow.expression {
                    match arrow.body.statements.first() {
                        Some(Statement::ExpressionStatement(stmt)) => Some(&stmt.expression),
                        _ => None,
                    }
                } else {
                    Self::first_return_expr(&arrow.body.statements)
                };
                (pname, &arrow.body.statements, ret)
            }
            // Named callback, e.g. `.then(render)`.
            Expression::Identifier(id) => {
                return self.named_promise_callback_kind(id.name.as_str(), id.span, &incoming);
            }
            _ => return PromiseValueKind::Unknown,
        };

        let saved_tainted = self.tainted_vars.clone();
        let saved_aliases = self.var_aliases.clone();
        let saved_response_vars = self.response_object_vars.clone();

        if let Some(name) = &param_name {
            // A fresh parameter binding shadows any same-named outer state.
            self.tainted_vars.remove(name);
            self.var_aliases.remove(name);
            self.response_object_vars.remove(name);
            match &incoming {
                PromiseValueKind::Response => {
                    self.response_object_vars.insert(name.clone());
                }
                PromiseValueKind::Tainted(source) => {
                    self.tainted_vars.insert(name.clone());
                    self.var_aliases.insert(name.clone(), source.clone());
                }
                PromiseValueKind::Unknown => {}
            }
        }

        self.walk_statements(statements);

        let result_kind = match return_expr {
            Some(re) if self.is_tainted(re) => PromiseValueKind::Tainted(
                self.find_source_in_expr(re)
                    .unwrap_or_else(|| "Response.text".to_string()),
            ),
            _ => PromiseValueKind::Unknown,
        };

        self.tainted_vars = saved_tainted;
        self.var_aliases = saved_aliases;
        self.response_object_vars = saved_response_vars;

        result_kind
    }
    /// Handle a named `.then(namedFn)` callback against the resolved promise
    /// value. When the incoming value is tainted and the callback's summary
    /// says its first parameter reaches a sink (e.g.
    /// `fetch().then(r => r.text()).then(render)` with
    /// `function render(t){ el.innerHTML = t; }`), report it — the
    /// fetch-chain driver consumed the call, so the normal function-summary
    /// call-site path never runs for this reference. Also propagate the
    /// callback's tainted return so the next `.then` sees it.
    pub(super) fn named_promise_callback_kind(
        &mut self,
        fn_name: &str,
        span: oxc_span::Span,
        incoming: &PromiseValueKind,
    ) -> PromiseValueKind {
        // Sink reached by the callback's first parameter, when the resolved
        // value flowing into it is tainted.
        if let PromiseValueKind::Tainted(source) = incoming
            && let Some(sink_name) = self
                .function_summaries
                .get(fn_name)
                .and_then(|summary| summary.tainted_param_sinks.get(&0))
                .cloned()
        {
            self.report_vulnerability_with_source(
                span,
                &sink_name,
                "Tainted fetch response reaches sink through named .then() callback",
                Some(source.clone()),
            );
        }

        if let Some(summary) = self.function_summaries.get(fn_name) {
            if matches!(
                incoming,
                PromiseValueKind::Tainted(_) | PromiseValueKind::Response
            ) && let Some(src) = summary.tainted_param_returns.get(&0)
            {
                return PromiseValueKind::Tainted(src.clone());
            }
            if let Some(src) = &summary.return_without_tainted_params {
                return PromiseValueKind::Tainted(src.clone());
            }
        }
        PromiseValueKind::Unknown
    }
    pub(super) fn first_param_name(params: &FormalParameters<'a>) -> Option<String> {
        params.items.first().and_then(|p| match &p.pattern {
            BindingPattern::BindingIdentifier(id) => Some(id.name.to_string()),
            _ => None,
        })
    }
}
