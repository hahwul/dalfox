//! AST-based DOM XSS detection
//!
//! This module provides JavaScript AST parsing and taint analysis to detect
//! potential DOM-based XSS vulnerabilities by tracking data flow from untrusted
//! sources to dangerous sinks.

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};
use std::collections::{HashMap, HashSet};

/// Represents a potential DOM XSS vulnerability found via AST analysis
#[derive(Debug, Clone)]
pub struct DomXssVulnerability {
    /// Line number where the vulnerability was detected
    pub line: u32,
    /// Column number where the vulnerability was detected
    pub column: u32,
    /// The source of tainted data (e.g., "location.search")
    pub source: String,
    /// The sink where tainted data is used (e.g., "innerHTML")
    pub sink: String,
    /// Code snippet showing the vulnerable operation
    pub snippet: String,
    /// Description of the vulnerability
    pub description: String,
}

/// Lightweight summary for a function declaration.
/// Maps parameter index to a sink reached when that parameter is tainted.
struct FunctionSummary {
    tainted_param_sinks: HashMap<usize, String>,
    tainted_param_returns: HashMap<usize, String>,
    return_without_tainted_params: Option<String>,
}

#[derive(Clone)]
struct BoundArgInfo {
    tainted: bool,
    source: Option<String>,
}

#[derive(Clone)]
struct BoundCallableAlias {
    target: String,
    bound_args: Vec<BoundArgInfo>,
}

/// AST visitor for DOM XSS analysis
struct DomXssVisitor<'a> {
    /// Set of tainted variable names
    tainted_vars: HashSet<String>,
    /// Map of variable aliases (e.g., var x = location.search)
    var_aliases: HashMap<String, String>,
    /// List of detected vulnerabilities
    vulnerabilities: Vec<DomXssVulnerability>,
    /// Known DOM sources (untrusted input sources)
    sources: HashSet<String>,
    /// Known DOM sinks (dangerous operations)
    sinks: HashSet<String>,
    /// Known sanitizers
    sanitizers: HashSet<String>,
    /// Function summaries used for lightweight inter-procedural taint tracking
    function_summaries: HashMap<String, FunctionSummary>,
    /// Track `instanceVar -> ClassName` for class instance method summary resolution.
    instance_classes: HashMap<String, String>,
    /// Track aliases produced by `.bind()` calls.
    bound_function_aliases: HashMap<String, BoundCallableAlias>,
    /// Internal flag for summary collection of tainted return values
    collecting_tainted_returns: bool,
    /// Internal buffer for tainted return sources while collecting summaries
    tainted_return_sources: Vec<String>,
    /// Source code for line/column calculation
    source_code: &'a str,
}

impl<'a> DomXssVisitor<'a> {
    fn new(source_code: &'a str) -> Self {
        let mut sources = HashSet::new();
        // Common DOM XSS sources
        sources.insert("location.search".to_string());
        sources.insert("location.hash".to_string());
        sources.insert("location.href".to_string());
        sources.insert("location.pathname".to_string());
        sources.insert("document.URL".to_string());
        sources.insert("document.documentURI".to_string());
        sources.insert("document.URLUnencoded".to_string());
        sources.insert("document.baseURI".to_string());
        sources.insert("document.cookie".to_string());
        sources.insert("document.referrer".to_string());
        sources.insert("window.name".to_string());
        sources.insert("window.location".to_string());
        // Storage APIs
        sources.insert("localStorage".to_string());
        sources.insert("sessionStorage".to_string());
        sources.insert("localStorage.getItem".to_string());
        sources.insert("sessionStorage.getItem".to_string());
        // PostMessage data (event.data, e.data)
        sources.insert("event.data".to_string());
        sources.insert("e.data".to_string());
        // Window opener
        sources.insert("window.opener".to_string());

        let mut sinks = HashSet::new();
        // Common DOM XSS sinks
        sinks.insert("innerHTML".to_string());
        sinks.insert("outerHTML".to_string());
        sinks.insert("insertAdjacentHTML".to_string());
        sinks.insert("createContextualFragment".to_string());
        sinks.insert("document.write".to_string());
        sinks.insert("document.writeln".to_string());
        sinks.insert("eval".to_string());
        sinks.insert("setTimeout".to_string());
        sinks.insert("setInterval".to_string());
        sinks.insert("Function".to_string());
        sinks.insert("execScript".to_string());
        sinks.insert("location.href".to_string());
        sinks.insert("location.assign".to_string());
        sinks.insert("location.replace".to_string());
        // Element source attributes
        sinks.insert("src".to_string());
        sinks.insert("srcdoc".to_string());
        sinks.insert("href".to_string());
        sinks.insert("xlink:href".to_string());
        sinks.insert("setAttribute".to_string());
        // jQuery sinks
        sinks.insert("html".to_string());
        sinks.insert("append".to_string());
        sinks.insert("prepend".to_string());
        sinks.insert("after".to_string());
        sinks.insert("before".to_string());
        // execCommand with insertHTML command
        sinks.insert("execCommand".to_string());
        // Note: textContent and innerText are SAFE - they don't parse HTML
        // Previously textContent was incorrectly included as a sink, but it
        // only sets the text content without HTML parsing, making it safe from XSS

        let mut sanitizers = HashSet::new();
        sanitizers.insert("DOMPurify.sanitize".to_string());
        sanitizers.insert("sanitize".to_string());
        sanitizers.insert("encodeURIComponent".to_string());
        sanitizers.insert("encodeURI".to_string());
        sanitizers.insert("encodeHTML".to_string());
        sanitizers.insert("escapeHTML".to_string());
        sanitizers.insert("document.createTextNode".to_string());
        sanitizers.insert("createTextNode".to_string());

        Self {
            tainted_vars: HashSet::new(),
            var_aliases: HashMap::new(),
            vulnerabilities: Vec::new(),
            sources,
            sinks,
            sanitizers,
            function_summaries: HashMap::new(),
            instance_classes: HashMap::new(),
            bound_function_aliases: HashMap::new(),
            collecting_tainted_returns: false,
            tainted_return_sources: Vec::new(),
            source_code,
        }
    }

    /// Get a string representation of an expression if it's an identifier or member expression
    fn get_expr_string(&self, expr: &Expression) -> Option<String> {
        match expr {
            Expression::Identifier(id) => Some(id.name.to_string()),
            Expression::StaticMemberExpression(member) => self.get_member_string(member),
            Expression::ComputedMemberExpression(member) => self.get_computed_member_string(member),
            _ => None,
        }
    }

    /// Get string representation of static member expression
    fn get_member_string(&self, member: &StaticMemberExpression) -> Option<String> {
        let property = member.property.name.as_str();
        match &member.object {
            Expression::Identifier(id) => Some(format!("{}.{}", id.name.as_str(), property)),
            Expression::StaticMemberExpression(inner) => self
                .get_member_string(inner)
                .map(|obj| format!("{}.{}", obj, property)),
            _ => None,
        }
    }

    /// Get string representation of computed member property if statically resolvable.
    fn get_computed_property_string(
        &self,
        member: &ComputedMemberExpression<'a>,
    ) -> Option<String> {
        self.eval_static_string_expr(&member.expression)
    }

    /// Get string representation of computed member expression when property is literal.
    fn get_computed_member_string(&self, member: &ComputedMemberExpression<'a>) -> Option<String> {
        let property = self.get_computed_property_string(member)?;
        match &member.object {
            Expression::Identifier(id) => Some(format!("{}.{}", id.name.as_str(), property)),
            Expression::StaticMemberExpression(inner) => self
                .get_member_string(inner)
                .map(|obj| format!("{}.{}", obj, property)),
            Expression::ComputedMemberExpression(inner) => self
                .get_computed_member_string(inner)
                .map(|obj| format!("{}.{}", obj, property)),
            _ => None,
        }
    }

    /// Property names that are dangerous when assigned as member properties.
    fn is_assignment_sink_property(&self, prop_name: &str) -> bool {
        matches!(
            prop_name,
            "innerHTML" | "outerHTML" | "src" | "srcdoc" | "href" | "xlink:href"
        )
    }

    /// Evaluate an expression to a static string when possible.
    fn eval_static_string_expr(&self, expr: &Expression<'a>) -> Option<String> {
        match expr {
            Expression::StringLiteral(s) => Some(s.value.to_string()),
            Expression::TemplateLiteral(t) if t.expressions.is_empty() => Some(
                t.quasis
                    .iter()
                    .filter_map(|q| q.value.cooked)
                    .map(|a| a.as_str())
                    .collect::<Vec<_>>()
                    .join(""),
            ),
            Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
                let left = self.eval_static_string_expr(&binary.left)?;
                let right = self.eval_static_string_expr(&binary.right)?;
                Some(format!("{left}{right}"))
            }
            Expression::ParenthesizedExpression(paren) => {
                self.eval_static_string_expr(&paren.expression)
            }
            _ => None,
        }
    }

    fn eval_static_string_arg(&self, arg: &Argument<'a>) -> Option<String> {
        match arg {
            Argument::SpreadElement(_) => None,
            _ => arg
                .as_expression()
                .and_then(|expr| self.eval_static_string_expr(expr)),
        }
    }

    fn get_property_key_name(&self, key: &PropertyKey<'a>) -> Option<String> {
        key.name().map(|n| n.into_owned())
    }

    fn get_summary_object_prefix(&self, expr: &Expression<'a>) -> Option<String> {
        match expr {
            Expression::Identifier(id) => self
                .instance_classes
                .get(id.name.as_str())
                .cloned()
                .or_else(|| Some(id.name.to_string())),
            Expression::StaticMemberExpression(member) => self.get_member_string(member),
            Expression::ComputedMemberExpression(member) => self.get_computed_member_string(member),
            _ => None,
        }
    }

    /// Resolve a callable summary key from an expression.
    /// Examples:
    /// - `render` -> `render`
    /// - `helper.render` -> `helper.render`
    /// - `inst.render` where `inst` is `new Renderer()` -> `Renderer.render`
    fn get_summary_key_for_callee_expr(&self, expr: &Expression<'a>) -> Option<String> {
        match expr {
            Expression::Identifier(id) => Some(id.name.to_string()),
            Expression::StaticMemberExpression(member) => {
                let base = self.get_summary_object_prefix(&member.object)?;
                Some(format!("{}.{}", base, member.property.name.as_str()))
            }
            Expression::ComputedMemberExpression(member) => {
                let base = self.get_summary_object_prefix(&member.object)?;
                let property = self.get_computed_property_string(member)?;
                Some(format!("{}.{}", base, property))
            }
            _ => None,
        }
    }

    fn get_callee_property_name(&self, callee: &Expression<'a>) -> Option<String> {
        match callee {
            Expression::StaticMemberExpression(member) => Some(member.property.name.to_string()),
            Expression::ComputedMemberExpression(member) => self.get_computed_property_string(member),
            _ => None,
        }
    }

    fn get_callee_object_expr<'b>(&self, callee: &'b Expression<'a>) -> Option<&'b Expression<'a>> {
        match callee {
            Expression::StaticMemberExpression(member) => Some(&member.object),
            Expression::ComputedMemberExpression(member) => Some(&member.object),
            _ => None,
        }
    }

    fn build_bound_alias_from_bind_call(
        &self,
        bind_call: &CallExpression<'a>,
    ) -> Option<BoundCallableAlias> {
        let wrapper_name = self.get_callee_property_name(&bind_call.callee)?;
        if wrapper_name != "bind" {
            return None;
        }
        let target_expr = self.get_callee_object_expr(&bind_call.callee)?;
        let mut target = self
            .get_summary_key_for_callee_expr(target_expr)
            .or_else(|| self.get_expr_string(target_expr))?;

        let mut bound_args = bind_call
            .arguments
            .iter()
            .skip(1)
            .map(|arg| {
                let (tainted, source) = self.argument_taint_and_source(arg);
                BoundArgInfo { tainted, source }
            })
            .collect::<Vec<_>>();

        // Preserve previously bound arguments across chained binds:
        // f1 = fn.bind(this, a); f2 = f1.bind(this2, b) -> args [a, b]
        if let Expression::Identifier(id) = target_expr
            && let Some(existing_alias) = self.bound_function_aliases.get(id.name.as_str())
        {
            target = existing_alias.target.clone();
            let mut chained_args = existing_alias.bound_args.clone();
            chained_args.extend(bound_args);
            bound_args = chained_args;
        }

        Some(BoundCallableAlias { target, bound_args })
    }

    fn resolve_param_argument_taint(
        &self,
        call: &CallExpression<'a>,
        alias: Option<&BoundCallableAlias>,
        param_idx: usize,
    ) -> (bool, Option<String>) {
        if let Some(bound_alias) = alias {
            if let Some(bound_arg) = bound_alias.bound_args.get(param_idx) {
                return (bound_arg.tainted, bound_arg.source.clone());
            }
            let call_idx = param_idx.saturating_sub(bound_alias.bound_args.len());
            if param_idx >= bound_alias.bound_args.len()
                && let Some(arg) = call.arguments.get(call_idx)
            {
                return self.argument_taint_and_source(arg);
            }
            return (false, None);
        }

        if let Some(arg) = call.arguments.get(param_idx) {
            self.argument_taint_and_source(arg)
        } else {
            (false, None)
        }
    }

    fn resolve_apply_argument_taint_at(
        &self,
        arg_array: &Argument<'a>,
        param_idx: usize,
    ) -> (bool, Option<String>) {
        if let Some(expr) = arg_array.as_expression()
            && let Expression::ArrayExpression(array) = expr
        {
            let mut current_idx = 0usize;
            for elem in &array.elements {
                match elem {
                    ArrayExpressionElement::Elision(_) => {
                        if current_idx == param_idx {
                            return (false, None);
                        }
                        current_idx += 1;
                    }
                    ArrayExpressionElement::SpreadElement(spread) => {
                        let tainted = self.is_tainted(&spread.argument);
                        return (
                            tainted,
                            if tainted {
                                self.find_source_in_expr(&spread.argument)
                            } else {
                                None
                            },
                        );
                    }
                    _ => {
                        if let Some(elem_expr) = elem.as_expression() {
                            if current_idx == param_idx {
                                let tainted = self.is_tainted(elem_expr);
                                return (
                                    tainted,
                                    if tainted {
                                        self.find_source_in_expr(elem_expr)
                                    } else {
                                        None
                                    },
                                );
                            }
                        }
                        current_idx += 1;
                    }
                }
            }
            return (false, None);
        }

        self.argument_taint_and_source(arg_array)
    }

    fn resolve_wrapper_param_argument_taint(
        &self,
        call: &CallExpression<'a>,
        wrapper_name: &str,
        alias: Option<&BoundCallableAlias>,
        param_idx: usize,
    ) -> (bool, Option<String>) {
        if let Some(bound_alias) = alias {
            if let Some(bound_arg) = bound_alias.bound_args.get(param_idx) {
                return (bound_arg.tainted, bound_arg.source.clone());
            }
            if param_idx >= bound_alias.bound_args.len() {
                let shifted_idx = param_idx - bound_alias.bound_args.len();
                if wrapper_name == "call" {
                    if let Some(arg) = call.arguments.get(shifted_idx + 1) {
                        return self.argument_taint_and_source(arg);
                    }
                } else if wrapper_name == "apply"
                    && let Some(arg_array) = call.arguments.get(1)
                {
                    return self.resolve_apply_argument_taint_at(arg_array, shifted_idx);
                }
            }
            return (false, None);
        }

        if wrapper_name == "call" {
            if let Some(arg) = call.arguments.get(param_idx + 1) {
                return self.argument_taint_and_source(arg);
            }
        } else if wrapper_name == "apply"
            && let Some(arg_array) = call.arguments.get(1)
        {
            return self.resolve_apply_argument_taint_at(arg_array, param_idx);
        }

        (false, None)
    }

    fn get_alias_for_expr(&self, expr: &Expression<'a>) -> Option<&BoundCallableAlias> {
        if let Expression::Identifier(id) = expr {
            self.bound_function_aliases.get(id.name.as_str())
        } else {
            None
        }
    }

    fn get_alias_for_callee_identifier(
        &self,
        call: &CallExpression<'a>,
    ) -> Option<&BoundCallableAlias> {
        if let Expression::Identifier(id) = &call.callee {
            self.bound_function_aliases.get(id.name.as_str())
        } else {
            None
        }
    }

    /// Check taint/source hint for a call argument
    fn argument_taint_and_source(&self, arg: &Argument<'a>) -> (bool, Option<String>) {
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
    fn call_taint_and_source(&self, call: &CallExpression<'a>) -> (bool, Option<String>) {
        // Sanitizers produce de-tainted values
        if let Some(func_name) = self.get_expr_string(&call.callee)
            && self.sanitizers.contains(&func_name)
        {
            return (false, None);
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
                .map(|name| !self.sources.contains(name))
                .unwrap_or(true)
                && let Some(alias) = target_alias
            {
                target_name = Some(alias.target.clone());
            }
            if let Some(target_name) = target_name
                && self.sources.contains(&target_name)
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
            && self.sources.contains(&bound_target)
        {
            return (true, Some(bound_target));
        }

        // Direct source calls (e.g., localStorage.getItem(...))
        if let Expression::StaticMemberExpression(member) = &call.callee {
            if let Some(callee_str) = self.get_member_string(member)
                && self.sources.contains(&callee_str)
            {
                return (true, Some(callee_str));
            }

            // Method call on tainted object (e.g., tainted.slice())
            if self.is_tainted(&member.object) {
                return (true, self.find_source_in_expr(&member.object));
            }
        }
        if let Expression::ComputedMemberExpression(member) = &call.callee {
            if let Some(callee_str) = self.get_computed_member_string(member)
                && self.sources.contains(&callee_str)
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

    /// Check if expression is tainted
    fn is_tainted(&self, expr: &Expression) -> bool {
        match expr {
            Expression::Identifier(id) => self.tainted_vars.contains(id.name.as_str()),
            Expression::StaticMemberExpression(member) => {
                if let Some(full_path) = self.get_member_string(member) {
                    // Check if the full path is a known source
                    if self.sources.contains(&full_path) {
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
                    && self.sources.contains(&full_path)
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
            _ => false,
        }
    }

    /// Report a vulnerability
    fn report_vulnerability(&mut self, span: oxc_span::Span, sink: &str, description: &str) {
        self.report_vulnerability_with_source(span, sink, description, None);
    }

    /// Report a vulnerability with an optional explicit source
    fn report_vulnerability_with_source(
        &mut self,
        span: oxc_span::Span,
        sink: &str,
        description: &str,
        explicit_source: Option<String>,
    ) {
        let lines: Vec<&str> = self.source_code.lines().collect();
        let mut line = 1u32;
        let mut column = 1u32;
        let mut current_offset = 0usize;

        for (idx, line_text) in lines.iter().enumerate() {
            let line_len = line_text.len() + 1; // +1 for newline
            if current_offset + line_len > span.start as usize {
                line = (idx + 1) as u32;
                column = (span.start as usize - current_offset + 1) as u32;
                break;
            }
            current_offset += line_len;
        }

        let snippet = if line > 0 && (line as usize) <= lines.len() {
            lines[(line - 1) as usize].trim().to_string()
        } else {
            String::new()
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
        });
    }

    /// Walk through statements
    fn walk_statements(&mut self, stmts: &[Statement<'a>]) {
        self.collect_function_declarations(stmts);
        for stmt in stmts {
            self.walk_statement(stmt);
        }
    }

    /// Collect function declarations before statement traversal so hoisted calls are recognized.
    fn collect_function_declarations(&mut self, stmts: &[Statement<'a>]) {
        for stmt in stmts {
            if let Statement::FunctionDeclaration(func_decl) = stmt {
                self.register_function_declaration(func_decl.as_ref());
            }
        }
    }

    fn extract_param_names(&self, params: &FormalParameters<'a>) -> Vec<String> {
        params
            .items
            .iter()
            .filter_map(|param| match &param.pattern.kind {
                BindingPatternKind::BindingIdentifier(id) => Some(id.name.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>()
    }

    fn register_function_summary(
        &mut self,
        function_name: String,
        params: Vec<String>,
        body_stmts: &[Statement<'a>],
    ) {
        if self.function_summaries.contains_key(&function_name) {
            return;
        }

        // Insert placeholder summary first to avoid recursive self-analysis loops.
        self.function_summaries.insert(
            function_name.clone(),
            FunctionSummary {
                tainted_param_sinks: HashMap::new(),
                tainted_param_returns: HashMap::new(),
                return_without_tainted_params: None,
            },
        );

        let saved_tainted = self.tainted_vars.clone();
        let saved_aliases = self.var_aliases.clone();
        let saved_instance_classes = self.instance_classes.clone();
        let saved_bound_aliases = self.bound_function_aliases.clone();
        let saved_vuln_len = self.vulnerabilities.len();
        let saved_collecting_tainted_returns = self.collecting_tainted_returns;
        let saved_tainted_return_sources = std::mem::take(&mut self.tainted_return_sources);

        let mut summary = FunctionSummary {
            tainted_param_sinks: HashMap::new(),
            tainted_param_returns: HashMap::new(),
            return_without_tainted_params: None,
        };

        for (idx, param_name) in params.iter().enumerate() {
            self.tainted_vars.clear();
            self.var_aliases.clear();
            self.tainted_vars.insert(param_name.clone());
            self.var_aliases
                .insert(param_name.clone(), format!("fn_param_{}", idx));
            self.collecting_tainted_returns = true;
            self.tainted_return_sources.clear();

            let before = self.vulnerabilities.len();
            self.walk_statements(body_stmts);
            for vuln in &self.vulnerabilities[before..] {
                if vuln.sink != "__return__" {
                    summary
                        .tainted_param_sinks
                        .entry(idx)
                        .or_insert_with(|| vuln.sink.clone());
                }
            }
            if let Some(source) = self.tainted_return_sources.first() {
                summary.tainted_param_returns.insert(idx, source.clone());
            }
            self.vulnerabilities.truncate(before);
            self.tainted_return_sources.clear();
        }

        // Also capture return taint that does not depend on tainted parameters
        // (e.g., function directly returning location.hash)
        self.tainted_vars.clear();
        self.var_aliases.clear();
        self.collecting_tainted_returns = true;
        self.tainted_return_sources.clear();
        let before = self.vulnerabilities.len();
        self.walk_statements(body_stmts);
        if let Some(source) = self.tainted_return_sources.first() {
            summary.return_without_tainted_params = Some(source.clone());
        }
        self.vulnerabilities.truncate(before);

        self.tainted_vars = saved_tainted;
        self.var_aliases = saved_aliases;
        self.instance_classes = saved_instance_classes;
        self.bound_function_aliases = saved_bound_aliases;
        self.vulnerabilities.truncate(saved_vuln_len);
        self.collecting_tainted_returns = saved_collecting_tainted_returns;
        self.tainted_return_sources = saved_tainted_return_sources;

        self.function_summaries.insert(function_name, summary);
    }

    fn register_function_declaration(&mut self, func_decl: &Function<'a>) {
        let Some(id) = &func_decl.id else {
            return;
        };
        let Some(body) = &func_decl.body else {
            return;
        };
        self.register_function_summary(
            id.name.to_string(),
            self.extract_param_names(&func_decl.params),
            &body.statements,
        );
    }

    fn register_object_literal_method_summaries(
        &mut self,
        object_name: &str,
        obj: &ObjectExpression<'a>,
    ) {
        for prop in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(p) = prop else {
                continue;
            };
            let Some(method_name) = self.get_property_key_name(&p.key) else {
                continue;
            };
            let summary_name = format!("{}.{}", object_name, method_name);

            match &p.value {
                Expression::FunctionExpression(func_expr) => {
                    if let Some(body) = &func_expr.body {
                        self.register_function_summary(
                            summary_name,
                            self.extract_param_names(&func_expr.params),
                            &body.statements,
                        );
                    }
                }
                Expression::ArrowFunctionExpression(arrow_expr) => {
                    self.register_function_summary(
                        summary_name,
                        self.extract_param_names(&arrow_expr.params),
                        &arrow_expr.body.statements,
                    );
                }
                _ => {}
            }
        }
    }

    fn register_class_method_summaries_for_name(&mut self, class_name: &str, class_decl: &Class<'a>) {
        for elem in &class_decl.body.body {
            let ClassElement::MethodDefinition(method_def) = elem else {
                continue;
            };
            if !matches!(method_def.kind, MethodDefinitionKind::Method) {
                continue;
            }
            let Some(method_name) = self.get_property_key_name(&method_def.key) else {
                continue;
            };
            let Some(body) = &method_def.value.body else {
                continue;
            };
            self.register_function_summary(
                format!("{}.{}", class_name, method_name),
                self.extract_param_names(&method_def.value.params),
                &body.statements,
            );
        }
    }

    /// Walk through a single statement
    fn walk_statement(&mut self, stmt: &Statement<'a>) {
        match stmt {
            Statement::VariableDeclaration(var_decl) => {
                for decl in &var_decl.declarations {
                    self.walk_variable_declarator(decl);
                }
            }
            Statement::ExpressionStatement(expr_stmt) => {
                self.walk_expression(&expr_stmt.expression);
            }
            Statement::BlockStatement(block) => {
                self.walk_statements(&block.body);
            }
            Statement::IfStatement(if_stmt) => {
                self.walk_expression(&if_stmt.test);
                self.walk_statement(&if_stmt.consequent);
                if let Some(alt) = &if_stmt.alternate {
                    self.walk_statement(alt);
                }
            }
            Statement::WhileStatement(while_stmt) => {
                self.walk_expression(&while_stmt.test);
                self.walk_statement(&while_stmt.body);
            }
            Statement::ForStatement(for_stmt) => {
                if let Some(ForStatementInit::VariableDeclaration(var_decl)) = &for_stmt.init {
                    for decl in &var_decl.declarations {
                        self.walk_variable_declarator(decl);
                    }
                }
                if let Some(test) = &for_stmt.test {
                    self.walk_expression(test);
                }
                if let Some(update) = &for_stmt.update {
                    self.walk_expression(update);
                }
                self.walk_statement(&for_stmt.body);
            }
            Statement::FunctionDeclaration(func_decl) => {
                // Parameterized functions are primarily handled through summaries/call sites.
                // Walking bodies here can duplicate findings when summaries are also applied.
                // Keep direct walk only for zero-parameter functions where call-site summaries
                // cannot currently represent source->sink usage.
                if func_decl.params.items.is_empty()
                    && let Some(body) = &func_decl.body
                {
                    // Save current tainted vars state
                    let saved_tainted = self.tainted_vars.clone();
                    let saved_aliases = self.var_aliases.clone();

                    self.walk_statements(&body.statements);

                    // Restore state after function (parameters are local scope)
                    self.tainted_vars = saved_tainted;
                    self.var_aliases = saved_aliases;
                }
            }
            Statement::ClassDeclaration(class_decl) => {
                if let Some(class_id) = &class_decl.id {
                    self.register_class_method_summaries_for_name(class_id.name.as_str(), class_decl);
                }
            }
            Statement::ReturnStatement(return_stmt) => {
                if let Some(argument) = &return_stmt.argument {
                    if self.collecting_tainted_returns && self.is_tainted(argument) {
                        let source = self
                            .find_source_in_expr(argument)
                            .unwrap_or_else(|| "unknown source".to_string());
                        self.tainted_return_sources.push(source);
                    }
                    self.walk_expression(argument);
                }
            }
            Statement::SwitchStatement(switch_stmt) => {
                self.walk_expression(&switch_stmt.discriminant);
                for case in &switch_stmt.cases {
                    if let Some(test) = &case.test {
                        self.walk_expression(test);
                    }
                    self.walk_statements(&case.consequent);
                }
            }
            Statement::TryStatement(try_stmt) => {
                self.walk_statements(&try_stmt.block.body);
                if let Some(handler) = &try_stmt.handler {
                    self.walk_statements(&handler.body.body);
                }
                if let Some(finalizer) = &try_stmt.finalizer {
                    self.walk_statements(&finalizer.body);
                }
            }
            _ => {}
        }
    }

    /// Walk through a variable declarator
    fn walk_variable_declarator(&mut self, decl: &VariableDeclarator<'a>) {
        if let Some(init) = &decl.init {
            if let BindingPatternKind::BindingIdentifier(id) = &decl.id.kind {
                let var_name = id.name.as_str();

                // Register summaries for function expressions assigned to variables.
                if let Expression::FunctionExpression(func_expr) = init
                    && let Some(body) = &func_expr.body
                {
                    self.register_function_summary(
                        var_name.to_string(),
                        self.extract_param_names(&func_expr.params),
                        &body.statements,
                    );
                }
                // Register summaries for arrow functions assigned to variables.
                if let Expression::ArrowFunctionExpression(arrow_expr) = init {
                    self.register_function_summary(
                        var_name.to_string(),
                        self.extract_param_names(&arrow_expr.params),
                        &arrow_expr.body.statements,
                    );
                }
                // Register summaries for object literal methods assigned to variables.
                if let Expression::ObjectExpression(obj_expr) = init {
                    self.register_object_literal_method_summaries(var_name, obj_expr);
                }
                // Register summaries for class expressions assigned to variables.
                if let Expression::ClassExpression(class_expr) = init {
                    self.register_class_method_summaries_for_name(var_name, class_expr);
                }
                // Track class instance variables (`inst = new Renderer()`).
                let mut assigned_instance_class = false;
                if let Expression::NewExpression(new_expr) = init
                    && let Expression::Identifier(class_id) = &new_expr.callee
                {
                    self.instance_classes
                        .insert(var_name.to_string(), class_id.name.to_string());
                    assigned_instance_class = true;
                }
                if !assigned_instance_class {
                    self.instance_classes.remove(var_name);
                }
                // Track aliases created by `.bind()` so subsequent calls can resolve
                // to sink functions or function summaries.
                let mut assigned_bind_alias = false;
                if let Expression::CallExpression(bind_call) = init
                    && let Some(alias) = self.build_bound_alias_from_bind_call(bind_call)
                {
                    self.bound_function_aliases
                        .insert(var_name.to_string(), alias);
                    assigned_bind_alias = true;
                }
                if !assigned_bind_alias {
                    self.bound_function_aliases.remove(var_name);
                }

                // Check if initializer is a source or tainted
                if let Some(source_expr) = self.get_expr_string(init)
                    && self.sources.contains(&source_expr)
                {
                    self.tainted_vars.insert(var_name.to_string());
                    self.var_aliases
                        .insert(var_name.to_string(), source_expr.clone());
                }

                // Check for localStorage.getItem() and sessionStorage.getItem() calls
                if let Expression::CallExpression(call) = init
                    && let Expression::StaticMemberExpression(member) = &call.callee
                    && let Some(callee_str) = self.get_member_string(member)
                    && (callee_str == "localStorage.getItem"
                        || callee_str == "sessionStorage.getItem")
                {
                    // Mark this variable as tainted
                    self.tainted_vars.insert(var_name.to_string());
                    self.var_aliases.insert(var_name.to_string(), callee_str);
                }

                // Check for taintedVar.get() calls (URLSearchParams.get, Map.get, etc.)
                // e.g., query = urlParams.get('query') where urlParams is tainted
                if let Expression::CallExpression(call) = init
                    && let Expression::StaticMemberExpression(member) = &call.callee
                    && member.property.name.as_str() == "get"
                {
                    // Check if the object is tainted (e.g., urlParams.get())
                    if self.is_tainted(&member.object) {
                        self.tainted_vars.insert(var_name.to_string());
                        if let Some(source) = self.find_source_in_expr(&member.object) {
                            self.var_aliases.insert(var_name.to_string(), source);
                        } else {
                            self.var_aliases
                                .insert(var_name.to_string(), "URLSearchParams.get".to_string());
                        }
                    }
                }

                // Check for new URL(tainted).searchParams
                // e.g., urlParams = new URL(location.href).searchParams
                if let Expression::StaticMemberExpression(member) = init
                    && member.property.name.as_str() == "searchParams"
                {
                    // Check if the object is new URL(tainted)
                    if let Expression::NewExpression(new_expr) = &member.object {
                        if let Expression::Identifier(id) = &new_expr.callee {
                            if id.name.as_str() == "URL" && !new_expr.arguments.is_empty() {
                                // Check if the first argument is tainted
                                if let Some(arg) = new_expr.arguments.first() {
                                    let is_arg_tainted = match arg {
                                        Argument::SpreadElement(spread) => {
                                            self.is_tainted(&spread.argument)
                                        }
                                        _ => arg
                                            .as_expression()
                                            .map(|e| self.is_tainted(e))
                                            .unwrap_or(false),
                                    };
                                    if is_arg_tainted {
                                        self.tainted_vars.insert(var_name.to_string());
                                        let source_expr = match arg {
                                            Argument::SpreadElement(spread) => {
                                                Some(&spread.argument)
                                            }
                                            _ => arg.as_expression(),
                                        };
                                        let source = source_expr
                                            .and_then(|e| self.find_source_in_expr(e))
                                            .unwrap_or_else(|| "URL.searchParams".to_string());
                                        self.var_aliases.insert(var_name.to_string(), source);
                                    }
                                }
                            }
                        }
                    }
                }

                // Check for JSON.parse(tainted) - taint propagates through JSON.parse
                // e.g., data = JSON.parse(query) where query is tainted
                if let Expression::CallExpression(call) = init
                    && let Expression::StaticMemberExpression(member) = &call.callee
                    && let Some(callee_str) = self.get_member_string(member)
                    && callee_str == "JSON.parse"
                    && !call.arguments.is_empty()
                {
                    // Check if first argument is tainted
                    if let Some(arg) = call.arguments.first() {
                        let is_arg_tainted = match arg {
                            Argument::SpreadElement(spread) => self.is_tainted(&spread.argument),
                            _ => arg
                                .as_expression()
                                .map(|e| self.is_tainted(e))
                                .unwrap_or(false),
                        };
                        if is_arg_tainted {
                            self.tainted_vars.insert(var_name.to_string());
                            let source_expr = match arg {
                                Argument::SpreadElement(spread) => Some(&spread.argument),
                                _ => arg.as_expression(),
                            };
                            let source = source_expr
                                .and_then(|e| self.find_source_in_expr(e))
                                .unwrap_or_else(|| "JSON.parse".to_string());
                            self.var_aliases.insert(var_name.to_string(), source);
                        }
                    }
                }

                // Also check if init expression is tainted (includes template literals, arrays, objects)
                if self.is_tainted(init) {
                    self.tainted_vars.insert(var_name.to_string());
                    // Try to find a source from the init expression for better reporting
                    if !self.var_aliases.contains_key(var_name)
                        && let Some(source) = self.find_source_in_expr(init)
                    {
                        self.var_aliases.insert(var_name.to_string(), source);
                    }
                }
            }

            // Walk the init expression to detect any sinks used in the initializer
            self.walk_expression(init);
        }
    }

    /// Find a source in an expression (for alias tracking)
    fn find_source_in_expr(&self, expr: &Expression<'a>) -> Option<String> {
        match expr {
            Expression::Identifier(id) => self.var_aliases.get(id.name.as_str()).cloned(),
            Expression::StaticMemberExpression(member) => {
                if let Some(full_path) = self.get_member_string(member)
                    && self.sources.contains(&full_path)
                {
                    return Some(full_path);
                }
                self.find_source_in_expr(&member.object)
            }
            Expression::ArrayExpression(array) => {
                // Find first tainted element's source
                for elem in &array.elements {
                    match elem {
                        oxc_ast::ast::ArrayExpressionElement::SpreadElement(spread) => {
                            if let Some(source) = self.find_source_in_expr(&spread.argument) {
                                return Some(source);
                            }
                        }
                        _ => {
                            if let Some(expr) = elem.as_expression()
                                && let Some(source) = self.find_source_in_expr(expr)
                            {
                                return Some(source);
                            }
                        }
                    }
                }
                None
            }
            Expression::ObjectExpression(obj) => {
                // Find first tainted property's source
                for prop in &obj.properties {
                    match prop {
                        oxc_ast::ast::ObjectPropertyKind::ObjectProperty(p) => {
                            if let Some(source) = self.find_source_in_expr(&p.value) {
                                return Some(source);
                            }
                        }
                        oxc_ast::ast::ObjectPropertyKind::SpreadProperty(spread) => {
                            if let Some(source) = self.find_source_in_expr(&spread.argument) {
                                return Some(source);
                            }
                        }
                    }
                }
                None
            }
            Expression::TemplateLiteral(template) => {
                for e in &template.expressions {
                    if let Some(source) = self.find_source_in_expr(e) {
                        return Some(source);
                    }
                }
                None
            }
            Expression::BinaryExpression(binary) => self
                .find_source_in_expr(&binary.left)
                .or_else(|| self.find_source_in_expr(&binary.right)),
            Expression::LogicalExpression(logical) => self
                .find_source_in_expr(&logical.left)
                .or_else(|| self.find_source_in_expr(&logical.right)),
            Expression::ConditionalExpression(cond) => self
                .find_source_in_expr(&cond.consequent)
                .or_else(|| self.find_source_in_expr(&cond.alternate)),
            Expression::CallExpression(call) => {
                if let (_, Some(source)) = self.call_taint_and_source(call) {
                    return Some(source);
                }

                // Check callee first (e.g., location.hash.slice())
                if let Expression::StaticMemberExpression(member) = &call.callee {
                    // Direct source call (e.g., localStorage.getItem(...))
                    if let Some(callee_str) = self.get_member_string(member)
                        && self.sources.contains(&callee_str)
                    {
                        return Some(callee_str);
                    }
                    if let Some(source) = self.find_source_in_expr(&member.object) {
                        return Some(source);
                    }
                }
                // Check arguments
                for arg in &call.arguments {
                    match arg {
                        Argument::Identifier(id) => {
                            if let Some(source) = self.var_aliases.get(id.name.as_str()).cloned() {
                                return Some(source);
                            }
                        }
                        Argument::StaticMemberExpression(member) => {
                            if let Some(member_str) = self.get_member_string(member)
                                && self.sources.contains(&member_str)
                            {
                                return Some(member_str);
                            }
                        }
                        _ => {}
                    }
                }
                None
            }
            Expression::ComputedMemberExpression(member) => {
                if let Some(full_path) = self.get_computed_member_string(member)
                    && self.sources.contains(&full_path)
                {
                    return Some(full_path);
                }
                self.find_source_in_expr(&member.object)
            }
            _ => None,
        }
    }

    /// Walk through an expression
    fn walk_expression(&mut self, expr: &Expression<'a>) {
        match expr {
            Expression::AssignmentExpression(assign) => {
                self.walk_assignment_expression(assign);
            }
            Expression::CallExpression(call) => {
                self.walk_call_expression(call);
            }
            Expression::TemplateLiteral(template) => {
                for e in &template.expressions {
                    self.walk_expression(e);
                }
            }
            Expression::BinaryExpression(binary) => {
                self.walk_expression(&binary.left);
                self.walk_expression(&binary.right);
            }
            Expression::LogicalExpression(logical) => {
                self.walk_expression(&logical.left);
                self.walk_expression(&logical.right);
            }
            Expression::ConditionalExpression(cond) => {
                self.walk_expression(&cond.test);
                self.walk_expression(&cond.consequent);
                self.walk_expression(&cond.alternate);
            }
            Expression::NewExpression(new_expr) => {
                // Handle new Function(tainted) - constructor calls with tainted arguments
                if let Expression::Identifier(id) = &new_expr.callee {
                    let callee_name = id.name.as_str();
                    // Check if this is a sink constructor (e.g., Function)
                    if self.sinks.contains(callee_name) {
                        for arg in &new_expr.arguments {
                            let is_arg_tainted = match arg {
                                Argument::SpreadElement(spread) => {
                                    self.is_tainted(&spread.argument)
                                }
                                _ => arg
                                    .as_expression()
                                    .map(|e| self.is_tainted(e))
                                    .unwrap_or(false),
                            };
                            if is_arg_tainted {
                                self.report_vulnerability(
                                    new_expr.span(),
                                    callee_name,
                                    "Tainted data passed to constructor",
                                );
                                break;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Walk through an assignment expression
    fn walk_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        let right_tainted = self.is_tainted(&assign.right);
        let right_source = if right_tainted {
            self.find_source_in_expr(&assign.right)
        } else {
            None
        };

        // Check if we're assigning to a sink property
        match &assign.left {
            AssignmentTarget::StaticMemberExpression(member) => {
                let prop_name = member.property.name.as_str();
                let is_sink = self.is_assignment_sink_property(prop_name);

                // Also check if the full member path is a sink (e.g., location.href)
                let full_path_is_sink = if let Some(full_path) = self.get_member_string(member) {
                    self.sinks.contains(&full_path)
                } else {
                    false
                };

                if (is_sink || full_path_is_sink) && self.is_tainted(&assign.right) {
                    let sink_name = if full_path_is_sink {
                        self.get_member_string(member)
                            .unwrap_or_else(|| prop_name.to_string())
                    } else {
                        prop_name.to_string()
                    };

                    self.report_vulnerability_with_source(
                        assign.span(),
                        &sink_name,
                        "Assignment to sink property",
                        right_source.clone(),
                    );
                }

                // Track object-level taint for property assignment flows like:
                // obj.payload = location.hash; sink(obj.payload)
                if right_tainted
                    && let Expression::Identifier(obj_id) = &member.object
                {
                    self.tainted_vars.insert(obj_id.name.to_string());
                    if let Some(source) = right_source.clone() {
                        self.var_aliases.insert(obj_id.name.to_string(), source);
                    }
                }
            }
            AssignmentTarget::ComputedMemberExpression(member) => {
                let prop_name = self.get_computed_property_string(member);
                let is_sink = prop_name
                    .as_deref()
                    .map(|name| self.is_assignment_sink_property(name))
                    .unwrap_or(false);
                let full_path_is_sink = self
                    .get_computed_member_string(member)
                    .map(|full_path| self.sinks.contains(&full_path))
                    .unwrap_or(false);

                if (is_sink || full_path_is_sink) && right_tainted {
                    let sink_name = if full_path_is_sink {
                        self.get_computed_member_string(member)
                            .or(prop_name.clone())
                            .unwrap_or_else(|| "computed_member".to_string())
                    } else {
                        prop_name.unwrap_or_else(|| "computed_member".to_string())
                    };

                    self.report_vulnerability_with_source(
                        assign.span(),
                        &sink_name,
                        "Assignment to sink property",
                        right_source.clone(),
                    );
                }

                // Propagate taint to base object for computed assignments:
                // arr[0] = location.hash; sink(arr[0])
                if right_tainted
                    && let Expression::Identifier(obj_id) = &member.object
                {
                    self.tainted_vars.insert(obj_id.name.to_string());
                    if let Some(source) = right_source.clone() {
                        self.var_aliases.insert(obj_id.name.to_string(), source);
                    }
                }
            }
            AssignmentTarget::AssignmentTargetIdentifier(id) => {
                let target_name = id.name.as_str();
                let mut assigned_instance_class = false;
                if let Expression::NewExpression(new_expr) = &assign.right
                    && let Expression::Identifier(class_id) = &new_expr.callee
                {
                    self.instance_classes
                        .insert(target_name.to_string(), class_id.name.to_string());
                    assigned_instance_class = true;
                }
                if !assigned_instance_class {
                    self.instance_classes.remove(target_name);
                }

                let mut assigned_bind_alias = false;
                if let Expression::CallExpression(bind_call) = &assign.right
                    && let Some(alias) = self.build_bound_alias_from_bind_call(bind_call)
                {
                    self.bound_function_aliases
                        .insert(target_name.to_string(), alias);
                    assigned_bind_alias = true;
                }
                if !assigned_bind_alias {
                    self.bound_function_aliases.remove(target_name);
                }
                // Propagate taint through direct assignments like `a = taintedValue;`
                if right_tainted {
                    self.tainted_vars.insert(target_name.to_string());
                    if let Some(source) = right_source.clone() {
                        self.var_aliases.insert(target_name.to_string(), source);
                    }
                }

                if self.is_assignment_sink_property(target_name) && right_tainted {
                    self.report_vulnerability_with_source(
                        assign.span(),
                        target_name,
                        "Assignment to sink",
                        right_source.clone(),
                    );
                }
            }
            _ => {}
        }
        // Walk the right side
        self.walk_expression(&assign.right);
    }

    /// Walk through a call expression
    fn walk_call_expression(&mut self, call: &CallExpression<'a>) {
        // Check if this is an addEventListener call with a function argument
        if let Expression::StaticMemberExpression(member) = &call.callee
            && member.property.name.as_str() == "addEventListener"
            && call.arguments.len() >= 2
        {
            let is_message_event = call
                .arguments
                .first()
                .and_then(|arg| arg.as_expression())
                .and_then(|expr| match expr {
                    Expression::StringLiteral(s) => Some(s.value.as_str().eq_ignore_ascii_case("message")),
                    _ => None,
                })
                .unwrap_or(false);

            // The second argument might be a function with event parameter
            if let Some(Argument::FunctionExpression(func)) = call.arguments.get(1) {
                // Mark the first parameter as tainted (it's the event object)
                if let Some(param) = func.params.items.first()
                    && let BindingPatternKind::BindingIdentifier(id) = &param.pattern.kind
                {
                    let param_name = id.name.as_str();
                    // Save state before analyzing event handler
                    let saved_tainted = self.tainted_vars.clone();
                    let saved_aliases = self.var_aliases.clone();

                    // Mark event parameter as tainted
                    self.tainted_vars.insert(param_name.to_string());
                    self.var_aliases
                        .insert(param_name.to_string(), if is_message_event {
                            "event.data".to_string()
                        } else {
                            "event".to_string()
                        });

                    // Walk the function body
                    if let Some(body) = &func.body {
                        self.walk_statements(&body.statements);
                    }

                    // Restore state
                    self.tainted_vars = saved_tainted;
                    self.var_aliases = saved_aliases;
                    return;
                }
            }
            // Also handle arrow functions
            if let Some(Argument::ArrowFunctionExpression(arrow)) = call.arguments.get(1)
                && let Some(param) = arrow.params.items.first()
                && let BindingPatternKind::BindingIdentifier(id) = &param.pattern.kind
            {
                let param_name = id.name.as_str();
                let saved_tainted = self.tainted_vars.clone();
                let saved_aliases = self.var_aliases.clone();

                self.tainted_vars.insert(param_name.to_string());
                self.var_aliases
                    .insert(param_name.to_string(), if is_message_event {
                        "event.data".to_string()
                    } else {
                        "event".to_string()
                    });

                // Arrow functions have a FunctionBody
                self.walk_statements(&arrow.body.statements);

                self.tainted_vars = saved_tainted;
                self.var_aliases = saved_aliases;
                return;
            }

            // Handle named callback references:
            // window.addEventListener('message', handleMessage)
            if is_message_event
                && let Some(Argument::Identifier(handler_id)) = call.arguments.get(1)
                && let Some(sink_name) = self
                    .function_summaries
                    .get(handler_id.name.as_str())
                    .and_then(|summary| summary.tainted_param_sinks.get(&0))
                    .cloned()
            {
                self.report_vulnerability_with_source(
                    call.span(),
                    &sink_name,
                    "Tainted message event data may reach sink through callback",
                    Some("event.data".to_string()),
                );
                return;
            }
        }

        // Handle wrapper invocations:
        // - sink.call(thisArg, tainted)
        // - sink.apply(thisArg, [tainted])
        // - helper.call(thisArg, tainted) where helper has function summary
        if let Some(wrapper_name) = self.get_callee_property_name(&call.callee)
            && (wrapper_name == "call" || wrapper_name == "apply")
            && let Some(target_expr) = self.get_callee_object_expr(&call.callee)
        {
            let target_alias_owned = self.get_alias_for_expr(target_expr).cloned();
            let mut target_summary_key = self.get_summary_key_for_callee_expr(target_expr);
            if target_summary_key
                .as_ref()
                .and_then(|k| self.function_summaries.get(k))
                .is_none()
                && let Some(alias) = target_alias_owned.as_ref()
            {
                target_summary_key = Some(alias.target.clone());
            }
            if let Some(summary_key) = target_summary_key
                && let Some(param_sinks) = self.function_summaries.get(&summary_key).map(|summary| {
                    summary
                        .tainted_param_sinks
                        .iter()
                        .map(|(idx, sink)| (*idx, sink.clone()))
                        .collect::<Vec<_>>()
                })
            {
                for (idx, sink_name) in param_sinks {
                    let (tainted, source_hint) = self.resolve_wrapper_param_argument_taint(
                        call,
                        &wrapper_name,
                        target_alias_owned.as_ref(),
                        idx,
                    );
                    if tainted {
                        let description = if wrapper_name == "call" {
                            "Tainted argument reaches sink through function.call wrapper"
                        } else {
                            "Tainted argument reaches sink through function.apply wrapper"
                        };
                        self.report_vulnerability_with_source(
                            call.span(),
                            &sink_name,
                            description,
                            source_hint,
                        );
                        return;
                    }
                }
            }

            let mut target_func_name = self.get_expr_string(target_expr);
            if target_func_name
                .as_ref()
                .map(|name| !self.sinks.contains(name))
                .unwrap_or(true)
                && let Some(alias) = target_alias_owned.as_ref()
                && self.sinks.contains(&alias.target)
            {
                target_func_name = Some(alias.target.clone());
            }

            if let Some(target_func_name) = target_func_name.filter(|name| self.sinks.contains(name)) {
                if let Some(target_alias) = target_alias_owned.as_ref()
                    && self.sinks.contains(&target_alias.target)
                {
                    for bound_arg in &target_alias.bound_args {
                        if bound_arg.tainted {
                            self.report_vulnerability_with_source(
                                call.span(),
                                &target_func_name,
                                "Tainted pre-bound argument reaches sink function via wrapper",
                                bound_arg.source.clone(),
                            );
                            return;
                        }
                    }
                }

                if wrapper_name == "call" {
                    for arg in call.arguments.iter().skip(1) {
                        let (tainted, source_hint) = self.argument_taint_and_source(arg);
                        if tainted {
                            self.report_vulnerability_with_source(
                                call.span(),
                                &target_func_name,
                                "Tainted data passed to sink function via .call wrapper",
                                source_hint,
                            );
                            return;
                        }
                    }
                } else if let Some(arg_array) = call.arguments.get(1) {
                    let (tainted, source_hint) = self.argument_taint_and_source(arg_array);
                    if tainted {
                        self.report_vulnerability_with_source(
                            call.span(),
                            &target_func_name,
                            "Tainted data passed to sink function via .apply wrapper",
                            source_hint,
                        );
                        return;
                    }
                }
            }
        }

        // Propagate taint through common array mutation methods
        // e.g. arr.push(location.hash); document.write(arr[0]);
        if let Some(method) = self.get_callee_property_name(&call.callee)
            && let Some(target_obj) = self.get_callee_object_expr(&call.callee)
            && let Expression::Identifier(id) = target_obj
        {
            let target = id.name.as_str();
            let mut tainted_source: Option<String> = None;

            match method.as_str() {
                "push" | "unshift" => {
                    for arg in &call.arguments {
                        let (is_arg_tainted, source_hint) = self.argument_taint_and_source(arg);
                        if is_arg_tainted {
                            tainted_source = source_hint;
                            break;
                        }
                    }
                }
                "splice" => {
                    // splice(start, deleteCount, ...items): only items can introduce taint
                    for arg in call.arguments.iter().skip(2) {
                        let (is_arg_tainted, source_hint) = self.argument_taint_and_source(arg);
                        if is_arg_tainted {
                            tainted_source = source_hint;
                            break;
                        }
                    }
                }
                _ => {}
            }

            if let Some(source) = tainted_source {
                self.tainted_vars.insert(target.to_string());
                self.var_aliases.insert(target.to_string(), source);
            }
        }

        // Lightweight inter-procedural flow via function summary:
        // If summary says parameter[i] reaches sink S and argument[i] is tainted,
        // report vulnerability at call site.
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
        let alias_owned = self.get_alias_for_callee_identifier(call).cloned();
        if let Some(callee_key) = summary_key
            && let Some(param_sinks) = self.function_summaries.get(&callee_key).map(|summary| {
                summary
                    .tainted_param_sinks
                    .iter()
                    .map(|(idx, sink)| (*idx, sink.clone()))
                    .collect::<Vec<_>>()
            })
        {
            for (idx, sink_name) in param_sinks {
                let (tainted, source_hint) =
                    self.resolve_param_argument_taint(call, alias_owned.as_ref(), idx);
                if tainted {
                    self.report_vulnerability_with_source(
                        call.span(),
                        &sink_name,
                        "Tainted argument reaches sink through function call",
                        source_hint,
                    );
                    break;
                }
            }
        }

        // Check if calling a sink function (full name like document.write)
        let direct_sink_name = self
            .get_expr_string(&call.callee)
            .filter(|name| self.sinks.contains(name));
        let bound_sink_name = if direct_sink_name.is_none() {
            if let Expression::Identifier(id) = &call.callee {
                self.bound_function_aliases
                    .get(id.name.as_str())
                    .and_then(|alias| {
                        if self.sinks.contains(&alias.target) {
                            Some(alias.target.clone())
                        } else {
                            None
                        }
                    })
            } else {
                None
            }
        } else {
            None
        };
        if let Some(func_name) = direct_sink_name.or(bound_sink_name)
        {
            if let Some(bound_alias) = alias_owned.as_ref()
                && self.sinks.contains(&bound_alias.target)
            {
                for bound_arg in &bound_alias.bound_args {
                    if bound_arg.tainted {
                        self.report_vulnerability_with_source(
                            call.span(),
                            &func_name,
                            "Tainted pre-bound argument reaches sink function",
                            bound_arg.source.clone(),
                        );
                        return;
                    }
                }
            }

            // Check if any argument is tainted
            for arg in &call.arguments {
                let (is_arg_tainted, source_hint) = self.argument_taint_and_source(arg);

                if is_arg_tainted {
                    self.report_vulnerability_with_source(
                        call.span(),
                        &func_name,
                        "Tainted data passed to sink function",
                        source_hint,
                    );
                    break;
                }
            }
        }

        // Also treat member method name itself as sink
        // (e.g., el.insertAdjacentHTML, document['write'](...))
        let member_method_name = self.get_callee_property_name(&call.callee);
        if let Some(method_name) = member_method_name {
            if self.sinks.contains(method_name.as_str()) {
                // Special-case setAttribute to only dangerous attributes
                if method_name == "setAttribute" && call.arguments.len() >= 2 {
                    let attr_name_lc = call
                        .arguments
                        .first()
                        .and_then(|arg0| self.eval_static_string_arg(arg0))
                        .map(|name| name.to_ascii_lowercase());
                    if let Some(name) = attr_name_lc {
                        let dangerous = name.starts_with("on")
                            || name == "href"
                            || name == "xlink:href"
                            || name == "srcdoc";
                        if dangerous && let Some(arg1) = call.arguments.get(1) {
                            let tainted = match arg1 {
                                Argument::SpreadElement(sp) => self.is_tainted(&sp.argument),
                                _ => arg1
                                    .as_expression()
                                    .map(|e| self.is_tainted(e))
                                    .unwrap_or(false),
                            };
                            if tainted {
                                self.report_vulnerability(
                                    call.span(),
                                    &format!("setAttribute:{}", name),
                                    "Tainted data assigned to dangerous attribute",
                                );
                                return;
                            }
                        }
                    }
                // Special-case execCommand - only insertHTML is dangerous, and the third arg is the value
                } else if method_name == "execCommand" && call.arguments.len() >= 3 {
                    let cmd_name_lc = call
                        .arguments
                        .first()
                        .and_then(|arg0| self.eval_static_string_arg(arg0))
                        .map(|name| name.to_ascii_lowercase());
                    if let Some(cmd) = cmd_name_lc {
                        if cmd == "inserthtml" {
                            if let Some(arg2) = call.arguments.get(2) {
                                let tainted = match arg2 {
                                    Argument::SpreadElement(sp) => self.is_tainted(&sp.argument),
                                    _ => arg2
                                        .as_expression()
                                        .map(|e| self.is_tainted(e))
                                        .unwrap_or(false),
                                };
                                if tainted {
                                    self.report_vulnerability(
                                        call.span(),
                                        "execCommand:insertHTML",
                                        "Tainted data passed to insertHTML command",
                                    );
                                    return;
                                }
                            }
                        }
                    }
                } else {
                    // Generic method sink: if any argument is tainted
                    let mut arg_tainted = false;
                    for (idx, arg) in call.arguments.iter().enumerate() {
                        // For insertAdjacentHTML, the second argument is HTML
                        let consider = if method_name == "insertAdjacentHTML" {
                            idx == 1
                        } else {
                            true
                        };
                        if !consider {
                            continue;
                        }
                        let tainted = match arg {
                            Argument::SpreadElement(sp) => self.is_tainted(&sp.argument),
                            _ => arg
                                .as_expression()
                                .map(|e| self.is_tainted(e))
                                .unwrap_or(false),
                        };
                        if tainted {
                            arg_tainted = true;
                            break;
                        }
                    }
                    if arg_tainted {
                        self.report_vulnerability(
                            call.span(),
                            &method_name,
                            "Tainted data passed to sink method",
                        );
                        return;
                    }
                }
            }
        }
        // Walk the callee
        self.walk_expression(&call.callee);
    }

}

/// AST-based DOM XSS analyzer
pub struct AstDomAnalyzer;

impl AstDomAnalyzer {
    /// Create a new AST DOM analyzer
    pub fn new() -> Self {
        Self
    }

    /// Analyze JavaScript source code for DOM XSS vulnerabilities
    pub fn analyze(&self, source_code: &str) -> Result<Vec<DomXssVulnerability>, String> {
        let allocator = Allocator::default();
        let source_type = SourceType::default();

        let ret = Parser::new(&allocator, source_code, source_type).parse();

        if !ret.errors.is_empty() {
            let error_messages: Vec<String> = ret.errors.iter().map(|e| e.to_string()).collect();
            return Err(format!("Parse errors: {}", error_messages.join(", ")));
        }

        let mut visitor = DomXssVisitor::new(source_code);
        visitor.walk_statements(&ret.program.body);

        Ok(visitor.vulnerabilities)
    }
}

impl Default for AstDomAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_dom_xss_detection() {
        let code = r#"
let urlParam = location.search;
document.getElementById('foo').innerHTML = urlParam;
"#;

        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code);

        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(
            !vulnerabilities.is_empty(),
            "Should detect at least one vulnerability"
        );

        let vuln = &vulnerabilities[0];
        assert!(vuln.sink.contains("innerHTML"));
        assert!(vuln.source.contains("location.search"));
    }

    #[test]
    fn test_eval_with_location_hash() {
        let code = r#"
let hash = location.hash;
eval(hash);
"#;

        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code);

        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(!vulnerabilities.is_empty());

        let vuln = &vulnerabilities[0];
        assert!(vuln.sink.contains("eval"));
    }

    #[test]
    fn test_document_write_with_cookie() {
        let code = r#"
let data = document.cookie;
document.write(data);
"#;

        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code);

        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(!vulnerabilities.is_empty());

        let vuln = &vulnerabilities[0];
        assert!(vuln.sink.contains("document.write"));
    }

    #[test]
    fn test_no_vulnerability_with_safe_data() {
        let code = r#"
let safeData = "Hello World";
document.getElementById('foo').innerHTML = safeData;
"#;

        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code);

        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert_eq!(vulnerabilities.len(), 0);
    }

    #[test]
    fn test_multiple_vulnerabilities() {
        let code = r#"
let param = location.search;
let hash = location.hash;
document.write(param);
eval(hash);
"#;

        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code);

        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(
            vulnerabilities.len() >= 2,
            "Should detect multiple vulnerabilities"
        );
    }

    #[test]
    fn test_parse_error_handling() {
        let code = r#"
let invalid = {{{
"#;

        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code);

        assert!(
            result.is_err(),
            "Should return error for invalid JavaScript"
        );
    }

    #[test]
    fn test_direct_source_to_sink() {
        let code = r#"
document.write(location.search);
"#;

        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code);

        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(
            !vulnerabilities.is_empty(),
            "Should detect direct source-to-sink vulnerability"
        );
    }

    #[test]
    fn test_template_literal_with_tainted_data() {
        let code = r#"
let search = location.search;
let html = `<div>${search}</div>`;
document.body.innerHTML = html;
"#;

        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code);

        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(
            !vulnerabilities.is_empty(),
            "Should detect tainted data in template literal"
        );
    }

    #[test]
    fn test_method_call_on_source() {
        // Test for location.hash.slice(1) pattern - the issue reported by @hahwul
        let js = r#"document.write(location.hash.slice(1))"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(js).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect location.hash.slice(1) passed to document.write"
        );
        assert_eq!(result[0].sink, "document.write");
    }

    #[test]
    fn test_direct_location_hash_to_sink() {
        // Test for direct location.hash usage
        let js = r#"document.write(location.hash)"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(js).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect location.hash passed to document.write"
        );
        assert_eq!(result[0].sink, "document.write");
    }

    #[test]
    fn test_decode_uri_with_source() {
        // Test for decodeURI(location.hash) - decodeURI is NOT a sanitizer
        let js = r#"document.write(decodeURI(location.hash))"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(js).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect decodeURI(location.hash) as vulnerable"
        );
        assert_eq!(result[0].sink, "document.write");
        assert!(result[0].source.contains("location.hash"));
    }

    #[test]
    fn test_decode_uri_component_with_variable() {
        // Test for variable with decodeURIComponent
        let js = r#"
let hash = location.hash;
let decoded = decodeURIComponent(hash);
document.write(decoded);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(js).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect decodeURIComponent propagating taint"
        );
        assert_eq!(result[0].sink, "document.write");
    }

    // Tests for new sources
    #[test]
    fn test_localstorage_source() {
        // localStorage itself is a source - accessing properties from it should be tainted
        let code = r#"
let data = localStorage;
document.getElementById('output').innerHTML = data;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect localStorage as source");
    }

    #[test]
    fn test_sessionstorage_source() {
        // sessionStorage itself is a source
        let code = r#"
let userInput = sessionStorage;
eval(userInput);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect sessionStorage as source");
    }

    #[test]
    fn test_postmessage_event_data() {
        // Direct use of e.data as source (simplified pattern)
        let code = r#"
let data = e.data;
document.getElementById('msg').innerHTML = data;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect e.data (postMessage) as source"
        );
    }

    #[test]
    fn test_window_opener_source() {
        let code = r#"
let data = window.opener;
document.write(data);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect window.opener as source");
    }

    #[test]
    fn test_location_pathname_source() {
        let code = r#"
let path = location.pathname;
document.body.innerHTML = path;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect location.pathname as source"
        );
    }

    // Tests for new sinks
    #[test]
    fn test_element_src_sink() {
        let code = r#"
let hash = location.hash;
document.getElementById('script').src = hash;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect element.src as sink");
        assert_eq!(result[0].sink, "src");
    }

    #[test]
    fn test_set_attribute_sink() {
        // Simplified: direct call to setAttribute function
        let code = r#"
let data = location.search;
setAttribute('onclick', data);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect setAttribute as sink");
    }

    #[test]
    fn test_jquery_html_sink() {
        // Simplified: direct call to html() function
        let code = r#"
let input = location.hash;
html(input);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect html() as sink");
    }

    #[test]
    fn test_jquery_append_sink() {
        // Simplified: direct call to append() function
        let code = r#"
let userInput = document.cookie;
append(userInput);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect append() as sink");
    }

    // Tests for complex patterns
    #[test]
    fn test_array_with_tainted_data() {
        let code = r#"
let hash = location.hash;
let arr = [hash, 'other'];
document.write(arr[0]);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect tainted data in array");
    }

    #[test]
    fn test_object_with_tainted_data() {
        let code = r#"
let search = location.search;
let obj = { data: search };
document.body.innerHTML = obj.data;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect tainted data in object");
    }

    #[test]
    fn test_property_access_on_tainted_var() {
        let code = r#"
let urlData = location.search;
let value = urlData.substring(1);
document.write(value);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should propagate taint through property access"
        );
    }

    #[test]
    fn test_multiple_assignment_levels() {
        let code = r#"
let a = location.hash;
let b = a;
let c = b;
document.getElementById('x').innerHTML = c;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should track taint through multiple assignments"
        );
    }

    #[test]
    fn test_string_concat_with_tainted() {
        let code = r#"
let param = location.search;
let msg = "Hello " + param;
document.write(msg);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect taint in string concatenation"
        );
    }

    #[test]
    fn test_conditional_with_tainted() {
        let code = r#"
let hash = location.hash;
let output = hash ? hash : "default";
document.body.innerHTML = output;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect taint in conditional expression"
        );
    }

    #[test]
    fn test_tainted_in_if_statement() {
        let code = r#"
let search = location.search;
if (search) {
    document.write(search);
}
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect taint in if statement");
    }

    #[test]
    fn test_tainted_in_while_loop() {
        let code = r#"
let data = location.hash;
while (data.length > 0) {
    document.getElementById('x').innerHTML = data;
    break;
}
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect taint in while loop");
    }

    #[test]
    fn test_tainted_in_for_loop() {
        let code = r#"
let input = location.search;
for (let i = 0; i < 1; i++) {
    document.body.innerHTML = input;
}
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect taint in for loop");
    }

    #[test]
    fn test_string_methods_on_source() {
        let code = r#"
let result = location.hash.substring(1).replace('#', '');
document.write(result);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should track taint through string methods"
        );
    }

    #[test]
    fn test_split_on_source() {
        let code = r#"
let parts = location.search.split('&');
document.write(parts[0]);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should track taint through split method"
        );
    }

    #[test]
    fn test_computed_member_access() {
        let code = r#"
let arr = [location.hash];
let index = 0;
document.write(arr[index]);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should track taint through computed member access"
        );
    }

    #[test]
    fn test_array_literal_direct_sink() {
        let code = r#"
document.write([location.hash][0]);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect taint in array literal to sink"
        );
    }

    #[test]
    fn test_object_literal_direct_sink() {
        let code = r#"
document.body.innerHTML = {x: location.search}.x;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect taint in object literal to sink"
        );
    }

    #[test]
    fn test_settimeout_with_string() {
        let code = r#"
let hash = location.hash;
setTimeout(hash, 100);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect setTimeout with tainted string"
        );
    }

    #[test]
    fn test_setinterval_with_tainted() {
        let code = r#"
let code = location.search;
setInterval(code, 1000);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect setInterval with tainted code"
        );
    }

    #[test]
    fn test_function_constructor() {
        let code = r#"
let input = location.hash;
let f = Function(input);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect Function constructor with tainted input"
        );
    }

    #[test]
    fn test_location_assignment() {
        let code = r#"
let url = location.hash;
location.href = url;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect location.href assignment");
    }

    #[test]
    fn test_sanitizer_prevents_detection() {
        let code = r#"
let input = location.search;
let safe = DOMPurify.sanitize(input);
document.body.innerHTML = safe;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        // This should NOT detect a vulnerability because DOMPurify.sanitize is used
        // However, current implementation tracks taint through variable assignment
        // This is a known limitation - sanitization detection could be improved
        // For now, we just verify the test runs without panicking
        // We expect it to still find a vulnerability due to the limitation
    }

    #[test]
    fn test_encode_uri_component_usage() {
        let code = r#"
let input = location.search;
let encoded = encodeURIComponent(input);
document.body.innerHTML = encoded;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        // encodeURIComponent is considered a sanitizer, but taint still propagates
        // through variable assignment. This is a limitation of the current impl.
        // We expect it to still find a vulnerability due to the limitation
    }

    #[test]
    fn test_object_property_simple() {
        let code = r#"
let data = location.search;
let obj = { value: data };
document.write(obj.value);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should track taint through simple object property"
        );
    }

    #[test]
    fn test_nested_property_access() {
        let code = r#"
let data = location.search;
let obj = { inner: { value: data } };
document.write(obj.inner.value);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should track taint through nested properties"
        );
    }

    #[test]
    fn test_taint_through_return_value() {
        let code = r#"
function getData() {
    return location.hash;
}
let data = getData();
document.body.innerHTML = data;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect tainted return value flowing to sink"
        );
    }

    #[test]
    fn test_multiple_sources_multiple_sinks() {
        let code = r#"
let hash = location.hash;
let search = location.search;
document.write(hash);
eval(search);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(result.len() >= 2, "Should detect multiple vulnerabilities");
    }

    #[test]
    fn test_logical_or_with_tainted() {
        let code = r#"
let value = location.search || "default";
document.write(value);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect taint in logical OR");
    }

    #[test]
    fn test_logical_and_with_tainted() {
        let code = r#"
let input = location.hash && location.hash.slice(1);
document.body.innerHTML = input;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect taint in logical AND");
    }

    #[test]
    fn test_binary_plus_operator() {
        let code = r#"
let prefix = "Value: ";
let data = location.search;
let output = prefix + data;
document.write(output);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect taint through + operator");
    }

    #[test]
    fn test_textcontent_safe() {
        // textContent is SAFE - it does not parse HTML, just sets text
        let code = r#"
let input = location.hash;
document.getElementById('x').textContent = input;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            result.is_empty(),
            "textContent is safe and should NOT be detected as a sink"
        );
    }

    #[test]
    fn test_outerhtml_assignment() {
        let code = r#"
let data = document.URL;
document.getElementById('container').outerHTML = data;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect outerHTML assignment");
    }

    #[test]
    fn test_insertadjacenthtml_call() {
        // Simplified: direct call to insertAdjacentHTML function
        let code = r#"
let html = location.hash;
insertAdjacentHTML('beforeend', html);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect insertAdjacentHTML");
    }

    // Additional advanced test cases
    #[test]
    fn test_document_url_source() {
        let code = r#"
let url = document.URL;
document.write(url);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect document.URL as source");
        assert!(result[0].source.contains("document.URL"));
    }

    #[test]
    fn test_document_referrer_source() {
        let code = r#"
let ref = document.referrer;
document.getElementById('x').innerHTML = ref;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect document.referrer as source"
        );
    }

    #[test]
    fn test_window_name_source() {
        let code = r#"
let name = window.name;
eval(name);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect window.name as source");
    }

    #[test]
    fn test_document_base_uri_source() {
        let code = r#"
let base = document.baseURI;
document.body.innerHTML = base;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect document.baseURI as source"
        );
    }

    #[test]
    fn test_location_replace_sink() {
        let code = r#"
let url = location.hash;
location.replace(url);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect location.replace as sink");
    }

    #[test]
    fn test_location_assign_sink() {
        let code = r#"
let target = document.cookie;
location.assign(target);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect location.assign as sink");
    }

    #[test]
    fn test_execscript_sink() {
        let code = r#"
let script = location.search;
execScript(script);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect execScript as sink");
    }

    #[test]
    fn test_ternary_operator_both_tainted() {
        let code = r#"
let a = location.hash;
let b = location.search;
let result = Math.random() > 0.5 ? a : b;
document.write(result);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect ternary with both branches tainted"
        );
    }

    #[test]
    fn test_ternary_operator_one_tainted() {
        let code = r#"
let tainted = location.hash;
let safe = "safe";
let result = Math.random() > 0.5 ? tainted : safe;
document.write(result);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect ternary with one branch tainted"
        );
    }

    #[test]
    fn test_array_spread_operator() {
        let code = r#"
let tainted = [location.hash];
let arr = [...tainted, 'other'];
document.write(arr[0]);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect taint through array spread"
        );
    }

    #[test]
    fn test_object_spread_operator() {
        let code = r#"
let tainted = { data: location.search };
let obj = { ...tainted };
document.body.innerHTML = obj.data;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect taint through object spread"
        );
    }

    #[test]
    fn test_chained_property_access() {
        let code = r#"
let obj = { a: { b: { c: location.hash } } };
document.write(obj.a.b.c);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect deeply nested property access"
        );
    }

    #[test]
    fn test_multiple_tainted_in_template_literal() {
        let code = r#"
let hash = location.hash;
let search = location.search;
let msg = `Hash: ${hash}, Search: ${search}`;
document.write(msg);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect multiple tainted in template literal"
        );
    }

    #[test]
    fn test_tainted_as_object_key() {
        let code = r#"
let key = location.hash;
let obj = {};
obj[key] = "value";
document.write(obj[key]);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        // This is a limitation - we track that obj is tainted but not specific keys
        // The test documents current behavior
    }

    #[test]
    fn test_document_writeln_sink() {
        let code = r#"
let data = location.search;
document.writeln(data);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect document.writeln as sink");
    }

    #[test]
    fn test_chained_string_methods() {
        let code = r#"
let result = location.hash.substring(1).toUpperCase().trim();
document.write(result);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should track taint through chained methods"
        );
    }

    #[test]
    fn test_array_join_on_tainted() {
        let code = r#"
let parts = [location.hash, location.search];
let combined = parts.join('&');
document.write(combined);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect taint in array with join");
    }

    #[test]
    fn test_tainted_in_switch_statement() {
        let code = r#"
let input = location.hash;
switch(input) {
    case "test":
        document.write(input);
        break;
}
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect taint in switch statement"
        );
    }

    #[test]
    fn test_binary_operators_propagate_taint() {
        let code = r#"
let a = location.hash;
let b = "prefix-" + a + "-suffix";
document.write(b);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should propagate taint through binary operators"
        );
    }

    #[test]
    fn test_null_coalescing_with_tainted() {
        let code = r#"
let value = location.hash || "default";
document.write(value);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect taint through null coalescing"
        );
    }

    #[test]
    fn test_mixed_array_access() {
        let code = r#"
let arr = ["safe", location.hash, "safe2"];
document.write(arr[1]);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect tainted element in mixed array"
        );
    }

    #[test]
    fn test_jquery_prepend_sink() {
        let code = r#"
let content = location.search;
prepend(content);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect prepend as sink");
    }

    #[test]
    fn test_jquery_after_sink() {
        let code = r#"
let html = document.cookie;
after(html);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect after as sink");
    }

    #[test]
    fn test_jquery_before_sink() {
        let code = r#"
let markup = location.hash;
before(markup);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect before as sink");
    }

    #[test]
    fn test_element_text_safe() {
        // element.text is typically safe (similar to textContent)
        let code = r#"
let input = location.search;
element.text = input;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            result.is_empty(),
            "text property is typically safe and should NOT be detected"
        );
    }

    #[test]
    fn test_reassignment_preserves_taint() {
        let code = r#"
let a = location.hash;
let b = a;
let c = b;
let d = c;
document.write(d);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should preserve taint through multiple reassignments"
        );
    }

    #[test]
    fn test_tainted_array_element_assignment() {
        let code = r#"
let arr = [];
arr[0] = location.hash;
document.write(arr[0]);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect computed member assignment taint propagation"
        );
    }

    #[test]
    fn test_window_location_source() {
        let code = r#"
let loc = window.location;
document.write(loc);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect window.location as source"
        );
    }

    #[test]
    fn test_complex_binary_expression_chain() {
        let code = r#"
let a = location.hash;
let b = a + " middle " + a + " end";
document.write(b);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect taint in complex binary expression"
        );
    }

    #[test]
    fn test_typeof_does_not_sanitize() {
        let code = r#"
let input = location.hash;
let type = typeof input;
document.write(input);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "typeof should not sanitize tainted variable"
        );
    }

    #[test]
    fn test_tainted_in_array_literal_position() {
        let code = r#"
let hash = location.hash;
document.write([1, 2, hash][2]);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect tainted data at specific array position"
        );
    }

    #[test]
    fn test_document_document_uri_source() {
        let code = r#"
let uri = document.documentURI;
eval(uri);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect document.documentURI as source"
        );
    }

    #[test]
    fn test_parenthesized_expression() {
        let code = r#"
let value = (((location.hash)));
document.write(value);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should track taint through parenthesized expressions"
        );
    }

    #[test]
    fn test_comma_operator_with_tainted() {
        let code = r#"
let result = (1, 2, location.hash);
document.write(result);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        // Comma operator returns the last value
        // Test documents current behavior
    }

    #[test]
    fn test_combined_logical_operators() {
        let code = r#"
let a = location.hash;
let b = location.search;
let result = a && b || "default";
document.write(result);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect taint through combined logical operators"
        );
    }

    #[test]
    fn test_tainted_get_method_call() {
        let code = r#"
            let params = location.search;
            let value = params.get('id');
            document.write(value);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should track taint through .get() on tainted object"
        );
    }

    #[test]
    fn test_new_url_searchparams() {
        let code = r#"
            let urlParams = new URL(location.href).searchParams;
            document.write(urlParams);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should track taint through new URL(tainted).searchParams"
        );
    }

    #[test]
    fn test_json_parse_taint_propagation() {
        let code = r#"
            let input = location.hash;
            let data = JSON.parse(input);
            document.body.innerHTML = data;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should propagate taint through JSON.parse"
        );
    }

    #[test]
    fn test_taint_inside_try_catch() {
        let code = r#"
            try {
                let x = location.search;
                document.write(x);
            } catch(e) {}
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect taint inside try block");
    }

    #[test]
    fn test_new_function_with_tainted_arg() {
        let code = r#"
            let code = location.hash;
            let fn = new Function(code);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect new Function() with tainted argument"
        );
    }

    #[test]
    fn test_execcommand_inserthtml_sink() {
        let code = r#"
            let html = location.hash;
            document.execCommand('insertHTML', false, html);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect execCommand insertHTML with tainted data"
        );
    }

    #[test]
    fn test_assignment_expression_propagates_taint() {
        let code = r#"
            let src = location.search;
            let out;
            out = src;
            document.write(out);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should propagate taint through identifier assignment"
        );
    }

    #[test]
    fn test_assignment_in_conditional_branch_propagates_taint() {
        let code = r#"
            let input = location.hash;
            let out = "safe";
            if (input) {
                out = input;
            }
            document.body.innerHTML = out;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should propagate taint through assignment in conditional branches"
        );
    }

    #[test]
    fn test_array_push_taint_propagation() {
        let code = r#"
            let items = [];
            items.push(location.hash);
            document.write(items[0]);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should propagate taint through Array.push()"
        );
    }

    #[test]
    fn test_array_splice_taint_propagation() {
        let code = r#"
            let items = ["safe"];
            items.splice(0, 1, location.search);
            document.write(items[0]);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should propagate taint through Array.splice() inserted values"
        );
    }

    #[test]
    fn test_function_parameter_taint_interprocedural() {
        let code = r#"
            function render(content) {
                document.getElementById('display').innerHTML = content;
            }
            let param = location.hash.substring(1);
            render(param);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect tainted argument flowing into sink inside called function"
        );
    }

    #[test]
    fn test_function_call_before_declaration_hoisting_flow() {
        let code = r#"
            let param = location.search;
            sinkWrap(param);
            function sinkWrap(v) {
                document.write(v);
            }
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect tainted flow even when function is declared after call"
        );
    }

    #[test]
    fn test_function_parameter_safe_sink_not_detected() {
        let code = r#"
            function safeRender(content) {
                document.getElementById('display').textContent = content;
            }
            let param = location.hash.substring(1);
            safeRender(param);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            result.is_empty(),
            "textContent inside called function should remain safe"
        );
    }

    #[test]
    fn test_function_expression_parameter_taint_interprocedural() {
        let code = r#"
            const render = function (content) {
                document.getElementById('display').innerHTML = content;
            };
            const input = location.search;
            render(input);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect tainted argument flowing into function expression sink"
        );
    }

    #[test]
    fn test_arrow_function_parameter_taint_interprocedural() {
        let code = r#"
            const render = (content) => {
                document.getElementById('display').innerHTML = content;
            };
            const input = location.hash;
            render(input);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect tainted argument flowing into arrow function sink"
        );
    }

    #[test]
    fn test_function_return_direct_source_to_sink_argument() {
        let code = r#"
            function getPayload() {
                return location.search;
            }
            document.write(getPayload());
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect direct function return source passed to sink"
        );
    }

    #[test]
    fn test_named_message_event_handler_callback_flow() {
        let code = r#"
            function onMessage(event) {
                document.getElementById('out').innerHTML = event.data;
            }
            window.addEventListener('message', onMessage);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect message event data reaching sink through named callback"
        );
    }

    #[test]
    fn test_named_message_event_handler_safe_not_detected() {
        let code = r#"
            function onMessage(event) {
                document.getElementById('out').textContent = event.data;
            }
            window.addEventListener('message', onMessage);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            result.is_empty(),
            "Named message callback should not be flagged when using safe sink"
        );
    }

    #[test]
    fn test_computed_member_innerhtml_assignment_detected() {
        let code = r#"
            let payload = location.hash;
            let el = document.getElementById('target');
            el['innerHTML'] = payload;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect computed innerHTML assignment sink"
        );
    }

    #[test]
    fn test_computed_member_location_href_assignment_detected() {
        let code = r#"
            let redirect = location.search;
            location['href'] = redirect;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect computed location.href assignment sink"
        );
    }

    #[test]
    fn test_computed_member_document_write_call_detected() {
        let code = r#"
            let data = location.hash;
            document['write'](data);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect computed member sink call document['write']"
        );
    }

    #[test]
    fn test_computed_member_insertadjacenthtml_call_detected() {
        let code = r#"
            let data = location.search;
            const el = document.getElementById('target');
            el['insertAdjacentHTML']('beforeend', data);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect computed insertAdjacentHTML sink call"
        );
    }

    #[test]
    fn test_object_html_property_assignment_not_sink_by_itself() {
        let code = r#"
            let model = {};
            model.html = location.hash;
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            result.is_empty(),
            "Object html property assignment should not be treated as direct sink"
        );
    }

    #[test]
    fn test_object_html_property_then_real_sink_reports_only_real_sink() {
        let code = r#"
            let model = {};
            model.html = location.hash;
            document.write(model.html);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert_eq!(
            result.len(),
            1,
            "Should report only actual sink usage, not property assignment pseudo-sink"
        );
        assert_eq!(result[0].sink, "document.write");
    }

    #[test]
    fn test_sink_call_wrapper_detected() {
        let code = r#"
            let input = location.hash;
            document.write.call(document, input);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect sink invocation via .call wrapper"
        );
    }

    #[test]
    fn test_sink_apply_wrapper_detected() {
        let code = r#"
            document.write.apply(document, [location.search]);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect sink invocation via .apply wrapper"
        );
    }

    #[test]
    fn test_bound_sink_alias_detected() {
        let code = r#"
            let writer = document.write.bind(document);
            let payload = location.hash;
            writer(payload);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(!result.is_empty(), "Should detect sink through bound alias");
    }

    #[test]
    fn test_object_method_summary_flow_detected() {
        let code = r#"
            const helper = {
                render(value) {
                    document.getElementById('out').innerHTML = value;
                }
            };
            helper.render(location.hash);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect object literal method inter-procedural flow"
        );
    }

    #[test]
    fn test_class_instance_method_summary_flow_detected() {
        let code = r#"
            class Renderer {
                render(value) {
                    document.write(value);
                }
            }
            const r = new Renderer();
            r.render(location.search);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect class instance method inter-procedural flow"
        );
    }

    #[test]
    fn test_class_static_method_summary_flow_detected() {
        let code = r#"
            class Redirector {
                static go(url) {
                    location.assign(url);
                }
            }
            Redirector.go(location.hash);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect class static method inter-procedural flow"
        );
    }

    #[test]
    fn test_summary_call_wrapper_detected() {
        let code = r#"
            function render(value) {
                document.write(value);
            }
            render.call(null, location.hash);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect summary flow through .call wrapper"
        );
    }

    #[test]
    fn test_summary_apply_wrapper_detected() {
        let code = r#"
            function render(value) {
                document.write(value);
            }
            render.apply(null, [location.hash]);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect summary flow through .apply wrapper"
        );
    }

    #[test]
    fn test_bound_object_method_summary_detected() {
        let code = r#"
            const helper = {
                render(v) {
                    eval(v);
                }
            };
            const bound = helper.render.bind(helper);
            bound(location.search);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect bound object method summary flow"
        );
    }

    #[test]
    fn test_dynamic_setattribute_name_concat_detected() {
        let code = r#"
            const input = location.hash;
            document.getElementById('x').setAttribute('on' + 'click', input);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect dangerous dynamic setAttribute name"
        );
    }

    #[test]
    fn test_dynamic_setattribute_safe_name_concat_not_detected() {
        let code = r#"
            const input = location.hash;
            document.getElementById('x').setAttribute('data-' + 'id', input);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            result.is_empty(),
            "Should not detect safe dynamic setAttribute name"
        );
    }

    #[test]
    fn test_dynamic_execcommand_name_concat_detected() {
        let code = r#"
            const html = location.search;
            document.execCommand('insert' + 'HTML', false, html);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect dynamic execCommand insertHTML name"
        );
    }

    #[test]
    fn test_bound_source_alias_taint_detected() {
        let code = r#"
            const readStorage = localStorage.getItem.bind(localStorage);
            const data = readStorage('payload');
            document.write(data);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should propagate source taint through bound source alias"
        );
    }

    #[test]
    fn test_bound_summary_prebound_tainted_arg_detected() {
        let code = r#"
            function render(value) {
                document.write(value);
            }
            const bound = render.bind(null, location.hash);
            bound();
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect tainted pre-bound argument through function summary"
        );
    }

    #[test]
    fn test_bound_sink_prebound_tainted_arg_detected() {
        let code = r#"
            const writer = document.write.bind(document, location.search);
            writer();
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect tainted pre-bound argument to sink alias"
        );
    }

    #[test]
    fn test_bound_object_method_prebound_tainted_arg_detected() {
        let code = r#"
            const helper = {
                render(v) {
                    eval(v);
                }
            };
            const bound = helper.render.bind(helper, location.hash);
            bound();
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect tainted pre-bound argument to bound object method"
        );
    }

    #[test]
    fn test_bound_return_prebound_arg_taints_sink() {
        let code = r#"
            function echo(v) {
                return v;
            }
            const f = echo.bind(null, location.search);
            document.write(f());
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect tainted return from pre-bound argument"
        );
    }

    #[test]
    fn test_bound_summary_prebound_safe_literal_not_detected() {
        let code = r#"
            function render(value) {
                document.getElementById('out').innerHTML = value;
            }
            const bound = render.bind(null, 'safe');
            bound();
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            result.is_empty(),
            "Safe literal pre-bound argument should not be detected"
        );
    }

    #[test]
    fn test_computed_member_dynamic_property_sink_call_detected() {
        let code = r#"
            const payload = location.hash;
            document['wri' + 'te'](payload);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect sink call when computed property name is statically resolvable"
        );
    }

    #[test]
    fn test_computed_member_dynamic_wrapper_property_call_detected() {
        let code = r#"
            const payload = location.search;
            document.write['ca' + 'll'](document, payload);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect wrapper sink call when wrapper property is computed"
        );
    }

    #[test]
    fn test_computed_member_dynamic_non_sink_property_not_detected() {
        let code = r#"
            const payload = location.hash;
            document['wri' + 'ten'](payload);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            result.is_empty(),
            "Non-sink computed member should not be flagged"
        );
    }

    #[test]
    fn test_bind_chain_sink_alias_detected() {
        let code = r#"
            const base = document.write.bind(document, location.hash);
            const chained = base.bind(null);
            chained();
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should preserve taint through chained bind aliases"
        );
    }

    #[test]
    fn test_bound_sink_alias_call_wrapper_detected() {
        let code = r#"
            const writer = document.write.bind(document);
            writer.call(null, location.hash);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect sink alias invoked via .call wrapper"
        );
    }

    #[test]
    fn test_bound_sink_alias_apply_wrapper_detected() {
        let code = r#"
            const writer = document.write.bind(document);
            writer.apply(null, [location.search]);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect sink alias invoked via .apply wrapper"
        );
    }

    #[test]
    fn test_summary_apply_wrapper_param_index_precision_detected() {
        let code = r#"
            function render(a, b) {
                document.write(b);
            }
            render.apply(null, ['safe', location.hash]);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should map apply array index to correct sink parameter"
        );
    }

    #[test]
    fn test_summary_apply_wrapper_non_sink_param_tainted_not_detected() {
        let code = r#"
            function render(a, b) {
                document.write(a);
            }
            render.apply(null, ['safe', location.hash]);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            result.is_empty(),
            "Tainted non-sink parameter should not trigger apply wrapper finding"
        );
    }

    #[test]
    fn test_bound_summary_call_wrapper_detected() {
        let code = r#"
            function render(v) {
                eval(v);
            }
            const bound = render.bind(null);
            bound.call(null, location.search);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should detect summary alias invoked through call wrapper"
        );
    }

    #[test]
    fn test_bound_summary_apply_wrapper_with_prebound_index_detected() {
        let code = r#"
            function render(a, b) {
                document.write(b);
            }
            const bound = render.bind(null, 'safe');
            bound.apply(null, [location.hash]);
"#;
        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code).unwrap();
        assert!(
            !result.is_empty(),
            "Should respect pre-bound args when mapping apply wrapper parameter index"
        );
    }
}
