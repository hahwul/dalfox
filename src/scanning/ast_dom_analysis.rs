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
use std::sync::LazyLock;

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
    sources: &'static HashSet<&'static str>,
    /// Known DOM sinks (dangerous operations)
    sinks: &'static HashSet<&'static str>,
    /// Known sanitizers
    sanitizers: &'static HashSet<&'static str>,
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
    /// Precomputed byte offsets of line starts for O(log n) span → line/column lookup
    line_starts: Vec<usize>,
    /// Field-level taint tracking: "obj.field" -> source
    field_taints: HashMap<String, String>,
    /// Top-level global variable taint tracking
    global_taints: HashSet<String>,
    /// Track `urlVar -> base source` for `new URL(tainted)` instances.
    url_object_sources: HashMap<String, String>,
    /// Track `paramsVar -> base source` for `url.searchParams` aliases.
    url_search_params_sources: HashMap<String, String>,
    /// Track variables known to hold URLSearchParams objects.
    url_search_params_objects: HashSet<String>,
    /// Track `paramsVar.key -> upstream source` for URLSearchParams set/get reparses.
    url_search_params_field_sources: HashMap<String, String>,
    /// Variables that hold a `<script>` element created via
    /// `document.createElement('script')`. Assigning a tainted value to
    /// `.text` / `.textContent` / `.innerText` / `.innerHTML` on these
    /// variables runs the value as JS once the element is appended, which
    /// is otherwise indistinguishable from a harmless text assignment.
    script_element_vars: HashSet<String>,
}

// Module-level DOM source/sink/sanitizer constants
//
// Both `self`, `top`, `parent`, and `globalThis` refer to the same
// `Window` object as bare `location` / `name` / `opener`, so a single
// taint source has up to five spellings the AST recogniser must match.
// We keep the bare form as the canonical source and add the `self.*`
// alias for the cases that matter in real-world bundles (xss-game L3
// uses `self.location.hash.substr(1)`). The `find_source_in_expr`
// recurses into `.object`, so adding just the second-level alias
// (`self.location`) is enough for `self.location.hash` to taint —
// recursion strips the leaf property and matches the alias one level
// down. `window.location` was already covered for the same reason.
const DOM_SOURCES: &[&str] = &[
    "location.search",
    "location.hash",
    "location.href",
    "location.pathname",
    "document.URL",
    "document.documentURI",
    "document.URLUnencoded",
    "document.baseURI",
    "document.cookie",
    "document.referrer",
    "window.name",
    "window.location",
    "window.location.hash",
    "window.location.search",
    "window.location.href",
    "window.location.pathname",
    "self.location",
    "self.location.hash",
    "self.location.search",
    "self.location.href",
    "self.location.pathname",
    "top.location",
    "parent.location",
    "localStorage",
    "sessionStorage",
    "localStorage.getItem",
    "sessionStorage.getItem",
    "event.data",
    "e.data",
    "event.newValue",
    "e.newValue",
    "event.oldValue",
    "e.oldValue",
    "e.target.value",
    "event.target.value",
    "window.opener",
    "URLSearchParams",
    "import.meta.url",
    "location.origin",
    "location.host",
    "history.state",
    "document.domain",
    "Response.text",
    "Response.json",
    "XMLHttpRequest.responseText",
    "XMLHttpRequest.response",
    // Clipboard reads on `paste` events expose attacker-controlled bytes from
    // the OS clipboard. The `getData(...)` call is the canonical reach; the
    // bare `clipboardData` object holds metadata (`.types`, `.files`, …) that
    // isn't user-controlled string content, so we don't mark it as a source.
    "event.clipboardData.getData",
    "e.clipboardData.getData",
    "navigator.clipboard.readText",
    // Keyboard / composition events – `key` / `code` carry user input
    // verbatim and are the natural source on autocompletion-style handlers.
    "event.key",
    "e.key",
    "event.code",
    "e.code",
    // `event.target.innerText` / `textContent` / `innerHTML` is the common
    // contenteditable / paste-into-div shape: the user typed it, so the
    // value is tainted at read time.
    "event.target.innerText",
    "e.target.innerText",
    "event.target.textContent",
    "e.target.textContent",
    "event.target.innerHTML",
    "e.target.innerHTML",
];

const DOM_SINKS: &[&str] = &[
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "createContextualFragment",
    "document.write",
    "document.writeln",
    "eval",
    "setTimeout",
    "setInterval",
    "Function",
    "execScript",
    "location.href",
    "location.assign",
    "location.replace",
    "src",
    "srcdoc",
    "href",
    "xlink:href",
    "setAttribute",
    "html",
    "append",
    "prepend",
    "after",
    "before",
    "execCommand",
    // Modern Sanitizer-API methods. `setHTML` accepts a Sanitizer config and
    // strips known XSS vectors, so on its own it is not an exploitable sink —
    // we leave it out. `setHTMLUnsafe` is explicitly the opt-out path that
    // parses the argument as HTML with no sanitization, which is exactly the
    // shape of an exploitable injection.
    "setHTMLUnsafe",
];

const DOM_SANITIZERS: &[&str] = &[
    "DOMPurify.sanitize",
    "encodeURIComponent",
    "encodeURI",
    "encodeHTML",
    "escapeHTML",
    "document.createTextNode",
    "createTextNode",
    "sanitizeHtml",
    "xss",
    "filterXSS",
    "he.encode",
    "he.escape",
    "_.escape",
    "escapeHtml",
    "htmlEscape",
    "htmlEncode",
    "sanitizeHTML",
    "validator.escape",
];

static STATIC_SOURCES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut set = HashSet::with_capacity(DOM_SOURCES.len());
    set.extend(DOM_SOURCES.iter().copied());
    set
});
static STATIC_SINKS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut set = HashSet::with_capacity(DOM_SINKS.len());
    set.extend(DOM_SINKS.iter().copied());
    set
});
static STATIC_SANITIZERS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut set = HashSet::with_capacity(DOM_SANITIZERS.len());
    set.extend(DOM_SANITIZERS.iter().copied());
    set
});

impl<'a> DomXssVisitor<'a> {
    fn extract_static_string_argument(call: &CallExpression<'a>, idx: usize) -> Option<String> {
        let arg = call.arguments.get(idx)?;
        let expr = arg.as_expression()?;
        match expr {
            Expression::StringLiteral(s) => Some(s.value.to_string()),
            Expression::TemplateLiteral(t) if t.expressions.is_empty() && t.quasis.len() == 1 => {
                t.quasis.first().map(|q| q.value.raw.to_string())
            }
            _ => None,
        }
    }

    fn normalize_search_param_source(&self, source: &str) -> String {
        match source {
            "location.href" | "document.URL" | "document.documentURI" | "document.baseURI" => {
                "location.search".to_string()
            }
            _ => source.to_string(),
        }
    }

    fn compose_search_param_source(&self, base_source: &str, param_name: &str) -> String {
        if base_source.starts_with("URLSearchParams.get(") {
            format!("{base_source}.get({param_name})")
        } else {
            format!("URLSearchParams.get({param_name})")
        }
    }

    fn storage_get_source(&self, call: &CallExpression<'a>, callee_str: &str) -> Option<String> {
        if callee_str != "localStorage.getItem" && callee_str != "sessionStorage.getItem" {
            return None;
        }

        if let Some(key) = Self::extract_static_string_argument(call, 0) {
            Some(format!("{callee_str}({key})"))
        } else {
            Some(callee_str.to_string())
        }
    }

    fn url_source_from_argument(&self, arg: &Argument<'a>) -> Option<String> {
        let expr = match arg {
            Argument::SpreadElement(spread) => &spread.argument,
            _ => arg.as_expression()?,
        };
        self.find_source_in_expr(expr)
            .map(|source| self.normalize_search_param_source(&source))
    }

    fn url_object_source_from_new_expression(
        &self,
        new_expr: &NewExpression<'a>,
    ) -> Option<String> {
        let Expression::Identifier(id) = &new_expr.callee else {
            return None;
        };
        if id.name.as_str() != "URL" {
            return None;
        }

        new_expr
            .arguments
            .first()
            .and_then(|arg| self.url_source_from_argument(arg))
    }

    fn url_object_source_for_expr(&self, expr: &Expression<'a>) -> Option<String> {
        match expr {
            Expression::Identifier(id) => self.url_object_sources.get(id.name.as_str()).cloned(),
            Expression::NewExpression(new_expr) => {
                self.url_object_source_from_new_expression(new_expr)
            }
            Expression::ParenthesizedExpression(paren) => {
                self.url_object_source_for_expr(&paren.expression)
            }
            _ => None,
        }
    }

    fn url_search_params_source_for_member(
        &self,
        member: &StaticMemberExpression<'a>,
    ) -> Option<String> {
        if member.property.name.as_str() != "searchParams" {
            return None;
        }

        self.url_object_source_for_expr(&member.object)
    }

    fn url_search_params_source_for_expr(&self, expr: &Expression<'a>) -> Option<String> {
        match expr {
            Expression::Identifier(id) => self
                .url_search_params_sources
                .get(id.name.as_str())
                .cloned(),
            Expression::NewExpression(new_expr) => {
                let Expression::Identifier(id) = &new_expr.callee else {
                    return None;
                };
                if id.name.as_str() != "URLSearchParams" {
                    return None;
                }
                new_expr
                    .arguments
                    .first()
                    .and_then(|arg| self.url_source_from_argument(arg))
            }
            Expression::StaticMemberExpression(member) => {
                self.url_search_params_source_for_member(member)
            }
            Expression::ParenthesizedExpression(paren) => {
                self.url_search_params_source_for_expr(&paren.expression)
            }
            _ => None,
        }
    }

    fn url_search_params_get_source(
        &self,
        call: &CallExpression<'a>,
        object: &Expression<'a>,
    ) -> Option<String> {
        let base_source = self.url_search_params_source_for_expr(object)?;

        if let Some(param_name) = Self::extract_static_string_argument(call, 0) {
            if let Some(source) = self.url_search_params_field_source_for_expr(object, &param_name)
            {
                return Some(source);
            }
            Some(self.compose_search_param_source(&base_source, &param_name))
        } else {
            Some(base_source)
        }
    }

    fn url_search_params_field_key(var_name: &str, param_name: &str) -> String {
        format!("{var_name}.{param_name}")
    }

    fn url_search_params_field_source_for_expr(
        &self,
        expr: &Expression<'a>,
        param_name: &str,
    ) -> Option<String> {
        let Expression::Identifier(id) = expr else {
            return None;
        };
        self.url_search_params_field_sources
            .get(&Self::url_search_params_field_key(
                id.name.as_str(),
                param_name,
            ))
            .cloned()
    }

    fn clear_url_search_params_field_sources(&mut self, var_name: &str) {
        let prefix = format!("{var_name}.");
        self.url_search_params_field_sources
            .retain(|key, _| !key.starts_with(&prefix));
    }

    fn clone_url_search_params_field_sources(&mut self, from: &str, to: &str) {
        let prefix = format!("{from}.");
        let cloned = self
            .url_search_params_field_sources
            .iter()
            .filter_map(|(key, value)| {
                key.strip_prefix(&prefix)
                    .map(|suffix| (Self::url_search_params_field_key(to, suffix), value.clone()))
            })
            .collect::<Vec<_>>();

        for (key, value) in cloned {
            self.url_search_params_field_sources.insert(key, value);
        }
    }

    fn clone_url_search_params_field_sources_from_expr(
        &mut self,
        expr: &Expression<'a>,
        target: &str,
    ) {
        let Expression::CallExpression(call) = expr else {
            return;
        };
        let Some(method) = self.get_callee_property_name(&call.callee) else {
            return;
        };
        if method != "toString" {
            return;
        }
        let Some(target_obj) = self.get_callee_object_expr(&call.callee) else {
            return;
        };
        let Expression::Identifier(id) = target_obj else {
            return;
        };
        if self.url_search_params_objects.contains(id.name.as_str()) {
            self.clone_url_search_params_field_sources(id.name.as_str(), target);
        }
    }

    fn new(source_code: &'a str) -> Self {
        // Precompute line start offsets for fast span→line/column lookup
        let mut line_starts = vec![0usize];
        for (i, b) in source_code.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push(i + 1);
            }
        }
        Self {
            tainted_vars: HashSet::new(),
            var_aliases: HashMap::new(),
            vulnerabilities: Vec::new(),
            sources: &*STATIC_SOURCES,
            sinks: &*STATIC_SINKS,
            sanitizers: &*STATIC_SANITIZERS,
            function_summaries: HashMap::new(),
            instance_classes: HashMap::new(),
            bound_function_aliases: HashMap::new(),
            collecting_tainted_returns: false,
            tainted_return_sources: Vec::new(),
            source_code,
            line_starts,
            field_taints: HashMap::new(),
            global_taints: HashSet::new(),
            url_object_sources: HashMap::new(),
            url_search_params_sources: HashMap::new(),
            url_search_params_objects: HashSet::new(),
            url_search_params_field_sources: HashMap::new(),
            script_element_vars: HashSet::new(),
        }
    }

    /// Recognise `document.createElement('script')` (and the spelling variants
    /// the AST gives us) so the caller can remember which JS variables hold a
    /// script element. We accept the call with a case-insensitive `script`
    /// argument because HTML element tag names are case-insensitive.
    fn expr_creates_script_element(&self, expr: &Expression<'a>) -> bool {
        let Expression::CallExpression(call) = expr else {
            return false;
        };
        let callee = match &call.callee {
            Expression::StaticMemberExpression(m) => self.get_member_string(m),
            _ => None,
        };
        if callee.as_deref() != Some("document.createElement") {
            return false;
        }
        let Some(arg) = call.arguments.first() else {
            return false;
        };
        let tag = match arg.as_expression() {
            Some(Expression::StringLiteral(s)) => Some(s.value.as_str()),
            Some(Expression::TemplateLiteral(t))
                if t.expressions.is_empty() && t.quasis.len() == 1 =>
            {
                t.quasis
                    .first()
                    .and_then(|q| q.value.cooked.as_ref())
                    .map(|c| c.as_str())
            }
            _ => None,
        };
        matches!(tag.map(|s| s.eq_ignore_ascii_case("script")), Some(true))
    }

    /// Property names that, when assigned on a `<script>` element variable,
    /// turn the assigned value into executable JavaScript once the element
    /// is inserted into the document. `text` / `textContent` / `innerText`
    /// all set the script body; `innerHTML` does the same and additionally
    /// re-parses tag soup inside. We do *not* include `src` here because
    /// `src` is already covered by the generic URL-attribute sink path.
    fn is_script_element_text_sink_prop(prop: &str) -> bool {
        matches!(prop, "text" | "textContent" | "innerText" | "innerHTML")
    }

    /// Get a string representation of an expression if it's an identifier or member expression
    fn get_expr_string(&self, expr: &Expression) -> Option<String> {
        match expr {
            Expression::Identifier(id) => Some(id.name.to_string()),
            Expression::StaticMemberExpression(member) => self.get_member_string(member),
            Expression::ComputedMemberExpression(member) => self.get_computed_member_string(member),
            Expression::MetaProperty(meta) => {
                Some(format!("{}.{}", meta.meta.name, meta.property.name))
            }
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
            Expression::MetaProperty(meta) => Some(format!(
                "{}.{}.{}",
                meta.meta.name, meta.property.name, property
            )),
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

    /// Pattern-based sanitizer name detection for names not in the explicit allowlist.
    /// Matches specific combinations: "sanitize"+"html"/"xss", "escape"+"html"/"xss",
    /// "encode"+"html".
    fn is_likely_sanitizer_name(name: &str) -> bool {
        let lower = name.to_lowercase();
        let func = lower.split('.').next_back().unwrap_or(&lower);

        // "sanitize" combined with "html" or "xss"
        if func.contains("sanitize") && (func.contains("html") || func.contains("xss")) {
            return true;
        }
        // "escape" combined with "html" or "xss"
        if func.contains("escape") && (func.contains("html") || func.contains("xss")) {
            return true;
        }
        // "encode" combined with "html"
        if func.contains("encode") && func.contains("html") {
            return true;
        }
        // "purify" or "dompurify"
        if func.contains("purify") {
            return true;
        }
        false
    }

    /// Evaluate an expression to a static string when possible.
    fn eval_static_string_expr(&self, expr: &Expression<'a>) -> Option<String> {
        match expr {
            Expression::StringLiteral(s) => Some(s.value.to_string()),
            Expression::TemplateLiteral(t) if t.expressions.is_empty() => {
                Some(t.quasis.iter().filter_map(|q| q.value.cooked).fold(
                    String::new(),
                    |mut acc, a| {
                        acc.push_str(a.as_str());
                        acc
                    },
                ))
            }
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
            Expression::ComputedMemberExpression(member) => {
                self.get_computed_property_string(member)
            }
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
                        if let Some(elem_expr) = elem.as_expression()
                            && current_idx == param_idx
                        {
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
                        current_idx += 1;
                    }
                }
            }
            return (false, None);
        }

        self.argument_taint_and_source(arg_array)
    }

    fn resolve_apply_static_string_at(
        &self,
        arg_array: &Argument<'a>,
        param_idx: usize,
    ) -> Option<String> {
        let expr = arg_array.as_expression()?;
        let Expression::ArrayExpression(array) = expr else {
            return None;
        };

        let mut current_idx = 0usize;
        for elem in &array.elements {
            match elem {
                ArrayExpressionElement::Elision(_) => {
                    if current_idx == param_idx {
                        return None;
                    }
                    current_idx += 1;
                }
                ArrayExpressionElement::SpreadElement(_) => {
                    return None;
                }
                _ => {
                    if let Some(elem_expr) = elem.as_expression()
                        && current_idx == param_idx
                    {
                        return self.eval_static_string_expr(elem_expr);
                    }
                    current_idx += 1;
                }
            }
        }

        None
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

    fn resolve_reflect_apply_param_argument_taint(
        &self,
        call: &CallExpression<'a>,
        alias: Option<&BoundCallableAlias>,
        param_idx: usize,
    ) -> (bool, Option<String>) {
        if let Some(bound_alias) = alias {
            if let Some(bound_arg) = bound_alias.bound_args.get(param_idx) {
                return (bound_arg.tainted, bound_arg.source.clone());
            }
            if param_idx >= bound_alias.bound_args.len()
                && let Some(arg_array) = call.arguments.get(2)
            {
                let shifted_idx = param_idx - bound_alias.bound_args.len();
                return self.resolve_apply_argument_taint_at(arg_array, shifted_idx);
            }
            return (false, None);
        }

        if let Some(arg_array) = call.arguments.get(2) {
            self.resolve_apply_argument_taint_at(arg_array, param_idx)
        } else {
            (false, None)
        }
    }

    fn get_alias_for_expr(&self, expr: &Expression<'a>) -> Option<&BoundCallableAlias> {
        if let Expression::Identifier(id) = expr {
            self.bound_function_aliases.get(id.name.as_str())
        } else {
            None
        }
    }

    fn get_callable_target_alias_from_argument(
        &self,
        arg: &Argument<'a>,
    ) -> Option<&BoundCallableAlias> {
        arg.as_expression()
            .and_then(|expr| self.get_alias_for_expr(expr))
    }

    fn get_callable_target_key_from_argument(&self, arg: &Argument<'a>) -> Option<String> {
        let expr = arg.as_expression()?;
        let mut key = self
            .get_summary_key_for_callee_expr(expr)
            .or_else(|| self.get_expr_string(expr));

        if key
            .as_ref()
            .and_then(|k| self.function_summaries.get(k))
            .is_none()
            && let Some(alias) = self.get_alias_for_expr(expr)
        {
            key = Some(alias.target.clone());
        }

        key
    }

    fn get_sink_name_for_callable_expr(&self, expr: &Expression<'a>) -> Option<String> {
        if let Some(full_name) = self.get_expr_string(expr)
            && self.sinks.contains(full_name.as_str())
        {
            return Some(full_name);
        }
        if let Some(method_name) = self.get_callee_property_name(expr)
            && self.sinks.contains(method_name.as_str())
        {
            return Some(method_name);
        }
        None
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
                .map(|name| !self.sources.contains(name.as_str()))
                .unwrap_or(true)
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

    /// Check if expression is tainted
    fn is_tainted(&self, expr: &Expression) -> bool {
        match expr {
            Expression::Identifier(id) => {
                self.tainted_vars.contains(id.name.as_str())
                    || self.global_taints.contains(id.name.as_str())
            }
            Expression::StaticMemberExpression(member) => {
                if self.url_search_params_source_for_member(member).is_some() {
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
            .filter_map(|param| match &param.pattern {
                BindingPattern::BindingIdentifier(id) => Some(id.name.to_string()),
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

    fn register_class_method_summaries_for_name(
        &mut self,
        class_name: &str,
        class_decl: &Class<'a>,
    ) {
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
                    self.register_class_method_summaries_for_name(
                        class_id.name.as_str(),
                        class_decl,
                    );
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
            if let BindingPattern::BindingIdentifier(id) = &decl.id {
                let var_name = id.name.as_str();
                self.clear_url_search_params_field_sources(var_name);

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

                let mut assigned_url_object_source = false;
                if let Expression::NewExpression(new_expr) = init
                    && let Some(source) = self.url_object_source_from_new_expression(new_expr)
                {
                    self.url_object_sources.insert(var_name.to_string(), source);
                    assigned_url_object_source = true;
                }
                if !assigned_url_object_source {
                    self.url_object_sources.remove(var_name);
                }

                // `let s = document.createElement('script')` — remember the
                // variable so a later `s.text = tainted` is recognised as a
                // sink even though `text` is a benign property on every
                // other element kind.
                if self.expr_creates_script_element(init) {
                    self.script_element_vars.insert(var_name.to_string());
                } else {
                    self.script_element_vars.remove(var_name);
                }

                let mut assigned_url_search_params_source = false;
                if let Expression::StaticMemberExpression(member) = init
                    && let Some(source) = self.url_search_params_source_for_member(member)
                {
                    self.tainted_vars.insert(var_name.to_string());
                    self.var_aliases
                        .insert(var_name.to_string(), source.clone());
                    self.url_search_params_sources
                        .insert(var_name.to_string(), source);
                    assigned_url_search_params_source = true;
                }
                if !assigned_url_search_params_source {
                    self.url_search_params_sources.remove(var_name);
                }

                let mut assigned_url_search_params_object = false;
                if let Expression::StaticMemberExpression(member) = init
                    && self.url_search_params_source_for_member(member).is_some()
                {
                    self.url_search_params_objects.insert(var_name.to_string());
                    assigned_url_search_params_object = true;
                }
                if let Expression::NewExpression(new_expr) = init
                    && let Expression::Identifier(id) = &new_expr.callee
                    && id.name.as_str() == "URLSearchParams"
                {
                    self.url_search_params_objects.insert(var_name.to_string());
                    assigned_url_search_params_object = true;
                }
                if !assigned_url_search_params_object {
                    self.url_search_params_objects.remove(var_name);
                }

                // Check if initializer is a source or tainted
                if let Some(source_expr) = self.get_expr_string(init)
                    && self.sources.contains(source_expr.as_str())
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
                    let source = self
                        .storage_get_source(call, &callee_str)
                        .unwrap_or(callee_str);
                    self.var_aliases.insert(var_name.to_string(), source);
                }

                // Check for new URL(tainted) / new URLSearchParams(tainted)
                if let Expression::NewExpression(new_expr) = init
                    && let Expression::Identifier(id) = &new_expr.callee
                    && (id.name.as_str() == "URL" || id.name.as_str() == "URLSearchParams")
                    && !new_expr.arguments.is_empty()
                    && let Some(arg) = new_expr.arguments.first()
                {
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
                            .map(|source| {
                                if id.name.as_str() == "URLSearchParams" {
                                    self.normalize_search_param_source(&source)
                                } else {
                                    source
                                }
                            })
                            .unwrap_or_else(|| "location.search".to_string());
                        self.var_aliases
                            .insert(var_name.to_string(), source.clone());
                        if id.name.as_str() == "URLSearchParams" {
                            self.url_search_params_objects.insert(var_name.to_string());
                            self.url_search_params_sources
                                .insert(var_name.to_string(), source);
                            if let Some(source_expr) = source_expr {
                                self.clone_url_search_params_field_sources_from_expr(
                                    source_expr,
                                    var_name,
                                );
                            }
                        }
                    }
                }

                // Check for taintedVar.get() calls (URLSearchParams.get, Map.get, etc.)
                // e.g., query = urlParams.get('query') where urlParams is tainted
                if let Expression::CallExpression(call) = init
                    && let Expression::StaticMemberExpression(member) = &call.callee
                    && member.property.name.as_str() == "get"
                {
                    if let Some(source) = self.url_search_params_get_source(call, &member.object) {
                        self.tainted_vars.insert(var_name.to_string());
                        self.var_aliases.insert(var_name.to_string(), source);
                    } else if self.is_tainted(&member.object) {
                        // Check if the object is tainted (e.g., taintedMap.get())
                        self.tainted_vars.insert(var_name.to_string());
                        if let Some(source) = self.find_source_in_expr(&member.object) {
                            let source = self.normalize_search_param_source(&source);
                            self.var_aliases.insert(var_name.to_string(), source);
                        } else {
                            self.var_aliases
                                .insert(var_name.to_string(), "location.search".to_string());
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

            // Handle object destructuring: const { a, b } = tainted → a, b all tainted
            if let BindingPattern::ObjectPattern(obj_pat) = &decl.id
                && self.is_tainted(init)
            {
                let source = self.find_source_in_expr(init);
                for prop in &obj_pat.properties {
                    if let BindingPattern::BindingIdentifier(id) = &prop.value {
                        let name = id.name.to_string();
                        self.tainted_vars.insert(name.clone());
                        self.global_taints.insert(name.clone());
                        if let Some(ref src) = source {
                            self.var_aliases.insert(name, src.clone());
                        }
                    }
                }
                if let Some(rest) = &obj_pat.rest
                    && let BindingPattern::BindingIdentifier(id) = &rest.argument
                {
                    let name = id.name.to_string();
                    self.tainted_vars.insert(name.clone());
                    self.global_taints.insert(name.clone());
                    if let Some(ref src) = source {
                        self.var_aliases.insert(name, src.clone());
                    }
                }
            }

            // Handle array destructuring: const [a, b] = tainted → a, b all tainted
            if let BindingPattern::ArrayPattern(arr_pat) = &decl.id
                && self.is_tainted(init)
            {
                let source = self.find_source_in_expr(init);
                for elem in arr_pat.elements.iter().flatten() {
                    if let BindingPattern::BindingIdentifier(id) = &elem {
                        let name = id.name.to_string();
                        self.tainted_vars.insert(name.clone());
                        self.global_taints.insert(name.clone());
                        if let Some(ref src) = source {
                            self.var_aliases.insert(name, src.clone());
                        }
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
                if let Some(source) = self.url_search_params_source_for_member(member) {
                    return Some(source);
                }
                if let Some(full_path) = self.get_member_string(member) {
                    if matches!(
                        full_path.as_str(),
                        "event.data" | "e.data" | "event.newValue"
                    ) && let Some(source) = self.field_taints.get(&full_path)
                    {
                        return Some(source.clone());
                    }
                    if self.sources.contains(full_path.as_str()) {
                        return Some(full_path);
                    }
                    if let Some(source) = self.field_taints.get(&full_path) {
                        return Some(source.clone());
                    }
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
                        && self.sources.contains(callee_str.as_str())
                    {
                        return self
                            .storage_get_source(call, &callee_str)
                            .or(Some(callee_str));
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
                                && self.sources.contains(member_str.as_str())
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
                    && self.sources.contains(full_path.as_str())
                {
                    return Some(full_path);
                }
                self.find_source_in_expr(&member.object)
            }
            Expression::ParenthesizedExpression(paren) => {
                self.find_source_in_expr(&paren.expression)
            }
            Expression::SequenceExpression(seq) => seq
                .expressions
                .last()
                .and_then(|expr| self.find_source_in_expr(expr)),
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
            // Anonymous function expressions assigned to globals
            // (`window.onload = function () { … }`,
            // `addEventListener("load", function () { … })`, IIFE
            // wrappers) used to short-circuit here, so any taint flow
            // inside their body was invisible to the analyzer — the
            // xss-game level 3 shape (hash → `chooseTab(…)` inside a
            // `window.onload = function () {}` body) slipped through.
            // Walk the function body so call expressions inside reach
            // `walk_call_expression`, where the function-summary
            // lookup fires the sink finding.
            Expression::FunctionExpression(func) => {
                if let Some(body) = &func.body {
                    self.walk_statements(&body.statements);
                }
            }
            Expression::ArrowFunctionExpression(arrow) => {
                self.walk_statements(&arrow.body.statements);
            }

            _ => {}
        }
    }

    fn walk_event_handler_body(
        &mut self,
        param_name: &str,
        event_source: &str,
        statements: &oxc_allocator::Vec<'a, Statement<'a>>,
    ) {
        let saved_tainted = self.tainted_vars.clone();
        let saved_aliases = self.var_aliases.clone();
        let saved_field_taints = self.field_taints.clone();

        self.tainted_vars.insert(param_name.to_string());
        self.var_aliases
            .insert(param_name.to_string(), event_source.to_string());
        if matches!(event_source, "event.data" | "e.data") || event_source.ends_with(".message") {
            self.field_taints
                .insert(format!("{param_name}.data"), event_source.to_string());
        } else if event_source == "event.newValue" {
            self.field_taints.insert(
                format!("{param_name}.newValue"),
                "event.newValue".to_string(),
            );
            self.field_taints.insert(
                format!("{param_name}.oldValue"),
                "event.oldValue".to_string(),
            );
        } else if event_source == "e.target.value" || event_source == "event.target.value" {
            // Input/change events: e.target.value is user-controlled
            self.field_taints.insert(
                format!("{param_name}.target.value"),
                "e.target.value".to_string(),
            );
            self.field_taints
                .insert(format!("{param_name}.target"), "e.target.value".to_string());
        }

        self.walk_statements(statements);

        self.tainted_vars = saved_tainted;
        self.var_aliases = saved_aliases;
        self.field_taints = saved_field_taints;
    }

    fn message_event_source_for_receiver(&self, receiver: &Expression<'a>) -> String {
        match receiver {
            Expression::Identifier(id) => match self.instance_classes.get(id.name.as_str()) {
                Some(class_name) if class_name == "BroadcastChannel" => {
                    "BroadcastChannel.message".to_string()
                }
                Some(class_name) if class_name == "WebSocket" => "WebSocket.message".to_string(),
                Some(class_name) if class_name == "Worker" => "Worker.message".to_string(),
                Some(class_name) if class_name == "SharedWorker" => {
                    "SharedWorker.message".to_string()
                }
                Some(class_name) if class_name == "EventSource" => {
                    "EventSource.message".to_string()
                }
                Some(class_name) if class_name == "MessagePort" => {
                    "MessagePort.message".to_string()
                }
                _ => "event.data".to_string(),
            },
            Expression::StaticMemberExpression(member) => {
                if let Some(full_path) = self.get_member_string(member)
                    && full_path == "navigator.serviceWorker"
                {
                    return "ServiceWorker.message".to_string();
                }

                if matches!(member.property.name.as_str(), "port1" | "port2")
                    && let Expression::Identifier(id) = &member.object
                    && matches!(
                        self.instance_classes
                            .get(id.name.as_str())
                            .map(|name| name.as_str()),
                        Some("MessageChannel")
                    )
                {
                    return "MessagePort.message".to_string();
                }

                if member.property.name.as_str() == "port"
                    && let Expression::Identifier(id) = &member.object
                    && matches!(
                        self.instance_classes
                            .get(id.name.as_str())
                            .map(|name| name.as_str()),
                        Some("SharedWorker")
                    )
                {
                    return "SharedWorker.message".to_string();
                }

                self.message_event_source_for_receiver(&member.object)
            }
            _ => "event.data".to_string(),
        }
    }

    fn event_listener_source(
        &self,
        receiver: &Expression<'a>,
        arg: Option<&Argument<'a>>,
    ) -> Option<String> {
        let event_name = arg
            .and_then(|arg| arg.as_expression())
            .and_then(|expr| match expr {
                Expression::StringLiteral(s) => Some(s.value.as_str()),
                _ => None,
            })?;

        if event_name.eq_ignore_ascii_case("message") {
            Some(self.message_event_source_for_receiver(receiver))
        } else if event_name.eq_ignore_ascii_case("storage") {
            Some("event.newValue".to_string())
        } else if matches!(
            event_name.to_ascii_lowercase().as_str(),
            "input" | "change" | "keyup" | "keydown" | "keypress" | "paste" | "cut"
        ) {
            // User-controlled input events: e.target.value is the tainted source
            Some("e.target.value".to_string())
        } else if event_name.eq_ignore_ascii_case("hashchange") {
            Some("location.hash".to_string())
        } else if event_name.eq_ignore_ascii_case("popstate") {
            Some("history.state".to_string())
        } else {
            None
        }
    }

    fn analyze_onmessage_assignment(
        &mut self,
        span: oxc_span::Span,
        receiver: &Expression<'a>,
        property_name: &str,
        right: &Expression<'a>,
    ) {
        if property_name != "onmessage" {
            return;
        }

        match right {
            Expression::FunctionExpression(func) => {
                if let Some(param) = func.params.items.first()
                    && let BindingPattern::BindingIdentifier(id) = &param.pattern
                    && let Some(body) = &func.body
                {
                    let event_source = self.message_event_source_for_receiver(receiver);
                    self.walk_event_handler_body(id.name.as_str(), &event_source, &body.statements);
                }
            }
            Expression::ArrowFunctionExpression(arrow) => {
                if let Some(param) = arrow.params.items.first()
                    && let BindingPattern::BindingIdentifier(id) = &param.pattern
                {
                    let event_source = self.message_event_source_for_receiver(receiver);
                    self.walk_event_handler_body(
                        id.name.as_str(),
                        &event_source,
                        &arrow.body.statements,
                    );
                }
            }
            Expression::Identifier(handler_id) => {
                if let Some(sink_name) = self
                    .function_summaries
                    .get(handler_id.name.as_str())
                    .and_then(|summary| summary.tainted_param_sinks.get(&0))
                    .cloned()
                {
                    self.report_vulnerability_with_source(
                        span,
                        &sink_name,
                        "Tainted message event data may reach sink through callback",
                        Some(self.message_event_source_for_receiver(receiver)),
                    );
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
                self.analyze_onmessage_assignment(
                    assign.span(),
                    &member.object,
                    prop_name,
                    &assign.right,
                );
                // Script-element body assignments (e.g. `s.text = tainted`
                // where `s` came from `document.createElement('script')`).
                // The browser parses the value as JS source once the
                // element is inserted, so this is a real eval-equivalent
                // sink that the generic `is_assignment_sink_property`
                // check below would miss.
                let script_text_sink = right_tainted
                    && Self::is_script_element_text_sink_prop(prop_name)
                    && matches!(&member.object, Expression::Identifier(id) if self.script_element_vars.contains(id.name.as_str()));
                if script_text_sink {
                    self.report_vulnerability_with_source(
                        assign.span(),
                        &format!("script.{prop_name}"),
                        "Assignment to script-element body executes as JS",
                        right_source.clone(),
                    );
                }
                // Suppress the generic assignment-sink path when the more
                // specific script-element sink already fired — otherwise
                // `s.innerHTML = tainted` (where `s` is a script element)
                // would surface twice, once as `script.innerHTML` and once
                // as the generic `innerHTML`. The script-element form is
                // the correct one for PoC payload selection.
                let is_sink = !script_text_sink && self.is_assignment_sink_property(prop_name);

                // Also check if the full member path is a sink (e.g., location.href)
                let full_path_is_sink = if let Some(full_path) = self.get_member_string(member) {
                    self.sinks.contains(full_path.as_str())
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

                // Track field-level taint for property assignments like:
                // obj.payload = location.hash; sink(obj.payload)
                if right_tainted {
                    if let Some(full_path) = self.get_member_string(member) {
                        if let Some(source) = right_source.clone() {
                            self.field_taints.insert(full_path.clone(), source.clone());
                        } else {
                            self.field_taints
                                .insert(full_path.clone(), "unknown".to_string());
                        }
                    }
                    // Also propagate to object level
                    if let Expression::Identifier(obj_id) = &member.object {
                        self.tainted_vars.insert(obj_id.name.to_string());
                        if let Some(source) = right_source.clone() {
                            self.var_aliases.insert(obj_id.name.to_string(), source);
                        }
                    }
                }
            }
            AssignmentTarget::ComputedMemberExpression(member) => {
                let prop_name = self.get_computed_property_string(member);
                if let Some(property_name) = prop_name.as_deref() {
                    self.analyze_onmessage_assignment(
                        assign.span(),
                        &member.object,
                        property_name,
                        &assign.right,
                    );
                }
                let is_sink = prop_name
                    .as_deref()
                    .map(|name| self.is_assignment_sink_property(name))
                    .unwrap_or(false);
                let full_path_is_sink = self
                    .get_computed_member_string(member)
                    .map(|full_path| self.sinks.contains(full_path.as_str()))
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
                if right_tainted && let Expression::Identifier(obj_id) = &member.object {
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
        if let Expression::StaticMemberExpression(member) = &call.callee
            && member.property.name.as_str() == "set"
            && call.arguments.len() >= 2
        {
            let (value_tainted, source_hint) = self.argument_taint_and_source(&call.arguments[1]);
            if value_tainted && let Expression::Identifier(obj_id) = &member.object {
                self.tainted_vars.insert(obj_id.name.to_string());
                if let Some(source) = source_hint {
                    self.var_aliases.insert(obj_id.name.to_string(), source);
                }
            }
        }

        // Check if this is an addEventListener call with a function argument
        if let Expression::StaticMemberExpression(member) = &call.callee
            && member.property.name.as_str() == "addEventListener"
            && call.arguments.len() >= 2
        {
            let event_source = self.event_listener_source(&member.object, call.arguments.first());

            // The second argument might be a function with event parameter
            if let Some(Argument::FunctionExpression(func)) = call.arguments.get(1) {
                // Mark the first parameter as tainted (it's the event object)
                if let Some(param) = func.params.items.first()
                    && let BindingPattern::BindingIdentifier(id) = &param.pattern
                    && let Some(body) = &func.body
                    && let Some(event_source) = event_source.as_deref()
                {
                    self.walk_event_handler_body(id.name.as_str(), event_source, &body.statements);
                    return;
                }
            }
            // Also handle arrow functions
            if let Some(Argument::ArrowFunctionExpression(arrow)) = call.arguments.get(1)
                && let Some(param) = arrow.params.items.first()
                && let BindingPattern::BindingIdentifier(id) = &param.pattern
                && let Some(event_source) = event_source.as_deref()
            {
                self.walk_event_handler_body(
                    id.name.as_str(),
                    event_source,
                    &arrow.body.statements,
                );
                return;
            }

            // Handle named callback references:
            // window.addEventListener('message', handleMessage)
            if let Some(event_source) = event_source.as_deref()
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
                    Some(event_source.to_string()),
                );
                return;
            }
        }

        // Handle Reflect.apply(targetFn, thisArg, argsArray)
        if let Some(callee_name) = self.get_expr_string(&call.callee)
            && callee_name == "Reflect.apply"
            && call.arguments.len() >= 3
        {
            let target_arg = call.arguments.first();
            let target_expr = target_arg.and_then(|arg| arg.as_expression());
            let target_alias_owned = target_arg
                .and_then(|arg0| self.get_callable_target_alias_from_argument(arg0))
                .cloned();
            let mut target_summary_key =
                target_arg.and_then(|arg0| self.get_callable_target_key_from_argument(arg0));

            if target_summary_key
                .as_ref()
                .and_then(|k| self.function_summaries.get(k))
                .is_none()
                && let Some(alias) = target_alias_owned.as_ref()
            {
                target_summary_key = Some(alias.target.clone());
            }

            if let Some(summary_key) = target_summary_key
                && let Some(param_sinks) =
                    self.function_summaries.get(&summary_key).map(|summary| {
                        summary
                            .tainted_param_sinks
                            .iter()
                            .map(|(idx, sink)| (*idx, sink.clone()))
                            .collect::<Vec<_>>()
                    })
            {
                for (idx, sink_name) in param_sinks {
                    let (tainted, source_hint) = self.resolve_reflect_apply_param_argument_taint(
                        call,
                        target_alias_owned.as_ref(),
                        idx,
                    );
                    if tainted {
                        self.report_vulnerability_with_source(
                            call.span(),
                            &sink_name,
                            "Tainted argument reaches sink through Reflect.apply",
                            source_hint,
                        );
                        return;
                    }
                }
            }

            let mut target_sink_name =
                target_expr.and_then(|expr| self.get_sink_name_for_callable_expr(expr));
            if target_sink_name.is_none()
                && let Some(alias) = target_alias_owned.as_ref()
                && self.sinks.contains(alias.target.as_str())
            {
                target_sink_name = Some(alias.target.clone());
            }

            if let Some(sink_name) = target_sink_name {
                if let Some(target_alias) = target_alias_owned.as_ref()
                    && self.sinks.contains(target_alias.target.as_str())
                {
                    for bound_arg in &target_alias.bound_args {
                        if bound_arg.tainted {
                            self.report_vulnerability_with_source(
                                call.span(),
                                &sink_name,
                                "Tainted pre-bound argument reaches sink function via Reflect.apply",
                                bound_arg.source.clone(),
                            );
                            return;
                        }
                    }
                }

                if let Some(arg_array) = call.arguments.get(2) {
                    let target_method_name = target_expr
                        .and_then(|expr| self.get_callee_property_name(expr))
                        .or_else(|| {
                            if self.sinks.contains(sink_name.as_str()) {
                                Some(sink_name.clone())
                            } else {
                                None
                            }
                        });

                    if target_method_name.as_deref() == Some("setAttribute") {
                        let attr_name_lc = self
                            .resolve_apply_static_string_at(arg_array, 0)
                            .map(|name| name.to_ascii_lowercase());
                        if let Some(name) = attr_name_lc {
                            let dangerous = name.starts_with("on")
                                || name == "href"
                                || name == "xlink:href"
                                || name == "srcdoc";
                            if dangerous {
                                let (tainted, source_hint) =
                                    self.resolve_apply_argument_taint_at(arg_array, 1);
                                if tainted {
                                    self.report_vulnerability_with_source(
                                        call.span(),
                                        &format!("setAttribute:{name}"),
                                        "Tainted data assigned to dangerous attribute via Reflect.apply",
                                        source_hint,
                                    );
                                    return;
                                }
                            }
                        }
                    } else if target_method_name.as_deref() == Some("execCommand") {
                        let cmd_name_lc = self
                            .resolve_apply_static_string_at(arg_array, 0)
                            .map(|name| name.to_ascii_lowercase());
                        if let Some(cmd) = cmd_name_lc
                            && cmd == "inserthtml"
                        {
                            let (tainted, source_hint) =
                                self.resolve_apply_argument_taint_at(arg_array, 2);
                            if tainted {
                                self.report_vulnerability_with_source(
                                    call.span(),
                                    "execCommand:insertHTML",
                                    "Tainted data passed to insertHTML command via Reflect.apply",
                                    source_hint,
                                );
                                return;
                            }
                        }
                    } else if target_method_name.as_deref() == Some("insertAdjacentHTML") {
                        let (tainted, source_hint) =
                            self.resolve_apply_argument_taint_at(arg_array, 1);
                        if tainted {
                            self.report_vulnerability_with_source(
                                call.span(),
                                "insertAdjacentHTML",
                                "Tainted HTML argument passed to sink method via Reflect.apply",
                                source_hint,
                            );
                            return;
                        }
                    } else {
                        let (tainted, source_hint) = self.argument_taint_and_source(arg_array);
                        if tainted {
                            self.report_vulnerability_with_source(
                                call.span(),
                                &sink_name,
                                "Tainted data passed to sink function via Reflect.apply",
                                source_hint,
                            );
                            return;
                        }
                    }
                }
            }
        }

        // Handle Reflect.construct(Function, [taintedCode])
        if let Some(callee_name) = self.get_expr_string(&call.callee)
            && callee_name == "Reflect.construct"
            && call.arguments.len() >= 2
        {
            let target_key = call
                .arguments
                .first()
                .and_then(|arg0| self.get_callable_target_key_from_argument(arg0));
            if target_key.as_deref() == Some("Function")
                && let Some(arg_array) = call.arguments.get(1)
            {
                let (tainted, source_hint) = self.resolve_apply_argument_taint_at(arg_array, 0);
                if tainted {
                    self.report_vulnerability_with_source(
                        call.span(),
                        "Function",
                        "Tainted data passed to Function constructor via Reflect.construct",
                        source_hint,
                    );
                    return;
                }
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
                && let Some(param_sinks) =
                    self.function_summaries.get(&summary_key).map(|summary| {
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
                .map(|name| !self.sinks.contains(name.as_str()))
                .unwrap_or(true)
                && let Some(alias) = target_alias_owned.as_ref()
                && self.sinks.contains(alias.target.as_str())
            {
                target_func_name = Some(alias.target.clone());
            }

            if let Some(target_func_name) =
                target_func_name.filter(|name| self.sinks.contains(name.as_str()))
            {
                if let Some(target_alias) = target_alias_owned.as_ref()
                    && self.sinks.contains(target_alias.target.as_str())
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

        // Propagate taint through common mutation methods.
        // e.g. arr.push(location.hash); document.write(arr[0]);
        // e.g. params.set('html', tainted); replay = new URLSearchParams(params.toString());
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
                "set" if self.url_search_params_objects.contains(target) => {
                    if let Some(arg) = call.arguments.get(1) {
                        let (is_arg_tainted, source_hint) = self.argument_taint_and_source(arg);
                        if is_arg_tainted {
                            tainted_source = source_hint;
                            if let Some(param_name) = Self::extract_static_string_argument(call, 0)
                                && let Some(source) = tainted_source.clone()
                            {
                                self.url_search_params_field_sources.insert(
                                    Self::url_search_params_field_key(target, &param_name),
                                    source,
                                );
                            }
                        }
                    }
                }
                _ => {}
            }

            if let Some(source) = tainted_source {
                self.tainted_vars.insert(target.to_string());
                self.var_aliases.insert(target.to_string(), source.clone());
                if method == "set" && self.url_search_params_objects.contains(target) {
                    self.url_search_params_sources
                        .insert(target.to_string(), source);
                }
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
            .filter(|name| self.sinks.contains(name.as_str()));
        let bound_sink_name = if direct_sink_name.is_none() {
            if let Expression::Identifier(id) = &call.callee {
                self.bound_function_aliases
                    .get(id.name.as_str())
                    .and_then(|alias| {
                        if self.sinks.contains(alias.target.as_str()) {
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
        if let Some(func_name) = direct_sink_name.or(bound_sink_name) {
            if let Some(bound_alias) = alias_owned.as_ref()
                && self.sinks.contains(bound_alias.target.as_str())
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
        if let Some(method_name) = member_method_name
            && self.sinks.contains(method_name.as_str())
        {
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
                        let (tainted, source_hint) = self.argument_taint_and_source(arg1);
                        if tainted {
                            self.report_vulnerability_with_source(
                                call.span(),
                                &format!("setAttribute:{}", name),
                                "Tainted data assigned to dangerous attribute",
                                source_hint,
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
                if let Some(cmd) = cmd_name_lc
                    && cmd == "inserthtml"
                    && let Some(arg2) = call.arguments.get(2)
                {
                    let (tainted, source_hint) = self.argument_taint_and_source(arg2);
                    if tainted {
                        self.report_vulnerability_with_source(
                            call.span(),
                            "execCommand:insertHTML",
                            "Tainted data passed to insertHTML command",
                            source_hint,
                        );
                        return;
                    }
                }
            } else {
                // Generic method sink: if any argument is tainted
                let mut tainted_source: Option<String> = None;
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
                    let (tainted, source_hint) = self.argument_taint_and_source(arg);
                    if tainted {
                        tainted_source = source_hint;
                        break;
                    }
                }
                if tainted_source.is_some() {
                    self.report_vulnerability_with_source(
                        call.span(),
                        &method_name,
                        "Tainted data passed to sink method",
                        tainted_source,
                    );
                    return;
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
mod tests;
