//! AST-based DOM XSS detection
//!
//! This module provides JavaScript AST parsing and taint analysis to detect
//! potential DOM-based XSS vulnerabilities by tracking data flow from untrusted
//! sources to dangerous sinks.

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::LazyLock;

/// Maximum AST recursion depth for the taint-analysis visitor. The JavaScript
/// fed to the analyzer comes from the scanned (attacker-controlled) page, and
/// oxc parses left-leaning member/binary chains *iteratively* — so a chain like
/// `a.b.c.d…`, `a+a+a+…`, a flat method chain `x.a().a().a()…`, or a deeply
/// nested array/object the parser accepted, would overflow the stack inside the
/// recursive visitor (`is_tainted`, `find_source_in_expr`, `walk_expression`,
/// `walk_statement`, `get_member_string`, …) and abort the whole scanner with an
/// uncatchable SIGABRT. Real-world code nests only a few dozen levels, so this
/// cap degrades analysis gracefully far past anything legitimate while keeping
/// the visitor's stack usage bounded. Enforced by a single shared counter
/// ([`DomXssVisitor::enter_recursion`]) checked at the entry of every recursive
/// analysis fn, so the bound holds across helper boundaries (e.g.
/// `call_taint_and_source`) that would reset a per-call depth parameter.
const MAX_AST_VISIT_DEPTH: u32 = 256;

/// Upper bound on the size of a single JavaScript block handed to [`analyze`].
/// oxc's recursive-descent parser has no depth guard, and some constructs the
/// pre-parse [`source_nesting_exceeds_limit`] scan can't cheaply bound — long
/// right-leaning statement/assignment chains (`if(a)if(b)…`, `x=y=z=…`,
/// `for(;;)for(;;)…`) where each level costs ≥2 source bytes — recurse once per
/// level *inside* `.parse()`. Because every such level consumes at least one
/// source byte, capping the input length bounds the achievable parser depth;
/// combined with [`ANALYZE_STACK_BYTES`] this guarantees the parser can't
/// overflow. Scripts larger than this skip AST analysis (best-effort); the cap
/// sits far above any realistic inline `<script>` while staying well under the
/// point where a maximally-dense chain could exhaust the analysis stack.
const MAX_ANALYZE_SOURCE_BYTES: usize = 512 * 1024;

/// Stack size for the dedicated thread that runs the parse + walk. The *walk* is
/// separately bounded to [`MAX_AST_VISIT_DEPTH`] frames by the shared recursion
/// guard, so the deepest consumer of this stack is the **parser**: the densest
/// legal-after-pre-parse-guard input is a ~2-byte-per-level assignment/label
/// chain within [`MAX_ANALYZE_SOURCE_BYTES`], i.e. ~256k parser frames at
/// ~600 B/frame ≈ 150 MiB, which this absorbs with ~1.7× headroom. The
/// reservation is virtual (lazily committed), so the real RSS cost on the common
/// shallow script is only the few KB of stack actually touched.
const ANALYZE_STACK_BYTES: usize = 256 * 1024 * 1024;

/// Below this size [`analyze`] parses inline instead of spawning an
/// [`ANALYZE_STACK_BYTES`] thread. After the pre-parse guard rejects the
/// 1-byte-per-level chains, every surviving parser-recursion level costs ≥2
/// source bytes (`=y`, `a:`, `if(a)`, …), so a script this small can reach at
/// most ~1k parser frames — comfortably within a normal worker stack — and the
/// visitor walk is depth-capped to [`MAX_AST_VISIT_DEPTH`] regardless of stack.
/// The vast majority of inline `<script>` blocks land here and skip the
/// thread-spawn cost; larger blocks pay for the big stack they might need.
const INLINE_PARSE_BYTES: usize = 2 * 1024;

/// Maximum source-level nesting depth accepted before parsing. oxc's
/// recursive-descent parser has **no** internal depth/stack guard (only a 4 GiB
/// byte-length cap), so deeply nested brackets (`((((…`, `{a:{a:…`, `[[[[…`) or
/// long prefix-operator runs (`!!!!…`, `typeof typeof …`, `new new …`) overflow
/// the stack *inside* `.parse()` itself — before the visitor (and its depth
/// guard) ever runs. Empirically oxc overflows a 2 MiB worker stack at roughly
/// 500–600 nested brackets; this conservative cap stays well below that while
/// sitting far above any legitimate script, so `analyze` skips (rather than
/// crashes on) pathological input. See [`source_nesting_exceeds_limit`].
const MAX_SOURCE_NESTING_DEPTH: usize = 200;

/// Conservatively reject source whose structural nesting could overflow oxc's
/// recursive-descent parser. Scans once, counting two independent things that
/// each drive parser recursion:
///
/// * bracket nesting depth — `(`/`[`/`{` raise it, `)`/`]`/`}` lower it;
/// * the length of a run of consecutive prefix-unary operators — the single
///   chars `!`/`~` and the word operators `typeof`/`void`/`delete`/`new`/
///   `await`/`yield`, each of which the parser descends into recursively.
///
/// The scan is intentionally *not* string/comment aware: counting brackets that
/// happen to sit inside a string literal can only *over*-estimate nesting, so it
/// never lets a genuinely dangerous input through — at worst it skips analysis
/// of a script that crams 200+ literal brackets into a string, which is itself
/// pathological. Returns `true` when either measure exceeds
/// [`MAX_SOURCE_NESTING_DEPTH`].
fn source_nesting_exceeds_limit(source: &str) -> bool {
    const PREFIX_KEYWORDS: [&str; 6] = ["typeof", "void", "delete", "new", "await", "yield"];

    let bytes = source.as_bytes();
    let mut bracket_depth: usize = 0;
    let mut unary_run: usize = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'(' | b'[' | b'{' => {
                bracket_depth += 1;
                if bracket_depth > MAX_SOURCE_NESTING_DEPTH {
                    return true;
                }
                unary_run = 0;
                i += 1;
            }
            b')' | b']' | b'}' => {
                bracket_depth = bracket_depth.saturating_sub(1);
                unary_run = 0;
                i += 1;
            }
            b'!' | b'~' => {
                unary_run += 1;
                if unary_run > MAX_SOURCE_NESTING_DEPTH {
                    return true;
                }
                i += 1;
            }
            b' ' | b'\t' | b'\r' | b'\n' => {
                // Whitespace separates tokens without ending a unary run
                // (`! ! !x` / `typeof typeof x` are still nested unaries).
                i += 1;
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'$' => {
                // Read a full identifier/keyword token.
                let start = i;
                while i < bytes.len() {
                    let c = bytes[i];
                    if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' {
                        i += 1;
                    } else {
                        break;
                    }
                }
                let word = &source[start..i];
                if PREFIX_KEYWORDS.contains(&word) {
                    unary_run += 1;
                    if unary_run > MAX_SOURCE_NESTING_DEPTH {
                        return true;
                    }
                } else {
                    unary_run = 0;
                }
            }
            _ => {
                unary_run = 0;
                i += 1;
            }
        }
    }
    false
}

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

/// What a Promise in a `fetch().then(…).then(…)` chain resolves to, threaded
/// from one `.then` callback's return value to the next callback's parameter.
#[derive(Clone)]
enum PromiseValueKind {
    /// The value is a `fetch()` `Response` object — its `.text()`/`.json()`
    /// reads are tainted network data.
    Response,
    /// The value is tainted, carrying the given source label.
    Tainted(String),
    /// The value is not (known to be) tainted.
    Unknown,
}

/// Strictness of a Trusted Types policy `create*` callback.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TtStrictness {
    /// The callback genuinely neutralizes its input — it returns a recognised
    /// sanitizer's output, or never returns the raw parameter at all. Routing a
    /// tainted value through such a callback (or its auto-applied default
    /// policy) is safe, so the finding is a false positive and is suppressed.
    Strict,
    /// Identity / passthrough (`x => x`), trivial wrapping, or a body we cannot
    /// prove safe. The conservative default: taint is *kept*, so a permissive
    /// `createPolicy('default', {createHTML: x=>x})` is correctly flagged as a
    /// bypassable no-op rather than mistaken for protection.
    Permissive,
}

/// Per-method strictness of a `trustedTypes.createPolicy(name, {...})` policy.
/// Methods absent from the config default to [`TtStrictness::Permissive`] so an
/// unanalyzable policy never suppresses a finding (no false negative).
#[derive(Clone, Copy)]
struct TtPolicyInfo {
    create_html: TtStrictness,
    create_script: TtStrictness,
    create_script_url: TtStrictness,
}

/// The first parameter of a Trusted Types `create*` callback, as far as the
/// classifier can reason about it.
enum TtParam {
    /// No parameter at all (and no rest param) — the callback can't reference
    /// the untrusted input, so its result is input-independent.
    None,
    /// A plain `BindingIdentifier` we can track by name.
    Named(String),
    /// A default (`s = ''`), destructured (`{h}`), or rest (`...args`) param —
    /// the input is reachable but not trackable by a simple name, so the
    /// callback is treated conservatively (permissive).
    Complex,
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
    /// IDs of `<script>` elements observed in the surrounding HTML.
    /// When `document.getElementById('id')` resolves to one of these,
    /// the returned element is a real `<script>` and text-property
    /// assignments execute as JS, even though the call is inline and
    /// never bound to a variable. Populated by the HTML pre-scan in
    /// `ast_integration::extract_script_element_ids`.
    script_element_ids: HashSet<String>,
    /// Callback parameters currently bound to a `fetch()` `Response`
    /// object — the first `.then(resp => …)` of a fetch chain. While such
    /// a parameter is in scope, `resp.text()` / `resp.json()` read the
    /// network response body, which is an untrusted DOM-XSS source. The
    /// set is pushed/popped as the promise-chain driver enters and leaves
    /// each callback so the binding never leaks past its callback.
    response_object_vars: HashSet<String>,
    /// Nesting depth of conditional/loop/switch/try branch bodies currently
    /// being walked. The analysis is flow-insensitive, so taint is a *union*
    /// over paths: it is always added, but only *cleared* on an unconditional
    /// reassignment (`branch_depth == 0`). Clearing inside a branch would
    /// wrongly drop taint set on a sibling path — e.g.
    /// `if (c) out = taint; else out = 'x'; sink(out)`.
    branch_depth: u32,
    /// Current recursion depth of the analysis walk, shared across every
    /// mutually-recursive analysis fn (`is_tainted`, `find_source_in_expr`,
    /// `walk_expression`, `walk_statement`, `get_member_string`, …). Incremented
    /// on entry / decremented on exit via [`DomXssVisitor::enter_recursion`];
    /// when it reaches [`MAX_AST_VISIT_DEPTH`] the entered fn bails with a safe
    /// default. A single shared counter (rather than a per-call depth argument)
    /// is what makes the guard impossible to defeat by routing recursion through
    /// a helper that re-enters at depth 0 — the flat-call-chain shape
    /// `x.a().a().a()…` did exactly that. An `Rc<Cell<…>>` (rather than a bare
    /// `Cell`) so the RAII guard can own a handle to the counter without
    /// borrowing `self` — the walkers take `&mut self`, which a `&self`-borrow
    /// held across the call would conflict with.
    recursion_depth: Rc<Cell<u32>>,
    /// Whether `require-trusted-types-for 'script'` is enforced for this page
    /// (threaded from the response CSP). Gates the program-wide default-policy
    /// suppression: without enforcement a `'default'` policy is inert, so we
    /// never suppress on its account — preserving today's findings exactly.
    trusted_types_enforced: bool,
    /// `policyVar -> per-method strictness` for `const p = trustedTypes
    /// .createPolicy(name, {...})`. Lets `p.createHTML(taint)` be treated as a
    /// (strict) sanitizer or a (permissive) no-op. Populated as the walk passes
    /// each binding, so a policy defined before a sink is known at the sink; a
    /// policy defined *after* simply isn't applied (the finding is kept — the
    /// safe direction).
    tt_policies: HashMap<String, TtPolicyInfo>,
    /// Strictness of the auto-applied `'default'` policy, when one is defined in
    /// this block. Used — only under [`trusted_types_enforced`] — to suppress
    /// TrustedHTML-sink findings the browser's default `createHTML` would
    /// neutralize.
    ///
    /// [`trusted_types_enforced`]: DomXssVisitor::trusted_types_enforced
    default_tt_policy: Option<TtPolicyInfo>,
}

/// RAII token returned by [`DomXssVisitor::enter_recursion`]; decrements the
/// shared recursion counter when the analysis fn that holds it returns.
struct RecursionGuard {
    depth: Rc<Cell<u32>>,
}

impl Drop for RecursionGuard {
    fn drop(&mut self) {
        self.depth.set(self.depth.get().saturating_sub(1));
    }
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
            script_element_ids: HashSet::new(),
            response_object_vars: HashSet::new(),
            branch_depth: 0,
            recursion_depth: Rc::new(Cell::new(0)),
            trusted_types_enforced: false,
            tt_policies: HashMap::new(),
            default_tt_policy: None,
        }
    }

    fn with_script_element_ids(mut self, ids: HashSet<String>) -> Self {
        self.script_element_ids = ids;
        self
    }

    /// Mark that the page enforces `require-trusted-types-for 'script'`, so a
    /// strict `'default'` Trusted Types policy genuinely neutralizes TrustedHTML
    /// sinks and those findings can be suppressed. Off by default — when off,
    /// behaviour is identical to before Trusted Types awareness existed.
    fn with_trusted_types_enforced(mut self, enforced: bool) -> Self {
        self.trusted_types_enforced = enforced;
        self
    }

    /// Enter one recursive analysis step. Returns `None` — telling the caller to
    /// bail with a safe default (`false` / `None` / stop walking) — once the
    /// shared recursion depth has reached [`MAX_AST_VISIT_DEPTH`]; otherwise
    /// increments the counter and hands back a [`RecursionGuard`] that restores
    /// it on scope exit. See [`recursion_depth`](DomXssVisitor::recursion_depth).
    fn enter_recursion(&self) -> Option<RecursionGuard> {
        let depth = self.recursion_depth.get();
        if depth >= MAX_AST_VISIT_DEPTH {
            return None;
        }
        self.recursion_depth.set(depth + 1);
        Some(RecursionGuard {
            depth: Rc::clone(&self.recursion_depth),
        })
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
                    .map(Str::as_str)
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

    /// Decide whether an expression resolves to a `<script>` DOM element.
    /// Covers:
    ///   * identifiers previously assigned a script element
    ///     (`document.createElement('script')` or a script lookup);
    ///   * inline `document.getElementById('id')` when `id` matches a
    ///     `<script id="...">` observed in the surrounding HTML;
    ///   * inline `document.querySelector(...)` / `querySelectorAll(...)[N]`
    ///     when the selector statically picks a script element;
    ///   * `document.getElementsByTagName('script')[N]` /
    ///     `document.scripts[N]`.
    ///
    /// The selector parsing is intentionally conservative — only fully
    /// static literal arguments resolve, so a dynamic selector never
    /// false-positives on a non-script element.
    fn expr_resolves_to_script_element(&self, expr: &Expression<'a>) -> bool {
        match expr {
            Expression::Identifier(id) => self.script_element_vars.contains(id.name.as_str()),
            Expression::ParenthesizedExpression(p) => {
                self.expr_resolves_to_script_element(&p.expression)
            }
            Expression::CallExpression(call) => self.call_resolves_to_script_element(call),
            Expression::ComputedMemberExpression(member) => {
                self.computed_member_resolves_to_script_element(member)
            }
            Expression::StaticMemberExpression(member) => {
                // `document.scripts` as a *value* is a collection, not an
                // element. Only `document.scripts[N]` resolves, and that
                // shape is handled in `computed_member_resolves_to_script_element`.
                let _ = member;
                false
            }
            _ => false,
        }
    }

    fn call_resolves_to_script_element(&self, call: &CallExpression<'a>) -> bool {
        let Some(method) = self.get_callee_property_name(&call.callee) else {
            return false;
        };
        match method.as_str() {
            "getElementById" => {
                let Some(id) = Self::extract_static_string_argument(call, 0) else {
                    return false;
                };
                self.script_element_ids.contains(&id)
            }
            "querySelector" => {
                let Some(sel) = Self::extract_static_string_argument(call, 0) else {
                    return false;
                };
                Self::selector_targets_script(&sel)
            }
            _ => false,
        }
    }

    fn computed_member_resolves_to_script_element(
        &self,
        member: &ComputedMemberExpression<'a>,
    ) -> bool {
        // Look at the object being indexed.
        match &member.object {
            // `document.scripts[N]` — `scripts` is an HTMLCollection of all
            // `<script>` elements, so any numeric / string-numeric index
            // returns a script element.
            Expression::StaticMemberExpression(inner) => {
                if let Some(path) = self.get_member_string(inner)
                    && path == "document.scripts"
                {
                    return true;
                }
                false
            }
            // `document.getElementsByTagName('script')[N]` and
            // `document.querySelectorAll('script')[N]`.
            Expression::CallExpression(call) => {
                let Some(method) = self.get_callee_property_name(&call.callee) else {
                    return false;
                };
                match method.as_str() {
                    "getElementsByTagName" => Self::call_first_arg_eq_ignore_case(call, "script"),
                    "querySelectorAll" => {
                        let Some(sel) = Self::extract_static_string_argument(call, 0) else {
                            return false;
                        };
                        Self::selector_targets_script(&sel)
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    fn call_first_arg_eq_ignore_case(call: &CallExpression<'a>, expected: &str) -> bool {
        Self::extract_static_string_argument(call, 0)
            .is_some_and(|s| s.eq_ignore_ascii_case(expected))
    }

    /// Static-selector matcher for "this picks a `<script>`."
    /// Accepts the conservative shapes that appear in real bundles —
    /// `script`, `script#id`, `script[id="x"]`, `script.cls`, `script[*]`.
    /// Combinators (`,`, ` `, `>`, `+`, `~`) are rejected so we never
    /// claim a selector resolves to script when the rightmost element
    /// could be anything.
    fn selector_targets_script(selector: &str) -> bool {
        let trimmed = selector.trim();
        if trimmed.is_empty() {
            return false;
        }
        // A descendant / sibling / list combinator means the matched
        // element is the *last* compound selector. Be safe and reject —
        // we'd need real CSS parsing to handle these reliably.
        if trimmed
            .chars()
            .any(|c| [',', ' ', '>', '+', '~'].contains(&c))
        {
            return false;
        }
        // The tag portion is everything up to the first `.`, `#`, `[`, or `:`.
        let tag_end = trimmed.find(['.', '#', '[', ':']).unwrap_or(trimmed.len());
        let tag = &trimmed[..tag_end];
        tag.eq_ignore_ascii_case("script")
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

    /// Get string representation of static member expression.
    ///
    /// A long `a.b.c.d…` member chain (which oxc parses iteratively, so the
    /// parser never overflows) recurses here once per `.` segment; the shared
    /// recursion guard bails past [`MAX_AST_VISIT_DEPTH`] so a hostile chain
    /// can't overflow the stack and abort the scanner.
    fn get_member_string(&self, member: &StaticMemberExpression) -> Option<String> {
        let _guard = self.enter_recursion()?;
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

    /// Get string representation of computed member expression when property is
    /// literal. Mutually recursive with [`get_member_string`]; the shared
    /// recursion guard bounds `a["b"]["c"]…` chains so a hostile computed-member
    /// chain can't overflow the stack.
    fn get_computed_member_string(&self, member: &ComputedMemberExpression<'a>) -> Option<String> {
        let _guard = self.enter_recursion()?;
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
    fn tt_create_policy_config<'b>(
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
    fn tt_create_policy_call<'b>(
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
    fn tt_callback_param(params: &FormalParameters<'a>) -> TtParam {
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
    fn classify_tt_create_method(&self, fn_expr: &Expression<'a>) -> TtStrictness {
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
    fn identifier_referenced(src: &str, name: &str) -> bool {
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
            from = start + 1;
        }
        false
    }

    /// Source text spanning a list of statements (first start .. last end),
    /// empty when the list is empty. Used to inspect a callback body without
    /// the surrounding braces or parameter list.
    fn stmts_source(&self, stmts: &[Statement<'a>]) -> &'a str {
        match (stmts.first(), stmts.last()) {
            (Some(first), Some(last)) => self
                .source_code
                .get(first.span().start as usize..last.span().end as usize)
                .unwrap_or(""),
            _ => "",
        }
    }

    /// Source text of a single expression.
    fn expr_source(&self, expr: &Expression<'a>) -> &'a str {
        let span = expr.span();
        self.source_code
            .get(span.start as usize..span.end as usize)
            .unwrap_or("")
    }

    /// Build a [`TtPolicyInfo`] from a `createPolicy` config object literal.
    fn build_tt_policy_info(&self, config: &ObjectExpression<'a>) -> TtPolicyInfo {
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
    fn record_tt_policy_binding(&mut self, var_name: &str, init: &Expression<'a>) {
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
    fn tt_wrapper_call_strictness(&self, call: &CallExpression<'a>) -> Option<TtStrictness> {
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
    fn is_trusted_html_sink(sink: &str) -> bool {
        matches!(
            sink,
            "innerHTML"
                | "outerHTML"
                | "insertAdjacentHTML"
                | "createContextualFragment"
                | "document.write"
                | "document.writeln"
                | "setHTMLUnsafe"
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
    fn default_policy_suppresses_sink(&self, sink: &str) -> bool {
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

    /// Evaluate an expression to a static string when possible.
    ///
    /// Recurses unguarded by the visitor walk (it's reached from
    /// `get_computed_member_string` for `x[ "a" + "b" + … ]` keys), so it carries
    /// the shared recursion guard itself — a hostile `+`/paren chain here would
    /// otherwise overflow the stack independently of the visitor's other guards.
    fn eval_static_string_expr(&self, expr: &Expression<'a>) -> Option<String> {
        let _guard = self.enter_recursion()?;
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
        key.name().map(std::borrow::Cow::into_owned)
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

    /// Walk the object chain of a member-expression callee and return true
    /// when the chain terminates in a `$(...)` or `jQuery(...)` call.
    ///
    /// Used to gate native-vs-jQuery DOM insertion methods (`append`,
    /// `prepend`, `after`, `before`). On a native `Element` these methods
    /// insert string arguments as text nodes — no HTML parsing, no script
    /// execution — so they are NOT XSS sinks. They only behave as sinks
    /// when called on a jQuery selector chain, where `.append(html)`
    /// invokes `innerHTML` semantics under the hood.
    ///
    /// Handles chains like `$('#x').append(...)` and
    /// `$('#x').find('.y').append(...)` by following the `object` link of
    /// each intermediate `StaticMemberExpression` / `CallExpression`.
    fn callee_receiver_is_jquery_chain(callee: &Expression<'a>) -> bool {
        let mut current: &Expression<'a> = match callee {
            Expression::StaticMemberExpression(m) => &m.object,
            Expression::ComputedMemberExpression(m) => &m.object,
            _ => return false,
        };
        loop {
            match current {
                Expression::CallExpression(call) => match &call.callee {
                    Expression::Identifier(id) => {
                        return id.name == "$" || id.name == "jQuery";
                    }
                    Expression::StaticMemberExpression(m) => current = &m.object,
                    Expression::ComputedMemberExpression(m) => current = &m.object,
                    _ => return false,
                },
                Expression::StaticMemberExpression(m) => current = &m.object,
                Expression::ComputedMemberExpression(m) => current = &m.object,
                Expression::ParenthesizedExpression(p) => current = &p.expression,
                _ => return false,
            }
        }
    }

    /// The non-empty constant string that must appear at the *start* of
    /// `expr`'s value, when statically determinable. Used to decide whether a
    /// jQuery `$()` argument is forced into selector mode (a leading
    /// `#`/`.`/tag char) or can be parsed as HTML (no static prefix, or a
    /// leading `<`).
    ///
    /// Returns `None` when no non-empty static leading text can be determined
    /// — including a template literal that opens with `${expr}` (empty first
    /// quasi), where the runtime prefix is dynamic.
    fn static_leading_string(&self, expr: &Expression<'a>) -> Option<String> {
        // Recurses down `+` / paren chains outside the main walkers (reached via
        // the jQuery selector heuristic), so it carries the shared recursion
        // guard — `$("a"+"a"+…+location.hash)` would otherwise overflow here.
        let _guard = self.enter_recursion()?;
        match expr {
            Expression::StringLiteral(s) => Some(s.value.to_string()),
            Expression::TemplateLiteral(t) => {
                // A template opening with `${…}` has an empty first quasi, so
                // the runtime prefix is whatever that expression yields — no
                // static leading text we can rely on.
                let first = t.quasis.first()?;
                let raw = first.value.cooked.as_ref().map(Str::as_str).unwrap_or("");
                if raw.is_empty() {
                    None
                } else {
                    Some(raw.to_string())
                }
            }
            Expression::BinaryExpression(b) if b.operator == BinaryOperator::Addition => {
                self.static_leading_string(&b.left)
            }
            Expression::ParenthesizedExpression(p) => self.static_leading_string(&p.expression),
            _ => None,
        }
    }

    /// True when a jQuery `$()` / `jQuery()` argument is pinned into *selector*
    /// mode by a constant leading character (`#id`, `.class`, `tag`, `[attr]`,
    /// …). jQuery only builds DOM nodes (the XSS-relevant path) when the first
    /// non-whitespace character of the string is `<`, so a constant non-`<`
    /// prefix means the tainted tail can never start an HTML tag — suppress.
    ///
    /// No static prefix (`$(taint)`, `$(decodeURIComponent(...))`) or a
    /// leading `<` (`$('<div>' + taint)`) does NOT force selector mode, so the
    /// constructor can create elements and we keep the finding.
    fn jquery_arg_forces_selector(&self, expr: &Expression<'a>) -> bool {
        match self.static_leading_string(expr) {
            Some(prefix) => {
                let trimmed = prefix.trim_start();
                !trimmed.is_empty() && !trimmed.starts_with('<')
            }
            None => false,
        }
    }

    /// Recognise the `fetch(...)` global call (bare, or via `window`/`self`/
    /// `globalThis`). Its returned Promise resolves to a `Response`.
    fn is_fetch_call(&self, call: &CallExpression<'a>) -> bool {
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
    fn awaited_fetch_var(&self, expr: &Expression<'a>) -> bool {
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

    /// If `call` invokes a Promise combinator (`.then` / `.catch` / `.finally`),
    /// return the method name.
    fn promise_method_name(call: &CallExpression<'a>) -> Option<&'static str> {
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
    /// whose root is a `fetch(...)` call. Walks the receiver chain down through
    /// nested combinators.
    fn promise_chain_roots_at_fetch(&self, call: &CallExpression<'a>) -> bool {
        let mut current: &Expression<'a> = match &call.callee {
            Expression::StaticMemberExpression(m) => &m.object,
            _ => return false,
        };
        loop {
            match current {
                Expression::ParenthesizedExpression(p) => current = &p.expression,
                Expression::CallExpression(inner) => {
                    if self.is_fetch_call(inner) {
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
    fn first_return_expr<'b>(stmts: &'b [Statement<'a>]) -> Option<&'b Expression<'a>> {
        for stmt in stmts {
            if let Statement::ReturnStatement(ret) = stmt {
                return ret.argument.as_ref();
            }
        }
        None
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
    fn xhr_response_source_for_member(
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
    fn is_tainted(&self, expr: &Expression) -> bool {
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
    fn report_vulnerability_with_source(
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
        let saved_response_vars = self.response_object_vars.clone();
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
        self.response_object_vars = saved_response_vars;
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

    /// Walk through a single statement.
    ///
    /// Nested statements (`if(a)if(b)…`, `for(;;)for(;;)…`, nested blocks)
    /// recurse here, so the shared recursion guard bounds statement nesting the
    /// same way it bounds expression nesting — stopping past
    /// [`MAX_AST_VISIT_DEPTH`] so a hostile chain that parsed (on the large
    /// analysis stack) can't overflow the walk.
    fn walk_statement(&mut self, stmt: &Statement<'a>) {
        let Some(_guard) = self.enter_recursion() else {
            return;
        };
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
                // Branch bodies are conditional: suppress detaint inside them.
                self.branch_depth += 1;
                self.walk_statement(&if_stmt.consequent);
                if let Some(alt) = &if_stmt.alternate {
                    self.walk_statement(alt);
                }
                self.branch_depth -= 1;
            }
            Statement::WhileStatement(while_stmt) => {
                self.walk_expression(&while_stmt.test);
                self.branch_depth += 1;
                self.walk_statement(&while_stmt.body);
                self.branch_depth -= 1;
            }
            Statement::ForStatement(for_stmt) => {
                // `init` runs unconditionally; `update`/`body` are conditional.
                if let Some(ForStatementInit::VariableDeclaration(var_decl)) = &for_stmt.init {
                    for decl in &var_decl.declarations {
                        self.walk_variable_declarator(decl);
                    }
                }
                if let Some(test) = &for_stmt.test {
                    self.walk_expression(test);
                }
                self.branch_depth += 1;
                if let Some(update) = &for_stmt.update {
                    self.walk_expression(update);
                }
                self.walk_statement(&for_stmt.body);
                self.branch_depth -= 1;
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
                    let saved_response_vars = self.response_object_vars.clone();

                    self.walk_statements(&body.statements);

                    // Restore state after function (locals don't leak out —
                    // e.g. a `const r = await fetch()` Response binding must
                    // not taint an unrelated outer `r.text()`).
                    self.tainted_vars = saved_tainted;
                    self.var_aliases = saved_aliases;
                    self.response_object_vars = saved_response_vars;
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
                self.branch_depth += 1;
                for case in &switch_stmt.cases {
                    if let Some(test) = &case.test {
                        self.walk_expression(test);
                    }
                    self.walk_statements(&case.consequent);
                }
                self.branch_depth -= 1;
            }
            Statement::TryStatement(try_stmt) => {
                // `catch`/`finally` are conditional; the `try` block may also
                // abort partway, so treat the whole construct as a branch.
                self.branch_depth += 1;
                self.walk_statements(&try_stmt.block.body);
                if let Some(handler) = &try_stmt.handler {
                    self.walk_statements(&handler.body.body);
                }
                if let Some(finalizer) = &try_stmt.finalizer {
                    self.walk_statements(&finalizer.body);
                }
                self.branch_depth -= 1;
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
                // `const r = await fetch(url)` — r holds a Response, so later
                // `r.text()` / `r.json()` reads are tainted (issue #1024).
                if self.awaited_fetch_var(init) {
                    self.response_object_vars.insert(var_name.to_string());
                } else {
                    self.response_object_vars.remove(var_name);
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
                // other element kind. Also covers element lookups that
                // statically resolve to a `<script>` element
                // (`getElementById('script-id')`, `querySelector('script')`,
                // `document.scripts[N]`, …).
                if self.expr_creates_script_element(init)
                    || self.expr_resolves_to_script_element(init)
                {
                    self.script_element_vars.insert(var_name.to_string());
                } else {
                    self.script_element_vars.remove(var_name);
                }

                // `const p = trustedTypes.createPolicy(name, {...})` — track the
                // policy so a later `p.createHTML(x)` resolves, and note the
                // auto-applied `'default'` policy.
                self.record_tt_policy_binding(var_name, init);

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
                        _ => arg.as_expression().is_some_and(|e| self.is_tainted(e)),
                    };
                    if is_arg_tainted {
                        self.tainted_vars.insert(var_name.to_string());
                        let source_expr = match arg {
                            Argument::SpreadElement(spread) => Some(&spread.argument),
                            _ => arg.as_expression(),
                        };
                        let source = source_expr
                            .and_then(|e| self.find_source_in_expr(e))
                            .map_or_else(
                                || "location.search".to_string(),
                                |source| {
                                    if id.name.as_str() == "URLSearchParams" {
                                        self.normalize_search_param_source(&source)
                                    } else {
                                        source
                                    }
                                },
                            );
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
                            _ => arg.as_expression().is_some_and(|e| self.is_tainted(e)),
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

    /// Find a source in an expression (for alias tracking).
    ///
    /// Mirrors the recursion guard in [`is_tainted`]: a deeply nested
    /// attacker-controlled expression would otherwise overflow the stack here
    /// and abort the scanner. Returns `None` (no source found) once the shared
    /// recursion depth reaches [`MAX_AST_VISIT_DEPTH`].
    fn find_source_in_expr(&self, expr: &Expression<'a>) -> Option<String> {
        let _guard = self.enter_recursion()?;
        match expr {
            Expression::Identifier(id) => self.var_aliases.get(id.name.as_str()).cloned(),
            Expression::StaticMemberExpression(member) => {
                if let Some(source) = self.url_search_params_source_for_member(member) {
                    return Some(source);
                }
                if let Some(source) = self.xhr_response_source_for_member(member) {
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
            Expression::AwaitExpression(await_expr) => {
                self.find_source_in_expr(&await_expr.argument)
            }
            _ => None,
        }
    }

    /// Walk through an expression.
    ///
    /// Guards the same way as [`is_tainted`]: member / binary / logical /
    /// conditional chains (and, via `walk_call_expression`, flat call chains)
    /// recurse here, so a hostile deeply nested expression would overflow the
    /// stack and SIGABRT the scanner. The shared recursion guard stops
    /// descending past [`MAX_AST_VISIT_DEPTH`].
    fn walk_expression(&mut self, expr: &Expression<'a>) {
        let Some(_guard) = self.enter_recursion() else {
            return;
        };
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
                            let arg_expr = match arg {
                                Argument::SpreadElement(spread) => Some(&spread.argument),
                                _ => arg.as_expression(),
                            };
                            let is_arg_tainted = arg_expr.is_some_and(|e| self.is_tainted(e));
                            if is_arg_tainted {
                                // Propagate the originating source (e.g.
                                // `URLSearchParams.get('q')`) instead of
                                // letting the finding fall back to
                                // "unknown source". CallExpression sinks
                                // already do this — mirror it here so
                                // `new Function(...)` carries the same
                                // provenance string into the report.
                                let source = arg_expr.and_then(|e| self.find_source_in_expr(e));
                                self.report_vulnerability_with_source(
                                    new_expr.span(),
                                    callee_name,
                                    "Tainted data passed to constructor",
                                    source,
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
            // Dynamic `import(tainted)` runs an attacker-controlled module
            // (issue #1022). Detect it here; reached both as a bare statement
            // (`import(t);`) and as the object of a chain (`import(t).then(…)`)
            // via the member-object recursion below.
            Expression::ImportExpression(import_expr) => {
                self.walk_import_expression(import_expr);
            }
            Expression::AwaitExpression(await_expr) => {
                self.walk_expression(&await_expr.argument);
            }
            Expression::ParenthesizedExpression(paren) => {
                self.walk_expression(&paren.expression);
            }
            Expression::SequenceExpression(seq) => {
                for e in &seq.expressions {
                    self.walk_expression(e);
                }
            }
            // Reach call / import expressions that sit as the *object* of a
            // member access — e.g. `$(tainted).appendTo(...)`,
            // `import(tainted).then(...)`, `eval(tainted).x`. A member-callee
            // chain otherwise never visits its leftmost operand.
            Expression::StaticMemberExpression(member) => {
                self.walk_expression(&member.object);
            }
            Expression::ComputedMemberExpression(member) => {
                self.walk_expression(&member.object);
                self.walk_expression(&member.expression);
            }

            _ => {}
        }
    }

    /// Report `import(tainted)` as a code-execution sink and walk the
    /// specifier for any nested sinks. A tainted module specifier (a
    /// `data:text/javascript,…` URL or a remote/`//host` URL derived from
    /// `location.*`, `URLSearchParams`, `name`, `document.referrer`, …) loads
    /// and runs an attacker-controlled ES module — a real DOM XSS.
    fn walk_import_expression(&mut self, import_expr: &ImportExpression<'a>) {
        if self.is_tainted(&import_expr.source) {
            let source = self.find_source_in_expr(&import_expr.source);
            self.report_vulnerability_with_source(
                import_expr.span,
                "import",
                "Tainted module specifier passed to dynamic import() runs attacker-controlled module code",
                source,
            );
        }
        self.walk_expression(&import_expr.source);
    }

    /// Drive a `fetch().then(...)…` Promise chain (issue #1024): walk each
    /// callback body so nested sinks fire, threading the resolved value
    /// (`Response`, then the awaited text/json) from one callback's return
    /// into the next callback's parameter. Returns the kind the chain
    /// ultimately resolves to (unused at the top level).
    fn promise_kind_of_call(&mut self, call: &CallExpression<'a>) -> PromiseValueKind {
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

    fn promise_kind_of_expr(&mut self, expr: &Expression<'a>) -> PromiseValueKind {
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
    fn process_promise_callback(
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
    fn named_promise_callback_kind(
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

    fn first_param_name(params: &FormalParameters<'a>) -> Option<String> {
        params.items.first().and_then(|p| match &p.pattern {
            BindingPattern::BindingIdentifier(id) => Some(id.name.to_string()),
            _ => None,
        })
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
        // Descends a `.`-chain receiver outside the main walkers (reached from
        // onmessage assignments / addEventListener("message", …)), so it carries
        // the shared recursion guard, falling back to its generic default. A
        // hostile `a.a.a.….onmessage = fn` chain would otherwise overflow here.
        let Some(_guard) = self.enter_recursion() else {
            return "event.data".to_string();
        };
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
                            .map(String::as_str),
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
                            .map(String::as_str),
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
                    && self.expr_resolves_to_script_element(&member.object);
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
                    .is_some_and(|name| self.is_assignment_sink_property(name));
                let full_path_is_sink = self
                    .get_computed_member_string(member)
                    .is_some_and(|full_path| self.sinks.contains(full_path.as_str()));

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

                // `p = trustedTypes.createPolicy(name, {...})` assignment form.
                self.record_tt_policy_binding(target_name, &assign.right);

                // Propagate taint through direct assignments like `a = taintedValue;`
                if right_tainted {
                    self.tainted_vars.insert(target_name.to_string());
                    if let Some(source) = right_source.clone() {
                        self.var_aliases.insert(target_name.to_string(), source);
                    }
                } else if self.branch_depth == 0 {
                    // Reassigning a previously-tainted variable to a clean or
                    // sanitized value clears its taint — e.g.
                    // `x = location.hash; x = DOMPurify.sanitize(x)` or
                    // `x = "static"`. Without this the flow-insensitive walker
                    // keeps the stale taint and reports a false positive at any
                    // later sink that reads `x`. This mirrors the
                    // `instance_classes` / `bound_function_aliases` clears just
                    // above. Because the walker runs top-to-bottom, a sink that
                    // consumed the tainted value *before* this reassignment was
                    // already reported, so confirmed flows are not lost.
                    //
                    // Only clear at `branch_depth == 0` (unconditional
                    // reassignment). Taint is a union over paths, so a clean
                    // assignment inside one conditional branch must not drop
                    // taint set on a sibling branch
                    // (`if (c) out = taint; else out = 'x'; sink(out)`).
                    self.tainted_vars.remove(target_name);
                    self.var_aliases.remove(target_name);
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
        // Standalone `trustedTypes.createPolicy('default', {...})` (not bound to
        // a variable) still registers the auto-applied default policy.
        if let Some((name, config)) = self.tt_create_policy_config(call)
            && name.as_deref() == Some("default")
        {
            let info = self.build_tt_policy_info(config);
            self.default_tt_policy = Some(info);
        }

        // fetch().then(...) response-source chains (issue #1024). Drive the
        // whole chain here so each callback body is walked with the resolved
        // Response / tainted value bound to its parameter, then return.
        if Self::promise_method_name(call).is_some() && self.promise_chain_roots_at_fetch(call) {
            self.promise_kind_of_call(call);
            return;
        }

        // jQuery `$(tainted)` / `jQuery(tainted)` selector-to-HTML constructor
        // (issue #1021). A string whose first non-whitespace char is `<` makes
        // jQuery build live DOM nodes (running onerror/onload). Fire only when
        // the argument is tainted AND not pinned into selector mode by a
        // constant `#`/`.`/tag prefix — see `jquery_arg_forces_selector`.
        if let Expression::Identifier(id) = &call.callee
            && (id.name == "$" || id.name == "jQuery")
            && let Some(arg0) = call.arguments.first()
            && let Some(arg_expr) = arg0.as_expression()
            && self.is_tainted(arg_expr)
            && !self.jquery_arg_forces_selector(arg_expr)
        {
            let source = self.find_source_in_expr(arg_expr);
            self.report_vulnerability_with_source(
                call.span(),
                "jQuery$",
                "Tainted HTML string passed to jQuery $() constructor builds DOM nodes (selector-to-HTML)",
                source,
            );
            // Walk the (tainted) argument so a nested sink inside it — e.g.
            // `$(eval(location.hash))` — is also reported; the trailing
            // `walk_expression(&call.callee)` only descends the `$` callee,
            // never the call's arguments.
            self.walk_expression(arg_expr);
        }

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
                .is_none_or(|name| !self.sinks.contains(name.as_str()))
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
            } else if matches!(
                method_name.as_str(),
                "append" | "prepend" | "after" | "before"
            ) && !Self::callee_receiver_is_jquery_chain(&call.callee)
            {
                // FP suppression: native `Element.append / .prepend / .after
                // / .before` insert string arguments as text nodes — they do
                // NOT parse HTML and cannot trigger script execution. Only
                // jQuery's same-named methods are real HTML sinks (they call
                // `innerHTML` internally). Without a `$(...)` / `jQuery(...)`
                // receiver chain, treat these method calls as inert.
                //
                // Falls through to walk the callee so taint tracking through
                // arguments and sub-expressions still proceeds.
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

        // Descend into function/arrow callbacks passed as arguments so a
        // source→sink flow that lives *inside* a deferred callback is still
        // analyzed. The classic shape is a `setTimeout` / `setInterval` /
        // `requestAnimationFrame` / `queueMicrotask` body — e.g.
        // `setTimeout(function(){ el.innerHTML = location.search }, 0)`. The
        // callback never runs at parse time, and the call's arguments are not
        // walked anywhere else (the trailing `walk_expression(&call.callee)`
        // only descends the callee), so without this the body is invisible.
        // Cases that own their callback walking (`addEventListener`, `.then`
        // chains, `Reflect.apply`, …) `return` early and never reach here.
        self.walk_callback_argument_bodies(call);
    }

    /// Walk function/arrow callbacks passed as call arguments, each with an
    /// isolated taint scope so a callback-local variable (`var q = …` inside
    /// the callback) does not leak taint into the enclosing scope. Only
    /// function-shaped arguments are descended; data arguments keep their
    /// existing taint-evaluation-only treatment.
    fn walk_callback_argument_bodies(&mut self, call: &CallExpression<'a>) {
        for arg in &call.arguments {
            let Some(expr) = arg.as_expression() else {
                continue;
            };
            let statements = match expr {
                Expression::FunctionExpression(func) => {
                    let Some(body) = &func.body else {
                        continue;
                    };
                    &body.statements
                }
                Expression::ArrowFunctionExpression(arrow) => &arrow.body.statements,
                _ => continue,
            };

            let saved_tainted = self.tainted_vars.clone();
            let saved_aliases = self.var_aliases.clone();
            let saved_field_taints = self.field_taints.clone();
            self.walk_statements(statements);
            self.tainted_vars = saved_tainted;
            self.var_aliases = saved_aliases;
            self.field_taints = saved_field_taints;
        }
    }
}

/// AST-based DOM XSS analyzer
#[derive(Default)]
pub struct AstDomAnalyzer {
    /// IDs of `<script>` elements gathered from the surrounding HTML
    /// (see `ast_integration::extract_script_element_ids`). Empty when
    /// the caller has no HTML context.
    script_element_ids: HashSet<String>,
    /// Whether the response CSP enforces `require-trusted-types-for 'script'`.
    /// Threaded into the visitor to gate strict-default-policy suppression.
    /// Off by default — preserving pre-Trusted-Types behaviour for callers
    /// without CSP context.
    trusted_types_enforced: bool,
}

impl AstDomAnalyzer {
    /// Create a new AST DOM analyzer
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the set of `<script>` element IDs from the surrounding HTML
    /// so `document.getElementById('id').innerText = tainted` can be
    /// recognised as a JS-eval sink even when the lookup is inline.
    pub fn with_script_element_ids(mut self, ids: HashSet<String>) -> Self {
        self.script_element_ids = ids;
        self
    }

    /// Mark that the response CSP enforces `require-trusted-types-for 'script'`,
    /// so a strict `'default'` Trusted Types policy in the page neutralizes
    /// TrustedHTML sinks and those (now false-positive) findings are suppressed.
    pub fn with_trusted_types_enforced(mut self, enforced: bool) -> Self {
        self.trusted_types_enforced = enforced;
        self
    }

    /// Analyze JavaScript source code for DOM XSS vulnerabilities.
    ///
    /// The input comes from the scanned (attacker-controlled) page, and oxc's
    /// recursive-descent parser has no depth guard — so hostile nesting could
    /// stack-overflow the parser (an uncatchable SIGABRT) before any of the
    /// visitor's own [`MAX_AST_VISIT_DEPTH`] guards run. Three layers prevent
    /// that, in order of cost:
    ///
    /// 1. **Length cap** ([`MAX_ANALYZE_SOURCE_BYTES`]): every nesting level
    ///    costs ≥1 source byte, so bounding length bounds the achievable parser
    ///    depth. Oversized blocks skip analysis (best-effort).
    /// 2. **Pre-parse scan** ([`source_nesting_exceeds_limit`]): rejects the
    ///    1-byte-per-level vectors (`((((…`, `!!!!…`) that would otherwise blow
    ///    the budget the length cap alone allows.
    /// 3. **Large parse stack** ([`ANALYZE_STACK_BYTES`]): the surviving
    ///    multi-byte chains (`if(a)if(b)…`, `x=y=z=…`) still recurse in the
    ///    parser, so the parse + walk run on a dedicated big-stack thread sized
    ///    to absorb the depth the length cap permits.
    pub fn analyze(&self, source_code: &str) -> Result<Vec<DomXssVulnerability>, String> {
        if source_code.len() > MAX_ANALYZE_SOURCE_BYTES || source_nesting_exceeds_limit(source_code)
        {
            if crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!(
                    "[ast] skipping DOM-XSS analysis of a {}-byte script (over length cap {} or nesting guard)",
                    source_code.len(),
                    MAX_ANALYZE_SOURCE_BYTES
                );
            }
            return Ok(Vec::new());
        }

        let script_element_ids = self.script_element_ids.clone();
        let trusted_types_enforced = self.trusted_types_enforced;

        // Fast path: a script this small can't nest a parser-recursion vector
        // deep enough to overflow a normal worker stack (see [`INLINE_PARSE_BYTES`]),
        // so parse it inline and skip the thread-spawn cost the common small
        // inline `<script>` block would otherwise pay on every call.
        if source_code.len() <= INLINE_PARSE_BYTES {
            return Self::analyze_on_stack(source_code, script_element_ids, trusted_types_enforced);
        }

        // Larger input may carry a deep multi-byte statement/assignment chain
        // (`if(a)if(b)…`, `x=y=z=…`) the parser would overflow on a normal stack,
        // so run the parse + walk on a thread with a large (mostly-virtual,
        // lazily-committed) stack. `scope` keeps it synchronous and lets the
        // closure borrow `source_code`.
        std::thread::scope(|scope| {
            let handle = std::thread::Builder::new()
                .stack_size(ANALYZE_STACK_BYTES)
                .spawn_scoped(scope, move || {
                    Self::analyze_on_stack(source_code, script_element_ids, trusted_types_enforced)
                });
            match handle {
                // A panic inside the parse/walk (not a stack overflow, which
                // would abort the process) degrades to "no findings" rather than
                // taking down the scan.
                Ok(h) => h.join().unwrap_or_else(|_| Ok(Vec::new())),
                // Thread spawn failed (e.g. resource limits). We must NOT parse
                // inline: an input that passed the guards (e.g. a ~512 KiB
                // statement chain) can need tens of MiB of stack and would
                // overflow the caller's worker stack. Skip analysis instead —
                // best-effort, and spawn failure is rare.
                Err(_) => Ok(Vec::new()),
            }
        })
    }

    /// Parse `source_code` and run the DOM-XSS walk, returning the findings.
    /// Factored out of [`analyze`] so it can run on a dedicated large-stack
    /// thread.
    fn analyze_on_stack(
        source_code: &str,
        script_element_ids: HashSet<String>,
        trusted_types_enforced: bool,
    ) -> Result<Vec<DomXssVulnerability>, String> {
        let allocator = Allocator::default();
        let source_type = SourceType::default();

        let ret = Parser::new(&allocator, source_code, source_type).parse();

        if !ret.errors.is_empty() {
            let error_messages: Vec<String> = ret.errors.iter().map(ToString::to_string).collect();
            return Err(format!("Parse errors: {}", error_messages.join(", ")));
        }

        let mut visitor = DomXssVisitor::new(source_code)
            .with_script_element_ids(script_element_ids)
            .with_trusted_types_enforced(trusted_types_enforced);
        visitor.walk_statements(&ret.program.body);

        Ok(visitor.vulnerabilities)
    }
}

#[cfg(test)]
mod tests;
