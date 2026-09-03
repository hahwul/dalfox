//! AST-based DOM XSS detection
//!
//! This module provides JavaScript AST parsing and taint analysis to detect
//! potential DOM-based XSS vulnerabilities by tracking data flow from untrusted
//! sources to dangerous sinks.
//!
//! This file holds what the whole analysis shares — the parse guards, the
//! source/sink/sanitizer catalogs, every type definition, and the public
//! [`AstDomAnalyzer`] entry point. `DomXssVisitor`'s ~110 methods are split
//! across the sibling modules below by the question each answers, one
//! `impl DomXssVisitor` block per file:
//!
//! - `sources` — which DOM source is behind this expression
//! - `resolve` — what literal string does this expression denote
//! - `script_element` — is this a `<script>` element the page built
//! - `taint` — is this expression attacker-controlled, and reporting
//! - `trusted_types` — does a Trusted Types policy make a sink inert
//! - `async_flow` — taint through `fetch`, `await`, and promise chains
//! - `bound_calls` — `bind` / `call` / `apply` / `Reflect` argument re-indexing
//! - `summaries` — which parameter of a helper reaches which sink
//! - `bindings` — what a `let`/`const` name now stands for
//! - `walk` — the traversal that reaches all of the above
//! - `events` — handler parameters as entry points
//! - `sinks` — where a tainted value finally lands
//!
//! Their methods are `pub(super)` only so the sibling modules can reach them;
//! nothing here is part of the crate's API beyond [`AstDomAnalyzer`].

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::LazyLock;

mod async_flow;
mod bindings;
mod bound_calls;
mod events;
mod resolve;
mod script_element;
mod sinks;
mod sources;
mod summaries;
mod taint;
mod trusted_types;
mod walk;

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

/// True when `source` must NOT be handed to oxc's `Parser::parse` on a normal
/// worker stack — either it exceeds [`MAX_ANALYZE_SOURCE_BYTES`] or its
/// structural nesting could overflow the recursive-descent parser (see
/// [`source_nesting_exceeds_limit`]). Shared by every oxc parse site so a
/// hostile `<script>` body can't SIGABRT the process from one of them.
pub(crate) fn source_exceeds_parse_guards(source: &str) -> bool {
    source.len() > MAX_ANALYZE_SOURCE_BYTES || source_nesting_exceeds_limit(source)
}

/// Inputs at or below this size parse safely on a normal worker stack (see
/// [`INLINE_PARSE_BYTES`]); larger inputs that pass [`source_exceeds_parse_guards`]
/// should run through [`run_parse_on_large_stack`].
pub(crate) const SAFE_INLINE_PARSE_BYTES: usize = INLINE_PARSE_BYTES;

/// Run `f` (an oxc parse + collect) on a dedicated thread with a large,
/// mostly-virtual stack ([`ANALYZE_STACK_BYTES`]) so a deep — but
/// guard-approved — statement/assignment chain can't overflow the caller's
/// worker stack. Returns `None` if the thread can't be spawned (rare; the
/// caller treats that as "skip / inert", never parsing inline, since such an
/// input could need tens of MiB of stack). `f` must return an owned value.
pub(crate) fn run_parse_on_large_stack<T, F>(f: F) -> Option<T>
where
    T: Send,
    F: FnOnce() -> T + Send,
{
    std::thread::scope(|scope| {
        match std::thread::Builder::new()
            .stack_size(ANALYZE_STACK_BYTES)
            .spawn_scoped(scope, f)
        {
            // A panic inside the parse degrades to None rather than aborting.
            Ok(h) => h.join().ok(),
            Err(_) => None,
        }
    })
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
    /// True when the sink was reached from inside a conditional / loop / try
    /// body — the flow exists but is not taken unconditionally. A confidence
    /// signal only; it never suppresses the finding.
    pub guarded: bool,
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
    /// `"Class.field" -> constructor parameter index`, for fields a class
    /// constructor stores straight from one of its parameters
    /// (`constructor(v) { this._value = v; }`). Together with
    /// [`class_getter_fields`] this is what connects `new C(tainted).accessor`
    /// back to the argument, since the accessor read is a function call that
    /// never mentions the constructor argument.
    ///
    /// Only a *bare parameter* right-hand side is recorded: a constructor that
    /// stores `escapeHtml(v)` has no entry, so the accessor reads clean.
    ///
    /// [`class_getter_fields`]: DomXssVisitor::class_getter_fields
    class_ctor_param_fields: HashMap<String, usize>,
    /// `"Class.getter" -> field name` for `get x() { return this.field; }`
    /// accessors — the indirection between the property the sink reads and the
    /// field the constructor wrote.
    class_getter_fields: HashMap<String, String>,
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
    /// `--custom-property -> source` for CSS custom properties the page wrote a
    /// tainted value into (`el.style.setProperty('--label', tainted)`). A
    /// custom property round-trips through the CSSOM verbatim, so reading it
    /// back with `getPropertyValue('--label')` returns the attacker's string —
    /// a laundering step that hides the flow from a source/sink pairing.
    ///
    /// Keyed by the property name, and only ever populated from a tainted
    /// write, so reading a custom property the page never fed untrusted data
    /// into stays clean. Standard CSS properties are deliberately excluded:
    /// the CSSOM normalizes those, so what comes back is not the input.
    css_custom_property_sources: HashMap<String, String>,
    /// Variables bound to an IndexedDB *value* request — the object an
    /// `objectStore(...).get(...)` / `.getAll()` / `.openCursor()` call
    /// returns. Its `onsuccess` handler receives the stored record, which is
    /// same-origin persisted data in exactly the trust class `localStorage` /
    /// `sessionStorage` already sit in: whatever wrote it (an earlier visit, a
    /// seeded parameter, another page on the origin) is not this page's
    /// literal text. The database handle from `indexedDB.open(...)` is
    /// deliberately *not* in here — its `result` is a connection, not data.
    idb_request_vars: HashSet<String>,
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
    // Drag-and-drop `drop` handlers: `dataTransfer.getData(type)` returns the
    // dragged payload, which the attacker controls end-to-end when the drag
    // originates from a page they control (the classic drag-and-drop XSS: a
    // crafted `text/html` flavour dropped into a widget that innerHTMLs it).
    // Exactly the same trust model as the sibling `clipboardData.getData`
    // reads above. The bare `dataTransfer` object is not listed: `.types` /
    // `.files` / `.effectAllowed` are metadata, not attacker string content.
    "event.dataTransfer.getData",
    "e.dataTransfer.getData",
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
    // `window.open(url, …)` navigates the opened window to `url`; a
    // `javascript:` / `data:text/html` scheme there executes script, exactly
    // like the sibling `location.assign` / `location.replace` navigation
    // sinks. Only the argument-0 URL position is dangerous (see the
    // `first_arg_only` gate), so a tainted window-name / features argument is
    // not treated as a sink. `self` / `globalThis` are the standard global
    // aliases for `window`. Bare `open(...)` is intentionally excluded — it
    // collides with `xhr.open` / `indexedDB.open` / `caches.open`, which are
    // not navigation sinks.
    "window.open",
    "self.open",
    "globalThis.open",
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
    // Namespaced sibling of `setAttribute`. Same danger, different arity:
    // `setAttributeNS(ns, name, value)` puts the attribute name at index 1 and
    // the value at index 2, so it gets its own arity-aware branch below.
    "setAttributeNS",
    // `new DOMParser().parseFromString(html, 'text/html')` parses attacker HTML
    // into a document with no browsing context. Nothing executes *there*, but
    // the resulting nodes are routinely moved into the live document with
    // `adoptNode` / `importNode` / `appendChild`, at which point they do — the
    // same "inert until inserted" shape as the `createContextualFragment` sink
    // already modeled. Gated on an HTML-ish MIME type below.
    "parseFromString",
    "execCommand",
    // Modern Sanitizer-API methods. `setHTML` accepts a Sanitizer config and
    // strips known XSS vectors, so on its own it is not an exploitable sink —
    // we leave it out. `setHTMLUnsafe` is explicitly the opt-out path that
    // parses the argument as HTML with no sanitization, which is exactly the
    // shape of an exploitable injection.
    "setHTMLUnsafe",
    // `Document.parseHTMLUnsafe(html)` is the parse-to-live-DOM analog of
    // `setHTMLUnsafe` / `createContextualFragment`: it parses the string into
    // a detached `Document` with no sanitizer, whose nodes are then adopted
    // into the page. Matched as a bare method name so both the static
    // `Document.parseHTMLUnsafe(...)` form and a bare `parseHTMLUnsafe(...)`
    // are caught. The safe sibling `Document.parseHTML(...)` runs the built-in
    // Sanitizer and is deliberately not modeled.
    "parseHTMLUnsafe",
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
            class_ctor_param_fields: HashMap::new(),
            class_getter_fields: HashMap::new(),
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
            css_custom_property_sources: HashMap::new(),
            idb_request_vars: HashSet::new(),
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
    pub(crate) fn with_script_element_ids(mut self, ids: HashSet<String>) -> Self {
        self.script_element_ids = ids;
        self
    }

    /// Mark that the response CSP enforces `require-trusted-types-for 'script'`,
    /// so a strict `'default'` Trusted Types policy in the page neutralizes
    /// TrustedHTML sinks and those (now false-positive) findings are suppressed.
    pub(crate) fn with_trusted_types_enforced(mut self, enforced: bool) -> Self {
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
