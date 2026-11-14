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
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;
use std::sync::{Arc, LazyLock};

pub use reflected_markup::PageMarkup;
pub(crate) use resolve::{attribute_sink_target, is_navigation_sink};
use scoped_state::{ScopedMap, ScopedSet};
use url_lead::UrlLead;

mod async_flow;
mod bindings;
mod bound_calls;
mod events;
mod guards;
mod reflected_markup;
mod resolve;
mod scoped_state;
mod script_element;
mod sinks;
mod sources;
mod summaries;
mod taint;
mod trusted_types;
mod url_lead;
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

/// Total analysis steps (entries into [`DomXssVisitor::enter_recursion`]) one
/// [`AstDomAnalyzer::analyze`] call may take before the walk stops and returns
/// the findings gathered so far. The depth cap bounds the stack, not the time:
/// the walk re-visits function bodies (once per summarized parameter, once per
/// callback scope), so a hostile script can still multiply work without ever
/// nesting deeply. Measured on real bundles: vue.global.js (525 KB) takes
/// ~350k steps, katex/vueuse/the vue-eslint-parser bundle ~170–205k, and a
/// 1.2 MB Vue app bundle (over the length cap, so never analyzed) ~520k. This
/// sits ~30x above the largest of those while capping a pathological block
/// at a few seconds.
const MAX_AST_WORK_STEPS: u64 = 10_000_000;

/// Upper bound on the size of a single JavaScript block handed to [`analyze`].
/// oxc's recursive-descent parser has no depth guard, and every nesting level
/// consumes at least one source byte, so capping the input length bounds the
/// achievable parser depth; the parse stack grows with the length (see
/// [`STACK_BYTES_PER_SOURCE_BYTE`]), so the parser can't overflow. Scripts
/// larger than this skip AST analysis (best-effort).
const MAX_ANALYZE_SOURCE_BYTES: usize = 512 * 1024;

/// Smallest stack for the dedicated thread that runs the parse + walk. The
/// *walk* is bounded to [`MAX_AST_VISIT_DEPTH`] frames by the shared
/// recursion guard; this floor holds those frames on any build.
const ANALYZE_STACK_BYTES: usize = 256 * 1024 * 1024;

/// Parse stack per source byte, so the parser cannot overflow whatever the
/// pre-parse scan misses. oxc's deepest frame per byte of input (release
/// build, oxc 0.133) is ~1,840 bytes, for a bare `((((…`; the densest input
/// that gets past [`source_nesting_exceeds_limit`] measured ~921 (openers
/// whose closers sit in a string the scan does not skip), and its runs reset
/// on bytes it does not classify (`/**/`, U+00A0, `\x0b`), which keeps a
/// `+-+-…` or `a:a:…` chain at ~576. 2,048 holds every shape the scan lets
/// through with ~2.2× headroom (1 GiB at [`MAX_ANALYZE_SOURCE_BYTES`]), and
/// the bare `((((…` with only ~1.1×, so keep the scan: it is what rejects
/// the single-byte openers, and on a debug build (bare `(` ~3,600 bytes per
/// level) the only thing that does. The reservation is virtual; a shallow
/// script touches a few KB of it, a hostile one commits what it recurses
/// into (~500 MiB at the cap, see [`PARSE_BUDGET_BYTES`]).
const STACK_BYTES_PER_SOURCE_BYTE: usize = 2048;

/// The stack [`guarded_parse`] gives a `len`-byte script.
fn analyze_stack_bytes(len: usize) -> usize {
    ANALYZE_STACK_BYTES.max(len.saturating_mul(STACK_BYTES_PER_SOURCE_BYTE))
}

/// Below this size [`analyze`] parses inline instead of spawning a
/// big-stack thread: at most this many parser levels at ~1,840 bytes each
/// (~470 KB), well within a worker thread's 2 MiB even on a debug build, and
/// the visitor walk is depth-capped to [`MAX_AST_VISIT_DEPTH`] regardless.
/// Short inline `<script>` blocks skip the thread-spawn cost; larger blocks
/// pay for the stack they might need.
const INLINE_PARSE_BYTES: usize = 256;

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
/// recursive-descent parser. Scans once, counting three independent things
/// that each drive parser recursion:
///
/// * bracket nesting depth — `(`/`[`/`{` raise it, `)`/`]`/`}` lower it;
/// * the length of a run of consecutive prefix-unary operators — the single
///   chars `!`/`~`/`+`/`-` and the word operators `typeof`/`void`/`delete`/
///   `new`/`await`/`yield`, each of which the parser descends into
///   recursively;
/// * the length of a run of statement labels (`a:b:c:…`), each labelling
///   the next.
///
/// The scan is *not* string/comment aware, so it is a heuristic: closers in a
/// string lower the count while the parser keeps nesting, and a byte the scan
/// does not classify (`/**/`, U+00A0) resets a run the parser continues. The
/// length-scaled stack ([`analyze_stack_bytes`]) is what keeps those from
/// overflowing; this scan keeps the plain shapes from committing that stack. A comment or string holding a 200+ character run of `-`
/// or `+` is skipped the same way. Returns `true` when any measure exceeds
/// [`MAX_SOURCE_NESTING_DEPTH`].
fn source_nesting_exceeds_limit(source: &str) -> bool {
    const PREFIX_KEYWORDS: [&str; 6] = ["typeof", "void", "delete", "new", "await", "yield"];

    let bytes = source.as_bytes();
    let mut bracket_depth: usize = 0;
    let mut unary_run: usize = 0;
    let mut label_run: usize = 0;
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
                label_run = 0;
                i += 1;
            }
            b')' | b']' | b'}' => {
                bracket_depth = bracket_depth.saturating_sub(1);
                unary_run = 0;
                label_run = 0;
                i += 1;
            }
            // `+`/`-` too: `+-+-…x` and `++++…x` nest one level per byte,
            // and a run broken by `!` (`+!+!…`) must still count as one.
            b'!' | b'~' | b'+' | b'-' => {
                unary_run += 1;
                label_run = 0;
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
                // `a:a:a:…` labels a statement with a labelled statement,
                // two bytes per (large) parser frame.
                let mut j = i;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if bytes.get(j) == Some(&b':') {
                    label_run += 1;
                    unary_run = 0;
                    if label_run > MAX_SOURCE_NESTING_DEPTH {
                        return true;
                    }
                    i = j + 1;
                    continue;
                }
                label_run = 0;
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
                label_run = 0;
                i += 1;
            }
        }
    }
    false
}

/// Run `parse` (an oxc parse + walk of `source`, which comes from the scanned,
/// attacker-controlled page) without letting hostile input stack-overflow the
/// process. oxc's recursive-descent parser has no depth guard, so this is the
/// single entry point every oxc parse site must go through. Three layers, in
/// order of cost:
///
/// 1. **Length cap** ([`MAX_ANALYZE_SOURCE_BYTES`]): every nesting level
///    costs ≥1 source byte, so bounding length bounds the achievable parser
///    depth. Oversized blocks are skipped (best-effort).
/// 2. **Pre-parse scan** ([`source_nesting_exceeds_limit`]): skips the plain
///    deep shapes (`((((…`, `!!!!…`, `a:a:…`) before they commit hundreds of
///    MiB of stack. A heuristic that the bypasses below get past.
/// 3. **Length-scaled parse stack** ([`analyze_stack_bytes`]): the bound for
///    what gets past the scan.
///    Input above [`INLINE_PARSE_BYTES`] runs `parse` on a dedicated thread
///    whose stack holds the deepest parse that many bytes can drive.
///    `scope` keeps it synchronous and lets the closure borrow.
///
/// Returns `None` when the input was skipped, the thread could not be spawned,
/// or `parse` panicked. A spawn failure must NOT fall back to an inline parse:
/// a ~512 KiB script can need up to ~1 GiB of stack.
pub(crate) fn guarded_parse<T: Send>(source: &str, parse: impl FnOnce() -> T + Send) -> Option<T> {
    if let Some(reason) = parse_skip_reason(source) {
        crate::dbg_log!(
            "[ast] skipping parse of a {}-byte script ({})",
            source.len(),
            reason.as_str()
        );
        return None;
    }
    // Fast path: the common small inline `<script>` skips the thread spawn.
    if source.len() <= INLINE_PARSE_BYTES {
        return Some(parse());
    }
    let _budget = ParseBudget::acquire(source.len());
    std::thread::scope(|scope| {
        match std::thread::Builder::new()
            .stack_size(analyze_stack_bytes(source.len()))
            .spawn_scoped(scope, || {
                IN_GUARDED_PARSE.set(true);
                parse()
            }) {
            // A panic inside the parse (not a stack overflow, which would abort
            // the process) degrades to None rather than taking down the scan.
            Ok(h) => h.join().ok(),
            Err(_) => None,
        }
    })
}

/// Source bytes allowed in big-stack parses at once. A hostile script can
/// commit ~921 stack bytes per source byte (see
/// [`STACK_BYTES_PER_SOURCE_BYTE`]), so this caps what concurrent parses can
/// commit together at ~1 GiB: without it, 20 parameters reflecting the same
/// 512 KiB page took the scan to 7 GB RSS. A script larger than the budget
/// still runs, alone.
const PARSE_BUDGET_BYTES: usize = 1024 * 1024;

static PARSE_BUDGET: (std::sync::Mutex<usize>, std::sync::Condvar) =
    (std::sync::Mutex::new(0), std::sync::Condvar::new());

thread_local! {
    /// Set on a [`guarded_parse`] thread, so a parse nested inside one does
    /// not wait for budget its parent holds.
    static IN_GUARDED_PARSE: Cell<bool> = const { Cell::new(false) };
}

/// A share of [`PARSE_BUDGET_BYTES`], held for one big-stack parse.
struct ParseBudget(usize);

impl ParseBudget {
    fn acquire(len: usize) -> Self {
        if IN_GUARDED_PARSE.get() {
            return Self(0);
        }
        let want = len.min(PARSE_BUDGET_BYTES);
        let (lock, freed) = &PARSE_BUDGET;
        let mut in_use = lock.lock().unwrap_or_else(|e| e.into_inner());
        while *in_use + want > PARSE_BUDGET_BYTES {
            in_use = freed.wait(in_use).unwrap_or_else(|e| e.into_inner());
        }
        *in_use += want;
        Self(want)
    }
}

impl Drop for ParseBudget {
    fn drop(&mut self) {
        if self.0 == 0 {
            return;
        }
        let (lock, freed) = &PARSE_BUDGET;
        let mut in_use = lock.lock().unwrap_or_else(|e| e.into_inner());
        *in_use -= self.0;
        freed.notify_all();
    }
}

/// Why [`guarded_parse`] refuses a script without parsing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParseSkipReason {
    /// Longer than [`MAX_ANALYZE_SOURCE_BYTES`].
    Size,
    /// Nested past what the pre-parse guard lets the parser recurse into.
    Nesting,
}

impl ParseSkipReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Size => "size",
            Self::Nesting => "nesting",
        }
    }
}

/// The reason [`guarded_parse`] (and so [`AstDomAnalyzer::analyze`]) would
/// skip `source`, so a caller can report a script it never read instead of
/// taking the empty result for a clean one.
pub(crate) fn parse_skip_reason(source: &str) -> Option<ParseSkipReason> {
    if source.len() > MAX_ANALYZE_SOURCE_BYTES {
        Some(ParseSkipReason::Size)
    } else if source_nesting_exceeds_limit(source) {
        Some(ParseSkipReason::Nesting)
    } else {
        None
    }
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
    /// True when the sink was reached from inside a conditional / loop / try
    /// body — the flow exists but is not taken unconditionally. A confidence
    /// signal only; it never suppresses the finding.
    pub guarded: bool,
}

/// Lightweight summary for a function declaration.
/// Maps parameter index to a sink reached when that parameter is tainted.
#[derive(Default)]
struct FunctionSummary {
    tainted_param_sinks: BTreeMap<usize, String>,
    /// For a parameter whose sink above is a navigation: the sink an
    /// argument that cannot start with a script scheme (see `url_lead`)
    /// still reaches — the body cut its head off, or wrote it to
    /// `innerHTML` as well. No entry when there is none.
    pinned_param_sinks: BTreeMap<usize, String>,
    tainted_param_returns: BTreeMap<usize, String>,
    /// Parameters whose default value is tainted: a call that leaves the
    /// argument out passes the default's source.
    tainted_param_defaults: BTreeMap<usize, String>,
    /// The summarised function's parameter list, telling a second function
    /// registered under the same name apart from this one.
    params_span: oxc_span::Span,
    /// Outer field paths (`cfg.html`) and globals the body writes a tainted
    /// parameter into, applied at a call site that passes a tainted argument.
    tainted_param_writes: BTreeMap<usize, (Vec<String>, Vec<String>)>,
    /// The sink parameter 0 reaches when it is a `message` event whose
    /// origin the body checks — `Some(None)` when the check covers every
    /// sink. `None` when the body never mentions an origin.
    message_param_sink: Option<Option<String>>,
    /// Outer values that origin check compared against (`e.origin !==
    /// allowed`). The summary pass cannot know whether they are tainted;
    /// the place the handler is registered can.
    origin_guard_deps: Vec<String>,
    return_without_tainted_params: Option<String>,
}

impl FunctionSummary {
    /// The sink this function reaches as the handler of an event whose
    /// parameter is tainted; `window_message` for a `window` message event,
    /// the one kind whose `origin` a handler can check.
    fn handler_sink(&self, window_message: bool) -> Option<String> {
        match &self.message_param_sink {
            Some(guarded) if window_message => guarded.clone(),
            _ => self.tainted_param_sinks.get(&0).cloned(),
        }
    }
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
    tainted_vars: ScopedSet<String>,
    /// Names in `tainted_vars` only because a field of theirs was assigned a
    /// tainted value (`o.html = location.hash`): `o` flows on whole, but a
    /// read of another of its fields is clean. Cleared by any other taint.
    /// Deliberately not rolled back with nested bodies: a whole reassignment
    /// inside one (`cfg = JSON.parse(…)`) outlives it, and a stale mark on a
    /// name that is not tainted reads nothing. Only summary passes, which
    /// are hypothetical, swap it out.
    field_only_taint: HashSet<String>,
    /// Map of variable aliases (e.g., var x = location.search)
    var_aliases: ScopedMap<String, String>,
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
    /// Parameters of the function whose parameter-free summary pass is
    /// running. `function onMessage(event) { sink(event.data) }` reads its
    /// *parameter* there, so that pass must not see the name-based
    /// `event.data` source and take the flow away from parameter 0.
    plain_params: HashSet<String>,
    /// Parameters of the function bodies being walked. A call to one
    /// (`function (t) { t(x) }`) is a call to whatever the caller passed, not
    /// to the function a summary happens to be registered for under the same
    /// name — summaries are keyed by bare name, and minified code reuses
    /// `e`/`t`/`n` in every scope. A body's own declarations take the name back.
    shadow_params: ScopedSet<String>,
    /// Parameter lists (by span) of functions whose calls this analysis sees
    /// with their arguments — summarised functions and IIFEs — so their
    /// defaults apply per call, not to every walk of the body.
    arity_known: HashSet<oxc_span::Span>,
    /// Numeric built-ins (see [`NUMERIC_COERCIONS`]) the page overrides by
    /// assignment — `window.parseInt = …`, `Number.parseInt = …`,
    /// `parseInt = …` — so the name no longer coerces to a number.
    overridden_coercions: HashSet<String>,
    /// Track `instanceVar -> ClassName` for class instance method summary resolution.
    instance_classes: ScopedMap<String, String>,
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
    bound_function_aliases: ScopedMap<String, BoundCallableAlias>,
    /// Internal flag for summary collection of tainted return values
    collecting_tainted_returns: bool,
    /// Internal buffer for tainted return sources while collecting summaries
    tainted_return_sources: Vec<String>,
    /// Source code for line/column calculation
    source_code: &'a str,
    /// Built-in method names the script defines itself (see
    /// [`taint::page_defined_methods`]), which #1663's inert-result rule skips.
    page_defined_methods: HashSet<&'static str>,
    /// Precomputed byte offsets of line starts for O(log n) span → line/column lookup
    line_starts: Vec<usize>,
    /// Field-level taint tracking: "obj.field" -> source
    field_taints: ScopedMap<String, String>,
    /// Top-level global variable taint tracking
    global_taints: ScopedSet<String>,
    /// Track `urlVar -> base source` for `new URL(tainted)` instances.
    url_object_sources: HashMap<String, String>,
    /// Names the function body being walked binds itself (parameters and
    /// top-level declarations), so a local `location` is not mistaken for the
    /// global `Location` object.
    local_names: ScopedSet<String>,
    /// The `this` that `this.*` paths currently resolve against, and how many
    /// have been handed out — see `with_own_this`.
    this_scope: usize,
    this_scopes: usize,
    /// The `this` of each named constructor function, shared by its body and
    /// the methods assigned to its `prototype`.
    named_this: HashMap<String, usize>,
    /// An object literal's methods are being walked once just to learn which
    /// `this.*` fields they taint; nested literals skip their own such pass.
    in_field_prepass: bool,
    /// Variables bound to `new URL(location)` / `new URL(document.URL)` — a
    /// copy of the page's own URL, whose scheme and host the attacker cannot
    /// pick (unlike `new URL(location.hash.slice(1))`). Scoped like
    /// `tainted_vars`, and any rebinding of the name drops it, since the
    /// entry *pins* a sink: a stale one would hide a real flow.
    page_url_objects: ScopedSet<String>,
    /// What each variable's value starts with, for navigation sinks, and
    /// whether the variable was tainted when that was recorded — see
    /// [`url_lead`]. Like `page_url_objects` an entry pins a sink.
    url_leads: ScopedMap<String, (UrlLead, bool)>,
    /// Names whose `url_leads` entry was rewritten since the enclosing
    /// function body began (see `url_leads_exit`).
    url_lead_kills: Vec<String>,
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
    css_custom_property_sources: ScopedMap<String, String>,
    /// Variables bound to an IndexedDB object store or index
    /// (`tx.objectStore('notes')`). Real code names the store before reading
    /// from it, so without this only the fully-chained
    /// `…objectStore(…).get(k)` spelling would resolve.
    idb_object_store_vars: ScopedSet<String>,
    /// Variables bound to an IndexedDB *value* request — the object an
    /// `objectStore(...).get(...)` / `.getAll()` / `.openCursor()` call
    /// returns. Its `onsuccess` handler receives the stored record, which is
    /// same-origin persisted data in exactly the trust class `localStorage` /
    /// `sessionStorage` already sit in: whatever wrote it (an earlier visit, a
    /// seeded parameter, another page on the origin) is not this page's
    /// literal text. The database handle from `indexedDB.open(...)` is
    /// deliberately *not* in here — its `result` is a connection, not data.
    idb_request_vars: ScopedSet<String>,
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
    script_element_ids: Arc<HashSet<String>>,
    /// Page slots that carry this scan's marker (see [`PageMarkup`]).
    reflected_markup: Arc<PageMarkup>,
    /// Variables bound to an element in [`Self::reflected_markup`], by `id`.
    reflected_element_vars: HashMap<String, String>,
    /// Variables bound to a `<form>` element (see `expr_resolves_to_form`).
    form_element_vars: HashSet<String>,
    /// Variables bound to an element of a known tag (`createElement('img')`,
    /// `new Image()`, `querySelector('iframe')`), lowercased. What `src` /
    /// `href` do depends on it: an image's `src` loads a picture, a
    /// `<link>`'s `href` a stylesheet, and neither runs script.
    element_tag_vars: ScopedMap<String, String>,
    /// Callback parameters currently bound to a `fetch()` `Response`
    /// object — the first `.then(resp => …)` of a fetch chain. While such
    /// a parameter is in scope, `resp.text()` / `resp.json()` read the
    /// network response body, which is an untrusted DOM-XSS source. The
    /// set is pushed/popped as the promise-chain driver enters and leaves
    /// each callback so the binding never leaks past its callback.
    response_object_vars: ScopedSet<String>,
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
    /// The kind of sink the expression being evaluated lands in.
    sink_ctx: Cell<SinkCtx>,
    /// Steps taken so far by this walk, against [`work_budget`].
    /// Counted in [`DomXssVisitor::enter_recursion`], so once the budget is
    /// spent every recursive analysis fn bails with the same safe default the
    /// depth guard uses and the walk unwinds with what it already found.
    ///
    /// [`work_budget`]: DomXssVisitor::work_budget
    work_steps: Cell<u64>,
    /// Step budget for this walk — [`MAX_AST_WORK_STEPS`] outside tests.
    work_budget: u64,
    /// Variables bound to a global object — `var d = document, w = window,
    /// l = location` — mapped to its canonical name, so `d.write(l.hash)`
    /// reads as `document.write(location.hash)`.
    global_aliases: ScopedMap<String, &'static str>,
    /// Aliases for the parameters of the IIFE about to be walked
    /// (`(function (w, d) { … })(window, document)`).
    pending_param_aliases: Vec<(String, &'static str)>,
    /// Parameters of the IIFE about to be walked that are handed the outer
    /// binding of the same name — `(function (App) { … })(App)` — and so do
    /// not shadow it (see `shadow_params`).
    iife_passthrough: Vec<String>,
    /// What the origin checks of the summary pass under way compared
    /// against (see `FunctionSummary::origin_guard_deps`).
    origin_guard_deps: RefCell<Vec<String>>,
    /// `branch_depth` at the start of the function body being walked: a
    /// statement at this depth runs on every path through the body.
    branch_base: u32,
    /// Globals an early-exit guard vouched for until the body ends (see
    /// `guards::untaint_for_rest_of_body`).
    body_guarded_globals: Vec<String>,
    /// `message` handlers being walked: the path of the event's origin
    /// (`e.origin`, or a destructured `origin`) → the names carrying its data.
    message_origins: ScopedMap<String, Vec<String>>,
    /// Event names whose origin a guard checked, switching the name-based
    /// `event.data` source off for them.
    origin_checked: ScopedSet<String>,
    /// Set only while walking the `if` right after `var i = LIST.indexOf(x)`
    /// (see `guards::adjacent_index_result`).
    adjacent_index: Option<(String, guards::GuardTarget)>,
    /// Name of the class whose body is being walked, so `this.onMessage`
    /// resolves to the `Class.onMessage` method summary.
    current_class: Option<String>,
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

/// What a sink does with its value, which decides the sanitizers that help.
/// HTML escaping leaves `javascript:alert(1)` and `alert(1)` untouched, so
/// `location.href = escapeHtml(u)` and `eval(DOMPurify.sanitize(c))` are as
/// exploitable as the bare forms.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SinkCtx {
    /// Parsed as markup: every recognised sanitizer applies.
    Html,
    /// Used as a URL: only a number or `encodeURIComponent` (which encodes
    /// the `:` a scheme needs) is safe.
    Url,
    /// Run as script: only a number is safe.
    Code,
}

impl SinkCtx {
    fn of(sink: &str) -> Self {
        let target = attribute_sink_target(sink);
        if (target != sink && target.starts_with("on"))
            || matches!(
                target,
                "eval"
                    | "Function"
                    | "setTimeout"
                    | "setInterval"
                    | "execScript"
                    | "$.globalEval"
                    | "jQuery.globalEval"
            )
        {
            SinkCtx::Code
        } else if is_navigation_sink(sink)
            || matches!(
                target,
                "src" | "import" | "$.getScript" | "jQuery.getScript"
            )
        {
            SinkCtx::Url
        } else {
            SinkCtx::Html
        }
    }
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
    // `document.location` is the same `Location` object as `window.location`;
    // the second-level alias is enough for `document.location.hash` (see above).
    "document.location",
    "globalThis.location",
    "localStorage",
    "sessionStorage",
    "localStorage.getItem",
    "sessionStorage.getItem",
    // Event properties are sources by name only under the conventional
    // `event` spelling. A bare `e` is whatever a minifier called its first
    // parameter (`success: function (e) { render(e.data) }`), so `e.*` reads
    // count only where the handler's registration is seen
    // (`addEventListener('message', …)`, `onmessage = …`), which taints the
    // parameter itself whatever it is called.
    "event.data",
    "event.newValue",
    "event.oldValue",
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
    "navigator.clipboard.readText",
    // Drag-and-drop `drop` handlers: `dataTransfer.getData(type)` returns the
    // dragged payload, which the attacker controls end-to-end when the drag
    // originates from a page they control (the classic drag-and-drop XSS: a
    // crafted `text/html` flavour dropped into a widget that innerHTMLs it).
    // Exactly the same trust model as the sibling `clipboardData.getData`
    // reads above. The bare `dataTransfer` object is not listed: `.types` /
    // `.files` / `.effectAllowed` are metadata, not attacker string content.
    "event.dataTransfer.getData",
    // Keyboard / composition events – `key` / `code` carry user input
    // verbatim and are the natural source on autocompletion-style handlers.
    "event.key",
    "event.code",
    // `event.target.innerText` / `textContent` / `innerHTML` is the common
    // contenteditable / paste-into-div shape: the user typed it, so the
    // value is tainted at read time.
    "event.target.innerText",
    "event.target.textContent",
    "event.target.innerHTML",
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
    // jQuery's script runners: `globalEval` evaluates its argument, and
    // `getScript` loads and runs the script at the URL it is given.
    "$.globalEval",
    "jQuery.globalEval",
    "$.getScript",
    "jQuery.getScript",
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
    // Numeric coercions (see `NUMERIC_COERCIONS`).
    "parseInt",
    "parseFloat",
    "Number",
    "Number.parseInt",
    "Number.parseFloat",
    "Number.isNaN",
    "Number.isFinite",
    "Number.isInteger",
    "Boolean",
    "isNaN",
    "isFinite",
    "btoa",
];

/// Sanitizer entries that are built-ins whose result cannot carry markup: a
/// number (or NaN), a boolean, or — for `btoa` — base64 text, so
/// `innerHTML = 'Page ' + parseInt(p)` is inert. Unlike an `escapeHtml` helper
/// (whose page-local definition is the normal case), a page declaring its own
/// function under one of these names has shadowed the built-in, so the name
/// stops counting as a sanitizer there.
const NUMERIC_COERCIONS: &[&str] = &[
    "parseInt",
    "parseFloat",
    "Number",
    "Number.parseInt",
    "Number.parseFloat",
    "Number.isNaN",
    "Number.isFinite",
    "Number.isInteger",
    "Boolean",
    "isNaN",
    "isFinite",
    "btoa",
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
            tainted_vars: Default::default(),
            field_only_taint: Default::default(),
            var_aliases: Default::default(),
            vulnerabilities: Vec::new(),
            sources: &*STATIC_SOURCES,
            sinks: &*STATIC_SINKS,
            sanitizers: &*STATIC_SANITIZERS,
            function_summaries: HashMap::new(),
            shadow_params: Default::default(),
            plain_params: HashSet::new(),
            arity_known: HashSet::new(),
            overridden_coercions: HashSet::new(),
            instance_classes: Default::default(),
            class_ctor_param_fields: HashMap::new(),
            class_getter_fields: HashMap::new(),
            bound_function_aliases: Default::default(),
            collecting_tainted_returns: false,
            tainted_return_sources: Vec::new(),
            page_defined_methods: taint::page_defined_methods(source_code),
            source_code,
            line_starts,
            field_taints: Default::default(),
            global_taints: Default::default(),
            url_object_sources: HashMap::new(),
            page_url_objects: Default::default(),
            url_leads: Default::default(),
            url_lead_kills: Vec::new(),
            local_names: Default::default(),
            this_scope: 0,
            this_scopes: 0,
            named_this: HashMap::new(),
            in_field_prepass: false,
            url_search_params_sources: HashMap::new(),
            url_search_params_objects: HashSet::new(),
            url_search_params_field_sources: HashMap::new(),
            css_custom_property_sources: Default::default(),
            idb_object_store_vars: Default::default(),
            idb_request_vars: Default::default(),
            script_element_vars: HashSet::new(),
            script_element_ids: Arc::default(),
            reflected_markup: Arc::default(),
            reflected_element_vars: HashMap::new(),
            form_element_vars: HashSet::new(),
            element_tag_vars: Default::default(),
            response_object_vars: Default::default(),
            branch_depth: 0,
            global_aliases: Default::default(),
            pending_param_aliases: Vec::new(),
            iife_passthrough: Vec::new(),
            origin_guard_deps: RefCell::new(Vec::new()),
            branch_base: 0,
            body_guarded_globals: Vec::new(),
            message_origins: Default::default(),
            origin_checked: Default::default(),
            adjacent_index: None,
            current_class: None,
            recursion_depth: Rc::new(Cell::new(0)),
            sink_ctx: Cell::new(SinkCtx::Html),
            work_steps: Cell::new(0),
            work_budget: MAX_AST_WORK_STEPS,
            trusted_types_enforced: false,
            tt_policies: HashMap::new(),
            default_tt_policy: None,
        }
    }
    /// Evaluate `eval` as the value of `sink`.
    fn for_sink<R>(&self, sink: &str, eval: impl FnOnce(&Self) -> R) -> R {
        let outer = self.sink_ctx.replace(SinkCtx::of(sink));
        let result = eval(self);
        self.sink_ctx.set(outer);
        result
    }
    /// `path` names a DOM source (`location.hash`, `event.data`).
    fn is_source(&self, path: &str) -> bool {
        let root = path.split('.').next().unwrap_or(path);
        self.sources.contains(path)
            && !self.plain_params.contains(root)
            && !self.origin_checked.contains(root)
    }
    /// The summary registered under `key` (`render`, `helper.render`), unless
    /// its root name is a parameter of an enclosing function (see
    /// [`shadow_params`](Self::shadow_params)).
    fn summary(&self, key: &str) -> Option<&FunctionSummary> {
        let root = key.split('.').next().unwrap_or(key);
        if self.shadow_params.contains(root) {
            return None;
        }
        self.function_summaries.get(key)
    }
    /// Enter one recursive analysis step. Returns `None` — telling the caller to
    /// bail with a safe default (`false` / `None` / stop walking) — once the
    /// shared recursion depth has reached [`MAX_AST_VISIT_DEPTH`] or the walk has
    /// spent its [`MAX_AST_WORK_STEPS`] budget; otherwise increments the counter
    /// and hands back a [`RecursionGuard`] that restores it on scope exit. See
    /// [`recursion_depth`](DomXssVisitor::recursion_depth).
    fn enter_recursion(&self) -> Option<RecursionGuard> {
        let depth = self.recursion_depth.get();
        let steps = self.work_steps.get();
        if depth >= MAX_AST_VISIT_DEPTH || steps >= self.work_budget {
            return None;
        }
        self.work_steps.set(steps + 1);
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
    ///
    /// Shared (`Arc`): a page with N scripts builds one analyzer per block, and
    /// cloning the page-wide set per block made that O(N²).
    script_element_ids: Arc<HashSet<String>>,
    /// Slots of the analysed response that carry this scan's marker (see
    /// [`PageMarkup`]). Empty when the caller has no HTML context.
    reflected_markup: Arc<PageMarkup>,
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
    pub(crate) fn with_script_element_ids(mut self, ids: impl Into<Arc<HashSet<String>>>) -> Self {
        self.script_element_ids = ids.into();
        self
    }

    /// Attach the marker-carrying slots of the analysed response so reads of
    /// them (`el.dataset.x`, `getAttribute`, `textContent`, CSS custom
    /// properties) count as sources.
    pub(crate) fn with_reflected_markup(mut self, markup: impl Into<Arc<PageMarkup>>) -> Self {
        self.reflected_markup = markup.into();
        self
    }

    /// Mark that the response CSP enforces `require-trusted-types-for 'script'`,
    /// so a strict `'default'` Trusted Types policy in the page neutralizes
    /// TrustedHTML sinks and those (now false-positive) findings are suppressed.
    pub(crate) fn with_trusted_types_enforced(mut self, enforced: bool) -> Self {
        self.trusted_types_enforced = enforced;
        self
    }

    /// Analyze JavaScript source code for DOM XSS vulnerabilities. The input
    /// comes from the scanned page, so the parse runs behind [`guarded_parse`];
    /// a skipped or failed parse yields no findings.
    pub fn analyze(&self, source_code: &str) -> Result<Vec<DomXssVulnerability>, String> {
        guarded_parse(source_code, || self.analyze_on_stack(source_code))
            .unwrap_or_else(|| Ok(Vec::new()))
    }

    /// Parse `source_code` and run the DOM-XSS walk, returning the findings.
    /// Factored out of [`analyze`] so it can run on a dedicated large-stack
    /// thread.
    fn analyze_on_stack(&self, source_code: &str) -> Result<Vec<DomXssVulnerability>, String> {
        let allocator = Allocator::default();

        // Module first, so `import`/`export`/top-level `await` bundles keep
        // working. Inline `<script>` bodies are classic scripts though, and
        // sloppy-only syntax (`<!--` comments, `await` as an identifier) is a
        // module parse error that would silently drop the whole block, so
        // retry as a script before giving up.
        let mut ret = Parser::new(&allocator, source_code, SourceType::default()).parse();
        if !ret.errors.is_empty() {
            let script = Parser::new(&allocator, source_code, SourceType::script()).parse();
            if script.errors.is_empty() {
                ret = script;
            }
        }

        if !ret.errors.is_empty() {
            let error_messages: Vec<String> = ret.errors.iter().map(ToString::to_string).collect();
            return Err(format!("Parse errors: {}", error_messages.join(", ")));
        }

        let mut visitor = DomXssVisitor {
            script_element_ids: Arc::clone(&self.script_element_ids),
            reflected_markup: Arc::clone(&self.reflected_markup),
            trusted_types_enforced: self.trusted_types_enforced,
            ..DomXssVisitor::new(source_code)
        };
        visitor.walk_statements(&ret.program.body);
        if visitor.work_steps.get() >= visitor.work_budget {
            crate::dbg_log!(
                "[ast] DOM-XSS analysis of a {}-byte script stopped at its {}-step work budget; {} finding(s) kept",
                source_code.len(),
                visitor.work_budget,
                visitor.vulnerabilities.len()
            );
        }

        Ok(visitor.vulnerabilities)
    }
}

#[cfg(test)]
mod tests;
