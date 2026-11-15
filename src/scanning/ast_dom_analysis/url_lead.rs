//! Can the attacker write the *start* of a URL value?
//!
//! A navigation sink (`location.href = v`, `a.href = v`, `window.open(v)`)
//! only runs script when `v` begins with a script scheme, so a tainted value
//! is harmless there unless the attacker controls its first characters.
//! `'/search?q=' + q` cannot; neither can `location.href` (the page's own
//! `http(s):` URL), `location.search` (`?…` or empty) or `base + location.search`.
//!
//! [`DomXssVisitor::url_lead`] reads a value left to right and answers with a
//! [`UrlLead`]. Variables remember theirs (`var u = '/s?q=' + q; location.href = u`),
//! in [`DomXssVisitor::url_leads`] — state that *suppresses* a sink, so it is
//! dropped far more readily than it is recorded: on any rebinding it cannot
//! vouch for, and a write made inside a function body can only ever worsen
//! what the enclosing scope believes (see [`DomXssVisitor::url_leads_exit`]).

use super::*;

/// What the first characters of a URL value can be, best to worst.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(super) enum UrlLead {
    /// Starts with the page's own `http(s):` URL text.
    PageUrl,
    /// Starts with text that fixes a non-script scheme or makes it relative.
    Pinned,
    /// Empty, or text that cannot itself be a script scheme (`?a=b`, `#x`, a
    /// value the page authored). Whatever follows may still lead.
    Passive,
    /// The attacker may write the first characters.
    Open,
}

/// One operand of a string concatenation.
enum UrlPart<'b, 'a> {
    Text(String),
    Expr(&'b Expression<'a>),
}

#[derive(PartialEq, Eq)]
enum PrefixKind {
    /// A non-script scheme is closed (`https:`), or the URL is relative (`/`).
    Pins,
    /// A script scheme is closed (`javascript:`).
    Script,
    /// Empty or all scheme characters (`java`): the next operand continues it.
    Partial,
}

/// Classify the literal text a URL starts with. The URL parser drops
/// tab/CR/LF anywhere and leading C0/space, so those are skipped first; then
/// the first non-scheme character (`/`, `?`, `#`, …) makes it relative, and a
/// `:` closes the scheme.
fn classify_url_prefix(prefix: &str) -> PrefixKind {
    let cleaned: String = prefix
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let s = cleaned.trim_start_matches(|c: char| c <= ' ');
    for (i, c) in s.char_indices() {
        if c == ':' {
            return if matches!(
                s[..i].to_ascii_lowercase().as_str(),
                "javascript" | "data" | "vbscript"
            ) {
                PrefixKind::Script
            } else {
                PrefixKind::Pins
            };
        }
        if !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
            return PrefixKind::Pins;
        }
    }
    PrefixKind::Partial
}

/// A regex that cannot match at index 0 of a string starting with `http`:
/// its first atom is one literal character (or a plain class) other than
/// `h`, taken exactly — no alternation, no optional quantifier.
fn regex_misses_http_start(pattern: &str) -> bool {
    if pattern.contains('|') {
        return false;
    }
    let mut chars = pattern.chars();
    let literal = |c: char| !matches!(c, 'h' | 'H');
    let ok = match chars.next() {
        Some('\\') => chars
            .next()
            .is_some_and(|c| !c.is_ascii_alphanumeric() && literal(c)),
        Some('[') => {
            let body: String = chars.by_ref().take_while(|c| *c != ']').collect();
            !body.is_empty() && !body.starts_with('^') && !body.contains(['\\', '-', 'h', 'H'])
        }
        Some(c) => !"^$.*+?()]{}/".contains(c) && literal(c),
        None => false,
    };
    ok && !chars.next().is_some_and(|c| matches!(c, '?' | '*' | '{'))
}

/// A journal position in [`DomXssVisitor::url_leads`] plus where this scope's
/// entries in the kill list start.
pub(super) struct UrlLeadScope {
    checkpoint: scoped_state::Checkpoint,
    kills_start: usize,
}

impl<'a> DomXssVisitor<'a> {
    /// True when the URL `expr` evaluates to cannot be given a script scheme
    /// by its tainted parts — `'/search?q=' + q`, `location.origin + path`,
    /// `base + location.search`.
    pub(super) fn url_scheme_is_pinned(&self, expr: &Expression<'a>) -> bool {
        self.url_lead(expr) != UrlLead::Open
    }

    /// See the module docs.
    pub(super) fn url_lead(&self, expr: &Expression<'a>) -> UrlLead {
        // What counts as tainted here is what counts in a URL: an HTML
        // escaper does not stop `javascript:` (see `SinkCtx`).
        self.for_sink("href", |v| v.url_lead_in_url_context(expr))
    }

    fn url_lead_in_url_context(&self, expr: &Expression<'a>) -> UrlLead {
        let Some(_guard) = self.enter_recursion() else {
            return UrlLead::Open;
        };
        let mut parts = Vec::new();
        self.concat_parts(expr, &mut parts);
        let mut literal = String::new();
        let mut first = true;
        let mut unknown_prefix = false;
        for part in parts {
            match part {
                UrlPart::Text(text) => {
                    literal.push_str(&text);
                    // A passive operand may be partial scheme text (`java`).
                    // A later colon can finish it; a relative delimiter cannot.
                    if self.collecting_return_url_lead.get()
                        && unknown_prefix
                        && literal
                            .chars()
                            .take_while(|c| {
                                c.is_ascii_alphanumeric()
                                    || matches!(c, '+' | '-' | '.' | ':' | '\t' | '\n' | '\r')
                            })
                            .any(|c| c == ':')
                    {
                        return UrlLead::Open;
                    }
                    match classify_url_prefix(&literal) {
                        PrefixKind::Pins => return UrlLead::Pinned,
                        PrefixKind::Script => return UrlLead::Open,
                        PrefixKind::Partial => {}
                    }
                    first &= literal.is_empty();
                }
                UrlPart::Expr(part) => match self.url_part_lead(part) {
                    UrlLead::Passive => {
                        if self.collecting_return_url_lead.get()
                            && (!literal.is_empty() || unknown_prefix)
                        {
                            return UrlLead::Open;
                        }
                        first = false;
                        unknown_prefix = true;
                    }
                    // After other text it no longer *starts* the value.
                    UrlLead::PageUrl if !first => return UrlLead::Pinned,
                    lead => return lead,
                },
            }
        }
        UrlLead::Passive
    }

    /// Flatten `a + b`, `` `${a}b` `` and `a.concat(b)` into operands.
    fn concat_parts<'b>(&self, expr: &'b Expression<'a>, out: &mut Vec<UrlPart<'b, 'a>>) {
        let Some(_guard) = self.enter_recursion() else {
            out.push(UrlPart::Expr(expr));
            return;
        };
        match expr {
            Expression::ParenthesizedExpression(p) => self.concat_parts(&p.expression, out),
            Expression::StringLiteral(s) => out.push(UrlPart::Text(s.value.to_string())),
            Expression::TemplateLiteral(t) => {
                for (i, quasi) in t.quasis.iter().enumerate() {
                    if let Some(cooked) = &quasi.value.cooked {
                        out.push(UrlPart::Text(cooked.to_string()));
                    }
                    if let Some(e) = t.expressions.get(i) {
                        self.concat_parts(e, out);
                    }
                }
            }
            Expression::BinaryExpression(b) if b.operator == BinaryOperator::Addition => {
                self.concat_parts(&b.left, out);
                self.concat_parts(&b.right, out);
            }
            Expression::CallExpression(call)
                if !self.collecting_return_url_lead.get()
                    && self.get_callee_property_name(&call.callee).as_deref() == Some("concat") =>
            {
                match self.get_callee_object_expr(&call.callee) {
                    Some(receiver) => self.concat_parts(receiver, out),
                    None => return out.push(UrlPart::Expr(expr)),
                }
                for arg in &call.arguments {
                    match arg {
                        Argument::SpreadElement(spread) => {
                            out.push(UrlPart::Expr(&spread.argument))
                        }
                        _ => {
                            if let Some(e) = arg.as_expression() {
                                self.concat_parts(e, out);
                            }
                        }
                    }
                }
            }
            _ => out.push(UrlPart::Expr(expr)),
        }
    }

    /// Lead of one operand that is not itself a concatenation.
    fn url_part_lead(&self, expr: &Expression<'a>) -> UrlLead {
        if self.collecting_return_url_lead.get()
            && self.get_expr_string(expr).is_some_and(|path| {
                let root = path.split('.').next().unwrap_or(&path);
                matches!(
                    root,
                    "window" | "document" | "location" | "self" | "globalThis" | "top" | "parent"
                ) && (self.local_names.contains(root)
                    || self.return_shadowed_globals.contains(root))
            })
        {
            return UrlLead::Open;
        }
        // The page's own URL — `top.location = self.location` frame-busting,
        // or a `new URL(location)` copy with its query rewritten.
        if self.expr_is_location_object(expr) || self.expr_is_page_url_object(expr) {
            return UrlLead::PageUrl;
        }
        match expr {
            Expression::Identifier(id) => return self.identifier_url_lead(id.name.as_str()),
            Expression::ConditionalExpression(c) => {
                return self
                    .url_lead(&c.consequent)
                    .max(self.url_lead(&c.alternate));
            }
            Expression::LogicalExpression(l) => {
                return self.url_lead(&l.left).max(self.url_lead(&l.right));
            }
            // `new URL(path, base)` is never empty, and takes its scheme from
            // an absolute first argument or else from the base. Setting
            // `.search` / `.hash` on it later does not change that.
            Expression::NewExpression(new_expr) if matches!(&new_expr.callee, Expression::Identifier(id) if id.name == "URL") =>
            {
                if self.collecting_return_url_lead.get() {
                    return UrlLead::Open;
                }
                let arg = |i: usize| new_expr.arguments.get(i).and_then(|a| a.as_expression());
                return match (
                    arg(0).map(|a| self.url_lead(a)),
                    arg(1).map(|b| self.url_lead(b)),
                ) {
                    (None | Some(UrlLead::Open), _) | (_, Some(UrlLead::Open)) => UrlLead::Open,
                    (Some(UrlLead::PageUrl), None) => UrlLead::PageUrl,
                    _ => UrlLead::Pinned,
                };
            }
            _ => {}
        }
        // Page-authored text of unknown content: assumed not to spell a
        // script scheme, and possibly empty.
        if !self.collecting_return_url_lead.get() && !self.is_tainted(expr) {
            return UrlLead::Passive;
        }
        match expr {
            Expression::StaticMemberExpression(member) => self.url_member_lead(member),
            // `lead.split(sep)[0]` keeps the leading text.
            Expression::ComputedMemberExpression(member) => {
                if self.collecting_return_url_lead.get() {
                    return UrlLead::Open;
                }
                if matches!(&member.expression, Expression::NumericLiteral(n) if n.value == 0.0)
                    && let Expression::CallExpression(call) = &member.object
                    && self.get_callee_property_name(&call.callee).as_deref() == Some("split")
                    && let Some(receiver) = self.get_callee_object_expr(&call.callee)
                {
                    self.url_lead(receiver).max(UrlLead::Pinned)
                } else {
                    UrlLead::Open
                }
            }
            Expression::CallExpression(call) => self.url_call_lead(call),
            Expression::AwaitExpression(a) => self.url_lead(&a.argument),
            Expression::SequenceExpression(seq) => seq
                .expressions
                .last()
                .map_or(UrlLead::Open, |last| self.url_lead(last)),
            _ => UrlLead::Open,
        }
    }

    /// What the variable `name` starts with: what its last binding recorded,
    /// while that record still describes it.
    pub(super) fn identifier_url_lead(&self, name: &str) -> UrlLead {
        // Ordinary bindings may carry a lead inferred from unknown clean
        // prefixes. Only records built inside this proof can certify a call.
        if self.collecting_return_url_lead.get() && !self.in_return_lead_pass {
            return UrlLead::Open;
        }
        let tainted = self.tainted_vars.contains(name) || self.global_taints.contains(name);
        match self.url_leads.get(name) {
            // A record made while the name was clean says nothing once
            // something else tainted it, and the other way round.
            Some((lead, was_tainted)) if *was_tainted == tainted => *lead,
            _ if tainted || self.collecting_return_url_lead.get() => UrlLead::Open,
            _ => UrlLead::Passive,
        }
    }

    fn url_member_lead(&self, member: &StaticMemberExpression<'a>) -> UrlLead {
        let prop = member.property.name.as_str();
        // `?…` / `#…` or empty, on `Location` and on any `URL` object.
        if matches!(prop, "search" | "hash")
            && (self.expr_is_location_object(&member.object)
                || self.url_object_source_for_expr(&member.object).is_some())
        {
            return UrlLead::Passive;
        }
        // A `URL` object's own start: `u.href`, `u.origin`.
        if matches!(prop, "href" | "origin")
            && let Expression::Identifier(id) = &member.object
            && self.url_leads.contains_key(id.name.as_str())
        {
            return self.identifier_url_lead(id.name.as_str());
        }
        // …read off a `URL` copy of the page's own (`new URL(location.href).pathname`).
        match self.url_object_part_source(member).as_deref() {
            Some("location.href") => return UrlLead::PageUrl,
            Some("location.pathname") => return UrlLead::Pinned,
            _ => {}
        }
        let Some(path) = self.get_member_string(member) else {
            return UrlLead::Open;
        };
        let path = path
            .trim_start_matches("window.")
            .trim_start_matches("self.")
            .trim_start_matches("document.");
        match path {
            "location.href" | "location.origin" | "location.protocol" | "URL" | "documentURI"
            | "baseURI" => UrlLead::PageUrl,
            "location.pathname" | "location.host" => UrlLead::Pinned,
            // The referring page's `http(s):` URL, or empty.
            "referrer" => UrlLead::Passive,
            _ => UrlLead::Open,
        }
    }

    fn url_call_lead(&self, call: &CallExpression<'a>) -> UrlLead {
        // Calls can decode, replace, or supply a different implementation.
        // Prove only the surrounding expression, not another callee's body.
        if self.collecting_return_url_lead.get() {
            return UrlLead::Open;
        }
        if let Some(summary) = self.stable_call_summary(call) {
            let mut lead = summary.return_url_lead.unwrap_or(UrlLead::Open);
            for (idx, pinned_lead) in &summary.pinned_param_return_leads {
                if call
                    .arguments
                    .get(*idx)
                    .and_then(Argument::as_expression)
                    .is_some_and(|arg| {
                        let outer = self.collecting_return_url_lead.replace(true);
                        let pinned = self.url_scheme_is_pinned(arg);
                        self.collecting_return_url_lead.set(outer);
                        pinned
                    })
                {
                    lead = lead.min(*pinned_lead);
                }
            }
            return lead;
        }
        // An ineligible page function is still not the built-in of its name.
        if let Expression::Identifier(id) = &call.callee
            && self.summary(id.name.as_str()).is_some()
        {
            return UrlLead::Open;
        }
        // Legacy direct-expression rules; return proofs above do not rely
        // on decoding preserving a URL's start.
        if let Expression::Identifier(id) = &call.callee
            && matches!(
                id.name.as_str(),
                "decodeURIComponent" | "decodeURI" | "unescape" | "String"
            )
            && let Some(arg) = call.arguments.first().and_then(|a| a.as_expression())
        {
            return self.url_lead(arg);
        }
        let (Some(method), Some(receiver)) = (
            self.get_callee_property_name(&call.callee),
            self.get_callee_object_expr(&call.callee),
        ) else {
            return UrlLead::Open;
        };
        match method.as_str() {
            "toString" | "valueOf" | "trim" | "trimEnd" | "toLowerCase" | "toUpperCase" => {
                self.url_lead(receiver)
            }
            "replace" | "replaceAll" => {
                let lead = self.url_lead(receiver);
                if lead == UrlLead::Open {
                    return lead;
                }
                let arg = |i: usize| call.arguments.get(i).and_then(|a| a.as_expression());
                // `$1` / `$&` splice the matched text back in: not static.
                let replacement = arg(1)
                    .and_then(|r| self.eval_static_string_expr(r))
                    .filter(|text| !text.contains('$'));
                // The result starts the way the receiver did, or with the
                // replacement: `href.replace(/^http:/, 'https:')`.
                if let Some(text) = replacement.as_deref()
                    && classify_url_prefix(text) == PrefixKind::Pins
                {
                    return match lead {
                        UrlLead::PageUrl if !text.starts_with("http") => UrlLead::Pinned,
                        lead => lead,
                    };
                }
                // A match that cannot sit at index 0 leaves the page URL's
                // `h…` in place: `href.replace('lang=en', x)`, `.replace(/#.*/, '')`.
                let misses_start = lead == UrlLead::PageUrl
                    && match arg(0).map(Expression::without_parentheses) {
                        Some(Expression::StringLiteral(s)) => {
                            !s.value.is_empty() && !s.value.starts_with('h')
                        }
                        Some(Expression::RegExpLiteral(re)) => self
                            .regex_literal_parts(re.span)
                            .is_some_and(|(pattern, _)| regex_misses_http_start(pattern)),
                        // `location.hash` may be empty, and an empty pattern
                        // puts the replacement first.
                        Some(Expression::StaticMemberExpression(m)) => {
                            self.url_member_lead(m) == UrlLead::Passive
                                && replacement.as_deref().is_some_and(str::is_empty)
                        }
                        _ => false,
                    };
                if misses_start {
                    UrlLead::PageUrl
                } else {
                    UrlLead::Open
                }
            }
            _ => UrlLead::Open,
        }
    }

    pub(super) fn return_argument_exposes_window(&self, expr: &Expression<'a>) -> bool {
        let Some(_guard) = self.enter_recursion() else {
            return true;
        };
        if self.global_alias_of(expr) == Some("window") {
            return true;
        }
        match expr {
            Expression::ThisExpression(_) => true,
            Expression::ConditionalExpression(c) => {
                self.return_argument_exposes_window(&c.consequent)
                    || self.return_argument_exposes_window(&c.alternate)
            }
            Expression::LogicalExpression(l) => {
                self.return_argument_exposes_window(&l.left)
                    || self.return_argument_exposes_window(&l.right)
            }
            Expression::SequenceExpression(s) => s
                .expressions
                .last()
                .is_some_and(|expr| self.return_argument_exposes_window(expr)),
            Expression::AssignmentExpression(a) => self.return_argument_exposes_window(&a.right),
            Expression::AwaitExpression(a) => self.return_argument_exposes_window(&a.argument),
            Expression::ParenthesizedExpression(p) => {
                self.return_argument_exposes_window(&p.expression)
            }
            Expression::ArrayExpression(array) => {
                array.elements.iter().any(|element| match element {
                    ArrayExpressionElement::SpreadElement(spread) => {
                        self.return_argument_exposes_window(&spread.argument)
                    }
                    _ => element
                        .as_expression()
                        .is_some_and(|expr| self.return_argument_exposes_window(expr)),
                })
            }
            Expression::ObjectExpression(object) => {
                object.properties.iter().any(|property| match property {
                    ObjectPropertyKind::ObjectProperty(property) => {
                        self.return_argument_exposes_window(&property.value)
                    }
                    ObjectPropertyKind::SpreadProperty(spread) => {
                        self.return_argument_exposes_window(&spread.argument)
                    }
                })
            }
            _ => false,
        }
    }

    pub(super) fn note_return_write(&mut self, root: String) {
        if self.return_written_roots.len() >= 1024 {
            self.return_written_roots.insert(String::new());
        } else if !self.return_written_roots.contains("") {
            self.return_written_roots.insert(root);
        }
    }

    pub(super) fn collect_return_url_lead(&mut self, expr: Option<&Expression<'a>>) {
        if self.collecting_return_url_lead.get() {
            let lead = expr.map_or(UrlLead::Passive, |expr| self.url_lead(expr));
            self.return_url_lead = Some(self.return_url_lead.map_or(lead, |old| old.max(lead)));
        }
    }

    /// `(pattern, flags)` of the regex literal at `span`, read off the source.
    pub(super) fn regex_literal_parts(&self, span: oxc_span::Span) -> Option<(&str, &str)> {
        let raw = self
            .source_code
            .get(span.start as usize..span.end as usize)?;
        let body = raw.strip_prefix('/')?;
        let close = body.rfind('/')?;
        Some((&body[..close], &body[close + 1..]))
    }

    /// Record what `name` starts with after `name = value` / `var name = value`.
    /// `old` and `lead` are [`identifier_url_lead`](Self::identifier_url_lead)
    /// of the name and [`url_lead`](Self::url_lead) of the value, both read
    /// *before* the binding changed any state.
    pub(super) fn set_url_lead(&mut self, name: &str, old: UrlLead, lead: UrlLead) {
        // On one branch of several the name holds either value.
        let lead = if self.branch_depth > 0 {
            lead.max(old)
        } else {
            lead
        };
        let tainted = self.tainted_vars.contains(name) || self.global_taints.contains(name);
        self.url_lead_kills.push(name.to_string());
        // Drop the record that says what no record says: a tainted name is
        // `Open`, a clean one `Passive`. (`var js = 'javascript:'` is clean
        // and `Open`, so that one is kept.)
        let default = if tainted {
            UrlLead::Open
        } else {
            UrlLead::Passive
        };
        // Nor does a record outlive a global some function body taints
        // (`function set() { u = location.hash }`): any call may run it.
        if lead == default || self.global_taints.contains(name) {
            self.url_leads.remove(name);
        } else {
            self.url_leads.insert(name.to_string(), (lead, tainted));
        }
    }

    /// Lead of `old + appended` (`name += value`).
    pub(super) fn appended_url_lead(old: UrlLead, appended: UrlLead) -> UrlLead {
        match (old, appended) {
            // No longer the very start of the value.
            (UrlLead::Passive, UrlLead::PageUrl) => UrlLead::Pinned,
            (UrlLead::Passive, appended) => appended,
            (old, _) => old,
        }
    }

    /// `name` was rebound to something this analysis does not follow.
    pub(super) fn forget_url_lead(&mut self, name: &str) {
        if self.url_leads.remove(name).is_some() {
            self.url_lead_kills.push(name.to_string());
        }
    }

    /// Enter a function body: its `shadowed` parameters and locals start
    /// without a record.
    pub(super) fn url_leads_enter<'n>(
        &mut self,
        shadowed: impl IntoIterator<Item = &'n String>,
    ) -> UrlLeadScope {
        let scope = UrlLeadScope {
            checkpoint: self.url_leads.checkpoint(),
            kills_start: self.url_lead_kills.len(),
        };
        for name in shadowed {
            self.url_leads.remove(name.as_str());
        }
        scope
    }

    /// Leave a function body. Its writes are rolled back — the body may never
    /// run, or run before the code that follows — except that an outer name
    /// it rebound keeps the *worse* of the two records: a body can take a pin
    /// away, never grant one.
    pub(super) fn url_leads_exit(&mut self, scope: UrlLeadScope, locals: &HashSet<String>) {
        let rebound: Vec<(String, Option<UrlLead>)> = self
            .url_lead_kills
            .drain(scope.kills_start..)
            .filter(|name| !locals.contains(name))
            .map(|name| {
                let lead = self.url_leads.get(&name).map(|(lead, _)| *lead);
                (name, lead)
            })
            .collect();
        self.url_leads.rollback(scope.checkpoint);
        for (name, inner) in rebound {
            match (self.url_leads.get(&name).copied(), inner) {
                (Some((outer, tainted)), Some(inner)) => {
                    self.url_leads
                        .insert(name.clone(), (outer.max(inner), tainted));
                }
                _ => {
                    self.url_leads.remove(&name);
                }
            }
            // The enclosing body must hand the same verdict further out.
            self.url_lead_kills.push(name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_prefix_classification() {
        for pins in ["/x", "?a", "#a", "https://a", "mailto:", " \t/x", "http:"] {
            assert!(classify_url_prefix(pins) == PrefixKind::Pins, "{pins}");
        }
        for script in [
            "javascript:",
            "JavaScript:x",
            "java\tscript:",
            " data:",
            "vbscript:",
        ] {
            assert!(
                classify_url_prefix(script) == PrefixKind::Script,
                "{script}"
            );
        }
        for partial in ["", "java", "http", "  "] {
            assert!(
                classify_url_prefix(partial) == PrefixKind::Partial,
                "{partial}"
            );
        }
    }

    #[test]
    fn regex_start_miss_is_conservative() {
        for misses in ["#.*$", r"\?.*", "[?&]lang=[^&]*", "&x=1", r"\/$"] {
            assert!(regex_misses_http_start(misses), "{misses}");
        }
        for may_match in [
            "^http:", ".*#", "h", "[a-z]+", "[^/]", r"\w+", "#?x", "#*", "a|^h", "(x)", "", "[h#]",
        ] {
            assert!(!regex_misses_http_start(may_match), "{may_match}");
        }
    }
}
