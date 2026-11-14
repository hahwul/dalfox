//! Conditions that prove a tainted value harmless on one of their branches.
//!
//! The walk is flow-insensitive, so `if (ALLOWED.includes(tab)) el.innerHTML =
//! tabs(tab)` used to report exactly like the unguarded write. Two kinds of
//! test are precise enough to act on:
//!
//! * an **allowlist** on a tainted variable — `x === 'a'`, `['a','b']
//!   .includes(x)`, `SET.has(x)`, `/^[\w-]+$/.test(x)`, a `switch (x)` over
//!   literals — after which `x` holds page-authored text or a string from a
//!   safe alphabet;
//! * a **strict origin check** in a `message` handler — `e.origin === ORIGIN`
//!   or an array / `Set` of origins — after which the message came from a
//!   sender the page chose. A substring test (`indexOf`, `startsWith`, an
//!   unanchored regex) is the classic bypass and proves nothing.
//!
//! The proof holds on the branch the test selects and, when the other branch
//! always leaves the function (`if (e.origin !== ORIGIN) return;`), for the
//! rest of the body.

use super::*;

/// A name a condition vouches for.
#[derive(Clone)]
pub(super) enum GuardTarget {
    /// A tainted variable.
    Var(String),
    /// The parameters / bindings of a `message` handler that carry its data.
    Message(Vec<String>),
}

/// Taint taken away by a guard, to hand back when its branch ends.
pub(super) struct Untainted {
    vars: Vec<String>,
    globals: Vec<String>,
    fields: Vec<(String, String)>,
    /// Names added to `origin_checked`.
    checked: Vec<String>,
}

/// What [`DomXssVisitor::enter_body`] saved.
pub(super) struct BodyFrame {
    branch_base: u32,
    guarded_globals: usize,
    origin_checked: scoped_state::Checkpoint,
}

/// A regex that only matches whole strings over `[A-Za-z0-9_-]`: anchored at
/// both ends, no `m` flag (it would anchor per line), and built from nothing
/// but those characters, plain classes of them, `\d` / `\w`, groups and
/// quantifiers. Alternation is only safe inside a group — `^a|b$` anchors
/// each side once. A class range must stay inside one run (`a-z`, `0-9`):
/// `[A-z]` takes in the backtick and `[.-_]` takes in `<`, `>` and `:`.
// ponytail: `.` is not in the alphabet — it is harmless in HTML but a whole
// hostname in `script.src = 'https://' + x`, and a guard clears every sink
// alike. Allow it once guards know which sink they vouch for.
pub(super) fn regex_is_strict_allowlist(pattern: &str, flags: &str) -> bool {
    if flags.contains('m') {
        return false;
    }
    let Some(body) = pattern
        .strip_prefix('^')
        .and_then(|rest| rest.strip_suffix('$'))
    else {
        return false;
    };
    let safe_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-');
    let safe_escape = |c: Option<char>| matches!(c, Some('d' | 'w' | '-' | '_'));
    let same_run = |lo: char, hi: char| {
        lo <= hi
            && ((lo.is_ascii_digit() && hi.is_ascii_digit())
                || (lo.is_ascii_lowercase() && hi.is_ascii_lowercase())
                || (lo.is_ascii_uppercase() && hi.is_ascii_uppercase()))
    };
    let mut depth = 0usize;
    let mut chars = body.chars().peekable();
    let mut matched_something = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if !safe_escape(chars.next()) {
                    return false;
                }
                matched_something = true;
            }
            '[' => {
                if chars.peek() == Some(&'^') {
                    return false;
                }
                // The last single character, which a following `-` would
                // make the low end of a range.
                let mut low: Option<char> = None;
                loop {
                    match chars.next() {
                        Some(']') => break,
                        Some('\\') => {
                            let escaped = chars.next();
                            if !safe_escape(escaped) {
                                return false;
                            }
                            low = escaped.filter(|c| matches!(c, '-' | '_'));
                        }
                        Some('-') => match (low.take(), chars.peek().copied()) {
                            // Literal at either edge of the class.
                            (None, _) | (_, Some(']')) => {}
                            (Some(lo), Some(hi)) if same_run(lo, hi) => {
                                chars.next();
                            }
                            _ => return false,
                        },
                        Some(c) if safe_char(c) => low = Some(c),
                        _ => return false,
                    }
                }
                matched_something = true;
            }
            '(' => {
                depth += 1;
                if chars.peek() == Some(&'?') {
                    chars.next();
                    if chars.next() != Some(':') {
                        return false;
                    }
                }
            }
            ')' => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            '|' if depth > 0 => {}
            '+' | '*' | '?' => {}
            '{' => {
                if !chars
                    .by_ref()
                    .take_while(|c| *c != '}')
                    .all(|c| c.is_ascii_digit() || c == ',')
                {
                    return false;
                }
            }
            c if safe_char(c) => matched_something = true,
            _ => return false,
        }
    }
    depth == 0 && matched_something
}

impl<'a> DomXssVisitor<'a> {
    /// The names `test` vouches for when it is true, and when it is false.
    pub(super) fn condition_guards(
        &self,
        test: &Expression<'a>,
    ) -> (Vec<GuardTarget>, Vec<GuardTarget>) {
        let (mut when_true, mut when_false) = (Vec::new(), Vec::new());
        self.collect_guards(test, true, &mut when_true);
        self.collect_guards(test, false, &mut when_false);
        (when_true, when_false)
    }

    /// Collect what `test` evaluating to `outcome` proves.
    fn collect_guards(&self, test: &Expression<'a>, outcome: bool, out: &mut Vec<GuardTarget>) {
        let Some(_guard) = self.enter_recursion() else {
            return;
        };
        match test.without_parentheses() {
            Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::LogicalNot => {
                self.collect_guards(&unary.argument, !outcome, out);
            }
            // `a && b` true means both held; `a || b` false means neither did.
            Expression::LogicalExpression(logical)
                if (logical.operator == LogicalOperator::And) == outcome
                    && logical.operator != LogicalOperator::Coalesce =>
            {
                self.collect_guards(&logical.left, outcome, out);
                self.collect_guards(&logical.right, outcome, out);
            }
            Expression::BinaryExpression(binary) => {
                if self.collect_index_guard(binary, outcome, out) {
                    return;
                }
                let equal = match binary.operator {
                    BinaryOperator::StrictEquality | BinaryOperator::Equality => true,
                    BinaryOperator::StrictInequality | BinaryOperator::Inequality => false,
                    _ => return,
                };
                if equal != outcome {
                    return;
                }
                for (subject, other) in
                    [(&binary.left, &binary.right), (&binary.right, &binary.left)]
                {
                    match self.guard_subject(subject) {
                        Some(target @ GuardTarget::Var(_)) if Self::is_plain_literal(other) => {
                            out.push(target)
                        }
                        Some(target @ GuardTarget::Message(_))
                            if !self.is_tainted(other) || self.expr_is_own_origin(other) =>
                        {
                            self.note_origin_dep(other);
                            out.push(target)
                        }
                        _ => {}
                    }
                }
            }
            Expression::CallExpression(call) if outcome => {
                if let Some(target) = self.membership_guard(call) {
                    out.push(target);
                }
            }
            _ => {}
        }
    }

    /// The page's own origin (`location.origin`, `window.origin`) — a source
    /// by name, but the one value an origin check is meant to compare with.
    fn expr_is_own_origin(&self, expr: &Expression<'a>) -> bool {
        self.get_expr_string(expr.without_parentheses())
            .is_some_and(|path| {
                let path = path
                    .trim_start_matches("window.")
                    .trim_start_matches("self.")
                    .trim_start_matches("document.");
                matches!(path, "location.origin" | "origin")
            })
    }

    /// `LIST.indexOf(x) !== -1` and its spellings. True when `binary` is a
    /// comparison of an `indexOf` result at all, vouching or not.
    fn collect_index_guard(
        &self,
        binary: &BinaryExpression<'a>,
        outcome: bool,
        out: &mut Vec<GuardTarget>,
    ) -> bool {
        // `LIST.indexOf(x) === -1`, or `i === -1` right after `var i = LIST.indexOf(x)`.
        let (call, stored) = match binary.left.without_parentheses() {
            Expression::CallExpression(call)
                if self.get_callee_property_name(&call.callee).as_deref() == Some("indexOf") =>
            {
                (Some(call), None)
            }
            Expression::Identifier(id) => match &self.adjacent_index {
                Some((name, target)) if name == id.name.as_str() => (None, Some(target.clone())),
                _ => return false,
            },
            _ => return false,
        };
        let number = match binary.right.without_parentheses() {
            Expression::NumericLiteral(n) => n.value,
            Expression::UnaryExpression(u) if u.operator == UnaryOperator::UnaryNegation => {
                match &u.argument {
                    Expression::NumericLiteral(n) => -n.value,
                    _ => return true,
                }
            }
            _ => return true,
        };
        // Which outcome of the comparison means "found".
        // `-1` or `0`, as an integer the comparison can be matched on.
        let number = if number == -1.0 {
            -1
        } else if number == 0.0 {
            0
        } else {
            return true;
        };
        let found_when = match (binary.operator, number) {
            (BinaryOperator::StrictInequality | BinaryOperator::Inequality, -1) => true,
            (BinaryOperator::GreaterThan, -1) => true,
            (BinaryOperator::GreaterEqualThan, 0) => true,
            (BinaryOperator::StrictEquality | BinaryOperator::Equality, -1) => false,
            (BinaryOperator::LessThan, 0) => false,
            _ => return true,
        };
        if found_when == outcome
            && let Some(target) = stored.or_else(|| self.membership_target(call?))
        {
            out.push(target);
        }
        true
    }

    /// `(i, what i === -1 vouches for)` when `prev` is `var i = LIST.indexOf(x)`
    /// or `i = LIST.indexOf(x)` and `next` is the `if` that tests it. Only the
    /// adjacent pair: nothing can have rebound `i` or `x` between them.
    pub(super) fn adjacent_index_result(
        &self,
        prev: &Statement<'a>,
        next: &Statement<'a>,
    ) -> Option<(String, GuardTarget)> {
        if !matches!(next, Statement::IfStatement(_)) {
            return None;
        }
        let (name, init) = match prev {
            Statement::VariableDeclaration(decl) => match decl.declarations.last()? {
                VariableDeclarator {
                    id: BindingPattern::BindingIdentifier(id),
                    init: Some(init),
                    ..
                } => (id.name.as_str(), init),
                _ => return None,
            },
            Statement::ExpressionStatement(stmt) => match &stmt.expression {
                Expression::AssignmentExpression(assign)
                    if assign.operator == AssignmentOperator::Assign =>
                {
                    match &assign.left {
                        AssignmentTarget::AssignmentTargetIdentifier(id) => {
                            (id.name.as_str(), &assign.right)
                        }
                        _ => return None,
                    }
                }
                _ => return None,
            },
            _ => return None,
        };
        let Expression::CallExpression(call) = init.without_parentheses() else {
            return None;
        };
        if self.get_callee_property_name(&call.callee).as_deref() != Some("indexOf") {
            return None;
        }
        Some((name.to_string(), self.membership_target(call)?))
    }

    /// A call that is true only for a vouched-for value: `LIST.includes(x)`,
    /// `SET.has(x)`, `/^…$/.test(x)`, `x.match(/^…$/)`.
    fn membership_guard(&self, call: &CallExpression<'a>) -> Option<GuardTarget> {
        let method = self.get_callee_property_name(&call.callee)?;
        let receiver = self.get_callee_object_expr(&call.callee)?;
        let arg = call.arguments.first().and_then(|a| a.as_expression());
        let strict_regex = |expr: &Expression<'a>| match expr.without_parentheses() {
            Expression::RegExpLiteral(re) => self
                .regex_literal_parts(re.span)
                .is_some_and(|(pattern, flags)| regex_is_strict_allowlist(pattern, flags)),
            _ => false,
        };
        match method.as_str() {
            "includes" | "has" => self.membership_target(call),
            "test" if strict_regex(receiver) => match self.guard_subject(arg?)? {
                target @ GuardTarget::Var(_) => Some(target),
                GuardTarget::Message(_) => None,
            },
            "match" if arg.is_some_and(strict_regex) => match self.guard_subject(receiver)? {
                target @ GuardTarget::Var(_) => Some(target),
                GuardTarget::Message(_) => None,
            },
            _ => None,
        }
    }

    /// The subject of `LIST.includes(x)` / `.has(x)` / `.indexOf(x)`, when the
    /// receiver is a page-authored collection.
    fn membership_target(&self, call: &CallExpression<'a>) -> Option<GuardTarget> {
        let receiver = self
            .get_callee_object_expr(&call.callee)?
            .without_parentheses();
        let subject = self.guard_subject(call.arguments.first()?.as_expression()?)?;
        if self.is_tainted(receiver) {
            return None;
        }
        let collection = match receiver {
            Expression::ArrayExpression(_) => true,
            Expression::NewExpression(new_expr) => {
                matches!(&new_expr.callee, Expression::Identifier(id) if id.name == "Set")
            }
            Expression::Identifier(id) => matches!(
                self.instance_classes
                    .get(id.name.as_str())
                    .map(String::as_str),
                Some("Array" | "Set")
            ),
            _ => false,
        };
        // A substring of page-authored text is page-authored too — but an
        // origin that is a *substring* of the allowed one is the classic
        // bypass (`https://trusted.co`), so strings only vouch for variables.
        let text = matches!(receiver, Expression::StringLiteral(_));
        match subject {
            target @ GuardTarget::Var(_) if collection || text => Some(target),
            target @ GuardTarget::Message(_) if collection => {
                self.note_origin_dep(receiver);
                Some(target)
            }
            _ => None,
        }
    }

    /// In a summary pass every outer value reads clean, so an origin check
    /// against one is taken on trust there and re-examined where the handler
    /// is registered (see `FunctionSummary::origin_guard_deps`).
    fn note_origin_dep(&self, compared: &Expression<'a>) {
        if self.collecting_tainted_returns
            && let Some(path) = self.get_expr_string(compared.without_parentheses())
        {
            self.origin_guard_deps.borrow_mut().push(path);
        }
    }

    /// What `expr` is, as the subject of a guard: a `message` handler's
    /// origin, or a tainted variable.
    pub(super) fn guard_subject(&self, expr: &Expression<'a>) -> Option<GuardTarget> {
        let expr = expr.without_parentheses();
        if let Some(path) = self.get_expr_string(expr) {
            if let Some(carriers) = self.message_origins.get(&path) {
                return Some(GuardTarget::Message(carriers.clone()));
            }
            // The conventional spelling, where `event.data` is a source by
            // name (see `DOM_SOURCES`).
            if path == "event.origin" {
                return Some(GuardTarget::Message(vec!["event".to_string()]));
            }
        }
        match expr {
            Expression::Identifier(id)
                if self.tainted_vars.contains(id.name.as_str())
                    || self.global_taints.contains(id.name.as_str()) =>
            {
                Some(GuardTarget::Var(id.name.to_string()))
            }
            _ => None,
        }
    }

    pub(super) fn is_plain_literal(expr: &Expression<'a>) -> bool {
        match expr.without_parentheses() {
            Expression::StringLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_) => true,
            Expression::TemplateLiteral(t) => t.expressions.is_empty(),
            _ => false,
        }
    }

    /// Take the taint off `targets`, returning what to hand back.
    pub(super) fn untaint(&mut self, targets: &[GuardTarget]) -> Untainted {
        let mut taken = Untainted {
            vars: Vec::new(),
            globals: Vec::new(),
            fields: Vec::new(),
            checked: Vec::new(),
        };
        for target in targets {
            let names = match target {
                GuardTarget::Var(name) => std::slice::from_ref(name),
                GuardTarget::Message(carriers) => {
                    for carrier in carriers {
                        let field = format!("{carrier}.data");
                        if let Some(source) = self.field_taints.remove(&field) {
                            taken.fields.push((field, source));
                        }
                        if self.origin_checked.insert(carrier.clone()) {
                            taken.checked.push(carrier.clone());
                        }
                    }
                    carriers.as_slice()
                }
            };
            for name in names {
                if self.tainted_vars.remove(name.as_str()) {
                    taken.vars.push(name.clone());
                }
                if self.global_taints.remove(name.as_str()) {
                    taken.globals.push(name.clone());
                }
            }
        }
        taken
    }

    pub(super) fn retaint(&mut self, taken: Untainted) {
        for name in taken.vars {
            self.tainted_vars.insert(name);
        }
        for name in taken.globals {
            self.global_taints.insert(name);
        }
        for (field, source) in taken.fields {
            self.field_taints.insert(field, source);
        }
        for name in taken.checked {
            self.origin_checked.remove(name.as_str());
        }
    }

    /// Walk `stmt` as the branch on which `targets` are vouched for.
    pub(super) fn walk_guarded_branch(&mut self, targets: &[GuardTarget], stmt: &Statement<'a>) {
        let taken = self.untaint(targets);
        self.walk_statement(stmt);
        self.retaint(taken);
    }

    /// `targets` are vouched for until the function body ends. Body-local
    /// taint is rolled back with the body anyway; `global_taints` is not, so
    /// those are noted for [`leave_body`](Self::leave_body) to hand back.
    pub(super) fn untaint_for_rest_of_body(&mut self, targets: &[GuardTarget]) {
        let taken = self.untaint(targets);
        self.body_guarded_globals.extend(taken.globals);
    }

    /// Start a function body: branches are counted from here, so an early
    /// `return` at its top level is unconditional *for this body*.
    pub(super) fn enter_body(&mut self) -> BodyFrame {
        let frame = BodyFrame {
            branch_base: self.branch_base,
            guarded_globals: self.body_guarded_globals.len(),
            origin_checked: self.origin_checked.checkpoint(),
        };
        self.branch_base = self.branch_depth;
        frame
    }

    pub(super) fn leave_body(&mut self, frame: BodyFrame) {
        self.branch_base = frame.branch_base;
        self.origin_checked.rollback(frame.origin_checked);
        for name in self.body_guarded_globals.split_off(frame.guarded_globals) {
            self.global_taints.insert(name);
        }
    }

    /// The statement leaves the function on every path through it.
    pub(super) fn always_exits(stmt: &Statement<'a>) -> bool {
        match stmt {
            Statement::ReturnStatement(_) | Statement::ThrowStatement(_) => true,
            Statement::BlockStatement(block) => block.body.last().is_some_and(Self::always_exits),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::regex_is_strict_allowlist as strict;

    #[test]
    fn strict_allowlist_regexes() {
        for (pattern, flags) in [
            (r"^[a-z0-9]+$", ""),
            (r"^\d+$", ""),
            (r"^[\w-]+$", "i"),
            (r"^[A-Za-z0-9_-]{1,32}$", ""),
            (r"^[-\w]+$", ""),
            (r"^(?:home|about|contact)$", ""),
        ] {
            assert!(strict(pattern, flags), "{pattern}");
        }
        for (pattern, flags) in [
            (r"[a-z]+", ""),       // unanchored
            (r"^[a-z]+", ""),      // open end
            (r"^[a-z]+$", "m"),    // per-line anchors
            (r"^home|about$", ""), // each side anchored once
            (r"^.+$", ""),         // anything
            (r"^[^<>]+$", ""),     // a denylist
            (r"^[a-z:]+$", ""),    // scheme separator
            (r"^[\s\w]+$", ""),    // whitespace
            (r"^\S+$", ""),
            (r"^$", ""),
            (r"^(a$", ""),
            (r"^[\w.-]+$", ""), // a hostname
            (r"^v\d+\.\d+$", ""),
            (r"^[a-zA-Z0-9.-_]+$", ""), // `.-_` spans `<`, `>`, `:`
            (r"^[A-z0-9]+$", ""),       // spans the backtick
            (r"^[0-z]+$", ""),
            (r"^[\--z]+$", ""),
        ] {
            assert!(!strict(pattern, flags), "{pattern}");
        }
    }
}
