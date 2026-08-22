//! Turning an expression back into the literal string it denotes.
//!
//! Member paths (`a.b.c`), computed accesses with a constant key, and
//! concatenations of literals all have to collapse to a name before the source,
//! sink, and sanitizer catalogs can be consulted.

use super::*;

impl<'a> DomXssVisitor<'a> {
    /// Get a string representation of an expression if it's an identifier or member expression
    pub(super) fn get_expr_string(&self, expr: &Expression) -> Option<String> {
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
    pub(super) fn get_member_string(&self, member: &StaticMemberExpression) -> Option<String> {
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
    pub(super) fn get_computed_property_string(
        &self,
        member: &ComputedMemberExpression<'a>,
    ) -> Option<String> {
        self.eval_static_string_expr(&member.expression)
    }
    /// Get string representation of computed member expression when property is
    /// literal. Mutually recursive with [`get_member_string`]; the shared
    /// recursion guard bounds `a["b"]["c"]…` chains so a hostile computed-member
    /// chain can't overflow the stack.
    pub(super) fn get_computed_member_string(
        &self,
        member: &ComputedMemberExpression<'a>,
    ) -> Option<String> {
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
    pub(super) fn is_assignment_sink_property(&self, prop_name: &str) -> bool {
        matches!(
            prop_name,
            "innerHTML" | "outerHTML" | "src" | "srcdoc" | "href" | "xlink:href"
        )
    }
    /// Pattern-based sanitizer name detection for names not in the explicit allowlist.
    /// Matches specific combinations: "sanitize"+"html"/"xss", "escape"+"html"/"xss",
    /// "encode"+"html".
    pub(super) fn is_likely_sanitizer_name(name: &str) -> bool {
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
        // "purify"/"dompurify" as a *whole* segment only. Matching "purify" as a
        // bare substring also fires on unrelated names like `impurifyData`,
        // `purifyConfig`, or `unpurified`, wrongly clearing taint and hiding real
        // DOM-XSS. The canonical `DOMPurify.sanitize` form is already covered by
        // the explicit `DOM_SANITIZERS` allowlist.
        if func == "purify" || func == "dompurify" {
            return true;
        }
        false
    }
    /// Evaluate an expression to a static string when possible.
    ///
    /// Recurses unguarded by the visitor walk (it's reached from
    /// `get_computed_member_string` for `x[ "a" + "b" + … ]` keys), so it carries
    /// the shared recursion guard itself — a hostile `+`/paren chain here would
    /// otherwise overflow the stack independently of the visitor's other guards.
    pub(super) fn eval_static_string_expr(&self, expr: &Expression<'a>) -> Option<String> {
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
    pub(super) fn eval_static_string_arg(&self, arg: &Argument<'a>) -> Option<String> {
        match arg {
            Argument::SpreadElement(_) => None,
            _ => arg
                .as_expression()
                .and_then(|expr| self.eval_static_string_expr(expr)),
        }
    }
    pub(super) fn get_property_key_name(&self, key: &PropertyKey<'a>) -> Option<String> {
        key.name().map(std::borrow::Cow::into_owned)
    }
    pub(super) fn get_summary_object_prefix(&self, expr: &Expression<'a>) -> Option<String> {
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
    pub(super) fn get_summary_key_for_callee_expr(&self, expr: &Expression<'a>) -> Option<String> {
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
    pub(super) fn get_callee_property_name(&self, callee: &Expression<'a>) -> Option<String> {
        match callee {
            Expression::StaticMemberExpression(member) => Some(member.property.name.to_string()),
            Expression::ComputedMemberExpression(member) => {
                self.get_computed_property_string(member)
            }
            _ => None,
        }
    }
    pub(super) fn get_callee_object_expr<'b>(
        &self,
        callee: &'b Expression<'a>,
    ) -> Option<&'b Expression<'a>> {
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
    pub(super) fn callee_receiver_is_jquery_chain(callee: &Expression<'a>) -> bool {
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
    pub(super) fn static_leading_string(&self, expr: &Expression<'a>) -> Option<String> {
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
    pub(super) fn jquery_arg_forces_selector(&self, expr: &Expression<'a>) -> bool {
        match self.static_leading_string(expr) {
            Some(prefix) => {
                let trimmed = prefix.trim_start();
                !trimmed.is_empty() && !trimmed.starts_with('<')
            }
            None => false,
        }
    }
}
