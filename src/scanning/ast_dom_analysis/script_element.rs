//! Recognizing a `<script>` element the script built itself.
//!
//! Assigning to `.text` / `.textContent` / `.innerHTML` of one is a code-execution
//! sink even though the same property on any other element is not, so the sink
//! rules need to know what an expression resolves to.

use super::*;

impl<'a> DomXssVisitor<'a> {
    /// Recognise `document.createElement('script')` (and the spelling variants
    /// the AST gives us) so the caller can remember which JS variables hold a
    /// script element. We accept the call with a case-insensitive `script`
    /// argument because HTML element tag names are case-insensitive.
    pub(super) fn expr_creates_script_element(&self, expr: &Expression<'a>) -> bool {
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
    pub(super) fn is_script_element_text_sink_prop(prop: &str) -> bool {
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
    pub(super) fn expr_resolves_to_script_element(&self, expr: &Expression<'a>) -> bool {
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
    pub(super) fn call_resolves_to_script_element(&self, call: &CallExpression<'a>) -> bool {
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
    pub(super) fn computed_member_resolves_to_script_element(
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
    pub(super) fn call_first_arg_eq_ignore_case(call: &CallExpression<'a>, expected: &str) -> bool {
        Self::extract_static_string_argument(call, 0)
            .is_some_and(|s| s.eq_ignore_ascii_case(expected))
    }
    /// Static-selector matcher for "this picks a `<script>`."
    /// Accepts the conservative shapes that appear in real bundles —
    /// `script`, `script#id`, `script[id="x"]`, `script.cls`, `script[*]`.
    /// Combinators (`,`, ` `, `>`, `+`, `~`) are rejected so we never
    /// claim a selector resolves to script when the rightmost element
    /// could be anything.
    pub(super) fn selector_targets_script(selector: &str) -> bool {
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
}
