//! Markup the server filled from the scanned parameter, read back by the page.
//!
//! `<div id="t" data-content="…">` + `el.innerHTML = t.dataset.content` is a
//! real flow when the server wrote the parameter into `data-content`, and a
//! harmless component idiom when it did not. Reading a `data-*` attribute,
//! `getAttribute()`, `textContent` or a CSS custom property is therefore only
//! a source for the slots the HTML pre-scan saw carrying this scan's marker in
//! the very response being analysed (see
//! `ast_integration::reflected_markup_from_document`). The marker is
//! session-random, so its presence proves the slot reflects the parameter;
//! the property or attribute name alone never decides anything.

use super::*;

/// Slots of one response that carry a scan marker, keyed by element `id`.
#[derive(Debug, Clone, Default)]
pub struct ReflectedMarkup {
    /// `id` → lowercased names of the attributes whose value carries a marker.
    pub(crate) attrs: HashMap<String, HashSet<String>>,
    /// `id`s of elements whose text content carries a marker.
    pub(crate) text: HashSet<String>,
    /// CSS custom property names (`--x`) declared with a value carrying a
    /// marker, in a `<style>` block or a `style` attribute.
    pub(crate) css_custom_properties: HashSet<String>,
}

impl ReflectedMarkup {
    pub(crate) fn is_empty(&self) -> bool {
        self.attrs.is_empty() && self.text.is_empty() && self.css_custom_properties.is_empty()
    }

    /// Add every slot `other` proved.
    pub(crate) fn merge(&mut self, other: &ReflectedMarkup) {
        for (id, names) in &other.attrs {
            self.attrs
                .entry(id.clone())
                .or_default()
                .extend(names.iter().cloned());
        }
        self.text.extend(other.text.iter().cloned());
        self.css_custom_properties
            .extend(other.css_custom_properties.iter().cloned());
    }
}

/// `dataset.fooBar` reads the `data-foo-bar` attribute.
fn dataset_attr_name(prop: &str) -> String {
    let mut out = String::from("data-");
    for c in prop.chars() {
        if c.is_ascii_uppercase() {
            out.push('-');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

impl<'a> DomXssVisitor<'a> {
    /// The `id` of the reflected element `expr` resolves to: an inline
    /// `document.getElementById('id')` / `querySelector('#id')` with a literal
    /// argument, or a variable bound to one.
    pub(super) fn reflected_element_id(&self, expr: &Expression<'a>) -> Option<String> {
        if self.reflected_markup.is_empty() {
            return None;
        }
        let id = match expr {
            Expression::Identifier(id) => {
                self.reflected_element_vars.get(id.name.as_str()).cloned()
            }
            Expression::ParenthesizedExpression(p) => self.reflected_element_id(&p.expression),
            Expression::CallExpression(call) => {
                let method = self.get_callee_property_name(&call.callee)?;
                let arg = Self::extract_static_string_argument(call, 0)?;
                match method.as_str() {
                    "getElementById" => Some(arg),
                    "querySelector" => arg
                        .strip_prefix('#')
                        .filter(|s| {
                            !s.is_empty()
                                && s.chars()
                                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                        })
                        .map(str::to_string),
                    _ => None,
                }
            }
            _ => None,
        }?;
        let m = &self.reflected_markup;
        (m.attrs.contains_key(&id) || m.text.contains(&id)).then_some(id)
    }

    /// Source label when `member` reads a reflected slot: `el.dataset.x` or
    /// `el.textContent` / `el.innerText`.
    pub(super) fn reflected_markup_source_for_member(
        &self,
        member: &StaticMemberExpression<'a>,
    ) -> Option<String> {
        if self.reflected_markup.is_empty() {
            return None;
        }
        let prop = member.property.name.as_str();
        if matches!(prop, "textContent" | "innerText") {
            let id = self.reflected_element_id(&member.object)?;
            return self
                .reflected_markup
                .text
                .contains(&id)
                .then(|| format!("markup:#{id}.{prop}"));
        }
        if let Expression::StaticMemberExpression(inner) = &member.object
            && inner.property.name == "dataset"
        {
            let id = self.reflected_element_id(&inner.object)?;
            let attr = dataset_attr_name(prop);
            return self
                .reflected_markup
                .attrs
                .get(&id)
                .is_some_and(|a| a.contains(&attr))
                .then(|| format!("markup:#{id}[{attr}]"));
        }
        None
    }

    /// Source label when `call` reads a reflected slot:
    /// `el.getAttribute('x')`, or `getPropertyValue('--x')` for a custom
    /// property the server declared with the parameter's value.
    pub(super) fn reflected_markup_source_for_call(
        &self,
        call: &CallExpression<'a>,
    ) -> Option<String> {
        if self.reflected_markup.is_empty() {
            return None;
        }
        let method = self.get_callee_property_name(&call.callee)?;
        let name = Self::extract_static_string_argument(call, 0)?;
        match method.as_str() {
            "getAttribute" => {
                let obj = self.get_callee_object_expr(&call.callee)?;
                let id = self.reflected_element_id(obj)?;
                let attr = name.to_ascii_lowercase();
                self.reflected_markup
                    .attrs
                    .get(&id)
                    .is_some_and(|a| a.contains(&attr))
                    .then(|| format!("markup:#{id}[{attr}]"))
            }
            "getPropertyValue" => self
                .reflected_markup
                .css_custom_properties
                .contains(&name)
                .then(|| format!("markup:{name}")),
            _ => None,
        }
    }
}
