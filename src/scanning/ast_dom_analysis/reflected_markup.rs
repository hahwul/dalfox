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

/// What the HTML pre-scan learned about the analysed response's elements:
/// the slots that carry a scan marker (keyed by element `id`), and the ids of
/// its `<form>` elements.
#[derive(Debug, Clone, Default)]
pub struct PageMarkup {
    /// `id`s of `<form>` elements, so `getElementById('f').action = …` is
    /// known to write a real form's action. Not marker-gated.
    pub(crate) form_ids: HashSet<String>,
    /// `id` → tag of the media, frame and `<link>` elements, so
    /// `getElementById('logo').src = …` is known to write an image's `src`.
    /// Not marker-gated.
    pub(crate) element_tags: HashMap<String, String>,
    /// `id` → lowercased names of the attributes whose value carries a marker.
    pub(crate) attrs: HashMap<String, HashSet<String>>,
    /// `id`s of elements whose text content carries a marker.
    pub(crate) text: HashSet<String>,
    /// CSS custom property names (`--x`) declared with a value carrying a
    /// marker, in a `<style>` block or a `style` attribute.
    pub(crate) css_custom_properties: HashSet<String>,
    /// The value the tested parameter carried in the request that produced
    /// this response. A string literal that decodes to it is the server's
    /// copy of the parameter even when the value carries no marker (an attack
    /// payload such as `');alert(1)//`).
    pub(crate) sent_value: Option<String>,
    /// The script being analysed was loaded from a `<script src>` whose URL
    /// carries a marker, so `document.currentScript.src` holds the parameter.
    pub(crate) current_script_src: bool,
}

impl PageMarkup {
    /// No slot carries a marker (form ids do not count).
    pub(crate) fn is_empty(&self) -> bool {
        self.attrs.is_empty()
            && self.text.is_empty()
            && self.css_custom_properties.is_empty()
            && !self.current_script_src
    }

    /// Add every slot `other` proved.
    pub(crate) fn merge(&mut self, other: &PageMarkup) {
        for (id, names) in &other.attrs {
            self.attrs
                .entry(id.clone())
                .or_default()
                .extend(names.iter().cloned());
        }
        self.text.extend(other.text.iter().cloned());
        self.form_ids.extend(other.form_ids.iter().cloned());
        for (id, tag) in &other.element_tags {
            self.element_tags.insert(id.clone(), tag.clone());
        }
        self.css_custom_properties
            .extend(other.css_custom_properties.iter().cloned());
        if self.sent_value.is_none() {
            self.sent_value = other.sent_value.clone();
        }
    }
}

/// The tag a selector's only compound names (`img.hero` → `img`). A selector
/// with a combinator or a list matches its *last* compound, which this does
/// not parse, so those resolve to nothing.
fn selector_tag(selector: &str) -> Option<String> {
    let selector = selector.trim();
    if selector.contains([',', ' ', '>', '+', '~']) {
        return None;
    }
    let tag = &selector[..selector
        .find(['.', '#', '[', ':'])
        .unwrap_or(selector.len())];
    (!tag.is_empty() && tag.chars().all(|c| c.is_ascii_alphanumeric()))
        .then(|| tag.to_ascii_lowercase())
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
    /// The `id` of the element `expr` resolves to: an inline
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
        // Every caller then checks the specific slot (`attrs[id]`, `text`).
        Some(id)
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
        if self.reflected_markup.current_script_src
            && prop == "src"
            && let Expression::StaticMemberExpression(inner) = &member.object
            && self.get_member_string(inner).is_some_and(|path| {
                matches!(
                    path.as_str(),
                    "document.currentScript" | "window.document.currentScript"
                )
            })
        {
            return Some("markup:document.currentScript.src".to_string());
        }
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

    /// Whether `expr` resolves to a `<form>` element: a variable bound to one,
    /// `document.getElementById('id')` for a form id the pre-scan saw,
    /// `document.forms[…]` / `document.forms.name`,
    /// `document.createElement('form')`, or `querySelector('form…')`.
    pub(super) fn expr_resolves_to_form(&self, expr: &Expression<'a>) -> bool {
        match expr {
            Expression::Identifier(id) => self.form_element_vars.contains(id.name.as_str()),
            Expression::ParenthesizedExpression(p) => self.expr_resolves_to_form(&p.expression),
            Expression::StaticMemberExpression(m) => {
                matches!(&m.object, Expression::StaticMemberExpression(inner)
                    if self.get_member_string(inner).as_deref() == Some("document.forms"))
            }
            Expression::ComputedMemberExpression(m) => {
                matches!(&m.object, Expression::StaticMemberExpression(inner)
                    if self.get_member_string(inner).as_deref() == Some("document.forms"))
            }
            Expression::CallExpression(call) => {
                let Some(method) = self.get_callee_property_name(&call.callee) else {
                    return false;
                };
                let Some(arg) = Self::extract_static_string_argument(call, 0) else {
                    return false;
                };
                match method.as_str() {
                    "getElementById" => self.reflected_markup.form_ids.contains(&arg),
                    "createElement" => arg.eq_ignore_ascii_case("form"),
                    "querySelector" => {
                        let sel = arg.trim().to_ascii_lowercase();
                        sel == "form"
                            || sel
                                .strip_prefix("form")
                                .is_some_and(|rest| rest.starts_with(['#', '.', '[', ':']))
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// The lowercased tag of the element `expr` resolves to, when the script
    /// says so itself: `createElement('img')`, `new Image()` / `new Audio()`,
    /// `querySelector('iframe.x')`, `document.images[0]`,
    /// `getElementsByTagName('img')[0]`, `getElementById('id')` for an id the
    /// HTML pre-scan saw on a media, frame or link element, or a variable
    /// bound to one of those.
    pub(super) fn expr_element_tag(&self, expr: &Expression<'a>) -> Option<String> {
        match expr {
            Expression::Identifier(id) => self.element_tag_vars.get(id.name.as_str()).cloned(),
            Expression::ParenthesizedExpression(p) => self.expr_element_tag(&p.expression),
            Expression::NewExpression(new_expr) => match &new_expr.callee {
                Expression::Identifier(id) if id.name == "Image" => Some("img".to_string()),
                Expression::Identifier(id) if id.name == "Audio" => Some("audio".to_string()),
                _ => None,
            },
            Expression::CallExpression(call) => {
                let method = self.get_callee_property_name(&call.callee)?;
                let arg = Self::extract_static_string_argument(call, 0)?;
                match method.as_str() {
                    "createElement" => Some(arg.to_ascii_lowercase()),
                    "querySelector" | "closest" => selector_tag(&arg),
                    "getElementById" => self.reflected_markup.element_tags.get(&arg).cloned(),
                    _ => None,
                }
            }
            Expression::ComputedMemberExpression(member) => match &member.object {
                Expression::StaticMemberExpression(inner) => {
                    (self.get_member_string(inner).as_deref() == Some("document.images"))
                        .then(|| "img".to_string())
                }
                Expression::CallExpression(call) => {
                    let method = self.get_callee_property_name(&call.callee)?;
                    let arg = Self::extract_static_string_argument(call, 0)?;
                    match method.as_str() {
                        "getElementsByTagName" => Some(arg.to_ascii_lowercase()),
                        "querySelectorAll" => selector_tag(&arg),
                        _ => None,
                    }
                }
                _ => None,
            },
            _ => None,
        }
    }

    /// Source label when `call` percent-decodes a string literal that is the
    /// server's copy of the parameter: `decodeURIComponent('…')` where the
    /// server wrote it, percent-encoded, into the script. The encoding leaves
    /// no raw breakout for the reflection engine to see. Proof is either this
    /// scan's marker in the literal (alphanumeric, so it survives encoding) or
    /// the literal decoding to the value this very request sent. A literal
    /// that reaches a sink undecoded is left to the reflection engine, which
    /// already sees it.
    pub(super) fn decoded_reflected_literal_source(
        &self,
        call: &CallExpression<'a>,
    ) -> Option<String> {
        let Expression::Identifier(callee) = &call.callee else {
            return None;
        };
        let name = callee.name.as_str();
        if !matches!(name, "decodeURIComponent" | "decodeURI" | "unescape") {
            return None;
        }
        let literal = Self::extract_static_string_argument(call, 0)?;
        let decoded = urlencoding::decode(&literal).map(|d| d.into_owned()).ok();
        let is_sent_value = self
            .reflected_markup
            .sent_value
            .as_deref()
            // A short value (`1`, `a`) could match a constant by accident.
            .filter(|v| v.len() >= 8)
            .zip(decoded.as_deref())
            .is_some_and(|(sent, decoded)| decoded.contains(sent));
        (crate::scanning::markers::carries_scan_marker(&literal) || is_sent_value)
            .then(|| format!("markup:{name}(<reflected string>)"))
    }
}
