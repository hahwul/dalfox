//! Where an untrusted value enters the script: `location`/`document`
//! properties reached through `URL`, `URLSearchParams`, and the storage APIs.
//!
//! These resolve an expression to the *name* of the DOM source behind it, which
//! is what a finding reports and what the taint tracker keys on.

use super::*;

impl<'a> DomXssVisitor<'a> {
    pub(super) fn extract_static_string_argument(
        call: &CallExpression<'a>,
        idx: usize,
    ) -> Option<String> {
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
    pub(super) fn normalize_search_param_source(&self, source: &str) -> String {
        match source {
            "location.href" | "document.URL" | "document.documentURI" | "document.baseURI" => {
                "location.search".to_string()
            }
            _ => source.to_string(),
        }
    }
    pub(super) fn compose_search_param_source(
        &self,
        base_source: &str,
        param_name: &str,
    ) -> String {
        if base_source.starts_with("URLSearchParams.get(") {
            format!("{base_source}.get({param_name})")
        } else {
            format!("URLSearchParams.get({param_name})")
        }
    }
    pub(super) fn storage_get_source(
        &self,
        call: &CallExpression<'a>,
        callee_str: &str,
    ) -> Option<String> {
        if callee_str != "localStorage.getItem" && callee_str != "sessionStorage.getItem" {
            return None;
        }

        if let Some(key) = Self::extract_static_string_argument(call, 0) {
            Some(format!("{callee_str}({key})"))
        } else {
            Some(callee_str.to_string())
        }
    }
    pub(super) fn url_source_from_argument(&self, arg: &Argument<'a>) -> Option<String> {
        let expr = match arg {
            Argument::SpreadElement(spread) => &spread.argument,
            _ => arg.as_expression()?,
        };
        self.find_source_in_expr(expr)
            .map(|source| self.normalize_search_param_source(&source))
    }
    pub(super) fn url_object_source_from_new_expression(
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
    pub(super) fn url_object_source_for_expr(&self, expr: &Expression<'a>) -> Option<String> {
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
    pub(super) fn url_search_params_source_for_member(
        &self,
        member: &StaticMemberExpression<'a>,
    ) -> Option<String> {
        if member.property.name.as_str() != "searchParams" {
            return None;
        }

        self.url_object_source_for_expr(&member.object)
    }
    pub(super) fn url_search_params_source_for_expr(
        &self,
        expr: &Expression<'a>,
    ) -> Option<String> {
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
    pub(super) fn url_search_params_get_source(
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
    pub(super) fn url_search_params_field_key(var_name: &str, param_name: &str) -> String {
        format!("{var_name}.{param_name}")
    }
    pub(super) fn url_search_params_field_source_for_expr(
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
    pub(super) fn clear_url_search_params_field_sources(&mut self, var_name: &str) {
        let prefix = format!("{var_name}.");
        self.url_search_params_field_sources
            .retain(|key, _| !key.starts_with(&prefix));
    }
    pub(super) fn clone_url_search_params_field_sources(&mut self, from: &str, to: &str) {
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
    pub(super) fn clone_url_search_params_field_sources_from_expr(
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

    /// True when `expr` is an IndexedDB request whose `result` is a *stored
    /// value* — `store.get(k)`, `.getAll()`, `.openCursor()` and friends.
    ///
    /// The receiver has to be an `objectStore(...)` / `index(...)` call, which
    /// is what separates a record read from the two IndexedDB calls whose
    /// `result` is not data: `indexedDB.open(...)` resolves to a database
    /// connection, and `store.put(...)` / `.add(...)` resolve to the key that
    /// was written.
    pub(super) fn expr_is_idb_value_request(&self, expr: &Expression<'a>) -> bool {
        let Expression::CallExpression(call) = expr else {
            return false;
        };
        let Some(method) = self.get_callee_property_name(&call.callee) else {
            return false;
        };
        if !matches!(
            method.as_str(),
            "get" | "getAll" | "getAllKeys" | "openCursor" | "openKeyCursor"
        ) {
            return false;
        }
        let Some(receiver) = self.get_callee_object_expr(&call.callee) else {
            return false;
        };
        let Expression::CallExpression(store_call) = receiver else {
            return false;
        };
        matches!(
            self.get_callee_property_name(&store_call.callee).as_deref(),
            Some("objectStore" | "index")
        )
    }

    /// Record `el.style.setProperty('--name', tainted)` so a later
    /// `getPropertyValue('--name')` reads back tainted.
    ///
    /// Only custom properties (`--*`) are tracked: the CSSOM stores their value
    /// as the author wrote it, while a standard property is parsed and
    /// serialized back, so what a read returns is not the input string.
    pub(super) fn record_css_custom_property_write(&mut self, call: &CallExpression<'a>) {
        if self.get_callee_property_name(&call.callee).as_deref() != Some("setProperty") {
            return;
        }
        let Some(name) = Self::extract_static_string_argument(call, 0) else {
            return;
        };
        if !name.starts_with("--") {
            return;
        }
        let Some(value) = call.arguments.get(1) else {
            return;
        };
        let (tainted, source) = self.argument_taint_and_source(value);
        if !tainted {
            return;
        }
        self.css_custom_property_sources
            .insert(name, source.unwrap_or_else(|| "unknown source".to_string()));
    }
    /// Source label when `call` reads back a CSS custom property this script
    /// previously wrote a tainted value into.
    pub(super) fn css_custom_property_read_source(
        &self,
        call: &CallExpression<'a>,
    ) -> Option<String> {
        if self.get_callee_property_name(&call.callee).as_deref() != Some("getPropertyValue") {
            return None;
        }
        let name = Self::extract_static_string_argument(call, 0)?;
        self.css_custom_property_sources.get(&name).cloned()
    }
}
