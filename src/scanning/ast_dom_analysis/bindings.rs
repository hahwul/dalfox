//! What a binding holds.
//!
//! `bind_declarator_identifier` records the source (or sink alias, or promise
//! kind) a `let`/`const` name now stands for; `find_source_in_expr` answers the
//! same question for an arbitrary expression.

use super::*;

impl<'a> DomXssVisitor<'a> {
    /// `const x = <init>` where the binding is a plain identifier.
    ///
    /// The bulk of declarator handling: alias tracking, source binding, taint
    /// propagation and the Trusted Types policy bookkeeping all key off the
    /// bound name, which the destructuring forms below do not have.
    pub(super) fn bind_declarator_identifier(
        &mut self,
        id: &BindingIdentifier<'a>,
        init: &Expression<'a>,
    ) {
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
            // `const m = new Message(tainted)` — record the accessor reads that
            // now hand the tainted constructor argument back out, so a later
            // `m.body` resolves without re-deriving the construction.
            self.seed_instance_field_taints(
                var_name,
                class_id.name.as_str(),
                &new_expr.arguments,
            );
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

        // `const req = store.get(key)` — remember the request so its
        // `onsuccess` handler is walked with the stored record treated as
        // untrusted, and so a direct `req.result` read resolves.
        if self.expr_is_idb_value_request(init) {
            self.idb_request_vars.insert(var_name.to_string());
            self.field_taints
                .insert(format!("{var_name}.result"), "indexedDB".to_string());
        } else {
            self.idb_request_vars.remove(var_name);
        }

        // `let s = document.createElement('script')` — remember the
        // variable so a later `s.text = tainted` is recognised as a
        // sink even though `text` is a benign property on every
        // other element kind. Also covers element lookups that
        // statically resolve to a `<script>` element
        // (`getElementById('script-id')`, `querySelector('script')`,
        // `document.scripts[N]`, …).
        if self.expr_creates_script_element(init) || self.expr_resolves_to_script_element(init) {
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
            && (callee_str == "localStorage.getItem" || callee_str == "sessionStorage.getItem")
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
                        self.clone_url_search_params_field_sources_from_expr(source_expr, var_name);
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
    /// Find a source in an expression (for alias tracking).
    ///
    /// Mirrors the recursion guard in [`is_tainted`]: a deeply nested
    /// attacker-controlled expression would otherwise overflow the stack here
    /// and abort the scanner. Returns `None` (no source found) once the shared
    /// recursion depth reaches [`MAX_AST_VISIT_DEPTH`].
    pub(super) fn find_source_in_expr(&self, expr: &Expression<'a>) -> Option<String> {
        let _guard = self.enter_recursion()?;
        match expr {
            Expression::Identifier(id) => self.var_aliases.get(id.name.as_str()).cloned(),
            Expression::StaticMemberExpression(member) => {
                if let Some(source) = self.url_search_params_source_for_member(member) {
                    return Some(source);
                }
                if let Some(source) = self.class_accessor_taint_source(member) {
                    return Some(source);
                }
                if let Some(source) = self.xhr_response_source_for_member(member) {
                    return Some(source);
                }
                if let Some(source) = self.file_reader_source_for_member(member) {
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
            Expression::TaggedTemplateExpression(tagged) => self.tagged_template_source(tagged),
            Expression::NewExpression(new_expr) => self
                .taint_forwarding_new_argument(new_expr)
                .and_then(|arg| self.find_source_in_expr(arg)),
            _ => None,
        }
    }

    /// Mark the properties of `var_name` that read back a tainted constructor
    /// argument of `class_name` — the stored fields themselves, and every
    /// getter that aliases one.
    pub(super) fn seed_instance_field_taints(
        &mut self,
        var_name: &str,
        class_name: &str,
        args: &[Argument<'a>],
    ) {
        let prefix = format!("{class_name}.");
        let fields: Vec<(String, usize)> = self
            .class_ctor_param_fields
            .iter()
            .filter_map(|(key, idx)| key.strip_prefix(&prefix).map(|f| (f.to_string(), *idx)))
            .collect();
        if fields.is_empty() {
            return;
        }
        let getters: Vec<(String, String)> = self
            .class_getter_fields
            .iter()
            .filter_map(|(key, field)| {
                key.strip_prefix(&prefix)
                    .map(|g| (g.to_string(), field.clone()))
            })
            .collect();

        for (field, idx) in &fields {
            let Some(arg) = args.get(*idx) else {
                continue;
            };
            let (tainted, source) = self.argument_taint_and_source(arg);
            if !tainted {
                continue;
            }
            let source = source.unwrap_or_else(|| "unknown source".to_string());
            self.field_taints
                .insert(format!("{var_name}.{field}"), source.clone());
            for (getter, getter_field) in &getters {
                if getter_field == field {
                    self.field_taints
                        .insert(format!("{var_name}.{getter}"), source.clone());
                }
            }
        }
    }
}
