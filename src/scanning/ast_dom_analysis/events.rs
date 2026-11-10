//! Event handlers as an entry point.
//!
//! `addEventListener("message", …)` and `onmessage =` hand the callback a
//! `MessageEvent` whose `.data` is cross-origin input, so the parameter itself
//! is the source.

use super::*;

impl<'a> DomXssVisitor<'a> {
    pub(super) fn walk_event_handler_body(
        &mut self,
        param_name: &str,
        event_source: &str,
        statements: &oxc_allocator::Vec<'a, Statement<'a>>,
    ) {
        // Journal checkpoints, not clones — see `walk_function_literal_body`.
        let tainted_checkpoint = self.tainted_vars.checkpoint();
        let aliases_checkpoint = self.var_aliases.checkpoint();
        let field_taints_checkpoint = self.field_taints.checkpoint();
        let page_url_checkpoint = self.page_url_objects.checkpoint();
        self.page_url_objects.remove(param_name);
        let handler_locals = HashSet::from([param_name.to_string()]);
        let url_lead_scope = self.url_leads_enter(&handler_locals);
        let origins_checkpoint = self.message_origins.checkpoint();
        if event_source == "event.data" {
            self.message_origins
                .insert(format!("{param_name}.origin"), vec![param_name.to_string()]);
        }

        self.tainted_vars.insert(param_name.to_string());
        self.var_aliases
            .insert(param_name.to_string(), event_source.to_string());
        if matches!(event_source, "event.data" | "e.data") || event_source.ends_with(".message") {
            self.field_taints
                .insert(format!("{param_name}.data"), event_source.to_string());
        } else if event_source == "event.newValue" {
            self.field_taints.insert(
                format!("{param_name}.newValue"),
                "event.newValue".to_string(),
            );
            self.field_taints.insert(
                format!("{param_name}.oldValue"),
                "event.oldValue".to_string(),
            );
        } else if event_source == "e.target.value" || event_source == "event.target.value" {
            // Input/change events: e.target.value is user-controlled
            self.field_taints.insert(
                format!("{param_name}.target.value"),
                "e.target.value".to_string(),
            );
            self.field_taints
                .insert(format!("{param_name}.target"), "e.target.value".to_string());
        }

        let body_frame = self.enter_body();
        self.walk_statements(statements);
        self.leave_body(body_frame);

        self.message_origins.rollback(origins_checkpoint);
        self.url_leads_exit(url_lead_scope, &handler_locals);
        self.tainted_vars.rollback(tainted_checkpoint);
        self.var_aliases.rollback(aliases_checkpoint);
        self.rollback_fields_keeping_this(field_taints_checkpoint);
        self.page_url_objects.rollback(page_url_checkpoint);
    }
    /// Walk a handler whose event parameter is destructured —
    /// `({ data }) => …`. Only the properties that carry the untrusted value
    /// for this event kind are tainted; `origin`, `source`, `type` and the
    /// rest stay clean.
    pub(super) fn walk_destructured_event_handler_body(
        &mut self,
        pattern: &ObjectPattern<'a>,
        event_source: &str,
        statements: &oxc_allocator::Vec<'a, Statement<'a>>,
    ) {
        let tainted_fields: &[&str] = match event_source {
            "event.newValue" => &["newValue", "oldValue"],
            "e.target.value" | "event.target.value" | "indexedDB" => &["target"],
            "location.hash" => &["newURL", "oldURL"],
            "history.state" => &["state"],
            _ => &["data"],
        };
        let tainted_checkpoint = self.tainted_vars.checkpoint();
        let aliases_checkpoint = self.var_aliases.checkpoint();
        let field_taints_checkpoint = self.field_taints.checkpoint();
        let page_url_checkpoint = self.page_url_objects.checkpoint();
        let mut shadowed_globals = Vec::new();
        let mut handler_locals = Vec::new();
        for prop in &pattern.properties {
            Self::collect_binding_pattern_names(&prop.value, &mut handler_locals);
        }
        let handler_locals: HashSet<String> = handler_locals.into_iter().collect();
        let url_lead_scope = self.url_leads_enter(&handler_locals);
        // `({ origin, data }) => …`: a check on `origin` vouches for `data`.
        let origins_checkpoint = self.message_origins.checkpoint();
        if event_source == "event.data" {
            let bound = |key: &str| {
                let mut names = Vec::new();
                for prop in &pattern.properties {
                    if self.get_property_key_name(&prop.key).as_deref() == Some(key) {
                        Self::collect_binding_pattern_names(&prop.value, &mut names);
                    }
                }
                names
            };
            let carriers = bound("data");
            for origin in bound("origin") {
                self.message_origins.insert(origin, carriers.clone());
            }
        }
        for prop in &pattern.properties {
            if self
                .get_property_key_name(&prop.key)
                .is_some_and(|key| tainted_fields.contains(&key.as_str()))
            {
                self.taint_binding_pattern(&prop.value, event_source);
                continue;
            }
            // `({ origin }) => …` binds a clean `origin` over any outer one.
            let mut names = Vec::new();
            Self::collect_binding_pattern_names(&prop.value, &mut names);
            for name in names {
                self.page_url_objects.remove(name.as_str());
                self.tainted_vars.remove(name.as_str());
                self.var_aliases.remove(name.as_str());
                if self.global_taints.remove(name.as_str()) {
                    shadowed_globals.push(name);
                }
            }
        }
        let body_frame = self.enter_body();
        self.walk_statements(statements);
        self.leave_body(body_frame);
        self.message_origins.rollback(origins_checkpoint);
        self.url_leads_exit(url_lead_scope, &handler_locals);
        self.tainted_vars.rollback(tainted_checkpoint);
        self.var_aliases.rollback(aliases_checkpoint);
        self.rollback_fields_keeping_this(field_taints_checkpoint);
        self.page_url_objects.rollback(page_url_checkpoint);
        for name in shadowed_globals {
            self.global_taints.insert(name);
        }
    }
    /// Walk a handler body with its first parameter bound as the event, in
    /// either the plain (`e => …`) or destructured (`({ data }) => …`) form.
    /// False when the parameter has neither shape.
    pub(super) fn walk_event_handler_param(
        &mut self,
        param: Option<&FormalParameter<'a>>,
        event_source: &str,
        statements: &oxc_allocator::Vec<'a, Statement<'a>>,
    ) -> bool {
        match param.map(|p| &p.pattern) {
            Some(BindingPattern::BindingIdentifier(id)) => {
                self.walk_event_handler_body(id.name.as_str(), event_source, statements);
                true
            }
            Some(BindingPattern::ObjectPattern(pattern)) => {
                self.walk_destructured_event_handler_body(pattern, event_source, statements);
                true
            }
            _ => false,
        }
    }
    pub(super) fn message_event_source_for_receiver(&self, receiver: &Expression<'a>) -> String {
        // Descends a `.`-chain receiver outside the main walkers (reached from
        // onmessage assignments / addEventListener("message", …)), so it carries
        // the shared recursion guard, falling back to its generic default. A
        // hostile `a.a.a.….onmessage = fn` chain would otherwise overflow here.
        let Some(_guard) = self.enter_recursion() else {
            return "event.data".to_string();
        };
        match receiver {
            Expression::Identifier(id) => match self.instance_classes.get(id.name.as_str()) {
                Some(class_name) if class_name == "BroadcastChannel" => {
                    "BroadcastChannel.message".to_string()
                }
                Some(class_name) if class_name == "WebSocket" => "WebSocket.message".to_string(),
                Some(class_name) if class_name == "Worker" => "Worker.message".to_string(),
                Some(class_name) if class_name == "SharedWorker" => {
                    "SharedWorker.message".to_string()
                }
                Some(class_name) if class_name == "EventSource" => {
                    "EventSource.message".to_string()
                }
                Some(class_name) if class_name == "MessagePort" => {
                    "MessagePort.message".to_string()
                }
                _ => "event.data".to_string(),
            },
            Expression::StaticMemberExpression(member) => {
                if let Some(full_path) = self.get_member_string(member)
                    && full_path == "navigator.serviceWorker"
                {
                    return "ServiceWorker.message".to_string();
                }

                if matches!(member.property.name.as_str(), "port1" | "port2")
                    && let Expression::Identifier(id) = &member.object
                    && matches!(
                        self.instance_classes
                            .get(id.name.as_str())
                            .map(String::as_str),
                        Some("MessageChannel")
                    )
                {
                    return "MessagePort.message".to_string();
                }

                if member.property.name.as_str() == "port"
                    && let Expression::Identifier(id) = &member.object
                    && matches!(
                        self.instance_classes
                            .get(id.name.as_str())
                            .map(String::as_str),
                        Some("SharedWorker")
                    )
                {
                    return "SharedWorker.message".to_string();
                }

                self.message_event_source_for_receiver(&member.object)
            }
            _ => "event.data".to_string(),
        }
    }
    pub(super) fn event_listener_source(
        &self,
        receiver: &Expression<'a>,
        arg: Option<&Argument<'a>>,
    ) -> Option<String> {
        let event_name = arg
            .and_then(|arg| arg.as_expression())
            .and_then(|expr| match expr {
                Expression::StringLiteral(s) => Some(s.value.as_str()),
                _ => None,
            })?;

        if event_name.eq_ignore_ascii_case("message") {
            Some(self.message_event_source_for_receiver(receiver))
        } else if event_name.eq_ignore_ascii_case("storage") {
            Some("event.newValue".to_string())
        } else if matches!(
            event_name.to_ascii_lowercase().as_str(),
            "input" | "change" | "keyup" | "keydown" | "keypress" | "paste" | "cut"
        ) {
            // User-controlled input events: e.target.value is the tainted source
            Some("e.target.value".to_string())
        } else if event_name.eq_ignore_ascii_case("hashchange") {
            Some("location.hash".to_string())
        } else if event_name.eq_ignore_ascii_case("popstate") {
            Some("history.state".to_string())
        } else {
            None
        }
    }
    /// `target.onmessage = handler` / `window.onstorage = handler`; a bare
    /// `onmessage = handler` (no `receiver`) sets the window's.
    pub(super) fn analyze_onmessage_assignment(
        &mut self,
        span: oxc_span::Span,
        receiver: Option<&Expression<'a>>,
        property_name: &str,
        right: &Expression<'a>,
    ) {
        let event_source = match (property_name, receiver) {
            ("onmessage", Some(receiver)) => self.message_event_source_for_receiver(receiver),
            ("onmessage", None) => "event.data".to_string(),
            ("onstorage", _) => "event.newValue".to_string(),
            _ => return,
        };

        match right {
            Expression::FunctionExpression(func) => {
                if let Some(body) = &func.body {
                    self.with_own_this(|v| {
                        v.walk_event_handler_param(
                            func.params.items.first(),
                            &event_source,
                            &body.statements,
                        )
                    });
                }
            }
            Expression::ArrowFunctionExpression(arrow) => {
                self.walk_event_handler_param(
                    arrow.params.items.first(),
                    &event_source,
                    &arrow.body.statements,
                );
            }
            handler => {
                if let Some(sink_name) = self
                    .handler_summary_key(handler)
                    .and_then(|key| self.summary_handler_sink(&key, &event_source))
                {
                    self.report_vulnerability_with_source(span, &sink_name, Some(event_source));
                }
            }
        }
    }

    /// The sink the handler summarised under `key` reaches when registered
    /// for an event from `event_source`.
    pub(super) fn summary_handler_sink(&self, key: &str, event_source: &str) -> Option<String> {
        let summary = self.summary(key)?;
        // An origin check against a value the attacker supplies vouches for
        // nothing: `if (e.origin !== allowedFromQuery) return;`.
        let unchecked = summary.origin_guard_deps.iter().any(|path| {
            let root = path.split('.').next().unwrap_or(path);
            self.tainted_vars.contains(root)
                || self.global_taints.contains(root)
                || self.field_taints.contains_key(path)
        });
        summary.handler_sink(event_source == "event.data" && !unchecked)
    }

    /// `debounce(function (e) { … }, 100)` — the handler is the function the
    /// wrapper was given. `handler.bind(this)` is left to
    /// [`handler_summary_key`](Self::handler_summary_key).
    pub(super) fn unwrap_handler<'b>(&self, handler: &'b Expression<'a>) -> &'b Expression<'a> {
        if let Expression::CallExpression(call) = handler.without_parentheses()
            && self.get_callee_property_name(&call.callee).as_deref() != Some("bind")
            && let Some(inner) = call
                .arguments
                .iter()
                .filter_map(|arg| arg.as_expression())
                .find(|arg| {
                    matches!(
                        arg,
                        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
                    )
                })
        {
            return inner;
        }
        handler
    }

    /// Summary key of a handler passed by reference rather than written
    /// inline: `handle`, `obj.handle`, `this.handle` inside a class, and any
    /// of those behind `.bind(…)`.
    pub(super) fn handler_summary_key(&self, handler: &Expression<'a>) -> Option<String> {
        match handler.without_parentheses() {
            Expression::CallExpression(call)
                if self.get_callee_property_name(&call.callee).as_deref() == Some("bind") =>
            {
                self.handler_summary_key(self.get_callee_object_expr(&call.callee)?)
            }
            // `const h = this.onMessage.bind(this); on('message', h)`.
            Expression::Identifier(id) if self.summary(id.name.as_str()).is_none() => Some(
                self.bound_function_aliases
                    .get(id.name.as_str())
                    .map_or_else(|| id.name.to_string(), |alias| alias.target.clone()),
            ),
            expr @ (Expression::Identifier(_) | Expression::StaticMemberExpression(_)) => {
                self.get_summary_key_for_callee_expr(expr)
            }
            _ => None,
        }
    }

    /// `request.onsuccess = function (ev) { … }` on an IndexedDB value request:
    /// walk the handler with its event parameter treated as untrusted, so the
    /// `ev.target.result` read inside resolves to the stored record.
    ///
    /// Reached from the assignment walk, which does not otherwise bind
    /// anything to a handler's parameter — the handler body *is* walked
    /// (it is the assignment's right-hand side), but with `ev` clean, so every
    /// flow out of the record was lost.
    pub(super) fn analyze_idb_success_assignment(
        &mut self,
        receiver: &Expression<'a>,
        property_name: &str,
        right: &Expression<'a>,
    ) {
        if property_name != "onsuccess" {
            return;
        }
        let is_value_request = match receiver {
            Expression::Identifier(id) => self.idb_request_vars.contains(id.name.as_str()),
            other => self.expr_is_idb_value_request(other),
        };
        if !is_value_request {
            return;
        }

        let (param, statements, owns_this) = match right {
            Expression::FunctionExpression(func) => {
                let Some(body) = &func.body else {
                    return;
                };
                (func.params.items.first(), &body.statements, true)
            }
            Expression::ArrowFunctionExpression(arrow) => {
                (arrow.params.items.first(), &arrow.body.statements, false)
            }
            _ => return,
        };
        let Some(BindingPattern::BindingIdentifier(id)) = param.map(|p| &p.pattern) else {
            return;
        };
        let param_name = id.name.to_string();
        // A cursor request hands the record one level deeper, on
        // `ev.target.result.value`; both spellings resolve through the
        // parameter binding `walk_event_handler_body` installs.
        if owns_this {
            self.with_own_this(|v| v.walk_event_handler_body(&param_name, "indexedDB", statements));
        } else {
            self.walk_event_handler_body(&param_name, "indexedDB", statements);
        }
    }
}
