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
        let saved_tainted = self.tainted_vars.clone();
        let saved_aliases = self.var_aliases.clone();
        let saved_field_taints = self.field_taints.clone();

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

        self.walk_statements(statements);

        self.tainted_vars = saved_tainted;
        self.var_aliases = saved_aliases;
        self.field_taints = saved_field_taints;
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
    pub(super) fn analyze_onmessage_assignment(
        &mut self,
        span: oxc_span::Span,
        receiver: &Expression<'a>,
        property_name: &str,
        right: &Expression<'a>,
    ) {
        if property_name != "onmessage" {
            return;
        }

        match right {
            Expression::FunctionExpression(func) => {
                if let Some(param) = func.params.items.first()
                    && let BindingPattern::BindingIdentifier(id) = &param.pattern
                    && let Some(body) = &func.body
                {
                    let event_source = self.message_event_source_for_receiver(receiver);
                    self.walk_event_handler_body(id.name.as_str(), &event_source, &body.statements);
                }
            }
            Expression::ArrowFunctionExpression(arrow) => {
                if let Some(param) = arrow.params.items.first()
                    && let BindingPattern::BindingIdentifier(id) = &param.pattern
                {
                    let event_source = self.message_event_source_for_receiver(receiver);
                    self.walk_event_handler_body(
                        id.name.as_str(),
                        &event_source,
                        &arrow.body.statements,
                    );
                }
            }
            Expression::Identifier(handler_id) => {
                if let Some(sink_name) = self
                    .function_summaries
                    .get(handler_id.name.as_str())
                    .and_then(|summary| summary.tainted_param_sinks.get(&0))
                    .cloned()
                {
                    self.report_vulnerability_with_source(
                        span,
                        &sink_name,
                        "Tainted message event data may reach sink through callback",
                        Some(self.message_event_source_for_receiver(receiver)),
                    );
                }
            }
            _ => {}
        }
    }
}
