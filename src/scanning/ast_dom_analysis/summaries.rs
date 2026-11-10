//! Function summaries.
//!
//! A sink reached inside a helper is only a finding when a tainted value can
//! reach that helper's parameter, so declarations are collected ahead of the
//! walk and recorded as which parameter flows to which sink.

use super::*;

/// A reported sink, as `(line, column, sink)`.
type Report = (u32, u32, String);

impl<'a> DomXssVisitor<'a> {
    /// Walk through statements
    pub(super) fn walk_statements(&mut self, stmts: &[Statement<'a>]) {
        self.collect_function_declarations(stmts);
        for stmt in stmts {
            self.walk_statement(stmt);
        }
    }
    /// Collect function declarations before statement traversal so hoisted calls are recognized.
    pub(super) fn collect_function_declarations(&mut self, stmts: &[Statement<'a>]) {
        for stmt in stmts {
            let func_decl = match stmt {
                Statement::FunctionDeclaration(func_decl) => func_decl,
                Statement::ExportNamedDeclaration(export) => match &export.declaration {
                    Some(Declaration::FunctionDeclaration(func_decl)) => func_decl,
                    _ => continue,
                },
                Statement::ExportDefaultDeclaration(export) => match &export.declaration {
                    ExportDefaultDeclarationKind::FunctionDeclaration(func_decl) => func_decl,
                    _ => continue,
                },
                // `W.prototype.render = function () { … }` is as much a
                // declaration: `function W() { on('message', this.render) }`
                // above it must find the method.
                Statement::ExpressionStatement(stmt) => {
                    if let Expression::AssignmentExpression(assign) = &stmt.expression
                        && let Some((ctor, method, func)) = Self::prototype_method(assign)
                        && let Some(body) = &func.body
                    {
                        self.register_function_summary(
                            format!("{ctor}.{method}"),
                            &func.params,
                            &body.statements,
                            false,
                        );
                    }
                    continue;
                }
                _ => continue,
            };
            self.register_function_declaration(func_decl);
        }
    }
    /// `(W, render, fn)` of `W.prototype.render = function () { … }`.
    pub(super) fn prototype_method<'b>(
        assign: &'b AssignmentExpression<'a>,
    ) -> Option<(&'b str, &'b str, &'b Function<'a>)> {
        if let AssignmentTarget::StaticMemberExpression(target) = &assign.left
            && let Expression::StaticMemberExpression(proto) = &target.object
            && proto.property.name == "prototype"
            && let Expression::Identifier(ctor) = &proto.object
            && let Expression::FunctionExpression(func) = &assign.right
        {
            return Some((ctor.name.as_str(), target.property.name.as_str(), func));
        }
        None
    }
    /// The first sink reported since `before` that the parameter-free pass
    /// (`free`) did not report too.
    fn first_param_sink(&self, before: usize, free: &HashSet<Report>) -> Option<String> {
        self.vulnerabilities[before..]
            .iter()
            .filter(|vuln| vuln.sink != "__return__")
            .map(|vuln| (vuln.line, vuln.column, vuln.sink.clone()))
            .find(|report| !free.contains(report))
            .map(|(_, _, sink)| sink)
    }
    /// Parameter names by position. A destructured parameter keeps its slot
    /// under an unbindable `#<index>` placeholder so the indices still line up
    /// with call-site arguments; the summary loop skips placeholders.
    pub(super) fn extract_param_names(&self, params: &FormalParameters<'a>) -> Vec<String> {
        params
            .items
            .iter()
            .enumerate()
            .map(|(idx, param)| match &param.pattern {
                BindingPattern::BindingIdentifier(id) => id.name.to_string(),
                _ => format!("#{idx}"),
            })
            .collect()
    }
    pub(super) fn register_function_summary(
        &mut self,
        function_name: String,
        formal_params: &FormalParameters<'a>,
        body_stmts: &[Statement<'a>],
        concise: bool,
    ) {
        self.arity_known.insert(formal_params.span);
        if let Some(existing) = self.function_summaries.get_mut(&function_name) {
            // Another function under the same name (minified bundles reuse
            // `e`/`t`): a call that leaves an argument out may be either.
            if existing.params_span != formal_params.span {
                existing.tainted_param_defaults.clear();
            }
            return;
        }

        // Insert placeholder summary first to avoid recursive self-analysis loops.
        self.function_summaries.insert(
            function_name.clone(),
            FunctionSummary {
                params_span: formal_params.span,
                ..Default::default()
            },
        );
        let params = self.extract_param_names(formal_params);
        // Read against the live state, before the passes below clear it. A
        // default fed by an enclosing summary pass's *assumed* parameter
        // (`fn_param_N`) is not a source.
        let tainted_param_defaults = formal_params
            .items
            .iter()
            .enumerate()
            .filter_map(|(idx, param)| {
                let default = param.initializer.as_deref()?;
                if !self.is_tainted(default) {
                    return None;
                }
                let source = self
                    .find_source_in_expr(default)
                    .unwrap_or_else(|| "unknown source".to_string());
                (!source.starts_with("fn_param_")).then_some((idx, source))
            })
            .collect();

        // The summary walk starts from empty taint/alias state (each pass
        // clears it below), so the live maps are moved out and moved back
        // rather than cloned; the state the walk only reads is journaled and
        // rolled back. Cloning it all made every hoisted declaration cost
        // O(live state) — O(N²) across a bundle of them.
        let saved_tainted = std::mem::take(&mut self.tainted_vars);
        let saved_aliases = std::mem::take(&mut self.var_aliases);
        let instance_classes_checkpoint = self.instance_classes.checkpoint();
        let bound_aliases_checkpoint = self.bound_function_aliases.checkpoint();
        let response_vars_checkpoint = self.response_object_vars.checkpoint();
        // The summary walk is *hypothetical* — it assumes each parameter in
        // turn is tainted — so any state it records must not leak into the real
        // walk. The CSS custom-property map is keyed by a global property name
        // rather than by a variable, so a helper that writes a parameter into
        // `--label` would otherwise leave every later `getPropertyValue('--label')`
        // reading tainted no matter what the helper was actually called with.
        let css_custom_properties_checkpoint = self.css_custom_property_sources.checkpoint();
        let idb_requests_checkpoint = self.idb_request_vars.checkpoint();
        let idb_stores_checkpoint = self.idb_object_store_vars.checkpoint();
        let image_vars_checkpoint = self.element_tag_vars.checkpoint();
        let saved_vuln_len = self.vulnerabilities.len();
        let saved_collecting_tainted_returns = self.collecting_tainted_returns;
        let saved_tainted_return_sources = std::mem::take(&mut self.tainted_return_sources);

        let mut summary = FunctionSummary {
            tainted_param_defaults,
            params_span: formal_params.span,
            ..Default::default()
        };

        // A per-parameter pass assumes its parameter is tainted, so the field
        // and global writes it makes are rolled back with it and recorded as
        // `tainted_param_writes` instead — applied only where a call actually
        // passes a tainted argument. Writes rooted at a local or a parameter
        // die with the call.
        // Every name each parameter slot binds: `{ q }`, `[a, b]` and a rest
        // parameter (one slot past the last) included, so `f({ q: tainted })`
        // reaches a sink on `q`.
        let mut param_bindings: Vec<Vec<String>> = formal_params
            .items
            .iter()
            .map(|param| {
                let mut names = Vec::new();
                Self::collect_binding_pattern_names(&param.pattern, &mut names);
                names
            })
            .collect();
        if let Some(rest) = &formal_params.rest {
            let mut names = Vec::new();
            Self::collect_binding_pattern_names(&rest.rest.argument, &mut names);
            param_bindings.push(names);
        }
        let mut declared = HashSet::new();
        Self::collect_declared_names(body_stmts, &mut declared);
        let mut locals: HashSet<String> = param_bindings.iter().flatten().cloned().collect();
        locals.extend(declared.iter().cloned());
        let local_names_checkpoint = self.local_names.checkpoint();
        let page_url_checkpoint = self.page_url_objects.checkpoint();
        let shadow_params_checkpoint = self.shadow_params.checkpoint();
        let url_lead_scope = self.url_leads_enter(&locals);
        let global_aliases_checkpoint = self.global_aliases.checkpoint();
        for name in &locals {
            self.global_aliases.remove(name.as_str());
            self.local_names.insert(name.clone());
            self.page_url_objects.remove(name.as_str());
        }
        // A local constructor `t` is not the outer `t` (see `named_this`).
        let shadowed_this: Vec<(String, usize)> = locals
            .iter()
            .filter_map(|name| Some((name.clone(), self.named_this.remove(name)?)))
            .collect();
        // A body-level declaration wins over a parameter of the same name.
        for name in param_bindings.iter().flatten() {
            self.shadow_params.insert(name.clone());
        }
        for name in &declared {
            self.shadow_params.remove(name.as_str());
        }
        let is_outer = |path: &String| {
            let root = path.split(['.', '[']).next().unwrap_or(path);
            !root.starts_with("this@") && !locals.contains(root)
        };
        // What each per-parameter pass reported, as `(line, column, sink)`.
        // A sink the body reaches with *no* parameter tainted (a free
        // `location.hash`, a tainted global) is not that parameter's flow, so
        // those are subtracted once the parameter-free pass below has run.
        let mut param_reports: Vec<(usize, Vec<Report>)> = Vec::new();
        for (idx, names) in param_bindings.iter().enumerate() {
            if names.is_empty() {
                continue;
            }
            let field_taints_checkpoint = self.field_taints.checkpoint();
            let global_taints_checkpoint = self.global_taints.checkpoint();
            self.tainted_vars.clear();
            self.var_aliases.clear();
            for name in names {
                self.tainted_vars.insert(name.clone());
                self.var_aliases
                    .insert(name.clone(), format!("fn_param_{}", idx));
            }
            self.collecting_tainted_returns = true;
            self.tainted_return_sources.clear();

            let before = self.vulnerabilities.len();
            self.summary_body_walk(formal_params, body_stmts, concise);
            param_reports.push((
                idx,
                self.vulnerabilities[before..]
                    .iter()
                    .filter(|vuln| vuln.sink != "__return__")
                    .map(|vuln| (vuln.line, vuln.column, vuln.sink.clone()))
                    .collect(),
            ));
            if let Some(source) = self.tainted_return_sources.first() {
                summary.tainted_param_returns.insert(idx, source.clone());
            }
            self.vulnerabilities.truncate(before);
            self.tainted_return_sources.clear();
            let fields: Vec<String> = self
                .field_taints
                .keys_added_since(&field_taints_checkpoint)
                .into_iter()
                .filter(is_outer)
                .collect();
            let globals: Vec<String> = self
                .global_taints
                .keys_added_since(&global_taints_checkpoint)
                .into_iter()
                .filter(is_outer)
                .collect();
            self.global_taints.rollback(global_taints_checkpoint);
            self.field_taints.rollback(field_taints_checkpoint);
            if !fields.is_empty() || !globals.is_empty() {
                summary.tainted_param_writes.insert(idx, (fields, globals));
            }
        }

        // Also capture return taint that does not depend on tainted parameters
        // (e.g., function directly returning location.hash)
        self.tainted_vars.clear();
        self.var_aliases.clear();
        self.collecting_tainted_returns = true;
        self.tainted_return_sources.clear();
        let before = self.vulnerabilities.len();
        // Not a parameter named for the global it is handed: `function
        // readCookie(document) { return document.cookie }`.
        let is_global = |name: &&String| {
            matches!(
                name.as_str(),
                "window" | "document" | "location" | "self" | "globalThis" | "top" | "parent"
            )
        };
        let outer_plain_params = std::mem::replace(
            &mut self.plain_params,
            params
                .iter()
                .filter(|name| !is_global(name))
                .cloned()
                .collect(),
        );
        // A global this pass taints stays tainted (`function () { g =
        // location.hash; }`), but its source label lives in `var_aliases`,
        // which is put back wholesale below — so carry the labels across.
        let global_taints_checkpoint = self.global_taints.checkpoint();
        self.summary_body_walk(formal_params, body_stmts, concise);
        let tainted_globals: Vec<(String, String)> = self
            .global_taints
            .keys_added_since(&global_taints_checkpoint)
            .into_iter()
            .filter_map(|name| {
                let source = self.var_aliases.get(&name).cloned()?;
                // An enclosing pass's assumed parameter is not a source.
                (!source.starts_with("fn_param_")).then_some((name, source))
            })
            .collect();
        self.global_taints.rollback(global_taints_checkpoint);
        for (name, _) in &tainted_globals {
            self.global_taints.insert(name.clone());
        }
        self.plain_params = outer_plain_params;
        // An enclosing summary pass's *assumed* parameter (`fn_param_N`,
        // reaching this body through a global it wrote) is not a source.
        if let Some(source) = self
            .tainted_return_sources
            .iter()
            .find(|source| !source.starts_with("fn_param_"))
        {
            summary.return_without_tainted_params = Some(source.clone());
        }
        let free: HashSet<Report> = self.vulnerabilities[before..]
            .iter()
            .map(|vuln| (vuln.line, vuln.column, vuln.sink.clone()))
            .collect();
        for (idx, reports) in &param_reports {
            if let Some((_, _, sink)) = reports.iter().find(|report| !free.contains(report)) {
                summary.tainted_param_sinks.insert(*idx, sink.clone());
            }
        }
        self.vulnerabilities.truncate(before);

        // A navigation sink is harmless to an argument whose first characters
        // the attacker does not write (see `url_lead`) — as long as the body
        // hands the argument on as it came. One more pass with the parameter
        // assumed to be such a value: what that still reports is what a
        // pinned argument reaches (`location.href = u.slice(1)`, a second
        // write to `innerHTML`).
        for (idx, names) in param_bindings.iter().enumerate() {
            if !summary
                .tainted_param_sinks
                .get(&idx)
                .is_some_and(|sink| is_navigation_sink(sink))
            {
                continue;
            }
            let field_taints_checkpoint = self.field_taints.checkpoint();
            let global_taints_checkpoint = self.global_taints.checkpoint();
            self.tainted_vars.clear();
            self.var_aliases.clear();
            for name in names {
                self.tainted_vars.insert(name.clone());
                self.var_aliases
                    .insert(name.clone(), format!("fn_param_{idx}"));
                self.url_leads
                    .insert(name.clone(), (UrlLead::Passive, true));
            }
            self.summary_body_walk(formal_params, body_stmts, concise);
            if let Some(sink) = self.first_param_sink(before, &free) {
                summary.pinned_param_sinks.insert(idx, sink);
            }
            self.vulnerabilities.truncate(before);
            for name in names {
                self.url_leads.remove(name.as_str());
            }
            self.global_taints.rollback(global_taints_checkpoint);
            self.field_taints.rollback(field_taints_checkpoint);
        }

        // As a `message` handler, parameter 0 is an event whose `origin` the
        // body may check (see `guards`): one more pass with that known, only
        // for a body that mentions an origin at all.
        if let Some(event) = params.first().filter(|name| !name.starts_with('#'))
            && summary.tainted_param_sinks.contains_key(&0)
            && let (Some(first), Some(last)) = (body_stmts.first(), body_stmts.last())
            && self
                .source_code
                .get(first.span().start as usize..last.span().end as usize)
                .is_some_and(|body| body.contains("origin"))
        {
            let field_taints_checkpoint = self.field_taints.checkpoint();
            let global_taints_checkpoint = self.global_taints.checkpoint();
            let origins_checkpoint = self.message_origins.checkpoint();
            self.tainted_vars.clear();
            self.var_aliases.clear();
            self.tainted_vars.insert(event.clone());
            self.var_aliases
                .insert(event.clone(), "fn_param_0".to_string());
            self.message_origins
                .insert(format!("{event}.origin"), vec![event.clone()]);
            let outer_deps = self.origin_guard_deps.take();
            self.summary_body_walk(formal_params, body_stmts, concise);
            summary.origin_guard_deps = self.origin_guard_deps.replace(outer_deps);
            summary.message_param_sink = Some(self.first_param_sink(before, &free));
            self.vulnerabilities.truncate(before);
            self.message_origins.rollback(origins_checkpoint);
            self.global_taints.rollback(global_taints_checkpoint);
            self.field_taints.rollback(field_taints_checkpoint);
        }

        self.tainted_vars = saved_tainted;
        self.var_aliases = saved_aliases;
        for (name, source) in tainted_globals {
            self.var_aliases.insert(name, source);
        }
        self.url_leads_exit(url_lead_scope, &locals);
        for name in &locals {
            self.named_this.remove(name);
        }
        self.named_this.extend(shadowed_this);
        self.instance_classes.rollback(instance_classes_checkpoint);
        self.bound_function_aliases
            .rollback(bound_aliases_checkpoint);
        self.response_object_vars.rollback(response_vars_checkpoint);
        self.css_custom_property_sources
            .rollback(css_custom_properties_checkpoint);
        self.idb_request_vars.rollback(idb_requests_checkpoint);
        self.idb_object_store_vars.rollback(idb_stores_checkpoint);
        self.element_tag_vars.rollback(image_vars_checkpoint);
        self.local_names.rollback(local_names_checkpoint);
        self.page_url_objects.rollback(page_url_checkpoint);
        self.shadow_params.rollback(shadow_params_checkpoint);
        self.global_aliases.rollback(global_aliases_checkpoint);
        self.vulnerabilities.truncate(saved_vuln_len);
        self.collecting_tainted_returns = saved_collecting_tainted_returns;
        self.tainted_return_sources = saved_tainted_return_sources;

        self.function_summaries.insert(function_name, summary);
    }
    /// One hypothetical walk of a summarised function's body.
    fn summary_body_walk(
        &mut self,
        formal_params: &FormalParameters<'a>,
        body_stmts: &[Statement<'a>],
        concise: bool,
    ) {
        let body_frame = self.enter_body();
        self.with_function_this(formal_params, |v| v.walk_statements(body_stmts));
        if concise {
            self.collect_concise_return(body_stmts);
        }
        self.leave_body(body_frame);
    }
    /// A concise arrow (`n => expr`) has no `return` statement — its body
    /// *is* the returned expression — so record it the way the `return` walk
    /// in `walk_statement` would.
    fn collect_concise_return(&mut self, body_stmts: &[Statement<'a>]) {
        let Some(Statement::ExpressionStatement(stmt)) = body_stmts.first() else {
            return;
        };
        if self.is_tainted(&stmt.expression) {
            let source = self
                .find_source_in_expr(&stmt.expression)
                .unwrap_or_else(|| "unknown source".to_string());
            self.tainted_return_sources.push(source);
        }
    }
    pub(super) fn register_function_declaration(&mut self, func_decl: &Function<'a>) {
        let Some(id) = &func_decl.id else {
            return;
        };
        let Some(body) = &func_decl.body else {
            return;
        };
        self.register_function_summary(
            id.name.to_string(),
            &func_decl.params,
            &body.statements,
            false,
        );
    }
    pub(super) fn register_object_literal_method_summaries(
        &mut self,
        object_name: &str,
        obj: &ObjectExpression<'a>,
    ) {
        for prop in &obj.properties {
            let ObjectPropertyKind::ObjectProperty(p) = prop else {
                continue;
            };
            let Some(method_name) = self.get_property_key_name(&p.key) else {
                continue;
            };
            let summary_name = format!("{}.{}", object_name, method_name);

            match &p.value {
                Expression::FunctionExpression(func_expr) => {
                    if let Some(body) = &func_expr.body {
                        self.register_function_summary(
                            summary_name.clone(),
                            &func_expr.params,
                            &body.statements,
                            false,
                        );
                    }
                    // `{ get v() { return location.hash } }` — reading `o.v`
                    // runs the getter.
                    if p.kind == PropertyKind::Get
                        && let Some(source) = self
                            .summary(&summary_name)
                            .and_then(|summary| summary.return_without_tainted_params.clone())
                    {
                        self.field_taints.insert(summary_name, source);
                    }
                }
                Expression::ArrowFunctionExpression(arrow_expr) => {
                    self.register_function_summary(
                        summary_name,
                        &arrow_expr.params,
                        &arrow_expr.body.statements,
                        arrow_expr.expression,
                    );
                }
                _ => {}
            }
        }
    }
    pub(super) fn register_class_method_summaries_for_name(
        &mut self,
        class_name: &str,
        class_decl: &Class<'a>,
    ) {
        self.register_class_accessor_fields(class_name, class_decl);
        for elem in &class_decl.body.body {
            // `onMessage = (e) => { … }` is a method in all but spelling.
            if let ClassElement::PropertyDefinition(property) = elem
                && let Some(name) = self.get_property_key_name(&property.key)
            {
                let key = format!("{class_name}.{name}");
                match &property.value {
                    Some(Expression::ArrowFunctionExpression(arrow)) => self
                        .register_function_summary(
                            key,
                            &arrow.params,
                            &arrow.body.statements,
                            arrow.expression,
                        ),
                    Some(Expression::FunctionExpression(func)) => {
                        if let Some(body) = &func.body {
                            self.register_function_summary(
                                key,
                                &func.params,
                                &body.statements,
                                false,
                            );
                        }
                    }
                    _ => {}
                }
                continue;
            }
            let ClassElement::MethodDefinition(method_def) = elem else {
                continue;
            };
            if !matches!(
                method_def.kind,
                MethodDefinitionKind::Method | MethodDefinitionKind::Constructor
            ) {
                continue;
            }
            let Some(method_name) = self.get_property_key_name(&method_def.key) else {
                continue;
            };
            let Some(body) = &method_def.value.body else {
                continue;
            };
            self.register_function_summary(
                format!("{}.{}", class_name, method_name),
                &method_def.value.params,
                &body.statements,
                false,
            );
        }
    }

    /// Record the two halves of the accessor indirection for `class_name`:
    /// which fields the constructor stores straight from a parameter, and which
    /// getters just hand a field back.
    ///
    /// Together they let `new C(tainted).accessor` resolve — a read the member
    /// walk cannot follow on its own, because the accessor is a function call
    /// whose body never mentions the constructor argument.
    ///
    /// Both halves are deliberately literal-minded. Only a bare
    /// `this.field = param` is a stored parameter, so a constructor that
    /// sanitizes (`this.field = escapeHtml(param)`) records nothing and the
    /// accessor reads clean; and only a getter whose body is `return this.field`
    /// is an alias, so a getter that formats or escapes its field records
    /// nothing either.
    pub(super) fn register_class_accessor_fields(
        &mut self,
        class_name: &str,
        class_decl: &Class<'a>,
    ) {
        for elem in &class_decl.body.body {
            let ClassElement::MethodDefinition(method_def) = elem else {
                continue;
            };
            let Some(body) = &method_def.value.body else {
                continue;
            };
            match method_def.kind {
                MethodDefinitionKind::Constructor => {
                    let params = self.extract_param_names(&method_def.value.params);
                    for stmt in &body.statements {
                        let Statement::ExpressionStatement(expr_stmt) = stmt else {
                            continue;
                        };
                        let Expression::AssignmentExpression(assign) = &expr_stmt.expression else {
                            continue;
                        };
                        if assign.operator != AssignmentOperator::Assign {
                            continue;
                        }
                        let AssignmentTarget::StaticMemberExpression(target) = &assign.left else {
                            continue;
                        };
                        if !matches!(target.object, Expression::ThisExpression(_)) {
                            continue;
                        }
                        let Expression::Identifier(rhs) = &assign.right else {
                            continue;
                        };
                        let Some(idx) = params.iter().position(|p| p == rhs.name.as_str()) else {
                            continue;
                        };
                        self.class_ctor_param_fields.insert(
                            format!("{class_name}.{}", target.property.name.as_str()),
                            idx,
                        );
                    }
                }
                MethodDefinitionKind::Get => {
                    let Some(getter_name) = self.get_property_key_name(&method_def.key) else {
                        continue;
                    };
                    for stmt in &body.statements {
                        let Statement::ReturnStatement(ret) = stmt else {
                            continue;
                        };
                        let Some(Expression::StaticMemberExpression(member)) = &ret.argument else {
                            continue;
                        };
                        if !matches!(member.object, Expression::ThisExpression(_)) {
                            continue;
                        }
                        self.class_getter_fields.insert(
                            format!("{class_name}.{getter_name}"),
                            member.property.name.to_string(),
                        );
                        break;
                    }
                }
                _ => {}
            }
        }
    }
}
