//! Function summaries.
//!
//! A sink reached inside a helper is only a finding when a tainted value can
//! reach that helper's parameter, so declarations are collected ahead of the
//! walk and recorded as which parameter flows to which sink.

use super::*;

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
            if let Statement::FunctionDeclaration(func_decl) = stmt {
                self.register_function_declaration(func_decl.as_ref());
            }
        }
    }
    pub(super) fn extract_param_names(&self, params: &FormalParameters<'a>) -> Vec<String> {
        params
            .items
            .iter()
            .filter_map(|param| match &param.pattern {
                BindingPattern::BindingIdentifier(id) => Some(id.name.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>()
    }
    pub(super) fn register_function_summary(
        &mut self,
        function_name: String,
        params: Vec<String>,
        body_stmts: &[Statement<'a>],
    ) {
        if self.function_summaries.contains_key(&function_name) {
            return;
        }

        // Insert placeholder summary first to avoid recursive self-analysis loops.
        self.function_summaries.insert(
            function_name.clone(),
            FunctionSummary {
                tainted_param_sinks: HashMap::new(),
                tainted_param_returns: HashMap::new(),
                return_without_tainted_params: None,
            },
        );

        let saved_tainted = self.tainted_vars.clone();
        let saved_aliases = self.var_aliases.clone();
        let saved_instance_classes = self.instance_classes.clone();
        let saved_bound_aliases = self.bound_function_aliases.clone();
        let saved_response_vars = self.response_object_vars.clone();
        let saved_vuln_len = self.vulnerabilities.len();
        let saved_collecting_tainted_returns = self.collecting_tainted_returns;
        let saved_tainted_return_sources = std::mem::take(&mut self.tainted_return_sources);

        let mut summary = FunctionSummary {
            tainted_param_sinks: HashMap::new(),
            tainted_param_returns: HashMap::new(),
            return_without_tainted_params: None,
        };

        for (idx, param_name) in params.iter().enumerate() {
            self.tainted_vars.clear();
            self.var_aliases.clear();
            self.tainted_vars.insert(param_name.clone());
            self.var_aliases
                .insert(param_name.clone(), format!("fn_param_{}", idx));
            self.collecting_tainted_returns = true;
            self.tainted_return_sources.clear();

            let before = self.vulnerabilities.len();
            self.walk_statements(body_stmts);
            for vuln in &self.vulnerabilities[before..] {
                if vuln.sink != "__return__" {
                    summary
                        .tainted_param_sinks
                        .entry(idx)
                        .or_insert_with(|| vuln.sink.clone());
                }
            }
            if let Some(source) = self.tainted_return_sources.first() {
                summary.tainted_param_returns.insert(idx, source.clone());
            }
            self.vulnerabilities.truncate(before);
            self.tainted_return_sources.clear();
        }

        // Also capture return taint that does not depend on tainted parameters
        // (e.g., function directly returning location.hash)
        self.tainted_vars.clear();
        self.var_aliases.clear();
        self.collecting_tainted_returns = true;
        self.tainted_return_sources.clear();
        let before = self.vulnerabilities.len();
        self.walk_statements(body_stmts);
        if let Some(source) = self.tainted_return_sources.first() {
            summary.return_without_tainted_params = Some(source.clone());
        }
        self.vulnerabilities.truncate(before);

        self.tainted_vars = saved_tainted;
        self.var_aliases = saved_aliases;
        self.instance_classes = saved_instance_classes;
        self.bound_function_aliases = saved_bound_aliases;
        self.response_object_vars = saved_response_vars;
        self.vulnerabilities.truncate(saved_vuln_len);
        self.collecting_tainted_returns = saved_collecting_tainted_returns;
        self.tainted_return_sources = saved_tainted_return_sources;

        self.function_summaries.insert(function_name, summary);
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
            self.extract_param_names(&func_decl.params),
            &body.statements,
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
                            summary_name,
                            self.extract_param_names(&func_expr.params),
                            &body.statements,
                        );
                    }
                }
                Expression::ArrowFunctionExpression(arrow_expr) => {
                    self.register_function_summary(
                        summary_name,
                        self.extract_param_names(&arrow_expr.params),
                        &arrow_expr.body.statements,
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
        for elem in &class_decl.body.body {
            let ClassElement::MethodDefinition(method_def) = elem else {
                continue;
            };
            if !matches!(method_def.kind, MethodDefinitionKind::Method) {
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
                self.extract_param_names(&method_def.value.params),
                &body.statements,
            );
        }
    }
}
