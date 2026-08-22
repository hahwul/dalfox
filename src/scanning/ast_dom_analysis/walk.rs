//! The traversal itself: statements, declarators, and expressions.
//!
//! Every other module in here is reached from this walk, which is also where the
//! recursion guard is taken — hostile deeply-nested input would otherwise
//! overflow the stack before any analysis happens.

use super::*;

impl<'a> DomXssVisitor<'a> {
    /// Walk through a single statement.
    ///
    /// Nested statements (`if(a)if(b)…`, `for(;;)for(;;)…`, nested blocks)
    /// recurse here, so the shared recursion guard bounds statement nesting the
    /// same way it bounds expression nesting — stopping past
    /// [`MAX_AST_VISIT_DEPTH`] so a hostile chain that parsed (on the large
    /// analysis stack) can't overflow the walk.
    pub(super) fn walk_statement(&mut self, stmt: &Statement<'a>) {
        let Some(_guard) = self.enter_recursion() else {
            return;
        };
        match stmt {
            Statement::VariableDeclaration(var_decl) => {
                for decl in &var_decl.declarations {
                    self.walk_variable_declarator(decl);
                }
            }
            Statement::ExpressionStatement(expr_stmt) => {
                self.walk_expression(&expr_stmt.expression);
            }
            Statement::BlockStatement(block) => {
                self.walk_statements(&block.body);
            }
            Statement::IfStatement(if_stmt) => {
                self.walk_expression(&if_stmt.test);
                // Branch bodies are conditional: suppress detaint inside them.
                self.branch_depth += 1;
                self.walk_statement(&if_stmt.consequent);
                if let Some(alt) = &if_stmt.alternate {
                    self.walk_statement(alt);
                }
                self.branch_depth -= 1;
            }
            Statement::WhileStatement(while_stmt) => {
                self.walk_expression(&while_stmt.test);
                self.branch_depth += 1;
                self.walk_statement(&while_stmt.body);
                self.branch_depth -= 1;
            }
            Statement::ForStatement(for_stmt) => {
                // `init` runs unconditionally; `update`/`body` are conditional.
                match &for_stmt.init {
                    Some(ForStatementInit::VariableDeclaration(var_decl)) => {
                        for decl in &var_decl.declarations {
                            self.walk_variable_declarator(decl);
                        }
                    }
                    // Expression-form init (`for (x = location.hash; …)`): the
                    // assignment runs unconditionally, so walk it so its taint is
                    // tracked into the body (otherwise a downstream sink is missed).
                    Some(init) => {
                        if let Some(expr) = init.as_expression() {
                            self.walk_expression(expr);
                        }
                    }
                    None => {}
                }
                if let Some(test) = &for_stmt.test {
                    self.walk_expression(test);
                }
                self.branch_depth += 1;
                if let Some(update) = &for_stmt.update {
                    self.walk_expression(update);
                }
                self.walk_statement(&for_stmt.body);
                self.branch_depth -= 1;
            }
            // `for (x of iterable)`: iterating a tainted iterable yields tainted
            // elements, so taint the loop binding when the right-hand expression
            // is tainted. Without this arm the old catch-all `_ => {}` dropped the
            // body entirely — a false negative for source->sink flows inside this
            // common (especially minified) loop form.
            Statement::ForOfStatement(for_of) => {
                self.walk_expression(&for_of.right);
                if self.is_tainted(&for_of.right)
                    && let ForStatementLeft::VariableDeclaration(var_decl) = &for_of.left
                {
                    for decl in &var_decl.declarations {
                        if let BindingPattern::BindingIdentifier(id) = &decl.id {
                            self.tainted_vars.insert(id.name.to_string());
                        }
                    }
                }
                self.branch_depth += 1;
                self.walk_statement(&for_of.body);
                self.branch_depth -= 1;
            }
            // `for (k in obj)` binds property *keys* (strings), not the iterated
            // values, so don't taint the binding; still walk the iterated
            // expression and the body so sources/sinks inside them are seen.
            Statement::ForInStatement(for_in) => {
                self.walk_expression(&for_in.right);
                self.branch_depth += 1;
                self.walk_statement(&for_in.body);
                self.branch_depth -= 1;
            }
            Statement::DoWhileStatement(do_while) => {
                self.branch_depth += 1;
                self.walk_statement(&do_while.body);
                self.branch_depth -= 1;
                self.walk_expression(&do_while.test);
            }
            // A labeled statement (`loop: for (…) …`) just wraps its body; walk
            // through so the labeled loop/block isn't skipped.
            Statement::LabeledStatement(labeled) => {
                self.walk_statement(&labeled.body);
            }
            Statement::FunctionDeclaration(func_decl) => {
                // Parameterized functions are primarily handled through summaries/call sites.
                // Walking bodies here can duplicate findings when summaries are also applied.
                // Keep direct walk only for zero-parameter functions where call-site summaries
                // cannot currently represent source->sink usage.
                if func_decl.params.items.is_empty()
                    && let Some(body) = &func_decl.body
                {
                    // Save current tainted vars state
                    let saved_tainted = self.tainted_vars.clone();
                    let saved_aliases = self.var_aliases.clone();
                    let saved_response_vars = self.response_object_vars.clone();

                    self.walk_statements(&body.statements);

                    // Restore state after function (locals don't leak out —
                    // e.g. a `const r = await fetch()` Response binding must
                    // not taint an unrelated outer `r.text()`).
                    self.tainted_vars = saved_tainted;
                    self.var_aliases = saved_aliases;
                    self.response_object_vars = saved_response_vars;
                }
            }
            Statement::ClassDeclaration(class_decl) => {
                if let Some(class_id) = &class_decl.id {
                    self.register_class_method_summaries_for_name(
                        class_id.name.as_str(),
                        class_decl,
                    );
                }
            }
            Statement::ReturnStatement(return_stmt) => {
                if let Some(argument) = &return_stmt.argument {
                    if self.collecting_tainted_returns && self.is_tainted(argument) {
                        let source = self
                            .find_source_in_expr(argument)
                            .unwrap_or_else(|| "unknown source".to_string());
                        self.tainted_return_sources.push(source);
                    }
                    self.walk_expression(argument);
                }
            }
            Statement::SwitchStatement(switch_stmt) => {
                self.walk_expression(&switch_stmt.discriminant);
                self.branch_depth += 1;
                for case in &switch_stmt.cases {
                    if let Some(test) = &case.test {
                        self.walk_expression(test);
                    }
                    self.walk_statements(&case.consequent);
                }
                self.branch_depth -= 1;
            }
            Statement::TryStatement(try_stmt) => {
                // `catch`/`finally` are conditional; the `try` block may also
                // abort partway, so treat the whole construct as a branch.
                self.branch_depth += 1;
                self.walk_statements(&try_stmt.block.body);
                if let Some(handler) = &try_stmt.handler {
                    self.walk_statements(&handler.body.body);
                }
                if let Some(finalizer) = &try_stmt.finalizer {
                    self.walk_statements(&finalizer.body);
                }
                self.branch_depth -= 1;
            }
            _ => {}
        }
    }
    /// Walk through a variable declarator, dispatching on the binding form:
    /// a plain identifier, object destructuring, or array destructuring.
    pub(super) fn walk_variable_declarator(&mut self, decl: &VariableDeclarator<'a>) {
        if let Some(init) = &decl.init {
            if let BindingPattern::BindingIdentifier(id) = &decl.id {
                self.bind_declarator_identifier(id, init);
            }

            // Handle object destructuring: const { a, b } = tainted → a, b all tainted
            if let BindingPattern::ObjectPattern(obj_pat) = &decl.id
                && self.is_tainted(init)
            {
                let source = self.find_source_in_expr(init);
                for prop in &obj_pat.properties {
                    if let BindingPattern::BindingIdentifier(id) = &prop.value {
                        let name = id.name.to_string();
                        self.tainted_vars.insert(name.clone());
                        self.global_taints.insert(name.clone());
                        if let Some(ref src) = source {
                            self.var_aliases.insert(name, src.clone());
                        }
                    }
                }
                if let Some(rest) = &obj_pat.rest
                    && let BindingPattern::BindingIdentifier(id) = &rest.argument
                {
                    let name = id.name.to_string();
                    self.tainted_vars.insert(name.clone());
                    self.global_taints.insert(name.clone());
                    if let Some(ref src) = source {
                        self.var_aliases.insert(name, src.clone());
                    }
                }
            }

            // Handle array destructuring: const [a, b] = tainted → a, b all tainted
            if let BindingPattern::ArrayPattern(arr_pat) = &decl.id
                && self.is_tainted(init)
            {
                let source = self.find_source_in_expr(init);
                for elem in arr_pat.elements.iter().flatten() {
                    if let BindingPattern::BindingIdentifier(id) = &elem {
                        let name = id.name.to_string();
                        self.tainted_vars.insert(name.clone());
                        self.global_taints.insert(name.clone());
                        if let Some(ref src) = source {
                            self.var_aliases.insert(name, src.clone());
                        }
                    }
                }
            }

            // Walk the init expression to detect any sinks used in the initializer
            self.walk_expression(init);
        }
    }
    /// Walk through an expression.
    ///
    /// Guards the same way as [`is_tainted`]: member / binary / logical /
    /// conditional chains (and, via `walk_call_expression`, flat call chains)
    /// recurse here, so a hostile deeply nested expression would overflow the
    /// stack and SIGABRT the scanner. The shared recursion guard stops
    /// descending past [`MAX_AST_VISIT_DEPTH`].
    pub(super) fn walk_expression(&mut self, expr: &Expression<'a>) {
        let Some(_guard) = self.enter_recursion() else {
            return;
        };
        match expr {
            Expression::AssignmentExpression(assign) => {
                self.walk_assignment_expression(assign);
            }
            Expression::CallExpression(call) => {
                self.walk_call_expression(call);
            }
            Expression::TemplateLiteral(template) => {
                for e in &template.expressions {
                    self.walk_expression(e);
                }
            }
            Expression::BinaryExpression(binary) => {
                self.walk_expression(&binary.left);
                self.walk_expression(&binary.right);
            }
            Expression::LogicalExpression(logical) => {
                self.walk_expression(&logical.left);
                self.walk_expression(&logical.right);
            }
            Expression::ConditionalExpression(cond) => {
                self.walk_expression(&cond.test);
                self.walk_expression(&cond.consequent);
                self.walk_expression(&cond.alternate);
            }
            Expression::NewExpression(new_expr) => {
                // Handle new Function(tainted) - constructor calls with tainted arguments
                if let Expression::Identifier(id) = &new_expr.callee {
                    let callee_name = id.name.as_str();
                    // Check if this is a sink constructor (e.g., Function)
                    if self.sinks.contains(callee_name) {
                        for arg in &new_expr.arguments {
                            let arg_expr = match arg {
                                Argument::SpreadElement(spread) => Some(&spread.argument),
                                _ => arg.as_expression(),
                            };
                            let is_arg_tainted = arg_expr.is_some_and(|e| self.is_tainted(e));
                            if is_arg_tainted {
                                // Propagate the originating source (e.g.
                                // `URLSearchParams.get('q')`) instead of
                                // letting the finding fall back to
                                // "unknown source". CallExpression sinks
                                // already do this — mirror it here so
                                // `new Function(...)` carries the same
                                // provenance string into the report.
                                let source = arg_expr.and_then(|e| self.find_source_in_expr(e));
                                self.report_vulnerability_with_source(
                                    new_expr.span(),
                                    callee_name,
                                    "Tainted data passed to constructor",
                                    source,
                                );
                                break;
                            }
                        }
                    }
                }
            }
            // Anonymous function expressions assigned to globals
            // (`window.onload = function () { … }`,
            // `addEventListener("load", function () { … })`, IIFE
            // wrappers) used to short-circuit here, so any taint flow
            // inside their body was invisible to the analyzer — the
            // xss-game level 3 shape (hash → `chooseTab(…)` inside a
            // `window.onload = function () {}` body) slipped through.
            // Walk the function body so call expressions inside reach
            // `walk_call_expression`, where the function-summary
            // lookup fires the sink finding.
            Expression::FunctionExpression(func) => {
                if let Some(body) = &func.body {
                    self.walk_statements(&body.statements);
                }
            }
            Expression::ArrowFunctionExpression(arrow) => {
                self.walk_statements(&arrow.body.statements);
            }
            // Dynamic `import(tainted)` runs an attacker-controlled module
            // (issue #1022). Detect it here; reached both as a bare statement
            // (`import(t);`) and as the object of a chain (`import(t).then(…)`)
            // via the member-object recursion below.
            Expression::ImportExpression(import_expr) => {
                self.walk_import_expression(import_expr);
            }
            Expression::AwaitExpression(await_expr) => {
                self.walk_expression(&await_expr.argument);
            }
            Expression::ParenthesizedExpression(paren) => {
                self.walk_expression(&paren.expression);
            }
            Expression::SequenceExpression(seq) => {
                for e in &seq.expressions {
                    self.walk_expression(e);
                }
            }
            // Reach call / import expressions that sit as the *object* of a
            // member access — e.g. `$(tainted).appendTo(...)`,
            // `import(tainted).then(...)`, `eval(tainted).x`. A member-callee
            // chain otherwise never visits its leftmost operand.
            Expression::StaticMemberExpression(member) => {
                self.walk_expression(&member.object);
            }
            Expression::ComputedMemberExpression(member) => {
                self.walk_expression(&member.object);
                self.walk_expression(&member.expression);
            }

            _ => {}
        }
    }
    /// Report `import(tainted)` as a code-execution sink and walk the
    /// specifier for any nested sinks. A tainted module specifier (a
    /// `data:text/javascript,…` URL or a remote/`//host` URL derived from
    /// `location.*`, `URLSearchParams`, `name`, `document.referrer`, …) loads
    /// and runs an attacker-controlled ES module — a real DOM XSS.
    pub(super) fn walk_import_expression(&mut self, import_expr: &ImportExpression<'a>) {
        if self.is_tainted(&import_expr.source) {
            let source = self.find_source_in_expr(&import_expr.source);
            self.report_vulnerability_with_source(
                import_expr.span,
                "import",
                "Tainted module specifier passed to dynamic import() runs attacker-controlled module code",
                source,
            );
        }
        self.walk_expression(&import_expr.source);
    }
}
