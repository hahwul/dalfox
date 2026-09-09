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
                // Parameter *flows* belong to the summary registered for this
                // declaration and are reported at each call site. What the
                // summary cannot represent is a free variable the body reads
                // on its own (`function render(el) { el.innerHTML =
                // location.hash; }`), so the body is walked here too — with
                // its parameters shadowed, which is what keeps the two from
                // reporting the same flow twice.
                if let Some(body) = &func_decl.body {
                    self.walk_function_literal_body(&func_decl.params, &body.statements);
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
            Expression::ChainExpression(chain) => {
                self.branch_depth += 1;
                match &chain.expression {
                    ChainElement::CallExpression(call) => self.walk_call_expression(call),
                    ChainElement::StaticMemberExpression(member) => {
                        self.walk_expression(&member.object)
                    }
                    ChainElement::ComputedMemberExpression(member) => {
                        self.walk_expression(&member.object);
                        self.walk_expression(&member.expression);
                    }
                    _ => {}
                }
                self.branch_depth -= 1;
            }
            Expression::UnaryExpression(unary) => self.walk_expression(&unary.argument),
            Expression::ArrayExpression(array) => {
                for element in &array.elements {
                    if let ArrayExpressionElement::SpreadElement(spread) = element {
                        self.walk_expression(&spread.argument);
                    } else if let Some(expr) = element.as_expression() {
                        self.walk_expression(expr);
                    }
                }
            }
            Expression::ObjectExpression(object) => {
                for property in &object.properties {
                    match property {
                        ObjectPropertyKind::ObjectProperty(property) => {
                            if property.computed
                                && let Some(key) = property.key.as_expression()
                            {
                                self.walk_expression(key);
                            }
                            self.walk_expression(&property.value);
                        }
                        ObjectPropertyKind::SpreadProperty(spread) => {
                            self.walk_expression(&spread.argument)
                        }
                    }
                }
            }
            Expression::TemplateLiteral(template) => {
                for e in &template.expressions {
                    self.walk_expression(e);
                }
            }
            // ``tag`…${x}…` `` — walk the interpolated slots so a sink nested
            // inside one (`` html`${eval(location.hash)}` ``) is still seen.
            Expression::TaggedTemplateExpression(tagged) => {
                for e in &tagged.quasi.expressions {
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
                self.walk_expression(&new_expr.callee);
                for arg in &new_expr.arguments {
                    if let Argument::SpreadElement(spread) = arg {
                        self.walk_expression(&spread.argument);
                    } else if let Some(expr) = arg.as_expression() {
                        self.walk_expression(expr);
                    }
                }
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
                    self.walk_function_literal_body(&func.params, &body.statements);
                }
            }
            Expression::ArrowFunctionExpression(arrow) => {
                self.walk_function_literal_body(&arrow.params, &arrow.body.statements);
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
    /// Walk a function literal's body the way [`Statement::FunctionDeclaration`]
    /// does — locals must not leak back out — with one addition: the parameter
    /// names shadow whatever the enclosing scope bound to them.
    ///
    /// Without the shadowing step `const f = function (x) { sink(x); }` reports
    /// the *outer* `x`'s source even though the body can only ever see the
    /// argument, and the summary registered for `f` already covers the real
    /// parameter flow at each call site. Free variables read inside the body
    /// (`function () { sink(location.hash); }`) are genuine flows and stay
    /// reported, which is the whole reason the body is walked here at all —
    /// as are writes the body makes to bindings it does not own, which escape
    /// the rollback as globals.
    pub(super) fn walk_function_literal_body(
        &mut self,
        params: &FormalParameters<'a>,
        statements: &[Statement<'a>],
    ) {
        let saved_tainted = self.tainted_vars.clone();
        let saved_aliases = self.var_aliases.clone();
        let saved_response_vars = self.response_object_vars.clone();
        let param_names = self.function_param_bindings(params);
        // `global_taints` is deliberately *not* saved wholesale — see the
        // escape handling below. Only the shadowed parameter names are lifted
        // out for the walk and put back afterwards.
        let mut shadowed_globals = Vec::new();
        for name in &param_names {
            self.tainted_vars.remove(name.as_str());
            self.var_aliases.remove(name.as_str());
            if self.global_taints.remove(name.as_str()) {
                shadowed_globals.push(name.clone());
            }
        }

        self.walk_statements(statements);

        // A name the body tainted that it neither declared nor took as a
        // parameter is an *outer* binding: `function () { g = location.hash; }`
        // leaves `g` tainted for every later read. Those escape into
        // `global_taints`, which is scope-free by design; everything else is
        // rolled back so a body-local (`const r = await fetch()`) cannot taint
        // an unrelated outer name of the same spelling.
        let mut locals: HashSet<String> = param_names.into_iter().collect();
        Self::collect_declared_names(statements, &mut locals);
        let escaped: Vec<(String, Option<String>)> = self
            .tainted_vars
            .iter()
            .filter(|name| !saved_tainted.contains(*name) && !locals.contains(*name))
            .map(|name| (name.clone(), self.var_aliases.get(name).cloned()))
            .collect();

        self.tainted_vars = saved_tainted;
        self.var_aliases = saved_aliases;
        self.response_object_vars = saved_response_vars;
        self.global_taints.extend(shadowed_globals);
        for (name, source) in escaped {
            if let Some(source) = source {
                self.var_aliases.insert(name.clone(), source);
            }
            self.global_taints.insert(name);
        }
    }

    /// Names bound by declarations anywhere in a function body, so the escape
    /// check above can tell a local apart from a write to an outer binding.
    ///
    /// Nested function bodies are skipped: their own locals are theirs, and a
    /// write *they* make to an outer name has already escaped through this
    /// same path. A statement form missed here just means a local escapes as
    /// if it were a global — the behaviour function literals had before this
    /// scoping existed at all.
    fn collect_declared_names(statements: &[Statement<'a>], out: &mut HashSet<String>) {
        for stmt in statements {
            match stmt {
                Statement::VariableDeclaration(decl) => {
                    for declarator in &decl.declarations {
                        Self::collect_binding_pattern_strs(&declarator.id, out);
                    }
                }
                Statement::FunctionDeclaration(func) => {
                    if let Some(id) = &func.id {
                        out.insert(id.name.to_string());
                    }
                }
                Statement::ClassDeclaration(class) => {
                    if let Some(id) = &class.id {
                        out.insert(id.name.to_string());
                    }
                }
                Statement::BlockStatement(block) => Self::collect_declared_names(&block.body, out),
                Statement::IfStatement(if_stmt) => {
                    Self::collect_declared_names(std::slice::from_ref(&if_stmt.consequent), out);
                    if let Some(alt) = &if_stmt.alternate {
                        Self::collect_declared_names(std::slice::from_ref(alt), out);
                    }
                }
                Statement::ForStatement(for_stmt) => {
                    if let Some(ForStatementInit::VariableDeclaration(decl)) = &for_stmt.init {
                        for declarator in &decl.declarations {
                            Self::collect_binding_pattern_strs(&declarator.id, out);
                        }
                    }
                    Self::collect_declared_names(std::slice::from_ref(&for_stmt.body), out);
                }
                Statement::ForInStatement(for_in) => {
                    Self::collect_for_loop_left(&for_in.left, out);
                    Self::collect_declared_names(std::slice::from_ref(&for_in.body), out);
                }
                Statement::ForOfStatement(for_of) => {
                    Self::collect_for_loop_left(&for_of.left, out);
                    Self::collect_declared_names(std::slice::from_ref(&for_of.body), out);
                }
                Statement::WhileStatement(while_stmt) => {
                    Self::collect_declared_names(std::slice::from_ref(&while_stmt.body), out);
                }
                Statement::DoWhileStatement(do_while) => {
                    Self::collect_declared_names(std::slice::from_ref(&do_while.body), out);
                }
                Statement::LabeledStatement(labeled) => {
                    Self::collect_declared_names(std::slice::from_ref(&labeled.body), out);
                }
                Statement::SwitchStatement(switch_stmt) => {
                    for case in &switch_stmt.cases {
                        Self::collect_declared_names(&case.consequent, out);
                    }
                }
                Statement::TryStatement(try_stmt) => {
                    Self::collect_declared_names(&try_stmt.block.body, out);
                    if let Some(handler) = &try_stmt.handler {
                        if let Some(param) = &handler.param {
                            Self::collect_binding_pattern_strs(&param.pattern, out);
                        }
                        Self::collect_declared_names(&handler.body.body, out);
                    }
                    if let Some(finalizer) = &try_stmt.finalizer {
                        Self::collect_declared_names(&finalizer.body, out);
                    }
                }
                _ => {}
            }
        }
    }

    fn collect_for_loop_left(left: &ForStatementLeft<'a>, out: &mut HashSet<String>) {
        if let ForStatementLeft::VariableDeclaration(decl) = left {
            for declarator in &decl.declarations {
                Self::collect_binding_pattern_strs(&declarator.id, out);
            }
        }
    }

    fn collect_binding_pattern_strs(pattern: &BindingPattern<'a>, out: &mut HashSet<String>) {
        let mut names = Vec::new();
        Self::collect_binding_pattern_names(pattern, &mut names);
        out.extend(names);
    }

    /// Every name a parameter list binds, destructuring and rest included.
    ///
    /// Unlike [`extract_param_names`](Self::extract_param_names) — which is
    /// positional, because summaries key sinks by parameter index — this is a
    /// flat set used only to decide which outer bindings a body cannot see.
    fn function_param_bindings(&self, params: &FormalParameters<'a>) -> Vec<String> {
        let mut names = Vec::new();
        for param in &params.items {
            Self::collect_binding_pattern_names(&param.pattern, &mut names);
        }
        if let Some(rest) = &params.rest {
            Self::collect_binding_pattern_names(&rest.rest.argument, &mut names);
        }
        names
    }

    fn collect_binding_pattern_names(pattern: &BindingPattern<'a>, names: &mut Vec<String>) {
        match pattern {
            BindingPattern::BindingIdentifier(id) => names.push(id.name.to_string()),
            BindingPattern::ObjectPattern(obj) => {
                for property in &obj.properties {
                    Self::collect_binding_pattern_names(&property.value, names);
                }
                if let Some(rest) = &obj.rest {
                    Self::collect_binding_pattern_names(&rest.argument, names);
                }
            }
            BindingPattern::ArrayPattern(array) => {
                for element in array.elements.iter().flatten() {
                    Self::collect_binding_pattern_names(element, names);
                }
                if let Some(rest) = &array.rest {
                    Self::collect_binding_pattern_names(&rest.argument, names);
                }
            }
            BindingPattern::AssignmentPattern(assign) => {
                Self::collect_binding_pattern_names(&assign.left, names);
            }
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
