//! Calls across webpack modules in one bundle file.
//!
//! A bundle is a map of module factories, `{456: function (e, t, n) { … }}`.
//! A factory publishes with `n.d(t, {Z: () => o})` and reads another module
//! with `var r = n(456)`, so `r.Z(x)` calls module 456's `o`. Names are
//! minified and reused in every factory (`o` is some other function next
//! door), so a summary keyed by the bare name cannot be the callee's. Here
//! the export gets a summary under the pair (module id, export name), taken
//! from the function declared *in that factory*, and `r` is bound to the
//! module the way an instance is bound to its class (`instance_classes`), so
//! the ordinary summary lookup for `r.Z(…)` / `(0, r.Z)(…)` finds it.
//!
//! Literal module ids and getter exports of a function declared at the
//! factory's top level only; anything else stays unresolved.

use super::*;

/// One module factory of a map.
struct Factory<'b, 'a> {
    id: String,
    params_span: oxc_span::Span,
    require: &'b str,
    statements: &'b [Statement<'a>],
    /// `(export name, local name)` from `n.d(t, {…})`.
    exports: Vec<(String, &'b str)>,
    /// `(local name, module id)` from top-level `var r = n(456)`.
    imports: Vec<(&'b str, String)>,
}

/// The summary-key prefix a variable bound to module `id` resolves to. No
/// script name can start with NUL, and a `.` in a path-like id would read as
/// a member separator.
fn module_key(id: &str) -> String {
    format!("\u{0}wp:{}", id.replace('.', "\u{1}"))
}

fn literal_id(arg: &Argument<'_>) -> Option<String> {
    match arg.as_expression()?.without_parentheses() {
        Expression::NumericLiteral(n) => Some(n.value.to_string()),
        Expression::StringLiteral(s) => Some(s.value.to_string()),
        _ => None,
    }
}

/// `n(456)` with `n` the factory's require parameter.
fn required_id(expr: &Expression<'_>, require: &str) -> Option<String> {
    let Expression::CallExpression(call) = expr.without_parentheses() else {
        return None;
    };
    let Expression::Identifier(callee) = &call.callee else {
        return None;
    };
    (callee.name == require && call.arguments.len() == 1)
        .then(|| literal_id(&call.arguments[0]))
        .flatten()
}

/// The identifier a getter hands back: `() => o`, `function () { return o }`.
fn getter_target<'b>(getter: &'b Expression<'_>) -> Option<&'b str> {
    let returned = match getter.without_parentheses() {
        Expression::ArrowFunctionExpression(arrow) if arrow.expression => {
            match arrow.body.statements.first()? {
                Statement::ExpressionStatement(statement) => &statement.expression,
                _ => return None,
            }
        }
        Expression::FunctionExpression(function) => {
            match function.body.as_ref()?.statements.as_slice() {
                [Statement::ReturnStatement(ret)] => ret.argument.as_ref()?,
                _ => return None,
            }
        }
        _ => return None,
    };
    match returned.without_parentheses() {
        Expression::Identifier(id) => Some(id.name.as_str()),
        _ => None,
    }
}

/// Exports one `n.d(…)` call declares: `n.d(t, {Z: () => o})`, or webpack
/// 4's `n.d(t, "Z", function () { return o })`.
fn exports_of_call<'b>(
    call: &'b CallExpression<'_>,
    require: &str,
    exports_param: &str,
    out: &mut Vec<(String, &'b str)>,
) {
    let Expression::StaticMemberExpression(callee) = &call.callee else {
        return;
    };
    let is_define = callee.property.name == "d"
        && matches!(&callee.object, Expression::Identifier(id) if id.name == require)
        && matches!(
            call.arguments.first().and_then(Argument::as_expression),
            Some(Expression::Identifier(id)) if id.name == exports_param
        );
    if !is_define {
        return;
    }
    let arg = |idx: usize| call.arguments.get(idx).and_then(Argument::as_expression);
    match (arg(1), arg(2)) {
        (Some(Expression::ObjectExpression(getters)), None) => {
            for property in &getters.properties {
                if let ObjectPropertyKind::ObjectProperty(p) = property
                    && !p.computed
                    && let Some(name) = p.key.static_name()
                    && let Some(target) = getter_target(&p.value)
                {
                    out.push((name.into_owned(), target));
                }
            }
        }
        (Some(Expression::StringLiteral(name)), Some(getter)) => {
            if let Some(target) = getter_target(getter) {
                out.push((name.value.to_string(), target));
            }
        }
        _ => {}
    }
}

/// A property of a module map as a factory: `456: function (e, t, n) { … }`.
fn factory_of<'b, 'a>(property: &'b ObjectPropertyKind<'a>) -> Option<Factory<'b, 'a>> {
    let ObjectPropertyKind::ObjectProperty(property) = property else {
        return None;
    };
    if property.computed {
        return None;
    }
    let (params, statements) = match &property.value {
        Expression::FunctionExpression(function) => {
            (&function.params, &function.body.as_ref()?.statements)
        }
        Expression::ArrowFunctionExpression(arrow) if !arrow.expression => {
            (&arrow.params, &arrow.body.statements)
        }
        _ => return None,
    };
    let name = |idx: usize| match &params.items.get(idx)?.pattern {
        BindingPattern::BindingIdentifier(id) => Some(id.name.as_str()),
        _ => None,
    };
    let (exports_param, require) = (name(1)?, name(2)?);
    let mut factory = Factory {
        id: property.key.static_name()?.into_owned(),
        params_span: params.span,
        require,
        statements,
        exports: Vec::new(),
        imports: Vec::new(),
    };
    for statement in statements.iter() {
        match statement {
            Statement::ExpressionStatement(statement) => match &statement.expression {
                Expression::CallExpression(call) => {
                    exports_of_call(call, require, exports_param, &mut factory.exports);
                }
                Expression::SequenceExpression(sequence) => {
                    for operand in &sequence.expressions {
                        if let Expression::CallExpression(call) = operand {
                            exports_of_call(call, require, exports_param, &mut factory.exports);
                        }
                    }
                }
                _ => {}
            },
            Statement::VariableDeclaration(declaration) => {
                for declarator in &declaration.declarations {
                    if let BindingPattern::BindingIdentifier(id) = &declarator.id
                        && let Some(init) = &declarator.init
                        && let Some(module) = required_id(init, require)
                    {
                        factory.imports.push((id.name.as_str(), module));
                    }
                }
            }
            _ => {}
        }
    }
    Some(factory)
}

impl<'a> DomXssVisitor<'a> {
    /// The module a `var r = n(456)` initializer names, inside a factory.
    pub(super) fn webpack_import(&self, init: &Expression<'a>) -> Option<String> {
        let id = required_id(init, self.webpack_require.as_deref()?)?;
        (!self.webpack_ambiguous_ids.contains(&id)).then(|| module_key(&id))
    }

    /// `var t = {…module map…}`: remember the name, so the runtime's
    /// `n.m = t` can name its require function (see
    /// [`Self::note_webpack_runtime`]).
    pub(super) fn note_webpack_map_var(&mut self, name: &str, init: &Expression<'a>) {
        if let Expression::ObjectExpression(object) = init
            && self.register_webpack_modules(object)
        {
            self.webpack_map_var = Some(name.to_string());
        }
    }

    /// The webpack runtime publishes its module map as `n.m = t`
    /// (`__webpack_require__.m = __webpack_modules__`). The entry module runs
    /// in the runtime's own scope, not in a factory, so that is where `n`
    /// becomes the `require` its `var o = n(826)` calls.
    pub(super) fn note_webpack_runtime(&mut self, assign: &AssignmentExpression<'a>) {
        if let AssignmentTarget::StaticMemberExpression(target) = &assign.left
            && target.property.name == "m"
            && let Expression::Identifier(require) = &target.object
            && let Expression::Identifier(map) = &assign.right
            && self.webpack_map_var.as_deref() == Some(map.name.as_str())
        {
            self.webpack_require = Some(require.name.to_string());
        }
    }

    /// When `object` is a webpack module map, register a summary for every
    /// exported function and remember its factories, so the walk that follows
    /// can bind their imports; says whether it is one. An object with no
    /// factory that exports anything is not a module map and costs one look
    /// at its properties.
    pub(super) fn register_webpack_modules(&mut self, object: &ObjectExpression<'a>) -> bool {
        if !object
            .properties
            .iter()
            .any(|p| matches!(p, ObjectPropertyKind::ObjectProperty(p) if p.value.is_function()))
        {
            return false;
        }
        if let Some(is_map) = self.webpack_maps_seen.get(&object.span) {
            return *is_map;
        }
        let factories: Vec<Factory<'_, 'a>> =
            object.properties.iter().filter_map(factory_of).collect();
        let is_map = factories.iter().any(|factory| !factory.exports.is_empty());
        self.webpack_maps_seen.insert(object.span, is_map);
        if !is_map {
            return false;
        }
        for factory in &factories {
            self.webpack_factories
                .insert(factory.params_span, factory.require.to_string());
            // A second map defining the same id (two bundles in one file):
            // an import of it could mean either, so it means neither.
            if self
                .webpack_module_spans
                .insert(factory.id.clone(), factory.params_span)
                .is_some_and(|earlier| earlier != factory.params_span)
            {
                self.webpack_ambiguous_ids.insert(factory.id.clone());
            }
        }

        // A module's exports are summarised after the modules it imports, so
        // a call it forwards (`function o(e) { return r.Y(e) }`) resolves.
        let index: HashMap<&str, usize> = factories
            .iter()
            .enumerate()
            .map(|(at, factory)| (factory.id.as_str(), at))
            .collect();
        let mut state = vec![0u8; factories.len()]; // 0 new, 1 open, 2 done
        for root in 0..factories.len() {
            let mut stack = vec![root];
            while let Some(&at) = stack.last() {
                if state[at] == 0 {
                    state[at] = 1;
                    stack.extend(
                        factories[at]
                            .imports
                            .iter()
                            .filter_map(|(_, id)| index.get(id.as_str()).copied())
                            .filter(|dep| state[*dep] == 0),
                    );
                    continue;
                }
                stack.pop();
                if state[at] == 1 {
                    state[at] = 2;
                    self.register_webpack_exports(&factories[at]);
                }
            }
        }
        true
    }

    fn register_webpack_exports(&mut self, factory: &Factory<'_, 'a>) {
        if factory.exports.is_empty() {
            return;
        }
        let checkpoint = self.instance_classes.checkpoint();
        for (local, id) in &factory.imports {
            if !self.webpack_ambiguous_ids.contains(id) {
                self.instance_classes
                    .insert(local.to_string(), module_key(id));
            }
        }
        let prefix = module_key(&factory.id);
        for (export, local) in &factory.exports {
            let key = format!("{prefix}.{export}");
            for statement in factory.statements {
                match statement {
                    Statement::FunctionDeclaration(function)
                        if function.id.as_ref().is_some_and(|id| id.name == *local) =>
                    {
                        if let Some(body) = &function.body {
                            self.register_function_summary(
                                key.clone(),
                                &function.params,
                                &body.statements,
                                false,
                            );
                        }
                    }
                    Statement::VariableDeclaration(declaration) => {
                        for declarator in &declaration.declarations {
                            if !matches!(&declarator.id, BindingPattern::BindingIdentifier(id) if id.name == *local)
                            {
                                continue;
                            }
                            match declarator
                                .init
                                .as_ref()
                                .map(Expression::without_parentheses)
                            {
                                Some(Expression::FunctionExpression(function)) => {
                                    if let Some(body) = &function.body {
                                        self.register_function_summary(
                                            key.clone(),
                                            &function.params,
                                            &body.statements,
                                            false,
                                        );
                                    }
                                }
                                Some(Expression::ArrowFunctionExpression(arrow)) => {
                                    self.register_function_summary(
                                        key.clone(),
                                        &arrow.params,
                                        &arrow.body.statements,
                                        arrow.expression,
                                    );
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        self.instance_classes.rollback(checkpoint);
    }
}
