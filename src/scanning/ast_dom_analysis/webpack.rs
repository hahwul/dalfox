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

pub(super) const MAX_WEBPACK_MODULES: usize = 1024;
const MAX_WEBPACK_MAPS: usize = 256;
const MAX_WEBPACK_EXPORTS: usize = 256;
const MAX_WEBPACK_IMPORTS: usize = 256;
const MAX_WEBPACK_BINDINGS: usize = 2048;
pub(super) const MAX_WEBPACK_NAME_BYTES: usize = 256;

/// One module factory of a map.
struct Factory<'b, 'a> {
    id: String,
    params_span: oxc_span::Span,
    params: &'b FormalParameters<'a>,
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
    format!("\u{0}wp:{}", id.replace('%', "%25").replace('.', "%2E"))
}

fn literal_id(arg: &Argument<'_>) -> Option<String> {
    match arg.as_expression()?.without_parentheses() {
        Expression::NumericLiteral(n) if n.value.is_finite() => Some(n.value.to_string()),
        Expression::StringLiteral(s) if s.value.len() <= MAX_WEBPACK_NAME_BYTES => {
            Some(s.value.to_string())
        }
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
        Expression::ArrowFunctionExpression(arrow)
            if arrow.expression
                && !arrow.r#async
                && arrow.params.items.is_empty()
                && arrow.params.rest.is_none() =>
        {
            match arrow.body.statements.first()? {
                Statement::ExpressionStatement(statement) => &statement.expression,
                _ => return None,
            }
        }
        Expression::FunctionExpression(function)
            if !function.r#async
                && !function.generator
                && function.id.is_none()
                && function.params.items.is_empty()
                && function.params.rest.is_none() =>
        {
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
        (Some(Expression::ObjectExpression(getters)), None)
            if getters.properties.len() <= MAX_WEBPACK_EXPORTS =>
        {
            if getters.properties.iter().any(|p| !matches!(p,ObjectPropertyKind::ObjectProperty(p) if !p.computed && p.kind == PropertyKind::Init)) { return; }
            let mut entries: Vec<(String, &str)> = Vec::new();
            for property in &getters.properties {
                if let ObjectPropertyKind::ObjectProperty(p) = property
                    && let Some(name) = p.key.static_name()
                {
                    entries.retain(|(known, _)| known != name.as_ref());
                    if name.len() <= MAX_WEBPACK_NAME_BYTES
                        && name != "__proto__"
                        && let Some(target) = getter_target(&p.value)
                    {
                        entries.push((name.into_owned(), target));
                    }
                }
            }
            for entry in entries {
                if !out.iter().any(|(name, _)| name == &entry.0) {
                    out.push(entry);
                }
            }
        }
        (Some(Expression::StringLiteral(name)), Some(getter)) => {
            if name.value.len() <= MAX_WEBPACK_NAME_BYTES
                && let Some(target) = getter_target(getter)
                && !out.iter().any(|(known, _)| known == name.value.as_str())
            {
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
        Expression::FunctionExpression(function)
            if !function.generator && !function.r#async && function.id.is_none() =>
        {
            (&function.params, &function.body.as_ref()?.statements)
        }
        Expression::ArrowFunctionExpression(arrow) if !arrow.expression && !arrow.r#async => {
            (&arrow.params, &arrow.body.statements)
        }
        _ => return None,
    };
    let name = |idx: usize| match &params.items.get(idx)?.pattern {
        BindingPattern::BindingIdentifier(id) => Some(id.name.as_str()),
        _ => None,
    };
    let (exports_param, require) = (name(1)?, name(2)?);
    if params.items.len() != 3
        || name(0).is_none()
        || params
            .items
            .iter()
            .any(|p| !matches!(p.pattern, BindingPattern::BindingIdentifier(_)))
        || name(0) == name(1)
        || name(0) == name(2)
        || name(1) == name(2)
    {
        return None;
    }
    if params.items.iter().any(|p| p.initializer.is_some())
        || params.rest.is_some()
        || statements.iter().any(|stmt| match stmt {
            Statement::FunctionDeclaration(f) => f.id.as_ref().is_some_and(|id| id.name == require || id.name == exports_param),
            Statement::VariableDeclaration(d) => d.declarations.iter().any(|d| {
                d.init.is_some()
                    && matches!(&d.id,BindingPattern::BindingIdentifier(id) if id.name == require || id.name == exports_param)
            }),
            _ => false,
        })
    {
        return None;
    }
    let id = property.key.static_name()?;
    if id.len() > MAX_WEBPACK_NAME_BYTES {
        return None;
    }
    let mut factory = Factory {
        id: id.into_owned(),
        params_span: params.span,
        params,
        require,
        statements,
        exports: Vec::new(),
        imports: Vec::new(),
    };
    'statements: for statement in statements.iter() {
        match statement {
            Statement::ExpressionStatement(statement) => match &statement.expression {
                Expression::CallExpression(call) => {
                    exports_of_call(call, require, exports_param, &mut factory.exports);
                }
                Expression::SequenceExpression(sequence) => {
                    for operand in &sequence.expressions {
                        if let Expression::CallExpression(call) = operand {
                            exports_of_call(call, require, exports_param, &mut factory.exports);
                            if factory.exports.len() > MAX_WEBPACK_EXPORTS {
                                break 'statements;
                            }
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
                        if factory.imports.len() > MAX_WEBPACK_IMPORTS {
                            break 'statements;
                        }
                    }
                }
            }
            _ => {}
        }
        if factory.exports.len() > MAX_WEBPACK_EXPORTS {
            break;
        }
    }
    Some(factory)
}

type CallableBody<'b, 'a> = (&'b FormalParameters<'a>, &'b [Statement<'a>], bool);

fn callable_body<'b, 'a>(expr: &'b Expression<'a>) -> Option<CallableBody<'b, 'a>> {
    match expr.without_parentheses() {
        Expression::FunctionExpression(f) if !f.generator && f.id.is_none() => {
            Some((&f.params, f.body.as_ref()?.statements.as_slice(), false))
        }
        Expression::ArrowFunctionExpression(a) => {
            Some((&a.params, a.body.statements.as_slice(), a.expression))
        }
        _ => None,
    }
}

fn stable_factory_expr(expr: &Expression<'_>, require: &str, exports: &str, depth: u8) -> bool {
    if depth == 0 {
        return false;
    }
    let check = |expr| stable_factory_expr(expr, require, exports, depth - 1);
    match expr.without_parentheses() {
        Expression::Identifier(id) => id.name != require && id.name != exports,
        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_) => true,
        Expression::CallExpression(call) => {
            let helper = match call.callee.without_parentheses() {
                Expression::Identifier(id) if id.name == require => {
                    return required_id(expr, require).is_some();
                }
                Expression::StaticMemberExpression(member) if matches!(&member.object,Expression::Identifier(id) if id.name == require) => {
                    member.property.name.as_str()
                }
                _ => return false,
            };
            matches!(helper, "d" | "r" | "n" | "t" | "o")
                && call.arguments.iter().all(|arg| {
                    arg.as_expression().is_some_and(|arg| {
                        if matches!(helper, "d" | "r" | "o")
                            && matches!(arg,Expression::Identifier(id) if id.name == exports)
                        {
                            true
                        } else {
                            check(arg)
                        }
                    })
                })
        }
        Expression::SequenceExpression(sequence) => sequence.expressions.iter().all(check),
        Expression::ArrayExpression(array) => array
            .elements
            .iter()
            .all(|e| e.as_expression().is_some_and(check)),
        Expression::ObjectExpression(object) => object.properties.iter().all(|p| match p {
            ObjectPropertyKind::ObjectProperty(p)
                if !p.computed && p.kind == PropertyKind::Init =>
            {
                check(&p.value)
            }
            _ => false,
        }),
        Expression::ConditionalExpression(c) => [&c.test, &c.consequent, &c.alternate]
            .into_iter()
            .all(check),
        Expression::LogicalExpression(l) => check(&l.left) && check(&l.right),
        Expression::BinaryExpression(b) => check(&b.left) && check(&b.right),
        Expression::UnaryExpression(u) => check(&u.argument),
        Expression::StaticMemberExpression(m) => check(&m.object),
        Expression::ComputedMemberExpression(m) => check(&m.object) && check(&m.expression),
        Expression::TemplateLiteral(t) => t.expressions.iter().all(check),
        Expression::NewExpression(n) => {
            matches!(&n.callee,Expression::Identifier(id) if id.name == "DOMParser")
                && n.arguments.is_empty()
        }
        expr if expr.is_literal() => true,
        _ => false,
    }
}

impl<'a> DomXssVisitor<'a> {
    /// The module a `var r = n(456)` initializer names, inside a factory.
    pub(super) fn webpack_import(&self, init: &Expression<'a>) -> Option<String> {
        if self.webpack_disabled {
            return None;
        }
        let id = required_id(init, self.webpack_require.as_deref()?)?;
        (!self.webpack_ambiguous_ids.contains(&id)).then(|| module_key(&id))
    }

    /// `var t = {…module map…}`: remember the name, so the runtime's
    /// `n.m = t` can name its require function (see
    /// [`Self::note_webpack_runtime`]).
    pub(super) fn probe_webpack_pattern_defaults(&mut self, pattern: &BindingPattern<'a>) {
        let Some(_guard) = self.enter_recursion() else {
            self.note_webpack_rebinding("");
            return;
        };
        match pattern {
            BindingPattern::AssignmentPattern(p) => {
                self.walk_expression(&p.right);
                self.probe_webpack_pattern_defaults(&p.left);
            }
            BindingPattern::ObjectPattern(p) => {
                for property in &p.properties {
                    self.probe_webpack_pattern_defaults(&property.value);
                }
                if let Some(rest) = &p.rest {
                    self.probe_webpack_pattern_defaults(&rest.argument);
                }
            }
            BindingPattern::ArrayPattern(p) => {
                for item in p.elements.iter().flatten() {
                    self.probe_webpack_pattern_defaults(item);
                }
                if let Some(rest) = &p.rest {
                    self.probe_webpack_pattern_defaults(&rest.argument);
                }
            }
            BindingPattern::BindingIdentifier(_) => {}
        }
    }

    pub(super) fn enter_webpack_write_scope(&mut self) -> Option<HashSet<String>> {
        let outer = self.webpack_binding_writes.take();
        if outer.is_some() {
            self.webpack_binding_writes = Some(HashSet::new());
        }
        outer
    }

    // shortcut: block-only local writes can leave a factory unresolved; use binding IDs for finer lexical ownership.
    pub(super) fn leave_webpack_write_scope(
        &mut self,
        outer: Option<HashSet<String>>,
        owned: &HashSet<String>,
    ) {
        let writes = self.webpack_binding_writes.take().unwrap_or_default();
        self.webpack_binding_writes = outer;
        for name in writes {
            if !owned.contains(&name) {
                self.note_webpack_rebinding(&name);
            }
        }
    }

    pub(super) fn note_webpack_rebinding(&mut self, name: &str) {
        if let Some(writes) = &mut self.webpack_binding_writes {
            if writes.len() >= MAX_WEBPACK_BINDINGS {
                writes.insert(String::new());
            } else if !writes.contains("") {
                writes.insert(name.to_string());
            }
        }
    }

    pub(super) fn note_webpack_assignment(&mut self, target: &AssignmentTarget<'a>) {
        match target {
            AssignmentTarget::AssignmentTargetIdentifier(id) => {
                self.note_webpack_rebinding(id.name.as_str())
            }
            AssignmentTarget::ArrayAssignmentTarget(_)
            | AssignmentTarget::ObjectAssignmentTarget(_) => self.note_webpack_rebinding(""),
            AssignmentTarget::StaticMemberExpression(m) if m.property.name == "exports" => {
                self.note_webpack_rebinding("")
            }
            AssignmentTarget::ComputedMemberExpression(m) if matches!(m.expression.without_parentheses(),Expression::StringLiteral(s) if s.value == "exports") => {
                self.note_webpack_rebinding("")
            }
            _ => {}
        }
    }

    pub(super) fn forget_webpack_binding(&mut self, name: &str) {
        if self.webpack_require.as_deref() == Some(name) {
            self.webpack_require = None;
        }
        if self.webpack_map_var.as_deref() == Some(name) {
            self.webpack_map_var = None;
            self.webpack_require = None;
        }
    }

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
        if let AssignmentTarget::AssignmentTargetIdentifier(id) = &assign.left {
            self.forget_webpack_binding(id.name.as_str());
        }
        if let AssignmentTarget::StaticMemberExpression(target) = &assign.left
            && target.property.name == "m"
            && matches!(&target.object,Expression::Identifier(id) if self.webpack_require.as_deref() == Some(id.name.as_str()))
        {
            self.webpack_require = None;
        }
        if self.webpack_disabled {
            return;
        }
        if let AssignmentTarget::StaticMemberExpression(target) = &assign.left
            && target.property.name == "m"
            && assign.operator == AssignmentOperator::Assign
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
        let Some(_guard) = self.enter_recursion() else {
            return false;
        };
        if self.webpack_disabled {
            return false;
        }
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
        if object.properties.len() > MAX_WEBPACK_MODULES
            || self.webpack_maps_seen.len() >= MAX_WEBPACK_MAPS
        {
            self.webpack_disabled = true;
            return false;
        }
        let factories: Vec<Factory<'_, 'a>> =
            object.properties.iter().filter_map(factory_of).collect();
        let is_map = factories.iter().any(|factory| !factory.exports.is_empty());
        self.webpack_maps_seen.insert(object.span, is_map);
        // A callable candidate can replace an earlier module even when its
        // getter or parameter shape is unsupported. Such IDs stay ambiguous.
        for property in &object.properties {
            if let ObjectPropertyKind::ObjectProperty(property) = property
                && (is_map || property.value.is_function())
                && let Some(id) = property.key.static_name()
                && id.len() <= MAX_WEBPACK_NAME_BYTES
            {
                if self.webpack_module_spans.len() >= MAX_WEBPACK_MODULES
                    && !self.webpack_module_spans.contains_key(id.as_ref())
                {
                    self.webpack_disabled = true;
                    return false;
                }
                if self
                    .webpack_module_spans
                    .insert(id.to_string(), property.value.span())
                    .is_some_and(|old| old != property.value.span())
                {
                    self.webpack_ambiguous_ids.insert(id.into_owned());
                }
            }
        }
        if !is_map {
            return false;
        }
        if object
            .properties
            .iter()
            .any(|p| !matches!(p,ObjectPropertyKind::ObjectProperty(p) if !p.computed))
            || factories.iter().any(|f| {
                f.exports.len() > MAX_WEBPACK_EXPORTS
                    || f.imports.len() > MAX_WEBPACK_IMPORTS
                    || f.statements.len() > MAX_WEBPACK_BINDINGS
            })
        {
            self.webpack_disabled = true;
            return false;
        }
        for factory in &factories {
            self.webpack_factories
                .insert(factory.params_span, factory.require.to_string());
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
                let Some(_guard) = self.enter_recursion() else {
                    self.webpack_disabled = true;
                    return false;
                };
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
        // Hoisted declarations first, then runtime initializers. The final
        // binding is what the getter reads, not the first matching name.
        let mut functions = HashMap::new();
        let mut imports = HashMap::new();
        for statement in factory.statements {
            if let Statement::FunctionDeclaration(f) = statement
                && let (Some(id), Some(body)) = (&f.id, &f.body)
            {
                functions.remove(id.name.as_str());
                if !f.generator {
                    functions.insert(
                        id.name.as_str(),
                        (&*f.params, body.statements.as_slice(), false),
                    );
                }
            }
        }
        for statement in factory.statements {
            match statement {
                Statement::VariableDeclaration(d) => {
                    for d in &d.declarations {
                        let BindingPattern::BindingIdentifier(id) = &d.id else {
                            return;
                        };
                        if let Some(init) = &d.init {
                            let exports = match &factory.params.items[1].pattern {
                                BindingPattern::BindingIdentifier(id) => id.name.as_str(),
                                _ => return,
                            };
                            if !stable_factory_expr(init, factory.require, exports, 32) {
                                return;
                            }
                            functions.remove(id.name.as_str());
                            imports.remove(id.name.as_str());
                            if let Some(body) = callable_body(init) {
                                functions.insert(id.name.as_str(), body);
                            }
                            if let Some(module) = required_id(init, factory.require) {
                                imports.insert(id.name.as_str(), module);
                            }
                        }
                    }
                }
                Statement::ExpressionStatement(stmt) => {
                    let exports = match &factory.params.items[1].pattern {
                        BindingPattern::BindingIdentifier(id) => id.name.as_str(),
                        _ => return,
                    };
                    if !stable_factory_expr(&stmt.expression, factory.require, exports, 32) {
                        return;
                    }
                }
                Statement::FunctionDeclaration(_) | Statement::EmptyStatement(_) => {}
                // Control-flow-sensitive factory bindings remain unresolved.
                _ => return,
            }
        }
        if functions.len() > MAX_WEBPACK_BINDINGS || imports.len() > MAX_WEBPACK_IMPORTS {
            self.webpack_disabled = true;
            return;
        }
        let mut locals = self
            .extract_param_names(factory.params)
            .into_iter()
            .collect::<HashSet<_>>();
        for statement in factory.statements {
            match statement {
                Statement::FunctionDeclaration(f) => {
                    locals.extend(f.id.iter().map(|id| id.name.to_string()));
                }
                Statement::VariableDeclaration(d) => {
                    for d in &d.declarations {
                        if let BindingPattern::BindingIdentifier(id) = &d.id {
                            locals.insert(id.name.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
        if locals.len() > MAX_WEBPACK_BINDINGS {
            self.webpack_disabled = true;
            return;
        }
        let end = factory
            .statements
            .last()
            .map_or(factory.params_span.end, |stmt| stmt.span().end);
        let in_factory = |s: &FunctionSummary| {
            s.params_span.start >= factory.params_span.end && s.params_span.end <= end
        };
        let classes = self.instance_classes.checkpoint();
        let bound = self.bound_function_aliases.checkpoint();
        let globals = self.global_aliases.checkpoint();
        let local_names = self.local_names.checkpoint();
        let shadow = self.shadow_params.checkpoint();
        let values = self.value_locals.checkpoint();
        let fields = self.field_taints.checkpoint();
        let global_taints = self.global_taints.checkpoint();
        let leads = self.url_leads.checkpoint();
        let kills = self.url_lead_kills.len();
        let pages = self.page_url_objects.checkpoint();
        let responses = self.response_object_vars.checkpoint();
        let elements = self.element_tag_vars.checkpoint();
        let hidden_urls: Vec<_> = locals
            .iter()
            .filter_map(|n| self.url_object_sources.remove(n).map(|v| (n.clone(), v)))
            .collect();
        let hidden_search: Vec<_> = locals
            .iter()
            .filter_map(|n| {
                self.url_search_params_sources
                    .remove(n)
                    .map(|v| (n.clone(), v))
            })
            .collect();
        let hidden_search_objects: Vec<_> = locals
            .iter()
            .filter(|n| self.url_search_params_objects.remove(*n))
            .cloned()
            .collect();
        let hidden_this: Vec<_> = locals
            .iter()
            .filter_map(|n| self.named_this.remove(n).map(|v| (n.clone(), v)))
            .collect();
        let outer_functions: Vec<_> = locals
            .iter()
            .map(|n| (n.clone(), self.function_summaries.remove(n)))
            .collect();
        let nested_names: Vec<_> = self
            .function_summaries
            .iter()
            .filter(|(key, summary)| !key.starts_with("\0wp:") && in_factory(summary))
            .map(|(key, _)| key.clone())
            .collect();
        let outer_nested: Vec<_> = nested_names
            .into_iter()
            .filter_map(|key| {
                self.function_summaries
                    .remove(&key)
                    .map(|value| (key, value))
            })
            .collect();
        let outer_require = self.webpack_require.replace(factory.require.to_string());
        let outer_map = self.webpack_map_var.take();
        let outer_probe = self.webpack_binding_writes.take();
        let outer_writes = std::mem::take(&mut self.return_written_roots);
        let outer_callable_roots = std::mem::take(&mut self.return_callable_roots);
        for name in &locals {
            self.clear_instance_field_taints(name);
            self.instance_classes.remove(name);
            self.bound_function_aliases.remove(name);
            self.global_aliases.remove(name);
            self.local_names.insert(name.clone());
            self.shadow_params.remove(name);
            self.value_locals.remove(name);
            self.global_taints.remove(name);
            self.url_leads.remove(name);
            self.page_url_objects.remove(name);
            self.response_object_vars.remove(name);
            self.element_tag_vars.remove(name);
            if !functions.contains_key(name.as_str()) {
                self.value_locals.insert(name.clone());
            }
        }
        for name in self.extract_param_names(factory.params) {
            self.shadow_params.insert(name);
        }
        let mut functions: Vec<_> = functions.into_iter().collect();
        functions.sort_by_key(|(_, (params, _, _))| params.span.start);
        // The probe observes writes even in captured helper bodies. Its
        // assumed taints, aliases, and reports must not become the final environment.
        let probe_findings = self.vulnerabilities.len();
        let probe_globals = self.global_taints.checkpoint();
        let probe_fields = self.field_taints.checkpoint();
        let probe_aliases = self.var_aliases.checkpoint();
        let probe_classes = self.instance_classes.checkpoint();
        let probe_bound_aliases = self.bound_function_aliases.checkpoint();
        let probe_css = self.css_custom_property_sources.checkpoint();
        let probe_idb_requests = self.idb_request_vars.checkpoint();
        let probe_idb_stores = self.idb_object_store_vars.checkpoint();
        let url_objects = std::mem::take(&mut self.url_object_sources);
        let search_sources = std::mem::take(&mut self.url_search_params_sources);
        let search_objects = std::mem::take(&mut self.url_search_params_objects);
        self.webpack_binding_writes = Some(HashSet::new());
        for stmt in factory.statements {
            if let Statement::VariableDeclaration(declaration) = stmt {
                for d in &declaration.declarations {
                    if let Some(init) = &d.init
                        && !init.is_function()
                    {
                        self.walk_expression(init);
                    }
                }
            }
        }
        for (name, (params, body, concise)) in &functions {
            self.register_function_summary((*name).to_string(), params, body, *concise);
        }
        let writes = self.webpack_binding_writes.take().unwrap_or_default();
        self.vulnerabilities.truncate(probe_findings);
        let unstable_runtime = writes.contains("") || writes.contains(factory.require)
            || factory.params.items.get(1).is_some_and(|p| matches!(&p.pattern, BindingPattern::BindingIdentifier(id) if writes.contains(id.name.as_str())));
        self.return_written_roots.clear();
        self.global_taints.rollback(probe_globals);
        self.field_taints.rollback(probe_fields);
        self.var_aliases.rollback(probe_aliases);
        self.instance_classes.rollback(probe_classes);
        self.bound_function_aliases.rollback(probe_bound_aliases);
        self.css_custom_property_sources.rollback(probe_css);
        self.idb_request_vars.rollback(probe_idb_requests);
        self.idb_object_store_vars.rollback(probe_idb_stores);
        self.url_object_sources = url_objects;
        self.url_search_params_sources = search_sources;
        self.url_search_params_objects = search_objects;
        for name in &locals {
            self.function_summaries.remove(name);
        }
        self.function_summaries
            .retain(|key, summary| key.starts_with("\0wp:") || !in_factory(summary));
        self.declaration_summaries
            .retain(|span, _| span.start < factory.params_span.end || span.end > end);
        for (name, id) in &imports {
            if !unstable_runtime
                && !writes.contains(*name)
                && !self.webpack_ambiguous_ids.contains(id)
            {
                self.instance_classes
                    .insert((*name).to_string(), module_key(id));
            }
        }
        // Revisit local helpers after all names are registered, so an export
        // can call a helper declared later in the factory.
        for (name, _) in &functions {
            if writes.contains(*name) {
                self.value_locals.insert((*name).to_string());
            }
        }
        for _ in 0..2 {
            for (name, (params, body, concise)) in &functions {
                if writes.contains(*name) {
                    continue;
                }
                self.function_summaries.remove(*name);
                self.register_function_summary((*name).to_string(), params, body, *concise);
            }
        }
        let prefix = module_key(&factory.id);
        for (export, local) in &factory.exports {
            if unstable_runtime || writes.contains(*local) {
                continue;
            }
            if let Some((_, (params, body, concise))) =
                functions.iter().find(|(name, _)| name == local)
            {
                self.register_function_summary(
                    format!("{prefix}.{export}"),
                    params,
                    body,
                    *concise,
                );
            }
        }
        for name in &locals {
            self.function_summaries.remove(name);
        }
        self.function_summaries
            .retain(|key, summary| key.starts_with("\0wp:") || !in_factory(summary));
        self.function_summaries.extend(outer_nested);
        for (name, old) in outer_functions {
            if let Some(old) = old {
                self.function_summaries.insert(name, old);
            }
        }
        for name in &locals {
            self.url_object_sources.remove(name);
            self.url_search_params_sources.remove(name);
            self.url_search_params_objects.remove(name);
            self.named_this.remove(name);
        }
        self.url_object_sources.extend(hidden_urls);
        self.url_search_params_sources.extend(hidden_search);
        self.url_search_params_objects.extend(hidden_search_objects);
        self.named_this.extend(hidden_this);
        self.webpack_binding_writes = outer_probe;
        for name in &writes {
            if !locals.contains(name) {
                self.note_webpack_rebinding(name);
            }
        }
        self.return_written_roots = outer_writes;
        self.return_callable_roots = outer_callable_roots;
        self.webpack_require = outer_require;
        self.webpack_map_var = outer_map;
        self.element_tag_vars.rollback(elements);
        self.response_object_vars.rollback(responses);
        self.page_url_objects.rollback(pages);
        self.url_leads.rollback(leads);
        self.url_lead_kills.truncate(kills);
        self.global_taints.rollback(global_taints);
        self.field_taints.rollback(fields);
        self.value_locals.rollback(values);
        self.shadow_params.rollback(shadow);
        self.local_names.rollback(local_names);
        self.global_aliases.rollback(globals);
        self.bound_function_aliases.rollback(bound);
        self.instance_classes.rollback(classes);
    }
}
