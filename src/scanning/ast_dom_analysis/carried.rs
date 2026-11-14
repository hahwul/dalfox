//! Tainted globals handed from one `<script>` of a page to the next.
//!
//! A page's classic scripts share one global scope, so
//! `<script>var q = location.hash</script><script>el.innerHTML = q</script>`
//! is one flow across two blocks that are each analyzed alone. Each block
//! starts with what the earlier ones left tainted ([`CarriedGlobals`]) and
//! hands on what is still tainted when it ends. Nothing is joined: line
//! numbers, dedup and hoisting stay per block.
//!
//! A carried name keeps what the walk knew about its value that *suppresses*
//! a sink or names the source (its URL lead, whether it is the page's own URL
//! or a `URL` / `URLSearchParams` object), so a split script reads like the
//! joined one.

use super::*;

/// What one carried global is.
#[derive(Clone)]
struct Carried {
    source: String,
    lead: Option<(UrlLead, bool)>,
    page_url: bool,
    url_object: Option<String>,
    params_source: Option<String>,
    params_object: bool,
}

/// Most names one script hands on, and the longest name or source label.
/// The page chooses how many globals it declares, what they are called and
/// how many blocks follow; each block copies what it receives.
pub(super) const MAX_CARRIED_GLOBALS: usize = 256;
pub(super) const MAX_CARRIED_TEXT_BYTES: usize = 128;

/// Names seeded across all the blocks of one page before carrying stops.
pub(super) const MAX_CARRY_WORK: usize = 200_000;

/// The globals the scripts so far have left tainted.
#[derive(Clone)]
pub(crate) struct CarriedGlobals {
    names: BTreeMap<String, Carried>,
    work_left: usize,
}

impl Default for CarriedGlobals {
    fn default() -> Self {
        Self {
            names: BTreeMap::new(),
            work_left: MAX_CARRY_WORK,
        }
    }
}

impl CarriedGlobals {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.names.len()
    }

    /// A script whose effect on the globals is unknown ran here (a repeat of
    /// an earlier body, which is listed once): nothing is known to be
    /// tainted any more.
    pub(crate) fn forget(&mut self) {
        self.names.clear();
    }

    /// What a block with a scope of its own starts from: an inline handler,
    /// a `javascript:` URL, a module. It reads the page's globals and hands
    /// nothing back. `event` is the handler's own argument.
    pub(crate) fn for_own_scope(&mut self) -> Self {
        self.charge();
        let mut own = self.clone();
        own.names.remove("event");
        own
    }

    /// Pay for seeding one more block; past the page's budget nothing is
    /// carried any further.
    fn charge(&mut self) {
        match self.work_left.checked_sub(self.names.len()) {
            Some(left) => self.work_left = left,
            None => {
                self.names.clear();
                self.work_left = 0;
            }
        }
    }
}

/// What a script's own top level does to the page's global scope.
#[derive(Default)]
struct TopLevelWrites<'b> {
    /// Globals the script may write: a `var` anywhere outside a function
    /// body, a top-level `let` / `const`, an assignment to a bare name.
    names: Vec<&'b str>,
    /// Names the script binds anew before anything runs: a top-level
    /// `function`, `class`, `let`, `const` or import.
    rebound: Vec<&'b str>,
    /// Names a nested block binds for itself (`let` / `const` in a block, a
    /// `for (let …)` head, a `catch` parameter). The walk has no block
    /// scope, so an assignment to one inside its block is not a global's.
    block_scoped: Vec<&'b str>,
    /// The script has `import` / `export`: its top-level bindings are
    /// module-scoped, not globals.
    is_module: bool,
}

/// Statement nesting followed when looking for `var` and assignments.
const MAX_WRITE_DEPTH: u8 = 32;

fn binding_names<'b>(pattern: &'b BindingPattern<'_>, out: &mut Vec<&'b str>) {
    match pattern {
        BindingPattern::BindingIdentifier(id) => out.push(id.name.as_str()),
        BindingPattern::ObjectPattern(object) => {
            for property in &object.properties {
                binding_names(&property.value, out);
            }
            if let Some(rest) = &object.rest {
                binding_names(&rest.argument, out);
            }
        }
        BindingPattern::ArrayPattern(array) => {
            for element in array.elements.iter().flatten() {
                binding_names(element, out);
            }
            if let Some(rest) = &array.rest {
                binding_names(&rest.argument, out);
            }
        }
        BindingPattern::AssignmentPattern(assignment) => binding_names(&assignment.left, out),
    }
}

/// Bare names an expression assigns: `q = …`, `a = b = …`, `a && (q = …)`,
/// `c ? q = … : 0`, comma operands.
fn assigned_names<'b>(expr: &'b Expression<'_>, depth: u8, out: &mut Vec<&'b str>) {
    if depth == 0 {
        return;
    }
    match expr {
        Expression::AssignmentExpression(assign) => {
            if let AssignmentTarget::AssignmentTargetIdentifier(id) = &assign.left {
                out.push(id.name.as_str());
            }
            assigned_names(&assign.right, depth - 1, out);
        }
        Expression::SequenceExpression(sequence) => {
            for operand in &sequence.expressions {
                assigned_names(operand, depth - 1, out);
            }
        }
        Expression::LogicalExpression(logical) => {
            assigned_names(&logical.left, depth - 1, out);
            assigned_names(&logical.right, depth - 1, out);
        }
        Expression::ConditionalExpression(conditional) => {
            assigned_names(&conditional.consequent, depth - 1, out);
            assigned_names(&conditional.alternate, depth - 1, out);
        }
        Expression::ParenthesizedExpression(paren) => {
            assigned_names(&paren.expression, depth - 1, out);
        }
        _ => {}
    }
}

fn loop_head_bindings<'b>(left: &'b ForStatementLeft<'_>, out: &mut TopLevelWrites<'b>) {
    if let ForStatementLeft::VariableDeclaration(declaration) = left
        && declaration.kind != VariableDeclarationKind::Var
    {
        for declarator in &declaration.declarations {
            binding_names(&declarator.id, &mut out.block_scoped);
        }
    }
}

fn collect_writes<'b>(
    statements: &'b [Statement<'_>],
    top: bool,
    depth: u8,
    out: &mut TopLevelWrites<'b>,
) {
    if depth == 0 {
        return;
    }
    let nested = |body: &'b Statement<'_>, out: &mut TopLevelWrites<'b>| {
        collect_writes(std::slice::from_ref(body), false, depth - 1, out);
    };
    for statement in statements {
        match statement {
            Statement::VariableDeclaration(declaration) => {
                let lexical = declaration.kind != VariableDeclarationKind::Var;
                // A nested `let` / `const` is the block's own.
                if lexical && !top {
                    for declarator in &declaration.declarations {
                        binding_names(&declarator.id, &mut out.block_scoped);
                    }
                    continue;
                }
                for declarator in &declaration.declarations {
                    let start = out.names.len();
                    binding_names(&declarator.id, &mut out.names);
                    if lexical {
                        out.rebound.extend_from_slice(&out.names[start..]);
                    }
                    if let Some(init) = &declarator.init {
                        assigned_names(init, MAX_WRITE_DEPTH, &mut out.names);
                    }
                }
            }
            Statement::ExpressionStatement(statement) => {
                assigned_names(&statement.expression, MAX_WRITE_DEPTH, &mut out.names);
            }
            Statement::FunctionDeclaration(function) if top => {
                out.rebound
                    .extend(function.id.iter().map(|id| id.name.as_str()));
            }
            Statement::ClassDeclaration(class) if top => {
                out.rebound
                    .extend(class.id.iter().map(|id| id.name.as_str()));
            }
            Statement::ImportDeclaration(import) => {
                out.is_module = true;
                for specifier in import.specifiers.iter().flatten() {
                    out.rebound.push(specifier.local().name.as_str());
                }
            }
            Statement::BlockStatement(block) => {
                collect_writes(&block.body, false, depth - 1, out);
            }
            Statement::IfStatement(branch) => {
                nested(&branch.consequent, out);
                if let Some(alternate) = &branch.alternate {
                    nested(alternate, out);
                }
            }
            Statement::TryStatement(attempt) => {
                collect_writes(&attempt.block.body, false, depth - 1, out);
                if let Some(handler) = &attempt.handler {
                    if let Some(param) = &handler.param {
                        binding_names(&param.pattern, &mut out.block_scoped);
                    }
                    collect_writes(&handler.body.body, false, depth - 1, out);
                }
                if let Some(finalizer) = &attempt.finalizer {
                    collect_writes(&finalizer.body, false, depth - 1, out);
                }
            }
            Statement::ForStatement(each) => {
                if let Some(ForStatementInit::VariableDeclaration(declaration)) = &each.init {
                    let var = declaration.kind == VariableDeclarationKind::Var;
                    for declarator in &declaration.declarations {
                        let into = if var {
                            &mut out.names
                        } else {
                            &mut out.block_scoped
                        };
                        binding_names(&declarator.id, into);
                    }
                }
                nested(&each.body, out);
            }
            Statement::ForInStatement(each) => {
                loop_head_bindings(&each.left, out);
                nested(&each.body, out)
            }
            Statement::ForOfStatement(each) => {
                loop_head_bindings(&each.left, out);
                nested(&each.body, out)
            }
            Statement::WhileStatement(each) => nested(&each.body, out),
            Statement::DoWhileStatement(each) => nested(&each.body, out),
            Statement::LabeledStatement(labeled) => nested(&labeled.body, out),
            other => out.is_module |= top && other.is_module_declaration(),
        }
    }
}

impl<'a> DomXssVisitor<'a> {
    /// Start a script from what the scripts before it left tainted, walk it,
    /// and leave in `globals` what it hands on.
    pub(super) fn walk_script_after(
        &mut self,
        body: &[Statement<'a>],
        globals: &mut CarriedGlobals,
    ) {
        let mut written = TopLevelWrites::default();
        collect_writes(body, true, MAX_WRITE_DEPTH, &mut written);
        globals.charge();
        let block_scoped: HashSet<&str> = written.block_scoped.iter().copied().collect();
        written.names.retain(|name| !block_scoped.contains(name));
        for name in &written.rebound {
            globals.names.remove(*name);
        }
        for (name, carried) in &globals.names {
            self.taint_var(name.clone());
            self.var_aliases
                .insert(name.clone(), carried.source.clone());
            if let Some(lead) = carried.lead {
                self.url_leads.insert(name.clone(), lead);
            }
            if carried.page_url {
                self.page_url_objects.insert(name.clone());
            }
            if let Some(source) = &carried.url_object {
                self.url_object_sources.insert(name.clone(), source.clone());
            }
            if let Some(source) = &carried.params_source {
                self.url_search_params_sources
                    .insert(name.clone(), source.clone());
            }
            if carried.params_object {
                self.url_search_params_objects.insert(name.clone());
            }
        }

        self.walk_statements(body);

        // What this script hands on: the globals it wrote or received that
        // are still tainted whole when it ends. A name tainted only inside a
        // function body is not among them (the body may never run), and a
        // module's bindings are its own. Its own writes go first, so a full
        // map of received names cannot crowd them out.
        let own = if written.is_module {
            &[][..]
        } else {
            written.names.as_slice()
        };
        let mut handed_on = BTreeMap::new();
        for name in own
            .iter()
            .copied()
            .chain(globals.names.keys().map(String::as_str))
        {
            if handed_on.len() >= MAX_CARRIED_GLOBALS {
                break;
            }
            if name.len() <= MAX_CARRIED_TEXT_BYTES
                && self.tainted_vars.contains(name)
                && !self.field_only_taint.contains(name)
                && let Some(source) = self.var_aliases.get(name)
                && source.len() <= MAX_CARRIED_TEXT_BYTES
                && self
                    .url_object_sources
                    .get(name)
                    .is_none_or(|s| s.len() <= MAX_CARRIED_TEXT_BYTES)
                && self
                    .url_search_params_sources
                    .get(name)
                    .is_none_or(|s| s.len() <= MAX_CARRIED_TEXT_BYTES)
            {
                handed_on.insert(
                    name.to_string(),
                    Carried {
                        source: source.clone(),
                        lead: self.url_leads.get(name).copied(),
                        page_url: self.page_url_objects.contains(name),
                        url_object: self.url_object_sources.get(name).cloned(),
                        params_source: self.url_search_params_sources.get(name).cloned(),
                        params_object: self.url_search_params_objects.contains(name),
                    },
                );
            }
        }
        if !handed_on.is_empty() {
            crate::dbg_log!(
                "[ast] {} tainted global(s) handed to the next script: {}",
                handed_on.len(),
                handed_on
                    .keys()
                    .take(8)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        globals.names = handed_on;
    }
}
