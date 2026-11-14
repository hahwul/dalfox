//! What a script's own top level does to the page's global scope, for
//! handing tainted globals from one `<script>` to the next (see
//! [`CarriedGlobals`](super::CarriedGlobals)).

use oxc_ast::ast::*;

#[derive(Default)]
pub(super) struct TopLevelWrites<'b> {
    /// Names a top-level statement declares (`var` / `let` / `const`) or
    /// assigns (`q = …`, also as a comma operand).
    pub(super) names: Vec<&'b str>,
    /// Names a top-level `function` / `class` declaration binds.
    pub(super) redeclared: Vec<&'b str>,
    /// The script has `import` / `export`: its top-level bindings are
    /// module-scoped, not globals.
    pub(super) is_module: bool,
}

pub(super) fn top_level_writes<'b>(body: &'b [Statement<'_>]) -> TopLevelWrites<'b> {
    let mut out = TopLevelWrites::default();
    for statement in body {
        match statement {
            Statement::VariableDeclaration(declaration) => {
                for declarator in &declaration.declarations {
                    if let BindingPattern::BindingIdentifier(id) = &declarator.id {
                        out.names.push(id.name.as_str());
                    }
                }
            }
            Statement::ExpressionStatement(statement) => {
                assigned_names(&statement.expression, &mut out.names);
            }
            Statement::FunctionDeclaration(function) => {
                if let Some(id) = &function.id {
                    out.redeclared.push(id.name.as_str());
                }
            }
            Statement::ClassDeclaration(class) => {
                if let Some(id) = &class.id {
                    out.redeclared.push(id.name.as_str());
                }
            }
            other => out.is_module |= other.is_module_declaration(),
        }
    }
    out
}

fn assigned_names<'b>(expr: &'b Expression<'_>, out: &mut Vec<&'b str>) {
    match expr {
        Expression::AssignmentExpression(assign) => {
            if let AssignmentTarget::AssignmentTargetIdentifier(id) = &assign.left {
                out.push(id.name.as_str());
            }
        }
        Expression::SequenceExpression(sequence) => {
            for operand in &sequence.expressions {
                if let Expression::AssignmentExpression(_) = operand {
                    assigned_names(operand, out);
                }
            }
        }
        Expression::ParenthesizedExpression(paren) => assigned_names(&paren.expression, out),
        _ => {}
    }
}
