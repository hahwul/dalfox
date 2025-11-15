//! Example demonstrating AST-based DOM XSS detection
//!
//! This example shows how to use the AST-based DOM XSS analyzer to detect
//! potential vulnerabilities in JavaScript code.
//!
//! Usage:
//!   cargo run --example ast_dom_xss_demo

// Since dalfox is a binary crate, we need to include the module directly
// In a real library, you would use: use dalfox::scanning::ast_dom_analysis::AstDomAnalyzer;

// For this example, we'll demonstrate the functionality inline
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
struct DomXssVulnerability {
    line: u32,
    column: u32,
    source: String,
    sink: String,
    snippet: String,
    description: String,
}

struct DomXssVisitor<'a> {
    tainted_vars: HashSet<String>,
    var_aliases: HashMap<String, String>,
    vulnerabilities: Vec<DomXssVulnerability>,
    sources: HashSet<String>,
    sinks: HashSet<String>,
    source_code: &'a str,
}

impl<'a> DomXssVisitor<'a> {
    fn new(source_code: &'a str) -> Self {
        let mut sources = HashSet::new();
        sources.insert("location.search".to_string());
        sources.insert("location.hash".to_string());
        sources.insert("document.cookie".to_string());

        let mut sinks = HashSet::new();
        sinks.insert("innerHTML".to_string());
        sinks.insert("eval".to_string());
        sinks.insert("document.write".to_string());

        Self {
            tainted_vars: HashSet::new(),
            var_aliases: HashMap::new(),
            vulnerabilities: Vec::new(),
            sources,
            sinks,
            source_code,
        }
    }

    fn get_expr_string(&self, expr: &Expression) -> Option<String> {
        match expr {
            Expression::Identifier(id) => Some(id.name.to_string()),
            Expression::StaticMemberExpression(member) => self.get_member_string(member),
            _ => None,
        }
    }

    fn get_member_string(&self, member: &StaticMemberExpression) -> Option<String> {
        let property = member.property.name.as_str();
        match &member.object {
            Expression::Identifier(id) => Some(format!("{}.{}", id.name.as_str(), property)),
            Expression::StaticMemberExpression(inner) => self
                .get_member_string(inner)
                .map(|obj| format!("{}.{}", obj, property)),
            _ => None,
        }
    }

    fn is_tainted(&self, expr: &Expression) -> bool {
        match expr {
            Expression::Identifier(id) => self.tainted_vars.contains(id.name.as_str()),
            Expression::StaticMemberExpression(member) => {
                if let Some(full_path) = self.get_member_string(member) {
                    self.sources.contains(&full_path)
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn report_vulnerability(&mut self, span: oxc_span::Span, sink: &str, description: &str) {
        let lines: Vec<&str> = self.source_code.lines().collect();
        let mut line = 1u32;
        let mut column = 1u32;
        let mut current_offset = 0usize;

        for (idx, line_text) in lines.iter().enumerate() {
            let line_len = line_text.len() + 1;
            if current_offset + line_len > span.start as usize {
                line = (idx + 1) as u32;
                column = (span.start as usize - current_offset + 1) as u32;
                break;
            }
            current_offset += line_len;
        }

        let snippet = if line > 0 && (line as usize) <= lines.len() {
            lines[(line - 1) as usize].trim().to_string()
        } else {
            String::new()
        };

        let source = self
            .tainted_vars
            .iter()
            .next()
            .and_then(|var| self.var_aliases.get(var))
            .cloned()
            .unwrap_or_else(|| "unknown source".to_string());

        self.vulnerabilities.push(DomXssVulnerability {
            line,
            column,
            source,
            sink: sink.to_string(),
            snippet,
            description: description.to_string(),
        });
    }

    fn walk_statements(&mut self, stmts: &[Statement<'a>]) {
        for stmt in stmts {
            self.walk_statement(stmt);
        }
    }

    fn walk_statement(&mut self, stmt: &Statement<'a>) {
        match stmt {
            Statement::VariableDeclaration(var_decl) => {
                for decl in &var_decl.declarations {
                    self.walk_variable_declarator(decl);
                }
            }
            Statement::ExpressionStatement(expr_stmt) => {
                self.walk_expression(&expr_stmt.expression);
            }
            _ => {}
        }
    }

    fn walk_variable_declarator(&mut self, decl: &VariableDeclarator<'a>) {
        if let Some(init) = &decl.init {
            if let BindingPatternKind::BindingIdentifier(id) = &decl.id.kind {
                let var_name = id.name.as_str();
                if let Some(source_expr) = self.get_expr_string(init) {
                    if self.sources.contains(&source_expr) {
                        self.tainted_vars.insert(var_name.to_string());
                        self.var_aliases
                            .insert(var_name.to_string(), source_expr.clone());
                    }
                }
                if self.is_tainted(init) {
                    self.tainted_vars.insert(var_name.to_string());
                }
            }
        }
    }

    fn walk_expression(&mut self, expr: &Expression<'a>) {
        match expr {
            Expression::AssignmentExpression(assign) => {
                self.walk_assignment_expression(assign);
            }
            Expression::CallExpression(call) => {
                self.walk_call_expression(call);
            }
            _ => {}
        }
    }

    fn walk_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        match &assign.left {
            AssignmentTarget::StaticMemberExpression(member) => {
                let prop_name = member.property.name.as_str();
                if self.sinks.contains(prop_name) && self.is_tainted(&assign.right) {
                    self.report_vulnerability(
                        assign.span(),
                        prop_name,
                        "Assignment to sink property",
                    );
                }
            }
            _ => {}
        }
        self.walk_expression(&assign.right);
    }

    fn walk_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some(func_name) = self.get_expr_string(&call.callee) {
            if self.sinks.contains(&func_name) {
                for arg in &call.arguments {
                    match arg {
                        Argument::Identifier(id)
                            if self.tainted_vars.contains(id.name.as_str()) =>
                        {
                            self.report_vulnerability(
                                call.span(),
                                &func_name,
                                "Tainted data passed to sink function",
                            );
                            break;
                        }
                        Argument::StaticMemberExpression(member) => {
                            if let Some(member_str) = self.get_member_string(member) {
                                if self.sources.contains(&member_str) {
                                    self.report_vulnerability(
                                        call.span(),
                                        &func_name,
                                        "Source data passed directly to sink function",
                                    );
                                    break;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        self.walk_expression(&call.callee);
    }
}

fn main() {
    let js_code = r#"
// Vulnerable: location.search -> innerHTML
let urlParam = location.search;
document.getElementById('foo').innerHTML = urlParam;

// Vulnerable: location.hash -> eval
let hash = location.hash;
eval(hash);

// Vulnerable: document.cookie -> document.write
let data = document.cookie;
document.write(data);

// Vulnerable: Direct source to sink
document.write(location.search);

// Safe: No tainted data
let safeData = "Hello World";
document.getElementById('bar').innerHTML = safeData;
"#;

    println!("🦊 Dalfox AST-based DOM XSS Analyzer\n");
    println!("Analyzing JavaScript code for DOM XSS vulnerabilities...\n");

    let allocator = Allocator::default();
    let source_type = SourceType::default();
    let ret = Parser::new(&allocator, js_code, source_type).parse();

    if !ret.errors.is_empty() {
        eprintln!("❌ Parse errors:");
        for error in ret.errors {
            eprintln!("  {}", error);
        }
        std::process::exit(1);
    }

    let mut visitor = DomXssVisitor::new(js_code);
    visitor.walk_statements(&ret.program.body);

    if visitor.vulnerabilities.is_empty() {
        println!("✓ No DOM XSS vulnerabilities detected!");
    } else {
        println!(
            "⚠️  Found {} potential DOM XSS vulnerabilit{}:\n",
            visitor.vulnerabilities.len(),
            if visitor.vulnerabilities.len() == 1 {
                "y"
            } else {
                "ies"
            }
        );

        for (i, vuln) in visitor.vulnerabilities.iter().enumerate() {
            println!(
                "{}. Vulnerability at line {}:{}:",
                i + 1,
                vuln.line,
                vuln.column
            );
            println!("   Description: {}", vuln.description);
            println!("   Source: {}", vuln.source);
            println!("   Sink: {}", vuln.sink);
            println!("   Code: {}", vuln.snippet);
            println!();
        }
    }
}
