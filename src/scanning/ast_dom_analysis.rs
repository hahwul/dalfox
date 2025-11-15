//! AST-based DOM XSS detection
//!
//! This module provides JavaScript AST parsing and taint analysis to detect
//! potential DOM-based XSS vulnerabilities by tracking data flow from untrusted
//! sources to dangerous sinks.

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};
use std::collections::{HashMap, HashSet};

/// Represents a potential DOM XSS vulnerability found via AST analysis
#[derive(Debug, Clone)]
pub struct DomXssVulnerability {
    /// Line number where the vulnerability was detected
    pub line: u32,
    /// Column number where the vulnerability was detected
    pub column: u32,
    /// The source of tainted data (e.g., "location.search")
    pub source: String,
    /// The sink where tainted data is used (e.g., "innerHTML")
    pub sink: String,
    /// Code snippet showing the vulnerable operation
    pub snippet: String,
    /// Description of the vulnerability
    pub description: String,
}

/// AST visitor for DOM XSS analysis
struct DomXssVisitor<'a> {
    /// Set of tainted variable names
    tainted_vars: HashSet<String>,
    /// Map of variable aliases (e.g., var x = location.search)
    var_aliases: HashMap<String, String>,
    /// List of detected vulnerabilities
    vulnerabilities: Vec<DomXssVulnerability>,
    /// Known DOM sources (untrusted input sources)
    sources: HashSet<String>,
    /// Known DOM sinks (dangerous operations)
    sinks: HashSet<String>,
    /// Known sanitizers
    sanitizers: HashSet<String>,
    /// Source code for line/column calculation
    source_code: &'a str,
}

impl<'a> DomXssVisitor<'a> {
    fn new(source_code: &'a str) -> Self {
        let mut sources = HashSet::new();
        // Common DOM XSS sources
        sources.insert("location.search".to_string());
        sources.insert("location.hash".to_string());
        sources.insert("location.href".to_string());
        sources.insert("document.URL".to_string());
        sources.insert("document.documentURI".to_string());
        sources.insert("document.URLUnencoded".to_string());
        sources.insert("document.baseURI".to_string());
        sources.insert("document.cookie".to_string());
        sources.insert("document.referrer".to_string());
        sources.insert("window.name".to_string());
        sources.insert("window.location".to_string());

        let mut sinks = HashSet::new();
        // Common DOM XSS sinks
        sinks.insert("innerHTML".to_string());
        sinks.insert("outerHTML".to_string());
        sinks.insert("insertAdjacentHTML".to_string());
        sinks.insert("document.write".to_string());
        sinks.insert("document.writeln".to_string());
        sinks.insert("eval".to_string());
        sinks.insert("setTimeout".to_string());
        sinks.insert("setInterval".to_string());
        sinks.insert("Function".to_string());
        sinks.insert("execScript".to_string());
        sinks.insert("location.href".to_string());
        sinks.insert("location.assign".to_string());
        sinks.insert("location.replace".to_string());

        let mut sanitizers = HashSet::new();
        sanitizers.insert("DOMPurify.sanitize".to_string());
        sanitizers.insert("sanitize".to_string());
        sanitizers.insert("encodeURIComponent".to_string());
        sanitizers.insert("encodeURI".to_string());

        Self {
            tainted_vars: HashSet::new(),
            var_aliases: HashMap::new(),
            vulnerabilities: Vec::new(),
            sources,
            sinks,
            sanitizers,
            source_code,
        }
    }

    /// Get a string representation of an expression if it's an identifier or member expression
    fn get_expr_string(&self, expr: &Expression) -> Option<String> {
        match expr {
            Expression::Identifier(id) => Some(id.name.to_string()),
            Expression::StaticMemberExpression(member) => self.get_member_string(member),
            _ => None,
        }
    }

    /// Get string representation of static member expression
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

    /// Check if expression is tainted
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
            Expression::TemplateLiteral(template) => {
                template.expressions.iter().any(|e| self.is_tainted(e))
            }
            Expression::BinaryExpression(binary) => {
                self.is_tainted(&binary.left) || self.is_tainted(&binary.right)
            }
            Expression::LogicalExpression(logical) => {
                self.is_tainted(&logical.left) || self.is_tainted(&logical.right)
            }
            Expression::ConditionalExpression(cond) => {
                self.is_tainted(&cond.consequent) || self.is_tainted(&cond.alternate)
            }
            Expression::CallExpression(call) => {
                // Check if it's a sanitizer
                if let Some(func_name) = self.get_expr_string(&call.callee) {
                    if self.sanitizers.contains(&func_name) {
                        return false; // Sanitized
                    }
                }
                // Check if any argument is tainted
                call.arguments.iter().any(|arg| {
                    if let Argument::SpreadElement(spread) = arg {
                        self.is_tainted(&spread.argument)
                    } else {
                        // For other argument types, check if they're expressions that are tainted
                        // This is a simplified check - a real implementation would handle all argument types
                        false
                    }
                })
            }
            _ => false,
        }
    }

    /// Report a vulnerability
    fn report_vulnerability(&mut self, span: oxc_span::Span, sink: &str, description: &str) {
        let lines: Vec<&str> = self.source_code.lines().collect();
        let mut line = 1u32;
        let mut column = 1u32;
        let mut current_offset = 0usize;

        for (idx, line_text) in lines.iter().enumerate() {
            let line_len = line_text.len() + 1; // +1 for newline
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

        // Find the source that led to this
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

    /// Walk through statements
    fn walk_statements(&mut self, stmts: &[Statement<'a>]) {
        for stmt in stmts {
            self.walk_statement(stmt);
        }
    }

    /// Walk through a single statement
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
            Statement::BlockStatement(block) => {
                self.walk_statements(&block.body);
            }
            Statement::IfStatement(if_stmt) => {
                self.walk_expression(&if_stmt.test);
                self.walk_statement(&if_stmt.consequent);
                if let Some(alt) = &if_stmt.alternate {
                    self.walk_statement(alt);
                }
            }
            Statement::WhileStatement(while_stmt) => {
                self.walk_expression(&while_stmt.test);
                self.walk_statement(&while_stmt.body);
            }
            Statement::ForStatement(for_stmt) => {
                if let Some(init) = &for_stmt.init {
                    match init {
                        ForStatementInit::VariableDeclaration(var_decl) => {
                            for decl in &var_decl.declarations {
                                self.walk_variable_declarator(decl);
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(test) = &for_stmt.test {
                    self.walk_expression(test);
                }
                if let Some(update) = &for_stmt.update {
                    self.walk_expression(update);
                }
                self.walk_statement(&for_stmt.body);
            }
            Statement::FunctionDeclaration(func_decl) => {
                if let Some(body) = &func_decl.body {
                    self.walk_statements(&body.statements);
                }
            }
            _ => {}
        }
    }

    /// Walk through a variable declarator
    fn walk_variable_declarator(&mut self, decl: &VariableDeclarator<'a>) {
        if let Some(init) = &decl.init {
            if let BindingPatternKind::BindingIdentifier(id) = &decl.id.kind {
                let var_name = id.name.as_str();

                // Check if initializer is a source or tainted
                if let Some(source_expr) = self.get_expr_string(init) {
                    if self.sources.contains(&source_expr) {
                        self.tainted_vars.insert(var_name.to_string());
                        self.var_aliases
                            .insert(var_name.to_string(), source_expr.clone());
                    }
                }

                // Also check if init expression is tainted (includes template literals)
                if self.is_tainted(init) {
                    self.tainted_vars.insert(var_name.to_string());
                }
            }
        }
    }

    /// Walk through an expression
    fn walk_expression(&mut self, expr: &Expression<'a>) {
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
            _ => {}
        }
    }

    /// Walk through an assignment expression
    fn walk_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        // Check if we're assigning to a sink property
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
            AssignmentTarget::AssignmentTargetIdentifier(id) => {
                let target_name = id.name.as_str();
                if self.sinks.contains(target_name) && self.is_tainted(&assign.right) {
                    self.report_vulnerability(assign.span(), target_name, "Assignment to sink");
                }
            }
            _ => {}
        }
        // Walk the right side
        self.walk_expression(&assign.right);
    }

    /// Walk through a call expression
    fn walk_call_expression(&mut self, call: &CallExpression<'a>) {
        // Check if calling a sink function
        if let Some(func_name) = self.get_expr_string(&call.callee) {
            if self.sinks.contains(&func_name) {
                // Check if any argument is tainted
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
        // Walk the callee
        self.walk_expression(&call.callee);
    }
}

/// AST-based DOM XSS analyzer
pub struct AstDomAnalyzer;

impl AstDomAnalyzer {
    /// Create a new AST DOM analyzer
    pub fn new() -> Self {
        Self
    }

    /// Analyze JavaScript source code for DOM XSS vulnerabilities
    pub fn analyze(&self, source_code: &str) -> Result<Vec<DomXssVulnerability>, String> {
        let allocator = Allocator::default();
        let source_type = SourceType::default();

        let ret = Parser::new(&allocator, source_code, source_type).parse();

        if !ret.errors.is_empty() {
            let error_messages: Vec<String> = ret.errors.iter().map(|e| e.to_string()).collect();
            return Err(format!("Parse errors: {}", error_messages.join(", ")));
        }

        let mut visitor = DomXssVisitor::new(source_code);
        visitor.walk_statements(&ret.program.body);

        Ok(visitor.vulnerabilities)
    }
}

impl Default for AstDomAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_dom_xss_detection() {
        let code = r#"
let urlParam = location.search;
document.getElementById('foo').innerHTML = urlParam;
"#;

        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code);

        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(
            !vulnerabilities.is_empty(),
            "Should detect at least one vulnerability"
        );

        let vuln = &vulnerabilities[0];
        assert!(vuln.sink.contains("innerHTML"));
        assert!(vuln.source.contains("location.search"));
    }

    #[test]
    fn test_eval_with_location_hash() {
        let code = r#"
let hash = location.hash;
eval(hash);
"#;

        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code);

        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(!vulnerabilities.is_empty());

        let vuln = &vulnerabilities[0];
        assert!(vuln.sink.contains("eval"));
    }

    #[test]
    fn test_document_write_with_cookie() {
        let code = r#"
let data = document.cookie;
document.write(data);
"#;

        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code);

        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(!vulnerabilities.is_empty());

        let vuln = &vulnerabilities[0];
        assert!(vuln.sink.contains("document.write"));
    }

    #[test]
    fn test_no_vulnerability_with_safe_data() {
        let code = r#"
let safeData = "Hello World";
document.getElementById('foo').innerHTML = safeData;
"#;

        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code);

        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert_eq!(vulnerabilities.len(), 0);
    }

    #[test]
    fn test_multiple_vulnerabilities() {
        let code = r#"
let param = location.search;
let hash = location.hash;
document.write(param);
eval(hash);
"#;

        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code);

        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(
            vulnerabilities.len() >= 2,
            "Should detect multiple vulnerabilities"
        );
    }

    #[test]
    fn test_parse_error_handling() {
        let code = r#"
let invalid = {{{
"#;

        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code);

        assert!(
            result.is_err(),
            "Should return error for invalid JavaScript"
        );
    }

    #[test]
    fn test_direct_source_to_sink() {
        let code = r#"
document.write(location.search);
"#;

        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code);

        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(
            !vulnerabilities.is_empty(),
            "Should detect direct source-to-sink vulnerability"
        );
    }

    #[test]
    fn test_template_literal_with_tainted_data() {
        let code = r#"
let search = location.search;
let html = `<div>${search}</div>`;
document.body.innerHTML = html;
"#;

        let analyzer = AstDomAnalyzer::new();
        let result = analyzer.analyze(code);

        assert!(result.is_ok());
        let vulnerabilities = result.unwrap();
        assert!(!vulnerabilities.is_empty());
    }
}
