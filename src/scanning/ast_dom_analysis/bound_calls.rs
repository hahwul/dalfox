//! Calls that reach their target indirectly: `bind`, `call`, `apply`, and
//! `Reflect.apply` / `Reflect.construct`.
//!
//! Each re-indexes the arguments the callee sees, so the argument a sink
//! actually receives has to be resolved through the alias before its taint can
//! be decided.

use super::*;

impl<'a> DomXssVisitor<'a> {
    pub(super) fn build_bound_alias_from_bind_call(
        &self,
        bind_call: &CallExpression<'a>,
    ) -> Option<BoundCallableAlias> {
        let wrapper_name = self.get_callee_property_name(&bind_call.callee)?;
        if wrapper_name != "bind" {
            return None;
        }
        let target_expr = self.get_callee_object_expr(&bind_call.callee)?;
        let mut target = self
            .get_summary_key_for_callee_expr(target_expr)
            .or_else(|| self.get_expr_string(target_expr))?;

        let mut bound_args = bind_call
            .arguments
            .iter()
            .skip(1)
            .map(|arg| {
                let (tainted, source) = self.argument_taint_and_source(arg);
                BoundArgInfo { tainted, source }
            })
            .collect::<Vec<_>>();

        // Preserve previously bound arguments across chained binds:
        // f1 = fn.bind(this, a); f2 = f1.bind(this2, b) -> args [a, b]
        if let Expression::Identifier(id) = target_expr
            && let Some(existing_alias) = self.bound_function_aliases.get(id.name.as_str())
        {
            target = existing_alias.target.clone();
            let mut chained_args = existing_alias.bound_args.clone();
            chained_args.extend(bound_args);
            bound_args = chained_args;
        }

        Some(BoundCallableAlias { target, bound_args })
    }
    pub(super) fn resolve_param_argument_taint(
        &self,
        call: &CallExpression<'a>,
        alias: Option<&BoundCallableAlias>,
        param_idx: usize,
    ) -> (bool, Option<String>) {
        if let Some(bound_alias) = alias {
            if let Some(bound_arg) = bound_alias.bound_args.get(param_idx) {
                return (bound_arg.tainted, bound_arg.source.clone());
            }
            let call_idx = param_idx.saturating_sub(bound_alias.bound_args.len());
            if param_idx >= bound_alias.bound_args.len()
                && let Some(arg) = call.arguments.get(call_idx)
            {
                return self.argument_taint_and_source(arg);
            }
            return (false, None);
        }

        if let Some(arg) = call.arguments.get(param_idx) {
            self.argument_taint_and_source(arg)
        } else {
            (false, None)
        }
    }
    pub(super) fn resolve_apply_argument_taint_at(
        &self,
        arg_array: &Argument<'a>,
        param_idx: usize,
    ) -> (bool, Option<String>) {
        if let Some(expr) = arg_array.as_expression()
            && let Expression::ArrayExpression(array) = expr
        {
            let mut current_idx = 0usize;
            for elem in &array.elements {
                match elem {
                    ArrayExpressionElement::Elision(_) => {
                        if current_idx == param_idx {
                            return (false, None);
                        }
                        current_idx += 1;
                    }
                    ArrayExpressionElement::SpreadElement(spread) => {
                        let tainted = self.is_tainted(&spread.argument);
                        return (
                            tainted,
                            if tainted {
                                self.find_source_in_expr(&spread.argument)
                            } else {
                                None
                            },
                        );
                    }
                    _ => {
                        if let Some(elem_expr) = elem.as_expression()
                            && current_idx == param_idx
                        {
                            let tainted = self.is_tainted(elem_expr);
                            return (
                                tainted,
                                if tainted {
                                    self.find_source_in_expr(elem_expr)
                                } else {
                                    None
                                },
                            );
                        }
                        current_idx += 1;
                    }
                }
            }
            return (false, None);
        }

        self.argument_taint_and_source(arg_array)
    }
    pub(super) fn resolve_apply_static_string_at(
        &self,
        arg_array: &Argument<'a>,
        param_idx: usize,
    ) -> Option<String> {
        let expr = arg_array.as_expression()?;
        let Expression::ArrayExpression(array) = expr else {
            return None;
        };

        let mut current_idx = 0usize;
        for elem in &array.elements {
            match elem {
                ArrayExpressionElement::Elision(_) => {
                    if current_idx == param_idx {
                        return None;
                    }
                    current_idx += 1;
                }
                ArrayExpressionElement::SpreadElement(_) => {
                    return None;
                }
                _ => {
                    if let Some(elem_expr) = elem.as_expression()
                        && current_idx == param_idx
                    {
                        return self.eval_static_string_expr(elem_expr);
                    }
                    current_idx += 1;
                }
            }
        }

        None
    }
    pub(super) fn resolve_wrapper_param_argument_taint(
        &self,
        call: &CallExpression<'a>,
        wrapper_name: &str,
        alias: Option<&BoundCallableAlias>,
        param_idx: usize,
    ) -> (bool, Option<String>) {
        if let Some(bound_alias) = alias {
            if let Some(bound_arg) = bound_alias.bound_args.get(param_idx) {
                return (bound_arg.tainted, bound_arg.source.clone());
            }
            if param_idx >= bound_alias.bound_args.len() {
                let shifted_idx = param_idx - bound_alias.bound_args.len();
                if wrapper_name == "call" {
                    if let Some(arg) = call.arguments.get(shifted_idx + 1) {
                        return self.argument_taint_and_source(arg);
                    }
                } else if wrapper_name == "apply"
                    && let Some(arg_array) = call.arguments.get(1)
                {
                    return self.resolve_apply_argument_taint_at(arg_array, shifted_idx);
                }
            }
            return (false, None);
        }

        if wrapper_name == "call" {
            if let Some(arg) = call.arguments.get(param_idx + 1) {
                return self.argument_taint_and_source(arg);
            }
        } else if wrapper_name == "apply"
            && let Some(arg_array) = call.arguments.get(1)
        {
            return self.resolve_apply_argument_taint_at(arg_array, param_idx);
        }

        (false, None)
    }
    pub(super) fn resolve_reflect_apply_param_argument_taint(
        &self,
        call: &CallExpression<'a>,
        alias: Option<&BoundCallableAlias>,
        param_idx: usize,
    ) -> (bool, Option<String>) {
        if let Some(bound_alias) = alias {
            if let Some(bound_arg) = bound_alias.bound_args.get(param_idx) {
                return (bound_arg.tainted, bound_arg.source.clone());
            }
            if param_idx >= bound_alias.bound_args.len()
                && let Some(arg_array) = call.arguments.get(2)
            {
                let shifted_idx = param_idx - bound_alias.bound_args.len();
                return self.resolve_apply_argument_taint_at(arg_array, shifted_idx);
            }
            return (false, None);
        }

        if let Some(arg_array) = call.arguments.get(2) {
            self.resolve_apply_argument_taint_at(arg_array, param_idx)
        } else {
            (false, None)
        }
    }
    pub(super) fn get_alias_for_expr(&self, expr: &Expression<'a>) -> Option<&BoundCallableAlias> {
        if let Expression::Identifier(id) = expr {
            self.bound_function_aliases.get(id.name.as_str())
        } else {
            None
        }
    }
    pub(super) fn get_callable_target_alias_from_argument(
        &self,
        arg: &Argument<'a>,
    ) -> Option<&BoundCallableAlias> {
        arg.as_expression()
            .and_then(|expr| self.get_alias_for_expr(expr))
    }
    pub(super) fn get_callable_target_key_from_argument(
        &self,
        arg: &Argument<'a>,
    ) -> Option<String> {
        let expr = arg.as_expression()?;
        let mut key = self
            .get_summary_key_for_callee_expr(expr)
            .or_else(|| self.get_expr_string(expr));

        if key
            .as_ref()
            .and_then(|k| self.function_summaries.get(k))
            .is_none()
            && let Some(alias) = self.get_alias_for_expr(expr)
        {
            key = Some(alias.target.clone());
        }

        key
    }
    pub(super) fn get_sink_name_for_callable_expr(&self, expr: &Expression<'a>) -> Option<String> {
        if let Some(full_name) = self.get_expr_string(expr)
            && self.sinks.contains(full_name.as_str())
        {
            return Some(full_name);
        }
        if let Some(method_name) = self.get_callee_property_name(expr)
            && self.sinks.contains(method_name.as_str())
        {
            return Some(method_name);
        }
        None
    }
    pub(super) fn get_alias_for_callee_identifier(
        &self,
        call: &CallExpression<'a>,
    ) -> Option<&BoundCallableAlias> {
        if let Expression::Identifier(id) = &call.callee {
            self.bound_function_aliases.get(id.name.as_str())
        } else {
            None
        }
    }
}
