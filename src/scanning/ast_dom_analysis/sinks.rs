//! Where a tainted value lands: assignment sinks (`innerHTML =`), method
//! sinks (`el.insertAdjacentHTML(…)`), and the call forms that reach one
//! indirectly through a summary, a wrapper, or `Reflect`.

use super::*;

impl<'a> DomXssVisitor<'a> {
    /// Walk through an assignment expression
    pub(super) fn walk_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        let right_tainted = self.is_tainted(&assign.right);
        let right_source = if right_tainted {
            self.find_source_in_expr(&assign.right)
        } else {
            None
        };

        // Check if we're assigning to a sink property
        match &assign.left {
            AssignmentTarget::StaticMemberExpression(member) => {
                let prop_name = member.property.name.as_str();
                self.analyze_onmessage_assignment(
                    assign.span(),
                    &member.object,
                    prop_name,
                    &assign.right,
                );
                // Script-element body assignments (e.g. `s.text = tainted`
                // where `s` came from `document.createElement('script')`).
                // The browser parses the value as JS source once the
                // element is inserted, so this is a real eval-equivalent
                // sink that the generic `is_assignment_sink_property`
                // check below would miss.
                let script_text_sink = right_tainted
                    && Self::is_script_element_text_sink_prop(prop_name)
                    && self.expr_resolves_to_script_element(&member.object);
                if script_text_sink {
                    self.report_vulnerability_with_source(
                        assign.span(),
                        &format!("script.{prop_name}"),
                        "Assignment to script-element body executes as JS",
                        right_source.clone(),
                    );
                }
                // Suppress the generic assignment-sink path when the more
                // specific script-element sink already fired — otherwise
                // `s.innerHTML = tainted` (where `s` is a script element)
                // would surface twice, once as `script.innerHTML` and once
                // as the generic `innerHTML`. The script-element form is
                // the correct one for PoC payload selection.
                let is_sink = !script_text_sink && self.is_assignment_sink_property(prop_name);

                // Also check if the full member path is a sink (e.g., location.href)
                let full_path_is_sink = if let Some(full_path) = self.get_member_string(member) {
                    self.sinks.contains(full_path.as_str())
                } else {
                    false
                };

                if (is_sink || full_path_is_sink) && self.is_tainted(&assign.right) {
                    let sink_name = if full_path_is_sink {
                        self.get_member_string(member)
                            .unwrap_or_else(|| prop_name.to_string())
                    } else {
                        prop_name.to_string()
                    };

                    self.report_vulnerability_with_source(
                        assign.span(),
                        &sink_name,
                        "Assignment to sink property",
                        right_source.clone(),
                    );
                }

                // Track field-level taint for property assignments like:
                // obj.payload = location.hash; sink(obj.payload)
                if right_tainted {
                    if let Some(full_path) = self.get_member_string(member) {
                        if let Some(source) = right_source.clone() {
                            self.field_taints.insert(full_path.clone(), source.clone());
                        } else {
                            self.field_taints
                                .insert(full_path.clone(), "unknown".to_string());
                        }
                    }
                    // Also propagate to object level
                    if let Expression::Identifier(obj_id) = &member.object {
                        self.tainted_vars.insert(obj_id.name.to_string());
                        if let Some(source) = right_source.clone() {
                            self.var_aliases.insert(obj_id.name.to_string(), source);
                        }
                    }
                }
            }
            AssignmentTarget::ComputedMemberExpression(member) => {
                let prop_name = self.get_computed_property_string(member);
                if let Some(property_name) = prop_name.as_deref() {
                    self.analyze_onmessage_assignment(
                        assign.span(),
                        &member.object,
                        property_name,
                        &assign.right,
                    );
                }
                let is_sink = prop_name
                    .as_deref()
                    .is_some_and(|name| self.is_assignment_sink_property(name));
                let full_path_is_sink = self
                    .get_computed_member_string(member)
                    .is_some_and(|full_path| self.sinks.contains(full_path.as_str()));

                if (is_sink || full_path_is_sink) && right_tainted {
                    let sink_name = if full_path_is_sink {
                        self.get_computed_member_string(member)
                            .or(prop_name.clone())
                            .unwrap_or_else(|| "computed_member".to_string())
                    } else {
                        prop_name.unwrap_or_else(|| "computed_member".to_string())
                    };

                    self.report_vulnerability_with_source(
                        assign.span(),
                        &sink_name,
                        "Assignment to sink property",
                        right_source.clone(),
                    );
                }

                // Propagate taint to base object for computed assignments:
                // arr[0] = location.hash; sink(arr[0])
                if right_tainted && let Expression::Identifier(obj_id) = &member.object {
                    self.tainted_vars.insert(obj_id.name.to_string());
                    if let Some(source) = right_source.clone() {
                        self.var_aliases.insert(obj_id.name.to_string(), source);
                    }
                }
            }
            AssignmentTarget::AssignmentTargetIdentifier(id) => {
                let target_name = id.name.as_str();
                let mut assigned_instance_class = false;
                if let Expression::NewExpression(new_expr) = &assign.right
                    && let Expression::Identifier(class_id) = &new_expr.callee
                {
                    self.instance_classes
                        .insert(target_name.to_string(), class_id.name.to_string());
                    assigned_instance_class = true;
                }
                if !assigned_instance_class {
                    self.instance_classes.remove(target_name);
                }

                let mut assigned_bind_alias = false;
                if let Expression::CallExpression(bind_call) = &assign.right
                    && let Some(alias) = self.build_bound_alias_from_bind_call(bind_call)
                {
                    self.bound_function_aliases
                        .insert(target_name.to_string(), alias);
                    assigned_bind_alias = true;
                }
                if !assigned_bind_alias {
                    self.bound_function_aliases.remove(target_name);
                }

                // `p = trustedTypes.createPolicy(name, {...})` assignment form.
                self.record_tt_policy_binding(target_name, &assign.right);

                // Propagate taint through direct assignments like `a = taintedValue;`
                if right_tainted {
                    self.tainted_vars.insert(target_name.to_string());
                    if let Some(source) = right_source.clone() {
                        self.var_aliases.insert(target_name.to_string(), source);
                    }
                } else if self.branch_depth == 0 {
                    // Reassigning a previously-tainted variable to a clean or
                    // sanitized value clears its taint — e.g.
                    // `x = location.hash; x = DOMPurify.sanitize(x)` or
                    // `x = "static"`. Without this the flow-insensitive walker
                    // keeps the stale taint and reports a false positive at any
                    // later sink that reads `x`. This mirrors the
                    // `instance_classes` / `bound_function_aliases` clears just
                    // above. Because the walker runs top-to-bottom, a sink that
                    // consumed the tainted value *before* this reassignment was
                    // already reported, so confirmed flows are not lost.
                    //
                    // Only clear at `branch_depth == 0` (unconditional
                    // reassignment). Taint is a union over paths, so a clean
                    // assignment inside one conditional branch must not drop
                    // taint set on a sibling branch
                    // (`if (c) out = taint; else out = 'x'; sink(out)`).
                    self.tainted_vars.remove(target_name);
                    self.var_aliases.remove(target_name);
                }

                if self.is_assignment_sink_property(target_name) && right_tainted {
                    self.report_vulnerability_with_source(
                        assign.span(),
                        target_name,
                        "Assignment to sink",
                        right_source.clone(),
                    );
                }
            }
            _ => {}
        }
        // Walk the right side
        self.walk_expression(&assign.right);
    }
    /// A call whose *member method* names a sink (`el.insertAdjacentHTML(...)`, `document['write'](...)`), including the computed-property spelling.
    pub(super) fn handle_member_method_sink(&mut self, call: &CallExpression<'a>) -> bool {
        // Also treat member method name itself as sink
        // (e.g., el.insertAdjacentHTML, document['write'](...))
        let member_method_name = self.get_callee_property_name(&call.callee);
        if let Some(method_name) = member_method_name
            && self.sinks.contains(method_name.as_str())
        {
            // Special-case setAttribute to only dangerous attributes
            if method_name == "setAttribute" && call.arguments.len() >= 2 {
                let attr_name_lc = call
                    .arguments
                    .first()
                    .and_then(|arg0| self.eval_static_string_arg(arg0))
                    .map(|name| name.to_ascii_lowercase());
                if let Some(name) = attr_name_lc {
                    let dangerous = name.starts_with("on")
                        || name == "href"
                        || name == "xlink:href"
                        || name == "srcdoc";
                    if dangerous && let Some(arg1) = call.arguments.get(1) {
                        let (tainted, source_hint) = self.argument_taint_and_source(arg1);
                        if tainted {
                            self.report_vulnerability_with_source(
                                call.span(),
                                &format!("setAttribute:{}", name),
                                "Tainted data assigned to dangerous attribute",
                                source_hint,
                            );
                            return true;
                        }
                    }
                }
            // `setAttributeNS(ns, name, value)` — same dangerous-attribute
            // filter as `setAttribute`, shifted one index for the namespace.
            } else if method_name == "setAttributeNS" && call.arguments.len() >= 3 {
                let attr_name_lc = call
                    .arguments
                    .get(1)
                    .and_then(|arg1| self.eval_static_string_arg(arg1))
                    .map(|name| name.to_ascii_lowercase());
                if let Some(name) = attr_name_lc {
                    // Namespaced attribute names arrive as `xlink:href` or a
                    // bare local name depending on the call, so match both.
                    let local = name.rsplit(':').next().unwrap_or(&name);
                    let dangerous = local.starts_with("on")
                        || local == "href"
                        || local == "srcdoc"
                        || name == "xlink:href";
                    if dangerous && let Some(arg2) = call.arguments.get(2) {
                        let (tainted, source_hint) = self.argument_taint_and_source(arg2);
                        if tainted {
                            self.report_vulnerability_with_source(
                                call.span(),
                                &format!("setAttributeNS:{}", name),
                                "Tainted data assigned to dangerous namespaced attribute",
                                source_hint,
                            );
                            return true;
                        }
                    }
                }
            // `parseFromString(str, mime)` only builds a DOM that can carry
            // script for HTML/XHTML/SVG MIME types. A `text/xml` /
            // `application/json`-style parse cannot produce executable nodes,
            // so restrict to the HTML-ish types; an unknown (non-literal) MIME
            // still fires, to fail toward reporting.
            } else if method_name == "parseFromString" {
                let mime = call
                    .arguments
                    .get(1)
                    .and_then(|arg1| self.eval_static_string_arg(arg1))
                    .map(|m| m.trim().to_ascii_lowercase());
                let html_ish = match mime.as_deref() {
                    None => true,
                    Some(m) => matches!(m, "text/html" | "application/xhtml+xml" | "image/svg+xml"),
                };
                if html_ish && let Some(arg0) = call.arguments.first() {
                    let (tainted, source_hint) = self.argument_taint_and_source(arg0);
                    if tainted {
                        self.report_vulnerability_with_source(
                                call.span(),
                                "parseFromString",
                                "Tainted data parsed as HTML (executes once the nodes are adopted into the live document)",
                                source_hint,
                            );
                        return true;
                    }
                }
            // Special-case execCommand - only insertHTML is dangerous, and the third arg is the value
            } else if method_name == "execCommand" && call.arguments.len() >= 3 {
                let cmd_name_lc = call
                    .arguments
                    .first()
                    .and_then(|arg0| self.eval_static_string_arg(arg0))
                    .map(|name| name.to_ascii_lowercase());
                if let Some(cmd) = cmd_name_lc
                    && cmd == "inserthtml"
                    && let Some(arg2) = call.arguments.get(2)
                {
                    let (tainted, source_hint) = self.argument_taint_and_source(arg2);
                    if tainted {
                        self.report_vulnerability_with_source(
                            call.span(),
                            "execCommand:insertHTML",
                            "Tainted data passed to insertHTML command",
                            source_hint,
                        );
                        return true;
                    }
                }
            } else if matches!(
                method_name.as_str(),
                "append" | "prepend" | "after" | "before"
            ) && !Self::callee_receiver_is_jquery_chain(&call.callee)
            {
                // FP suppression: native `Element.append / .prepend / .after
                // / .before` insert string arguments as text nodes — they do
                // NOT parse HTML and cannot trigger script execution. Only
                // jQuery's same-named methods are real HTML sinks (they call
                // `innerHTML` internally). Without a `$(...)` / `jQuery(...)`
                // receiver chain, treat these method calls as inert.
                //
                // Falls through to walk the callee so taint tracking through
                // arguments and sub-expressions still proceeds.
            } else {
                // Generic method sink: if any argument is tainted
                let mut tainted_source: Option<String> = None;
                for (idx, arg) in call.arguments.iter().enumerate() {
                    // For insertAdjacentHTML, the second argument is HTML
                    let consider = if method_name == "insertAdjacentHTML" {
                        idx == 1
                    } else {
                        true
                    };
                    if !consider {
                        continue;
                    }
                    let (tainted, source_hint) = self.argument_taint_and_source(arg);
                    if tainted {
                        tainted_source = source_hint;
                        break;
                    }
                }
                if tainted_source.is_some() {
                    self.report_vulnerability_with_source(
                        call.span(),
                        &method_name,
                        "Tainted data passed to sink method",
                        tainted_source,
                    );
                    return true;
                }
            }
        }
        false
    }
    /// Inter-procedural flow via the function summary, then the direct-sink case (`document.write(...)`). Kept together because the sink branch reads the callee alias the summary branch resolved.
    pub(super) fn handle_summary_and_sink_call(&mut self, call: &CallExpression<'a>) -> bool {
        // Lightweight inter-procedural flow via function summary:
        // If summary says parameter[i] reaches sink S and argument[i] is tainted,
        // report vulnerability at call site.
        let mut summary_key = self.get_summary_key_for_callee_expr(&call.callee);
        if let Expression::Identifier(id) = &call.callee
            && (summary_key.is_none()
                || summary_key
                    .as_ref()
                    .and_then(|k| self.function_summaries.get(k))
                    .is_none())
        {
            summary_key = self
                .bound_function_aliases
                .get(id.name.as_str())
                .map(|alias| alias.target.clone())
                .or(summary_key);
        }
        let alias_owned = self.get_alias_for_callee_identifier(call).cloned();
        if let Some(callee_key) = summary_key
            && let Some(param_sinks) = self.function_summaries.get(&callee_key).map(|summary| {
                summary
                    .tainted_param_sinks
                    .iter()
                    .map(|(idx, sink)| (*idx, sink.clone()))
                    .collect::<Vec<_>>()
            })
        {
            for (idx, sink_name) in param_sinks {
                let (tainted, source_hint) =
                    self.resolve_param_argument_taint(call, alias_owned.as_ref(), idx);
                if tainted {
                    self.report_vulnerability_with_source(
                        call.span(),
                        &sink_name,
                        "Tainted argument reaches sink through function call",
                        source_hint,
                    );
                    break;
                }
            }
        }

        // Check if calling a sink function (full name like document.write)
        let direct_sink_name = self
            .get_expr_string(&call.callee)
            .filter(|name| self.sinks.contains(name.as_str()));
        let bound_sink_name = if direct_sink_name.is_none() {
            if let Expression::Identifier(id) = &call.callee {
                self.bound_function_aliases
                    .get(id.name.as_str())
                    .and_then(|alias| {
                        if self.sinks.contains(alias.target.as_str()) {
                            Some(alias.target.clone())
                        } else {
                            None
                        }
                    })
            } else {
                None
            }
        } else {
            None
        };
        if let Some(func_name) = direct_sink_name
            .or(bound_sink_name)
            .or_else(|| self.indirect_call_sink_name(call))
        {
            if let Some(bound_alias) = alias_owned.as_ref()
                && self.sinks.contains(bound_alias.target.as_str())
            {
                for bound_arg in &bound_alias.bound_args {
                    if bound_arg.tainted {
                        self.report_vulnerability_with_source(
                            call.span(),
                            &func_name,
                            "Tainted pre-bound argument reaches sink function",
                            bound_arg.source.clone(),
                        );
                        return true;
                    }
                }
            }

            // Check if any argument is tainted. For the timer / code sinks
            // (setTimeout / setInterval / execScript) only the FIRST argument is
            // the executed code — a tainted 2nd `delay` argument
            // (`setTimeout(fn, location.hash)`) is not exploitable, so consider
            // index 0 only (mirroring the setAttribute / execCommand
            // positional special-cases below). The `*.open` navigation sinks are
            // the same shape: only argument-0 (the URL) is exploitable; a
            // tainted window-name (`window.open('/x', location.hash)`) or
            // features string is not.
            let first_arg_only = matches!(
                func_name.as_str(),
                "setTimeout"
                    | "setInterval"
                    | "execScript"
                    | "window.open"
                    | "self.open"
                    | "globalThis.open"
            );
            for (idx, arg) in call.arguments.iter().enumerate() {
                if first_arg_only && idx != 0 {
                    continue;
                }
                let (is_arg_tainted, source_hint) = self.argument_taint_and_source(arg);

                if is_arg_tainted {
                    self.report_vulnerability_with_source(
                        call.span(),
                        &func_name,
                        "Tainted data passed to sink function",
                        source_hint,
                    );
                    break;
                }
            }
        }
        false
    }
    /// Taint propagation through mutating methods: a tainted argument makes the
    /// receiver tainted. Covers `push` / `unshift` / `splice`, plus `set` on a
    /// tracked `URLSearchParams` object.
    pub(super) fn propagate_mutation_taint(&mut self, call: &CallExpression<'a>) {
        // Propagate taint through common mutation methods.
        // e.g. arr.push(location.hash); document.write(arr[0]);
        // e.g. params.set('html', tainted); replay = new URLSearchParams(params.toString());
        if let Some(method) = self.get_callee_property_name(&call.callee)
            && let Some(target_obj) = self.get_callee_object_expr(&call.callee)
            && let Expression::Identifier(id) = target_obj
        {
            let target = id.name.as_str();
            let mut tainted_source: Option<String> = None;

            match method.as_str() {
                "push" | "unshift" => {
                    for arg in &call.arguments {
                        let (is_arg_tainted, source_hint) = self.argument_taint_and_source(arg);
                        if is_arg_tainted {
                            tainted_source = source_hint;
                            break;
                        }
                    }
                }
                "splice" => {
                    // splice(start, deleteCount, ...items): only items can introduce taint
                    for arg in call.arguments.iter().skip(2) {
                        let (is_arg_tainted, source_hint) = self.argument_taint_and_source(arg);
                        if is_arg_tainted {
                            tainted_source = source_hint;
                            break;
                        }
                    }
                }
                "set" if self.url_search_params_objects.contains(target) => {
                    if let Some(arg) = call.arguments.get(1) {
                        let (is_arg_tainted, source_hint) = self.argument_taint_and_source(arg);
                        if is_arg_tainted {
                            tainted_source = source_hint;
                            if let Some(param_name) = Self::extract_static_string_argument(call, 0)
                                && let Some(source) = tainted_source.clone()
                            {
                                self.url_search_params_field_sources.insert(
                                    Self::url_search_params_field_key(target, &param_name),
                                    source,
                                );
                            }
                        }
                    }
                }
                _ => {}
            }

            if let Some(source) = tainted_source {
                self.tainted_vars.insert(target.to_string());
                self.var_aliases.insert(target.to_string(), source.clone());
                if method == "set" && self.url_search_params_objects.contains(target) {
                    self.url_search_params_sources
                        .insert(target.to_string(), source);
                }
            }
        }
    }
    /// `sink.call(thisArg, tainted)` / `sink.apply(thisArg, [tainted])`, and the
    /// same two forms on a helper that carries a function summary.
    ///
    /// Only these two spellings — the callee's *property* must literally be
    /// `call` or `apply`. A callee that is an alias of a sink
    /// (`const f = eval; f(x)`) is resolved later, by the
    /// `bound_function_aliases` / `indirect_call_sink_name` lookup inside
    /// [`Self::handle_summary_and_sink_call`]; moving this helper past that
    /// stage would not pick those up, it would just reorder two unrelated
    /// checks.
    pub(super) fn handle_wrapper_invocation(&mut self, call: &CallExpression<'a>) -> bool {
        // Handle wrapper invocations:
        // - sink.call(thisArg, tainted)
        // - sink.apply(thisArg, [tainted])
        // - helper.call(thisArg, tainted) where helper has function summary
        if let Some(wrapper_name) = self.get_callee_property_name(&call.callee)
            && (wrapper_name == "call" || wrapper_name == "apply")
            && let Some(target_expr) = self.get_callee_object_expr(&call.callee)
        {
            let target_alias_owned = self.get_alias_for_expr(target_expr).cloned();
            let mut target_summary_key = self.get_summary_key_for_callee_expr(target_expr);
            if target_summary_key
                .as_ref()
                .and_then(|k| self.function_summaries.get(k))
                .is_none()
                && let Some(alias) = target_alias_owned.as_ref()
            {
                target_summary_key = Some(alias.target.clone());
            }
            if let Some(summary_key) = target_summary_key
                && let Some(param_sinks) =
                    self.function_summaries.get(&summary_key).map(|summary| {
                        summary
                            .tainted_param_sinks
                            .iter()
                            .map(|(idx, sink)| (*idx, sink.clone()))
                            .collect::<Vec<_>>()
                    })
            {
                for (idx, sink_name) in param_sinks {
                    let (tainted, source_hint) = self.resolve_wrapper_param_argument_taint(
                        call,
                        &wrapper_name,
                        target_alias_owned.as_ref(),
                        idx,
                    );
                    if tainted {
                        let description = if wrapper_name == "call" {
                            "Tainted argument reaches sink through function.call wrapper"
                        } else {
                            "Tainted argument reaches sink through function.apply wrapper"
                        };
                        self.report_vulnerability_with_source(
                            call.span(),
                            &sink_name,
                            description,
                            source_hint,
                        );
                        return true;
                    }
                }
            }

            let mut target_func_name = self.get_expr_string(target_expr);
            if target_func_name
                .as_ref()
                .is_none_or(|name| !self.sinks.contains(name.as_str()))
                && let Some(alias) = target_alias_owned.as_ref()
                && self.sinks.contains(alias.target.as_str())
            {
                target_func_name = Some(alias.target.clone());
            }

            if let Some(target_func_name) =
                target_func_name.filter(|name| self.sinks.contains(name.as_str()))
            {
                if let Some(target_alias) = target_alias_owned.as_ref()
                    && self.sinks.contains(target_alias.target.as_str())
                {
                    for bound_arg in &target_alias.bound_args {
                        if bound_arg.tainted {
                            self.report_vulnerability_with_source(
                                call.span(),
                                &target_func_name,
                                "Tainted pre-bound argument reaches sink function via wrapper",
                                bound_arg.source.clone(),
                            );
                            return true;
                        }
                    }
                }

                if wrapper_name == "call" {
                    for arg in call.arguments.iter().skip(1) {
                        let (tainted, source_hint) = self.argument_taint_and_source(arg);
                        if tainted {
                            self.report_vulnerability_with_source(
                                call.span(),
                                &target_func_name,
                                "Tainted data passed to sink function via .call wrapper",
                                source_hint,
                            );
                            return true;
                        }
                    }
                } else if let Some(arg_array) = call.arguments.get(1) {
                    let (tainted, source_hint) = self.argument_taint_and_source(arg_array);
                    if tainted {
                        self.report_vulnerability_with_source(
                            call.span(),
                            &target_func_name,
                            "Tainted data passed to sink function via .apply wrapper",
                            source_hint,
                        );
                        return true;
                    }
                }
            }
        }
        false
    }
    /// `Reflect.construct(Function, [taintedCode])` — the constructor form of dynamic code evaluation.
    pub(super) fn handle_reflect_construct(&mut self, call: &CallExpression<'a>) -> bool {
        // Handle Reflect.construct(Function, [taintedCode])
        if let Some(callee_name) = self.get_expr_string(&call.callee)
            && callee_name == "Reflect.construct"
            && call.arguments.len() >= 2
        {
            let target_key = call
                .arguments
                .first()
                .and_then(|arg0| self.get_callable_target_key_from_argument(arg0));
            if target_key.as_deref() == Some("Function")
                && let Some(arg_array) = call.arguments.get(1)
            {
                let (tainted, source_hint) = self.resolve_apply_argument_taint_at(arg_array, 0);
                if tainted {
                    self.report_vulnerability_with_source(
                        call.span(),
                        "Function",
                        "Tainted data passed to Function constructor via Reflect.construct",
                        source_hint,
                    );
                    return true;
                }
            }
        }
        false
    }
    /// `Reflect.apply(fn, thisArg, [args])` — resolve the target function and propagate taint through it as if it had been called directly.
    pub(super) fn handle_reflect_apply(&mut self, call: &CallExpression<'a>) -> bool {
        // Handle Reflect.apply(targetFn, thisArg, argsArray)
        if let Some(callee_name) = self.get_expr_string(&call.callee)
            && callee_name == "Reflect.apply"
            && call.arguments.len() >= 3
        {
            let target_arg = call.arguments.first();
            let target_expr = target_arg.and_then(|arg| arg.as_expression());
            let target_alias_owned = target_arg
                .and_then(|arg0| self.get_callable_target_alias_from_argument(arg0))
                .cloned();
            let mut target_summary_key =
                target_arg.and_then(|arg0| self.get_callable_target_key_from_argument(arg0));

            if target_summary_key
                .as_ref()
                .and_then(|k| self.function_summaries.get(k))
                .is_none()
                && let Some(alias) = target_alias_owned.as_ref()
            {
                target_summary_key = Some(alias.target.clone());
            }

            if let Some(summary_key) = target_summary_key
                && let Some(param_sinks) =
                    self.function_summaries.get(&summary_key).map(|summary| {
                        summary
                            .tainted_param_sinks
                            .iter()
                            .map(|(idx, sink)| (*idx, sink.clone()))
                            .collect::<Vec<_>>()
                    })
            {
                for (idx, sink_name) in param_sinks {
                    let (tainted, source_hint) = self.resolve_reflect_apply_param_argument_taint(
                        call,
                        target_alias_owned.as_ref(),
                        idx,
                    );
                    if tainted {
                        self.report_vulnerability_with_source(
                            call.span(),
                            &sink_name,
                            "Tainted argument reaches sink through Reflect.apply",
                            source_hint,
                        );
                        return true;
                    }
                }
            }

            let mut target_sink_name =
                target_expr.and_then(|expr| self.get_sink_name_for_callable_expr(expr));
            if target_sink_name.is_none()
                && let Some(alias) = target_alias_owned.as_ref()
                && self.sinks.contains(alias.target.as_str())
            {
                target_sink_name = Some(alias.target.clone());
            }

            if let Some(sink_name) = target_sink_name {
                if let Some(target_alias) = target_alias_owned.as_ref()
                    && self.sinks.contains(target_alias.target.as_str())
                {
                    for bound_arg in &target_alias.bound_args {
                        if bound_arg.tainted {
                            self.report_vulnerability_with_source(
                                    call.span(),
                                    &sink_name,
                                    "Tainted pre-bound argument reaches sink function via Reflect.apply",
                                    bound_arg.source.clone(),
                                );
                            return true;
                        }
                    }
                }

                if let Some(arg_array) = call.arguments.get(2) {
                    let target_method_name = target_expr
                        .and_then(|expr| self.get_callee_property_name(expr))
                        .or_else(|| {
                            if self.sinks.contains(sink_name.as_str()) {
                                Some(sink_name.clone())
                            } else {
                                None
                            }
                        });

                    if target_method_name.as_deref() == Some("setAttribute") {
                        let attr_name_lc = self
                            .resolve_apply_static_string_at(arg_array, 0)
                            .map(|name| name.to_ascii_lowercase());
                        if let Some(name) = attr_name_lc {
                            let dangerous = name.starts_with("on")
                                || name == "href"
                                || name == "xlink:href"
                                || name == "srcdoc";
                            if dangerous {
                                let (tainted, source_hint) =
                                    self.resolve_apply_argument_taint_at(arg_array, 1);
                                if tainted {
                                    self.report_vulnerability_with_source(
                                            call.span(),
                                            &format!("setAttribute:{name}"),
                                            "Tainted data assigned to dangerous attribute via Reflect.apply",
                                            source_hint,
                                        );
                                    return true;
                                }
                            }
                        }
                    } else if target_method_name.as_deref() == Some("execCommand") {
                        let cmd_name_lc = self
                            .resolve_apply_static_string_at(arg_array, 0)
                            .map(|name| name.to_ascii_lowercase());
                        if let Some(cmd) = cmd_name_lc
                            && cmd == "inserthtml"
                        {
                            let (tainted, source_hint) =
                                self.resolve_apply_argument_taint_at(arg_array, 2);
                            if tainted {
                                self.report_vulnerability_with_source(
                                    call.span(),
                                    "execCommand:insertHTML",
                                    "Tainted data passed to insertHTML command via Reflect.apply",
                                    source_hint,
                                );
                                return true;
                            }
                        }
                    } else if target_method_name.as_deref() == Some("insertAdjacentHTML") {
                        let (tainted, source_hint) =
                            self.resolve_apply_argument_taint_at(arg_array, 1);
                        if tainted {
                            self.report_vulnerability_with_source(
                                call.span(),
                                "insertAdjacentHTML",
                                "Tainted HTML argument passed to sink method via Reflect.apply",
                                source_hint,
                            );
                            return true;
                        }
                    } else {
                        let (tainted, source_hint) = self.argument_taint_and_source(arg_array);
                        if tainted {
                            self.report_vulnerability_with_source(
                                call.span(),
                                &sink_name,
                                "Tainted data passed to sink function via Reflect.apply",
                                source_hint,
                            );
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
    /// `addEventListener('x', handler)` — walk the handler body with the event parameter bound, so `e.data`-style sources are seen.
    pub(super) fn handle_add_event_listener(&mut self, call: &CallExpression<'a>) -> bool {
        // Check if this is an addEventListener call with a function argument
        if let Expression::StaticMemberExpression(member) = &call.callee
            && member.property.name.as_str() == "addEventListener"
            && call.arguments.len() >= 2
        {
            let event_source = self.event_listener_source(&member.object, call.arguments.first());

            // The second argument might be a function with event parameter
            if let Some(Argument::FunctionExpression(func)) = call.arguments.get(1) {
                // Mark the first parameter as tainted (it's the event object)
                if let Some(param) = func.params.items.first()
                    && let BindingPattern::BindingIdentifier(id) = &param.pattern
                    && let Some(body) = &func.body
                    && let Some(event_source) = event_source.as_deref()
                {
                    self.walk_event_handler_body(id.name.as_str(), event_source, &body.statements);
                    return true;
                }
            }
            // Also handle arrow functions
            if let Some(Argument::ArrowFunctionExpression(arrow)) = call.arguments.get(1)
                && let Some(param) = arrow.params.items.first()
                && let BindingPattern::BindingIdentifier(id) = &param.pattern
                && let Some(event_source) = event_source.as_deref()
            {
                self.walk_event_handler_body(
                    id.name.as_str(),
                    event_source,
                    &arrow.body.statements,
                );
                return true;
            }

            // Handle named callback references:
            // window.addEventListener('message', handleMessage)
            if let Some(event_source) = event_source.as_deref()
                && let Some(Argument::Identifier(handler_id)) = call.arguments.get(1)
                && let Some(sink_name) = self
                    .function_summaries
                    .get(handler_id.name.as_str())
                    .and_then(|summary| summary.tainted_param_sinks.get(&0))
                    .cloned()
            {
                self.report_vulnerability_with_source(
                    call.span(),
                    &sink_name,
                    "Tainted message event data may reach sink through callback",
                    Some(event_source.to_string()),
                );
                return true;
            }
        }
        false
    }
    /// jQuery's `$(tainted)` / `jQuery(tainted)`: a string whose first non-whitespace char is `<` makes jQuery build live DOM nodes, running `onerror`/`onload`. Fires only when the argument is tainted and not pinned into selector mode by a constant prefix.
    pub(super) fn handle_jquery_html_constructor(&mut self, call: &CallExpression<'a>) {
        // jQuery `$(tainted)` / `jQuery(tainted)` selector-to-HTML constructor
        // (issue #1021). A string whose first non-whitespace char is `<` makes
        // jQuery build live DOM nodes (running onerror/onload). Fire only when
        // the argument is tainted AND not pinned into selector mode by a
        // constant `#`/`.`/tag prefix — see `jquery_arg_forces_selector`.
        if let Expression::Identifier(id) = &call.callee
            && (id.name == "$" || id.name == "jQuery")
            && let Some(arg0) = call.arguments.first()
            && let Some(arg_expr) = arg0.as_expression()
            && self.is_tainted(arg_expr)
            && !self.jquery_arg_forces_selector(arg_expr)
        {
            let source = self.find_source_in_expr(arg_expr);
            self.report_vulnerability_with_source(
                    call.span(),
                    "jQuery$",
                    "Tainted HTML string passed to jQuery $() constructor builds DOM nodes (selector-to-HTML)",
                    source,
                );
            // Walk the (tainted) argument so a nested sink inside it — e.g.
            // `$(eval(location.hash))` — is also reported; the trailing
            // `walk_expression(&call.callee)` only descends the `$` callee,
            // never the call's arguments.
            self.walk_expression(arg_expr);
        }
    }
    /// Walk through a call expression
    pub(super) fn walk_call_expression(&mut self, call: &CallExpression<'a>) {
        // Standalone `trustedTypes.createPolicy('default', {...})` (not bound to
        // a variable) still registers the auto-applied default policy.
        if let Some((name, config)) = self.tt_create_policy_config(call)
            && name.as_deref() == Some("default")
        {
            let info = self.build_tt_policy_info(config);
            self.default_tt_policy = Some(info);
        }

        // fetch().then(...) response-source chains (issue #1024) and async
        // source chains such as `navigator.clipboard.readText().then(...)`.
        // Drive the whole chain here so each callback body is walked with the
        // resolved Response / tainted value bound to its parameter, then return.
        if Self::promise_method_name(call).is_some()
            && self.promise_chain_roots_at_untrusted_source(call)
        {
            self.promise_kind_of_call(call);
            return;
        }

        self.handle_jquery_html_constructor(call);

        if let Expression::StaticMemberExpression(member) = &call.callee
            && member.property.name.as_str() == "set"
            && call.arguments.len() >= 2
        {
            let (value_tainted, source_hint) = self.argument_taint_and_source(&call.arguments[1]);
            if value_tainted && let Expression::Identifier(obj_id) = &member.object {
                self.tainted_vars.insert(obj_id.name.to_string());
                if let Some(source) = source_hint {
                    self.var_aliases.insert(obj_id.name.to_string(), source);
                }
            }
        }

        if self.handle_add_event_listener(call) {
            return;
        }

        if self.handle_reflect_apply(call) {
            return;
        }

        if self.handle_reflect_construct(call) {
            return;
        }

        if self.handle_wrapper_invocation(call) {
            return;
        }

        self.propagate_mutation_taint(call);

        if self.handle_summary_and_sink_call(call) {
            return;
        }

        if self.handle_member_method_sink(call) {
            return;
        }
        // Walk the callee
        self.walk_expression(&call.callee);

        // Descend into function/arrow callbacks passed as arguments so a
        // source→sink flow that lives *inside* a deferred callback is still
        // analyzed. The classic shape is a `setTimeout` / `setInterval` /
        // `requestAnimationFrame` / `queueMicrotask` body — e.g.
        // `setTimeout(function(){ el.innerHTML = location.search }, 0)`. The
        // callback never runs at parse time, and the call's arguments are not
        // walked anywhere else (the trailing `walk_expression(&call.callee)`
        // only descends the callee), so without this the body is invisible.
        // Cases that own their callback walking (`addEventListener`, `.then`
        // chains, `Reflect.apply`, …) `return` early and never reach here.
        self.walk_callback_argument_bodies(call);
    }
    /// Walk function/arrow callbacks passed as call arguments, each with an
    /// isolated taint scope so a callback-local variable (`var q = …` inside
    /// the callback) does not leak taint into the enclosing scope. Only
    /// function-shaped arguments are descended; data arguments keep their
    /// existing taint-evaluation-only treatment.
    pub(super) fn walk_callback_argument_bodies(&mut self, call: &CallExpression<'a>) {
        for arg in &call.arguments {
            let Some(expr) = arg.as_expression() else {
                continue;
            };
            let statements = match expr {
                Expression::FunctionExpression(func) => {
                    let Some(body) = &func.body else {
                        continue;
                    };
                    &body.statements
                }
                Expression::ArrowFunctionExpression(arrow) => &arrow.body.statements,
                _ => continue,
            };

            let saved_tainted = self.tainted_vars.clone();
            let saved_aliases = self.var_aliases.clone();
            let saved_field_taints = self.field_taints.clone();
            self.walk_statements(statements);
            self.tainted_vars = saved_tainted;
            self.var_aliases = saved_aliases;
            self.field_taints = saved_field_taints;
        }
    }
}
