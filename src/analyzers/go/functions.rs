//! Function analysis and extraction.
//!
//! Extracts function metadata and metrics from Go source code.

use crate::types::{
    AnalysisReport, CallPatternMetrics, ControlFlowMetrics, Function, FunctionProperties,
    FunctionSignature, NestingMetrics,
};

impl super::GoAnalyzer {
    pub(super) fn extract_functions(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let mut cursor = root.walk();

        loop {
            let node = cursor.node();

            if node.kind() == "function_declaration" || node.kind() == "method_declaration" {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(func_name) = name_node.utf8_text(source) {
                        let func_name_str = func_name.to_string();

                        // Calculate all metrics
                        let complexity = self.calculate_cyclomatic_complexity(&node, source);
                        let signature = self.analyze_function_signature(&node, source);
                        let nesting = self.calculate_nesting_depth(&node);
                        let call_patterns =
                            self.analyze_call_patterns(&node, source, &func_name_str);

                        // Extract function calls
                        let mut calls = Vec::new();
                        let mut call_cursor = node.walk();
                        loop {
                            let call_node = call_cursor.node();
                            if call_node.kind() == "call_expression" {
                                if let Some(func_node) = call_node.child_by_field_name("function") {
                                    if let Ok(func_text) = func_node.utf8_text(source) {
                                        calls.push(func_text.to_string());
                                    }
                                }
                            }
                            if call_cursor.goto_first_child() {
                                continue;
                            }
                            loop {
                                if call_cursor.goto_next_sibling() {
                                    break;
                                }
                                if !call_cursor.goto_parent() {
                                    break;
                                }
                            }
                            if call_cursor.node() == node {
                                break;
                            }
                        }
                        calls.sort();
                        calls.dedup();

                        // Build control flow metrics
                        let control_flow = ControlFlowMetrics {
                            basic_blocks: complexity,
                            edges: if complexity > 1 { complexity + 1 } else { 1 },
                            cyclomatic_complexity: complexity,
                            max_block_size: 0,
                            avg_block_size: 0.0,
                            is_linear: complexity == 1,
                            loop_count: 0,
                            branch_density: 0.0,
                            in_degree: 0,
                            out_degree: call_patterns.unique_callees,
                        };

                        // Build properties
                        let properties = FunctionProperties {
                            is_pure: false,
                            is_noreturn: false,
                            is_recursive: call_patterns.recursive_calls > 0,
                            stack_frame: 0,
                            local_vars: 0,
                            args: signature.param_count,
                            is_leaf: call_patterns.call_count == 0,
                        };

                        report.functions.push(Function {
                            name: func_name_str,
                            offset: Some(format!("line:{}", node.start_position().row + 1)),
                            size: Some((node.end_byte() - node.start_byte()) as u64),
                            complexity: Some(complexity),
                            calls,
                            source: "tree-sitter-go".to_string(),
                            control_flow: Some(control_flow),
                            instruction_analysis: None,
                            register_usage: None,
                            constants: Vec::new(),
                            properties: Some(properties),
                            signature: Some(signature),
                            nesting: Some(nesting),
                            call_patterns: Some(call_patterns),
                        });
                    }
                }
            }

            // Recurse
            if cursor.goto_first_child() {
                continue;
            }

            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return;
                }
            }
        }
    }

    pub(super) fn calculate_cyclomatic_complexity(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
    ) -> u32 {
        let mut complexity = 1; // Base complexity
        let mut cursor = node.walk();

        loop {
            let n = cursor.node();
            match n.kind() {
                "if_statement" | "for_statement" | "switch_statement" | "case_clause"
                | "expression_switch_statement" | "type_switch_statement" => {
                    complexity += 1;
                }
                "binary_expression" => {
                    if let Ok(text) = n.utf8_text(source) {
                        if text.contains("&&") || text.contains("||") {
                            complexity += 1;
                        }
                    }
                }
                _ => {}
            }

            if cursor.goto_first_child() {
                continue;
            }

            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return complexity;
                }
                if cursor.node() == *node {
                    return complexity;
                }
            }
        }
    }

    pub(super) fn analyze_function_signature(
        &self,
        node: &tree_sitter::Node,
        _source: &[u8],
    ) -> FunctionSignature {
        let mut param_count = 0;
        let mut has_return = false;
        let mut is_variadic = false;

        // Count parameters
        if let Some(params) = node.child_by_field_name("parameters") {
            let mut param_cursor = params.walk();
            if param_cursor.goto_first_child() {
                loop {
                    let param = param_cursor.node();
                    if param.kind() == "parameter_declaration" {
                        // Count identifiers in this declaration
                        let mut id_cursor = param.walk();
                        if id_cursor.goto_first_child() {
                            loop {
                                if id_cursor.node().kind() == "identifier" {
                                    param_count += 1;
                                }
                                if id_cursor.node().kind() == "variadic_parameter_declaration" {
                                    is_variadic = true;
                                    param_count += 1;
                                }
                                if !id_cursor.goto_next_sibling() {
                                    break;
                                }
                            }
                        }
                    } else if param.kind() == "variadic_parameter_declaration" {
                        is_variadic = true;
                        param_count += 1;
                    }
                    if !param_cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }

        // Check for return type
        if node.child_by_field_name("result").is_some() {
            has_return = true;
        }

        FunctionSignature {
            param_count,
            default_param_count: 0, // Go doesn't have default parameters
            has_var_positional: is_variadic,
            has_var_keyword: false, // Go doesn't have keyword arguments
            has_type_hints: true,   // Go is statically typed
            has_return_type: has_return,
            decorators: Vec::new(), // Go doesn't have decorators
            is_async: false,        // Go uses goroutines, not async keyword
            is_generator: false,    // Go doesn't have generators
            is_lambda: false,       // Go doesn't have lambda functions (uses anonymous functions)
        }
    }

    pub(super) fn calculate_nesting_depth(&self, node: &tree_sitter::Node) -> NestingMetrics {
        let mut max_depth: u32 = 0;
        let mut current_depth: u32 = 0;
        let mut total_depth: u32 = 0;
        let mut block_count: u32 = 0;
        let mut deep_nest_count: u32 = 0;

        let mut cursor = node.walk();
        loop {
            let n = cursor.node();
            match n.kind() {
                "block" | "if_statement" | "for_statement" | "switch_statement" => {
                    current_depth += 1;
                    max_depth = max_depth.max(current_depth);
                    total_depth += current_depth;
                    block_count += 1;
                    if current_depth > 4 {
                        deep_nest_count += 1;
                    }
                }
                _ => {}
            }

            if cursor.goto_first_child() {
                continue;
            }

            loop {
                match cursor.node().kind() {
                    "block" | "if_statement" | "for_statement" | "switch_statement" => {
                        current_depth = current_depth.saturating_sub(1);
                    }
                    _ => {}
                }
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    let avg_depth = if block_count > 0 {
                        total_depth as f32 / block_count as f32
                    } else {
                        0.0
                    };
                    return NestingMetrics {
                        max_depth,
                        avg_depth,
                        deep_nest_count,
                        depth_limit_hit: false,
                    };
                }
                if cursor.node() == *node {
                    let avg_depth = if block_count > 0 {
                        total_depth as f32 / block_count as f32
                    } else {
                        0.0
                    };
                    return NestingMetrics {
                        max_depth,
                        avg_depth,
                        deep_nest_count,
                        depth_limit_hit: false,
                    };
                }
            }
        }
    }

    pub(super) fn analyze_call_patterns(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        func_name: &str,
    ) -> CallPatternMetrics {
        let mut call_count = 0;
        let mut recursive_calls = 0;
        let mut callees = std::collections::HashSet::new();

        let mut cursor = node.walk();
        loop {
            let n = cursor.node();
            if n.kind() == "call_expression" {
                if let Some(func_node) = n.child_by_field_name("function") {
                    if let Ok(func_text) = func_node.utf8_text(source) {
                        call_count += 1;
                        callees.insert(func_text.to_string());

                        if func_text == func_name {
                            recursive_calls += 1;
                        }
                    }
                }
            }

            if cursor.goto_first_child() {
                continue;
            }

            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return CallPatternMetrics {
                        call_count,
                        unique_callees: callees.len() as u32,
                        chained_calls: 0,
                        max_chain_length: 0,
                        recursive_calls,
                        dynamic_calls: 0,
                    };
                }
                if cursor.node() == *node {
                    return CallPatternMetrics {
                        call_count,
                        unique_callees: callees.len() as u32,
                        chained_calls: 0,
                        max_chain_length: 0,
                        recursive_calls,
                        dynamic_calls: 0,
                    };
                }
            }
        }
    }
}
