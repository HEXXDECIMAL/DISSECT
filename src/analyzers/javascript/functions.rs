//! Function extraction and analysis for JavaScript code
//!
//! This module implements:
//! - Function extraction from AST
//! - Cyclomatic complexity calculation
//! - Function signature analysis (parameters, async, generators)
//! - Nesting depth calculation
//! - Call pattern analysis (recursion, dynamic calls, chaining)
//! - JavaScript idiom detection (arrow functions, promises, async/await)

use crate::types::*;

use super::JavaScriptAnalyzer;

/// Extract functions from AST and compute their metrics
pub(crate) fn extract_functions(
    _analyzer: &JavaScriptAnalyzer,
    root: &tree_sitter::Node,
    source: &[u8],
    report: &mut AnalysisReport,
) {
    let mut cursor = root.walk();

    loop {
        let node = cursor.node();

        // Match both function declarations and arrow functions
        if matches!(
            node.kind(),
            "function_declaration" | "arrow_function" | "function" | "method_definition"
        ) {
            let func_name = if let Some(name_node) = node.child_by_field_name("name") {
                name_node
                    .utf8_text(source)
                    .unwrap_or("<unnamed>")
                    .to_string()
            } else {
                "<anonymous>".to_string()
            };

            // Calculate all metrics
            let complexity = calculate_cyclomatic_complexity(&node, source);
            let signature = analyze_function_signature(&node, source);
            let nesting = calculate_nesting_depth(&node);
            let call_patterns = analyze_call_patterns(&node, source, &func_name);

            // Extract actual function calls
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
                basic_blocks: complexity, // Approximation: CC relates to BBs
                edges: if complexity > 1 { complexity + 1 } else { 1 },
                cyclomatic_complexity: complexity,
                max_block_size: 0, // Not easily calculated from tree-sitter
                avg_block_size: 0.0,
                is_linear: complexity == 1,
                loop_count: 0, // Could count for/while nodes if needed
                branch_density: 0.0,
                in_degree: 0, // Would need global call graph analysis
                out_degree: call_patterns.unique_callees,
            };

            // Build properties
            let properties = FunctionProperties {
                is_pure: false, // Hard to determine from AST alone
                is_noreturn: false,
                is_recursive: call_patterns.recursive_calls > 0,
                stack_frame: 0, // Not applicable to JavaScript
                local_vars: 0,  // Could count variable declarations if needed
                args: signature.param_count,
                is_leaf: call_patterns.call_count == 0,
            };

            report.functions.push(Function {
                name: func_name,
                offset: Some(format!("line:{}", node.start_position().row + 1)),
                size: Some((node.end_byte() - node.start_byte()) as u64),
                complexity: Some(complexity),
                calls,
                source: "tree-sitter-javascript".to_string(),
                control_flow: Some(control_flow),
                instruction_analysis: None,
                register_usage: None,
                constants: Vec::new(),
                properties: Some(properties),
                call_patterns: Some(call_patterns),
                nesting: Some(nesting),
                signature: Some(signature),
            });
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

/// Calculate cyclomatic complexity for a JavaScript function
///
/// CC = decision points + 1
pub(crate) fn calculate_cyclomatic_complexity(node: &tree_sitter::Node, source: &[u8]) -> u32 {
    let mut complexity = 1; // Base complexity
    let mut cursor = node.walk();

    loop {
        let current = cursor.node();
        match current.kind() {
            "if_statement" => complexity += 1,
            "switch_case" => complexity += 1,
            "for_statement" | "for_in_statement" => complexity += 1,
            "while_statement" | "do_statement" => complexity += 1,
            "catch_clause" => complexity += 1,
            "ternary_expression" => complexity += 1,
            "binary_expression" => {
                if let Ok(text) = current.utf8_text(source) {
                    if text.contains("&&") || text.contains("||") {
                        complexity += 1;
                    }
                }
            }
            _ => {}
        }

        // Traverse
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
        }
    }
}

/// Analyze function signature (params, arrow vs regular, async, etc.)
pub(crate) fn analyze_function_signature(
    node: &tree_sitter::Node,
    _source: &[u8],
) -> FunctionSignature {
    let mut param_count = 0u32;
    let mut default_param_count = 0u32;
    let mut has_var_positional = false; // rest params
    let has_type_hints = false; // TypeScript
    let has_return_type = false; // TypeScript
    let mut is_async = false;
    let is_generator = false;
    let is_lambda = node.kind() == "arrow_function";

    // Check for async
    if let Some(parent) = node.parent() {
        if parent.kind() == "function_declaration" || parent.kind() == "method_definition" {
            let mut cursor = parent.walk();
            for child in parent.children(&mut cursor) {
                if child.kind() == "async" {
                    is_async = true;
                    break;
                }
            }
        }
    }
    // Also check if node itself has async
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "async" {
            is_async = true;
            break;
        }
    }

    // Extract parameters
    if let Some(params_node) = node.child_by_field_name("parameters") {
        let mut param_cursor = params_node.walk();
        for child in params_node.children(&mut param_cursor) {
            match child.kind() {
                "identifier" | "required_parameter" | "optional_parameter" => {
                    param_count += 1;
                }
                "assignment_pattern" => {
                    param_count += 1;
                    default_param_count += 1;
                }
                "rest_pattern" => {
                    has_var_positional = true;
                    param_count += 1;
                }
                _ => {}
            }
        }
    }

    FunctionSignature {
        param_count,
        default_param_count,
        has_var_positional,
        has_var_keyword: false, // JavaScript doesn't have **kwargs
        has_type_hints,
        has_return_type,
        decorators: Vec::new(), // JavaScript doesn't have decorators (except TS experimental)
        is_async,
        is_generator,
        is_lambda,
    }
}

/// Calculate nesting depth of control structures (iterative to avoid stack overflow)
pub(crate) fn calculate_nesting_depth(node: &tree_sitter::Node) -> NestingMetrics {
    let mut max_depth = 0u32;
    let mut depths = Vec::new();
    let mut deep_nest_count = 0u32;
    let mut limit_hit = false;

    // Use explicit stack: (node_id, depth) - we track by byte range since Node isn't easily stored
    let mut cursor = node.walk();
    let mut depth_stack: Vec<u32> = vec![0]; // Track depth as we traverse

    loop {
        // Check for depth limit (iterative equivalent of recursion limit)
        if depth_stack.len() > crate::analyzers::ast_walker::MAX_AST_DEPTH {
            limit_hit = true;
            break;
        }

        let current = cursor.node();
        let current_depth = *depth_stack.last().unwrap_or(&0);

        // Check if this node increases nesting depth
        let new_depth = match current.kind() {
            "if_statement" | "for_statement" | "for_in_statement" | "while_statement"
            | "do_statement" | "switch_statement" | "try_statement" => {
                let d = current_depth + 1;
                depths.push(d);
                if d > max_depth {
                    max_depth = d;
                }
                if d > 4 {
                    deep_nest_count += 1;
                }
                d
            }
            _ => current_depth,
        };

        // Depth-first traversal
        if cursor.goto_first_child() {
            depth_stack.push(new_depth);
            continue;
        }

        if cursor.goto_next_sibling() {
            continue;
        }

        // Walk back up
        loop {
            if !cursor.goto_parent() {
                // Done traversing
                return NestingMetrics {
                    max_depth,
                    avg_depth: if !depths.is_empty() {
                        depths.iter().sum::<u32>() as f32 / depths.len() as f32
                    } else {
                        0.0
                    },
                    deep_nest_count,
                    depth_limit_hit: limit_hit,
                };
            }
            depth_stack.pop();
            if cursor.goto_next_sibling() {
                break;
            }
        }
    }

    // Return if we hit the depth limit
    NestingMetrics {
        max_depth,
        avg_depth: if !depths.is_empty() {
            depths.iter().sum::<u32>() as f32 / depths.len() as f32
        } else {
            0.0
        },
        deep_nest_count,
        depth_limit_hit: limit_hit,
    }
}

/// Analyze call patterns (promise chains, callbacks, recursion, dynamic calls)
pub(crate) fn analyze_call_patterns(
    node: &tree_sitter::Node,
    source: &[u8],
    func_name: &str,
) -> CallPatternMetrics {
    let mut call_count = 0u32;
    let mut callees: Vec<String> = Vec::new();
    let mut recursive_calls = 0u32;
    let mut dynamic_calls = 0u32;
    let mut chained_calls = 0u32;
    let mut max_chain_length = 0u32;

    let mut cursor = node.walk();
    loop {
        let current = cursor.node();
        if current.kind() == "call_expression" {
            call_count += 1;

            if let Some(func_node) = current.child_by_field_name("function") {
                if let Ok(func_text) = func_node.utf8_text(source) {
                    let func_str = func_text.to_string();
                    callees.push(func_str.clone());

                    // Check recursion
                    if func_str == func_name || func_str.ends_with(&format!(".{}", func_name)) {
                        recursive_calls += 1;
                    }

                    // Check dynamic calls
                    if ["eval", "Function", "setTimeout", "setInterval"]
                        .iter()
                        .any(|&d| func_str.contains(d))
                    {
                        dynamic_calls += 1;
                    }

                    // Count method chaining
                    let chain_length = func_str.matches('.').count() as u32;
                    if chain_length > 0 {
                        chained_calls += 1;
                        if chain_length > max_chain_length {
                            max_chain_length = chain_length;
                        }
                    }
                }
            }
        }

        // Traverse
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                // Deduplicate callees
                callees.sort();
                callees.dedup();

                return CallPatternMetrics {
                    call_count,
                    unique_callees: callees.len() as u32,
                    chained_calls,
                    max_chain_length,
                    recursive_calls,
                    dynamic_calls,
                };
            }
        }
    }
}

/// Detect JavaScript-specific idioms
pub(crate) fn detect_javascript_idioms(
    root: &tree_sitter::Node,
    source: &[u8],
) -> JavaScriptIdioms {
    let mut arrow_function_count = 0u32;
    let mut promise_count = 0u32;
    let mut async_await_count = 0u32;
    let mut template_literal_count = 0u32;
    let mut destructuring_count = 0u32;
    let mut spread_operator_count = 0u32;
    let mut class_count = 0u32;
    let mut callback_count = 0u32;
    let mut iife_count = 0u32;
    let object_shorthand_count = 0u32;
    let mut optional_chaining_count = 0u32;
    let mut nullish_coalescing_count = 0u32;

    let mut cursor = root.walk();
    loop {
        let node = cursor.node();
        match node.kind() {
            "arrow_function" => {
                arrow_function_count += 1;
                // Check if it's a callback (passed as argument)
                if let Some(parent) = node.parent() {
                    if parent.kind() == "arguments" {
                        callback_count += 1;
                    }
                }
            }
            "class_declaration" => {
                class_count += 1;
            }
            "template_string" => {
                template_literal_count += 1;
            }
            "spread_element" => {
                spread_operator_count += 1;
            }
            "object_pattern" | "array_pattern" => {
                destructuring_count += 1;
            }
            "optional_chain" => {
                optional_chaining_count += 1;
            }
            "call_expression" => {
                if let Ok(text) = node.utf8_text(source) {
                    // Promise detection
                    if text.contains("new Promise")
                        || text.contains(".then(")
                        || text.contains(".catch(")
                        || text.contains(".finally(")
                    {
                        promise_count += 1;
                    }
                    // IIFE detection
                    if text.starts_with("(function") || text.starts_with("(async function") {
                        iife_count += 1;
                    }
                }
            }
            "function_declaration" | "method_definition" => {
                // Check for async
                let mut func_cursor = node.walk();
                for child in node.children(&mut func_cursor) {
                    if child.kind() == "async" {
                        async_await_count += 1;
                        break;
                    }
                }
            }
            "binary_expression" => {
                if let Ok(text) = node.utf8_text(source) {
                    if text.contains("??") {
                        nullish_coalescing_count += 1;
                    }
                }
            }
            _ => {}
        }

        // Traverse
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return JavaScriptIdioms {
                    arrow_function_count,
                    promise_count,
                    async_await_count,
                    template_literal_count,
                    destructuring_count,
                    spread_operator_count,
                    class_count,
                    callback_count,
                    iife_count,
                    object_shorthand_count,
                    optional_chaining_count,
                    nullish_coalescing_count,
                };
            }
        }
    }
}
