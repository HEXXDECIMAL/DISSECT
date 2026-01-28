//! AST traversal and data extraction utilities for Python.
//!
//! Provides helpers for extracting:
//! - Identifiers
//! - String literals
//! - Function information

use crate::analyzers::function_metrics::FunctionInfo;
use crate::types::{
    AnalysisReport, CallPatternMetrics, ControlFlowMetrics, Function, FunctionProperties,
    FunctionSignature, NestingMetrics,
};

impl super::PythonAnalyzer {
    pub(super) fn extract_identifiers(&self, root: &tree_sitter::Node, source: &[u8]) -> Vec<String> {
        let mut identifiers = Vec::new();
        let mut cursor = root.walk();
        self.walk_for_identifiers(&mut cursor, source, &mut identifiers);
        identifiers
    }

    fn walk_for_identifiers(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        identifiers: &mut Vec<String>,
    ) {
        loop {
            let node = cursor.node();
            if node.kind() == "identifier" {
                if let Ok(text) = node.utf8_text(source) {
                    if !text.is_empty() {
                        identifiers.push(text.to_string());
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
                    return;
                }
            }
        }
    }

    pub(super) fn extract_string_literals(&self, root: &tree_sitter::Node, source: &[u8]) -> Vec<String> {
        let mut strings = Vec::new();
        let mut cursor = root.walk();
        self.walk_for_strings(&mut cursor, source, &mut strings);
        strings
    }

    fn walk_for_strings(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        strings: &mut Vec<String>,
    ) {
        loop {
            let node = cursor.node();
            if node.kind() == "string" {
                if let Ok(text) = node.utf8_text(source) {
                    let s = text
                        .trim_start_matches("r\"")
                        .trim_start_matches("r'")
                        .trim_start_matches("b\"")
                        .trim_start_matches("b'")
                        .trim_start_matches("f\"")
                        .trim_start_matches("f'")
                        .trim_start_matches('"')
                        .trim_start_matches('\'')
                        .trim_end_matches('"')
                        .trim_end_matches('\'');
                    if !s.is_empty() {
                        strings.push(s.to_string());
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
                    return;
                }
            }
        }
    }

    pub(super) fn extract_function_info(&self, root: &tree_sitter::Node, source: &[u8]) -> Vec<FunctionInfo> {
        let mut functions = Vec::new();
        let mut cursor = root.walk();
        self.walk_for_function_info(&mut cursor, source, &mut functions, 0);
        functions
    }

    fn walk_for_function_info(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        functions: &mut Vec<FunctionInfo>,
        depth: u32,
    ) {
        let mut depth = depth;
        loop {
            let node = cursor.node();
            let kind = node.kind();

            if kind == "function_definition" {
                let mut info = FunctionInfo::default();
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(source) {
                        info.name = name.to_string();
                    }
                }
                if let Some(params) = node.child_by_field_name("parameters") {
                    let mut param_cursor = params.walk();
                    if param_cursor.goto_first_child() {
                        loop {
                            let param = param_cursor.node();
                            if param.kind() == "identifier" || param.kind() == "typed_parameter" {
                                info.param_count += 1;
                                if let Ok(name) = param.utf8_text(source) {
                                    info.param_names.push(name.to_string());
                                }
                            }
                            if !param_cursor.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }
                info.start_line = node.start_position().row as u32;
                info.end_line = node.end_position().row as u32;
                info.line_count = info.end_line.saturating_sub(info.start_line) + 1;
                info.nesting_depth = depth;
                functions.push(info);
            }

            if cursor.goto_first_child() {
                if kind == "function_definition" {
                    depth += 1;
                }
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                let parent_kind = cursor.node().kind();
                if parent_kind == "function_definition" {
                    depth = depth.saturating_sub(1);
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    pub(super) fn extract_functions(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let mut cursor = root.walk();

        loop {
            let node = cursor.node();

            if node.kind() == "function_definition" {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(func_name) = name_node.utf8_text(source) {
                        let func_name_str = func_name.to_string();

                        let complexity = self.calculate_cyclomatic_complexity(&node, source);
                        let signature = self.analyze_function_signature(&node, source);
                        let nesting = self.calculate_nesting_depth(&node);
                        let call_patterns = self.analyze_call_patterns(&node, source, &func_name_str);

                        let mut calls = Vec::new();
                        let mut call_cursor = node.walk();
                        loop {
                            let call_node = call_cursor.node();
                            if call_node.kind() == "call" {
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
                            source: "tree-sitter-python".to_string(),
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
        let mut complexity: u32 = 1;
        let mut cursor = node.walk();

        loop {
            let n = cursor.node();
            match n.kind() {
                "if_statement" | "elif_clause" | "for_statement" | "while_statement"
                | "except_clause" | "with_statement" => {
                    complexity += 1;
                }
                "boolean_operator" => {
                    if let Ok(text) = n.utf8_text(source) {
                        if text.contains(" and ") || text.contains(" or ") {
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
        source: &[u8],
    ) -> FunctionSignature {
        let mut param_count: u32 = 0;
        let mut default_param_count: u32 = 0;
        let mut has_var_positional = false;
        let mut has_var_keyword = false;
        let mut has_type_hints = false;
        let mut has_return_type = false;
        let mut decorators = Vec::new();
        let is_async = node.kind() == "async_function_definition"
            || if let Ok(text) = node.utf8_text(source) {
                text.starts_with("async ")
            } else {
                false
            };

        // Count parameters
        if let Some(params) = node.child_by_field_name("parameters") {
            let mut param_cursor = params.walk();
            if param_cursor.goto_first_child() {
                loop {
                    let param = param_cursor.node();
                    match param.kind() {
                        "identifier" => param_count += 1,
                        "typed_parameter" => {
                            param_count += 1;
                            has_type_hints = true;
                        }
                        "default_parameter" => {
                            param_count += 1;
                            default_param_count += 1;
                        }
                        "typed_default_parameter" => {
                            param_count += 1;
                            default_param_count += 1;
                            has_type_hints = true;
                        }
                        "list_splat_pattern" => {
                            has_var_positional = true;
                            param_count += 1;
                        }
                        "dictionary_splat_pattern" => {
                            has_var_keyword = true;
                            param_count += 1;
                        }
                        _ => {}
                    }
                    if !param_cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }

        // Check for return type
        if node.child_by_field_name("return_type").is_some() {
            has_return_type = true;
        }

        // Extract decorators
        let mut prev_sibling = node.prev_sibling();
        while let Some(sibling) = prev_sibling {
            if sibling.kind() == "decorator" {
                if let Ok(text) = sibling.utf8_text(source) {
                    decorators.push(text.trim_start_matches('@').to_string());
                }
                prev_sibling = sibling.prev_sibling();
            } else {
                break;
            }
        }
        decorators.reverse();

        // Check if it's a generator
        let is_generator = self.contains_yield(node, source);

        // Check if it's a lambda (shouldn't happen in function_definition but for completeness)
        let is_lambda = node.kind() == "lambda";

        FunctionSignature {
            param_count,
            default_param_count,
            has_var_positional,
            has_var_keyword,
            has_type_hints,
            has_return_type,
            decorators,
            is_async,
            is_generator,
            is_lambda,
        }
    }

    fn contains_yield(&self, node: &tree_sitter::Node, _source: &[u8]) -> bool {
        let mut cursor = node.walk();
        loop {
            let n = cursor.node();
            if n.kind() == "yield" || n.kind() == "yield_statement" {
                return true;
            }
            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return false;
                }
                if cursor.node() == *node {
                    return false;
                }
            }
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
                "block" | "if_statement" | "for_statement" | "while_statement" | "with_statement" => {
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
                    "block" | "if_statement" | "for_statement" | "while_statement" | "with_statement" => {
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
        let mut call_count: u32 = 0;
        let mut recursive_calls: u32 = 0;
        let mut dynamic_calls: u32 = 0;
        let mut callees = std::collections::HashSet::new();

        let mut cursor = node.walk();
        loop {
            let n = cursor.node();
            if n.kind() == "call" {
                if let Some(func_node) = n.child_by_field_name("function") {
                    if let Ok(func_text) = func_node.utf8_text(source) {
                        call_count += 1;
                        callees.insert(func_text.to_string());

                        if func_text == func_name {
                            recursive_calls += 1;
                        }

                        // Check for dynamic calls
                        if func_text == "eval" || func_text == "exec" || func_text == "__import__"
                            || func_text == "getattr" || func_text == "setattr"
                        {
                            dynamic_calls += 1;
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
                        dynamic_calls,
                    };
                }
                if cursor.node() == *node {
                    return CallPatternMetrics {
                        call_count,
                        unique_callees: callees.len() as u32,
                        chained_calls: 0,
                        max_chain_length: 0,
                        recursive_calls,
                        dynamic_calls,
                    };
                }
            }
        }
    }
}
