//! Shell extraction utilities.

use crate::analyzers::function_metrics::FunctionInfo;
use crate::types::*;
use tree_sitter;

impl super::ShellAnalyzer {
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
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            // Variable names in shell
            if node.kind() == "variable_name" || node.kind() == "simple_expansion" {
                if let Ok(text) = node.utf8_text(source) {
                    let name = text.trim_start_matches('$');
                    if !name.is_empty() {
                        identifiers.push(name.to_string());
                    }
                }
            }

            if cursor.goto_first_child() {
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Extract string literals from shell script
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
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            if node.kind() == "string" || node.kind() == "raw_string" {
                if let Ok(text) = node.utf8_text(source) {
                    // Strip quotes
                    let s = text
                        .trim_start_matches('"')
                        .trim_end_matches('"')
                        .trim_start_matches('\'')
                        .trim_end_matches('\'');
                    if !s.is_empty() {
                        strings.push(s.to_string());
                    }
                }
            }

            if cursor.goto_first_child() {
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Extract function information for metrics
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
        _depth: u32,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        let mut depth = _depth;
        loop {
            let node = cursor.node();

            if node.kind() == "function_definition" {
                let mut info = FunctionInfo::default();

                // Get function name
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(source) {
                        info.name = name.to_string();
                    }
                }

                // Shell functions don't have explicit parameters
                // They use $1, $2, etc. which we could count in the body
                info.param_count = 0;

                // Line count
                info.start_line = node.start_position().row as u32;
                info.end_line = node.end_position().row as u32;
                info.line_count = info.end_line.saturating_sub(info.start_line) + 1;
                info.nesting_depth = depth;

                functions.push(info);
            }

            if cursor.goto_first_child() {
                if node.kind() == "function_definition" {
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
                let parent = cursor.node();
                if parent.kind() == "function_definition" {
                    depth = depth.saturating_sub(1);
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Compute shell-specific metrics
    pub(super) fn compute_shell_metrics(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
        content: &str,
    ) -> ShellMetrics {
        let mut metrics = ShellMetrics::default();
        let mut cursor = root.walk();
        self.walk_for_shell_metrics(&mut cursor, source, &mut metrics);

        // Pattern-based detection
        metrics.eval_count += content.matches("eval ").count() as u32;
        metrics.base64_decode_count += content.matches("base64 -d").count() as u32;
        metrics.base64_decode_count += content.matches("base64 --decode").count() as u32;

        metrics
    }

    fn walk_for_shell_metrics(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        metrics: &mut ShellMetrics,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            if node.kind() == "command" {
                if let Ok(text) = node.utf8_text(source) {
                    // Command execution patterns
                    if text.starts_with("eval ") {
                        metrics.eval_count += 1;
                    }
                    if text.starts_with("source ") || text.starts_with(". ") {
                        metrics.source_count += 1;
                    }
                    if text.contains("curl ") || text.contains("wget ") {
                        metrics.curl_wget_count += 1;
                    }
                    if text.contains("chmod +x") || text.contains("chmod 7") {
                        metrics.chmod_x_count += 1;
                    }
                    if text.contains("rm -rf") || text.contains("shred ") {
                        metrics.secure_delete_count += 1;
                    }
                }
            } else if node.kind() == "process_substitution" {
                metrics.process_substitution += 1;
            } else if node.kind() == "pipeline" {
                metrics.pipe_count += 1;
            } else if node.kind() == "heredoc_body" || node.kind() == "heredoc_redirect" {
                metrics.here_doc_count += 1;
            }

            if cursor.goto_first_child() {
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    fn calculate_cyclomatic_complexity(&self, node: &tree_sitter::Node, source: &[u8]) -> u32 {
        let mut complexity = 1; // Base complexity
        let mut cursor = node.walk();

        loop {
            let current = cursor.node();
            match current.kind() {
                "if_statement" => complexity += 1,
                "case_statement" | "case_item" => complexity += 1,
                "for_statement" | "c_style_for_statement" => complexity += 1,
                "while_statement" | "until_statement" => complexity += 1,
                "elif_clause" => complexity += 1,
                "test_command" => {
                    // Count && and || in test commands
                    if let Ok(text) = current.utf8_text(source) {
                        complexity += text.matches("&&").count() as u32;
                        complexity += text.matches("||").count() as u32;
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

    /// Analyze function signature for shell functions
    fn analyze_function_signature(
        &self,
        _node: &tree_sitter::Node,
        _source: &[u8],
    ) -> FunctionSignature {
        // Shell functions don't have explicit parameter declarations
        // Parameters are accessed via $1, $2, etc.
        FunctionSignature {
            param_count: 0, // Not explicitly declared in shell
            default_param_count: 0,
            has_var_positional: false, // Shell uses $@
            has_var_keyword: false,
            has_type_hints: false,
            has_return_type: false,
            decorators: Vec::new(),
            is_async: false, // Shell has background jobs but not async in the modern sense
            is_generator: false,
            is_lambda: false,
        }
    }

    /// Calculate nesting depth of control structures
    fn calculate_nesting_depth(&self, node: &tree_sitter::Node) -> NestingMetrics {
        let mut max_depth = 0u32;
        let mut depths = Vec::new();
        let mut deep_nest_count = 0u32;
        let mut limit_hit = false;

        fn traverse(
            node: &tree_sitter::Node,
            current_depth: u32,
            max: &mut u32,
            depths: &mut Vec<u32>,
            deep: &mut u32,
            limit_hit: &mut bool,
        ) {
            // Prevent stack overflow on deeply nested/malformed ASTs
            if current_depth > crate::analyzers::ast_walker::MAX_RECURSION_DEPTH {
                *limit_hit = true;
                return;
            }
            let mut depth = current_depth;
            match node.kind() {
                "if_statement" | "case_statement" | "for_statement" | "while_statement"
                | "until_statement" | "subshell" => {
                    depth += 1;
                    depths.push(depth);
                    if depth > *max {
                        *max = depth;
                    }
                    if depth > 4 {
                        *deep += 1;
                    }
                }
                _ => {}
            }

            // Recurse through children
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                traverse(&child, depth, max, depths, deep, limit_hit);
            }
        }

        traverse(
            node,
            0,
            &mut max_depth,
            &mut depths,
            &mut deep_nest_count,
            &mut limit_hit,
        );

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

    /// Analyze call patterns in shell functions
    fn analyze_call_patterns(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        func_name: &str,
    ) -> CallPatternMetrics {
        let mut call_count = 0u32;
        let mut callees: Vec<String> = Vec::new();
        let mut recursive_calls = 0u32;
        let mut dynamic_calls = 0u32;

        let mut cursor = node.walk();
        loop {
            let current = cursor.node();
            if current.kind() == "command" {
                call_count += 1;

                if let Some(name_node) = current.child_by_field_name("name") {
                    if let Ok(cmd_text) = name_node.utf8_text(source) {
                        let cmd_str = cmd_text.to_string();
                        callees.push(cmd_str.clone());

                        // Check recursion
                        if cmd_str == func_name {
                            recursive_calls += 1;
                        }

                        // Check dynamic calls (eval, source with variables)
                        if ["eval", "source", "."].iter().any(|&d| cmd_str.contains(d)) {
                            // Check if there's a variable expansion
                            if let Ok(full_text) = current.utf8_text(source) {
                                if full_text.contains('$') {
                                    dynamic_calls += 1;
                                }
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
                    callees.sort();
                    callees.dedup();

                    return CallPatternMetrics {
                        call_count,
                        unique_callees: callees.len() as u32,
                        chained_calls: 0, // Shell uses pipes, not method chaining
                        max_chain_length: 0,
                        recursive_calls,
                        dynamic_calls,
                    };
                }
            }
        }
    }

    /// Detect shell-specific idioms
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

                        // Calculate all metrics
                        let complexity = self.calculate_cyclomatic_complexity(&node, source);
                        let signature = self.analyze_function_signature(&node, source);
                        let nesting = self.calculate_nesting_depth(&node);
                        let call_patterns =
                            self.analyze_call_patterns(&node, source, &func_name_str);

                        // Extract command calls
                        let mut calls = Vec::new();
                        let mut call_cursor = node.walk();
                        loop {
                            let call_node = call_cursor.node();
                            if call_node.kind() == "command" {
                                if let Some(cmd_name_node) = call_node.child_by_field_name("name") {
                                    if let Ok(cmd_text) = cmd_name_node.utf8_text(source) {
                                        calls.push(cmd_text.to_string());
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
                            source: "tree-sitter-bash".to_string(),
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

}
