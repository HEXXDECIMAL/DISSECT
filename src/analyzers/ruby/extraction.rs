//! Ruby extraction utilities.

use crate::analyzers::function_metrics::FunctionInfo;
use crate::types::*;
use tree_sitter;

impl super::RubyAnalyzer {
    /// Extract identifiers from Ruby AST
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

            if node.kind() == "identifier"
                || node.kind() == "constant"
                || node.kind() == "instance_variable"
                || node.kind() == "class_variable"
                || node.kind() == "global_variable"
            {
                if let Ok(text) = node.utf8_text(source) {
                    let name = text.trim_start_matches('@').trim_start_matches('$');
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

    /// Extract string literals from Ruby AST
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

            if node.kind() == "string" || node.kind() == "string_content" {
                if let Ok(text) = node.utf8_text(source) {
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
            let kind = node.kind();

            if kind == "method" || kind == "singleton_method" {
                let mut info = FunctionInfo::default();

                // Get method name
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(source) {
                        info.name = name.to_string();
                    }
                }

                // Get parameters
                if let Some(params_node) = node.child_by_field_name("parameters") {
                    let mut param_cursor = params_node.walk();
                    if param_cursor.goto_first_child() {
                        loop {
                            let param = param_cursor.node();
                            if param.kind() == "identifier"
                                || param.kind() == "optional_parameter"
                                || param.kind() == "splat_parameter"
                                || param.kind() == "keyword_parameter"
                            {
                                info.param_count += 1;
                                if let Ok(param_text) = param.utf8_text(source) {
                                    let name = param_text
                                        .trim_start_matches('*')
                                        .trim_start_matches('&')
                                        .split('=')
                                        .next()
                                        .unwrap_or(param_text)
                                        .trim();
                                    if !name.is_empty() && name != "," {
                                        info.param_names.push(name.to_string());
                                    }
                                }
                            }
                            if !param_cursor.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }

                // Line count
                info.start_line = node.start_position().row as u32;
                info.end_line = node.end_position().row as u32;
                info.line_count = info.end_line.saturating_sub(info.start_line) + 1;
                info.nesting_depth = depth;

                functions.push(info);
            }

            if cursor.goto_first_child() {
                if kind == "method" || kind == "singleton_method" {
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
                if parent_kind == "method" || parent_kind == "singleton_method" {
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
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let mut cursor = node.walk();
        self.walk_for_functions(&mut cursor, source, report);
    }

    fn walk_for_functions(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            if node.kind() == "method" || node.kind() == "singleton_method" {
                let name = self
                    .extract_function_name(&node, source)
                    .unwrap_or_else(|| "anonymous".to_string());

                report.functions.push(Function {
                    name,
                    offset: Some(format!("0x{:x}", node.start_byte())),
                    size: Some((node.end_byte() - node.start_byte()) as u64),
                    complexity: None,
                    calls: Vec::new(),
                    source: "tree-sitter-ruby".to_string(),
                    control_flow: None,
                    instruction_analysis: None,
                    register_usage: None,
                    constants: Vec::new(),
                    properties: None,
                    signature: None,
                    nesting: None,
                    call_patterns: None,
                });
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

    fn extract_function_name(&self, node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
        if let Some(name_node) = node.child_by_field_name("name") {
            name_node.utf8_text(source).ok().map(|s| s.to_string())
        } else {
            None
        }
    }
}
