//! PHP extraction utilities.

use crate::analyzers::function_metrics::FunctionInfo;
use crate::types::*;
use tree_sitter;

impl super::PhpAnalyzer {
    /// Extract identifiers from PHP AST
    pub(super) fn extract_identifiers(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) -> Vec<String> {
        let mut identifiers = Vec::new();
        let mut cursor = root.walk();
        self.walk_for_identifiers(&mut cursor, source, &mut identifiers, report);
        identifiers
    }

    fn walk_for_identifiers(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        identifiers: &mut Vec<String>,
        report: &mut AnalysisReport,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            if node.kind() == "name" || node.kind() == "variable_name" {
                if let Ok(text) = node.utf8_text(source) {
                    let name = text.trim_start_matches('$');
                    if !name.is_empty() {
                        identifiers.push(name.to_string());

                        // Detect unusually long variable names (potential obfuscation)
                        if name.len() > 15 {
                            report.findings.push(Finding {
                                kind: FindingKind::Capability,
                                trait_refs: vec![],
                                id: "anti-analysis/obfuscation/long-identifier".to_string(),
                                desc: "Unusually long identifier (potential obfuscation)"
                                    .to_string(),
                                conf: 0.8,
                                crit: Criticality::Notable,
                                mbc: None,
                                attack: None,
                                evidence: vec![Evidence {
                                    method: "ast".to_string(),
                                    source: "tree-sitter-php".to_string(),
                                    value: name.to_string(),
                                    location: Some(format!(
                                        "{}:{}",
                                        node.start_position().row + 1,
                                        node.start_position().column
                                    )),
                                }],
                            });
                        }
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

    /// Extract string literals from PHP AST
    pub(super) fn extract_string_literals(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
    ) -> Vec<String> {
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

            if node.kind() == "string" || node.kind() == "encapsed_string" {
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

    /// Extract string literals and add them to the report's strings field.
    pub(super) fn extract_strings_to_report(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
        report: &mut crate::types::AnalysisReport,
    ) {
        let mut cursor = root.walk();
        self.walk_for_string_info(&mut cursor, source, &mut report.strings);
    }

    fn walk_for_string_info(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        strings: &mut Vec<crate::types::StringInfo>,
    ) {
        loop {
            let node = cursor.node();

            if node.kind() == "string" || node.kind() == "encapsed_string" {
                if let Ok(text) = node.utf8_text(source) {
                    let s = text
                        .trim_start_matches('"')
                        .trim_end_matches('"')
                        .trim_start_matches('\'')
                        .trim_end_matches('\'');
                    if !s.is_empty() {
                        strings.push(crate::types::StringInfo {
                            value: s.to_string(),
                            offset: Some(format!("0x{:x}", node.start_byte())),
                            string_type: crate::types::StringType::Literal,
                            encoding: "utf-8".to_string(),
                            section: Some("ast".to_string()),
                        });
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
    pub(super) fn extract_function_info(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
    ) -> Vec<FunctionInfo> {
        let mut functions = Vec::new();
        let mut cursor = root.walk();
        self.walk_for_func_info(&mut cursor, source, &mut functions, 0);
        functions
    }

    fn walk_for_func_info(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        functions: &mut Vec<FunctionInfo>,
        depth: u32,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        let mut depth = depth;
        loop {
            let node = cursor.node();
            let kind = node.kind();

            if kind == "function_definition" || kind == "method_declaration" {
                let mut info = FunctionInfo::default();

                // Get function name
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
                            if param.kind() == "simple_parameter"
                                || param.kind() == "variadic_parameter"
                            {
                                info.param_count += 1;
                                // Try to get variable name
                                if let Some(var_node) = param.child_by_field_name("name") {
                                    if let Ok(var_text) = var_node.utf8_text(source) {
                                        let name = var_text.trim_start_matches('$');
                                        if !name.is_empty() {
                                            info.param_names.push(name.to_string());
                                        }
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
                if kind == "function_definition" || kind == "method_declaration" {
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
                if parent_kind == "function_definition" || parent_kind == "method_declaration" {
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

            if node.kind() == "function_definition" || node.kind() == "method_declaration" {
                let name = self
                    .extract_function_name(&node, source)
                    .unwrap_or_else(|| "anonymous".to_string());

                report.functions.push(Function {
                    name,
                    offset: Some(format!("0x{:x}", node.start_byte())),
                    size: Some((node.end_byte() - node.start_byte()) as u64),
                    complexity: None,
                    calls: Vec::new(),
                    source: "tree-sitter-php".to_string(),
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
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.kind() == "name" {
                    return child.utf8_text(source).ok().map(|s| s.to_string());
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        None
    }
}
