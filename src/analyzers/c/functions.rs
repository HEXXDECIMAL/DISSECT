//! Function extraction and analysis for C source code.
//!
//! This module provides functionality to extract function definitions from C code
//! and collect them into the analysis report. It walks the AST to identify function
//! definitions and extracts metadata like name, offset, and size.

use crate::types::{AnalysisReport, Function};

use super::CAnalyzer;

/// Extract all function definitions from the AST and add to report.
pub(crate) fn extract_functions(
    analyzer: &CAnalyzer,
    node: &tree_sitter::Node,
    source: &[u8],
    report: &mut AnalysisReport,
) {
    let mut cursor = node.walk();
    walk_for_functions(analyzer, &mut cursor, source, report);
}

/// Iteratively walk AST to collect function definitions (avoids stack overflow).
fn walk_for_functions(
    analyzer: &CAnalyzer,
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    report: &mut AnalysisReport,
) {
    // Iterative traversal to avoid stack overflow on deeply nested code
    loop {
        let node = cursor.node();

        if node.kind() == "function_definition" {
            if let Ok(_text) = node.utf8_text(source) {
                // Extract function name
                let name = extract_function_name(analyzer, &node, source)
                    .unwrap_or_else(|| "anonymous".to_string());

                report.functions.push(Function {
                    name,
                    offset: Some(format!("0x{:x}", node.start_byte())),
                    size: Some((node.end_byte() - node.start_byte()) as u64),
                    complexity: None,
                    calls: Vec::new(),
                    source: "tree-sitter-c".to_string(),
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

/// Extract function name from a function definition node.
///
/// This searches for the function_declarator within the definition and
/// then finds the identifier within the declarator.
fn extract_function_name(
    _analyzer: &CAnalyzer,
    node: &tree_sitter::Node,
    source: &[u8],
) -> Option<String> {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "function_declarator" {
                // Find identifier inside declarator
                let mut decl_cursor = child.walk();
                if decl_cursor.goto_first_child() {
                    loop {
                        let decl_child = decl_cursor.node();
                        if decl_child.kind() == "identifier" {
                            return decl_child.utf8_text(source).ok().map(|s| s.to_string());
                        }
                        if !decl_cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    None
}
