//! Capability detection for C source code.
//!
//! This module provides the core capability detection logic by walking the AST
//! and routing nodes to appropriate pattern analyzers. It serves as the dispatcher
//! that coordinates detection across different node types (calls, includes, ASM, etc.).

use crate::types::AnalysisReport;

use super::patterns::{
    analyze_asm, analyze_call, analyze_comment, analyze_declaration, analyze_expression,
    analyze_function_definition, analyze_include, analyze_preproc_call,
};
use super::CAnalyzer;

/// Entry point for capability detection in C source code.
///
/// This initiates the AST traversal that identifies capabilities and suspicious patterns
/// throughout the source code.
pub(crate) fn detect_capabilities(
    analyzer: &CAnalyzer,
    node: &tree_sitter::Node,
    source: &[u8],
    report: &mut AnalysisReport,
) {
    let mut cursor = node.walk();
    walk_ast(analyzer, &mut cursor, source, report);
}

/// Walk the AST iteratively and route nodes to appropriate analyzers.
///
/// This uses an iterative approach to avoid stack overflow on deeply nested code.
/// Each node type is dispatched to a specialized analyzer that understands its
/// patterns and implications.
pub(crate) fn walk_ast(
    analyzer: &CAnalyzer,
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    report: &mut AnalysisReport,
) {
    // Iterative traversal to avoid stack overflow on deeply nested code
    loop {
        let node = cursor.node();

        match node.kind() {
            "call_expression" => {
                analyze_call(analyzer, &node, source, report);
            }
            "preproc_include" => {
                analyze_include(analyzer, &node, source, report);
            }
            "asm_statement" | "gnu_asm_expression" => {
                analyze_asm(analyzer, &node, source, report);
            }
            "declaration" => {
                analyze_declaration(analyzer, &node, source, report);
            }
            "assignment_expression" | "update_expression" | "binary_expression" => {
                analyze_expression(analyzer, &node, source, report);
            }
            "comment" => {
                analyze_comment(analyzer, &node, source, report);
            }
            "preproc_call" | "preproc_function_def" | "expression_statement" => {
                analyze_preproc_call(analyzer, &node, source, report);
            }
            "function_definition" => {
                analyze_function_definition(analyzer, &node, source, report);
            }
            "subscript_expression" | "field_expression" => {
                // Analyze array subscript for syscall table access
                // and field access for THIS_MODULE, task->flags, etc.
                analyze_expression(analyzer, &node, source, report);
            }
            _ => {}
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
