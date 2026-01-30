//! Capability detection for Go source code.
//!
//! Most detections have been migrated to YAML traits in traits/ directory.

use crate::types::AnalysisReport;

impl super::GoAnalyzer {
    pub(super) fn detect_capabilities(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let mut cursor = node.walk();
        self.walk_ast(&mut cursor, source, report);
    }

    pub(super) fn walk_ast(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        _source: &[u8],
        _report: &mut AnalysisReport,
    ) {
        // Iterative traversal
        loop {
            let _node = cursor.node();

            // Native AST-based detections can be added here if needed
            // currently all Go detections are string/symbol based in YAML

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
}
