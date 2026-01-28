//! PHP metrics computation.

use crate::analyzers::comment_metrics::CommentStyle;
use crate::analyzers::{
    comment_metrics, function_metrics, identifier_metrics, string_metrics, text_metrics,
};
use crate::types::*;
use tree_sitter;

impl super::PhpAnalyzer {
    pub(super) fn compute_metrics(
        &self,
        root: &tree_sitter::Node,
        content: &str,
        report: &mut AnalysisReport,
    ) -> Metrics {
        let source = content.as_bytes();
        let total_lines = content.lines().count() as u32;

        // Extract identifiers from AST
        let identifiers = self.extract_identifiers(root, source, report);
        let ident_refs: Vec<&str> = identifiers.iter().map(|s| s.as_str()).collect();
        let identifier_metrics = identifier_metrics::analyze_identifiers(&ident_refs);

        // Extract strings from AST
        let strings = self.extract_string_literals(root, source);
        let str_refs: Vec<&str> = strings.iter().map(|s| s.as_str()).collect();
        let string_metrics = string_metrics::analyze_strings(&str_refs);

        // Comment metrics (C-style for PHP)
        let comment_metrics = comment_metrics::analyze_comments(content, CommentStyle::CStyle);

        // Function metrics
        let func_infos = self.extract_function_info(root, source);
        let func_metrics = function_metrics::analyze_functions(&func_infos, total_lines);

        Metrics {
            text: Some(text_metrics::analyze_text(content)),
            identifiers: Some(identifier_metrics),
            strings: Some(string_metrics),
            comments: Some(comment_metrics),
            functions: Some(func_metrics),
            ..Default::default()
        }
    }
}
