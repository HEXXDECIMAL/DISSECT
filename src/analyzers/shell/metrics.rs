//! Shell metrics computation.

use crate::analyzers::{
    comment_metrics::{self, CommentStyle},
    function_metrics, identifier_metrics, string_metrics, text_metrics,
};
use crate::types::*;
use tree_sitter;

impl super::ShellAnalyzer {
    pub(super) fn compute_metrics(&self, root: &tree_sitter::Node, content: &str, _report: &mut AnalysisReport) -> Metrics {
        let source = content.as_bytes();
        let total_lines = content.lines().count() as u32;

        // Universal text metrics
        let text = text_metrics::analyze_text(content);

        // Extract identifiers (variable names in shell)
        let identifiers = self.extract_identifiers(root, source);
        let ident_refs: Vec<&str> = identifiers.iter().map(|s| s.as_str()).collect();
        let identifier_metrics = identifier_metrics::analyze_identifiers(&ident_refs);

        // Extract strings
        let strings = self.extract_string_literals(root, source);
        let str_refs: Vec<&str> = strings.iter().map(|s| s.as_str()).collect();
        let string_metrics = string_metrics::analyze_strings(&str_refs);

        // Comment metrics (hash comments for shell)
        let comment_metrics = comment_metrics::analyze_comments(content, CommentStyle::Hash);

        // Function metrics
        let func_infos = self.extract_function_info(root, source);
        let func_metrics = function_metrics::analyze_functions(&func_infos, total_lines);

        // Shell-specific metrics
        let shell_metrics = self.compute_shell_metrics(root, source, content);

        Metrics {
            text: Some(text),
            identifiers: Some(identifier_metrics),
            strings: Some(string_metrics),
            comments: Some(comment_metrics),
            functions: Some(func_metrics),
            shell: Some(shell_metrics),
            ..Default::default()
        }
    }

    /// Extract identifiers (variable names) from shell script
    #[allow(dead_code)]
    pub(super) fn detect_shell_idioms(&self, root: &tree_sitter::Node, source: &[u8]) -> ShellIdioms {
        let mut pipe_count = 0u32;
        let mut redirect_count = 0u32;
        let mut input_redirect_count = 0u32;
        let mut command_substitution_count = 0u32;
        let mut heredoc_count = 0u32;
        let mut case_statement_count = 0u32;
        let mut test_expression_count = 0u32;
        let mut while_read_count = 0u32;
        let mut subshell_count = 0u32;
        let mut for_loop_count = 0u32;
        let mut background_job_count = 0u32;
        let mut process_substitution_count = 0u32;

        let mut cursor = root.walk();
        loop {
            let node = cursor.node();
            match node.kind() {
                "pipeline" => {
                    // Count pipes in the pipeline
                    if let Ok(text) = node.utf8_text(source) {
                        pipe_count += text.matches('|').count() as u32;
                    }
                }
                "redirected_statement" | "file_redirect" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains('>') {
                            redirect_count += 1;
                        }
                        if text.contains('<') && !text.contains("<<") {
                            input_redirect_count += 1;
                        }
                    }
                }
                "command_substitution" => {
                    command_substitution_count += 1;
                }
                "heredoc_redirect" => {
                    heredoc_count += 1;
                }
                "case_statement" => {
                    case_statement_count += 1;
                }
                "test_command" | "bracket_command" => {
                    test_expression_count += 1;
                }
                "while_statement" => {
                    // Check if it's a while read loop
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("read") {
                            while_read_count += 1;
                        }
                    }
                }
                "subshell" => {
                    subshell_count += 1;
                }
                "for_statement" | "c_style_for_statement" => {
                    for_loop_count += 1;
                }
                "command" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.ends_with('&') {
                            background_job_count += 1;
                        }
                    }
                }
                "process_substitution" => {
                    process_substitution_count += 1;
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
                    return ShellIdioms {
                        pipe_count,
                        redirect_count,
                        input_redirect_count,
                        command_substitution_count,
                        heredoc_count,
                        case_statement_count,
                        test_expression_count,
                        while_read_count,
                        subshell_count,
                        for_loop_count,
                        background_job_count,
                        process_substitution_count,
                    };
                }
            }
        }
    }

}
