//! Metrics computation for Python source code.

use crate::analyzers::comment_metrics::CommentStyle;
use crate::analyzers::{
    comment_metrics, function_metrics, identifier_metrics, string_metrics, text_metrics,
};
use crate::types::{Metrics, PythonMetrics};

impl super::PythonAnalyzer {
    pub(super) fn compute_metrics(&self, root: &tree_sitter::Node, content: &str) -> Metrics {
        let source = content.as_bytes();
        let total_lines = content.lines().count() as u32;

        let text = text_metrics::analyze_text(content);

        let identifiers = self.extract_identifiers(root, source);
        let ident_refs: Vec<&str> = identifiers.iter().map(|s| s.as_str()).collect();
        let identifier_metrics = identifier_metrics::analyze_identifiers(&ident_refs);

        let strings = self.extract_string_literals(root, source);
        let str_refs: Vec<&str> = strings.iter().map(|s| s.as_str()).collect();
        let string_metrics = string_metrics::analyze_strings(&str_refs);

        let comment_metrics = comment_metrics::analyze_comments(content, CommentStyle::Hash);

        let func_infos = self.extract_function_info(root, source);
        let func_metrics = function_metrics::analyze_functions(&func_infos, total_lines);

        let python_metrics = self.compute_python_metrics(root, source, content);

        Metrics {
            text: Some(text),
            identifiers: Some(identifier_metrics),
            strings: Some(string_metrics),
            comments: Some(comment_metrics),
            functions: Some(func_metrics),
            python: Some(python_metrics),
            ..Default::default()
        }
    }

    fn compute_python_metrics(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
        content: &str,
    ) -> PythonMetrics {
        let mut metrics = PythonMetrics::default();
        let mut cursor = root.walk();
        self.walk_for_python_metrics(&mut cursor, source, &mut metrics);

        // Pattern-based detection via string matching
        metrics.dunder_method_count += content.matches("def __").count() as u32;

        metrics
    }

    fn walk_for_python_metrics(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        metrics: &mut PythonMetrics,
    ) {
        loop {
            let node = cursor.node();

            match node.kind() {
                "import_statement" | "import_from_statement" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("__import__") {
                            metrics.dunder_import_count += 1;
                        }
                        if text.contains("pickle") {
                            metrics.pickle_usage += 1;
                        }
                        if text.contains("base64") {
                            metrics.base64_calls += 1;
                        }
                    }
                }
                "function_definition" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        if let Ok(name_text) = name.utf8_text(source) {
                            if name_text.starts_with("__") && name_text.ends_with("__") {
                                metrics.dunder_method_count += 1;
                            }
                        }
                    }
                    // Check for decorators
                    let mut prev = node.prev_sibling();
                    while let Some(sibling) = prev {
                        if sibling.kind() == "decorator" {
                            metrics.decorator_count += 1;
                            prev = sibling.prev_sibling();
                        } else {
                            break;
                        }
                    }
                }
                "class_definition" => {
                    metrics.class_count += 1;
                }
                "try_statement" => {
                    metrics.try_except_count += 1;
                }
                "with_statement" => {
                    metrics.with_statement_count += 1;
                }
                "lambda" => {
                    metrics.lambda_count += 1;
                }
                "list_comprehension" | "dictionary_comprehension" | "set_comprehension" => {
                    // For now just track presence, depth calculation would require more complex traversal
                    if metrics.comprehension_depth_max == 0 {
                        metrics.comprehension_depth_max = 1;
                    }
                }
                "call" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("eval(") {
                            metrics.eval_count += 1;
                        }
                        if text.contains("exec(") {
                            metrics.exec_count += 1;
                        }
                        if text.contains("compile(") {
                            metrics.compile_count += 1;
                        }
                        if text.contains("__import__(") {
                            metrics.dunder_import_count += 1;
                        }
                        if text.contains("getattr(")
                            || text.contains("setattr(")
                            || text.contains("hasattr(")
                        {
                            metrics.attr_manipulation_count += 1;
                        }
                        if text.contains("globals(") || text.contains("locals(") {
                            metrics.globals_locals_access += 1;
                        }
                    }
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
}
