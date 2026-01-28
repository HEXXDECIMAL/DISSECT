//! Metrics computation for Go source code.
//!
//! Computes various code metrics including:
//! - Go-specific metrics (goroutines, channels, etc.)
//! - Text metrics (comments, identifiers, strings)
//! - Code structure metrics

use crate::analyzers::comment_metrics::CommentStyle;
use crate::analyzers::{
    comment_metrics, function_metrics, identifier_metrics, string_metrics, text_metrics,
};
use crate::types::{GoMetrics, Metrics};

impl super::GoAnalyzer {
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

        let comment_metrics = comment_metrics::analyze_comments(content, CommentStyle::CStyle);

        let func_infos = self.extract_function_info(root, source);
        let func_metrics = function_metrics::analyze_functions(&func_infos, total_lines);

        // Compute Go-specific metrics
        let go_metrics = self.compute_go_metrics(root, source, content);

        Metrics {
            text: Some(text),
            identifiers: Some(identifier_metrics),
            strings: Some(string_metrics),
            comments: Some(comment_metrics),
            functions: Some(func_metrics),
            go_metrics: Some(go_metrics),
            ..Default::default()
        }
    }

    /// Compute Go-specific metrics for malware/obfuscation detection
    fn compute_go_metrics(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
        content: &str,
    ) -> GoMetrics {
        let mut metrics = GoMetrics::default();
        let mut cursor = root.walk();
        self.walk_for_go_metrics(&mut cursor, source, &mut metrics);

        // Additional pattern-based detection via string matching
        // These catch patterns that might be in comments or string literals
        metrics.linkname_count += content.matches("//go:linkname").count() as u32;
        metrics.noescape_count += content.matches("//go:noescape").count() as u32;
        metrics.embed_directive_count += content.matches("//go:embed").count() as u32;
        metrics.cgo_directives += content.matches("#cgo ").count() as u32;

        metrics
    }

    fn walk_for_go_metrics(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        metrics: &mut GoMetrics,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            match node.kind() {
                "import_spec" => {
                    if let Ok(text) = node.utf8_text(source) {
                        // Dangerous package imports
                        if text.contains("\"unsafe\"") {
                            metrics.unsafe_usage += 1;
                        }
                        if text.contains("\"reflect\"") {
                            metrics.reflect_usage += 1;
                        }
                        if text.contains("\"C\"") {
                            metrics.cgo_usage += 1;
                        }
                        if text.contains("\"plugin\"") {
                            metrics.plugin_usage += 1;
                        }
                        if text.contains("\"syscall\"") {
                            metrics.syscall_direct += 1;
                        }
                        // Blank imports (import _ "pkg") - often used for side effects
                        if text.starts_with("_ ") || text.contains("_ \"") {
                            metrics.blank_import_count += 1;
                        }
                    }
                }
                "function_declaration" => {
                    // Count init functions
                    if let Some(name_node) = node.child_by_field_name("name") {
                        if let Ok(name) = name_node.utf8_text(source) {
                            if name == "init" {
                                metrics.init_function_count += 1;
                            }
                        }
                    }
                }
                "call_expression" => {
                    if let Ok(text) = node.utf8_text(source) {
                        // Execution
                        if text.contains("exec.Command") {
                            metrics.exec_command_count += 1;
                        }
                        if text.contains("os.StartProcess") {
                            metrics.os_startprocess_count += 1;
                        }

                        // Network
                        if text.contains("net.Dial")
                            || text.contains("net.DialTCP")
                            || text.contains("net.DialUDP")
                        {
                            metrics.net_dial_count += 1;
                        }
                        if text.contains("http.Get")
                            || text.contains("http.Post")
                            || text.contains("http.Do")
                            || text.contains("http.ListenAndServe")
                            || text.contains("http.NewRequest")
                        {
                            metrics.http_usage += 1;
                        }
                        if text.contains("syscall.Socket")
                            || text.contains("net.ListenPacket")
                            || text.contains("icmp")
                        {
                            metrics.raw_socket_count += 1;
                        }
                    }
                }
                "selector_expression" => {
                    if let Ok(text) = node.utf8_text(source) {
                        // Track unsafe.Pointer usage
                        if text.contains("unsafe.Pointer")
                            || text.contains("unsafe.Sizeof")
                            || text.contains("unsafe.Offsetof")
                            || text.contains("unsafe.Alignof")
                        {
                            metrics.unsafe_usage += 1;
                        }
                        // Track reflect usage
                        if text.contains("reflect.ValueOf")
                            || text.contains("reflect.TypeOf")
                            || text.contains("reflect.Call")
                        {
                            metrics.reflect_usage += 1;
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
