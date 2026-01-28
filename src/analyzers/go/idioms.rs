//! Go-specific idiom detection.
//!
//! Detects idiomatic Go patterns:
//! - Goroutines (concurrent execution)
//! - Channels (communication between goroutines)
//! - Defer statements
//! - Select statements
//! - Type assertions
//! - Interface usage

use crate::types::GoIdioms;

impl super::GoAnalyzer {
    pub(super) fn detect_go_idioms(&self, root: &tree_sitter::Node, source: &[u8]) -> GoIdioms {
        let mut goroutine_count = 0u32;
        let mut channel_count = 0u32;
        let mut defer_count = 0u32;
        let mut select_statement_count = 0u32;
        let mut type_assertion_count = 0u32;
        let mut method_count = 0u32;
        let mut interface_count = 0u32;
        let mut range_loop_count = 0u32;
        let mut error_return_count = 0u32;
        let mut panic_recover_count = 0u32;
        let mut cgo_count = 0u32;
        let mut unsafe_count = 0u32;

        let mut cursor = root.walk();
        loop {
            let node = cursor.node();
            match node.kind() {
                "go_statement" => goroutine_count += 1,
                "channel_type" => channel_count += 1,
                "defer_statement" => defer_count += 1,
                "select_statement" => select_statement_count += 1,
                "type_assertion" | "type_assertion_expression" => type_assertion_count += 1,
                "method_declaration" => method_count += 1,
                "interface_type" => interface_count += 1,
                "range_clause" => range_loop_count += 1,
                "function_declaration" => {
                    // Check for error return type
                    if let Some(result) = node.child_by_field_name("result") {
                        if let Ok(text) = result.utf8_text(source) {
                            if text.contains("error") {
                                error_return_count += 1;
                            }
                        }
                    }
                }
                "call_expression" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("panic") || text.contains("recover") {
                            panic_recover_count += 1;
                        }
                        if text.contains("unsafe.Pointer") || text.contains("unsafe.Sizeof") {
                            unsafe_count += 1;
                        }
                    }
                }
                "import_spec" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("\"C\"") {
                            cgo_count += 1;
                        }
                    }
                }
                _ => {}
            }

            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return GoIdioms {
                        goroutine_count,
                        channel_count,
                        defer_count,
                        select_statement_count,
                        type_assertion_count,
                        method_count,
                        interface_count,
                        range_loop_count,
                        error_return_count,
                        panic_recover_count,
                        cgo_count,
                        unsafe_count,
                    };
                }
            }
        }
    }
}
