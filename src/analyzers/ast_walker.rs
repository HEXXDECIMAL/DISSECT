//! Iterative AST traversal utilities
//!
//! Provides stack-safe alternatives to recursive AST walking.
//! This prevents stack overflow on deeply nested code (minified JS, malicious files).

use tree_sitter::{Node, TreeCursor};

/// Maximum depth to prevent runaway traversal on malformed ASTs
pub const MAX_AST_DEPTH: usize = 10_000;

/// Maximum recursion depth for nested function traversal
pub const MAX_RECURSION_DEPTH: u32 = 500;

/// Result of AST traversal with limit detection
#[derive(Debug, Clone, Default)]
pub struct WalkStats {
    /// Whether the depth limit was reached (potential anti-analysis)
    pub depth_limit_hit: bool,
    /// Maximum depth actually reached
    pub max_depth_reached: usize,
}

impl WalkStats {
    /// Merge another WalkStats, taking the worst case
    pub fn merge(&mut self, other: &WalkStats) {
        self.depth_limit_hit = self.depth_limit_hit || other.depth_limit_hit;
        self.max_depth_reached = self.max_depth_reached.max(other.max_depth_reached);
    }
}

/// Iteratively walk all nodes in a tree, calling the visitor function on each.
/// Returns early if depth exceeds MAX_AST_DEPTH.
///
/// The visitor receives (node, depth) and can return `false` to skip children.
pub fn walk_tree<F>(cursor: &mut TreeCursor, visitor: F)
where
    F: FnMut(Node, usize) -> bool,
{
    let _ = walk_tree_with_stats(cursor, visitor);
}

/// Like walk_tree but returns stats including whether depth limits were hit.
/// Use this when you need to detect potential anti-analysis techniques.
pub fn walk_tree_with_stats<F>(cursor: &mut TreeCursor, mut visitor: F) -> WalkStats
where
    F: FnMut(Node, usize) -> bool,
{
    let mut stats = WalkStats::default();
    let mut depth = 0usize;

    loop {
        if depth > stats.max_depth_reached {
            stats.max_depth_reached = depth;
        }

        if depth > MAX_AST_DEPTH {
            stats.depth_limit_hit = true;
            return stats; // Safety limit reached
        }

        let node = cursor.node();
        let should_descend = visitor(node, depth);

        // Try to descend if visitor allows
        if should_descend && cursor.goto_first_child() {
            depth += 1;
            continue;
        }

        // Try to go to sibling
        if cursor.goto_next_sibling() {
            continue;
        }

        // Go back up until we can go sideways or reach root
        loop {
            if !cursor.goto_parent() {
                return stats; // Reached root, done
            }
            depth = depth.saturating_sub(1);
            if cursor.goto_next_sibling() {
                break; // Found a sibling, continue outer loop
            }
        }
    }
}

/// Iteratively walk and collect items that match a predicate.
/// More efficient than walk_tree when you only need to collect specific nodes.
pub fn collect_nodes<'a, F>(cursor: &mut TreeCursor<'a>, mut predicate: F) -> Vec<Node<'a>>
where
    F: FnMut(&Node) -> bool,
{
    let mut results = Vec::new();
    let mut depth = 0usize;

    loop {
        if depth > MAX_AST_DEPTH {
            break;
        }

        let node = cursor.node();
        if predicate(&node) {
            results.push(node);
        }

        if cursor.goto_first_child() {
            depth += 1;
            continue;
        }

        if cursor.goto_next_sibling() {
            continue;
        }

        loop {
            if !cursor.goto_parent() {
                return results;
            }
            depth = depth.saturating_sub(1);
            if cursor.goto_next_sibling() {
                break;
            }
        }
    }

    results
}

/// Walk tree and collect nodes of specific kinds
pub fn collect_by_kind<'a>(cursor: &mut TreeCursor<'a>, kinds: &[&str]) -> Vec<Node<'a>> {
    collect_nodes(cursor, |node| kinds.contains(&node.kind()))
}

/// Walk tree and extract text from nodes of specific kinds
pub fn extract_text_by_kind(cursor: &mut TreeCursor, source: &[u8], kinds: &[&str]) -> Vec<String> {
    let mut results = Vec::new();
    let mut depth = 0usize;

    loop {
        if depth > MAX_AST_DEPTH {
            break;
        }

        let node = cursor.node();
        if kinds.contains(&node.kind()) {
            if let Ok(text) = node.utf8_text(source) {
                results.push(text.to_string());
            }
        }

        if cursor.goto_first_child() {
            depth += 1;
            continue;
        }

        if cursor.goto_next_sibling() {
            continue;
        }

        loop {
            if !cursor.goto_parent() {
                return results;
            }
            depth = depth.saturating_sub(1);
            if cursor.goto_next_sibling() {
                break;
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_js(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        parser.parse(code, None).unwrap()
    }

    #[test]
    fn test_walk_tree_basic() {
        let tree = parse_js("function foo() { return 1; }");
        let mut cursor = tree.walk();
        let mut count = 0;

        walk_tree(&mut cursor, |_node, _depth| {
            count += 1;
            true // Continue descending
        });

        assert!(count > 5); // Should visit multiple nodes
    }

    #[test]
    fn test_collect_by_kind() {
        let code = "function foo() { bar(); baz(); }";
        let tree = parse_js(code);
        let mut cursor = tree.walk();

        let calls = collect_by_kind(&mut cursor, &["call_expression"]);
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn test_extract_text_by_kind() {
        let code = r#"const x = "hello"; const y = "world";"#;
        let tree = parse_js(code);
        let mut cursor = tree.walk();

        let strings = extract_text_by_kind(&mut cursor, code.as_bytes(), &["string"]);
        assert_eq!(strings.len(), 2);
        assert!(strings.contains(&"\"hello\"".to_string()));
        assert!(strings.contains(&"\"world\"".to_string()));
    }

    #[test]
    fn test_depth_tracking() {
        let code = "function a() { function b() { function c() { } } }";
        let tree = parse_js(code);
        let mut cursor = tree.walk();
        let mut max_depth = 0;

        walk_tree(&mut cursor, |_node, depth| {
            if depth > max_depth {
                max_depth = depth;
            }
            true
        });

        assert!(max_depth > 3); // Should have decent nesting
    }

    #[test]
    fn test_skip_children() {
        let code = "function foo() { nested(); } function bar() { }";
        let tree = parse_js(code);
        let mut cursor = tree.walk();
        let mut func_count = 0;

        walk_tree(&mut cursor, |node, _depth| {
            if node.kind() == "function_declaration" {
                func_count += 1;
                false // Don't descend into function bodies
            } else {
                true
            }
        });

        assert_eq!(func_count, 2);
    }
}
