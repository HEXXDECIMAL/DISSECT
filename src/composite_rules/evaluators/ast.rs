//! AST-based condition evaluators for source code analysis.
//!
//! This module handles evaluation of Abstract Syntax Tree conditions:
//! - Pattern matching within specific AST node types
//! - Tree-sitter query execution
//! - Safe AST traversal with depth limits

use super::{build_regex, truncate_evidence};
use crate::composite_rules::context::{AnalysisWarning, ConditionResult, EvaluationContext};
use crate::composite_rules::types::FileType;
use crate::types::Evidence;
use streaming_iterator::StreamingIterator;

/// Evaluate AST pattern condition - searches for text patterns within specific AST node types
pub fn eval_ast_pattern(
    node_type: &str,
    pattern: &str,
    use_regex: bool,
    case_insensitive: bool,
    ctx: &EvaluationContext,
) -> ConditionResult {
    // Only works for source code files
    let source = match std::str::from_utf8(ctx.binary_data) {
        Ok(s) => s,
        Err(_) => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
            }
        }
    };

    // Use cached AST if available
    if let Some(cached_tree) = ctx.cached_ast {
        return eval_ast_pattern_with_tree(cached_tree, source, node_type, pattern, use_regex, case_insensitive);
    }

    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!("⚠️  WARNING: AST cache miss - re-parsing AST for each trait! File type: {:?}", ctx.file_type);
    }

    // No cached AST, need to parse
    let parser_lang = match ctx.file_type {
        FileType::C => Some(tree_sitter_c::LANGUAGE),
        FileType::Python => Some(tree_sitter_python::LANGUAGE),
        FileType::JavaScript => Some(tree_sitter_javascript::LANGUAGE),
        FileType::TypeScript => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT),
        FileType::Rust => Some(tree_sitter_rust::LANGUAGE),
        FileType::Go => Some(tree_sitter_go::LANGUAGE),
        FileType::Java => Some(tree_sitter_java::LANGUAGE),
        FileType::Ruby => Some(tree_sitter_ruby::LANGUAGE),
        FileType::Shell => Some(tree_sitter_bash::LANGUAGE),
        FileType::Php => Some(tree_sitter_php::LANGUAGE_PHP),
        FileType::CSharp => Some(tree_sitter_c_sharp::LANGUAGE),
        FileType::Lua => Some(tree_sitter_lua::LANGUAGE),
        FileType::Perl => Some(tree_sitter_perl::LANGUAGE),
        FileType::PowerShell => Some(tree_sitter_powershell::LANGUAGE),
        FileType::Swift => Some(tree_sitter_swift::LANGUAGE),
        FileType::ObjectiveC => Some(tree_sitter_objc::LANGUAGE),
        FileType::Groovy => Some(tree_sitter_groovy::LANGUAGE),
        FileType::Scala => Some(tree_sitter_scala::LANGUAGE),
        FileType::Zig => Some(tree_sitter_zig::LANGUAGE),
        FileType::Elixir => Some(tree_sitter_elixir::LANGUAGE),
        _ => None,
    };

    let lang: tree_sitter::Language = match parser_lang {
        Some(l) => l.into(),
        None => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
            }
        }
    };

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&lang).is_err() {
        return ConditionResult {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
            warnings: Vec::new(),
        };
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
            }
        }
    };

    eval_ast_pattern_with_tree(&tree, source, node_type, pattern, use_regex, case_insensitive)
}

/// Helper function to evaluate AST pattern with a given tree
fn eval_ast_pattern_with_tree(
    tree: &tree_sitter::Tree,
    source: &str,
    node_type: &str,
    pattern: &str,
    use_regex: bool,
    case_insensitive: bool,
) -> ConditionResult {
    // Skip analysis if the tree has errors (malformed input)
    if tree.root_node().has_error() {
        return ConditionResult {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
            warnings: vec![AnalysisWarning::AstTooDeep { max_depth: 0 }],
        };
    }

    // Build the regex/pattern matcher
    let matcher: Box<dyn Fn(&str) -> bool> = if use_regex {
        match build_regex(pattern, case_insensitive) {
            Ok(re) => Box::new(move |s: &str| re.is_match(s)),
            Err(_) => {
                return ConditionResult {
                    matched: false,
                    evidence: Vec::new(),
                    traits: Vec::new(),
                    warnings: Vec::new(),
                }
            }
        }
    } else if case_insensitive {
        let pattern_lower = pattern.to_lowercase();
        Box::new(move |s: &str| s.to_lowercase().contains(&pattern_lower))
    } else {
        let pattern_owned = pattern.to_string();
        Box::new(move |s: &str| s.contains(&pattern_owned))
    };

    // Walk the AST and find matching nodes
    let mut evidence = Vec::new();
    let mut cursor = tree.walk();
    let stats = walk_ast_for_pattern(
        &mut cursor,
        source.as_bytes(),
        node_type,
        &matcher,
        &mut evidence,
    );

    let mut warnings = Vec::new();
    if stats.depth_limit_hit {
        warnings.push(AnalysisWarning::AstTooDeep {
            max_depth: stats.max_depth_reached,
        });
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
        warnings,
    }
}

/// Iteratively walk AST looking for nodes matching the pattern (stack-safe)
/// Returns WalkStats to detect potential anti-analysis (recursion bombs)
fn walk_ast_for_pattern(
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    target_node_type: &str,
    matcher: &dyn Fn(&str) -> bool,
    evidence: &mut Vec<Evidence>,
) -> crate::analyzers::ast_walker::WalkStats {
    crate::analyzers::ast_walker::walk_tree_with_stats(cursor, |node, _depth| {
        // Check if this node matches the target type
        if node.kind() == target_node_type {
            if let Ok(text) = node.utf8_text(source) {
                if matcher(text) {
                    evidence.push(Evidence {
                        method: "ast_pattern".to_string(),
                        source: "tree-sitter".to_string(),
                        value: truncate_evidence(text, 100),
                        location: Some(format!(
                            "{}:{}",
                            node.start_position().row + 1,
                            node.start_position().column + 1
                        )),
                    });
                }
            }
        }
        true // continue traversal into children
    })
}

/// Evaluate full tree-sitter query condition
pub fn eval_ast_query(query_str: &str, ctx: &EvaluationContext) -> ConditionResult {
    // Only works for source code files
    let source = match std::str::from_utf8(ctx.binary_data) {
        Ok(s) => s,
        Err(_) => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
            }
        }
    };

    // Get the appropriate parser and language based on file type
    let lang: tree_sitter::Language = match ctx.file_type {
        FileType::C => tree_sitter_c::LANGUAGE.into(),
        FileType::Python => tree_sitter_python::LANGUAGE.into(),
        FileType::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        FileType::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        FileType::Rust => tree_sitter_rust::LANGUAGE.into(),
        FileType::Go => tree_sitter_go::LANGUAGE.into(),
        FileType::Java => tree_sitter_java::LANGUAGE.into(),
        FileType::Ruby => tree_sitter_ruby::LANGUAGE.into(),
        FileType::Shell => tree_sitter_bash::LANGUAGE.into(),
        FileType::Php => tree_sitter_php::LANGUAGE_PHP.into(),
        FileType::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
        FileType::Lua => tree_sitter_lua::LANGUAGE.into(),
        FileType::Perl => tree_sitter_perl::LANGUAGE.into(),
        FileType::PowerShell => tree_sitter_powershell::LANGUAGE.into(),
        FileType::Swift => tree_sitter_swift::LANGUAGE.into(),
        FileType::ObjectiveC => tree_sitter_objc::LANGUAGE.into(),
        FileType::Groovy => tree_sitter_groovy::LANGUAGE.into(),
        FileType::Scala => tree_sitter_scala::LANGUAGE.into(),
        FileType::Zig => tree_sitter_zig::LANGUAGE.into(),
        FileType::Elixir => tree_sitter_elixir::LANGUAGE.into(),
        _ => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
            }
        }
    };

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&lang).is_err() {
        return ConditionResult {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
            warnings: Vec::new(),
        };
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
            }
        }
    };

    // Skip query execution if the tree has errors (malformed input)
    if tree.root_node().has_error() {
        return ConditionResult {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
            warnings: vec![AnalysisWarning::AstTooDeep { max_depth: 0 }],
        };
    }

    // Compile the query
    let query = match tree_sitter::Query::new(&lang, query_str) {
        Ok(q) => q,
        Err(_) => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
            }
        }
    };

    // Execute the query with safety limits
    let mut query_cursor = tree_sitter::QueryCursor::new();

    // Set limits to prevent runaway queries on pathological inputs
    // This prevents tree-sitter assertion failures on malformed files
    query_cursor.set_match_limit(100_000); // Limit pattern matches
    query_cursor.set_byte_range(0..source.len().min(10_000_000)); // Limit to first 10MB

    let mut evidence = Vec::new();
    const MAX_MATCHES: usize = 1000; // Cap evidence collection

    // Use captures() with StreamingIterator pattern (advance + get)
    let mut captures = query_cursor.captures(&query, tree.root_node(), source.as_bytes());
    while let Some((m, _)) = captures.next() {
        for capture in m.captures {
            if let Ok(text) = capture.node.utf8_text(source.as_bytes()) {
                evidence.push(Evidence {
                    method: "ast_query".to_string(),
                    source: "tree-sitter".to_string(),
                    value: truncate_evidence(text, 100),
                    location: Some(format!(
                        "{}:{}",
                        capture.node.start_position().row + 1,
                        capture.node.start_position().column + 1
                    )),
                });

                // Bail early if we've collected enough evidence
                if evidence.len() >= MAX_MATCHES {
                    break;
                }
            }
        }

        // Break outer loop too
        if evidence.len() >= MAX_MATCHES {
            break;
        }
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
        warnings: Vec::new(),
    }
}
