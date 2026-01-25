//! Symbol extraction from source code
//!
//! Extracts function calls and references from source files using AST analysis.
//! Populates the imports list so symbol-based rules can match.

use crate::types::{AnalysisReport, Import};

/// Extract function calls from source code and add to report.imports
pub fn extract_symbols(
    source: &str,
    lang: tree_sitter::Language,
    call_types: &[&str],
    report: &mut AnalysisReport,
) {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&lang).is_err() {
        return;
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return,
    };

    let mut symbols = std::collections::HashSet::new();
    let mut cursor = tree.walk();
    extract_calls(&mut cursor, source.as_bytes(), call_types, &mut symbols);

    // Add unique symbols to imports
    for symbol in symbols {
        // Skip very short symbols (likely false positives)
        if symbol.len() < 2 {
            continue;
        }
        report.imports.push(Import {
            symbol,
            library: None,
            source: "ast".to_string(),
        });
    }
}

/// Recursively walk AST to find function calls
fn extract_calls(
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    call_types: &[&str],
    symbols: &mut std::collections::HashSet<String>,
) {
    loop {
        let node = cursor.node();
        let node_type = node.kind();

        // Check if this is a call node type we're interested in
        if call_types.contains(&node_type) {
            if let Some(func_name) = extract_function_name(&node, source) {
                // Clean up the function name
                let clean_name = func_name
                    .trim()
                    .trim_start_matches('_')
                    .trim_start_matches('$');
                if !clean_name.is_empty() && clean_name.len() < 100 {
                    symbols.insert(clean_name.to_string());
                }
            }
        }

        // Recurse into children
        if cursor.goto_first_child() {
            extract_calls(cursor, source, call_types, symbols);
            cursor.goto_parent();
        }

        // Move to next sibling
        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

/// Extract the function name from a call expression node
fn extract_function_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            let kind = child.kind();

            // Look for identifier-like nodes
            if matches!(
                kind,
                "identifier"
                    | "field_identifier"
                    | "property_identifier"
                    | "attribute"
                    | "name"
                    | "command_name"
                    | "word"
                    | "simple_identifier"
            ) {
                return child.utf8_text(source).ok().map(|s| s.to_string());
            }

            // For member expressions, recurse to find the method name
            if matches!(
                kind,
                "member_expression"
                    | "field_expression"
                    | "attribute"
                    | "call"
                    | "method_call"
                    | "selector_expression"
                    | "call_expression"
            ) {
                if let Some(name) = extract_function_name(&child, source) {
                    return Some(name);
                }
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    None
}

/// Get the tree-sitter language and call node types for a file type
pub fn get_language_config(
    file_type: &crate::analyzers::FileType,
) -> Option<(tree_sitter::Language, Vec<&'static str>)> {
    use crate::analyzers::FileType;

    match file_type {
        FileType::C => Some((tree_sitter_c::LANGUAGE.into(), vec!["call_expression"])),
        FileType::Python => Some((tree_sitter_python::LANGUAGE.into(), vec!["call"])),
        FileType::JavaScript => Some((
            tree_sitter_javascript::LANGUAGE.into(),
            vec!["call_expression"],
        )),
        FileType::TypeScript => Some((
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            vec!["call_expression"],
        )),
        FileType::Rust => Some((
            tree_sitter_rust::LANGUAGE.into(),
            vec!["call_expression", "macro_invocation"],
        )),
        FileType::Go => Some((tree_sitter_go::LANGUAGE.into(), vec!["call_expression"])),
        FileType::Java => Some((tree_sitter_java::LANGUAGE.into(), vec!["method_invocation"])),
        FileType::Ruby => Some((
            tree_sitter_ruby::LANGUAGE.into(),
            vec!["call", "method_call"],
        )),
        FileType::Shell => Some((
            tree_sitter_bash::LANGUAGE.into(),
            vec!["command", "command_name"],
        )),
        FileType::CSharp => Some((
            tree_sitter_c_sharp::LANGUAGE.into(),
            vec!["invocation_expression"],
        )),
        FileType::Php => Some((
            tree_sitter_php::LANGUAGE_PHP.into(),
            vec!["function_call_expression"],
        )),
        FileType::Lua => Some((tree_sitter_lua::LANGUAGE.into(), vec!["function_call"])),
        FileType::Perl => Some((
            tree_sitter_perl::LANGUAGE.into(),
            vec!["function_call", "method_call"],
        )),
        FileType::PowerShell => Some((
            tree_sitter_powershell::LANGUAGE.into(),
            vec!["command_expression", "invocation_expression"],
        )),
        FileType::Swift => Some((tree_sitter_swift::LANGUAGE.into(), vec!["call_expression"])),
        FileType::ObjectiveC => Some((
            tree_sitter_objc::LANGUAGE.into(),
            vec!["message_expression", "call_expression"],
        )),
        FileType::Groovy => Some((
            tree_sitter_groovy::LANGUAGE.into(),
            vec!["method_call", "function_call"],
        )),
        FileType::Scala => Some((
            tree_sitter_scala::LANGUAGE.into(),
            vec!["call_expression", "apply_expression"],
        )),
        FileType::Zig => Some((tree_sitter_zig::LANGUAGE.into(), vec!["call_expression"])),
        FileType::Elixir => Some((tree_sitter_elixir::LANGUAGE.into(), vec!["call"])),
        _ => None,
    }
}
