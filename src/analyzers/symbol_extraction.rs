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

/// Walk AST iteratively to find function calls (avoids stack overflow on deep nesting)
fn extract_calls(
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    call_types: &[&str],
    symbols: &mut std::collections::HashSet<String>,
) {
    // Use iterative traversal with explicit depth tracking to avoid stack overflow
    // on maliciously crafted or minified files with extreme nesting
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

        // Iterative tree traversal: try to go deeper, then sideways, then back up
        if cursor.goto_first_child() {
            continue;
        }
        if cursor.goto_next_sibling() {
            continue;
        }
        // Go back up until we can go sideways or reach the root
        loop {
            if !cursor.goto_parent() {
                return; // Reached root, done
            }
            if cursor.goto_next_sibling() {
                break; // Found a sibling, continue outer loop
            }
        }
    }
}

/// Extract the function name from a call expression node
fn extract_function_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    // For call expressions, the function being called is usually the first child or
    // named field "function", "callee", or "method".
    let callee = node
        .child_by_field_name("function")
        .or_else(|| node.child_by_field_name("callee"))
        .or_else(|| node.child_by_field_name("method"))
        .or_else(|| node.child(0))?;

    get_full_identifier(&callee, source)
}

/// Recursively extract a full identifier from member expressions (e.g., "os.Open")
fn get_full_identifier(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let kind = node.kind();

    // Base case: simple identifiers
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
        return node.utf8_text(source).ok().map(|s| s.to_string());
    }

    // Recursive case: member/selector expressions
    if matches!(
        kind,
        "member_expression"
            | "field_expression"
            | "selector_expression"
            | "attribute"
            | "dot_index_expression"
    ) {
        // Most member expressions have an object/operand and a property/field
        let object = node
            .child_by_field_name("object")
            .or_else(|| node.child_by_field_name("operand"))
            .or_else(|| node.child(0))?;

        let property = node
            .child_by_field_name("property")
            .or_else(|| node.child_by_field_name("field"))
            .or_else(|| node.child(node.child_count().saturating_sub(1) as u32))?;

        if let (Some(obj_name), Some(prop_name)) = (
            get_full_identifier(&object, source),
            get_full_identifier(&property, source),
        ) {
            return Some(format!("{}.{}", obj_name, prop_name));
        }
    }

    // Fallback: if it's a call, try to get the function name
    if kind.contains("call") || kind.contains("invocation") {
        return extract_function_name(node, source);
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
