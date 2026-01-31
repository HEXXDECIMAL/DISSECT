//! Abstract AST kind mapping to tree-sitter node types.
//!
//! Maps normalized kind names (like "call", "function", "class") to
//! language-specific tree-sitter node types. This allows rules to be
//! written once and work across multiple languages.

use crate::composite_rules::types::FileType;

/// Map an abstract kind to language-specific tree-sitter node types.
/// Returns multiple node types since some kinds map to several node types per language.
pub fn map_kind_to_node_types(kind: &str, file_type: FileType) -> Vec<&'static str> {
    match kind {
        "call" => match file_type {
            FileType::Python => vec!["call"],
            FileType::JavaScript | FileType::TypeScript => vec!["call_expression"],
            FileType::Ruby => vec!["call", "method_call"],
            FileType::Go => vec!["call_expression"],
            FileType::C | FileType::ObjectiveC => vec!["call_expression"],
            FileType::Rust => vec!["call_expression"],
            FileType::Java => vec!["method_invocation"],
            FileType::CSharp => vec!["invocation_expression"],
            FileType::Php => vec!["function_call_expression", "member_call_expression"],
            FileType::Shell => vec!["command"],
            FileType::Lua => vec!["function_call"],
            FileType::Perl => vec!["function_call"],
            FileType::PowerShell => vec!["command_expression", "invocation_expression"],
            FileType::Swift => vec!["call_expression"],
            FileType::Groovy => vec!["method_call"],
            FileType::Scala => vec!["call_expression"],
            FileType::Zig => vec!["call_expression"],
            FileType::Elixir => vec!["call"],
            _ => vec![],
        },

        "function" => match file_type {
            FileType::Python => vec!["function_definition"],
            FileType::JavaScript | FileType::TypeScript => {
                vec!["function_declaration", "arrow_function", "function_expression"]
            }
            FileType::Ruby => vec!["method", "singleton_method"],
            FileType::Go => vec!["function_declaration", "method_declaration"],
            FileType::C | FileType::ObjectiveC => vec!["function_definition"],
            FileType::Rust => vec!["function_item"],
            FileType::Java => vec!["method_declaration"],
            FileType::CSharp => vec!["method_declaration"],
            FileType::Php => vec!["function_definition", "method_declaration"],
            FileType::Shell => vec!["function_definition"],
            FileType::Lua => vec!["function_definition", "local_function_definition_statement"],
            FileType::Perl => vec!["subroutine_declaration_statement"],
            FileType::PowerShell => vec!["function_statement"],
            FileType::Swift => vec!["function_declaration"],
            FileType::Groovy => vec!["method_definition"],
            FileType::Scala => vec!["function_definition"],
            FileType::Zig => vec!["fn_decl"],
            FileType::Elixir => vec!["call"], // def/defp are function calls in Elixir AST
            _ => vec![],
        },

        "class" => match file_type {
            FileType::Python => vec!["class_definition"],
            FileType::JavaScript | FileType::TypeScript => vec!["class_declaration", "class"],
            FileType::Ruby => vec!["class", "singleton_class"],
            FileType::Go => vec!["type_declaration"],
            FileType::C => vec!["struct_specifier"],
            FileType::ObjectiveC => vec!["class_interface", "class_implementation"],
            FileType::Rust => vec!["struct_item", "impl_item"],
            FileType::Java => vec!["class_declaration"],
            FileType::CSharp => vec!["class_declaration"],
            FileType::Php => vec!["class_declaration"],
            FileType::Lua => vec![], // Lua doesn't have native classes
            FileType::Perl => vec!["package_statement"],
            FileType::PowerShell => vec!["class_statement"],
            FileType::Swift => vec!["class_declaration"],
            FileType::Groovy => vec!["class_definition"],
            FileType::Scala => vec!["class_definition"],
            FileType::Zig => vec!["container_decl"],
            FileType::Elixir => vec!["call"], // defmodule is a function call in Elixir AST
            _ => vec![],
        },

        "import" => match file_type {
            FileType::Python => vec!["import_statement", "import_from_statement"],
            FileType::JavaScript | FileType::TypeScript => {
                vec!["import_statement", "import_declaration"]
            }
            FileType::Ruby => vec!["call"], // require/require_relative are function calls
            FileType::Go => vec!["import_declaration"],
            FileType::C | FileType::ObjectiveC => vec!["preproc_include", "preproc_import"],
            FileType::Rust => vec!["use_declaration"],
            FileType::Java => vec!["import_declaration"],
            FileType::CSharp => vec!["using_directive"],
            FileType::Php => vec!["use_declaration", "namespace_use_declaration"],
            FileType::Shell => vec!["command"], // source/. commands
            FileType::Lua => vec!["function_call"], // require is a function call
            FileType::Perl => vec!["use_statement", "require_statement"],
            FileType::PowerShell => vec!["using_statement"],
            FileType::Swift => vec!["import_declaration"],
            FileType::Groovy => vec!["import_declaration"],
            FileType::Scala => vec!["import_declaration"],
            FileType::Zig => vec!["builtin_call_expr"], // @import
            FileType::Elixir => vec!["call"], // import/use/require are function calls
            _ => vec![],
        },

        "string" => match file_type {
            FileType::Python => vec!["string", "concatenated_string"],
            FileType::JavaScript | FileType::TypeScript => vec!["string", "template_string"],
            FileType::Ruby => vec!["string", "string_content", "heredoc_body"],
            FileType::Go => vec!["interpreted_string_literal", "raw_string_literal"],
            FileType::C | FileType::ObjectiveC => vec!["string_literal"],
            FileType::Rust => vec!["string_literal", "raw_string_literal"],
            FileType::Java => vec!["string_literal"],
            FileType::CSharp => vec!["string_literal", "verbatim_string_literal"],
            FileType::Php => vec!["string", "encapsed_string"],
            FileType::Shell => vec!["string", "raw_string"],
            FileType::Lua => vec!["string"],
            FileType::Perl => vec!["string_literal", "interpolated_string_literal"],
            FileType::PowerShell => vec!["string_literal", "expandable_string_literal"],
            FileType::Swift => vec!["line_string_literal"],
            FileType::Groovy => vec!["string"],
            FileType::Scala => vec!["string"],
            FileType::Zig => vec!["string_literal"],
            FileType::Elixir => vec!["string"],
            _ => vec![],
        },

        "comment" => match file_type {
            FileType::Python => vec!["comment"],
            FileType::JavaScript | FileType::TypeScript => vec!["comment"],
            FileType::Ruby => vec!["comment"],
            FileType::Go => vec!["comment"],
            FileType::C | FileType::ObjectiveC => vec!["comment"],
            FileType::Rust => vec!["line_comment", "block_comment"],
            FileType::Java => vec!["line_comment", "block_comment"],
            FileType::CSharp => vec!["comment"],
            FileType::Php => vec!["comment"],
            FileType::Shell => vec!["comment"],
            FileType::Lua => vec!["comment"],
            FileType::Perl => vec!["comment"],
            FileType::PowerShell => vec!["comment"],
            FileType::Swift => vec!["comment", "multiline_comment"],
            FileType::Groovy => vec!["comment"],
            FileType::Scala => vec!["comment"],
            FileType::Zig => vec!["line_comment"],
            FileType::Elixir => vec!["comment"],
            _ => vec![],
        },

        "assignment" => match file_type {
            FileType::Python => vec!["assignment", "augmented_assignment"],
            FileType::JavaScript | FileType::TypeScript => {
                vec!["assignment_expression", "variable_declaration"]
            }
            FileType::Ruby => vec!["assignment"],
            FileType::Go => vec!["short_var_declaration", "assignment_statement"],
            FileType::C | FileType::ObjectiveC => vec!["assignment_expression"],
            FileType::Rust => vec!["let_declaration"],
            FileType::Java => vec!["assignment_expression", "local_variable_declaration"],
            FileType::CSharp => vec!["assignment_expression", "local_declaration_statement"],
            FileType::Php => vec!["assignment_expression"],
            FileType::Shell => vec!["variable_assignment"],
            FileType::Lua => vec!["assignment_statement"],
            FileType::Perl => vec!["assignment_expression"],
            FileType::PowerShell => vec!["assignment_expression"],
            FileType::Swift => vec!["value_binding_pattern"],
            FileType::Groovy => vec!["assignment"],
            FileType::Scala => vec!["val_definition", "var_definition"],
            FileType::Zig => vec!["var_decl"],
            FileType::Elixir => vec!["binary_operator"], // = is a binary operator in Elixir
            _ => vec![],
        },

        "return" => match file_type {
            FileType::Python => vec!["return_statement"],
            FileType::JavaScript | FileType::TypeScript => vec!["return_statement"],
            FileType::Ruby => vec!["return"],
            FileType::Go => vec!["return_statement"],
            FileType::C | FileType::ObjectiveC => vec!["return_statement"],
            FileType::Rust => vec!["return_expression"],
            FileType::Java => vec!["return_statement"],
            FileType::CSharp => vec!["return_statement"],
            FileType::Php => vec!["return_statement"],
            FileType::Shell => vec!["command"], // return is a command
            FileType::Lua => vec!["return_statement"],
            FileType::Perl => vec!["return_expression"],
            FileType::PowerShell => vec!["return_statement"],
            FileType::Swift => vec!["return_statement"],
            FileType::Groovy => vec!["return_statement"],
            FileType::Scala => vec!["return_expression"],
            FileType::Zig => vec!["return_expression"],
            FileType::Elixir => vec![], // Elixir doesn't have explicit return
            _ => vec![],
        },

        "binary_op" => match file_type {
            FileType::Python => vec!["binary_operator", "comparison_operator", "boolean_operator"],
            FileType::JavaScript | FileType::TypeScript => vec!["binary_expression"],
            FileType::Ruby => vec!["binary"],
            FileType::Go => vec!["binary_expression"],
            FileType::C | FileType::ObjectiveC => vec!["binary_expression"],
            FileType::Rust => vec!["binary_expression"],
            FileType::Java => vec!["binary_expression"],
            FileType::CSharp => vec!["binary_expression"],
            FileType::Php => vec!["binary_expression"],
            FileType::Shell => vec!["binary_expression"],
            FileType::Lua => vec!["binary_expression"],
            FileType::Perl => vec!["binary_expression"],
            FileType::PowerShell => vec!["binary_expression"],
            FileType::Swift => vec!["infix_expression"],
            FileType::Groovy => vec!["binary_expression"],
            FileType::Scala => vec!["infix_expression"],
            FileType::Zig => vec!["binary_expression"],
            FileType::Elixir => vec!["binary_operator"],
            _ => vec![],
        },

        "identifier" => match file_type {
            FileType::Python => vec!["identifier"],
            FileType::JavaScript | FileType::TypeScript => vec!["identifier"],
            FileType::Ruby => vec!["identifier"],
            FileType::Go => vec!["identifier"],
            FileType::C | FileType::ObjectiveC => vec!["identifier"],
            FileType::Rust => vec!["identifier"],
            FileType::Java => vec!["identifier"],
            FileType::CSharp => vec!["identifier"],
            FileType::Php => vec!["name"],
            FileType::Shell => vec!["word", "variable_name"],
            FileType::Lua => vec!["identifier"],
            FileType::Perl => vec!["scalar_variable", "array_variable", "hash_variable"],
            FileType::PowerShell => vec!["variable"],
            FileType::Swift => vec!["simple_identifier"],
            FileType::Groovy => vec!["identifier"],
            FileType::Scala => vec!["identifier"],
            FileType::Zig => vec!["identifier"],
            FileType::Elixir => vec!["identifier"],
            _ => vec![],
        },

        "attribute" => match file_type {
            FileType::Python => vec!["attribute"],
            FileType::JavaScript | FileType::TypeScript => vec!["member_expression"],
            FileType::Ruby => vec!["call"], // method calls look like attribute access
            FileType::Go => vec!["selector_expression"],
            FileType::C | FileType::ObjectiveC => vec!["field_expression"],
            FileType::Rust => vec!["field_expression"],
            FileType::Java => vec!["field_access"],
            FileType::CSharp => vec!["member_access_expression"],
            FileType::Php => vec!["member_access_expression"],
            FileType::Shell => vec![], // Shell doesn't have attribute access
            FileType::Lua => vec!["field_expression"],
            FileType::Perl => vec!["method_call_expression"],
            FileType::PowerShell => vec!["member_expression"],
            FileType::Swift => vec!["navigation_expression"],
            FileType::Groovy => vec!["member_expression"],
            FileType::Scala => vec!["field_expression"],
            FileType::Zig => vec!["field_access"],
            FileType::Elixir => vec!["access_call"],
            _ => vec![],
        },

        "subscript" => match file_type {
            FileType::Python => vec!["subscript"],
            FileType::JavaScript | FileType::TypeScript => vec!["subscript_expression"],
            FileType::Ruby => vec!["element_reference"],
            FileType::Go => vec!["index_expression"],
            FileType::C | FileType::ObjectiveC => vec!["subscript_expression"],
            FileType::Rust => vec!["index_expression"],
            FileType::Java => vec!["array_access"],
            FileType::CSharp => vec!["element_access_expression"],
            FileType::Php => vec!["subscript_expression"],
            FileType::Shell => vec![], // Shell uses ${array[index]} syntax
            FileType::Lua => vec!["bracket_index_expression"],
            FileType::Perl => vec!["array_element_expression", "hash_element_expression"],
            FileType::PowerShell => vec!["index_expression"],
            FileType::Swift => vec!["subscript_expression"],
            FileType::Groovy => vec!["index_expression"],
            FileType::Scala => vec!["call_expression"], // Scala uses apply() for indexing
            FileType::Zig => vec!["array_access"],
            FileType::Elixir => vec!["access_call"],
            _ => vec![],
        },

        "conditional" => match file_type {
            FileType::Python => vec!["if_statement", "conditional_expression"],
            FileType::JavaScript | FileType::TypeScript => {
                vec!["if_statement", "ternary_expression"]
            }
            FileType::Ruby => vec!["if", "unless", "if_modifier", "unless_modifier"],
            FileType::Go => vec!["if_statement"],
            FileType::C | FileType::ObjectiveC => vec!["if_statement", "conditional_expression"],
            FileType::Rust => vec!["if_expression"],
            FileType::Java => vec!["if_statement", "ternary_expression"],
            FileType::CSharp => vec!["if_statement", "conditional_expression"],
            FileType::Php => vec!["if_statement", "conditional_expression"],
            FileType::Shell => vec!["if_statement", "case_statement"],
            FileType::Lua => vec!["if_statement"],
            FileType::Perl => vec!["if_statement", "unless_statement", "ternary_expression"],
            FileType::PowerShell => vec!["if_statement"],
            FileType::Swift => vec!["if_statement", "ternary_expression"],
            FileType::Groovy => vec!["if_statement"],
            FileType::Scala => vec!["if_expression"],
            FileType::Zig => vec!["if_expression"],
            FileType::Elixir => vec!["call"], // if/unless are function calls in Elixir
            _ => vec![],
        },

        "loop" => match file_type {
            FileType::Python => vec!["for_statement", "while_statement"],
            FileType::JavaScript | FileType::TypeScript => {
                vec!["for_statement", "while_statement", "for_in_statement", "for_of_statement"]
            }
            FileType::Ruby => vec!["for", "while", "until", "while_modifier", "until_modifier"],
            FileType::Go => vec!["for_statement"],
            FileType::C | FileType::ObjectiveC => {
                vec!["for_statement", "while_statement", "do_statement"]
            }
            FileType::Rust => vec!["for_expression", "while_expression", "loop_expression"],
            FileType::Java => vec![
                "for_statement",
                "enhanced_for_statement",
                "while_statement",
                "do_statement",
            ],
            FileType::CSharp => {
                vec!["for_statement", "foreach_statement", "while_statement", "do_statement"]
            }
            FileType::Php => vec!["for_statement", "foreach_statement", "while_statement"],
            FileType::Shell => vec!["for_statement", "while_statement"],
            FileType::Lua => vec!["for_statement", "while_statement", "repeat_statement"],
            FileType::Perl => vec![
                "for_statement",
                "foreach_statement",
                "while_statement",
                "until_statement",
            ],
            FileType::PowerShell => vec!["for_statement", "foreach_statement", "while_statement"],
            FileType::Swift => vec!["for_statement", "while_statement", "repeat_while_statement"],
            FileType::Groovy => vec!["for_statement", "while_statement"],
            FileType::Scala => vec!["for_expression", "while_expression"],
            FileType::Zig => vec!["for_expression", "while_expression"],
            FileType::Elixir => vec!["call"], // for/Enum.each are function calls
            _ => vec![],
        },

        // If kind is not recognized, return empty vec
        _ => vec![],
    }
}

/// Get all supported abstract kinds
pub fn supported_kinds() -> &'static [&'static str] {
    &[
        "call",
        "function",
        "class",
        "import",
        "string",
        "comment",
        "assignment",
        "return",
        "binary_op",
        "identifier",
        "attribute",
        "subscript",
        "conditional",
        "loop",
    ]
}
