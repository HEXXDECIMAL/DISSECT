//! Condition types for composite rules.

use super::types::Platform;
use anyhow::Result;
use serde::Deserialize;
use std::sync::Arc;

/// Condition type in composite rules
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    /// Match a symbol (import/export)
    Symbol {
        pattern: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        platforms: Option<Vec<Platform>>,
    },

    /// Match a string in the binary
    String {
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        #[serde(default)]
        case_insensitive: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        exclude_patterns: Option<Vec<String>>,
        #[serde(default = "default_min_count")]
        min_count: usize,
        /// Search raw file content instead of extracted strings (for counting occurrences)
        #[serde(default)]
        search_raw: bool,
    },

    /// Match a YARA rule result
    YaraMatch {
        namespace: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        rule: Option<String>,
    },

    /// Match a structural feature
    Structure {
        feature: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        min_sections: Option<usize>,
    },

    /// Match symbol OR string (convenience)
    SymbolOrString { any: Vec<String> },

    /// Check import count
    ImportsCount {
        #[serde(skip_serializing_if = "Option::is_none")]
        min: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        filter: Option<String>,
    },

    /// Check export count
    ExportsCount {
        #[serde(skip_serializing_if = "Option::is_none")]
        min: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<usize>,
    },

    /// Reference a previously-defined trait by ID
    Trait { id: String },

    /// Simple AST pattern matching - searches for text patterns within specific AST node types
    /// Example: { type: ast_pattern, node_type: call_expression, pattern: "kallsyms_lookup_name" }
    AstPattern {
        /// AST node type to search (e.g., call_expression, preproc_include, comment, declaration)
        node_type: String,
        /// Text pattern to match within the node
        pattern: String,
        /// Use regex matching instead of substring (default: false)
        #[serde(default)]
        regex: bool,
        /// Case insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
    },

    /// Full tree-sitter query for complex AST matching
    /// Example: { type: ast_query, language: javascript, query: "(call_expression function: (identifier) @fn (#eq? @fn \"eval\"))" }
    AstQuery {
        /// Tree-sitter query pattern (S-expression syntax)
        query: String,
        /// Optional: language for query validation (javascript, python, c, etc.)
        /// If not specified, validation is skipped and query is compiled at runtime
        #[serde(skip_serializing_if = "Option::is_none")]
        language: Option<String>,
    },

    /// Inline YARA rule for pattern matching
    /// Example: { type: yara, source: "rule test { strings: $a = \"test\" condition: $a }" }
    Yara {
        /// YARA rule source code
        source: String,
        /// Pre-compiled YARA rules (populated at load time, skipped during deserialization)
        #[serde(skip)]
        compiled: Option<Arc<yara_x::Rules>>,
    },

    /// Match syscalls detected via radare2 binary analysis
    /// For detecting direct syscall usage patterns in ELF/Mach-O binaries
    Syscall {
        /// Syscall name(s) to match (e.g., "socket", "connect", "execve")
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<Vec<String>>,
        /// Syscall number(s) to match (architecture-dependent)
        #[serde(skip_serializing_if = "Option::is_none")]
        number: Option<Vec<u32>>,
        /// Architecture filter (e.g., "mips", "x86_64", "arm")
        #[serde(skip_serializing_if = "Option::is_none")]
        arch: Option<Vec<String>>,
        /// Minimum number of matching syscalls required
        #[serde(skip_serializing_if = "Option::is_none")]
        min_count: Option<usize>,
    },

    /// Check section size ratio (e.g., __const is 80%+ of binary)
    /// For detecting encrypted payload droppers
    SectionRatio {
        /// Section name pattern (regex)
        section: String,
        /// Compare to "total" binary size or another section pattern
        #[serde(default = "default_compare_to")]
        compare_to: String,
        /// Minimum ratio (0.0-1.0)
        #[serde(skip_serializing_if = "Option::is_none")]
        min_ratio: Option<f64>,
        /// Maximum ratio (0.0-1.0)
        #[serde(skip_serializing_if = "Option::is_none")]
        max_ratio: Option<f64>,
    },

    /// Check section entropy (0.0-8.0)
    /// High entropy (>7.0) indicates encryption or compression
    SectionEntropy {
        /// Section name pattern (regex)
        section: String,
        /// Minimum entropy threshold
        #[serde(skip_serializing_if = "Option::is_none")]
        min_entropy: Option<f64>,
        /// Maximum entropy threshold
        #[serde(skip_serializing_if = "Option::is_none")]
        max_entropy: Option<f64>,
    },

    /// Check import patterns (required + suspicious combination)
    /// For detecting malware import fingerprints
    ImportCombination {
        /// All of these imports must be present
        #[serde(skip_serializing_if = "Option::is_none")]
        required: Option<Vec<String>>,
        /// Count matches from this suspicious list
        #[serde(skip_serializing_if = "Option::is_none")]
        suspicious: Option<Vec<String>>,
        /// Minimum number of suspicious imports required
        #[serde(skip_serializing_if = "Option::is_none")]
        min_suspicious: Option<usize>,
        /// Maximum total import count (low count = suspicious)
        #[serde(skip_serializing_if = "Option::is_none")]
        max_total: Option<usize>,
    },

    /// Check extracted string count
    /// For detecting string concealment (very few visible strings)
    StringCount {
        /// Minimum number of strings
        #[serde(skip_serializing_if = "Option::is_none")]
        min: Option<usize>,
        /// Maximum number of strings (low count = suspicious)
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<usize>,
        /// Only count strings of this minimum length
        #[serde(skip_serializing_if = "Option::is_none")]
        min_length: Option<usize>,
    },

    /// Check computed metrics for obfuscation/anomaly detection
    /// For detecting obfuscation patterns in source code via statistical analysis
    Metrics {
        /// Metric path (e.g., "identifiers.avg_entropy", "functions.density_per_100_lines")
        field: String,
        /// Minimum value threshold
        #[serde(skip_serializing_if = "Option::is_none")]
        min: Option<f64>,
        /// Maximum value threshold
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<f64>,
    },

    /// Match hex byte patterns in binary data
    /// Supports wildcards (??) and variable-length gaps ([N] or [N-M])
    /// Example: { type: hex, pattern: "7F 45 4C 46" }  # ELF magic
    /// Example: { type: hex, pattern: "31 ?? 48 83" }  # With wildcards
    /// Example: { type: hex, pattern: "00 03 [4] 00 04" }  # With 4-byte gap
    Hex {
        /// Hex pattern with optional wildcards (??) and gaps ([N] or [N-M])
        /// Format: space-separated hex bytes, ?? for any byte, [N] for N-byte gap
        pattern: String,
        /// Only check at specific offset (e.g., 0 for file header)
        #[serde(skip_serializing_if = "Option::is_none")]
        offset: Option<usize>,
        /// Only check within offset range [start, end)
        #[serde(skip_serializing_if = "Option::is_none")]
        offset_range: Option<(usize, usize)>,
        /// Minimum number of matches required (default: 1)
        #[serde(default = "default_min_count")]
        min_count: usize,
    },
}

fn default_compare_to() -> String {
    "total".to_string()
}

pub fn default_min_count() -> usize {
    1
}

impl Condition {
    /// Returns true if this condition is a trait reference
    pub fn is_trait_reference(&self) -> bool {
        matches!(self, Condition::Trait { .. })
    }

    /// Returns a description of the condition type for error messages
    pub fn type_name(&self) -> &'static str {
        match self {
            Condition::Symbol { .. } => "symbol",
            Condition::String { .. } => "string",
            Condition::YaraMatch { .. } => "yara_match",
            Condition::Structure { .. } => "structure",
            Condition::SymbolOrString { .. } => "symbol_or_string",
            Condition::ImportsCount { .. } => "imports_count",
            Condition::ExportsCount { .. } => "exports_count",
            Condition::Trait { .. } => "trait",
            Condition::AstPattern { .. } => "ast_pattern",
            Condition::AstQuery { .. } => "ast_query",
            Condition::Yara { .. } => "yara",
            Condition::Syscall { .. } => "syscall",
            Condition::SectionRatio { .. } => "section_ratio",
            Condition::SectionEntropy { .. } => "section_entropy",
            Condition::ImportCombination { .. } => "import_combination",
            Condition::StringCount { .. } => "string_count",
            Condition::Metrics { .. } => "metrics",
            Condition::Hex { .. } => "hex",
        }
    }

    /// Validate that condition can be compiled (for YARA/AST rules)
    /// Call this at load time to catch syntax errors early
    pub fn validate(&self) -> Result<()> {
        match self {
            Condition::Yara { source, .. } => {
                // Only validate syntax - add_source catches parse errors
                // Don't call build() here as it triggers expensive JIT compilation
                let mut compiler = yara_x::Compiler::new();
                compiler
                    .add_source(source.as_bytes())
                    .map_err(|e| anyhow::anyhow!("invalid YARA rule: {}", e))?;
                Ok(())
            }
            Condition::AstQuery { query, language } => {
                // Validate tree-sitter query syntax against the specified language
                // If no language specified, skip validation (will be validated at runtime)
                let lang: tree_sitter::Language = match language.as_deref() {
                    Some("c") => tree_sitter_c::LANGUAGE.into(),
                    Some("python") => tree_sitter_python::LANGUAGE.into(),
                    Some("javascript") | Some("js") => tree_sitter_javascript::LANGUAGE.into(),
                    Some("typescript") | Some("ts") => {
                        tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
                    }
                    Some("rust") => tree_sitter_rust::LANGUAGE.into(),
                    Some("go") => tree_sitter_go::LANGUAGE.into(),
                    Some("java") => tree_sitter_java::LANGUAGE.into(),
                    Some("ruby") => tree_sitter_ruby::LANGUAGE.into(),
                    Some("shell") | Some("bash") => tree_sitter_bash::LANGUAGE.into(),
                    Some("php") => tree_sitter_php::LANGUAGE_PHP.into(),
                    Some("csharp") | Some("c#") => tree_sitter_c_sharp::LANGUAGE.into(),
                    Some("lua") => tree_sitter_lua::LANGUAGE.into(),
                    Some("perl") => tree_sitter_perl::LANGUAGE.into(),
                    Some("powershell") | Some("ps1") => tree_sitter_powershell::LANGUAGE.into(),
                    Some("swift") => tree_sitter_swift::LANGUAGE.into(),
                    Some("objc") | Some("objective-c") => tree_sitter_objc::LANGUAGE.into(),
                    Some("groovy") => tree_sitter_groovy::LANGUAGE.into(),
                    Some("scala") => tree_sitter_scala::LANGUAGE.into(),
                    Some("zig") => tree_sitter_zig::LANGUAGE.into(),
                    Some("elixir") => tree_sitter_elixir::LANGUAGE.into(),
                    Some(other) => {
                        return Err(anyhow::anyhow!(
                            "unsupported language for ast_query: {}",
                            other
                        ))
                    }
                    None => {
                        // No language specified - skip validation, will validate at runtime
                        return Ok(());
                    }
                };
                tree_sitter::Query::new(&lang, query)
                    .map_err(|e| anyhow::anyhow!("invalid tree-sitter query: {}", e))?;
                Ok(())
            }
            // Other conditions don't need compilation validation
            _ => Ok(()),
        }
    }

    /// Pre-compile YARA rules for faster evaluation
    /// Call this after loading traits to avoid repeated compilation during scanning
    pub fn compile_yara(&mut self) {
        if let Condition::Yara { source, compiled } = self {
            if compiled.is_none() {
                let mut compiler = yara_x::Compiler::new();
                compiler.new_namespace("inline");
                if compiler.add_source(source.as_bytes()).is_ok() {
                    *compiled = Some(Arc::new(compiler.build()));
                }
            }
        }
    }
}
