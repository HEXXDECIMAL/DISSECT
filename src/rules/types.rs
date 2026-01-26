//! Type definitions for rule evaluation
//!
//! Contains enums and structs used across the rules module.

use crate::types::{Criticality, Evidence};
use anyhow::Result;
use serde::Deserialize;

/// Platform specifier for trait targeting
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    All,
    Linux,
    MacOS,
    Windows,
    Unix,
    Android,
    Ios,
}

/// File type specifier for rule targeting
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FileType {
    All,
    // Binary formats
    Elf,
    Macho,
    Pe,
    Dylib,
    So,
    Dll,
    Class, // Java bytecode
    // Source code formats
    Shell,
    Batch,
    Python,
    JavaScript,
    TypeScript,
    Rust,
    Java,
    Ruby,
    C,
    Go,
    Php,
    CSharp,
    Lua,
    Perl,
    PowerShell,
    Swift,
    ObjectiveC,
    Groovy,
    Scala,
    Zig,
    Elixir,
    AppleScript,
    // Manifest/config formats
    PackageJson,
}

impl FileType {
    /// Returns true if this file type is source code (not a compiled binary)
    /// Symbol matching for source files should fall back to string matching
    pub fn is_source_code(&self) -> bool {
        matches!(
            self,
            FileType::Shell
                | FileType::Batch
                | FileType::Python
                | FileType::JavaScript
                | FileType::TypeScript
                | FileType::Rust
                | FileType::Java
                | FileType::Ruby
                | FileType::C
                | FileType::Go
                | FileType::CSharp
                | FileType::Php
                | FileType::Lua
                | FileType::Perl
                | FileType::PowerShell
                | FileType::Swift
                | FileType::ObjectiveC
                | FileType::Groovy
                | FileType::Scala
                | FileType::Zig
                | FileType::Elixir
                | FileType::AppleScript
        )
    }
}

/// Scope level for proximity constraints
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScopeLevel {
    /// No scope constraint (default)
    #[default]
    None,
    /// All traits must be in the same method/function
    Method,
    /// All traits must be in the same class
    Class,
    /// All traits must be in the same block (e.g., if/for/while body)
    Block,
}

/// Numeric range for threshold-based conditions (min/max checks)
#[derive(Debug, Clone, Deserialize)]
pub struct NumericRange {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<u32>,
}

impl NumericRange {
    /// Check if a value is within this range
    pub fn matches(&self, value: u32) -> bool {
        if let Some(min) = self.min {
            if value < min {
                return false;
            }
        }
        if let Some(max) = self.max {
            if value > max {
                return false;
            }
        }
        true
    }
}

/// Float range for threshold-based conditions (entropy, density)
#[derive(Debug, Clone, Deserialize)]
pub struct FloatRange {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
}

impl FloatRange {
    /// Check if a value is within this range
    pub fn matches(&self, value: f64) -> bool {
        if let Some(min) = self.min {
            if value < min {
                return false;
            }
        }
        if let Some(max) = self.max {
            if value > max {
                return false;
            }
        }
        true
    }
}

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
    AstQuery {
        /// Tree-sitter query pattern (S-expression syntax)
        query: String,
    },

    /// Inline YARA rule for pattern matching
    Yara {
        /// YARA rule source code
        source: String,
    },

    /// Match functions based on complexity and structure metrics (radare2)
    FunctionMetrics {
        #[serde(skip_serializing_if = "Option::is_none")]
        cyclomatic_complexity: Option<NumericRange>,
        #[serde(skip_serializing_if = "Option::is_none")]
        basic_blocks: Option<NumericRange>,
        #[serde(skip_serializing_if = "Option::is_none")]
        loops: Option<NumericRange>,
        #[serde(skip_serializing_if = "Option::is_none")]
        instructions: Option<NumericRange>,
        #[serde(skip_serializing_if = "Option::is_none")]
        stack_frame: Option<NumericRange>,
        #[serde(skip_serializing_if = "Option::is_none")]
        is_recursive: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        is_leaf: Option<bool>,
    },

    /// Match sections by entropy (randomness)
    Entropy {
        #[serde(skip_serializing_if = "Option::is_none")]
        section: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        min: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<f64>,
    },

    /// Match binary header properties (goblin)
    /// For ELF/PE/Mach-O structural analysis
    #[serde(rename = "binary")]
    Binary {
        /// Number of sections (e_shnum for ELF)
        #[serde(skip_serializing_if = "Option::is_none")]
        section_count: Option<NumericRange>,
        /// Number of program headers/segments
        #[serde(skip_serializing_if = "Option::is_none")]
        segment_count: Option<NumericRange>,
        /// Minimum file size in bytes
        #[serde(skip_serializing_if = "Option::is_none")]
        pub min_size: Option<u64>,
        /// Maximum file size in bytes
        #[serde(skip_serializing_if = "Option::is_none")]
        pub max_size: Option<u64>,
        /// Whole-file entropy (0.0-8.0)
        #[serde(skip_serializing_if = "Option::is_none")]
        file_entropy: Option<FloatRange>,
        /// Overlay/appended data size (bytes after last segment)
        #[serde(skip_serializing_if = "Option::is_none")]
        overlay_size: Option<NumericRange>,
        /// Machine type (e.g., 3=i386, 62=x86_64, 20=ppc, 8=mips)
        #[serde(skip_serializing_if = "Option::is_none")]
        machine_type: Option<Vec<u16>>,
        /// Big-endian byte order
        #[serde(skip_serializing_if = "Option::is_none")]
        is_big_endian: Option<bool>,
        /// Has writable+executable segments (W^X violation)
        #[serde(skip_serializing_if = "Option::is_none")]
        has_rwx_segments: Option<bool>,
        /// 64-bit binary
        #[serde(skip_serializing_if = "Option::is_none")]
        is_64bit: Option<bool>,
        /// Has interpreter/dynamic linker
        #[serde(skip_serializing_if = "Option::is_none")]
        has_interpreter: Option<bool>,
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

    /// Match against computed source code metrics
    /// Supports fields like: go_metrics.unsafe_usage, python.eval_count, etc.
    Metrics {
        /// Dot-separated path to metric field (e.g., "go_metrics.unsafe_usage")
        field: String,
        /// Minimum value (inclusive)
        #[serde(skip_serializing_if = "Option::is_none")]
        min: Option<f64>,
        /// Maximum value (inclusive)
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<f64>,
        /// Minimum file size in bytes (only apply this rule to files >= this size)
        #[serde(skip_serializing_if = "Option::is_none")]
        min_size: Option<u64>,
        /// Maximum file size in bytes (only apply this rule to files <= this size)
        #[serde(skip_serializing_if = "Option::is_none")]
        max_size: Option<u64>,
    },
}

impl Condition {
    /// Validate that condition can be compiled (for YARA/AST rules)
    pub fn validate(&self) -> Result<()> {
        match self {
            Condition::Yara { source } => {
                let mut compiler = yara_x::Compiler::new();
                compiler
                    .add_source(source.as_bytes())
                    .map_err(|e| anyhow::anyhow!("invalid YARA rule: {}", e))?;
                let _ = compiler.build();
                Ok(())
            }
            Condition::AstQuery { query } => {
                let language = tree_sitter_c::LANGUAGE;
                tree_sitter::Query::new(&language.into(), query)
                    .map_err(|e| anyhow::anyhow!("invalid tree-sitter query: {}", e))?;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

fn default_min_count() -> usize {
    1
}

/// Definition of an atomic observable trait
#[derive(Debug, Clone, Deserialize)]
pub struct TraitDefinition {
    pub id: String,
    pub desc: String,
    #[serde(default = "default_confidence")]
    pub conf: f32,
    #[serde(default)]
    pub crit: Criticality,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mbc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attack: Option<String>,
    #[serde(default = "default_platforms")]
    pub platforms: Vec<Platform>,
    #[serde(default = "default_file_types")]
    pub for: Vec<FileType>,
    pub if: Condition,
}

fn default_confidence() -> f32 {
    1.0
}

/// Boolean logic for combining conditions/traits
#[derive(Debug, Clone, Deserialize)]
pub struct CompositeTrait {
    #[serde(alias = "capability")]
    pub id: String,
    pub desc: String,
    pub conf: f32,
    #[serde(default)]
    pub crit: Criticality,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mbc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attack: Option<String>,
    #[serde(default = "default_platforms")]
    pub platforms: Vec<Platform>,
    #[serde(default = "default_file_types")]
    pub for: Vec<FileType>,

    // File size constraints
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub min_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_size: Option<u64>,

    // Proximity constraints
    #[serde(default)]
    pub scope: ScopeLevel,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub near: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub near_lines: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub within: Option<String>,

    // Boolean operators (only one should be set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all: Option<Vec<Condition>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub any: Option<Vec<Condition>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub any: Option<Vec<Condition>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub none: Option<Vec<Condition>>,
}

pub fn default_platforms() -> Vec<Platform> {
    vec![Platform::All]
}

pub fn default_file_types() -> Vec<FileType> {
    vec![FileType::All]
}

/// Context for evaluating composite rules
pub struct EvaluationContext<'a> {
    pub report: &'a crate::types::AnalysisReport,
    pub binary_data: &'a [u8],
    pub file_type: FileType,
    pub platform: Platform,
}

/// Result of evaluating a condition
#[derive(Debug)]
pub struct ConditionResult {
    pub matched: bool,
    pub evidence: Vec<Evidence>,
    pub traits: Vec<String>,
}

impl ConditionResult {
    pub fn no_match() -> Self {
        Self {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
        }
    }

    pub fn matched_with(evidence: Vec<Evidence>) -> Self {
        Self {
            matched: true,
            evidence,
            traits: Vec::new(),
        }
    }

    pub fn matched_with_traits(evidence: Vec<Evidence>, traits: Vec<String>) -> Self {
        Self {
            matched: true,
            evidence,
            traits,
        }
    }
}

/// Parameters for string condition evaluation
pub struct StringParams<'a> {
    pub exact: Option<&'a String>,
    pub regex: Option<&'a String>,
    pub case_insensitive: bool,
    pub exclude_patterns: Option<&'a Vec<String>>,
    pub min_count: usize,
    pub search_raw: bool,
}
