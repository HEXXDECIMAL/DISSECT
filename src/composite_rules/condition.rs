//! Condition types for composite rules.

use super::types::Platform;
use anyhow::Result;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum AnyMatcher {
    Shorthand(String),
    Structured {
        #[serde(default)]
        exact: Option<String>,
        #[serde(default)]
        substr: Option<String>,
        #[serde(default)]
        regex: Option<String>,
        #[serde(default)]
        word: Option<String>,
    },
}

fn matcher_to_regex_fragment(
    exact: Option<String>,
    substr: Option<String>,
    regex: Option<String>,
    word: Option<String>,
) -> Vec<String> {
    let mut fragments = Vec::new();
    if let Some(v) = exact {
        fragments.push(format!("^(?:{})$", regex::escape(&v)));
    }
    if let Some(v) = substr {
        fragments.push(regex::escape(&v));
    }
    if let Some(v) = regex {
        fragments.push(format!("(?:{})", v));
    }
    if let Some(v) = word {
        fragments.push(format!("\\b{}\\b", regex::escape(&v)));
    }
    fragments
}

fn normalize_any_matchers(
    exact: Option<String>,
    substr: Option<String>,
    regex: Option<String>,
    word: Option<String>,
    any: Option<Vec<AnyMatcher>>,
    allow_word: bool,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let mut fragments = matcher_to_regex_fragment(exact, substr, regex, word);

    if let Some(items) = any {
        for item in items {
            match item {
                AnyMatcher::Shorthand(v) => fragments.push(regex::escape(&v)),
                AnyMatcher::Structured {
                    exact,
                    substr,
                    regex,
                    word,
                } => {
                    let normalized_word = if allow_word { word } else { None };
                    fragments.extend(matcher_to_regex_fragment(
                        exact,
                        substr,
                        regex,
                        normalized_word,
                    ));
                }
            }
        }
    }

    if fragments.is_empty() {
        (None, None, None, None)
    } else {
        (
            None,
            None,
            Some(format!("(?:{})", fragments.join("|"))),
            None,
        )
    }
}

/// String exception specification for `not:` directive
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum NotException {
    /// Shorthand: bare string defaults to substr match
    Shorthand(String),

    /// Structured exception with explicit match type
    Structured {
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
    },
}

impl NotException {
    /// Check if a string matches this exception
    pub fn matches(&self, value: &str) -> bool {
        match self {
            NotException::Shorthand(pattern) => {
                value.to_lowercase().contains(&pattern.to_lowercase())
            }
            NotException::Structured {
                exact,
                substr,
                regex,
            } => {
                if let Some(exact_str) = exact {
                    value.eq_ignore_ascii_case(exact_str)
                } else if let Some(substr_str) = substr {
                    value.to_lowercase().contains(&substr_str.to_lowercase())
                } else if let Some(regex_str) = regex {
                    regex::Regex::new(regex_str)
                        .map(|re| re.is_match(value))
                        .unwrap_or(false)
                } else {
                    false
                }
            }
        }
    }
}

/// Intermediate type for deserializing conditions with shorthand support.
/// Converts `{ id: my-trait }` to `Condition::Trait { id: "my-trait" }`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ConditionDeser {
    /// Shorthand for trait reference - just `id` field, no `type` needed
    /// Must be listed first so serde tries it before the tagged variants
    TraitShorthand { id: String },

    /// All other condition types require explicit `type` field
    Tagged(Box<ConditionTagged>),
}

/// Internal tagged enum for deserializing conditions with explicit `type` field
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ConditionTagged {
    Symbol {
        /// Full symbol name match (entire symbol must equal this)
        #[serde(default)]
        exact: Option<String>,
        /// Substring match (appears anywhere in symbol name)
        #[serde(default)]
        substr: Option<String>,
        /// Regex pattern to match symbol names
        #[serde(default)]
        regex: Option<String>,
        #[serde(default)]
        any: Option<Vec<AnyMatcher>>,
        platforms: Option<Vec<Platform>>,
    },
    String {
        /// Full string match (entire string must equal this)
        #[serde(default)]
        exact: Option<String>,
        /// Substring match (appears anywhere in string)
        #[serde(default)]
        substr: Option<String>,
        /// Regex pattern match
        #[serde(default)]
        regex: Option<String>,
        /// Word boundary match (equivalent to regex "\bword\b")
        #[serde(default)]
        word: Option<String>,
        #[serde(default)]
        any: Option<Vec<AnyMatcher>>,
        #[serde(default)]
        case_insensitive: bool,
        #[serde(default)]
        exclude_patterns: Option<Vec<String>>,
        /// Minimum match count (preferred over deprecated min_count)
        #[serde(default = "default_count_min", alias = "min_count")]
        count_min: usize,
        /// Maximum match count - matches fail if exceeded
        #[serde(default)]
        count_max: Option<usize>,
        /// Minimum matches per kilobyte of file size (density threshold)
        #[serde(default)]
        per_kb_min: Option<f64>,
        /// Maximum matches per kilobyte of file size (density ceiling)
        #[serde(default)]
        per_kb_max: Option<f64>,
        /// Require match to contain a valid external IP address (not private/loopback/reserved)
        #[serde(default)]
        external_ip: bool,
        /// Section constraint: only match strings in this section (supports fuzzy names like "text")
        #[serde(default)]
        section: Option<String>,
        /// Absolute file offset: only match at this exact byte position (negative = from end)
        #[serde(default)]
        offset: Option<i64>,
        /// Absolute offset range: [start, end) (negative values resolved from file end)
        #[serde(default)]
        offset_range: Option<(i64, Option<i64>)>,
        /// Section-relative offset: only match at this offset within the section
        #[serde(default)]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end) within section bounds
        #[serde(default)]
        section_offset_range: Option<(i64, Option<i64>)>,
    },
    YaraMatch {
        namespace: String,
        rule: Option<String>,
    },
    Structure {
        feature: String,
        min_sections: Option<usize>,
    },
    ImportsCount {
        min: Option<usize>,
        max: Option<usize>,
        filter: Option<String>,
    },
    ExportsCount {
        min: Option<usize>,
        max: Option<usize>,
    },
    Trait {
        id: String,
    },
    /// Unified AST condition type - replaces ast_pattern and ast_query
    /// Simple mode: kind + exact/substr/regex (or node + exact/substr/regex for raw node types)
    /// Advanced mode: query (tree-sitter S-expression)
    Ast {
        /// Abstract node category (e.g., "call", "function", "class")
        /// Maps to language-specific tree-sitter node types automatically
        #[serde(skip_serializing_if = "Option::is_none")]
        kind: Option<String>,
        /// Raw tree-sitter node type (escape hatch, bypasses kind mapping)
        #[serde(skip_serializing_if = "Option::is_none")]
        node: Option<String>,
        /// Full match (entire node text must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in node text)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex match in node text
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Tree-sitter S-expression query (advanced mode)
        #[serde(skip_serializing_if = "Option::is_none")]
        query: Option<String>,
        /// Language hint for query validation
        #[serde(skip_serializing_if = "Option::is_none")]
        language: Option<String>,
        /// Case-insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
    },
    Yara {
        source: String,
    },
    Syscall {
        name: Option<Vec<String>>,
        number: Option<Vec<u32>>,
        arch: Option<Vec<String>>,
        min_count: Option<usize>,
    },
    SectionRatio {
        section: String,
        #[serde(default = "default_compare_to")]
        compare_to: String,
        min_ratio: Option<f64>,
        max_ratio: Option<f64>,
    },
    SectionEntropy {
        section: String,
        min_entropy: Option<f64>,
        max_entropy: Option<f64>,
    },
    ImportCombination {
        required: Option<Vec<String>>,
        suspicious: Option<Vec<String>>,
        min_suspicious: Option<usize>,
        max_total: Option<usize>,
    },
    StringCount {
        min: Option<usize>,
        max: Option<usize>,
        min_length: Option<usize>,
    },
    Metrics {
        field: String,
        min: Option<f64>,
        max: Option<f64>,
        min_size: Option<u64>,
        max_size: Option<u64>,
    },
    Hex {
        pattern: String,
        /// Absolute file offset (negative = from end of file)
        offset: Option<i64>,
        /// Absolute offset range: [start, end) (negative values resolved from file end, null = open-ended)
        #[serde(default)]
        offset_range: Option<(i64, Option<i64>)>,
        /// Minimum match count (preferred over deprecated min_count)
        #[serde(default = "default_count_min", alias = "min_count")]
        count_min: usize,
        /// Maximum match count - matches fail if exceeded
        #[serde(default)]
        count_max: Option<usize>,
        /// Minimum matches per kilobyte of file size (density threshold)
        #[serde(default)]
        per_kb_min: Option<f64>,
        /// Maximum matches per kilobyte of file size (density ceiling)
        #[serde(default)]
        per_kb_max: Option<f64>,
        /// If true, extracts the bytes matching '??' wildcards and includes them in evidence value
        #[serde(default)]
        extract_wildcards: bool,
        /// Section constraint: only match in this section (supports fuzzy names like "text")
        #[serde(default)]
        section: Option<String>,
        /// Section-relative offset: only match at this offset within the section
        #[serde(default)]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end) within section bounds
        #[serde(default)]
        section_offset_range: Option<(i64, Option<i64>)>,
    },

    /// Check file size constraints
    /// Example: { type: filesize, max: 10485760 }  # max 10MB
    Filesize {
        /// Minimum file size in bytes
        #[serde(skip_serializing_if = "Option::is_none")]
        min: Option<usize>,
        /// Maximum file size in bytes
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<usize>,
    },
    /// Match multiple traits by glob pattern
    /// Example: { type: trait_glob, pattern: "xdp-*", match: any }
    TraitGlob {
        /// Glob pattern to match trait IDs (e.g., "xdp-*", "socket-*")
        pattern: String,
        /// How to combine matches: "any" (default), "all", or count (e.g., "3")
        #[serde(default = "default_match_mode")]
        r#match: String,
    },

    /// Search raw file content (for source files or when you need to match
    /// across string boundaries in binaries). Unlike `type: string` which only
    /// searches properly extracted/bounded strings, this searches the raw bytes.
    #[serde(rename = "content", alias = "raw")]
    Content {
        /// Full match (entire content must equal this - rarely useful)
        exact: Option<String>,
        /// Substring match (appears anywhere in content)
        substr: Option<String>,
        regex: Option<String>,
        word: Option<String>,
        #[serde(default)]
        any: Option<Vec<AnyMatcher>>,
        #[serde(default)]
        case_insensitive: bool,
        /// Minimum match count (preferred over deprecated min_count)
        #[serde(default = "default_count_min", alias = "min_count")]
        count_min: usize,
        /// Maximum match count - matches fail if exceeded
        #[serde(default)]
        count_max: Option<usize>,
        /// Minimum matches per kilobyte of file size (density threshold)
        #[serde(default)]
        per_kb_min: Option<f64>,
        /// Maximum matches per kilobyte of file size (density ceiling)
        #[serde(default)]
        per_kb_max: Option<f64>,
        /// Require match to contain a valid external IP address (not private/loopback/reserved)
        #[serde(default)]
        external_ip: bool,
        /// Section constraint: only match in this section (supports fuzzy names like "text")
        #[serde(default)]
        section: Option<String>,
        /// Absolute file offset: only match at this exact byte position (negative = from end)
        #[serde(default)]
        offset: Option<i64>,
        /// Absolute offset range: [start, end) (negative values resolved from file end)
        #[serde(default)]
        offset_range: Option<(i64, Option<i64>)>,
        /// Section-relative offset: only match at this offset within the section
        #[serde(default)]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end) within section bounds
        #[serde(default)]
        section_offset_range: Option<(i64, Option<i64>)>,
    },

    /// Match section names in binary files (PE, ELF, Mach-O)
    /// Replaces YARA patterns like: `for any section in pe.sections : (section.name matches /^UPX/)`
    /// Example: { type: section_name, pattern: "^UPX", regex: true }
    SectionName {
        /// Pattern to match against section names
        pattern: String,
        /// Use regex matching (default: false, uses substring match)
        #[serde(default)]
        regex: bool,
    },

    /// Match patterns in base64-decoded strings
    /// Example: { type: base64, regex: "https?://" }
    /// Example: { type: base64, substr: "eval(" }
    Base64 {
        /// Full match (entire decoded string must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in decoded string)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern to match
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        #[serde(default)]
        any: Option<Vec<AnyMatcher>>,
        /// Case insensitive matching
        #[serde(default)]
        case_insensitive: bool,
        /// Minimum match count (preferred over deprecated min_count)
        #[serde(default = "default_count_min", alias = "min_count")]
        count_min: usize,
        /// Maximum match count - matches fail if exceeded
        #[serde(default)]
        count_max: Option<usize>,
        /// Minimum matches per kilobyte of file size (density threshold)
        #[serde(default)]
        per_kb_min: Option<f64>,
        /// Maximum matches per kilobyte of file size (density ceiling)
        #[serde(default)]
        per_kb_max: Option<f64>,
        /// Section constraint: only match in this section (supports fuzzy names like "text")
        #[serde(default)]
        section: Option<String>,
        /// Absolute file offset: only match at this exact byte position (negative = from end)
        #[serde(default)]
        offset: Option<i64>,
        /// Absolute offset range: [start, end) (negative values resolved from file end)
        #[serde(default)]
        offset_range: Option<(i64, Option<i64>)>,
        /// Section-relative offset: only match at this offset within the section
        #[serde(default)]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end) within section bounds
        #[serde(default)]
        section_offset_range: Option<(i64, Option<i64>)>,
    },

    /// Match patterns in XOR-decoded strings
    /// Example: { type: xor, key: 0x42, substr: "http://" }
    /// Example: { type: xor, regex: "eval\\(" } - searches all keys if key not specified
    Xor {
        /// XOR key (hex byte, e.g. "0x42"). If not specified, searches all keys 0x01-0xFF
        #[serde(skip_serializing_if = "Option::is_none")]
        key: Option<String>,
        /// Full match (entire decoded string must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in decoded string)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern to match
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        #[serde(default)]
        any: Option<Vec<AnyMatcher>>,
        /// Case insensitive matching
        #[serde(default)]
        case_insensitive: bool,
        /// Minimum match count (preferred over deprecated min_count)
        #[serde(default = "default_count_min", alias = "min_count")]
        count_min: usize,
        /// Maximum match count - matches fail if exceeded
        #[serde(default)]
        count_max: Option<usize>,
        /// Minimum matches per kilobyte of file size (density threshold)
        #[serde(default)]
        per_kb_min: Option<f64>,
        /// Maximum matches per kilobyte of file size (density ceiling)
        #[serde(default)]
        per_kb_max: Option<f64>,
        /// Section constraint: only match in this section (supports fuzzy names like "text")
        #[serde(default)]
        section: Option<String>,
        /// Absolute file offset: only match at this exact byte position (negative = from end)
        #[serde(default)]
        offset: Option<i64>,
        /// Absolute offset range: [start, end) (negative values resolved from file end)
        #[serde(default)]
        offset_range: Option<(i64, Option<i64>)>,
        /// Section-relative offset: only match at this offset within the section
        #[serde(default)]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end) within section bounds
        #[serde(default)]
        section_offset_range: Option<(i64, Option<i64>)>,
    },

    /// Match the basename (final path component, not the full path)
    /// Example: { type: basename, exact: "__init__.py" }
    /// Example: { type: basename, regex: "^setup\\." }
    Basename {
        /// Full basename match (entire basename must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in basename)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern to match
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Case insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
    },

    /// Match strings by their encoding layer path
    /// Example: { type: layer_path, value: "meta/layers/.text/stack" }
    /// Layer paths are computed as: meta/layers/{section}/{encoding_chain_joined}
    LayerPath {
        value: String,
    },

    /// Query structured data in JSON, YAML, and TOML manifests using path expressions.
    /// Supports dot notation for nested access and [*] for array iteration.
    /// Example: { type: kv, path: "permissions", exact: "debugger" }
    /// Example: { type: kv, path: "scripts.postinstall", substr: "curl" }
    /// Example: { type: kv, path: "content_scripts[*].matches", exact: "<all_urls>" }
    Kv {
        /// Path to navigate using dot notation, [n] for indices, [*] for wildcards
        path: String,
        /// Value/element equals exactly
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Value/element contains substring
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Value/element matches regex pattern
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Case insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
    },
}

fn default_match_mode() -> String {
    "any".to_string()
}

impl From<ConditionDeser> for Condition {
    fn from(deser: ConditionDeser) -> Self {
        match deser {
            ConditionDeser::TraitShorthand { id } => Condition::Trait { id },
            ConditionDeser::Tagged(tagged) => match *tagged {
                ConditionTagged::Symbol {
                    exact,
                    substr,
                    regex,
                    any,
                    platforms,
                } => {
                    let (exact, substr, regex, _) =
                        normalize_any_matchers(exact, substr, regex, None, any, false);
                    Condition::Symbol {
                        exact,
                        substr,
                        regex,
                        platforms,
                        compiled_regex: None,
                    }
                }
                ConditionTagged::String {
                    exact,
                    substr,
                    regex,
                    word,
                    any,
                    case_insensitive,
                    exclude_patterns,
                    count_min,
                    count_max,
                    per_kb_min,
                    per_kb_max,
                    external_ip,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                } => {
                    let (exact, substr, regex, word) =
                        normalize_any_matchers(exact, substr, regex, word, any, true);
                    Condition::String {
                        exact,
                        substr,
                        regex,
                        word,
                        case_insensitive,
                        exclude_patterns,
                        count_min,
                        count_max,
                        per_kb_min,
                        per_kb_max,
                        external_ip,
                        section,
                        offset,
                        offset_range,
                        section_offset,
                        section_offset_range,
                        compiled_regex: None,
                        compiled_excludes: Vec::new(),
                    }
                }
                ConditionTagged::YaraMatch { namespace, rule } => {
                    Condition::YaraMatch { namespace, rule }
                }
                ConditionTagged::Structure {
                    feature,
                    min_sections,
                } => Condition::Structure {
                    feature,
                    min_sections,
                },
                ConditionTagged::ImportsCount { min, max, filter } => {
                    Condition::ImportsCount { min, max, filter }
                }
                ConditionTagged::ExportsCount { min, max } => Condition::ExportsCount { min, max },
                ConditionTagged::Trait { id } => Condition::Trait { id },
                ConditionTagged::Ast {
                    kind,
                    node,
                    exact,
                    substr,
                    regex,
                    query,
                    language,
                    case_insensitive,
                } => Condition::Ast {
                    kind,
                    node,
                    exact,
                    substr,
                    regex,
                    query,
                    language,
                    case_insensitive,
                },
                ConditionTagged::Yara { source } => Condition::Yara {
                    source,
                    compiled: None,
                },
                ConditionTagged::Syscall {
                    name,
                    number,
                    arch,
                    min_count,
                } => Condition::Syscall {
                    name,
                    number,
                    arch,
                    min_count,
                },
                ConditionTagged::SectionRatio {
                    section,
                    compare_to,
                    min_ratio,
                    max_ratio,
                } => Condition::SectionRatio {
                    section,
                    compare_to,
                    min_ratio,
                    max_ratio,
                },
                ConditionTagged::SectionEntropy {
                    section,
                    min_entropy,
                    max_entropy,
                } => Condition::SectionEntropy {
                    section,
                    min_entropy,
                    max_entropy,
                },
                ConditionTagged::ImportCombination {
                    required,
                    suspicious,
                    min_suspicious,
                    max_total,
                } => Condition::ImportCombination {
                    required,
                    suspicious,
                    min_suspicious,
                    max_total,
                },
                ConditionTagged::StringCount {
                    min,
                    max,
                    min_length,
                } => Condition::StringCount {
                    min,
                    max,
                    min_length,
                },
                ConditionTagged::Metrics {
                    field,
                    min,
                    max,
                    min_size,
                    max_size,
                } => Condition::Metrics {
                    field,
                    min,
                    max,
                    min_size,
                    max_size,
                },
                ConditionTagged::Hex {
                    pattern,
                    offset,
                    offset_range,
                    count_min,
                    count_max,
                    per_kb_min,
                    per_kb_max,
                    extract_wildcards,
                    section,
                    section_offset,
                    section_offset_range,
                } => Condition::Hex {
                    pattern,
                    offset,
                    offset_range,
                    count_min,
                    count_max,
                    per_kb_min,
                    per_kb_max,
                    extract_wildcards,
                    section,
                    section_offset,
                    section_offset_range,
                },
                ConditionTagged::Filesize { min, max } => Condition::Filesize { min, max },
                ConditionTagged::TraitGlob { pattern, r#match } => {
                    Condition::TraitGlob { pattern, r#match }
                }
                ConditionTagged::Content {
                    exact,
                    substr,
                    regex,
                    word,
                    any,
                    case_insensitive,
                    count_min,
                    count_max,
                    per_kb_min,
                    per_kb_max,
                    external_ip,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                } => {
                    let (exact, substr, regex, word) =
                        normalize_any_matchers(exact, substr, regex, word, any, true);
                    Condition::Content {
                        exact,
                        substr,
                        regex,
                        word,
                        case_insensitive,
                        count_min,
                        count_max,
                        per_kb_min,
                        per_kb_max,
                        external_ip,
                        section,
                        offset,
                        offset_range,
                        section_offset,
                        section_offset_range,
                        compiled_regex: None,
                    }
                }
                ConditionTagged::SectionName { pattern, regex } => {
                    Condition::SectionName { pattern, regex }
                }
                ConditionTagged::Base64 {
                    exact,
                    substr,
                    regex,
                    any,
                    case_insensitive,
                    count_min,
                    count_max,
                    per_kb_min,
                    per_kb_max,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                } => {
                    let (exact, substr, regex, _) =
                        normalize_any_matchers(exact, substr, regex, None, any, false);
                    Condition::Base64 {
                        exact,
                        substr,
                        regex,
                        case_insensitive,
                        count_min,
                        count_max,
                        per_kb_min,
                        per_kb_max,
                        section,
                        offset,
                        offset_range,
                        section_offset,
                        section_offset_range,
                    }
                }
                ConditionTagged::Xor {
                    key,
                    exact,
                    substr,
                    regex,
                    any,
                    case_insensitive,
                    count_min,
                    count_max,
                    per_kb_min,
                    per_kb_max,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                } => {
                    let (exact, substr, regex, _) =
                        normalize_any_matchers(exact, substr, regex, None, any, false);
                    Condition::Xor {
                        key,
                        exact,
                        substr,
                        regex,
                        case_insensitive,
                        count_min,
                        count_max,
                        per_kb_min,
                        per_kb_max,
                        section,
                        offset,
                        offset_range,
                        section_offset,
                        section_offset_range,
                    }
                }
                ConditionTagged::Basename {
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                } => Condition::Basename {
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                },
                ConditionTagged::LayerPath { value } => Condition::LayerPath { value },
                ConditionTagged::Kv {
                    path,
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                } => Condition::Kv {
                    path,
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                    compiled_regex: None,
                },
            },
        }
    }
}

/// Condition type in composite rules.
///
/// Supports two YAML formats:
/// 1. Tagged: `{ type: string, exact: "foo" }` - explicit type field
/// 2. Shorthand: `{ id: my-trait }` - defaults to Trait when only `id` is present
#[derive(Debug, Clone, Deserialize)]
#[serde(from = "ConditionDeser")]
pub enum Condition {
    /// Match a symbol (import/export)
    Symbol {
        /// Full symbol name match (entire symbol must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in symbol name)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern to match symbol names
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        platforms: Option<Vec<Platform>>,
        /// Pre-compiled regex (populated after deserialization, not serialized)
        #[serde(skip)]
        compiled_regex: Option<regex::Regex>,
    },

    /// Match a string in the binary
    String {
        /// Full string match (entire string must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in string)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern match
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Match pattern only at word boundaries (convenience for \bpattern\b)
        #[serde(skip_serializing_if = "Option::is_none")]
        word: Option<String>,
        #[serde(default)]
        case_insensitive: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        exclude_patterns: Option<Vec<String>>,
        /// Minimum match count (use count_min in YAML, min_count is deprecated alias)
        #[serde(default = "default_count_min")]
        count_min: usize,
        /// Maximum match count - matches fail if exceeded
        #[serde(skip_serializing_if = "Option::is_none")]
        count_max: Option<usize>,
        /// Minimum matches per kilobyte of file size (density threshold)
        #[serde(skip_serializing_if = "Option::is_none")]
        per_kb_min: Option<f64>,
        /// Maximum matches per kilobyte of file size (density ceiling)
        #[serde(skip_serializing_if = "Option::is_none")]
        per_kb_max: Option<f64>,
        /// Require match to contain a valid external IP address (not private/loopback/reserved)
        #[serde(default)]
        external_ip: bool,
        /// Section constraint: only match strings in this section (supports fuzzy names like "text")
        #[serde(skip_serializing_if = "Option::is_none")]
        section: Option<String>,
        /// Absolute file offset: only match at this exact byte position (negative = from end)
        #[serde(skip_serializing_if = "Option::is_none")]
        offset: Option<i64>,
        /// Absolute offset range: [start, end) (negative values resolved from file end)
        #[serde(skip_serializing_if = "Option::is_none")]
        offset_range: Option<(i64, Option<i64>)>,
        /// Section-relative offset: only match at this offset within the section
        #[serde(skip_serializing_if = "Option::is_none")]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end) within section bounds
        #[serde(skip_serializing_if = "Option::is_none")]
        section_offset_range: Option<(i64, Option<i64>)>,
        /// Pre-compiled regex (populated after deserialization, not serialized)
        #[serde(skip)]
        compiled_regex: Option<regex::Regex>,
        /// Pre-compiled exclude regexes (populated after deserialization, not serialized)
        #[serde(skip)]
        compiled_excludes: Vec<regex::Regex>,
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

    /// Unified AST condition - search for patterns in AST nodes
    ///
    /// Simple mode (kind + exact/substr/regex):
    /// ```yaml
    /// type: ast
    /// kind: call              # abstract kind: call, function, class, import, etc.
    /// substr: "eval"          # substring match
    /// # OR
    /// exact: "eval"           # full match (entire node text must equal this)
    /// # OR
    /// regex: "eval\\("        # regex match
    /// ```
    ///
    /// Raw node type mode (node + exact/substr/regex):
    /// ```yaml
    /// type: ast
    /// node: call_expression   # raw tree-sitter node type (escape hatch)
    /// substr: "eval"
    /// ```
    ///
    /// Advanced mode (query):
    /// ```yaml
    /// type: ast
    /// query: |
    ///   (call_expression
    ///     function: (identifier) @fn
    ///     (#eq? @fn "eval"))
    /// language: javascript    # optional, for validation
    /// ```
    Ast {
        /// Abstract node category (e.g., "call", "function", "class")
        #[serde(skip_serializing_if = "Option::is_none")]
        kind: Option<String>,
        /// Raw tree-sitter node type (escape hatch, bypasses kind mapping)
        #[serde(skip_serializing_if = "Option::is_none")]
        node: Option<String>,
        /// Full match (entire node text must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in node text)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex match in node text
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Tree-sitter S-expression query (advanced mode)
        #[serde(skip_serializing_if = "Option::is_none")]
        query: Option<String>,
        /// Language hint for query validation
        #[serde(skip_serializing_if = "Option::is_none")]
        language: Option<String>,
        /// Case-insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
    },

    /// Inline YARA rule for pattern matching
    /// Example: { type: yara, source: "rule test { strings: $a = \"test\" if: $a }" }
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
        /// Minimum file size in bytes (only apply this rule to files >= this size)
        #[serde(skip_serializing_if = "Option::is_none")]
        min_size: Option<u64>,
        /// Maximum file size in bytes (only apply this rule to files <= this size)
        #[serde(skip_serializing_if = "Option::is_none")]
        max_size: Option<u64>,
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
        /// Absolute file offset (negative = from end of file)
        #[serde(skip_serializing_if = "Option::is_none")]
        offset: Option<i64>,
        /// Absolute offset range: [start, end) (negative values resolved from file end, null = open-ended)
        #[serde(skip_serializing_if = "Option::is_none")]
        offset_range: Option<(i64, Option<i64>)>,
        /// Minimum match count (use count_min in YAML, min_count is deprecated alias)
        #[serde(default = "default_count_min")]
        count_min: usize,
        /// Maximum match count - matches fail if exceeded
        #[serde(skip_serializing_if = "Option::is_none")]
        count_max: Option<usize>,
        /// Minimum matches per kilobyte of file size (density threshold)
        #[serde(skip_serializing_if = "Option::is_none")]
        per_kb_min: Option<f64>,
        /// Maximum matches per kilobyte of file size (density ceiling)
        #[serde(skip_serializing_if = "Option::is_none")]
        per_kb_max: Option<f64>,
        /// If true, extracts the bytes matching '??' wildcards and includes them in evidence value
        #[serde(default)]
        extract_wildcards: bool,
        /// Section constraint: only match in this section (supports fuzzy names like "text")
        #[serde(skip_serializing_if = "Option::is_none")]
        section: Option<String>,
        /// Section-relative offset: only match at this offset within the section
        #[serde(skip_serializing_if = "Option::is_none")]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end) within section bounds
        #[serde(skip_serializing_if = "Option::is_none")]
        section_offset_range: Option<(i64, Option<i64>)>,
    },

    /// Check file size constraints
    /// Example: { type: filesize, max: 10485760 }  # max 10MB
    Filesize {
        /// Minimum file size in bytes
        #[serde(skip_serializing_if = "Option::is_none")]
        min: Option<usize>,
        /// Maximum file size in bytes
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<usize>,
    },

    /// Match multiple traits by glob pattern
    /// Example: { type: trait_glob, pattern: "xdp-*", match: any }
    /// Example: { type: trait_glob, pattern: "socket-*", match: "3" }
    TraitGlob {
        /// Glob pattern to match trait IDs (e.g., "xdp-*", "socket-*")
        pattern: String,
        /// How to combine matches: "any" (at least 1), "all", or a number (e.g., "3")
        #[serde(default = "default_match_mode")]
        r#match: String,
    },

    /// Search raw file content directly (for source files or matching across
    /// string boundaries in binaries). Unlike `type: string` which only searches
    /// properly extracted/bounded strings, this searches the raw bytes as text.
    /// Use this when you need to match patterns in source code or when string
    /// extraction may not capture what you're looking for.
    /// Example: { type: raw, substr: "eval(" }
    /// Example: { type: raw, exact: "#!/bin/sh" }  # Entire file must equal this
    /// Example: { type: raw, regex: "\\bpassword\\s*=", case_insensitive: true }
    /// Example: { type: raw, word: "socket" }  # Match "socket" as whole word
    Content {
        /// Full file match (entire file content must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in file)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern to match
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Match pattern only at word boundaries (convenience for \bpattern\b)
        #[serde(skip_serializing_if = "Option::is_none")]
        word: Option<String>,
        /// Case insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
        /// Minimum match count (use count_min in YAML, min_count is deprecated alias)
        #[serde(default = "default_count_min")]
        count_min: usize,
        /// Maximum match count - matches fail if exceeded
        #[serde(skip_serializing_if = "Option::is_none")]
        count_max: Option<usize>,
        /// Minimum matches per kilobyte of file size (density threshold)
        #[serde(skip_serializing_if = "Option::is_none")]
        per_kb_min: Option<f64>,
        /// Maximum matches per kilobyte of file size (density ceiling)
        #[serde(skip_serializing_if = "Option::is_none")]
        per_kb_max: Option<f64>,
        /// Require match to contain a valid external IP address (not private/loopback/reserved)
        #[serde(default)]
        external_ip: bool,
        /// Section constraint: only match in this section (supports fuzzy names like "text")
        #[serde(skip_serializing_if = "Option::is_none")]
        section: Option<String>,
        /// Absolute file offset: only match at this exact byte position (negative = from end)
        #[serde(skip_serializing_if = "Option::is_none")]
        offset: Option<i64>,
        /// Absolute offset range: [start, end) (negative values resolved from file end)
        #[serde(skip_serializing_if = "Option::is_none")]
        offset_range: Option<(i64, Option<i64>)>,
        /// Section-relative offset: only match at this offset within the section
        #[serde(skip_serializing_if = "Option::is_none")]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end) within section bounds
        #[serde(skip_serializing_if = "Option::is_none")]
        section_offset_range: Option<(i64, Option<i64>)>,
        /// Pre-compiled regex (populated after deserialization, not serialized)
        #[serde(skip)]
        compiled_regex: Option<regex::Regex>,
    },

    /// Match section names in binary files (PE, ELF, Mach-O)
    /// Replaces YARA patterns like: `for any section in pe.sections : (section.name matches /^UPX/)`
    /// Example: { type: section_name, pattern: "^UPX", regex: true }
    SectionName {
        /// Pattern to match against section names
        pattern: String,
        /// Use regex matching (default: false, uses substring match)
        #[serde(default)]
        regex: bool,
    },

    /// Match patterns in base64-decoded strings
    /// Example: { type: base64, regex: "https?://" }
    /// Example: { type: base64, substr: "eval(" }
    Base64 {
        /// Full match (entire decoded string must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in decoded string)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern to match
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Case insensitive matching
        #[serde(default)]
        case_insensitive: bool,
        /// Minimum match count (use count_min in YAML, min_count is deprecated alias)
        #[serde(default = "default_count_min")]
        count_min: usize,
        /// Maximum match count - matches fail if exceeded
        #[serde(skip_serializing_if = "Option::is_none")]
        count_max: Option<usize>,
        /// Minimum matches per kilobyte of file size (density threshold)
        #[serde(skip_serializing_if = "Option::is_none")]
        per_kb_min: Option<f64>,
        /// Maximum matches per kilobyte of file size (density ceiling)
        #[serde(skip_serializing_if = "Option::is_none")]
        per_kb_max: Option<f64>,
        /// Section constraint: only match in this section (supports fuzzy names like "text")
        #[serde(skip_serializing_if = "Option::is_none")]
        section: Option<String>,
        /// Absolute file offset: only match at this exact byte position (negative = from end)
        #[serde(skip_serializing_if = "Option::is_none")]
        offset: Option<i64>,
        /// Absolute offset range: [start, end) (negative values resolved from file end)
        #[serde(skip_serializing_if = "Option::is_none")]
        offset_range: Option<(i64, Option<i64>)>,
        /// Section-relative offset: only match at this offset within the section
        #[serde(skip_serializing_if = "Option::is_none")]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end) within section bounds
        #[serde(skip_serializing_if = "Option::is_none")]
        section_offset_range: Option<(i64, Option<i64>)>,
    },

    /// Match patterns in XOR-decoded strings
    /// Example: { type: xor, key: "0x42", substr: "http://" }
    Xor {
        /// XOR key (hex byte, e.g. "0x42"). If not specified, searches all keys 0x01-0xFF
        #[serde(skip_serializing_if = "Option::is_none")]
        key: Option<String>,
        /// Full match (entire decoded string must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in decoded string)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern to match
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Case insensitive matching
        #[serde(default)]
        case_insensitive: bool,
        /// Minimum match count (use count_min in YAML, min_count is deprecated alias)
        #[serde(default = "default_count_min")]
        count_min: usize,
        /// Maximum match count - matches fail if exceeded
        #[serde(skip_serializing_if = "Option::is_none")]
        count_max: Option<usize>,
        /// Minimum matches per kilobyte of file size (density threshold)
        #[serde(skip_serializing_if = "Option::is_none")]
        per_kb_min: Option<f64>,
        /// Maximum matches per kilobyte of file size (density ceiling)
        #[serde(skip_serializing_if = "Option::is_none")]
        per_kb_max: Option<f64>,
        /// Section constraint: only match in this section (supports fuzzy names like "text")
        #[serde(skip_serializing_if = "Option::is_none")]
        section: Option<String>,
        /// Absolute file offset: only match at this exact byte position (negative = from end)
        #[serde(skip_serializing_if = "Option::is_none")]
        offset: Option<i64>,
        /// Absolute offset range: [start, end) (negative values resolved from file end)
        #[serde(skip_serializing_if = "Option::is_none")]
        offset_range: Option<(i64, Option<i64>)>,
        /// Section-relative offset: only match at this offset within the section
        #[serde(skip_serializing_if = "Option::is_none")]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end) within section bounds
        #[serde(skip_serializing_if = "Option::is_none")]
        section_offset_range: Option<(i64, Option<i64>)>,
    },

    /// Match the basename (final path component, not the full path)
    /// Useful for special files like __init__.py, setup.py, etc.
    /// Example: { type: basename, exact: "__init__.py" }
    /// Example: { type: basename, regex: "^setup\\." }
    Basename {
        /// Full basename match (entire basename must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in basename)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern to match
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Case insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
    },

    /// Match strings by their encoding layer path
    /// Layer paths are computed as: meta/layers/{section}/{encoding_chain_joined}
    LayerPath { value: String },

    /// Query structured data in JSON, YAML, and TOML manifests using path expressions.
    /// Supports dot notation for nested access and [*] for array iteration.
    /// Example: { type: kv, path: "permissions", exact: "debugger" }
    /// Example: { type: kv, path: "scripts.postinstall", substr: "curl" }
    /// Example: { type: kv, path: "content_scripts[*].matches", exact: "<all_urls>" }
    Kv {
        /// Path to navigate using dot notation, [n] for indices, [*] for wildcards
        path: String,
        /// Value/element equals exactly
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Value/element contains substring
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Value/element matches regex pattern
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Case insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
        /// Pre-compiled regex (populated after deserialization)
        #[serde(skip)]
        compiled_regex: Option<regex::Regex>,
    },
}

fn default_compare_to() -> String {
    "total".to_string()
}

/// Default for count_min - at least 1 match required
pub fn default_count_min() -> usize {
    1
}

/// Deprecated: use default_count_min instead
pub fn default_min_count() -> usize {
    1
}

impl Condition {
    /// Returns true if this condition is a trait reference
    pub fn is_trait_reference(&self) -> bool {
        matches!(self, Condition::Trait { .. })
    }

    /// Check if this condition can possibly match for a given file type.
    /// Returns false for conditions that require binary section analysis
    /// when evaluating source/text files.
    pub fn can_match_file_type(&self, file_type: &super::FileType) -> bool {
        use super::FileType;

        // Binary section analysis requires PE/ELF/Mach-O format
        let is_binary = matches!(
            file_type,
            FileType::Elf
                | FileType::Macho
                | FileType::Pe
                | FileType::Dll
                | FileType::So
                | FileType::Dylib
        );

        match self {
            // Section analysis is binary-only
            Condition::SectionRatio { .. }
            | Condition::SectionEntropy { .. }
            | Condition::SectionName { .. }
            | Condition::Structure { .. }
            | Condition::LayerPath { .. } => is_binary,

            // AST requires source code
            Condition::Ast { .. } => file_type.is_source_code(),

            // All other conditions can potentially match any file type
            _ => true,
        }
    }

    /// Returns a description of the condition type for error messages
    pub fn type_name(&self) -> &'static str {
        match self {
            Condition::Symbol { .. } => "symbol",
            Condition::String { .. } => "string",
            Condition::YaraMatch { .. } => "yara_match",
            Condition::Structure { .. } => "structure",
            Condition::ImportsCount { .. } => "imports_count",
            Condition::ExportsCount { .. } => "exports_count",
            Condition::Trait { .. } => "trait",
            Condition::Ast { .. } => "ast",
            Condition::Yara { .. } => "yara",
            Condition::Syscall { .. } => "syscall",
            Condition::SectionRatio { .. } => "section_ratio",
            Condition::SectionEntropy { .. } => "section_entropy",
            Condition::ImportCombination { .. } => "import_combination",
            Condition::StringCount { .. } => "string_count",
            Condition::Metrics { .. } => "metrics",
            Condition::Hex { .. } => "hex",
            Condition::Filesize { .. } => "filesize",
            Condition::TraitGlob { .. } => "trait_glob",
            Condition::Content { .. } => "content",
            Condition::SectionName { .. } => "section_name",
            Condition::Base64 { .. } => "base64",
            Condition::Xor { .. } => "xor",
            Condition::Basename { .. } => "basename",
            Condition::LayerPath { .. } => "layer_path",
            Condition::Kv { .. } => "kv",
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
            Condition::Ast {
                kind,
                node,
                exact,
                regex,
                query,
                language,
                ..
            } => {
                // Validate mode: either (kind/node + exact/regex) or query, not both
                let has_simple_mode = kind.is_some() || node.is_some();
                let has_pattern = exact.is_some() || regex.is_some();
                let has_query = query.is_some();

                if has_query && has_simple_mode {
                    return Err(anyhow::anyhow!(
                        "ast condition cannot have both 'query' and 'kind'/'node'"
                    ));
                }

                if !has_query && !has_simple_mode {
                    return Err(anyhow::anyhow!(
                        "ast condition must have either 'kind'/'node' or 'query'"
                    ));
                }

                if has_simple_mode && !has_pattern {
                    return Err(anyhow::anyhow!(
                        "ast condition with 'kind'/'node' must have 'exact' or 'regex'"
                    ));
                }

                if kind.is_some() && node.is_some() {
                    return Err(anyhow::anyhow!(
                        "ast condition cannot have both 'kind' and 'node'"
                    ));
                }

                if exact.is_some() && regex.is_some() {
                    return Err(anyhow::anyhow!(
                        "ast condition cannot have both 'exact' and 'regex'"
                    ));
                }

                // Validate query if present
                if let Some(q) = query {
                    validate_ast_query(q, language.as_deref())?;
                }

                Ok(())
            }
            Condition::Kv {
                path,
                exact,
                substr,
                regex,
                ..
            } => {
                // Path must not be empty
                if path.is_empty() {
                    return Err(anyhow::anyhow!("kv condition requires non-empty path"));
                }

                // At most one matcher
                let matchers = [exact.is_some(), substr.is_some(), regex.is_some()];
                if matchers.iter().filter(|&&b| b).count() > 1 {
                    return Err(anyhow::anyhow!(
                        "kv condition can only have one of: exact, substr, regex"
                    ));
                }

                // Validate regex compiles
                if let Some(re) = regex {
                    regex::Regex::new(re)
                        .map_err(|e| anyhow::anyhow!("invalid regex in kv condition: {}", e))?;
                }

                Ok(())
            }
            // Validate location constraints for string/content conditions
            Condition::String {
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            } => validate_location_constraints(
                section,
                *offset,
                *offset_range,
                *section_offset,
                *section_offset_range,
                "string",
            ),
            Condition::Content {
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            } => validate_location_constraints(
                section,
                *offset,
                *offset_range,
                *section_offset,
                *section_offset_range,
                "content",
            ),
            Condition::Base64 {
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            } => validate_location_constraints(
                section,
                *offset,
                *offset_range,
                *section_offset,
                *section_offset_range,
                "base64",
            ),
            Condition::Xor {
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            } => validate_location_constraints(
                section,
                *offset,
                *offset_range,
                *section_offset,
                *section_offset_range,
                "xor",
            ),
            Condition::Hex {
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            } => {
                // Validate location constraints
                validate_location_constraints(
                    section,
                    *offset,
                    *offset_range,
                    *section_offset,
                    *section_offset_range,
                    "hex",
                )
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

    /// Check for unbounded greedy regex patterns (.*) that can cause performance issues.
    /// Returns a warning message if found, None otherwise.
    pub fn check_greedy_patterns(&self) -> Option<String> {
        let regex_to_check = match self {
            Condition::String { regex: Some(r), .. } => Some(r.as_str()),
            Condition::Content { regex: Some(r), .. } => Some(r.as_str()),
            _ => None,
        };

        if let Some(regex) = regex_to_check {
            if has_unbounded_greedy(regex) {
                return Some(format!(
                    "unbounded greedy pattern (.*) found - use bounded pattern like .{{0,50}} instead: {}",
                    regex
                ));
            }
        }
        None
    }

    /// Pre-compile regexes in this condition for performance.
    /// Should be called once after deserialization.
    pub fn precompile_regexes(&mut self) {
        match self {
            Condition::Symbol {
                regex: Some(regex_pattern),
                compiled_regex,
                ..
            } => {
                // Compile symbol regex if present
                *compiled_regex = regex::Regex::new(regex_pattern).ok();
            }
            Condition::Symbol { regex: None, .. } => {
                // No regex to compile
            }
            Condition::String {
                regex,
                word,
                case_insensitive,
                exclude_patterns,
                compiled_regex,
                compiled_excludes,
                ..
            } => {
                // Compile main regex or word pattern
                if let Some(word_pattern) = word {
                    let regex_pattern = format!(r"\b{}\b", regex::escape(word_pattern));
                    *compiled_regex = if *case_insensitive {
                        regex::Regex::new(&format!("(?i){}", regex_pattern)).ok()
                    } else {
                        regex::Regex::new(&regex_pattern).ok()
                    };
                } else if let Some(regex_pattern) = regex {
                    *compiled_regex = if *case_insensitive {
                        regex::Regex::new(&format!("(?i){}", regex_pattern)).ok()
                    } else {
                        regex::Regex::new(regex_pattern).ok()
                    };
                }

                // Compile exclude patterns
                if let Some(excludes) = exclude_patterns {
                    *compiled_excludes = excludes
                        .iter()
                        .filter_map(|p| regex::Regex::new(p).ok())
                        .collect();
                }
            }
            Condition::Content {
                regex,
                word,
                case_insensitive,
                compiled_regex,
                ..
            } => {
                // Compile main regex or word pattern for content searches
                if let Some(word_pattern) = word {
                    let regex_pattern = format!(r"\b{}\b", regex::escape(word_pattern));
                    *compiled_regex = if *case_insensitive {
                        regex::Regex::new(&format!("(?i){}", regex_pattern)).ok()
                    } else {
                        regex::Regex::new(&regex_pattern).ok()
                    };
                } else if let Some(regex_pattern) = regex {
                    *compiled_regex = if *case_insensitive {
                        regex::Regex::new(&format!("(?i){}", regex_pattern)).ok()
                    } else {
                        regex::Regex::new(regex_pattern).ok()
                    };
                }
            }
            Condition::Kv {
                regex: Some(regex_pattern),
                case_insensitive,
                compiled_regex,
                ..
            } => {
                // Compile regex pattern for kv searches
                *compiled_regex = if *case_insensitive {
                    regex::Regex::new(&format!("(?i){}", regex_pattern)).ok()
                } else {
                    regex::Regex::new(regex_pattern).ok()
                };
            }
            _ => {}
        }
    }
}

/// Validate a tree-sitter query against the specified language
fn validate_ast_query(query: &str, language: Option<&str>) -> Result<()> {
    let lang: tree_sitter::Language = match language {
        Some("c") => tree_sitter_c::LANGUAGE.into(),
        Some("python") => tree_sitter_python::LANGUAGE.into(),
        Some("javascript") | Some("js") => tree_sitter_javascript::LANGUAGE.into(),
        Some("typescript") | Some("ts") => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
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
                "unsupported language for ast query: {}",
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

/// Check if a regex contains unbounded greedy patterns like .* or .+
/// Returns true if found, false otherwise.
/// Bounded patterns like .{0,50} or lazy patterns like .*? are acceptable.
fn has_unbounded_greedy(regex: &str) -> bool {
    let chars: Vec<char> = regex.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Skip escaped characters
        if chars[i] == '\\' {
            i += 2;
            continue;
        }

        // Check for character classes (skip them as .* inside [] is different)
        if chars[i] == '[' {
            while i < len && chars[i] != ']' {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            continue;
        }

        // Check for . followed by * or +
        if chars[i] == '.' && i + 1 < len {
            let next = chars[i + 1];
            if next == '*' || next == '+' {
                // Check if it's lazy (followed by ?)
                if i + 2 < len && chars[i + 2] == '?' {
                    i += 3;
                    continue;
                }
                // Check if there's a reasonable limit after (not truly unbounded)
                // This is an unbounded greedy pattern
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Validate location constraint parameters for consistency.
/// Returns an error if mutually exclusive constraints are specified.
fn validate_location_constraints(
    section: &Option<String>,
    offset: Option<i64>,
    offset_range: Option<(i64, Option<i64>)>,
    section_offset: Option<i64>,
    section_offset_range: Option<(i64, Option<i64>)>,
    condition_type: &str,
) -> Result<()> {
    // offset and offset_range are mutually exclusive
    if offset.is_some() && offset_range.is_some() {
        return Err(anyhow::anyhow!(
            "{} condition cannot have both 'offset' and 'offset_range'",
            condition_type
        ));
    }

    // section_offset and section_offset_range are mutually exclusive
    if section_offset.is_some() && section_offset_range.is_some() {
        return Err(anyhow::anyhow!(
            "{} condition cannot have both 'section_offset' and 'section_offset_range'",
            condition_type
        ));
    }

    // section_offset/section_offset_range require section
    if section.is_none() && (section_offset.is_some() || section_offset_range.is_some()) {
        return Err(anyhow::anyhow!(
            "{} condition with 'section_offset' or 'section_offset_range' requires 'section'",
            condition_type
        ));
    }

    // Validate offset_range format
    if let Some((start, Some(e))) = offset_range {
        if start >= 0 && e >= 0 && start > e {
            return Err(anyhow::anyhow!(
                "{} condition 'offset_range' start ({}) must be <= end ({})",
                condition_type,
                start,
                e
            ));
        }
    }

    // Validate section_offset_range format
    if let Some((start, Some(e))) = section_offset_range {
        if start >= 0 && e >= 0 && start > e {
            return Err(anyhow::anyhow!(
                "{} condition 'section_offset_range' start ({}) must be <= end ({})",
                condition_type,
                start,
                e
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod location_constraint_tests {
    use super::*;

    #[test]
    fn test_validate_location_no_constraints() {
        let result = validate_location_constraints(&None, None, None, None, None, "string");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_location_section_only() {
        let result = validate_location_constraints(
            &Some(".text".to_string()),
            None,
            None,
            None,
            None,
            "string",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_location_offset_only() {
        let result = validate_location_constraints(&None, Some(0x1000), None, None, None, "string");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_location_offset_range_only() {
        let result = validate_location_constraints(
            &None,
            None,
            Some((0, Some(0x1000))),
            None,
            None,
            "string",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_location_offset_and_offset_range_fails() {
        let result = validate_location_constraints(
            &None,
            Some(0x100),
            Some((0, Some(0x1000))),
            None,
            None,
            "string",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("offset"));
    }

    #[test]
    fn test_validate_location_section_offset_without_section_fails() {
        let result = validate_location_constraints(&None, None, None, Some(0x100), None, "content");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("requires 'section'"));
    }

    #[test]
    fn test_validate_location_section_offset_range_without_section_fails() {
        let result = validate_location_constraints(
            &None,
            None,
            None,
            None,
            Some((0, Some(0x100))),
            "base64",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_location_section_with_section_offset() {
        let result = validate_location_constraints(
            &Some(".data".to_string()),
            None,
            None,
            Some(0x100),
            None,
            "xor",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_location_section_offset_and_range_fails() {
        let result = validate_location_constraints(
            &Some(".text".to_string()),
            None,
            None,
            Some(0x100),
            Some((0, Some(0x200))),
            "string",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("section_offset"));
    }

    #[test]
    fn test_validate_location_invalid_offset_range() {
        // start > end should fail
        let result = validate_location_constraints(
            &None,
            None,
            Some((0x1000, Some(0x100))), // 0x1000 > 0x100
            None,
            None,
            "string",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("start"));
    }

    #[test]
    fn test_validate_location_negative_offsets_allowed() {
        // Negative offsets are allowed (means from end)
        let result =
            validate_location_constraints(&None, None, Some((-1024, None)), None, None, "content");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_location_open_ended_range() {
        // Open-ended range (start, None) is allowed
        let result =
            validate_location_constraints(&None, None, Some((0x1000, None)), None, None, "string");
        assert!(result.is_ok());
    }

    #[test]
    fn test_condition_validate_string_location() {
        // Test that Condition::String validates location constraints
        let condition = Condition::String {
            exact: Some("test".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            count_min: 1,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            external_ip: false,
            section: None,
            offset: Some(0x100),
            offset_range: Some((0, Some(0x1000))), // Mutually exclusive with offset
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };
        assert!(condition.validate().is_err());
    }

    #[test]
    fn test_condition_validate_content_location() {
        // Valid content condition with section constraint
        let condition = Condition::Content {
            exact: Some("test".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            count_min: 1,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            external_ip: false,
            section: Some(".text".to_string()),
            offset: None,
            offset_range: Some((0, Some(0x1000))),
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
        };
        assert!(condition.validate().is_ok());
    }
}
