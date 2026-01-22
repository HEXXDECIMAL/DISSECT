use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
use anyhow::Result;
use regex::Regex;
use serde::Deserialize;
use streaming_iterator::StreamingIterator;

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
    Elf,
    Macho,
    Pe,
    Dylib,
    So,
    Dll,
    Shell,
    Python,
    JavaScript,
    Rust,
    Java,
    Class,
    Ruby,
    C,
    Go,
}

/// Parameters for string condition evaluation (reduces argument count)
struct StringParams<'a> {
    exact: Option<&'a String>,
    regex: Option<&'a String>,
    case_insensitive: bool,
    exclude_patterns: Option<&'a Vec<String>>,
    min_count: usize,
    search_raw: bool,
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
    /// Example: { type: ast_query, language: c, query: "(call_expression function: (identifier) @fn (#eq? @fn \"system\"))" }
    AstQuery {
        /// Tree-sitter query pattern (S-expression syntax)
        query: String,
    },

    /// Inline YARA rule for pattern matching
    /// Example: { type: yara, source: "rule test { strings: $a = \"test\" condition: $a }" }
    Yara {
        /// YARA rule source code
        source: String,
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
}

impl Condition {
    /// Validate that condition can be compiled (for YARA/AST rules)
    /// Call this at load time to catch syntax errors early
    pub fn validate(&self) -> Result<()> {
        match self {
            Condition::Yara { source } => {
                let mut compiler = yara_x::Compiler::new();
                compiler
                    .add_source(source.as_bytes())
                    .map_err(|e| anyhow::anyhow!("invalid YARA rule: {}", e))?;
                // build() doesn't return Result in yara-x, compilation errors are caught by add_source
                let _ = compiler.build();
                Ok(())
            }
            Condition::AstQuery { query } => {
                // Validate tree-sitter query syntax for common languages
                // We try C as the base language for validation
                let language = tree_sitter_c::LANGUAGE;
                tree_sitter::Query::new(&language.into(), query)
                    .map_err(|e| anyhow::anyhow!("invalid tree-sitter query: {}", e))?;
                Ok(())
            }
            // Other conditions don't need compilation validation
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
    pub description: String,
    #[serde(default = "default_confidence")]
    pub confidence: f32,

    /// Criticality level (defaults to None = internal only)
    #[serde(default)]
    pub criticality: Criticality,

    /// MBC (Malware Behavior Catalog) ID - most specific available (e.g., "B0015.001")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mbc: Option<String>,

    /// MITRE ATT&CK Technique ID (e.g., "T1056.001")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attack: Option<String>,

    #[serde(default = "default_platforms")]
    pub platforms: Vec<Platform>,

    #[serde(default = "default_file_types")]
    pub file_types: Vec<FileType>,

    // Detection condition - just one condition per trait (atomic!)
    pub condition: Condition,
}

fn default_confidence() -> f32 {
    1.0
}

/// Boolean logic for combining conditions/traits
#[derive(Debug, Clone, Deserialize)]
pub struct CompositeTrait {
    #[serde(alias = "capability")]
    pub id: String,
    pub description: String,
    pub confidence: f32,

    /// Criticality level (defaults to None)
    #[serde(default)]
    pub criticality: Criticality,

    /// MBC (Malware Behavior Catalog) ID - most specific available (e.g., "B0015.001")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mbc: Option<String>,

    /// MITRE ATT&CK Technique ID (e.g., "T1056.001")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attack: Option<String>,

    #[serde(default = "default_platforms")]
    pub platforms: Vec<Platform>,

    #[serde(default = "default_file_types")]
    pub file_types: Vec<FileType>,

    // Boolean operators (only one should be set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_all: Option<Vec<Condition>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_any: Option<Vec<Condition>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_count: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<Condition>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_none: Option<Vec<Condition>>,
}

fn default_platforms() -> Vec<Platform> {
    vec![Platform::All]
}

fn default_file_types() -> Vec<FileType> {
    vec![FileType::All]
}

/// Context for evaluating composite rules
pub struct EvaluationContext<'a> {
    pub report: &'a AnalysisReport,
    pub binary_data: &'a [u8],
    pub file_type: FileType,
    pub platform: Platform,
}

/// Result of evaluating a condition
#[derive(Debug)]
struct ConditionResult {
    matched: bool,
    evidence: Vec<Evidence>,
    traits: Vec<String>, // Trait IDs referenced
}

impl CompositeTrait {
    /// Evaluate this rule against the analysis context
    pub fn evaluate(&self, ctx: &EvaluationContext) -> Option<Finding> {
        // Check if this rule applies to the current platform/file type
        if !self.matches_target(ctx) {
            return None;
        }

        // Evaluate conditions based on the boolean operator
        let result = if let Some(ref conditions) = self.requires_all {
            self.eval_requires_all(conditions, ctx)
        } else if let Some(ref conditions) = self.requires_any {
            self.eval_requires_any(conditions, ctx)
        } else if let Some(count) = self.requires_count {
            if let Some(ref conditions) = self.conditions {
                self.eval_requires_count(conditions, count, ctx)
            } else {
                return None;
            }
        } else if let Some(ref conditions) = self.requires_none {
            self.eval_requires_none(conditions, ctx)
        } else {
            return None;
        };

        if result.matched {
            Some(Finding {
                id: self.id.clone(),
                kind: FindingKind::Capability,
                description: self.description.clone(),
                confidence: self.confidence,
                criticality: self.criticality,
                mbc: self.mbc.clone(),
                attack: self.attack.clone(),
                trait_refs: vec![],
                evidence: result.evidence,
            })
        } else {
            None
        }
    }

    /// Check if rule applies to current platform/file type
    fn matches_target(&self, ctx: &EvaluationContext) -> bool {
        // Platform matches if:
        // - Trait specifies All platforms, OR
        // - Context platform is All (unknown, match any trait), OR
        // - Trait platforms contains the context platform
        let platform_match = self.platforms.contains(&Platform::All)
            || ctx.platform == Platform::All
            || self.platforms.contains(&ctx.platform);

        // File type matches if:
        // - Trait specifies All file types, OR
        // - Context file type is All (unknown, match any trait), OR
        // - Trait file types contains the context file type
        let file_type_match = self.file_types.contains(&FileType::All)
            || ctx.file_type == FileType::All
            || self.file_types.contains(&ctx.file_type);

        platform_match && file_type_match
    }

    /// Evaluate ALL conditions must match (AND)
    fn eval_requires_all(
        &self,
        conditions: &[Condition],
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        let mut all_evidence = Vec::new();

        for condition in conditions {
            let result = self.eval_condition(condition, ctx);
            if !result.matched {
                return ConditionResult {
                    matched: false,
                    evidence: Vec::new(),
                    traits: Vec::new(),
                };
            }
            all_evidence.extend(result.evidence);
        }

        ConditionResult {
            matched: true,
            evidence: all_evidence,
            traits: Vec::new(),
        }
    }

    /// Evaluate at least ONE condition must match (OR)
    fn eval_requires_any(
        &self,
        conditions: &[Condition],
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        for condition in conditions {
            let result = self.eval_condition(condition, ctx);
            if result.matched {
                return result;
            }
        }

        ConditionResult {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
        }
    }

    /// Evaluate at least N conditions must match
    fn eval_requires_count(
        &self,
        conditions: &[Condition],
        count: usize,
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        let mut matched_count = 0;
        let mut all_evidence = Vec::new();

        for condition in conditions {
            let result = self.eval_condition(condition, ctx);
            if result.matched {
                matched_count += 1;
                all_evidence.extend(result.evidence);
            }
        }

        ConditionResult {
            matched: matched_count >= count,
            evidence: all_evidence,
            traits: Vec::new(),
        }
    }

    /// Evaluate NONE of the conditions can match (NOT)
    fn eval_requires_none(
        &self,
        conditions: &[Condition],
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        for condition in conditions {
            let result = self.eval_condition(condition, ctx);
            if result.matched {
                return ConditionResult {
                    matched: false,
                    evidence: Vec::new(),
                    traits: Vec::new(),
                };
            }
        }

        ConditionResult {
            matched: true,
            evidence: vec![Evidence {
                method: "exclusion".to_string(),
                source: "composite_rule".to_string(),
                value: "negative_conditions_not_found".to_string(),
                location: None,
            }],
            traits: Vec::new(),
        }
    }

    /// Evaluate a single condition
    fn eval_condition(&self, condition: &Condition, ctx: &EvaluationContext) -> ConditionResult {
        match condition {
            Condition::Symbol { pattern, platforms } => {
                self.eval_symbol(pattern, platforms.as_ref(), ctx)
            }
            Condition::String {
                exact,
                regex,
                case_insensitive,
                exclude_patterns,
                min_count,
                search_raw,
            } => {
                let params = StringParams {
                    exact: exact.as_ref(),
                    regex: regex.as_ref(),
                    case_insensitive: *case_insensitive,
                    exclude_patterns: exclude_patterns.as_ref(),
                    min_count: *min_count,
                    search_raw: *search_raw,
                };
                eval_string(&params, ctx)
            }
            Condition::YaraMatch { namespace, rule } => {
                self.eval_yara_match(namespace, rule.as_ref(), ctx)
            }
            Condition::Structure {
                feature,
                min_sections,
            } => self.eval_structure(feature, *min_sections, ctx),
            Condition::SymbolOrString { any } => self.eval_symbol_or_string(any, ctx),
            Condition::ImportsCount { min, max, filter } => {
                self.eval_imports_count(*min, *max, filter.as_ref(), ctx)
            }
            Condition::ExportsCount { min, max } => self.eval_exports_count(*min, *max, ctx),
            Condition::Trait { .. } => {
                // Trait conditions are evaluated separately via TraitMapper
                ConditionResult {
                    matched: false,
                    evidence: Vec::new(),
                    traits: Vec::new(),
                }
            }
            Condition::AstPattern {
                node_type,
                pattern,
                regex,
                case_insensitive,
            } => eval_ast_pattern(node_type, pattern, *regex, *case_insensitive, ctx),
            Condition::AstQuery { query } => eval_ast_query(query, ctx),
            Condition::Yara { source } => eval_yara_inline(source, ctx),
            Condition::Syscall {
                name,
                number,
                arch,
                min_count,
            } => eval_syscall(name.as_ref(), number.as_ref(), arch.as_ref(), *min_count, ctx),
        }
    }

    /// Evaluate symbol condition
    fn eval_symbol(
        &self,
        pattern: &str,
        platforms: Option<&Vec<Platform>>,
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        // Check platform constraint
        if let Some(plats) = platforms {
            if !plats.contains(&ctx.platform) && !plats.contains(&Platform::All) {
                return ConditionResult {
                    matched: false,
                    evidence: Vec::new(),
                    traits: Vec::new(),
                };
            }
        }

        let mut evidence = Vec::new();

        // Search in imports
        for import in &ctx.report.imports {
            if symbol_matches(&import.symbol, pattern) {
                evidence.push(Evidence {
                    method: "symbol".to_string(),
                    source: import.source.clone(),
                    value: import.symbol.clone(),
                    location: Some("import".to_string()),
                });
            }
        }

        // Search in exports
        for export in &ctx.report.exports {
            if symbol_matches(&export.symbol, pattern) {
                evidence.push(Evidence {
                    method: "symbol".to_string(),
                    source: export.source.clone(),
                    value: export.symbol.clone(),
                    location: export.offset.clone(),
                });
            }
        }

        ConditionResult {
            matched: !evidence.is_empty(),
            evidence,
            traits: Vec::new(),
        }
    }

    /// Evaluate YARA match condition
    fn eval_yara_match(
        &self,
        namespace: &str,
        rule: Option<&String>,
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        let mut evidence = Vec::new();

        for yara_match in &ctx.report.yara_matches {
            let namespace_match = yara_match.namespace == namespace
                || yara_match.namespace.starts_with(&format!("{}.", namespace));

            let rule_match = rule.is_none_or(|r| &yara_match.rule == r);

            if namespace_match && rule_match {
                evidence.push(Evidence {
                    method: "yara".to_string(),
                    source: "yara-x".to_string(),
                    value: format!("{}:{}", yara_match.namespace, yara_match.rule),
                    location: Some(yara_match.namespace.clone()),
                });
            }
        }

        ConditionResult {
            matched: !evidence.is_empty(),
            evidence,
            traits: Vec::new(),
        }
    }

    /// Evaluate structure condition
    fn eval_structure(
        &self,
        feature: &str,
        min_sections: Option<usize>,
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        let mut count = 0;
        let mut evidence = Vec::new();

        for structural_feature in &ctx.report.structure {
            if structural_feature.id == feature
                || structural_feature.id.starts_with(&format!("{}/", feature))
            {
                count += 1;
                evidence.extend(structural_feature.evidence.clone());
            }
        }

        let matched = if let Some(min) = min_sections {
            count >= min
        } else {
            count > 0
        };

        ConditionResult {
            matched,
            evidence,
            traits: Vec::new(),
        }
    }

    /// Evaluate symbol OR string condition
    fn eval_symbol_or_string(
        &self,
        patterns: &[String],
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        for pattern in patterns {
            // Try as symbol first
            let symbol_result = self.eval_symbol(pattern, None, ctx);
            if symbol_result.matched {
                return symbol_result;
            }

            // Try as exact string match
            let params = StringParams {
                exact: Some(pattern),
                regex: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            };
            let string_result = eval_string(&params, ctx);
            if string_result.matched {
                return string_result;
            }
        }

        ConditionResult {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
        }
    }

    /// Evaluate imports count condition
    fn eval_imports_count(
        &self,
        min: Option<usize>,
        max: Option<usize>,
        filter: Option<&String>,
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        let count = if let Some(filter_pattern) = filter {
            // Compile regex once, then filter
            if let Ok(re) = Regex::new(filter_pattern) {
                ctx.report
                    .imports
                    .iter()
                    .filter(|imp| re.is_match(&imp.symbol))
                    .count()
            } else {
                0
            }
        } else {
            ctx.report.imports.len()
        };

        let matched = min.is_none_or(|m| count >= m) && max.is_none_or(|m| count <= m);

        ConditionResult {
            matched,
            evidence: if matched {
                vec![Evidence {
                    method: "import_count".to_string(),
                    source: "composite_rule".to_string(),
                    value: count.to_string(),
                    location: None,
                }]
            } else {
                Vec::new()
            },
            traits: Vec::new(),
        }
    }

    /// Evaluate exports count condition
    fn eval_exports_count(
        &self,
        min: Option<usize>,
        max: Option<usize>,
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        let count = ctx.report.exports.len();
        let matched = min.is_none_or(|m| count >= m) && max.is_none_or(|m| count <= m);

        ConditionResult {
            matched,
            evidence: if matched {
                vec![Evidence {
                    method: "export_count".to_string(),
                    source: "composite_rule".to_string(),
                    value: count.to_string(),
                    location: None,
                }]
            } else {
                Vec::new()
            },
            traits: Vec::new(),
        }
    }
}

/// Check if a symbol matches a pattern (supports exact match or regex)
fn symbol_matches(symbol: &str, pattern: &str) -> bool {
    // Clean symbol (remove leading underscores)
    let clean = symbol.trim_start_matches('_').trim_start_matches("__");

    // Try exact match first
    if clean == pattern || symbol == pattern {
        return true;
    }

    // Try as regex if pattern contains regex metacharacters
    if pattern.contains('|') || pattern.contains('*') || pattern.contains('[') {
        if let Ok(re) = Regex::new(pattern) {
            return re.is_match(clean) || re.is_match(symbol);
        }
    }

    false
}

/// Build a regex with optional case insensitivity
fn build_regex(pattern: &str, case_insensitive: bool) -> Result<Regex> {
    if case_insensitive {
        Ok(Regex::new(&format!("(?i){}", pattern))?)
    } else {
        Ok(Regex::new(pattern)?)
    }
}

impl TraitDefinition {
    /// Evaluate this trait definition against the analysis context
    pub fn evaluate(&self, ctx: &EvaluationContext) -> Option<Finding> {
        // Check if this trait applies to the current platform/file type
        if !self.matches_target(ctx) {
            return None;
        }

        // Evaluate the condition (traits only have one atomic condition)
        let result = self.eval_condition(&self.condition, ctx);

        if result.matched {
            Some(Finding {
                id: self.id.clone(),
                kind: FindingKind::Capability,
                description: self.description.clone(),
                confidence: self.confidence,
                criticality: self.criticality,
                mbc: self.mbc.clone(),
                attack: self.attack.clone(),
                trait_refs: vec![],
                evidence: result.evidence,
            })
        } else {
            None
        }
    }

    /// Check if trait applies to current platform/file type
    fn matches_target(&self, ctx: &EvaluationContext) -> bool {
        // Platform matches if:
        // - Trait specifies All platforms, OR
        // - Context platform is All (unknown, match any trait), OR
        // - Trait platforms contains the context platform
        let platform_match = self.platforms.contains(&Platform::All)
            || ctx.platform == Platform::All
            || self.platforms.contains(&ctx.platform);

        // File type matches if:
        // - Trait specifies All file types, OR
        // - Context file type is All (unknown, match any trait), OR
        // - Trait file types contains the context file type
        let file_type_match = self.file_types.contains(&FileType::All)
            || ctx.file_type == FileType::All
            || self.file_types.contains(&ctx.file_type);

        platform_match && file_type_match
    }

    /// Evaluate a single condition (reuse CompositeRule's implementation)
    fn eval_condition(&self, condition: &Condition, ctx: &EvaluationContext) -> ConditionResult {
        // We can reuse all the condition evaluation logic from CompositeRule
        // by creating a temporary rule and calling its eval_condition method
        // This is a bit hacky but avoids code duplication

        // For now, let's duplicate the condition evaluation logic
        match condition {
            Condition::Symbol { pattern, platforms } => {
                eval_symbol(pattern, platforms.as_ref(), ctx)
            }
            Condition::String {
                exact,
                regex,
                case_insensitive,
                exclude_patterns,
                min_count,
                search_raw,
            } => {
                let params = StringParams {
                    exact: exact.as_ref(),
                    regex: regex.as_ref(),
                    case_insensitive: *case_insensitive,
                    exclude_patterns: exclude_patterns.as_ref(),
                    min_count: *min_count,
                    search_raw: *search_raw,
                };
                eval_string(&params, ctx)
            }
            Condition::YaraMatch { namespace, rule } => {
                eval_yara_match(namespace, rule.as_ref(), ctx)
            }
            Condition::Structure {
                feature,
                min_sections,
            } => eval_structure(feature, *min_sections, ctx),
            Condition::SymbolOrString { any } => eval_symbol_or_string(any, ctx),
            Condition::ImportsCount { min, max, filter } => {
                eval_imports_count(*min, *max, filter.as_ref(), ctx)
            }
            Condition::ExportsCount { min, max } => eval_exports_count(*min, *max, ctx),
            Condition::Trait { .. } => {
                // Traits cannot reference other traits in their definition
                ConditionResult {
                    matched: false,
                    evidence: Vec::new(),
                    traits: Vec::new(),
                }
            }
            Condition::AstPattern {
                node_type,
                pattern,
                regex,
                case_insensitive,
            } => eval_ast_pattern(node_type, pattern, *regex, *case_insensitive, ctx),
            Condition::AstQuery { query } => eval_ast_query(query, ctx),
            Condition::Yara { source } => eval_yara_inline(source, ctx),
            Condition::Syscall {
                name,
                number,
                arch,
                min_count,
            } => eval_syscall(name.as_ref(), number.as_ref(), arch.as_ref(), *min_count, ctx),
        }
    }
}

// Helper functions for trait evaluation (same as CompositeRule methods but standalone)
fn eval_symbol(
    pattern: &str,
    platforms: Option<&Vec<Platform>>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    // Check platform constraint
    if let Some(plats) = platforms {
        if !plats.contains(&ctx.platform) && !plats.contains(&Platform::All) {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            };
        }
    }

    let mut evidence = Vec::new();

    // Search in imports
    for import in &ctx.report.imports {
        if symbol_matches(&import.symbol, pattern) {
            evidence.push(Evidence {
                method: "symbol".to_string(),
                source: import.source.clone(),
                value: import.symbol.clone(),
                location: Some("import".to_string()),
            });
        }
    }

    // Search in exports
    for export in &ctx.report.exports {
        if symbol_matches(&export.symbol, pattern) {
            evidence.push(Evidence {
                method: "symbol".to_string(),
                source: export.source.clone(),
                value: export.symbol.clone(),
                location: export.offset.clone(),
            });
        }
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
    }
}

fn eval_string(params: &StringParams, ctx: &EvaluationContext) -> ConditionResult {
    let mut evidence = Vec::new();

    // If search_raw is true, count all occurrences in raw content
    if params.search_raw {
        if let Ok(content) = std::str::from_utf8(ctx.binary_data) {
            if let Some(regex_pattern) = params.regex {
                if let Ok(re) = build_regex(regex_pattern, params.case_insensitive) {
                    let mut match_count = 0;
                    let mut first_match = None;
                    for mat in re.find_iter(content) {
                        match_count += 1;
                        if first_match.is_none() {
                            first_match = Some(mat.as_str().to_string());
                        }
                    }
                    if match_count >= params.min_count {
                        // Add a single evidence entry with the count
                        evidence.push(Evidence {
                            method: "string".to_string(),
                            source: "raw_content".to_string(),
                            value: format!(
                                "Found {} {}",
                                match_count,
                                first_match.unwrap_or_default()
                            ),
                            location: Some("file".to_string()),
                        });
                    }
                }
            } else if let Some(exact_str) = params.exact {
                let search_content = if params.case_insensitive {
                    content.to_lowercase()
                } else {
                    content.to_string()
                };
                let search_pattern = if params.case_insensitive {
                    exact_str.to_lowercase()
                } else {
                    exact_str.clone()
                };
                let match_count = search_content.matches(&search_pattern).count();
                if match_count >= params.min_count {
                    evidence.push(Evidence {
                        method: "string".to_string(),
                        source: "raw_content".to_string(),
                        value: format!("Found {} {}", match_count, exact_str),
                        location: Some("file".to_string()),
                    });
                }
            }
        }
        return ConditionResult {
            matched: !evidence.is_empty(),
            evidence,
            traits: Vec::new(),
        };
    }

    // Pre-compile regex patterns ONCE before iterating strings
    let compiled_regex = params
        .regex
        .and_then(|pattern| build_regex(pattern, params.case_insensitive).ok());

    let compiled_excludes: Vec<Regex> = params
        .exclude_patterns
        .map(|excludes| {
            excludes
                .iter()
                .filter_map(|p| Regex::new(p).ok())
                .collect()
        })
        .unwrap_or_default();

    // Check in extracted strings from report (for binaries)
    for string_info in &ctx.report.strings {
        let mut matched = false;
        let mut match_value = String::new();

        if let Some(exact_str) = params.exact {
            matched = if params.case_insensitive {
                string_info
                    .value
                    .to_lowercase()
                    .contains(&exact_str.to_lowercase())
            } else {
                string_info.value.contains(exact_str)
            };
            if matched {
                match_value = exact_str.clone();
            }
        } else if let Some(ref re) = compiled_regex {
            if let Some(mat) = re.find(&string_info.value) {
                matched = true;
                match_value = mat.as_str().to_string();
            }
        }

        if matched {
            // Check exclusion patterns (already compiled)
            let excluded = compiled_excludes
                .iter()
                .any(|re| re.is_match(&string_info.value));
            if excluded {
                continue;
            }

            evidence.push(Evidence {
                method: "string".to_string(),
                source: "string_extractor".to_string(),
                value: match_value,
                location: string_info.offset.clone(),
            });
        }
    }

    // For source files or when no strings were extracted, search binary_data directly
    if ctx.report.strings.is_empty()
        || matches!(
            ctx.file_type,
            FileType::Python | FileType::Ruby | FileType::JavaScript | FileType::Shell
        )
    {
        // Convert binary data to string for source code matching
        if let Ok(content) = std::str::from_utf8(ctx.binary_data) {
            let mut matched = false;
            let mut match_value = String::new();

            if let Some(exact_str) = params.exact {
                matched = if params.case_insensitive {
                    content.to_lowercase().contains(&exact_str.to_lowercase())
                } else {
                    content.contains(exact_str)
                };
                if matched {
                    match_value = exact_str.clone();
                }
            } else if let Some(ref re) = compiled_regex {
                if let Some(mat) = re.find(content) {
                    matched = true;
                    match_value = mat.as_str().to_string();
                }
            }

            if matched {
                // Check exclusion patterns (already compiled)
                let excluded = compiled_excludes
                    .iter()
                    .any(|re| re.is_match(&match_value));
                if !excluded {
                    evidence.push(Evidence {
                        method: "string".to_string(),
                        source: "source_code".to_string(),
                        value: match_value,
                        location: Some("file".to_string()),
                    });
                }
            }
        }
    }

    ConditionResult {
        matched: evidence.len() >= params.min_count,
        evidence,
        traits: Vec::new(),
    }
}

fn eval_yara_match(
    namespace: &str,
    rule: Option<&String>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let mut evidence = Vec::new();

    for yara_match in &ctx.report.yara_matches {
        let namespace_match = yara_match.namespace == namespace
            || yara_match.namespace.starts_with(&format!("{}.", namespace));

        let rule_match = rule.is_none_or(|r| &yara_match.rule == r);

        if namespace_match && rule_match {
            evidence.push(Evidence {
                method: "yara".to_string(),
                source: "yara-x".to_string(),
                value: format!("{}:{}", yara_match.namespace, yara_match.rule),
                location: Some(yara_match.namespace.clone()),
            });
        }
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
    }
}

fn eval_structure(
    feature: &str,
    min_sections: Option<usize>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let mut count = 0;
    let mut evidence = Vec::new();

    for structural_feature in &ctx.report.structure {
        if structural_feature.id == feature
            || structural_feature.id.starts_with(&format!("{}/", feature))
        {
            count += 1;
            evidence.extend(structural_feature.evidence.clone());
        }
    }

    let matched = if let Some(min) = min_sections {
        count >= min
    } else {
        count > 0
    };

    ConditionResult {
        matched,
        evidence,
        traits: Vec::new(),
    }
}

fn eval_symbol_or_string(patterns: &[String], ctx: &EvaluationContext) -> ConditionResult {
    for pattern in patterns {
        // Try as symbol first
        let symbol_result = eval_symbol(pattern, None, ctx);
        if symbol_result.matched {
            return symbol_result;
        }

        // Try as exact string match
        let params = StringParams {
            exact: Some(pattern),
            regex: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            search_raw: false,
        };
        let string_result = eval_string(&params, ctx);
        if string_result.matched {
            return string_result;
        }
    }

    ConditionResult {
        matched: false,
        evidence: Vec::new(),
        traits: Vec::new(),
    }
}

fn eval_imports_count(
    min: Option<usize>,
    max: Option<usize>,
    filter: Option<&String>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let count = if let Some(filter_pattern) = filter {
        ctx.report
            .imports
            .iter()
            .filter(|imp| imp.symbol.contains(filter_pattern))
            .count()
    } else {
        ctx.report.imports.len()
    };

    let matched = min.is_none_or(|m| count >= m) && max.is_none_or(|m| count <= m);

    ConditionResult {
        matched,
        evidence: if matched {
            vec![Evidence {
                method: "imports_count".to_string(),
                source: "analysis".to_string(),
                value: count.to_string(),
                location: None,
            }]
        } else {
            Vec::new()
        },
        traits: Vec::new(),
    }
}

fn eval_exports_count(
    min: Option<usize>,
    max: Option<usize>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let count = ctx.report.exports.len();
    let matched = min.is_none_or(|m| count >= m) && max.is_none_or(|m| count <= m);

    ConditionResult {
        matched,
        evidence: if matched {
            vec![Evidence {
                method: "exports_count".to_string(),
                source: "analysis".to_string(),
                value: count.to_string(),
                location: None,
            }]
        } else {
            Vec::new()
        },
        traits: Vec::new(),
    }
}

/// Evaluate AST pattern condition - searches for text patterns within specific AST node types
fn eval_ast_pattern(
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
            }
        }
    };

    // Get the appropriate parser based on file type
    let parser_lang = match ctx.file_type {
        FileType::C => Some(tree_sitter_c::LANGUAGE),
        FileType::Python => Some(tree_sitter_python::LANGUAGE),
        FileType::JavaScript => Some(tree_sitter_javascript::LANGUAGE),
        FileType::Rust => Some(tree_sitter_rust::LANGUAGE),
        FileType::Go => Some(tree_sitter_go::LANGUAGE),
        FileType::Java => Some(tree_sitter_java::LANGUAGE),
        FileType::Ruby => Some(tree_sitter_ruby::LANGUAGE),
        FileType::Shell => Some(tree_sitter_bash::LANGUAGE),
        _ => None,
    };

    let lang = match parser_lang {
        Some(l) => l,
        None => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            }
        }
    };

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&lang.into()).is_err() {
        return ConditionResult {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
        };
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            }
        }
    };

    // Build the regex/pattern matcher
    let matcher: Box<dyn Fn(&str) -> bool> = if use_regex {
        match build_regex(pattern, case_insensitive) {
            Ok(re) => Box::new(move |s: &str| re.is_match(s)),
            Err(_) => {
                return ConditionResult {
                    matched: false,
                    evidence: Vec::new(),
                    traits: Vec::new(),
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
    walk_ast_for_pattern(
        &mut cursor,
        source.as_bytes(),
        node_type,
        &matcher,
        &mut evidence,
    );

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
    }
}

/// Recursively walk AST looking for nodes matching the pattern
fn walk_ast_for_pattern(
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    target_node_type: &str,
    matcher: &dyn Fn(&str) -> bool,
    evidence: &mut Vec<Evidence>,
) {
    loop {
        let node = cursor.node();

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

        // Recurse into children
        if cursor.goto_first_child() {
            walk_ast_for_pattern(cursor, source, target_node_type, matcher, evidence);
            cursor.goto_parent();
        }

        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

/// Evaluate full tree-sitter query condition
fn eval_ast_query(query_str: &str, ctx: &EvaluationContext) -> ConditionResult {
    // Only works for source code files
    let source = match std::str::from_utf8(ctx.binary_data) {
        Ok(s) => s,
        Err(_) => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            }
        }
    };

    // Get the appropriate parser and language based on file type
    let lang = match ctx.file_type {
        FileType::C => tree_sitter_c::LANGUAGE.into(),
        FileType::Python => tree_sitter_python::LANGUAGE.into(),
        FileType::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        FileType::Rust => tree_sitter_rust::LANGUAGE.into(),
        FileType::Go => tree_sitter_go::LANGUAGE.into(),
        FileType::Java => tree_sitter_java::LANGUAGE.into(),
        FileType::Ruby => tree_sitter_ruby::LANGUAGE.into(),
        FileType::Shell => tree_sitter_bash::LANGUAGE.into(),
        _ => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            }
        }
    };

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&lang).is_err() {
        return ConditionResult {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
        };
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            }
        }
    };

    // Compile the query
    let query = match tree_sitter::Query::new(&lang, query_str) {
        Ok(q) => q,
        Err(_) => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            }
        }
    };

    // Execute the query
    let mut query_cursor = tree_sitter::QueryCursor::new();
    let mut evidence = Vec::new();

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
            }
        }
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
    }
}

/// Evaluate inline YARA rule condition
fn eval_yara_inline(source: &str, ctx: &EvaluationContext) -> ConditionResult {
    // Compile the YARA rule
    let mut compiler = yara_x::Compiler::new();
    compiler.new_namespace("inline");
    if compiler.add_source(source.as_bytes()).is_err() {
        // Should not happen if validated at load time
        return ConditionResult {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
        };
    }
    let rules = compiler.build();

    // Scan the binary data
    let mut scanner = yara_x::Scanner::new(&rules);
    let results = match scanner.scan(ctx.binary_data) {
        Ok(r) => r,
        Err(_) => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            }
        }
    };

    // Collect evidence from matches
    let mut evidence = Vec::new();
    for matched_rule in results.matching_rules() {
        for pattern in matched_rule.patterns() {
            for m in pattern.matches() {
                // Extract matched bytes as string if possible
                let match_value = ctx
                    .binary_data
                    .get(m.range())
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .map(|s| truncate_evidence(s, 50))
                    .unwrap_or_else(|| format!("<{} bytes>", m.range().len()));

                evidence.push(Evidence {
                    method: "yara".to_string(),
                    source: "yara-x".to_string(),
                    value: format!(
                        "{}:{} = {}",
                        matched_rule.identifier(),
                        pattern.identifier(),
                        match_value
                    ),
                    location: Some(format!("offset:{}", m.range().start)),
                });
            }
        }
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
    }
}

/// Truncate evidence string to max length
fn truncate_evidence(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

/// Evaluate syscall condition - matches syscalls detected via radare2 analysis
fn eval_syscall(
    name: Option<&Vec<String>>,
    number: Option<&Vec<u32>>,
    arch: Option<&Vec<String>>,
    min_count: Option<usize>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let mut evidence = Vec::new();
    let mut match_count = 0;

    for syscall in &ctx.report.syscalls {
        let name_match = name.is_none_or(|names| names.contains(&syscall.name));
        let number_match = number.is_none_or(|nums| nums.contains(&syscall.number));
        let arch_match = arch.is_none_or(|archs| {
            archs
                .iter()
                .any(|a| syscall.arch.to_lowercase().contains(&a.to_lowercase()))
        });

        if name_match && number_match && arch_match {
            match_count += 1;
            evidence.push(Evidence {
                method: "syscall".to_string(),
                source: "radare2".to_string(),
                value: format!("{}({}) at 0x{:x}", syscall.name, syscall.number, syscall.address),
                location: Some(format!("0x{:x}", syscall.address)),
            });
        }
    }

    let min_required = min_count.unwrap_or(1);
    let matched = match_count >= min_required;

    ConditionResult {
        matched,
        evidence: if matched { evidence } else { Vec::new() },
        traits: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::radare2::SyscallInfo;
    use crate::types::{Export, Import, StringInfo, StringType, StructuralFeature, TargetInfo};

    fn create_test_context() -> (AnalysisReport, Vec<u8>) {
        let target = TargetInfo {
            path: "/test".to_string(),
            file_type: "elf".to_string(),
            size_bytes: 1024,
            sha256: "test".to_string(),
            architectures: Some(vec!["x86_64".to_string()]),
        };

        let mut report = AnalysisReport::new(target);

        // Add some test imports
        report.imports.push(Import {
            symbol: "socket".to_string(),
            library: None,
            source: "test".to_string(),
        });

        report.imports.push(Import {
            symbol: "connect".to_string(),
            library: None,
            source: "test".to_string(),
        });

        // Add some test strings
        report.strings.push(StringInfo {
            value: "/bin/sh".to_string(),
            offset: Some("0x1000".to_string()),
            encoding: "utf8".to_string(),
            string_type: crate::types::StringType::Path,
            section: None,
        });

        (report, vec![])
    }

    #[test]
    fn test_symbol_condition() {
        let (report, data) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "test/capability".to_string(),
            description: "Test".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::All],
            requires_all: Some(vec![Condition::Symbol {
                pattern: "socket".to_string(),
                platforms: None,
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some());

        let cap = result.unwrap();
        assert_eq!(cap.id, "test/capability");
        assert!(!cap.evidence.is_empty());
    }

    #[test]
    fn test_requires_all() {
        let (report, data) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "net/reverse-shell".to_string(),
            description: "Reverse shell".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::All],
            requires_all: Some(vec![
                Condition::Symbol {
                    pattern: "socket".to_string(),
                    platforms: None,
                },
                Condition::String {
                    exact: Some("/bin/sh".to_string()),
                    regex: None,
                    case_insensitive: false,
                    exclude_patterns: None,
                    min_count: 1,
                    search_raw: false,
                },
            ]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_requires_count() {
        let (report, data) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "test/multi".to_string(),
            description: "Multiple conditions".to_string(),
            confidence: 0.85,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::All],
            requires_all: None,
            requires_any: None,
            requires_count: Some(2),
            conditions: Some(vec![
                Condition::Symbol {
                    pattern: "socket".to_string(),
                    platforms: None,
                },
                Condition::Symbol {
                    pattern: "connect".to_string(),
                    platforms: None,
                },
                Condition::Symbol {
                    pattern: "nonexistent".to_string(),
                    platforms: None,
                },
            ]),
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_string_exact_condition() {
        let (report, data) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "test/string-exact".to_string(),
            description: "Exact string match".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::All],
            requires_all: Some(vec![Condition::String {
                exact: Some("/bin/sh".to_string()),
                regex: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_string_regex_condition() {
        let (mut report, data) = create_test_context();
        report.strings.push(StringInfo {
            value: "192.168.1.1".to_string(),
            offset: Some("0x2000".to_string()),
            encoding: "utf8".to_string(),
            string_type: StringType::Plain,
            section: None,
        });

        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "test/string-regex".to_string(),
            description: "Regex string match".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::All],
            requires_all: Some(vec![Condition::String {
                exact: None,
                regex: Some(r"\d+\.\d+\.\d+\.\d+".to_string()),
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_string_case_insensitive() {
        let (mut report, data) = create_test_context();
        report.strings.push(StringInfo {
            value: "PASSWORD".to_string(),
            offset: Some("0x3000".to_string()),
            encoding: "utf8".to_string(),
            string_type: StringType::Plain,
            section: None,
        });

        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "test/string-case".to_string(),
            description: "Case insensitive match".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::All],
            requires_all: Some(vec![Condition::String {
                exact: Some("password".to_string()),
                regex: None,
                case_insensitive: true,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_symbol_or_string_condition() {
        let (report, data) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "test/symbol-or-string".to_string(),
            description: "Symbol or string match".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::All],
            requires_all: Some(vec![Condition::SymbolOrString {
                any: vec!["socket".to_string(), "/bin/sh".to_string()],
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_imports_count_condition() {
        let (report, data) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "test/imports-count".to_string(),
            description: "Imports count check".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::All],
            requires_all: Some(vec![Condition::ImportsCount {
                min: Some(1),
                max: Some(10),
                filter: None,
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_exports_count_condition() {
        let (mut report, data) = create_test_context();
        report.exports.push(Export {
            symbol: "main".to_string(),
            offset: Some("0x1000".to_string()),
            source: "test".to_string(),
        });

        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "test/exports-count".to_string(),
            description: "Exports count check".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::All],
            requires_all: Some(vec![Condition::ExportsCount {
                min: Some(1),
                max: Some(10),
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_structure_condition() {
        let (mut report, data) = create_test_context();
        report.structure.push(StructuralFeature {
            id: "binary/format/elf".to_string(),
            description: "ELF binary".to_string(),
            evidence: vec![],
        });

        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "test/structure".to_string(),
            description: "Structure check".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::All],
            requires_all: Some(vec![Condition::Structure {
                feature: "binary/format/elf".to_string(),
                min_sections: None,
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_requires_any() {
        let (report, data) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "test/requires-any".to_string(),
            description: "Requires any condition".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::All],
            requires_all: None,
            requires_any: Some(vec![
                Condition::Symbol {
                    pattern: "nonexistent".to_string(),
                    platforms: None,
                },
                Condition::Symbol {
                    pattern: "socket".to_string(),
                    platforms: None,
                },
            ]),
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_requires_none() {
        let (report, data) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "test/requires-none".to_string(),
            description: "Requires none condition".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::All],
            requires_all: Some(vec![Condition::Symbol {
                pattern: "socket".to_string(),
                platforms: None,
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: Some(vec![Condition::Symbol {
                pattern: "totally_nonexistent_symbol".to_string(),
                platforms: None,
            }]),
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_requires_none_fails() {
        let (report, data) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "test/requires-none-fail".to_string(),
            description: "Requires none fails".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::All],
            requires_all: None,
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: Some(vec![Condition::Symbol {
                pattern: "socket".to_string(),
                platforms: None,
            }]),
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_none());
    }

    #[test]
    fn test_platform_filter() {
        let (report, data) = create_test_context();

        // Linux platform should match
        let ctx_linux = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "test/platform".to_string(),
            description: "Platform filter".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::Linux],
            file_types: vec![FileType::All],
            requires_all: Some(vec![Condition::Symbol {
                pattern: "socket".to_string(),
                platforms: None,
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        assert!(rule.evaluate(&ctx_linux).is_some());

        // Windows platform should not match
        let ctx_windows = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Pe,
            platform: Platform::Windows,
        };

        assert!(rule.evaluate(&ctx_windows).is_none());
    }

    #[test]
    fn test_file_type_filter() {
        let (report, data) = create_test_context();

        // ELF file type should match
        let ctx_elf = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "test/filetype".to_string(),
            description: "File type filter".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::Elf],
            requires_all: Some(vec![Condition::Symbol {
                pattern: "socket".to_string(),
                platforms: None,
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        assert!(rule.evaluate(&ctx_elf).is_some());

        // PE file type should not match
        let ctx_pe = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Pe,
            platform: Platform::Windows,
        };

        assert!(rule.evaluate(&ctx_pe).is_none());
    }

    #[test]
    fn test_min_count_string() {
        let (mut report, data) = create_test_context();
        report.strings.push(StringInfo {
            value: "test".to_string(),
            offset: Some("0x1000".to_string()),
            encoding: "utf8".to_string(),
            string_type: StringType::Plain,
            section: None,
        });
        report.strings.push(StringInfo {
            value: "test".to_string(),
            offset: Some("0x2000".to_string()),
            encoding: "utf8".to_string(),
            string_type: StringType::Plain,
            section: None,
        });

        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "test/min-count".to_string(),
            description: "Min count check".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::All],
            requires_all: Some(vec![Condition::String {
                exact: Some("test".to_string()),
                regex: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 2,
                search_raw: false,
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_exclude_patterns() {
        let (mut report, data) = create_test_context();
        // Add both an included and excluded string
        report.strings.push(StringInfo {
            value: "/bin/sh".to_string(), // This should match
            offset: Some("0x1000".to_string()),
            encoding: "utf8".to_string(),
            string_type: StringType::Plain,
            section: None,
        });
        report.strings.push(StringInfo {
            value: "/bin/bash".to_string(), // This should be excluded
            offset: Some("0x2000".to_string()),
            encoding: "utf8".to_string(),
            string_type: StringType::Plain,
            section: None,
        });

        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "test/exclude".to_string(),
            description: "Exclude patterns".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::All],
            requires_all: Some(vec![Condition::String {
                exact: None,
                regex: Some("/bin/.*".to_string()),
                case_insensitive: false,
                exclude_patterns: Some(vec!["bash".to_string()]),
                min_count: 1,
                search_raw: false,
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        // Should match because /bin/sh matches and is not excluded
        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_imports_count_with_filter() {
        let (mut report, data) = create_test_context();
        report.imports.push(Import {
            symbol: "bind".to_string(),
            library: None,
            source: "test".to_string(),
        });

        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "test/imports-filter".to_string(),
            description: "Imports count with filter".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::All],
            requires_all: Some(vec![Condition::ImportsCount {
                min: Some(2),
                max: None,
                filter: Some("socket|connect|bind".to_string()),
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }

    // ============================================================
    // AST PATTERN CONDITION TESTS
    // ============================================================

    #[test]
    fn test_ast_pattern_call_expression() {
        let c_code = r#"
#include <stdlib.h>
int main() {
    system("ls -la");
    return 0;
}
"#;
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: c_code.as_bytes(),
            file_type: FileType::C,
            platform: Platform::Linux,
        };

        let result = eval_ast_pattern("call_expression", "system", false, false, &ctx);
        assert!(result.matched);
        assert!(!result.evidence.is_empty());
    }

    #[test]
    fn test_ast_pattern_preproc_include() {
        let c_code = r#"
#include <linux/module.h>
#include <linux/kernel.h>
int init_module(void) { return 0; }
"#;
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: c_code.as_bytes(),
            file_type: FileType::C,
            platform: Platform::Linux,
        };

        let result = eval_ast_pattern("preproc_include", "linux/module.h", false, false, &ctx);
        assert!(result.matched);
    }

    #[test]
    fn test_ast_pattern_comment() {
        let c_code = r#"
/* This is a rootkit for educational purposes */
int main() { return 0; }
"#;
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: c_code.as_bytes(),
            file_type: FileType::C,
            platform: Platform::Linux,
        };

        let result = eval_ast_pattern("comment", "rootkit", false, true, &ctx);
        assert!(result.matched);
    }

    #[test]
    fn test_ast_pattern_declaration() {
        let c_code = r#"
struct task_struct *current_task;
int main() { return 0; }
"#;
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: c_code.as_bytes(),
            file_type: FileType::C,
            platform: Platform::Linux,
        };

        let result = eval_ast_pattern("declaration", "task_struct", false, false, &ctx);
        assert!(result.matched);
    }

    #[test]
    fn test_ast_pattern_regex() {
        let c_code = r#"
void hide_process(void) {}
void make_invisible(void) {}
"#;
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: c_code.as_bytes(),
            file_type: FileType::C,
            platform: Platform::Linux,
        };

        // Should match "hide" or "invisible" using regex
        let result = eval_ast_pattern("function_definition", "hide|invisible", true, false, &ctx);
        assert!(result.matched);
        // Should have two matches
        assert!(!result.evidence.is_empty());
    }

    #[test]
    fn test_ast_pattern_case_insensitive() {
        let c_code = r#"
/* ROOTKIT implementation */
int main() { return 0; }
"#;
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: c_code.as_bytes(),
            file_type: FileType::C,
            platform: Platform::Linux,
        };

        // Should match "ROOTKIT" with case insensitive search for "rootkit"
        let result = eval_ast_pattern("comment", "rootkit", false, true, &ctx);
        assert!(result.matched);
    }

    #[test]
    fn test_ast_pattern_no_match() {
        let c_code = r#"
int main() {
    printf("Hello, world!\n");
    return 0;
}
"#;
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: c_code.as_bytes(),
            file_type: FileType::C,
            platform: Platform::Linux,
        };

        let result = eval_ast_pattern(
            "call_expression",
            "kallsyms_lookup_name",
            false,
            false,
            &ctx,
        );
        assert!(!result.matched);
        assert!(result.evidence.is_empty());
    }

    #[test]
    fn test_ast_pattern_non_source_file() {
        let binary_data = vec![0x7f, 0x45, 0x4c, 0x46]; // ELF header bytes
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: &binary_data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        // Should not match on binary data
        let result = eval_ast_pattern("call_expression", "system", false, false, &ctx);
        assert!(!result.matched);
    }

    #[test]
    fn test_ast_query_basic() {
        let c_code = r#"
int main() {
    system("ls");
    return 0;
}
"#;
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: c_code.as_bytes(),
            file_type: FileType::C,
            platform: Platform::Linux,
        };

        // Query for call expressions
        let result = eval_ast_query("(call_expression) @call", &ctx);
        assert!(result.matched);
    }

    #[test]
    fn test_ast_query_function_definition() {
        let c_code = r#"
void hide_module(void) {
    // hidden
}
int main() { return 0; }
"#;
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: c_code.as_bytes(),
            file_type: FileType::C,
            platform: Platform::Linux,
        };

        // Query for function definitions
        let result = eval_ast_query("(function_definition) @func", &ctx);
        assert!(result.matched);
        assert!(result.evidence.len() >= 2); // hide_module and main
    }

    #[test]
    fn test_ast_pattern_python() {
        let python_code = r#"
import os
os.system("whoami")
"#;
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: python_code.as_bytes(),
            file_type: FileType::Python,
            platform: Platform::Linux,
        };

        let result = eval_ast_pattern("call", "system", false, false, &ctx);
        assert!(result.matched);
    }

    #[test]
    fn test_ast_pattern_javascript() {
        let js_code = r#"
const exec = require('child_process').exec;
exec('ls -la');
"#;
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: js_code.as_bytes(),
            file_type: FileType::JavaScript,
            platform: Platform::Linux,
        };

        let result = eval_ast_pattern("call_expression", "exec", false, false, &ctx);
        assert!(result.matched);
    }

    #[test]
    fn test_trait_definition_with_ast_pattern() {
        let c_code = r#"
void kallsyms_lookup_name(const char *name);
int main() {
    kallsyms_lookup_name("sys_call_table");
    return 0;
}
"#;
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: c_code.as_bytes(),
            file_type: FileType::C,
            platform: Platform::Linux,
        };

        let trait_def = TraitDefinition {
            id: "kernel/symbol-lookup".to_string(),
            description: "Kernel symbol lookup".to_string(),
            confidence: 0.98,
            criticality: Criticality::Hostile,
            mbc: None,
            attack: None,
            platforms: vec![Platform::Linux],
            file_types: vec![FileType::C],
            condition: Condition::AstPattern {
                node_type: "call_expression".to_string(),
                pattern: "kallsyms_lookup_name".to_string(),
                regex: false,
                case_insensitive: false,
            },
        };

        let result = trait_def.evaluate(&ctx);
        assert!(result.is_some());
        let detected_trait = result.unwrap();
        assert_eq!(detected_trait.id, "kernel/symbol-lookup");
        assert_eq!(detected_trait.criticality, Criticality::Hostile);
    }

    #[test]
    fn test_yara_inline_basic() {
        let binary_data = b"This contains a test_string for matching";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let result = eval_yara_inline(
            r#"
            rule test_rule {
                strings:
                    $test = "test_string"
                condition:
                    $test
            }
            "#,
            &ctx,
        );
        assert!(result.matched);
        assert!(!result.evidence.is_empty());
        assert!(result.evidence[0].method == "yara");
    }

    #[test]
    fn test_yara_inline_no_match() {
        let binary_data = b"This contains nothing interesting";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let result = eval_yara_inline(
            r#"
            rule test_rule {
                strings:
                    $test = "not_present"
                condition:
                    $test
            }
            "#,
            &ctx,
        );
        assert!(!result.matched);
        assert!(result.evidence.is_empty());
    }

    #[test]
    fn test_yara_inline_multiple_strings() {
        let binary_data = b"VMware virtualization QEMU detected";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let result = eval_yara_inline(
            r#"
            rule vm_detect {
                strings:
                    $vmware = "VMware"
                    $qemu = "QEMU"
                condition:
                    any of them
            }
            "#,
            &ctx,
        );
        assert!(result.matched);
        // Should have evidence for both matches
        assert!(result.evidence.len() >= 2);
    }

    #[test]
    fn test_yara_condition_validation() {
        // Valid YARA rule should pass validation
        let valid = Condition::Yara {
            source: r#"rule test { strings: $a = "test" condition: $a }"#.to_string(),
        };
        assert!(valid.validate().is_ok());

        // Invalid YARA rule should fail validation
        let invalid = Condition::Yara {
            source: "this is not valid yara syntax".to_string(),
        };
        assert!(invalid.validate().is_err());
    }

    // ============================================================
    // Tests for search_raw: YARA-like counting pattern support
    // ============================================================

    #[test]
    fn test_search_raw_regex_matches_when_count_exceeds_threshold() {
        // Test that search_raw: true with regex counts all occurrences in raw content
        // Pattern: _0x[a-fA-F0-9]{4} should match _0x1234, _0xABCD, etc.
        let content =
            b"var _0x1234 = 1; var _0x5678 = 2; var _0xABCD = 3; var _0xDEF0 = 4; var _0x9999 = 5;";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: content,
            file_type: FileType::JavaScript,
            platform: Platform::All,
        };

        // With min_count: 3, should match (we have 5 occurrences)
        let params = StringParams {
            exact: None,
            regex: Some(&"_0x[a-fA-F0-9]{4}".to_string()),
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 3,
            search_raw: true,
        };
        let result = eval_string(&params, &ctx);
        assert!(
            result.matched,
            "Should match when count (5) >= min_count (3)"
        );
        assert!(!result.evidence.is_empty());
        assert!(
            result.evidence[0].value.contains("Found 5"),
            "Evidence should show count: {}",
            result.evidence[0].value
        );
    }

    #[test]
    fn test_search_raw_regex_no_match_when_count_below_threshold() {
        // Test that search_raw: true doesn't match when count < min_count
        let content = b"var _0x1234 = 1; var _0x5678 = 2;";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: content,
            file_type: FileType::JavaScript,
            platform: Platform::All,
        };

        // With min_count: 5, should NOT match (we only have 2 occurrences)
        let params = StringParams {
            exact: None,
            regex: Some(&"_0x[a-fA-F0-9]{4}".to_string()),
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 5,
            search_raw: true,
        };
        let result = eval_string(&params, &ctx);
        assert!(
            !result.matched,
            "Should NOT match when count (2) < min_count (5)"
        );
        assert!(result.evidence.is_empty());
    }

    #[test]
    fn test_search_raw_regex_matches_exactly_at_threshold() {
        // Test edge case: count exactly equals min_count
        let content = b"_0xAAAA _0xBBBB _0xCCCC";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: content,
            file_type: FileType::JavaScript,
            platform: Platform::All,
        };

        // With min_count: 3, should match (we have exactly 3)
        let params = StringParams {
            exact: None,
            regex: Some(&"_0x[A-F]{4}".to_string()),
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 3,
            search_raw: true,
        };
        let result = eval_string(&params, &ctx);
        assert!(
            result.matched,
            "Should match when count (3) == min_count (3)"
        );
    }

    #[test]
    fn test_search_raw_exact_string_counting() {
        // Test that search_raw: true with exact string counts all occurrences
        let content = b"console.log('test'); console.log('hello'); console.log('world');";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: content,
            file_type: FileType::JavaScript,
            platform: Platform::All,
        };

        // With min_count: 2, should match (we have 3 occurrences of "console.log")
        let params = StringParams {
            exact: Some(&"console.log".to_string()),
            regex: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 2,
            search_raw: true,
        };
        let result = eval_string(&params, &ctx);
        assert!(
            result.matched,
            "Should match when exact string count (3) >= min_count (2)"
        );
        assert!(result.evidence[0].value.contains("Found 3"));
    }

    #[test]
    fn test_search_raw_exact_string_no_match_below_threshold() {
        // Test that exact string doesn't match when count < min_count
        let content = b"hello world";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: content,
            file_type: FileType::JavaScript,
            platform: Platform::All,
        };

        // With min_count: 5, should NOT match (we only have 1 occurrence)
        let params = StringParams {
            exact: Some(&"hello".to_string()),
            regex: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 5,
            search_raw: true,
        };
        let result = eval_string(&params, &ctx);
        assert!(
            !result.matched,
            "Should NOT match when count (1) < min_count (5)"
        );
    }

    #[test]
    fn test_search_raw_case_insensitive_regex() {
        // Test that case_insensitive works with search_raw
        let content = b"_0xabcd _0xABCD _0xAbCd";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: content,
            file_type: FileType::JavaScript,
            platform: Platform::All,
        };

        // Case insensitive should match all 3
        let params = StringParams {
            exact: None,
            regex: Some(&"_0x[a-f]{4}".to_string()),
            case_insensitive: true,
            exclude_patterns: None,
            min_count: 3,
            search_raw: true,
        };
        let result = eval_string(&params, &ctx);
        assert!(
            result.matched,
            "Case insensitive should match all variations"
        );
    }

    #[test]
    fn test_search_raw_case_insensitive_exact() {
        // Test that case_insensitive works with exact string in search_raw
        let content = b"ERROR error Error ERROR";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: content,
            file_type: FileType::JavaScript,
            platform: Platform::All,
        };

        // Case insensitive should count all 4 occurrences
        let params = StringParams {
            exact: Some(&"error".to_string()),
            regex: None,
            case_insensitive: true,
            exclude_patterns: None,
            min_count: 4,
            search_raw: true,
        };
        let result = eval_string(&params, &ctx);
        assert!(
            result.matched,
            "Case insensitive exact should match all 4 variations"
        );
    }

    #[test]
    fn test_search_raw_false_does_not_count_raw_content() {
        // Test that search_raw: false (default) doesn't count raw content occurrences
        // It should only match extracted strings, not count occurrences in raw data
        let content = b"_0x1111 _0x2222 _0x3333 _0x4444 _0x5555";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: content,
            file_type: FileType::JavaScript,
            platform: Platform::All,
        };

        // With search_raw: false and min_count: 3, behavior is different
        // It only matches if the pattern appears in extracted strings (report.strings)
        // Since report.strings is empty, we get at most 1 match from source code search
        let params = StringParams {
            exact: None,
            regex: Some(&"_0x[0-9]{4}".to_string()),
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 3,
            search_raw: false,
        };
        let result = eval_string(&params, &ctx);
        // Should NOT match because default behavior finds first match, not all
        assert!(
            !result.matched,
            "search_raw: false should not count all occurrences"
        );
    }

    #[test]
    fn test_search_raw_with_hex_literal_pattern() {
        // Test realistic hex literal density detection (like js-obfuscator)
        let content = b"var a = 0x1234 + 0x5678 - 0xABCD * 0xDEF0 / 0x1111;
                       var b = 0x2222 + 0x3333 - 0x4444 * 0x5555 / 0x6666;";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: content,
            file_type: FileType::JavaScript,
            platform: Platform::All,
        };

        // Pattern for hex literals: 0x followed by hex digits
        let params = StringParams {
            exact: None,
            regex: Some(&"0x[a-fA-F0-9]+".to_string()),
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 10,
            search_raw: true,
        };
        let result = eval_string(&params, &ctx);
        assert!(result.matched, "Should detect 10 hex literals");
        assert!(result.evidence[0].value.contains("Found 10"));
    }

    #[test]
    fn test_search_raw_evidence_includes_first_match_example() {
        // Test that evidence includes an example of the matched pattern
        let content = b"_0xDEAD _0xBEEF _0xCAFE";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: content,
            file_type: FileType::JavaScript,
            platform: Platform::All,
        };

        let params = StringParams {
            exact: None,
            regex: Some(&"_0x[A-F]{4}".to_string()),
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 2,
            search_raw: true,
        };
        let result = eval_string(&params, &ctx);
        assert!(result.matched);
        // Evidence should include "Found 3" and an example like "_0xDEAD"
        let evidence_value = &result.evidence[0].value;
        assert!(evidence_value.contains("Found 3"));
        assert!(
            evidence_value.contains("_0x"),
            "Should include example match: {}",
            evidence_value
        );
    }

    #[test]
    fn test_search_raw_with_composite_rule() {
        // Test search_raw through CompositeTrait evaluation
        let content = b"_0xAAAA _0xBBBB _0xCCCC _0xDDDD _0xEEEE";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: content,
            file_type: FileType::JavaScript,
            platform: Platform::All,
        };

        let rule = CompositeTrait {
            id: "anti-analysis/obfuscation/js-obfuscator".to_string(),
            description: "JavaScript obfuscator detection".to_string(),
            confidence: 0.95,
            criticality: Criticality::Suspicious,
            mbc: None,
            attack: Some("T1027".to_string()),
            platforms: vec![Platform::All],
            file_types: vec![FileType::JavaScript],
            requires_all: Some(vec![Condition::String {
                exact: None,
                regex: Some("_0x[A-F]{4}".to_string()),
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 5,
                search_raw: true,
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some(), "CompositeTrait should match");
        let cap = result.unwrap();
        assert_eq!(cap.id, "anti-analysis/obfuscation/js-obfuscator");
        assert_eq!(cap.criticality, Criticality::Suspicious);
    }

    #[test]
    fn test_search_raw_with_trait_definition() {
        // Test search_raw through TraitDefinition evaluation
        let content = b"0x1234 0x5678 0xABCD 0xDEF0 0x1111 0x2222";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: content,
            file_type: FileType::JavaScript,
            platform: Platform::All,
        };

        let trait_def = TraitDefinition {
            id: "hex-literal-density".to_string(),
            description: "High density of hex literals".to_string(),
            confidence: 0.85,
            criticality: Criticality::Suspicious,
            mbc: None,
            attack: Some("T1027".to_string()),
            platforms: vec![Platform::All],
            file_types: vec![FileType::JavaScript],
            condition: Condition::String {
                exact: None,
                regex: Some("0x[a-fA-F0-9]+".to_string()),
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 5,
                search_raw: true,
            },
        };

        // Evaluate the trait definition directly
        let result = trait_def.evaluate(&ctx);
        assert!(result.is_some(), "TraitDefinition should match");
        let detected_trait = result.unwrap();
        assert_eq!(detected_trait.id, "hex-literal-density");
        assert_eq!(detected_trait.criticality, Criticality::Suspicious);
        assert!(!detected_trait.evidence.is_empty());
    }

    #[test]
    fn test_search_raw_no_match_with_zero_occurrences() {
        // Test that no match occurs when pattern doesn't exist in content
        let content = b"normal javascript code without obfuscation";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: content,
            file_type: FileType::JavaScript,
            platform: Platform::All,
        };

        let params = StringParams {
            exact: None,
            regex: Some(&"_0x[a-fA-F0-9]+".to_string()),
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            search_raw: true,
        };
        let result = eval_string(&params, &ctx);
        assert!(!result.matched, "Should not match when pattern not found");
    }

    #[test]
    fn test_search_raw_min_count_one_matches_single_occurrence() {
        // Test that min_count: 1 matches a single occurrence
        let content = b"var secret = _0xDEAD;";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: content,
            file_type: FileType::JavaScript,
            platform: Platform::All,
        };

        let params = StringParams {
            exact: None,
            regex: Some(&"_0x[A-F0-9]+".to_string()),
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            search_raw: true,
        };
        let result = eval_string(&params, &ctx);
        assert!(
            result.matched,
            "min_count: 1 should match single occurrence"
        );
        assert!(result.evidence[0].value.contains("Found 1"));
    }

    #[test]
    fn test_search_raw_invalid_utf8_gracefully_handled() {
        // Test that invalid UTF-8 content doesn't cause panic
        let content: &[u8] = &[0xFF, 0xFE, 0x00, 0x01]; // Invalid UTF-8
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: content,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let params = StringParams {
            exact: None,
            regex: Some(&"test".to_string()),
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            search_raw: true,
        };
        let result = eval_string(&params, &ctx);
        // Should not panic, just not match
        assert!(!result.matched);
    }

    #[test]
    fn test_search_raw_yaml_parsing() {
        // Test that search_raw and min_count are correctly parsed from YAML
        let yaml = r#"
traits:
  - id: obfuscator-variable-names
    description: JavaScript obfuscator tool signature
    criticality: suspicious
    confidence: 0.95
    attack: "T1027"
    file_types: [javascript]
    condition:
      type: string
      regex: "_0x[a-fA-F0-9]{4,8}"
      min_count: 10
      search_raw: true
"#;

        #[derive(Debug, serde::Deserialize)]
        struct TraitFile {
            traits: Vec<TraitDefinition>,
        }

        let parsed: TraitFile = serde_yaml::from_str(yaml).expect("YAML should parse");
        assert_eq!(parsed.traits.len(), 1);

        let trait_def = &parsed.traits[0];
        assert_eq!(trait_def.id, "obfuscator-variable-names");
        assert_eq!(trait_def.criticality, Criticality::Suspicious);

        // Verify the condition parsed correctly
        if let Condition::String {
            regex,
            min_count,
            search_raw,
            ..
        } = &trait_def.condition
        {
            assert_eq!(regex.as_ref().unwrap(), "_0x[a-fA-F0-9]{4,8}");
            assert_eq!(*min_count, 10);
            assert!(*search_raw, "search_raw should be true");
        } else {
            panic!("Expected String condition");
        }
    }

    #[test]
    fn test_search_raw_yaml_default_false() {
        // Test that search_raw defaults to false when not specified
        let yaml = r#"
traits:
  - id: simple-string
    description: Simple string match
    criticality: notable
    condition:
      type: string
      exact: "test"
"#;

        #[derive(Debug, serde::Deserialize)]
        struct TraitFile {
            traits: Vec<TraitDefinition>,
        }

        let parsed: TraitFile = serde_yaml::from_str(yaml).expect("YAML should parse");
        let trait_def = &parsed.traits[0];

        if let Condition::String {
            min_count,
            search_raw,
            ..
        } = &trait_def.condition
        {
            assert_eq!(*min_count, 1, "min_count should default to 1");
            assert!(!*search_raw, "search_raw should default to false");
        } else {
            panic!("Expected String condition");
        }
    }

    #[test]
    fn test_search_raw_end_to_end_yaml_to_detection() {
        // Test the full pipeline: YAML -> TraitDefinition -> evaluation -> detection
        let yaml = r#"
traits:
  - id: test-hex-density
    description: Test hex density detection
    criticality: suspicious
    attack: "T1027"
    file_types: [javascript]
    condition:
      type: string
      regex: "0x[0-9A-F]+"
      min_count: 3
      search_raw: true
"#;

        #[derive(Debug, serde::Deserialize)]
        struct TraitFile {
            traits: Vec<TraitDefinition>,
        }

        let parsed: TraitFile = serde_yaml::from_str(yaml).expect("YAML should parse");
        let trait_def = &parsed.traits[0];

        // Content with 5 hex literals - should match min_count: 3
        let content =
            b"var a = 0x1234; var b = 0xABCD; var c = 0xDEF0; var d = 0x5678; var e = 0x9999;";
        let (report, _) = create_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: content,
            file_type: FileType::JavaScript,
            platform: Platform::All,
        };

        let result = trait_def.evaluate(&ctx);
        assert!(
            result.is_some(),
            "YAML-parsed trait should detect hex patterns"
        );
        let detected = result.unwrap();
        assert_eq!(detected.id, "test-hex-density");
        assert!(
            detected.evidence[0].value.contains("Found 5"),
            "Should detect 5 hex literals: {}",
            detected.evidence[0].value
        );
    }

    // ============== Syscall Condition Tests ==============

    fn create_syscall_test_context() -> (AnalysisReport, Vec<u8>) {
        let target = TargetInfo {
            path: "/test/binary".to_string(),
            file_type: "elf".to_string(),
            size_bytes: 1024,
            sha256: "test".to_string(),
            architectures: Some(vec!["mips".to_string()]),
        };

        let mut report = AnalysisReport::new(target);

        // Add some syscalls (simulating MIPS malware syscalls)
        report.syscalls.push(SyscallInfo {
            address: 0x1000,
            number: 4001,
            name: "exit".to_string(),
            description: "terminates process".to_string(),
            arch: "mips".to_string(),
        });
        report.syscalls.push(SyscallInfo {
            address: 0x1100,
            number: 4039,
            name: "mkdir".to_string(),
            description: "creates directory".to_string(),
            arch: "mips".to_string(),
        });
        report.syscalls.push(SyscallInfo {
            address: 0x1200,
            number: 4120,
            name: "clone".to_string(),
            description: "creates process or thread".to_string(),
            arch: "mips".to_string(),
        });
        report.syscalls.push(SyscallInfo {
            address: 0x1300,
            number: 4183,
            name: "socket".to_string(),
            description: "creates network socket".to_string(),
            arch: "mips".to_string(),
        });
        report.syscalls.push(SyscallInfo {
            address: 0x1400,
            number: 4185,
            name: "connect".to_string(),
            description: "connects to remote host".to_string(),
            arch: "mips".to_string(),
        });

        (report, vec![])
    }

    #[test]
    fn test_syscall_condition_match_by_name() {
        let (report, data) = create_syscall_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "syscall/network".to_string(),
            description: "Network syscalls".to_string(),
            confidence: 0.9,
            criticality: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::Elf],
            requires_all: Some(vec![Condition::Syscall {
                name: Some(vec!["socket".to_string(), "connect".to_string()]),
                number: None,
                arch: None,
                min_count: Some(2),
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some(), "Should match syscalls by name");
        let cap = result.unwrap();
        assert_eq!(cap.evidence.len(), 2);
    }

    #[test]
    fn test_syscall_condition_match_by_number() {
        let (report, data) = create_syscall_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "syscall/mips-socket".to_string(),
            description: "MIPS socket syscall".to_string(),
            confidence: 0.9,
            criticality: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::Elf],
            requires_all: Some(vec![Condition::Syscall {
                name: None,
                number: Some(vec![4183]), // MIPS socket syscall number
                arch: None,
                min_count: None,
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some(), "Should match syscall by number");
        let cap = result.unwrap();
        assert!(cap.evidence[0].value.contains("socket"));
    }

    #[test]
    fn test_syscall_condition_match_by_arch() {
        let (report, data) = create_syscall_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "syscall/mips-any".to_string(),
            description: "Any MIPS syscall".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::Elf],
            requires_all: Some(vec![Condition::Syscall {
                name: None,
                number: None,
                arch: Some(vec!["mips".to_string()]),
                min_count: Some(3),
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_some(), "Should match MIPS syscalls with min_count");
        let cap = result.unwrap();
        assert!(cap.evidence.len() >= 3);
    }

    #[test]
    fn test_syscall_condition_no_match() {
        let (report, data) = create_syscall_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "syscall/x86".to_string(),
            description: "x86 syscalls".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::Elf],
            requires_all: Some(vec![Condition::Syscall {
                name: None,
                number: None,
                arch: Some(vec!["x86_64".to_string()]),
                min_count: None,
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_none(), "Should not match x86_64 syscalls in MIPS binary");
    }

    #[test]
    fn test_syscall_condition_min_count_not_met() {
        let (report, data) = create_syscall_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let rule = CompositeTrait {
            id: "syscall/many".to_string(),
            description: "Many syscalls".to_string(),
            confidence: 0.9,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            file_types: vec![FileType::Elf],
            requires_all: Some(vec![Condition::Syscall {
                name: None,
                number: None,
                arch: None,
                min_count: Some(100), // More than we have
            }]),
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
        };

        let result = rule.evaluate(&ctx);
        assert!(result.is_none(), "Should not match when min_count not met");
    }

    #[test]
    fn test_syscall_yaml_parsing() {
        // Test atomic trait (TraitDefinition) with syscall condition
        #[derive(Deserialize)]
        struct AtomicTraitFile {
            traits: Vec<TraitDefinition>,
        }

        let yaml = r#"
traits:
  - id: syscall/clone
    description: Clone syscall detected
    confidence: 0.9
    criticality: notable
    platforms: [linux]
    file_types: [elf]
    condition:
      type: syscall
      name: ["clone"]
"#;
        let parsed: AtomicTraitFile = serde_yaml::from_str(yaml).expect("YAML should parse");
        assert_eq!(parsed.traits.len(), 1);

        let (report, data) = create_syscall_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let result = parsed.traits[0].evaluate(&ctx);
        assert!(result.is_some(), "Parsed syscall trait should match");
    }

    #[test]
    fn test_syscall_composite_yaml_parsing() {
        // Test composite trait (CompositeTrait) with requires_all syscalls
        #[derive(Deserialize)]
        struct CompositeTraitFile {
            traits: Vec<CompositeTrait>,
        }

        let yaml = r#"
traits:
  - id: syscall/daemon
    description: Daemon behavior via syscalls
    confidence: 0.9
    criticality: notable
    platforms: [linux]
    file_types: [elf]
    requires_all:
      - type: syscall
        name: ["clone", "exit"]
        min_count: 2
"#;
        let parsed: CompositeTraitFile = serde_yaml::from_str(yaml).expect("YAML should parse");
        assert_eq!(parsed.traits.len(), 1);

        let (report, data) = create_syscall_test_context();
        let ctx = EvaluationContext {
            report: &report,
            binary_data: &data,
            file_type: FileType::Elf,
            platform: Platform::Linux,
        };

        let result = parsed.traits[0].evaluate(&ctx);
        assert!(result.is_some(), "Parsed composite syscall trait should match");
    }
}
