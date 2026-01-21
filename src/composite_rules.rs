use crate::types::{AnalysisReport, Capability, Criticality, Evidence, Trait};
use anyhow::Result;
use regex::Regex;
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
    Elf,
    Macho,
    Pe,
    Dylib,
    So,
    Dll,
    ShellScript,
    Python,
    JavaScript,
    Rust,
    Java,
    Ruby,
    C,
    Go,
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

    /// If true, also emit this trait as a capability
    #[serde(default)]
    pub capability: bool,

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
    pub fn evaluate(&self, ctx: &EvaluationContext) -> Option<Capability> {
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
            Some(Capability {
                id: self.id.clone(),
                description: self.description.clone(),
                confidence: self.confidence,
                criticality: self.criticality,
                mbc: self.mbc.clone(),
                attack: self.attack.clone(),
                evidence: result.evidence,
                traits: result.traits,
                referenced_paths: None,
                referenced_directories: None,
            })
        } else {
            None
        }
    }

    /// Check if rule applies to current platform/file type
    fn matches_target(&self, ctx: &EvaluationContext) -> bool {
        let platform_match =
            self.platforms.contains(&Platform::All) || self.platforms.contains(&ctx.platform);

        let file_type_match =
            self.file_types.contains(&FileType::All) || self.file_types.contains(&ctx.file_type);

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
            } => self.eval_string(
                exact.as_ref(),
                regex.as_ref(),
                *case_insensitive,
                exclude_patterns.as_ref(),
                *min_count,
                ctx,
            ),
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

    /// Evaluate string condition
    fn eval_string(
        &self,
        exact: Option<&String>,
        regex: Option<&String>,
        case_insensitive: bool,
        exclude_patterns: Option<&Vec<String>>,
        min_count: usize,
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        let mut evidence = Vec::new();

        // Check in extracted strings from report
        for string_info in &ctx.report.strings {
            let mut matched = false;

            if let Some(exact_str) = exact {
                matched = if case_insensitive {
                    string_info
                        .value
                        .to_lowercase()
                        .contains(&exact_str.to_lowercase())
                } else {
                    string_info.value.contains(exact_str)
                };
            } else if let Some(regex_pattern) = regex {
                if let Ok(re) = build_regex(regex_pattern, case_insensitive) {
                    matched = re.is_match(&string_info.value);
                }
            }

            if matched {
                // Check exclusion patterns
                if let Some(excludes) = exclude_patterns {
                    let mut excluded = false;
                    for exclude_pattern in excludes {
                        if let Ok(re) = Regex::new(exclude_pattern) {
                            if re.is_match(&string_info.value) {
                                excluded = true;
                                break;
                            }
                        }
                    }
                    if excluded {
                        continue;
                    }
                }

                evidence.push(Evidence {
                    method: "string".to_string(),
                    source: "string_extractor".to_string(),
                    value: string_info.value.clone(),
                    location: string_info.offset.clone(),
                });
            }
        }

        ConditionResult {
            matched: evidence.len() >= min_count,
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

            let rule_match = rule.map_or(true, |r| &yara_match.rule == r);

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
            let string_result = self.eval_string(Some(pattern), None, false, None, 1, ctx);
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
            // Count only imports matching filter
            ctx.report
                .imports
                .iter()
                .filter(|imp| {
                    if let Ok(re) = Regex::new(filter_pattern) {
                        re.is_match(&imp.symbol)
                    } else {
                        false
                    }
                })
                .count()
        } else {
            ctx.report.imports.len()
        };

        let matched = min.map_or(true, |m| count >= m) && max.map_or(true, |m| count <= m);

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
        let matched = min.map_or(true, |m| count >= m) && max.map_or(true, |m| count <= m);

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
    pub fn evaluate(&self, ctx: &EvaluationContext) -> Option<Trait> {
        // Check if this trait applies to the current platform/file type
        if !self.matches_target(ctx) {
            return None;
        }

        // Evaluate the condition (traits only have one atomic condition)
        let result = self.eval_condition(&self.condition, ctx);

        if result.matched {
            Some(Trait {
                id: self.id.clone(),
                description: self.description.clone(),
                confidence: self.confidence,
                criticality: self.criticality,
                capability: true, // Composite rules detect capabilities
                mbc: self.mbc.clone(),
                attack: self.attack.clone(),
                language: None,
                platforms: Vec::new(),
                evidence: result.evidence,
                referenced_paths: None,
                referenced_directories: None,
            })
        } else {
            None
        }
    }

    /// Check if trait applies to current platform/file type
    fn matches_target(&self, ctx: &EvaluationContext) -> bool {
        let platform_match =
            self.platforms.contains(&Platform::All) || self.platforms.contains(&ctx.platform);

        let file_type_match =
            self.file_types.contains(&FileType::All) || self.file_types.contains(&ctx.file_type);

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
            } => eval_string(
                exact.as_ref(),
                regex.as_ref(),
                *case_insensitive,
                exclude_patterns.as_ref(),
                *min_count,
                ctx,
            ),
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

fn eval_string(
    exact: Option<&String>,
    regex: Option<&String>,
    case_insensitive: bool,
    exclude_patterns: Option<&Vec<String>>,
    min_count: usize,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let mut evidence = Vec::new();

    // Check in extracted strings from report (for binaries)
    for string_info in &ctx.report.strings {
        let mut matched = false;

        if let Some(exact_str) = exact {
            matched = if case_insensitive {
                string_info
                    .value
                    .to_lowercase()
                    .contains(&exact_str.to_lowercase())
            } else {
                string_info.value.contains(exact_str)
            };
        } else if let Some(regex_pattern) = regex {
            if let Ok(re) = build_regex(regex_pattern, case_insensitive) {
                matched = re.is_match(&string_info.value);
            }
        }

        if matched {
            // Check exclusion patterns
            if let Some(excludes) = exclude_patterns {
                let mut excluded = false;
                for exclude_pattern in excludes {
                    if let Ok(re) = Regex::new(exclude_pattern) {
                        if re.is_match(&string_info.value) {
                            excluded = true;
                            break;
                        }
                    }
                }
                if excluded {
                    continue;
                }
            }

            evidence.push(Evidence {
                method: "string".to_string(),
                source: "string_extractor".to_string(),
                value: string_info.value.clone(),
                location: string_info.offset.clone(),
            });
        }
    }

    // For source files or when no strings were extracted, search binary_data directly
    if ctx.report.strings.is_empty()
        || matches!(
            ctx.file_type,
            FileType::Python | FileType::Ruby | FileType::JavaScript | FileType::ShellScript
        )
    {
        // Convert binary data to string for source code matching
        if let Ok(content) = std::str::from_utf8(ctx.binary_data) {
            let mut matched = false;
            let mut match_value = String::new();

            if let Some(exact_str) = exact {
                matched = if case_insensitive {
                    content.to_lowercase().contains(&exact_str.to_lowercase())
                } else {
                    content.contains(exact_str)
                };
                if matched {
                    match_value = exact_str.clone();
                }
            } else if let Some(regex_pattern) = regex {
                if let Ok(re) = build_regex(regex_pattern, case_insensitive) {
                    if let Some(mat) = re.find(content) {
                        matched = true;
                        match_value = mat.as_str().to_string();
                    }
                }
            }

            if matched {
                // Check exclusion patterns
                if let Some(excludes) = exclude_patterns {
                    let mut excluded = false;
                    for exclude_pattern in excludes {
                        if let Ok(re) = Regex::new(exclude_pattern) {
                            if re.is_match(&match_value) {
                                excluded = true;
                                break;
                            }
                        }
                    }
                    if !excluded {
                        evidence.push(Evidence {
                            method: "string".to_string(),
                            source: "source_code".to_string(),
                            value: match_value,
                            location: Some("file".to_string()),
                        });
                    }
                } else {
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
        matched: evidence.len() >= min_count,
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

        let rule_match = rule.map_or(true, |r| &yara_match.rule == r);

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
        let string_result = eval_string(Some(pattern), None, false, None, 1, ctx);
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

    let matched = min.map_or(true, |m| count >= m) && max.map_or(true, |m| count <= m);

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
    let matched = min.map_or(true, |m| count >= m) && max.map_or(true, |m| count <= m);

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

#[cfg(test)]
mod tests {
    use super::*;
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
}
