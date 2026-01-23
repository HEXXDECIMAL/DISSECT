//! Trait definitions for composite rules.
//!
//! This module contains TraitDefinition (atomic traits) and CompositeTrait
//! (boolean combinations of conditions).

use super::condition::Condition;
use super::context::{ConditionResult, EvaluationContext, StringParams};
use super::evaluators::{
    eval_ast_pattern, eval_ast_query, eval_exports_count, eval_import_combination,
    eval_imports_count, eval_section_entropy, eval_section_ratio, eval_string, eval_string_count,
    eval_structure, eval_symbol, eval_symbol_or_string, eval_syscall, eval_yara_inline,
    eval_yara_match,
};
use super::types::{default_file_types, default_platforms, FileType, Platform};
use crate::types::{Criticality, Evidence, Finding, FindingKind};
use regex::Regex;
use serde::Deserialize;

fn default_confidence() -> f32 {
    1.0
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

impl TraitDefinition {
    /// Pre-compile YARA rules in this trait's condition
    pub fn compile_yara(&mut self) {
        self.condition.compile_yara();
    }

    /// Evaluate this trait definition against the analysis context
    pub fn evaluate(&self, ctx: &EvaluationContext) -> Option<Finding> {
        // Check if this trait applies to the current platform/file type
        if !self.matches_target(ctx) {
            return None;
        }

        // Evaluate the condition (traits only have one atomic condition)
        let result = self.eval_condition(&self.condition, ctx);

        // Debug: trace evaluation result for eco/npm traits
        if self.id.contains("eco/npm/metadata/vscode") {
            eprintln!(
                "DEBUG evaluate: {} result.matched={} evidence_count={}",
                self.id, result.matched, result.evidence.len()
            );
        }

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
        let platform_match = self.platforms.contains(&Platform::All)
            || ctx.platform == Platform::All
            || self.platforms.contains(&ctx.platform);

        let file_type_match = self.file_types.contains(&FileType::All)
            || ctx.file_type == FileType::All
            || self.file_types.contains(&ctx.file_type);

        // Debug: print trait file type matching for packagejson
        if self.id.contains("eco/npm") {
            eprintln!(
                "DEBUG: trait {} file_types={:?} ctx.file_type={:?} match={}",
                self.id, self.file_types, ctx.file_type, file_type_match
            );
        }

        platform_match && file_type_match
    }

    /// Evaluate a single condition
    fn eval_condition(&self, condition: &Condition, ctx: &EvaluationContext) -> ConditionResult {
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
            Condition::AstQuery { query, .. } => eval_ast_query(query, ctx),
            Condition::Yara { source, compiled } => {
                eval_yara_inline(source, compiled.as_ref(), ctx)
            }
            Condition::Syscall {
                name,
                number,
                arch,
                min_count,
            } => eval_syscall(
                name.as_ref(),
                number.as_ref(),
                arch.as_ref(),
                *min_count,
                ctx,
            ),
            Condition::SectionRatio {
                section,
                compare_to,
                min_ratio,
                max_ratio,
            } => eval_section_ratio(section, compare_to, *min_ratio, *max_ratio, ctx),
            Condition::SectionEntropy {
                section,
                min_entropy,
                max_entropy,
            } => eval_section_entropy(section, *min_entropy, *max_entropy, ctx),
            Condition::ImportCombination {
                required,
                suspicious,
                min_suspicious,
                max_total,
            } => eval_import_combination(
                required.as_ref(),
                suspicious.as_ref(),
                *min_suspicious,
                *max_total,
                ctx,
            ),
            Condition::StringCount {
                min,
                max,
                min_length,
            } => eval_string_count(*min, *max, *min_length, ctx),
        }
    }
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

impl CompositeTrait {
    /// Pre-compile YARA rules in all conditions
    pub fn compile_yara(&mut self) {
        if let Some(ref mut conditions) = self.requires_all {
            for cond in conditions.iter_mut() {
                cond.compile_yara();
            }
        }
        if let Some(ref mut conditions) = self.requires_any {
            for cond in conditions.iter_mut() {
                cond.compile_yara();
            }
        }
        if let Some(ref mut conditions) = self.conditions {
            for cond in conditions.iter_mut() {
                cond.compile_yara();
            }
        }
        if let Some(ref mut conditions) = self.requires_none {
            for cond in conditions.iter_mut() {
                cond.compile_yara();
            }
        }
    }

    /// Evaluate this rule against the analysis context
    pub fn evaluate(&self, ctx: &EvaluationContext) -> Option<Finding> {
        // Check if this rule applies to the current platform/file type
        if !self.matches_target(ctx) {
            return None;
        }

        // Evaluate conditions based on the boolean operator(s)
        // Support combined requires_all + requires_any (both must be satisfied)
        let result = if self.requires_all.is_some() && self.requires_any.is_some() {
            // Both requires_all AND requires_any: all must match AND any must match
            let all_result = self.eval_requires_all(self.requires_all.as_ref().unwrap(), ctx);
            if !all_result.matched {
                return None;
            }
            let any_result = self.eval_requires_any(self.requires_any.as_ref().unwrap(), ctx);
            if !any_result.matched {
                return None;
            }
            // Combine evidence from both
            let mut combined_evidence = all_result.evidence;
            combined_evidence.extend(any_result.evidence);
            ConditionResult {
                matched: true,
                evidence: combined_evidence,
                traits: Vec::new(),
            }
        } else if let Some(ref conditions) = self.requires_all {
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
        let platform_match = self.platforms.contains(&Platform::All)
            || ctx.platform == Platform::All
            || self.platforms.contains(&ctx.platform);

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
            Condition::AstQuery { query, .. } => eval_ast_query(query, ctx),
            Condition::Yara { source, compiled } => {
                eval_yara_inline(source, compiled.as_ref(), ctx)
            }
            Condition::Syscall {
                name,
                number,
                arch,
                min_count,
            } => eval_syscall(
                name.as_ref(),
                number.as_ref(),
                arch.as_ref(),
                *min_count,
                ctx,
            ),
            Condition::SectionRatio {
                section,
                compare_to,
                min_ratio,
                max_ratio,
            } => eval_section_ratio(section, compare_to, *min_ratio, *max_ratio, ctx),
            Condition::SectionEntropy {
                section,
                min_entropy,
                max_entropy,
            } => eval_section_entropy(section, *min_entropy, *max_entropy, ctx),
            Condition::ImportCombination {
                required,
                suspicious,
                min_suspicious,
                max_total,
            } => eval_import_combination(
                required.as_ref(),
                suspicious.as_ref(),
                *min_suspicious,
                *max_total,
                ctx,
            ),
            Condition::StringCount {
                min,
                max,
                min_length,
            } => eval_string_count(*min, *max, *min_length, ctx),
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

        eval_symbol(pattern, None, ctx)
    }

    /// Evaluate YARA match condition
    fn eval_yara_match(
        &self,
        namespace: &str,
        rule: Option<&String>,
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        eval_yara_match(namespace, rule, ctx)
    }

    /// Evaluate structure condition
    fn eval_structure(
        &self,
        feature: &str,
        min_sections: Option<usize>,
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        eval_structure(feature, min_sections, ctx)
    }

    /// Evaluate symbol OR string condition
    fn eval_symbol_or_string(
        &self,
        patterns: &[String],
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        eval_symbol_or_string(patterns, ctx)
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
