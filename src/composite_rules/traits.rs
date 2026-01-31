//! Trait definitions for composite rules.
//!
//! This module contains TraitDefinition (atomic traits) and CompositeTrait
//! (boolean combinations of conditions).

use super::condition::{Condition, NotException};
use super::context::{ConditionResult, EvaluationContext, StringParams};
use super::evaluators::{
    eval_ast, eval_ast_pattern, eval_ast_query, eval_base64, eval_exports_count, eval_filesize,
    eval_hex, eval_import_combination, eval_imports_count, eval_metrics, eval_raw,
    eval_section_entropy, eval_section_name, eval_section_ratio, eval_string, eval_string_count,
    eval_structure, eval_symbol, eval_syscall, eval_trait, eval_trait_glob, eval_xor,
    eval_yara_inline, eval_yara_match,
};
use super::types::{default_file_types, default_platforms, FileType, Platform};
use crate::types::{Criticality, Evidence, Finding, FindingKind};
use regex::Regex;
use serde::Deserialize;

fn default_confidence() -> f32 {
    1.0
}

/// Conditions for a downgrade level (supports composite syntax)
#[derive(Debug, Clone, Deserialize)]
pub struct DowngradeConditions {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub any: Option<Vec<Condition>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub all: Option<Vec<Condition>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub none: Option<Vec<Condition>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub count_exact: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub count_min: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub count_max: Option<usize>,
}

/// Downgrade rules: criticality level → conditions that trigger downgrade
#[derive(Debug, Clone, Deserialize)]
pub struct DowngradeRules {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hostile: Option<DowngradeConditions>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub suspicious: Option<DowngradeConditions>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub notable: Option<DowngradeConditions>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub inert: Option<DowngradeConditions>,
}

/// Definition of an atomic observable trait
#[derive(Debug, Clone, Deserialize)]
pub struct TraitDefinition {
    pub id: String,
    #[serde(alias = "description")]
    pub desc: String,
    #[serde(default = "default_confidence", alias = "confidence")]
    pub conf: f32,

    /// Criticality level (defaults to None = internal only)
    #[serde(default, alias = "criticality")]
    pub crit: Criticality,

    /// MBC (Malware Behavior Catalog) ID - most specific available (e.g., "B0015.001")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mbc: Option<String>,

    /// MITRE ATT&CK Technique ID (e.g., "T1056.001")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attack: Option<String>,

    #[serde(default = "default_platforms")]
    pub platforms: Vec<Platform>,

    #[serde(default = "default_file_types", alias = "file_types", alias = "files")]
    pub r#for: Vec<FileType>,

    /// Minimum file size in bytes
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size_min: Option<usize>,

    /// Maximum file size in bytes
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size_max: Option<usize>,

    // Detection condition - just one condition per trait (atomic!)
    #[serde(alias = "condition")]
    pub r#if: Condition,

    /// String-level exceptions - filter matched strings
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub not: Option<Vec<NotException>>,

    /// File-level skip conditions - composite rule that skips trait if matched
    /// Default semantics: skip if ANY condition matches (unless: [list])
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub unless: Option<Vec<Condition>>,

    /// Criticality downgrade rules - map of target criticality to conditions
    /// Only levels LOWER than base `crit` are allowed (validated at load time)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub downgrade: Option<DowngradeRules>,
}

impl TraitDefinition {
    /// Pre-compile YARA rules in this trait's condition
    pub fn compile_yara(&mut self) {
        self.r#if.compile_yara();
    }

    /// Evaluate this trait definition against the analysis context
    pub fn evaluate(&self, ctx: &EvaluationContext) -> Option<Finding> {
        // Check if this trait applies to the current platform/file type
        if !self.matches_target(ctx) {
            return None;
        }

        // Check size constraints
        if !self.matches_size(ctx) {
            return None;
        }

        // Check unless conditions (file-level skip)
        if let Some(unless_conds) = &self.unless {
            // Default 'any' semantics: skip if ANY condition matches
            for condition in unless_conds {
                let result = self.eval_condition(condition, ctx);
                if result.matched {
                    // Skip this trait - condition matched
                    return None;
                }
            }
        }

        // Evaluate the condition (traits only have one atomic condition)
        let result = self.eval_condition(&self.r#if, ctx);

        // Debug: trace evaluation result for eco/npm traits
        if self.id.contains("eco/npm/metadata/vscode") {
            eprintln!(
                "DEBUG evaluate: {} result.matched={} evidence_count={}",
                self.id,
                result.matched,
                result.evidence.len()
            );
        }

        if result.matched {
            let mut final_crit = self.crit;

            // Check downgrade conditions
            if let Some(downgrade_rules) = &self.downgrade {
                final_crit = self.evaluate_downgrade(downgrade_rules, &self.crit, ctx);
            }

            Some(Finding {
                id: self.id.clone(),
                kind: FindingKind::Capability,
                desc: self.desc.clone(),
                conf: self.conf,
                crit: final_crit,
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

        let file_type_match = self.r#for.contains(&FileType::All)
            || ctx.file_type == FileType::All
            || self.r#for.contains(&ctx.file_type);

        platform_match && file_type_match
    }

    /// Check if rule matches size constraints
    fn matches_size(&self, ctx: &EvaluationContext) -> bool {
        let file_size = ctx.report.target.size_bytes as usize;

        if let Some(min) = self.size_min {
            if file_size < min {
                return false;
            }
        }

        if let Some(max) = self.size_max {
            if file_size > max {
                return false;
            }
        }

        true
    }

    /// Evaluate downgrade rules and return final criticality
    fn evaluate_downgrade(
        &self,
        rules: &DowngradeRules,
        base_crit: &Criticality,
        ctx: &EvaluationContext,
    ) -> Criticality {
        // Check in severity order: hostile → suspicious → notable → inert
        // First match wins

        if let Some(conditions) = &rules.hostile {
            if self.eval_downgrade_conditions(conditions, ctx) {
                return Criticality::Hostile;
            }
        }

        if let Some(conditions) = &rules.suspicious {
            if self.eval_downgrade_conditions(conditions, ctx) {
                return Criticality::Suspicious;
            }
        }

        if let Some(conditions) = &rules.notable {
            if self.eval_downgrade_conditions(conditions, ctx) {
                return Criticality::Notable;
            }
        }

        if let Some(conditions) = &rules.inert {
            if self.eval_downgrade_conditions(conditions, ctx) {
                return Criticality::Inert;
            }
        }

        // No downgrade matched - return base criticality
        *base_crit
    }

    /// Evaluate a single downgrade condition set
    fn eval_downgrade_conditions(
        &self,
        conditions: &DowngradeConditions,
        ctx: &EvaluationContext,
    ) -> bool {
        // If 'all' is specified, all must match
        if let Some(all_conds) = &conditions.all {
            for cond in all_conds {
                if !self.eval_condition(cond, ctx).matched {
                    return false;
                }
            }
            return true;
        }

        // If 'any' is specified, at least one must match
        if let Some(any_conds) = &conditions.any {
            for cond in any_conds {
                if self.eval_condition(cond, ctx).matched {
                    return true;
                }
            }
            return false;
        }

        // If 'none' is specified, none can match
        if let Some(none_conds) = &conditions.none {
            for cond in none_conds {
                if self.eval_condition(cond, ctx).matched {
                    return false;
                }
            }
            return true;
        }

        false
    }

    /// Evaluate a single condition
    fn eval_condition(&self, condition: &Condition, ctx: &EvaluationContext) -> ConditionResult {
        match condition {
            Condition::Symbol {
                exact,
                regex,
                platforms,
                compiled_regex,
            } => eval_symbol(
                exact.as_ref(),
                regex.as_ref(),
                platforms.as_ref(),
                compiled_regex.as_ref(),
                ctx,
            ),
            Condition::String {
                exact,
                contains,
                regex,
                word,
                case_insensitive,
                exclude_patterns,
                min_count,
                compiled_regex,
                compiled_excludes,
            } => {
                let params = StringParams {
                    exact: exact.as_ref(),
                    contains: contains.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    exclude_patterns: exclude_patterns.as_ref(),
                    min_count: *min_count,
                    compiled_regex: compiled_regex.as_ref(),
                    compiled_excludes,
                };
                eval_string(&params, self.not.as_ref(), ctx)
            }
            Condition::YaraMatch { namespace, rule } => {
                eval_yara_match(namespace, rule.as_ref(), ctx)
            }
            Condition::Structure {
                feature,
                min_sections,
            } => eval_structure(feature, *min_sections, ctx),
            Condition::ImportsCount { min, max, filter } => {
                eval_imports_count(*min, *max, filter.as_ref(), ctx)
            }
            Condition::ExportsCount { min, max } => eval_exports_count(*min, *max, ctx),
            Condition::Trait { id } => eval_trait(id, ctx),
            Condition::AstPattern {
                node_type,
                exact,
                regex,
                case_insensitive,
            } => eval_ast_pattern(node_type, exact, *regex, *case_insensitive, ctx),
            Condition::AstQuery { query, .. } => eval_ast_query(query, ctx),
            Condition::Ast {
                kind,
                node,
                exact,
                regex,
                query,
                case_insensitive,
                ..
            } => eval_ast(
                kind.as_deref(),
                node.as_deref(),
                exact.as_deref(),
                regex.as_deref(),
                query.as_deref(),
                *case_insensitive,
                ctx,
            ),
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
            Condition::Metrics {
                field,
                min,
                max,
                min_size,
                max_size,
            } => eval_metrics(field, *min, *max, *min_size, *max_size, ctx),
            Condition::Hex {
                pattern,
                offset,
                offset_range,
                min_count,
                extract_wildcards,
            } => eval_hex(
                pattern,
                *offset,
                *offset_range,
                *min_count,
                *extract_wildcards,
                ctx,
            ),
            Condition::Filesize { min, max } => eval_filesize(*min, *max, ctx),
            Condition::TraitGlob { pattern, r#match } => eval_trait_glob(pattern, r#match, ctx),
            Condition::Content {
                exact,
                contains,
                regex,
                word,
                case_insensitive,
                min_count,
                compiled_regex,
            } => eval_raw(
                exact.as_ref(),
                contains.as_ref(),
                regex.as_ref(),
                word.as_ref(),
                *case_insensitive,
                *min_count,
                compiled_regex.as_ref(),
                ctx,
            ),
            Condition::SectionName { pattern, regex } => eval_section_name(pattern, *regex, ctx),
            Condition::Base64 {
                exact,
                regex,
                case_insensitive,
                min_count,
            } => eval_base64(
                exact.as_ref(),
                regex.as_ref(),
                *case_insensitive,
                *min_count,
                ctx,
            ),
            Condition::Xor {
                key,
                exact,
                regex,
                case_insensitive,
                min_count,
            } => eval_xor(
                key.as_ref(),
                exact.as_ref(),
                regex.as_ref(),
                *case_insensitive,
                *min_count,
                ctx,
            ),
        }
    }
}

/// Boolean logic for combining conditions/traits
#[derive(Debug, Clone, Deserialize)]
pub struct CompositeTrait {
    #[serde(alias = "capability")]
    pub id: String,
    #[serde(alias = "description")]
    pub desc: String,
    #[serde(alias = "confidence")]
    pub conf: f32,

    /// Criticality level (defaults to None)
    #[serde(default, alias = "criticality")]
    pub crit: Criticality,

    /// MBC (Malware Behavior Catalog) ID - most specific available (e.g., "B0015.001")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mbc: Option<String>,

    /// MITRE ATT&CK Technique ID (e.g., "T1056.001")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attack: Option<String>,

    #[serde(default = "default_platforms")]
    pub platforms: Vec<Platform>,

    #[serde(default = "default_file_types", alias = "file_types", alias = "files")]
    pub r#for: Vec<FileType>,

    /// Minimum file size in bytes
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size_min: Option<usize>,

    /// Maximum file size in bytes
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size_max: Option<usize>,

    // Boolean operators
    #[serde(alias = "requires_all", skip_serializing_if = "Option::is_none")]
    pub all: Option<Vec<Condition>>,

    /// List of conditions - use count_min/count_max/count_exact to control how many must match
    #[serde(
        alias = "requires_any",
        alias = "conditions",
        skip_serializing_if = "Option::is_none"
    )]
    pub any: Option<Vec<Condition>>,

    /// Exactly this many conditions from `any` must match (rare - use count_min for "at least N")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count_exact: Option<usize>,

    /// At least this many conditions from `any` must match (most common usage)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count_min: Option<usize>,

    /// At most this many conditions from `any` can match
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count_max: Option<usize>,

    #[serde(alias = "requires_none", skip_serializing_if = "Option::is_none")]
    pub none: Option<Vec<Condition>>,

    /// File-level skip conditions - skip entire rule if ANY condition matches
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub unless: Option<Vec<Condition>>,

    /// String-level exceptions - filter matched strings
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub not: Option<Vec<NotException>>,
}

impl CompositeTrait {
    /// Pre-compile YARA rules in all conditions
    pub fn compile_yara(&mut self) {
        if let Some(ref mut conds) = self.all {
            for cond in conds.iter_mut() {
                cond.compile_yara();
            }
        }
        if let Some(ref mut conds) = self.any {
            for cond in conds.iter_mut() {
                cond.compile_yara();
            }
        }
        if let Some(ref mut conds) = self.none {
            for cond in conds.iter_mut() {
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

        // Check size constraints
        if !self.matches_size(ctx) {
            return None;
        }

        // Evaluate positive conditions based on the boolean operator(s)
        let has_positive = self.all.is_some() || self.any.is_some();

        let positive_result = match (&self.all, &self.any) {
            (Some(all), Some(any)) => {
                // Both all AND any: all must match AND any must match
                let all_result = self.eval_requires_all(all, ctx);
                if !all_result.matched {
                    return None;
                }
                let any_result = self.eval_requires_any(any, ctx);
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
                    warnings: Vec::new(),
                }
            }
            (Some(conds), None) => self.eval_requires_all(conds, ctx),
            (None, Some(conds)) => {
                // Handle count constraints on `any` conditions
                let has_count_constraint = self.count_exact.is_some()
                    || self.count_min.is_some()
                    || self.count_max.is_some();
                if has_count_constraint {
                    self.eval_count_constraints(
                        conds,
                        self.count_exact,
                        self.count_min,
                        self.count_max,
                        ctx,
                    )
                } else {
                    self.eval_requires_any(conds, ctx)
                }
            }
            (None, None) => {
                // No positive conditions - will check none below
                ConditionResult {
                    matched: true,
                    evidence: Vec::new(),
                    traits: Vec::new(),
                    warnings: Vec::new(),
                }
            }
        };

        if !positive_result.matched {
            return None;
        }

        // Evaluate none (can be combined with positive conditions)
        // If none is present, none of its conditions can match
        let result = if let Some(ref none_conds) = self.none {
            let none_result = self.eval_requires_none(none_conds, ctx);
            if !none_result.matched {
                return None; // A "none" condition matched, so rule fails
            }
            // Combine evidence
            let mut combined_evidence = positive_result.evidence;
            combined_evidence.extend(none_result.evidence);
            ConditionResult {
                matched: true,
                evidence: combined_evidence,
                traits: Vec::new(),
                warnings: Vec::new(),
            }
        } else if !has_positive {
            // No positive conditions and no none - invalid rule
            return None;
        } else {
            positive_result
        };

        if result.matched {
            Some(Finding {
                id: self.id.clone(),
                kind: FindingKind::Capability,
                desc: self.desc.clone(),
                conf: self.conf,
                crit: self.crit,
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

        let file_type_match = self.r#for.contains(&FileType::All)
            || ctx.file_type == FileType::All
            || self.r#for.contains(&ctx.file_type);

        platform_match && file_type_match
    }

    /// Check if rule matches size constraints
    fn matches_size(&self, ctx: &EvaluationContext) -> bool {
        let file_size = ctx.report.target.size_bytes as usize;

        if let Some(min) = self.size_min {
            if file_size < min {
                return false;
            }
        }

        if let Some(max) = self.size_max {
            if file_size > max {
                return false;
            }
        }

        true
    }

    /// Evaluate ALL conditions must match (AND)
    fn eval_requires_all(&self, conds: &[Condition], ctx: &EvaluationContext) -> ConditionResult {
        let mut all_evidence = Vec::new();

        for condition in conds {
            let result = self.eval_condition(condition, ctx);
            if !result.matched {
                return ConditionResult {
                    matched: false,
                    evidence: Vec::new(),
                    traits: Vec::new(),
                    warnings: Vec::new(),
                };
            }
            all_evidence.extend(result.evidence);
        }

        ConditionResult {
            matched: true,
            evidence: all_evidence,
            traits: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Evaluate at least ONE condition must match (OR)
    /// Collects evidence from ALL matching conditions, not just the first
    fn eval_requires_any(&self, conds: &[Condition], ctx: &EvaluationContext) -> ConditionResult {
        let mut any_matched = false;
        let mut all_evidence = Vec::new();

        for condition in conds {
            let result = self.eval_condition(condition, ctx);
            if result.matched {
                any_matched = true;
                all_evidence.extend(result.evidence);
            }
        }

        ConditionResult {
            matched: any_matched,
            evidence: all_evidence,
            traits: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Evaluate with count constraints: exact count, min_count, max_count
    fn eval_count_constraints(
        &self,
        conds: &[Condition],
        exact: Option<usize>,
        min: Option<usize>,
        max: Option<usize>,
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        let mut matched_count = 0;
        let mut all_evidence = Vec::new();

        for condition in conds.iter() {
            let result = self.eval_condition(condition, ctx);
            if result.matched {
                matched_count += 1;
                all_evidence.extend(result.evidence);
            }
        }

        let matched = if let Some(exact_count) = exact {
            // Exact match required
            matched_count == exact_count
        } else {
            // Range check
            let min_ok = min.is_none_or(|m| matched_count >= m);
            let max_ok = max.is_none_or(|m| matched_count <= m);
            min_ok && max_ok
        };

        ConditionResult {
            matched,
            evidence: if matched { all_evidence } else { Vec::new() },
            traits: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Evaluate NONE of the conditions can match (NOT)
    fn eval_requires_none(&self, conds: &[Condition], ctx: &EvaluationContext) -> ConditionResult {
        for condition in conds {
            let result = self.eval_condition(condition, ctx);
            if result.matched {
                return ConditionResult {
                    matched: false,
                    evidence: Vec::new(),
                    traits: Vec::new(),
                    warnings: Vec::new(),
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
            warnings: Vec::new(),
        }
    }

    /// Evaluate a single condition
    fn eval_condition(&self, condition: &Condition, ctx: &EvaluationContext) -> ConditionResult {
        match condition {
            Condition::Symbol {
                exact,
                regex,
                platforms,
                compiled_regex,
            } => self.eval_symbol(
                exact.as_ref(),
                regex.as_ref(),
                platforms.as_ref(),
                compiled_regex.as_ref(),
                ctx,
            ),
            Condition::String {
                exact,
                contains,
                regex,
                word,
                case_insensitive,
                exclude_patterns,
                min_count,
                compiled_regex,
                compiled_excludes,
            } => {
                let params = StringParams {
                    exact: exact.as_ref(),
                    contains: contains.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    exclude_patterns: exclude_patterns.as_ref(),
                    min_count: *min_count,
                    compiled_regex: compiled_regex.as_ref(),
                    compiled_excludes,
                };
                eval_string(&params, self.not.as_ref(), ctx)
            }
            Condition::YaraMatch { namespace, rule } => {
                self.eval_yara_match(namespace, rule.as_ref(), ctx)
            }
            Condition::Structure {
                feature,
                min_sections,
            } => self.eval_structure(feature, *min_sections, ctx),
            Condition::ImportsCount { min, max, filter } => {
                self.eval_imports_count(*min, *max, filter.as_ref(), ctx)
            }
            Condition::ExportsCount { min, max } => self.eval_exports_count(*min, *max, ctx),
            Condition::Trait { id } => eval_trait(id, ctx),
            Condition::AstPattern {
                node_type,
                exact,
                regex,
                case_insensitive,
            } => eval_ast_pattern(node_type, exact, *regex, *case_insensitive, ctx),
            Condition::AstQuery { query, .. } => eval_ast_query(query, ctx),
            Condition::Ast {
                kind,
                node,
                exact,
                regex,
                query,
                case_insensitive,
                ..
            } => eval_ast(
                kind.as_deref(),
                node.as_deref(),
                exact.as_deref(),
                regex.as_deref(),
                query.as_deref(),
                *case_insensitive,
                ctx,
            ),
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
            Condition::Metrics {
                field,
                min,
                max,
                min_size,
                max_size,
            } => eval_metrics(field, *min, *max, *min_size, *max_size, ctx),
            Condition::Hex {
                pattern,
                offset,
                offset_range,
                min_count,
                extract_wildcards,
            } => eval_hex(
                pattern,
                *offset,
                *offset_range,
                *min_count,
                *extract_wildcards,
                ctx,
            ),
            Condition::Filesize { min, max } => eval_filesize(*min, *max, ctx),
            Condition::TraitGlob { pattern, r#match } => eval_trait_glob(pattern, r#match, ctx),
            Condition::Content {
                exact,
                contains,
                regex,
                word,
                case_insensitive,
                min_count,
                compiled_regex,
            } => eval_raw(
                exact.as_ref(),
                contains.as_ref(),
                regex.as_ref(),
                word.as_ref(),
                *case_insensitive,
                *min_count,
                compiled_regex.as_ref(),
                ctx,
            ),
            Condition::SectionName { pattern, regex } => eval_section_name(pattern, *regex, ctx),
            Condition::Base64 {
                exact,
                regex,
                case_insensitive,
                min_count,
            } => eval_base64(
                exact.as_ref(),
                regex.as_ref(),
                *case_insensitive,
                *min_count,
                ctx,
            ),
            Condition::Xor {
                key,
                exact,
                regex,
                case_insensitive,
                min_count,
            } => eval_xor(
                key.as_ref(),
                exact.as_ref(),
                regex.as_ref(),
                *case_insensitive,
                *min_count,
                ctx,
            ),
        }
    }

    /// Evaluate symbol condition
    fn eval_symbol(
        &self,
        exact: Option<&String>,
        pattern: Option<&String>,
        platforms: Option<&Vec<Platform>>,
        compiled_regex: Option<&regex::Regex>,
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        // Check platform constraint
        if let Some(plats) = platforms {
            if !plats.contains(&ctx.platform) && !plats.contains(&Platform::All) {
                return ConditionResult {
                    matched: false,
                    evidence: Vec::new(),
                    traits: Vec::new(),
                    warnings: Vec::new(),
                };
            }
        }

        eval_symbol(exact, pattern, None, compiled_regex, ctx)
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
            warnings: Vec::new(),
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
            warnings: Vec::new(),
        }
    }

    /// Returns true if this rule has negative (none) conditions
    pub fn has_negative_conditions(&self) -> bool {
        self.none.as_ref().map(|n| !n.is_empty()).unwrap_or(false)
    }
}
