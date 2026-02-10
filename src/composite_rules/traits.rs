//! Trait definitions for composite rules.
//!
//! This module contains TraitDefinition (atomic traits) and CompositeTrait
//! (boolean combinations of conditions).

use super::condition::{Condition, NotException};
use super::context::{ConditionResult, EvaluationContext, StringParams};
use super::evaluators::{
    eval_ast, eval_base64, eval_basename, eval_exports_count, eval_filesize, eval_hex,
    eval_import_combination, eval_imports_count, eval_layer_path, eval_metrics, eval_raw,
    eval_section_entropy, eval_section_name, eval_section_ratio, eval_string, eval_string_count,
    eval_structure, eval_symbol, eval_syscall, eval_trait, eval_trait_glob, eval_xor,
    eval_yara_inline, eval_yara_match, ContentLocationParams,
};
use super::types::{default_file_types, default_platforms, FileType, Platform};
use crate::types::{Criticality, Evidence, Finding, FindingKind};
use anyhow::Context;
use regex::Regex;
use serde::Deserialize;

fn default_confidence() -> f32 {
    1.0
}

/// Conditions for a downgrade level (supports composite syntax)
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DowngradeConditions {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub any: Option<Vec<Condition>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub all: Option<Vec<Condition>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub none: Option<Vec<Condition>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub needs: Option<usize>,
}

/// Definition of an atomic observable trait
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraitDefinition {
    pub id: String,
    pub desc: String,
    #[serde(default = "default_confidence")]
    pub conf: f32,

    /// Criticality level (defaults to None = internal only)
    #[serde(default)]
    pub crit: Criticality,

    /// MBC (Malware Behavior Catalog) ID - most specific available (e.g., "B0015.001")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mbc: Option<String>,

    /// MITRE ATT&CK Technique ID (e.g., "T1056.001")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attack: Option<String>,

    #[serde(default = "default_platforms")]
    pub platforms: Vec<Platform>,

    #[serde(default = "default_file_types")]
    pub r#for: Vec<FileType>,

    /// Minimum file size in bytes
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size_min: Option<usize>,

    /// Maximum file size in bytes
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size_max: Option<usize>,

    // Detection condition - just one condition per trait (atomic!)
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
    pub downgrade: Option<DowngradeConditions>,
    #[serde(skip)]
    pub defined_in: std::path::PathBuf,
}

impl TraitDefinition {
    /// Pre-compile all regexes in this trait's conditions for performance.
    /// Returns an error if any regex pattern is invalid.
    pub fn precompile_regexes(&mut self) -> anyhow::Result<()> {
        self.r#if.precompile_regexes()
            .with_context(|| format!("in trait '{}' main condition", self.id))?;
        if let Some(ref mut conds) = self.unless {
            for (idx, cond) in conds.iter_mut().enumerate() {
                cond.precompile_regexes()
                    .with_context(|| format!("in trait '{}' unless condition #{}", self.id, idx + 1))?;
            }
        }
        if let Some(ref mut downgrade) = self.downgrade {
            if let Some(ref mut any) = downgrade.any {
                for (idx, cond) in any.iter_mut().enumerate() {
                    cond.precompile_regexes()
                        .with_context(|| format!("in trait '{}' downgrade.any condition #{}", self.id, idx + 1))?;
                }
            }
            if let Some(ref mut all) = downgrade.all {
                for (idx, cond) in all.iter_mut().enumerate() {
                    cond.precompile_regexes()
                        .with_context(|| format!("in trait '{}' downgrade.all condition #{}", self.id, idx + 1))?;
                }
            }
            if let Some(ref mut none) = downgrade.none {
                for (idx, cond) in none.iter_mut().enumerate() {
                    cond.precompile_regexes()
                        .with_context(|| format!("in trait '{}' downgrade.none condition #{}", self.id, idx + 1))?;
                }
            }
        }
        Ok(())
    }

    /// Pre-compile YARA rules in this trait's condition
    pub fn compile_yara(&mut self) {
        self.r#if.compile_yara();
        if let Some(ref mut conds) = self.unless {
            for cond in conds.iter_mut() {
                cond.compile_yara();
            }
        }
    }

    /// Check if criticality level is valid for user-defined traits.
    /// Returns an error message if invalid, None otherwise.
    pub fn check_criticality(&self) -> Option<String> {
        use crate::types::Criticality;

        // Check if criticality is "Filtered" which is internal-only
        if self.crit == Criticality::Filtered {
            return Some(
                "crit: 'filtered' is an internal-only criticality level. Use one of: 'inert' (informational), 'notable' (interesting behavior), 'suspicious' (potentially malicious), or 'hostile' (clearly malicious)".to_string()
            );
        }

        None
    }

    /// Check if confidence value is in valid range.
    /// Returns an error message if invalid, None otherwise.
    pub fn check_confidence(&self) -> Option<String> {
        if self.conf < 0.0 || self.conf > 1.0 {
            return Some(format!(
                "conf: {} is outside valid range [0.0, 1.0]",
                self.conf
            ));
        }
        None
    }

    /// Check if size constraints are valid.
    /// Returns an error message if invalid, None otherwise.
    pub fn check_size_constraints(&self) -> Option<String> {
        if let (Some(min), Some(max)) = (self.size_min, self.size_max) {
            if max < min {
                return Some(format!(
                    "size_max ({}) cannot be less than size_min ({})",
                    max, min
                ));
            }
        }
        None
    }

    /// Check for empty or very short descriptions (common LLM mistake).
    /// Returns a warning message if found, None otherwise.
    pub fn check_description_quality(&self) -> Option<String> {
        let desc = self.desc.trim();

        if desc.is_empty() {
            return Some(
                "desc: field is empty. Write a clear, concise description of what this trait detects. Examples: 'XOR decryption loop' or 'Detects SSH key theft attempts'".to_string()
            );
        }

        if desc.len() < 5 {
            return Some(format!(
                "desc: '{}' is too short ({} chars). Write a clear description. Examples: 'JOIN command for IRC' or 'Detects IRC communication patterns'",
                desc, desc.len()
            ));
        }

        None
    }

    /// Check for empty not: arrays (common LLM mistake).
    /// Returns a warning message if found, None otherwise.
    pub fn check_empty_not_array(&self) -> Option<String> {
        if let Some(not_exceptions) = &self.not {
            if not_exceptions.is_empty() {
                return Some(
                    "not: array is empty - either remove the not: field or add exception patterns".to_string()
                );
            }
        }
        None
    }

    /// Check for empty unless: arrays (common LLM mistake).
    /// Returns a warning message if found, None otherwise.
    pub fn check_empty_unless_array(&self) -> Option<String> {
        if let Some(unless_conditions) = &self.unless {
            if unless_conditions.is_empty() {
                return Some(
                    "unless: array is empty - either remove the unless: field or add skip conditions".to_string()
                );
            }
        }
        None
    }

    /// Check if `not:` field is used appropriately based on match type.
    /// Returns a warning message if misused, None otherwise.
    pub fn check_not_field_usage(&self) -> Option<String> {
        let not_exceptions = self.not.as_ref()?;

        // Helper to check if a pattern could match a literal string
        fn pattern_could_match(pattern: &str, literal: &str) -> bool {
            if let Ok(re) = regex::Regex::new(pattern) {
                re.is_match(literal)
            } else {
                false
            }
        }

        // Helper to extract exception string for validation
        fn get_exception_str(exc: &NotException) -> Option<&str> {
            match exc {
                NotException::Shorthand(s) => Some(s.as_str()),
                NotException::Structured { exact: Some(s), .. }
                | NotException::Structured {
                    substr: Some(s), ..
                }
                | NotException::Structured { regex: Some(s), .. } => Some(s.as_str()),
                _ => None,
            }
        }

        // Helper to check if a string contains a substring (case-sensitive or insensitive)
        fn contains_substr(haystack: &str, needle: &str, case_insensitive: bool) -> bool {
            if case_insensitive {
                haystack.to_lowercase().contains(&needle.to_lowercase())
            } else {
                haystack.contains(needle)
            }
        }

        match &self.r#if {
            // Symbol conditions with not: - validate exceptions match the pattern
            Condition::Symbol {
                exact: Some(_),
                regex: None,
                ..
            } => {
                return Some(
                    "not: field used with symbol exact match - consider using 'unless:' instead for deterministic patterns".to_string()
                );
            }
            Condition::Symbol {
                substr: Some(search_substr),
                regex: None,
                ..
            } => {
                // For symbol substr, validate not: exceptions contain the search substr
                for exc in not_exceptions {
                    match exc {
                        NotException::Shorthand(exc_str) => {
                            if !exc_str.contains(search_substr) {
                                return Some(format!(
                                    "not: exception '{}' does not contain the search substr '{}' - symbols matching the substr won't contain this exception, so it will never be applied",
                                    exc_str, search_substr
                                ));
                            }
                        }
                        NotException::Structured {
                            exact: Some(exc_str),
                            ..
                        } => {
                            if !exc_str.contains(search_substr) {
                                return Some(format!(
                                    "not: exception (exact) '{}' does not contain the search substr '{}' - symbols matching the substr won't match this exception, so it will never be applied",
                                    exc_str, search_substr
                                ));
                            }
                        }
                        NotException::Structured {
                            substr: Some(exc_substr),
                            ..
                        } => {
                            if !exc_substr.contains(search_substr)
                                && !search_substr.contains(exc_substr)
                            {
                                return Some(format!(
                                    "not: exception (substr) '{}' has no overlap with search substr '{}' - they won't match the same symbols, so the exception will never be applied",
                                    exc_substr, search_substr
                                ));
                            }
                        }
                        _ => {}
                    }
                }
            }
            Condition::Symbol {
                regex: Some(pattern),
                ..
            } => {
                // For symbol regex, validate exceptions match the pattern
                for exc in not_exceptions {
                    let exc_str = match exc {
                        NotException::Shorthand(s) => Some(s.as_str()),
                        NotException::Structured { exact: Some(s), .. }
                        | NotException::Structured {
                            substr: Some(s), ..
                        }
                        | NotException::Structured { regex: Some(s), .. } => Some(s.as_str()),
                        _ => None,
                    };

                    if let Some(exc_str) = exc_str {
                        if !pattern_could_match(pattern, exc_str) {
                            return Some(format!(
                                "not: exception '{}' does not match the search regex '{}' - it will never be applied",
                                exc_str, pattern
                            ));
                        }
                    }
                }
            }
            // Exact matches should use `unless:` instead of `not:`
            Condition::String {
                exact: Some(_),
                regex: None,
                word: None,
                ..
            } => {
                return Some(
                    "not: field used with exact match - consider using 'unless:' instead for deterministic patterns".to_string()
                );
            }
            // For Content exact matches, not: doesn't make sense
            Condition::Content {
                exact: Some(_),
                regex: None,
                word: None,
                ..
            } => {
                return Some(
                    "not: field used with content/exact match - this doesn't make sense. Content exact matches the entire file content.".to_string()
                );
            }
            // For String substr matches, validate that not: exceptions could match strings containing the substr
            Condition::String {
                substr: Some(search_substr),
                regex: None,
                word: None,
                case_insensitive,
                ..
            } => {
                let case_insensitive = *case_insensitive;

                for exc in not_exceptions {
                    match exc {
                        // For shorthand (substr match in not:), check if the exception contains the search substr
                        NotException::Shorthand(exc_str) => {
                            if !contains_substr(exc_str, search_substr, case_insensitive) {
                                return Some(format!(
                                    "not: exception '{}' does not contain the search substr '{}' - strings matching the substr won't contain this exception, so it will never be applied",
                                    exc_str, search_substr
                                ));
                            }
                        }
                        NotException::Structured {
                            exact: Some(exc_str),
                            ..
                        } => {
                            // Exception is exact match - it should contain the search substr
                            if !contains_substr(exc_str, search_substr, case_insensitive) {
                                return Some(format!(
                                    "not: exception (exact) '{}' does not contain the search substr '{}' - strings matching the substr won't match this exception, so it will never be applied",
                                    exc_str, search_substr
                                ));
                            }
                        }
                        NotException::Structured {
                            substr: Some(exc_substr),
                            ..
                        } => {
                            // Exception is substr - it should contain the search substr or vice versa
                            // Either the exception contains the search, or the search contains the exception
                            if !contains_substr(exc_substr, search_substr, case_insensitive)
                                && !contains_substr(search_substr, exc_substr, case_insensitive)
                            {
                                return Some(format!(
                                    "not: exception (substr) '{}' has no overlap with search substr '{}' - they won't match the same strings, so the exception will never be applied",
                                    exc_substr, search_substr
                                ));
                            }
                        }
                        NotException::Structured {
                            regex: Some(_exc_regex),
                            ..
                        } => {
                            // For regex exceptions with substr search, we can't easily validate
                            // The regex might match strings containing the substr
                            // We'll allow this without validation
                        }
                        _ => {}
                    }
                }
            }
            // For Content substr matches, not: is unclear - content searches don't extract individual strings
            Condition::Content {
                substr: Some(_),
                regex: None,
                word: None,
                ..
            } => {
                return Some(
                    "not: field used with content/substr match - behavior is unclear because content searches on binary data don't extract individual strings for filtering. Use regex instead, or use 'string' type with substr.".to_string()
                );
            }
            // For regex matches, validate that exceptions could actually match
            Condition::String {
                regex: Some(pattern),
                ..
            }
            | Condition::Content {
                regex: Some(pattern),
                ..
            } => {
                for exc in not_exceptions {
                    if let Some(exc_str) = get_exception_str(exc) {
                        if !pattern_could_match(pattern, exc_str) {
                            return Some(format!(
                                "not: exception '{}' does not match the search regex '{}' - it will never be applied",
                                exc_str, pattern
                            ));
                        }
                    }
                }
            }
            // For hex patterns, validate exceptions match
            Condition::Hex { pattern: _, .. } => {
                // For hex patterns, we should validate that not: exceptions make sense
                // Since hex matching is complex, we'll do a basic check
                // Hex patterns match byte sequences, so not: exceptions should be regex-based
                for exc in not_exceptions {
                    match exc {
                        NotException::Structured { exact: Some(_), .. }
                        | NotException::Structured {
                            substr: Some(_), ..
                        }
                        | NotException::Shorthand(_) => {
                            // For hex matches, exact/substr don't make as much sense
                            // The matched bytes need to be converted to string representation first
                            // This is a valid but potentially confusing use case
                            // We'll allow it but note it in the debug logs if needed
                        }
                        NotException::Structured { regex: Some(_), .. } => {
                            // Regex-based exceptions for hex matches are fine
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        None
    }

    /// Evaluate this trait definition against the analysis context
    pub fn evaluate(&self, ctx: &EvaluationContext) -> Option<Finding> {
        use super::debug::{ConditionDebug, DowngradeDebug, SkipReason};

        // Check platform match
        let platform_match = self.platforms.contains(&Platform::All)
            || ctx.platforms.contains(&Platform::All)
            || self.platforms.iter().any(|p| ctx.platforms.contains(p));

        if !platform_match {
            if let Some(collector) = &ctx.debug_collector {
                if let Ok(mut debug) = collector.write() {
                    debug.record_skip(SkipReason::PlatformMismatch {
                        rule: self.platforms.clone(),
                        context: ctx.platforms.clone(),
                    });
                }
            }
            return None;
        }

        // Check file type match
        let file_type_match = self.r#for.contains(&FileType::All)
            || ctx.file_type == FileType::All
            || self.r#for.contains(&ctx.file_type);

        if !file_type_match {
            if let Some(collector) = &ctx.debug_collector {
                if let Ok(mut debug) = collector.write() {
                    debug.record_skip(SkipReason::FileTypeMismatch {
                        rule: self.r#for.clone(),
                        context: ctx.file_type,
                    });
                }
            }
            return None;
        }

        // Check size constraints
        let file_size = ctx.report.target.size_bytes as usize;
        if let Some(min) = self.size_min {
            if file_size < min {
                if let Some(collector) = &ctx.debug_collector {
                    if let Ok(mut debug) = collector.write() {
                        debug.record_skip(SkipReason::SizeTooSmall {
                            actual: file_size,
                            min,
                        });
                    }
                }
                return None;
            }
        }
        if let Some(max) = self.size_max {
            if file_size > max {
                if let Some(collector) = &ctx.debug_collector {
                    if let Ok(mut debug) = collector.write() {
                        debug.record_skip(SkipReason::SizeTooLarge {
                            actual: file_size,
                            max,
                        });
                    }
                }
                return None;
            }
        }

        // Check unless conditions (file-level skip)
        if let Some(unless_conds) = &self.unless {
            // Default 'any' semantics: skip if ANY condition matches
            for condition in unless_conds {
                let result = self.eval_condition(condition, ctx);
                if result.matched {
                    // Record skip reason if debug collector is present
                    if let Some(collector) = &ctx.debug_collector {
                        if let Ok(mut debug) = collector.write() {
                            debug.record_skip(SkipReason::UnlessConditionMatched {
                                condition_desc: format!("{:?}", condition),
                            });
                        }
                    }
                    return None;
                }
            }
        }

        // Evaluate the condition (traits only have one atomic condition)
        let result = self.eval_condition(&self.r#if, ctx);

        // Record condition result if debug collector is present
        if let Some(collector) = &ctx.debug_collector {
            if let Ok(mut debug) = collector.write() {
                let cond_debug = ConditionDebug::new(format!("{:?}", self.r#if))
                    .with_matched(result.matched)
                    .with_evidence(result.evidence.clone())
                    .with_precision(result.precision);
                debug.add_condition(cond_debug);
            }
        }

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
            if let Some(downgrade_conds) = &self.downgrade {
                let debug_downgrade = std::env::var("DEBUG_DOWNGRADE").is_ok();
                if debug_downgrade {
                    eprintln!(
                        "DEBUG: Evaluating downgrade for trait '{}' (current: {:?})",
                        self.id, self.crit
                    );
                }
                let triggered = self.eval_downgrade_conditions(downgrade_conds, ctx);
                if triggered {
                    final_crit = match self.crit {
                        Criticality::Hostile => Criticality::Suspicious,
                        Criticality::Suspicious => Criticality::Notable,
                        Criticality::Notable | Criticality::Inert | Criticality::Filtered => {
                            Criticality::Inert
                        }
                    };
                }

                // Record downgrade debug if collector is present
                if let Some(collector) = &ctx.debug_collector {
                    if let Ok(mut debug) = collector.write() {
                        debug.set_downgrade(DowngradeDebug {
                            original_crit: self.crit,
                            final_crit,
                            triggered,
                            conditions: Vec::new(), // Could add condition details here
                        });
                    }
                }

                if debug_downgrade {
                    eprintln!(
                        "DEBUG: Final criticality for '{}': {:?}",
                        self.id, final_crit
                    );
                }
            }

            // Record match in debug collector
            if let Some(collector) = &ctx.debug_collector {
                if let Ok(mut debug) = collector.write() {
                    debug.matched = true;
                    debug.precision = result.precision;
                }
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

    /// Evaluate a single downgrade condition set
    fn eval_downgrade_conditions(
        &self,
        conditions: &DowngradeConditions,
        ctx: &EvaluationContext,
    ) -> bool {
        let debug_downgrade = std::env::var("DEBUG_DOWNGRADE").is_ok();

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
            for (i, cond) in any_conds.iter().enumerate() {
                let result = self.eval_condition(cond, ctx);
                if debug_downgrade {
                    eprintln!(
                        "DEBUG TraitDef: downgrade any[{}] cond={:?} matched={}",
                        i, cond, result.matched
                    );
                }
                if result.matched {
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
                substr,
                regex,
                platforms,
                compiled_regex,
            } => eval_symbol(
                exact.as_ref(),
                substr.as_ref(),
                regex.as_ref(),
                platforms.as_ref(),
                compiled_regex.as_ref(),
                self.not.as_ref(),
                ctx,
            ),
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
                compiled_regex,
                compiled_excludes,
            } => {
                let params = StringParams {
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    exclude_patterns: exclude_patterns.as_ref(),
                    count_min: *count_min,
                    count_max: *count_max,
                    per_kb_min: *per_kb_min,
                    per_kb_max: *per_kb_max,
                    external_ip: *external_ip,
                    compiled_regex: compiled_regex.as_ref(),
                    compiled_excludes,
                    section: section.as_ref(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
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
            Condition::Ast {
                kind,
                node,
                exact,
                substr,
                regex,
                query,
                case_insensitive,
                ..
            } => eval_ast(
                kind.as_deref(),
                node.as_deref(),
                exact.as_deref(),
                substr.as_deref(),
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
                count_min,
                count_max,
                per_kb_min,
                per_kb_max,
                extract_wildcards,
                section,
                section_offset,
                section_offset_range,
            } => eval_hex(
                pattern,
                *count_min,
                *count_max,
                *per_kb_min,
                *per_kb_max,
                *extract_wildcards,
                &ContentLocationParams {
                    section: section.clone(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                },
                ctx,
            ),
            Condition::Filesize { min, max } => eval_filesize(*min, *max, ctx),
            Condition::TraitGlob { pattern, r#match } => eval_trait_glob(pattern, r#match, ctx),
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
                compiled_regex,
            } => {
                use super::evaluators::ContentLocationParams;
                let location = ContentLocationParams {
                    section: section.clone(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                };
                eval_raw(
                    exact.as_ref(),
                    substr.as_ref(),
                    regex.as_ref(),
                    word.as_ref(),
                    *case_insensitive,
                    *count_min,
                    *count_max,
                    *per_kb_min,
                    *per_kb_max,
                    *external_ip,
                    compiled_regex.as_ref(),
                    self.not.as_ref(),
                    &location,
                    ctx,
                )
            }
            Condition::SectionName { pattern, regex } => eval_section_name(pattern, *regex, ctx),
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
            } => {
                use super::evaluators::ContentLocationParams;
                let location = ContentLocationParams {
                    section: section.clone(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                };
                eval_base64(
                    exact.as_ref(),
                    substr.as_ref(),
                    regex.as_ref(),
                    *case_insensitive,
                    *count_min,
                    *count_max,
                    *per_kb_min,
                    *per_kb_max,
                    &location,
                    ctx,
                )
            }
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
            } => {
                use super::evaluators::ContentLocationParams;
                let location = ContentLocationParams {
                    section: section.clone(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                };
                eval_xor(
                    key.as_ref(),
                    exact.as_ref(),
                    substr.as_ref(),
                    regex.as_ref(),
                    *case_insensitive,
                    *count_min,
                    *count_max,
                    *per_kb_min,
                    *per_kb_max,
                    &location,
                    ctx,
                )
            }
            Condition::Basename {
                exact,
                substr,
                regex,
                case_insensitive,
            } => eval_basename(
                exact.as_ref(),
                substr.as_ref(),
                regex.as_ref(),
                *case_insensitive,
                ctx,
            ),
            Condition::LayerPath { value } => eval_layer_path(value, ctx),
            Condition::Kv { .. } => {
                // Delegate to kv evaluator
                let file_path = std::path::Path::new(&ctx.report.target.path);
                if let Some(evidence) =
                    super::evaluators::evaluate_kv(condition, ctx.binary_data, file_path)
                {
                    ConditionResult::matched_with(vec![evidence])
                } else {
                    ConditionResult::no_match()
                }
            }
        }
    }
}

/// Boolean logic for combining conditions/traits
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeTrait {
    pub id: String,
    pub desc: String,
    pub conf: f32,

    /// Criticality level (defaults to None)
    #[serde(default)]
    pub crit: Criticality,

    /// MBC (Malware Behavior Catalog) ID - most specific available (e.g., "B0015.001")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mbc: Option<String>,

    /// MITRE ATT&CK Technique ID (e.g., "T1056.001")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attack: Option<String>,

    #[serde(default = "default_platforms")]
    pub platforms: Vec<Platform>,

    #[serde(default = "default_file_types")]
    pub r#for: Vec<FileType>,

    /// Minimum file size in bytes
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size_min: Option<usize>,

    /// Maximum file size in bytes
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size_max: Option<usize>,

    // Boolean operators
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all: Option<Vec<Condition>>,

    /// List of conditions - use `needs` to control how many must match
    #[serde(skip_serializing_if = "Option::is_none")]
    pub any: Option<Vec<Condition>>,

    /// Minimum number of conditions from `any` that must match
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub none: Option<Vec<Condition>>,

    /// Proximity constraint: at least count_min findings must be within N lines
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub near_lines: Option<usize>,

    /// Proximity constraint: at least count_min findings must be within N bytes/characters
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub near_bytes: Option<usize>,

    /// File-level skip conditions - skip entire rule if ANY condition matches
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub unless: Option<Vec<Condition>>,

    /// String-level exceptions - filter matched strings
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub not: Option<Vec<NotException>>,

    /// Criticality downgrade rules - map of target criticality to conditions
    /// Only levels LOWER than base `crit` are allowed (validated at load time)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub downgrade: Option<DowngradeConditions>,
}

impl CompositeTrait {
    /// Pre-compile all regexes in this rule's conditions for performance.
    /// Returns an error if any regex pattern is invalid.
    pub fn precompile_regexes(&mut self) -> anyhow::Result<()> {
        if let Some(ref mut conds) = self.all {
            for (idx, cond) in conds.iter_mut().enumerate() {
                cond.precompile_regexes()
                    .with_context(|| format!("in composite rule '{}' all condition #{}", self.id, idx + 1))?;
            }
        }
        if let Some(ref mut conds) = self.any {
            for (idx, cond) in conds.iter_mut().enumerate() {
                cond.precompile_regexes()
                    .with_context(|| format!("in composite rule '{}' any condition #{}", self.id, idx + 1))?;
            }
        }
        if let Some(ref mut conds) = self.none {
            for (idx, cond) in conds.iter_mut().enumerate() {
                cond.precompile_regexes()
                    .with_context(|| format!("in composite rule '{}' none condition #{}", self.id, idx + 1))?;
            }
        }
        if let Some(ref mut conds) = self.unless {
            for (idx, cond) in conds.iter_mut().enumerate() {
                cond.precompile_regexes()
                    .with_context(|| format!("in composite rule '{}' unless condition #{}", self.id, idx + 1))?;
            }
        }
        if let Some(ref mut downgrade) = self.downgrade {
            if let Some(ref mut any) = downgrade.any {
                for (idx, cond) in any.iter_mut().enumerate() {
                    cond.precompile_regexes()
                        .with_context(|| format!("in composite rule '{}' downgrade.any condition #{}", self.id, idx + 1))?;
                }
            }
            if let Some(ref mut all) = downgrade.all {
                for (idx, cond) in all.iter_mut().enumerate() {
                    cond.precompile_regexes()
                        .with_context(|| format!("in composite rule '{}' downgrade.all condition #{}", self.id, idx + 1))?;
                }
            }
            if let Some(ref mut none) = downgrade.none {
                for (idx, cond) in none.iter_mut().enumerate() {
                    cond.precompile_regexes()
                        .with_context(|| format!("in composite rule '{}' downgrade.none condition #{}", self.id, idx + 1))?;
                }
            }
        }
        Ok(())
    }

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
        if let Some(ref mut conds) = self.unless {
            for cond in conds.iter_mut() {
                cond.compile_yara();
            }
        }
    }

    /// Evaluate this rule against the analysis context
    pub fn evaluate(&self, ctx: &EvaluationContext) -> Option<Finding> {
        use super::debug::{DowngradeDebug, ProximityDebug, SkipReason};

        // Check platform match
        let platform_match = self.platforms.contains(&Platform::All)
            || ctx.platforms.contains(&Platform::All)
            || self.platforms.iter().any(|p| ctx.platforms.contains(p));

        if !platform_match {
            if let Some(collector) = &ctx.debug_collector {
                if let Ok(mut debug) = collector.write() {
                    debug.record_skip(SkipReason::PlatformMismatch {
                        rule: self.platforms.clone(),
                        context: ctx.platforms.clone(),
                    });
                }
            }
            return None;
        }

        // Check file type match
        let file_type_match = self.r#for.contains(&FileType::All)
            || ctx.file_type == FileType::All
            || self.r#for.contains(&ctx.file_type);

        if !file_type_match {
            if let Some(collector) = &ctx.debug_collector {
                if let Ok(mut debug) = collector.write() {
                    debug.record_skip(SkipReason::FileTypeMismatch {
                        rule: self.r#for.clone(),
                        context: ctx.file_type,
                    });
                }
            }
            return None;
        }

        // Check size constraints
        let file_size = ctx.report.target.size_bytes as usize;
        if let Some(min) = self.size_min {
            if file_size < min {
                if let Some(collector) = &ctx.debug_collector {
                    if let Ok(mut debug) = collector.write() {
                        debug.record_skip(SkipReason::SizeTooSmall {
                            actual: file_size,
                            min,
                        });
                    }
                }
                return None;
            }
        }
        if let Some(max) = self.size_max {
            if file_size > max {
                if let Some(collector) = &ctx.debug_collector {
                    if let Ok(mut debug) = collector.write() {
                        debug.record_skip(SkipReason::SizeTooLarge {
                            actual: file_size,
                            max,
                        });
                    }
                }
                return None;
            }
        }

        // Check unless conditions (file-level skip)
        if let Some(unless_conds) = &self.unless {
            // Default 'any' semantics: skip if ANY condition matches
            for condition in unless_conds {
                let result = self.eval_condition(condition, ctx);
                if result.matched {
                    if let Some(collector) = &ctx.debug_collector {
                        if let Ok(mut debug) = collector.write() {
                            debug.record_skip(SkipReason::UnlessConditionMatched {
                                condition_desc: format!("{:?}", condition),
                            });
                        }
                    }
                    return None;
                }
            }
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
                    precision: 0.0,
                }
            }
            (Some(conds), None) => self.eval_requires_all(conds, ctx),
            (None, Some(conds)) => {
                // Handle needs constraint on `any` conditions
                if let Some(required_count) = self.needs {
                    self.eval_count_constraints(conds, None, Some(required_count), None, ctx)
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
                    precision: 0.0,
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
                precision: 0.0,
            }
        } else if !has_positive {
            // No positive conditions and no none - invalid rule
            return None;
        } else {
            positive_result
        };

        if result.matched {
            // Check proximity constraints (near_lines, near_bytes)
            let proximity_result = self.check_proximity_constraints(result.evidence.clone());

            // Record proximity debug if applicable
            if self.near_lines.is_some() || self.near_bytes.is_some() {
                if let Some(collector) = &ctx.debug_collector {
                    if let Ok(mut debug) = collector.write() {
                        let constraint_type = if self.near_lines.is_some() {
                            "near_lines"
                        } else {
                            "near_bytes"
                        };
                        let max_span = self.near_lines.or(self.near_bytes).unwrap_or(0);
                        debug.set_proximity(ProximityDebug {
                            constraint_type: constraint_type.to_string(),
                            max_span,
                            min_required: self.needs.unwrap_or(1).max(1),
                            satisfied: proximity_result.is_some(),
                            positions: Vec::new(), // Could extract from evidence
                        });
                    }
                }
            }

            let evidence = proximity_result?;

            // Boost precision if proximity constraints were applied
            let mut precision_boost = 0.0;
            if self.near_lines.is_some() || self.near_bytes.is_some() {
                precision_boost = 1.0;
            }

            let mut final_crit = self.crit;

            // Check downgrade conditions
            if let Some(downgrade_conds) = &self.downgrade {
                let debug_downgrade = std::env::var("DEBUG_DOWNGRADE").is_ok();
                if debug_downgrade {
                    eprintln!(
                        "DEBUG: Evaluating downgrade for composite '{}' (current: {:?})",
                        self.id, self.crit
                    );
                }
                let triggered = self.eval_downgrade_conditions(downgrade_conds, ctx);
                if triggered {
                    final_crit = match self.crit {
                        Criticality::Hostile => Criticality::Suspicious,
                        Criticality::Suspicious => Criticality::Notable,
                        Criticality::Notable | Criticality::Inert | Criticality::Filtered => {
                            Criticality::Inert
                        }
                    };
                }

                // Record downgrade debug
                if let Some(collector) = &ctx.debug_collector {
                    if let Ok(mut debug) = collector.write() {
                        debug.set_downgrade(DowngradeDebug {
                            original_crit: self.crit,
                            final_crit,
                            triggered,
                            conditions: Vec::new(),
                        });
                    }
                }

                if debug_downgrade {
                    eprintln!(
                        "DEBUG: Final criticality for composite '{}': {:?}",
                        self.id, final_crit
                    );
                }
            }

            // Record match in debug collector
            if let Some(collector) = &ctx.debug_collector {
                if let Ok(mut debug) = collector.write() {
                    debug.matched = true;
                    debug.precision = result.precision + precision_boost;
                }
            }

            let boosted_conf = (self.conf + precision_boost).min(1.0);

            Some(Finding {
                id: self.id.clone(),
                kind: FindingKind::Capability,
                desc: self.desc.clone(),
                conf: boosted_conf,
                crit: final_crit,
                mbc: self.mbc.clone(),
                attack: self.attack.clone(),
                trait_refs: vec![],
                evidence,
            })
        } else {
            None
        }
    }

    /// Evaluate downgrade conditions and return final criticality.
    /// Public so that mapper can re-evaluate downgrades after all findings are collected.
    /// When matched, drops one level: hostile→suspicious→notable→inert
    pub fn evaluate_downgrade(
        &self,
        conditions: &DowngradeConditions,
        base_crit: &Criticality,
        ctx: &EvaluationContext,
    ) -> Criticality {
        if self.eval_downgrade_conditions(conditions, ctx) {
            return match base_crit {
                Criticality::Hostile => Criticality::Suspicious,
                Criticality::Suspicious => Criticality::Notable,
                Criticality::Notable | Criticality::Inert | Criticality::Filtered => {
                    Criticality::Inert
                }
            };
        }
        *base_crit
    }

    /// Evaluate a single downgrade condition set
    fn eval_downgrade_conditions(
        &self,
        conditions: &DowngradeConditions,
        ctx: &EvaluationContext,
    ) -> bool {
        let debug_downgrade = std::env::var("DEBUG_DOWNGRADE").is_ok();

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
            for (i, cond) in any_conds.iter().enumerate() {
                let result = self.eval_condition(cond, ctx);
                if debug_downgrade {
                    eprintln!(
                        "DEBUG CompositeTrait: downgrade any[{}] cond={:?} matched={}",
                        i, cond, result.matched
                    );
                }
                if result.matched {
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

    /// Evaluate ALL conditions must match (AND)
    fn eval_requires_all(&self, conds: &[Condition], ctx: &EvaluationContext) -> ConditionResult {
        let mut all_evidence = Vec::new();
        let mut total_precision = 0.0f32;

        for condition in conds {
            let result = self.eval_condition(condition, ctx);
            if !result.matched {
                return ConditionResult {
                    matched: false,
                    evidence: Vec::new(),
                    traits: Vec::new(),
                    warnings: Vec::new(),
                    precision: 0.0,
                };
            }
            all_evidence.extend(result.evidence);
            total_precision += result.precision; // SUM for 'all'
        }

        ConditionResult {
            matched: true,
            evidence: all_evidence,
            traits: Vec::new(),
            warnings: Vec::new(),
            precision: total_precision,
        }
    }

    /// Evaluate at least ONE condition must match (OR)
    /// Collects evidence from ALL matching conditions, not just the first
    fn eval_requires_any(&self, conds: &[Condition], ctx: &EvaluationContext) -> ConditionResult {
        let mut any_matched = false;
        let mut all_evidence = Vec::new();
        let mut min_precision = f32::MAX;

        for condition in conds {
            let result = self.eval_condition(condition, ctx);
            if result.matched {
                any_matched = true;
                all_evidence.extend(result.evidence);
                min_precision = min_precision.min(result.precision); // MIN for 'any'
            }
        }

        let precision = if any_matched { min_precision } else { 0.0 };

        ConditionResult {
            matched: any_matched,
            evidence: all_evidence,
            traits: Vec::new(),
            warnings: Vec::new(),
            precision,
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
        let mut precision_sum = 0.0f32;

        for condition in conds.iter() {
            let result = self.eval_condition(condition, ctx);
            if result.matched {
                matched_count += 1;
                all_evidence.extend(result.evidence);
                precision_sum += result.precision;
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

        // Calculate precision: average + 0.5 bonus for count constraint
        let avg_precision = if matched_count > 0 {
            (precision_sum / matched_count as f32) + 0.5 // +0.5 bonus for count constraint
        } else {
            0.0
        };

        ConditionResult {
            matched,
            evidence: if matched { all_evidence } else { Vec::new() },
            traits: Vec::new(),
            warnings: Vec::new(),
            precision: avg_precision,
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
                    precision: 0.0,
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
            precision: 0.5, // Fixed +0.5 for exclusion logic (negative conditions)
        }
    }

    /// Evaluate a single condition
    fn eval_condition(&self, condition: &Condition, ctx: &EvaluationContext) -> ConditionResult {
        match condition {
            Condition::Symbol {
                exact,
                substr,
                regex,
                platforms,
                compiled_regex,
            } => self.eval_symbol(
                exact.as_ref(),
                substr.as_ref(),
                regex.as_ref(),
                platforms.as_ref(),
                compiled_regex.as_ref(),
                ctx,
            ),
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
                compiled_regex,
                compiled_excludes,
            } => {
                let params = StringParams {
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    exclude_patterns: exclude_patterns.as_ref(),
                    count_min: *count_min,
                    count_max: *count_max,
                    per_kb_min: *per_kb_min,
                    per_kb_max: *per_kb_max,
                    external_ip: *external_ip,
                    compiled_regex: compiled_regex.as_ref(),
                    compiled_excludes,
                    section: section.as_ref(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
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
            Condition::Ast {
                kind,
                node,
                exact,
                substr,
                regex,
                query,
                case_insensitive,
                ..
            } => eval_ast(
                kind.as_deref(),
                node.as_deref(),
                exact.as_deref(),
                substr.as_deref(),
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
                count_min,
                count_max,
                per_kb_min,
                per_kb_max,
                extract_wildcards,
                section,
                section_offset,
                section_offset_range,
            } => eval_hex(
                pattern,
                *count_min,
                *count_max,
                *per_kb_min,
                *per_kb_max,
                *extract_wildcards,
                &ContentLocationParams {
                    section: section.clone(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                },
                ctx,
            ),
            Condition::Filesize { min, max } => eval_filesize(*min, *max, ctx),
            Condition::TraitGlob { pattern, r#match } => eval_trait_glob(pattern, r#match, ctx),
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
                compiled_regex,
            } => {
                use super::evaluators::ContentLocationParams;
                let location = ContentLocationParams {
                    section: section.clone(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                };
                eval_raw(
                    exact.as_ref(),
                    substr.as_ref(),
                    regex.as_ref(),
                    word.as_ref(),
                    *case_insensitive,
                    *count_min,
                    *count_max,
                    *per_kb_min,
                    *per_kb_max,
                    *external_ip,
                    compiled_regex.as_ref(),
                    self.not.as_ref(),
                    &location,
                    ctx,
                )
            }
            Condition::SectionName { pattern, regex } => eval_section_name(pattern, *regex, ctx),
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
            } => {
                use super::evaluators::ContentLocationParams;
                let location = ContentLocationParams {
                    section: section.clone(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                };
                eval_base64(
                    exact.as_ref(),
                    substr.as_ref(),
                    regex.as_ref(),
                    *case_insensitive,
                    *count_min,
                    *count_max,
                    *per_kb_min,
                    *per_kb_max,
                    &location,
                    ctx,
                )
            }
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
            } => {
                use super::evaluators::ContentLocationParams;
                let location = ContentLocationParams {
                    section: section.clone(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                };
                eval_xor(
                    key.as_ref(),
                    exact.as_ref(),
                    substr.as_ref(),
                    regex.as_ref(),
                    *case_insensitive,
                    *count_min,
                    *count_max,
                    *per_kb_min,
                    *per_kb_max,
                    &location,
                    ctx,
                )
            }
            Condition::Basename {
                exact,
                substr,
                regex,
                case_insensitive,
            } => eval_basename(
                exact.as_ref(),
                substr.as_ref(),
                regex.as_ref(),
                *case_insensitive,
                ctx,
            ),
            Condition::LayerPath { value } => eval_layer_path(value, ctx),
            Condition::Kv { .. } => {
                // Delegate to kv evaluator
                let file_path = std::path::Path::new(&ctx.report.target.path);
                if let Some(evidence) =
                    super::evaluators::evaluate_kv(condition, ctx.binary_data, file_path)
                {
                    ConditionResult::matched_with(vec![evidence])
                } else {
                    ConditionResult::no_match()
                }
            }
        }
    }

    /// Evaluate symbol condition
    fn eval_symbol(
        &self,
        exact: Option<&String>,
        substr: Option<&String>,
        pattern: Option<&String>,
        platforms: Option<&Vec<Platform>>,
        compiled_regex: Option<&regex::Regex>,
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        // Check platform constraint
        // Match if: trait allows All platforms, OR context includes All (no --platforms filter),
        // OR trait's platforms intersect with context's platforms
        if let Some(plats) = platforms {
            let platform_match = plats.contains(&Platform::All)
                || ctx.platforms.contains(&Platform::All)
                || plats.iter().any(|p| ctx.platforms.contains(p));
            if !platform_match {
                return ConditionResult {
                    matched: false,
                    evidence: Vec::new(),
                    traits: Vec::new(),
                    warnings: Vec::new(),
                    precision: 0.0,
                };
            }
        }

        eval_symbol(exact, substr, pattern, None, compiled_regex, None, ctx)
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
            precision: 0.0,
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
            precision: 0.0,
        }
    }

    /// Check if evidence satisfies proximity constraints
    /// Returns None if constraints fail, otherwise returns the filtered evidence
    fn check_proximity_constraints(&self, evidence: Vec<Evidence>) -> Option<Vec<Evidence>> {
        // If no proximity constraints, pass through
        if self.near_lines.is_none() && self.near_bytes.is_none() {
            return Some(evidence);
        }

        // Get the minimum required matches (needs or 1)
        let min_required = self.needs.unwrap_or(1).max(1);

        // Check near_lines constraint
        if let Some(max_line_span) = self.near_lines {
            if !self.evidence_within_line_range(&evidence, max_line_span, min_required) {
                return None;
            }
        }

        // Check near_bytes constraint
        if let Some(max_byte_span) = self.near_bytes {
            if !self.evidence_within_byte_range(&evidence, max_byte_span, min_required) {
                return None;
            }
        }

        Some(evidence)
    }

    /// Check if at least min_required evidence items have line numbers within max_line_span
    /// Location format is "line:column" (e.g., "42:5")
    fn evidence_within_line_range(
        &self,
        evidence: &[Evidence],
        max_line_span: usize,
        min_required: usize,
    ) -> bool {
        // Extract line numbers from evidence
        let mut line_numbers: Vec<usize> = evidence
            .iter()
            .filter_map(|e| {
                e.location.as_ref().and_then(|loc| {
                    loc.split(':')
                        .next()
                        .and_then(|line_str| line_str.parse::<usize>().ok())
                })
            })
            .collect();

        if line_numbers.len() < min_required {
            return false; // Not enough evidence with line numbers
        }

        // Sort to find the smallest window
        line_numbers.sort_unstable();

        // Check all possible windows of size max_line_span to see if we can fit min_required items
        for i in 0..line_numbers.len() {
            let start_line = line_numbers[i];
            let mut count = 0;
            for &line in line_numbers[i..].iter() {
                if line - start_line <= max_line_span {
                    count += 1;
                    if count >= min_required {
                        return true;
                    }
                } else {
                    break;
                }
            }
        }

        false
    }

    /// Check if at least min_required evidence items have byte offsets within max_byte_span
    /// Location format can be "line:column" where we extract the byte offset, or direct byte offsets
    fn evidence_within_byte_range(
        &self,
        evidence: &[Evidence],
        max_byte_span: usize,
        min_required: usize,
    ) -> bool {
        // Extract byte offsets from evidence
        let mut byte_offsets: Vec<usize> = evidence
            .iter()
            .filter_map(|e| {
                e.location.as_ref().and_then(|loc| {
                    // Try to parse as direct byte offset first
                    if let Ok(offset) = loc.parse::<usize>() {
                        return Some(offset);
                    }
                    // Otherwise try "line:column" format - column is often byte position within line
                    loc.split(':')
                        .nth(1)
                        .and_then(|col_str| col_str.parse::<usize>().ok())
                })
            })
            .collect();

        if byte_offsets.len() < min_required {
            return false; // Not enough evidence with byte offsets
        }

        // Sort to find the smallest window
        byte_offsets.sort_unstable();

        // Check all possible windows of size max_byte_span
        for i in 0..byte_offsets.len() {
            let start_offset = byte_offsets[i];
            let mut count = 0;
            for &offset in byte_offsets[i..].iter() {
                if offset - start_offset <= max_byte_span {
                    count += 1;
                    if count >= min_required {
                        return true;
                    }
                } else {
                    break;
                }
            }
        }

        false
    }

    /// Returns true if this rule has negative (none) conditions
    pub fn has_negative_conditions(&self) -> bool {
        self.none.as_ref().map(|n| !n.is_empty()).unwrap_or(false)
    }
}
