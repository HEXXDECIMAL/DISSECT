//! Debug/test rule evaluation module.
//!
//! This module provides detailed tracing of rule evaluation for debugging purposes.
//! It shows exactly why rules match or fail, including:
//! - For composites: which conditions matched and which didn't
//! - What values were actually matched against
//! - Regex patterns being used
//! - Context about available data (strings, symbols, etc.)

use crate::capabilities::CapabilityMapper;
use crate::capabilities::validation::calculate_composite_precision;
use crate::composite_rules::{
    eval_trait, Condition, CompositeTrait, EvaluationContext, FileType as RuleFileType,
    Platform, TraitDefinition,
};
use crate::types::{AnalysisReport, Evidence};
use colored::Colorize;
use std::collections::{HashMap, HashSet};

/// Result of debugging a single condition
#[derive(Debug)]
pub struct ConditionDebugResult {
    pub condition_desc: String,
    pub matched: bool,
    pub evidence: Vec<Evidence>,
    pub details: Vec<String>,
    pub sub_results: Vec<ConditionDebugResult>,
}

impl ConditionDebugResult {
    fn new(condition_desc: String, matched: bool) -> Self {
        Self {
            condition_desc,
            matched,
            evidence: Vec::new(),
            details: Vec::new(),
            sub_results: Vec::new(),
        }
    }

    fn with_detail(mut self, detail: String) -> Self {
        self.details.push(detail);
        self
    }

    fn with_evidence(mut self, evidence: Vec<Evidence>) -> Self {
        self.evidence = evidence;
        self
    }
}

/// Result of debugging an entire rule
#[derive(Debug)]
pub struct RuleDebugResult {
    pub rule_id: String,
    pub rule_type: String, // "trait" or "composite"
    pub description: String,
    pub matched: bool,
    pub skipped_reason: Option<String>,
    pub requirements: String,
    pub condition_results: Vec<ConditionDebugResult>,
    pub context_info: ContextInfo,
    pub precision: Option<f32>,
}

/// Information about the analysis context
#[derive(Debug, Default)]
pub struct ContextInfo {
    pub file_type: String,
    pub platform: String,
    pub string_count: usize,
    pub symbol_count: usize,
    pub import_count: usize,
    pub export_count: usize,
    pub finding_count: usize,
    pub sample_strings: Vec<String>,
    pub sample_symbols: Vec<String>,
}

/// Debug evaluator that traces through rule matching
pub struct RuleDebugger<'a> {
    mapper: &'a CapabilityMapper,
    report: &'a AnalysisReport,
    binary_data: &'a [u8],
    file_type: RuleFileType,
    platform: Platform,
    composites: &'a [CompositeTrait],
    traits: &'a [TraitDefinition],
}

impl<'a> RuleDebugger<'a> {
    pub fn new(
        mapper: &'a CapabilityMapper,
        report: &'a AnalysisReport,
        binary_data: &'a [u8],
        composites: &'a [CompositeTrait],
        traits: &'a [TraitDefinition],
    ) -> Self {
        let platform = detect_platform(&report.target.file_type);
        let file_type = detect_file_type(&report.target.file_type);

        Self {
            mapper,
            report,
            binary_data,
            file_type,
            platform,
            composites,
            traits,
        }
    }

    /// Get context information about the analysis
    pub fn context_info(&self) -> ContextInfo {
        let strings: Vec<String> = self
            .report
            .strings
            .iter()
            .map(|s| s.value.clone())
            .collect();
        let symbols: Vec<String> = self
            .report
            .imports
            .iter()
            .map(|i| i.symbol.clone())
            .chain(self.report.exports.iter().map(|e| e.symbol.clone()))
            .collect();

        ContextInfo {
            file_type: format!("{:?}", self.file_type),
            platform: format!("{:?}", self.platform),
            string_count: strings.len(),
            symbol_count: symbols.len(),
            import_count: self.report.imports.len(),
            export_count: self.report.exports.len(),
            finding_count: self.report.findings.len(),
            sample_strings: strings.into_iter().take(20).collect(),
            sample_symbols: symbols.into_iter().take(20).collect(),
        }
    }

    /// Debug a specific rule by ID
    pub fn debug_rule(&self, rule_id: &str) -> Option<RuleDebugResult> {
        // First try to find as a trait definition
        if let Some(result) = self.debug_trait(rule_id) {
            return Some(result);
        }

        // Then try as a composite rule
        if let Some(result) = self.debug_composite(rule_id) {
            return Some(result);
        }

        None
    }

    /// Debug a trait definition
    fn debug_trait(&self, rule_id: &str) -> Option<RuleDebugResult> {
        // Access trait definitions through the mapper
        // We need to find the trait by ID
        let trait_def = self.find_trait_definition(rule_id)?;

        // Calculate precision
        let mut cache = HashMap::new();
        let mut visiting = HashSet::new();
        let precision_value = calculate_composite_precision(
            rule_id,
            self.composites,
            self.traits,
            &mut cache,
            &mut visiting,
        );

        let mut result = RuleDebugResult {
            rule_id: trait_def.id.clone(),
            rule_type: "trait".to_string(),
            description: trait_def.desc.clone(),
            matched: false,
            skipped_reason: None,
            requirements: format!("Condition: {:?}", describe_condition(&trait_def.r#if)),
            condition_results: Vec::new(),
            context_info: self.context_info(),
            precision: Some(precision_value as f32),
        };

        // Check platform/file type constraints
        let platform_match = trait_def
            .platforms
            .iter()
            .any(|p| *p == Platform::All || *p == self.platform);
        let file_type_match = trait_def
            .r#for
            .iter()
            .any(|f| *f == RuleFileType::All || *f == self.file_type);

        if !platform_match {
            result.skipped_reason = Some(format!(
                "Platform mismatch: rule requires {:?}, file is {:?}",
                trait_def.platforms, self.platform
            ));
            return Some(result);
        }

        if !file_type_match {
            result.skipped_reason = Some(format!(
                "File type mismatch: rule requires {:?}, file is {:?}",
                trait_def.r#for, self.file_type
            ));
            return Some(result);
        }

        // Check unless conditions
        if let Some(unless_conds) = &trait_def.unless {
            for cond in unless_conds {
                let cond_result = self.debug_condition(cond);
                if cond_result.matched {
                    result.skipped_reason = Some(format!(
                        "Skipped by 'unless' condition: {}",
                        cond_result.condition_desc
                    ));
                    result.condition_results.push(cond_result);
                    return Some(result);
                }
            }
        }

        // Evaluate the main condition
        let cond_result = self.debug_condition(&trait_def.r#if);
        result.matched = cond_result.matched;
        result.condition_results.push(cond_result);

        Some(result)
    }

    /// Debug a composite rule
    fn debug_composite(&self, rule_id: &str) -> Option<RuleDebugResult> {
        let composite = self.find_composite_rule(rule_id)?;

        // Calculate precision
        let mut cache = HashMap::new();
        let mut visiting = HashSet::new();
        let precision_value = calculate_composite_precision(
            rule_id,
            self.composites,
            self.traits,
            &mut cache,
            &mut visiting,
        );

        let mut result = RuleDebugResult {
            rule_id: composite.id.clone(),
            rule_type: "composite".to_string(),
            description: composite.desc.clone(),
            matched: false,
            skipped_reason: None,
            requirements: build_composite_requirements(composite),
            condition_results: Vec::new(),
            context_info: self.context_info(),
            precision: Some(precision_value as f32),
        };

        // Check platform/file type constraints
        let platform_match = composite
            .platforms
            .iter()
            .any(|p| *p == Platform::All || *p == self.platform);
        let file_type_match = composite
            .r#for
            .iter()
            .any(|f| *f == RuleFileType::All || *f == self.file_type);

        if !platform_match {
            result.skipped_reason = Some(format!(
                "Platform mismatch: rule requires {:?}, file is {:?}",
                composite.platforms, self.platform
            ));
            return Some(result);
        }

        if !file_type_match {
            result.skipped_reason = Some(format!(
                "File type mismatch: rule requires {:?}, file is {:?}",
                composite.r#for, self.file_type
            ));
            return Some(result);
        }

        // Evaluate 'all' conditions
        let mut all_matched = true;
        let mut all_results = Vec::new();
        if let Some(all_conds) = &composite.all {
            for cond in all_conds {
                let cond_result = self.debug_condition(cond);
                if !cond_result.matched {
                    all_matched = false;
                }
                all_results.push(cond_result);
            }
        }

        // Evaluate 'any' conditions with count constraints
        let mut any_matched_count = 0;
        let mut any_results = Vec::new();
        if let Some(any_conds) = &composite.any {
            for cond in any_conds {
                let cond_result = self.debug_condition(cond);
                if cond_result.matched {
                    any_matched_count += 1;
                }
                any_results.push(cond_result);
            }
        }

        // Evaluate 'none' conditions
        let mut none_passed = true;
        let mut none_results = Vec::new();
        if let Some(none_conds) = &composite.none {
            for cond in none_conds {
                let cond_result = self.debug_condition(cond);
                if cond_result.matched {
                    none_passed = false;
                }
                none_results.push(cond_result);
            }
        }

        // Check needs constraint for 'any'
        let any_satisfied = if composite.any.is_some() {
            if let Some(needed) = composite.needs {
                any_matched_count >= needed
            } else {
                any_matched_count > 0
            }
        } else {
            true
        };

        // Combine results
        result.matched = all_matched && any_satisfied && none_passed;

        // Add all results with appropriate labels
        if !all_results.is_empty() {
            let mut group = ConditionDebugResult::new(
                format!(
                    "all: ({}/{})",
                    all_results.iter().filter(|r| r.matched).count(),
                    all_results.len()
                ),
                all_matched,
            );
            group.sub_results = all_results;
            result.condition_results.push(group);
        }

        if !any_results.is_empty() {
            let count_info = if let Some(needed) = composite.needs {
                format!("at least {}", needed)
            } else {
                "at least 1".to_string()
            };

            let mut group = ConditionDebugResult::new(
                format!(
                    "any: ({}/{}) [{}]",
                    any_matched_count,
                    any_results.len(),
                    count_info
                ),
                any_satisfied,
            );
            group.sub_results = any_results;
            result.condition_results.push(group);
        }

        if !none_results.is_empty() {
            let none_matched = none_results.iter().filter(|r| r.matched).count();
            let mut group = ConditionDebugResult::new(
                format!("none: ({} matched, need 0)", none_matched),
                none_passed,
            );
            group.sub_results = none_results;
            result.condition_results.push(group);
        }

        Some(result)
    }

    /// Debug a single condition
    fn debug_condition(&self, condition: &Condition) -> ConditionDebugResult {
        let ctx = EvaluationContext {
            report: self.report,
            binary_data: self.binary_data,
            file_type: self.file_type,
            platform: self.platform.clone(),
            additional_findings: None,
            cached_ast: None,
            finding_id_index: None,
        };

        match condition {
            Condition::Trait { id } => self.debug_trait_reference(id),
            Condition::String {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                min_count,
                ..
            } => self.debug_string_condition(
                exact,
                substr,
                regex,
                word,
                *case_insensitive,
                *min_count,
            ),
            Condition::Symbol { exact, regex, .. } => self.debug_symbol_condition(exact, regex),
            Condition::Metrics {
                field, min, max, ..
            } => self.debug_metrics_condition(field, *min, *max),
            Condition::YaraMatch { namespace, rule } => {
                self.debug_yara_match_condition(namespace, rule.as_ref())
            }
            Condition::Yara { source, .. } => self.debug_yara_inline_condition(source),
            Condition::Structure { feature, .. } => self.debug_structure_condition(feature),
            Condition::Content {
                regex,
                substr,
                exact,
                word,
                ..
            } => self.debug_content_condition(exact, substr, regex, word),
            Condition::Ast {
                kind,
                node,
                exact,
                substr,
                regex,
                query,
                case_insensitive,
                ..
            } => {
                self.debug_ast_condition(kind, node, exact, substr, regex, query, *case_insensitive)
            }
            _ => {
                // Generic fallback for other condition types
                let desc = describe_condition(condition);
                let result = evaluate_condition_simple(condition, &ctx);
                ConditionDebugResult::new(desc, result.matched).with_evidence(result.evidence)
            }
        }
    }

    fn debug_trait_reference(&self, id: &str) -> ConditionDebugResult {
        let desc = format!("trait: {}", id);

        // Use the same trait resolver as runtime evaluation
        // This supports both exact matches and directory prefix matches
        let ctx = EvaluationContext {
            report: self.report,
            binary_data: self.binary_data,
            file_type: self.file_type,
            platform: self.platform.clone(),
            additional_findings: None,
            cached_ast: None,
            finding_id_index: None,
        };

        let eval_result = eval_trait(id, &ctx);
        let mut result = ConditionDebugResult::new(desc, eval_result.matched);

        if eval_result.matched {
            result.details.push(format!(
                "Found in findings with {} evidence items",
                eval_result.evidence.len()
            ));
            result.evidence = eval_result.evidence;
        } else {
            // Try to debug why the trait didn't match
            // First check if it's an exact trait definition ID
            if let Some(trait_result) = self.debug_trait(id) {
                result.details.push(format!("Trait '{}' did not match", id));
                if let Some(reason) = &trait_result.skipped_reason {
                    result.details.push(format!("Reason: {}", reason));
                }
                result.sub_results = trait_result.condition_results;
            } else if self.find_composite_rule(id).is_some() {
                // It's a composite rule ID but didn't match - composite evaluation
                // results are already in the findings, so this means conditions weren't met
                result.details.push(format!(
                    "Composite rule '{}' did not match (required conditions not met)",
                    id
                ));
            } else {
                // Not an exact trait ID, check if it's a directory prefix reference
                let slash_count = id.matches('/').count();
                if slash_count > 0 {
                    // Directory path reference - show what traits exist in that directory
                    let matching_findings: Vec<_> = self
                        .report
                        .findings
                        .iter()
                        .filter(|f| f.id.starts_with(&format!("{}/", id)))
                        .collect();

                    if matching_findings.is_empty() {
                        result
                            .details
                            .push(format!("No traits matched in directory '{}/'", id));
                        // Show available trait prefixes for debugging
                        let available_prefixes: std::collections::HashSet<_> = self
                            .report
                            .findings
                            .iter()
                            .filter_map(|f| f.id.rfind('/').map(|i| &f.id[..i]))
                            .collect();
                        if !available_prefixes.is_empty() {
                            let mut prefixes: Vec<_> = available_prefixes.into_iter().collect();
                            prefixes.sort();
                            result.details.push(format!(
                                "Available trait directories: {}",
                                prefixes.join(", ")
                            ));
                        }
                    }
                } else {
                    result
                        .details
                        .push(format!("Trait '{}' not found in definitions", id));
                }
            }
        }

        result
    }

    fn debug_string_condition(
        &self,
        exact: &Option<String>,
        substr: &Option<String>,
        regex: &Option<String>,
        word: &Option<String>,
        case_insensitive: bool,
        min_count: usize,
    ) -> ConditionDebugResult {
        let pattern_desc = if let Some(e) = exact {
            format!("exact: \"{}\"", e)
        } else if let Some(c) = substr {
            format!("substr: \"{}\"", c)
        } else if let Some(r) = regex {
            format!("regex: /{}/", r)
        } else if let Some(w) = word {
            format!("word: \"{}\"", w)
        } else {
            "unknown".to_string()
        };

        let desc = format!(
            "string: {} (min_count: {}{})",
            pattern_desc,
            min_count,
            if case_insensitive {
                ", case_insensitive"
            } else {
                ""
            }
        );

        let strings: Vec<&str> = self
            .report
            .strings
            .iter()
            .map(|s| s.value.as_str())
            .collect();
        let matched_strings =
            find_matching_strings(&strings, exact, substr, regex, word, case_insensitive);

        let matched = matched_strings.len() >= min_count;

        let mut result = ConditionDebugResult::new(desc, matched);

        result
            .details
            .push(format!("Total strings in file: {}", strings.len()));
        result
            .details
            .push(format!("Matching strings: {}", matched_strings.len()));

        if !matched_strings.is_empty() {
            let display_count = matched_strings.len().min(10);
            for s in matched_strings.iter().take(display_count) {
                result
                    .details
                    .push(format!("  Matched: \"{}\"", truncate_string(s, 80)));
            }
            if matched_strings.len() > display_count {
                result.details.push(format!(
                    "  ... and {} more",
                    matched_strings.len() - display_count
                ));
            }

            result.evidence = matched_strings
                .iter()
                .take(5)
                .map(|s| Evidence {
                    method: "string".to_string(),
                    source: "test_rules".to_string(),
                    value: s.to_string(),
                    location: None,
                })
                .collect();

            // Suggest better match types
            if let Some(s) = substr {
                // Check if exact would work: all matched strings equal the pattern
                if matched_strings.iter().all(|m| {
                    if case_insensitive {
                        m.eq_ignore_ascii_case(s)
                    } else {
                        *m == s
                    }
                }) {
                    result.details.push(format!(
                        "💡 All matches are exact - consider using `exact: \"{}\"` instead of `substr:`",
                        s
                    ));
                } else {
                    // Check if word would be a better fit
                    let word_pattern = if case_insensitive {
                        format!(r"(?i)\b{}\b", regex::escape(s))
                    } else {
                        format!(r"\b{}\b", regex::escape(s))
                    };
                    if let Ok(re) = regex::Regex::new(&word_pattern) {
                        let word_matches: Vec<_> =
                            matched_strings.iter().filter(|m| re.is_match(m)).collect();
                        if word_matches.len() == matched_strings.len() {
                            result.details.push(format!(
                                "💡 All matches appear as whole words - consider using `word: \"{}\"` for precision",
                                s
                            ));
                        }
                    }
                }
            } else if let Some(r) = regex {
                // Check if regex could be simplified to exact or substr
                let simple_pattern = r
                    .replace(r"\.", ".")
                    .replace(r"\-", "-")
                    .replace(r"\_", "_");
                if !simple_pattern.contains(|c: char| "^$.*+?[](){}|\\".contains(c)) {
                    // Pattern has no regex metacharacters after unescaping common ones
                    if matched_strings.iter().all(|m| {
                        if case_insensitive {
                            m.eq_ignore_ascii_case(&simple_pattern)
                        } else {
                            *m == simple_pattern
                        }
                    }) {
                        result.details.push(format!(
                            "💡 Regex matches exact string - consider using `exact: \"{}\"` instead",
                            simple_pattern
                        ));
                    } else if matched_strings.iter().all(|m| m.contains(&simple_pattern)) {
                        result.details.push(format!(
                            "💡 Regex matches substring - consider using `substr: \"{}\"` instead",
                            simple_pattern
                        ));
                    }
                }
            }
        } else if strings.len() <= 20 {
            result.details.push("All strings in file:".to_string());
            for s in &strings {
                result
                    .details
                    .push(format!("  \"{}\"", truncate_string(s, 60)));
            }
        }

        // Check alternatives if string condition didn't match
        if !matched {
            // Check symbols (only for exact or regex patterns)
            if exact.is_some() || regex.is_some() {
                let symbols: Vec<&str> = self
                    .report
                    .imports
                    .iter()
                    .map(|i| i.symbol.as_str())
                    .chain(self.report.exports.iter().map(|e| e.symbol.as_str()))
                    .chain(self.report.functions.iter().map(|f| f.name.as_str()))
                    .collect();
                let symbol_matches = find_matching_symbols(&symbols, exact, regex);
                if !symbol_matches.is_empty() {
                    result.details.push(format!(
                        "💡 Found in symbols ({} matches) - try `symbol:` instead",
                        symbol_matches.len()
                    ));
                }
            }

            // Check content
            let content = String::from_utf8_lossy(self.binary_data);
            let content_matched = if let Some(e) = exact {
                &content == e
            } else if let Some(c) = substr {
                content.contains(c)
            } else if let Some(r) = regex {
                let pattern = if case_insensitive {
                    format!("(?i){}", r)
                } else {
                    r.clone()
                };
                regex::Regex::new(&pattern).is_ok_and(|re| re.is_match(&content))
            } else if let Some(w) = word {
                let pattern = if case_insensitive {
                    format!(r"(?i)\b{}\b", regex::escape(w))
                } else {
                    format!(r"\b{}\b", regex::escape(w))
                };
                regex::Regex::new(&pattern).is_ok_and(|re| re.is_match(&content))
            } else {
                false
            };
            if content_matched {
                result
                    .details
                    .push("💡 Found in content - try `content:` instead".to_string());
            }
        }

        result
    }

    fn debug_symbol_condition(
        &self,
        exact: &Option<String>,
        regex: &Option<String>,
    ) -> ConditionDebugResult {
        let pattern_desc = if let Some(e) = exact {
            format!("exact: \"{}\"", e)
        } else if let Some(r) = regex {
            format!("regex: /{}/", r)
        } else {
            "unknown".to_string()
        };

        let desc = format!("symbol: {}", pattern_desc);

        let symbols: Vec<&str> = self
            .report
            .imports
            .iter()
            .map(|i| i.symbol.as_str())
            .chain(self.report.exports.iter().map(|e| e.symbol.as_str()))
            .chain(self.report.functions.iter().map(|f| f.name.as_str()))
            .collect();

        let matched_symbols = find_matching_symbols(&symbols, exact, regex);
        let matched = !matched_symbols.is_empty();

        let mut result = ConditionDebugResult::new(desc, matched);

        result.details.push(format!(
            "Total symbols: {} ({} imports, {} exports)",
            symbols.len(),
            self.report.imports.len(),
            self.report.exports.len()
        ));
        result
            .details
            .push(format!("Matching symbols: {}", matched_symbols.len()));

        if !matched_symbols.is_empty() {
            let display_count = matched_symbols.len().min(10);
            for s in matched_symbols.iter().take(display_count) {
                result.details.push(format!("  Matched: \"{}\"", s));
            }
            if matched_symbols.len() > display_count {
                result.details.push(format!(
                    "  ... and {} more",
                    matched_symbols.len() - display_count
                ));
            }
        } else if symbols.len() <= 20 {
            result.details.push("All symbols:".to_string());
            for s in &symbols {
                result.details.push(format!("  \"{}\"", s));
            }
        }

        // Check alternatives if no symbol match
        if !matched {
            // Check strings
            let string_values: Vec<&str> = self
                .report
                .strings
                .iter()
                .map(|s| s.value.as_str())
                .collect();
            let string_matches =
                find_matching_strings(&string_values, exact, &None, regex, &None, false);
            if !string_matches.is_empty() {
                result.details.push(format!(
                    "💡 Found in strings ({} matches) - try `string:` instead",
                    string_matches.len()
                ));
            }

            // Check content
            let content = String::from_utf8_lossy(self.binary_data);
            let content_matched = if let Some(e) = exact {
                content.contains(e)
            } else if let Some(r) = regex {
                regex::Regex::new(r).is_ok_and(|re| re.is_match(&content))
            } else {
                false
            };
            if content_matched {
                result
                    .details
                    .push("💡 Found in content - try `content:` instead".to_string());
            }
        }

        result
    }

    fn debug_metrics_condition(
        &self,
        field: &str,
        min: Option<f64>,
        max: Option<f64>,
    ) -> ConditionDebugResult {
        let desc = format!("metrics: {} (min: {:?}, max: {:?})", field, min, max);

        let value = get_metric_value(self.report, field);
        let matched =
            value.is_some_and(|v| min.is_none_or(|m| v >= m) && max.is_none_or(|m| v <= m));

        let mut result = ConditionDebugResult::new(desc, matched);

        if let Some(v) = value {
            result.details.push(format!("Actual value: {:.4}", v));
        } else {
            result
                .details
                .push(format!("Metric '{}' not found in report", field));
            if let Some(metrics) = &self.report.metrics {
                result.details.push("Available metrics:".to_string());
                if let Some(text) = &metrics.text {
                    result
                        .details
                        .push(format!("  text.total_lines: {}", text.total_lines));
                }
                if let Some(funcs) = &metrics.functions {
                    result
                        .details
                        .push(format!("  functions.count: {}", funcs.total));
                }
                if let Some(ids) = &metrics.identifiers {
                    result.details.push(format!(
                        "  identifiers.single_char_ratio: {:.4}",
                        ids.single_char_ratio
                    ));
                    result
                        .details
                        .push(format!("  identifiers.avg_length: {:.4}", ids.avg_length));
                    result
                        .details
                        .push(format!("  identifiers.total: {}", ids.total));
                    result
                        .details
                        .push(format!("  identifiers.unique: {}", ids.unique));
                }
            }
        }

        result
    }

    fn debug_yara_match_condition(
        &self,
        namespace: &str,
        rule: Option<&String>,
    ) -> ConditionDebugResult {
        let desc = if let Some(r) = rule {
            format!("yara_match: {}:{}", namespace, r)
        } else {
            format!("yara_match: {}:*", namespace)
        };

        let matched = self
            .report
            .yara_matches
            .iter()
            .any(|m| m.namespace == namespace && rule.is_none_or(|r| m.rule == *r));

        let mut result = ConditionDebugResult::new(desc, matched);

        result.details.push(format!(
            "Total YARA matches: {}",
            self.report.yara_matches.len()
        ));

        if !self.report.yara_matches.is_empty() {
            result.details.push("YARA matches in file:".to_string());
            for m in &self.report.yara_matches {
                result.details.push(format!("  {}:{}", m.namespace, m.rule));
            }
        }

        result
    }

    fn debug_yara_inline_condition(&self, source: &str) -> ConditionDebugResult {
        use crate::composite_rules::evaluators::eval_yara_inline;

        // Extract rule name from YARA source
        let rule_name = source
            .lines()
            .find(|l| l.trim().starts_with("rule "))
            .and_then(|l| l.trim().strip_prefix("rule "))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or("inline");

        let desc = format!("yara: {} ({} chars)", rule_name, source.len());

        // Create evaluation context
        let ctx = EvaluationContext {
            report: self.report,
            binary_data: self.binary_data,
            file_type: self.file_type,
            platform: self.platform.clone(),
            additional_findings: None,
            cached_ast: None,
            finding_id_index: None,
        };

        // Actually evaluate the inline YARA rule
        let eval_result = eval_yara_inline(source, None, &ctx);

        let mut result = ConditionDebugResult::new(desc, eval_result.matched);
        result.evidence = eval_result.evidence;

        if eval_result.matched {
            result
                .details
                .push("✓ Inline YARA rule matched".to_string());
        } else {
            result
                .details
                .push("✗ Inline YARA rule did not match".to_string());
        }

        result.details.push(format!(
            "Rule source preview: {}...",
            truncate_string(source, 100)
        ));

        result
    }

    fn debug_structure_condition(&self, feature: &str) -> ConditionDebugResult {
        let desc = format!("structure: {}", feature);

        let matched = self.report.structure.iter().any(|s| s.id == feature);

        let mut result = ConditionDebugResult::new(desc, matched);

        result.details.push(format!(
            "Structures in file: {}",
            self.report.structure.len()
        ));
        if self.report.structure.len() <= 20 {
            for s in &self.report.structure {
                result.details.push(format!("  {}", s.id));
            }
        }

        result
    }

    fn debug_content_condition(
        &self,
        exact: &Option<String>,
        substr: &Option<String>,
        regex: &Option<String>,
        word: &Option<String>,
    ) -> ConditionDebugResult {
        let pattern_desc = if let Some(e) = exact {
            format!("exact: \"{}\"", truncate_string(e, 40))
        } else if let Some(c) = substr {
            format!("substr: \"{}\"", truncate_string(c, 40))
        } else if let Some(r) = regex {
            format!("regex: /{}/", truncate_string(r, 40))
        } else if let Some(w) = word {
            format!("word: \"{}\"", w)
        } else {
            "unknown".to_string()
        };

        let desc = format!("content: {}", pattern_desc);

        // Search in raw binary data
        let content = String::from_utf8_lossy(self.binary_data);
        let matched = if let Some(e) = exact {
            &content == e
        } else if let Some(c) = substr {
            content.contains(c)
        } else if let Some(r) = regex {
            regex::Regex::new(r).is_ok_and(|re| re.is_match(&content))
        } else if let Some(w) = word {
            let pattern = format!(r"\b{}\b", regex::escape(w));
            regex::Regex::new(&pattern).is_ok_and(|re| re.is_match(&content))
        } else {
            false
        };

        let mut result = ConditionDebugResult::new(desc, matched);
        result
            .details
            .push(format!("File size: {} bytes", self.binary_data.len()));

        // Check alternatives if content didn't match
        if !matched {
            // Check symbols (only for exact or regex patterns)
            if exact.is_some() || regex.is_some() {
                let symbols: Vec<&str> = self
                    .report
                    .imports
                    .iter()
                    .map(|i| i.symbol.as_str())
                    .chain(self.report.exports.iter().map(|e| e.symbol.as_str()))
                    .chain(self.report.functions.iter().map(|f| f.name.as_str()))
                    .collect();
                let symbol_matches = find_matching_symbols(&symbols, exact, regex);
                if !symbol_matches.is_empty() {
                    result.details.push(format!(
                        "💡 Found in symbols ({} matches) - try `symbol:` instead",
                        symbol_matches.len()
                    ));
                }
            }

            // Check strings
            let strings: Vec<&str> = self
                .report
                .strings
                .iter()
                .map(|s| s.value.as_str())
                .collect();
            let string_matches = find_matching_strings(&strings, exact, substr, regex, word, false);
            if !string_matches.is_empty() {
                result.details.push(format!(
                    "💡 Found in strings ({} matches) - try `string:` instead",
                    string_matches.len()
                ));
            }
        }

        result
    }

    #[allow(clippy::too_many_arguments)]
    fn debug_ast_condition(
        &self,
        kind: &Option<String>,
        node: &Option<String>,
        exact: &Option<String>,
        substr: &Option<String>,
        regex: &Option<String>,
        query: &Option<String>,
        case_insensitive: bool,
    ) -> ConditionDebugResult {
        // Build description based on mode
        let desc = if let Some(q) = query {
            format!("ast: query={}", truncate_string(q, 50))
        } else {
            let node_spec = kind
                .as_ref()
                .map(|k| format!("kind={}", k))
                .or_else(|| node.as_ref().map(|n| format!("node={}", n)))
                .unwrap_or_else(|| "unknown".to_string());
            let pattern_spec = exact
                .as_ref()
                .map(|e| format!("exact=\"{}\"", truncate_string(e, 30)))
                .or_else(|| {
                    substr
                        .as_ref()
                        .map(|s| format!("substr=\"{}\"", truncate_string(s, 30)))
                })
                .or_else(|| {
                    regex
                        .as_ref()
                        .map(|r| format!("regex=/{}/", truncate_string(r, 30)))
                })
                .unwrap_or_default();
            format!(
                "ast: {} {} (case_insensitive: {})",
                node_spec, pattern_spec, case_insensitive
            )
        };

        // For query mode, show simplified debug info
        if query.is_some() {
            let mut result = ConditionDebugResult::new(desc, false);
            result
                .details
                .push("AST query debugging not yet implemented".to_string());
            return result;
        }

        // For simple mode, use eval_ast directly
        let ctx = EvaluationContext {
            report: self.report,
            binary_data: self.binary_data,
            file_type: self.file_type,
            platform: self.platform.clone(),
            additional_findings: None,
            cached_ast: None,
            finding_id_index: None,
        };

        let eval_result = crate::composite_rules::evaluators::eval_ast(
            kind.as_deref(),
            node.as_deref(),
            exact.as_deref(),
            substr.as_deref(),
            regex.as_deref(),
            query.as_deref(),
            case_insensitive,
            &ctx,
        );

        let mut result = ConditionDebugResult::new(desc, eval_result.matched);
        if eval_result.matched {
            result.details.push(format!(
                "Found {} matching AST node(s)",
                eval_result.evidence.len()
            ));
            for ev in eval_result.evidence.iter().take(10) {
                if let Some(loc) = &ev.location {
                    result
                        .details
                        .push(format!("  {}: {}", loc, truncate_string(&ev.value, 60)));
                } else {
                    result
                        .details
                        .push(format!("  {}", truncate_string(&ev.value, 60)));
                }
            }
        } else {
            result
                .details
                .push("No matching AST nodes found".to_string());
        }

        result
    }

    // Helper to find trait definition by ID
    fn find_trait_definition(&self, id: &str) -> Option<&crate::composite_rules::TraitDefinition> {
        self.mapper.find_trait(id)
    }

    // Helper to find composite rule by ID
    fn find_composite_rule(&self, id: &str) -> Option<&crate::composite_rules::CompositeTrait> {
        self.mapper.composite_rules.iter().find(|r| r.id == id)
    }
}

// Helper functions

fn describe_condition(condition: &Condition) -> String {
    match condition {
        Condition::Trait { id } => format!("trait: {}", id),
        Condition::String {
            exact,
            substr,
            regex,
            word,
            ..
        } => {
            if let Some(e) = exact {
                format!("string[exact]: \"{}\"", truncate_string(e, 30))
            } else if let Some(c) = substr {
                format!("string[substr]: \"{}\"", truncate_string(c, 30))
            } else if let Some(r) = regex {
                format!("string[regex]: /{}/", truncate_string(r, 30))
            } else if let Some(w) = word {
                format!("string[word]: \"{}\"", w)
            } else {
                "string[?]".to_string()
            }
        }
        Condition::Symbol { exact, regex, .. } => {
            if let Some(e) = exact {
                format!("symbol[exact]: \"{}\"", e)
            } else if let Some(r) = regex {
                format!("symbol[regex]: /{}/", r)
            } else {
                "symbol[?]".to_string()
            }
        }
        Condition::Metrics {
            field, min, max, ..
        } => {
            format!("metrics: {} [{:?}, {:?}]", field, min, max)
        }
        Condition::YaraMatch { namespace, rule } => {
            if let Some(r) = rule {
                format!("yara_match: {}:{}", namespace, r)
            } else {
                format!("yara_match: {}:*", namespace)
            }
        }
        Condition::Yara { .. } => "yara[inline]".to_string(),
        Condition::Structure { feature, .. } => format!("structure: {}", feature),
        Condition::Content {
            exact,
            substr,
            regex,
            word,
            ..
        } => {
            if exact.is_some() {
                "content[exact]".to_string()
            } else if substr.is_some() {
                "content[substr]".to_string()
            } else if regex.is_some() {
                "content[regex]".to_string()
            } else if word.is_some() {
                "content[word]".to_string()
            } else {
                "content[?]".to_string()
            }
        }
        _ => format!("{:?}", condition).chars().take(50).collect(),
    }
}

fn build_composite_requirements(composite: &crate::composite_rules::CompositeTrait) -> String {
    let mut parts = Vec::new();

    if let Some(all) = &composite.all {
        parts.push(format!("all: {} conditions", all.len()));
    }

    if let Some(any) = &composite.any {
        let needed = composite.needs.unwrap_or(1);
        parts.push(format!("any: needs {} of {} conditions", needed, any.len()));
    }

    if let Some(none) = &composite.none {
        parts.push(format!("none: {} exclusions", none.len()));
    }

    parts.join(", ")
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

pub fn find_matching_strings<'a>(
    strings: &[&'a str],
    exact: &Option<String>,
    substr: &Option<String>,
    regex_pat: &Option<String>,
    word: &Option<String>,
    case_insensitive: bool,
) -> Vec<&'a str> {
    strings
        .iter()
        .filter(|s| {
            if let Some(e) = exact {
                if case_insensitive {
                    s.eq_ignore_ascii_case(e)
                } else {
                    *s == e
                }
            } else if let Some(c) = substr {
                if case_insensitive {
                    s.to_lowercase().contains(&c.to_lowercase())
                } else {
                    s.contains(c.as_str())
                }
            } else if let Some(r) = regex_pat {
                let pattern = if case_insensitive {
                    format!("(?i){}", r)
                } else {
                    r.clone()
                };
                regex::Regex::new(&pattern).is_ok_and(|re| re.is_match(s))
            } else if let Some(w) = word {
                let pattern = if case_insensitive {
                    format!(r"(?i)\b{}\b", regex::escape(w))
                } else {
                    format!(r"\b{}\b", regex::escape(w))
                };
                regex::Regex::new(&pattern).is_ok_and(|re| re.is_match(s))
            } else {
                false
            }
        })
        .copied()
        .collect()
}

pub fn find_matching_symbols<'a>(
    symbols: &[&'a str],
    exact: &Option<String>,
    regex: &Option<String>,
) -> Vec<&'a str> {
    symbols
        .iter()
        .filter(|s| {
            let clean = s.trim_start_matches('_').trim_start_matches("__");
            if let Some(e) = exact {
                *s == e || clean == e
            } else if let Some(r) = regex {
                if let Ok(re) = regex::Regex::new(r) {
                    re.is_match(s) || re.is_match(clean)
                } else {
                    false
                }
            } else {
                false
            }
        })
        .copied()
        .collect()
}

fn get_metric_value(report: &AnalysisReport, field: &str) -> Option<f64> {
    let metrics = report.metrics.as_ref()?;

    match field {
        "text.total_lines" | "total_lines" => metrics.text.as_ref().map(|t| t.total_lines as f64),
        "functions.count" | "function_count" => metrics.functions.as_ref().map(|f| f.total as f64),
        "identifiers.single_char_ratio" => metrics
            .identifiers
            .as_ref()
            .map(|i| i.single_char_ratio as f64),
        "identifiers.avg_length" => metrics.identifiers.as_ref().map(|i| i.avg_length as f64),
        "identifiers.total" => metrics.identifiers.as_ref().map(|i| i.total as f64),
        "identifiers.unique" => metrics.identifiers.as_ref().map(|i| i.unique as f64),
        "identifiers.single_char_count" => metrics
            .identifiers
            .as_ref()
            .map(|i| i.single_char_count as f64),
        _ => None,
    }
}

fn evaluate_condition_simple(
    _condition: &Condition,
    _ctx: &EvaluationContext,
) -> crate::composite_rules::context::ConditionResult {
    // Simple evaluation - just check if it matches
    // Full implementation would use the evaluators module
    crate::composite_rules::context::ConditionResult::no_match()
}

fn detect_platform(file_type: &str) -> Platform {
    match file_type.to_lowercase().as_str() {
        "elf" | "so" => Platform::Linux,
        "macho" | "dylib" => Platform::MacOS,
        "pe" | "dll" | "exe" => Platform::Windows,
        _ => Platform::All,
    }
}

fn detect_file_type(file_type: &str) -> RuleFileType {
    match file_type.to_lowercase().as_str() {
        "elf" => RuleFileType::Elf,
        "macho" => RuleFileType::Macho,
        "pe" | "exe" => RuleFileType::Pe,
        "dylib" => RuleFileType::Dylib,
        "so" => RuleFileType::So,
        "dll" => RuleFileType::Dll,
        "shell" | "shellscript" => RuleFileType::Shell,
        "batch" | "bat" | "cmd" => RuleFileType::Batch,
        "python" => RuleFileType::Python,
        "javascript" => RuleFileType::JavaScript,
        "typescript" => RuleFileType::TypeScript,
        "go" => RuleFileType::Go,
        "rust" => RuleFileType::Rust,
        "ruby" => RuleFileType::Ruby,
        "java" => RuleFileType::Java,
        "c" | "cpp" | "c++" => RuleFileType::C,
        "php" => RuleFileType::Php,
        "lua" => RuleFileType::Lua,
        "perl" => RuleFileType::Perl,
        "csharp" | "cs" => RuleFileType::CSharp,
        "powershell" | "ps1" => RuleFileType::PowerShell,
        "applescript" => RuleFileType::AppleScript,
        _ => RuleFileType::All,
    }
}

/// Format the debug results for terminal output
pub fn format_debug_output(results: &[RuleDebugResult]) -> String {
    let mut output = String::new();
    let mut matched_count = 0;
    let mut not_matched_count = 0;

    for result in results {
        if result.matched {
            matched_count += 1;
        } else {
            not_matched_count += 1;
        }

        // Rule header
        let status = if result.matched {
            "MATCHED".green().bold()
        } else {
            "NOT MATCHED".red().bold()
        };

        output.push_str(&format!(
            "\n{} {} ({})",
            status,
            result.rule_id.cyan().bold(),
            result.rule_type.dimmed()
        ));
        output.push_str(&format!("  {}\n", result.description.dimmed()));
        output.push_str(&format!("  Requires: {}\n", result.requirements));

        if let Some(precision) = result.precision {
            output.push_str(&format!("  Precision: {:.1}\n", precision));
        }

        if let Some(reason) = &result.skipped_reason {
            output.push_str(&format!("  {} {}\n", "Skipped:".yellow(), reason));
        }

        // Context info
        output.push_str(&format!(
            "  Context: file_type={}, platform={}, strings={}, symbols={}, findings={}\n",
            result.context_info.file_type,
            result.context_info.platform,
            result.context_info.string_count,
            result.context_info.symbol_count,
            result.context_info.finding_count
        ));

        // Condition results
        if !result.condition_results.is_empty() {
            output.push_str("  Conditions:\n");
            for cond_result in &result.condition_results {
                format_condition_result(&mut output, cond_result, 2);
            }
        }

        output.push('\n');
    }

    // Summary line
    if !results.is_empty() {
        output.push_str(&format!(
            "Summary: {} matched, {} not matched ({} total)\n",
            matched_count,
            not_matched_count,
            results.len()
        ));
    }

    output
}

fn format_condition_result(output: &mut String, result: &ConditionDebugResult, indent: usize) {
    let indent_str = "  ".repeat(indent);
    let icon = if result.matched {
        "✓".green()
    } else {
        "✗".red()
    };

    output.push_str(&format!(
        "{}{} {}\n",
        indent_str, icon, result.condition_desc
    ));

    for detail in &result.details {
        output.push_str(&format!("{}  {}\n", indent_str, detail.dimmed()));
    }

    for sub in &result.sub_results {
        format_condition_result(output, sub, indent + 1);
    }
}
