//! Debug/test rule evaluation module.
//!
//! This module provides detailed tracing of rule evaluation for debugging purposes.
//! It shows exactly why rules match or fail, including:
//! - For composites: which conditions matched and which didn't
//! - What values were actually matched against
//! - Regex patterns being used
//! - Context about available data (strings, symbols, etc.)

use crate::capabilities::CapabilityMapper;
use crate::composite_rules::{Condition, EvaluationContext, FileType as RuleFileType, Platform};
use crate::types::{AnalysisReport, Evidence};
use colored::Colorize;

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
}

impl<'a> RuleDebugger<'a> {
    pub fn new(
        mapper: &'a CapabilityMapper,
        report: &'a AnalysisReport,
        binary_data: &'a [u8],
    ) -> Self {
        let platform = detect_platform(&report.target.file_type);
        let file_type = detect_file_type(&report.target.file_type);

        Self {
            mapper,
            report,
            binary_data,
            file_type,
            platform,
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

        let mut result = RuleDebugResult {
            rule_id: trait_def.id.clone(),
            rule_type: "trait".to_string(),
            description: trait_def.desc.clone(),
            matched: false,
            skipped_reason: None,
            requirements: format!("Condition: {:?}", describe_condition(&trait_def.r#if)),
            condition_results: Vec::new(),
            context_info: self.context_info(),
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

        let mut result = RuleDebugResult {
            rule_id: composite.id.clone(),
            rule_type: "composite".to_string(),
            description: composite.desc.clone(),
            matched: false,
            skipped_reason: None,
            requirements: build_composite_requirements(composite),
            condition_results: Vec::new(),
            context_info: self.context_info(),
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

        // Check count constraints for 'any'
        let any_satisfied = if composite.any.is_some() {
            let has_count = composite.count_min.is_some()
                || composite.count_max.is_some()
                || composite.count_exact.is_some();

            if has_count {
                let min_ok = composite.count_min.map_or(true, |m| any_matched_count >= m);
                let max_ok = composite.count_max.map_or(true, |m| any_matched_count <= m);
                let exact_ok = composite
                    .count_exact
                    .map_or(true, |e| any_matched_count == e);
                min_ok && max_ok && exact_ok
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
            let count_info = if composite.count_min.is_some()
                || composite.count_max.is_some()
                || composite.count_exact.is_some()
            {
                let min = composite
                    .count_min
                    .map_or("0".to_string(), |m| m.to_string());
                let max = composite
                    .count_max
                    .map_or("*".to_string(), |m| m.to_string());
                if let Some(exact) = composite.count_exact {
                    format!("exactly {}", exact)
                } else {
                    format!("{}-{}", min, max)
                }
            } else {
                "at least 1".to_string()
            };

            let mut group = ConditionDebugResult::new(
                format!(
                    "any: ({}/{}) [need {}]",
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
            file_type: self.file_type.clone(),
            platform: self.platform.clone(),
            additional_findings: None,
            cached_ast: None,
        };

        match condition {
            Condition::Trait { id } => self.debug_trait_reference(id),
            Condition::String {
                exact,
                contains,
                regex,
                word,
                case_insensitive,
                min_count,
                ..
            } => self.debug_string_condition(
                exact,
                contains,
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
                contains,
                exact,
                word,
                ..
            } => self.debug_content_condition(exact, contains, regex, word),
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

        // Check if trait matched in findings
        let matched = self.report.findings.iter().any(|f| f.id == id);

        let mut result = ConditionDebugResult::new(desc, matched);

        if matched {
            if let Some(finding) = self.report.findings.iter().find(|f| f.id == id) {
                result.details.push(format!(
                    "Found in findings with {} evidence items",
                    finding.evidence.len()
                ));
                result.evidence = finding.evidence.clone();
            }
        } else {
            // Try to debug why the trait didn't match
            if let Some(trait_result) = self.debug_trait(id) {
                result.details.push(format!("Trait '{}' did not match", id));
                if let Some(reason) = &trait_result.skipped_reason {
                    result.details.push(format!("Reason: {}", reason));
                }
                result.sub_results = trait_result.condition_results;
            } else {
                result
                    .details
                    .push(format!("Trait '{}' not found in definitions", id));
            }
        }

        result
    }

    fn debug_string_condition(
        &self,
        exact: &Option<String>,
        contains: &Option<String>,
        regex: &Option<String>,
        word: &Option<String>,
        case_insensitive: bool,
        min_count: usize,
    ) -> ConditionDebugResult {
        let pattern_desc = if let Some(e) = exact {
            format!("exact: \"{}\"", e)
        } else if let Some(c) = contains {
            format!("contains: \"{}\"", c)
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
            find_matching_strings(&strings, exact, contains, regex, word, case_insensitive);

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
        } else if strings.len() <= 20 {
            result.details.push("All strings in file:".to_string());
            for s in &strings {
                result
                    .details
                    .push(format!("  \"{}\"", truncate_string(s, 60)));
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
        let matched = value.map_or(false, |v| {
            min.map_or(true, |m| v >= m) && max.map_or(true, |m| v <= m)
        });

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
            .any(|m| m.namespace == namespace && rule.map_or(true, |r| m.rule == *r));

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
        // Extract rule name from YARA source
        let rule_name = source
            .lines()
            .find(|l| l.trim().starts_with("rule "))
            .and_then(|l| l.trim().strip_prefix("rule "))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or("inline");

        let desc = format!("yara: {} ({} chars)", rule_name, source.len());

        // For inline YARA, we'd need to compile and run it
        // For now, show the source and note we can't evaluate it in debug mode
        let mut result = ConditionDebugResult::new(desc, false);
        result
            .details
            .push("YARA inline rules require full evaluation (not shown in debug)".to_string());
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
        contains: &Option<String>,
        regex: &Option<String>,
        word: &Option<String>,
    ) -> ConditionDebugResult {
        let pattern_desc = if let Some(e) = exact {
            format!("exact: \"{}\"", truncate_string(e, 40))
        } else if let Some(c) = contains {
            format!("contains: \"{}\"", truncate_string(c, 40))
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
            content.contains(e)
        } else if let Some(c) = contains {
            content.contains(c)
        } else if let Some(r) = regex {
            regex::Regex::new(r).map_or(false, |re| re.is_match(&content))
        } else if let Some(w) = word {
            let pattern = format!(r"\b{}\b", regex::escape(w));
            regex::Regex::new(&pattern).map_or(false, |re| re.is_match(&content))
        } else {
            false
        };

        let mut result = ConditionDebugResult::new(desc, matched);
        result
            .details
            .push(format!("File size: {} bytes", self.binary_data.len()));

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
            contains,
            regex,
            word,
            ..
        } => {
            if let Some(e) = exact {
                format!("string[exact]: \"{}\"", truncate_string(e, 30))
            } else if let Some(c) = contains {
                format!("string[contains]: \"{}\"", truncate_string(c, 30))
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
            contains,
            regex,
            word,
            ..
        } => {
            if exact.is_some() {
                "content[exact]".to_string()
            } else if contains.is_some() {
                "content[contains]".to_string()
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
        let count_desc = if let Some(exact) = composite.count_exact {
            format!("exactly {}", exact)
        } else {
            let min = composite.count_min.unwrap_or(1);
            if let Some(max) = composite.count_max {
                format!("{}-{}", min, max)
            } else {
                format!("{}", min)
            }
        };
        parts.push(format!("any: {} of {} conditions", count_desc, any.len()));
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

fn find_matching_strings<'a>(
    strings: &[&'a str],
    exact: &Option<String>,
    contains: &Option<String>,
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
            } else if let Some(c) = contains {
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
                regex::Regex::new(&pattern).map_or(false, |re| re.is_match(s))
            } else if let Some(w) = word {
                let pattern = if case_insensitive {
                    format!(r"(?i)\b{}\b", regex::escape(w))
                } else {
                    format!(r"\b{}\b", regex::escape(w))
                };
                regex::Regex::new(&pattern).map_or(false, |re| re.is_match(s))
            } else {
                false
            }
        })
        .copied()
        .collect()
}

fn find_matching_symbols<'a>(
    symbols: &[&'a str],
    exact: &Option<String>,
    regex: &Option<String>,
) -> Vec<&'a str> {
    symbols
        .iter()
        .filter(|s| {
            if let Some(e) = exact {
                *s == e
            } else if let Some(r) = regex {
                regex::Regex::new(r).is_ok_and(|re| re.is_match(s))
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

    for result in results {
        // Rule header
        let status = if result.matched {
            "MATCHED".green().bold()
        } else {
            "NOT MATCHED".red().bold()
        };

        output.push_str(&format!(
            "\n{} {} ({})\n",
            status,
            result.rule_id.cyan().bold(),
            result.rule_type.dimmed()
        ));
        output.push_str(&format!("  {}\n", result.description.dimmed()));
        output.push_str(&format!("  Requirements: {}\n", result.requirements));

        if let Some(reason) = &result.skipped_reason {
            output.push_str(&format!("  {} {}\n", "Skipped:".yellow(), reason));
        }

        // Context info
        output.push_str(&format!(
            "\n  {} file_type={}, platform={}\n",
            "Context:".blue().bold(),
            result.context_info.file_type,
            result.context_info.platform
        ));
        output.push_str(&format!(
            "  Strings: {}, Symbols: {}, Imports: {}, Exports: {}, Findings: {}\n",
            result.context_info.string_count,
            result.context_info.symbol_count,
            result.context_info.import_count,
            result.context_info.export_count,
            result.context_info.finding_count
        ));

        // Condition results
        if !result.condition_results.is_empty() {
            output.push_str(&format!("\n  {}\n", "Conditions:".blue().bold()));
            for cond_result in &result.condition_results {
                format_condition_result(&mut output, cond_result, 2);
            }
        }

        output.push('\n');
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
        output.push_str(&format!("{}    {}\n", indent_str, detail.dimmed()));
    }

    for sub in &result.sub_results {
        format_condition_result(output, sub, indent + 1);
    }
}
