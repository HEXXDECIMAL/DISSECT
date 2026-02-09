//! Rule validation and precision analysis.
//!
//! This module provides validation functions for trait definitions and composite rules:
//! - Precision calculation for composite rules (recursive trait reference expansion)
//! - Validation of composite rule criticality precision thresholds
//! - Validation that composite rules only contain trait references (not inline primitives)
//! - Auto-prefixing of trait references based on file path

use crate::composite_rules::{
    CompositeTrait, Condition, FileType as RuleFileType, Platform, TraitDefinition,
};
use crate::types::Criticality;
use std::collections::{HashMap, HashSet};

use super::parsing::parse_file_types;

const BASE_TRAIT_PRECISION: f32 = 1.0;
const PARAM_UNIT: f32 = 0.3;
const CASE_INSENSITIVE_MULTIPLIER: f32 = 0.25;

fn score_string_value(value: &str) -> f32 {
    let len = value.chars().count();
    if len == 0 {
        return 0.0;
    }
    let buckets = len.div_ceil(5) as f32;
    buckets * PARAM_UNIT
}

fn score_word_value(value: &str) -> f32 {
    // Word matching implies delimiter boundaries around the token.
    let len = value.chars().count() + 2;
    let buckets = len.div_ceil(5) as f32;
    buckets * PARAM_UNIT
}

fn score_regex_value(value: &str) -> f32 {
    let normalized_len = value.chars().filter(|c| *c != '\\').count();
    if normalized_len == 0 {
        return 0.0;
    }
    let buckets = normalized_len.div_ceil(5) as f32;
    buckets * PARAM_UNIT
}

fn score_presence<T>(value: Option<&T>) -> f32 {
    if value.is_some() {
        PARAM_UNIT
    } else {
        0.0
    }
}

fn score_condition(condition: &Condition) -> f32 {
    let mut score = 0.0f32;

    match condition {
        Condition::Symbol {
            exact,
            substr,
            regex,
            platforms,
            ..
        } => {
            score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
            score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
            score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
            if let Some(p) = platforms {
                for platform in p.iter().filter(|p| **p != Platform::All) {
                    score += score_string_value(&format!("{:?}", platform).to_lowercase());
                }
            }
        }
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
            ..
        } => {
            score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
            score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
            score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
            score += word.as_deref().map(score_word_value).unwrap_or(0.0);
            if let Some(exclusions) = exclude_patterns {
                for exclusion in exclusions {
                    score += score_regex_value(exclusion);
                }
            }
            if *count_min > 1 {
                score += PARAM_UNIT;
            }
            score += score_presence(count_max.as_ref());
            score += score_presence(per_kb_min.as_ref());
            score += score_presence(per_kb_max.as_ref());
            if *external_ip {
                score += PARAM_UNIT;
            }
            score += section.as_deref().map(score_string_value).unwrap_or(0.0);
            score += score_presence(offset.as_ref());
            score += score_presence(offset_range.as_ref());
            score += score_presence(section_offset.as_ref());
            score += score_presence(section_offset_range.as_ref());
            if *case_insensitive {
                score *= CASE_INSENSITIVE_MULTIPLIER;
            }
        }
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
            ..
        } => {
            score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
            score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
            score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
            score += word.as_deref().map(score_word_value).unwrap_or(0.0);
            if *count_min > 1 {
                score += PARAM_UNIT;
            }
            score += score_presence(count_max.as_ref());
            score += score_presence(per_kb_min.as_ref());
            score += score_presence(per_kb_max.as_ref());
            if *external_ip {
                score += PARAM_UNIT;
            }
            score += section.as_deref().map(score_string_value).unwrap_or(0.0);
            score += score_presence(offset.as_ref());
            score += score_presence(offset_range.as_ref());
            score += score_presence(section_offset.as_ref());
            score += score_presence(section_offset_range.as_ref());
            if *case_insensitive {
                score *= CASE_INSENSITIVE_MULTIPLIER;
            }
        }
        Condition::YaraMatch { namespace, rule } => {
            score += score_string_value(namespace);
            score += rule.as_deref().map(score_string_value).unwrap_or(0.0);
        }
        Condition::Structure {
            feature,
            min_sections,
        } => {
            score += score_string_value(feature);
            score += score_presence(min_sections.as_ref());
        }
        Condition::ImportsCount { min, max, filter } => {
            score += score_presence(min.as_ref());
            score += score_presence(max.as_ref());
            score += filter.as_deref().map(score_string_value).unwrap_or(0.0);
        }
        Condition::ExportsCount { min, max } => {
            score += score_presence(min.as_ref());
            score += score_presence(max.as_ref());
        }
        Condition::Trait { id } => {
            score += score_string_value(id);
        }
        Condition::Ast {
            kind,
            node,
            exact,
            substr,
            regex,
            query,
            language,
            case_insensitive,
        } => {
            score += kind.as_deref().map(score_string_value).unwrap_or(0.0);
            score += node.as_deref().map(score_string_value).unwrap_or(0.0);
            score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
            score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
            score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
            score += query.as_deref().map(score_regex_value).unwrap_or(0.0);
            score += language.as_deref().map(score_string_value).unwrap_or(0.0);
            if *case_insensitive {
                score *= CASE_INSENSITIVE_MULTIPLIER;
            }
        }
        Condition::Yara { source, .. } => {
            score += score_regex_value(source);
        }
        Condition::Syscall {
            name,
            number,
            arch,
            min_count,
        } => {
            if let Some(names) = name {
                for value in names {
                    score += score_string_value(value);
                }
            }
            if let Some(values) = number {
                score += PARAM_UNIT * (values.len() as f32);
            }
            if let Some(values) = arch {
                for value in values {
                    score += score_string_value(value);
                }
            }
            score += score_presence(min_count.as_ref());
        }
        Condition::SectionRatio {
            section,
            compare_to,
            min_ratio,
            max_ratio,
        } => {
            score += score_regex_value(section);
            score += score_regex_value(compare_to);
            score += score_presence(min_ratio.as_ref());
            score += score_presence(max_ratio.as_ref());
        }
        Condition::SectionEntropy {
            section,
            min_entropy,
            max_entropy,
        } => {
            score += score_regex_value(section);
            score += score_presence(min_entropy.as_ref());
            score += score_presence(max_entropy.as_ref());
        }
        Condition::ImportCombination {
            required,
            suspicious,
            min_suspicious,
            max_total,
        } => {
            if let Some(values) = required {
                for value in values {
                    score += score_string_value(value);
                }
            }
            if let Some(values) = suspicious {
                for value in values {
                    score += score_string_value(value);
                }
            }
            score += score_presence(min_suspicious.as_ref());
            score += score_presence(max_total.as_ref());
        }
        Condition::StringCount {
            min,
            max,
            min_length,
        } => {
            score += score_presence(min.as_ref());
            score += score_presence(max.as_ref());
            score += score_presence(min_length.as_ref());
        }
        Condition::Metrics {
            field,
            min,
            max,
            min_size,
            max_size,
        } => {
            score += score_string_value(field);
            score += score_presence(min.as_ref());
            score += score_presence(max.as_ref());
            score += score_presence(min_size.as_ref());
            score += score_presence(max_size.as_ref());
        }
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
        } => {
            score += score_string_value(pattern);
            score += score_presence(offset.as_ref());
            score += score_presence(offset_range.as_ref());
            if *count_min > 1 {
                score += PARAM_UNIT;
            }
            score += score_presence(count_max.as_ref());
            score += score_presence(per_kb_min.as_ref());
            score += score_presence(per_kb_max.as_ref());
            if *extract_wildcards {
                score += PARAM_UNIT;
            }
            score += section.as_deref().map(score_string_value).unwrap_or(0.0);
            score += score_presence(section_offset.as_ref());
            score += score_presence(section_offset_range.as_ref());
        }
        Condition::Filesize { min, max } => {
            score += score_presence(min.as_ref());
            score += score_presence(max.as_ref());
        }
        Condition::TraitGlob { pattern, r#match } => {
            score += score_string_value(pattern);
            score += score_string_value(r#match);
        }
        Condition::SectionName { pattern, regex } => {
            score += score_regex_value(pattern);
            if *regex {
                score += PARAM_UNIT;
            }
        }
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
        | Condition::Xor {
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
            ..
        } => {
            score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
            score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
            score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
            if *count_min > 1 {
                score += PARAM_UNIT;
            }
            score += score_presence(count_max.as_ref());
            score += score_presence(per_kb_min.as_ref());
            score += score_presence(per_kb_max.as_ref());
            score += section.as_deref().map(score_string_value).unwrap_or(0.0);
            score += score_presence(offset.as_ref());
            score += score_presence(offset_range.as_ref());
            score += score_presence(section_offset.as_ref());
            score += score_presence(section_offset_range.as_ref());
            if *case_insensitive {
                score *= CASE_INSENSITIVE_MULTIPLIER;
            }
        }
        Condition::Basename {
            exact,
            substr,
            regex,
            case_insensitive,
        }
        | Condition::Kv {
            exact,
            substr,
            regex,
            case_insensitive,
            ..
        } => {
            score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
            score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
            score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
            if *case_insensitive {
                score *= CASE_INSENSITIVE_MULTIPLIER;
            }
        }
        Condition::LayerPath { value } => {
            score += score_string_value(value);
        }
    }

    score
}

fn score_not_exceptions(exceptions: &[crate::composite_rules::condition::NotException]) -> f32 {
    let mut score = 0.0f32;
    for exception in exceptions {
        match exception {
            crate::composite_rules::condition::NotException::Shorthand(value) => {
                score += score_string_value(value);
            }
            crate::composite_rules::condition::NotException::Structured {
                exact,
                substr,
                regex,
            } => {
                score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
                score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
                score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
            }
        }
    }
    score
}

fn sum_weakest(mut values: Vec<f32>, count: usize) -> f32 {
    if values.is_empty() || count == 0 {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let len = values.len();
    values.into_iter().take(count.min(len)).sum()
}

/// Calculate trait-level precision (static rule precision).
///
/// This is rule-definition precision, not runtime match precision.
/// It counts structural constraints that make a trait more specific.
pub fn calculate_trait_precision(trait_def: &TraitDefinition) -> f32 {
    let mut precision = BASE_TRAIT_PRECISION;

    precision += score_presence(trait_def.size_min.as_ref());
    precision += score_presence(trait_def.size_max.as_ref());

    for platform in trait_def.platforms.iter().filter(|p| **p != Platform::All) {
        precision += score_string_value(&format!("{:?}", platform).to_lowercase());
    }

    for file_type in trait_def
        .r#for
        .iter()
        .filter(|f| !matches!(f, RuleFileType::All))
    {
        precision += score_string_value(&format!("{:?}", file_type).to_lowercase());
    }

    precision += score_condition(&trait_def.r#if);

    if let Some(exceptions) = trait_def.not.as_ref() {
        precision += PARAM_UNIT;
        precision += score_not_exceptions(exceptions);
    }

    if let Some(unless_conds) = trait_def.unless.as_ref() {
        precision += PARAM_UNIT;
        let unless_scores: Vec<f32> = unless_conds.iter().map(score_condition).collect();
        precision += sum_weakest(unless_scores, 1);
    }

    if trait_def.downgrade.is_some() {
        precision += PARAM_UNIT;
    }

    precision
}

/// Calculate the precision of a composite rule or trait
///
/// Precision is a measure of how specific/constrained the rule is - how many filters/constraints it has.
/// This RECURSIVELY counts ALL filters across the entire rule tree:
/// - Base trait: pattern + size_min + size_max + platform + file_type + not + unless
/// - Composite: file_type + recursively expanded all/any/none/unless clauses
///
/// IMPORTANT: This is the ONLY place in the codebase for measuring rule precision.
/// Do not duplicate this logic elsewhere.
pub fn calculate_composite_precision(
    rule_id: &str,
    all_composites: &[CompositeTrait],
    all_traits: &[TraitDefinition],
    cache: &mut HashMap<String, f32>,
    visiting: &mut HashSet<String>,
) -> f32 {
    if let Some(&precision) = cache.get(rule_id) {
        return precision;
    }

    // Detect cycles
    if !visiting.insert(rule_id.to_string()) {
        return BASE_TRAIT_PRECISION;
    }

    // Try to find as composite rule first
    // Support both new format (dir::name) and legacy format (dir/name)
    let rule = all_composites.iter().find(|r| r.id == rule_id).or_else(|| {
        if rule_id.contains("::") {
            let legacy_id = rule_id.replace("::", "/");
            all_composites.iter().find(|r| r.id == legacy_id)
        } else if rule_id.contains('/') {
            if let Some(idx) = rule_id.rfind('/') {
                let new_id = format!("{}::{}", &rule_id[..idx], &rule_id[idx + 1..]);
                all_composites.iter().find(|r| r.id == new_id)
            } else {
                None
            }
        } else {
            None
        }
    });
    if let Some(rule) = rule {
        let mut precision = 0.0f32;

        for file_type in rule
            .r#for
            .iter()
            .filter(|f| !matches!(f, RuleFileType::All))
        {
            precision += score_string_value(&format!("{:?}", file_type).to_lowercase());
        }

        // `all` clause: recursively sum all elements
        if let Some(ref conditions) = rule.all {
            for cond in conditions {
                match cond {
                    Condition::Trait { id } => {
                        // Recursively calculate trait/composite precision
                        precision += calculate_composite_precision(
                            id,
                            all_composites,
                            all_traits,
                            cache,
                            visiting,
                        );
                    }
                    _ => {
                        precision += score_condition(cond);
                    }
                }
            }
        }

        // `any` clause: sum the N weakest required branches
        if let Some(ref conditions) = rule.any {
            let branch_scores: Vec<f32> = conditions
                .iter()
                .map(|cond| match cond {
                    Condition::Trait { id } => calculate_composite_precision(
                        id,
                        all_composites,
                        all_traits,
                        cache,
                        visiting,
                    ),
                    _ => score_condition(cond),
                })
                .collect();

            if !branch_scores.is_empty() {
                let required = rule.needs.unwrap_or(1).max(1);
                precision += sum_weakest(branch_scores, required);
            }
        }

        if let Some(ref none_conds) = rule.none {
            precision += PARAM_UNIT;
            let scores: Vec<f32> = none_conds
                .iter()
                .map(|cond| match cond {
                    Condition::Trait { id } => calculate_composite_precision(
                        id,
                        all_composites,
                        all_traits,
                        cache,
                        visiting,
                    ),
                    _ => score_condition(cond),
                })
                .collect();
            precision += scores.into_iter().sum::<f32>();
        }
        if let Some(ref unless_conds) = rule.unless {
            precision += PARAM_UNIT;
            let scores: Vec<f32> = unless_conds
                .iter()
                .map(|cond| match cond {
                    Condition::Trait { id } => calculate_composite_precision(
                        id,
                        all_composites,
                        all_traits,
                        cache,
                        visiting,
                    ),
                    _ => score_condition(cond),
                })
                .collect();
            precision += sum_weakest(scores, 1);
        }

        visiting.remove(rule_id);
        cache.insert(rule_id.to_string(), precision);
        return precision;
    }

    // Not a composite - try to find as a trait definition
    // Support both new format (dir::name) and legacy format (dir/name)
    let trait_def = all_traits.iter().find(|t| t.id == rule_id).or_else(|| {
        // Try converting legacy format to new format or vice versa
        if rule_id.contains("::") {
            // Reference uses new format, trait might use legacy
            let legacy_id = rule_id.replace("::", "/");
            all_traits.iter().find(|t| t.id == legacy_id)
        } else if rule_id.contains('/') {
            // Reference uses legacy format, trait might use new format
            // Convert last '/' to '::'
            if let Some(idx) = rule_id.rfind('/') {
                let new_id = format!("{}::{}", &rule_id[..idx], &rule_id[idx + 1..]);
                all_traits.iter().find(|t| t.id == new_id)
            } else {
                None
            }
        } else {
            None
        }
    });

    if let Some(trait_def) = trait_def {
        let precision = calculate_trait_precision(trait_def);
        visiting.remove(rule_id);
        cache.insert(rule_id.to_string(), precision);
        return precision;
    }

    // Not found - treat as external/unknown trait
    visiting.remove(rule_id);
    cache.insert(rule_id.to_string(), BASE_TRAIT_PRECISION);
    BASE_TRAIT_PRECISION
}

/// Validate and downgrade composite rules that don't meet precision requirements.
///
/// - HOSTILE must have precision >= 4, else downgraded to SUSPICIOUS.
/// - SUSPICIOUS must have precision >= 2, else downgraded to NOTABLE.
///
/// Returns a list of warnings for rules that were downgraded.
pub(crate) fn validate_hostile_composite_precision(
    composite_rules: &mut [CompositeTrait],
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
) {
    let mut cache: HashMap<String, f32> = HashMap::new();

    // First pass: calculate precision for HOSTILE/SUSPICIOUS rules (immutable borrow)
    let scored_rules: Vec<(String, Criticality, f32)> = composite_rules
        .iter()
        .filter(|rule| matches!(rule.crit, Criticality::Hostile | Criticality::Suspicious))
        .map(|rule| {
            let mut visiting = std::collections::HashSet::new();
            let precision = calculate_composite_precision(
                &rule.id,
                composite_rules,
                trait_definitions,
                &mut cache,
                &mut visiting,
            );
            (rule.id.clone(), rule.crit, precision)
        })
        .collect();

    // Second pass: downgrade rules that don't meet requirements (mutable borrow)
    for (rule_id, crit, precision) in scored_rules {
        if let Some(rule) = composite_rules.iter_mut().find(|r| r.id == rule_id) {
            match crit {
                Criticality::Hostile if precision < min_hostile_precision => {
                    warnings.push(format!(
                        "Composite trait '{}' is marked HOSTILE but has precision {:.1} (need >={:.1}).",
                        rule_id, precision, min_hostile_precision
                    ));
                    rule.crit = Criticality::Suspicious;
                }
                Criticality::Suspicious if precision < min_suspicious_precision => {
                    warnings.push(format!(
                        "Composite trait '{}' is marked SUSPICIOUS but has precision {:.1} (need >={:.1}).",
                        rule_id, precision, min_suspicious_precision
                    ));
                    rule.crit = Criticality::Notable;
                }
                _ => {}
            }
        }
    }

    // Pass 3: Detect duplicate atomic traits (same effective search parameters)
    let mut trait_params: HashMap<String, Vec<String>> = HashMap::new();
    for t in trait_definitions {
        // Include all matching controls that affect detection behavior.
        let signature = format!(
            "{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}",
            t.r#if, t.platforms, t.r#for, t.size_min, t.size_max, t.not, t.unless
        );
        trait_params
            .entry(signature)
            .or_default()
            .push(t.id.clone());
    }

    for (_sig, ids) in trait_params {
        if ids.len() > 1 {
            warnings.push(format!(
                "Duplicate atomic traits detected (same search parameters): {}",
                ids.join(", ")
            ));
        }
    }

    // Pass 4: Detect duplicate composite rules (same effective condition sets)
    // Include ALL conditions (not just trait refs) so rules with different inline conditions
    // are not falsely flagged as duplicates
    let mut composite_sigs: HashMap<String, Vec<String>> = HashMap::new();
    for r in composite_rules {
        // Collect ALL conditions as sorted strings for deterministic comparison
        let mut all_conds: Vec<String> = r
            .all
            .as_ref()
            .map(|c| c.iter().map(|cond| format!("{:?}", cond)).collect())
            .unwrap_or_default();
        all_conds.sort();

        let mut any_conds: Vec<String> = r
            .any
            .as_ref()
            .map(|c| c.iter().map(|cond| format!("{:?}", cond)).collect())
            .unwrap_or_default();
        any_conds.sort();

        let mut none_conds: Vec<String> = r
            .none
            .as_ref()
            .map(|c| c.iter().map(|cond| format!("{:?}", cond)).collect())
            .unwrap_or_default();
        none_conds.sort();

        let mut unless_conds: Vec<String> = r
            .unless
            .as_ref()
            .map(|c| c.iter().map(|cond| format!("{:?}", cond)).collect())
            .unwrap_or_default();
        unless_conds.sort();

        // Only check signatures for rules that have conditions
        if !all_conds.is_empty()
            || !any_conds.is_empty()
            || !none_conds.is_empty()
            || !unless_conds.is_empty()
        {
            let signature = format!(
                "all:{:?}|any:{:?}|none:{:?}|unless:{:?}|needs:{:?}|for:{:?}|platforms:{:?}|size_min:{:?}|size_max:{:?}",
                all_conds, any_conds, none_conds, unless_conds, r.needs, r.r#for, r.platforms, r.size_min, r.size_max
            );
            composite_sigs
                .entry(signature)
                .or_default()
                .push(r.id.clone());
        }
    }

    for (_sig, ids) in composite_sigs {
        if ids.len() > 1 {
            warnings.push(format!(
                "Duplicate composite rules detected (same conditions): {}",
                ids.join(", ")
            ));
        }
    }

    // Pass 5: Detect traits searching for same text with different match types
    // (substr vs exact vs word) but similar characteristics
    let mut text_searches: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for t in trait_definitions {
        let search_text = match &t.r#if {
            Condition::String {
                exact: Some(s), ..
            } => Some((s.clone(), "exact".to_string())),
            Condition::String {
                substr: Some(s), ..
            } => Some((s.clone(), "substr".to_string())),
            Condition::String { word: Some(s), .. } => Some((s.clone(), "word".to_string())),
            Condition::Content {
                exact: Some(s), ..
            } => Some((s.clone(), "exact".to_string())),
            Condition::Content {
                substr: Some(s), ..
            } => Some((s.clone(), "substr".to_string())),
            Condition::Content { word: Some(s), .. } => Some((s.clone(), "word".to_string())),
            _ => None,
        };

        if let Some((text, match_type)) = search_text {
            // Create a signature based on the text and search context
            let signature = format!(
                "text:{}|type:{}|crit:{:?}|for:{:?}|platforms:{:?}",
                text.to_lowercase(),
                match &t.r#if {
                    Condition::String { .. } => "string",
                    Condition::Content { .. } => "content",
                    _ => "other",
                },
                t.crit,
                t.r#for,
                t.platforms
            );
            text_searches
                .entry(signature)
                .or_default()
                .push((t.id.clone(), match_type));
        }
    }

    for (_sig, matches) in text_searches {
        if matches.len() > 1 {
            // Check if they use different match types
            let match_types: std::collections::HashSet<&String> =
                matches.iter().map(|(_, mt)| mt).collect();
            if match_types.len() > 1 {
                let trait_list: Vec<String> = matches
                    .iter()
                    .map(|(id, mt)| format!("{}({})", id, mt))
                    .collect();
                warnings.push(format!(
                    "Traits searching for same text with different match types (likely duplicates): {}",
                    trait_list.join(", ")
                ));
            }
        }
    }

    // Pass 6: Detect regex traits that overlap with existing substr/exact matches
    validate_regex_overlap_with_literal(trait_definitions, warnings);
}

/// Helper function to check if two file type lists have any overlap
fn file_types_overlap(types1: &[RuleFileType], types2: &[RuleFileType]) -> bool {
    // If either contains All, they overlap
    if types1.contains(&RuleFileType::All) || types2.contains(&RuleFileType::All) {
        return true;
    }
    // Check if any concrete types match
    types1.iter().any(|t1| types2.contains(t1))
}

/// Helper function to check if a regex pattern could match a literal string
/// First tries a fast heuristic (string matching), then falls back to actually
/// compiling and testing the regex for accuracy.
fn regex_could_match_literal(regex: &str, literal: &str) -> bool {
    // Fast path: check if the literal text appears in the regex directly
    if regex.contains(literal) {
        return true;
    }

    // Fast path: check if the literal appears with common regex escaping
    let escaped_literal: String = literal
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_string()
            } else {
                format!("\\{}", c)
            }
        })
        .collect();

    if regex.contains(&escaped_literal) {
        return true;
    }

    // Slow path: actually compile and test the regex
    // This catches cases like "c?mod" matching "chmod"
    if let Ok(re) = regex::Regex::new(regex) {
        if re.is_match(literal) {
            return true;
        }
    }

    false
}

/// Validate that regex traits don't overlap with existing substr/exact matches
///
/// Reports ambiguous cases where the same pattern could be detected by multiple traits
/// with the same criticality level and overlapping file types. This indicates redundancy
/// where one trait should be removed to avoid confusion and duplicate detections.
///
/// The solution is to remove one of the conflicting traits - typically the regex version
/// should be removed in favor of the simpler substr/exact match, unless the regex
/// provides additional matching capabilities.
fn validate_regex_overlap_with_literal(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    // Build a map of literal (exact/substr) patterns with their context
    let mut literal_patterns: Vec<(String, String, String, Criticality, Vec<RuleFileType>)> =
        Vec::new();

    for t in trait_definitions {
        match &t.r#if {
            Condition::String {
                exact: Some(s), ..
            } => {
                literal_patterns.push((
                    s.clone(),
                    "exact".to_string(),
                    t.id.clone(),
                    t.crit,
                    t.r#for.clone(),
                ));
            }
            Condition::String {
                substr: Some(s), ..
            } => {
                literal_patterns.push((
                    s.clone(),
                    "substr".to_string(),
                    t.id.clone(),
                    t.crit,
                    t.r#for.clone(),
                ));
            }
            Condition::Symbol {
                exact: Some(s), ..
            } => {
                literal_patterns.push((
                    s.clone(),
                    "exact".to_string(),
                    t.id.clone(),
                    t.crit,
                    t.r#for.clone(),
                ));
            }
            Condition::Symbol {
                substr: Some(s), ..
            } => {
                literal_patterns.push((
                    s.clone(),
                    "substr".to_string(),
                    t.id.clone(),
                    t.crit,
                    t.r#for.clone(),
                ));
            }
            _ => {}
        }
    }

    // Check regex patterns against literal patterns
    for t in trait_definitions {
        let regex_pattern = match &t.r#if {
            Condition::String {
                regex: Some(r), ..
            } => Some(r),
            Condition::Symbol {
                regex: Some(r), ..
            } => Some(r),
            _ => None,
        };

        if let Some(regex) = regex_pattern {
            for (literal, match_type, literal_id, literal_crit, literal_types) in
                &literal_patterns
            {
                // Check if criticality matches
                if t.crit != *literal_crit {
                    continue;
                }

                // Check if file types overlap
                if !file_types_overlap(&t.r#for, literal_types) {
                    continue;
                }

                // Check if regex could match the literal
                if regex_could_match_literal(regex, literal) {
                    warnings.push(format!(
                        "Ambiguous regex overlap: trait '{}' (regex: '{}') could match same pattern as '{}' ({}: '{}'). Consider removing one.",
                        t.id, regex, literal_id, match_type, literal
                    ));
                }
            }
        }
    }
}

/// Validate that all conditions in a composite rule are trait references only.
/// Composite rules should combine traits, not contain inline primitives.
pub(crate) fn validate_composite_trait_only(
    rule: &CompositeTrait,
    source_file: &str,
) -> Vec<String> {
    let mut errors = Vec::new();

    fn check_conditions(
        conditions: &[Condition],
        rule_id: &str,
        field_name: &str,
        source_file: &str,
        errors: &mut Vec<String>,
    ) {
        for cond in conditions {
            if !cond.is_trait_reference() {
                errors.push(format!(
                    "{}: Composite rule '{}' has inline '{}' in {}. Convert to a trait.",
                    source_file,
                    rule_id,
                    cond.type_name(),
                    field_name
                ));
            }
        }
    }

    if let Some(ref c) = rule.all {
        check_conditions(c, &rule.id, "all", source_file, &mut errors);
    }
    if let Some(ref c) = rule.any {
        check_conditions(c, &rule.id, "any", source_file, &mut errors);
    }
    if let Some(ref c) = rule.none {
        check_conditions(c, &rule.id, "none", source_file, &mut errors);
    }

    errors
}

/// Auto-prefix trait references in composite rule conditions
/// If a trait reference doesn't contain '::' or '/', prepend the given prefix with ::
pub(crate) fn autoprefix_trait_refs(rule: &mut CompositeTrait, prefix: &str) {
    fn prefix_conditions(conditions: &mut [Condition], prefix: &str) {
        for cond in conditions {
            if let Condition::Trait { id } = cond {
                // Only prefix if ID doesn't already contain '::' or '/' (i.e., it's local to this file)
                if !id.contains("::") && !id.contains('/') {
                    *id = format!("{}::{}", prefix, id);
                }
            }
        }
    }

    if let Some(ref mut conditions) = rule.all {
        prefix_conditions(conditions, prefix);
    }
    if let Some(ref mut conditions) = rule.any {
        prefix_conditions(conditions, prefix);
    }
    if let Some(ref mut conditions) = rule.none {
        prefix_conditions(conditions, prefix);
    }
}

/// Collect all trait reference IDs from a composite rule's conditions
pub(crate) fn collect_trait_refs_from_rule(rule: &CompositeTrait) -> Vec<(String, String)> {
    let mut refs = Vec::new();

    fn collect_from_conditions(
        conditions: &[Condition],
        rule_id: &str,
        refs: &mut Vec<(String, String)>,
    ) {
        for cond in conditions {
            if let Condition::Trait { id } = cond {
                refs.push((id.clone(), rule_id.to_string()));
            }
        }
    }

    if let Some(ref conditions) = rule.all {
        collect_from_conditions(conditions, &rule.id, &mut refs);
    }
    if let Some(ref conditions) = rule.any {
        collect_from_conditions(conditions, &rule.id, &mut refs);
    }
    if let Some(ref conditions) = rule.none {
        collect_from_conditions(conditions, &rule.id, &mut refs);
    }

    refs
}

/// Find `any:` clauses that reference 3+ traits from the same external directory.
/// Returns a list of (rule_id, directory, trait_count, trait_ids) for violations.
pub(crate) fn find_redundant_any_refs(
    rule: &CompositeTrait,
) -> Vec<(String, String, usize, Vec<String>)> {
    let mut violations = Vec::new();

    let Some(ref any_conditions) = rule.any else {
        return violations;
    };

    // Extract the rule's own directory prefix
    let rule_dir = if let Some(idx) = rule.id.find("::") {
        &rule.id[..idx]
    } else if let Some(idx) = rule.id.rfind('/') {
        &rule.id[..idx]
    } else {
        ""
    };

    // Collect trait refs from `any:` and group by directory
    // ONLY count specific trait IDs (with ::), not directory references
    let mut dir_refs: HashMap<String, Vec<String>> = HashMap::new();

    for cond in any_conditions {
        if let Condition::Trait { id } = cond {
            // Only process specific trait references (with ::)
            // Skip directory references like "obj/creds/browser/chromium"
            if let Some(idx) = id.find("::") {
                let trait_dir = &id[..idx];

                // Only flag external directories (different from rule's directory)
                // Skip meta/ paths since those are auto-generated and can't use directory notation
                if trait_dir != rule_dir && !trait_dir.starts_with("meta/") {
                    dir_refs
                        .entry(trait_dir.to_string())
                        .or_default()
                        .push(id.clone());
                }
            }
            // If no ::, it's a directory reference - these are always fine
        }
    }

    // Find directories with 3+ references
    for (dir, trait_ids) in dir_refs {
        if trait_ids.len() >= 3 {
            violations.push((rule.id.clone(), dir, trait_ids.len(), trait_ids));
        }
    }

    violations
}

/// Find composite rules that have only a single condition total across `any:` and `all:`.
/// A single-item `any:` or `all:` is only a problem if there's no other clause.
/// When both exist, they work together and aren't redundant.
/// Also skip rules that have `none:` or `downgrade:` clauses - these add meaningful logic.
/// Returns (rule_id, clause_type: "any" or "all", trait_id).
pub(crate) fn find_single_item_clauses(rule: &CompositeTrait) -> Vec<(String, &'static str, String)> {
    let mut violations = Vec::new();

    // Skip rules with none: or downgrade: clauses - they add meaningful conditions
    let has_none = rule.none.as_ref().map_or(false, |v| !v.is_empty());
    let has_downgrade = rule.downgrade.is_some();
    if has_none || has_downgrade {
        return violations;
    }

    let any_count = rule.any.as_ref().map_or(0, |v| v.len());
    let all_count = rule.all.as_ref().map_or(0, |v| v.len());
    let total_count = any_count + all_count;

    // Only flag if there's exactly 1 condition total
    if total_count != 1 {
        return violations;
    }

    // Check which clause has the single item
    // Skip directory references (no :: separator) - they match multiple traits
    if any_count == 1 {
        if let Some(Condition::Trait { id }) = rule.any.as_ref().and_then(|v| v.first()) {
            // Only flag specific trait references (with ::), not directory references
            if id.contains("::") {
                violations.push((rule.id.clone(), "any", id.clone()));
            }
        }
    }

    if all_count == 1 {
        if let Some(Condition::Trait { id }) = rule.all.as_ref().and_then(|v| v.first()) {
            // Only flag specific trait references (with ::), not directory references
            if id.contains("::") {
                violations.push((rule.id.clone(), "all", id.clone()));
            }
        }
    }

    violations
}

/// Find cap/ rules with hostile criticality.
/// Cap rules represent observable capabilities and should never be hostile.
/// Hostile criticality requires objective-level evidence and belongs in obj/.
/// Returns (rule_id, source_file) for violations.
pub(crate) fn find_hostile_cap_rules(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    // Helper to check if rule is in cap/
    fn is_cap_rule(id: &str) -> bool {
        if let Some(idx) = id.find("::") {
            let prefix = &id[..idx];
            if let Some(slash_idx) = prefix.find('/') {
                return &prefix[..slash_idx] == "cap";
            }
            return prefix == "cap";
        } else if let Some(slash_idx) = id.find('/') {
            return &id[..slash_idx] == "cap";
        }
        false
    }

    // Check trait definitions
    for trait_def in trait_definitions {
        if is_cap_rule(&trait_def.id) && trait_def.crit == Criticality::Hostile {
            let source = rule_source_files
                .get(&trait_def.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((trait_def.id.clone(), source));
        }
    }

    // Check composite rules
    for rule in composite_rules {
        if is_cap_rule(&rule.id) && rule.crit == Criticality::Hostile {
            let source = rule_source_files
                .get(&rule.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((rule.id.clone(), source));
        }
    }

    violations
}

/// Find cap/ rules that reference obj/ rules.
/// Cap contains micro-behaviors while obj contains larger behaviors.
/// Cap rules should not depend on obj rules.
/// Returns (rule_id, ref_id, source_file) for violations.
pub(crate) fn find_cap_obj_violations(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String, String)> {
    let mut violations = Vec::new();

    // Helper to extract tier prefix from a rule ID
    fn extract_tier(id: &str) -> Option<&str> {
        if let Some(idx) = id.find("::") {
            let prefix = &id[..idx];
            if let Some(slash_idx) = prefix.find('/') {
                Some(&prefix[..slash_idx])
            } else {
                Some(prefix)
            }
        } else if let Some(slash_idx) = id.find('/') {
            Some(&id[..slash_idx])
        } else {
            None
        }
    }

    // Check trait definitions
    for trait_def in trait_definitions {
        // Only check cap/ traits
        if let Some(tier) = extract_tier(&trait_def.id) {
            if tier != "cap" {
                continue;
            }

            // Check if the trait condition references other traits
            if let Condition::Trait { id: ref_id } = &trait_def.r#if {
                if let Some(ref_tier) = extract_tier(ref_id) {
                    if ref_tier == "obj" {
                        let source = rule_source_files
                            .get(&trait_def.id)
                            .cloned()
                            .unwrap_or_else(|| "unknown".to_string());
                        violations.push((trait_def.id.clone(), ref_id.clone(), source));
                    }
                }
            }
        }
    }

    // Check composite rules
    for rule in composite_rules {
        // Only check cap/ rules
        if let Some(tier) = extract_tier(&rule.id) {
            if tier != "cap" {
                continue;
            }

            // Collect all trait references from this rule
            let trait_refs = collect_trait_refs_from_rule(rule);
            for (ref_id, _) in trait_refs {
                if let Some(ref_tier) = extract_tier(&ref_id) {
                    if ref_tier == "obj" {
                        let source = rule_source_files
                            .get(&rule.id)
                            .cloned()
                            .unwrap_or_else(|| "unknown".to_string());
                        violations.push((rule.id.clone(), ref_id.clone(), source));
                    }
                }
            }
        }
    }

    violations
}

/// Platform/language names that should be YAML filenames, not directories.
/// These match values that can be used in `for:` or `platform:` fields.
const PLATFORM_NAMES: &[&str] = &[
    // Languages
    "python",
    "javascript",
    "typescript",
    "ruby",
    "java",
    "go",
    "rust",
    "c",
    "php",
    "perl",
    "lua",
    "swift",
    "csharp",
    "powershell",
    "groovy",
    "scala",
    "zig",
    "elixir",
    // Note: "shell" and "batch" excluded - they represent execution categories, not just platforms
    // Note: "dylib", "so", "dll" excluded - they represent library operation categories
    "objectivec",
    "applescript",
    // Binary formats (allowed in meta/format/)
    "elf",
    "macho",
    "pe",
    // Node.js variants
    "node",
    "nodejs",
    // Common aliases
    "bash",
    "sh",
    "zsh",
    "dotnet",
    // Operating systems / platforms
    "linux",
    "unix",
    "windows",
    "macos",
    "darwin",
    "android",
    "ios",
    "freebsd",
    "openbsd",
];

/// Check if a directory path contains platform/language names as directories.
/// Returns a list of (directory_path, platform_name) violations.
pub(crate) fn find_platform_named_directories(
    trait_dirs: &[String],
) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    for dir_path in trait_dirs {
        // Skip meta/format/ paths - binary format names are legitimate there
        if dir_path.starts_with("meta/format/") {
            continue;
        }

        // Split the path and check each component
        for component in dir_path.split('/') {
            let lower = component.to_lowercase();
            if PLATFORM_NAMES.contains(&lower.as_str()) {
                violations.push((dir_path.clone(), component.to_string()));
                break; // Only report first violation per path
            }
        }
    }

    violations
}

/// Check if YAML file paths in cap/ or obj/ are at the correct depth.
/// Valid depths are 3 or 4 subdirectories: cap/a/b/c/x.yaml or cap/a/b/c/d/x.yaml
/// Returns (path, depth, "shallow" or "deep") for violations.
pub(crate) fn find_depth_violations(yaml_files: &[String]) -> Vec<(String, usize, &'static str)> {
    let mut violations = Vec::new();

    for path in yaml_files {
        // Only check cap/ and obj/ paths
        if !path.starts_with("cap/") && !path.starts_with("obj/") {
            continue;
        }

        // Count directory components (excluding the root cap/ or obj/ and the filename)
        // e.g., "cap/comm/http/client/shell.yaml" -> ["cap", "comm", "http", "client", "shell.yaml"]
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() < 2 {
            continue;
        }

        // Subdirectory count = total parts - 1 (root) - 1 (filename)
        let subdir_count = parts.len() - 2;

        if subdir_count < 3 {
            violations.push((path.clone(), subdir_count, "shallow"));
        } else if subdir_count > 4 {
            violations.push((path.clone(), subdir_count, "deep"));
        }
    }

    violations
}

/// Validate that a trait ID contains only valid characters.
/// Valid characters are: alphanumerics, dashes, and underscores.
/// Returns None if valid, Some(invalid_char) if invalid.
fn validate_trait_id_chars(id: &str) -> Option<char> {
    for c in id.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            return Some(c);
        }
    }
    None
}

/// Find trait and composite rule IDs that contain invalid characters.
/// IDs should only contain alphanumerics, dashes, and underscores (no slashes).
/// Returns a list of (id, invalid_char, source_file) violations.
pub(crate) fn find_invalid_trait_ids(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, char, String)> {
    let mut violations = Vec::new();

    for trait_def in trait_definitions {
        // Extract local ID (after :: delimiter, or the whole ID if no delimiter)
        let local_id = if let Some(idx) = trait_def.id.find("::") {
            &trait_def.id[idx + 2..]
        } else {
            &trait_def.id
        };

        if let Some(invalid_char) = validate_trait_id_chars(local_id) {
            let source = rule_source_files
                .get(&trait_def.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((trait_def.id.clone(), invalid_char, source));
        }
    }

    for rule in composite_rules {
        // Extract local ID (after :: delimiter, or the whole ID if no delimiter)
        let local_id = if let Some(idx) = rule.id.find("::") {
            &rule.id[idx + 2..]
        } else {
            &rule.id
        };

        if let Some(invalid_char) = validate_trait_id_chars(local_id) {
            let source = rule_source_files
                .get(&rule.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((rule.id.clone(), invalid_char, source));
        }
    }

    violations
}

/// Try to find the line number where a string appears in a file
pub(crate) fn find_line_number(file_path: &str, search_str: &str) -> Option<usize> {
    let content = std::fs::read_to_string(file_path).ok()?;
    for (line_num, line) in content.lines().enumerate() {
        if line.contains(search_str) {
            return Some(line_num + 1); // 1-indexed
        }
    }
    None
}

/// Convert a simple rule with constraints into a composite rule
pub(crate) fn simple_rule_to_composite_rule(rule: super::models::SimpleRule) -> CompositeTrait {
    // Parse platforms
    let platforms = if rule.platforms.is_empty() {
        vec![Platform::All]
    } else {
        rule.platforms
            .iter()
            .filter_map(|p| match p.to_lowercase().as_str() {
                "all" => Some(Platform::All),
                "linux" => Some(Platform::Linux),
                "macos" => Some(Platform::MacOS),
                "windows" => Some(Platform::Windows),
                "unix" => Some(Platform::Unix),
                "android" => Some(Platform::Android),
                "ios" => Some(Platform::Ios),
                _ => None,
            })
            .collect()
    };

    // Parse file types
    let file_types = if rule.file_types.is_empty() {
        vec![RuleFileType::All]
    } else {
        parse_file_types(&rule.file_types)
    };

    // Create a composite trait with a single symbol condition
    CompositeTrait {
        id: rule.capability,
        desc: rule.desc,
        conf: rule.conf,
        crit: Criticality::Inert,
        mbc: None,
        attack: None,
        platforms,
        r#for: file_types,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some(rule.symbol),
            platforms: None,
            compiled_regex: None,
        }]),
        any: None,
        needs: None,
        none: None,
        near_lines: None,
        near_bytes: None,
        unless: None,
        not: None,
        downgrade: None,
    }
}

/// Signature for string/content matching conditions (for collision detection)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MatchSignature {
    exact: Option<String>,
    substr: Option<String>,
    regex: Option<String>,
    word: Option<String>,
    case_insensitive: bool,
    count_min: usize,
    count_max: Option<usize>,
    per_kb_min: Option<String>, // f64 as string for hashing
    per_kb_max: Option<String>,
    external_ip: bool,
    section: Option<String>,
    offset: Option<i64>,
    offset_range: Option<(i64, Option<i64>)>,
    section_offset: Option<i64>,
    section_offset_range: Option<(i64, Option<i64>)>,
}

/// Extract matching signature from a Condition (for string/content collision detection)
fn extract_match_signature(condition: &Condition) -> Option<(bool, MatchSignature)> {
    match condition {
        Condition::String {
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
            ..
        } => Some((
            true, // is_string_type
            MatchSignature {
                exact: exact.clone(),
                substr: substr.clone(),
                regex: regex.clone(),
                word: word.clone(),
                case_insensitive: *case_insensitive,
                count_min: *count_min,
                count_max: *count_max,
                per_kb_min: per_kb_min.map(|v| format!("{:.6}", v)),
                per_kb_max: per_kb_max.map(|v| format!("{:.6}", v)),
                external_ip: *external_ip,
                section: section.clone(),
                offset: *offset,
                offset_range: *offset_range,
                section_offset: *section_offset,
                section_offset_range: *section_offset_range,
            },
        )),
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
            ..
        } => Some((
            false, // is_content_type
            MatchSignature {
                exact: exact.clone(),
                substr: substr.clone(),
                regex: regex.clone(),
                word: word.clone(),
                case_insensitive: *case_insensitive,
                count_min: *count_min,
                count_max: *count_max,
                per_kb_min: per_kb_min.map(|v| format!("{:.6}", v)),
                per_kb_max: per_kb_max.map(|v| format!("{:.6}", v)),
                external_ip: *external_ip,
                section: section.clone(),
                offset: *offset,
                offset_range: *offset_range,
                section_offset: *section_offset,
                section_offset_range: *section_offset_range,
            },
        )),
        _ => None,
    }
}

/// Find traits where both `type: string` and `type: content` exist for the same pattern
/// at the same criticality. These should be merged to just `content` (which is broader).
/// Returns: Vec<(string_trait_id, content_trait_id, pattern_description)>
pub(crate) fn find_string_content_collisions(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, String, String)> {
    let mut collisions = Vec::new();

    // Group traits by (signature, criticality, for, platforms)
    // Key: (signature, crit, for, platforms) -> Vec<(trait_id, is_string_type)>
    let mut groups: HashMap<(MatchSignature, String, String, String), Vec<(String, bool)>> =
        HashMap::new();

    for t in trait_definitions {
        if let Some((is_string, sig)) = extract_match_signature(&t.r#if) {
            // Create a key that includes criticality, for, and platforms
            let crit_key = format!("{:?}", t.crit);
            let for_key = format!("{:?}", t.r#for);
            let platforms_key = format!("{:?}", t.platforms);
            let key = (sig, crit_key, for_key, platforms_key);

            groups
                .entry(key)
                .or_default()
                .push((t.id.clone(), is_string));
        }
    }

    // Find groups with both string and content types
    for ((sig, _crit, _for, _platforms), traits) in groups {
        let string_traits: Vec<_> = traits.iter().filter(|(_, is_str)| *is_str).collect();
        let content_traits: Vec<_> = traits.iter().filter(|(_, is_str)| !*is_str).collect();

        if !string_traits.is_empty() && !content_traits.is_empty() {
            // Describe the pattern for the warning
            let pattern_desc = if let Some(ref s) = sig.exact {
                format!("exact: \"{}\"", s)
            } else if let Some(ref s) = sig.substr {
                format!("substr: \"{}\"", s)
            } else if let Some(ref s) = sig.regex {
                format!("regex: \"{}\"", s)
            } else if let Some(ref s) = sig.word {
                format!("word: \"{}\"", s)
            } else {
                "unknown pattern".to_string()
            };

            for (string_id, _) in &string_traits {
                for (content_id, _) in &content_traits {
                    collisions.push((string_id.clone(), content_id.clone(), pattern_desc.clone()));
                }
            }
        }
    }

    collisions
}

/// Find traits that are identical except for the `for:` field.
/// These should be merged into a single trait with combined file types.
/// Returns: Vec<(trait_ids, shared_pattern_description)>
pub(crate) fn find_for_only_duplicates(
    trait_definitions: &[TraitDefinition],
) -> Vec<(Vec<String>, String)> {
    let mut duplicates = Vec::new();

    // Create signature excluding `for:` field but including everything else
    // Key: (if, crit, conf, platforms, size_min, size_max, not, unless) -> Vec<(trait_id, for)>
    let mut groups: HashMap<String, Vec<(String, Vec<RuleFileType>)>> = HashMap::new();

    for t in trait_definitions {
        let signature = format!(
            "{:?}:{:?}:{:.2}:{:?}:{:?}:{:?}:{:?}:{:?}",
            t.r#if, t.crit, t.conf, t.platforms, t.size_min, t.size_max, t.not, t.unless
        );
        groups
            .entry(signature)
            .or_default()
            .push((t.id.clone(), t.r#for.clone()));
    }

    // Find groups with multiple traits (different `for:` values)
    for (sig, traits) in groups {
        if traits.len() > 1 {
            // Check that they actually have different `for:` values
            let unique_fors: HashSet<String> =
                traits.iter().map(|(_, f)| format!("{:?}", f)).collect();
            if unique_fors.len() > 1 {
                let trait_ids: Vec<String> = traits.into_iter().map(|(id, _)| id).collect();

                // Extract a brief pattern description from the signature
                let pattern_desc = if sig.len() > 100 {
                    format!("{}...", &sig[..100])
                } else {
                    sig
                };

                duplicates.push((trait_ids, pattern_desc));
            }
        }
    }

    duplicates
}

/// Find traits with regex patterns that differ only in the first token (alternation candidates).
/// For example: `nc\s+-e`, `ncat\s+-e`, `netcat\s+-e` should become `(nc|ncat|netcat)\s+-e`
/// Returns: Vec<(trait_ids, common_suffix, suggested_prefix_alternation)>
pub(crate) fn find_alternation_merge_candidates(
    trait_definitions: &[TraitDefinition],
) -> Vec<(Vec<String>, String, String)> {
    let mut candidates = Vec::new();

    // Extract regex patterns with their metadata
    // Group by (crit, for, platforms, all other condition params except regex)
    let mut groups: HashMap<String, Vec<(String, String)>> = HashMap::new(); // key -> [(trait_id, regex)]

    for t in trait_definitions {
        let regex_pattern = match &t.r#if {
            Condition::String { regex: Some(r), .. } => Some(r.clone()),
            Condition::Content { regex: Some(r), .. } => Some(r.clone()),
            _ => None,
        };

        if let Some(regex) = regex_pattern {
            // Create key excluding the regex pattern itself
            let key = format!(
                "{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}",
                t.crit, t.r#for, t.platforms, t.size_min, t.size_max, t.not, t.unless
            );
            groups.entry(key).or_default().push((t.id.clone(), regex));
        }
    }

    // Regex to extract prefix (first word-like token) and suffix
    // Match patterns like: ^word or ^word\s or ^word[^a-z]
    let prefix_regex =
        regex::Regex::new(r"^(\^?)([a-zA-Z_][a-zA-Z0-9_-]*)(.*)$").expect("valid regex");

    // For each group, find patterns that share a common suffix
    for (_key, traits) in groups {
        if traits.len() < 2 {
            continue;
        }

        // Try to find common suffix by splitting on first non-word pattern
        // Look for patterns like: `word\s+rest` or `word-rest` or `word_rest`
        let mut suffix_groups: HashMap<String, Vec<(String, String)>> = HashMap::new();

        for (trait_id, regex) in &traits {
            // Try to extract prefix (first word-like token) and suffix
            if let Some(captures) = prefix_regex.captures(regex) {
                let caret = captures.get(1).map(|m| m.as_str()).unwrap_or("");
                let prefix = captures.get(2).map(|m| m.as_str()).unwrap_or("");
                let suffix = captures.get(3).map(|m| m.as_str()).unwrap_or("");

                // Only group if suffix is non-trivial (at least a few chars)
                if suffix.len() >= 3 {
                    let suffix_key = format!("{}{}", caret, suffix);
                    suffix_groups
                        .entry(suffix_key)
                        .or_default()
                        .push((trait_id.clone(), prefix.to_string()));
                }
            }
        }

        // Find suffix groups with 2+ traits
        for (suffix, prefix_traits) in suffix_groups {
            if prefix_traits.len() >= 2 {
                let trait_ids: Vec<String> = prefix_traits.iter().map(|(id, _)| id.clone()).collect();
                let prefixes: Vec<String> = prefix_traits.iter().map(|(_, p)| p.clone()).collect();

                // Build suggested alternation
                let suggested = format!("({}){}", prefixes.join("|"), suffix);

                candidates.push((trait_ids, suffix, suggested));
            }
        }
    }

    candidates
}

// ==================== Taxonomy Validations ====================

/// Directory name segments that add no semantic meaning.
/// These make the taxonomy harder to navigate and provide no value for ML classification.
const BANNED_DIRECTORY_SEGMENTS: &[&str] = &[
    "generic",  // says nothing about what's inside
    "method",   // everything is a method
    "modes",    // dumping ground
    "types",    // dumping ground
    "techniques",    // dumping ground
    "technique",    // dumping ground
    "notable",    // dumping ground
    "suspicious",    // dumping ground
    "hostile",    // dumping ground
    "category",    // dumping ground
    "misc",     // dumping ground
    "other",    // dumping ground
    "utils",    // too vague
    "helpers",  // too vague
    "common",   // too vague
    "base",     // too vague
    "impl",     // implementation detail
    "default",  // meaningless
    "basic",    // meaningless
    "simple",   // meaningless
    "advanced", // subjective
    "new",      // temporal, will rot
    "old",      // temporal, will rot
    "stuff",    // obviously bad
    "things",   // obviously bad
    "type",     // too vague
    "types",    // too vague
    "kind",     // too vague
    "kinds",    // too vague
    "various",  // dumping ground
    "assorted", // dumping ground
];

/// Find directories containing banned meaningless segments.
/// Returns: Vec<(directory_path, banned_segment)>
pub(crate) fn find_banned_directory_segments(trait_dirs: &[String]) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    for dir_path in trait_dirs {
        for segment in dir_path.split('/') {
            let lower = segment.to_lowercase();
            if BANNED_DIRECTORY_SEGMENTS.contains(&lower.as_str()) {
                violations.push((dir_path.clone(), segment.to_string()));
                break; // Only report first violation per path
            }
        }
    }

    violations
}

/// Find paths with duplicate words across segments.
/// e.g., "obj/anti-analysis/analysis/" or "cap/exec/execute/"
/// Returns: Vec<(directory_path, duplicate_word)>
pub(crate) fn find_duplicate_words_in_path(trait_dirs: &[String]) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    for dir_path in trait_dirs {
        // Exception: firewalld is the actual name of the software
        if dir_path.contains("firewall/firewalld") {
            continue;
        }

        // Split path into segments and extract word stems
        let segments: Vec<&str> = dir_path.split('/').collect();

        // For each segment, extract "words" (split on - and _)
        let mut seen_words: HashSet<String> = HashSet::new();

        for segment in &segments {
            // Split segment into constituent words
            let words: Vec<&str> = segment.split(|c| c == '-' || c == '_').collect();

            for word in words {
                let lower = word.to_lowercase();
                // Skip very short words (likely abbreviations or prefixes)
                if lower.len() < 3 {
                    continue;
                }

                // Check for exact duplicates
                if seen_words.contains(&lower) {
                    violations.push((dir_path.clone(), word.to_string()));
                    break;
                }

                // Check for stem duplicates (e.g., "exec" vs "execute", "analysis" vs "anti-analysis")
                // Simple heuristic: if one word starts with another (min 4 chars), it's a duplicate
                for seen in &seen_words {
                    if seen.len() >= 4 && lower.len() >= 4 {
                        if lower.starts_with(seen) || seen.starts_with(&lower) {
                            violations.push((dir_path.clone(), word.to_string()));
                            break;
                        }
                    }
                }

                seen_words.insert(lower);
            }
        }
    }

    // Deduplicate violations (same path might trigger multiple times)
    violations.sort();
    violations.dedup();
    violations
}

/// Find directories where a segment duplicates its immediate parent.
/// e.g., "cap/exec/exec/" or "obj/creds/credentials/"
/// Returns: Vec<(directory_path, duplicated_segment)>
pub(crate) fn find_parent_duplicate_segments(trait_dirs: &[String]) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    for dir_path in trait_dirs {
        let segments: Vec<&str> = dir_path.split('/').collect();

        for window in segments.windows(2) {
            let parent = window[0].to_lowercase();
            let child = window[1].to_lowercase();

            // Exact duplicate
            if parent == child {
                violations.push((dir_path.clone(), window[1].to_string()));
                break;
            }

            // Plural/singular variants (simple check)
            if parent.len() >= 3 && child.len() >= 3 {
                // "cred" vs "creds" or "credentials"
                let parent_stem = parent.trim_end_matches('s');
                let child_stem = child.trim_end_matches('s');
                if parent_stem == child_stem {
                    violations.push((dir_path.clone(), window[1].to_string()));
                    break;
                }
            }
        }
    }

    violations
}

/// Maximum number of traits allowed in a single directory.
/// Directories exceeding this should be split into subdirectories.
pub const MAX_TRAITS_PER_DIRECTORY: usize = 40;

/// Find directories with too many traits (suggests need for subdirectories).
/// Returns: Vec<(directory_path, trait_count)>
pub(crate) fn find_oversized_trait_directories(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, usize)> {
    // Count traits per directory (extract directory from trait ID)
    let mut dir_counts: HashMap<String, usize> = HashMap::new();

    for t in trait_definitions {
        // Extract directory from trait ID (everything before ::)
        let dir = if let Some(idx) = t.id.find("::") {
            t.id[..idx].to_string()
        } else if let Some(idx) = t.id.rfind('/') {
            t.id[..idx].to_string()
        } else {
            continue; // No directory prefix
        };

        *dir_counts.entry(dir).or_insert(0) += 1;
    }

    let mut violations: Vec<_> = dir_counts
        .into_iter()
        .filter(|(_, count)| *count > MAX_TRAITS_PER_DIRECTORY)
        .collect();

    violations.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by count descending
    violations
}

/// Find composite rules where `needs` exceeds the number of items in `any:`.
/// This makes the rule impossible to satisfy.
/// Returns: Vec<(rule_id, needs_value, any_length)>
pub(crate) fn find_impossible_needs(composite_rules: &[CompositeTrait]) -> Vec<(String, usize, usize)> {
    let mut violations = Vec::new();

    for rule in composite_rules {
        if let (Some(needs), Some(any_items)) = (rule.needs, rule.any.as_ref()) {
            if needs > any_items.len() {
                violations.push((rule.id.clone(), needs, any_items.len()));
            }
        }
    }

    violations
}

/// Find traits/rules with impossible size constraints (size_min > size_max).
/// Returns: Vec<(id, size_min, size_max, is_composite)>
pub(crate) fn find_impossible_size_constraints(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, usize, usize, bool)> {
    let mut violations = Vec::new();

    for t in trait_definitions {
        if let (Some(min), Some(max)) = (t.size_min, t.size_max) {
            if min > max {
                violations.push((t.id.clone(), min, max, false));
            }
        }
    }

    for r in composite_rules {
        if let (Some(min), Some(max)) = (r.size_min, r.size_max) {
            if min > max {
                violations.push((r.id.clone(), min, max, true));
            }
        }
    }

    violations
}

/// Find conditions with impossible count constraints (count_min > count_max).
/// Returns: Vec<(trait_id, count_min, count_max)>
pub(crate) fn find_impossible_count_constraints(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, usize, usize)> {
    let mut violations = Vec::new();

    for t in trait_definitions {
        let (count_min, count_max) = match &t.r#if {
            Condition::String {
                count_min,
                count_max,
                ..
            }
            | Condition::Content {
                count_min,
                count_max,
                ..
            }
            | Condition::Hex {
                count_min,
                count_max,
                ..
            }
            | Condition::Base64 {
                count_min,
                count_max,
                ..
            }
            | Condition::Xor {
                count_min,
                count_max,
                ..
            } => (*count_min, *count_max),
            _ => continue,
        };

        if let Some(max) = count_max {
            if count_min > max {
                violations.push((t.id.clone(), count_min, max));
            }
        }
    }

    violations
}

/// Find composite rules with empty `any:` or `all:` clauses that are the only condition.
/// An empty clause makes the rule either always match (empty all) or never match (empty any with needs > 0).
/// Returns: Vec<(rule_id, clause_type)>
pub(crate) fn find_empty_condition_clauses(
    composite_rules: &[CompositeTrait],
) -> Vec<(String, &'static str)> {
    let mut violations = Vec::new();

    for rule in composite_rules {
        let all_empty = rule.all.as_ref().map_or(true, |v| v.is_empty());
        let any_empty = rule.any.as_ref().map_or(true, |v| v.is_empty());
        let none_empty = rule.none.as_ref().map_or(true, |v| v.is_empty());

        // Only flag if we have an explicit empty clause (Some([]))
        if let Some(all) = &rule.all {
            if all.is_empty() && any_empty && none_empty {
                violations.push((rule.id.clone(), "all"));
            }
        }

        if let Some(any) = &rule.any {
            if any.is_empty() && all_empty && none_empty {
                violations.push((rule.id.clone(), "any"));
            }
        }
    }

    violations
}

/// Find string/content conditions with no actual search pattern.
/// A condition needs at least one of: exact, substr, regex, word.
/// Returns: Vec<trait_id>
pub(crate) fn find_missing_search_patterns(
    trait_definitions: &[TraitDefinition],
) -> Vec<String> {
    let mut violations = Vec::new();

    for t in trait_definitions {
        let has_pattern = match &t.r#if {
            Condition::String {
                exact,
                substr,
                regex,
                word,
                ..
            }
            | Condition::Content {
                exact,
                substr,
                regex,
                word,
                ..
            } => exact.is_some() || substr.is_some() || regex.is_some() || word.is_some(),
            Condition::Base64 {
                exact,
                substr,
                regex,
                ..
            }
            | Condition::Xor {
                exact,
                substr,
                regex,
                ..
            } => exact.is_some() || substr.is_some() || regex.is_some(),
            Condition::Hex { pattern, .. } => !pattern.is_empty(),
            Condition::Symbol {
                exact,
                substr,
                regex,
                ..
            } => exact.is_some() || substr.is_some() || regex.is_some(),
            // Other condition types have required fields
            _ => true,
        };

        if !has_pattern {
            violations.push(t.id.clone());
        }
    }

    violations
}

/// Find composite rules with redundant `needs: 1` when only `any:` clause exists.
/// `needs: 1` is the default, so specifying it explicitly adds noise.
/// Returns: Vec<rule_id>
pub(crate) fn find_redundant_needs_one(composite_rules: &[CompositeTrait]) -> Vec<String> {
    let mut violations = Vec::new();

    for rule in composite_rules {
        // Check if needs is explicitly set to 1
        if rule.needs != Some(1) {
            continue;
        }

        // Check if only `any:` clause exists (no all:, no none:)
        let has_all = rule.all.as_ref().map_or(false, |v| !v.is_empty());
        let has_none = rule.none.as_ref().map_or(false, |v| !v.is_empty());
        let has_any = rule.any.as_ref().map_or(false, |v| !v.is_empty());

        if has_any && !has_all && !has_none {
            violations.push(rule.id.clone());
        }
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== String Scoring Tests ====================

    #[test]
    fn test_score_string_value_empty() {
        assert_eq!(score_string_value(""), 0.0);
    }

    #[test]
    fn test_score_string_value_short() {
        // 1-5 chars = 1 bucket = 0.3
        assert_eq!(score_string_value("a"), PARAM_UNIT);
        assert_eq!(score_string_value("abcde"), PARAM_UNIT);
    }

    #[test]
    fn test_score_string_value_medium() {
        // 6-10 chars = 2 buckets = 0.6
        assert_eq!(score_string_value("abcdef"), PARAM_UNIT * 2.0);
        assert_eq!(score_string_value("abcdefghij"), PARAM_UNIT * 2.0);
    }

    #[test]
    fn test_score_string_value_long() {
        // 11-15 chars = 3 buckets = 0.9
        assert_eq!(score_string_value("abcdefghijk"), PARAM_UNIT * 3.0);
        // 16-20 chars = 4 buckets = 1.2
        assert_eq!(score_string_value("abcdefghijklmnop"), PARAM_UNIT * 4.0);
    }

    #[test]
    fn test_score_word_value_adds_delimiters() {
        // Word matching adds 2 for boundaries, so "abc" (3 chars) becomes 5 = 1 bucket
        assert_eq!(score_word_value("abc"), PARAM_UNIT);
        // "abcd" (4 chars) + 2 = 6 = 2 buckets
        assert_eq!(score_word_value("abcd"), PARAM_UNIT * 2.0);
    }

    #[test]
    fn test_score_regex_value_ignores_backslashes() {
        // "\btest\b" has 6 non-backslash chars = 2 buckets
        assert_eq!(score_regex_value(r"\btest\b"), PARAM_UNIT * 2.0);
        // Empty after removing backslashes
        assert_eq!(score_regex_value(r"\\\\"), 0.0);
    }

    #[test]
    fn test_score_presence_some() {
        assert_eq!(score_presence(Some(&42)), PARAM_UNIT);
    }

    #[test]
    fn test_score_presence_none() {
        assert_eq!(score_presence::<i32>(None), 0.0);
    }

    // ==================== Sum Weakest Tests ====================

    #[test]
    fn test_sum_weakest_empty() {
        assert_eq!(sum_weakest(vec![], 3), 0.0);
    }

    #[test]
    fn test_sum_weakest_zero_count() {
        assert_eq!(sum_weakest(vec![1.0, 2.0, 3.0], 0), 0.0);
    }

    #[test]
    fn test_sum_weakest_single() {
        assert_eq!(sum_weakest(vec![5.0, 2.0, 8.0], 1), 2.0);
    }

    #[test]
    fn test_sum_weakest_multiple() {
        // Sorted: [2.0, 5.0, 8.0], take 2 weakest = 2.0 + 5.0 = 7.0
        assert_eq!(sum_weakest(vec![5.0, 2.0, 8.0], 2), 7.0);
    }

    #[test]
    fn test_sum_weakest_more_than_available() {
        // Only 2 values, asking for 5
        assert_eq!(sum_weakest(vec![3.0, 1.0], 5), 4.0);
    }

    // ==================== Trait ID Validation Tests ====================

    #[test]
    fn test_validate_trait_id_chars_valid() {
        assert_eq!(validate_trait_id_chars("valid-trait_name123"), None);
        assert_eq!(validate_trait_id_chars("abc"), None);
        assert_eq!(validate_trait_id_chars("ABC-123_test"), None);
    }

    #[test]
    fn test_validate_trait_id_chars_invalid_slash() {
        assert_eq!(validate_trait_id_chars("invalid/trait"), Some('/'));
    }

    #[test]
    fn test_validate_trait_id_chars_invalid_space() {
        assert_eq!(validate_trait_id_chars("invalid trait"), Some(' '));
    }

    #[test]
    fn test_validate_trait_id_chars_invalid_special() {
        assert_eq!(validate_trait_id_chars("trait@name"), Some('@'));
        assert_eq!(validate_trait_id_chars("trait.name"), Some('.'));
    }

    // ==================== Platform Directory Validation Tests ====================

    #[test]
    fn test_find_platform_named_directories_empty() {
        let dirs: Vec<String> = vec![];
        assert!(find_platform_named_directories(&dirs).is_empty());
    }

    #[test]
    fn test_find_platform_named_directories_no_violations() {
        let dirs = vec![
            "cap/comm/http/client".to_string(),
            "obj/creds/browser".to_string(),
        ];
        assert!(find_platform_named_directories(&dirs).is_empty());
    }

    #[test]
    fn test_find_platform_named_directories_with_violation() {
        let dirs = vec![
            "cap/exec/python/imports".to_string(), // "python" is a platform name
        ];
        let violations = find_platform_named_directories(&dirs);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1, "python");
    }

    #[test]
    fn test_find_platform_named_directories_skips_meta_format() {
        let dirs = vec![
            "meta/format/elf".to_string(), // Should be skipped
        ];
        assert!(find_platform_named_directories(&dirs).is_empty());
    }

    // ==================== Depth Violation Tests ====================

    #[test]
    fn test_find_depth_violations_valid_depths() {
        let files = vec![
            "cap/a/b/c/test.yaml".to_string(),    // depth 3, valid
            "cap/a/b/c/d/test.yaml".to_string(),  // depth 4, valid
            "obj/x/y/z/file.yaml".to_string(),    // depth 3, valid
        ];
        assert!(find_depth_violations(&files).is_empty());
    }

    #[test]
    fn test_find_depth_violations_too_shallow() {
        let files = vec![
            "cap/a/test.yaml".to_string(),        // depth 1, too shallow
            "cap/a/b/test.yaml".to_string(),      // depth 2, too shallow
        ];
        let violations = find_depth_violations(&files);
        assert_eq!(violations.len(), 2);
        assert_eq!(violations[0].2, "shallow");
        assert_eq!(violations[1].2, "shallow");
    }

    #[test]
    fn test_find_depth_violations_too_deep() {
        let files = vec![
            "cap/a/b/c/d/e/test.yaml".to_string(), // depth 5, too deep
        ];
        let violations = find_depth_violations(&files);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].2, "deep");
    }

    #[test]
    fn test_find_depth_violations_skips_other_paths() {
        let files = vec![
            "meta/test.yaml".to_string(),         // Not cap/ or obj/, skipped
            "known/malware/test.yaml".to_string(), // Not cap/ or obj/, skipped
        ];
        assert!(find_depth_violations(&files).is_empty());
    }

    // ==================== Single Item Clause Tests ====================

    #[test]
    fn test_find_single_item_clauses_empty_rule() {
        let rule = CompositeTrait {
            id: "test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: None,
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        assert!(find_single_item_clauses(&rule).is_empty());
    }

    #[test]
    fn test_find_single_item_clauses_single_all() {
        let rule = CompositeTrait {
            id: "test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: Some(vec![Condition::Trait { id: "other::trait".to_string() }]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        let violations = find_single_item_clauses(&rule);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1, "all");
    }

    #[test]
    fn test_find_single_item_clauses_multiple_items_ok() {
        let rule = CompositeTrait {
            id: "test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: Some(vec![
                Condition::Trait { id: "trait1".to_string() },
                Condition::Trait { id: "trait2".to_string() },
            ]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        assert!(find_single_item_clauses(&rule).is_empty());
    }

    #[test]
    fn test_find_single_item_clauses_skips_with_none() {
        let rule = CompositeTrait {
            id: "test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: Some(vec![Condition::Trait { id: "trait1".to_string() }]),
            any: None,
            needs: None,
            none: Some(vec![Condition::Trait { id: "excluded".to_string() }]),
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        // Should be empty because rule has none: clause
        assert!(find_single_item_clauses(&rule).is_empty());
    }

    // ==================== Redundant Any Refs Tests ====================

    #[test]
    fn test_find_redundant_any_refs_no_any() {
        let rule = CompositeTrait {
            id: "test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: None,
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        assert!(find_redundant_any_refs(&rule).is_empty());
    }

    #[test]
    fn test_find_redundant_any_refs_few_refs_ok() {
        let rule = CompositeTrait {
            id: "test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: None,
            any: Some(vec![
                Condition::Trait { id: "other/dir::trait1".to_string() },
                Condition::Trait { id: "other/dir::trait2".to_string() },
            ]),
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        // Only 2 refs from same dir, need 3+ for violation
        assert!(find_redundant_any_refs(&rule).is_empty());
    }

    #[test]
    fn test_find_redundant_any_refs_violation() {
        let rule = CompositeTrait {
            id: "test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: None,
            any: Some(vec![
                Condition::Trait { id: "other/dir::trait1".to_string() },
                Condition::Trait { id: "other/dir::trait2".to_string() },
                Condition::Trait { id: "other/dir::trait3".to_string() },
            ]),
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        let violations = find_redundant_any_refs(&rule);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1, "other/dir");
        assert_eq!(violations[0].2, 3);
    }

    // ==================== Autoprefix Tests ====================

    #[test]
    fn test_autoprefix_trait_refs_local_ids() {
        let mut rule = CompositeTrait {
            id: "cap/test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: Some(vec![
                Condition::Trait { id: "local-trait".to_string() },
            ]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };

        autoprefix_trait_refs(&mut rule, "cap/test");

        if let Some(Condition::Trait { id }) = rule.all.as_ref().and_then(|v| v.first()) {
            assert_eq!(id, "cap/test::local-trait");
        } else {
            panic!("Expected trait condition");
        }
    }

    #[test]
    fn test_autoprefix_trait_refs_already_qualified() {
        let mut rule = CompositeTrait {
            id: "cap/test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: Some(vec![
                Condition::Trait { id: "other/path::trait".to_string() },
            ]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };

        autoprefix_trait_refs(&mut rule, "cap/test");

        // Should NOT be modified since it already has ::
        if let Some(Condition::Trait { id }) = rule.all.as_ref().and_then(|v| v.first()) {
            assert_eq!(id, "other/path::trait");
        } else {
            panic!("Expected trait condition");
        }
    }

    // ==================== Collect Trait Refs Tests ====================

    #[test]
    fn test_collect_trait_refs_from_rule_empty() {
        let rule = CompositeTrait {
            id: "test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: None,
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        assert!(collect_trait_refs_from_rule(&rule).is_empty());
    }

    #[test]
    fn test_collect_trait_refs_from_rule_all_clauses() {
        let rule = CompositeTrait {
            id: "test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: Some(vec![Condition::Trait { id: "trait1".to_string() }]),
            any: Some(vec![Condition::Trait { id: "trait2".to_string() }]),
            needs: None,
            none: Some(vec![Condition::Trait { id: "trait3".to_string() }]),
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        let refs = collect_trait_refs_from_rule(&rule);
        assert_eq!(refs.len(), 3);
        assert!(refs.iter().any(|(id, _)| id == "trait1"));
        assert!(refs.iter().any(|(id, _)| id == "trait2"));
        assert!(refs.iter().any(|(id, _)| id == "trait3"));
    }

    // ==================== String/Content Collision Tests ====================

    fn make_string_trait(id: &str, substr: &str, crit: Criticality) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 0.9,
            crit,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            r#if: Condition::String {
                exact: None,
                substr: Some(substr.to_string()),
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
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
        }
    }

    fn make_content_trait(id: &str, substr: &str, crit: Criticality) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 0.9,
            crit,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            r#if: Condition::Content {
                exact: None,
                substr: Some(substr.to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                count_min: 1,
                count_max: None,
                per_kb_min: None,
                per_kb_max: None,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
            },
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
        }
    }

    #[test]
    fn test_find_string_content_collisions_empty() {
        let traits: Vec<TraitDefinition> = vec![];
        assert!(find_string_content_collisions(&traits).is_empty());
    }

    #[test]
    fn test_find_string_content_collisions_no_collision() {
        let traits = vec![
            make_string_trait("test::string1", "eval", Criticality::Notable),
            make_string_trait("test::string2", "exec", Criticality::Notable),
        ];
        assert!(find_string_content_collisions(&traits).is_empty());
    }

    #[test]
    fn test_find_string_content_collisions_same_pattern_same_crit() {
        let traits = vec![
            make_string_trait("test::string-eval", "eval", Criticality::Notable),
            make_content_trait("test::content-eval", "eval", Criticality::Notable),
        ];
        let collisions = find_string_content_collisions(&traits);
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].0, "test::string-eval");
        assert_eq!(collisions[0].1, "test::content-eval");
    }

    #[test]
    fn test_find_string_content_collisions_different_crit_no_collision() {
        let traits = vec![
            make_string_trait("test::string-eval", "eval", Criticality::Notable),
            make_content_trait("test::content-eval", "eval", Criticality::Suspicious),
        ];
        // Different criticality means no collision
        assert!(find_string_content_collisions(&traits).is_empty());
    }

    // ==================== For-Only Duplicates Tests ====================

    fn make_trait_with_for(
        id: &str,
        substr: &str,
        file_types: Vec<RuleFileType>,
    ) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 0.9,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: file_types,
            size_min: None,
            size_max: None,
            r#if: Condition::String {
                exact: None,
                substr: Some(substr.to_string()),
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
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
        }
    }

    #[test]
    fn test_find_for_only_duplicates_empty() {
        let traits: Vec<TraitDefinition> = vec![];
        assert!(find_for_only_duplicates(&traits).is_empty());
    }

    #[test]
    fn test_find_for_only_duplicates_no_duplicates() {
        let traits = vec![
            make_trait_with_for("test::eval-py", "eval", vec![RuleFileType::Python]),
            make_trait_with_for("test::exec-py", "exec", vec![RuleFileType::Python]),
        ];
        // Different patterns, so no duplicates
        assert!(find_for_only_duplicates(&traits).is_empty());
    }

    #[test]
    fn test_find_for_only_duplicates_same_pattern_different_for() {
        let traits = vec![
            make_trait_with_for("test::eval-py", "eval", vec![RuleFileType::Python]),
            make_trait_with_for("test::eval-js", "eval", vec![RuleFileType::JavaScript]),
        ];
        let duplicates = find_for_only_duplicates(&traits);
        assert_eq!(duplicates.len(), 1);
        assert!(duplicates[0].0.contains(&"test::eval-py".to_string()));
        assert!(duplicates[0].0.contains(&"test::eval-js".to_string()));
    }

    #[test]
    fn test_find_for_only_duplicates_same_for_not_duplicate() {
        let traits = vec![
            make_trait_with_for("test::eval1", "eval", vec![RuleFileType::Python]),
            make_trait_with_for("test::eval2", "eval", vec![RuleFileType::Python]),
        ];
        // Same `for:` values means not a "for-only" duplicate (it's a true duplicate)
        assert!(find_for_only_duplicates(&traits).is_empty());
    }

    // ==================== Alternation Merge Candidates Tests ====================

    fn make_regex_trait(id: &str, regex: &str) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 0.9,
            crit: Criticality::Suspicious,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::Shell],
            size_min: None,
            size_max: None,
            r#if: Condition::String {
                exact: None,
                substr: None,
                regex: Some(regex.to_string()),
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                count_min: 1,
                count_max: None,
                per_kb_min: None,
                per_kb_max: None,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
        }
    }

    #[test]
    fn test_find_alternation_merge_candidates_empty() {
        let traits: Vec<TraitDefinition> = vec![];
        assert!(find_alternation_merge_candidates(&traits).is_empty());
    }

    #[test]
    fn test_find_alternation_merge_candidates_no_candidates() {
        let traits = vec![
            make_regex_trait("test::pattern1", r"foo\s+bar"),
            make_regex_trait("test::pattern2", r"baz\s+qux"),
        ];
        // Completely different patterns
        assert!(find_alternation_merge_candidates(&traits).is_empty());
    }

    #[test]
    fn test_find_alternation_merge_candidates_common_suffix() {
        let traits = vec![
            make_regex_trait("test::nc-exec", r"nc\s+-e\s+/bin/sh"),
            make_regex_trait("test::ncat-exec", r"ncat\s+-e\s+/bin/sh"),
            make_regex_trait("test::netcat-exec", r"netcat\s+-e\s+/bin/sh"),
        ];
        let candidates = find_alternation_merge_candidates(&traits);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0.len(), 3);
        // The suggested pattern should include alternation
        assert!(candidates[0].2.contains("nc|ncat|netcat") || candidates[0].2.contains("ncat|nc|netcat"));
    }

    #[test]
    fn test_find_alternation_merge_candidates_different_crit_no_match() {
        // Create traits with different criticality
        let mut trait1 = make_regex_trait("test::nc-exec", r"nc\s+-e\s+/bin/sh");
        trait1.crit = Criticality::Notable;
        let trait2 = make_regex_trait("test::ncat-exec", r"ncat\s+-e\s+/bin/sh");
        // trait2 keeps Suspicious

        let traits = vec![trait1, trait2];
        // Different criticality means they shouldn't be grouped
        assert!(find_alternation_merge_candidates(&traits).is_empty());
    }

    #[test]
    fn test_find_alternation_merge_candidates_short_suffix_ignored() {
        let traits = vec![
            make_regex_trait("test::a1", r"foo\s"),
            make_regex_trait("test::a2", r"bar\s"),
        ];
        // Suffix is too short (< 3 chars after prefix)
        assert!(find_alternation_merge_candidates(&traits).is_empty());
    }

    // ==================== Impossible Needs Tests ====================

    fn make_composite_rule(id: &str, any_count: usize, needs: Option<usize>) -> CompositeTrait {
        let any_items: Vec<Condition> = (0..any_count)
            .map(|i| Condition::Trait {
                id: format!("trait-{}", i),
            })
            .collect();

        CompositeTrait {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 0.9,
            crit: Criticality::Suspicious,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: None,
            any: if any_count > 0 { Some(any_items) } else { None },
            needs,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        }
    }

    #[test]
    fn test_find_impossible_needs_empty() {
        let rules: Vec<CompositeTrait> = vec![];
        assert!(find_impossible_needs(&rules).is_empty());
    }

    #[test]
    fn test_find_impossible_needs_valid() {
        let rules = vec![
            make_composite_rule("test::rule1", 5, Some(3)),
            make_composite_rule("test::rule2", 3, Some(3)),
        ];
        assert!(find_impossible_needs(&rules).is_empty());
    }

    #[test]
    fn test_find_impossible_needs_violation() {
        let rules = vec![make_composite_rule("test::rule1", 2, Some(5))];
        let violations = find_impossible_needs(&rules);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "test::rule1");
        assert_eq!(violations[0].1, 5); // needs
        assert_eq!(violations[0].2, 2); // any length
    }

    // ==================== Impossible Size Constraints Tests ====================

    fn make_trait_with_size(id: &str, size_min: Option<usize>, size_max: Option<usize>) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 0.9,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min,
            size_max,
            r#if: Condition::String {
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
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
        }
    }

    #[test]
    fn test_find_impossible_size_constraints_empty() {
        let traits: Vec<TraitDefinition> = vec![];
        let rules: Vec<CompositeTrait> = vec![];
        assert!(find_impossible_size_constraints(&traits, &rules).is_empty());
    }

    #[test]
    fn test_find_impossible_size_constraints_valid() {
        let traits = vec![
            make_trait_with_size("test::t1", Some(100), Some(1000)),
            make_trait_with_size("test::t2", Some(100), None),
            make_trait_with_size("test::t3", None, Some(1000)),
        ];
        let rules: Vec<CompositeTrait> = vec![];
        assert!(find_impossible_size_constraints(&traits, &rules).is_empty());
    }

    #[test]
    fn test_find_impossible_size_constraints_violation() {
        let traits = vec![make_trait_with_size("test::t1", Some(1000), Some(100))];
        let rules: Vec<CompositeTrait> = vec![];
        let violations = find_impossible_size_constraints(&traits, &rules);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "test::t1");
        assert_eq!(violations[0].1, 1000); // min
        assert_eq!(violations[0].2, 100); // max
    }

    // ==================== Impossible Count Constraints Tests ====================

    fn make_trait_with_count(id: &str, count_min: usize, count_max: Option<usize>) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 0.9,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            r#if: Condition::String {
                exact: None,
                substr: Some("test".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                count_min,
                count_max,
                per_kb_min: None,
                per_kb_max: None,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
        }
    }

    #[test]
    fn test_find_impossible_count_constraints_empty() {
        let traits: Vec<TraitDefinition> = vec![];
        assert!(find_impossible_count_constraints(&traits).is_empty());
    }

    #[test]
    fn test_find_impossible_count_constraints_valid() {
        let traits = vec![
            make_trait_with_count("test::t1", 1, Some(10)),
            make_trait_with_count("test::t2", 5, Some(5)), // min == max is valid
            make_trait_with_count("test::t3", 1, None),
        ];
        assert!(find_impossible_count_constraints(&traits).is_empty());
    }

    #[test]
    fn test_find_impossible_count_constraints_violation() {
        let traits = vec![make_trait_with_count("test::t1", 10, Some(5))];
        let violations = find_impossible_count_constraints(&traits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "test::t1");
        assert_eq!(violations[0].1, 10); // min
        assert_eq!(violations[0].2, 5); // max
    }

    // ==================== Empty Condition Clauses Tests ====================

    #[test]
    fn test_find_empty_condition_clauses_empty() {
        let rules: Vec<CompositeTrait> = vec![];
        assert!(find_empty_condition_clauses(&rules).is_empty());
    }

    #[test]
    fn test_find_empty_condition_clauses_valid() {
        let rules = vec![make_composite_rule("test::rule", 3, Some(2))];
        assert!(find_empty_condition_clauses(&rules).is_empty());
    }

    #[test]
    fn test_find_empty_condition_clauses_empty_any() {
        let mut rule = make_composite_rule("test::rule", 0, None);
        rule.any = Some(vec![]); // Explicitly empty
        let violations = find_empty_condition_clauses(&[rule]);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1, "any");
    }

    // ==================== Missing Search Patterns Tests ====================

    fn make_trait_no_pattern(id: &str) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 0.9,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            r#if: Condition::String {
                exact: None,
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
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
        }
    }

    #[test]
    fn test_find_missing_search_patterns_empty() {
        let traits: Vec<TraitDefinition> = vec![];
        assert!(find_missing_search_patterns(&traits).is_empty());
    }

    #[test]
    fn test_find_missing_search_patterns_valid() {
        let traits = vec![
            make_string_trait("test::t1", "eval", Criticality::Notable),
            make_regex_trait("test::t2", r"foo.*bar"),
        ];
        assert!(find_missing_search_patterns(&traits).is_empty());
    }

    #[test]
    fn test_find_missing_search_patterns_violation() {
        let traits = vec![make_trait_no_pattern("test::empty")];
        let violations = find_missing_search_patterns(&traits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0], "test::empty");
    }

    // ==================== Redundant Needs One Tests ====================

    #[test]
    fn test_find_redundant_needs_one_empty() {
        let rules: Vec<CompositeTrait> = vec![];
        assert!(find_redundant_needs_one(&rules).is_empty());
    }

    #[test]
    fn test_find_redundant_needs_one_not_redundant() {
        // needs: 2 is not redundant
        let rules = vec![make_composite_rule("test::rule", 3, Some(2))];
        assert!(find_redundant_needs_one(&rules).is_empty());
    }

    #[test]
    fn test_find_redundant_needs_one_violation() {
        // needs: 1 with only any: is redundant
        let rules = vec![make_composite_rule("test::rule", 3, Some(1))];
        let violations = find_redundant_needs_one(&rules);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0], "test::rule");
    }

    #[test]
    fn test_find_redundant_needs_one_with_all_not_redundant() {
        // needs: 1 with both all: and any: is not flagged (different behavior)
        let mut rule = make_composite_rule("test::rule", 3, Some(1));
        rule.all = Some(vec![Condition::Trait {
            id: "other".to_string(),
        }]);
        let rules = vec![rule];
        assert!(find_redundant_needs_one(&rules).is_empty());
    }

    // ==================== Taxonomy Validation Tests ====================

    #[test]
    fn test_find_banned_directory_segments_empty() {
        let dirs: Vec<String> = vec![];
        assert!(find_banned_directory_segments(&dirs).is_empty());
    }

    #[test]
    fn test_find_banned_directory_segments_valid() {
        let dirs = vec![
            "cap/comm/http/client".to_string(),
            "obj/creds/browser/chromium".to_string(),
        ];
        assert!(find_banned_directory_segments(&dirs).is_empty());
    }

    #[test]
    fn test_find_banned_directory_segments_generic() {
        let dirs = vec!["cap/exec/generic/shell".to_string()];
        let violations = find_banned_directory_segments(&dirs);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1, "generic");
    }

    #[test]
    fn test_find_banned_directory_segments_method() {
        let dirs = vec!["obj/c2/reverse-shell/method".to_string()];
        let violations = find_banned_directory_segments(&dirs);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1, "method");
    }

    #[test]
    fn test_find_banned_directory_segments_misc() {
        let dirs = vec!["cap/misc/utils".to_string()];
        let violations = find_banned_directory_segments(&dirs);
        assert_eq!(violations.len(), 1);
        // First banned segment found
        assert!(violations[0].1 == "misc" || violations[0].1 == "utils");
    }

    #[test]
    fn test_find_duplicate_words_in_path_empty() {
        let dirs: Vec<String> = vec![];
        assert!(find_duplicate_words_in_path(&dirs).is_empty());
    }

    #[test]
    fn test_find_duplicate_words_in_path_valid() {
        let dirs = vec![
            "cap/comm/http/client".to_string(),
            "obj/anti-analysis/vm-detect".to_string(),
        ];
        assert!(find_duplicate_words_in_path(&dirs).is_empty());
    }

    #[test]
    fn test_find_duplicate_words_in_path_exact_duplicate() {
        // "beacon" appears twice - once in dir name, once in segment
        let dirs = vec!["obj/beacon/beacon-http".to_string()];
        let violations = find_duplicate_words_in_path(&dirs);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_find_duplicate_words_in_path_stem_duplicate() {
        let dirs = vec!["obj/anti-analysis/analysis".to_string()];
        let violations = find_duplicate_words_in_path(&dirs);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_find_duplicate_words_in_path_exec_execute() {
        let dirs = vec!["cap/exec/execute".to_string()];
        let violations = find_duplicate_words_in_path(&dirs);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_find_parent_duplicate_segments_empty() {
        let dirs: Vec<String> = vec![];
        assert!(find_parent_duplicate_segments(&dirs).is_empty());
    }

    #[test]
    fn test_find_parent_duplicate_segments_valid() {
        let dirs = vec![
            "cap/exec/shell".to_string(),
            "obj/creds/browser".to_string(),
        ];
        assert!(find_parent_duplicate_segments(&dirs).is_empty());
    }

    #[test]
    fn test_find_parent_duplicate_segments_exact() {
        let dirs = vec!["cap/exec/exec".to_string()];
        let violations = find_parent_duplicate_segments(&dirs);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1, "exec");
    }

    #[test]
    fn test_find_parent_duplicate_segments_plural() {
        let dirs = vec!["obj/creds/cred".to_string()];
        let violations = find_parent_duplicate_segments(&dirs);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_find_oversized_trait_directories_empty() {
        let traits: Vec<TraitDefinition> = vec![];
        assert!(find_oversized_trait_directories(&traits).is_empty());
    }

    #[test]
    fn test_find_oversized_trait_directories_under_limit() {
        // Create 5 traits in same directory (under 30 limit)
        let traits: Vec<TraitDefinition> = (0..5)
            .map(|i| {
                let mut t = make_string_trait(
                    &format!("cap/test/dir::trait-{}", i),
                    "test",
                    Criticality::Notable,
                );
                t.id = format!("cap/test/dir::trait-{}", i);
                t
            })
            .collect();
        assert!(find_oversized_trait_directories(&traits).is_empty());
    }

    #[test]
    fn test_find_oversized_trait_directories_over_limit() {
        // Create 35 traits in same directory (over 30 limit)
        let traits: Vec<TraitDefinition> = (0..35)
            .map(|i| {
                let mut t = make_string_trait(
                    &format!("cap/test/oversized::trait-{}", i),
                    "test",
                    Criticality::Notable,
                );
                t.id = format!("cap/test/oversized::trait-{}", i);
                t
            })
            .collect();
        let violations = find_oversized_trait_directories(&traits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "cap/test/oversized");
        assert_eq!(violations[0].1, 35);
    }

    #[test]
    fn test_find_oversized_trait_directories_multiple_dirs() {
        // 35 in one dir (violation), 10 in another (ok)
        let mut traits: Vec<TraitDefinition> = (0..35)
            .map(|i| {
                let mut t = make_string_trait(
                    &format!("cap/test/big::trait-{}", i),
                    "test",
                    Criticality::Notable,
                );
                t.id = format!("cap/test/big::trait-{}", i);
                t
            })
            .collect();

        for i in 0..10 {
            let mut t = make_string_trait(
                &format!("cap/test/small::trait-{}", i),
                "test",
                Criticality::Notable,
            );
            t.id = format!("cap/test/small::trait-{}", i);
            traits.push(t);
        }

        let violations = find_oversized_trait_directories(&traits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "cap/test/big");
    }

    // ==================== Cap/Obj Violation Tests ====================

    #[test]
    fn test_find_cap_obj_violations_empty() {
        let traits: Vec<TraitDefinition> = vec![];
        let composites: Vec<CompositeTrait> = vec![];
        let sources = HashMap::new();
        assert!(find_cap_obj_violations(&traits, &composites, &sources).is_empty());
    }

    #[test]
    fn test_find_cap_obj_violations_no_violations() {
        // Cap rule referencing another cap rule is OK
        let rule = CompositeTrait {
            id: "cap/test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: Some(vec![Condition::Trait {
                id: "cap/other::trait1".to_string(),
            }]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let sources = HashMap::new();
        assert!(find_cap_obj_violations(&traits, &composites, &sources).is_empty());
    }

    #[test]
    fn test_find_cap_obj_violations_cap_references_obj() {
        // Cap rule referencing an obj rule is a VIOLATION
        let rule = CompositeTrait {
            id: "cap/test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: Some(vec![Condition::Trait {
                id: "obj/c2/backdoor::trait1".to_string(),
            }]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let mut sources = HashMap::new();
        sources.insert("cap/test::rule".to_string(), "test.yaml".to_string());

        let violations = find_cap_obj_violations(&traits, &composites, &sources);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "cap/test::rule");
        assert_eq!(violations[0].1, "obj/c2/backdoor::trait1");
    }

    #[test]
    fn test_find_cap_obj_violations_obj_references_cap_ok() {
        // Obj rule referencing a cap rule is OK (objectives can use capabilities)
        let rule = CompositeTrait {
            id: "obj/test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: Some(vec![Condition::Trait {
                id: "cap/exec/shell::exec".to_string(),
            }]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let sources = HashMap::new();
        assert!(find_cap_obj_violations(&traits, &composites, &sources).is_empty());
    }

    #[test]
    fn test_find_cap_obj_violations_known_references_obj_ok() {
        // Known rule referencing an obj rule is OK
        let rule = CompositeTrait {
            id: "known/malware/test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: Some(vec![Condition::Trait {
                id: "obj/c2/backdoor::trait1".to_string(),
            }]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let sources = HashMap::new();
        assert!(find_cap_obj_violations(&traits, &composites, &sources).is_empty());
    }

    #[test]
    fn test_find_cap_obj_violations_multiple_violations() {
        // Multiple references to obj in a single cap rule
        let rule = CompositeTrait {
            id: "cap/test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: Some(vec![Condition::Trait {
                id: "obj/c2/backdoor::trait1".to_string(),
            }]),
            any: Some(vec![Condition::Trait {
                id: "obj/exfil/data::trait2".to_string(),
            }]),
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let mut sources = HashMap::new();
        sources.insert("cap/test::rule".to_string(), "test.yaml".to_string());

        let violations = find_cap_obj_violations(&traits, &composites, &sources);
        assert_eq!(violations.len(), 2);
    }

    // ==================== Hostile Cap Rules Tests ====================

    #[test]
    fn test_find_hostile_cap_rules_empty() {
        let traits: Vec<TraitDefinition> = vec![];
        let composites: Vec<CompositeTrait> = vec![];
        let sources = HashMap::new();
        assert!(find_hostile_cap_rules(&traits, &composites, &sources).is_empty());
    }

    #[test]
    fn test_find_hostile_cap_rules_no_violations() {
        // Cap rule with suspicious criticality is OK
        let rule = CompositeTrait {
            id: "cap/test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Suspicious,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: None,
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let sources = HashMap::new();
        assert!(find_hostile_cap_rules(&traits, &composites, &sources).is_empty());
    }

    #[test]
    fn test_find_hostile_cap_rules_violation() {
        // Cap rule with hostile criticality is a VIOLATION
        let rule = CompositeTrait {
            id: "cap/test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Hostile,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: None,
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let mut sources = HashMap::new();
        sources.insert("cap/test::rule".to_string(), "test.yaml".to_string());

        let violations = find_hostile_cap_rules(&traits, &composites, &sources);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "cap/test::rule");
    }

    #[test]
    fn test_find_hostile_cap_rules_obj_ok() {
        // Obj rule with hostile criticality is OK
        let rule = CompositeTrait {
            id: "obj/c2/backdoor::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Hostile,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: None,
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let sources = HashMap::new();
        assert!(find_hostile_cap_rules(&traits, &composites, &sources).is_empty());
    }

    #[test]
    fn test_find_hostile_cap_rules_known_ok() {
        // Known rule with hostile criticality is OK
        let rule = CompositeTrait {
            id: "known/malware/test::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Hostile,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            size_min: None,
            size_max: None,
            all: None,
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let sources = HashMap::new();
        assert!(find_hostile_cap_rules(&traits, &composites, &sources).is_empty());
    }

    #[test]
    fn test_find_hostile_cap_rules_trait_violation() {
        // Cap trait with hostile criticality is a VIOLATION
        let mut trait_def = make_string_trait(
            "cap/test::trait",
            "test",
            Criticality::Hostile,
        );
        trait_def.id = "cap/test::trait".to_string();

        let traits = vec![trait_def];
        let composites: Vec<CompositeTrait> = vec![];
        let mut sources = HashMap::new();
        sources.insert("cap/test::trait".to_string(), "test.yaml".to_string());

        let violations = find_hostile_cap_rules(&traits, &composites, &sources);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "cap/test::trait");
    }

    // ==================== File Type Overlap Tests ====================

    #[test]
    fn test_file_types_overlap_both_all() {
        let types1 = vec![RuleFileType::All];
        let types2 = vec![RuleFileType::Python];
        assert!(file_types_overlap(&types1, &types2));
    }

    #[test]
    fn test_file_types_overlap_one_all() {
        let types1 = vec![RuleFileType::Python];
        let types2 = vec![RuleFileType::All];
        assert!(file_types_overlap(&types1, &types2));
    }

    #[test]
    fn test_file_types_overlap_matching_concrete() {
        let types1 = vec![RuleFileType::Python, RuleFileType::JavaScript];
        let types2 = vec![RuleFileType::Python, RuleFileType::Ruby];
        assert!(file_types_overlap(&types1, &types2));
    }

    #[test]
    fn test_file_types_overlap_no_match() {
        let types1 = vec![RuleFileType::Python];
        let types2 = vec![RuleFileType::JavaScript];
        assert!(!file_types_overlap(&types1, &types2));
    }

    // ==================== Regex Pattern Matching Tests ====================

    #[test]
    fn test_regex_could_match_literal_direct_match() {
        assert!(regex_could_match_literal("eval", "eval"));
    }

    #[test]
    fn test_regex_could_match_literal_with_anchors() {
        assert!(regex_could_match_literal("^eval$", "eval"));
    }

    #[test]
    fn test_regex_could_match_literal_escaped() {
        assert!(regex_could_match_literal(r"eval\(", "eval("));
    }

    #[test]
    fn test_regex_could_match_literal_no_match() {
        assert!(!regex_could_match_literal("execve", "eval"));
    }

    #[test]
    fn test_regex_could_match_literal_partial() {
        assert!(regex_could_match_literal("eval.*args", "eval"));
    }

    #[test]
    fn test_regex_could_match_literal_optional_char() {
        // The regex "c?mod" matches "chmod" and "cmod"
        assert!(regex_could_match_literal("c?mod", "chmod"));
        assert!(regex_could_match_literal("c?mod", "cmod"));
    }

    #[test]
    fn test_regex_could_match_literal_alternation() {
        // The regex "eval|exec" matches both "eval" and "exec"
        assert!(regex_could_match_literal("eval|exec", "eval"));
        assert!(regex_could_match_literal("eval|exec", "exec"));
    }

    #[test]
    fn test_regex_could_match_literal_no_match_different() {
        // The regex "socket" does not match "connect"
        assert!(!regex_could_match_literal("socket", "connect"));
    }

    // ==================== Regex Overlap Validation Tests ====================

    #[test]
    fn test_validate_regex_overlap_detects_overlap() {
        // Create a substr trait for "eval"
        let trait1 = make_string_trait("test::substr_eval", "eval", Criticality::Hostile);

        // Create a regex trait that contains "eval"
        let mut trait2 = make_string_trait("test::regex_eval", "", Criticality::Hostile);
        trait2.r#if = Condition::String {
            exact: None,
            substr: None,
            regex: Some("eval\\(".to_string()),
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            count_min: 1,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };

        let traits = vec![trait1, trait2];
        let mut warnings = Vec::new();
        validate_regex_overlap_with_literal(&traits, &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("test::regex_eval"));
        assert!(warnings[0].contains("test::substr_eval"));
        assert!(warnings[0].contains("Ambiguous regex overlap"));
    }

    #[test]
    fn test_validate_regex_overlap_different_criticality() {
        // Create a substr trait with Hostile criticality
        let trait1 = make_string_trait("test::substr_eval", "eval", Criticality::Hostile);

        // Create a regex trait with Suspicious criticality (different)
        let mut trait2 = make_string_trait("test::regex_eval", "", Criticality::Suspicious);
        trait2.r#if = Condition::String {
            exact: None,
            substr: None,
            regex: Some("eval\\(".to_string()),
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            count_min: 1,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };

        let traits = vec![trait1, trait2];
        let mut warnings = Vec::new();
        validate_regex_overlap_with_literal(&traits, &mut warnings);

        // Should NOT warn because criticality is different
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_validate_regex_overlap_different_file_types() {
        // Create a substr trait for Python
        let mut trait1 = make_string_trait("test::substr_eval", "eval", Criticality::Hostile);
        trait1.r#for = vec![RuleFileType::Python];

        // Create a regex trait for JavaScript (different file type)
        let mut trait2 = make_string_trait("test::regex_eval", "", Criticality::Hostile);
        trait2.r#for = vec![RuleFileType::JavaScript];
        trait2.r#if = Condition::String {
            exact: None,
            substr: None,
            regex: Some("eval\\(".to_string()),
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            count_min: 1,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };

        let traits = vec![trait1, trait2];
        let mut warnings = Vec::new();
        validate_regex_overlap_with_literal(&traits, &mut warnings);

        // Should NOT warn because file types don't overlap
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_validate_regex_overlap_with_exact_match() {
        // Create an exact match trait
        let mut trait1 = make_string_trait("test::exact_socket", "", Criticality::Hostile);
        trait1.r#if = Condition::String {
            exact: Some("socket".to_string()),
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
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };

        // Create a regex trait that contains "socket"
        let mut trait2 = make_string_trait("test::regex_socket", "", Criticality::Hostile);
        trait2.r#if = Condition::String {
            exact: None,
            substr: None,
            regex: Some("^socket$".to_string()),
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            count_min: 1,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };

        let traits = vec![trait1, trait2];
        let mut warnings = Vec::new();
        validate_regex_overlap_with_literal(&traits, &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Ambiguous regex overlap"));
    }

    #[test]
    fn test_validate_regex_overlap_symbol_conditions() {
        // Create a substr Symbol trait
        let mut trait1 = make_string_trait("test::substr_connect", "", Criticality::Hostile);
        trait1.r#if = Condition::Symbol {
            exact: None,
            substr: Some("connect".to_string()),
            regex: None,
            platforms: None,
            compiled_regex: None,
        };

        // Create a regex Symbol trait
        let mut trait2 = make_string_trait("test::regex_connect", "", Criticality::Hostile);
        trait2.r#if = Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("connect.*".to_string()),
            platforms: None,
            compiled_regex: None,
        };

        let traits = vec![trait1, trait2];
        let mut warnings = Vec::new();
        validate_regex_overlap_with_literal(&traits, &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("test::regex_connect"));
        assert!(warnings[0].contains("test::substr_connect"));
    }

    #[test]
    fn test_validate_regex_overlap_inert_traits() {
        // Create a substr trait with Inert criticality
        let trait1 = make_string_trait("test::substr_buffer", "Buffer.from", Criticality::Inert);

        // Create a regex trait with Inert criticality that overlaps
        let mut trait2 = make_string_trait("test::regex_buffer", "", Criticality::Inert);
        trait2.r#if = Condition::String {
            exact: None,
            substr: None,
            regex: Some("Buffer\\.from\\(".to_string()),
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            count_min: 1,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };

        let traits = vec![trait1, trait2];
        let mut warnings = Vec::new();
        validate_regex_overlap_with_literal(&traits, &mut warnings);

        // Should detect overlap even for Inert traits
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("test::regex_buffer"));
        assert!(warnings[0].contains("test::substr_buffer"));
        assert!(warnings[0].contains("Ambiguous regex overlap"));
    }

    #[test]
    fn test_validate_regex_overlap_notable_traits() {
        // Create a substr trait with Notable criticality
        let trait1 = make_string_trait("test::substr_chmod", "chmod", Criticality::Notable);

        // Create a regex trait with Notable criticality that overlaps
        let mut trait2 = make_string_trait("test::regex_chmod", "", Criticality::Notable);
        trait2.r#if = Condition::String {
            exact: None,
            substr: None,
            regex: Some("chmod\\s+\\d{3,4}".to_string()),
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            count_min: 1,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };

        let traits = vec![trait1, trait2];
        let mut warnings = Vec::new();
        validate_regex_overlap_with_literal(&traits, &mut warnings);

        // Should detect overlap even for Notable traits
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("test::regex_chmod"));
        assert!(warnings[0].contains("test::substr_chmod"));
        assert!(warnings[0].contains("Ambiguous regex overlap"));
    }

    #[test]
    fn test_validate_regex_overlap_exact_vs_optional_regex() {
        // Create an exact match trait for "chmod"
        let mut trait1 = make_string_trait("test::exact_chmod", "", Criticality::Notable);
        trait1.r#if = Condition::String {
            exact: Some("chmod".to_string()),
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
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };

        // Create a regex trait with optional character pattern "c?mod" that matches "chmod"
        let mut trait2 = make_string_trait("test::regex_optional_chmod", "", Criticality::Notable);
        trait2.r#if = Condition::String {
            exact: None,
            substr: None,
            regex: Some("c?mod".to_string()),
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            count_min: 1,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };

        let traits = vec![trait1, trait2];
        let mut warnings = Vec::new();
        validate_regex_overlap_with_literal(&traits, &mut warnings);

        // Should detect overlap: regex "c?mod" can match exact "chmod"
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("test::regex_optional_chmod"));
        assert!(warnings[0].contains("test::exact_chmod"));
        assert!(warnings[0].contains("Ambiguous regex overlap"));
        assert!(warnings[0].contains("exact: 'chmod'"));
    }
}
