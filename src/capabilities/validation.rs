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
    let mut dir_refs: HashMap<String, Vec<String>> = HashMap::new();

    for cond in any_conditions {
        if let Condition::Trait { id } = cond {
            // Extract directory from trait ID
            let trait_dir = if let Some(idx) = id.find("::") {
                &id[..idx]
            } else if let Some(idx) = id.rfind('/') {
                &id[..idx]
            } else {
                continue; // Short name, skip
            };

            // Only flag external directories (different from rule's directory)
            // Skip meta/ paths since those are auto-generated and can't use directory notation
            if trait_dir != rule_dir && !trait_dir.starts_with("meta/") {
                dir_refs
                    .entry(trait_dir.to_string())
                    .or_default()
                    .push(id.clone());
            }
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
