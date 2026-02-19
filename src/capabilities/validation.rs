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
use std::sync::OnceLock;

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
        },
        Condition::String {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            exclude_patterns,
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
            // count_min, count_max, per_kb_min, per_kb_max now scored at trait level
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
        },
        Condition::Raw {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
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
            // count_min, count_max, per_kb_min, per_kb_max now scored at trait level
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
        },
        Condition::Structure {
            feature,
            min_sections,
        } => {
            score += score_string_value(feature);
            score += score_presence(min_sections.as_ref());
        },
        Condition::ExportsCount { min, max } => {
            score += score_presence(min.as_ref());
            score += score_presence(max.as_ref());
        },
        Condition::Trait { id } => {
            score += score_string_value(id);
        },
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
        },
        Condition::Yara { source, .. } => {
            score += score_regex_value(source);
        },
        Condition::Syscall { name, number, arch } => {
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
            // count_min, count_max, per_kb_min, per_kb_max now scored at trait level
        },
        Condition::SectionRatio {
            section,
            compare_to,
            min,
            max,
        } => {
            score += score_regex_value(section);
            score += score_regex_value(compare_to);
            score += score_presence(min.as_ref());
            score += score_presence(max.as_ref());
        },
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
        },
        Condition::StringCount {
            min,
            max,
            min_length,
            ..
        } => {
            score += score_presence(min.as_ref());
            score += score_presence(max.as_ref());
            score += score_presence(min_length.as_ref());
        },
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
        },
        Condition::Hex {
            pattern,
            offset,
            offset_range,
            section,
            section_offset,
            section_offset_range,
        } => {
            score += score_string_value(pattern);
            score += score_presence(offset.as_ref());
            score += score_presence(offset_range.as_ref());
            // count_min, count_max, per_kb_min, per_kb_max now scored at trait level
            score += section.as_deref().map(score_string_value).unwrap_or(0.0);
            score += score_presence(section_offset.as_ref());
            score += score_presence(section_offset_range.as_ref());
        },
        Condition::Section {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            length_min,
            length_max,
            entropy_min,
            entropy_max,
        } => {
            score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
            score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
            score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
            score += word.as_deref().map(score_word_value).unwrap_or(0.0);
            if *case_insensitive {
                score += PARAM_UNIT;
            }
            if length_min.is_some() {
                score += PARAM_UNIT;
            }
            if length_max.is_some() {
                score += PARAM_UNIT;
            }
            if entropy_min.is_some() {
                score += PARAM_UNIT;
            }
            if entropy_max.is_some() {
                score += PARAM_UNIT;
            }
        },
        Condition::Encoded {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
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
            // count_min, count_max, per_kb_min, per_kb_max now scored at trait level
            score += section.as_deref().map(score_string_value).unwrap_or(0.0);
            score += score_presence(offset.as_ref());
            score += score_presence(offset_range.as_ref());
            score += score_presence(section_offset.as_ref());
            score += score_presence(section_offset_range.as_ref());
            if *case_insensitive {
                score *= CASE_INSENSITIVE_MULTIPLIER;
            }
        },
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
        },
    }

    score
}

fn score_not_exceptions(exceptions: &[crate::composite_rules::condition::NotException]) -> f32 {
    let mut score = 0.0f32;
    for exception in exceptions {
        match exception {
            crate::composite_rules::condition::NotException::Shorthand(value) => {
                score += score_string_value(value);
            },
            crate::composite_rules::condition::NotException::Structured {
                exact,
                substr,
                regex,
            } => {
                score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
                score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
                score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
            },
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
pub(crate) fn calculate_trait_precision(trait_def: &TraitDefinition) -> f32 {
    let mut precision = BASE_TRAIT_PRECISION;

    precision += score_presence(trait_def.r#if.size_min.as_ref());
    precision += score_presence(trait_def.r#if.size_max.as_ref());

    for platform in trait_def.platforms.iter().filter(|p| **p != Platform::All) {
        precision += score_string_value(&format!("{:?}", platform).to_lowercase());
    }

    for file_type in trait_def.r#for.iter().filter(|f| !matches!(f, RuleFileType::All)) {
        precision += score_string_value(&format!("{:?}", file_type).to_lowercase());
    }

    precision += score_condition(&trait_def.r#if.condition);

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
pub(crate) fn calculate_composite_precision(
    rule_id: &str,
    composite_lookup: &HashMap<&str, &CompositeTrait>,
    trait_lookup: &HashMap<&str, &TraitDefinition>,
    cache: &mut HashMap<String, f32>,
    visiting: &mut HashSet<String>,
) -> f32 {
    if let Some(&precision) = cache.get(rule_id) {
        return precision;
    }

    // Debug output controlled by DISSECT_DEBUG environment variable
    let debug = std::env::var("DISSECT_DEBUG").is_ok();

    // Detect cycles
    if !visiting.insert(rule_id.to_string()) {
        return BASE_TRAIT_PRECISION;
    }

    // Try to find as composite rule first
    // Support both new format (dir::name) and legacy format (dir/name)
    let rule = composite_lookup.get(rule_id).copied().or_else(|| {
        if rule_id.contains("::") {
            let legacy_id = rule_id.replace("::", "/");
            composite_lookup.get(legacy_id.as_str()).copied()
        } else if rule_id.contains('/') {
            if let Some(idx) = rule_id.rfind('/') {
                let new_id = format!("{}::{}", &rule_id[..idx], &rule_id[idx + 1..]);
                composite_lookup.get(new_id.as_str()).copied()
            } else {
                None
            }
        } else {
            None
        }
    });
    if let Some(rule) = rule {
        let mut precision = 0.0f32;

        for file_type in rule.r#for.iter().filter(|f| !matches!(f, RuleFileType::All)) {
            let score = score_string_value(&format!("{:?}", file_type).to_lowercase());
            precision += score;
            if debug {
                eprintln!("  [DEBUG] {} file_type score: {:.2}", rule_id, score);
            }
        }

        // `all` clause: recursively sum all elements
        if let Some(ref conditions) = rule.all {
            for cond in conditions {
                let _before = precision;
                match cond {
                    Condition::Trait { id } => {
                        // Recursively calculate trait/composite precision
                        let score = calculate_composite_precision(
                            id,
                            composite_lookup,
                            trait_lookup,
                            cache,
                            visiting,
                        );
                        precision += score;
                        if debug {
                            eprintln!(
                                "  [DEBUG] {} all trait '{}' score: {:.2}",
                                rule_id, id, score
                            );
                        }
                    },
                    _ => {
                        let score = score_condition(cond);
                        precision += score;
                        if debug {
                            eprintln!("  [DEBUG] {} all condition score: {:.2}", rule_id, score);
                        }
                    },
                }
            }
        }

        // `any` clause: sum the N weakest required branches
        if let Some(ref conditions) = rule.any {
            let branch_scores: Vec<f32> = conditions
                .iter()
                .enumerate()
                .map(|(i, cond)| {
                    let score = match cond {
                        Condition::Trait { id } => {
                            let s = calculate_composite_precision(
                                id,
                                composite_lookup,
                                trait_lookup,
                                cache,
                                visiting,
                            );
                            if debug {
                                eprintln!(
                                    "  [DEBUG] {} any[{}] trait '{}' score: {:.2}",
                                    rule_id, i, id, s
                                );
                            }
                            s
                        },
                        _ => {
                            let s = score_condition(cond);
                            if debug {
                                eprintln!(
                                    "  [DEBUG] {} any[{}] condition score: {:.2}",
                                    rule_id, i, s
                                );
                            }
                            s
                        },
                    };
                    score
                })
                .collect();

            if !branch_scores.is_empty() {
                let required = rule.needs.unwrap_or(1).max(1);
                if debug {
                    eprintln!(
                        "  [DEBUG] {} any clause: needs={}, scores={:?}",
                        rule_id, required, branch_scores
                    );
                }
                let weakest_sum = sum_weakest(branch_scores, required);
                if debug {
                    eprintln!(
                        "  [DEBUG] {} any clause: sum_weakest={:.2}",
                        rule_id, weakest_sum
                    );
                }
                precision += weakest_sum;
            }
        }

        if let Some(ref none_conds) = rule.none {
            precision += PARAM_UNIT;
            let scores: Vec<f32> = none_conds
                .iter()
                .map(|cond| match cond {
                    Condition::Trait { id } => calculate_composite_precision(
                        id,
                        composite_lookup,
                        trait_lookup,
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
                        composite_lookup,
                        trait_lookup,
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
        if debug {
            eprintln!("  [DEBUG] {} TOTAL PRECISION: {:.2}", rule_id, precision);
        }
        return precision;
    }

    // Not a composite - try to find as a trait definition
    // Support both new format (dir::name) and legacy format (dir/name)
    if debug {
        eprintln!("  [DEBUG] Looking up trait: '{}'", rule_id);
    }
    let trait_def = trait_lookup.get(rule_id).copied().or_else(|| {
        // Try converting legacy format to new format or vice versa
        if rule_id.contains("::") {
            // Reference uses new format, trait might use legacy
            let legacy_id = rule_id.replace("::", "/");
            if debug {
                eprintln!("  [DEBUG]   Trying legacy conversion: '{}'", legacy_id);
            }
            trait_lookup.get(legacy_id.as_str()).copied()
        } else if rule_id.contains('/') {
            // Reference uses legacy format, trait might use new format
            // Convert last '/' to '::'
            if let Some(idx) = rule_id.rfind('/') {
                let new_id = format!("{}::{}", &rule_id[..idx], &rule_id[idx + 1..]);
                if debug {
                    eprintln!("  [DEBUG]   Trying new format conversion: '{}'", new_id);
                }
                trait_lookup.get(new_id.as_str()).copied()
            } else {
                None
            }
        } else {
            None
        }
    });

    if let Some(trait_def) = trait_def {
        let precision = calculate_trait_precision(trait_def);
        if debug {
            eprintln!(
                "  [DEBUG]   FOUND trait '{}' with stored ID '{}', precision: {:.2}",
                rule_id, trait_def.id, precision
            );
        }
        visiting.remove(rule_id);
        cache.insert(rule_id.to_string(), precision);
        return precision;
    }

    // Not found - treat as external/unknown trait
    if debug {
        eprintln!(
            "  [DEBUG]   NOT FOUND - returning BASE_TRAIT_PRECISION: {:.2}",
            BASE_TRAIT_PRECISION
        );
        eprintln!("  [DEBUG]   Available trait IDs (first 20):");
        for (i, id) in trait_lookup.keys().take(20).enumerate() {
            eprintln!("  [DEBUG]     [{}] '{}'", i, id);
        }
    }
    visiting.remove(rule_id);
    cache.insert(rule_id.to_string(), BASE_TRAIT_PRECISION);
    BASE_TRAIT_PRECISION
}

/// Pre-calculate precision for ALL composite rules and store in their precision field.
/// This should be called once after all traits and composites are loaded,
/// before any validation. After this runs, precision will be cached and never recalculated.
pub(crate) fn precalculate_all_composite_precisions(
    composite_rules: &mut [CompositeTrait],
    trait_definitions: &[TraitDefinition],
) {
    let mut cache: HashMap<String, f32> = HashMap::new();

    // Pre-seed cache with all atomic trait precisions
    for trait_def in trait_definitions {
        if let Some(precision) = trait_def.precision {
            cache.insert(trait_def.id.clone(), precision);
        }
    }

    // Build lookup tables (immutable borrow)
    let composite_lookup: HashMap<&str, &CompositeTrait> =
        composite_rules.iter().map(|r| (r.id.as_str(), r)).collect();
    let trait_lookup: HashMap<&str, &TraitDefinition> =
        trait_definitions.iter().map(|t| (t.id.as_str(), t)).collect();

    // First pass: Calculate precisions for rules that don't have them (immutable borrow)
    let calculated_precisions: Vec<(String, f32)> = composite_rules
        .iter()
        .filter(|rule| rule.precision.is_none())
        .map(|rule| {
            let mut visiting = std::collections::HashSet::new();
            let precision = calculate_composite_precision(
                &rule.id,
                &composite_lookup,
                &trait_lookup,
                &mut cache,
                &mut visiting,
            );
            (rule.id.clone(), precision)
        })
        .collect();

    // Second pass: Store the calculated precisions (mutable borrow)
    for (rule_id, precision) in calculated_precisions {
        if let Some(rule) = composite_rules.iter_mut().find(|r| r.id == rule_id) {
            rule.precision = Some(precision);
        }
    }
}

/// Validate and downgrade composite rules that don't meet precision requirements.
///
/// - HOSTILE must have precision >= 4, else downgraded to SUSPICIOUS.
/// - SUSPICIOUS must have precision >= 2, else downgraded to NOTABLE.
///
/// IMPORTANT: Call precalculate_all_composite_precisions() first!
/// This function expects all precisions to already be calculated and stored.
pub(crate) fn validate_hostile_composite_precision(
    composite_rules: &mut [CompositeTrait],
    _trait_definitions: &[TraitDefinition],
    _warnings: &mut Vec<String>,
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
) {
    // Check HOSTILE/SUSPICIOUS rules and downgrade if needed
    for rule in composite_rules.iter_mut() {
        if !matches!(rule.crit, Criticality::Hostile | Criticality::Suspicious) {
            continue;
        }

        // Precision should already be calculated - if not, that's a bug
        let precision = rule.precision.unwrap_or_else(|| {
            eprintln!(
                "WARNING: Composite rule '{}' has no precision calculated!",
                rule.id
            );
            0.0
        });

        match rule.crit {
            Criticality::Hostile if precision < min_hostile_precision => {
                // Silently downgrade - the precision calculation handles this automatically
                rule.crit = Criticality::Suspicious;
            },
            Criticality::Suspicious if precision < min_suspicious_precision => {
                // Silently downgrade - the precision calculation handles this automatically
                rule.crit = Criticality::Notable;
            },
            _ => {},
        }
    }
}

/// Detect duplicate atomic traits and composite rules.
///
/// OPTIMIZATION STRATEGY:
/// 1. Bincode serialization (10-100x faster than Debug formatting)
/// 2. Partition-and-merge pattern (eliminates lock contention)
/// 3. u64 hash keys instead of Vec<u8> (50x faster HashMap operations)
/// 4. Removed redundant serialization (size_min/max already in r#if)
///
/// Combined: ~100-500x faster than original mutex-based implementation.
pub(crate) fn find_duplicate_traits_and_composites(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    warnings: &mut Vec<String>,
) {
    use rayon::prelude::*;

    let start = std::time::Instant::now();

    // Pass 1: Detect duplicate atomic traits using hash-based deduplication
    // OPTIMIZATION: Uses u64 hash as key (50x faster than Vec<u8> comparisons)
    if !trait_definitions.is_empty() {
        tracing::debug!(
            "Starting atomic trait duplicate detection for {} traits",
            trait_definitions.len()
        );
        let serialize_start = std::time::Instant::now();

        // Process in parallel chunks (no locks needed)
        let chunk_size = (trait_definitions.len() / rayon::current_num_threads()).max(1000);
        let trait_maps: Vec<HashMap<u64, Vec<String>>> = trait_definitions
            .par_chunks(chunk_size)
            .map(|chunk| {
                let mut local_map: HashMap<u64, Vec<String>> = HashMap::with_capacity(chunk.len());
                for t in chunk {
                    // Serialize the trait's unique characteristics
                    // Note: size_min/size_max are already inside r#if, no need to serialize separately
                    if let Ok(serialized) =
                        bincode::serialize(&(&t.r#if, &t.platforms, &t.r#for, &t.not, &t.unless))
                    {
                        // Hash the serialized data to get a u64 key (much faster HashMap operations)
                        use std::collections::hash_map::DefaultHasher;
                        use std::hash::{Hash, Hasher};

                        let mut hasher = DefaultHasher::new();
                        serialized.hash(&mut hasher);
                        let hash_key = hasher.finish();

                        local_map.entry(hash_key).or_default().push(t.id.clone());
                    }
                }
                local_map
            })
            .collect();

        tracing::debug!(
            "Atomic trait parallel hashing took {:?}",
            serialize_start.elapsed()
        );

        // Merge maps sequentially (fast since we have few chunks)
        let merge_start = std::time::Instant::now();
        let mut final_map: HashMap<u64, Vec<String>> = HashMap::new();
        for map in trait_maps {
            for (k, mut v) in map {
                final_map.entry(k).or_default().append(&mut v);
            }
        }
        tracing::debug!("Atomic trait merge took {:?}", merge_start.elapsed());

        let check_start = std::time::Instant::now();
        for (_hash, ids) in final_map {
            if ids.len() > 1 {
                warnings.push(format!(
                    "Duplicate atomic traits detected (same search parameters): {}",
                    ids.join(", ")
                ));
            }
        }
        tracing::debug!(
            "Atomic trait duplicate check took {:?}",
            check_start.elapsed()
        );
        tracing::debug!(
            "Total atomic trait processing took {:?}",
            serialize_start.elapsed()
        );
    }

    // Pass 2: Detect duplicate composite rules using hash-based deduplication
    // OPTIMIZATION: Uses u64 hash as key (50x faster than Vec<u8> comparisons)
    if !composite_rules.is_empty() {
        tracing::debug!(
            "Starting composite rule duplicate detection for {} rules",
            composite_rules.len()
        );
        let composite_start = std::time::Instant::now();

        // Process in parallel chunks (no locks needed)
        let chunk_size = (composite_rules.len() / rayon::current_num_threads()).max(1000);
        let composite_maps: Vec<HashMap<u64, Vec<String>>> = composite_rules
            .par_chunks(chunk_size)
            .map(|chunk| {
                let mut local_map: HashMap<u64, Vec<String>> = HashMap::with_capacity(chunk.len());
                for r in chunk {
                    // Skip rules with no conditions
                    if r.all.is_none() && r.any.is_none() && r.none.is_none() && r.unless.is_none()
                    {
                        continue;
                    }

                    // Serialize the rule's unique characteristics
                    if let Ok(serialized) = bincode::serialize(&(
                        &r.all,
                        &r.any,
                        &r.none,
                        &r.unless,
                        &r.needs,
                        &r.r#for,
                        &r.platforms,
                        &r.size_min,
                        &r.size_max,
                    )) {
                        // Hash the serialized data to get a u64 key
                        use std::collections::hash_map::DefaultHasher;
                        use std::hash::{Hash, Hasher};

                        let mut hasher = DefaultHasher::new();
                        serialized.hash(&mut hasher);
                        let hash_key = hasher.finish();

                        local_map.entry(hash_key).or_default().push(r.id.clone());
                    }
                }
                local_map
            })
            .collect();

        tracing::debug!(
            "Composite rule parallel hashing took {:?}",
            composite_start.elapsed()
        );

        // Merge maps sequentially
        let merge_start = std::time::Instant::now();
        let mut final_map: HashMap<u64, Vec<String>> = HashMap::new();
        for map in composite_maps {
            for (k, mut v) in map {
                final_map.entry(k).or_default().append(&mut v);
            }
        }
        tracing::debug!("Composite rule merge took {:?}", merge_start.elapsed());

        let composite_check_start = std::time::Instant::now();
        for (_hash, ids) in final_map {
            if ids.len() > 1 {
                warnings.push(format!(
                    "Duplicate composite rules detected (same conditions): {}",
                    ids.join(", ")
                ));
            }
        }
        tracing::debug!(
            "Composite rule duplicate check took {:?}",
            composite_check_start.elapsed()
        );
        tracing::debug!(
            "Total composite rule processing took {:?}",
            composite_start.elapsed()
        );
    }

    tracing::debug!("Total duplicate detection took {:?}", start.elapsed());
}

/// Information about where a pattern was found
#[derive(Debug, Clone)]
struct PatternLocation {
    trait_id: String,
    file_path: String,
    condition_type: String, // "string", "symbol", "raw"
    match_type: String,     // "exact", "substr", "word", "regex"
    original_value: String, // Original pattern before normalization
    for_types: HashSet<String>,
    count_min: Option<usize>,
    count_max: Option<usize>,
    per_kb_min: Option<f64>,
    per_kb_max: Option<f64>,
}

/// Split a regex pattern on top-level `|` only — not inside parentheses or brackets.
/// This avoids false positives from patterns like `(?:foo|bar)baz` being split into
/// `(?:foo` and `bar)baz`.
fn split_top_level_alternation(pattern: &str) -> Vec<&str> {
    let mut depth = 0i32;
    let mut in_char_class = false;
    let mut last = 0;
    let mut result = Vec::new();
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 2; // skip escaped character
                continue;
            }
            b'[' if !in_char_class => {
                in_char_class = true;
            }
            b']' if in_char_class => {
                in_char_class = false;
            }
            b'(' if !in_char_class => {
                depth += 1;
            }
            b')' if !in_char_class => {
                depth -= 1;
            }
            b'|' if !in_char_class && depth == 0 => {
                result.push(&pattern[last..i]);
                last = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    result.push(&pattern[last..]);
    result
}

/// Normalize a regex pattern by stripping anchors (^ and $)
fn normalize_regex(pattern: &str) -> String {
    let mut normalized = pattern.to_string();
    if normalized.starts_with('^') {
        normalized = normalized[1..].to_string();
    }
    if normalized.ends_with('$') && !normalized.ends_with("\\$") {
        normalized.truncate(normalized.len() - 1);
    }
    normalized
}

/// Extract all searchable patterns from a trait definition
/// Returns: Vec<(normalized_value, PatternLocation)>
fn extract_patterns(trait_def: &TraitDefinition) -> Vec<(String, PatternLocation)> {
    let mut patterns = Vec::new();

    let for_types: HashSet<String> =
        trait_def.r#for.iter().map(|ft| format!("{:?}", ft).to_lowercase()).collect();

    let file_path = trait_def.defined_in.to_string_lossy().to_string();

    // Helper to add a pattern
    let mut add_pattern = |condition_type: &str, match_type: &str, value: String| {
        let normalized = if match_type == "regex" {
            normalize_regex(&value)
        } else {
            value.clone()
        };

        patterns.push((
            normalized,
            PatternLocation {
                trait_id: trait_def.id.clone(),
                file_path: file_path.clone(),
                condition_type: condition_type.to_string(),
                match_type: match_type.to_string(),
                original_value: value,
                for_types: for_types.clone(),
                count_min: trait_def.r#if.count_min,
                count_max: trait_def.r#if.count_max,
                per_kb_min: trait_def.r#if.per_kb_min,
                per_kb_max: trait_def.r#if.per_kb_max,
            },
        ));
    };

    // Extract patterns from String, Symbol, and Raw conditions
    match &trait_def.r#if.condition {
        Condition::String {
            exact,
            substr,
            word,
            regex,
            ..
        } => {
            if let Some(v) = exact {
                add_pattern("string", "exact", v.clone());
            }
            if let Some(v) = substr {
                add_pattern("string", "substr", v.clone());
            }
            if let Some(v) = word {
                add_pattern("string", "word", v.clone());
            }
            if let Some(v) = regex {
                add_pattern("string", "regex", v.clone());
            }
        },
        Condition::Symbol {
            exact,
            substr,
            regex,
            ..
        } => {
            if let Some(v) = exact {
                add_pattern("symbol", "exact", v.clone());
            }
            if let Some(v) = substr {
                add_pattern("symbol", "substr", v.clone());
            }
            if let Some(v) = regex {
                add_pattern("symbol", "regex", v.clone());
            }
        },
        Condition::Raw {
            exact,
            substr,
            word,
            regex,
            ..
        } => {
            if let Some(v) = exact {
                add_pattern("raw", "exact", v.clone());
            }
            if let Some(v) = substr {
                add_pattern("raw", "substr", v.clone());
            }
            if let Some(v) = word {
                add_pattern("raw", "word", v.clone());
            }
            if let Some(v) = regex {
                add_pattern("raw", "regex", v.clone());
            }
        },
        _ => {}, // Skip Encoded, Yara, etc.
    }

    patterns
}

/// Check if two pattern locations have overlapping file type coverage
fn has_filetype_overlap(loc_a: &PatternLocation, loc_b: &PatternLocation) -> bool {
    // Both have no restrictions -> overlap
    if loc_a.for_types.is_empty() && loc_b.for_types.is_empty() {
        return true;
    }

    // One has no restrictions -> overlaps with everything
    if loc_a.for_types.is_empty() || loc_b.for_types.is_empty() {
        return true;
    }

    // Check intersection
    !loc_a.for_types.is_disjoint(&loc_b.for_types)
}

fn has_same_count_density_filters(loc_a: &PatternLocation, loc_b: &PatternLocation) -> bool {
    loc_a.count_min == loc_b.count_min
        && loc_a.count_max == loc_b.count_max
        && loc_a.per_kb_min == loc_b.per_kb_min
        && loc_a.per_kb_max == loc_b.per_kb_max
}

/// Detect string pattern duplicates and overlaps across trait files
/// Detect duplicate string patterns across trait files
/// Only detects exact matches of normalized patterns (regex anchors stripped)
/// Checks string, symbol, and raw condition types (not encoded)
pub(crate) fn find_string_pattern_duplicates(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();

    // Build index: normalized_pattern -> Vec<PatternLocation>
    let mut pattern_index: HashMap<String, Vec<PatternLocation>> = HashMap::new();

    for trait_def in trait_definitions {
        for (normalized, location) in extract_patterns(trait_def) {
            pattern_index.entry(normalized).or_default().push(location);
        }
    }

    // Find duplicates: same normalized pattern in multiple files with overlapping file types
    let total_patterns = pattern_index.len();
    let initial_warning_count = warnings.len();

    for (normalized_pattern, locations) in pattern_index {
        if locations.len() <= 1 {
            continue;
        }

        // Group by file
        let mut by_file: HashMap<String, Vec<&PatternLocation>> = HashMap::new();
        for loc in &locations {
            by_file.entry(loc.file_path.clone()).or_default().push(loc);
        }

        // Only warn about cross-file duplicates
        if by_file.len() <= 1 {
            continue;
        }

        // Check if any pair has overlapping file type coverage
        let mut has_overlap = false;
        'outer: for i in 0..locations.len() {
            for j in (i + 1)..locations.len() {
                if locations[i].file_path != locations[j].file_path
                    && has_filetype_overlap(&locations[i], &locations[j])
                {
                    has_overlap = true;
                    break 'outer;
                }
            }
        }

        if !has_overlap {
            continue;
        }

        // Format warning message
        let location_details: Vec<String> = locations
            .iter()
            .map(|l| {
                let for_str = if l.for_types.is_empty() {
                    "all types".to_string()
                } else {
                    let mut types: Vec<_> = l.for_types.iter().cloned().collect();
                    types.sort();
                    format!("[{}]", types.join(", "))
                };
                format!(
                    "   {}: {} ({} {}: '{}', for: {})",
                    l.file_path,
                    l.trait_id,
                    l.condition_type,
                    l.match_type,
                    l.original_value,
                    for_str
                )
            })
            .collect();

        warnings.push(format!(
            "Duplicate pattern '{}' appears in {} files with overlapping file type coverage:\n{}",
            normalized_pattern,
            by_file.len(),
            location_details.join("\n")
        ));
    }

    let duplicates_found = warnings.len() - initial_warning_count;
    tracing::debug!(
        "String pattern duplicate detection completed in {:?} ({} patterns checked, {} duplicates found)",
        start.elapsed(),
        total_patterns,
        duplicates_found
    );
}

/// Check for regex patterns with | (OR) that overlap with standalone exact/word/substr patterns.
pub(crate) fn check_regex_or_overlapping_exact(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    // First pass: collect all regex patterns with | (OR operators)
    let mut regex_patterns: Vec<(String, PatternLocation)> = Vec::new();

    for trait_def in trait_definitions {
        let patterns = extract_patterns(trait_def);
        for (_, location) in patterns {
            if location.match_type == "regex" && location.original_value.contains('|') {
                regex_patterns.push((location.original_value.clone(), location));
            }
        }
    }

    // Second pass: collect all exact/word/substr patterns
    let mut literal_patterns: HashMap<String, Vec<PatternLocation>> = HashMap::new();

    for trait_def in trait_definitions {
        let patterns = extract_patterns(trait_def);
        for (normalized, location) in patterns {
            if location.match_type != "regex" {
                literal_patterns.entry(normalized).or_default().push(location);
            }
        }
    }

    // Check each regex OR pattern against all literals
    for (regex_value, regex_loc) in regex_patterns {
        // Split the regex on top-level | only (not inside parentheses/brackets)
        let alternatives: Vec<&str> = split_top_level_alternation(&regex_value);

        let mut overlapping_literals: Vec<(String, Vec<String>)> = Vec::new();

        for alternative in alternatives {
            // Normalize the alternative (strip anchors)
            let normalized_alt = normalize_regex(alternative);

            // Check if this alternative exists as a literal pattern elsewhere
            if let Some(literal_locs) = literal_patterns.get(&normalized_alt) {
                // Only report if the literal is in a different file AND has file type overlap
                let overlapping_files: Vec<String> = literal_locs
                    .iter()
                    .filter(|loc| {
                        loc.file_path != regex_loc.file_path
                            && has_filetype_overlap(loc, &regex_loc)
                    })
                    .map(|loc| format!("{}::{}", loc.file_path, loc.trait_id))
                    .collect();

                if !overlapping_files.is_empty() {
                    overlapping_literals.push((normalized_alt, overlapping_files));
                }
            }
        }

        if !overlapping_literals.is_empty() {
            let details: Vec<String> = overlapping_literals
                .iter()
                .map(|(pattern, files)| format!("   '{}' found in: {}", pattern, files.join(", ")))
                .collect();

            warnings.push(format!(
                "Regex OR pattern overlaps with exact/word/substr patterns:\n   Regex: {} (in {}::{})\n{}",
                regex_value,
                regex_loc.file_path,
                regex_loc.trait_id,
                details.join("\n")
            ));
        }
    }

    let overlaps_found = warnings.len() - initial_warning_count;
    tracing::debug!(
        "Regex OR overlap detection completed in {:?} ({} overlaps found)",
        start.elapsed(),
        overlaps_found
    );
}

/// Check for overlapping regex patterns across traits with overlapping file type coverage.
///
/// This bans regex-to-regex overlap where alternatives are shared, which usually indicates
/// a monolithic rule layout and should be split into atomic traits.
pub(crate) fn check_overlapping_regex_patterns(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    let mut regex_locations: Vec<PatternLocation> = Vec::new();
    for trait_def in trait_definitions {
        let patterns = extract_patterns(trait_def);
        for (_, location) in patterns {
            if location.match_type == "regex" {
                regex_locations.push(location);
            }
        }
    }

    let mut seen_pairs: HashSet<(String, String)> = HashSet::new();

    for i in 0..regex_locations.len() {
        for j in (i + 1)..regex_locations.len() {
            let a = &regex_locations[i];
            let b = &regex_locations[j];

            // Skip same trait instance.
            if a.trait_id == b.trait_id && a.file_path == b.file_path {
                continue;
            }

            // Must overlap in filetype scope to be a real conflict.
            if !has_filetype_overlap(a, b) {
                continue;
            }

            // Different count/per-kb thresholds are intentionally layered evidence.
            if !has_same_count_density_filters(a, b) {
                continue;
            }

            let shared = shared_top_level_regex_alternatives(&a.original_value, &b.original_value);
            if shared.is_empty() {
                continue;
            }

            let key_a = format!("{}::{}", a.file_path, a.trait_id);
            let key_b = format!("{}::{}", b.file_path, b.trait_id);
            let key = if key_a <= key_b {
                (key_a.clone(), key_b.clone())
            } else {
                (key_b.clone(), key_a.clone())
            };

            if !seen_pairs.insert(key) {
                continue;
            }

            let mut shared_preview = shared;
            shared_preview.sort();
            if shared_preview.len() > 5 {
                shared_preview.truncate(5);
            }

            warnings.push(format!(
                "Overlapping regex patterns with same file type coverage:\n   {}::{} => {}\n   {}::{} => {}\n   shared alternatives: {}",
                a.file_path,
                a.trait_id,
                a.original_value,
                b.file_path,
                b.trait_id,
                b.original_value,
                shared_preview.join(", ")
            ));
        }
    }

    let overlaps_found = warnings.len() - initial_warning_count;
    tracing::debug!(
        "Regex-to-regex overlap detection completed in {:?} ({} overlaps found)",
        start.elapsed(),
        overlaps_found
    );
}

fn shared_top_level_regex_alternatives(regex_a: &str, regex_b: &str) -> Vec<String> {
    let mut set_a: HashSet<String> = split_top_level_alternation(regex_a)
        .into_iter()
        .map(|s| normalize_regex(s.trim()))
        .filter(|s| !s.is_empty())
        .collect();

    let set_b: HashSet<String> = split_top_level_alternation(regex_b)
        .into_iter()
        .map(|s| normalize_regex(s.trim()))
        .filter(|s| !s.is_empty())
        .collect();

    // If no top-level alternatives exist, still treat exact-normalized equality as overlap.
    if set_a.is_empty() && set_b.is_empty() {
        let na = normalize_regex(regex_a.trim());
        let nb = normalize_regex(regex_b.trim());
        if !na.is_empty() && na == nb {
            return vec![na];
        }
        return Vec::new();
    }

    set_a.retain(|alt| set_b.contains(alt));
    set_a.into_iter().collect()
}

/// Check for regex patterns that are just ^word$ and should use exact instead
/// Regex should only be used when there are actual variations or special characters
pub(crate) fn check_regex_should_be_exact(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    for trait_def in trait_definitions {
        let patterns = extract_patterns(trait_def);

        for (_, location) in patterns {
            if location.match_type != "regex" {
                continue;
            }

            let regex_value = &location.original_value;

            // Check if this is a simple anchored pattern: ^word$
            // Allow common variations like ? * + but flag pure anchored words
            if regex_value.starts_with('^') && regex_value.ends_with('$') {
                let inner = &regex_value[1..regex_value.len() - 1];

                // Check if inner contains only word characters (no regex operators)
                // Allow backslash escaping but flag if there are no actual regex features
                let has_regex_operators = inner.chars().any(|c| {
                    matches!(
                        c,
                        '?' | '*' | '+' | '|' | '[' | ']' | '(' | ')' | '{' | '}' | '.'
                    )
                });

                if !has_regex_operators {
                    // Additional check: if it's just a simple word or escaped word, flag it
                    let is_simple_word = inner.chars().all(|c| c.is_alphanumeric() || c == '_');
                    let is_escaped_word =
                        inner.replace("\\\\", "").chars().filter(|&c| c == '\\').count() <= 2;

                    if is_simple_word || (is_escaped_word && inner.len() < 50) {
                        warnings.push(format!(
                            "Regex pattern '{}' is just ^word$ and should use exact: '{}' instead ({}::{})",
                            regex_value,
                            inner,
                            location.file_path,
                            location.trait_id
                        ));
                    }
                }
            }
        }
    }

    let simple_regexes_found = warnings.len() - initial_warning_count;
    tracing::debug!(
        "Simple regex detection completed in {:?} ({} simple regexes found)",
        start.elapsed(),
        simple_regexes_found
    );
}

/// Check for the same pattern appearing with different types across {string, symbol, raw}
/// This indicates poor organization - pick one canonical type and extend language support
pub(crate) fn check_same_string_different_types(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    // Build index: normalized_pattern -> Vec<PatternLocation> grouped by type
    let mut pattern_by_type: HashMap<String, HashMap<String, Vec<PatternLocation>>> =
        HashMap::new();

    for trait_def in trait_definitions {
        let patterns = extract_patterns(trait_def);

        for (normalized, location) in patterns {
            // Only check string, symbol, and raw types
            if !matches!(
                location.condition_type.as_str(),
                "string" | "symbol" | "raw"
            ) {
                continue;
            }

            pattern_by_type
                .entry(normalized)
                .or_default()
                .entry(location.condition_type.clone())
                .or_default()
                .push(location);
        }
    }

    // Find patterns that appear with multiple types
    for (pattern, types_map) in pattern_by_type {
        if types_map.len() < 2 {
            continue; // Only one type, no issue
        }

        // Check if any pair of different types has file type overlap
        let all_locations: Vec<&PatternLocation> = types_map.values().flatten().collect();

        let mut has_overlap = false;
        'outer: for i in 0..all_locations.len() {
            for j in (i + 1)..all_locations.len() {
                // Only check if they have different condition types
                if all_locations[i].condition_type != all_locations[j].condition_type
                    && has_filetype_overlap(all_locations[i], all_locations[j])
                {
                    has_overlap = true;
                    break 'outer;
                }
            }
        }

        if !has_overlap {
            continue; // No file type overlap, patterns won't conflict
        }

        // We have the same pattern with different types AND file type overlap
        let type_details: Vec<String> = types_map
            .iter()
            .map(|(type_name, locations)| {
                let location_strs: Vec<String> = locations
                    .iter()
                    .map(|loc| {
                        let for_str = if loc.for_types.is_empty() {
                            "all".to_string()
                        } else {
                            let mut types: Vec<_> = loc.for_types.iter().cloned().collect();
                            types.sort();
                            types.join(", ")
                        };
                        format!("{}::{} (for: {})", loc.file_path, loc.trait_id, for_str)
                    })
                    .collect();
                format!("   type: {} in: {}", type_name, location_strs.join(", "))
            })
            .collect();

        warnings.push(format!(
            "Pattern '{}' appears with multiple types and overlapping file type coverage (choose one canonical type):\n{}",
            pattern,
            type_details.join("\n")
        ));
    }

    let type_conflicts_found = warnings.len() - initial_warning_count;
    tracing::debug!(
        "Type conflict detection completed in {:?} ({} conflicts found)",
        start.elapsed(),
        type_conflicts_found
    );
}

/// Helper function to check if two file type lists have any overlap
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
fn validate_regex_overlap_with_literal(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    // Build a map of literal (exact/substr) patterns with their context
    let mut literal_patterns: Vec<(String, String, String, Criticality, Vec<RuleFileType>)> =
        Vec::new();

    for t in trait_definitions {
        match &t.r#if.condition {
            Condition::String { exact: Some(s), .. } => {
                literal_patterns.push((
                    s.clone(),
                    "exact".to_string(),
                    t.id.clone(),
                    t.crit,
                    t.r#for.clone(),
                ));
            },
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
            },
            Condition::Symbol { exact: Some(s), .. } => {
                literal_patterns.push((
                    s.clone(),
                    "exact".to_string(),
                    t.id.clone(),
                    t.crit,
                    t.r#for.clone(),
                ));
            },
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
            },
            _ => {},
        }
    }

    // Check regex patterns against literal patterns
    for t in trait_definitions {
        let regex_pattern = match &t.r#if.condition {
            Condition::String { regex: Some(r), .. } => Some(r),
            Condition::Symbol { regex: Some(r), .. } => Some(r),
            _ => None,
        };

        if let Some(regex) = regex_pattern {
            for (literal, match_type, literal_id, literal_crit, literal_types) in &literal_patterns
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
            // Skip directory references like "objectives/credential-access/browser/chromium"
            if let Some(idx) = id.find("::") {
                let trait_dir = &id[..idx];

                // Only flag external directories (different from rule's directory)
                // Skip metadata/ paths since those are auto-generated and can't use directory notation
                if trait_dir != rule_dir && !trait_dir.starts_with("metadata/") {
                    dir_refs.entry(trait_dir.to_string()).or_default().push(id.clone());
                }
            }
            // If no ::, it's a directory reference - these are always fine
        }
    }

    // Find directories with 4+ references
    for (dir, trait_ids) in dir_refs {
        if trait_ids.len() >= 4 {
            violations.push((rule.id.clone(), dir, trait_ids.len(), trait_ids));
        }
    }

    violations
}

/// Find composite rules that have only a single condition total across `any:` and `all:`.
/// A single-item `any:` or `all:` is only a problem if there's no other clause.
/// When both exist, they work together and aren't redundant.
/// Also skip rules that have `none:`, `unless:`, or `downgrade:` clauses - these add meaningful logic.
/// Returns (rule_id, clause_type: "any" or "all", trait_id).
pub(crate) fn find_single_item_clauses(
    rule: &CompositeTrait,
) -> Vec<(String, &'static str, String)> {
    let mut violations = Vec::new();

    // Skip rules with none:, unless:, or downgrade: clauses - they add meaningful conditions
    let has_none = rule.none.as_ref().is_some_and(|v| !v.is_empty());
    let has_unless = rule.unless.as_ref().is_some_and(|v| !v.is_empty());
    let has_downgrade = rule.downgrade.is_some();
    if has_none || has_unless || has_downgrade {
        return violations;
    }

    let any_count = rule.any.as_ref().map_or(0, std::vec::Vec::len);
    let all_count = rule.all.as_ref().map_or(0, std::vec::Vec::len);
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

/// Find composite rules where an `all:` or `any:` clause contains overlapping IDs.
/// Overlap occurs when one entry is a directory reference that is a prefix of another
/// specific trait reference in the same clause (e.g. `micro-behaviors/foo` subsumes `micro-behaviors/foo::bar`).
/// Returns a list of `(rule_id, clause_type, dir_ref, specific_ref)` for each overlap.
pub(crate) fn find_overlapping_conditions(
    rule: &CompositeTrait,
) -> Vec<(String, &'static str, String, String)> {
    let mut violations = Vec::new();

    for (conditions, clause) in [
        (rule.all.as_deref(), "all"),
        (rule.any.as_deref(), "any"),
    ] {
        let Some(conditions) = conditions else { continue };

        let dir_refs: Vec<&str> = conditions
            .iter()
            .filter_map(|c| {
                if let Condition::Trait { id } = c {
                    if !id.contains("::") { Some(id.as_str()) } else { None }
                } else {
                    None
                }
            })
            .collect();

        for cond in conditions {
            if let Condition::Trait { id } = cond {
                if let Some(idx) = id.find("::") {
                    let trait_dir = &id[..idx];
                    if let Some(&dir) = dir_refs.iter().find(|&&d| d == trait_dir) {
                        violations.push((rule.id.clone(), clause, dir.to_string(), id.clone()));
                    }
                }
            }
        }
    }

    violations
}

/// Find micro-behaviors/ rules with hostile criticality.
/// Cap rules represent observable capabilities and should never be hostile.
/// Hostile criticality requires objective-level evidence and belongs in objectives/.
/// Returns (rule_id, source_file) for violations.
pub(crate) fn find_hostile_cap_rules(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    // Helper to check if rule is in micro-behaviors/
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

/// Find objectives/ rules with inert criticality.
/// Obj rules represent attacker objectives and must carry analytical signal.
/// Inert rules either belong in micro-behaviors/ or metadata/ (if truly neutral),
/// or should be upgraded to notable (if they indicate program purpose).
/// Returns (rule_id, source_file) for violations.
pub(crate) fn find_inert_obj_rules(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    fn is_obj_rule(id: &str) -> bool {
        let prefix = id.find("::").map_or(id, |i| &id[..i]);
        match prefix.find('/') {
            Some(slash_idx) => &prefix[..slash_idx] == "obj",
            None => prefix == "obj",
        }
    }

    for trait_def in trait_definitions {
        if is_obj_rule(&trait_def.id) && trait_def.crit == Criticality::Inert {
            let source = rule_source_files
                .get(&trait_def.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((trait_def.id.clone(), source));
        }
    }

    for rule in composite_rules {
        if is_obj_rule(&rule.id) && rule.crit == Criticality::Inert {
            let source = rule_source_files
                .get(&rule.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((rule.id.clone(), source));
        }
    }

    violations
}

/// Find micro-behaviors/ rules that reference objectives/ rules.
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
        // Only check micro-behaviors/ traits
        if let Some(tier) = extract_tier(&trait_def.id) {
            if tier != "cap" {
                continue;
            }

            // Check if the trait condition references other traits
            if let Condition::Trait { id: ref_id } = &trait_def.r#if.condition {
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
        // Only check micro-behaviors/ rules
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

/// Find rules that use `malware/` as a subcategory of `objectives/` or `micro-behaviors/`.
///
/// Malware-specific signatures belong in `well-known/malware/`, not as subcategories
/// of objectives or capabilities. See TAXONOMY.md for the correct structure.
///
/// Returns `(rule_id, source_file)` for violations.
pub(crate) fn find_malware_subcategory_violations(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    fn is_misplaced(id: &str) -> bool {
        let path = id.find("::").map_or(id, |i| &id[..i]);
        path.starts_with("objectives/malware/") || path.starts_with("micro-behaviors/malware/")
    }

    for trait_def in trait_definitions {
        if is_misplaced(&trait_def.id) {
            let source = rule_source_files
                .get(&trait_def.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((trait_def.id.clone(), source));
        }
    }

    for rule in composite_rules {
        if is_misplaced(&rule.id) {
            let source = rule_source_files
                .get(&rule.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((rule.id.clone(), source));
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
    // Binary formats (allowed in metadata/format/)
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
pub(crate) fn find_platform_named_directories(trait_dirs: &[String]) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    for dir_path in trait_dirs {
        // Skip metadata/format/ paths - binary format names are legitimate there
        if dir_path.starts_with("metadata/format/") {
            continue;
        }

        // Skip interpreter/<language> paths - language names are expected there
        // e.g., objectives/execution/interpreter/powershell, objectives/execution/interpreter/python
        if dir_path.contains("/interpreter/") {
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

/// Check for duplicate second-level directories across metadata/, micro-behaviors/, objectives/, and well-known/.
/// This indicates taxonomy violations - directories should not be repeated across namespaces.
/// For example, micro-behaviors/command-and-control/ and objectives/command-and-control/ suggests micro-behaviors/command-and-control/ is misplaced (C2 is an objective, not a capability).
/// Returns a list of (second_level_dir, namespaces_found_in) violations.
pub(crate) fn find_duplicate_second_level_directories(
    trait_dirs: &[String],
) -> Vec<(String, Vec<String>)> {
    let mut second_level_map: HashMap<String, Vec<String>> = HashMap::new();

    for dir_path in trait_dirs {
        // Split path: "micro-behaviors/comm/http" -> ["cap", "comm", "http"]
        let parts: Vec<&str> = dir_path.split('/').collect();
        if parts.len() < 2 {
            continue; // Need at least namespace/second-level
        }

        let namespace = parts[0]; // "cap", "obj", "known", "meta"
        let second_level = parts[1]; // "comm", "c2", "discovery", etc.

        // Only check the four main namespaces
        if !matches!(namespace, "cap" | "obj" | "known" | "meta") {
            continue;
        }

        second_level_map
            .entry(second_level.to_string())
            .or_default()
            .push(namespace.to_string());
    }

    // Find second-level directories that appear in multiple namespaces
    let mut violations = Vec::new();
    for (second_level, mut namespaces) in second_level_map {
        // Deduplicate and sort namespaces
        namespaces.sort();
        namespaces.dedup();

        if namespaces.len() > 1 {
            violations.push((second_level, namespaces));
        }
    }

    // Sort by directory name for consistent output
    violations.sort_by(|a, b| a.0.cmp(&b.0));

    violations
}

/// Check if YAML file paths in micro-behaviors/ or objectives/ are at the correct depth.
/// Valid depths are 3 or 4 subdirectories: micro-behaviors/a/b/c/x.yaml or micro-behaviors/a/b/c/d/x.yaml
/// Returns (path, depth, "shallow" or "deep") for violations.
pub(crate) fn find_depth_violations(yaml_files: &[String]) -> Vec<(String, usize, &'static str)> {
    let mut violations = Vec::new();

    for path in yaml_files {
        // Only check micro-behaviors/ and objectives/ paths
        if !path.starts_with("micro-behaviors/") && !path.starts_with("objectives/") {
            continue;
        }

        // Count directory components (excluding the root micro-behaviors/ or objectives/ and the filename)
        // e.g., "micro-behaviors/comm/http/client/shell.yaml" -> ["cap", "comm", "http", "client", "shell.yaml"]
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() < 2 {
            continue;
        }

        // Subdirectory count = total parts - 1 (root) - 1 (filename)
        let subdir_count = parts.len() - 2;

        // micro-behaviors/dylib/ is a foundational namespace with atomic, non-decomposable operations
        // (load, lookup, enumerate, library markers). Adding depth here would be padding.
        if subdir_count < 3 && path.starts_with("micro-behaviors/dylib/") {
            continue;
        }

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
    id.chars().find(|&c| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
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
/// Collects warnings into the provided vector.
pub(crate) fn simple_rule_to_composite_rule(
    rule: super::models::SimpleRule,
    warnings: &mut Vec<String>,
) -> CompositeTrait {
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
        parse_file_types(&rule.file_types, warnings)
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
        defined_in: std::path::PathBuf::from("converted_simple_rule"),
        precision: None,
    }
}

/// Signature for string/content matching conditions (for collision detection)
/// Note: count/density fields excluded - they're at trait level now and don't affect matching logic
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MatchSignature {
    exact: Option<String>,
    substr: Option<String>,
    regex: Option<String>,
    word: Option<String>,
    case_insensitive: bool,
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
                external_ip: *external_ip,
                section: section.clone(),
                offset: *offset,
                offset_range: *offset_range,
                section_offset: *section_offset,
                section_offset_range: *section_offset_range,
            },
        )),
        Condition::Raw {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
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

/// Find traits where both `type: string` and `type: raw` exist for the same pattern
/// at the same criticality. These should be merged to just `raw` (which is broader).
/// Returns: Vec<(string_trait_id, raw_trait_id, pattern_description)>
pub(crate) fn find_string_content_collisions(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, String, String)> {
    let mut collisions = Vec::new();

    // Group traits by (signature, criticality, for, platforms)
    // Key: (signature, crit, for, platforms) -> Vec<(trait_id, is_string_type)>
    type SignatureGroup = HashMap<(MatchSignature, String, String, String), Vec<(String, bool)>>;
    let mut groups: SignatureGroup = HashMap::new();

    for t in trait_definitions {
        if let Some((is_string, sig)) = extract_match_signature(&t.r#if.condition) {
            // Create a key that includes criticality, for, and platforms
            let crit_key = format!("{:?}", t.crit);
            let for_key = format!("{:?}", t.r#for);
            let platforms_key = format!("{:?}", t.platforms);
            let key = (sig, crit_key, for_key, platforms_key);

            groups.entry(key).or_default().push((t.id.clone(), is_string));
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
            t.r#if, t.crit, t.conf, t.platforms, t.r#if.size_min, t.r#if.size_max, t.not, t.unless
        );
        groups.entry(signature).or_default().push((t.id.clone(), t.r#for.clone()));
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

/// Find traits with regex patterns where the first token differs only in case (alternation candidates).
/// For example: `nc\s+-e` and `NC\s+-e` should become `(nc|NC)\s+-e`
/// Returns: Vec<(trait_ids, common_suffix, suggested_prefix_alternation)>
///
/// NOTE: This check only flags patterns where the same word appears with different cases.
/// Patterns with different words (like `nc` vs `ncat`) are NOT flagged, as they represent
/// genuinely different behaviors.
pub(crate) fn find_alternation_merge_candidates(
    trait_definitions: &[TraitDefinition],
    source_files: &HashMap<String, String>,
) -> Vec<(Vec<String>, String, String)> {
    let mut candidates = Vec::new();

    // Extract regex patterns with their metadata
    // Group by (directory, crit, for, platforms, all other condition params except regex)
    let mut groups: HashMap<String, Vec<(String, String)>> = HashMap::new(); // key -> [(trait_id, regex)]

    for t in trait_definitions {
        let regex_pattern = match &t.r#if.condition {
            Condition::String { regex: Some(r), .. }
            | Condition::Raw { regex: Some(r), .. } => Some(r.clone()),
            _ => None,
        };

        if let Some(regex) = regex_pattern {
            // Get the directory of the source file for this trait
            let directory = source_files
                .get(&t.id)
                .and_then(|path| std::path::Path::new(path).parent().and_then(|p| p.to_str()))
                .unwrap_or("");

            // Create key including directory so we only group traits from the same directory
            let key = format!(
                "{}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}",
                directory,
                t.crit,
                t.r#for,
                t.platforms,
                t.r#if.size_min,
                t.r#if.size_max,
                t.not,
                t.unless
            );
            groups.entry(key).or_default().push((t.id.clone(), regex));
        }
    }

    // Regex to extract prefix (first word-like token) and suffix
    // Match patterns like: ^word or ^word\s or ^word[^a-z]
    let prefix_regex = prefix_regex();

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

        // Find suffix groups with 2+ traits that differ only in case
        for (suffix, prefix_traits) in suffix_groups {
            if prefix_traits.len() >= 2 {
                // Group by lowercase prefix to find case-only differences
                let mut case_groups: HashMap<String, Vec<(String, String)>> = HashMap::new();
                for (trait_id, prefix) in &prefix_traits {
                    case_groups
                        .entry(prefix.to_lowercase())
                        .or_default()
                        .push((trait_id.clone(), prefix.clone()));
                }

                // Only flag groups where the same prefix appears with different cases
                for (_, case_variants) in case_groups {
                    if case_variants.len() >= 2 {
                        // Check if they actually differ in case (not just duplicates)
                        let unique_cases: std::collections::HashSet<_> =
                            case_variants.iter().map(|(_, p)| p.as_str()).collect();

                        if unique_cases.len() >= 2 {
                            let trait_ids: Vec<String> =
                                case_variants.iter().map(|(id, _)| id.clone()).collect();
                            let prefixes: Vec<String> =
                                case_variants.iter().map(|(_, p)| p.clone()).collect();

                            // Build suggested alternation
                            let suggested = format!("({}){}", prefixes.join("|"), suffix);

                            candidates.push((trait_ids, suffix.clone(), suggested));
                        }
                    }
                }
            }
        }
    }

    candidates
}

// ==================== Taxonomy Validations ====================

/// Directory name segments that add no semantic meaning.
/// These make the taxonomy harder to navigate and provide no value for ML classification.
const BANNED_DIRECTORY_SEGMENTS: &[&str] = &[
    "advanced",   // subjective
    "api", // almost everything is an API
    "assorted",   // dumping ground
    "atomic",     // vague
    "base",       // too vague
    "basic",      // meaningless
    "category",   // dumping ground
    "combos",     // vague
    "code",       // vague
    "identifier", // vague
    "common",     // too vague
    "composite",  // vague
    "composite",  // vague
    "composites", // vague
    "default",    // meaningless
    "derived",    // yes
    "generic",    // says nothing about what's inside
    "helpers",    // too vague
    "hostile",    // dumping ground
    "impl",       // implementation detail
    "kind",       // too vague
    "kinds",      // too vague
    "method",     // everything is a method
    "misc",       // dumping ground
    "modes",      // dumping ground
    "new",        // temporal, will rot
    "notable",    // dumping ground
    "old",        // temporal, will rot
    "other",      // dumping ground
    "pattern",    // vague
    "patterns",   // vague
    "go-runtime", // platform
    "simple",     // meaningless
    "stuff",      // obviously badcgl
    "suspicious", // dumping ground
    "technique",  // dumping ground
    "techniques", // dumping ground
    "things",     // obviously bad
    "type",       // too vague
    "types",      // dumping ground
    "types",      // too vague
    "utils",      // too vague
    "various",    // dumping ground
    "windows",    // generic platform
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

/// Find directories where a segment duplicates its immediate parent.
/// e.g., "micro-behaviors/execution/execution/" or "objectives/credential-access/credentials/"
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
                // "cred" vs "credential-access" or "credentials"
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
pub(crate) const MAX_TRAITS_PER_DIRECTORY: usize = 80;

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
pub(crate) fn find_impossible_needs(
    composite_rules: &[CompositeTrait],
) -> Vec<(String, usize, usize)> {
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
        if let (Some(min), Some(max)) = (t.r#if.size_min, t.r#if.size_max) {
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
        // count_min and count_max are now at trait level in ConditionWithFilters
        if let (Some(min), Some(max)) = (t.r#if.count_min, t.r#if.count_max) {
            if min > max {
                violations.push((t.id.clone(), min, max));
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
        let all_empty = rule.all.as_ref().is_none_or(std::vec::Vec::is_empty);
        let any_empty = rule.any.as_ref().is_none_or(std::vec::Vec::is_empty);
        let none_empty = rule.none.as_ref().is_none_or(std::vec::Vec::is_empty);

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
pub(crate) fn find_missing_search_patterns(trait_definitions: &[TraitDefinition]) -> Vec<String> {
    let mut violations = Vec::new();

    for t in trait_definitions {
        let has_pattern = match &t.r#if.condition {
            Condition::String {
                exact,
                substr,
                regex,
                word,
                ..
            }
            | Condition::Raw {
                exact,
                substr,
                regex,
                word,
                ..
            }
            | Condition::Encoded {
                exact,
                substr,
                regex,
                word,
                ..
            } => exact.is_some() || substr.is_some() || regex.is_some() || word.is_some(),
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
        let has_all = rule.all.as_ref().is_some_and(|v| !v.is_empty());
        let has_none = rule.none.as_ref().is_some_and(|v| !v.is_empty());
        let has_any = rule.any.as_ref().is_some_and(|v| !v.is_empty());

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
            "micro-behaviors/comm/http/client".to_string(),
            "objectives/credential-access/browser".to_string(),
        ];
        assert!(find_platform_named_directories(&dirs).is_empty());
    }

    #[test]
    fn test_find_platform_named_directories_with_violation() {
        let dirs = vec![
            "micro-behaviors/execution/python/imports".to_string(), // "python" is a platform name
        ];
        let violations = find_platform_named_directories(&dirs);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1, "python");
    }

    #[test]
    fn test_find_platform_named_directories_skips_meta_format() {
        let dirs = vec![
            "metadata/format/elf".to_string(), // Should be skipped
        ];
        assert!(find_platform_named_directories(&dirs).is_empty());
    }

    // ==================== Depth Violation Tests ====================

    #[test]
    fn test_find_depth_violations_valid_depths() {
        let files = vec![
            "micro-behaviors/a/b/c/test.yaml".to_string(),   // depth 3, valid
            "micro-behaviors/a/b/c/d/test.yaml".to_string(), // depth 4, valid
            "objectives/x/y/z/file.yaml".to_string(),   // depth 3, valid
        ];
        assert!(find_depth_violations(&files).is_empty());
    }

    #[test]
    fn test_find_depth_violations_too_shallow() {
        let files = vec![
            "micro-behaviors/a/test.yaml".to_string(),   // depth 1, too shallow
            "micro-behaviors/a/b/test.yaml".to_string(), // depth 2, too shallow
        ];
        let violations = find_depth_violations(&files);
        assert_eq!(violations.len(), 2);
        assert_eq!(violations[0].2, "shallow");
        assert_eq!(violations[1].2, "shallow");
    }

    #[test]
    fn test_find_depth_violations_too_deep() {
        let files = vec![
            "micro-behaviors/a/b/c/d/e/test.yaml".to_string(), // depth 5, too deep
        ];
        let violations = find_depth_violations(&files);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].2, "deep");
    }

    #[test]
    fn test_find_depth_violations_skips_other_paths() {
        let files = vec![
            "metadata/test.yaml".to_string(),          // Not micro-behaviors/ or objectives/, skipped
            "well-known/malware/test.yaml".to_string(), // Not micro-behaviors/ or objectives/, skipped
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
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
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
            all: Some(vec![Condition::Trait {
                id: "other::trait".to_string(),
            }]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
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
                Condition::Trait {
                    id: "trait1".to_string(),
                },
                Condition::Trait {
                    id: "trait2".to_string(),
                },
            ]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
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
            all: Some(vec![Condition::Trait {
                id: "trait1".to_string(),
            }]),
            any: None,
            needs: None,
            none: Some(vec![Condition::Trait {
                id: "excluded".to_string(),
            }]),
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
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
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
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
                Condition::Trait {
                    id: "other/dir::trait1".to_string(),
                },
                Condition::Trait {
                    id: "other/dir::trait2".to_string(),
                },
            ]),
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
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
                Condition::Trait {
                    id: "other/dir::trait1".to_string(),
                },
                Condition::Trait {
                    id: "other/dir::trait2".to_string(),
                },
                Condition::Trait {
                    id: "other/dir::trait3".to_string(),
                },
                Condition::Trait {
                    id: "other/dir::trait4".to_string(),
                },
            ]),
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        };
        let violations = find_redundant_any_refs(&rule);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1, "other/dir");
        assert_eq!(violations[0].2, 4);
    }

    // ==================== Overlapping Condition Tests ====================

    #[test]
    fn test_find_overlapping_conditions_no_overlap() {
        let rule = CompositeTrait {
            id: "micro-behaviors/code/syntax/actionscript::rule".to_string(),
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
                Condition::Trait {
                    id: "micro-behaviors/code/syntax/actionscript::trait-a".to_string(),
                },
                Condition::Trait {
                    id: "micro-behaviors/code/syntax/actionscript::trait-b".to_string(),
                },
            ]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        };
        assert!(find_overlapping_conditions(&rule).is_empty());
    }

    #[test]
    fn test_find_overlapping_conditions_all_overlap() {
        let rule = CompositeTrait {
            id: "micro-behaviors/test::rule".to_string(),
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
                Condition::Trait {
                    id: "micro-behaviors/code/syntax/actionscript::obfuscated-identifier-section".to_string(),
                },
                Condition::Trait {
                    id: "micro-behaviors/code/syntax/actionscript".to_string(),
                },
            ]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        };
        let violations = find_overlapping_conditions(&rule);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1, "all");
        assert_eq!(violations[0].2, "micro-behaviors/code/syntax/actionscript");
        assert_eq!(
            violations[0].3,
            "micro-behaviors/code/syntax/actionscript::obfuscated-identifier-section"
        );
    }

    #[test]
    fn test_find_overlapping_conditions_any_overlap() {
        let rule = CompositeTrait {
            id: "micro-behaviors/test::rule".to_string(),
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
                Condition::Trait {
                    id: "micro-behaviors/code/syntax/javascript".to_string(),
                },
                Condition::Trait {
                    id: "micro-behaviors/code/syntax/javascript::eval-obfuscation".to_string(),
                },
            ]),
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        };
        let violations = find_overlapping_conditions(&rule);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1, "any");
        assert_eq!(violations[0].2, "micro-behaviors/code/syntax/javascript");
        assert_eq!(violations[0].3, "micro-behaviors/code/syntax/javascript::eval-obfuscation");
    }

    #[test]
    fn test_find_overlapping_conditions_different_dirs_no_overlap() {
        let rule = CompositeTrait {
            id: "micro-behaviors/test::rule".to_string(),
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
                Condition::Trait {
                    id: "micro-behaviors/code/syntax/actionscript".to_string(),
                },
                Condition::Trait {
                    id: "micro-behaviors/code/syntax/javascript::eval-obfuscation".to_string(),
                },
            ]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        };
        assert!(find_overlapping_conditions(&rule).is_empty());
    }

    // ==================== Autoprefix Tests ====================

    #[test]
    fn test_autoprefix_trait_refs_local_ids() {
        let mut rule = CompositeTrait {
            id: "micro-behaviors/test::rule".to_string(),
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
                id: "local-trait".to_string(),
            }]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        };

        autoprefix_trait_refs(&mut rule, "micro-behaviors/test");

        if let Some(Condition::Trait { id }) = rule.all.as_ref().and_then(|v| v.first()) {
            assert_eq!(id, "micro-behaviors/test::local-trait");
        } else {
            panic!("Expected trait condition");
        }
    }

    #[test]
    fn test_autoprefix_trait_refs_already_qualified() {
        let mut rule = CompositeTrait {
            id: "micro-behaviors/test::rule".to_string(),
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
                id: "other/path::trait".to_string(),
            }]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        };

        autoprefix_trait_refs(&mut rule, "micro-behaviors/test");

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
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
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
            all: Some(vec![Condition::Trait {
                id: "trait1".to_string(),
            }]),
            any: Some(vec![Condition::Trait {
                id: "trait2".to_string(),
            }]),
            needs: None,
            none: Some(vec![Condition::Trait {
                id: "trait3".to_string(),
            }]),
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
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
            r#if: crate::composite_rules::ConditionWithFilters {
                condition: Condition::String {
                    exact: None,
                    substr: Some(substr.to_string()),
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    exclude_patterns: None,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    compiled_regex: None,
                    compiled_excludes: Vec::new(),
                },
                size_min: None,
                size_max: None,
                count_min: Some(1),
                count_max: None,
                per_kb_min: None,
                per_kb_max: None,
            },
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
            precision: None,
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
            r#if: crate::composite_rules::ConditionWithFilters {
                condition: Condition::Raw {
                    exact: None,
                    substr: Some(substr.to_string()),
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    compiled_regex: None,
                },
                size_min: None,
                size_max: None,
                count_min: Some(1),
                count_max: None,
                per_kb_min: None,
                per_kb_max: None,
            },
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
            precision: None,
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
            r#if: crate::composite_rules::ConditionWithFilters {
                condition: Condition::String {
                    exact: None,
                    substr: Some(substr.to_string()),
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    exclude_patterns: None,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    compiled_regex: None,
                    compiled_excludes: Vec::new(),
                },
                size_min: None,
                size_max: None,
                count_min: Some(1),
                count_max: None,
                per_kb_min: None,
                per_kb_max: None,
            },
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
            precision: None,
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
            r#if: crate::composite_rules::ConditionWithFilters {
                condition: Condition::String {
                    exact: None,
                    substr: None,
                    regex: Some(regex.to_string()),
                    word: None,
                    case_insensitive: false,
                    exclude_patterns: None,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    compiled_regex: None,
                    compiled_excludes: Vec::new(),
                },
                size_min: None,
                size_max: None,
                count_min: Some(1),
                count_max: None,
                per_kb_min: None,
                per_kb_max: None,
            },
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
            precision: None,
        }
    }

    #[test]
    fn test_find_alternation_merge_candidates_empty() {
        let traits: Vec<TraitDefinition> = vec![];
        assert!(
            find_alternation_merge_candidates(&traits, &std::collections::HashMap::new())
                .is_empty()
        );
    }

    #[test]
    fn test_find_alternation_merge_candidates_no_candidates() {
        let traits = vec![
            make_regex_trait("test::pattern1", r"foo\s+bar"),
            make_regex_trait("test::pattern2", r"baz\s+qux"),
        ];
        // Completely different patterns
        assert!(
            find_alternation_merge_candidates(&traits, &std::collections::HashMap::new())
                .is_empty()
        );
    }

    #[test]
    fn test_find_alternation_merge_candidates_common_suffix() {
        // Test case-only differences with common suffix
        let traits = vec![
            make_regex_trait("test::nc-exec", r"nc\s+-e\s+/bin/sh"),
            make_regex_trait("test::NC-exec", r"NC\s+-e\s+/bin/sh"),
            make_regex_trait("test::Nc-exec", r"Nc\s+-e\s+/bin/sh"),
        ];
        let candidates =
            find_alternation_merge_candidates(&traits, &std::collections::HashMap::new());
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0.len(), 3);
        // The suggested pattern should include alternation
        assert!(
            candidates[0].2.contains("nc|NC|Nc")
                || candidates[0].2.contains("NC|nc|Nc")
                || candidates[0].2.contains("Nc|nc|NC")
        );
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
        assert!(
            find_alternation_merge_candidates(&traits, &std::collections::HashMap::new())
                .is_empty()
        );
    }

    #[test]
    fn test_find_alternation_merge_candidates_short_suffix_ignored() {
        let traits = vec![
            make_regex_trait("test::a1", r"foo\s"),
            make_regex_trait("test::a2", r"bar\s"),
        ];
        // Suffix is too short (< 3 chars after prefix)
        assert!(
            find_alternation_merge_candidates(&traits, &std::collections::HashMap::new())
                .is_empty()
        );
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
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
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

    fn make_trait_with_size(
        id: &str,
        size_min: Option<usize>,
        size_max: Option<usize>,
    ) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 0.9,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            r#if: crate::composite_rules::ConditionWithFilters {
                condition: Condition::String {
                    exact: Some("test".to_string()),
                    substr: None,
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    exclude_patterns: None,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    compiled_regex: None,
                    compiled_excludes: Vec::new(),
                },
                size_min,
                size_max,
                count_min: Some(1),
                count_max: None,
                per_kb_min: None,
                per_kb_max: None,
            },
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
            precision: None,
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

    fn make_trait_with_count(
        id: &str,
        count_min: usize,
        count_max: Option<usize>,
    ) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 0.9,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            r#if: crate::composite_rules::ConditionWithFilters {
                condition: Condition::String {
                    exact: None,
                    substr: Some("test".to_string()),
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    exclude_patterns: None,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    compiled_regex: None,
                    compiled_excludes: Vec::new(),
                },
                size_min: None,
                size_max: None,
                count_min: Some(count_min),
                count_max,
                per_kb_min: None,
                per_kb_max: None,
            },
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
            precision: None,
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
            r#if: crate::composite_rules::ConditionWithFilters {
                condition: Condition::String {
                    exact: None,
                    substr: None,
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    exclude_patterns: None,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    compiled_regex: None,
                    compiled_excludes: Vec::new(),
                },
                size_min: None,
                size_max: None,
                count_min: Some(1),
                count_max: None,
                per_kb_min: None,
                per_kb_max: None,
            },
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
            precision: None,
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
            "micro-behaviors/comm/http/client".to_string(),
            "objectives/credential-access/browser/chromium".to_string(),
        ];
        assert!(find_banned_directory_segments(&dirs).is_empty());
    }

    #[test]
    fn test_find_banned_directory_segments_generic() {
        let dirs = vec!["micro-behaviors/execution/generic/shell".to_string()];
        let violations = find_banned_directory_segments(&dirs);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1, "generic");
    }

    #[test]
    fn test_find_banned_directory_segments_method() {
        let dirs = vec!["objectives/command-and-control/reverse-shell/method".to_string()];
        let violations = find_banned_directory_segments(&dirs);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1, "method");
    }

    #[test]
    fn test_find_banned_directory_segments_misc() {
        let dirs = vec!["micro-behaviors/misc/utils".to_string()];
        let violations = find_banned_directory_segments(&dirs);
        assert_eq!(violations.len(), 1);
        // First banned segment found
        assert!(violations[0].1 == "misc" || violations[0].1 == "utils");
    }

    #[test]
    fn test_find_parent_duplicate_segments_empty() {
        let dirs: Vec<String> = vec![];
        assert!(find_parent_duplicate_segments(&dirs).is_empty());
    }

    #[test]
    fn test_find_parent_duplicate_segments_valid() {
        let dirs = vec![
            "micro-behaviors/execution/shell".to_string(),
            "objectives/credential-access/browser".to_string(),
        ];
        assert!(find_parent_duplicate_segments(&dirs).is_empty());
    }

    #[test]
    fn test_find_parent_duplicate_segments_exact() {
        let dirs = vec!["micro-behaviors/execution/exec".to_string()];
        let violations = find_parent_duplicate_segments(&dirs);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1, "exec");
    }

    #[test]
    fn test_find_parent_duplicate_segments_plural() {
        let dirs = vec!["objectives/credential-access/cred".to_string()];
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
                    &format!("micro-behaviors/test/dir::trait-{}", i),
                    "test",
                    Criticality::Notable,
                );
                t.id = format!("micro-behaviors/test/dir::trait-{}", i);
                t
            })
            .collect();
        assert!(find_oversized_trait_directories(&traits).is_empty());
    }

    #[test]
    fn test_find_oversized_trait_directories_over_limit() {
        // Create 85 traits in same directory (over 80 limit)
        let traits: Vec<TraitDefinition> = (0..85)
            .map(|i| {
                let mut t = make_string_trait(
                    &format!("micro-behaviors/test/oversized::trait-{}", i),
                    "test",
                    Criticality::Notable,
                );
                t.id = format!("micro-behaviors/test/oversized::trait-{}", i);
                t
            })
            .collect();
        let violations = find_oversized_trait_directories(&traits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "micro-behaviors/test/oversized");
        assert_eq!(violations[0].1, 85);
    }

    #[test]
    fn test_find_oversized_trait_directories_multiple_dirs() {
        // 85 in one dir (violation), 10 in another (ok)
        let mut traits: Vec<TraitDefinition> = (0..85)
            .map(|i| {
                let mut t = make_string_trait(
                    &format!("micro-behaviors/test/big::trait-{}", i),
                    "test",
                    Criticality::Notable,
                );
                t.id = format!("micro-behaviors/test/big::trait-{}", i);
                t
            })
            .collect();

        for i in 0..10 {
            let mut t = make_string_trait(
                &format!("micro-behaviors/test/small::trait-{}", i),
                "test",
                Criticality::Notable,
            );
            t.id = format!("micro-behaviors/test/small::trait-{}", i);
            traits.push(t);
        }

        let violations = find_oversized_trait_directories(&traits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "micro-behaviors/test/big");
    }

    // ==================== micro-behaviors/Obj Violation Tests ====================

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
            id: "micro-behaviors/test::rule".to_string(),
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
                id: "micro-behaviors/other::trait1".to_string(),
            }]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
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
            id: "micro-behaviors/test::rule".to_string(),
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
                id: "objectives/command-and-control/backdoor::trait1".to_string(),
            }]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let mut sources = HashMap::new();
        sources.insert("micro-behaviors/test::rule".to_string(), "test.yaml".to_string());

        let violations = find_cap_obj_violations(&traits, &composites, &sources);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "micro-behaviors/test::rule");
        assert_eq!(violations[0].1, "objectives/command-and-control/backdoor::trait1");
    }

    #[test]
    fn test_find_cap_obj_violations_obj_references_cap_ok() {
        // Obj rule referencing a cap rule is OK (objectives can use capabilities)
        let rule = CompositeTrait {
            id: "objectives/test::rule".to_string(),
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
                id: "micro-behaviors/execution/shell::exec".to_string(),
            }]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
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
            id: "well-known/malware/test::rule".to_string(),
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
                id: "objectives/command-and-control/backdoor::trait1".to_string(),
            }]),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
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
            id: "micro-behaviors/test::rule".to_string(),
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
                id: "objectives/command-and-control/backdoor::trait1".to_string(),
            }]),
            any: Some(vec![Condition::Trait {
                id: "objectives/exfiltration/data::trait2".to_string(),
            }]),
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let mut sources = HashMap::new();
        sources.insert("micro-behaviors/test::rule".to_string(), "test.yaml".to_string());

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
            id: "micro-behaviors/test::rule".to_string(),
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
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
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
            id: "micro-behaviors/test::rule".to_string(),
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
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let mut sources = HashMap::new();
        sources.insert("micro-behaviors/test::rule".to_string(), "test.yaml".to_string());

        let violations = find_hostile_cap_rules(&traits, &composites, &sources);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "micro-behaviors/test::rule");
    }

    #[test]
    fn test_find_hostile_cap_rules_obj_ok() {
        // Obj rule with hostile criticality is OK
        let rule = CompositeTrait {
            id: "objectives/command-and-control/backdoor::rule".to_string(),
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
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
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
            id: "well-known/malware/test::rule".to_string(),
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
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let sources = HashMap::new();
        assert!(find_hostile_cap_rules(&traits, &composites, &sources).is_empty());
    }

    #[test]
    fn test_find_hostile_cap_rules_trait_violation() {
        // Cap trait with hostile criticality is a VIOLATION
        let mut trait_def = make_string_trait("micro-behaviors/test::trait", "test", Criticality::Hostile);
        trait_def.id = "micro-behaviors/test::trait".to_string();

        let traits = vec![trait_def];
        let composites: Vec<CompositeTrait> = vec![];
        let mut sources = HashMap::new();
        sources.insert("micro-behaviors/test::trait".to_string(), "test.yaml".to_string());

        let violations = find_hostile_cap_rules(&traits, &composites, &sources);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "micro-behaviors/test::trait");
    }

    // ==================== Inert Obj Rule Tests ====================

    #[test]
    fn test_find_inert_obj_rules_empty() {
        let traits: Vec<TraitDefinition> = vec![];
        let composites: Vec<CompositeTrait> = vec![];
        let sources = HashMap::new();
        assert!(find_inert_obj_rules(&traits, &composites, &sources).is_empty());
    }

    #[test]
    fn test_find_inert_obj_rules_no_violations() {
        // Obj rule with notable criticality is OK
        let rule = CompositeTrait {
            id: "objectives/command-and-control/backdoor::rule".to_string(),
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
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let sources = HashMap::new();
        assert!(find_inert_obj_rules(&traits, &composites, &sources).is_empty());
    }

    #[test]
    fn test_find_inert_obj_rules_violation() {
        // Obj rule with inert criticality is a VIOLATION
        let rule = CompositeTrait {
            id: "objectives/command-and-control/backdoor::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Inert,
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
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let mut sources = HashMap::new();
        sources.insert("objectives/command-and-control/backdoor::rule".to_string(), "test.yaml".to_string());

        let violations = find_inert_obj_rules(&traits, &composites, &sources);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "objectives/command-and-control/backdoor::rule");
    }

    #[test]
    fn test_find_inert_obj_rules_cap_ok() {
        // Cap rule with inert criticality is fine (handled by other validators)
        let rule = CompositeTrait {
            id: "micro-behaviors/comm/socket::rule".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Inert,
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
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let sources = HashMap::new();
        assert!(find_inert_obj_rules(&traits, &composites, &sources).is_empty());
    }

    #[test]
    fn test_find_inert_obj_rules_trait_violation() {
        // Obj trait definition with inert criticality is a VIOLATION
        let mut trait_def = make_string_trait("objectives/exfiltration/test::trait", "test", Criticality::Inert);
        trait_def.id = "objectives/exfiltration/test::trait".to_string();

        let traits = vec![trait_def];
        let composites: Vec<CompositeTrait> = vec![];
        let mut sources = HashMap::new();
        sources.insert("objectives/exfiltration/test::trait".to_string(), "test.yaml".to_string());

        let violations = find_inert_obj_rules(&traits, &composites, &sources);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "objectives/exfiltration/test::trait");
    }

    // ==================== Malware Subcategory Violation Tests ====================

    #[test]
    fn test_find_malware_subcategory_violations_empty() {
        let traits: Vec<TraitDefinition> = vec![];
        let composites: Vec<CompositeTrait> = vec![];
        let sources = HashMap::new();
        assert!(find_malware_subcategory_violations(&traits, &composites, &sources).is_empty());
    }

    #[test]
    fn test_find_malware_subcategory_violations_known_ok() {
        // well-known/malware/ is the correct location — not a violation
        let rule = CompositeTrait {
            id: "well-known/malware/apt/rule::rule".to_string(),
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
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let sources = HashMap::new();
        assert!(find_malware_subcategory_violations(&traits, &composites, &sources).is_empty());
    }

    #[test]
    fn test_find_malware_subcategory_violations_obj_malware() {
        // objectives/malware/ is a violation
        let rule = CompositeTrait {
            id: "objectives/malware/backdoor::rule".to_string(),
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
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        };
        let traits: Vec<TraitDefinition> = vec![];
        let composites = vec![rule];
        let mut sources = HashMap::new();
        sources.insert(
            "objectives/malware/backdoor::rule".to_string(),
            "objectives/malware/backdoor/rule.yaml".to_string(),
        );
        let violations = find_malware_subcategory_violations(&traits, &composites, &sources);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "objectives/malware/backdoor::rule");
    }

    #[test]
    fn test_find_malware_subcategory_violations_cap_malware() {
        // micro-behaviors/malware/ is a violation
        let trait_def =
            make_string_trait("micro-behaviors/malware/dropper::trait", "test", Criticality::Suspicious);
        let traits = vec![trait_def];
        let composites: Vec<CompositeTrait> = vec![];
        let mut sources = HashMap::new();
        sources.insert(
            "micro-behaviors/malware/dropper::trait".to_string(),
            "micro-behaviors/malware/dropper/trait.yaml".to_string(),
        );
        let violations = find_malware_subcategory_violations(&traits, &composites, &sources);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "micro-behaviors/malware/dropper::trait");
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
        trait2.r#if = crate::composite_rules::ConditionWithFilters {
            condition: Condition::String {
                exact: None,
                substr: None,
                regex: Some("eval\\(".to_string()),
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            size_min: None,
            size_max: None,
            count_min: Some(1),
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
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
        trait2.r#if = crate::composite_rules::ConditionWithFilters {
            condition: Condition::String {
                exact: None,
                substr: None,
                regex: Some("eval\\(".to_string()),
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            size_min: None,
            size_max: None,
            count_min: Some(1),
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
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
        trait2.r#if = crate::composite_rules::ConditionWithFilters {
            condition: Condition::String {
                exact: None,
                substr: None,
                regex: Some("eval\\(".to_string()),
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            size_min: None,
            size_max: None,
            count_min: Some(1),
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
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
        trait1.r#if = crate::composite_rules::ConditionWithFilters {
            condition: Condition::String {
                exact: Some("socket".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            size_min: None,
            size_max: None,
            count_min: Some(1),
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
        };

        // Create a regex trait that contains "socket"
        let mut trait2 = make_string_trait("test::regex_socket", "", Criticality::Hostile);
        trait2.r#if = crate::composite_rules::ConditionWithFilters {
            condition: Condition::String {
                exact: None,
                substr: None,
                regex: Some("^socket$".to_string()),
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            size_min: None,
            size_max: None,
            count_min: Some(1),
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
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
        trait1.r#if = crate::composite_rules::ConditionWithFilters {
            condition: Condition::Symbol {
                exact: None,
                substr: Some("connect".to_string()),
                regex: None,
                platforms: None,
                compiled_regex: None,
            },
            size_min: None,
            size_max: None,
            count_min: Some(1),
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
        };

        // Create a regex Symbol trait
        let mut trait2 = make_string_trait("test::regex_connect", "", Criticality::Hostile);
        trait2.r#if = crate::composite_rules::ConditionWithFilters {
            condition: Condition::Symbol {
                exact: None,
                substr: None,
                regex: Some("connect.*".to_string()),
                platforms: None,
                compiled_regex: None,
            },
            size_min: None,
            size_max: None,
            count_min: Some(1),
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
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
        trait2.r#if = crate::composite_rules::ConditionWithFilters {
            condition: Condition::String {
                exact: None,
                substr: None,
                regex: Some("Buffer\\.from\\(".to_string()),
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            size_min: None,
            size_max: None,
            count_min: Some(1),
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
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
        trait2.r#if = crate::composite_rules::ConditionWithFilters {
            condition: Condition::String {
                exact: None,
                substr: None,
                regex: Some("chmod\\s+\\d{3,4}".to_string()),
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            size_min: None,
            size_max: None,
            count_min: Some(1),
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
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
        trait1.r#if = crate::composite_rules::ConditionWithFilters {
            condition: Condition::String {
                exact: Some("chmod".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            size_min: None,
            size_max: None,
            count_min: Some(1),
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
        };

        // Create a regex trait with optional character pattern "c?mod" that matches "chmod"
        let mut trait2 = make_string_trait("test::regex_optional_chmod", "", Criticality::Notable);
        trait2.r#if = crate::composite_rules::ConditionWithFilters {
            condition: Condition::String {
                exact: None,
                substr: None,
                regex: Some("c?mod".to_string()),
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            size_min: None,
            size_max: None,
            count_min: Some(1),
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
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

    #[test]
    fn test_string_pattern_exact_duplicate_different_files() {
        // Two traits with identical substr pattern in different files for same file type
        let mut trait1 =
            make_string_trait("micro-behaviors/fs/proc/info::proc-net-tcp", "", Criticality::Notable);
        trait1.defined_in = std::path::PathBuf::from("traits/micro-behaviors/fs/proc/info/linux.yaml");
        trait1.r#if.condition = Condition::String {
            substr: Some("/proc/net/tcp".to_string()),
            exact: None,
            word: None,
            regex: None,
            case_insensitive: false,
            exclude_patterns: None,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };
        trait1.r#for = vec![RuleFileType::Elf];

        let mut trait2 = make_string_trait(
            "objectives/discovery/network/scan::tcp-connections",
            "",
            Criticality::Suspicious,
        );
        trait2.defined_in = std::path::PathBuf::from("traits/objectives/discovery/network/scan/proc.yaml");
        trait2.r#if.condition = Condition::String {
            substr: Some("/proc/net/tcp".to_string()),
            exact: None,
            word: None,
            regex: None,
            case_insensitive: false,
            exclude_patterns: None,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };
        trait2.r#for = vec![RuleFileType::Elf];
        trait2.platforms = vec![Platform::Linux];

        let traits = vec![trait1, trait2];
        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&traits, &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("/proc/net/tcp"));
        assert!(warnings[0].contains("2 files"));
        assert!(warnings[0].contains("micro-behaviors/fs/proc/info/linux.yaml"));
        assert!(warnings[0].contains("objectives/discovery/network/scan/proc.yaml"));
    }

    #[test]
    fn test_string_pattern_exact_duplicate_no_overlap() {
        // Two traits with identical pattern but different file types - should NOT warn
        let mut trait1 = make_string_trait("micro-behaviors/test::pattern-a", "", Criticality::Notable);
        trait1.defined_in = std::path::PathBuf::from("traits/micro-behaviors/test/file1.yaml");
        trait1.r#if.condition = Condition::String {
            substr: Some("/proc/net/tcp".to_string()),
            exact: None,
            word: None,
            regex: None,
            case_insensitive: false,
            exclude_patterns: None,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };
        trait1.r#for = vec![RuleFileType::Elf];

        let mut trait2 = make_string_trait("micro-behaviors/test::pattern-b", "", Criticality::Notable);
        trait2.defined_in = std::path::PathBuf::from("traits/micro-behaviors/test/file2.yaml");
        trait2.r#if.condition = Condition::String {
            substr: Some("/proc/net/tcp".to_string()),
            exact: None,
            word: None,
            regex: None,
            case_insensitive: false,
            exclude_patterns: None,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };
        trait2.r#for = vec![RuleFileType::Python]; // Different file type

        let traits = vec![trait1, trait2];
        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&traits, &mut warnings);

        // Should NOT warn - no filetype overlap
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_string_pattern_cross_type_duplicate() {
        // Same pattern in String and Symbol conditions - should warn
        let mut trait1 = make_string_trait("micro-behaviors/execution/load::dlsym-import", "", Criticality::Notable);
        trait1.defined_in = std::path::PathBuf::from("traits/micro-behaviors/execution/load/unix.yaml");
        trait1.r#if.condition = Condition::Symbol {
            exact: Some("dlsym".to_string()),
            substr: None,
            regex: None,
            platforms: None,
            compiled_regex: None,
        };
        trait1.r#for = vec![RuleFileType::Elf];

        let mut trait2 = make_string_trait("micro-behaviors/execution/load::dlsym-string", "", Criticality::Notable);
        trait2.defined_in = std::path::PathBuf::from("traits/micro-behaviors/execution/load/linux.yaml");
        trait2.r#if.condition = Condition::String {
            substr: Some("dlsym".to_string()),
            exact: None,
            word: None,
            regex: None,
            case_insensitive: false,
            exclude_patterns: None,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };
        trait2.r#for = vec![RuleFileType::Elf];

        let traits = vec![trait1, trait2];
        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&traits, &mut warnings);

        // Should warn - same normalized pattern "dlsym" in different files
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("dlsym"));
        assert!(warnings[0].contains("symbol"));
        assert!(warnings[0].contains("string"));
    }

    #[test]
    fn test_string_pattern_regex_anchor_normalization() {
        // Regex with anchors should match exact pattern
        let mut trait1 = make_string_trait("micro-behaviors/test::pattern-regex", "", Criticality::Notable);
        trait1.defined_in = std::path::PathBuf::from("traits/micro-behaviors/test/file1.yaml");
        trait1.r#if.condition = Condition::String {
            exact: None,
            substr: None,
            word: None,
            regex: Some("^test_pattern$".to_string()),
            case_insensitive: false,
            exclude_patterns: None,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };
        trait1.r#for = vec![RuleFileType::Elf];

        let mut trait2 = make_string_trait("micro-behaviors/test::pattern-exact", "", Criticality::Notable);
        trait2.defined_in = std::path::PathBuf::from("traits/micro-behaviors/test/file2.yaml");
        trait2.r#if.condition = Condition::String {
            exact: Some("test_pattern".to_string()),
            substr: None,
            word: None,
            regex: None,
            case_insensitive: false,
            exclude_patterns: None,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };
        trait2.r#for = vec![RuleFileType::Elf];

        let traits = vec![trait1, trait2];
        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&traits, &mut warnings);

        // Should warn - ^test_pattern$ normalized to test_pattern matches exact
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("test_pattern"));
    }

    #[test]
    fn test_string_pattern_no_restrictions_overlaps_all() {
        // Trait with no `for:` restrictions should overlap with everything
        let mut trait1 = make_string_trait("micro-behaviors/test::unrestricted", "", Criticality::Notable);
        trait1.defined_in = std::path::PathBuf::from("traits/micro-behaviors/test/file1.yaml");
        trait1.r#if.condition = Condition::String {
            substr: Some("/proc/net/tcp".to_string()),
            exact: None,
            word: None,
            regex: None,
            case_insensitive: false,
            exclude_patterns: None,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };
        // No `for:` restriction - applies to all file types
        trait1.r#for = Vec::new();

        let mut trait2 = make_string_trait("micro-behaviors/test::elf-only", "", Criticality::Notable);
        trait2.defined_in = std::path::PathBuf::from("traits/micro-behaviors/test/file2.yaml");
        trait2.r#if.condition = Condition::String {
            substr: Some("/proc/net/tcp".to_string()),
            exact: None,
            word: None,
            regex: None,
            case_insensitive: false,
            exclude_patterns: None,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        };
        trait2.r#for = vec![RuleFileType::Elf];

        let traits = vec![trait1, trait2];
        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&traits, &mut warnings);

        // Should warn - unrestricted overlaps with restricted
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("/proc/net/tcp"));
    }

    #[test]
    fn test_check_overlapping_regex_patterns_warns_on_filetype_overlap() {
        let mut t1 = make_regex_trait("test::regex_a", r"eval|exec|system");
        t1.r#for = vec![RuleFileType::Python];
        t1.defined_in = std::path::PathBuf::from("traits/test/a.yaml");

        let mut t2 = make_regex_trait("test::regex_b", r"exec|spawn|popen");
        t2.r#for = vec![RuleFileType::Python, RuleFileType::Shell];
        t2.defined_in = std::path::PathBuf::from("traits/test/b.yaml");

        let traits = vec![t1, t2];
        let mut warnings = Vec::new();
        check_overlapping_regex_patterns(&traits, &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Overlapping regex patterns with same file type coverage"));
        assert!(warnings[0].contains("shared alternatives: exec"));
    }

    #[test]
    fn test_check_overlapping_regex_patterns_no_warning_without_filetype_overlap() {
        let mut t1 = make_regex_trait("test::regex_a", r"eval|exec|system");
        t1.r#for = vec![RuleFileType::Python];
        t1.defined_in = std::path::PathBuf::from("traits/test/a.yaml");

        let mut t2 = make_regex_trait("test::regex_b", r"exec|spawn|popen");
        t2.r#for = vec![RuleFileType::JavaScript];
        t2.defined_in = std::path::PathBuf::from("traits/test/b.yaml");

        let traits = vec![t1, t2];
        let mut warnings = Vec::new();
        check_overlapping_regex_patterns(&traits, &mut warnings);

        assert!(warnings.is_empty());
    }

    #[test]
    fn test_check_overlapping_regex_patterns_no_warning_when_count_filters_differ() {
        let mut t1 = make_regex_trait("test::regex_a", r"\bpopen\b");
        t1.r#for = vec![RuleFileType::Python];
        t1.defined_in = std::path::PathBuf::from("traits/test/a.yaml");
        t1.r#if.count_min = Some(10);
        t1.r#if.per_kb_min = Some(0.05);

        let mut t2 = make_regex_trait("test::regex_b", r"\bpopen\b");
        t2.r#for = vec![RuleFileType::Python];
        t2.defined_in = std::path::PathBuf::from("traits/test/b.yaml");
        t2.r#if.count_min = Some(20);
        t2.r#if.per_kb_min = Some(0.10);

        let traits = vec![t1, t2];
        let mut warnings = Vec::new();
        check_overlapping_regex_patterns(&traits, &mut warnings);

        assert!(warnings.is_empty());
    }
}

/// Cached regex pattern for extracting prefix from regex patterns
#[allow(clippy::expect_used)] // Static regex pattern is hardcoded and valid
fn prefix_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^(\^?)([a-zA-Z_][a-zA-Z0-9_-]*)(.*)$").expect("valid regex"))
}

#[allow(clippy::expect_used)] // Static regex pattern is hardcoded and valid
fn overlapping_alternations_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\([^)]*\.\*\|[^)]*\.\*\)").expect("valid regex"))
}

#[allow(clippy::expect_used)] // Static regex pattern is hardcoded and valid
fn greedy_range_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    // Flag all unbounded ranges (.{n,}) — bounded ranges (.{n,m}) have a known cost ceiling
    RE.get_or_init(|| regex::Regex::new(r"\.\{[0-9]+,\}").expect("valid regex"))
}

#[allow(clippy::expect_used)] // Static regex pattern is hardcoded and valid
fn large_range_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\.\{([0-9]+),([0-9]*)\}").expect("valid regex"))
}

/// Detect regex patterns that may cause catastrophic backtracking
///
/// Patterns with nested quantifiers or alternations with overlapping prefixes
/// can cause exponential runtime on certain inputs. This validates patterns
/// for common backtracking pitfalls.
pub(crate) fn find_slow_regex_patterns(traits: &[TraitDefinition], warnings: &mut Vec<String>) {
    for trait_def in traits {
        let pattern_opt = match &trait_def.r#if.condition {
            Condition::Raw {
                regex: Some(ref regex_str),
                case_insensitive,
                ..
            } => Some((regex_str.clone(), *case_insensitive)),
            _ => None,
        };

        if let Some((pattern, _ci)) = pattern_opt {
            let mut issues = Vec::new();

            // Check for overlapping alternations with wildcards like (a.*|ab.*)
            if overlapping_alternations_regex().is_match(&pattern) {
                issues.push("alternation with multiple .* patterns may cause backtracking");
            }

            // Check for patterns with unbounded .{n,} followed by complex matching
            // (bounded .{n,m} is acceptable — the upper bound limits cost)
            if greedy_range_regex().is_match(&pattern) {
                issues.push("open-ended range quantifier (.{n,}) — use a bounded range like .{0,50} instead");
            }

            // Check for very large ranges that could match huge spans
            if let Some(caps) = large_range_regex().captures(&pattern) {
                if let Ok(min) = caps[1].parse::<usize>() {
                    if min > 1000 {
                        issues.push(
                            "very large range quantifier (>{1000}) may cause performance issues",
                        );
                    }
                }
            }

            if !issues.is_empty() {
                let source_file = trait_def.defined_in.to_str().unwrap_or("unknown").to_string();

                let line_hint = find_line_number(&source_file, &trait_def.id);
                let location = if let Some(line) = line_hint {
                    format!("{}:{}", source_file, line)
                } else {
                    source_file
                };

                warnings.push(format!(
                    "Regex performance: trait '{}' in {} has potentially slow pattern '{}': {}",
                    trait_def.id,
                    location,
                    pattern,
                    issues.join(", ")
                ));
            }
        }
    }
}
