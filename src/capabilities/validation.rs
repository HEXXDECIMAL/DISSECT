//! Rule validation and complexity analysis.
//!
//! This module provides validation functions for trait definitions and composite rules:
//! - Complexity calculation for composite rules (recursive trait reference expansion)
//! - Validation of HOSTILE composite rules (must meet complexity threshold)
//! - Validation that composite rules only contain trait references (not inline primitives)
//! - Auto-prefixing of trait references based on file path

use crate::composite_rules::{
    CompositeTrait, Condition, FileType as RuleFileType, Platform, TraitDefinition,
};
use crate::types::Criticality;
use std::collections::{HashMap, HashSet};

use super::parsing::parse_file_types;

/// Calculate the complexity of a trait definition
/// Counts all filters/conditions that make the trait more precise
fn calculate_trait_complexity(trait_def: &TraitDefinition) -> usize {
    let mut complexity = 0;

    // Base condition (pattern match, string search, etc.)
    complexity += 1;

    // Size restrictions add precision
    if trait_def.size_min.is_some() {
        complexity += 1;
    }
    if trait_def.size_max.is_some() {
        complexity += 1;
    }

    // Platform filter (if not All)
    if !trait_def.platforms.contains(&Platform::All) {
        complexity += 1;
    }

    // File type filter (if not All)
    if !trait_def
        .r#for
        .iter()
        .any(|ft| matches!(ft, RuleFileType::All))
    {
        complexity += 1;
    }

    // Exception filters (not clause)
    if trait_def.not.is_some() {
        complexity += 1;
    }

    // Conditional skip (unless clause)
    if trait_def.unless.is_some() {
        complexity += 1;
    }

    complexity
}

/// Calculate the complexity of a composite rule or trait
///
/// Complexity is a measure of precision - how many filters/constraints the rule has.
/// This RECURSIVELY counts ALL filters across the entire rule tree:
/// - Base trait: pattern + size_min + size_max + platform + file_type + not + unless
/// - Composite: file_type + recursively expanded all/any/none/unless clauses
///
/// IMPORTANT: This is the ONLY place in the codebase for measuring rule complexity/precision.
/// Do not duplicate this logic elsewhere.
pub fn calculate_composite_complexity(
    rule_id: &str,
    all_composites: &[CompositeTrait],
    all_traits: &[TraitDefinition],
    cache: &mut HashMap<String, usize>,
    visiting: &mut HashSet<String>,
) -> usize {
    if let Some(&complexity) = cache.get(rule_id) {
        return complexity;
    }

    // Detect cycles
    if !visiting.insert(rule_id.to_string()) {
        return 1;
    }

    // Try to find as composite rule first
    if let Some(rule) = all_composites.iter().find(|r| r.id == rule_id) {
        let mut complexity = 0;

        // File type filter counts as 1 if it's specific
        if !rule.r#for.contains(&RuleFileType::All) {
            complexity += 1;
        }

        // `all` clause: recursively sum all elements
        if let Some(ref conditions) = rule.all {
            for cond in conditions {
                match cond {
                    Condition::Trait { id } => {
                        // Recursively calculate trait/composite complexity
                        complexity += calculate_composite_complexity(
                            id,
                            all_composites,
                            all_traits,
                            cache,
                            visiting,
                        );
                    }
                    _ => {
                        // Direct condition (string, symbol, etc.)
                        complexity += 1;
                    }
                }
            }
        }

        // `any` clause: use count requirement, recursively expand for single trait
        if let Some(ref conditions) = rule.any {
            let count = rule.count_exact.or(rule.count_min).unwrap_or(1);

            // If it's a single trait reference, expand it and multiply by count
            if conditions.len() == 1 {
                if let Condition::Trait { id } = &conditions[0] {
                    let trait_complexity = calculate_composite_complexity(
                        id,
                        all_composites,
                        all_traits,
                        cache,
                        visiting,
                    );
                    complexity += trait_complexity * count;
                } else {
                    // Single direct condition
                    complexity += count;
                }
            } else {
                // Multiple conditions in any - add the count requirement
                complexity += count;
            }
        }

        // `none` or `unless` clauses count as 1 for complexity
        if rule.none.is_some() {
            complexity += 1;
        }
        if rule.unless.is_some() {
            complexity += 1;
        }

        visiting.remove(rule_id);
        cache.insert(rule_id.to_string(), complexity);
        return complexity;
    }

    // Not a composite - try to find as a trait definition
    if let Some(trait_def) = all_traits.iter().find(|t| t.id == rule_id) {
        let complexity = calculate_trait_complexity(trait_def);
        visiting.remove(rule_id);
        cache.insert(rule_id.to_string(), complexity);
        return complexity;
    }

    // Not found - treat as external/unknown trait (count as 1)
    visiting.remove(rule_id);
    cache.insert(rule_id.to_string(), 1);
    1
}

/// Validate and downgrade HOSTILE composite rules that don't meet complexity requirements
pub(crate) fn validate_hostile_composite_complexity(
    composite_rules: &mut [CompositeTrait],
    trait_definitions: &[TraitDefinition],
) {
    let mut cache: HashMap<String, usize> = HashMap::new();

    // First pass: calculate complexity for all HOSTILE rules (immutable borrow)
    let hostile_complexities: Vec<(String, usize)> = composite_rules
        .iter()
        .filter(|rule| rule.crit == Criticality::Hostile)
        .map(|rule| {
            let mut visiting = std::collections::HashSet::new();
            let complexity = calculate_composite_complexity(
                &rule.id,
                composite_rules,
                trait_definitions,
                &mut cache,
                &mut visiting,
            );
            (rule.id.clone(), complexity)
        })
        .collect();

    // Second pass: downgrade rules that don't meet requirements (mutable borrow)
    for (rule_id, complexity) in hostile_complexities {
        if complexity < 4 {
            if let Some(rule) = composite_rules.iter_mut().find(|r| r.id == rule_id) {
                eprintln!(
                    "⚠️  WARNING: Composite trait '{}' is marked HOSTILE but has complexity {} (need >=4). Downgrading to SUSPICIOUS.",
                    rule_id, complexity
                );
                rule.crit = Criticality::Suspicious;
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
/// If a trait reference doesn't contain '/', prepend the given prefix
pub(crate) fn autoprefix_trait_refs(rule: &mut CompositeTrait, prefix: &str) {
    fn prefix_conditions(conditions: &mut [Condition], prefix: &str) {
        for cond in conditions {
            if let Condition::Trait { id } = cond {
                // Only prefix if ID doesn't already contain '/' (i.e., it's local to this file)
                if !id.contains('/') {
                    *id = format!("{}/{}", prefix, id);
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
            regex: Some(rule.symbol),
            platforms: None,
            compiled_regex: None,
        }]),
        any: None,
        count_exact: None,
        count_min: None,
        count_max: None,
        none: None,
        unless: None,
        not: None,
    }
}
