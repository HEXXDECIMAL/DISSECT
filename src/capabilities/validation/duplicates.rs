//! Duplicate trait and pattern detection.
//!
//! This module detects various types of duplicates and redundancies in trait definitions:
//!
//! - **Atomic trait duplicates**: Traits with identical search parameters (if, platforms, for, not, unless)
//! - **Composite rule duplicates**: Rules with identical condition sets
//! - **String pattern duplicates**: Same normalized pattern appearing in multiple files with overlapping file types
//! - **Regex overlaps**: Regex patterns with shared alternatives or substring matches overlapping with exact patterns
//! - **Type conflicts**: Same pattern appearing as different condition types (string vs symbol vs raw)
//! - **String/content collisions**: Pattern appearing as both string and raw conditions with same criticality
//! - **For-only duplicates**: Traits identical except for the `for:` field, indicating mergeable rules
//! - **Alternation merge candidates**: Regex patterns differing only in first token case that could be combined

use crate::composite_rules::{CompositeTrait, Condition, FileType as RuleFileType, TraitDefinition};
use std::collections::{HashMap, HashSet};
use super::shared::{PatternLocation, MatchSignature};
use std::sync::OnceLock;

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
pub(crate) fn validate_regex_overlap_with_literal(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    use crate::types::Criticality;

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

/// Find traits where both `type: string` and `type: raw` exist for the same pattern
/// at the same criticality. These should be merged to just `raw` (which is broader).
/// Returns: Vec<(string_trait_id, raw_trait_id, pattern_description)>
#[must_use]
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
#[must_use]
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
#[must_use]
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

#[allow(clippy::expect_used)] // Static regex pattern is hardcoded and valid
fn prefix_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^(\^?)([a-zA-Z_][a-zA-Z0-9_-]*)(.*)$").expect("valid regex"))
}
