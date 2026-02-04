//! Performance optimization indices for fast trait matching.
//!
//! This module provides specialized indices for efficient trait lookup and matching:
//! - `TraitIndex`: Fast trait lookup by file type
//! - `StringMatchIndex`: Batched string matching using Aho-Corasick automaton
//! - `RawContentRegexIndex`: Batched regex matching for binary content

use crate::composite_rules::{Condition, FileType as RuleFileType, TraitDefinition};
use crate::types::{Evidence, StringInfo};
use aho_corasick::AhoCorasick;
use regex::RegexSet;
use rustc_hash::{FxHashMap, FxHashSet};

/// Index of trait indices by file type for fast lookup.
/// Maps FileType -> Vec of indices into trait_definitions.
#[derive(Clone, Default)]
pub(crate) struct TraitIndex {
    /// Traits that apply to each specific file type
    by_file_type: FxHashMap<RuleFileType, Vec<usize>>,
    /// Traits that apply to all file types (Platform::All)
    universal: Vec<usize>,
}

impl TraitIndex {
    pub(crate) fn new() -> Self {
        Self {
            by_file_type: FxHashMap::default(),
            universal: Vec::new(),
        }
    }

    /// Build index from trait definitions
    pub(crate) fn build(traits: &[TraitDefinition]) -> Self {
        let mut index = Self::new();

        for (i, trait_def) in traits.iter().enumerate() {
            let has_all = trait_def.r#for.contains(&RuleFileType::All);

            if has_all {
                // Trait applies to all file types
                index.universal.push(i);
            } else {
                // Trait applies to specific file types
                for ft in &trait_def.r#for {
                    index.by_file_type.entry(*ft).or_default().push(i);
                }
            }
        }

        index
    }

    /// Get trait indices applicable to a given file type
    pub(crate) fn get_applicable(
        &self,
        file_type: &RuleFileType,
    ) -> impl Iterator<Item = usize> + '_ {
        // Universal traits + specific file type traits
        let specific = self
            .by_file_type
            .get(file_type)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);

        self.universal
            .iter()
            .copied()
            .chain(specific.iter().copied())
    }

    /// Get count of applicable traits for a file type
    #[allow(dead_code)]
    pub(crate) fn applicable_count(&self, file_type: &RuleFileType) -> usize {
        let specific_count = self
            .by_file_type
            .get(file_type)
            .map(|v: &Vec<usize>| v.len())
            .unwrap_or(0);
        self.universal.len() + specific_count
    }
}

/// Index for fast batched string matching using Aho-Corasick.
/// Pre-computes automatons from all exact string patterns in traits,
/// enabling single-pass matching across thousands of patterns.
#[derive(Clone, Default)]
pub(crate) struct StringMatchIndex {
    /// Aho-Corasick automaton for case-sensitive exact string patterns
    automaton: Option<AhoCorasick>,
    /// Maps pattern index -> trait indices that use this pattern
    pattern_to_traits: Vec<Vec<usize>>,
    /// Maps pattern index -> the pattern string (for evidence)
    patterns: Vec<String>,
    /// Aho-Corasick automaton for case-insensitive exact string patterns
    ci_automaton: Option<AhoCorasick>,
    /// Maps CI pattern index -> trait indices
    ci_pattern_to_traits: Vec<Vec<usize>>,
    /// Maps CI pattern index -> the pattern string (for evidence)
    ci_patterns: Vec<String>,
    /// Aho-Corasick automaton for regex literal prefixes (for pre-filtering)
    regex_literal_automaton: Option<AhoCorasick>,
    /// Maps regex literal index -> trait indices
    regex_literal_to_traits: Vec<Vec<usize>>,
    /// Set of all trait indices with regex patterns (for lookup)
    regex_trait_indices: FxHashSet<usize>,
    /// Total number of traits with exact string patterns
    pub(crate) total_patterns: usize,
}

impl StringMatchIndex {
    /// Extract the literal prefix from a regex pattern.
    /// Returns None if no useful literal can be extracted (pattern starts with metachar).
    fn extract_regex_literal(pattern: &str) -> Option<String> {
        let mut literal = String::new();
        let chars = pattern.chars().peekable();
        let mut in_escape = false;

        for c in chars {
            if in_escape {
                // Handle escaped characters
                match c {
                    // Common escapes that represent literals
                    's' | 'S' | 'd' | 'D' | 'w' | 'W' | 'b' | 'B' => break, // meta escapes
                    '.' | '*' | '+' | '?' | '[' | ']' | '(' | ')' | '{' | '}' | '|' | '^' | '$'
                    | '\\' => {
                        literal.push(c);
                    }
                    _ => literal.push(c),
                }
                in_escape = false;
            } else if c == '\\' {
                in_escape = true;
            } else if c.is_alphanumeric() || c == '_' || c == '-' || c == '/' || c == '.' {
                literal.push(c);
            } else {
                // Hit a metacharacter, stop
                break;
            }
        }

        // Return literal if it's at least 3 chars (useful for filtering)
        if literal.len() >= 3 {
            Some(literal)
        } else {
            None
        }
    }

    /// Build the string match index from trait definitions.
    /// Extracts all exact string patterns and builds AC automatons (case-sensitive and case-insensitive).
    pub(crate) fn build(traits: &[TraitDefinition]) -> Self {
        let mut patterns: Vec<String> = Vec::new();
        let mut pattern_to_traits: Vec<Vec<usize>> = Vec::new();
        let mut pattern_map: FxHashMap<String, usize> = FxHashMap::default();

        let mut ci_patterns: Vec<String> = Vec::new();
        let mut ci_pattern_to_traits: Vec<Vec<usize>> = Vec::new();
        let mut ci_pattern_map: FxHashMap<String, usize> = FxHashMap::default();

        let mut regex_literals: Vec<String> = Vec::new();
        let mut regex_literal_to_traits: Vec<Vec<usize>> = Vec::new();
        let mut regex_literal_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut regex_trait_indices: FxHashSet<usize> = FxHashSet::default();

        for (trait_idx, trait_def) in traits.iter().enumerate() {
            match &trait_def.r#if {
                // Exact string patterns
                Condition::String {
                    exact: Some(ref exact_str),
                    case_insensitive,
                    ..
                } => {
                    if *case_insensitive {
                        let lower = exact_str.to_lowercase();
                        if let Some(&pattern_idx) = ci_pattern_map.get(&lower) {
                            ci_pattern_to_traits[pattern_idx].push(trait_idx);
                        } else {
                            let pattern_idx = ci_patterns.len();
                            ci_pattern_map.insert(lower, pattern_idx);
                            ci_patterns.push(exact_str.clone());
                            ci_pattern_to_traits.push(vec![trait_idx]);
                        }
                    } else if let Some(&pattern_idx) = pattern_map.get(exact_str) {
                        pattern_to_traits[pattern_idx].push(trait_idx);
                    } else {
                        let pattern_idx = patterns.len();
                        pattern_map.insert(exact_str.clone(), pattern_idx);
                        patterns.push(exact_str.clone());
                        pattern_to_traits.push(vec![trait_idx]);
                    }
                }
                // Regex string patterns - extract literal prefix for pre-filtering
                Condition::String {
                    regex: Some(ref regex_str),
                    ..
                } => {
                    regex_trait_indices.insert(trait_idx);
                    if let Some(literal) = Self::extract_regex_literal(regex_str) {
                        if let Some(&pattern_idx) = regex_literal_map.get(&literal) {
                            regex_literal_to_traits[pattern_idx].push(trait_idx);
                        } else {
                            let pattern_idx = regex_literals.len();
                            regex_literal_map.insert(literal.clone(), pattern_idx);
                            regex_literals.push(literal);
                            regex_literal_to_traits.push(vec![trait_idx]);
                        }
                    }
                }
                _ => {}
            }
        }

        let total_patterns = patterns.len() + ci_patterns.len();

        // Build case-sensitive Aho-Corasick automaton
        let automaton = if !patterns.is_empty() {
            AhoCorasick::builder()
                .ascii_case_insensitive(false)
                .build(&patterns)
                .ok()
        } else {
            None
        };

        // Build case-insensitive Aho-Corasick automaton
        let ci_automaton = if !ci_patterns.is_empty() {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&ci_patterns)
                .ok()
        } else {
            None
        };

        // Build regex literal automaton for pre-filtering
        let regex_literal_automaton = if !regex_literals.is_empty() {
            AhoCorasick::builder()
                .ascii_case_insensitive(false)
                .build(&regex_literals)
                .ok()
        } else {
            None
        };

        Self {
            automaton,
            pattern_to_traits,
            patterns,
            ci_automaton,
            ci_pattern_to_traits,
            ci_patterns,
            regex_literal_automaton,
            regex_literal_to_traits,
            regex_trait_indices,
            total_patterns,
        }
    }

    /// Returns true if the index has patterns to match
    pub(crate) fn has_patterns(&self) -> bool {
        self.total_patterns > 0
    }

    /// Find matching traits with cached evidence.
    /// Returns trait indices AND the evidence (matched patterns + offsets) for each.
    /// This avoids re-iterating strings during trait evaluation.
    pub(crate) fn find_matches_with_evidence(
        &self,
        strings: &[StringInfo],
    ) -> (FxHashSet<usize>, FxHashMap<usize, Vec<Evidence>>) {
        let mut matching_traits = FxHashSet::default();
        let mut trait_evidence: FxHashMap<usize, Vec<Evidence>> = FxHashMap::default();

        // Case-sensitive matching
        if let Some(ref ac) = self.automaton {
            for string_info in strings {
                for mat in ac.find_iter(&string_info.value) {
                    let pattern_idx = mat.pattern().as_usize();
                    if let Some(trait_indices) = self.pattern_to_traits.get(pattern_idx) {
                        let pattern = &self.patterns[pattern_idx];
                        for &trait_idx in trait_indices {
                            matching_traits.insert(trait_idx);
                            // Cache evidence for this trait
                            trait_evidence.entry(trait_idx).or_default().push(Evidence {
                                method: "string".to_string(),
                                source: "string_extractor".to_string(),
                                value: pattern.clone(),
                                location: string_info.offset.clone(),
                            });
                        }
                    }
                }
            }
        }

        // Case-insensitive matching
        if let Some(ref ac) = self.ci_automaton {
            for string_info in strings {
                for mat in ac.find_iter(&string_info.value) {
                    let pattern_idx = mat.pattern().as_usize();
                    if let Some(trait_indices) = self.ci_pattern_to_traits.get(pattern_idx) {
                        let pattern = &self.ci_patterns[pattern_idx];
                        for &trait_idx in trait_indices {
                            matching_traits.insert(trait_idx);
                            trait_evidence.entry(trait_idx).or_default().push(Evidence {
                                method: "string".to_string(),
                                source: "string_extractor".to_string(),
                                value: pattern.clone(),
                                location: string_info.offset.clone(),
                            });
                        }
                    }
                }
            }
        }

        (matching_traits, trait_evidence)
    }

    /// Find regex traits that MIGHT match based on literal prefix matching.
    /// Returns trait indices whose regex patterns had their literal prefix found.
    /// Traits not in this set can be skipped without running the full regex.
    pub(crate) fn find_regex_candidates(&self, strings: &[StringInfo]) -> FxHashSet<usize> {
        let mut candidates = FxHashSet::default();

        if let Some(ref ac) = self.regex_literal_automaton {
            for string_info in strings {
                for mat in ac.find_iter(&string_info.value) {
                    let pattern_idx = mat.pattern().as_usize();
                    if let Some(trait_indices) = self.regex_literal_to_traits.get(pattern_idx) {
                        for &trait_idx in trait_indices {
                            candidates.insert(trait_idx);
                        }
                    }
                }
            }
        }

        // Traits without extractable literals can't be pre-filtered, so include them
        for &trait_idx in &self.regex_trait_indices {
            // If this trait isn't in any literal bucket, include it as candidate
            let has_literal = self
                .regex_literal_to_traits
                .iter()
                .any(|traits| traits.contains(&trait_idx));
            if !has_literal {
                candidates.insert(trait_idx);
            }
        }

        candidates
    }

    /// Check if a trait has a regex string pattern
    pub(crate) fn is_regex_trait(&self, trait_idx: usize) -> bool {
        self.regex_trait_indices.contains(&trait_idx)
    }
}

/// Index for regex patterns from `type: content` conditions.
/// Builds per-file-type RegexSets to avoid running irrelevant patterns.
#[derive(Clone, Default)]
pub(crate) struct RawContentRegexIndex {
    /// Per-file-type regex sets for targeted matching
    by_file_type: FxHashMap<RuleFileType, FileTypeRegexSet>,
    /// Universal patterns that apply to all file types
    universal: Option<FileTypeRegexSet>,
    /// Set of all trait indices that have content regex patterns (for quick lookup)
    indexed_traits: FxHashSet<usize>,
    /// Total number of traits with raw content regex patterns
    pub(crate) total_patterns: usize,
}

/// Regex set for a specific file type
#[derive(Clone)]
struct FileTypeRegexSet {
    regex_set: RegexSet,
    pattern_to_traits: Vec<Vec<usize>>,
}

impl RawContentRegexIndex {
    pub(crate) fn build(traits: &[TraitDefinition]) -> Self {
        // Group patterns by file type
        let mut by_file_type: FxHashMap<RuleFileType, Vec<(String, usize)>> = FxHashMap::default();
        let mut universal_patterns: Vec<(String, usize)> = Vec::new();
        let mut indexed_traits = FxHashSet::default();
        let mut total_patterns = 0;

        for (trait_idx, trait_def) in traits.iter().enumerate() {
            // Extract regex patterns from Content traits
            let pattern_opt = match &trait_def.r#if {
                Condition::Content {
                    regex: Some(ref regex_str),
                    case_insensitive,
                    ..
                } => Some(if *case_insensitive {
                    format!("(?i){}", regex_str)
                } else {
                    regex_str.clone()
                }),
                Condition::Content {
                    word: Some(ref word_str),
                    case_insensitive,
                    ..
                } => Some(if *case_insensitive {
                    format!("(?i)\\b{}\\b", regex::escape(word_str))
                } else {
                    format!("\\b{}\\b", regex::escape(word_str))
                }),
                _ => None,
            };

            if let Some(pattern) = pattern_opt {
                indexed_traits.insert(trait_idx);
                total_patterns += 1;

                // Check if trait applies to all file types
                if trait_def.r#for.contains(&RuleFileType::All) {
                    universal_patterns.push((pattern, trait_idx));
                } else {
                    // Add to each specific file type
                    for ft in &trait_def.r#for {
                        by_file_type
                            .entry(*ft)
                            .or_default()
                            .push((pattern.clone(), trait_idx));
                    }
                }
            }
        }

        // Build regex sets for each file type
        let by_file_type: FxHashMap<RuleFileType, FileTypeRegexSet> = by_file_type
            .into_iter()
            .filter_map(|(ft, patterns)| Self::build_regex_set(patterns).map(|rs| (ft, rs)))
            .collect();

        let universal = Self::build_regex_set(universal_patterns);

        Self {
            by_file_type,
            universal,
            indexed_traits,
            total_patterns,
        }
    }

    fn build_regex_set(patterns: Vec<(String, usize)>) -> Option<FileTypeRegexSet> {
        if patterns.is_empty() {
            return None;
        }

        let (pattern_strs, trait_indices): (Vec<_>, Vec<_>) = patterns.into_iter().unzip();

        // Build pattern_to_traits mapping
        let pattern_to_traits: Vec<Vec<usize>> =
            trait_indices.into_iter().map(|idx| vec![idx]).collect();

        match RegexSet::new(&pattern_strs) {
            Ok(regex_set) => Some(FileTypeRegexSet {
                regex_set,
                pattern_to_traits,
            }),
            Err(e) => {
                eprintln!(
                    "warning: Failed to compile regex set ({} patterns): {}",
                    pattern_strs.len(),
                    e
                );
                None
            }
        }
    }

    pub(crate) fn has_patterns(&self) -> bool {
        self.total_patterns > 0
    }

    /// Check if any of the given trait indices have content regex patterns
    pub(crate) fn has_applicable_patterns(&self, applicable: &[usize]) -> bool {
        applicable
            .iter()
            .any(|idx| self.indexed_traits.contains(idx))
    }

    /// Find matches using only patterns applicable to the given file type
    pub(crate) fn find_matches(
        &self,
        binary_data: &[u8],
        file_type: &RuleFileType,
    ) -> FxHashSet<usize> {
        let mut matching_traits = FxHashSet::default();

        let content = match std::str::from_utf8(binary_data) {
            Ok(c) => c,
            Err(_) => return matching_traits,
        };

        // Match universal patterns
        if let Some(ref universal) = self.universal {
            for pattern_idx in universal.regex_set.matches(content).iter() {
                if let Some(trait_indices) = universal.pattern_to_traits.get(pattern_idx) {
                    for &trait_idx in trait_indices {
                        matching_traits.insert(trait_idx);
                    }
                }
            }
        }

        // Match file-type-specific patterns
        if let Some(ft_set) = self.by_file_type.get(file_type) {
            for pattern_idx in ft_set.regex_set.matches(content).iter() {
                if let Some(trait_indices) = ft_set.pattern_to_traits.get(pattern_idx) {
                    for &trait_idx in trait_indices {
                        matching_traits.insert(trait_idx);
                    }
                }
            }
        }

        matching_traits
    }
}
