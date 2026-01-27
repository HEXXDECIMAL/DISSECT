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
                    index.by_file_type.entry(ft.clone()).or_default().push(i);
                }
            }
        }

        index
    }

    /// Get trait indices applicable to a given file type
    pub(crate) fn get_applicable(&self, file_type: &RuleFileType) -> impl Iterator<Item = usize> + '_ {
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
/// Pre-computes an automaton from all exact string patterns in traits,
/// enabling single-pass matching across thousands of patterns.
#[derive(Clone, Default)]
pub(crate) struct StringMatchIndex {
    /// Aho-Corasick automaton for all exact string patterns (case-sensitive)
    automaton: Option<AhoCorasick>,
    /// Maps pattern index -> trait indices that use this pattern
    pattern_to_traits: Vec<Vec<usize>>,
    /// Maps pattern index -> the pattern string (for evidence)
    patterns: Vec<String>,
    /// Total number of traits with exact string patterns
    pub(crate) total_patterns: usize,
}

impl StringMatchIndex {
    /// Build the string match index from trait definitions.
    /// Extracts all exact string patterns (case-sensitive only) and builds an AC automaton.
    pub(crate) fn build(traits: &[TraitDefinition]) -> Self {
        let mut patterns: Vec<String> = Vec::new();
        let mut pattern_to_traits: Vec<Vec<usize>> = Vec::new();
        let mut pattern_map: FxHashMap<String, usize> = FxHashMap::default();

        for (trait_idx, trait_def) in traits.iter().enumerate() {
            // Extract exact string pattern if present
            if let Condition::String {
                exact: Some(ref exact_str),
                case_insensitive: false,
                ..
            } = trait_def.r#if
            {
                // Check if we already have this pattern
                if let Some(&pattern_idx) = pattern_map.get(exact_str) {
                    pattern_to_traits[pattern_idx].push(trait_idx);
                } else {
                    // New pattern
                    let pattern_idx = patterns.len();
                    pattern_map.insert(exact_str.clone(), pattern_idx);
                    patterns.push(exact_str.clone());
                    pattern_to_traits.push(vec![trait_idx]);
                }
            }
        }

        let total_patterns = patterns.len();

        // Build Aho-Corasick automaton if we have patterns
        let automaton = if !patterns.is_empty() {
            AhoCorasick::builder()
                .ascii_case_insensitive(false)
                .build(&patterns)
                .ok()
        } else {
            None
        };

        Self {
            automaton,
            pattern_to_traits,
            patterns,
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
    ) -> (
        FxHashSet<usize>,
        FxHashMap<usize, Vec<Evidence>>,
    ) {
        let mut matching_traits = FxHashSet::default();
        let mut trait_evidence: FxHashMap<usize, Vec<Evidence>> =
            FxHashMap::default();

        if let Some(ref ac) = self.automaton {
            for string_info in strings {
                for mat in ac.find_iter(&string_info.value) {
                    let pattern_idx = mat.pattern().as_usize();
                    if let Some(trait_indices) = self.pattern_to_traits.get(pattern_idx) {
                        let pattern = &self.patterns[pattern_idx];
                        for &trait_idx in trait_indices {
                            matching_traits.insert(trait_idx);
                            // Cache evidence for this trait
                            trait_evidence.entry(trait_idx).or_default().push(
                                Evidence {
                                    method: "string".to_string(),
                                    source: "string_extractor".to_string(),
                                    value: pattern.clone(),
                                    location: string_info.offset.clone(),
                                },
                            );
                        }
                    }
                }
            }
        }

        (matching_traits, trait_evidence)
    }
}

/// Index for regex patterns that require raw content searching.
/// Enables single-pass RegexSet matching for search_raw: true traits with regex patterns.
#[derive(Clone, Default)]
pub(crate) struct RawContentRegexIndex {
    /// RegexSet for all regex patterns with search_raw: true
    regex_set: Option<RegexSet>,
    /// Maps regex index -> trait indices that use this pattern
    pattern_to_traits: Vec<Vec<usize>>,
    /// Total number of traits with raw content regex patterns
    pub(crate) total_patterns: usize,
}

impl RawContentRegexIndex {
    pub(crate) fn build(traits: &[TraitDefinition]) -> Self {
        let mut patterns: Vec<String> = Vec::new();
        let mut pattern_to_traits: Vec<Vec<usize>> = Vec::new();
        let mut pattern_map: FxHashMap<String, usize> = FxHashMap::default();

        for (trait_idx, trait_def) in traits.iter().enumerate() {
            // Extract regex patterns WITH search_raw: true
            let pattern_opt = match &trait_def.r#if {
                Condition::String {
                    regex: Some(ref regex_str),
                    search_raw: true,
                    case_insensitive,
                    ..
                } => {
                    Some(if *case_insensitive {
                        format!("(?i){}", regex_str)
                    } else {
                        regex_str.clone()
                    })
                }
                Condition::String {
                    word: Some(ref word_str),
                    search_raw: true,
                    case_insensitive,
                    ..
                } => {
                    Some(if *case_insensitive {
                        format!("(?i)\\b{}\\b", regex::escape(word_str))
                    } else {
                        format!("\\b{}\\b", regex::escape(word_str))
                    })
                }
                _ => None,
            };

            if let Some(pattern) = pattern_opt {
                if let Some(&pattern_idx) = pattern_map.get(&pattern) {
                    pattern_to_traits[pattern_idx].push(trait_idx);
                } else {
                    let pattern_idx = patterns.len();
                    pattern_map.insert(pattern.clone(), pattern_idx);
                    patterns.push(pattern);
                    pattern_to_traits.push(vec![trait_idx]);
                }
            }
        }

        let total_patterns = patterns.len();
        let regex_set = if !patterns.is_empty() {
            RegexSet::new(&patterns).ok()
        } else {
            None
        };

        Self {
            regex_set,
            pattern_to_traits,
            total_patterns,
        }
    }

    pub(crate) fn has_patterns(&self) -> bool {
        self.total_patterns > 0
    }

    pub(crate) fn find_matches(&self, binary_data: &[u8]) -> FxHashSet<usize> {
        let mut matching_traits = FxHashSet::default();

        if let Some(ref regex_set) = self.regex_set {
            if let Ok(content) = std::str::from_utf8(binary_data) {
                for pattern_idx in regex_set.matches(content).iter() {
                    if let Some(trait_indices) = self.pattern_to_traits.get(pattern_idx) {
                        for &trait_idx in trait_indices {
                            matching_traits.insert(trait_idx);
                        }
                    }
                }
            }
        }

        matching_traits
    }
}
