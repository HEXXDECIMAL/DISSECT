//! Core CapabilityMapper implementation.
//!
//! This module provides the main `CapabilityMapper` struct which:
//! - Loads capability definitions from YAML files
//! - Maps symbols to capability IDs
//! - Evaluates trait definitions and composite rules against analysis reports
//! - Provides platform and file type detection

// Removed: find_duplicate_words_in_path (disabled due to false positives)
use crate::composite_rules::{
    CompositeTrait, Condition, EvaluationContext, FileType as RuleFileType, Platform, SectionMap,
    TraitDefinition,
};
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
use anyhow::{Context, Result};
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use super::error_formatting::enhance_yaml_error;
use super::indexes::{RawContentRegexIndex, StringMatchIndex, TraitIndex};
use super::models::{TraitInfo, TraitMappings};
use super::parsing::{apply_composite_defaults, apply_trait_defaults};
use super::validation::{
    autoprefix_trait_refs, check_regex_or_overlapping_exact, check_regex_should_be_exact,
    check_same_string_different_types, collect_trait_refs_from_rule,
    find_alternation_merge_candidates, find_banned_directory_segments, find_cap_obj_violations,
    find_depth_violations, find_duplicate_second_level_directories,
    find_duplicate_traits_and_composites, find_empty_condition_clauses, find_for_only_duplicates,
    find_hostile_cap_rules, find_impossible_count_constraints, find_inert_obj_rules,
    find_malware_subcategory_violations, find_impossible_needs,
    find_impossible_size_constraints, find_invalid_trait_ids, find_line_number,
    find_missing_search_patterns, find_oversized_trait_directories, find_parent_duplicate_segments,
    find_overlapping_conditions, find_platform_named_directories, find_redundant_any_refs,
    find_redundant_needs_one, find_single_item_clauses, find_slow_regex_patterns,
    find_string_content_collisions,
    find_string_pattern_duplicates, precalculate_all_composite_precisions,
    simple_rule_to_composite_rule, validate_composite_trait_only,
    validate_hostile_composite_precision, MAX_TRAITS_PER_DIRECTORY,
};

/// Extract relative path from full path (relative to traits directory)
/// Returns None if path conversion fails
fn get_relative_source_file(path: &std::path::Path) -> Option<String> {
    // Try to find "traits/" in the path and return everything after it
    let path_str = path.to_string_lossy();
    if let Some(pos) = path_str.find("traits/") {
        let relative = &path_str[pos + 7..]; // Skip "traits/" prefix
        return Some(relative.to_string());
    }
    // Fallback: return the file name only if we can't find "traits/"
    path.file_name().and_then(|n| n.to_str()).map(std::string::ToString::to_string)
}

/// Maps symbols (function names, library calls) to capability IDs
/// Also supports trait definitions and composite rules that combine traits
#[derive(Clone, Debug)]
pub struct CapabilityMapper {
    symbol_map: HashMap<String, TraitInfo>,
    trait_definitions: Vec<TraitDefinition>,
    pub(crate) composite_rules: Vec<CompositeTrait>,
    /// Index for fast trait lookup by file type
    trait_index: TraitIndex,
    /// Index for fast batched string matching
    string_match_index: StringMatchIndex,
    /// Index for batched raw content regex matching
    raw_content_regex_index: RawContentRegexIndex,
    /// Platform filter(s) for rule evaluation (default: [All])
    platforms: Vec<Platform>,
}

impl CapabilityMapper {
    const DEFAULT_MIN_HOSTILE_PRECISION: f32 = 3.5;
    const DEFAULT_MIN_SUSPICIOUS_PRECISION: f32 = 2.0;

    /// Create an empty capability mapper for testing
    #[must_use] 
    pub(crate) fn empty() -> Self {
        Self {
            symbol_map: HashMap::new(),
            trait_definitions: Vec::new(),
            composite_rules: Vec::new(),
            trait_index: TraitIndex::new(),
            string_match_index: StringMatchIndex::default(),
            raw_content_regex_index: RawContentRegexIndex::default(),
            platforms: vec![Platform::All],
        }
    }

    /// Set the platform filter(s) for rule evaluation
    /// Pass vec![Platform::All] to match all platforms (default)
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn with_platforms(mut self, platforms: Vec<Platform>) -> Self {
        self.platforms = if platforms.is_empty() {
            vec![Platform::All]
        } else {
            platforms
        };
        self
    }

    /// Create a new mapper loading traits from the default capabilities directory or YAML file
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::new_with_precision_thresholds(
            Self::DEFAULT_MIN_HOSTILE_PRECISION,
            Self::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            true,
        )
    }

    /// Create a mapper with explicit precision thresholds for hostile/suspicious findings
    #[must_use]
    pub(crate) fn new_with_precision_thresholds(
        min_hostile_precision: f32,
        min_suspicious_precision: f32,
        enable_full_validation: bool,
    ) -> Self {
        // Try to load from capabilities directory, fall back to single file
        // YAML parse errors or invalid trait configurations are fatal
        let traits_dir = crate::cache::traits_path();
        match Self::from_directory_with_precision_thresholds(
            &traits_dir,
            min_hostile_precision,
            min_suspicious_precision,
            enable_full_validation,
        ) {
            Ok(mapper) => {
                return mapper;
            },
            Err(e) => {
                // Check if this is a YAML parse error or invalid configuration
                // These are fatal and should exit immediately with clear error message
                let error_chain = format!("{:#}", e);
                if error_chain.contains("Failed to parse YAML")
                    || error_chain.contains("invalid condition")
                {
                    eprintln!("\n❌ ERROR: Invalid trait configuration file\n");
                    eprintln!("   {}", error_chain);
                    eprintln!();
                    std::process::exit(1);
                }
                // Always show non-parse errors
                eprintln!(
                    "⚠️  Failed to load from {} directory: {:#}",
                    traits_dir.display(),
                    e
                );
            },
        }

        match Self::from_yaml_with_precision_thresholds(
            "capabilities.yaml",
            min_hostile_precision,
            min_suspicious_precision,
            enable_full_validation,
        ) {
            Ok(mapper) => {
                return mapper;
            },
            Err(e) => {
                // Check if this is a YAML parse error - fatal
                let error_chain = format!("{:#}", e);
                if error_chain.contains("Failed to parse") {
                    eprintln!("\n❌ ERROR: Invalid capabilities.yaml file\n");
                    for (i, cause) in e.chain().enumerate() {
                        if i == 0 {
                            eprintln!("   Error: {}", cause);
                        } else {
                            eprintln!("   Caused by: {}", cause);
                        }
                    }
                    eprintln!();
                    std::process::exit(1);
                }
                // Always show non-parse errors
                eprintln!("⚠️  Failed to load from capabilities.yaml: {:#}", e);
            },
        }

        eprintln!("\n❌ ERROR: Failed to load capabilities from any source");
        eprintln!("   Tried: traits/ directory, capabilities.yaml\n");
        std::process::exit(1);
    }

    /// Load capability mappings from directory of YAML files (recursively)
    #[allow(dead_code)] // Used in tests
    pub(crate) fn from_directory<P: AsRef<Path>>(dir_path: P) -> Result<Self> {
        Self::from_directory_with_precision_thresholds(
            dir_path,
            Self::DEFAULT_MIN_HOSTILE_PRECISION,
            Self::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            true,
        )
    }

    /// Load capability mappings from a directory of YAML files with explicit precision thresholds
    pub(crate) fn from_directory_with_precision_thresholds<P: AsRef<Path>>(
        dir_path: P,
        min_hostile_precision: f32,
        min_suspicious_precision: f32,
        enable_full_validation: bool,
    ) -> Result<Self> {
        let _span = tracing::info_span!("load_capabilities").entered();
        let debug = std::env::var("DISSECT_DEBUG").is_ok();
        let dir_path = dir_path.as_ref();
        let _t_start = std::time::Instant::now();

        // Check for DISSECT_VALIDATE env var or passed flag
        let enable_full_validation = enable_full_validation
            || std::env::var("DISSECT_VALIDATE").is_ok_and(|v| v == "1" || v == "true");

        tracing::info!("Loading trait definitions from {}", dir_path.display());
        if enable_full_validation {
            tracing::info!("Full validation enabled (this may take 60+ seconds)");
        } else {
            tracing::info!("Fast validation mode (validation disabled via --validate=false)");
        }
        if debug {
            eprintln!("🔍 Loading capabilities from: {}", dir_path.display());
        }

        // First, collect all YAML file paths
        tracing::debug!("Scanning directory for YAML files");
        let mut yaml_files: Vec<_> = walkdir::WalkDir::new(dir_path)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                let path = entry.path();
                if !path.is_file() || !path.extension().map(|e| e == "yaml").unwrap_or(false) {
                    return false;
                }
                let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
                !filename.to_lowercase().contains("readme") && !filename.starts_with("EXAMPLE")
            })
            .map(|entry| entry.path().to_path_buf())
            .collect();

        // Sort files deterministically by path string to ensure consistent loading order across OSes
        // Using string comparison instead of PathBuf comparison for true cross-platform consistency
        yaml_files.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));

        if yaml_files.is_empty() {
            anyhow::bail!("No YAML files found in {}", dir_path.display());
        }

        tracing::info!("Found {} YAML files to parse", yaml_files.len());
        let _t_parse = std::time::Instant::now();

        // Load all YAML files in parallel, preserving path for prefix calculation
        // Use indexed_map to preserve sorted order
        tracing::debug!("Parsing YAML files in parallel");
        let results: Vec<_> = yaml_files
            .par_iter()
            .enumerate()
            .map(|(idx, path)| {
                tracing::trace!("Parsing {}", path.display());
                if debug {
                    eprintln!("   📄 Loading: {}", path.display());
                }

                let bytes = fs::read(path).with_context(|| format!("Failed to read {:?}", path))?;
                let content = String::from_utf8_lossy(&bytes);

                // Check for meaningless YAML patterns before parsing
                let yaml_warnings = check_yaml_patterns(&content, path);

                let mappings: TraitMappings = serde_yaml::from_str(&content).map_err(|e| {
                    // Enhance YAML parsing errors with context and suggestions
                    let enhanced = enhance_yaml_error(&e.into(), path, &content);
                    anyhow::anyhow!("{}", enhanced)
                })?;

                Ok::<_, anyhow::Error>((idx, path.clone(), mappings, yaml_warnings))
            })
            .collect();

        // Sort results back to original order since par_iter doesn't preserve order
        let mut sorted_results: Vec<_> = results;
        sorted_results.sort_by_key(|r| match r {
            Ok((idx, _, _, _)) => *idx,
            Err(_) => usize::MAX,
        });

        tracing::debug!("Parsing complete");
        let _t_merge = std::time::Instant::now();

        // Merge all results, collecting errors to report all at once
        tracing::debug!("Merging trait definitions and composite rules");
        let mut symbol_map = HashMap::new();
        // Use HashMaps during loading for O(1) duplicate detection (will convert to Vec later)
        let mut trait_definitions_map: HashMap<String, TraitDefinition> = HashMap::new();
        let mut composite_rules_map: HashMap<String, CompositeTrait> = HashMap::new();
        let mut trait_source_files: HashMap<String, String> = HashMap::new(); // trait_id -> file_path
        let mut rule_source_files: HashMap<String, String> = HashMap::new(); // rule_id -> file_path
        let mut files_processed = 0;
        let mut warnings: Vec<String> = Vec::new();
        let mut parse_errors: Vec<String> = Vec::new();

        for result in sorted_results {
            let (path, mappings, yaml_warnings) = match result {
                Ok((_idx, p, m, w)) => (p, m, w),
                Err(e) => {
                    // Format error with full chain (includes filename from context)
                    parse_errors.push(format!("{:#}", e));
                    continue;
                },
            };
            files_processed += 1;

            // Collect YAML pattern warnings
            warnings.extend(yaml_warnings);

            // Calculate the prefix from the directory path relative to traits/
            // e.g., traits/credential/java/traits.yaml -> credential/java
            let trait_prefix = path
                .strip_prefix(dir_path)
                .ok()
                .and_then(|p| p.parent())
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .filter(|s| !s.is_empty());

            let before_symbols = symbol_map.len();
            let before_traits = trait_definitions_map.len();
            let before_composites = composite_rules_map.len();

            // Merge symbols
            for mapping in mappings.symbols {
                symbol_map.insert(
                    mapping.symbol.clone(),
                    TraitInfo {
                        id: mapping.capability,
                        desc: mapping.desc,
                        conf: mapping.conf,
                        crit: Criticality::Inert, // Legacy format defaults to Inert
                        mbc: None,                // Legacy format has no mbc field
                        attack: None,             // Legacy format has no attack field
                    },
                );
            }

            // Merge simple_rules
            let mut parsing_warnings = Vec::new();
            for rule in mappings.simple_rules {
                // If rule has platform or file_type constraints, convert to composite rule
                if !rule.platforms.is_empty() || !rule.file_types.is_empty() {
                    let composite = simple_rule_to_composite_rule(rule, &mut parsing_warnings);
                    composite_rules_map.insert(composite.id.clone(), composite);
                } else {
                    // No constraints - add to symbol map for fast lookup
                    symbol_map.insert(
                        rule.symbol.clone(),
                        TraitInfo {
                            id: rule.capability,
                            desc: rule.desc,
                            conf: rule.conf,
                            crit: Criticality::Inert, // Simple rules default to Inert
                            mbc: None,                // Simple rules have no mbc field
                            attack: None,             // Simple rules have no attack field
                        },
                    );
                }
            }

            // Add file path to unknown file type warnings, append others as-is
            let path_str = path.display().to_string();
            for warning in parsing_warnings {
                if warning.starts_with("Unknown file type") {
                    warnings.push(format!("{}: {}", path_str, warning));
                } else {
                    warnings.push(warning);
                }
            }

            // Merge trait definitions with auto-prefixed IDs, applying file-level defaults
            let mut parsing_warnings = Vec::new();
            for raw_trait in mappings.traits {
                // Convert raw trait to final trait, applying file-level defaults
                let mut trait_def = apply_trait_defaults(
                    raw_trait,
                    &mappings.defaults,
                    &mut parsing_warnings,
                    &path,
                );

                // Auto-prefix trait ID if it doesn't already have the path prefix
                // Uses :: as delimiter between directory path and trait name
                if let Some(ref prefix) = trait_prefix {
                    if !trait_def.id.starts_with(prefix)
                        && !trait_def.id.contains("::")
                        && !trait_def.id.contains('/')
                    {
                        trait_def.id = format!("{}::{}", prefix, trait_def.id);
                    }
                }
                // Validate YARA/AST conditions at load time
                trait_def
                    .r#if
                    .validate(&trait_def.id, enable_full_validation)
                    .map_err(|e| anyhow::anyhow!("{}", e))
                    .with_context(|| {
                        format!(
                            "invalid condition in trait '{}' from {:?}",
                            trait_def.id, path
                        )
                    })?;
                // Check for greedy regex patterns
                if let Some(warning) = trait_def.r#if.check_greedy_patterns(&trait_def.id) {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }
                // Check for word boundary regex patterns that should use type: word
                if let Some(warning) = trait_def.r#if.check_word_boundary_regex(&trait_def.id) {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for short case-insensitive patterns (high collision risk)
                if let Some(warning) =
                    trait_def.r#if.check_short_case_insensitive(trait_def.r#for.len())
                {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for improper use of not: field
                if let Some(warning) = trait_def.check_not_field_usage() {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for invalid criticality level
                if let Some(warning) = trait_def.check_criticality() {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for invalid confidence value
                if let Some(warning) = trait_def.check_confidence() {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for invalid size constraints
                if let Some(warning) = trait_def.check_size_constraints() {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for invalid count constraints in condition
                if let Some(warning) = trait_def.r#if.check_count_constraints(&trait_def.id) {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for invalid density constraints in condition
                if let Some(warning) = trait_def.r#if.check_density_constraints(&trait_def.id) {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for mutually exclusive match types in condition
                if let Some(warning) = trait_def.r#if.check_match_exclusivity(&trait_def.id) {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for empty patterns
                if let Some(warning) = trait_def.r#if.check_empty_patterns(&trait_def.id) {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for overly short patterns
                if let Some(warning) = trait_def.r#if.check_short_patterns(&trait_def.id) {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for literal strings used as regex
                if let Some(warning) = trait_def.r#if.check_literal_regex(&trait_def.id) {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for useless case_insensitive
                if let Some(warning) =
                    trait_def.r#if.check_case_insensitive_on_non_alpha(&trait_def.id)
                {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for count_min: 0
                if let Some(warning) = trait_def.r#if.check_count_min_value(&trait_def.id) {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for description quality
                if let Some(warning) = trait_def.check_description_quality() {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for empty not: array
                if let Some(warning) = trait_def.check_empty_not_array() {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for empty unless: array
                if let Some(warning) = trait_def.check_empty_unless_array() {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for ID conflicts with previously loaded traits (cross-file duplicates)
                if trait_definitions_map.contains_key(&trait_def.id) {
                    warnings.push(format!(
                        "Trait ID '{}' defined in multiple files - last definition wins",
                        trait_def.id
                    ));
                    // HashMap insert will automatically replace the old one
                }

                // Check for ID conflicts with composite rules
                if composite_rules_map.contains_key(&trait_def.id) {
                    warnings.push(format!(
                        "Rule ID '{}' defined as both trait and composite rule - trait will be used",
                        trait_def.id
                    ));
                    if let Some(comp_file) = rule_source_files.get(&trait_def.id) {
                        warnings.push(format!("  Trait: {}", path.display()));
                        warnings.push(format!("  Composite (will be replaced): {}", comp_file));
                    }
                    // Remove the composite rule
                    composite_rules_map.remove(&trait_def.id);
                }

                // Extract symbol mappings from trait definitions with symbol conditions
                // (Do this before inserting to avoid borrowing issues)
                if let Condition::Symbol {
                    exact,
                    substr: _,
                    regex,
                    platforms: _,
                    compiled_regex: _,
                    ..
                } = &trait_def.r#if.condition
                {
                    // If exact is specified, add it directly
                    if let Some(exact_val) = exact {
                        symbol_map.entry(exact_val.clone()).or_insert_with(|| TraitInfo {
                            id: trait_def.id.clone(),
                            desc: trait_def.desc.clone(),
                            conf: trait_def.conf,
                            crit: trait_def.crit,
                            mbc: trait_def.mbc.clone(),
                            attack: trait_def.attack.clone(),
                        });
                    }

                    // For each regex pattern (may contain "|" for alternatives)
                    if let Some(regex_val) = regex {
                        for symbol_pattern in regex_val.split('|') {
                            let symbol: String = symbol_pattern.trim().to_string();

                            // Only add if not already present (first match wins)
                            symbol_map.entry(symbol).or_insert_with(|| TraitInfo {
                                id: trait_def.id.clone(),
                                desc: trait_def.desc.clone(),
                                conf: trait_def.conf,
                                crit: trait_def.crit,
                                mbc: trait_def.mbc.clone(),
                                attack: trait_def.attack.clone(),
                            });
                        }
                    }
                }

                // Track source file for error reporting
                trait_source_files.insert(trait_def.id.clone(), path.display().to_string());
                trait_definitions_map.insert(trait_def.id.clone(), trait_def);
            }

            // Add file path to unknown file type warnings, append others as-is
            let path_str = path.display().to_string();
            for warning in parsing_warnings {
                if warning.starts_with("Unknown file type") {
                    warnings.push(format!("{}: {}", path_str, warning));
                } else {
                    warnings.push(warning);
                }
            }

            // Merge composite_rules with auto-prefixed IDs, applying file-level defaults
            let mut parsing_warnings = Vec::new();
            for raw_rule in mappings.composite_rules {
                // Convert raw rule to final rule, applying file-level defaults
                let mut rule = apply_composite_defaults(
                    raw_rule,
                    &mappings.defaults,
                    &mut parsing_warnings,
                    &path,
                );

                // Auto-prefix composite rule ID if it doesn't already have the path prefix
                if let Some(ref prefix) = trait_prefix {
                    // Auto-prefix composite rule ID using :: delimiter
                    if !rule.id.starts_with(prefix)
                        && !rule.id.contains("::")
                        && !rule.id.contains('/')
                    {
                        rule.id = format!("{}::{}", prefix, rule.id);
                    }
                    // Also auto-prefix trait references within the rule's conditions
                    autoprefix_trait_refs(&mut rule, prefix);
                }

                // Check for duplicate rule ID with other composite rules
                if composite_rules_map.contains_key(&rule.id) {
                    warnings.push(format!(
                        "Composite rule '{}' defined in multiple files - last definition wins",
                        rule.id
                    ));
                    // HashMap insert will automatically replace the old one
                }

                // Check for ID conflicts with trait definitions
                if trait_definitions_map.contains_key(&rule.id) {
                    warnings.push(format!(
                        "Rule ID '{}' defined as both trait and composite rule - composite will be used",
                        rule.id
                    ));
                    warnings.push("  Trait (will be replaced): (already loaded)".to_string());
                    warnings.push(format!("  Composite: {}", path.display()));
                    // Remove the trait definition
                    trait_definitions_map.remove(&rule.id);
                }

                // Track source file for error reporting
                rule_source_files.insert(rule.id.clone(), path.display().to_string());
                composite_rules_map.insert(rule.id.clone(), rule);
            }

            // Add file path to unknown file type warnings, append others as-is
            let path_str = path.display().to_string();
            for warning in parsing_warnings {
                if warning.starts_with("Unknown file type") {
                    warnings.push(format!("{}: {}", path_str, warning));
                } else {
                    warnings.push(warning);
                }
            }

            if debug {
                eprintln!(
                    "      +{} symbols, +{} traits, +{} composite rules",
                    symbol_map.len() - before_symbols,
                    trait_definitions_map.len() - before_traits,
                    composite_rules_map.len() - before_composites
                );
            }
        }

        // Check for unknown file types across all files
        let file_type_errors: Vec<&String> =
            warnings.iter().filter(|w| w.contains("Unknown file type")).collect();
        if !file_type_errors.is_empty() {
            // Sort and display errors (already include file paths)
            let mut sorted_errors: Vec<&str> =
                file_type_errors.iter().map(|e| e.as_str()).collect();
            sorted_errors.sort();

            return Err(anyhow::anyhow!(
                "Invalid file types found in trait files:\n  {}\n\nPlease fix these file type names in the YAML files.",
                sorted_errors.join("\n  ")
            ));
        }

        if debug {
            eprintln!("   ✅ Processed {} YAML files", files_processed);
        }

        let _t_yara = std::time::Instant::now();

        // Convert HashMaps to Vecs now that loading is complete
        // This was kept as HashMap during loading for O(1) duplicate detection
        let mut trait_definitions: Vec<TraitDefinition> =
            trait_definitions_map.into_values().collect();
        let mut composite_rules: Vec<CompositeTrait> = composite_rules_map.into_values().collect();

        // Register the combined-engine namespace for atomic traits whose top-level `if`
        // condition is `type: yara`.  These rules are compiled into the shared YaraEngine
        // (see `yara_engine::load_inline_trait_rules`), so we only need to record the
        // namespace here — actual compilation and scanning happen in the engine.
        let yara_count_traits = trait_definitions
            .iter()
            .filter(|t| matches!(t.r#if.condition, Condition::Yara { .. }))
            .count();

        trait_definitions.par_iter_mut().for_each(|t| {
            if matches!(t.r#if.condition, Condition::Yara { .. }) {
                // Set namespace for the combined engine; also compiles any `unless` YARA conditions.
                t.set_yara_if_namespace();
            }
        });

        // Composite rules still use per-condition compilation (they are rare and have
        // complex condition trees that are not currently in the combined engine).
        let yara_count_composite = composite_rules.len();
        composite_rules.par_iter_mut().for_each(|r| {
            r.compile_yara();
        });

        if debug && (yara_count_traits > 0 || yara_count_composite > 0) {
            eprintln!(
                "   ⚡ Registered {} inline YARA namespaces, compiled {} composite rules",
                yara_count_traits, yara_count_composite
            );
        }

        let _t_validate = std::time::Instant::now();

        // Track whether any fatal errors occurred (for deferred exit)
        let mut has_fatal_errors = false;

        // Pre-calculate precision for ALL composite rules once
        // Atomic trait precisions are already calculated during parsing
        tracing::debug!("Validating trait definitions and composite rules");
        if enable_full_validation {
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1/15: Pre-calculating composite rule precision");
            precalculate_all_composite_precisions(&mut composite_rules, &trait_definitions);
            tracing::debug!("Step 1 completed in {:?}", step_start.elapsed());

            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1b/15: Validating hostile composite precision");
            validate_hostile_composite_precision(
                &mut composite_rules,
                &trait_definitions,
                &mut warnings,
                min_hostile_precision,
                min_suspicious_precision,
            );
            tracing::debug!("Step 1b completed in {:?}", step_start.elapsed());

            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1c/15: Detecting duplicate traits and composites");
            find_duplicate_traits_and_composites(
                &trait_definitions,
                &composite_rules,
                &mut warnings,
            );
            tracing::debug!("Step 1c completed in {:?}", step_start.elapsed());

            // Detect string pattern duplicates and overlaps
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1d/15: Detecting string pattern duplicates and overlaps");
            find_string_pattern_duplicates(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1d completed in {:?}", step_start.elapsed());

            // Check for regex OR patterns overlapping with exact matches
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1e/15: Checking for regex OR patterns overlapping exact matches");
            check_regex_or_overlapping_exact(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1e completed in {:?}", step_start.elapsed());

            // Check for simple regex that should be exact
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1f/15: Checking for regex patterns that should be exact");
            check_regex_should_be_exact(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1f completed in {:?}", step_start.elapsed());

            // Check for same pattern with different types
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1g/15: Checking for patterns with conflicting types");
            check_same_string_different_types(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1g completed in {:?}", step_start.elapsed());

            // Detect potentially slow regex patterns that could cause catastrophic backtracking
            let step_start = std::time::Instant::now();
            tracing::debug!("Step 1h/15: Detecting potentially slow regex patterns");
            find_slow_regex_patterns(&trait_definitions, &mut warnings);
            tracing::debug!("Step 1h completed in {:?}", step_start.elapsed());
        } else {
            tracing::debug!("Step 1/15: Skipping precision validation (use --validate to enable)");
        }

        // Validate trait references in composite rules
        // Cross-directory references must match an existing directory prefix
        // Include both trait definition prefixes AND composite rule prefixes (rules can reference rules)
        tracing::debug!("Step 2/15: Building known prefixes");
        let mut known_prefixes: std::collections::HashSet<String> = trait_definitions
            .iter()
            .filter_map(|t| {
                // Extract the directory prefix from trait IDs
                // New format: everything before '::' (e.g., "cap/comm/http::curl" -> "cap/comm/http")
                // Legacy format: everything before last '/' (e.g., "cap/comm/http/curl" -> "cap/comm/http")
                if let Some(idx) = t.id.find("::") {
                    Some(t.id[..idx].to_string())
                } else {
                    t.id.rfind('/').map(|idx| t.id[..idx].to_string())
                }
            })
            .collect();

        // Also add composite rule prefixes (composite rules can reference other composite rules)
        for rule in &composite_rules {
            if let Some(idx) = rule.id.find("::") {
                known_prefixes.insert(rule.id[..idx].to_string());
            } else if let Some(idx) = rule.id.rfind('/') {
                known_prefixes.insert(rule.id[..idx].to_string());
            }
        }

        // Pre-compute all parent paths for O(1) prefix matching
        // This avoids O(n) iteration for every trait reference check
        let mut prefix_hierarchy = known_prefixes.clone();
        for prefix in &known_prefixes {
            // Add all parent paths: "cap/fs/write" -> ["cap", "cap/fs", "cap/fs/write"]
            let parts: Vec<&str> = prefix.split('/').collect();
            for i in 1..parts.len() {
                prefix_hierarchy.insert(parts[..i].join("/"));
            }
        }
        tracing::debug!(
            "Built prefix hierarchy with {} entries from {} base prefixes",
            prefix_hierarchy.len(),
            known_prefixes.len()
        );

        // Check for taxonomy violations: platform/language names as directories
        // According to TAXONOMY.md, languages should be YAML filenames, not directories
        tracing::debug!("Step 3/15: Checking for platform-named directories");
        let dir_list: Vec<String> = known_prefixes.iter().cloned().collect();
        let platform_dir_violations = find_platform_named_directories(&dir_list);
        if !platform_dir_violations.is_empty() {
            eprintln!(
                    "\n❌ ERROR: {} directories are named after platforms/languages (TAXONOMY.md violation)",
                    platform_dir_violations.len()
                );
            eprintln!("   Languages and platforms should be YAML filenames, not directories:\n");
            for (dir_path, platform_name) in &platform_dir_violations {
                eprintln!(
                    "   {}: contains platform directory '{}'",
                    dir_path, platform_name
                );
            }
            eprintln!("\n   Example: Instead of 'cap/exec/python/runtime.yaml',");
            eprintln!("   use 'cap/exec/runtime/python.yaml'\n");
            warnings.push(format!(
                "{} directories named after platforms (should be YAML filenames)",
                platform_dir_violations.len()
            ));
        }

        // Check for duplicate second-level directories across namespaces
        // According to TAXONOMY.md, directories should not be repeated across meta/, cap/, obj/, known/
        tracing::debug!("Step 3b/15: Checking for duplicate second-level directories");
        let duplicate_dirs = find_duplicate_second_level_directories(&dir_list);
        if !duplicate_dirs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} second-level directories are duplicated across namespaces (TAXONOMY.md violation)",
                duplicate_dirs.len()
            );
            eprintln!("   Second-level directories should not be repeated across meta/, cap/, obj/, known/:");
            eprintln!("   This indicates traits are misplaced - objectives should only be in obj/, capabilities in cap/.\n");
            for (dir_name, namespaces) in &duplicate_dirs {
                eprintln!(
                    "   '{}' appears in: {}/{}/ ",
                    dir_name,
                    namespaces.join("/, "),
                    dir_name
                );
            }
            eprintln!("\n   Examples:");
            eprintln!("   - cap/c2/ and obj/c2/ → C2 is an objective, should only be in obj/");
            eprintln!("   - cap/discovery/ and obj/discovery/ → Discovery is an objective, should only be in obj/");
            eprintln!(
                "   - cap/malware/ and known/malware/ → Malware detection should not be in cap/\n"
            );
            has_fatal_errors = true;
        }

        // Check for banned meaningless directory segments
        tracing::debug!("Step 4/15: Checking for banned directory segments");
        let banned_segment_violations = find_banned_directory_segments(&dir_list);
        if !banned_segment_violations.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} directories contain meaningless segment names",
                banned_segment_violations.len()
            );
            eprintln!("   These segments add no semantic value and hurt taxonomy clarity:\n");
            for (dir_path, segment) in &banned_segment_violations {
                eprintln!("   {}: contains banned segment '{}'", dir_path, segment);
            }
            eprintln!("\n   Use specific, descriptive names instead.\n");
            warnings.push(format!(
                "{} directories contain meaningless segments",
                banned_segment_violations.len()
            ));
        }

        // Check for duplicate words in path - REMOVED
        // This check had too many false positives (e.g., httpx library name)

        // Check for directory names that duplicate their parent
        tracing::debug!("Step 5/15: Checking for parent duplicate segments");
        let parent_dup_violations = find_parent_duplicate_segments(&dir_list);
        if !parent_dup_violations.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} directories duplicate their parent segment",
                parent_dup_violations.len()
            );
            eprintln!("   Child directories should not repeat parent names:\n");
            for (dir_path, segment) in &parent_dup_violations {
                eprintln!("   {}: segment '{}' duplicates parent", dir_path, segment);
            }
            eprintln!();
            warnings.push(format!(
                "{} directories duplicate parent segment",
                parent_dup_violations.len()
            ));
        }

        // Check for depth violations: cap/ and obj/ files must be 3-4 subdirectories deep
        tracing::debug!("Step 6/15: Checking for depth violations");
        let relative_paths: Vec<String> = yaml_files
            .iter()
            .filter_map(|p| {
                p.strip_prefix(dir_path)
                    .ok()
                    .map(|rel| rel.to_string_lossy().replace('\\', "/"))
            })
            .collect();
        let depth_violations = find_depth_violations(&relative_paths);
        if !depth_violations.is_empty() {
            let shallow: Vec<_> =
                depth_violations.iter().filter(|(_, _, kind)| *kind == "shallow").collect();
            let deep: Vec<_> =
                depth_violations.iter().filter(|(_, _, kind)| *kind == "deep").collect();

            if !shallow.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} files are too shallow (need 3-4 subdirectories in cap/obj)",
                    shallow.len()
                );
                for (path, depth, _) in &shallow {
                    eprintln!("   {} ({} subdirs, need 3-4)", path, depth);
                }
            }
            if !deep.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} files are too deep (max 4 subdirectories in cap/obj)",
                    deep.len()
                );
                for (path, depth, _) in &deep {
                    eprintln!("   {} ({} subdirs, max 4)", path, depth);
                }
            }
            warnings.push(format!(
                "{} files at wrong depth (need 3-4 subdirectories in cap/obj)",
                depth_violations.len()
            ));
        }

        // Check for invalid characters in trait/rule IDs
        tracing::debug!("Step 7/15: Checking for invalid trait IDs");
        let invalid_ids =
            find_invalid_trait_ids(&trait_definitions, &composite_rules, &rule_source_files);
        if !invalid_ids.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} trait/rule IDs contain invalid characters",
                invalid_ids.len()
            );
            if debug {
                eprintln!("   IDs must only contain alphanumerics, dashes, and underscores:\n");
                for (id, invalid_char, source_file) in &invalid_ids {
                    let line_hint = find_line_number(source_file, id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: ID '{}' contains invalid char '{}'",
                            source_file, line, id, invalid_char
                        );
                    } else {
                        eprintln!(
                            "   {}: ID '{}' contains invalid char '{}'",
                            source_file, id, invalid_char
                        );
                    }
                }
                eprintln!("\n   Use only [a-zA-Z0-9_-] in trait IDs. No slashes allowed.\n");
            } else {
                eprintln!("   Set DISSECT_DEBUG=1 to see details\n");
            }
            warnings.push(format!(
                "{} trait/rule IDs contain invalid characters",
                invalid_ids.len()
            ));
        }

        tracing::debug!("Step 8/15: Validating trait references in composite rules");
        let mut invalid_refs = Vec::new();
        for rule in &composite_rules {
            let trait_refs = collect_trait_refs_from_rule(rule);
            for (ref_id, rule_id) in trait_refs {
                // Only validate cross-directory references (those with slashes or ::)
                let is_cross_dir = ref_id.contains("::") || ref_id.contains('/');
                if is_cross_dir {
                    // Skip validation for meta/ paths - these are dynamically generated
                    if ref_id.starts_with("meta/import/")
                        || ref_id.starts_with("meta/dylib/")
                        || ref_id.starts_with("meta/signed/")
                        || ref_id.starts_with("meta/internal/")
                    {
                        continue;
                    }

                    // Extract the directory part for validation
                    let dir_part = if let Some(idx) = ref_id.find("::") {
                        &ref_id[..idx]
                    } else if let Some(idx) = ref_id.rfind('/') {
                        &ref_id[..idx]
                    } else {
                        &ref_id[..]
                    };

                    // Check if this matches any known prefix (O(1) lookup instead of O(n) iteration)
                    // Check exact match or any parent path exists in hierarchy
                    let matches_prefix = prefix_hierarchy.contains(dir_part)
                        || dir_part.split('/').enumerate().skip(1).any(|(i, _)| {
                            let parent = dir_part.split('/').take(i).collect::<Vec<_>>().join("/");
                            prefix_hierarchy.contains(&parent)
                        });
                    if !matches_prefix {
                        let source_file = rule_source_files
                            .get(&rule_id)
                            .map(std::string::String::as_str)
                            .unwrap_or("unknown");
                        invalid_refs.push((rule_id.clone(), ref_id, source_file.to_string()));
                    }
                }
            }
        }

        if !invalid_refs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} invalid trait references found in composite rules",
                invalid_refs.len()
            );
            if debug {
                for (rule_id, ref_id, source_file) in &invalid_refs {
                    // Try to find line number by searching the file
                    let line_hint = find_line_number(source_file, ref_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Rule '{}' references unknown path: '{}'",
                            source_file, line, rule_id, ref_id
                        );
                    } else {
                        eprintln!(
                            "   {}: Rule '{}' references unknown path: '{}'",
                            source_file, rule_id, ref_id
                        );
                    }
                }
                eprintln!("\n   Cross-directory references must use directory paths (e.g., 'discovery/system')");
                eprintln!("   that match existing trait directories, not exact trait IDs.\n");
            } else {
                eprintln!("   Set DISSECT_DEBUG=1 to see details\n");
            }
        }

        // Pre-compile all regexes for performance (parallelized)
        tracing::debug!("Step 9/15: Pre-compiling regexes in parallel");
        let regex_errors: Vec<String> = trait_definitions
            .par_iter_mut()
            .filter_map(|trait_def| {
                trait_def
                    .precompile_regexes()
                    .err()
                    .map(|e| format!("Regex compilation error: {:#}", e))
            })
            .collect();
        parse_errors.extend(regex_errors);

        // Validate exact trait ID references
        // Build set of all valid trait IDs (both atomic traits and composite rules)
        tracing::debug!("Step 10/15: Building valid trait IDs set");
        let mut valid_trait_ids: FxHashSet<String> =
            trait_definitions.iter().map(|t| t.id.clone()).collect();
        for rule in &composite_rules {
            valid_trait_ids.insert(rule.id.clone());
        }

        // Debug: Print sample of valid trait IDs
        if std::env::var("DISSECT_DEBUG").is_ok() {
            let mut sample_ids: Vec<_> = valid_trait_ids
                .iter()
                .filter(|id| {
                    id.contains("tiny-elf")
                        || id.contains("small-elf")
                        || id.contains("setup-py")
                        || id.contains("pkginfo")
                })
                .collect();
            sample_ids.sort();
            for id in sample_ids {
                eprintln!("[DEBUG] Valid trait ID: {}", id);
            }
        }

        // Validate that composite rules don't reference meta/internal/ paths
        // Internal paths are for ML usage only and must not be used in composite rules
        tracing::debug!("Step 11/15: Checking for internal path references");
        let mut internal_refs = Vec::new();
        for rule in &composite_rules {
            let trait_refs = collect_trait_refs_from_rule(rule);
            for (ref_id, rule_id) in trait_refs {
                if ref_id.starts_with("meta/internal/") {
                    let source_file =
                        rule_source_files.get(&rule_id).map(std::string::String::as_str).unwrap_or("unknown");
                    internal_refs.push((rule_id.clone(), ref_id, source_file.to_string()));
                }
            }
        }

        if !internal_refs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite rules reference internal paths",
                internal_refs.len()
            );
            eprintln!("   Internal paths (meta/internal/) are for ML usage only and cannot be used in composite rules:\n");
            for (rule_id, ref_id, source_file) in &internal_refs {
                let line_hint = find_line_number(source_file, ref_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Rule '{}' references internal path: '{}'",
                        source_file, line, rule_id, ref_id
                    );
                } else {
                    eprintln!(
                        "   {}: Rule '{}' references internal path: '{}'",
                        source_file, rule_id, ref_id
                    );
                }
            }
            eprintln!("\n   Use meta/import/ or meta/dylib/ for import-based detection instead.");
            warnings.push(format!(
                "{} composite rules reference internal paths (meta/internal/)",
                internal_refs.len()
            ));
        }

        // Validate that cap/ rules do not reference obj/ rules
        // Cap contains micro-behaviors, obj contains larger behaviors
        // Cap rules should be independent of obj rules
        tracing::debug!("Step 12/15: Checking for cap/obj violations");
        let cap_obj_violations =
            find_cap_obj_violations(&trait_definitions, &composite_rules, &rule_source_files);

        if !cap_obj_violations.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} cap/ rules reference obj/ rules",
                cap_obj_violations.len()
            );
            eprintln!("   Cap rules (micro-behaviors) should not depend on obj rules (larger behaviors):\n");
            for (rule_id, ref_id, source_file) in &cap_obj_violations {
                let line_hint = find_line_number(source_file, ref_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Rule '{}' references obj rule: '{}'",
                        source_file, line, rule_id, ref_id
                    );
                } else {
                    eprintln!(
                        "   {}: Rule '{}' references obj rule: '{}'",
                        source_file, rule_id, ref_id
                    );
                }
            }
            eprintln!("\n   Cap rules should only reference other cap rules or meta rules.");
            warnings.push(format!(
                "{} cap/ rules reference obj/ rules (cap should not depend on obj)",
                cap_obj_violations.len()
            ));
        }

        // Validate that cap/ rules are never hostile
        // Hostile criticality requires objective-level evidence and belongs in obj/
        tracing::debug!("Step 13/15: Checking for hostile cap rules");
        let hostile_cap_rules =
            find_hostile_cap_rules(&trait_definitions, &composite_rules, &rule_source_files);

        if !hostile_cap_rules.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} cap/ rules have hostile criticality",
                hostile_cap_rules.len()
            );
            eprintln!("   Cap contains micro-behaviors (atomic capabilities) which are generally neutral.");
            eprintln!(
                "   Hostile rules require intent inference and should be in obj/ where they can be"
            );
            eprintln!("   categorized properly by attacker objective (C2, exfil, impact, etc.):\n");
            for (rule_id, source_file) in &hostile_cap_rules {
                let line_hint = find_line_number(source_file, "crit: hostile");
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: Rule '{}'", source_file, line, rule_id);
                } else {
                    eprintln!("   {}: Rule '{}'", source_file, rule_id);
                }
            }
            eprintln!("\n   Cap rules max criticality: suspicious (rarely legitimate but still a capability)");
            eprintln!("   Move hostile rules to obj/c2/, obj/exfil/, obj/impact/, etc. based on objective.");
            warnings.push(format!(
                "{} cap/ rules have hostile criticality (should be in obj/)",
                hostile_cap_rules.len()
            ));
        }

        // Validate that obj/ rules are never inert
        // Obj rules represent attacker objectives and must carry analytical signal.
        // Inert rules either belong in cap/ or meta/ (if truly neutral), or should
        // be upgraded to notable if they indicate something of interest or suspicion.
        tracing::debug!("Step 13b/15: Checking for inert obj rules");
        let inert_obj_rules =
            find_inert_obj_rules(&trait_definitions, &composite_rules, &rule_source_files);

        if !inert_obj_rules.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} obj/ rules have inert criticality",
                inert_obj_rules.len()
            );
            eprintln!("   Obj rules represent attacker objectives and must carry analytical signal.");
            eprintln!("   Inert findings have no place in obj/ - every objective implies intent:\n");
            for (rule_id, source_file) in &inert_obj_rules {
                let line_hint = find_line_number(source_file, "crit: inert");
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: Rule '{}'", source_file, line, rule_id);
                } else {
                    eprintln!("   {}: Rule '{}'", source_file, rule_id);
                }
            }
            eprintln!("\n   To fix:");
            eprintln!("   - If truly neutral (no intent), migrate to cap/ or meta/");
            eprintln!("   - If it leans toward any level of interest or suspicion, upgrade to notable");
            eprintln!("   - See TAXONOMY.md for guidance on trait classification");
            warnings.push(format!(
                "{} obj/ rules have inert criticality (migrate to cap/meta/ or upgrade to notable)",
                inert_obj_rules.len()
            ));
        }

        // Validate that malware/ is not used as a subcategory of obj/ or cap/
        // Malware-specific signatures belong in known/malware/ per TAXONOMY.md
        tracing::debug!("Step 13b/15: Checking for misplaced malware/ subcategories");
        let malware_violations = find_malware_subcategory_violations(
            &trait_definitions,
            &composite_rules,
            &rule_source_files,
        );

        if !malware_violations.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} rules use malware/ as a subcategory of obj/ or cap/",
                malware_violations.len()
            );
            eprintln!("   Malware-specific signatures belong in known/malware/, not obj/ or cap/.");
            eprintln!("   See TAXONOMY.md for the correct taxonomy structure:\n");
            for (rule_id, source_file) in &malware_violations {
                eprintln!("   {}: Rule '{}'", source_file, rule_id);
            }
            eprintln!("\n   Move these rules to known/malware/<family>/ instead.");
            warnings.push(format!(
                "{} rules misuse malware/ as a subcategory of obj/ or cap/ (see TAXONOMY.md)",
                malware_violations.len()
            ));
            has_fatal_errors = true;
        }

        // Validate that `any:` clauses don't have 3+ traits from the same external directory
        // Recommend using directory references instead for better maintainability
        tracing::debug!("Step 14/15: Checking for redundant any refs");
        let mut redundant_any_refs = Vec::new();
        for rule in &composite_rules {
            let violations = find_redundant_any_refs(rule);
            for (rule_id, dir, count, trait_ids) in violations {
                let source_file =
                    rule_source_files.get(&rule_id).map(std::string::String::as_str).unwrap_or("unknown");
                redundant_any_refs.push((rule_id, dir, count, trait_ids, source_file.to_string()));
            }
        }

        if !redundant_any_refs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite rules have redundant any: clauses",
                redundant_any_refs.len()
            );
            eprintln!("   Rules with 4+ trait references from the same directory should use directory notation:\n");
            for (rule_id, dir, count, trait_ids, source_file) in &redundant_any_refs {
                let line_hint = find_line_number(source_file, rule_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Rule '{}' references {} traits from '{}'",
                        source_file, line, rule_id, count, dir
                    );
                } else {
                    eprintln!(
                        "   {}: Rule '{}' references {} traits from '{}'",
                        source_file, rule_id, count, dir
                    );
                }
                eprintln!("      Traits: {}", trait_ids.join(", "));
                eprintln!("      Recommendation: Use 'id: {}', or create a new subdirectory within it to hold common traits instead.\n", dir);
            }
            warnings.push(format!(
                "{} composite rules have redundant any: clauses (use directory notation)",
                redundant_any_refs.len()
            ));
        }

        // Validate that `any:` and `all:` clauses don't have exactly 1 item
        // Single-item clauses are pointless wrappers that add complexity
        tracing::debug!("Step 15/15: Checking for single-item clauses");
        let mut single_item_clauses = Vec::new();
        for rule in &composite_rules {
            let violations = find_single_item_clauses(rule);
            for (rule_id, clause_type, trait_id) in violations {
                let source_file =
                    rule_source_files.get(&rule_id).map(std::string::String::as_str).unwrap_or("unknown");
                single_item_clauses.push((rule_id, clause_type, trait_id, source_file.to_string()));
            }
        }

        if !single_item_clauses.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite rules have single-item any:/all: clauses",
                single_item_clauses.len()
            );
            eprintln!(
                "   Single-item clauses add no value - reference the trait directly instead:\n"
            );
            for (rule_id, clause_type, trait_id, source_file) in &single_item_clauses {
                let line_hint = find_line_number(source_file, rule_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Rule '{}' has single-item {}: clause referencing '{}'",
                        source_file, line, rule_id, clause_type, trait_id
                    );
                } else {
                    eprintln!(
                        "   {}: Rule '{}' has single-item {}: clause referencing '{}'",
                        source_file, rule_id, clause_type, trait_id
                    );
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} composite rules have single-item any:/all: clauses",
                single_item_clauses.len()
            ));
        }

        // Validate that all:/any: clauses don't contain overlapping IDs.
        // A directory reference subsumes any specific trait from that directory.
        let mut overlapping = Vec::new();
        for rule in &composite_rules {
            for (rule_id, clause, dir_ref, specific_ref) in find_overlapping_conditions(rule) {
                let source_file =
                    rule_source_files.get(&rule_id).map(std::string::String::as_str).unwrap_or("unknown");
                overlapping.push((rule_id, clause, dir_ref, specific_ref, source_file.to_string()));
            }
        }
        if !overlapping.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite rules have overlapping {}/{} conditions",
                overlapping.len(),
                "all:",
                "any:"
            );
            eprintln!("   A directory reference already includes all traits within it;\n   remove the specific trait reference:\n");
            for (rule_id, clause, dir_ref, specific_ref, source_file) in &overlapping {
                let line_hint = find_line_number(source_file, rule_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Rule '{}' {}: clause - '{}' is subsumed by '{}'",
                        source_file, line, rule_id, clause, specific_ref, dir_ref
                    );
                } else {
                    eprintln!(
                        "   {}: Rule '{}' {}: clause - '{}' is subsumed by '{}'",
                        source_file, rule_id, clause, specific_ref, dir_ref
                    );
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} composite rules have overlapping all:/any: conditions",
                overlapping.len()
            ));
            has_fatal_errors = true;
        }

        // Validate: string vs content type collisions (same pattern at same criticality)
        // These should be merged to just `content` (which is broader)
        let collisions = find_string_content_collisions(&trait_definitions);
        if !collisions.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} trait pairs have string/content type collisions",
                collisions.len()
            );
            eprintln!("   When both `type: string` and `type: raw` exist for the same pattern,");
            eprintln!("   merge to `raw` only (it's broader and includes string matches):\n");
            for (string_id, content_id, pattern) in &collisions {
                let string_source =
                    rule_source_files.get(string_id).map(std::string::String::as_str).unwrap_or("unknown");
                let line_hint = find_line_number(string_source, string_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: string trait '{}' duplicates content trait '{}'",
                        string_source, line, string_id, content_id
                    );
                } else {
                    eprintln!(
                        "   {}: string trait '{}' duplicates content trait '{}'",
                        string_source, string_id, content_id
                    );
                }
                eprintln!("      Pattern: {}", pattern);
                eprintln!("      Action: Delete the string trait, keep the raw trait\n");
            }
            warnings.push(format!(
                "{} string/raw type collisions (merge to raw only)",
                collisions.len()
            ));
        }

        // Validate: traits that differ only in `for:` field should be merged
        let for_duplicates = find_for_only_duplicates(&trait_definitions);
        if !for_duplicates.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} trait groups differ only in `for:` field",
                for_duplicates.len()
            );
            eprintln!("   These traits have identical logic (same criticality, condition, etc.) but different file types.");
            eprintln!("   Merge them into a single trait with combined `for:` values:\n");
            for (trait_ids, _pattern) in &for_duplicates {
                // Find source file for the first trait
                let first_id = &trait_ids[0];
                let source =
                    rule_source_files.get(first_id).map(std::string::String::as_str).unwrap_or("unknown");
                let line_hint = find_line_number(source, first_id);
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: {}", source, line, trait_ids.join(", "));
                } else {
                    eprintln!("   {}: {}", source, trait_ids.join(", "));
                }
                eprintln!(
                    "      Action: Merge into single trait with `for: [combined file types]`\n"
                );
            }
            warnings.push(format!(
                "{} trait groups differ only in `for:` field (should be merged)",
                for_duplicates.len()
            ));
        }

        // Validate: regex patterns that could be merged with alternation (case-only differences)
        // e.g., `nc\s+-e` and `NC\s+-e` -> `(nc|NC)\s+-e`
        let alternation_candidates =
            find_alternation_merge_candidates(&trait_definitions, &trait_source_files);
        if !alternation_candidates.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} trait groups have regex patterns that should use alternation",
                alternation_candidates.len()
            );
            eprintln!("   These traits have identical criticality and regex patterns where the first token differs only in case.");
            eprintln!("   Merge them into a single trait using alternation syntax:\n");
            for (trait_ids, _suffix, suggested) in &alternation_candidates {
                let first_id = &trait_ids[0];
                let source =
                    rule_source_files.get(first_id).map(std::string::String::as_str).unwrap_or("unknown");
                let line_hint = find_line_number(source, first_id);
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: {}", source, line, trait_ids.join(", "));
                } else {
                    eprintln!("   {}: {}", source, trait_ids.join(", "));
                }
                eprintln!("      Suggested regex: {}\n", suggested);
            }
            warnings.push(format!(
                "{} trait groups should use regex alternation",
                alternation_candidates.len()
            ));
        }

        // Validate: `needs` value exceeds number of items in `any:` (impossible to satisfy)
        let impossible_needs = find_impossible_needs(&composite_rules);
        if !impossible_needs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite rules have impossible `needs` values",
                impossible_needs.len()
            );
            eprintln!("   The `needs` value exceeds the number of items in `any:`:\n");
            for (rule_id, needs, any_len) in &impossible_needs {
                let source =
                    rule_source_files.get(rule_id).map(std::string::String::as_str).unwrap_or("unknown");
                let line_hint = find_line_number(source, rule_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: '{}' has needs: {} but only {} items in any:",
                        source, line, rule_id, needs, any_len
                    );
                } else {
                    eprintln!(
                        "   {}: '{}' has needs: {} but only {} items in any:",
                        source, rule_id, needs, any_len
                    );
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} composite rules have impossible `needs` values",
                impossible_needs.len()
            ));
        }

        // Validate: size_min > size_max (impossible constraint)
        let impossible_sizes =
            find_impossible_size_constraints(&trait_definitions, &composite_rules);
        if !impossible_sizes.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} rules have impossible size constraints (size_min > size_max)",
                impossible_sizes.len()
            );
            for (id, min, max, is_composite) in &impossible_sizes {
                let kind = if *is_composite { "composite" } else { "trait" };
                let source = rule_source_files.get(id).map(std::string::String::as_str).unwrap_or("unknown");
                let line_hint = find_line_number(source, id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: {} '{}' has size_min: {} > size_max: {}",
                        source, line, kind, id, min, max
                    );
                } else {
                    eprintln!(
                        "   {}: {} '{}' has size_min: {} > size_max: {}",
                        source, kind, id, min, max
                    );
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} rules have impossible size constraints",
                impossible_sizes.len()
            ));
        }

        // Validate: count_min > count_max (impossible constraint)
        let impossible_counts = find_impossible_count_constraints(&trait_definitions);
        if !impossible_counts.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} traits have impossible count constraints (count_min > count_max)",
                impossible_counts.len()
            );
            for (id, min, max) in &impossible_counts {
                let source = rule_source_files.get(id).map(std::string::String::as_str).unwrap_or("unknown");
                let line_hint = find_line_number(source, id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: '{}' has count_min: {} > count_max: {}",
                        source, line, id, min, max
                    );
                } else {
                    eprintln!(
                        "   {}: '{}' has count_min: {} > count_max: {}",
                        source, id, min, max
                    );
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} traits have impossible count constraints",
                impossible_counts.len()
            ));
        }

        // Validate: empty any:/all: clauses with no other conditions
        let empty_clauses = find_empty_condition_clauses(&composite_rules);
        if !empty_clauses.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite rules have empty condition clauses",
                empty_clauses.len()
            );
            eprintln!("   Empty `any:` or `all:` clauses make rules meaningless:\n");
            for (rule_id, clause_type) in &empty_clauses {
                let source =
                    rule_source_files.get(rule_id).map(std::string::String::as_str).unwrap_or("unknown");
                let line_hint = find_line_number(source, rule_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: '{}' has empty `{}:` clause",
                        source, line, rule_id, clause_type
                    );
                } else {
                    eprintln!(
                        "   {}: '{}' has empty `{}:` clause",
                        source, rule_id, clause_type
                    );
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} composite rules have empty condition clauses",
                empty_clauses.len()
            ));
        }

        // Validate: string/content conditions with no search pattern
        let missing_patterns = find_missing_search_patterns(&trait_definitions);
        if !missing_patterns.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} traits have no search pattern",
                missing_patterns.len()
            );
            eprintln!(
                "   String/content conditions need at least one of: exact, substr, regex, word:\n"
            );
            for id in &missing_patterns {
                let source = rule_source_files.get(id).map(std::string::String::as_str).unwrap_or("unknown");
                let line_hint = find_line_number(source, id);
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: '{}'", source, line, id);
                } else {
                    eprintln!("   {}: '{}'", source, id);
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} traits have no search pattern",
                missing_patterns.len()
            ));
        }

        // Validate: redundant `needs: 1` when only `any:` exists
        let redundant_needs = find_redundant_needs_one(&composite_rules);
        if !redundant_needs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite rules have redundant `needs: 1`",
                redundant_needs.len()
            );
            eprintln!("   `needs: 1` is the default when only `any:` exists - remove it:\n");
            for rule_id in &redundant_needs {
                let source =
                    rule_source_files.get(rule_id).map(std::string::String::as_str).unwrap_or("unknown");
                let line_hint = find_line_number(source, rule_id);
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: '{}'", source, line, rule_id);
                } else {
                    eprintln!("   {}: '{}'", source, rule_id);
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} composite rules have redundant `needs: 1`",
                redundant_needs.len()
            ));
        }

        // Validate: directories with too many traits (should be split)
        let oversized_dirs = find_oversized_trait_directories(&trait_definitions);
        if !oversized_dirs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} directories have more than {} traits",
                oversized_dirs.len(),
                MAX_TRAITS_PER_DIRECTORY
            );
            eprintln!("   Consider splitting these into subdirectories:\n");
            for (dir_path, count) in &oversized_dirs {
                eprintln!("   {}: {} traits", dir_path, count);
            }
            eprintln!();
            warnings.push(format!(
                "{} directories exceed {} traits (consider splitting)",
                oversized_dirs.len(),
                MAX_TRAITS_PER_DIRECTORY
            ));
        }

        let mut broken_refs = Vec::new();
        for rule in &composite_rules {
            let trait_refs = collect_trait_refs_from_rule(rule);
            for (ref_id, rule_id) in trait_refs {
                // Skip validation for directory-level references (intentional loose coupling)
                // e.g., "discovery/system" matches any trait in that directory
                // Also allow parent directory refs like "cap/fs/write/" when traits exist in subdirs
                let ref_without_slash = ref_id.trim_end_matches('/');
                // O(1) prefix hierarchy lookup instead of O(n) iteration
                let is_directory_ref = prefix_hierarchy.contains(&ref_id)
                    || prefix_hierarchy.contains(ref_without_slash);

                // Skip validation for dynamically generated meta/* references
                // - meta/import/ and meta/dylib/ are generated from binary imports
                // - meta/signed/ is generated from code signature parsing
                // - meta/internal/ is validated separately (forbidden in composite rules)
                let is_dynamic_or_internal = ref_id.starts_with("meta/import/")
                    || ref_id.starts_with("meta/dylib/")
                    || ref_id.starts_with("meta/signed/")
                    || ref_id.starts_with("meta/internal/");

                // Check if the exact trait ID exists (unless it's an intentional directory ref)
                // Note: We require exact matches. References like "cap/foo/bar/filename" where
                // "filename" is a YAML file (not a directory) are invalid - filenames are never
                // part of trait IDs, only the directory path is used for prefixing.
                if !is_directory_ref
                    && !is_dynamic_or_internal
                    && !valid_trait_ids.contains(&ref_id)
                {
                    // Debug: Print broken reference details
                    if std::env::var("DISSECT_DEBUG").is_ok()
                        && (ref_id.contains("tiny-elf")
                            || ref_id.contains("small-elf")
                            || ref_id.contains("setup-py")
                            || ref_id.contains("pkginfo"))
                    {
                        eprintln!(
                            "[DEBUG] Broken reference: '{}' (from rule '{}')",
                            ref_id, rule_id
                        );
                    }
                    let source_file =
                        rule_source_files.get(&rule_id).map(std::string::String::as_str).unwrap_or("unknown");
                    broken_refs.push((rule_id.clone(), ref_id, source_file.to_string()));
                }
            }
        }

        if !broken_refs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} broken trait references found in composite rules",
                broken_refs.len()
            );
            eprintln!("   Composite rules reference trait IDs that don't exist:\n");
            for (rule_id, ref_id, source_file) in &broken_refs {
                let line_hint = find_line_number(source_file, ref_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Rule '{}' references non-existent trait: '{}'",
                        source_file, line, rule_id, ref_id
                    );
                } else {
                    eprintln!(
                        "   {}: Rule '{}' references non-existent trait: '{}'",
                        source_file, rule_id, ref_id
                    );
                }
            }
            eprintln!();
        }

        // Validate metric field references
        let valid_metric_fields = get_valid_metric_fields();
        let mut invalid_metric_refs = Vec::new();

        for trait_def in &trait_definitions {
            let metric_fields = collect_metric_refs_from_trait(trait_def);
            for field in metric_fields {
                if !valid_metric_fields.contains(&field) {
                    let source_file = trait_source_files
                        .get(&trait_def.id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    invalid_metric_refs.push((
                        trait_def.id.clone(),
                        field,
                        source_file.to_string(),
                    ));
                }
            }
        }

        if !invalid_metric_refs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} unknown metric field references found in traits",
                invalid_metric_refs.len()
            );
            eprintln!("   Traits reference metric fields that don't exist:\n");
            for (trait_id, field, source_file) in &invalid_metric_refs {
                let line_hint = find_line_number(source_file, field);
                let suggestion = suggest_metric_field(&valid_metric_fields, field);
                if let Some(line) = line_hint {
                    if let Some(suggested) = suggestion {
                        eprintln!(
                            "   {}:{}: Trait '{}' references unknown metric '{}' (did you mean '{}'?)",
                            source_file, line, trait_id, field, suggested
                        );
                    } else {
                        eprintln!(
                            "   {}:{}: Trait '{}' references unknown metric '{}'",
                            source_file, line, trait_id, field
                        );
                    }
                } else if let Some(suggested) = suggestion {
                    eprintln!(
                        "   {}: Trait '{}' references unknown metric '{}' (did you mean '{}'?)",
                        source_file, trait_id, field, suggested
                    );
                } else {
                    eprintln!(
                        "   {}: Trait '{}' references unknown metric '{}'",
                        source_file, trait_id, field
                    );
                }
            }
            eprintln!("\n   Valid metric fields:");
            let mut sorted_fields: Vec<&String> = valid_metric_fields.iter().collect();
            sorted_fields.sort();
            for field in sorted_fields.iter().take(10) {
                eprintln!("     - {}", field);
            }
            if sorted_fields.len() > 10 {
                eprintln!("     ... and {} more", sorted_fields.len() - 10);
            }
            eprintln!();
        }

        // Validate that composite rules only contain trait references (not inline primitives)
        // Strict mode is the default - composite rules must only reference traits
        let mut inline_errors = Vec::new();
        for rule in &composite_rules {
            let source = rule_source_files.get(&rule.id).map(std::string::String::as_str).unwrap_or("unknown");
            inline_errors.extend(validate_composite_trait_only(rule, source));
        }

        if !inline_errors.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite rules have inline primitives\n",
                inline_errors.len()
            );
            for err in &inline_errors {
                eprintln!("   {}", err);
            }
            eprintln!("\n   Composite rules must only reference traits (type: trait).");
            eprintln!(
                "   Convert inline conditions (string, symbol, yara, etc.) to atomic traits.\n"
            );
            has_fatal_errors = true;
        }

        // Validate single-rule composites with identical file types
        // Build map of trait_id -> file_types for quick lookup
        let mut trait_file_types: FxHashMap<String, Vec<RuleFileType>> = FxHashMap::default();
        for trait_def in &trait_definitions {
            trait_file_types.insert(trait_def.id.clone(), trait_def.r#for.clone());
        }
        for rule in &composite_rules {
            trait_file_types.insert(rule.id.clone(), rule.r#for.clone());
        }

        // Build metadata lookup for traits and composites
        let mut trait_metadata: FxHashMap<
            String,
            (Criticality, f32, Option<String>, Option<String>),
        > = FxHashMap::default();
        for trait_def in &trait_definitions {
            trait_metadata.insert(
                trait_def.id.clone(),
                (
                    trait_def.crit,
                    trait_def.conf,
                    trait_def.attack.clone(),
                    trait_def.mbc.clone(),
                ),
            );
        }
        for rule in &composite_rules {
            trait_metadata.insert(
                rule.id.clone(),
                (rule.crit, rule.conf, rule.attack.clone(), rule.mbc.clone()),
            );
        }

        let mut redundant_composites = Vec::new();
        let mut unless_only_composites = Vec::new();

        for rule in &composite_rules {
            // Check if this is a single-rule composite
            let mut total_conditions = 0;
            if let Some(ref all) = rule.all {
                total_conditions += all.len();
            }
            if let Some(ref any) = rule.any {
                total_conditions += any.len();
            }
            if let Some(ref none) = rule.none {
                total_conditions += none.len();
            }

            // If it's a single-rule composite, check file types
            if total_conditions == 1 {
                let trait_refs = collect_trait_refs_from_rule(rule);
                if trait_refs.len() == 1 {
                    let (ref_id, _) = &trait_refs[0];

                    // Look up the referenced trait's file types
                    if let Some(ref_file_types) = trait_file_types.get(ref_id) {
                        // Compare file types - warn if identical
                        if rule.r#for == *ref_file_types {
                            let source_file = rule_source_files
                                .get(&rule.id)
                                .map(std::string::String::as_str)
                                .unwrap_or("unknown");

                            // Check if this composite only adds an 'unless' clause
                            // If so, it might be better expressed as a downgrade
                            let has_unless = rule.unless.as_ref().is_some_and(|u| !u.is_empty());
                            let has_downgrade = rule.downgrade.is_some();

                            // Check if metadata is being changed
                            let metadata_changed =
                                if let Some((ref_crit, ref_conf, ref_attack, ref_mbc)) =
                                    trait_metadata.get(ref_id)
                                {
                                    rule.crit != *ref_crit
                                        || (rule.conf - ref_conf).abs() > 0.001
                                        || rule.attack != *ref_attack
                                        || rule.mbc != *ref_mbc
                                } else {
                                    false
                                };

                            if has_unless && !has_downgrade && !metadata_changed {
                                // Only adds unless, no metadata changes - suggest downgrade pattern
                                unless_only_composites.push((
                                    rule.id.clone(),
                                    ref_id.clone(),
                                    source_file.to_string(),
                                ));
                            } else if !has_unless && !has_downgrade && !metadata_changed {
                                // Truly useless - no unless, no downgrade, no metadata changes, same file types
                                redundant_composites.push((
                                    rule.id.clone(),
                                    ref_id.clone(),
                                    source_file.to_string(),
                                ));
                            }
                            // If metadata_changed is true, this is a legitimate composite
                            // that's creating a distinct finding with different properties
                        }
                    }
                }
            }
        }

        if !redundant_composites.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} single-trait composites add no value",
                redundant_composites.len()
            );
            eprintln!(
                "   These composites only reference one trait with identical file types and no unless/downgrade clauses.\n"
            );
            eprintln!("   Consider removing them or adding more conditions:\n");
            for (rule_id, ref_id, source_file) in &redundant_composites {
                let line_hint = find_line_number(source_file, rule_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Composite '{}' only references '{}'",
                        source_file, line, rule_id, ref_id
                    );
                } else {
                    eprintln!(
                        "   {}: Composite '{}' only references '{}'",
                        source_file, rule_id, ref_id
                    );
                }
            }
            eprintln!();
            has_fatal_errors = true;
        }

        if !unless_only_composites.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} single-trait composites only add 'unless' clauses",
                unless_only_composites.len()
            );
            eprintln!("   Instead of creating a composite with only an unless clause:");
            eprintln!("   1. Increase the criticality of the base trait");
            eprintln!("   2. Add a downgrade clause to the base trait for the unless conditions\n");
            for (rule_id, ref_id, source_file) in &unless_only_composites {
                let line_hint = find_line_number(source_file, rule_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Composite '{}' only adds unless to '{}'",
                        source_file, line, rule_id, ref_id
                    );
                } else {
                    eprintln!(
                        "   {}: Composite '{}' only adds unless to '{}'",
                        source_file, rule_id, ref_id
                    );
                }
            }
            eprintln!();
            has_fatal_errors = true;
        }

        tracing::debug!("Validation complete");

        // Build trait index for fast lookup by file type
        tracing::debug!("Building trait indexes");
        let trait_index = TraitIndex::build(&trait_definitions);

        // Build string match index for batched AC matching
        let _t_string_index = std::time::Instant::now();
        tracing::debug!("Building Aho-Corasick string index");
        let string_match_index = StringMatchIndex::build(&trait_definitions);
        tracing::debug!("Indexes built successfully");

        // Build raw content regex index for batched regex matching
        let _t_raw_regex_index = std::time::Instant::now();
        let raw_content_regex_index = match RawContentRegexIndex::build(&trait_definitions) {
            Ok(index) => index,
            Err(errors) => {
                return Err(anyhow::anyhow!(errors.join("\n")));
            },
        };

        // Parse errors are fatal - print all and exit if any exist
        if !parse_errors.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} YAML parsing error(s) found:\n",
                parse_errors.len()
            );
            for error in &parse_errors {
                eprintln!("   {}", error);
            }
            eprintln!("\n   Fix these issues in the YAML files before continuing.\n");
            has_fatal_errors = true;
        }

        // Warnings are NOT fatal during analysis, just print them if in debug mode
        if !warnings.is_empty() {
            if debug {
                eprintln!(
                    "\n❌ ERROR: {} trait configuration warning(s) found:\n",
                    warnings.len()
                );
                for warning in &warnings {
                    eprintln!("   ⚠️  {}", warning);
                }
                eprintln!("\n   Consider fixing these issues in the YAML files.\n");
            } else {
                tracing::warn!(
                    "{} trait configuration warnings found (set DISSECT_DEBUG=1 to see details)",
                    warnings.len()
                );
            }
        }

        // Exit if any fatal errors occurred
        if has_fatal_errors {
            eprintln!("\n==> Fix all validation errors before continuing.\n");
            std::process::exit(1);
        }

        Ok(Self {
            symbol_map,
            trait_definitions,
            composite_rules,
            trait_index,
            string_match_index,
            raw_content_regex_index,
            platforms: vec![Platform::All],
        })
    }

    /// Load capability mappings from YAML file
    #[allow(dead_code)] // Used in tests
    pub(crate) fn from_yaml<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::from_yaml_with_precision_thresholds(
            path,
            Self::DEFAULT_MIN_HOSTILE_PRECISION,
            Self::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            true, // from_yaml always enables full validation (used in tests)
        )
    }

    /// Load capability mappings from a single YAML file with explicit precision thresholds
    pub(crate) fn from_yaml_with_precision_thresholds<P: AsRef<Path>>(
        path: P,
        min_hostile_precision: f32,
        min_suspicious_precision: f32,
        _enable_full_validation: bool,
    ) -> Result<Self> {
        let bytes = fs::read(path.as_ref()).context("Failed to read capabilities YAML file")?;
        let content = String::from_utf8_lossy(&bytes);

        let mappings: TraitMappings =
            serde_yaml::from_str(&content).context("Failed to parse capabilities YAML")?;

        let mut symbol_map = HashMap::new();

        // Load legacy "symbols" format
        for mapping in mappings.symbols {
            symbol_map.insert(
                mapping.symbol.clone(),
                TraitInfo {
                    id: mapping.capability,
                    desc: mapping.desc,
                    conf: mapping.conf,
                    crit: Criticality::Inert, // Legacy format defaults to Inert
                    mbc: None,                // Legacy format has no mbc field
                    attack: None,             // Legacy format has no attack field
                },
            );
        }

        // Load "simple_rules" format
        for rule in mappings.simple_rules {
            symbol_map.insert(
                rule.symbol.clone(),
                TraitInfo {
                    id: rule.capability,
                    desc: rule.desc,
                    conf: rule.conf,
                    crit: Criticality::Inert, // Simple rules default to Inert
                    mbc: None,                // Simple rules have no mbc field
                    attack: None,             // Simple rules have no attack field
                },
            );
        }

        // Convert raw traits to final traits with defaults applied
        let mut warnings: Vec<String> = Vec::new();
        let mut trait_definitions: Vec<TraitDefinition> = mappings
            .traits
            .into_iter()
            .map(|raw| apply_trait_defaults(raw, &mappings.defaults, &mut warnings, path.as_ref()))
            .collect();

        // Pre-compile all regexes for performance
        for trait_def in &mut trait_definitions {
            if let Err(e) = trait_def.precompile_regexes() {
                return Err(anyhow::anyhow!("Regex compilation error: {:#}", e));
            }
        }

        // Convert raw composite rules to final rules with defaults applied
        let mut composite_rules = Vec::new();
        for raw in mappings.composite_rules {
            composite_rules.push(apply_composite_defaults(
                raw,
                &mappings.defaults,
                &mut warnings,
                path.as_ref(),
            ));
        }

        // Print any warnings from parsing
        for warning in &warnings {
            eprintln!("Warning: {}", warning);
        }

        // Pre-compile all composite rule regexes
        for rule in &mut composite_rules {
            if let Err(e) = rule.precompile_regexes() {
                return Err(anyhow::anyhow!("Regex compilation error: {:#}", e));
            }
        }

        // Pre-calculate precision for all composite rules
        precalculate_all_composite_precisions(&mut composite_rules, &trait_definitions);

        // Validate HOSTILE composite precision
        validate_hostile_composite_precision(
            &mut composite_rules,
            &trait_definitions,
            &mut warnings,
            min_hostile_precision,
            min_suspicious_precision,
        );

        // Detect duplicate traits and composites
        find_duplicate_traits_and_composites(&trait_definitions, &composite_rules, &mut warnings);

        // Validate trait and composite conditions and warn about problematic patterns
        validate_conditions(&trait_definitions, &composite_rules, path.as_ref());

        // Final error check - exit if any validation errors occurred
        if !warnings.is_empty() {
            eprintln!("\n❌ ERROR: {} validation errors:\n", warnings.len());
            for warning in &warnings {
                eprintln!("   {}", warning);
            }
            eprintln!("\n==> Fix all validation errors before continuing.\n");
            std::process::exit(1);
        }

        // Build trait index for fast lookup by file type
        let trait_index = TraitIndex::build(&trait_definitions);

        // Build string match index for batched AC matching
        let string_match_index = StringMatchIndex::build(&trait_definitions);

        // Build raw content regex index for batched regex matching
        let raw_content_regex_index = match RawContentRegexIndex::build(&trait_definitions) {
            Ok(index) => index,
            Err(errors) => {
                return Err(anyhow::anyhow!(errors.join("\n")));
            },
        };

        Ok(Self {
            symbol_map,
            trait_definitions,
            composite_rules,
            trait_index,
            string_match_index,
            raw_content_regex_index,
            platforms: vec![Platform::All],
        })
    }

    /// Look up a symbol and return its capability finding if known
    #[must_use] 
    pub(crate) fn lookup(&self, symbol: &str, source: &str) -> Option<Finding> {
        // Strip common prefixes for matching
        let clean_symbol = symbol
            .trim_start_matches('_') // C symbols often have leading underscore
            .trim_start_matches("__"); // Some have double underscore

        if let Some(info) = self.symbol_map.get(clean_symbol) {
            return Some(Finding {
                id: info.id.clone(),
                kind: FindingKind::Capability,
                desc: info.desc.clone(),
                conf: info.conf,
                crit: info.crit,
                mbc: info.mbc.clone(),
                attack: info.attack.clone(),
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "symbol".to_string(),
                    source: source.to_string(),
                    value: symbol.to_string(),
                    location: None,
                }],

                source_file: None,
            });
        }

        None
    }

    /// Get the number of loaded symbol mappings
    #[allow(dead_code)] // Used in tests
    #[must_use]
    pub(crate) fn mapping_count(&self) -> usize {
        self.symbol_map.len()
    }

    /// Get the number of loaded composite rules
    #[allow(dead_code)] // Used in tests
    #[must_use]
    pub(crate) fn composite_rules_count(&self) -> usize {
        self.composite_rules.len()
    }

    /// Get a reference to the composite rules (for graph generation and analysis)
    #[allow(dead_code)] // Used in tests
    #[must_use]
    pub(crate) fn composite_rules(&self) -> &[CompositeTrait] {
        &self.composite_rules
    }

    /// Get the number of loaded trait definitions
    #[allow(dead_code)] // Used in tests
    #[must_use]
    pub(crate) fn trait_definitions_count(&self) -> usize {
        self.trait_definitions.len()
    }

    /// Get a reference to the trait definitions (for debugging/testing)
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn trait_definitions(&self) -> &[TraitDefinition] {
        &self.trait_definitions
    }

    /// Find a trait definition by ID
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn find_trait(&self, id: &str) -> Option<&TraitDefinition> {
        self.trait_definitions.iter().find(|t| t.id == id)
    }

    /// Evaluate trait definitions against an analysis report with optional cached AST.
    /// `inline_yara` supplies pre-scanned results from the combined YARA engine, keyed by
    /// namespace (`"inline.{trait_id}"`), enabling fast lookup in `eval_yara_inline`.
    ///
    /// Platform filtering is controlled by the `platform` field set via `with_platform()`.
    #[must_use]
    pub(crate) fn evaluate_traits_with_ast(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        inline_yara: Option<&HashMap<String, Vec<Evidence>>>,
    ) -> Vec<Finding> {
        // Determine file type from report (platform comes from self.platform)
        let file_type = self.detect_file_type(&report.target.file_type);

        // Build section map for location-constrained matching
        let section_map = SectionMap::from_binary(binary_data);

        let mut ctx = EvaluationContext::new(
            report,
            binary_data,
            file_type,
            self.platforms.clone(),
            None,
            cached_ast,
        )
        .with_section_map(section_map);
        if let Some(results) = inline_yara {
            ctx = ctx.with_inline_yara(results);
        }

        // Use trait index to only evaluate applicable traits
        // This dramatically reduces work for specific file types
        let applicable_indices: Vec<usize> = self.trait_index.get_applicable(&file_type).collect();

        // Pre-filter using batched Aho-Corasick string matching WITH evidence caching
        // This identifies which traits match AND caches the evidence to avoid re-iteration
        let _t_prematch = std::time::Instant::now();

        // Combine strings and symbols for pre-filtering
        // Pre-allocate capacity to avoid reallocations
        let total_capacity = report.strings.len() + report.imports.len() + report.exports.len();
        let mut all_strings = Vec::with_capacity(total_capacity);

        // Add existing strings (move instead of clone to avoid copy)
        all_strings.extend_from_slice(&report.strings);

        // Add imports as strings
        for imp in &report.imports {
            all_strings.push(crate::types::StringInfo {
                value: imp.symbol.clone(),
                offset: None,
                encoding: "symbol".to_string(),
                string_type: crate::types::StringType::Import,
                section: None,
                encoding_chain: Vec::new(),
                fragments: None,
            });
        }

        // Add exports as strings
        for exp in &report.exports {
            // Parse export offset from hex string to u64
            let offset = exp.offset.as_ref().and_then(|s| {
                let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
                u64::from_str_radix(s, 16).ok()
            });
            all_strings.push(crate::types::StringInfo {
                value: exp.symbol.clone(),
                offset,
                encoding: "symbol".to_string(),
                string_type: crate::types::StringType::Export,
                section: None,
                encoding_chain: Vec::new(),
                fragments: None,
            });
        }

        let (string_matched_traits, cached_evidence) = if self.string_match_index.has_patterns() {
            self.string_match_index.find_matches_with_evidence(&all_strings)
        } else {
            (FxHashSet::default(), FxHashMap::default())
        };

        // Also find regex candidates based on literal prefix matching
        let regex_candidates = self.string_match_index.find_regex_candidates(&all_strings);

        // Pre-filter using batched regex matching for Content conditions
        // Only run if any applicable traits have content regex patterns
        let _t_raw_regex = std::time::Instant::now();
        let raw_regex_prefilter_enabled = self.raw_content_regex_index.has_patterns()
            && self.raw_content_regex_index.has_applicable_patterns(&applicable_indices);
        let (raw_regex_matched_traits, _has_excessive_line_length) = if raw_regex_prefilter_enabled
        {
            self.raw_content_regex_index.find_matches(binary_data, &file_type)
        } else {
            (FxHashSet::default(), false)
        };

        // Evaluate only applicable traits in parallel
        // For exact string traits with cached evidence, use that directly instead of re-evaluating
        let _t_eval = std::time::Instant::now();

        // Early termination: if no strings and no pre-matched traits, skip evaluation
        let has_any_matches = !string_matched_traits.is_empty()
            || !raw_regex_matched_traits.is_empty()
            || !regex_candidates.is_empty();

        if !has_any_matches && all_strings.is_empty() && binary_data.len() < 100 {
            return vec![];
        }

        // Free all_strings memory immediately - no longer needed after this point
        drop(all_strings);

        let eval_count = std::sync::atomic::AtomicUsize::new(0);
        let skip_count = std::sync::atomic::AtomicUsize::new(0);

        let all_findings: Vec<Finding> = applicable_indices
            .par_iter()
            .with_min_len(64)
            .filter_map(|&idx| {
                let trait_def = &self.trait_definitions[idx];

                // Check if this is an exact string trait (no excludes, count_min=1, no downgrade)
                // Works for both case-sensitive and case-insensitive
                // NOTE: Cannot use fast path for traits with downgrade rules - they need full evaluation
                let is_simple_exact_string = trait_def.downgrade.is_none()
                    && matches!(
                        &trait_def.r#if.condition,
                        Condition::String {
                            exact: Some(_),
                            exclude_patterns: None,
                            ..
                        }
                    )
                    && trait_def.r#if.count_min.unwrap_or(1) == 1
                    && trait_def.r#if.count_max.is_none()
                    && trait_def.r#if.per_kb_min.is_none()
                    && trait_def.r#if.per_kb_max.is_none();

                if is_simple_exact_string {
                    // Use cached evidence directly - skip full evaluation
                    if let Some(evidence) = cached_evidence.get(&idx) {
                        if !evidence.is_empty() {
                            return Some(Finding {
                                id: trait_def.id.clone(),
                                desc: trait_def.desc.clone(),
                                conf: trait_def.conf,
                                crit: trait_def.crit,
                                mbc: trait_def.mbc.clone(),
                                attack: trait_def.attack.clone(),
                                evidence: evidence.clone(),
                                kind: FindingKind::Capability,
                                trait_refs: vec![],
                                source_file: get_relative_source_file(&trait_def.defined_in),
                            });
                        }
                    }
                    return None;
                }

                // Check if this trait has an exact string pattern that wasn't matched
                let has_exact_string = matches!(
                    trait_def.r#if.condition,
                    Condition::String { exact: Some(_), .. }
                );

                // If trait has an exact string pattern and it wasn't matched, skip it
                if has_exact_string && !string_matched_traits.contains(&idx) {
                    skip_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return None;
                }

                // If trait has a regex string pattern and its literal wasn't found, skip it
                if self.string_match_index.is_regex_trait(idx) && !regex_candidates.contains(&idx) {
                    skip_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return None;
                }

                // Check if this trait has a content-based regex/word pattern that wasn't matched
                let has_content_regex = matches!(
                    trait_def.r#if.condition,
                    Condition::Raw { regex: Some(_), .. } | Condition::Raw { word: Some(_), .. }
                );

                // Skip only when pre-filtering is enabled and this trait is indexed there.
                // Unindexed traits must still be evaluated normally.
                if has_content_regex
                    && raw_regex_prefilter_enabled
                    && self.raw_content_regex_index.is_indexed_trait(idx)
                    && !raw_regex_matched_traits.contains(&idx)
                {
                    skip_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return None;
                }

                // Skip conditions that can never match this file type
                // (e.g., binary-only conditions on source files)
                if !trait_def.r#if.can_match_file_type(&file_type) {
                    skip_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return None;
                }

                eval_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                trait_def.evaluate(&ctx)
            })
            .collect();

        // Deduplicate findings (keep first occurrence of each ID)
        let mut seen = std::collections::HashSet::new();
        let mut unique_findings: Vec<Finding> =
            all_findings.into_iter().filter(|f| seen.insert(f.id.clone())).collect();

        // Free excess capacity to reduce memory footprint
        unique_findings.shrink_to_fit();

        // Limit to reasonable maximum to prevent unbounded memory growth
        const MAX_FINDINGS_PER_FILE: usize = 500;
        if unique_findings.len() > MAX_FINDINGS_PER_FILE {
            // Keep highest priority findings (by criticality, then confidence)
            unique_findings.sort_by(|a, b| {
                b.crit.cmp(&a.crit).then_with(|| {
                    let conf_a = (a.conf * 100.0) as i32;
                    let conf_b = (b.conf * 100.0) as i32;
                    conf_b.cmp(&conf_a)
                })
            });
            unique_findings.truncate(MAX_FINDINGS_PER_FILE);
            unique_findings.shrink_to_fit();
        }

        unique_findings
    }

    /// Evaluate trait definitions against an analysis report (without cached AST)
    /// Wrapper for evaluate_traits_with_ast
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn evaluate_traits(&self, report: &AnalysisReport, binary_data: &[u8]) -> Vec<Finding> {
        self.evaluate_traits_with_ast(report, binary_data, None, None)
    }

    /// Evaluate composite rules against an analysis report.
    /// `inline_yara` supplies pre-scanned results from the combined YARA engine.
    ///
    /// Platform filtering is controlled by the `platform` field set via `with_platform()`.
    #[must_use]
    pub(crate) fn evaluate_composite_rules(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        inline_yara: Option<&HashMap<String, Vec<Evidence>>>,
    ) -> Vec<Finding> {
        // Determine file type from report (platform comes from self.platform)
        let file_type = self.detect_file_type(&report.target.file_type);

        // Pre-allocate capacity for findings to reduce reallocations
        let mut all_findings: Vec<Finding> = Vec::with_capacity(100);
        let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

        // Track which composite IDs have already matched (including original findings)
        for finding in &report.findings {
            seen_ids.insert(finding.id.clone());
        }

        // Split rules into two groups: those with negative conditions and those without
        let (negative_rules, positive_rules): (Vec<&CompositeTrait>, Vec<&CompositeTrait>) =
            self.composite_rules.iter().partition(|r| r.has_negative_conditions());

        // Build section map once for location-constrained matching
        let section_map = SectionMap::from_binary(binary_data);

        // Pass 1: Iterative evaluation of positive rules to reach a stable fixed-point
        const MAX_ITERATIONS: usize = 10;
        for _ in 0..MAX_ITERATIONS {
            let mut ctx = EvaluationContext::new(
                report,
                binary_data,
                file_type,
                self.platforms.clone(),
                if all_findings.is_empty() { None } else { Some(&all_findings) },
                cached_ast,
            )
            .with_section_map(section_map.clone());
            if let Some(results) = inline_yara {
                ctx = ctx.with_inline_yara(results);
            }

            // Evaluate positive rules (parallel for large sets, sequential for small)
            let new_findings: Vec<Finding> = if positive_rules.len() > 50 {
                positive_rules
                    .par_iter()
                    .filter_map(|rule| rule.evaluate(&ctx))
                    .filter(|f| !seen_ids.contains(&f.id))
                    .collect()
            } else {
                positive_rules
                    .iter()
                    .filter_map(|rule| rule.evaluate(&ctx))
                    .filter(|f| !seen_ids.contains(&f.id))
                    .collect()
            };

            if new_findings.is_empty() {
                break;
            }

            // Add new findings to the accumulated set
            for finding in new_findings {
                seen_ids.insert(finding.id.clone());
                all_findings.push(finding);
            }
        }

        // Pass 2: Final evaluation of rules with negative conditions (exclusions)
        // These are only checked AFTER all positive indicators have reached a stable state.
        let mut ctx = EvaluationContext::new(
            report,
            binary_data,
            file_type,
            self.platforms.clone(),
            if all_findings.is_empty() { None } else { Some(&all_findings) },
            cached_ast,
        )
        .with_section_map(section_map.clone());
        if let Some(results) = inline_yara {
            ctx = ctx.with_inline_yara(results);
        }

        let negative_findings: Vec<Finding> = if negative_rules.len() > 50 {
            negative_rules
                .par_iter()
                .filter_map(|rule| rule.evaluate(&ctx))
                .filter(|f| !seen_ids.contains(&f.id))
                .collect()
        } else {
            negative_rules
                .iter()
                .filter_map(|rule| rule.evaluate(&ctx))
                .filter(|f| !seen_ids.contains(&f.id))
                .collect()
        };

        for finding in negative_findings {
            all_findings.push(finding);
        }

        // Pass 3: Re-evaluate downgrades for all findings now that the full context is available.
        // This handles cases where a finding's downgrade depends on another composite that
        // wasn't available when it was first evaluated.
        self.reeval_downgrades(
            &mut all_findings,
            report,
            binary_data,
            cached_ast,
            file_type,
        );

        // Add finding for excessive line length (anti-analysis technique)
        // Check here as well in case composite rules are evaluated without traits
        const MAX_LINE_LENGTH: usize = 1_000_000;
        let content = String::from_utf8_lossy(binary_data);
        let has_excessive_line = content.lines().any(|line| line.len() > MAX_LINE_LENGTH);

        if has_excessive_line {
            all_findings.push(Finding {
                id: "obj/anti-static/excessive-line-length".to_string(),
                kind: FindingKind::Structural,
                desc:
                    "File contains excessively long lines (>1MB) that may cause regex backtracking"
                        .to_string(),
                conf: 0.9,
                crit: Criticality::Suspicious,
                mbc: None,
                attack: Some("T1027".to_string()), // Obfuscated Files or Information
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "line-length-analysis".to_string(),
                    source: "dissect".to_string(),
                    value: "Detected line(s) exceeding 1MB (potential anti-analysis technique)"
                        .to_string(),
                    location: None,
                }],
                source_file: None,
            });
        }

        all_findings
    }

    /// Re-evaluate downgrade conditions for all findings using the complete finding set.
    /// This handles ordering issues where a composite's downgrade depends on another composite.
    fn reeval_downgrades(
        &self,
        findings: &mut [Finding],
        report: &AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        file_type: RuleFileType,
    ) {
        use rustc_hash::FxHashMap;

        // Build a map of rule ID to rule for quick lookup
        let composite_map: FxHashMap<&str, &CompositeTrait> =
            self.composite_rules.iter().map(|r| (r.id.as_str(), r)).collect();

        // First pass: collect new criticalities (can't mutate while borrowing for context)
        let updates: Vec<(usize, Criticality)> = {
            // Build section map for location-constrained matching
            let section_map = SectionMap::from_binary(binary_data);

            // Create final context with all findings (immutable borrow)
            let ctx = EvaluationContext::new(
                report,
                binary_data,
                file_type,
                self.platforms.clone(),
                Some(findings),
                cached_ast,
            )
            .with_section_map(section_map);

            findings
                .iter()
                .enumerate()
                .filter_map(|(i, finding)| {
                    if let Some(rule) = composite_map.get(finding.id.as_str()) {
                        if let Some(downgrade_rules) = &rule.downgrade {
                            let new_crit =
                                rule.evaluate_downgrade(downgrade_rules, &rule.crit, &ctx);
                            if new_crit != finding.crit {
                                return Some((i, new_crit));
                            }
                        }
                    }
                    None
                })
                .collect()
        };

        // Second pass: apply updates
        let debug_downgrade = std::env::var("DEBUG_DOWNGRADE").is_ok();
        for (idx, new_crit) in updates {
            if debug_downgrade {
                eprintln!(
                    "DEBUG: Re-eval downgrade for '{}': {:?} -> {:?}",
                    findings[idx].id, findings[idx].crit, new_crit
                );
            }
            findings[idx].crit = new_crit;
        }
    }

    /// Evaluate all rules (atomic traits + composite rules) and merge findings into the report.
    /// This is the correct, foolproof way to evaluate traits that ensures evidence propagates
    /// from atomic traits to composite rules. Analyzers should use this method instead of
    /// calling evaluate_traits() and evaluate_composite_rules() separately.
    ///
    /// Platform filtering is controlled by the `platform` field set via `with_platform()`.
    /// Default is `Platform::All` which matches all rules regardless of platform.
    ///
    /// # Arguments
    /// * `report` - Mutable reference to the analysis report to merge findings into
    /// * `binary_data` - Raw file data for content-based matching
    /// * `cached_ast` - Optional cached tree-sitter AST for performance
    ///
    /// Evaluate all traits and composite rules and merge findings into the report.
    ///
    /// `inline_yara` supplies pre-scanned results from the combined YARA engine (keyed by
    /// `"inline.{trait_id}"`). Pass `None` when YARA is disabled or when called outside
    /// of a binary analysis context.
    ///
    /// # Example
    /// ```ignore
    /// // In an analyzer, after scanning:
    /// let (yara_matches, inline_yara) = engine.scan_bytes_with_inline(data, filter)?;
    /// self.capability_mapper.evaluate_and_merge_findings(&mut report, data, None, Some(&inline_yara));
    /// ```
    pub(crate) fn evaluate_and_merge_findings(
        &self,
        report: &mut AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        inline_yara: Option<&HashMap<String, Vec<Evidence>>>,
    ) {
        // Step 1: Evaluate atomic trait definitions
        let trait_findings =
            self.evaluate_traits_with_ast(report, binary_data, cached_ast, inline_yara);

        // Build a seen-IDs set once from existing report findings, then keep it up-to-date
        // as we merge — O(1) per lookup instead of O(n) linear scan.
        let mut seen: FxHashSet<String> =
            report.findings.iter().map(|f| f.id.clone()).collect();

        // Step 2: Merge atomic trait findings into report (so composites can reference them)
        for finding in trait_findings {
            if !seen.contains(finding.id.as_str()) {
                seen.insert(finding.id.clone());
                report.findings.push(finding);
            }
        }

        // Step 2.5: Generate synthetic meta/import findings from discovered imports
        // This MUST happen before Step 3 so composite rules can reference them
        Self::generate_import_findings(report);

        // Step 3: Evaluate composite rules (which can now access atomic traits AND meta/import findings)
        let composite_findings =
            self.evaluate_composite_rules(report, binary_data, cached_ast, inline_yara);

        // Step 4: Merge composite findings into report.
        // Rebuild seen to include meta/import findings added in step 2.5.
        let mut seen: FxHashSet<String> =
            report.findings.iter().map(|f| f.id.clone()).collect();
        for finding in composite_findings {
            if !seen.contains(finding.id.as_str()) {
                seen.insert(finding.id.clone());
                report.findings.push(finding);
            }
        }
    }

    /// Generate meta/import/ findings from discovered imports.
    ///
    /// Creates inert structural findings for each import, allowing composite rules
    /// to reference imports as traits. For example:
    /// - `meta/import/python/socket` for Python's socket module
    /// - `meta/import/npm/axios` for npm's axios package
    /// - `meta/import/elf/libcrypto.so` for ELF shared library imports
    pub(crate) fn generate_import_findings(report: &mut AnalysisReport) {
        // Collect existing finding IDs to avoid duplicates
        let mut seen_ids: FxHashSet<String> =
            report.findings.iter().map(|f| f.id.clone()).collect();

        let file_type = report.target.file_type.to_lowercase();
        let ecosystem = Self::detect_import_ecosystem(&file_type, "");
        let is_binary = matches!(ecosystem, "elf" | "macho" | "pe");

        let mut new_findings: Vec<Finding> = Vec::new();

        if is_binary {
            // For binaries: generate library-level and symbol-level findings
            // Library: meta/dylib/{library} - linked libraries (for composite trait matching)
            // Symbol: meta/internal/imported/{symbol} - imported symbols (for ML only, not composite traits)

            // Group symbols by library for dylib findings
            let mut libs_with_symbols: std::collections::HashMap<String, Vec<String>> =
                std::collections::HashMap::new();

            for import in &report.imports {
                if let Some(lib) = &import.library {
                    if !lib.is_empty() {
                        libs_with_symbols
                            .entry(lib.clone())
                            .or_default()
                            .push(import.symbol.clone());
                    }
                }

                // Generate symbol-level finding for ML (not for composite trait matching)
                let normalized_symbol = Self::normalize_import_name(&import.symbol);
                if !normalized_symbol.is_empty() {
                    let symbol_id = format!("meta/internal/imported::{}", normalized_symbol);
                    if !seen_ids.contains(&symbol_id) {
                        seen_ids.insert(symbol_id.clone());
                        new_findings.push(Finding {
                            id: symbol_id,
                            kind: FindingKind::Structural,
                            desc: format!("imports {}", import.symbol),
                            conf: 0.95,
                            crit: Criticality::Inert,
                            mbc: None,
                            attack: None,
                            trait_refs: Vec::new(),
                            evidence: vec![Evidence {
                                method: "symbol".to_string(),
                                source: "goblin".to_string(),
                                value: import.symbol.clone(),
                                location: import.library.clone(),
                            }],

                            source_file: None,
                        });
                    }
                }
            }

            // Generate a finding for each library
            for (library, symbols) in libs_with_symbols {
                let normalized_lib = Self::normalize_import_name(&library);
                if normalized_lib.is_empty() {
                    continue;
                }

                // No format prefix - we don't encode file types in trait IDs
                let id = format!("meta/dylib::{}", normalized_lib);

                if seen_ids.contains(&id) {
                    continue;
                }
                seen_ids.insert(id.clone());

                // Limit symbols in description to first 5
                let symbol_preview: Vec<_> = symbols.iter().take(5).cloned().collect();
                let desc = if symbols.len() > 5 {
                    format!(
                        "links {} ({}, ... +{} more)",
                        library,
                        symbol_preview.join(", "),
                        symbols.len() - 5
                    )
                } else {
                    format!("links {} ({})", library, symbol_preview.join(", "))
                };

                new_findings.push(Finding {
                    id,
                    kind: FindingKind::Structural,
                    desc,
                    conf: 0.95,
                    crit: Criticality::Inert,
                    mbc: None,
                    attack: None,
                    trait_refs: Vec::new(),
                    evidence: vec![Evidence {
                        method: "library".to_string(),
                        source: "goblin".to_string(),
                        value: library,
                        location: Some(format!("{} symbols", symbols.len())),
                    }],

                    source_file: None,
                });
            }
        } else {
            // For scripts: generate two types of findings:
            // 1. meta/import/{lang}/{module} for actual imports (usable in composite traits)
            // 2. meta/internal/imported/{symbol} for function calls (ML only, not for composites)
            for import in &report.imports {
                let normalized = Self::normalize_import_name(&import.symbol);
                if normalized.is_empty() {
                    continue;
                }

                if import.source == "ast" {
                    // Function calls go to meta/internal/imported/ for ML usage only
                    let symbol_id = format!("meta/internal/imported::{}", normalized);
                    if !seen_ids.contains(&symbol_id) {
                        seen_ids.insert(symbol_id.clone());
                        new_findings.push(Finding {
                            id: symbol_id,
                            kind: FindingKind::Structural,
                            desc: format!("calls {}", import.symbol),
                            conf: 0.95,
                            crit: Criticality::Inert,
                            mbc: None,
                            attack: None,
                            trait_refs: Vec::new(),
                            evidence: vec![Evidence {
                                method: "symbol".to_string(),
                                source: "ast".to_string(),
                                value: import.symbol.clone(),
                                location: None,
                            }],

                            source_file: None,
                        });
                    }
                } else {
                    // Actual imports go to meta/import/{lang}/{module} for composite traits
                    let source_ecosystem =
                        Self::detect_import_ecosystem(&file_type, &import.source);

                    let id = format!("meta/import/{}::{}", source_ecosystem, normalized);

                    if seen_ids.contains(&id) {
                        continue;
                    }
                    seen_ids.insert(id.clone());

                    let desc = match &import.library {
                        Some(lib) if !lib.is_empty() => {
                            format!("imports {} from {}", import.symbol, lib)
                        },
                        _ => format!("imports {}", import.symbol),
                    };

                    new_findings.push(Finding {
                        id,
                        kind: FindingKind::Structural,
                        desc,
                        conf: 0.95,
                        crit: Criticality::Inert,
                        mbc: None,
                        attack: None,
                        trait_refs: Vec::new(),
                        evidence: vec![Evidence {
                            method: "import".to_string(),
                            source: import.source.clone(),
                            value: import.symbol.clone(),
                            location: import.library.clone(),
                        }],

                        source_file: None,
                    });
                }
            }
        }

        report.findings.extend(new_findings);
    }

    /// Detect the ecosystem for an import based on file type and source.
    pub(crate) fn detect_import_ecosystem(file_type: &str, source: &str) -> &'static str {
        // First check source for explicit ecosystem markers
        match source {
            "npm" | "package.json" => return "npm",
            "pip" | "pypi" | "requirements.txt" => return "pypi",
            "gem" | "rubygems" | "gemfile" => return "rubygems",
            "cargo" | "crates.io" => return "cargo",
            "go" | "go.mod" => return "gomod",
            "maven" | "gradle" | "pom.xml" => return "maven",
            "composer" => return "composer",
            _ => {},
        }

        // For binary formats, use the binary type as ecosystem
        match file_type {
            "elf" | "so" => return "elf",
            "macho" | "dylib" => return "macho",
            "pe" | "exe" | "dll" => return "pe",
            _ => {},
        }

        // For source code, detect language from file type
        match file_type {
            "python" | "python_script" => "python",
            "javascript" | "js" | "typescript" | "ts" => "npm",
            "ruby" | "rb" => "ruby",
            "java" | "class" => "java",
            "go" => "go",
            "rust" | "rs" => "rust",
            "c" | "cpp" | "h" | "hpp" => "c",
            "php" => "php",
            "perl" | "pl" => "perl",
            "lua" => "lua",
            "shell" | "shellscript" | "shell_script" | "bash" | "sh" => "shell",
            "powershell" | "ps1" => "powershell",
            "swift" => "swift",
            "objectivec" | "objc" | "m" => "objc",
            "csharp" | "cs" => "dotnet",
            "scala" | "sc" => "scala",
            "groovy" | "gradle" => "groovy",
            "elixir" | "ex" | "exs" => "elixir",
            "zig" => "zig",
            "applescript" | "scpt" => "applescript",
            _ => "unknown",
        }
    }

    /// Normalize an import name for use in a finding ID.
    ///
    /// - Converts to lowercase
    /// - Converts dots and slashes to path separators (/)
    /// - Replaces other special characters with hyphens
    /// - Removes leading/trailing separators
    /// - Collapses multiple separators
    pub(crate) fn normalize_import_name(name: &str) -> String {
        // Convert dots and slashes to path separators for consistent hierarchical naming:
        // - Python: os.path.join -> os/path/join
        // - Ruby: net/http -> net/http
        // Replace other special chars with hyphens, collapse consecutive separators
        let mut result = String::with_capacity(name.len());
        let mut prev_sep = true; // Skip leading separators

        for c in name.to_lowercase().chars() {
            match c {
                c if c.is_ascii_alphanumeric() || c == '_' => {
                    result.push(c);
                    prev_sep = false;
                },
                '.' | '/' => {
                    // Both dots and slashes become path separators
                    if !prev_sep {
                        result.push('/');
                        prev_sep = true;
                    }
                },
                _ => {
                    if !prev_sep {
                        result.push('-');
                        prev_sep = true;
                    }
                },
            }
        }

        // Trim trailing separator
        if result.ends_with('/') || result.ends_with('-') {
            result.pop();
        }

        result
    }

    /// Detect file type from file type string
    fn detect_file_type(&self, file_type: &str) -> RuleFileType {
        match file_type.to_lowercase().as_str() {
            "elf" => RuleFileType::Elf,
            "macho" => RuleFileType::Macho,
            "pe" | "exe" => RuleFileType::Pe,
            "dylib" => RuleFileType::Dylib,
            "so" => RuleFileType::So,
            "dll" => RuleFileType::Dll,
            "shell" | "shellscript" | "shell_script" => RuleFileType::Shell,
            "batch" | "bat" | "cmd" => RuleFileType::Batch,
            "python" | "python_script" => RuleFileType::Python,
            "javascript" | "js" => RuleFileType::JavaScript,
            "typescript" | "ts" => RuleFileType::TypeScript,
            "c" | "h" => RuleFileType::C,
            "rust" | "rs" => RuleFileType::Rust,
            "go" => RuleFileType::Go,
            "java" => RuleFileType::Java,
            "class" => RuleFileType::Class,
            "ruby" | "rb" => RuleFileType::Ruby,
            "php" => RuleFileType::Php,
            "csharp" | "cs" => RuleFileType::CSharp,
            "lua" => RuleFileType::Lua,
            "perl" | "pl" => RuleFileType::Perl,
            "powershell" | "ps1" => RuleFileType::PowerShell,
            "swift" => RuleFileType::Swift,
            "objectivec" | "objc" | "m" => RuleFileType::ObjectiveC,
            "groovy" | "gradle" => RuleFileType::Groovy,
            "scala" | "sc" => RuleFileType::Scala,
            "zig" => RuleFileType::Zig,
            "elixir" | "ex" | "exs" => RuleFileType::Elixir,
            "applescript" | "scpt" => RuleFileType::AppleScript,
            // Manifest/config formats
            "package.json" | "packagejson" => RuleFileType::PackageJson,
            "chrome-manifest" | "chromemanifest" => RuleFileType::ChromeManifest,
            "cargo-toml" | "cargotoml" | "cargo.toml" => RuleFileType::CargoToml,
            "pyproject-toml" | "pyprojecttoml" | "pyproject.toml" => RuleFileType::PyProjectToml,
            "github-actions" | "githubactions" => RuleFileType::GithubActions,
            "composer-json" | "composerjson" | "composer.json" => RuleFileType::ComposerJson,
            "jpeg" | "jpg" => RuleFileType::Jpeg,
            "png" => RuleFileType::Png,
            _ => RuleFileType::All,
        }
    }
}

/// Validate trait and composite conditions for problematic patterns.
/// Warns about combinations that are unlikely to be helpful.
fn validate_conditions(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    path: &Path,
) {
    // Check trait definitions
    for trait_def in trait_definitions {
        check_condition(&trait_def.r#if.condition, &trait_def.id, path);
    }

    // Check composite rules
    for rule in composite_rules {
        // Check all conditions in the rule
        if let Some(all_conditions) = &rule.all {
            for cond in all_conditions {
                check_condition(cond, &rule.id, path);
            }
        }
        if let Some(any_conditions) = &rule.any {
            for cond in any_conditions {
                check_condition(cond, &rule.id, path);
            }
        }
        if let Some(none_conditions) = &rule.none {
            for cond in none_conditions {
                check_condition(cond, &rule.id, path);
            }
        }
        if let Some(unless_conditions) = &rule.unless {
            for cond in unless_conditions {
                check_condition(cond, &rule.id, path);
            }
        }
    }
}

/// Check raw YAML content for meaningless patterns before parsing.
/// Returns a list of warnings for patterns that are valid YAML but semantically meaningless.
fn check_yaml_patterns(content: &str, path: &Path) -> Vec<String> {
    let mut warnings = Vec::new();

    // Check for explicit 'offset: null' which is meaningless (same as not specifying)
    // Use regex to match the pattern with proper YAML indentation context
    #[allow(clippy::unwrap_used)] // Static regex pattern is hardcoded and valid
    fn offset_null_re() -> &'static regex::Regex {
        static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r"^\s+offset:\s*null\s*$").unwrap())
    }
    for (line_num, line) in content.lines().enumerate() {
        if offset_null_re().is_match(line) {
            warnings.push(format!(
                "{} line {}: 'offset: null' is meaningless (same as not specifying offset) - remove this line",
                path.display(),
                line_num + 1
            ));
        }
    }

    // Check for explicit 'section: null' which is also meaningless
    #[allow(clippy::unwrap_used)] // Static regex pattern is hardcoded and valid
    fn section_null_re() -> &'static regex::Regex {
        static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r"^\s+section:\s*null\s*$").unwrap())
    }
    for (line_num, line) in content.lines().enumerate() {
        if section_null_re().is_match(line) {
            warnings.push(format!(
                "{} line {}: 'section: null' is meaningless (same as not specifying section) - remove this line",
                path.display(),
                line_num + 1
            ));
        }
    }

    // Check for directories named "obfuscation" or "obfuscate" under cap/.
    // Obfuscation detection describes attacker intent (anti-analysis evasion), not observable
    // capability — it belongs in obj/, not cap/.
    {
        let components: Vec<_> = path.components().collect();
        // Find the index of a component named "cap"
        let cap_idx = components.iter().position(|c| {
            c.as_os_str().to_string_lossy().eq_ignore_ascii_case("cap")
        });
        if let Some(cap_pos) = cap_idx {
            // Check directory components after "cap/" but before the filename
            let dir_components = &components[cap_pos + 1..components.len().saturating_sub(1)];
            for component in dir_components {
                let name = component.as_os_str().to_string_lossy();
                if name.eq_ignore_ascii_case("obfuscation")
                    || name.eq_ignore_ascii_case("obfuscate")
                {
                    warnings.push(format!(
                        "{}: directory '{}' must not be under 'cap/' — obfuscation detection \
                         describes attacker intent (anti-analysis evasion), not an observable \
                         capability. Move this file to 'obj/anti-static/obfuscation/' or \
                         'obj/anti-analysis/obfuscation/'. See TAXONOMY.md: cap/ captures \
                         what code can do; obj/ captures attacker goals.",
                        path.display(),
                        name
                    ));
                    break; // one warning per file is enough
                }
            }
        }
    }

    warnings
}

/// Check a single condition for problematic patterns
fn check_condition(
    condition: &crate::composite_rules::condition::Condition,
    trait_id: &str,
    path: &Path,
) {
    use crate::composite_rules::condition::Condition;

    if let Condition::Raw { exact: Some(_), .. } = condition {
        eprintln!(
            "❌ ERROR: Trait '{}' in {} uses 'type: raw' with 'exact' match. \
            This requires the entire file content to exactly match the pattern, \
            which is rarely useful. Consider using 'substr' instead.",
            trait_id,
            path.display()
        );
    }
}

/// Collect all metric field references from a trait definition
fn collect_metric_refs_from_trait(trait_def: &TraitDefinition) -> Vec<String> {
    let mut fields = Vec::new();
    collect_metric_refs_from_condition(&trait_def.r#if.condition, &mut fields);
    fields
}

/// Recursively collect metric field references from a condition
fn collect_metric_refs_from_condition(condition: &Condition, fields: &mut Vec<String>) {
    if let Condition::Metrics { field, .. } = condition {
        fields.push(field.clone());
    }
}

/// Get all valid metric field paths
/// Dynamically extracts all field paths from metrics struct definitions
fn get_valid_metric_fields() -> FxHashSet<String> {
    // Use the auto-generated field paths from the ValidFieldPaths derive macro
    // This ensures the validation always stays in sync with actual struct definitions
    crate::types::field_paths::all_valid_metric_paths().into_iter().collect()
}

/// Suggest a similar metric field for typos (simple Levenshtein distance)
fn suggest_metric_field(valid_fields: &FxHashSet<String>, typo: &str) -> Option<String> {
    let mut best_match: Option<(String, usize)> = None;

    for valid_field in valid_fields {
        let distance = strsim::levenshtein(typo, valid_field);
        if distance <= 3 {
            // Only suggest if within 3 edits
            if let Some((_, best_dist)) = best_match {
                if distance < best_dist {
                    best_match = Some((valid_field.clone(), distance));
                }
            } else {
                best_match = Some((valid_field.clone(), distance));
            }
        }
    }

    best_match.map(|(field, _)| field)
}

impl Default for CapabilityMapper {
    fn default() -> Self {
        Self::new()
    }
}
