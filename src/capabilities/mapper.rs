//! Core CapabilityMapper implementation.
//!
//! This module provides the main `CapabilityMapper` struct which:
//! - Loads capability definitions from YAML files
//! - Maps symbols to capability IDs
//! - Evaluates trait definitions and composite rules against analysis reports
//! - Provides platform and file type detection

use crate::composite_rules::{
    CompositeTrait, Condition, EvaluationContext, FileType as RuleFileType, Platform,
    TraitDefinition,
};
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
use anyhow::{Context, Result};
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use super::indexes::{RawContentRegexIndex, StringMatchIndex, TraitIndex};
use super::models::{TraitInfo, TraitMappings};
use super::parsing::{apply_composite_defaults, apply_trait_defaults};
use super::validation::{
    autoprefix_trait_refs, collect_trait_refs_from_rule, find_line_number,
    simple_rule_to_composite_rule, validate_composite_trait_only,
    validate_hostile_composite_precision,
};

/// Maps symbols (function names, library calls) to capability IDs
/// Also supports trait definitions and composite rules that combine traits
#[derive(Clone)]
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
}

impl CapabilityMapper {
    /// Create an empty capability mapper for testing
    pub fn empty() -> Self {
        Self {
            symbol_map: HashMap::new(),
            trait_definitions: Vec::new(),
            composite_rules: Vec::new(),
            trait_index: TraitIndex::new(),
            string_match_index: StringMatchIndex::default(),
            raw_content_regex_index: RawContentRegexIndex::default(),
        }
    }

    pub fn new() -> Self {
        // Try to load from capabilities directory, fall back to single file
        // YAML parse errors or invalid trait configurations are fatal
        match Self::from_directory("traits") {
            Ok(mapper) => {
                return mapper;
            }
            Err(e) => {
                // Check if this is a YAML parse error or invalid configuration
                // These are fatal and should exit immediately with clear error message
                let error_chain = format!("{:#}", e);
                if error_chain.contains("Failed to parse YAML")
                    || error_chain.contains("invalid condition")
                {
                    eprintln!("\n❌ FATAL: Invalid trait configuration file\n");
                    eprintln!("   {}", error_chain);
                    eprintln!();
                    std::process::exit(1);
                }
                // Always show non-parse errors
                eprintln!("⚠️  Failed to load from traits/ directory: {:#}", e);
            }
        }

        match Self::from_yaml("capabilities.yaml") {
            Ok(mapper) => {
                return mapper;
            }
            Err(e) => {
                // Check if this is a YAML parse error - fatal
                let error_chain = format!("{:#}", e);
                if error_chain.contains("Failed to parse") {
                    eprintln!("\n❌ FATAL: Invalid capabilities.yaml file\n");
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
            }
        }

        eprintln!("\n❌ FATAL: Failed to load capabilities from any source");
        eprintln!("   Tried: traits/ directory, capabilities.yaml\n");
        std::process::exit(1);
    }

    /// Load capability mappings from directory of YAML files (recursively)
    pub fn from_directory<P: AsRef<Path>>(dir_path: P) -> Result<Self> {
        let debug = std::env::var("DISSECT_DEBUG").is_ok();
        let timing = std::env::var("DISSECT_TIMING").is_ok();
        let dir_path = dir_path.as_ref();
        let t_start = std::time::Instant::now();

        if debug {
            eprintln!("🔍 Loading capabilities from: {}", dir_path.display());
        }

        // First, collect all YAML file paths
        let mut yaml_files: Vec<_> = walkdir::WalkDir::new(dir_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
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

        // Sort files deterministically by path to ensure consistent loading order across OSes
        yaml_files.sort();

        if yaml_files.is_empty() {
            anyhow::bail!("No YAML files found in {}", dir_path.display());
        }

        if timing {
            eprintln!(
                "[TIMING] Collected {} YAML files: {:?}",
                yaml_files.len(),
                t_start.elapsed()
            );
        }
        let t_parse = std::time::Instant::now();

        // Load all YAML files in parallel, preserving path for prefix calculation
        // Use indexed_map to preserve sorted order
        let results: Vec<_> = yaml_files
            .par_iter()
            .enumerate()
            .map(|(idx, path)| {
                if debug {
                    eprintln!("   📄 Loading: {}", path.display());
                }

                let bytes = fs::read(path).with_context(|| format!("Failed to read {:?}", path))?;
                let content = String::from_utf8_lossy(&bytes);

                let mappings: TraitMappings = serde_yaml::from_str(&content)
                    .with_context(|| format!("Failed to parse YAML in {:?}", path))?;

                Ok::<_, anyhow::Error>((idx, path.clone(), mappings))
            })
            .collect();

        // Sort results back to original order since par_iter doesn't preserve order
        let mut sorted_results: Vec<_> = results;
        sorted_results.sort_by_key(|r| match r {
            Ok((idx, _, _)) => *idx,
            Err(_) => std::usize::MAX,
        });

        if timing {
            eprintln!("[TIMING] Parsed YAML files: {:?}", t_parse.elapsed());
        }
        let t_merge = std::time::Instant::now();

        // Merge all results, collecting errors to report all at once
        let mut symbol_map = HashMap::new();
        let mut trait_definitions: Vec<TraitDefinition> = Vec::new();
        let mut composite_rules: Vec<CompositeTrait> = Vec::new();
        let mut rule_source_files: HashMap<String, String> = HashMap::new(); // rule_id -> file_path
        let mut files_processed = 0;
        let mut warnings: Vec<String> = Vec::new();
        let mut parse_errors: Vec<String> = Vec::new();

        for result in sorted_results {
            let (path, mappings) = match result {
                Ok((_idx, p, m)) => (p, m),
                Err(e) => {
                    // Format error with full chain (includes filename from context)
                    parse_errors.push(format!("{:#}", e));
                    continue;
                }
            };
            files_processed += 1;

            // Calculate the prefix from the directory path relative to traits/
            // e.g., traits/credential/java/traits.yaml -> credential/java
            let trait_prefix = path
                .strip_prefix(dir_path)
                .ok()
                .and_then(|p| p.parent())
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .filter(|s| !s.is_empty());

            let before_symbols = symbol_map.len();
            let before_traits = trait_definitions.len();
            let before_composites = composite_rules.len();

            // Merge symbols
            for mapping in mappings.symbols {
                symbol_map.insert(
                    mapping.symbol.clone(),
                    TraitInfo {
                        id: mapping.capability,
                        desc: mapping.desc,
                        conf: mapping.conf,
                    },
                );
            }

            // Merge simple_rules
            for rule in mappings.simple_rules {
                // If rule has platform or file_type constraints, convert to composite rule
                if !rule.platforms.is_empty() || !rule.file_types.is_empty() {
                    let composite = simple_rule_to_composite_rule(rule);
                    composite_rules.push(composite);
                } else {
                    // No constraints - add to symbol map for fast lookup
                    symbol_map.insert(
                        rule.symbol.clone(),
                        TraitInfo {
                            id: rule.capability,
                            desc: rule.desc,
                            conf: rule.conf,
                        },
                    );
                }
            }

            // Merge trait definitions with auto-prefixed IDs, applying file-level defaults
            let traits_count = mappings.traits.len();
            for raw_trait in mappings.traits {
                // Convert raw trait to final trait, applying file-level defaults
                let mut trait_def =
                    apply_trait_defaults(raw_trait, &mappings.defaults, &mut warnings);

                // Auto-prefix trait ID if it doesn't already have the path prefix
                if let Some(ref prefix) = trait_prefix {
                    if !trait_def.id.starts_with(prefix) && !trait_def.id.contains('/') {
                        trait_def.id = format!("{}/{}", prefix, trait_def.id);
                    }
                }
                // Validate YARA/AST conditions at load time
                trait_def.r#if.validate().with_context(|| {
                    format!(
                        "invalid condition in trait '{}' from {:?}",
                        trait_def.id, path
                    )
                })?;
                // Check for greedy regex patterns
                if let Some(warning) = trait_def.r#if.check_greedy_patterns() {
                    warnings.push(format!(
                        "trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    ));
                }

                // Check for ID conflicts with previously loaded traits (cross-file duplicates)
                if trait_definitions.iter().any(|t| t.id == trait_def.id) {
                    warnings.push(format!(
                        "Trait ID '{}' defined in multiple files - last definition wins",
                        trait_def.id
                    ));
                    // Remove the old one so we add the new one
                    trait_definitions.retain(|t| t.id != trait_def.id);
                }

                // Check for ID conflicts with composite rules
                if composite_rules.iter().any(|r| r.id == trait_def.id) {
                    warnings.push(format!(
                        "Rule ID '{}' defined as both trait and composite rule - trait will be used",
                        trait_def.id
                    ));
                    if let Some(comp_file) = rule_source_files
                        .iter()
                        .find(|(id, _)| *id == &trait_def.id)
                        .map(|(_, f)| f)
                    {
                        warnings.push(format!("  Trait: {}", path.display()));
                        warnings.push(format!("  Composite (will be replaced): {}", comp_file));
                    }
                    // Remove the composite rule
                    composite_rules.retain(|r| r.id != trait_def.id);
                }

                trait_definitions.push(trait_def);
            }

            // Extract symbol mappings from trait definitions with symbol conditions
            for trait_def in
                &trait_definitions[trait_definitions.len().saturating_sub(traits_count)..]
            {
                // Check if this trait has a symbol condition
                if let Condition::Symbol {
                    exact,
                    substr: _,
                    regex,
                    platforms: _,
                    compiled_regex: _,
                } = &trait_def.r#if
                {
                    // Check if there are no platform constraints, or add anyway for lookup
                    // (platform filtering will happen later during evaluation)

                    // If exact is specified, add it directly
                    if let Some(exact_val) = exact {
                        symbol_map
                            .entry(exact_val.clone())
                            .or_insert_with(|| TraitInfo {
                                id: trait_def.id.clone(),
                                desc: trait_def.desc.clone(),
                                conf: trait_def.conf,
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
                            });
                        }
                    }
                }
            }

            // Merge composite_rules with auto-prefixed IDs, applying file-level defaults
            for raw_rule in mappings.composite_rules {
                // Convert raw rule to final rule, applying file-level defaults
                let mut rule = apply_composite_defaults(raw_rule, &mappings.defaults);

                // Auto-prefix composite rule ID if it doesn't already have the path prefix
                if let Some(ref prefix) = trait_prefix {
                    if !rule.id.starts_with(prefix) && !rule.id.contains('/') {
                        rule.id = format!("{}/{}", prefix, rule.id);
                    }
                    // Also auto-prefix trait references within the rule's conditions
                    autoprefix_trait_refs(&mut rule, prefix);
                }

                // Check for duplicate rule ID with other composite rules
                if let Some(existing) = composite_rules.iter().position(|r| r.id == rule.id) {
                    warnings.push(format!(
                        "Composite rule '{}' defined in multiple files - last definition wins",
                        rule.id
                    ));
                    composite_rules.remove(existing);
                }

                // Check for ID conflicts with trait definitions
                if trait_definitions.iter().any(|t| t.id == rule.id) {
                    warnings.push(format!(
                        "Rule ID '{}' defined as both trait and composite rule - composite will be used",
                        rule.id
                    ));
                    warnings.push(format!("  Trait (will be replaced): (already loaded)"));
                    warnings.push(format!("  Composite: {}", path.display()));
                    // Remove the trait definition
                    trait_definitions.retain(|t| t.id != rule.id);
                }

                // Track source file for error reporting
                rule_source_files.insert(rule.id.clone(), path.display().to_string());
                composite_rules.push(rule);
            }

            if debug {
                eprintln!(
                    "      +{} symbols, +{} traits, +{} composite rules",
                    symbol_map.len() - before_symbols,
                    trait_definitions.len() - before_traits,
                    composite_rules.len() - before_composites
                );
            }
        }

        if debug {
            eprintln!("   ✅ Processed {} YAML files", files_processed);
        }

        if timing {
            eprintln!("[TIMING] Merged results: {:?}", t_merge.elapsed());
        }
        let t_yara = std::time::Instant::now();

        // Pre-compile all YARA rules for faster evaluation (parallelized)
        let yara_count_traits = trait_definitions
            .iter()
            .filter(|t| matches!(t.r#if, Condition::Yara { .. }))
            .count();

        // Use rayon's par_iter_mut for parallel YARA compilation
        trait_definitions.par_iter_mut().for_each(|t| {
            if matches!(t.r#if, Condition::Yara { .. }) {
                t.compile_yara();
            }
        });

        let yara_count_composite = composite_rules.len();
        composite_rules.par_iter_mut().for_each(|r| {
            r.compile_yara();
        });

        if debug && (yara_count_traits > 0 || yara_count_composite > 0) {
            eprintln!(
                "   ⚡ Pre-compiled YARA rules in {} traits, {} composite rules",
                yara_count_traits, yara_count_composite
            );
        }

        if timing {
            eprintln!("[TIMING] Pre-compiled YARA: {:?}", t_yara.elapsed());
        }
        let t_validate = std::time::Instant::now();

        // Post-process HOSTILE composite rules to properly calculate precision
        // Now that all rules are loaded, we can recursively calculate true precision
        validate_hostile_composite_precision(
            &mut composite_rules,
            &trait_definitions,
            &mut warnings,
        );

        // Validate trait references in composite rules
        // Cross-directory references (containing '/') must match an existing directory prefix
        // Include both trait definition prefixes AND composite rule prefixes (rules can reference rules)
        let mut known_prefixes: std::collections::HashSet<String> = trait_definitions
            .iter()
            .filter_map(|t| {
                // Extract the directory prefix from trait IDs (everything before the last '/')
                t.id.rfind('/').map(|idx| t.id[..idx].to_string())
            })
            .collect();

        // Also add composite rule prefixes (composite rules can reference other composite rules)
        for rule in &composite_rules {
            if let Some(idx) = rule.id.rfind('/') {
                known_prefixes.insert(rule.id[..idx].to_string());
            }
        }

        let mut invalid_refs = Vec::new();
        for rule in &composite_rules {
            let trait_refs = collect_trait_refs_from_rule(rule);
            for (ref_id, rule_id) in trait_refs {
                // Only validate cross-directory references (those with slashes)
                if ref_id.contains('/') {
                    // Check if this matches any known prefix
                    let matches_prefix = known_prefixes
                        .iter()
                        .any(|prefix| prefix.starts_with(&ref_id) || ref_id.starts_with(prefix));
                    if !matches_prefix {
                        let source_file = rule_source_files
                            .get(&rule_id)
                            .map(|s| s.as_str())
                            .unwrap_or("unknown");
                        invalid_refs.push((rule_id.clone(), ref_id, source_file.to_string()));
                    }
                }
            }
        }

        if !invalid_refs.is_empty() {
            eprintln!(
                "\n⚠️  WARNING: {} invalid trait references found in composite rules",
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

        // Pre-compile all regexes for performance
        for trait_def in &mut trait_definitions {
            trait_def.r#if.precompile_regexes();
        }

        // Validate exact trait ID references
        // Build set of all valid trait IDs (both atomic traits and composite rules)
        let mut valid_trait_ids: FxHashSet<String> =
            trait_definitions.iter().map(|t| t.id.clone()).collect();
        for rule in &composite_rules {
            valid_trait_ids.insert(rule.id.clone());
        }

        let mut broken_refs = Vec::new();
        for rule in &composite_rules {
            let trait_refs = collect_trait_refs_from_rule(rule);
            for (ref_id, rule_id) in trait_refs {
                // Skip validation for directory-level references (intentional loose coupling)
                // e.g., "discovery/system" matches any trait in that directory
                let is_directory_ref = known_prefixes.contains(&ref_id);

                // Check if the exact trait ID exists (unless it's an intentional directory ref)
                if !is_directory_ref && !valid_trait_ids.contains(&ref_id) {
                    // Also check if it's a partial match to a known prefix (could be typo)
                    let matches_any_prefix = known_prefixes
                        .iter()
                        .any(|prefix| ref_id.starts_with(prefix) || prefix.starts_with(&ref_id));

                    if !matches_any_prefix {
                        let source_file = rule_source_files
                            .get(&rule_id)
                            .map(|s| s.as_str())
                            .unwrap_or("unknown");
                        broken_refs.push((rule_id.clone(), ref_id, source_file.to_string()));
                    }
                }
            }
        }

        if !broken_refs.is_empty() {
            eprintln!(
                "\n⚠️  WARNING: {} broken trait references found in composite rules",
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

        // Validate that composite rules only contain trait references (not inline primitives)
        // Strict mode is the default - composite rules must only reference traits
        // Set DISSECT_ALLOW_INLINE_PRIMITIVES=1 to temporarily allow inline primitives
        let allow_inline = std::env::var("DISSECT_ALLOW_INLINE_PRIMITIVES").is_ok();
        if !allow_inline {
            let mut inline_errors = Vec::new();
            for rule in &composite_rules {
                let source = rule_source_files
                    .get(&rule.id)
                    .map(|s| s.as_str())
                    .unwrap_or("unknown");
                inline_errors.extend(validate_composite_trait_only(rule, source));
            }

            if !inline_errors.is_empty() {
                eprintln!(
                    "\n❌ FATAL: {} composite rules have inline primitives\n",
                    inline_errors.len()
                );
                for err in &inline_errors {
                    eprintln!("   {}", err);
                }
                eprintln!("\n   Composite rules must only reference traits (type: trait).");
                eprintln!(
                    "   Convert inline conditions (string, symbol, yara, etc.) to atomic traits."
                );
                eprintln!(
                    "   Set DISSECT_ALLOW_INLINE_PRIMITIVES=1 to temporarily bypass this check.\n"
                );
                std::process::exit(1);
            }
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

        let mut redundant_composites = Vec::new();
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
                                .map(|s| s.as_str())
                                .unwrap_or("unknown");
                            redundant_composites.push((
                                rule.id.clone(),
                                ref_id.clone(),
                                source_file.to_string(),
                            ));
                        }
                    }
                }
            }
        }

        if !redundant_composites.is_empty() {
            eprintln!(
                "\n⚠️  WARNING: {} single-rule composites have identical file types to their referenced trait",
                redundant_composites.len()
            );
            eprintln!(
                "   These composites add no value - consider removing them or adding more conditions:\n"
            );
            for (rule_id, ref_id, source_file) in &redundant_composites {
                let line_hint = find_line_number(source_file, rule_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Composite '{}' only references '{}' with same file types",
                        source_file, line, rule_id, ref_id
                    );
                } else {
                    eprintln!(
                        "   {}: Composite '{}' only references '{}' with same file types",
                        source_file, rule_id, ref_id
                    );
                }
            }
            eprintln!();
            std::process::exit(1);
        }

        if timing {
            eprintln!("[TIMING] Validated refs: {:?}", t_validate.elapsed());
            eprintln!("[TIMING] Total from_directory: {:?}", t_start.elapsed());
        }

        // Build trait index for fast lookup by file type
        let trait_index = TraitIndex::build(&trait_definitions);

        // Build string match index for batched AC matching
        let t_string_index = std::time::Instant::now();
        let string_match_index = StringMatchIndex::build(&trait_definitions);
        if timing {
            eprintln!(
                "[TIMING] Built string index ({} patterns): {:?}",
                string_match_index.total_patterns,
                t_string_index.elapsed()
            );
        }

        // Build raw content regex index for batched regex matching
        let t_raw_regex_index = std::time::Instant::now();
        let raw_content_regex_index = RawContentRegexIndex::build(&trait_definitions);
        if timing {
            eprintln!(
                "[TIMING] Built raw content regex index ({} patterns): {:?}",
                raw_content_regex_index.total_patterns,
                t_raw_regex_index.elapsed()
            );
        }

        // Parse errors are fatal - print all and exit if any exist
        if !parse_errors.is_empty() {
            eprintln!(
                "\n❌ FATAL: {} YAML parsing error(s) found:\n",
                parse_errors.len()
            );
            for error in &parse_errors {
                eprintln!("   {}", error);
            }
            eprintln!("\n   Fix these issues in the YAML files before continuing.\n");
            std::process::exit(1);
        }

        // Warnings are fatal - print all and exit if any exist
        if !warnings.is_empty() {
            eprintln!(
                "\n❌ FATAL: {} trait configuration warning(s) found:\n",
                warnings.len()
            );
            for warning in &warnings {
                eprintln!("   ⚠️  {}", warning);
            }
            eprintln!("\n   Fix these issues in the YAML files before continuing.\n");
            std::process::exit(1);
        }

        Ok(Self {
            symbol_map,
            trait_definitions,
            composite_rules,
            trait_index,
            string_match_index,
            raw_content_regex_index,
        })
    }

    /// Load capability mappings from YAML file
    pub fn from_yaml<P: AsRef<Path>>(path: P) -> Result<Self> {
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
                },
            );
        }

        // Convert raw traits to final traits with defaults applied
        let mut warnings: Vec<String> = Vec::new();
        let mut trait_definitions: Vec<TraitDefinition> = mappings
            .traits
            .into_iter()
            .map(|raw| apply_trait_defaults(raw, &mappings.defaults, &mut warnings))
            .collect();

        // Pre-compile all regexes for performance
        for trait_def in &mut trait_definitions {
            trait_def.r#if.precompile_regexes();
        }

        // Convert raw composite rules to final rules with defaults applied
        let mut composite_rules: Vec<CompositeTrait> = mappings
            .composite_rules
            .into_iter()
            .map(|raw| apply_composite_defaults(raw, &mappings.defaults))
            .collect();

        // Validate HOSTILE composite precision
        validate_hostile_composite_precision(
            &mut composite_rules,
            &trait_definitions,
            &mut warnings,
        );

        // Validate trait and composite conditions and warn about problematic patterns
        validate_conditions(&trait_definitions, &composite_rules, path.as_ref());

        // Warnings are fatal
        if !warnings.is_empty() {
            eprintln!(
                "\n❌ FATAL: {} trait configuration warning(s) found:\n",
                warnings.len()
            );
            for warning in &warnings {
                eprintln!("   ⚠️  {}", warning);
            }
            eprintln!("\n   Fix these issues in the YAML files before continuing.\n");
            std::process::exit(1);
        }

        // Build trait index for fast lookup by file type
        let trait_index = TraitIndex::build(&trait_definitions);

        // Build string match index for batched AC matching
        let string_match_index = StringMatchIndex::build(&trait_definitions);

        // Build raw content regex index for batched regex matching
        let raw_content_regex_index = RawContentRegexIndex::build(&trait_definitions);

        Ok(Self {
            symbol_map,
            trait_definitions,
            composite_rules,
            trait_index,
            string_match_index,
            raw_content_regex_index,
        })
    }

    /// Look up a symbol and return its capability finding if known
    pub fn lookup(&self, symbol: &str, source: &str) -> Option<Finding> {
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
                crit: Criticality::Inert,
                mbc: None,
                attack: None,
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "symbol".to_string(),
                    source: source.to_string(),
                    value: symbol.to_string(),
                    location: None,
                }],
            });
        }

        None
    }

    /// Map YARA rule path to capability ID
    /// Example: "rules/exec/cmd/cmd.yara" → "exec/command/shell"
    pub fn yara_rule_to_capability(&self, rule_path: &str) -> Option<String> {
        // Extract the path components after "rules/"
        let path = rule_path.strip_prefix("rules/").unwrap_or(rule_path);

        // Map directory structure to capability IDs
        // This follows the malcontent rule structure
        let parts: Vec<&str> = path.split('/').collect();

        if parts.is_empty() {
            return None;
        }

        // Build capability ID from path components
        // Example: exec/cmd/cmd.yara → exec/command/shell
        match (parts.first(), parts.get(1)) {
            (Some(&"exec"), Some(&"cmd")) => Some("exec/command/shell".to_string()),
            (Some(&"exec"), Some(&"program")) => Some("exec/command/direct".to_string()),
            (Some(&"exec"), Some(&"shell")) => Some("exec/command/shell".to_string()),
            (Some(&"net"), Some(&"ftp")) => Some("net/ftp/client".to_string()),
            (Some(&"net"), Some(&"http")) => Some("net/http/client".to_string()),
            (Some(&"crypto"), sub) => Some(format!("crypto/{}", sub.unwrap_or(&"generic"))),
            (Some(&"anti-static"), Some(&"obfuscation")) => {
                // Get the specific obfuscation type
                if let Some(&obf_type) = parts.get(2) {
                    let type_clean = obf_type.trim_end_matches(".yara");
                    Some(format!("anti-analysis/obfuscation/{}", type_clean))
                } else {
                    Some("anti-analysis/obfuscation".to_string())
                }
            }
            (Some(&"fs"), sub) => Some(format!("fs/{}", sub.unwrap_or(&"generic"))),
            (Some(category), sub) => Some(format!("{}/{}", category, sub.unwrap_or(&"generic"))),
            _ => None,
        }
    }

    /// Get the number of loaded symbol mappings
    pub fn mapping_count(&self) -> usize {
        self.symbol_map.len()
    }

    /// Get the number of loaded composite rules
    pub fn composite_rules_count(&self) -> usize {
        self.composite_rules.len()
    }

    /// Get the number of loaded trait definitions
    pub fn trait_definitions_count(&self) -> usize {
        self.trait_definitions.len()
    }

    /// Get a reference to the trait definitions (for debugging/testing)
    pub fn trait_definitions(&self) -> &[TraitDefinition] {
        &self.trait_definitions
    }

    /// Find a trait definition by ID
    pub fn find_trait(&self, id: &str) -> Option<&TraitDefinition> {
        self.trait_definitions.iter().find(|t| t.id == id)
    }

    /// Evaluate trait definitions against an analysis report with optional cached AST
    /// Returns findings detected from trait definitions
    pub fn evaluate_traits_with_ast(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
    ) -> Vec<Finding> {
        let timing = std::env::var("DISSECT_TIMING").is_ok();

        // Determine platform and file type from report
        let platform = self.detect_platform(&report.target.file_type);
        let file_type = self.detect_file_type(&report.target.file_type);

        let ctx =
            EvaluationContext::new(report, binary_data, file_type, platform, None, cached_ast);

        // Use trait index to only evaluate applicable traits
        // This dramatically reduces work for specific file types
        let applicable_indices: Vec<usize> = self.trait_index.get_applicable(&file_type).collect();

        // Pre-filter using batched Aho-Corasick string matching WITH evidence caching
        // This identifies which traits match AND caches the evidence to avoid re-iteration
        let t_prematch = std::time::Instant::now();

        // Combine strings and symbols for pre-filtering
        let mut all_strings = report.strings.clone();

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
            all_strings.push(crate::types::StringInfo {
                value: exp.symbol.clone(),
                offset: exp.offset.clone(),
                encoding: "symbol".to_string(),
                string_type: crate::types::StringType::Export,
                section: None,
                encoding_chain: Vec::new(),
                fragments: None,
            });
        }

        let (string_matched_traits, cached_evidence) = if self.string_match_index.has_patterns() {
            self.string_match_index
                .find_matches_with_evidence(&all_strings)
        } else {
            (FxHashSet::default(), FxHashMap::default())
        };

        // Also find regex candidates based on literal prefix matching
        let regex_candidates = self.string_match_index.find_regex_candidates(&all_strings);

        if timing {
            eprintln!(
                "[TIMING] String pre-match: {:?} ({} exact, {} regex candidates)",
                t_prematch.elapsed(),
                string_matched_traits.len(),
                regex_candidates.len()
            );
        }

        // Pre-filter using batched regex matching for Content conditions
        // Only run if any applicable traits have content regex patterns
        let t_raw_regex = std::time::Instant::now();
        let raw_regex_matched_traits = if self.raw_content_regex_index.has_patterns()
            && self
                .raw_content_regex_index
                .has_applicable_patterns(&applicable_indices)
        {
            self.raw_content_regex_index
                .find_matches(binary_data, &file_type)
        } else {
            FxHashSet::default()
        };

        if timing {
            eprintln!(
                "[TIMING] Raw content regex pre-match: {:?} ({} traits matched)",
                t_raw_regex.elapsed(),
                raw_regex_matched_traits.len()
            );
        }

        // Evaluate only applicable traits in parallel
        // For exact string traits with cached evidence, use that directly instead of re-evaluating
        let t_eval = std::time::Instant::now();

        // Early termination: if no strings and no pre-matched traits, skip evaluation
        let has_any_matches = !string_matched_traits.is_empty()
            || !raw_regex_matched_traits.is_empty()
            || !regex_candidates.is_empty();

        if !has_any_matches && all_strings.is_empty() && binary_data.len() < 100 {
            if timing {
                eprintln!("[TIMING] Early termination: no strings or matches in small file");
            }
            return vec![];
        }

        if timing {
            eprintln!(
                "[TIMING] Applicable traits: {} (out of {})",
                applicable_indices.len(),
                self.trait_definitions.len()
            );
        }

        let eval_count = std::sync::atomic::AtomicUsize::new(0);
        let skip_count = std::sync::atomic::AtomicUsize::new(0);

        let all_findings: Vec<Finding> = applicable_indices
            .par_iter()
            .filter_map(|&idx| {
                let trait_def = &self.trait_definitions[idx];

                // Check if this is an exact string trait (no excludes, min_count=1, no downgrade)
                // Works for both case-sensitive and case-insensitive
                // NOTE: Cannot use fast path for traits with downgrade rules - they need full evaluation
                let is_simple_exact_string = trait_def.downgrade.is_none()
                    && matches!(
                        &trait_def.r#if,
                        Condition::String {
                            exact: Some(_),
                            exclude_patterns: None,
                            min_count: 1,
                            ..
                        }
                    );

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
                            });
                        }
                    }
                    return None;
                }

                // Check if this trait has an exact string pattern that wasn't matched
                let has_exact_string =
                    matches!(trait_def.r#if, Condition::String { exact: Some(_), .. });

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
                    trait_def.r#if,
                    Condition::Content { regex: Some(_), .. }
                        | Condition::Content { word: Some(_), .. }
                );

                // If trait has a raw content pattern and it wasn't matched, skip it
                if has_content_regex && !raw_regex_matched_traits.contains(&idx) {
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

        if timing {
            eprintln!(
                "[TIMING] Trait evaluation: {:?} (evaluated: {}, skipped: {})",
                t_eval.elapsed(),
                eval_count.load(std::sync::atomic::Ordering::Relaxed),
                skip_count.load(std::sync::atomic::Ordering::Relaxed)
            );
        }

        // Deduplicate findings (keep first occurrence of each ID)
        let mut seen = std::collections::HashSet::new();
        all_findings
            .into_iter()
            .filter(|f| seen.insert(f.id.clone()))
            .collect()
    }

    /// Evaluate trait definitions against an analysis report (without cached AST)
    /// Backwards-compatible wrapper for evaluate_traits_with_ast
    pub fn evaluate_traits(&self, report: &AnalysisReport, binary_data: &[u8]) -> Vec<Finding> {
        self.evaluate_traits_with_ast(report, binary_data, None)
    }

    /// Evaluate composite rules against an analysis report
    /// Returns additional findings detected by composite rules
    pub fn evaluate_composite_rules(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
    ) -> Vec<Finding> {
        // Determine platform and file type from report
        let platform = self.detect_platform(&report.target.file_type);
        let file_type = self.detect_file_type(&report.target.file_type);

        let mut all_findings: Vec<Finding> = Vec::new();
        let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

        // Track which composite IDs have already matched (including original findings)
        for finding in &report.findings {
            seen_ids.insert(finding.id.clone());
        }

        // Split rules into two groups: those with negative conditions and those without
        let (negative_rules, positive_rules): (Vec<&CompositeTrait>, Vec<&CompositeTrait>) = self
            .composite_rules
            .iter()
            .partition(|r| r.has_negative_conditions());

        // Pass 1: Iterative evaluation of positive rules to reach a stable fixed-point
        const MAX_ITERATIONS: usize = 10;
        for _ in 0..MAX_ITERATIONS {
            let ctx = EvaluationContext::new(
                report,
                binary_data,
                file_type,
                platform.clone(),
                if all_findings.is_empty() {
                    None
                } else {
                    Some(&all_findings)
                },
                cached_ast,
            );

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
        let ctx = EvaluationContext::new(
            report,
            binary_data,
            file_type,
            platform.clone(),
            if all_findings.is_empty() {
                None
            } else {
                Some(&all_findings)
            },
            cached_ast,
        );

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
            &platform,
        );

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
        platform: &Platform,
    ) {
        use rustc_hash::FxHashMap;

        // Build a map of rule ID to rule for quick lookup
        let composite_map: FxHashMap<&str, &CompositeTrait> = self
            .composite_rules
            .iter()
            .map(|r| (r.id.as_str(), r))
            .collect();

        // First pass: collect new criticalities (can't mutate while borrowing for context)
        let updates: Vec<(usize, Criticality)> = {
            // Create final context with all findings (immutable borrow)
            let ctx = EvaluationContext::new(
                report,
                binary_data,
                file_type,
                platform.clone(),
                Some(findings),
                cached_ast,
            );

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
    /// # Arguments
    /// * `report` - Mutable reference to the analysis report to merge findings into
    /// * `binary_data` - Raw file data for content-based matching
    /// * `cached_ast` - Optional cached tree-sitter AST for performance
    ///
    /// # Example
    /// ```ignore
    /// // In an analyzer:
    /// self.capability_mapper.evaluate_and_merge_findings(&mut report, data, None);
    /// ```
    pub fn evaluate_and_merge_findings(
        &self,
        report: &mut AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
    ) {
        // Step 1: Evaluate atomic trait definitions
        let trait_findings = self.evaluate_traits_with_ast(report, binary_data, cached_ast);

        // Step 2: Merge atomic trait findings into report (so composites can reference them)
        for finding in trait_findings {
            // Avoid duplicates
            if !report.findings.iter().any(|f| f.id == finding.id) {
                report.findings.push(finding);
            }
        }

        // Step 3: Evaluate composite rules (which can now access the atomic traits)
        let composite_findings = self.evaluate_composite_rules(report, binary_data, cached_ast);

        // Step 4: Merge composite findings into report
        for finding in composite_findings {
            // Avoid duplicates
            if !report.findings.iter().any(|f| f.id == finding.id) {
                report.findings.push(finding);
            }
        }
    }

    /// Detect platform from file type string
    fn detect_platform(&self, file_type: &str) -> Platform {
        match file_type.to_lowercase().as_str() {
            "elf" | "so" => Platform::Linux,
            "macho" | "dylib" => Platform::MacOS,
            "pe" | "dll" | "exe" => Platform::Windows,
            _ => Platform::All,
        }
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
            "package.json" | "packagejson" => RuleFileType::PackageJson,
            "applescript" | "scpt" => RuleFileType::AppleScript,
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
        check_condition(&trait_def.r#if, &trait_def.id, path);
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

/// Check a single condition for problematic patterns
fn check_condition(
    condition: &crate::composite_rules::condition::Condition,
    trait_id: &str,
    path: &Path,
) {
    use crate::composite_rules::condition::Condition;

    if let Condition::Content { exact: Some(_), .. } = condition {
        eprintln!(
            "⚠️  WARNING: Trait '{}' in {} uses 'type: content' with 'exact' match. \
            This requires the entire file content to exactly match the pattern, \
            which is rarely useful. Consider using 'contains' instead.",
            trait_id,
            path.display()
        );
    }
}

impl Default for CapabilityMapper {
    fn default() -> Self {
        Self::new()
    }
}
