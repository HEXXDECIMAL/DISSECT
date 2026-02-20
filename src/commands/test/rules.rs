//! Test and debug composite rules against sample files.
//!
//! This module provides the `test-rules` command implementation, which evaluates
//! specified rules against a target file and shows detailed evaluation traces.

use crate::analyzers::detect_file_type;
use crate::commands::shared::{create_analysis_report, find_rules_in_directory, find_similar_rules};
use crate::{cli, composite_rules, test_rules};
use anyhow::Result;
use std::fs;
use std::path::Path;

/// Test and debug composite rules against a sample file.
///
/// This function evaluates specified rules against a target file and provides
/// detailed diagnostics about why rules matched or didn't match.
///
/// # Arguments
///
/// * `target` - Path to the file to analyze
/// * `rules` - Comma-separated list of rule IDs to test
/// * `_disabled` - Disabled components configuration (unused)
/// * `platforms` - Platform filters for rule evaluation
/// * `min_hostile_precision` - Minimum precision for hostile rules
/// * `min_suspicious_precision` - Minimum precision for suspicious rules
///
/// # Returns
///
/// A formatted string containing the debug output showing rule evaluation results,
/// condition traces, and evidence.
pub(crate) fn run(
    target: &str,
    rules: &str,
    _disabled: &cli::DisabledComponents,
    platforms: Vec<composite_rules::Platform>,
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
) -> Result<String> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    eprintln!("Analyzing: {}", target);

    // Parse rule IDs, stripping trailing slashes
    let rule_ids: Vec<String> =
        rules.split(',').map(|s| s.trim().trim_end_matches('/').to_string()).collect();
    eprintln!("Debugging {} rule(s): {:?}", rule_ids.len(), rule_ids);

    // Detect file type
    let file_type = detect_file_type(path)?;
    eprintln!("Detected file type: {:?}", file_type);

    // Load capability mapper with full validation (test-rules is a developer command)
    let capability_mapper = crate::capabilities::CapabilityMapper::new_with_precision_thresholds(
        min_hostile_precision,
        min_suspicious_precision,
        true, // Always enable full validation for test-rules
    )
    .with_platforms(platforms.clone());

    // Read file data
    let binary_data = fs::read(path)?;

    // Create a basic report by analyzing the file
    let mut report = create_analysis_report(path, &file_type, &binary_data, &capability_mapper)?;

    // Evaluate traits first to populate findings
    capability_mapper.evaluate_and_merge_findings(&mut report, &binary_data, None, None);

    // Create debugger and debug each rule
    // Pass platforms from CLI for consistency with production evaluation
    let debugger = test_rules::RuleDebugger::new(
        &capability_mapper,
        &report,
        &binary_data,
        &capability_mapper.composite_rules,
        capability_mapper.trait_definitions(),
        platforms,
    );

    let mut results = Vec::new();
    for rule_id in &rule_ids {
        // First try exact match
        if let Some(result) = debugger.debug_rule(rule_id) {
            results.push(result);
        } else {
            // Check if this is a directory prefix - find all rules under it
            let rules_in_dir = find_rules_in_directory(&capability_mapper, rule_id);
            if !rules_in_dir.is_empty() {
                eprintln!(
                    "Warning: Rule '{}' not found, but found {} rules in directory:",
                    rule_id,
                    rules_in_dir.len()
                );
                for r in &rules_in_dir {
                    eprintln!("    - {}", r);
                }
                // Debug each rule in the directory
                for sub_rule_id in &rules_in_dir {
                    if let Some(result) = debugger.debug_rule(sub_rule_id) {
                        results.push(result);
                    }
                }
            } else {
                eprintln!("Warning: Rule '{}' not found", rule_id);
                // Search for similar rules
                let similar = find_similar_rules(&capability_mapper, rule_id);
                if !similar.is_empty() {
                    eprintln!("  Did you mean one of:");
                    for s in similar.iter().take(5) {
                        eprintln!("    - {}", s);
                    }
                }
            }
        }
    }

    // Format and return output
    Ok(test_rules::format_debug_output(&results))
}
