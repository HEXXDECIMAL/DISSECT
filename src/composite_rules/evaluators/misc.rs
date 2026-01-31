//! Miscellaneous condition evaluators.
//!
//! This module handles evaluation of various other condition types:
//! - Structure detection (e.g., PE headers, ELF signatures)
//! - Trait references (cross-trait dependencies)
//! - File size constraints
//! - Trait glob patterns (matching multiple traits)

use crate::composite_rules::context::{ConditionResult, EvaluationContext};
use crate::types::{Evidence, Finding};

/// Evaluate structure condition
pub fn eval_structure(
    feature: &str,
    min_sections: Option<usize>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let mut count = 0;
    let mut evidence = Vec::new();

    for structural_feature in &ctx.report.structure {
        if structural_feature.id == feature
            || structural_feature.id.starts_with(&format!("{}/", feature))
        {
            count += 1;
            evidence.extend(structural_feature.evidence.clone());
        }
    }

    let matched = if let Some(min) = min_sections {
        count >= min
    } else {
        count > 0
    };

    ConditionResult {
        matched,
        evidence,
        traits: Vec::new(),
        warnings: Vec::new(),
    }
}

/// Evaluate trait reference condition - check if a trait has already been matched
///
/// Reference formats:
/// - Short names (e.g., "terminate"): suffix match within same directory
/// - Directory paths (e.g., "anti-static/obfuscation/strings"): matches ANY trait
///   within that directory (prefix match). Cross-directory references cannot
///   specify exact trait IDs - they can only reference the directory.
pub fn eval_trait(id: &str, ctx: &EvaluationContext) -> ConditionResult {
    // Fast path: exact match using O(1) index lookup
    if ctx.has_finding_exact(id) {
        // Found exact match - collect evidence
        let evidence: Vec<_> = ctx
            .report
            .findings
            .iter()
            .chain(ctx.additional_findings.into_iter().flatten())
            .filter(|f| f.id == id)
            .flat_map(|f| f.evidence.iter().cloned())
            .collect();

        return ConditionResult {
            matched: true,
            evidence,
            traits: vec![id.to_string()],
            warnings: Vec::new(),
        };
    }

    // Slow path: prefix/suffix matching for non-exact references
    let slash_count = id.matches('/').count();
    if slash_count == 0 {
        // Short name: suffix match for same-directory relative reference
        // e.g., "terminate" matches "exec/process/terminate"
        let suffix = format!("/{}", id);
        let evidence: Vec<_> = ctx
            .report
            .findings
            .iter()
            .chain(ctx.additional_findings.into_iter().flatten())
            .filter(|f| f.id.ends_with(&suffix))
            .flat_map(|f| f.evidence.iter().cloned())
            .collect();

        if !evidence.is_empty() {
            return ConditionResult {
                matched: true,
                evidence,
                traits: vec![id.to_string()],
                warnings: Vec::new(),
            };
        }
    } else {
        // Directory path: prefix match (any trait within that directory)
        // e.g., "anti-static/obfuscation/strings" matches
        // "anti-static/obfuscation/strings/python-hex"
        let prefix = format!("{}/", id);
        let evidence: Vec<_> = ctx
            .report
            .findings
            .iter()
            .chain(ctx.additional_findings.into_iter().flatten())
            .filter(|f| f.id.starts_with(&prefix))
            .flat_map(|f| f.evidence.iter().cloned())
            .collect();

        if !evidence.is_empty() {
            return ConditionResult {
                matched: true,
                evidence,
                traits: vec![id.to_string()],
                warnings: Vec::new(),
            };
        }
    }

    ConditionResult::default()
}

/// Evaluate a filesize condition
pub fn eval_filesize(
    min: Option<usize>,
    max: Option<usize>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let size = ctx.binary_data.len();
    let matched = min.is_none_or(|m| size >= m) && max.is_none_or(|m| size <= m);

    ConditionResult {
        matched,
        evidence: if matched {
            vec![Evidence {
                method: "filesize".to_string(),
                source: "binary".to_string(),
                value: format!("{} bytes", size),
                location: None,
            }]
        } else {
            Vec::new()
        },
        traits: Vec::new(),
        warnings: Vec::new(),
    }
}

/// Evaluate a trait glob condition - match multiple traits by glob pattern
pub fn eval_trait_glob(
    pattern: &str,
    match_mode: &str,
    ctx: &EvaluationContext,
) -> ConditionResult {
    // Convert glob pattern to regex (simple: * -> .*, ? -> .)
    let regex_pattern = format!(
        "^{}$",
        pattern
            .replace('.', "\\.")
            .replace('*', ".*")
            .replace('?', ".")
    );

    let re = match regex::Regex::new(&regex_pattern) {
        Ok(r) => r,
        Err(_) => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
            }
        }
    };

    // Find all matching trait IDs from the report's findings
    let mut matched_traits = Vec::new();
    let mut all_evidence = Vec::new();

    // Check findings in the report
    for finding in &ctx.report.findings {
        if re.is_match(&finding.id) {
            matched_traits.push(finding.id.clone());
            all_evidence.push(Evidence {
                method: "trait_glob".to_string(),
                source: pattern.to_string(),
                value: finding.id.clone(),
                location: None,
            });
        }
    }

    // Also check additional_findings if available (for composite chaining)
    if let Some(additional) = ctx.additional_findings {
        for finding in additional {
            if re.is_match(&finding.id) && !matched_traits.contains(&finding.id) {
                matched_traits.push(finding.id.clone());
                all_evidence.push(Evidence {
                    method: "trait_glob".to_string(),
                    source: pattern.to_string(),
                    value: finding.id.clone(),
                    location: None,
                });
            }
        }
    }

    let count = matched_traits.len();

    // Determine if matched based on match mode
    let matched = match match_mode {
        "any" => count >= 1,
        "all" => {
            // "all" means all matching traits must be present - but we found them, so true if any
            // This is a bit tricky - "all" in YARA means all strings with prefix matched
            // Since we don't know the total set, we treat "all" as "at least 1"
            // For true "all" semantics, users should list traits explicitly
            count >= 1
        }
        n => {
            // Parse as number
            n.parse::<usize>()
                .map(|required| count >= required)
                .unwrap_or(false)
        }
    };

    ConditionResult {
        matched,
        evidence: if matched { all_evidence } else { Vec::new() },
        traits: matched_traits,
        warnings: Vec::new(),
    }
}
