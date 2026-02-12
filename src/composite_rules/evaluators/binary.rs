//! Binary analysis condition evaluators.
//!
//! This module handles evaluation of binary-specific conditions:
//! - Import/export counting and filtering
//! - Section analysis (entropy, ratios, names)
//! - Syscall detection
//! - Import combinations (required + suspicious patterns)

use super::build_regex;
use crate::composite_rules::context::{ConditionResult, EvaluationContext};
use crate::types::Evidence;
use regex::Regex;

/// Evaluate imports count condition
pub fn eval_imports_count(
    min: Option<usize>,
    max: Option<usize>,
    filter: Option<&String>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let matching_imports: Vec<&str> = if let Some(filter_pattern) = filter {
        ctx.report
            .imports
            .iter()
            .filter(|imp| imp.symbol.contains(filter_pattern))
            .map(|imp| imp.symbol.as_str())
            .collect()
    } else {
        ctx.report
            .imports
            .iter()
            .map(|imp| imp.symbol.as_str())
            .collect()
    };

    let count = matching_imports.len();
    let matched = min.is_none_or(|m| count >= m) && max.is_none_or(|m| count <= m);

    // Calculate precision: base 1.0 + 0.5 each for min/max/filter
    let mut precision = 1.0f32;
    if min.is_some() {
        precision += 0.5;
    }
    if max.is_some() {
        precision += 0.5;
    }
    if filter.is_some() {
        precision += 0.5;
    }

    ConditionResult {
        matched,
        evidence: if matched {
            // Deduplicate and take first few for display
            let mut unique: Vec<&str> = matching_imports.clone();
            unique.sort();
            unique.dedup();
            let sample: Vec<&str> = unique.into_iter().take(5).collect();
            vec![Evidence {
                method: "imports_count".to_string(),
                source: "analysis".to_string(),
                value: format!("({}) {}", count, sample.join(", ")),
                location: None,
            }]
        } else {
            Vec::new()
        },
        traits: Vec::new(),
        warnings: Vec::new(),
        precision,
    }
}

/// Evaluate exports count condition
pub fn eval_exports_count(
    min: Option<usize>,
    max: Option<usize>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let count = ctx.report.exports.len();
    let matched = min.is_none_or(|m| count >= m) && max.is_none_or(|m| count <= m);

    // Calculate precision: base 1.0 + 0.5 each for min/max
    let mut precision = 1.0f32;
    if min.is_some() {
        precision += 0.5;
    }
    if max.is_some() {
        precision += 0.5;
    }

    ConditionResult {
        matched,
        evidence: if matched {
            // Deduplicate and take first few for display
            let mut symbols: Vec<&str> = ctx
                .report
                .exports
                .iter()
                .map(|exp| exp.symbol.as_str())
                .collect();
            symbols.sort();
            symbols.dedup();
            let sample: Vec<&str> = symbols.into_iter().take(5).collect();
            vec![Evidence {
                method: "exports_count".to_string(),
                source: "analysis".to_string(),
                value: format!("({}) {}", count, sample.join(", ")),
                location: None,
            }]
        } else {
            Vec::new()
        },
        traits: Vec::new(),
        warnings: Vec::new(),
        precision,
    }
}

/// Evaluate section ratio condition - check if section size is within ratio bounds
pub fn eval_section_ratio(
    section_pattern: &str,
    compare_to: &str,
    min_ratio: Option<f64>,
    max_ratio: Option<f64>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let section_re = match Regex::new(section_pattern) {
        Ok(re) => re,
        Err(_) => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
                precision: 0.0,
            }
        }
    };

    // Find matching section(s) and sum their sizes
    let mut section_size: u64 = 0;
    let mut matched_sections = Vec::new();
    for section in &ctx.report.sections {
        if section_re.is_match(&section.name) {
            section_size += section.size;
            matched_sections.push(section.name.clone());
        }
    }

    if matched_sections.is_empty() {
        return ConditionResult {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
            warnings: Vec::new(),
            precision: 0.0,
        };
    }

    // Calculate comparison size
    let compare_size: u64 = if compare_to == "total" {
        ctx.report.sections.iter().map(|s| s.size).sum()
    } else {
        let compare_re = match Regex::new(compare_to) {
            Ok(re) => re,
            Err(_) => {
                return ConditionResult {
                    matched: false,
                    evidence: Vec::new(),
                    traits: Vec::new(),
                    warnings: Vec::new(),
                    precision: 0.0,
                }
            }
        };
        ctx.report
            .sections
            .iter()
            .filter(|s| compare_re.is_match(&s.name))
            .map(|s| s.size)
            .sum()
    };

    if compare_size == 0 {
        return ConditionResult {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
            warnings: Vec::new(),
            precision: 0.0,
        };
    }

    let ratio = section_size as f64 / compare_size as f64;
    let min_ok = min_ratio.is_none_or(|min| ratio >= min);
    let max_ok = max_ratio.is_none_or(|max| ratio <= max);
    let matched = min_ok && max_ok;

    // Calculate precision: base 1.0 + 1.0 for pattern + 0.5 each for min/max ratios
    let mut precision = 1.0f32;
    precision += 1.0; // section pattern always present
    if min_ratio.is_some() {
        precision += 0.5;
    }
    if max_ratio.is_some() {
        precision += 0.5;
    }

    ConditionResult {
        matched,
        evidence: if matched {
            vec![Evidence {
                method: "section_ratio".to_string(),
                source: "binary".to_string(),
                value: format!(
                    "{} = {:.1}% of {} ({} / {} bytes)",
                    matched_sections.join("+"),
                    ratio * 100.0,
                    compare_to,
                    section_size,
                    compare_size
                ),
                location: None,
            }]
        } else {
            Vec::new()
        },
        traits: Vec::new(),
        warnings: Vec::new(),
        precision,
    }
}

/// Evaluate section entropy condition - check if section entropy is within bounds
pub fn eval_section_entropy(
    section_pattern: &str,
    min_entropy: Option<f64>,
    max_entropy: Option<f64>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let section_re = match Regex::new(section_pattern) {
        Ok(re) => re,
        Err(_) => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
                precision: 0.0,
            };
        }
    };

    let mut evidence = Vec::new();
    let mut any_matched = false;

    for section in &ctx.report.sections {
        if section_re.is_match(&section.name) {
            let min_ok = min_entropy.is_none_or(|min| section.entropy >= min);
            let max_ok = max_entropy.is_none_or(|max| section.entropy <= max);

            if min_ok && max_ok {
                any_matched = true;
                evidence.push(Evidence {
                    method: "section_entropy".to_string(),
                    source: "binary".to_string(),
                    value: format!("{} entropy = {:.2}/8.0", section.name, section.entropy),
                    location: None,
                });
            }
        }
    }

    // Calculate precision: base 1.0 + 0.5 each for min/max entropy
    let mut precision = 1.0f32;
    if min_entropy.is_some() {
        precision += 0.5;
    }
    if max_entropy.is_some() {
        precision += 0.5;
    }

    ConditionResult {
        matched: any_matched,
        evidence,
        traits: Vec::new(),
        warnings: Vec::new(),
        precision,
    }
}

/// Evaluate section condition - match section names in binary files
/// Replaces YARA patterns like: `for any section in pe.sections : (section.name matches /^UPX/)`
pub fn eval_section(
    exact: Option<&String>,
    substr: Option<&String>,
    regex: Option<&String>,
    word: Option<&String>,
    case_insensitive: bool,
    length_min: Option<u64>,
    length_max: Option<u64>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let mut evidence = Vec::new();

    for section in &ctx.report.sections {
        // Apply case sensitivity transformation
        let (compare_name, compare_exact, compare_substr) = if case_insensitive {
            (
                section.name.to_lowercase(),
                exact.map(|s| s.to_lowercase()),
                substr.map(|s| s.to_lowercase()),
            )
        } else {
            (section.name.clone(), exact.cloned(), substr.cloned())
        };

        let name_matched = if let Some(exact_str) = &compare_exact {
            compare_name == *exact_str
        } else if let Some(substr_str) = &compare_substr {
            compare_name.contains(substr_str.as_str())
        } else if let Some(regex_str) = regex {
            let pattern = if case_insensitive {
                format!("(?i){}", regex_str)
            } else {
                regex_str.clone()
            };
            match build_regex(&pattern, false) {
                Ok(re) => re.is_match(&section.name),
                Err(_) => false,
            }
        } else if let Some(word_str) = word {
            let pattern = if case_insensitive {
                format!(r"(?i)\b{}\b", regex::escape(word_str))
            } else {
                format!(r"\b{}\b", regex::escape(word_str))
            };
            match build_regex(&pattern, false) {
                Ok(re) => re.is_match(&section.name),
                Err(_) => false,
            }
        } else {
            // No name pattern specified - match all sections
            true
        };

        // Check size constraints
        let size_ok = if let Some(min) = length_min {
            section.size >= min
        } else {
            true
        } && if let Some(max) = length_max {
            section.size <= max
        } else {
            true
        };

        let matched = name_matched && size_ok;

        if matched {
            let value = if length_min.is_some() || length_max.is_some() {
                format!("{} (size: {} bytes)", section.name, section.size)
            } else {
                section.name.clone()
            };
            evidence.push(Evidence {
                method: "section".to_string(),
                source: "binary".to_string(),
                value,
                location: None,
            });
        }
    }

    // Calculate precision matching other evaluators
    let mut precision = if exact.is_some() {
        2.0
    } else if regex.is_some() || word.is_some() {
        1.5
    } else if substr.is_some() {
        1.0
    } else if length_min.is_some() || length_max.is_some() {
        // Size constraints alone (no name pattern)
        1.0
    } else {
        0.0
    };

    // Add precision for size constraints
    if length_min.is_some() {
        precision += 0.5;
    }
    if length_max.is_some() {
        precision += 0.5;
    }

    if case_insensitive {
        precision *= 0.5;
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
        warnings: Vec::new(),
        precision,
    }
}

/// Evaluate import combination condition - check for required + suspicious import patterns
pub fn eval_import_combination(
    required: Option<&Vec<String>>,
    suspicious: Option<&Vec<String>>,
    min_suspicious: Option<usize>,
    max_total: Option<usize>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let import_symbols: Vec<&str> = ctx
        .report
        .imports
        .iter()
        .map(|i| i.symbol.as_str())
        .collect();
    let mut evidence = Vec::new();

    // Check required imports - all must be present
    if let Some(req) = required {
        for pattern in req {
            let re = match Regex::new(pattern) {
                Ok(re) => re,
                Err(_) => continue,
            };
            let found = import_symbols.iter().any(|sym| re.is_match(sym));
            if !found {
                return ConditionResult {
                    matched: false,
                    evidence: Vec::new(),
                    traits: Vec::new(),
                    warnings: Vec::new(),
                    precision: 0.0,
                };
            }
            evidence.push(Evidence {
                method: "import".to_string(),
                source: "required".to_string(),
                value: pattern.clone(),
                location: None,
            });
        }
    }

    // Count suspicious imports
    let mut suspicious_count = 0;
    if let Some(susp) = suspicious {
        for pattern in susp {
            let re = match Regex::new(pattern) {
                Ok(re) => re,
                Err(_) => continue,
            };
            for sym in &import_symbols {
                if re.is_match(sym) {
                    suspicious_count += 1;
                    evidence.push(Evidence {
                        method: "import".to_string(),
                        source: "suspicious".to_string(),
                        value: (*sym).to_string(),
                        location: None,
                    });
                }
            }
        }
    }

    // Check minimum suspicious count
    if let Some(min) = min_suspicious {
        if suspicious_count < min {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
                precision: 0.0,
            };
        }
    }

    // Check maximum total imports
    if let Some(max) = max_total {
        if ctx.report.imports.len() > max {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
                precision: 0.0,
            };
        }
        evidence.push(Evidence {
            method: "import_count".to_string(),
            source: "binary".to_string(),
            value: format!("{} imports (max {})", ctx.report.imports.len(), max),
            location: None,
        });
    }

    // Calculate precision: base 2.0 + 0.5 per required item + 0.3 per suspicious item
    let mut precision = 2.0f32;
    if let Some(req) = required {
        precision += (req.len() as f32) * 0.5;
    }
    if let Some(susp) = suspicious {
        precision += (susp.len() as f32) * 0.3;
    }

    ConditionResult {
        matched: true,
        evidence,
        traits: Vec::new(),
        warnings: Vec::new(),
        precision,
    }
}

/// Evaluate syscall condition - matches syscalls detected via radare2 analysis
pub fn eval_syscall(
    name: Option<&Vec<String>>,
    number: Option<&Vec<u32>>,
    arch: Option<&Vec<String>>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let mut evidence = Vec::new();
    let mut match_count = 0;

    for syscall in &ctx.report.syscalls {
        let name_match = name.is_none_or(|names| names.contains(&syscall.name));
        let number_match = number.is_none_or(|nums| nums.contains(&syscall.number));
        let arch_match = arch.is_none_or(|archs| {
            archs
                .iter()
                .any(|a| syscall.arch.to_lowercase().contains(&a.to_lowercase()))
        });

        if name_match && number_match && arch_match {
            match_count += 1;
            evidence.push(Evidence {
                method: "syscall".to_string(),
                source: "radare2".to_string(),
                value: format!(
                    "{}({}) at 0x{:x}",
                    syscall.name, syscall.number, syscall.address
                ),
                location: Some(format!("0x{:x}", syscall.address)),
            });
        }
    }

    // count/density constraints are now checked at trait level
    let matched = match_count > 0;

    // Calculate precision: base 2.0 + 0.5 for name/number/arch
    let mut precision = 2.0f32;
    if name.is_some() {
        precision += 0.5;
    }
    if number.is_some() {
        precision += 0.5;
    }
    if arch.is_some() {
        precision += 0.5;
    }

    ConditionResult {
        matched,
        evidence: if matched { evidence } else { Vec::new() },
        traits: Vec::new(),
        warnings: Vec::new(),
        precision,
    }
}
