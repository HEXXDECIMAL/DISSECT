//! Symbol and string-based condition evaluators.
//!
//! This module handles evaluation of:
//! - Symbol matching (imports, exports)
//! - String content matching (extracted strings, raw content)
//! - Decoded string matching (Base64, XOR)
//! - String count analysis

use super::symbol_matches;
use crate::composite_rules::condition::NotException;
use crate::composite_rules::context::{ConditionResult, EvaluationContext, StringParams};
use crate::composite_rules::types::Platform;
use crate::types::Evidence;

/// Evaluate symbol condition - matches symbols in imports/exports.
pub fn eval_symbol(
    exact: Option<&String>,
    pattern: Option<&String>,
    platforms: Option<&Vec<Platform>>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    // Check platform constraint
    if let Some(plats) = platforms {
        if !plats.contains(&ctx.platform) && !plats.contains(&Platform::All) {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
            };
        }
    }

    let mut evidence = Vec::new();

    // Search in imports
    for import in &ctx.report.imports {
        if symbol_matches_condition(&import.symbol, exact, pattern) {
            evidence.push(Evidence {
                method: "symbol".to_string(),
                source: import.source.clone(),
                value: import.symbol.clone(),
                location: Some("import".to_string()),
            });
        }
    }

    // Search in exports
    for export in &ctx.report.exports {
        if symbol_matches_condition(&export.symbol, exact, pattern) {
            evidence.push(Evidence {
                method: "symbol".to_string(),
                source: export.source.clone(),
                value: export.symbol.clone(),
                location: export.offset.clone(),
            });
        }
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
        warnings: Vec::new(),
    }
}

/// Check if a symbol matches an exact name or pattern.
fn symbol_matches_condition(
    symbol: &str,
    exact: Option<&String>,
    pattern: Option<&String>,
) -> bool {
    // Clean symbol (remove leading underscores)
    let clean = symbol.trim_start_matches('_').trim_start_matches("__");

    // If exact is specified, do strict equality match
    if let Some(exact_val) = exact {
        return clean == exact_val || symbol == exact_val;
    }

    // If pattern is specified, use the existing pattern matching logic
    if let Some(pattern_val) = pattern {
        return symbol_matches(symbol, pattern_val);
    }

    // Neither exact nor pattern specified - no match
    false
}

/// Evaluate string condition - searches ONLY in properly extracted/bounded strings.
///
/// For searching raw file content, use `eval_raw()` instead.
pub fn eval_string(
    params: &StringParams,
    trait_not: Option<&Vec<NotException>>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let profile = std::env::var("DISSECT_PROFILE").is_ok();
    let t_start = if profile { Some(std::time::Instant::now()) } else { None };

    let mut evidence = Vec::new();

    // Legacy support: if search_raw is true, delegate to eval_raw
    if params.search_raw {
        return eval_raw(
            params.exact,
            params.regex,
            params.word,
            params.case_insensitive,
            params.min_count,
            params.compiled_regex,
            ctx,
        );
    }

    // Use pre-compiled regex from trait definition (compiled at startup)
    let compiled_regex = params.compiled_regex;
    let compiled_excludes = params.compiled_excludes;

    // Check in extracted strings from report (for binaries)
    for string_info in &ctx.report.strings {
        let mut matched = false;
        let mut match_value = String::new();

        if let Some(exact_str) = params.exact {
            matched = if params.case_insensitive {
                string_info
                    .value
                    .to_lowercase()
                    .contains(&exact_str.to_lowercase())
            } else {
                string_info.value.contains(exact_str)
            };
            if matched {
                match_value = exact_str.clone();
            }
        } else if let Some(re) = compiled_regex {
            if let Some(mat) = re.find(&string_info.value) {
                matched = true;
                match_value = mat.as_str().to_string();
            }
        } else if let Some(regex_pattern) = params.regex {
            // Fallback: compile regex on-the-fly if not pre-compiled
            if let Ok(re) = super::build_regex(regex_pattern, params.case_insensitive) {
                if let Some(mat) = re.find(&string_info.value) {
                    matched = true;
                    match_value = mat.as_str().to_string();
                }
            }
        }

        if matched {
            // Check old-style exclude_patterns (deprecated, from condition level)
            let excluded_by_pattern = compiled_excludes
                .iter()
                .any(|re| re.is_match(&string_info.value));

            // Check new-style `not:` exceptions (trait level)
            let excluded_by_not = trait_not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(&match_value)))
                .unwrap_or(false);

            if excluded_by_pattern || excluded_by_not {
                continue;
            }

            evidence.push(Evidence {
                method: "string".to_string(),
                source: "string_extractor".to_string(),
                value: match_value,
                location: string_info.offset.clone(),
            });
        }
    }

    // For source files or when no strings were extracted, fall back to raw content search.
    // Source files (Python, Ruby, etc.) don't use string extraction - the file IS the strings.
    if evidence.is_empty() && (ctx.report.strings.is_empty() || ctx.file_type.is_source_code()) {
        if let Ok(content) = std::str::from_utf8(ctx.binary_data) {
            let mut matched = false;
            let mut match_value = String::new();

            if let Some(exact_str) = params.exact {
                matched = if params.case_insensitive {
                    content.to_lowercase().contains(&exact_str.to_lowercase())
                } else {
                    content.contains(exact_str)
                };
                if matched {
                    match_value = exact_str.clone();
                }
            } else if let Some(re) = compiled_regex {
                if let Some(mat) = re.find(content) {
                    matched = true;
                    match_value = mat.as_str().to_string();
                }
            } else if let Some(regex_pattern) = params.regex {
                // Fallback: compile regex on-the-fly if not pre-compiled
                if let Ok(re) = super::build_regex(regex_pattern, params.case_insensitive) {
                    if let Some(mat) = re.find(content) {
                        matched = true;
                        match_value = mat.as_str().to_string();
                    }
                }
            }

            if matched {
                let excluded_by_pattern = compiled_excludes.iter().any(|re| re.is_match(&match_value));
                let excluded_by_not = trait_not
                    .map(|exceptions| exceptions.iter().any(|exc| exc.matches(&match_value)))
                    .unwrap_or(false);

                if !excluded_by_pattern && !excluded_by_not {
                    evidence.push(Evidence {
                        method: "string".to_string(),
                        source: "raw_content".to_string(),
                        value: match_value,
                        location: Some("file".to_string()),
                    });
                }
            }
        }
    }

    if let Some(t) = t_start {
        if profile {
            eprintln!("[PROFILE]   eval_string: {}ms", t.elapsed().as_millis());
        }
    }

    ConditionResult {
        matched: evidence.len() >= params.min_count,
        evidence,
        traits: Vec::new(),
        warnings: Vec::new(),
    }
}

/// Evaluate raw content condition - searches directly in raw file bytes as text.
///
/// Use this for source files or when you need to match patterns that may span
/// string boundaries in binaries.
pub fn eval_raw(
    exact: Option<&String>,
    _regex: Option<&String>,
    _word: Option<&String>,
    case_insensitive: bool,
    min_count: usize,
    compiled_regex: Option<&regex::Regex>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let profile = std::env::var("DISSECT_PROFILE").is_ok();
    let t_start = if profile { Some(std::time::Instant::now()) } else { None };

    let mut evidence = Vec::new();

    // Convert binary data to string
    let content = match std::str::from_utf8(ctx.binary_data) {
        Ok(s) => s,
        Err(_) => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
            }
        }
    };

    // Use pre-compiled regex (handles both word and regex patterns)
    if let Some(re) = compiled_regex {
        let mut match_count = 0;
        let mut first_match = None;
        for mat in re.find_iter(content) {
            match_count += 1;
            if first_match.is_none() {
                first_match = Some(mat.as_str().to_string());
            }
        }
        if match_count >= min_count {
            evidence.push(Evidence {
                method: "raw".to_string(),
                source: "raw_content".to_string(),
                value: format!("Found {} {}", match_count, first_match.unwrap_or_default()),
                location: Some("file".to_string()),
            });
        }
    } else if let Some(exact_str) = exact {
        let search_content = if case_insensitive {
            content.to_lowercase()
        } else {
            content.to_string()
        };
        let search_pattern = if case_insensitive {
            exact_str.to_lowercase()
        } else {
            exact_str.clone()
        };
        let match_count = search_content.matches(&search_pattern).count();
        if match_count >= min_count {
            evidence.push(Evidence {
                method: "raw".to_string(),
                source: "raw_content".to_string(),
                value: format!("Found {} {}", match_count, exact_str),
                location: Some("file".to_string()),
            });
        }
    }

    if let Some(t) = t_start {
        if profile {
            eprintln!("[PROFILE]   eval_raw: {}ms", t.elapsed().as_millis());
        }
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
        warnings: Vec::new(),
    }
}

/// Search base64-decoded strings for patterns.
/// Decoded strings are extracted once during analysis and stored in the report.
pub fn eval_base64(
    exact: Option<&String>,
    regex: Option<&String>,
    case_insensitive: bool,
    min_count: usize,
    ctx: &EvaluationContext,
) -> ConditionResult {
    eval_decoded_helper("base64", exact, regex, case_insensitive, min_count, ctx)
}

/// Search XOR-decoded strings for patterns.
/// If key is specified, only searches that key. Otherwise searches all keys 0x01-0xFF (except 0x20).
pub fn eval_xor(
    key: Option<&String>,
    exact: Option<&String>,
    regex: Option<&String>,
    case_insensitive: bool,
    min_count: usize,
    ctx: &EvaluationContext,
) -> ConditionResult {
    // If key specified, filter to just that key
    let decoded_strings: Vec<_> = if let Some(key_str) = key {
        ctx.report
            .decoded_strings
            .iter()
            .filter(|s| s.method == "xor" && s.key.as_ref().map(|k| k == key_str).unwrap_or(false))
            .collect()
    } else {
        ctx.report
            .decoded_strings
            .iter()
            .filter(|s| s.method == "xor")
            .collect()
    };

    eval_decoded_strings_helper(&decoded_strings, "xor", exact, regex, case_insensitive, min_count)
}

/// Helper to search decoded strings for patterns.
fn eval_decoded_helper(
    method: &str,
    exact: Option<&String>,
    regex: Option<&String>,
    case_insensitive: bool,
    min_count: usize,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let decoded_strings: Vec<_> = ctx
        .report
        .decoded_strings
        .iter()
        .filter(|s| s.method == method)
        .collect();

    eval_decoded_strings_helper(&decoded_strings, method, exact, regex, case_insensitive, min_count)
}

/// Core logic for matching patterns in decoded strings.
fn eval_decoded_strings_helper(
    decoded_strings: &[&crate::types::DecodedString],
    method: &str,
    exact: Option<&String>,
    regex: Option<&String>,
    case_insensitive: bool,
    min_count: usize,
) -> ConditionResult {
    let mut evidence = Vec::new();
    let mut match_count = 0;

    // Build regex if needed
    let regex_matcher = if let Some(pattern) = regex {
        let pattern_with_flags = if case_insensitive {
            format!("(?i){}", pattern)
        } else {
            pattern.clone()
        };
        match regex::Regex::new(&pattern_with_flags) {
            Ok(re) => Some(re),
            Err(_) => return ConditionResult::no_match(),
        }
    } else {
        None
    };

    for decoded in decoded_strings {
        let mut matches = false;

        // Check exact match
        if let Some(exact_str) = exact {
            matches = if case_insensitive {
                decoded.value.to_lowercase().contains(&exact_str.to_lowercase())
            } else {
                decoded.value.contains(exact_str.as_str())
            };
        }

        // Check regex match
        if !matches {
            if let Some(ref re) = regex_matcher {
                matches = re.is_match(&decoded.value);
            }
        }

        if matches {
            match_count += 1;
            let value_preview = if decoded.value.len() > 100 {
                format!("{}...", &decoded.value[..100])
            } else {
                decoded.value.clone()
            };
            evidence.push(Evidence {
                method: format!("decoded_{}", method),
                source: "string".to_string(),
                value: value_preview,
                location: decoded.offset.clone(),
            });
        }
    }

    ConditionResult {
        matched: match_count >= min_count,
        evidence,
        traits: Vec::new(),
        warnings: Vec::new(),
    }
}

/// Evaluate string count condition - check if string count is within bounds.
pub fn eval_string_count(
    min: Option<usize>,
    max: Option<usize>,
    min_length: Option<usize>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let min_len = min_length.unwrap_or(0);
    let matching_strings: Vec<&str> = ctx
        .report
        .strings
        .iter()
        .filter(|s| s.value.len() >= min_len)
        .map(|s| s.value.as_str())
        .collect();

    let count = matching_strings.len();
    let min_ok = min.is_none_or(|m| count >= m);
    let max_ok = max.is_none_or(|m| count <= m);
    let matched = min_ok && max_ok;

    ConditionResult {
        matched,
        evidence: if matched {
            // Deduplicate and take first few for display
            let mut unique: Vec<&str> = matching_strings;
            unique.sort();
            unique.dedup();
            let sample: Vec<&str> = unique.into_iter().take(5).collect();
            vec![Evidence {
                method: "string_count".to_string(),
                source: "binary".to_string(),
                value: format!("({}) {}", count, sample.join(", ")),
                location: None,
            }]
        } else {
            Vec::new()
        },
        traits: Vec::new(),
        warnings: Vec::new(),
    }
}
