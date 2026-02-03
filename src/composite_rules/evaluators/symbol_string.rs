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
    substr: Option<&String>,
    pattern: Option<&String>,
    platforms: Option<&Vec<Platform>>,
    compiled_regex: Option<&regex::Regex>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    // Check platform constraint
    // Match if: trait allows All platforms, OR context is All (no --platform specified),
    // OR trait explicitly includes the context platform
    if let Some(plats) = platforms {
        if !plats.contains(&ctx.platform)
            && !plats.contains(&Platform::All)
            && ctx.platform != Platform::All
        {
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
        if symbol_matches_condition(&import.symbol, exact, substr, pattern, compiled_regex) {
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
        if symbol_matches_condition(&export.symbol, exact, substr, pattern, compiled_regex) {
            evidence.push(Evidence {
                method: "symbol".to_string(),
                source: export.source.clone(),
                value: export.symbol.clone(),
                location: export.offset.clone(),
            });
        }
    }

    // Search in internal functions (important for statically linked Go binaries)
    for func in &ctx.report.functions {
        if symbol_matches_condition(&func.name, exact, substr, pattern, compiled_regex) {
            evidence.push(Evidence {
                method: "symbol".to_string(),
                source: func.source.clone(),
                value: func.name.clone(),
                location: func.offset.clone(),
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

/// Check if a symbol matches an exact name, substring, or pattern.
fn symbol_matches_condition(
    symbol: &str,
    exact: Option<&String>,
    substr: Option<&String>,
    pattern: Option<&String>,
    compiled_regex: Option<&regex::Regex>,
) -> bool {
    // Clean symbol (remove leading underscores)
    let clean = symbol.trim_start_matches('_').trim_start_matches("__");

    // If exact is specified, do strict equality match
    if let Some(exact_val) = exact {
        return clean == exact_val || symbol == exact_val;
    }

    // If substr is specified, do substring match
    if let Some(substr_val) = substr {
        return symbol.contains(substr_val.as_str()) || clean.contains(substr_val.as_str());
    }

    // If pattern is specified, use precompiled regex if available
    if pattern.is_some() {
        if let Some(re) = compiled_regex {
            return re.is_match(symbol) || re.is_match(clean);
        } else if let Some(pattern_val) = pattern {
            // Fallback: use the existing pattern matching logic if not pre-compiled
            return symbol_matches(symbol, pattern_val);
        }
    }

    // Neither exact nor substr nor pattern specified - no match
    false
}

/// Evaluate string condition - searches in properly extracted/bounded strings,
/// as well as imports and exports if they match the string criteria.
///
/// For searching raw file content, use `eval_raw()` instead.
pub fn eval_string(
    params: &StringParams,
    trait_not: Option<&Vec<NotException>>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let profile = std::env::var("DISSECT_PROFILE").is_ok();
    let t_start = if profile {
        Some(std::time::Instant::now())
    } else {
        None
    };

    let mut evidence = Vec::new();

    // Use pre-compiled regex from trait definition (compiled at startup)
    let compiled_regex = params.compiled_regex;
    let compiled_excludes = params.compiled_excludes;

    // Helper to check if a value matches and add to evidence
    let check_and_add_evidence = |value: &str,
                                  source: &str,
                                  method: &str,
                                  location: Option<String>,
                                  evidence: &mut Vec<Evidence>| {
        let mut matched = false;
        let mut match_value = String::new();

        if let Some(exact_str) = params.exact {
            matched = if params.case_insensitive {
                value.eq_ignore_ascii_case(exact_str)
            } else {
                value == *exact_str
            };
            if matched {
                match_value = exact_str.clone();
            }
        } else if let Some(contains_str) = params.substr {
            matched = if params.case_insensitive {
                value.to_lowercase().contains(&contains_str.to_lowercase())
            } else {
                value.contains(contains_str)
            };
            if matched {
                match_value = contains_str.clone();
            }
        } else if let Some(re) = compiled_regex {
            if let Some(mat) = re.find(value) {
                matched = true;
                match_value = mat.as_str().to_string();
            }
        } else if let Some(regex_pattern) = params.regex {
            if let Ok(re) = super::build_regex(regex_pattern, params.case_insensitive) {
                if let Some(mat) = re.find(value) {
                    matched = true;
                    match_value = mat.as_str().to_string();
                }
            }
        }

        if matched {
            let excluded_by_pattern = compiled_excludes.iter().any(|re| re.is_match(value));
            let excluded_by_not = trait_not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(&match_value)))
                .unwrap_or(false);

            if !excluded_by_pattern && !excluded_by_not {
                evidence.push(Evidence {
                    method: method.to_string(),
                    source: source.to_string(),
                    value: match_value,
                    location,
                });
            }
        }
    };

    // 1. Check in extracted strings from report (for binaries)
    for string_info in &ctx.report.strings {
        check_and_add_evidence(
            &string_info.value,
            "string_extractor",
            "string",
            string_info.offset.clone(),
            &mut evidence,
        );
    }

    // 2. Check in imports (symbols are strings too!)
    for import in &ctx.report.imports {
        check_and_add_evidence(
            &import.symbol,
            &import.source,
            "import_symbol",
            None,
            &mut evidence,
        );
    }

    // 3. Check in exports
    for export in &ctx.report.exports {
        check_and_add_evidence(
            &export.symbol,
            &export.source,
            "export_symbol",
            export.offset.clone(),
            &mut evidence,
        );
    }

    // For source files or when no strings were extracted, fall back to raw content search.
    if evidence.is_empty() && (ctx.report.strings.is_empty() || ctx.file_type.is_source_code()) {
        if let Ok(content) = std::str::from_utf8(ctx.binary_data) {
            let mut matched = false;
            let mut match_value = String::new();

            if let Some(exact_str) = params.exact {
                // Exact match against whole file content (rarely matches, but semantically correct)
                matched = if params.case_insensitive {
                    content.eq_ignore_ascii_case(exact_str)
                } else {
                    content == exact_str
                };
                if matched {
                    match_value = exact_str.clone();
                }
            } else if let Some(substr_str) = params.substr {
                // Substring match in raw content
                matched = if params.case_insensitive {
                    content.to_lowercase().contains(&substr_str.to_lowercase())
                } else {
                    content.contains(substr_str)
                };
                if matched {
                    match_value = substr_str.clone();
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
                let excluded_by_pattern =
                    compiled_excludes.iter().any(|re| re.is_match(&match_value));
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

/// Evaluate content-based condition - searches directly in file bytes as text.
///
/// Used by `type: content` conditions to search raw file content rather than extracted strings.
/// Use for cross-boundary patterns or when string extraction is insufficient.
#[allow(clippy::too_many_arguments)]
pub fn eval_raw(
    exact: Option<&String>,
    substr: Option<&String>,
    _regex: Option<&String>,
    _word: Option<&String>,
    case_insensitive: bool,
    min_count: usize,
    compiled_regex: Option<&regex::Regex>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let profile = std::env::var("DISSECT_PROFILE").is_ok();
    let t_start = if profile {
        Some(std::time::Instant::now())
    } else {
        None
    };

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
        // Full string match - entire file content must equal the pattern
        let matched = if case_insensitive {
            content.eq_ignore_ascii_case(exact_str)
        } else {
            content == exact_str
        };
        if matched {
            evidence.push(Evidence {
                method: "raw".to_string(),
                source: "raw_content".to_string(),
                value: format!("Exact match: {}", exact_str),
                location: Some("file".to_string()),
            });
        }
    } else if let Some(substr_str) = substr {
        // Substring match - count occurrences in raw content
        let search_content = if case_insensitive {
            content.to_lowercase()
        } else {
            content.to_string()
        };
        let search_pattern = if case_insensitive {
            substr_str.to_lowercase()
        } else {
            substr_str.clone()
        };
        let match_count = search_content.matches(&search_pattern).count();
        if match_count >= min_count {
            evidence.push(Evidence {
                method: "raw".to_string(),
                source: "raw_content".to_string(),
                value: format!("Found {} occurrences of {}", match_count, substr_str),
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
    substr: Option<&String>,
    regex: Option<&String>,
    case_insensitive: bool,
    min_count: usize,
    ctx: &EvaluationContext,
) -> ConditionResult {
    eval_encoded_strings_helper(
        "base64",
        exact,
        substr,
        regex,
        case_insensitive,
        min_count,
        &ctx.report.strings,
    )
}

/// Search XOR-decoded strings for patterns.
/// If key is specified, only searches that key. Otherwise searches all xor strings.
pub fn eval_xor(
    _key: Option<&String>,
    exact: Option<&String>,
    substr: Option<&String>,
    regex: Option<&String>,
    case_insensitive: bool,
    min_count: usize,
    ctx: &EvaluationContext,
) -> ConditionResult {
    // Note: key parameter is deprecated - encoding_chain no longer carries key info
    eval_encoded_strings_helper(
        "xor",
        exact,
        substr,
        regex,
        case_insensitive,
        min_count,
        &ctx.report.strings,
    )
}

/// Helper to search encoded strings (with given encoding in chain) for patterns.
fn eval_encoded_strings_helper(
    encoding_type: &str,
    exact: Option<&String>,
    substr: Option<&String>,
    regex: Option<&String>,
    case_insensitive: bool,
    min_count: usize,
    strings: &[crate::types::StringInfo],
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

    // Filter strings that have this encoding in their chain
    for string_info in strings {
        if !string_info
            .encoding_chain
            .contains(&encoding_type.to_string())
        {
            continue;
        }

        let mut matches = false;

        // Check exact match (full string equality)
        if let Some(exact_str) = exact {
            matches = if case_insensitive {
                string_info.value.eq_ignore_ascii_case(exact_str)
            } else {
                string_info.value == *exact_str
            };
        }

        // Check substring match
        if !matches {
            if let Some(substr_str) = substr {
                matches = if case_insensitive {
                    string_info
                        .value
                        .to_lowercase()
                        .contains(&substr_str.to_lowercase())
                } else {
                    string_info.value.contains(substr_str.as_str())
                };
            }
        }

        // Check regex match
        if !matches {
            if let Some(ref re) = regex_matcher {
                matches = re.is_match(&string_info.value);
            }
        }

        if matches {
            match_count += 1;
            let value_preview = if string_info.value.len() > 100 {
                format!("{}...", &string_info.value[..100])
            } else {
                string_info.value.clone()
            };
            evidence.push(Evidence {
                method: format!("encoded_{}", encoding_type),
                source: "string".to_string(),
                value: value_preview,
                location: string_info.offset.clone(),
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

/// Evaluate layer_path condition - match strings by their encoding layer path.
/// Layer paths are computed as: meta/layers/{section}/{encoding_chain_joined}
pub fn eval_layer_path(value: &str, ctx: &EvaluationContext) -> ConditionResult {
    let mut evidence = Vec::new();

    for string_info in &ctx.report.strings {
        // Compute layer path from string's section and encoding_chain
        let section = string_info.section.as_ref().cloned().unwrap_or_else(|| "content".to_string());
        let layer_path = if string_info.encoding_chain.is_empty() {
            // No encoding layers - not a layered string, skip
            continue;
        } else {
            let chain_str = string_info.encoding_chain.join("/");
            format!("meta/layers/{}/{}", section, chain_str)
        };

        // Check if this string's layer path matches the condition value
        if layer_path == value {
            evidence.push(Evidence {
                method: "layer_path".to_string(),
                source: "string_extractor".to_string(),
                value: string_info.value.clone(),
                location: string_info.offset.clone(),
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
