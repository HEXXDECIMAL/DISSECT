//! Condition evaluators for composite rules.
//!
//! This module contains all the eval_* functions used to evaluate various
//! condition types against an analysis context.

use super::context::{ConditionResult, EvaluationContext, StringParams};
use super::types::{FileType, Platform};
use crate::types::Evidence;
use anyhow::Result;
use regex::Regex;
use std::sync::Arc;
use streaming_iterator::StreamingIterator;

/// Check if a symbol matches a pattern (supports exact match or regex)
pub fn symbol_matches(symbol: &str, pattern: &str) -> bool {
    // Clean symbol (remove leading underscores)
    let clean = symbol.trim_start_matches('_').trim_start_matches("__");

    // Try exact match first
    if clean == pattern || symbol == pattern {
        return true;
    }

    // Try as regex if pattern contains regex metacharacters
    if pattern.contains('|') || pattern.contains('*') || pattern.contains('[') {
        if let Ok(re) = Regex::new(pattern) {
            return re.is_match(clean) || re.is_match(symbol);
        }
    }

    false
}

/// Build a regex with optional case insensitivity
pub fn build_regex(pattern: &str, case_insensitive: bool) -> Result<Regex> {
    if case_insensitive {
        Ok(Regex::new(&format!("(?i){}", pattern))?)
    } else {
        Ok(Regex::new(pattern)?)
    }
}

/// Truncate evidence string to max length
pub fn truncate_evidence(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(max_len).collect::<String>())
    }
}

/// Evaluate symbol condition
pub fn eval_symbol(
    pattern: &str,
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
            };
        }
    }

    let mut evidence = Vec::new();

    // Search in imports
    for import in &ctx.report.imports {
        if symbol_matches(&import.symbol, pattern) {
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
        if symbol_matches(&export.symbol, pattern) {
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
    }
}

/// Evaluate string condition
pub fn eval_string(params: &StringParams, ctx: &EvaluationContext) -> ConditionResult {
    let mut evidence = Vec::new();

    // If search_raw is true, count all occurrences in raw content
    if params.search_raw {
        if let Ok(content) = std::str::from_utf8(ctx.binary_data) {
            if let Some(regex_pattern) = params.regex {
                if let Ok(re) = build_regex(regex_pattern, params.case_insensitive) {
                    let mut match_count = 0;
                    let mut first_match = None;
                    for mat in re.find_iter(content) {
                        match_count += 1;
                        if first_match.is_none() {
                            first_match = Some(mat.as_str().to_string());
                        }
                    }
                    if match_count >= params.min_count {
                        // Add a single evidence entry with the count
                        evidence.push(Evidence {
                            method: "string".to_string(),
                            source: "raw_content".to_string(),
                            value: format!(
                                "Found {} {}",
                                match_count,
                                first_match.unwrap_or_default()
                            ),
                            location: Some("file".to_string()),
                        });
                    }
                }
            } else if let Some(exact_str) = params.exact {
                let search_content = if params.case_insensitive {
                    content.to_lowercase()
                } else {
                    content.to_string()
                };
                let search_pattern = if params.case_insensitive {
                    exact_str.to_lowercase()
                } else {
                    exact_str.clone()
                };
                let match_count = search_content.matches(&search_pattern).count();
                // Debug: trace string matching
                if exact_str == "vscode" {
                    eprintln!(
                        "DEBUG eval_string: exact={} match_count={} min_count={} content_len={}",
                        exact_str,
                        match_count,
                        params.min_count,
                        content.len()
                    );
                }
                if match_count >= params.min_count {
                    evidence.push(Evidence {
                        method: "string".to_string(),
                        source: "raw_content".to_string(),
                        value: format!("Found {} {}", match_count, exact_str),
                        location: Some("file".to_string()),
                    });
                }
            }
        }
        return ConditionResult {
            matched: !evidence.is_empty(),
            evidence,
            traits: Vec::new(),
        };
    }

    // Pre-compile regex patterns ONCE before iterating strings
    let compiled_regex = params
        .regex
        .and_then(|pattern| build_regex(pattern, params.case_insensitive).ok());

    let compiled_excludes: Vec<Regex> = params
        .exclude_patterns
        .map(|excludes| excludes.iter().filter_map(|p| Regex::new(p).ok()).collect())
        .unwrap_or_default();

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
        } else if let Some(ref re) = compiled_regex {
            if let Some(mat) = re.find(&string_info.value) {
                matched = true;
                match_value = mat.as_str().to_string();
            }
        }

        if matched {
            // Check exclusion patterns (already compiled)
            let excluded = compiled_excludes
                .iter()
                .any(|re| re.is_match(&string_info.value));
            if excluded {
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

    // For source files or when no strings were extracted, search binary_data directly
    if ctx.report.strings.is_empty()
        || matches!(
            ctx.file_type,
            FileType::Python | FileType::Ruby | FileType::JavaScript | FileType::Shell
        )
    {
        // Convert binary data to string for source code matching
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
            } else if let Some(ref re) = compiled_regex {
                if let Some(mat) = re.find(content) {
                    matched = true;
                    match_value = mat.as_str().to_string();
                }
            }

            if matched {
                // Check exclusion patterns (already compiled)
                let excluded = compiled_excludes.iter().any(|re| re.is_match(&match_value));
                if !excluded {
                    evidence.push(Evidence {
                        method: "string".to_string(),
                        source: "source_code".to_string(),
                        value: match_value,
                        location: Some("file".to_string()),
                    });
                }
            }
        }
    }

    ConditionResult {
        matched: evidence.len() >= params.min_count,
        evidence,
        traits: Vec::new(),
    }
}

/// Evaluate YARA match condition
pub fn eval_yara_match(
    namespace: &str,
    rule: Option<&String>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let mut evidence = Vec::new();

    for yara_match in &ctx.report.yara_matches {
        let namespace_match = yara_match.namespace == namespace
            || yara_match.namespace.starts_with(&format!("{}.", namespace));

        let rule_match = rule.is_none_or(|r| &yara_match.rule == r);

        if namespace_match && rule_match {
            evidence.push(Evidence {
                method: "yara".to_string(),
                source: "yara-x".to_string(),
                value: format!("{}:{}", yara_match.namespace, yara_match.rule),
                location: Some(yara_match.namespace.clone()),
            });
        }
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
    }
}

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
    }
}

/// Evaluate symbol OR string condition
pub fn eval_symbol_or_string(patterns: &[String], ctx: &EvaluationContext) -> ConditionResult {
    for pattern in patterns {
        // Try as symbol first
        let symbol_result = eval_symbol(pattern, None, ctx);
        if symbol_result.matched {
            return symbol_result;
        }

        // Try as exact string match
        let params = StringParams {
            exact: Some(pattern),
            regex: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            search_raw: false,
        };
        let string_result = eval_string(&params, ctx);
        if string_result.matched {
            return string_result;
        }
    }

    ConditionResult {
        matched: false,
        evidence: Vec::new(),
        traits: Vec::new(),
    }
}

/// Evaluate imports count condition
pub fn eval_imports_count(
    min: Option<usize>,
    max: Option<usize>,
    filter: Option<&String>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let count = if let Some(filter_pattern) = filter {
        ctx.report
            .imports
            .iter()
            .filter(|imp| imp.symbol.contains(filter_pattern))
            .count()
    } else {
        ctx.report.imports.len()
    };

    let matched = min.is_none_or(|m| count >= m) && max.is_none_or(|m| count <= m);

    ConditionResult {
        matched,
        evidence: if matched {
            vec![Evidence {
                method: "imports_count".to_string(),
                source: "analysis".to_string(),
                value: count.to_string(),
                location: None,
            }]
        } else {
            Vec::new()
        },
        traits: Vec::new(),
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

    ConditionResult {
        matched,
        evidence: if matched {
            vec![Evidence {
                method: "exports_count".to_string(),
                source: "analysis".to_string(),
                value: count.to_string(),
                location: None,
            }]
        } else {
            Vec::new()
        },
        traits: Vec::new(),
    }
}

/// Evaluate AST pattern condition - searches for text patterns within specific AST node types
pub fn eval_ast_pattern(
    node_type: &str,
    pattern: &str,
    use_regex: bool,
    case_insensitive: bool,
    ctx: &EvaluationContext,
) -> ConditionResult {
    // Only works for source code files
    let source = match std::str::from_utf8(ctx.binary_data) {
        Ok(s) => s,
        Err(_) => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            }
        }
    };

    // Get the appropriate parser based on file type
    let parser_lang = match ctx.file_type {
        FileType::C => Some(tree_sitter_c::LANGUAGE),
        FileType::Python => Some(tree_sitter_python::LANGUAGE),
        FileType::JavaScript => Some(tree_sitter_javascript::LANGUAGE),
        FileType::TypeScript => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT),
        FileType::Rust => Some(tree_sitter_rust::LANGUAGE),
        FileType::Go => Some(tree_sitter_go::LANGUAGE),
        FileType::Java => Some(tree_sitter_java::LANGUAGE),
        FileType::Ruby => Some(tree_sitter_ruby::LANGUAGE),
        FileType::Shell => Some(tree_sitter_bash::LANGUAGE),
        FileType::Php => Some(tree_sitter_php::LANGUAGE_PHP),
        FileType::CSharp => Some(tree_sitter_c_sharp::LANGUAGE),
        _ => None,
    };

    let lang = match parser_lang {
        Some(l) => l,
        None => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            }
        }
    };

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&lang.into()).is_err() {
        return ConditionResult {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
        };
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            }
        }
    };

    // Build the regex/pattern matcher
    let matcher: Box<dyn Fn(&str) -> bool> = if use_regex {
        match build_regex(pattern, case_insensitive) {
            Ok(re) => Box::new(move |s: &str| re.is_match(s)),
            Err(_) => {
                return ConditionResult {
                    matched: false,
                    evidence: Vec::new(),
                    traits: Vec::new(),
                }
            }
        }
    } else if case_insensitive {
        let pattern_lower = pattern.to_lowercase();
        Box::new(move |s: &str| s.to_lowercase().contains(&pattern_lower))
    } else {
        let pattern_owned = pattern.to_string();
        Box::new(move |s: &str| s.contains(&pattern_owned))
    };

    // Walk the AST and find matching nodes
    let mut evidence = Vec::new();
    let mut cursor = tree.walk();
    walk_ast_for_pattern(
        &mut cursor,
        source.as_bytes(),
        node_type,
        &matcher,
        &mut evidence,
    );

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
    }
}

/// Recursively walk AST looking for nodes matching the pattern
fn walk_ast_for_pattern(
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    target_node_type: &str,
    matcher: &dyn Fn(&str) -> bool,
    evidence: &mut Vec<Evidence>,
) {
    loop {
        let node = cursor.node();

        // Check if this node matches the target type
        if node.kind() == target_node_type {
            if let Ok(text) = node.utf8_text(source) {
                if matcher(text) {
                    evidence.push(Evidence {
                        method: "ast_pattern".to_string(),
                        source: "tree-sitter".to_string(),
                        value: truncate_evidence(text, 100),
                        location: Some(format!(
                            "{}:{}",
                            node.start_position().row + 1,
                            node.start_position().column + 1
                        )),
                    });
                }
            }
        }

        // Recurse into children
        if cursor.goto_first_child() {
            walk_ast_for_pattern(cursor, source, target_node_type, matcher, evidence);
            cursor.goto_parent();
        }

        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

/// Evaluate full tree-sitter query condition
pub fn eval_ast_query(query_str: &str, ctx: &EvaluationContext) -> ConditionResult {
    // Only works for source code files
    let source = match std::str::from_utf8(ctx.binary_data) {
        Ok(s) => s,
        Err(_) => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            }
        }
    };

    // Get the appropriate parser and language based on file type
    let lang = match ctx.file_type {
        FileType::C => tree_sitter_c::LANGUAGE.into(),
        FileType::Python => tree_sitter_python::LANGUAGE.into(),
        FileType::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        FileType::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        FileType::Rust => tree_sitter_rust::LANGUAGE.into(),
        FileType::Go => tree_sitter_go::LANGUAGE.into(),
        FileType::Java => tree_sitter_java::LANGUAGE.into(),
        FileType::Ruby => tree_sitter_ruby::LANGUAGE.into(),
        FileType::Shell => tree_sitter_bash::LANGUAGE.into(),
        FileType::Php => tree_sitter_php::LANGUAGE_PHP.into(),
        FileType::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
        _ => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            }
        }
    };

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&lang).is_err() {
        return ConditionResult {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
        };
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            }
        }
    };

    // Compile the query
    let query = match tree_sitter::Query::new(&lang, query_str) {
        Ok(q) => q,
        Err(_) => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            }
        }
    };

    // Execute the query
    let mut query_cursor = tree_sitter::QueryCursor::new();
    let mut evidence = Vec::new();

    // Use captures() with StreamingIterator pattern (advance + get)
    let mut captures = query_cursor.captures(&query, tree.root_node(), source.as_bytes());
    while let Some((m, _)) = captures.next() {
        for capture in m.captures {
            if let Ok(text) = capture.node.utf8_text(source.as_bytes()) {
                evidence.push(Evidence {
                    method: "ast_query".to_string(),
                    source: "tree-sitter".to_string(),
                    value: truncate_evidence(text, 100),
                    location: Some(format!(
                        "{}:{}",
                        capture.node.start_position().row + 1,
                        capture.node.start_position().column + 1
                    )),
                });
            }
        }
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
    }
}

/// Evaluate inline YARA rule condition
pub fn eval_yara_inline(
    source: &str,
    compiled: Option<&Arc<yara_x::Rules>>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    // Use pre-compiled rules if available, otherwise compile on-the-fly (slower)
    let owned_rules;
    let rules: &yara_x::Rules = if let Some(pre_compiled) = compiled {
        pre_compiled.as_ref()
    } else {
        // Fallback: compile the YARA rule (this is slow, should be pre-compiled)
        let mut compiler = yara_x::Compiler::new();
        compiler.new_namespace("inline");
        if compiler.add_source(source.as_bytes()).is_err() {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            };
        }
        owned_rules = compiler.build();
        &owned_rules
    };

    // Scan the binary data
    let mut scanner = yara_x::Scanner::new(rules);
    let results = match scanner.scan(ctx.binary_data) {
        Ok(r) => r,
        Err(_) => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            }
        }
    };

    // Collect evidence from matches
    let mut evidence = Vec::new();
    for matched_rule in results.matching_rules() {
        for pattern in matched_rule.patterns() {
            for m in pattern.matches() {
                // Extract matched bytes as string if possible
                let match_value = ctx
                    .binary_data
                    .get(m.range())
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .map(|s| truncate_evidence(s, 50))
                    .unwrap_or_else(|| format!("<{} bytes>", m.range().len()));

                evidence.push(Evidence {
                    method: "yara".to_string(),
                    source: "yara-x".to_string(),
                    value: format!(
                        "{}:{} = {}",
                        matched_rule.identifier(),
                        pattern.identifier(),
                        match_value
                    ),
                    location: Some(format!("offset:{}", m.range().start)),
                });
            }
        }
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
    }
}

/// Evaluate syscall condition - matches syscalls detected via radare2 analysis
pub fn eval_syscall(
    name: Option<&Vec<String>>,
    number: Option<&Vec<u32>>,
    arch: Option<&Vec<String>>,
    min_count: Option<usize>,
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

    let min_required = min_count.unwrap_or(1);
    let matched = match_count >= min_required;

    ConditionResult {
        matched,
        evidence: if matched { evidence } else { Vec::new() },
        traits: Vec::new(),
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
        };
    }

    let ratio = section_size as f64 / compare_size as f64;
    let min_ok = min_ratio.is_none_or(|min| ratio >= min);
    let max_ok = max_ratio.is_none_or(|max| ratio <= max);
    let matched = min_ok && max_ok;

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
            }
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

    ConditionResult {
        matched: any_matched,
        evidence,
        traits: Vec::new(),
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
            };
        }
        evidence.push(Evidence {
            method: "import_count".to_string(),
            source: "binary".to_string(),
            value: format!("{} imports (max {})", ctx.report.imports.len(), max),
            location: None,
        });
    }

    ConditionResult {
        matched: true,
        evidence,
        traits: Vec::new(),
    }
}

/// Evaluate string count condition - check if string count is within bounds
pub fn eval_string_count(
    min: Option<usize>,
    max: Option<usize>,
    min_length: Option<usize>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let min_len = min_length.unwrap_or(0);
    let count = ctx
        .report
        .strings
        .iter()
        .filter(|s| s.value.len() >= min_len)
        .count();

    let min_ok = min.is_none_or(|m| count >= m);
    let max_ok = max.is_none_or(|m| count <= m);
    let matched = min_ok && max_ok;

    ConditionResult {
        matched,
        evidence: if matched {
            vec![Evidence {
                method: "string_count".to_string(),
                source: "binary".to_string(),
                value: format!("{} strings (>= {} chars)", count, min_len),
                location: None,
            }]
        } else {
            Vec::new()
        },
        traits: Vec::new(),
    }
}

/// Evaluate metrics condition - check computed metrics against thresholds
/// Field path examples: "identifiers.avg_entropy", "functions.density_per_100_lines"
pub fn eval_metrics(
    field: &str,
    min: Option<f64>,
    max: Option<f64>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let metrics = match &ctx.report.metrics {
        Some(m) => m,
        None => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            }
        }
    };

    // Parse field path and get value
    let value = match field {
        // Text metrics
        "text.char_entropy" => metrics.text.as_ref().map(|t| t.char_entropy as f64),
        "text.line_length_stddev" => metrics.text.as_ref().map(|t| t.line_length_stddev as f64),
        "text.avg_line_length" => metrics.text.as_ref().map(|t| t.avg_line_length as f64),
        "text.max_line_length" => metrics.text.as_ref().map(|t| t.max_line_length as f64),
        "text.empty_line_ratio" => metrics.text.as_ref().map(|t| t.empty_line_ratio as f64),
        "text.whitespace_ratio" => metrics.text.as_ref().map(|t| t.whitespace_ratio as f64),
        "text.digit_ratio" => metrics.text.as_ref().map(|t| t.digit_ratio as f64),

        // Identifier metrics
        "identifiers.total" => metrics.identifiers.as_ref().map(|i| i.total as f64),
        "identifiers.unique" => metrics.identifiers.as_ref().map(|i| i.unique as f64),
        "identifiers.reuse_ratio" => metrics.identifiers.as_ref().map(|i| i.reuse_ratio as f64),
        "identifiers.avg_length" => metrics.identifiers.as_ref().map(|i| i.avg_length as f64),
        "identifiers.avg_entropy" => metrics.identifiers.as_ref().map(|i| i.avg_entropy as f64),
        "identifiers.high_entropy_ratio" => metrics
            .identifiers
            .as_ref()
            .map(|i| i.high_entropy_ratio as f64),
        "identifiers.single_char_ratio" => metrics
            .identifiers
            .as_ref()
            .map(|i| i.single_char_ratio as f64),
        "identifiers.single_char_count" => metrics
            .identifiers
            .as_ref()
            .map(|i| i.single_char_count as f64),
        "identifiers.numeric_suffix_count" => metrics
            .identifiers
            .as_ref()
            .map(|i| i.numeric_suffix_count as f64),
        "identifiers.sequential_names" => metrics
            .identifiers
            .as_ref()
            .map(|i| i.sequential_names as f64),

        // String metrics
        "strings.total" => metrics.strings.as_ref().map(|s| s.total as f64),
        "strings.avg_entropy" => metrics.strings.as_ref().map(|s| s.avg_entropy as f64),
        "strings.entropy_stddev" => metrics.strings.as_ref().map(|s| s.entropy_stddev as f64),
        "strings.avg_length" => metrics.strings.as_ref().map(|s| s.avg_length as f64),

        // Comment metrics
        "comments.total" => metrics.comments.as_ref().map(|c| c.total as f64),
        "comments.to_code_ratio" => metrics.comments.as_ref().map(|c| c.to_code_ratio as f64),

        // Function metrics
        "functions.total" => metrics.functions.as_ref().map(|f| f.total as f64),
        "functions.anonymous" => metrics.functions.as_ref().map(|f| f.anonymous as f64),
        "functions.async_count" => metrics.functions.as_ref().map(|f| f.async_count as f64),
        "functions.avg_length_lines" => metrics
            .functions
            .as_ref()
            .map(|f| f.avg_length_lines as f64),
        "functions.max_length_lines" => metrics
            .functions
            .as_ref()
            .map(|f| f.max_length_lines as f64),
        "functions.length_stddev" => metrics.functions.as_ref().map(|f| f.length_stddev as f64),
        "functions.over_100_lines" => metrics.functions.as_ref().map(|f| f.over_100_lines as f64),
        "functions.over_500_lines" => metrics.functions.as_ref().map(|f| f.over_500_lines as f64),
        "functions.one_liners" => metrics.functions.as_ref().map(|f| f.one_liners as f64),
        "functions.avg_params" => metrics.functions.as_ref().map(|f| f.avg_params as f64),
        "functions.max_params" => metrics.functions.as_ref().map(|f| f.max_params as f64),
        "functions.many_params_count" => metrics
            .functions
            .as_ref()
            .map(|f| f.many_params_count as f64),
        "functions.single_char_names" => metrics
            .functions
            .as_ref()
            .map(|f| f.single_char_names as f64),
        "functions.high_entropy_names" => metrics
            .functions
            .as_ref()
            .map(|f| f.high_entropy_names as f64),
        "functions.numeric_suffix_names" => metrics
            .functions
            .as_ref()
            .map(|f| f.numeric_suffix_names as f64),
        "functions.max_nesting_depth" => metrics
            .functions
            .as_ref()
            .map(|f| f.max_nesting_depth as f64),
        "functions.avg_nesting_depth" => metrics
            .functions
            .as_ref()
            .map(|f| f.avg_nesting_depth as f64),
        "functions.nested_functions" => metrics
            .functions
            .as_ref()
            .map(|f| f.nested_functions as f64),
        "functions.density_per_100_lines" => metrics
            .functions
            .as_ref()
            .map(|f| f.density_per_100_lines as f64),
        "functions.code_in_functions_ratio" => metrics
            .functions
            .as_ref()
            .map(|f| f.code_in_functions_ratio as f64),
        "functions.single_char_params" => metrics
            .functions
            .as_ref()
            .map(|f| f.single_char_params as f64),
        "functions.avg_param_name_length" => metrics
            .functions
            .as_ref()
            .map(|f| f.avg_param_name_length as f64),

        // Binary metrics (from radare2 analysis)
        "binary.overall_entropy" => metrics.binary.as_ref().map(|b| b.overall_entropy as f64),
        "binary.code_entropy" => metrics.binary.as_ref().map(|b| b.code_entropy as f64),
        "binary.data_entropy" => metrics.binary.as_ref().map(|b| b.data_entropy as f64),
        "binary.entropy_variance" => metrics.binary.as_ref().map(|b| b.entropy_variance as f64),
        "binary.high_entropy_regions" => metrics
            .binary
            .as_ref()
            .map(|b| b.high_entropy_regions as f64),
        "binary.section_count" => metrics.binary.as_ref().map(|b| b.section_count as f64),
        "binary.executable_sections" => metrics
            .binary
            .as_ref()
            .map(|b| b.executable_sections as f64),
        "binary.writable_sections" => metrics.binary.as_ref().map(|b| b.writable_sections as f64),
        "binary.wx_sections" => metrics.binary.as_ref().map(|b| b.wx_sections as f64),
        "binary.section_name_entropy" => metrics
            .binary
            .as_ref()
            .map(|b| b.section_name_entropy as f64),
        "binary.largest_section_ratio" => metrics
            .binary
            .as_ref()
            .map(|b| b.largest_section_ratio as f64),
        "binary.import_count" => metrics.binary.as_ref().map(|b| b.import_count as f64),
        "binary.export_count" => metrics.binary.as_ref().map(|b| b.export_count as f64),
        "binary.import_entropy" => metrics.binary.as_ref().map(|b| b.import_entropy as f64),
        "binary.string_count" => metrics.binary.as_ref().map(|b| b.string_count as f64),
        "binary.avg_string_entropy" => metrics.binary.as_ref().map(|b| b.avg_string_entropy as f64),
        "binary.high_entropy_strings" => metrics
            .binary
            .as_ref()
            .map(|b| b.high_entropy_strings as f64),
        "binary.function_count" => metrics.binary.as_ref().map(|b| b.function_count as f64),
        "binary.avg_function_size" => metrics.binary.as_ref().map(|b| b.avg_function_size as f64),
        "binary.tiny_functions" => metrics.binary.as_ref().map(|b| b.tiny_functions as f64),
        "binary.huge_functions" => metrics.binary.as_ref().map(|b| b.huge_functions as f64),
        "binary.has_overlay" => metrics
            .binary
            .as_ref()
            .map(|b| if b.has_overlay { 1.0 } else { 0.0 }),
        "binary.overlay_size" => metrics.binary.as_ref().map(|b| b.overlay_size as f64),
        "binary.overlay_ratio" => metrics.binary.as_ref().map(|b| b.overlay_ratio as f64),
        "binary.overlay_entropy" => metrics.binary.as_ref().map(|b| b.overlay_entropy as f64),

        // Complexity metrics
        "binary.avg_complexity" => metrics.binary.as_ref().map(|b| b.avg_complexity as f64),
        "binary.max_complexity" => metrics.binary.as_ref().map(|b| b.max_complexity as f64),
        "binary.high_complexity_functions" => metrics
            .binary
            .as_ref()
            .map(|b| b.high_complexity_functions as f64),
        "binary.very_high_complexity_functions" => metrics
            .binary
            .as_ref()
            .map(|b| b.very_high_complexity_functions as f64),

        // Control flow metrics
        "binary.total_basic_blocks" => metrics.binary.as_ref().map(|b| b.total_basic_blocks as f64),
        "binary.avg_basic_blocks" => metrics.binary.as_ref().map(|b| b.avg_basic_blocks as f64),
        "binary.linear_functions" => metrics.binary.as_ref().map(|b| b.linear_functions as f64),
        "binary.recursive_functions" => metrics
            .binary
            .as_ref()
            .map(|b| b.recursive_functions as f64),
        "binary.noreturn_functions" => metrics.binary.as_ref().map(|b| b.noreturn_functions as f64),
        "binary.leaf_functions" => metrics.binary.as_ref().map(|b| b.leaf_functions as f64),

        // Stack metrics
        "binary.avg_stack_frame" => metrics.binary.as_ref().map(|b| b.avg_stack_frame as f64),
        "binary.max_stack_frame" => metrics.binary.as_ref().map(|b| b.max_stack_frame as f64),
        "binary.large_stack_functions" => metrics
            .binary
            .as_ref()
            .map(|b| b.large_stack_functions as f64),

        // Go metrics (language-specific)
        "go_metrics.unsafe_usage" => metrics.go_metrics.as_ref().map(|g| g.unsafe_usage as f64),
        "go_metrics.reflect_usage" => metrics.go_metrics.as_ref().map(|g| g.reflect_usage as f64),
        "go_metrics.cgo_usage" => metrics.go_metrics.as_ref().map(|g| g.cgo_usage as f64),
        "go_metrics.plugin_usage" => metrics.go_metrics.as_ref().map(|g| g.plugin_usage as f64),
        "go_metrics.syscall_direct" => metrics.go_metrics.as_ref().map(|g| g.syscall_direct as f64),
        "go_metrics.exec_command_count" => metrics
            .go_metrics
            .as_ref()
            .map(|g| g.exec_command_count as f64),
        "go_metrics.os_startprocess_count" => metrics
            .go_metrics
            .as_ref()
            .map(|g| g.os_startprocess_count as f64),
        "go_metrics.net_dial_count" => metrics.go_metrics.as_ref().map(|g| g.net_dial_count as f64),
        "go_metrics.http_usage" => metrics.go_metrics.as_ref().map(|g| g.http_usage as f64),
        "go_metrics.raw_socket_count" => metrics
            .go_metrics
            .as_ref()
            .map(|g| g.raw_socket_count as f64),
        "go_metrics.embed_directive_count" => metrics
            .go_metrics
            .as_ref()
            .map(|g| g.embed_directive_count as f64),
        "go_metrics.linkname_count" => metrics.go_metrics.as_ref().map(|g| g.linkname_count as f64),
        "go_metrics.noescape_count" => metrics.go_metrics.as_ref().map(|g| g.noescape_count as f64),
        "go_metrics.cgo_directives" => metrics.go_metrics.as_ref().map(|g| g.cgo_directives as f64),
        "go_metrics.init_function_count" => metrics
            .go_metrics
            .as_ref()
            .map(|g| g.init_function_count as f64),
        "go_metrics.blank_import_count" => metrics
            .go_metrics
            .as_ref()
            .map(|g| g.blank_import_count as f64),

        _ => None,
    };

    let value = match value {
        Some(v) => v,
        None => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
            }
        }
    };

    let min_ok = min.is_none_or(|m| value >= m);
    let max_ok = max.is_none_or(|m| value <= m);
    let matched = min_ok && max_ok;

    ConditionResult {
        matched,
        evidence: if matched {
            vec![Evidence {
                method: "metrics".to_string(),
                source: "analyzer".to_string(),
                value: format!("{} = {:.2}", field, value),
                location: None,
            }]
        } else {
            Vec::new()
        },
        traits: Vec::new(),
    }
}

/// Evaluate trait reference condition - check if a trait has already been matched
pub fn eval_trait(id: &str, ctx: &EvaluationContext) -> ConditionResult {
    let mut evidence = Vec::new();
    let mut matched = false;

    for finding in &ctx.report.findings {
        // Support exact match or suffix match (e.g. "net/socket" matches "legitimate/net/socket")
        if finding.id == id || finding.id.ends_with(&format!("/{}", id)) {
            matched = true;
            evidence.extend(finding.evidence.clone());
        }
    }

    ConditionResult {
        matched,
        evidence,
        traits: if matched {
            vec![id.to_string()]
        } else {
            Vec::new()
        },
    }
}
