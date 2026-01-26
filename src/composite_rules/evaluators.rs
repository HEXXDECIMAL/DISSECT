//! Condition evaluators for composite rules.
//!
//! This module contains all the eval_* functions used to evaluate various
//! condition types against an analysis context.

use super::context::{AnalysisWarning, ConditionResult, EvaluationContext, StringParams};
use super::types::{FileType, Platform};
use crate::types::Evidence;
use anyhow::Result;
use dashmap::DashMap;
use regex::Regex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use streaming_iterator::StreamingIterator;

/// Global cache for compiled regex patterns to avoid repeated compilation.
/// Key is (pattern, case_insensitive), value is compiled Regex.
static REGEX_CACHE: OnceLock<DashMap<(String, bool), Regex>> = OnceLock::new();

fn regex_cache() -> &'static DashMap<(String, bool), Regex> {
    REGEX_CACHE.get_or_init(DashMap::new)
}

// Thread-local cache for YARA Scanners to avoid expensive Scanner::new() calls.
// Key is the raw pointer to Rules (stable since Rules is behind Arc).
// Scanner creation involves wasmtime VM instantiation which is expensive (~200µs).
// Reusing scanners provides ~5x speedup.
thread_local! {
    static SCANNER_CACHE: RefCell<HashMap<usize, yara_x::Scanner<'static>>> = RefCell::new(HashMap::new());
}

/// Get or create a Scanner for the given Rules, using thread-local caching.
/// SAFETY: The Rules pointer must remain valid for the duration of Scanner use.
/// This is guaranteed because Rules is behind Arc<Rules> held by TraitDefinitions.
#[allow(clippy::mut_from_ref)] // Intentional: mutable Scanner from thread-local cache
fn get_or_create_scanner<'a>(rules: &'a yara_x::Rules) -> &'a mut yara_x::Scanner<'a> {
    let key = rules as *const yara_x::Rules as usize;

    SCANNER_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();

        // Get or insert scanner for these rules
        // SAFETY: We extend the lifetime to 'static for storage in the thread-local.
        // This is safe because:
        // 1. Rules is behind Arc<Rules> in TraitDefinition, living for program duration
        // 2. We only use the Scanner while Rules is valid (within eval_yara_inline)
        // 3. Thread-local storage means no cross-thread access
        let scanner = cache.entry(key).or_insert_with(|| {
            let scanner = yara_x::Scanner::new(rules);
            unsafe { std::mem::transmute(scanner) }
        });

        // Transmute lifetime back to caller's lifetime
        // SAFETY: We're returning a reference with the caller's lifetime 'a,
        // which is valid since we only call this while rules is valid.
        unsafe {
            std::mem::transmute::<&mut yara_x::Scanner<'static>, &mut yara_x::Scanner<'a>>(scanner)
        }
    })
}

/// Check if a symbol matches a pattern (supports exact match or regex).
/// Uses cached regex compilation for patterns with metacharacters.
pub fn symbol_matches(symbol: &str, pattern: &str) -> bool {
    // Clean symbol (remove leading underscores)
    let clean = symbol.trim_start_matches('_').trim_start_matches("__");

    // Try exact match first
    if clean == pattern || symbol == pattern {
        return true;
    }

    // Try as regex if pattern contains regex metacharacters
    if pattern.contains('|') || pattern.contains('*') || pattern.contains('[') {
        if let Ok(re) = build_regex(pattern, false) {
            return re.is_match(clean) || re.is_match(symbol);
        }
    }

    false
}

/// Build a regex with optional case insensitivity.
/// Results are cached globally for reuse across files.
pub fn build_regex(pattern: &str, case_insensitive: bool) -> Result<Regex> {
    let cache = regex_cache();
    let key = (pattern.to_string(), case_insensitive);

    // Check cache first
    if let Some(re) = cache.get(&key) {
        return Ok(re.value().clone());
    }

    // Compile and cache
    let regex = if case_insensitive {
        Regex::new(&format!("(?i){}", pattern))?
    } else {
        Regex::new(pattern)?
    };
    cache.insert(key, regex.clone());
    Ok(regex)
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

/// Check if a symbol matches an exact name or pattern
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
/// For searching raw file content, use `eval_raw()` instead.
pub fn eval_string(params: &StringParams, ctx: &EvaluationContext) -> ConditionResult {
    let mut evidence = Vec::new();

    // Legacy support: if search_raw is true, delegate to eval_raw
    if params.search_raw {
        return eval_raw(
            params.exact,
            params.regex,
            params.word,
            params.case_insensitive,
            params.min_count,
            ctx,
        );
    }

    // Pre-compile regex patterns ONCE before iterating strings
    // If `word` is provided, convert it to a regex with word boundaries
    let compiled_regex = if let Some(word_pattern) = params.word {
        let regex_pattern = format!(r"\b{}\b", regex::escape(word_pattern));
        build_regex(&regex_pattern, params.case_insensitive).ok()
    } else {
        params
            .regex
            .and_then(|pattern| build_regex(pattern, params.case_insensitive).ok())
    };

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
            } else if let Some(ref re) = compiled_regex {
                if let Some(mat) = re.find(content) {
                    matched = true;
                    match_value = mat.as_str().to_string();
                }
            }

            if matched {
                let excluded = compiled_excludes.iter().any(|re| re.is_match(&match_value));
                if !excluded {
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

    ConditionResult {
        matched: evidence.len() >= params.min_count,
        evidence,
        traits: Vec::new(),
        warnings: Vec::new(),
    }
}

/// Evaluate raw content condition - searches directly in raw file bytes as text.
/// Use this for source files or when you need to match patterns that may span
/// string boundaries in binaries.
pub fn eval_raw(
    exact: Option<&String>,
    regex: Option<&String>,
    word: Option<&String>,
    case_insensitive: bool,
    min_count: usize,
    ctx: &EvaluationContext,
) -> ConditionResult {
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

    // Priority: word > regex > exact
    if let Some(word_pattern) = word {
        // Convert word to regex with word boundaries
        let regex_pattern = format!(r"\b{}\b", regex::escape(word_pattern));
        if let Ok(re) = build_regex(&regex_pattern, case_insensitive) {
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
        }
    } else if let Some(regex_pattern) = regex {
        if let Ok(re) = build_regex(regex_pattern, case_insensitive) {
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

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
        warnings: Vec::new(),
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
            // Extract actual matched content from matched_strings
            if yara_match.matched_strings.is_empty() {
                evidence.push(Evidence {
                    method: "yara".to_string(),
                    source: "yara-x".to_string(),
                    value: yara_match.rule.clone(),
                    location: Some(yara_match.namespace.clone()),
                });
            } else {
                for ms in &yara_match.matched_strings {
                    // Use actual value if printable, otherwise use identifier
                    let is_printable = ms
                        .value
                        .bytes()
                        .all(|b| (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\t');
                    let evidence_value = if is_printable && !ms.value.is_empty() {
                        ms.value.clone()
                    } else {
                        ms.identifier.clone()
                    };

                    evidence.push(Evidence {
                        method: "yara".to_string(),
                        source: "yara-x".to_string(),
                        value: evidence_value,
                        location: Some(format!("0x{:x}", ms.offset)),
                    });
                }
            }
        }
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
        warnings: Vec::new(),
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
        warnings: Vec::new(),
    }
}

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
                warnings: Vec::new(),
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
        FileType::Lua => Some(tree_sitter_lua::LANGUAGE),
        FileType::Perl => Some(tree_sitter_perl::LANGUAGE),
        FileType::PowerShell => Some(tree_sitter_powershell::LANGUAGE),
        FileType::Swift => Some(tree_sitter_swift::LANGUAGE),
        FileType::ObjectiveC => Some(tree_sitter_objc::LANGUAGE),
        FileType::Groovy => Some(tree_sitter_groovy::LANGUAGE),
        FileType::Scala => Some(tree_sitter_scala::LANGUAGE),
        FileType::Zig => Some(tree_sitter_zig::LANGUAGE),
        FileType::Elixir => Some(tree_sitter_elixir::LANGUAGE),
        _ => None,
    };

    let lang: tree_sitter::Language = match parser_lang {
        Some(l) => l.into(),
        None => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
            }
        }
    };

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&lang).is_err() {
        return ConditionResult {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
            warnings: Vec::new(),
        };
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
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
                    warnings: Vec::new(),
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
    let stats = walk_ast_for_pattern(
        &mut cursor,
        source.as_bytes(),
        node_type,
        &matcher,
        &mut evidence,
    );

    let mut warnings = Vec::new();
    if stats.depth_limit_hit {
        warnings.push(AnalysisWarning::AstTooDeep {
            max_depth: stats.max_depth_reached,
        });
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
        warnings,
    }
}

/// Iteratively walk AST looking for nodes matching the pattern (stack-safe)
/// Returns WalkStats to detect potential anti-analysis (recursion bombs)
fn walk_ast_for_pattern(
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    target_node_type: &str,
    matcher: &dyn Fn(&str) -> bool,
    evidence: &mut Vec<Evidence>,
) -> crate::analyzers::ast_walker::WalkStats {
    crate::analyzers::ast_walker::walk_tree_with_stats(cursor, |node, _depth| {
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
        true // continue traversal into children
    })
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
                warnings: Vec::new(),
            }
        }
    };

    // Get the appropriate parser and language based on file type
    let lang: tree_sitter::Language = match ctx.file_type {
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
        FileType::Lua => tree_sitter_lua::LANGUAGE.into(),
        FileType::Perl => tree_sitter_perl::LANGUAGE.into(),
        FileType::PowerShell => tree_sitter_powershell::LANGUAGE.into(),
        FileType::Swift => tree_sitter_swift::LANGUAGE.into(),
        FileType::ObjectiveC => tree_sitter_objc::LANGUAGE.into(),
        FileType::Groovy => tree_sitter_groovy::LANGUAGE.into(),
        FileType::Scala => tree_sitter_scala::LANGUAGE.into(),
        FileType::Zig => tree_sitter_zig::LANGUAGE.into(),
        FileType::Elixir => tree_sitter_elixir::LANGUAGE.into(),
        _ => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
            }
        }
    };

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&lang).is_err() {
        return ConditionResult {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
            warnings: Vec::new(),
        };
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
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
                warnings: Vec::new(),
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
        warnings: Vec::new(),
    }
}

/// Collect evidence from YARA scan results.
fn collect_yara_evidence(results: yara_x::ScanResults, binary_data: &[u8]) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    for matched_rule in results.matching_rules() {
        for pattern in matched_rule.patterns() {
            for m in pattern.matches() {
                let match_bytes = binary_data.get(m.range());
                let evidence_value = match match_bytes {
                    Some(bytes) => {
                        let is_printable = bytes
                            .iter()
                            .all(|&b| (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\t');
                        if is_printable {
                            if let Ok(s) = std::str::from_utf8(bytes) {
                                truncate_evidence(s, 50)
                            } else {
                                pattern.identifier().to_string()
                            }
                        } else {
                            pattern.identifier().to_string()
                        }
                    }
                    None => pattern.identifier().to_string(),
                };

                evidence.push(Evidence {
                    method: "yara".to_string(),
                    source: "yara-x".to_string(),
                    value: evidence_value,
                    location: Some(format!("offset:{}", m.range().start)),
                });
            }
        }
    }
    evidence
}

/// Evaluate inline YARA rule condition.
/// Uses thread-local Scanner caching for pre-compiled rules (~5x speedup).
pub fn eval_yara_inline(
    source: &str,
    compiled: Option<&Arc<yara_x::Rules>>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    // For pre-compiled rules, use cached scanner (fast path)
    // For fallback compilation, create a new scanner (slow path, should be rare)
    let evidence = if let Some(pre_compiled) = compiled {
        // Fast path: use thread-local cached scanner
        let scanner = get_or_create_scanner(pre_compiled.as_ref());
        match scanner.scan(ctx.binary_data) {
            Ok(results) => collect_yara_evidence(results, ctx.binary_data),
            Err(_) => Vec::new(),
        }
    } else {
        // Slow path: compile on-the-fly (should be rare, pre-compilation preferred)
        let mut compiler = yara_x::Compiler::new();
        compiler.new_namespace("inline");
        if compiler.add_source(source.as_bytes()).is_err() {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
            };
        }
        let rules = compiler.build();
        let mut scanner = yara_x::Scanner::new(&rules);
        match scanner.scan(ctx.binary_data) {
            Ok(results) => collect_yara_evidence(results, ctx.binary_data),
            Err(_) => Vec::new(),
        }
    };

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
        warnings: Vec::new(),
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
        warnings: Vec::new(),
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
        warnings: Vec::new(),
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
        warnings: Vec::new(),
    }
}

/// Evaluate section name condition - match section names in binary files
/// Replaces YARA patterns like: `for any section in pe.sections : (section.name matches /^UPX/)`
pub fn eval_section_name(
    pattern: &str,
    use_regex: bool,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let mut evidence = Vec::new();

    for section in &ctx.report.sections {
        let matched = if use_regex {
            match build_regex(pattern, false) {
                Ok(re) => re.is_match(&section.name),
                Err(_) => false,
            }
        } else {
            section.name.contains(pattern)
        };

        if matched {
            evidence.push(Evidence {
                method: "section_name".to_string(),
                source: "binary".to_string(),
                value: section.name.clone(),
                location: None,
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
        warnings: Vec::new(),
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

/// Evaluate metrics condition - check computed metrics against thresholds
/// Field path examples: "identifiers.avg_entropy", "functions.density_per_100_lines"
pub fn eval_metrics(
    field: &str,
    min: Option<f64>,
    max: Option<f64>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    // Check file size constraints first
    let file_size = ctx.report.target.size_bytes;
    if let Some(min_sz) = min_size {
        if file_size < min_sz {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
            };
        }
    }
    if let Some(max_sz) = max_size {
        if file_size > max_sz {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
            };
        }
    }

    let metrics = match &ctx.report.metrics {
        Some(m) => m,
        None => {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                traits: Vec::new(),
                warnings: Vec::new(),
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
                warnings: Vec::new(),
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
    use crate::types::Finding;

    let mut evidence = Vec::new();
    let mut matched = false;

    // Count slashes to determine if this is a directory path or a short name
    let slash_count = id.matches('/').count();

    // Helper to check if a finding matches the trait ID
    let matches_trait = |finding: &Finding| -> bool {
        if slash_count == 0 {
            // Short name: suffix match for same-directory relative reference
            // e.g., "terminate" matches "exec/process/terminate"
            finding.id.ends_with(&format!("/{}", id))
        } else {
            // Directory path: prefix match (any trait within that directory)
            // e.g., "anti-static/obfuscation/strings" matches
            // "anti-static/obfuscation/strings/python-hex"
            // Note: We match if the finding starts with the path followed by /
            // This prevents "exec/command" from matching "exec/command-shell"
            finding.id.starts_with(&format!("{}/", id)) || finding.id == id
        }
    };

    // Check findings from the report
    for finding in &ctx.report.findings {
        if matches_trait(finding) {
            matched = true;
            evidence.extend(finding.evidence.clone());
        }
    }

    // Also check additional findings from previous evaluation iterations
    if let Some(additional) = ctx.additional_findings {
        for finding in additional {
            if matches_trait(finding) {
                matched = true;
                evidence.extend(finding.evidence.clone());
            }
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
        warnings: Vec::new(),
    }
}

/// Hex pattern segment for matching
#[derive(Debug, Clone)]
enum HexSegment {
    /// Fixed bytes to match exactly
    Bytes(Vec<u8>),
    /// Single wildcard byte (??)
    Wildcard,
    /// Variable gap [N] or [N-M]
    Gap { min: usize, max: usize },
}

/// Parse a hex pattern string into segments
/// Format: "7F 45 4C 46" or "31 ?? 48" or "00 [4] FF" or "00 [2-8] FF"
fn parse_hex_pattern(pattern: &str) -> Result<Vec<HexSegment>, String> {
    let mut segments: Vec<HexSegment> = Vec::new();
    let mut current_bytes: Vec<u8> = Vec::new();

    for token in pattern.split_whitespace() {
        if token == "??" {
            // Flush current bytes
            if !current_bytes.is_empty() {
                segments.push(HexSegment::Bytes(std::mem::take(&mut current_bytes)));
            }
            segments.push(HexSegment::Wildcard);
        } else if token.starts_with('[') && token.ends_with(']') {
            // Gap: [N] or [N-M]
            if !current_bytes.is_empty() {
                segments.push(HexSegment::Bytes(std::mem::take(&mut current_bytes)));
            }
            let inner = &token[1..token.len() - 1];
            if let Some(dash_pos) = inner.find('-') {
                let min: usize = inner[..dash_pos]
                    .parse()
                    .map_err(|_| format!("invalid gap min: {}", inner))?;
                let max: usize = inner[dash_pos + 1..]
                    .parse()
                    .map_err(|_| format!("invalid gap max: {}", inner))?;
                segments.push(HexSegment::Gap { min, max });
            } else {
                let n: usize = inner
                    .parse()
                    .map_err(|_| format!("invalid gap: {}", inner))?;
                segments.push(HexSegment::Gap { min: n, max: n });
            }
        } else {
            // Regular hex byte
            let byte = u8::from_str_radix(token, 16)
                .map_err(|_| format!("invalid hex byte: {}", token))?;
            current_bytes.push(byte);
        }
    }

    // Flush remaining bytes
    if !current_bytes.is_empty() {
        segments.push(HexSegment::Bytes(current_bytes));
    }

    Ok(segments)
}

/// Check if pattern is simple (no wildcards or gaps)
fn is_simple_pattern(segments: &[HexSegment]) -> bool {
    segments.len() == 1 && matches!(segments.first(), Some(HexSegment::Bytes(_)))
}

/// Extract the longest fixed byte sequence (atom) for fast pre-filtering
fn extract_best_atom(segments: &[HexSegment]) -> Option<&[u8]> {
    segments
        .iter()
        .filter_map(|s| match s {
            HexSegment::Bytes(b) if b.len() >= 2 => Some(b.as_slice()),
            _ => None,
        })
        .max_by_key(|b| b.len())
}

/// Match pattern at a specific position in data
fn match_pattern_at(data: &[u8], pos: usize, segments: &[HexSegment]) -> bool {
    let mut offset = pos;

    for (i, segment) in segments.iter().enumerate() {
        match segment {
            HexSegment::Bytes(bytes) => {
                if offset + bytes.len() > data.len() {
                    return false;
                }
                if &data[offset..offset + bytes.len()] != bytes.as_slice() {
                    return false;
                }
                offset += bytes.len();
            }
            HexSegment::Wildcard => {
                if offset >= data.len() {
                    return false;
                }
                offset += 1;
            }
            HexSegment::Gap { min, max } => {
                // For gaps, we need to try all possible lengths
                if *min == *max {
                    // Fixed gap - just skip
                    offset += min;
                } else {
                    // Variable gap - try each length
                    let remaining_segments = &segments[i + 1..];
                    for gap_len in *min..=*max {
                        if match_pattern_at(data, offset + gap_len, remaining_segments) {
                            return true;
                        }
                    }
                    return false;
                }
            }
        }
    }

    true
}

/// Evaluate hex pattern condition
/// Uses YARA-style atom extraction for efficient searching:
/// 1. Extract longest fixed byte sequence from pattern
/// 2. Use fast memmem search to find atom candidates
/// 3. Verify full pattern only at candidate positions
pub fn eval_hex(
    pattern: &str,
    offset: Option<usize>,
    offset_range: Option<(usize, usize)>,
    min_count: usize,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let data = ctx.binary_data;

    // Parse the pattern
    let segments = match parse_hex_pattern(pattern) {
        Ok(s) => s,
        Err(e) => {
            return ConditionResult {
                matched: false,
                evidence: vec![Evidence {
                    method: "hex".to_string(),
                    source: "error".to_string(),
                    value: format!("invalid hex pattern: {}", e),
                    location: None,
                }],
                traits: Vec::new(),
                warnings: Vec::new(),
            };
        }
    };

    if segments.is_empty() {
        return ConditionResult {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
            warnings: Vec::new(),
        };
    }

    let mut matches: Vec<usize> = Vec::new();

    // Handle offset constraint - only check at specific position
    if let Some(off) = offset {
        if match_pattern_at(data, off, &segments) {
            matches.push(off);
        }
    }
    // Handle offset range constraint
    else if let Some((start, end)) = offset_range {
        let end = end.min(data.len());
        for pos in start..end {
            if match_pattern_at(data, pos, &segments) {
                matches.push(pos);
                if matches.len() >= min_count {
                    break;
                }
            }
        }
    }
    // No offset constraint - search entire file
    else if is_simple_pattern(&segments) {
        // Simple pattern: use fast memmem search
        if let HexSegment::Bytes(bytes) = &segments[0] {
            let finder = memchr::memmem::Finder::new(bytes);
            for pos in finder.find_iter(data) {
                matches.push(pos);
                if matches.len() >= min_count {
                    break;
                }
            }
        }
    } else {
        // Complex pattern: use atom extraction for pre-filtering
        if let Some(atom) = extract_best_atom(&segments) {
            let finder = memchr::memmem::Finder::new(atom);

            // Find the atom's position within the pattern
            let atom_offset_in_pattern: usize = segments
                .iter()
                .take_while(|s| !matches!(s, HexSegment::Bytes(b) if b.as_slice() == atom))
                .map(|s| match s {
                    HexSegment::Bytes(b) => b.len(),
                    HexSegment::Wildcard => 1,
                    HexSegment::Gap { min, .. } => *min,
                })
                .sum();

            // Search for atom, then verify full pattern
            for atom_pos in finder.find_iter(data) {
                let pattern_start = atom_pos.saturating_sub(atom_offset_in_pattern);

                if match_pattern_at(data, pattern_start, &segments)
                    && !matches.contains(&pattern_start)
                {
                    matches.push(pattern_start);
                    if matches.len() >= min_count {
                        break;
                    }
                }
            }
        } else {
            // No good atom found - fall back to linear scan
            for pos in 0..data.len() {
                if match_pattern_at(data, pos, &segments) {
                    matches.push(pos);
                    if matches.len() >= min_count {
                        break;
                    }
                }
            }
        }
    }

    let matched = matches.len() >= min_count;

    ConditionResult {
        matched,
        evidence: if matched {
            matches
                .iter()
                .take(5)
                .map(|pos| Evidence {
                    method: "hex".to_string(),
                    source: "binary".to_string(),
                    value: pattern.to_string(),
                    location: Some(format!("0x{:x}", pos)),
                })
                .collect()
        } else {
            Vec::new()
        },
        traits: Vec::new(),
        warnings: Vec::new(),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_pattern_simple() {
        let segments = parse_hex_pattern("7F 45 4C 46").unwrap();
        assert_eq!(segments.len(), 1);
        match &segments[0] {
            HexSegment::Bytes(b) => assert_eq!(b, &[0x7F, 0x45, 0x4C, 0x46]),
            _ => panic!("expected Bytes"),
        }
    }

    #[test]
    fn test_parse_hex_pattern_wildcards() {
        let segments = parse_hex_pattern("31 ?? 48 83").unwrap();
        assert_eq!(segments.len(), 3);
        match &segments[0] {
            HexSegment::Bytes(b) => assert_eq!(b, &[0x31]),
            _ => panic!("expected Bytes"),
        }
        assert!(matches!(segments[1], HexSegment::Wildcard));
        match &segments[2] {
            HexSegment::Bytes(b) => assert_eq!(b, &[0x48, 0x83]),
            _ => panic!("expected Bytes"),
        }
    }

    #[test]
    fn test_parse_hex_pattern_fixed_gap() {
        let segments = parse_hex_pattern("00 03 [4] 00 04").unwrap();
        assert_eq!(segments.len(), 3);
        match &segments[1] {
            HexSegment::Gap { min, max } => {
                assert_eq!(*min, 4);
                assert_eq!(*max, 4);
            }
            _ => panic!("expected Gap"),
        }
    }

    #[test]
    fn test_parse_hex_pattern_variable_gap() {
        let segments = parse_hex_pattern("00 [2-8] FF").unwrap();
        assert_eq!(segments.len(), 3);
        match &segments[1] {
            HexSegment::Gap { min, max } => {
                assert_eq!(*min, 2);
                assert_eq!(*max, 8);
            }
            _ => panic!("expected Gap"),
        }
    }

    #[test]
    fn test_match_simple_pattern() {
        let data = b"\x7F\x45\x4C\x46\x01\x02\x03";
        let segments = parse_hex_pattern("7F 45 4C 46").unwrap();
        assert!(match_pattern_at(data, 0, &segments));
        assert!(!match_pattern_at(data, 1, &segments));
    }

    #[test]
    fn test_match_wildcard_pattern() {
        let data = b"\x31\xC0\x48\x83";
        let segments = parse_hex_pattern("31 ?? 48 83").unwrap();
        assert!(match_pattern_at(data, 0, &segments));

        let data2 = b"\x31\xFF\x48\x83";
        assert!(match_pattern_at(data2, 0, &segments));

        let data3 = b"\x31\xC0\x48\x84"; // Last byte differs
        assert!(!match_pattern_at(data3, 0, &segments));
    }

    #[test]
    fn test_match_fixed_gap() {
        let data = b"\x00\x03\xAA\xBB\xCC\xDD\x00\x04";
        let segments = parse_hex_pattern("00 03 [4] 00 04").unwrap();
        assert!(match_pattern_at(data, 0, &segments));
    }

    #[test]
    fn test_match_variable_gap() {
        // Gap of 2
        let data2 = b"\x00\xAA\xBB\xFF";
        let segments = parse_hex_pattern("00 [2-4] FF").unwrap();
        assert!(match_pattern_at(data2, 0, &segments));

        // Gap of 4
        let data4 = b"\x00\xAA\xBB\xCC\xDD\xFF";
        assert!(match_pattern_at(data4, 0, &segments));

        // Gap of 5 (too long)
        let data5 = b"\x00\xAA\xBB\xCC\xDD\xEE\xFF";
        assert!(!match_pattern_at(data5, 0, &segments));
    }

    #[test]
    fn test_is_simple_pattern() {
        let simple = parse_hex_pattern("7F 45 4C 46").unwrap();
        assert!(is_simple_pattern(&simple));

        let with_wildcard = parse_hex_pattern("7F ?? 4C 46").unwrap();
        assert!(!is_simple_pattern(&with_wildcard));

        let with_gap = parse_hex_pattern("7F [2] 46").unwrap();
        assert!(!is_simple_pattern(&with_gap));
    }

    #[test]
    fn test_extract_best_atom() {
        let segments = parse_hex_pattern("31 ?? 48 83 C4 08").unwrap();
        let atom = extract_best_atom(&segments).unwrap();
        // Should extract "48 83 C4 08" (4 bytes) not "31" (1 byte)
        assert_eq!(atom, &[0x48, 0x83, 0xC4, 0x08]);
    }

    #[test]
    fn test_parse_invalid_hex() {
        assert!(parse_hex_pattern("ZZ 45").is_err());
        assert!(parse_hex_pattern("[abc]").is_err());
    }
}
