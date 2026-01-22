//! Condition evaluation functions
//!
//! Contains all eval_* functions for evaluating different condition types.

use super::types::{
    Condition, ConditionResult, EvaluationContext, FileType, FloatRange, NumericRange, Platform,
    StringParams,
};
use crate::types::{Evidence, SourceSpan};
use regex::Regex;
use streaming_iterator::StreamingIterator;

/// Check if a symbol matches a pattern (supports exact match or regex)
pub fn symbol_matches(symbol: &str, pattern: &str) -> bool {
    let clean = symbol.trim_start_matches('_').trim_start_matches("__");

    if clean == pattern || symbol == pattern {
        return true;
    }

    if pattern.contains('|') || pattern.contains('*') || pattern.contains('[') {
        if let Ok(re) = Regex::new(pattern) {
            return re.is_match(clean) || re.is_match(symbol);
        }
    }

    false
}

/// Build a regex with optional case insensitivity
pub fn build_regex(pattern: &str, case_insensitive: bool) -> anyhow::Result<Regex> {
    if case_insensitive {
        Ok(Regex::new(&format!("(?i){}", pattern))?)
    } else {
        Ok(Regex::new(pattern)?)
    }
}

/// Truncate evidence string to max length
pub fn truncate_evidence(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

pub fn eval_symbol(
    pattern: &str,
    platforms: Option<&Vec<Platform>>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    if let Some(plats) = platforms {
        if !plats.contains(&ctx.platform) && !plats.contains(&Platform::All) {
            return ConditionResult::no_match();
        }
    }

    let mut evidence = Vec::new();

    for import in &ctx.report.imports {
        if symbol_matches(&import.symbol, pattern) {
            evidence.push(Evidence {
                method: "symbol".to_string(),
                source: import.source.clone(),
                value: import.symbol.clone(),
                location: Some("import".to_string()),
                span: None, analysis_layer: None,
                    analysis_layer: None,
            });
        }
    }

    for export in &ctx.report.exports {
        if symbol_matches(&export.symbol, pattern) {
            evidence.push(Evidence {
                method: "symbol".to_string(),
                source: export.source.clone(),
                value: export.symbol.clone(),
                location: export.offset.clone(),
                span: None, analysis_layer: None,
                    analysis_layer: None,
            });
        }
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
    }
}

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
                        evidence.push(Evidence {
                            method: "string".to_string(),
                            source: "raw_content".to_string(),
                            value: format!(
                                "Found {} {}",
                                match_count,
                                first_match.unwrap_or_default()
                            ),
                            location: Some("file".to_string()),
                            span: None, analysis_layer: None,
                    analysis_layer: None,
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
                if match_count >= params.min_count {
                    evidence.push(Evidence {
                        method: "string".to_string(),
                        source: "raw_content".to_string(),
                        value: format!("Found {} {}", match_count, exact_str),
                        location: Some("file".to_string()),
                        span: None, analysis_layer: None,
                    analysis_layer: None,
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
        } else if let Some(regex_pattern) = params.regex {
            if let Ok(re) = build_regex(regex_pattern, params.case_insensitive) {
                if let Some(mat) = re.find(&string_info.value) {
                    matched = true;
                    match_value = mat.as_str().to_string();
                }
            }
        }

        if matched {
            if let Some(excludes) = params.exclude_patterns {
                let mut excluded = false;
                for exclude_pattern in excludes {
                    if let Ok(re) = Regex::new(exclude_pattern) {
                        if re.is_match(&string_info.value) {
                            excluded = true;
                            break;
                        }
                    }
                }
                if excluded {
                    continue;
                }
            }

            evidence.push(Evidence {
                method: "string".to_string(),
                source: "string_extractor".to_string(),
                value: match_value,
                location: string_info.offset.clone(),
                span: None, analysis_layer: None,
                    analysis_layer: None,
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
            } else if let Some(regex_pattern) = params.regex {
                if let Ok(re) = build_regex(regex_pattern, params.case_insensitive) {
                    if let Some(mat) = re.find(content) {
                        matched = true;
                        match_value = mat.as_str().to_string();
                    }
                }
            }

            if matched {
                if let Some(excludes) = params.exclude_patterns {
                    let mut excluded = false;
                    for exclude_pattern in excludes {
                        if let Ok(re) = Regex::new(exclude_pattern) {
                            if re.is_match(&match_value) {
                                excluded = true;
                                break;
                            }
                        }
                    }
                    if !excluded {
                        evidence.push(Evidence {
                            method: "string".to_string(),
                            source: "source_code".to_string(),
                            value: match_value,
                            location: Some("file".to_string()),
                            span: None, analysis_layer: None,
                    analysis_layer: None,
                        });
                    }
                } else {
                    evidence.push(Evidence {
                        method: "string".to_string(),
                        source: "source_code".to_string(),
                        value: match_value,
                        location: Some("file".to_string()),
                        span: None, analysis_layer: None,
                    analysis_layer: None,
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
                span: None, analysis_layer: None,
                    analysis_layer: None,
            });
        }
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
    }
}

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

pub fn eval_symbol_or_string(patterns: &[String], ctx: &EvaluationContext) -> ConditionResult {
    for pattern in patterns {
        let symbol_result = eval_symbol(pattern, None, ctx);
        if symbol_result.matched {
            return symbol_result;
        }

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

    ConditionResult::no_match()
}

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
                span: None, analysis_layer: None,
                    analysis_layer: None,
            }]
        } else {
            Vec::new()
        },
        traits: Vec::new(),
    }
}

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
                span: None, analysis_layer: None,
                    analysis_layer: None,
            }]
        } else {
            Vec::new()
        },
        traits: Vec::new(),
    }
}

pub fn eval_ast_pattern(
    node_type: &str,
    pattern: &str,
    use_regex: bool,
    case_insensitive: bool,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let source = match std::str::from_utf8(ctx.binary_data) {
        Ok(s) => s,
        Err(_) => return ConditionResult::no_match(),
    };

    let parser_lang = match ctx.file_type {
        FileType::C => Some(tree_sitter_c::LANGUAGE),
        FileType::Python => Some(tree_sitter_python::LANGUAGE),
        FileType::JavaScript => Some(tree_sitter_javascript::LANGUAGE),
        FileType::Rust => Some(tree_sitter_rust::LANGUAGE),
        FileType::Go => Some(tree_sitter_go::LANGUAGE),
        FileType::Java => Some(tree_sitter_java::LANGUAGE),
        FileType::Ruby => Some(tree_sitter_ruby::LANGUAGE),
        FileType::Shell => Some(tree_sitter_bash::LANGUAGE),
        FileType::CSharp => Some(tree_sitter_c_sharp::LANGUAGE),
        _ => None,
    };

    let lang = match parser_lang {
        Some(l) => l,
        None => return ConditionResult::no_match(),
    };

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&lang.into()).is_err() {
        return ConditionResult::no_match();
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return ConditionResult::no_match(),
    };

    let matcher: Box<dyn Fn(&str) -> bool> = if use_regex {
        match build_regex(pattern, case_insensitive) {
            Ok(re) => Box::new(move |s: &str| re.is_match(s)),
            Err(_) => return ConditionResult::no_match(),
        }
    } else if case_insensitive {
        let pattern_lower = pattern.to_lowercase();
        Box::new(move |s: &str| s.to_lowercase().contains(&pattern_lower))
    } else {
        let pattern_owned = pattern.to_string();
        Box::new(move |s: &str| s.contains(&pattern_owned))
    };

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

fn walk_ast_for_pattern(
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    target_node_type: &str,
    matcher: &dyn Fn(&str) -> bool,
    evidence: &mut Vec<Evidence>,
) {
    loop {
        let node = cursor.node();

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
                        span: Some(SourceSpan::from_node(&node)),
                    });
                }
            }
        }

        if cursor.goto_first_child() {
            walk_ast_for_pattern(cursor, source, target_node_type, matcher, evidence);
            cursor.goto_parent();
        }

        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

pub fn eval_ast_query(query_str: &str, ctx: &EvaluationContext) -> ConditionResult {
    let source = match std::str::from_utf8(ctx.binary_data) {
        Ok(s) => s,
        Err(_) => return ConditionResult::no_match(),
    };

    let lang = match ctx.file_type {
        FileType::C => tree_sitter_c::LANGUAGE.into(),
        FileType::Python => tree_sitter_python::LANGUAGE.into(),
        FileType::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        FileType::Rust => tree_sitter_rust::LANGUAGE.into(),
        FileType::Go => tree_sitter_go::LANGUAGE.into(),
        FileType::Java => tree_sitter_java::LANGUAGE.into(),
        FileType::Ruby => tree_sitter_ruby::LANGUAGE.into(),
        FileType::Shell => tree_sitter_bash::LANGUAGE.into(),
        FileType::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
        _ => return ConditionResult::no_match(),
    };

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&lang).is_err() {
        return ConditionResult::no_match();
    }

    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return ConditionResult::no_match(),
    };

    let query = match tree_sitter::Query::new(&lang, query_str) {
        Ok(q) => q,
        Err(_) => return ConditionResult::no_match(),
    };

    let mut query_cursor = tree_sitter::QueryCursor::new();
    let mut evidence = Vec::new();

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
                    span: Some(SourceSpan::from_node(&capture.node)),
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

pub fn eval_yara_inline(source: &str, ctx: &EvaluationContext) -> ConditionResult {
    let mut compiler = yara_x::Compiler::new();
    compiler.new_namespace("inline");
    if compiler.add_source(source.as_bytes()).is_err() {
        return ConditionResult::no_match();
    }
    let rules = compiler.build();

    let mut scanner = yara_x::Scanner::new(&rules);
    let results = match scanner.scan(ctx.binary_data) {
        Ok(r) => r,
        Err(_) => return ConditionResult::no_match(),
    };

    let mut evidence = Vec::new();
    for matched_rule in results.matching_rules() {
        for pattern in matched_rule.patterns() {
            for m in pattern.matches() {
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
                    span: None, analysis_layer: None,
                    analysis_layer: None,
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

/// Parameters for function metrics condition evaluation
pub struct FunctionMetricsParams<'a> {
    pub cyclomatic_complexity: Option<&'a NumericRange>,
    pub basic_blocks: Option<&'a NumericRange>,
    pub loops: Option<&'a NumericRange>,
    pub instructions: Option<&'a NumericRange>,
    pub stack_frame: Option<&'a NumericRange>,
    pub is_recursive: Option<bool>,
    pub is_leaf: Option<bool>,
}

pub fn eval_function_metrics(
    params: &FunctionMetricsParams,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let mut evidence = Vec::new();

    for func in &ctx.report.functions {
        let mut matches = true;
        let mut match_reasons = Vec::new();

        if let Some(range) = params.cyclomatic_complexity {
            let complexity = func
                .control_flow
                .as_ref()
                .map(|cf| cf.cyclomatic_complexity)
                .or(func.complexity)
                .unwrap_or(0);
            if !range.matches(complexity) {
                matches = false;
            } else {
                match_reasons.push(format!("complexity={}", complexity));
            }
        }

        if let Some(range) = params.basic_blocks {
            let blocks = func
                .control_flow
                .as_ref()
                .map(|cf| cf.basic_blocks)
                .unwrap_or(0);
            if !range.matches(blocks) {
                matches = false;
            } else {
                match_reasons.push(format!("blocks={}", blocks));
            }
        }

        if let Some(range) = params.loops {
            let loop_count = func
                .control_flow
                .as_ref()
                .map(|cf| cf.loop_count)
                .unwrap_or(0);
            if !range.matches(loop_count) {
                matches = false;
            } else {
                match_reasons.push(format!("loops={}", loop_count));
            }
        }

        if let Some(range) = params.instructions {
            let inst_count = func
                .instruction_analysis
                .as_ref()
                .map(|ia| ia.total_instructions)
                .unwrap_or(0);
            if !range.matches(inst_count) {
                matches = false;
            } else {
                match_reasons.push(format!("instructions={}", inst_count));
            }
        }

        if let Some(range) = params.stack_frame {
            let frame_size = func.properties.as_ref().map(|p| p.stack_frame).unwrap_or(0);
            if !range.matches(frame_size) {
                matches = false;
            } else {
                match_reasons.push(format!("stack_frame={}", frame_size));
            }
        }

        if let Some(expected) = params.is_recursive {
            let actual = func.properties.as_ref().is_some_and(|p| p.is_recursive);
            if actual != expected {
                matches = false;
            } else if actual {
                match_reasons.push("recursive".to_string());
            }
        }

        if let Some(expected) = params.is_leaf {
            let actual = func.properties.as_ref().is_some_and(|p| p.is_leaf);
            if actual != expected {
                matches = false;
            } else if actual {
                match_reasons.push("leaf".to_string());
            }
        }

        if matches && !match_reasons.is_empty() {
            evidence.push(Evidence {
                method: "function_metrics".to_string(),
                source: "radare2".to_string(),
                value: format!("{}: {}", func.name, match_reasons.join(", ")),
                location: func.offset.clone(),
                span: None, analysis_layer: None,
                    analysis_layer: None,
            });
        }
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
    }
}

pub fn eval_entropy(
    section_pattern: Option<&String>,
    min: Option<f64>,
    max: Option<f64>,
    ctx: &EvaluationContext,
) -> ConditionResult {
    let mut evidence = Vec::new();

    let section_regex = section_pattern.and_then(|p| Regex::new(p).ok());

    for section in &ctx.report.sections {
        if let Some(ref re) = section_regex {
            if !re.is_match(&section.name) {
                continue;
            }
        }

        let mut matches = true;
        if let Some(min_val) = min {
            if section.entropy < min_val {
                matches = false;
            }
        }
        if let Some(max_val) = max {
            if section.entropy > max_val {
                matches = false;
            }
        }

        if matches {
            evidence.push(Evidence {
                method: "entropy".to_string(),
                source: "section_analysis".to_string(),
                value: format!("{}: entropy={:.2}", section.name, section.entropy),
                location: Some(section.name.clone()),
                span: None, analysis_layer: None,
                    analysis_layer: None,
            });
        }
    }

    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        traits: Vec::new(),
    }
}

/// Parameters for binary condition evaluation
pub struct BinaryParams<'a> {
    pub section_count: Option<&'a NumericRange>,
    pub segment_count: Option<&'a NumericRange>,
    pub file_entropy: Option<&'a FloatRange>,
    pub overlay_size: Option<&'a NumericRange>,
    pub machine_type: Option<&'a Vec<u16>>,
    pub is_big_endian: Option<bool>,
    pub has_rwx_segments: Option<bool>,
    pub is_64bit: Option<bool>,
    pub has_interpreter: Option<bool>,
}

pub fn eval_binary(params: &BinaryParams, ctx: &EvaluationContext) -> ConditionResult {
    let props = match &ctx.report.binary_properties {
        Some(p) => p,
        None => return ConditionResult::no_match(),
    };

    let header = match &props.header {
        Some(h) => h,
        None => return ConditionResult::no_match(),
    };

    let mut matches = true;
    let mut match_reasons = Vec::new();

    // Check section_count
    if let Some(range) = params.section_count {
        if !range.matches(header.section_count) {
            matches = false;
        } else {
            match_reasons.push(format!("section_count={}", header.section_count));
        }
    }

    // Check segment_count
    if let Some(range) = params.segment_count {
        if !range.matches(header.segment_count) {
            matches = false;
        } else {
            match_reasons.push(format!("segment_count={}", header.segment_count));
        }
    }

    // Check file_entropy
    if let Some(range) = params.file_entropy {
        if !range.matches(header.file_entropy) {
            matches = false;
        } else {
            match_reasons.push(format!("file_entropy={:.2}", header.file_entropy));
        }
    }

    // Check overlay_size
    if let Some(range) = params.overlay_size {
        let overlay_size = ctx
            .report
            .overlay_metrics
            .as_ref()
            .map(|o| o.size_bytes as u32)
            .unwrap_or(0);
        if !range.matches(overlay_size) {
            matches = false;
        } else if overlay_size > 0 {
            match_reasons.push(format!("overlay_size={}", overlay_size));
        }
    }

    // Check machine_type
    if let Some(types) = params.machine_type {
        if !types.contains(&(header.machine_type as u16)) {
            matches = false;
        } else {
            match_reasons.push(format!("machine_type={}", header.machine_type));
        }
    }

    // Check is_big_endian
    if let Some(expected) = params.is_big_endian {
        if header.is_big_endian != expected {
            matches = false;
        } else if header.is_big_endian {
            match_reasons.push("big_endian".to_string());
        }
    }

    // Check has_rwx_segments
    if let Some(expected) = params.has_rwx_segments {
        if header.has_rwx_segments != expected {
            matches = false;
        } else if header.has_rwx_segments {
            match_reasons.push("rwx_segments".to_string());
        }
    }

    // Check is_64bit
    if let Some(expected) = params.is_64bit {
        if header.is_64bit != expected {
            matches = false;
        } else {
            match_reasons.push(if header.is_64bit { "64bit" } else { "32bit" }.to_string());
        }
    }

    // Check has_interpreter
    if let Some(expected) = params.has_interpreter {
        if header.has_interpreter != expected {
            matches = false;
        } else if !header.has_interpreter {
            match_reasons.push("no_interpreter".to_string());
        }
    }

    if matches && !match_reasons.is_empty() {
        ConditionResult {
            matched: true,
            evidence: vec![Evidence {
                method: "binary".to_string(),
                source: "goblin".to_string(),
                value: match_reasons.join(", "),
                location: None,
                span: None, analysis_layer: None,
                    analysis_layer: None,
            }],
            traits: Vec::new(),
        }
    } else {
        ConditionResult::no_match()
    }
}

/// Parameters for syscall condition evaluation
pub struct SyscallParams<'a> {
    pub name: Option<&'a Vec<String>>,
    pub number: Option<&'a Vec<u32>>,
    pub arch: Option<&'a Vec<String>>,
    pub min_count: Option<usize>,
}

/// Evaluate syscall condition against detected syscalls
pub fn eval_syscall(params: &SyscallParams, ctx: &EvaluationContext) -> ConditionResult {
    let matching: Vec<_> = ctx
        .report
        .syscalls
        .iter()
        .filter(|sc| {
            // Match by name if specified
            if let Some(names) = params.name {
                if !names.iter().any(|n| sc.name == *n || sc.name.contains(n)) {
                    return false;
                }
            }
            // Match by number if specified
            if let Some(nums) = params.number {
                if !nums.contains(&sc.number) {
                    return false;
                }
            }
            // Match by architecture if specified
            if let Some(archs) = params.arch {
                if !archs.iter().any(|a| sc.arch == *a || sc.arch.contains(a)) {
                    return false;
                }
            }
            true
        })
        .collect();

    // Check min_count if specified
    if let Some(min) = params.min_count {
        if matching.len() < min {
            return ConditionResult::no_match();
        }
    }

    if matching.is_empty() {
        return ConditionResult::no_match();
    }

    // Build evidence from matching syscalls
    let evidence: Vec<Evidence> = matching
        .iter()
        .map(|sc| Evidence {
            method: "syscall".to_string(),
            source: "radare2".to_string(),
            value: format!("{}:{} ({})", sc.name, sc.number, sc.arch),
            location: Some(format!("{:#x}", sc.address)),
            span: None,
            analysis_layer: None,
        })
        .collect();

    ConditionResult {
        matched: true,
        evidence,
        traits: Vec::new(),
    }
}

/// Evaluate a condition based on its type
pub fn eval_condition(condition: &Condition, ctx: &EvaluationContext) -> ConditionResult {
    match condition {
        Condition::Symbol { pattern, platforms } => eval_symbol(pattern, platforms.as_ref(), ctx),
        Condition::String {
            exact,
            regex,
            case_insensitive,
            exclude_patterns,
            min_count,
            search_raw,
        } => {
            let params = StringParams {
                exact: exact.as_ref(),
                regex: regex.as_ref(),
                case_insensitive: *case_insensitive,
                exclude_patterns: exclude_patterns.as_ref(),
                min_count: *min_count,
                search_raw: *search_raw,
            };
            eval_string(&params, ctx)
        }
        Condition::YaraMatch { namespace, rule } => eval_yara_match(namespace, rule.as_ref(), ctx),
        Condition::Structure {
            feature,
            min_sections,
        } => eval_structure(feature, *min_sections, ctx),
        Condition::SymbolOrString { any } => eval_symbol_or_string(any, ctx),
        Condition::ImportsCount { min, max, filter } => {
            eval_imports_count(*min, *max, filter.as_ref(), ctx)
        }
        Condition::ExportsCount { min, max } => eval_exports_count(*min, *max, ctx),
        Condition::Trait { id } => eval_trait_ref(id, ctx),
        Condition::AstPattern {
            node_type,
            pattern,
            regex,
            case_insensitive,
        } => eval_ast_pattern(node_type, pattern, *regex, *case_insensitive, ctx),
        Condition::AstQuery { query } => eval_ast_query(query, ctx),
        Condition::Yara { source } => eval_yara_inline(source, ctx),
        Condition::FunctionMetrics {
            cyclomatic_complexity,
            basic_blocks,
            loops,
            instructions,
            stack_frame,
            is_recursive,
            is_leaf,
        } => {
            let params = FunctionMetricsParams {
                cyclomatic_complexity: cyclomatic_complexity.as_ref(),
                basic_blocks: basic_blocks.as_ref(),
                loops: loops.as_ref(),
                instructions: instructions.as_ref(),
                stack_frame: stack_frame.as_ref(),
                is_recursive: *is_recursive,
                is_leaf: *is_leaf,
            };
            eval_function_metrics(&params, ctx)
        }
        Condition::Entropy { section, min, max } => eval_entropy(section.as_ref(), *min, *max, ctx),
        Condition::Binary {
            section_count,
            segment_count,
            file_entropy,
            overlay_size,
            machine_type,
            is_big_endian,
            has_rwx_segments,
            is_64bit,
            has_interpreter,
        } => {
            let params = BinaryParams {
                section_count: section_count.as_ref(),
                segment_count: segment_count.as_ref(),
                file_entropy: file_entropy.as_ref(),
                overlay_size: overlay_size.as_ref(),
                machine_type: machine_type.as_ref(),
                is_big_endian: *is_big_endian,
                has_rwx_segments: *has_rwx_segments,
                is_64bit: *is_64bit,
                has_interpreter: *has_interpreter,
            };
            eval_binary(&params, ctx)
        }
        Condition::Syscall {
            name,
            number,
            arch,
            min_count,
        } => {
            let params = SyscallParams {
                name: name.as_ref(),
                number: number.as_ref(),
                arch: arch.as_ref(),
                min_count: *min_count,
            };
            eval_syscall(&params, ctx)
        }
    }
}

/// Evaluate a trait reference condition
fn eval_trait_ref(trait_id: &str, ctx: &EvaluationContext) -> ConditionResult {
    for finding in &ctx.report.findings {
        let matches = finding.id == trait_id
            || finding.id.ends_with(&format!("/{}", trait_id))
            || finding
                .trait_refs
                .iter()
                .any(|t| t == trait_id || t.ends_with(&format!("/{}", trait_id)));

        if matches {
            return ConditionResult {
                matched: true,
                evidence: finding.evidence.clone(),
                traits: vec![finding.id.clone()],
            };
        }
    }

    ConditionResult::no_match()
}
