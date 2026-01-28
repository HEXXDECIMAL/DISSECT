//! JavaScript/Node.js analyzer using tree-sitter
//!
//! This module provides comprehensive static analysis of JavaScript files, including:
//! - Capability detection (file system, network, process execution)
//! - Obfuscation detection (base64, eval, string manipulation)
//! - Function extraction and complexity analysis
//! - Metrics computation for ML-based analysis
//! - Supply chain attack pattern detection
//!
//! The analyzer uses tree-sitter for robust AST parsing with panic handling
//! to safely analyze potentially hostile code.

use crate::analyzers::Analyzer;
use crate::analyzers::{
    comment_metrics::{self, CommentStyle},
    function_metrics::{self, FunctionInfo},
    identifier_metrics, string_metrics, symbol_extraction, text_metrics,
};
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

mod capabilities;
mod functions;
mod patterns;
mod tests;

use capabilities::{check_global_obfuscation, check_npm_malware_patterns, check_supply_chain_patterns, detect_capabilities};
use functions::{detect_javascript_idioms, extract_functions};

/// JavaScript/Node.js analyzer using tree-sitter
pub struct JavaScriptAnalyzer {
    parser: RefCell<Parser>,
    capability_mapper: CapabilityMapper,
}

impl JavaScriptAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();

        Self {
            parser: RefCell::new(parser),
            capability_mapper: CapabilityMapper::empty(),
        }
    }

    /// Create analyzer with pre-existing capability mapper (avoids duplicate loading)
    pub fn with_capability_mapper(mut self, capability_mapper: CapabilityMapper) -> Self {
        self.capability_mapper = capability_mapper;
        self
    }

    fn analyze_script(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        use tracing::{debug, error, trace, warn};

        let start = std::time::Instant::now();
        let timing_enabled = std::env::var("DISSECT_PROFILE").is_ok();

        if timing_enabled {
            eprintln!(
                "[PROFILE] JS analyze_script start: {} ({} KB)",
                file_path.display(),
                content.len() / 1024
            );
        }

        debug!(
            "Parsing JavaScript file: {:?} ({} bytes)",
            file_path,
            content.len()
        );

        // Parse the JavaScript with panic catching (malware may crash tree-sitter)
        let parse_start = std::time::Instant::now();
        let parse_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.parser.borrow_mut().parse(content, None)
        }));

        let parse_duration = parse_start.elapsed();
        let parse_millis = parse_duration.as_millis();

        if timing_enabled {
            eprintln!(
                "[PROFILE]   AST parse: {}ms",
                parse_millis
            );
        }

        // Flag files that take abnormally long to parse (likely minified/obfuscated)
        let slow_parse_threshold_ms = 10_000; // 10 seconds
        let suspicious_parse = parse_millis > slow_parse_threshold_ms;

        let tree = match parse_result {
            Ok(Some(tree)) => {
                trace!(
                    "JavaScript parsed successfully, {} nodes",
                    tree.root_node().child_count()
                );
                tree
            }
            Ok(None) => {
                warn!("JavaScript parse returned None for {:?}", file_path);
                anyhow::bail!("Failed to parse JavaScript (parse returned None)");
            }
            Err(_panic_info) => {
                // Tree-sitter crashed - this is HOSTILE anti-analysis behavior
                error!("⚠️  tree-sitter-javascript CRASHED while parsing {:?} (HOSTILE anti-analysis detected)", file_path);
                eprintln!("⚠️  WARNING: tree-sitter-javascript crashed while parsing {:?} (HOSTILE anti-analysis detected)", file_path);

                let target = TargetInfo {
                    path: file_path.display().to_string(),
                    file_type: "javascript".to_string(),
                    size_bytes: content.len() as u64,
                    sha256: crate::analyzers::utils::calculate_sha256(content.as_bytes()),
                    architectures: None,
                };

                let mut report = AnalysisReport::new(target);
                report.findings.push(Finding {
                    id: "anti-analysis/parser-crash/treesitter-crash".to_string(),
                    kind: FindingKind::Indicator,
                    desc: "Code that crashes tree-sitter parser (anti-analysis)".to_string(),
                    conf: 0.95,
                    crit: Criticality::Hostile,
                    mbc: Some("B0001".to_string()),
                    attack: None,
                    trait_refs: Vec::new(),
                    evidence: vec![Evidence {
                        method: "panic_detection".to_string(),
                        source: "tree-sitter-javascript".to_string(),
                        value: "parser_crash".to_string(),
                        location: Some("parse".to_string()),
                    }],
                });

                report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
                report.metadata.tools_used = vec!["tree-sitter-javascript".to_string()];

                return Ok(report);
            }
        };

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "javascript".to_string(),
            size_bytes: content.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(crate::analyzers::utils::create_language_feature(
            "javascript",
            "tree-sitter-javascript",
            "JavaScript source code",
        ));

        // Detect capabilities and obfuscation
        let t = std::time::Instant::now();
        detect_capabilities(self, &root, content.as_bytes(), &mut report);
        if timing_enabled {
            eprintln!(
                "[PROFILE]   detect_capabilities: {}ms",
                t.elapsed().as_millis()
            );
        }

        // Check for cross-statement obfuscation patterns
        let t = std::time::Instant::now();
        check_global_obfuscation(self, content, &mut report);
        if timing_enabled {
            eprintln!(
                "[PROFILE]   check_global_obfuscation: {}ms",
                t.elapsed().as_millis()
            );
        }

        // Check for supply chain attack patterns
        let t = std::time::Instant::now();
        check_supply_chain_patterns(self, content, &mut report);
        if timing_enabled {
            eprintln!(
                "[PROFILE]   check_supply_chain_patterns: {}ms",
                t.elapsed().as_millis()
            );
        }

        // Check for npm malware patterns (obfuscator signatures, C2, etc.)
        let t = std::time::Instant::now();
        check_npm_malware_patterns(self, content, &mut report);
        if timing_enabled {
            eprintln!(
                "[PROFILE]   check_npm_malware_patterns: {}ms",
                t.elapsed().as_millis()
            );
        }

        // Extract functions
        let t = std::time::Instant::now();
        extract_functions(self, &root, content.as_bytes(), &mut report);
        if timing_enabled {
            eprintln!(
                "[PROFILE]   extract_functions: {}ms",
                t.elapsed().as_millis()
            );
        }

        // Extract function calls as symbols for symbol-based rule matching
        let t = std::time::Instant::now();
        symbol_extraction::extract_symbols(
            content,
            tree_sitter_javascript::LANGUAGE.into(),
            &["call_expression"],
            &mut report,
        );
        if timing_enabled {
            eprintln!(
                "[PROFILE]   symbol_extraction: {}ms",
                t.elapsed().as_millis()
            );
        }

        // Detect JavaScript idioms
        let t = std::time::Instant::now();
        let javascript_idioms = detect_javascript_idioms(&root, content.as_bytes());
        if timing_enabled {
            eprintln!(
                "[PROFILE]   detect_javascript_idioms: {}ms",
                t.elapsed().as_millis()
            );
        }

        // Add idioms to source code metrics if they exist
        if let Some(ref mut metrics) = report.source_code_metrics {
            metrics.javascript_idioms = Some(javascript_idioms);
        }

        // === Compute metrics for ML analysis (BEFORE trait evaluation) ===
        let t = std::time::Instant::now();
        let metrics = self.compute_metrics(&root, content);
        report.metrics = Some(metrics);
        if timing_enabled {
            eprintln!("[PROFILE]   compute_metrics: {}ms", t.elapsed().as_millis());
        }

        // Extract decoded strings (base64) for querying in traits
        let t = std::time::Instant::now();
        report.decoded_strings = extract_base64_strings(content.as_bytes());
        if timing_enabled {
            eprintln!("[PROFILE]   extract_base64: {}ms ({} decoded strings)",
                     t.elapsed().as_millis(), report.decoded_strings.len());
        }

        // Evaluate trait definitions and composite rules (with cached AST to avoid re-parsing)
        let t = std::time::Instant::now();
        let trait_findings = self
            .capability_mapper
            .evaluate_traits_with_ast(&report, content.as_bytes(), Some(&tree));
        if timing_enabled {
            eprintln!("[PROFILE]   evaluate_traits: {}ms", t.elapsed().as_millis());
        }

        // Add atomic traits first so composite rules can reference them
        for f in trait_findings {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }

        let composite_findings = self
            .capability_mapper
            .evaluate_composite_rules(&report, content.as_bytes());

        // Add all findings
        for f in composite_findings {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }

        // Add finding if parse took abnormally long (indicates obfuscation/minification)
        if suspicious_parse {
            warn!(
                "⚠️  AST parsing took {}ms (threshold: {}ms) - likely minified/obfuscated code",
                parse_millis, slow_parse_threshold_ms
            );
            report.findings.push(Finding {
                id: "anti-static/obfuscation/slow-ast-parse".to_string(),
                kind: FindingKind::Indicator,
                desc: format!(
                    "AST parsing took abnormally long ({}s), indicates heavily minified or obfuscated code",
                    parse_millis / 1000
                ),
                conf: 0.90,
                crit: Criticality::Suspicious,
                mbc: Some("E1027".to_string()), // Obfuscated Files or Information
                attack: Some("T1027".to_string()), // Obfuscated Files or Information
                trait_refs: Vec::new(),
                evidence: vec![Evidence {
                    method: "timing_analysis".to_string(),
                    source: "tree-sitter-javascript".to_string(),
                    value: format!("parse_duration_ms={}", parse_millis),
                    location: Some("ast_parse".to_string()),
                }],
            });
        }

        if timing_enabled {
            eprintln!(
                "[PROFILE] JS analyze_script complete: {}ms total\n",
                start.elapsed().as_millis()
            );
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-javascript".to_string()];

        Ok(report)
    }

    /// Compute all metrics for JavaScript code
    fn compute_metrics(&self, root: &tree_sitter::Node, content: &str) -> Metrics {
        let source = content.as_bytes();
        let total_lines = content.lines().count() as u32;

        // Universal text metrics
        let text = text_metrics::analyze_text(content);

        // Extract identifiers from AST
        let identifiers = self.extract_identifiers(root, source);
        let ident_refs: Vec<&str> = identifiers.iter().map(|s| s.as_str()).collect();
        let identifier_metrics = identifier_metrics::analyze_identifiers(&ident_refs);

        // Extract strings from AST
        let strings = self.extract_string_literals(root, source);
        let str_refs: Vec<&str> = strings.iter().map(|s| s.as_str()).collect();
        let string_metrics = string_metrics::analyze_strings(&str_refs);

        // Comment metrics (C-style comments for JS)
        let comment_metrics = comment_metrics::analyze_comments(content, CommentStyle::CStyle);

        // Function metrics
        let func_infos = self.extract_function_info(root, source);
        let func_metrics = function_metrics::analyze_functions(&func_infos, total_lines);

        // JavaScript-specific metrics
        let js_metrics = self.compute_javascript_metrics(root, source, content);

        Metrics {
            text: Some(text),
            identifiers: Some(identifier_metrics),
            strings: Some(string_metrics),
            comments: Some(comment_metrics),
            functions: Some(func_metrics),
            javascript: Some(js_metrics),
            ..Default::default()
        }
    }

    /// Extract function information from the AST for metrics
    fn extract_function_info(&self, root: &tree_sitter::Node, source: &[u8]) -> Vec<FunctionInfo> {
        let mut functions = Vec::new();
        let mut cursor = root.walk();
        self.walk_for_function_info(&mut cursor, source, &mut functions, 0);
        functions
    }

    fn walk_for_function_info(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        functions: &mut Vec<FunctionInfo>,
        initial_depth: u32,
    ) {
        // Iterative traversal with manual depth tracking to avoid stack overflow
        let mut depth = initial_depth;

        loop {
            let node = cursor.node();
            let kind = node.kind();

            // Function declarations and expressions
            if kind == "function_declaration"
                || kind == "function_expression"
                || kind == "method_definition"
                || kind == "arrow_function"
                || kind == "generator_function"
                || kind == "generator_function_declaration"
            {
                let mut info = FunctionInfo::default();

                // Get function name
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(source) {
                        info.name = name.to_string();
                    }
                }

                // Arrow functions and function expressions are anonymous if no name
                if (kind == "arrow_function" || kind == "function_expression")
                    && info.name.is_empty()
                {
                    info.is_anonymous = true;
                }

                // Check for async
                if let Ok(text) = node.utf8_text(source) {
                    if text.starts_with("async ") {
                        info.is_async = true;
                    }
                }

                // Check for generator
                if kind.contains("generator") {
                    info.is_generator = true;
                }

                // Get parameters
                if let Some(params_node) = node.child_by_field_name("parameters") {
                    let mut param_cursor = params_node.walk();
                    if param_cursor.goto_first_child() {
                        loop {
                            let param = param_cursor.node();
                            let param_kind = param.kind();
                            if param_kind == "identifier" {
                                if let Ok(param_name) = param.utf8_text(source) {
                                    info.param_names.push(param_name.to_string());
                                    info.param_count += 1;
                                }
                            } else if param_kind == "assignment_pattern"
                                || param_kind == "rest_pattern"
                            {
                                // Get left side of default parameter
                                if let Some(left) = param.child_by_field_name("left") {
                                    if let Ok(name) = left.utf8_text(source) {
                                        info.param_names.push(name.to_string());
                                        info.param_count += 1;
                                    }
                                } else if let Ok(text) = param.utf8_text(source) {
                                    let name = text.trim_start_matches("...");
                                    if let Some(name) = name.split('=').next() {
                                        let name = name.trim();
                                        if !name.is_empty() {
                                            info.param_names.push(name.to_string());
                                            info.param_count += 1;
                                        }
                                    }
                                }
                            }
                            if !param_cursor.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }

                // Line count
                info.start_line = node.start_position().row as u32;
                info.end_line = node.end_position().row as u32;
                info.line_count = info.end_line.saturating_sub(info.start_line) + 1;
                info.nesting_depth = depth;

                // Check for nested functions
                if let Some(body) = node.child_by_field_name("body") {
                    let body_text = body.utf8_text(source).unwrap_or("");
                    if body_text.contains("function ")
                        || body_text.contains("function(")
                        || body_text.contains("=>")
                    {
                        info.contains_nested_functions = true;
                    }
                }

                functions.push(info);
            }

            // Track depth increase when entering function bodies
            let is_function_node = kind == "function_declaration"
                || kind == "function_expression"
                || kind == "arrow_function"
                || kind == "method_definition";

            // Iterative tree traversal with depth tracking
            if cursor.goto_first_child() {
                if is_function_node {
                    depth += 1;
                }
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                // Check if we're leaving a function node to decrement depth
                let parent_kind = cursor.node().kind();
                if parent_kind == "function_declaration"
                    || parent_kind == "function_expression"
                    || parent_kind == "arrow_function"
                    || parent_kind == "method_definition"
                {
                    depth = depth.saturating_sub(1);
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Extract all identifiers from the AST
    fn extract_identifiers(&self, root: &tree_sitter::Node, source: &[u8]) -> Vec<String> {
        let mut identifiers = Vec::new();
        let mut cursor = root.walk();
        self.walk_for_identifiers(&mut cursor, source, &mut identifiers);
        identifiers
    }

    fn walk_for_identifiers(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        identifiers: &mut Vec<String>,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            if node.kind() == "identifier" || node.kind() == "property_identifier" {
                if let Ok(text) = node.utf8_text(source) {
                    identifiers.push(text.to_string());
                }
            }

            if cursor.goto_first_child() {
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Extract all string literals from the AST
    fn extract_string_literals(&self, root: &tree_sitter::Node, source: &[u8]) -> Vec<String> {
        let mut strings = Vec::new();
        let mut cursor = root.walk();
        self.walk_for_strings(&mut cursor, source, &mut strings);
        strings
    }

    fn walk_for_strings(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        strings: &mut Vec<String>,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            if node.kind() == "string" || node.kind() == "template_string" {
                if let Ok(text) = node.utf8_text(source) {
                    // Strip quotes if present
                    let s = text.trim_matches(|c| c == '"' || c == '\'' || c == '`');
                    if !s.is_empty() {
                        strings.push(s.to_string());
                    }
                }
            }

            if cursor.goto_first_child() {
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    /// Compute JavaScript-specific metrics
    fn compute_javascript_metrics(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
        content: &str,
    ) -> JavaScriptMetrics {
        let mut metrics = JavaScriptMetrics::default();
        let mut cursor = root.walk();
        self.walk_for_js_metrics(&mut cursor, source, &mut metrics);

        // Additional pattern-based detection
        metrics.eval_count += content.matches("eval(").count() as u32;
        if content.contains("new Function(") {
            metrics.function_constructor += 1;
        }

        metrics
    }

    fn walk_for_js_metrics(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        metrics: &mut JavaScriptMetrics,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            match node.kind() {
                "call_expression" => {
                    if let Ok(text) = node.utf8_text(source) {
                        // Dynamic execution
                        if text.starts_with("eval(") {
                            metrics.eval_count += 1;
                        }
                        if text.contains("setTimeout") && text.contains("\"") {
                            metrics.settimeout_string += 1;
                        }
                        if text.contains("setInterval") && text.contains("\"") {
                            metrics.setinterval_string += 1;
                        }
                        if text.contains("document.write") {
                            metrics.document_write += 1;
                        }
                        if text.contains("innerHTML") {
                            metrics.innerhtml_writes += 1;
                        }
                        if text.contains("fromCharCode") {
                            metrics.from_char_code_count += 1;
                        }
                        if text.contains("charCodeAt") {
                            metrics.char_code_at_count += 1;
                        }
                        if text.contains("atob(") || text.contains("btoa(") {
                            metrics.atob_btoa_count += 1;
                        }
                        if text.contains("decodeURIComponent") {
                            metrics.decode_uri_component += 1;
                        }
                        if text.contains(".join(") {
                            metrics.array_join_strings += 1;
                        }
                    }
                }
                "arrow_function" => {
                    metrics.arrow_function_count += 1;
                }
                "function_declaration" | "function_expression" => {
                    // Count functions
                }
                "new_expression" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("new Function(") {
                            metrics.function_constructor += 1;
                        }
                    }
                }
                "class_declaration" | "class_expression" => {
                    // Class counted for structural analysis
                }
                "debugger_statement" => {
                    metrics.debugger_statements += 1;
                }
                "with_statement" => {
                    metrics.with_statement += 1;
                }
                _ => {}
            }

            // Iterative tree traversal
            if cursor.goto_first_child() {
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
}

impl Default for JavaScriptAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for JavaScriptAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let bytes = fs::read(file_path).context("Failed to read JavaScript file")?;
        let content = String::from_utf8_lossy(&bytes);

        self.analyze_script(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            matches!(ext.to_str(), Some("js") | Some("mjs") | Some("cjs"))
        } else {
            false
        }
    }
}

/// Extract base64-decoded strings for trait querying
fn extract_base64_strings(data: &[u8]) -> Vec<DecodedString> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    let mut results = Vec::new();
    let text = String::from_utf8_lossy(data);

    // Find base64-like sequences (20+ alphanumeric/+/= chars)
    if let Ok(pattern) = regex::Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}") {
        for mat in pattern.find_iter(&text) {
            let encoded = mat.as_str();
            if let Ok(decoded_bytes) = STANDARD.decode(encoded) {
                if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                    if decoded_str.len() < 10 {
                        continue;
                    }
                    let printable_ratio = decoded_str.chars()
                        .filter(|c| c.is_ascii() && !c.is_control())
                        .count() as f32 / decoded_str.len() as f32;

                    if printable_ratio > 0.7 {
                        let encoded_preview = if encoded.len() > 100 {
                            format!("{}...", &encoded[..100])
                        } else {
                            encoded.to_string()
                        };
                        results.push(DecodedString {
                            value: decoded_str,
                            encoded: encoded_preview,
                            method: "base64".to_string(),
                            key: None,
                            offset: Some(format!("0x{:x}", mat.start())),
                        });
                    }
                }
            }
        }
    }
    results
}
