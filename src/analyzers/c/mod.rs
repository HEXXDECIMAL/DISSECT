//! C source code analyzer using tree-sitter.
//!
//! This module provides comprehensive analysis of C source files, including:
//! - Capability detection (system calls, unsafe functions, kernel operations)
//! - Pattern analysis (rootkit indicators, privilege escalation, anti-forensics)
//! - Function extraction and metrics computation
//! - YAML trait evaluation and composite rule matching
//!
//! The analyzer is optimized for detecting malicious patterns in C code, particularly
//! kernel modules and rootkits, while maintaining support for standard C analysis.

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
#[cfg(test)]
mod tests;

use capabilities::detect_capabilities;
use functions::extract_functions;

/// C analyzer using tree-sitter for parsing and pattern detection.
///
/// The analyzer maintains a tree-sitter parser and optional capability mapper
/// for trait evaluation. It uses iterative AST traversal to avoid stack overflow
/// on deeply nested code structures.
pub struct CAnalyzer {
    parser: RefCell<Parser>,
    capability_mapper: CapabilityMapper,
}

impl Default for CAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl CAnalyzer {
    /// Create a new C analyzer with default configuration.
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .unwrap();

        Self {
            parser: RefCell::new(parser),
            capability_mapper: CapabilityMapper::empty(),
        }
    }

    /// Create analyzer with pre-existing capability mapper (avoids duplicate loading).
    pub fn with_capability_mapper(mut self, capability_mapper: CapabilityMapper) -> Self {
        self.capability_mapper = capability_mapper;
        self
    }

    /// Analyze C source code and generate a comprehensive report.
    ///
    /// This performs:
    /// 1. Source parsing via tree-sitter
    /// 2. Capability detection through AST walking
    /// 3. Function extraction
    /// 4. Symbol extraction for rule matching
    /// 5. Metrics computation
    /// 6. YAML trait evaluation
    /// 7. Composite rule evaluation
    fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the C source
        let tree = self
            .parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse C source")?;

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "c".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "source/language/c".to_string(),
            desc: "C source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-c".to_string(),
                value: "c".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        // Detect capabilities and patterns
        detect_capabilities(self, &root, content.as_bytes(), &mut report);

        // Extract functions
        extract_functions(self, &root, content.as_bytes(), &mut report);

        // Extract function calls as symbols for symbol-based rule matching
        symbol_extraction::extract_symbols(
            content,
            tree_sitter_c::LANGUAGE.into(),
            &["call_expression"],
            &mut report,
        );

        // Compute metrics for ML analysis (BEFORE trait evaluation)
        let metrics = self.compute_metrics(&root, content);
        report.metrics = Some(metrics);

        // Evaluate YAML trait definitions first
        let trait_findings = self
            .capability_mapper
            .evaluate_traits(&report, content.as_bytes());

        // Add trait findings to report immediately so composite rules can see them
        for f in trait_findings {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }

        // Now evaluate composite rules (which can reference the traits above)
        let composite_findings = self
            .capability_mapper
            .evaluate_composite_rules(&report, content.as_bytes());

        // Add composite findings
        for f in composite_findings {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-c".to_string()];

        Ok(report)
    }

    /// Compute comprehensive metrics for the analyzed source.
    ///
    /// Metrics include:
    /// - Text statistics (lines, entropy, etc.)
    /// - Identifier analysis (naming patterns, uniqueness)
    /// - String literal analysis
    /// - Comment analysis
    /// - Function metrics (complexity, nesting, etc.)
    fn compute_metrics(&self, root: &tree_sitter::Node, content: &str) -> Metrics {
        let source = content.as_bytes();
        let total_lines = content.lines().count() as u32;

        let text = text_metrics::analyze_text(content);

        let identifiers = self.extract_identifiers(root, source);
        let ident_refs: Vec<&str> = identifiers.iter().map(|s| s.as_str()).collect();
        let identifier_metrics = identifier_metrics::analyze_identifiers(&ident_refs);

        let strings = self.extract_string_literals(root, source);
        let str_refs: Vec<&str> = strings.iter().map(|s| s.as_str()).collect();
        let string_metrics = string_metrics::analyze_strings(&str_refs);

        let comment_metrics = comment_metrics::analyze_comments(content, CommentStyle::CStyle);

        let func_infos = self.extract_function_info(root, source);
        let func_metrics = function_metrics::analyze_functions(&func_infos, total_lines);

        Metrics {
            text: Some(text),
            identifiers: Some(identifier_metrics),
            strings: Some(string_metrics),
            comments: Some(comment_metrics),
            functions: Some(func_metrics),
            ..Default::default()
        }
    }

    /// Extract all identifiers from the AST.
    pub(crate) fn extract_identifiers(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
    ) -> Vec<String> {
        let mut identifiers = Vec::new();
        let mut cursor = root.walk();
        self.walk_for_identifiers(&mut cursor, source, &mut identifiers);
        identifiers
    }

    /// Iteratively walk AST to collect identifiers (avoids stack overflow).
    fn walk_for_identifiers(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        identifiers: &mut Vec<String>,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();
            if node.kind() == "identifier" || node.kind() == "field_identifier" {
                if let Ok(text) = node.utf8_text(source) {
                    if !text.is_empty() {
                        identifiers.push(text.to_string());
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
        }
    }

    /// Extract all string literals from the AST.
    pub(crate) fn extract_string_literals(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
    ) -> Vec<String> {
        let mut strings = Vec::new();
        let mut cursor = root.walk();
        self.walk_for_strings(&mut cursor, source, &mut strings);
        strings
    }

    /// Iteratively walk AST to collect string literals (avoids stack overflow).
    fn walk_for_strings(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        strings: &mut Vec<String>,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();
            if node.kind() == "string_literal" {
                if let Ok(text) = node.utf8_text(source) {
                    let s = text.trim_start_matches('"').trim_end_matches('"');
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
        }
    }

    /// Extract function metadata for metrics computation.
    pub(crate) fn extract_function_info(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
    ) -> Vec<FunctionInfo> {
        let mut functions = Vec::new();
        let mut cursor = root.walk();
        self.walk_for_function_info(&mut cursor, source, &mut functions, 0);
        functions
    }

    /// Iteratively walk AST to collect function information (avoids stack overflow).
    fn walk_for_function_info(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        functions: &mut Vec<FunctionInfo>,
        mut depth: u32,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();
            let kind = node.kind();

            if kind == "function_definition" {
                let mut info = FunctionInfo::default();
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    // Find the function name within the declarator
                    let mut decl_cursor = declarator.walk();
                    self.find_function_name(&mut decl_cursor, source, &mut info);
                }
                info.start_line = node.start_position().row as u32;
                info.end_line = node.end_position().row as u32;
                info.line_count = info.end_line.saturating_sub(info.start_line) + 1;
                info.nesting_depth = depth;
                functions.push(info);
            }

            if cursor.goto_first_child() {
                if kind == "function_definition" {
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
                // Track depth when going back up through function definitions
                if cursor.node().kind() == "function_definition" {
                    depth = depth.saturating_sub(1);
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Helper to find function name within a declarator node.
    fn find_function_name(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        info: &mut FunctionInfo,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();
            if node.kind() == "identifier" {
                if let Ok(name) = node.utf8_text(source) {
                    info.name = name.to_string();
                    return;
                }
            }
            if node.kind() == "parameter_list" {
                // Count parameters
                let mut param_cursor = node.walk();
                if param_cursor.goto_first_child() {
                    loop {
                        let param = param_cursor.node();
                        if param.kind() == "parameter_declaration" {
                            info.param_count += 1;
                        }
                        if !param_cursor.goto_next_sibling() {
                            break;
                        }
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
        }
    }

    /// Calculate SHA256 hash of the given data.
    fn calculate_sha256(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

impl Analyzer for CAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let bytes = fs::read(file_path).context("Failed to read C file")?;
        let content = String::from_utf8_lossy(&bytes);
        self.analyze_source(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path.extension().and_then(|e| e.to_str()) == Some("c")
    }
}
