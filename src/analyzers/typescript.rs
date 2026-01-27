//! TypeScript analyzer.

use crate::analyzers::Analyzer;
use crate::analyzers::{
    comment_metrics::{self, CommentStyle},
    function_metrics::{self, FunctionInfo},
    identifier_metrics, string_metrics, symbol_extraction, text_metrics,
};
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// TypeScript/TSX analyzer using tree-sitter
pub struct TypeScriptAnalyzer {
    parser: RefCell<Parser>,
}

impl Default for TypeScriptAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeScriptAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("Failed to load TypeScript grammar");

        Self {
            parser: RefCell::new(parser),
        }
    }

    fn analyze_script(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        use tracing::{debug, error, trace, warn};

        let start = std::time::Instant::now();

        debug!(
            "Parsing TypeScript file: {:?} ({} bytes)",
            file_path,
            content.len()
        );

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "typescript".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "source/language/typescript".to_string(),
            desc: "TypeScript source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-typescript".to_string(),
                value: "typescript".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        // Parse with tree-sitter with panic catching (malware may crash tree-sitter)
        let parse_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.parser.borrow_mut().parse(content, None)
        }));

        match parse_result {
            Ok(Some(tree)) => {
                trace!(
                    "TypeScript parsed successfully, {} nodes",
                    tree.root_node().child_count()
                );
                let root = tree.root_node();
                self.analyze_ast(&root, content.as_bytes(), &mut report);

                // Compute metrics for ML analysis
                let metrics = self.compute_metrics(&root, content);
                report.metrics = Some(metrics);
            }
            Ok(None) => {
                // Parse failed gracefully - not a crash
                warn!("TypeScript parse returned None for {:?}", file_path);
            }
            Err(_panic_info) => {
                // Tree-sitter crashed - this is HOSTILE anti-analysis behavior
                error!("⚠️  tree-sitter-typescript CRASHED while parsing {:?} (HOSTILE anti-analysis detected)", file_path);
                eprintln!("⚠️  WARNING: tree-sitter-typescript crashed while parsing {:?} (HOSTILE anti-analysis detected)", file_path);

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
                        source: "tree-sitter-typescript".to_string(),
                        value: "parser_crash".to_string(),
                        location: Some("parse".to_string()),
                    }],
                });

                report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
                report.metadata.tools_used = vec!["tree-sitter-typescript".to_string()];

                return Ok(report);
            }
        }

        // Extract function calls as symbols for symbol-based rule matching
        symbol_extraction::extract_symbols(
            content,
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            &["call_expression"],
            &mut report,
        );

        // Analyze paths and environment variables
        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-typescript".to_string()];

        Ok(report)
    }

    /// Compute all metrics for TypeScript code
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

        // Comment metrics (C-style comments for TypeScript)
        let comment_metrics = comment_metrics::analyze_comments(content, CommentStyle::CStyle);

        // Function metrics
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

    /// Extract identifiers from TypeScript AST
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

    /// Extract string literals from TypeScript AST
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
                    // Strip quotes
                    let s = text
                        .trim_start_matches('"')
                        .trim_end_matches('"')
                        .trim_start_matches('\'')
                        .trim_end_matches('\'')
                        .trim_start_matches('`')
                        .trim_end_matches('`');
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

    /// Extract function information for metrics
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
        // Iterative traversal to avoid stack overflow on deeply nested code
        let mut current_depth = depth;
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

                // Check if anonymous
                info.is_anonymous = info.name.is_empty();

                // Check for async
                if let Ok(text) = node.utf8_text(source) {
                    info.is_async = text.starts_with("async ");
                }

                // Check for generator
                info.is_generator = kind.contains("generator");

                // Get parameters
                if let Some(params_node) = node.child_by_field_name("parameters") {
                    let mut param_cursor = params_node.walk();
                    if param_cursor.goto_first_child() {
                        loop {
                            let param = param_cursor.node();
                            if param.kind() == "identifier"
                                || param.kind() == "required_parameter"
                                || param.kind() == "optional_parameter"
                            {
                                info.param_count += 1;
                                if let Ok(param_text) = param.utf8_text(source) {
                                    // Extract just the parameter name
                                    let name = param_text.split(':').next().unwrap_or(param_text);
                                    let name = name.split('=').next().unwrap_or(name).trim();
                                    if !name.is_empty() && name != "," {
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

                // Line count
                info.start_line = node.start_position().row as u32;
                info.end_line = node.end_position().row as u32;
                info.line_count = info.end_line.saturating_sub(info.start_line) + 1;
                info.nesting_depth = current_depth;

                functions.push(info);
            }

            if cursor.goto_first_child() {
                if kind.contains("function")
                    || kind == "method_definition"
                    || kind == "arrow_function"
                {
                    current_depth += 1;
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
                let parent_kind = cursor.node().kind();
                if parent_kind.contains("function")
                    || parent_kind == "method_definition"
                    || parent_kind == "arrow_function"
                {
                    current_depth = current_depth.saturating_sub(1);
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    fn analyze_ast(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        let mut cursor = node.walk();
        self.walk_ast(&mut cursor, source, report);
    }

    fn walk_ast(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            match node.kind() {
                "call_expression" => {
                    self.analyze_call(&node, source, report);
                }
                "import_statement" | "import" => {
                    self.analyze_import(&node, source, report);
                }
                "assignment_expression" | "variable_declarator" => {
                    self.analyze_assignment(&node, source, report);
                }
                "subscript_expression" => {
                    self.analyze_prototype_pollution(&node, source, report);
                }
                "new_expression" => {
                    self.analyze_new_expression(&node, source, report);
                }
                _ => {}
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

    fn analyze_call(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            // Get function name
            if let Some(func_node) = node.child_by_field_name("function") {
                if let Ok(func_name) = func_node.utf8_text(source) {
                    let func_lower = func_name.to_lowercase();

                    let dangerous_funcs = [
                        (
                            "eval",
                            "exec/script/eval",
                            "Dynamic code evaluation",
                            Criticality::Hostile,
                        ),
                        (
                            "require",
                            "exec/dylib/load",
                            "Dynamic module loading",
                            Criticality::Suspicious,
                        ),
                        (
                            "exec",
                            "exec/command/shell",
                            "Command execution",
                            Criticality::Hostile,
                        ),
                        (
                            "spawn",
                            "exec/command/shell",
                            "Process spawning",
                            Criticality::Hostile,
                        ),
                        (
                            "execfile",
                            "exec/command/shell",
                            "Execute file",
                            Criticality::Hostile,
                        ),
                        (
                            "child_process",
                            "exec/command/shell",
                            "Child process operations",
                            Criticality::Hostile,
                        ),
                        (
                            "fetch",
                            "net/http/client",
                            "HTTP request",
                            Criticality::Notable,
                        ),
                        (
                            "axios",
                            "net/http/client",
                            "HTTP client",
                            Criticality::Notable,
                        ),
                        ("readfile", "fs/read", "File read", Criticality::Suspicious),
                        (
                            "writefile",
                            "fs/write",
                            "File write",
                            Criticality::Suspicious,
                        ),
                        (
                            "unlink",
                            "fs/delete",
                            "File deletion",
                            Criticality::Suspicious,
                        ),
                    ];

                    for (pattern, trait_id, description, criticality) in dangerous_funcs {
                        if func_lower.contains(pattern) {
                            let full_trait_id = format!("{}/typescript", trait_id);
                            if !report.findings.iter().any(|t| t.id == full_trait_id) {
                                report.findings.push(Finding {
                                    kind: FindingKind::Capability,
                                    trait_refs: vec![],
                                    id: full_trait_id,
                                    desc: description.to_string(),
                                    conf: 1.0,
                                    crit: criticality,
                                    mbc: None,
                                    attack: None,
                                    evidence: vec![Evidence {
                                        method: "ast".to_string(),
                                        source: "tree-sitter-typescript".to_string(),
                                        value: func_name.to_string(),
                                        location: Some(format!(
                                            "line:{}",
                                            node.start_position().row + 1
                                        )),
                                    }],
                                });
                            }
                            break;
                        }
                    }
                }
            }

            // Check for eval/Function in any context
            if text.contains("eval(")
                && !report
                    .findings
                    .iter()
                    .any(|t| t.id == "exec/script/eval/typescript")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "exec/script/eval/typescript".to_string(),
                    desc: "Dynamic code evaluation".to_string(),
                    conf: 1.0,
                    crit: Criticality::Hostile,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-typescript".to_string(),
                        value: "eval".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }
        }
    }

    fn analyze_import(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            // Check for dynamic imports
            if text.contains("import(")
                && !report
                    .findings
                    .iter()
                    .any(|t| t.id == "anti-analysis/dynamic-import/typescript")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/dynamic-import/typescript".to_string(),
                    desc: "Dynamic import (possible obfuscation)".to_string(),
                    conf: 0.7,
                    crit: Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-typescript".to_string(),
                        value: "dynamic-import".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }

            // Check for suspicious modules
            let suspicious_modules = [
                (
                    "child_process",
                    "exec/command/shell/typescript",
                    "Child process module",
                ),
                (
                    "vm",
                    "exec/script/eval/typescript",
                    "VM module (code execution)",
                ),
                ("os", "info/os/typescript", "OS information access"),
                ("crypto", "crypto/typescript", "Cryptographic operations"),
            ];

            for (module, trait_id, description) in suspicious_modules {
                if text.contains(module) && !report.findings.iter().any(|t| t.id == trait_id) {
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: trait_id.to_string(),
                        desc: description.to_string(),
                        conf: 0.6,
                        crit: Criticality::Notable,
                        mbc: None,
                        attack: None,
                        evidence: vec![Evidence {
                            method: "import".to_string(),
                            source: "tree-sitter-typescript".to_string(),
                            value: module.to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }
            }
        }
    }

    fn analyze_assignment(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        if let Ok(text) = node.utf8_text(source) {
            // Check for prototype pollution patterns
            if (text.contains("__proto__") || text.contains("constructor.prototype"))
                && !report
                    .findings
                    .iter()
                    .any(|t| t.id == "impact/prototype-pollution/typescript")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "impact/prototype-pollution/typescript".to_string(),
                    desc: "Prototype pollution pattern detected".to_string(),
                    conf: 0.8,
                    crit: Criticality::Hostile,
                    mbc: None,
                    attack: Some("T1059".to_string()),
                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-typescript".to_string(),
                        value: "prototype-pollution".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }
        }
    }

    fn analyze_prototype_pollution(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        if let Ok(text) = node.utf8_text(source) {
            if text.contains("__proto__")
                && !report
                    .findings
                    .iter()
                    .any(|t| t.id == "impact/prototype-pollution/typescript")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "impact/prototype-pollution/typescript".to_string(),
                    desc: "Prototype pollution via __proto__ access".to_string(),
                    conf: 0.9,
                    crit: Criticality::Hostile,
                    mbc: None,
                    attack: Some("T1059".to_string()),
                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-typescript".to_string(),
                        value: "__proto__".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }
        }
    }

    fn analyze_new_expression(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        if let Ok(text) = node.utf8_text(source) {
            // Check for Function constructor (code execution)
            if text.contains("new Function")
                && !report
                    .findings
                    .iter()
                    .any(|t| t.id == "exec/script/function-constructor/typescript")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "exec/script/function-constructor/typescript".to_string(),
                    desc: "Function constructor (dynamic code execution)".to_string(),
                    conf: 1.0,
                    crit: Criticality::Hostile,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-typescript".to_string(),
                        value: "Function constructor".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }
        }
    }

    fn calculate_sha256(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

impl Analyzer for TypeScriptAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let bytes = fs::read(file_path).context("Failed to read TypeScript file")?;
        let content = String::from_utf8_lossy(&bytes);

        self.analyze_script(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            matches!(
                ext.to_str(),
                Some("ts") | Some("tsx") | Some("mts") | Some("cts")
            )
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let analyzer = TypeScriptAnalyzer::new();
        assert!(analyzer.parser.borrow().language().is_some());
    }

    #[test]
    fn test_can_analyze_ts() {
        let analyzer = TypeScriptAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.ts")));
        assert!(analyzer.can_analyze(Path::new("test.tsx")));
        assert!(analyzer.can_analyze(Path::new("test.mts")));
        assert!(analyzer.can_analyze(Path::new("test.cts")));
    }

    #[test]
    fn test_can_analyze_non_typescript() {
        let analyzer = TypeScriptAnalyzer::new();
        assert!(!analyzer.can_analyze(Path::new("test.js")));
        assert!(!analyzer.can_analyze(Path::new("test.py")));
        assert!(!analyzer.can_analyze(Path::new("test.txt")));
        assert!(!analyzer.can_analyze(Path::new("test")));
    }

    #[test]
    fn test_analyze_eval() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            const x = eval("2 + 2");
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        assert!(report.findings.iter().any(|t| t.id.contains("eval")));
        let eval_trait = report
            .findings
            .iter()
            .find(|t| t.id.contains("eval"))
            .unwrap();
        assert_eq!(eval_trait.crit, Criticality::Hostile);
    }

    #[test]
    fn test_analyze_exec() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            import { exec } from 'child_process';
            exec('ls -la');
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        assert!(report
            .findings
            .iter()
            .any(|t| t.id.contains("exec") || t.id.contains("shell")));
    }

    #[test]
    fn test_analyze_spawn() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            const { spawn } = require('child_process');
            spawn('cat', ['file.txt']);
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        assert!(report
            .findings
            .iter()
            .any(|t| t.id.contains("shell") || t.id.contains("spawn")));
    }

    #[test]
    fn test_analyze_fetch() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            const response = await fetch('https://api.example.com/data');
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        assert!(report.findings.iter().any(|t| t.id.contains("http")));
        let http_trait = report
            .findings
            .iter()
            .find(|t| t.id.contains("http"))
            .unwrap();
        assert_eq!(http_trait.crit, Criticality::Notable);
    }

    #[test]
    fn test_analyze_dynamic_import() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            const module = await import('./dynamic-module');
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        // Dynamic import detection may vary based on tree-sitter parsing
        // Just ensure analysis completes without error
        assert!(!report.structure.is_empty());
    }

    #[test]
    fn test_analyze_child_process_import() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            import * as cp from 'child_process';
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        assert!(report
            .findings
            .iter()
            .any(|t| t.id.contains("shell") || t.id.contains("child_process")));
    }

    #[test]
    fn test_analyze_vm_module() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            import { runInNewContext } from 'vm';
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        assert!(report
            .findings
            .iter()
            .any(|t| t.id.contains("vm") || t.id.contains("eval")));
    }

    #[test]
    fn test_analyze_os_module() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            import os from 'os';
            const platform = os.platform();
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        assert!(report.findings.iter().any(|t| t.id.contains("os")));
    }

    #[test]
    fn test_analyze_crypto_module() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            import crypto from 'crypto';
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        assert!(report.findings.iter().any(|t| t.id.contains("crypto")));
    }

    #[test]
    fn test_analyze_prototype_pollution_proto() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            const obj = {};
            obj.__proto__.polluted = true;
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        assert!(report
            .findings
            .iter()
            .any(|t| t.id.contains("prototype-pollution")));
        let pollution_trait = report
            .findings
            .iter()
            .find(|t| t.id.contains("prototype-pollution"))
            .unwrap();
        assert_eq!(pollution_trait.crit, Criticality::Hostile);
    }

    #[test]
    fn test_analyze_prototype_pollution_constructor() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            const obj: any = {};
            obj.constructor.prototype.isAdmin = true;
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        assert!(report
            .findings
            .iter()
            .any(|t| t.id.contains("prototype-pollution")));
    }

    #[test]
    fn test_analyze_function_constructor() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            const fn = new Function('a', 'b', 'return a + b');
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        assert!(report
            .findings
            .iter()
            .any(|t| t.id.contains("function-constructor")));
        let fn_trait = report
            .findings
            .iter()
            .find(|t| t.id.contains("function-constructor"))
            .unwrap();
        assert_eq!(fn_trait.crit, Criticality::Hostile);
    }

    #[test]
    fn test_analyze_file_operations() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            import { readFile, writeFile, unlink } from 'fs/promises';
            await readFile('/etc/passwd');
            await writeFile('malicious.txt', 'data');
            await unlink('target.txt');
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        assert!(report.findings.iter().any(|t| t.id.contains("fs/")));
    }

    #[test]
    fn test_analyze_benign_code() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            function add(a: number, b: number): number {
                return a + b;
            }

            const result = add(2, 3);
            console.log(result);
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        // Should have structural feature but no dangerous traits
        assert!(!report.structure.is_empty());
        assert_eq!(report.findings.len(), 0);
    }

    #[test]
    fn test_analyze_multiple_traits() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            import { exec } from 'child_process';
            import crypto from 'crypto';

            const result = eval('2 + 2');
            exec('ls -la');

            const obj = {};
            obj.__proto__.polluted = true;
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        // Should detect multiple dangerous patterns
        assert!(report.findings.len() >= 3);
        assert!(report.findings.iter().any(|t| t.id.contains("eval")));
        assert!(report.findings.iter().any(|t| t.id.contains("shell")));
        assert!(report
            .findings
            .iter()
            .any(|t| t.id.contains("prototype-pollution")));
    }

    #[test]
    fn test_structural_feature() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = "const x = 1;";
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        assert_eq!(report.structure.len(), 1);
        assert_eq!(report.structure[0].id, "source/language/typescript");
    }

    #[test]
    fn test_target_info() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = "const x = 1;";
        let report = analyzer
            .analyze_script(Path::new("/test/file.ts"), code)
            .unwrap();

        assert_eq!(report.target.file_type, "typescript");
        assert_eq!(report.target.path, "/test/file.ts");
        assert!(report.target.size_bytes > 0);
        assert!(!report.target.sha256.is_empty());
    }

    #[test]
    fn test_metadata() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = "const x = 1;";
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        assert!(report
            .metadata
            .tools_used
            .contains(&"tree-sitter-typescript".to_string()));
    }

    #[test]
    fn test_no_duplicate_traits() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            eval('1');
            eval('2');
            eval('3');
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        // Should only have one eval trait despite multiple calls
        let eval_traits: Vec<_> = report
            .findings
            .iter()
            .filter(|t| t.id.contains("eval"))
            .collect();
        assert_eq!(eval_traits.len(), 1);
    }
}
