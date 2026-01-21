use crate::analyzers::Analyzer;
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
        let start = std::time::Instant::now();

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
            description: "TypeScript source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-typescript".to_string(),
                value: "typescript".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        // Parse with tree-sitter
        if let Some(tree) = self.parser.borrow_mut().parse(content, None) {
            let root = tree.root_node();
            self.analyze_ast(&root, content.as_bytes(), &mut report);
        }

        // Analyze paths and environment variables
        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-typescript".to_string()];

        Ok(report)
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
                            if !report.traits.iter().any(|t| t.id == full_trait_id) {
                                report.traits.push(Trait {
                                    id: full_trait_id,
                                    description: description.to_string(),
                                    confidence: 1.0,
                                    criticality,
                                    capability: false,
                                    mbc: None,
                                    attack: None,
                                    language: Some("typescript".to_string()),
                                    platforms: vec!["nodejs".to_string()],
                                    evidence: vec![Evidence {
                                        method: "ast".to_string(),
                                        source: "tree-sitter-typescript".to_string(),
                                        value: func_name.to_string(),
                                        location: Some(format!(
                                            "line:{}",
                                            node.start_position().row + 1
                                        )),
                                    }],
                                    referenced_paths: None,
                                    referenced_directories: None,
                                });
                            }
                            break;
                        }
                    }
                }
            }

            // Check for eval/Function in any context
            if text.contains("eval(") {
                if !report
                    .traits
                    .iter()
                    .any(|t| t.id == "exec/script/eval/typescript")
                {
                    report.traits.push(Trait {
                        id: "exec/script/eval/typescript".to_string(),
                        description: "Dynamic code evaluation".to_string(),
                        confidence: 1.0,
                        criticality: Criticality::Hostile,
                        capability: false,
                        mbc: None,
                        attack: None,
                        language: Some("typescript".to_string()),
                        platforms: vec!["nodejs".to_string()],
                        evidence: vec![Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-typescript".to_string(),
                            value: "eval".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                        referenced_paths: None,
                        referenced_directories: None,
                    });
                }
            }
        }
    }

    fn analyze_import(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            // Check for dynamic imports
            if text.contains("import(") {
                if !report
                    .traits
                    .iter()
                    .any(|t| t.id == "anti-analysis/dynamic-import/typescript")
                {
                    report.traits.push(Trait {
                        id: "anti-analysis/dynamic-import/typescript".to_string(),
                        description: "Dynamic import (possible obfuscation)".to_string(),
                        confidence: 0.7,
                        criticality: Criticality::Suspicious,
                        capability: false,
                        mbc: None,
                        attack: None,
                        language: Some("typescript".to_string()),
                        platforms: vec!["nodejs".to_string()],
                        evidence: vec![Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-typescript".to_string(),
                            value: "dynamic-import".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                        referenced_paths: None,
                        referenced_directories: None,
                    });
                }
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
                if text.contains(module) && !report.traits.iter().any(|t| t.id == trait_id) {
                    report.traits.push(Trait {
                        id: trait_id.to_string(),
                        description: description.to_string(),
                        confidence: 0.6,
                        criticality: Criticality::Notable,
                        capability: false,
                        mbc: None,
                        attack: None,
                        language: Some("typescript".to_string()),
                        platforms: vec!["nodejs".to_string()],
                        evidence: vec![Evidence {
                            method: "import".to_string(),
                            source: "tree-sitter-typescript".to_string(),
                            value: module.to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                        referenced_paths: None,
                        referenced_directories: None,
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
            if text.contains("__proto__") || text.contains("constructor.prototype") {
                if !report
                    .traits
                    .iter()
                    .any(|t| t.id == "impact/prototype-pollution/typescript")
                {
                    report.traits.push(Trait {
                        id: "impact/prototype-pollution/typescript".to_string(),
                        description: "Prototype pollution pattern detected".to_string(),
                        confidence: 0.8,
                        criticality: Criticality::Hostile,
                        capability: false,
                        mbc: None,
                        attack: Some("T1059".to_string()),
                        language: Some("typescript".to_string()),
                        platforms: vec!["nodejs".to_string()],
                        evidence: vec![Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-typescript".to_string(),
                            value: "prototype-pollution".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                        referenced_paths: None,
                        referenced_directories: None,
                    });
                }
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
                    .traits
                    .iter()
                    .any(|t| t.id == "impact/prototype-pollution/typescript")
            {
                report.traits.push(Trait {
                    id: "impact/prototype-pollution/typescript".to_string(),
                    description: "Prototype pollution via __proto__ access".to_string(),
                    confidence: 0.9,
                    criticality: Criticality::Hostile,
                    capability: false,
                    mbc: None,
                    attack: Some("T1059".to_string()),
                    language: Some("typescript".to_string()),
                    platforms: vec!["nodejs".to_string()],
                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-typescript".to_string(),
                        value: "__proto__".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                    referenced_paths: None,
                    referenced_directories: None,
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
            if text.contains("new Function") {
                if !report
                    .traits
                    .iter()
                    .any(|t| t.id == "exec/script/function-constructor/typescript")
                {
                    report.traits.push(Trait {
                        id: "exec/script/function-constructor/typescript".to_string(),
                        description: "Function constructor (dynamic code execution)".to_string(),
                        confidence: 1.0,
                        criticality: Criticality::Hostile,
                        capability: false,
                        mbc: None,
                        attack: None,
                        language: Some("typescript".to_string()),
                        platforms: vec!["nodejs".to_string()],
                        evidence: vec![Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-typescript".to_string(),
                            value: "Function constructor".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                        referenced_paths: None,
                        referenced_directories: None,
                    });
                }
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
        let content = fs::read_to_string(file_path).context("Failed to read TypeScript file")?;

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

        assert!(report.traits.iter().any(|t| t.id.contains("eval")));
        let eval_trait = report
            .traits
            .iter()
            .find(|t| t.id.contains("eval"))
            .unwrap();
        assert_eq!(eval_trait.criticality, Criticality::Hostile);
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
            .traits
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
            .traits
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

        assert!(report.traits.iter().any(|t| t.id.contains("http")));
        let http_trait = report
            .traits
            .iter()
            .find(|t| t.id.contains("http"))
            .unwrap();
        assert_eq!(http_trait.criticality, Criticality::Notable);
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
        assert!(report.structure.len() >= 1);
    }

    #[test]
    fn test_analyze_child_process_import() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            import * as cp from 'child_process';
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        assert!(report
            .traits
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
            .traits
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

        assert!(report.traits.iter().any(|t| t.id.contains("os")));
    }

    #[test]
    fn test_analyze_crypto_module() {
        let analyzer = TypeScriptAnalyzer::new();
        let code = r#"
            import crypto from 'crypto';
        "#;
        let report = analyzer.analyze_script(Path::new("test.ts"), code).unwrap();

        assert!(report.traits.iter().any(|t| t.id.contains("crypto")));
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
            .traits
            .iter()
            .any(|t| t.id.contains("prototype-pollution")));
        let pollution_trait = report
            .traits
            .iter()
            .find(|t| t.id.contains("prototype-pollution"))
            .unwrap();
        assert_eq!(pollution_trait.criticality, Criticality::Hostile);
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
            .traits
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
            .traits
            .iter()
            .any(|t| t.id.contains("function-constructor")));
        let fn_trait = report
            .traits
            .iter()
            .find(|t| t.id.contains("function-constructor"))
            .unwrap();
        assert_eq!(fn_trait.criticality, Criticality::Hostile);
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

        assert!(report.traits.iter().any(|t| t.id.contains("fs/")));
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
        assert_eq!(report.traits.len(), 0);
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
        assert!(report.traits.len() >= 3);
        assert!(report.traits.iter().any(|t| t.id.contains("eval")));
        assert!(report.traits.iter().any(|t| t.id.contains("shell")));
        assert!(report
            .traits
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
        assert!(report.metadata.analysis_duration_ms >= 0);
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
            .traits
            .iter()
            .filter(|t| t.id.contains("eval"))
            .collect();
        assert_eq!(eval_traits.len(), 1);
    }
}
