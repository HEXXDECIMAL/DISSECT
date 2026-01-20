use crate::analyzers::Analyzer;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// Python analyzer using tree-sitter
pub struct PythonAnalyzer {
    parser: RefCell<Parser>,
}

impl PythonAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser.set_language(&tree_sitter_python::LANGUAGE.into()).unwrap();

        Self { parser: RefCell::new(parser) }
    }

    fn analyze_script(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the Python script
        let tree = self.parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse Python script")?;

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "python_script".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "source/language/python".to_string(),
            description: "Python script".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-python".to_string(),
                value: "python".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        // Detect capabilities and obfuscation
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-python".to_string()];

        Ok(report)
    }

    fn detect_capabilities(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        let mut cursor = node.walk();
        self.walk_ast(&mut cursor, source, report);
    }

    fn walk_ast(&self, cursor: &mut tree_sitter::TreeCursor, source: &[u8], report: &mut AnalysisReport) {
        loop {
            let node = cursor.node();

            match node.kind() {
                "call" => {
                    self.analyze_call(&node, source, report);
                }
                "import_statement" | "import_from_statement" => {
                    self.analyze_import(&node, source, report);
                }
                "assignment" => {
                    self.check_obfuscation(&node, source, report);
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
            let capability = if text.contains("eval(") {
                Some(("exec/script/eval", "Evaluates dynamic code", "eval"))
            } else if text.contains("exec(") {
                Some(("exec/script/eval", "Executes dynamic code", "exec"))
            } else if text.contains("compile(") {
                Some(("exec/script/eval", "Compiles dynamic code", "compile"))
            } else if text.contains("__import__(") {
                Some(("anti-analysis/obfuscation/dynamic-import", "Dynamic module import", "__import__"))
            } else if text.contains("subprocess.") || text.contains("os.system") || text.contains("os.popen") {
                Some(("exec/command/shell", "Executes system commands", "subprocess/system"))
            } else if text.contains("requests.") || text.contains("urllib.") || text.contains("http.client") {
                Some(("net/http/client", "HTTP client operations", "http_client"))
            } else if text.contains("socket.") {
                Some(("net/socket/create", "Network socket operations", "socket"))
            } else if text.contains("open(") && (text.contains("'w'") || text.contains("\"w\"")) {
                Some(("fs/write", "Write files", "open_write"))
            } else if text.contains("os.remove") || text.contains("os.unlink") || text.contains("shutil.rmtree") {
                Some(("fs/delete", "Delete files/directories", "remove"))
            } else if text.contains("base64.b64decode") {
                Some(("anti-analysis/obfuscation/base64", "Base64 decoding", "b64decode"))
            } else {
                None
            };

            if let Some((cap_id, description, pattern)) = capability {
                if !report.capabilities.iter().any(|c| c.id == cap_id) {
                    report.capabilities.push(Capability {
                        id: cap_id.to_string(),
                        description: description.to_string(),
                        confidence: 1.0,
                        evidence: vec![Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-python".to_string(),
                            value: pattern.to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }
            }
        }
    }

    fn analyze_import(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            // Detect suspicious imports
            let suspicious_modules = [
                ("subprocess", "exec/command/shell", "Shell command execution"),
                ("os", "exec/command/shell", "OS operations"),
                ("socket", "net/socket/create", "Network sockets"),
                ("requests", "net/http/client", "HTTP client"),
                ("pickle", "anti-analysis/obfuscation/pickle", "Pickle deserialization"),
                ("ctypes", "exec/dylib/load", "C library loading"),
            ];

            for (module, cap_id, description) in suspicious_modules {
                if text.contains(module) {
                    if !report.capabilities.iter().any(|c| c.id == cap_id) {
                        report.capabilities.push(Capability {
                            id: cap_id.to_string(),
                            description: description.to_string(),
                            confidence: 0.7, // Import alone is not definitive
                            evidence: vec![Evidence {
                                method: "import".to_string(),
                                source: "tree-sitter-python".to_string(),
                                value: module.to_string(),
                                location: Some(format!("line:{}", node.start_position().row + 1)),
                            }],
                        });
                    }
                }
            }
        }
    }

    fn check_obfuscation(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            // Detect base64 + eval pattern (common obfuscation)
            if (text.contains("base64") || text.contains("b64decode"))
                && (text.contains("eval") || text.contains("exec")) {
                if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/base64-eval") {
                    report.capabilities.push(Capability {
                        id: "anti-analysis/obfuscation/base64-eval".to_string(),
                        description: "Base64 decode followed by eval (obfuscation)".to_string(),
                        confidence: 0.95,
                        evidence: vec![Evidence {
                            method: "pattern".to_string(),
                            source: "tree-sitter-python".to_string(),
                            value: "base64+eval".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }
            }

            // Detect hex string construction
            if text.contains("\\x") && text.matches("\\x").count() > 5 {
                if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/hex") {
                    report.capabilities.push(Capability {
                        id: "anti-analysis/obfuscation/hex".to_string(),
                        description: "Hex-encoded strings".to_string(),
                        confidence: 0.9,
                        evidence: vec![Evidence {
                            method: "pattern".to_string(),
                            source: "tree-sitter-python".to_string(),
                            value: "hex_encoding".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }
            }

            // Detect string obfuscation via join
            if text.contains(".join(") && (text.contains("chr(") || text.contains("ord(")) {
                if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/string-construct") {
                    report.capabilities.push(Capability {
                        id: "anti-analysis/obfuscation/string-construct".to_string(),
                        description: "Constructs strings via chr/ord".to_string(),
                        confidence: 0.9,
                        evidence: vec![Evidence {
                            method: "pattern".to_string(),
                            source: "tree-sitter-python".to_string(),
                            value: "chr_join_pattern".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }
            }
        }
    }

    fn extract_functions(&self, root: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        let mut cursor = root.walk();

        loop {
            let node = cursor.node();

            if node.kind() == "function_definition" {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(func_name) = name_node.utf8_text(source) {
                        report.functions.push(Function {
                            name: func_name.to_string(),
                            offset: Some(format!("line:{}", node.start_position().row + 1)),
                            size: Some((node.end_byte() - node.start_byte()) as u64),
                            complexity: None,
                            calls: Vec::new(),
                            source: "tree-sitter-python".to_string(),
                        });
                    }
                }
            }

            // Recurse
            if cursor.goto_first_child() {
                continue;
            }

            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return;
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

impl Default for PythonAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for PythonAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = fs::read_to_string(file_path)
            .context("Failed to read Python script")?;

        self.analyze_script(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            ext == "py"
        } else if let Ok(data) = fs::read(file_path) {
            data.starts_with(b"#!/usr/bin/env python") || data.starts_with(b"#!/usr/bin/python")
        } else {
            false
        }
    }
}
