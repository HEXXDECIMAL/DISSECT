use crate::analyzers::Analyzer;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// JavaScript/Node.js analyzer using tree-sitter
pub struct JavaScriptAnalyzer {
    parser: RefCell<Parser>,
}

impl JavaScriptAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser.set_language(&tree_sitter_javascript::LANGUAGE.into()).unwrap();

        Self { parser: RefCell::new(parser) }
    }

    fn analyze_script(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the JavaScript
        let tree = self.parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse JavaScript")?;

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "javascript".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "source/language/javascript".to_string(),
            description: "JavaScript source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-javascript".to_string(),
                value: "javascript".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        // Detect capabilities and obfuscation
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Check for cross-statement obfuscation patterns
        self.check_global_obfuscation(content, &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-javascript".to_string()];

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
                "call_expression" => {
                    self.analyze_call(&node, source, report);
                }
                "import_statement" => {
                    self.analyze_import(&node, source, report);
                }
                "variable_declarator" => {
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
            } else if text.contains("Function(") {
                Some(("exec/script/eval", "Dynamic function constructor", "Function"))
            } else if text.contains("child_process.exec") || text.contains("child_process.execSync") ||
                      (text.starts_with("exec(") || text.contains(" exec(")) {
                Some(("exec/command/shell", "Execute shell commands", "exec"))
            } else if text.contains("child_process.spawn") || text.contains("child_process.spawnSync") ||
                      (text.starts_with("spawn(") || text.contains(" spawn(")) {
                Some(("exec/command/direct", "Spawn child process", "spawn"))
            } else if text.contains("require(") && !text.contains("require('") && !text.contains("require(\"") {
                // Dynamic require with variable
                Some(("anti-analysis/obfuscation/dynamic-import", "Dynamic require", "require(variable)"))
            } else if text.contains("fs.writeFile") || text.contains("fs.writeFileSync") {
                Some(("fs/write", "Write files", "fs.writeFile"))
            } else if text.contains("fs.unlink") || text.contains("fs.unlinkSync") || text.contains("fs.rm") {
                Some(("fs/delete", "Delete files", "fs.unlink"))
            } else if text.contains("fs.chmod") || text.contains("fs.chmodSync") {
                Some(("fs/permissions", "Change file permissions", "fs.chmod"))
            } else if text.contains("http.request") || text.contains("https.request") {
                Some(("net/http/client", "HTTP client operations", "http.request"))
            } else if text.contains("net.connect") || text.contains("net.createConnection") {
                Some(("net/socket/connect", "Network socket connection", "net.connect"))
            } else if text.contains("net.createServer") {
                Some(("net/socket/listen", "Create network server", "net.createServer"))
            } else if text.contains("Buffer.from") && text.contains("'base64'") {
                Some(("anti-analysis/obfuscation/base64", "Base64 decoding", "Buffer.from"))
            } else if text.contains("atob(") {
                Some(("anti-analysis/obfuscation/base64", "Base64 decoding (browser)", "atob"))
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
                            source: "tree-sitter-javascript".to_string(),
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
                ("child_process", "exec/command/shell", "Child process execution"),
                ("fs", "fs/access", "Filesystem operations"),
                ("net", "net/socket/create", "Network sockets"),
                ("http", "net/http/client", "HTTP client"),
                ("https", "net/http/client", "HTTPS client"),
                ("crypto", "crypto/operation", "Cryptographic operations"),
                ("vm", "exec/script/eval", "Virtual machine (code execution)"),
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
                                source: "tree-sitter-javascript".to_string(),
                                value: module.to_string(),
                                location: Some(format!("line:{}", node.start_position().row + 1)),
                            }],
                        });
                    }
                }
            }
        }
    }

    fn check_global_obfuscation(&self, content: &str, report: &mut AnalysisReport) {
        // Check for base64 + eval pattern across the entire file
        let has_base64 = content.contains("Buffer.from") && content.contains("base64") || content.contains("atob(");
        let has_eval = content.contains("eval(") || content.contains("Function(");

        if has_base64 && has_eval {
            if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/base64-eval") {
                report.capabilities.push(Capability {
                    id: "anti-analysis/obfuscation/base64-eval".to_string(),
                    description: "Base64 decode followed by eval (obfuscation)".to_string(),
                    confidence: 0.95,
                    evidence: vec![Evidence {
                        method: "pattern".to_string(),
                        source: "tree-sitter-javascript".to_string(),
                        value: "base64+eval".to_string(),
                        location: None,
                    }],
                });
            }
        }
    }

    fn check_obfuscation(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            // Detect base64 + eval pattern
            if (text.contains("Buffer.from") && text.contains("base64")) || text.contains("atob(") {
                if text.contains("eval(") || text.contains("Function(") {
                    if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/base64-eval") {
                        report.capabilities.push(Capability {
                            id: "anti-analysis/obfuscation/base64-eval".to_string(),
                            description: "Base64 decode followed by eval (obfuscation)".to_string(),
                            confidence: 0.95,
                            evidence: vec![Evidence {
                                method: "pattern".to_string(),
                                source: "tree-sitter-javascript".to_string(),
                                value: "base64+eval".to_string(),
                                location: Some(format!("line:{}", node.start_position().row + 1)),
                            }],
                        });
                    }
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
                            source: "tree-sitter-javascript".to_string(),
                            value: "hex_encoding".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }
            }

            // Detect string manipulation obfuscation
            if text.contains(".split(") && text.contains(".reverse()") && text.contains(".join(") {
                if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/string-construct") {
                    report.capabilities.push(Capability {
                        id: "anti-analysis/obfuscation/string-construct".to_string(),
                        description: "String manipulation obfuscation".to_string(),
                        confidence: 0.9,
                        evidence: vec![Evidence {
                            method: "pattern".to_string(),
                            source: "tree-sitter-javascript".to_string(),
                            value: "split_reverse_join".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }
            }

            // Detect charAt obfuscation
            if text.contains(".charAt(") && text.matches(".charAt(").count() > 5 {
                if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/string-construct") {
                    report.capabilities.push(Capability {
                        id: "anti-analysis/obfuscation/string-construct".to_string(),
                        description: "Character-by-character string construction".to_string(),
                        confidence: 0.85,
                        evidence: vec![Evidence {
                            method: "pattern".to_string(),
                            source: "tree-sitter-javascript".to_string(),
                            value: "charAt_pattern".to_string(),
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

            // Match both function declarations and arrow functions
            if matches!(node.kind(), "function_declaration" | "arrow_function" | "function") {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(func_name) = name_node.utf8_text(source) {
                        report.functions.push(Function {
                            name: func_name.to_string(),
                            offset: Some(format!("line:{}", node.start_position().row + 1)),
                            size: Some((node.end_byte() - node.start_byte()) as u64),
                            complexity: None,
                            calls: Vec::new(),
                            source: "tree-sitter-javascript".to_string(),
                        });
                    }
                } else {
                    // Anonymous function
                    report.functions.push(Function {
                        name: "<anonymous>".to_string(),
                        offset: Some(format!("line:{}", node.start_position().row + 1)),
                        size: Some((node.end_byte() - node.start_byte()) as u64),
                        complexity: None,
                        calls: Vec::new(),
                        source: "tree-sitter-javascript".to_string(),
                    });
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

impl Default for JavaScriptAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for JavaScriptAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = fs::read_to_string(file_path)
            .context("Failed to read JavaScript file")?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_script() {
        let analyzer = JavaScriptAnalyzer::new();
        let script = r#"
            const fs = require('fs');
            const { exec } = require('child_process');

            exec('rm -rf /tmp/test', (error, stdout, stderr) => {
                console.log(stdout);
            });

            fs.writeFileSync('/tmp/malicious.txt', 'payload');
        "#;

        let report = analyzer.analyze_script(Path::new("test.js"), script).unwrap();

        // Should detect exec and fs imports
        assert!(!report.capabilities.is_empty());

        // Should detect shell execution
        assert!(report.capabilities.iter().any(|c| c.id.contains("exec/command")));

        // Should detect file write
        assert!(report.capabilities.iter().any(|c| c.id.contains("fs/write")));
    }

    #[test]
    fn test_obfuscated_script() {
        let analyzer = JavaScriptAnalyzer::new();
        let script = r#"
            const payload = Buffer.from('Y3VybCBldmlsLmNvbQ==', 'base64').toString();
            eval(payload);
        "#;

        let report = analyzer.analyze_script(Path::new("test.js"), script).unwrap();

        // Should detect base64 + eval obfuscation
        assert!(report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/base64-eval"));
    }
}
