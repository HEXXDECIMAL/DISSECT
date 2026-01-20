use crate::analyzers::Analyzer;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// Ruby analyzer using tree-sitter
pub struct RubyAnalyzer {
    parser: RefCell<Parser>,
}

impl RubyAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser.set_language(&tree_sitter_ruby::LANGUAGE.into()).unwrap();

        Self { parser: RefCell::new(parser) }
    }

    fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the Ruby source
        let tree = self.parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse Ruby source")?;

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "ruby".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "source/language/ruby".to_string(),
            description: "Ruby source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-ruby".to_string(),
                value: "ruby".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        // Detect capabilities and patterns
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-ruby".to_string()];

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
                "call" | "method_call" => {
                    self.analyze_call(&node, source, report);
                }
                "command" => {
                    self.analyze_command(&node, source, report);
                }
                "require" | "require_relative" => {
                    self.analyze_require(&node, source, report);
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

            // Command execution (critical in Ruby)
            if text.contains("system(") || text.contains("system ") {
                capabilities.push(("exec/command/shell", "system() command execution", "system", 0.95));
            }
            if text.contains("exec(") || text.contains("exec ") {
                capabilities.push(("exec/command/shell", "exec() command execution", "exec", 0.95));
            }
            if text.contains("spawn(") || text.contains("spawn ") {
                capabilities.push(("exec/command/shell", "spawn() command execution", "spawn", 0.9));
            }
            if text.contains("IO.popen") || text.contains("popen") {
                capabilities.push(("exec/command/shell", "popen command execution", "popen", 0.95));
            }
            if text.contains("`") || text.contains("%x") {
                capabilities.push(("exec/command/shell", "Backtick command execution", "backticks", 0.95));
            }

            // Dynamic code execution (eval family)
            if text.contains("eval(") || text.contains("eval ") {
                capabilities.push(("exec/eval", "eval() dynamic code execution", "eval", 0.95));
            }
            if text.contains("instance_eval") {
                capabilities.push(("exec/eval", "instance_eval dynamic execution", "instance_eval", 0.9));
            }
            if text.contains("class_eval") || text.contains("module_eval") {
                capabilities.push(("exec/eval", "class/module_eval dynamic execution", "class_eval", 0.9));
            }
            if text.contains("Binding.eval") {
                capabilities.push(("exec/eval", "Binding.eval execution", "Binding.eval", 0.9));
            }

            // Deserialization (Marshal)
            if text.contains("Marshal.load") || text.contains("Marshal.restore") {
                capabilities.push(("anti-analysis/deserialization", "Marshal deserialization", "Marshal.load", 0.95));
            }
            if text.contains("YAML.load") && !text.contains("YAML.safe_load") {
                capabilities.push(("anti-analysis/deserialization", "YAML unsafe deserialization", "YAML.load", 0.9));
            }

            // Network operations
            if text.contains("TCPSocket") {
                capabilities.push(("net/socket/create", "TCP socket", "TCPSocket", 0.9));
            }
            if text.contains("TCPServer") {
                capabilities.push(("net/socket/server", "TCP server", "TCPServer", 0.9));
            }
            if text.contains("Net::HTTP") {
                capabilities.push(("net/http/client", "HTTP client", "Net::HTTP", 0.8));
            }

            // File operations
            if text.contains("FileUtils.rm_rf") {
                capabilities.push(("fs/delete", "Recursive directory deletion", "rm_rf", 0.95));
            }
            if text.contains("File.delete") {
                capabilities.push(("fs/delete", "Delete file", "File.delete", 0.9));
            }

            // Reverse shell pattern
            if (text.contains("TCPSocket") || text.contains("socket")) &&
               (text.contains("system") || text.contains("exec") || text.contains("/bin/sh")) {
                capabilities.push(("c2/reverse-shell", "Reverse shell connection", "socket+exec", 0.98));
            }

            // Reflection/Metaprogramming
            if text.contains(".send(") || text.contains(".send ") {
                capabilities.push(("anti-analysis/reflection", "Dynamic method invocation", "send", 0.85));
            }
            if text.contains("const_get") {
                capabilities.push(("anti-analysis/reflection", "Dynamic constant access", "const_get", 0.85));
            }

            // Process manipulation
            if text.contains("Process.setuid") || text.contains("Process.setgid") {
                capabilities.push(("privilege/setuid", "Set user/group ID", "setuid/setgid", 0.95));
            }
            if text.contains("Process.kill") {
                capabilities.push(("process/manipulate", "Kill process", "Process.kill", 0.9));
            }

            // Add capabilities
            for (cap_id, desc, method, conf) in capabilities {
                report.capabilities.push(Capability {
                    id: cap_id.to_string(),
                    description: desc.to_string(),
                    confidence: conf,
                    criticality: Criticality::None,
                    mbc_id: None,
                    attack_id: None,
                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-ruby".to_string(),
                        value: method.to_string(),
                        location: Some(format!("{}:{}", node.start_position().row, node.start_position().column)),
                    }],
                    traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                });
            }
        }
    }

    fn analyze_command(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        // Ruby command nodes (backticks, %x, etc.)
        if let Ok(text) = node.utf8_text(source) {
            report.capabilities.push(Capability {
                id: "exec/command/shell".to_string(),
                description: "Shell command execution".to_string(),
                confidence: 0.95,
                criticality: Criticality::None,

                                    mbc_id: None,

                                    attack_id: None,

                                    evidence: vec![Evidence {
                    method: "ast".to_string(),
                    source: "tree-sitter-ruby".to_string(),
                    value: "command".to_string(),
                    location: Some(format!("{}:{}", node.start_position().row, node.start_position().column)),
                }],
                traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                });
        }
    }

    fn analyze_require(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            let mut capabilities = Vec::new();

            if text.contains("socket") || text.contains("net/http") {
                capabilities.push(("net/socket/create", "Network library import", "socket", 0.7));
            }
            if text.contains("fileutils") {
                capabilities.push(("fs/write", "File utilities import", "fileutils", 0.6));
            }
            if text.contains("open-uri") {
                capabilities.push(("net/http/client", "Open-URI import", "open-uri", 0.75));
            }

            for (cap_id, desc, method, conf) in capabilities {
                report.capabilities.push(Capability {
                    id: cap_id.to_string(),
                    description: desc.to_string(),
                    confidence: conf,
                    criticality: Criticality::None,
                    mbc_id: None,
                    attack_id: None,
                    evidence: vec![Evidence {
                        method: "import".to_string(),
                        source: "tree-sitter-ruby".to_string(),
                        value: method.to_string(),
                        location: Some(format!("{}:{}", node.start_position().row, node.start_position().column)),
                    }],
                    traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                });
            }
        }
    }

    fn extract_functions(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        let mut cursor = node.walk();
        self.walk_for_functions(&mut cursor, source, report);
    }

    fn walk_for_functions(&self, cursor: &mut tree_sitter::TreeCursor, source: &[u8], report: &mut AnalysisReport) {
        loop {
            let node = cursor.node();

            if node.kind() == "method" {
                if let Ok(text) = node.utf8_text(source) {
                    // Extract method name
                    let name = self.extract_function_name(&node, source).unwrap_or_else(|| "anonymous".to_string());

                    report.functions.push(Function {
                        name,
                        offset: Some(format!("0x{:x}", node.start_byte())),
                        size: Some((node.end_byte() - node.start_byte()) as u64),
                        complexity: None,
                        calls: Vec::new(),
                        source: "tree-sitter-ruby".to_string(),
                        control_flow: None,
                        instruction_analysis: None,
                        register_usage: None,
                        constants: Vec::new(),
                        properties: None,
                    signature: None,
                    nesting: None,
                    call_patterns: None,
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

impl Analyzer for RubyAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = fs::read_to_string(file_path)?;
        self.analyze_source(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path.extension().and_then(|e| e.to_str()) == Some("rb")
    }
}
