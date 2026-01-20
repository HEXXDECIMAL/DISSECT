use crate::analyzers::Analyzer;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// Rust analyzer using tree-sitter
pub struct RustAnalyzer {
    parser: RefCell<Parser>,
}

impl RustAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser.set_language(&tree_sitter_rust::LANGUAGE.into()).unwrap();

        Self { parser: RefCell::new(parser) }
    }

    fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the Rust source
        let tree = self.parser
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

        // Detect capabilities and patterns
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-rust".to_string()];

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

            // Command execution
            if text.contains("Command::new") {
                capabilities.push(("exec/command/shell", "Executes shell commands", "Command::new", 0.95));
            }

            // Network operations
            if text.contains("TcpStream::connect") {
                capabilities.push(("net/socket/create", "TCP connection", "TcpStream::connect", 0.9));
            }
            if text.contains("TcpListener::bind") {
                capabilities.push(("net/socket/server", "TCP server", "TcpListener::bind", 0.9));
            }

            // File operations
            if text.contains("fs::remove_dir_all") {
                capabilities.push(("fs/delete", "Recursive directory deletion", "remove_dir_all", 0.95));
            }
            if text.contains("fs::remove_file") {
                capabilities.push(("fs/delete", "Delete file", "remove_file", 0.9));
            }

            // Reverse shell pattern
            if (text.contains("TcpStream::connect") || text.contains("TcpStream")) &&
               (text.contains("Command::new") || text.contains("/bin/sh") || text.contains("cmd.exe")) {
                capabilities.push(("c2/reverse-shell", "Reverse shell connection", "TcpStream+Command", 0.98));
            }

            // Ransomware indicators
            if (text.contains("aes") || text.contains("cipher")) &&
               (text.contains("walkdir") || text.contains("read_dir")) {
                capabilities.push(("crypto/ransomware/encrypt", "File encryption pattern", "crypto+walk", 0.92));
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
                        source: "tree-sitter-rust".to_string(),
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

    fn analyze_import(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            let mut capabilities = Vec::new();

            if text.contains("std::process") || text.contains("std::process::Command") {
                capabilities.push(("exec/command/shell", "Process execution import", "std::process", 0.8));
            }
            if text.contains("std::net") {
                capabilities.push(("net/socket/create", "Network import", "std::net", 0.7));
            }
            if text.contains("libc") {
                capabilities.push(("exec/syscall", "Low-level system calls", "libc", 0.8));
            }
            if text.contains("libloading") || text.contains("dlopen") {
                capabilities.push(("exec/dylib/load", "Dynamic library loading", "libloading", 0.9));
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
                        source: "tree-sitter-rust".to_string(),
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

    fn analyze_unsafe(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            // Any unsafe block is noteworthy
            report.capabilities.push(Capability {
                id: "unsafe/block".to_string(),
                description: "Unsafe code block".to_string(),
                confidence: 1.0,
                criticality: Criticality::None,

                                    mbc_id: None,

                                    attack_id: None,

                                    evidence: vec![Evidence {
                    method: "ast".to_string(),
                    source: "tree-sitter-rust".to_string(),
                    value: "unsafe block".to_string(),
                    location: Some(format!("{}:{}", node.start_position().row, node.start_position().column)),
                }],
                traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                });

            // Check for specific unsafe operations
            if text.contains("transmute") {
                report.capabilities.push(Capability {
                    id: "unsafe/transmute".to_string(),
                    description: "Type transmutation (unsafe cast)".to_string(),
                    confidence: 0.95,
                    criticality: Criticality::None,

                                        mbc_id: None,

                                        attack_id: None,

                                        evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-rust".to_string(),
                        value: "transmute".to_string(),
                        location: Some(format!("{}:{}", node.start_position().row, node.start_position().column)),
                    }],
                    traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                });
            }

            if text.contains("*const") || text.contains("*mut") {
                report.capabilities.push(Capability {
                    id: "unsafe/pointer".to_string(),
                    description: "Raw pointer operations".to_string(),
                    confidence: 0.9,
                    criticality: Criticality::None,

                                        mbc_id: None,

                                        attack_id: None,

                                        evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-rust".to_string(),
                        value: "raw pointers".to_string(),
                        location: Some(format!("{}:{}", node.start_position().row, node.start_position().column)),
                    }],
                    traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                });
            }

            if text.contains("asm!") || text.contains("global_asm!") {
                report.capabilities.push(Capability {
                    id: "unsafe/inline-asm".to_string(),
                    description: "Inline assembly".to_string(),
                    confidence: 1.0,
                    criticality: Criticality::None,

                                        mbc_id: None,

                                        attack_id: None,

                                        evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-rust".to_string(),
                        value: "asm!".to_string(),
                        location: Some(format!("{}:{}", node.start_position().row, node.start_position().column)),
                    }],
                    traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                });
            }

            // FFI detection
            if text.contains("extern \"C\"") || text.contains("extern \"system\"") {
                report.capabilities.push(Capability {
                    id: "unsafe/ffi".to_string(),
                    description: "Foreign function interface (C boundary)".to_string(),
                    confidence: 0.95,
                    criticality: Criticality::None,

                                        mbc_id: None,

                                        attack_id: None,

                                        evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-rust".to_string(),
                        value: "extern".to_string(),
                        location: Some(format!("{}:{}", node.start_position().row, node.start_position().column)),
                    }],
                    traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                });
            }
        }
    }

    fn analyze_macro(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            if text.contains("asm!") || text.contains("global_asm!") {
                report.capabilities.push(Capability {
                    id: "unsafe/inline-asm".to_string(),
                    description: "Inline assembly macro".to_string(),
                    confidence: 1.0,
                    criticality: Criticality::None,

                                        mbc_id: None,

                                        attack_id: None,

                                        evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-rust".to_string(),
                        value: text.split('!').next().unwrap_or("asm").to_string(),
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

            if node.kind() == "function_item" {
                if let Ok(text) = node.utf8_text(source) {
                    // Extract function name
                    let name = self.extract_function_name(&node, source).unwrap_or_else(|| "anonymous".to_string());

                    report.functions.push(Function {
                        name,
                        offset: Some(format!("0x{:x}", node.start_byte())),
                        size: Some((node.end_byte() - node.start_byte()) as u64),
                        complexity: None,
                        calls: Vec::new(),
                        source: "tree-sitter-rust".to_string(),
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

impl Analyzer for RustAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = fs::read_to_string(file_path)?;
        self.analyze_source(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path.extension().and_then(|e| e.to_str()) == Some("rs")
    }
}
