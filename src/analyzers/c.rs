use crate::analyzers::Analyzer;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// C analyzer using tree-sitter
pub struct CAnalyzer {
    parser: RefCell<Parser>,
}

impl CAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser.set_language(&tree_sitter_c::LANGUAGE.into()).unwrap();

        Self { parser: RefCell::new(parser) }
    }

    fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the C source
        let tree = self.parser
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
            description: "C source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-c".to_string(),
                value: "c".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        // Detect capabilities and patterns
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-c".to_string()];

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
                "preproc_include" => {
                    self.analyze_include(&node, source, report);
                }
                "asm_statement" => {
                    self.analyze_asm(&node, source, report);
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
            if text.contains("system(") {
                capabilities.push(("exec/command/shell", "system() command execution", "system", 0.95));
            }
            if text.contains("popen(") {
                capabilities.push(("exec/command/shell", "popen() command execution", "popen", 0.9));
            }
            if text.contains("execve(") || text.contains("execv(") || text.contains("execl(") {
                capabilities.push(("exec/program/direct", "exec family program execution", "exec*", 0.9));
            }

            // Buffer overflow risks (dangerous functions)
            if text.contains("strcpy(") {
                capabilities.push(("unsafe/buffer-overflow-risk", "strcpy buffer overflow risk", "strcpy", 0.85));
            }
            if text.contains("strcat(") {
                capabilities.push(("unsafe/buffer-overflow-risk", "strcat buffer overflow risk", "strcat", 0.85));
            }
            if text.contains("gets(") {
                capabilities.push(("unsafe/buffer-overflow-risk", "gets buffer overflow risk", "gets", 0.95));
            }
            if text.contains("sprintf(") {
                capabilities.push(("unsafe/buffer-overflow-risk", "sprintf buffer overflow risk", "sprintf", 0.85));
            }
            if text.contains("vsprintf(") {
                capabilities.push(("unsafe/buffer-overflow-risk", "vsprintf buffer overflow risk", "vsprintf", 0.85));
            }

            // Network operations
            if text.contains("socket(") {
                capabilities.push(("net/socket/create", "Socket creation", "socket", 0.9));
            }
            if text.contains("connect(") {
                capabilities.push(("net/socket/create", "Socket connection", "connect", 0.9));
            }
            if text.contains("bind(") && text.contains("listen(") {
                capabilities.push(("net/socket/server", "Socket server", "bind+listen", 0.9));
            }

            // Memory operations (shellcode indicators)
            if text.contains("mmap(") {
                capabilities.push(("memory/map", "Memory mapping", "mmap", 0.9));
            }
            if text.contains("mprotect(") {
                capabilities.push(("memory/protect", "Change memory protection", "mprotect", 0.95));
            }
            if text.contains("VirtualAlloc(") {
                capabilities.push(("memory/map", "Virtual memory allocation (Windows)", "VirtualAlloc", 0.9));
            }
            if text.contains("VirtualProtect(") {
                capabilities.push(("memory/protect", "Change memory protection (Windows)", "VirtualProtect", 0.95));
            }

            // Classic reverse shell pattern (socket + dup2 + execve)
            if (text.contains("socket") || text.contains("connect")) &&
               (text.contains("dup2") || text.contains("dup")) &&
               (text.contains("execve") || text.contains("/bin/sh")) {
                capabilities.push(("c2/reverse-shell", "Classic reverse shell pattern", "socket+dup2+exec", 0.98));
            }

            // Shellcode execution pattern (mmap + mprotect)
            if text.contains("mmap") && text.contains("mprotect") {
                capabilities.push(("exec/shellcode", "Shellcode execution pattern", "mmap+mprotect", 0.95));
            }
            if text.contains("VirtualAlloc") && text.contains("VirtualProtect") {
                capabilities.push(("exec/shellcode", "Shellcode execution (Windows)", "VirtualAlloc+VirtualProtect", 0.95));
            }

            // Process manipulation
            if text.contains("ptrace(") {
                capabilities.push(("process/debug/attach", "ptrace process debugging", "ptrace", 0.95));
            }
            if text.contains("kill(") {
                capabilities.push(("process/manipulate", "Send signal to process", "kill", 0.9));
            }
            if text.contains("setuid(") || text.contains("setgid(") {
                capabilities.push(("privilege/setuid", "Set user/group ID", "setuid/setgid", 0.95));
            }

            // Dynamic loading
            if text.contains("dlopen(") {
                capabilities.push(("exec/dylib/load", "Dynamic library loading", "dlopen", 0.9));
            }
            if text.contains("dlsym(") {
                capabilities.push(("exec/dylib/resolve", "Resolve dynamic symbol", "dlsym", 0.85));
            }
            if text.contains("LoadLibrary(") {
                capabilities.push(("exec/dylib/load", "Load library (Windows)", "LoadLibrary", 0.9));
            }
            if text.contains("GetProcAddress(") {
                capabilities.push(("exec/dylib/resolve", "Get procedure address (Windows)", "GetProcAddress", 0.85));
            }

            // File operations
            if text.contains("remove(") || text.contains("unlink(") {
                capabilities.push(("fs/delete", "Delete file", "remove/unlink", 0.85));
            }
            if text.contains("chmod(") {
                capabilities.push(("fs/permissions", "Change file permissions", "chmod", 0.85));
            }
            if text.contains("chown(") {
                capabilities.push(("fs/permissions", "Change file ownership", "chown", 0.85));
            }

            // Add capabilities
            for (cap_id, desc, method, conf) in capabilities {
                report.capabilities.push(Capability {
                    id: cap_id.to_string(),
                    description: desc.to_string(),
                    confidence: conf,
                    criticality: Criticality::None,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-c".to_string(),
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

    fn analyze_include(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            let mut capabilities = Vec::new();

            if text.contains("sys/socket.h") || text.contains("netinet/") {
                capabilities.push(("net/socket/create", "Network header include", "socket.h", 0.7));
            }
            if text.contains("sys/ptrace.h") {
                capabilities.push(("process/debug/attach", "ptrace header include", "ptrace.h", 0.75));
            }
            if text.contains("sys/mman.h") {
                capabilities.push(("memory/map", "Memory mapping header", "mman.h", 0.7));
            }
            if text.contains("openssl/") {
                capabilities.push(("crypto/cipher", "OpenSSL header include", "openssl", 0.7));
            }

            for (cap_id, desc, method, conf) in capabilities {
                report.capabilities.push(Capability {
                    id: cap_id.to_string(),
                    description: desc.to_string(),
                    confidence: conf,
                    criticality: Criticality::None,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "include".to_string(),
                        source: "tree-sitter-c".to_string(),
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

    fn analyze_asm(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        // Inline assembly is a strong indicator of low-level operations
        report.capabilities.push(Capability {
            id: "unsafe/inline-asm".to_string(),
            description: "Inline assembly".to_string(),
            confidence: 1.0,
            criticality: Criticality::None,

                                mbc: None,

                                attack: None,

                                evidence: vec![Evidence {
                method: "ast".to_string(),
                source: "tree-sitter-c".to_string(),
                value: "asm".to_string(),
                location: Some(format!("{}:{}", node.start_position().row, node.start_position().column)),
            }],
            traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                });
    }

    fn extract_functions(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        let mut cursor = node.walk();
        self.walk_for_functions(&mut cursor, source, report);
    }

    fn walk_for_functions(&self, cursor: &mut tree_sitter::TreeCursor, source: &[u8], report: &mut AnalysisReport) {
        loop {
            let node = cursor.node();

            if node.kind() == "function_definition" {
                if let Ok(text) = node.utf8_text(source) {
                    // Extract function name
                    let name = self.extract_function_name(&node, source).unwrap_or_else(|| "anonymous".to_string());

                    report.functions.push(Function {
                        name,
                        offset: Some(format!("0x{:x}", node.start_byte())),
                        size: Some((node.end_byte() - node.start_byte()) as u64),
                        complexity: None,
                        calls: Vec::new(),
                        source: "tree-sitter-c".to_string(),
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
                if child.kind() == "function_declarator" {
                    // Find identifier inside declarator
                    let mut decl_cursor = child.walk();
                    if decl_cursor.goto_first_child() {
                        loop {
                            let decl_child = decl_cursor.node();
                            if decl_child.kind() == "identifier" {
                                return decl_child.utf8_text(source).ok().map(|s| s.to_string());
                            }
                            if !decl_cursor.goto_next_sibling() {
                                break;
                            }
                        }
                    }
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

impl Analyzer for CAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = fs::read_to_string(file_path)?;
        self.analyze_source(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path.extension().and_then(|e| e.to_str()) == Some("c")
    }
}
