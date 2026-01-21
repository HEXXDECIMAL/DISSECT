use crate::analyzers::Analyzer;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// Java analyzer using tree-sitter
pub struct JavaAnalyzer {
    parser: RefCell<Parser>,
}

impl JavaAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser.set_language(&tree_sitter_java::LANGUAGE.into()).unwrap();

        Self { parser: RefCell::new(parser) }
    }

    fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the Java source
        let tree = self.parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse Java source")?;

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "java".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "source/language/java".to_string(),
            description: "Java source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-java".to_string(),
                value: "java".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        // Detect capabilities and patterns
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-java".to_string()];

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
                "method_invocation" => {
                    self.analyze_call(&node, source, report);
                }
                "import_declaration" => {
                    self.analyze_import(&node, source, report);
                }
                "object_creation_expression" => {
                    self.analyze_object_creation(&node, source, report);
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

            // Command execution (critical for Java)
            if text.contains("Runtime.exec") || text.contains(".exec(") {
                capabilities.push(("exec/command/shell", "Runtime.exec() command execution", "Runtime.exec", 0.95));
            }

            // Reflection (major attack vector)
            if text.contains("Class.forName") {
                capabilities.push(("anti-analysis/reflection", "Dynamic class loading", "Class.forName", 0.9));
            }
            if text.contains("Method.invoke") || text.contains(".invoke(") {
                capabilities.push(("anti-analysis/reflection", "Dynamic method invocation", "Method.invoke", 0.95));
            }
            if text.contains(".setAccessible") {
                capabilities.push(("anti-analysis/reflection", "Bypass access control", "setAccessible", 0.95));
            }
            if text.contains(".getDeclaredMethod") {
                capabilities.push(("anti-analysis/reflection", "Get private method", "getDeclaredMethod", 0.9));
            }

            // Deserialization (Log4Shell-style)
            if text.contains("ObjectInputStream") || text.contains(".readObject(") {
                capabilities.push(("anti-analysis/deserialization", "Object deserialization", "ObjectInputStream", 0.9));
            }
            if text.contains("XMLDecoder") {
                capabilities.push(("anti-analysis/deserialization", "XML deserialization", "XMLDecoder", 0.9));
            }

            // JNDI injection (Log4Shell vector)
            if (text.contains(".lookup(") || text.contains("InitialContext")) &&
               (text.contains("ldap://") || text.contains("rmi://")) {
                capabilities.push(("jndi/injection", "JNDI injection pattern", "lookup+ldap/rmi", 0.95));
            }

            // JNI/Native methods
            if text.contains("System.loadLibrary") || text.contains("System.load") {
                capabilities.push(("exec/dylib/load", "Native library loading", "System.loadLibrary", 0.9));
            }

            // Reverse shell pattern
            if (text.contains("Socket") || text.contains("connect")) &&
               (text.contains("Runtime.exec") || text.contains("ProcessBuilder") || text.contains("/bin/sh")) {
                capabilities.push(("c2/reverse-shell", "Reverse shell connection", "Socket+exec", 0.98));
            }

            // ClassLoader manipulation (supply chain risk)
            if text.contains("URLClassLoader") || text.contains(".defineClass") {
                capabilities.push(("exec/classloader", "Dynamic class loading", "ClassLoader", 0.9));
            }

            // Script execution
            if text.contains("ScriptEngine") || text.contains("ScriptEngineManager") {
                capabilities.push(("exec/script", "Script engine execution", "ScriptEngine", 0.9));
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
                        source: "tree-sitter-java".to_string(),
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

            if text.contains("java.lang.Runtime") || text.contains("java.lang.ProcessBuilder") {
                capabilities.push(("exec/command/shell", "Process execution import", "Runtime/ProcessBuilder", 0.8));
            }
            if text.contains("java.lang.reflect") {
                capabilities.push(("anti-analysis/reflection", "Reflection import", "reflect", 0.7));
            }
            if text.contains("java.io.ObjectInputStream") {
                capabilities.push(("anti-analysis/deserialization", "Deserialization import", "ObjectInputStream", 0.8));
            }
            if text.contains("javax.naming") {
                capabilities.push(("jndi/import", "JNDI import (injection risk)", "javax.naming", 0.75));
            }
            if text.contains("com.thoughtworks.xstream") {
                capabilities.push(("anti-analysis/deserialization", "XStream deserialization", "xstream", 0.85));
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
                        method: "import".to_string(),
                        source: "tree-sitter-java".to_string(),
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

    fn analyze_object_creation(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            let mut capabilities = Vec::new();

            if text.contains("ProcessBuilder") {
                capabilities.push(("exec/command/shell", "ProcessBuilder creation", "ProcessBuilder", 0.9));
            }
            if text.contains("Socket") {
                capabilities.push(("net/socket/create", "Socket creation", "Socket", 0.85));
            }
            if text.contains("URLClassLoader") {
                capabilities.push(("exec/classloader", "URL class loader", "URLClassLoader", 0.9));
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
                        method: "ast".to_string(),
                        source: "tree-sitter-java".to_string(),
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

            if node.kind() == "method_declaration" {
                if let Ok(text) = node.utf8_text(source) {
                    // Extract method name
                    let name = self.extract_function_name(&node, source).unwrap_or_else(|| "anonymous".to_string());

                    // Check for native methods
                    if text.contains("native ") {
                        report.capabilities.push(Capability {
                            id: "jni/native-method".to_string(),
                            description: format!("Native method: {}", name),
                            confidence: 0.95,
                            criticality: Criticality::None,

                                                mbc: None,

                                                attack: None,

                                                evidence: vec![Evidence {
                                method: "ast".to_string(),
                                source: "tree-sitter-java".to_string(),
                                value: "native".to_string(),
                                location: Some(format!("{}:{}", node.start_position().row, node.start_position().column)),
                            }],
                            traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                });
                    }

                    report.functions.push(Function {
                        name,
                        offset: Some(format!("0x{:x}", node.start_byte())),
                        size: Some((node.end_byte() - node.start_byte()) as u64),
                        complexity: None,
                        calls: Vec::new(),
                        source: "tree-sitter-java".to_string(),
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

impl Analyzer for JavaAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = fs::read_to_string(file_path)?;
        self.analyze_source(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path.extension().and_then(|e| e.to_str()) == Some("java")
    }
}
