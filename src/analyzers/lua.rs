use crate::analyzers::Analyzer;
use crate::analyzers::{
    comment_metrics::{self, CommentStyle},
    function_metrics::{self, FunctionInfo},
    identifier_metrics, string_metrics, text_metrics,
};
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// Lua analyzer using tree-sitter
pub struct LuaAnalyzer {
    parser: RefCell<Parser>,
}

impl Default for LuaAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl LuaAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_lua::LANGUAGE.into())
            .expect("Failed to load Lua grammar");

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
            .context("Failed to parse Lua source")?;

        let root = tree.root_node();

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "lua".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        report.structure.push(StructuralFeature {
            id: "source/language/lua".to_string(),
            description: "Lua source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-lua".to_string(),
                value: "lua".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        self.detect_capabilities(&root, content.as_bytes(), &mut report);
        self.extract_functions(&root, content.as_bytes(), &mut report);

        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);

        // Compute metrics for ML analysis
        let metrics = self.compute_metrics(&root, content);
        report.metrics = Some(metrics);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-lua".to_string()];

        Ok(report)
    }

    /// Compute all metrics for Lua code
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

        // Lua uses -- for comments
        let comment_metrics = comment_metrics::analyze_comments(content, CommentStyle::Lua);

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
                self.walk_for_identifiers(cursor, source, identifiers);
                cursor.goto_parent();
            }
            if !cursor.goto_next_sibling() {
                break;
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
        loop {
            let node = cursor.node();
            if node.kind() == "string" {
                if let Ok(text) = node.utf8_text(source) {
                    let s = text.trim_start_matches('"').trim_end_matches('"')
                        .trim_start_matches('\'').trim_end_matches('\'')
                        .trim_start_matches("[[").trim_end_matches("]]");
                    if !s.is_empty() {
                        strings.push(s.to_string());
                    }
                }
            }
            if cursor.goto_first_child() {
                self.walk_for_strings(cursor, source, strings);
                cursor.goto_parent();
            }
            if !cursor.goto_next_sibling() {
                break;
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
        loop {
            let node = cursor.node();
            let kind = node.kind();

            if kind == "function_declaration" || kind == "function_definition" {
                let mut info = FunctionInfo::default();
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(source) {
                        info.name = name.to_string();
                    }
                }
                // Check if anonymous
                info.is_anonymous = info.name.is_empty();

                // Get parameters
                if let Some(params_node) = node.child_by_field_name("parameters") {
                    let mut param_cursor = params_node.walk();
                    if param_cursor.goto_first_child() {
                        loop {
                            let param = param_cursor.node();
                            if param.kind() == "identifier" {
                                info.param_count += 1;
                                if let Ok(name) = param.utf8_text(source) {
                                    if !name.is_empty() && name != "," {
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
                let new_depth = if kind == "function_declaration" || kind == "function_definition" {
                    depth + 1
                } else {
                    depth
                };
                self.walk_for_function_info(cursor, source, functions, new_depth);
                cursor.goto_parent();
            }
            if !cursor.goto_next_sibling() {
                break;
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
        loop {
            let node = cursor.node();

            match node.kind() {
                "function_call" => {
                    self.analyze_call(&node, source, report);
                }
                "method_index_expression" => {
                    self.analyze_method(&node, source, report);
                }
                _ => {}
            }

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
        let text = node.utf8_text(source).unwrap_or("");
        let mut capabilities: Vec<(&str, &str, &str, f32, Criticality)> = Vec::new();

        // Command execution
        if text.starts_with("os.execute") {
            capabilities.push((
                "exec/command/shell",
                "OS command execution",
                "os.execute",
                0.95,
                Criticality::Suspicious,
            ));
        }
        if text.starts_with("io.popen") {
            capabilities.push((
                "exec/command/shell",
                "Pipe command execution",
                "io.popen",
                0.95,
                Criticality::Suspicious,
            ));
        }

        // Code execution
        if text.starts_with("loadstring") || text.starts_with("load(") {
            capabilities.push((
                "exec/script/eval",
                "Dynamic code loading",
                "loadstring/load",
                0.95,
                Criticality::Suspicious,
            ));
        }
        if text.starts_with("loadfile") {
            capabilities.push((
                "exec/script/include",
                "Dynamic file loading",
                "loadfile",
                0.9,
                Criticality::Suspicious,
            ));
        }
        if text.starts_with("dofile") {
            capabilities.push((
                "exec/script/include",
                "Execute file",
                "dofile",
                0.9,
                Criticality::Suspicious,
            ));
        }

        // File operations
        if text.starts_with("io.open") {
            capabilities.push((
                "fs/open",
                "File open operation",
                "io.open",
                0.8,
                Criticality::Notable,
            ));
        }
        if text.starts_with("io.read") || text.contains(":read") {
            capabilities.push((
                "fs/read",
                "File read operation",
                "io.read",
                0.75,
                Criticality::Inert,
            ));
        }
        if text.starts_with("io.write") || text.contains(":write") {
            capabilities.push((
                "fs/write",
                "File write operation",
                "io.write",
                0.8,
                Criticality::Notable,
            ));
        }
        if text.starts_with("os.remove") {
            capabilities.push((
                "fs/delete",
                "File deletion",
                "os.remove",
                0.85,
                Criticality::Notable,
            ));
        }
        if text.starts_with("os.rename") {
            capabilities.push((
                "fs/modify",
                "File rename",
                "os.rename",
                0.8,
                Criticality::Notable,
            ));
        }

        // Environment
        if text.starts_with("os.getenv") {
            capabilities.push((
                "env/read",
                "Environment variable access",
                "os.getenv",
                0.7,
                Criticality::Inert,
            ));
        }
        if text.starts_with("os.setenv") {
            capabilities.push((
                "env/write",
                "Environment variable modification",
                "os.setenv",
                0.75,
                Criticality::Notable,
            ));
        }
        if text.starts_with("os.exit") {
            capabilities.push((
                "process/exit",
                "Process termination",
                "os.exit",
                0.7,
                Criticality::Inert,
            ));
        }

        // Network (LuaSocket)
        if text.contains("socket.tcp") || text.contains("socket.udp") {
            capabilities.push((
                "net/socket/create",
                "Socket creation",
                "socket.tcp/udp",
                0.85,
                Criticality::Suspicious,
            ));
        }
        if text.contains("socket.connect") || text.contains(":connect") {
            capabilities.push((
                "net/socket/connect",
                "Socket connection",
                "connect",
                0.85,
                Criticality::Notable,
            ));
        }
        if text.contains("socket.bind") || text.contains(":bind") {
            capabilities.push((
                "net/socket/listen",
                "Socket binding",
                "bind",
                0.9,
                Criticality::Suspicious,
            ));
        }
        if text.contains("http.request") {
            capabilities.push((
                "net/http/client",
                "HTTP request",
                "http.request",
                0.85,
                Criticality::Notable,
            ));
        }

        // FFI (LuaJIT Foreign Function Interface)
        if text.starts_with("ffi.cdef") || text.starts_with("ffi.load") {
            capabilities.push((
                "exec/ffi",
                "Foreign function interface",
                "ffi",
                0.9,
                Criticality::Suspicious,
            ));
        }
        if text.starts_with("ffi.C") {
            capabilities.push((
                "exec/ffi/c",
                "C library access via FFI",
                "ffi.C",
                0.9,
                Criticality::Suspicious,
            ));
        }

        // Require (module loading)
        if text.starts_with("require") {
            let module = text
                .trim_start_matches("require")
                .trim()
                .trim_matches(|c| c == '(' || c == ')' || c == '"' || c == '\'');

            let (cap_id, desc, criticality) = match module {
                m if m.contains("socket") => (
                    "net/socket/import",
                    "Socket module import",
                    Criticality::Notable,
                ),
                m if m.contains("http") => (
                    "net/http/import",
                    "HTTP module import",
                    Criticality::Notable,
                ),
                m if m.contains("ffi") => (
                    "exec/ffi/import",
                    "FFI module import",
                    Criticality::Suspicious,
                ),
                m if m.contains("os") => ("os/import", "OS module import", Criticality::Notable),
                m if m.contains("io") => ("fs/import", "IO module import", Criticality::Inert),
                _ => ("module/import", "Module import", Criticality::Inert),
            };

            capabilities.push((cap_id, desc, module, 0.7, criticality));
        }

        // Obfuscation patterns
        if text.contains("string.char") {
            capabilities.push((
                "anti-analysis/obfuscation/char",
                "Character code construction",
                "string.char",
                0.6,
                Criticality::Notable,
            ));
        }
        if text.contains("string.byte") {
            capabilities.push((
                "data/string-byte",
                "String to byte conversion",
                "string.byte",
                0.5,
                Criticality::Inert,
            ));
        }

        // Debug library (can be used for introspection)
        if text.starts_with("debug.") {
            capabilities.push((
                "anti-analysis/debug",
                "Debug library usage",
                "debug",
                0.7,
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
                    method: "ast".to_string(),
                    source: "tree-sitter-lua".to_string(),
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

    fn analyze_method(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        let text = node.utf8_text(source).unwrap_or("");

        // Check for socket methods
        if text.contains(":send") || text.contains(":receive") {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "net/socket/io".to_string(),
                description: "Socket I/O operation".to_string(),
                confidence: 0.8,
                criticality: Criticality::Notable,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "ast".to_string(),
                    source: "tree-sitter-lua".to_string(),
                    value: "send/receive".to_string(),
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
        loop {
            let node = cursor.node();

            if node.kind() == "function_declaration" || node.kind() == "local_function" {
                let name = self
                    .extract_function_name(&node, source)
                    .unwrap_or_else(|| "anonymous".to_string());

                report.functions.push(Function {
                    name,
                    offset: Some(format!("0x{:x}", node.start_byte())),
                    size: Some((node.end_byte() - node.start_byte()) as u64),
                    complexity: None,
                    calls: Vec::new(),
                    source: "tree-sitter-lua".to_string(),
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
                if child.kind() == "identifier" || child.kind() == "function_name" {
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

impl Analyzer for LuaAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = fs::read_to_string(file_path)?;
        self.analyze_source(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path.extension().and_then(|e| e.to_str()) == Some("lua")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn analyze_lua_code(code: &str) -> AnalysisReport {
        let analyzer = LuaAnalyzer::new();
        let path = PathBuf::from("test.lua");
        analyzer.analyze_source(&path, code).unwrap()
    }

    #[test]
    fn test_structural_feature() {
        let code = r#"print("Hello")"#;
        let report = analyze_lua_code(code);
        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/lua"));
    }

    #[test]
    fn test_detect_os_execute() {
        let code = r#"os.execute("whoami")"#;
        let report = analyze_lua_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_loadstring() {
        let code = r#"loadstring(code)()"#;
        let report = analyze_lua_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/script/eval"));
    }

    #[test]
    fn test_detect_io_popen() {
        let code = r#"local f = io.popen("ls")"#;
        let report = analyze_lua_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_file_operations() {
        let code = r#"
            local f = io.open("test.txt", "w")
            f:write("data")
            f:close()
        "#;
        let report = analyze_lua_code(code);
        assert!(report.findings.iter().any(|c| c.id == "fs/open"));
    }
}
