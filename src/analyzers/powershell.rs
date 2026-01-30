//! PowerShell script analyzer.

use crate::analyzers::Analyzer;
use crate::analyzers::{
    comment_metrics::{self, CommentStyle},
    function_metrics::{self, FunctionInfo},
    identifier_metrics, string_metrics, symbol_extraction, text_metrics,
};
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// PowerShell analyzer using tree-sitter
pub struct PowerShellAnalyzer {
    parser: RefCell<Parser>,
    capability_mapper: CapabilityMapper,
}

impl Default for PowerShellAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl PowerShellAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_powershell::LANGUAGE.into())
            .expect("Failed to load PowerShell grammar");

        Self {
            parser: RefCell::new(parser),
            capability_mapper: CapabilityMapper::empty(),
        }
    }

    pub fn with_capability_mapper(mut self, capability_mapper: CapabilityMapper) -> Self {
        self.capability_mapper = capability_mapper;
        self
    }

    fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        let tree = self
            .parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse PowerShell source")?;

        let root = tree.root_node();

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "powershell".to_string(),
            size_bytes: content.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        report
            .structure
            .push(crate::analyzers::utils::create_language_feature(
                "powershell",
                "tree-sitter-powershell",
                "PowerShell script",
            ));

        self.detect_capabilities(&root, content.as_bytes(), &mut report);
        self.detect_string_patterns(content, &mut report);
        self.extract_functions(&root, content.as_bytes(), &mut report);
        self.extract_strings_to_report(&root, content.as_bytes(), &mut report);

        // Extract command calls as symbols for symbol-based rule matching
        symbol_extraction::extract_symbols(
            content,
            tree_sitter_powershell::LANGUAGE.into(),
            &["command_expression", "invocation_expression"],
            &mut report,
        );

        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);

        // Compute metrics for ML analysis
        let metrics = self.compute_metrics(&root, content);
        report.metrics = Some(metrics);

        // Evaluate all rules (atomic + composite) and merge into report
        self.capability_mapper.evaluate_and_merge_findings(
            &mut report,
            content.as_bytes(),
            Some(&tree),
        );

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-powershell".to_string()];

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

        // PowerShell uses # for comments
        let comment_metrics = comment_metrics::analyze_comments(content, CommentStyle::Hash);

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
            if node.kind() == "simple_variable" || node.kind() == "variable" {
                if let Ok(text) = node.utf8_text(source) {
                    let name = text.trim_start_matches('$');
                    if !name.is_empty() {
                        identifiers.push(name.to_string());
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
            if node.kind() == "expandable_string_literal"
                || node.kind() == "verbatim_string_literal"
            {
                if let Ok(text) = node.utf8_text(source) {
                    let s = text
                        .trim_start_matches('"')
                        .trim_end_matches('"')
                        .trim_start_matches('\'')
                        .trim_end_matches('\'')
                        .trim_start_matches("@\"")
                        .trim_end_matches("\"@");
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

            if kind == "function_statement" {
                let mut info = FunctionInfo::default();
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(source) {
                        info.name = name.to_string();
                    }
                }
                // Get parameters
                if let Some(params_node) = node.child_by_field_name("parameters") {
                    let mut param_cursor = params_node.walk();
                    if param_cursor.goto_first_child() {
                        loop {
                            let param = param_cursor.node();
                            if param.kind() == "parameter" || param.kind() == "simple_variable" {
                                info.param_count += 1;
                                if let Ok(name) = param.utf8_text(source) {
                                    let param_name = name.trim_start_matches('$');
                                    if !param_name.is_empty() {
                                        info.param_names.push(param_name.to_string());
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
                if kind == "function_statement" {
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
                // Check if we're leaving a function_statement to decrement depth
                if cursor.node().kind() == "function_statement" {
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

            if matches!(node.kind(), "command" | "command_expression" | "pipeline") {
                self.analyze_command(&node, source, report);
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

    fn analyze_command(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let text = node.utf8_text(source).unwrap_or("");
        let text_lower = text.to_lowercase();
        let mut capabilities: Vec<(&str, &str, &str, f32, Criticality)> = Vec::new();

        // Code execution
        if text_lower.contains("invoke-expression") || text_lower.contains("iex ") {
            capabilities.push((
                "exec/script/eval",
                "Invoke-Expression (code execution)",
                "Invoke-Expression",
                0.95,
                Criticality::Suspicious,
            ));
        }
        if text_lower.contains("start-process") {
            capabilities.push((
                "exec/command/process",
                "Process execution",
                "Start-Process",
                0.9,
                Criticality::Suspicious,
            ));
        }

        // Download operations
        if text_lower.contains("invoke-webrequest") || text_lower.contains("iwr ") {
            capabilities.push((
                "net/http/download",
                "Web request/download",
                "Invoke-WebRequest",
                0.9,
                Criticality::Suspicious,
            ));
        }
        if text_lower.contains("downloadstring") || text_lower.contains("downloadfile") {
            capabilities.push((
                "net/http/download",
                "Download operation",
                "DownloadString/File",
                0.95,
                Criticality::Suspicious,
            ));
        }

        // Registry
        if text_lower.contains("registry::")
            || text_lower.contains("hklm:")
            || text_lower.contains("hkcu:")
        {
            capabilities.push((
                "registry/access",
                "Registry access",
                "Registry",
                0.85,
                Criticality::Notable,
            ));
        }

        // Bypass/Evasion
        if text_lower.contains("-executionpolicy bypass") || text_lower.contains("-ep bypass") {
            capabilities.push((
                "evasion/execution-policy",
                "Execution policy bypass",
                "ExecutionPolicy",
                0.95,
                Criticality::Suspicious,
            ));
        }
        if text_lower.contains("-windowstyle hidden") {
            capabilities.push((
                "evasion/hidden-window",
                "Hidden window execution",
                "Hidden",
                0.9,
                Criticality::Suspicious,
            ));
        }

        // Download+execute pattern
        if (text_lower.contains("downloadstring") || text_lower.contains("invoke-webrequest"))
            && (text_lower.contains("invoke-expression") || text_lower.contains("iex"))
        {
            capabilities.push((
                "c2/download-execute",
                "Download and execute pattern",
                "download+iex",
                0.98,
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
                    source: "tree-sitter-powershell".to_string(),
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

    fn detect_string_patterns(&self, content: &str, report: &mut AnalysisReport) {
        let content_lower = content.to_lowercase();

        // Base64 encoded commands
        if content_lower.contains("-encodedcommand") || content_lower.contains("-enc ") {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "anti-analysis/obfuscation/base64".to_string(),
                desc: "Base64 encoded command".to_string(),
                conf: 0.95,
                crit: Criticality::Suspicious,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "pattern".to_string(),
                    source: "string-search".to_string(),
                    value: "-EncodedCommand".to_string(),
                    location: None,
                }],
            });
        }

        // Stealthy execution pattern
        if content_lower.contains("-nop") && content_lower.contains("-w hidden") {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "evasion/stealthy-execution".to_string(),
                desc: "Stealthy execution flags".to_string(),
                conf: 0.95,
                crit: Criticality::Hostile,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "pattern".to_string(),
                    source: "string-search".to_string(),
                    value: "-nop -w hidden".to_string(),
                    location: None,
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

            if node.kind() == "function_statement" || node.kind() == "function_definition" {
                let name = self
                    .extract_function_name(&node, source)
                    .unwrap_or_else(|| "anonymous".to_string());

                report.functions.push(Function {
                    name,
                    offset: Some(format!("0x{:x}", node.start_byte())),
                    size: Some((node.end_byte() - node.start_byte()) as u64),
                    complexity: None,
                    calls: Vec::new(),
                    source: "tree-sitter-powershell".to_string(),
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
                if child.kind() == "simple_name" || child.kind() == "identifier" {
                    return child.utf8_text(source).ok().map(|s| s.to_string());
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        None
    }

    fn extract_strings_to_report(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let mut cursor = root.walk();
        loop {
            let node = cursor.node();

            if node.kind() == "string_literal"
                || node.kind() == "verbatim_string_literal"
                || node.kind() == "expandable_string_literal"
            {
                if let Ok(text) = node.utf8_text(source) {
                    let s = text
                        .trim_start_matches('"')
                        .trim_end_matches('"')
                        .trim_start_matches('\'')
                        .trim_end_matches('\'')
                        .trim_start_matches('@');
                    if !s.is_empty() && !s.starts_with('"') {
                        report.strings.push(StringInfo {
                            value: s.to_string(),
                            offset: Some(format!("0x{:x}", node.start_byte())),
                            string_type: StringType::Literal,
                            encoding: "utf-8".to_string(),
                            section: Some("ast".to_string()),
                        });
                    }
                }
            }

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
}

impl Analyzer for PowerShellAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let bytes = fs::read(file_path).context("Failed to read PowerShell file")?;
        let content = String::from_utf8_lossy(&bytes);
        self.analyze_source(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        matches!(
            file_path.extension().and_then(|e| e.to_str()),
            Some("ps1" | "psm1" | "psd1")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn analyze_ps_code(code: &str) -> AnalysisReport {
        let analyzer = PowerShellAnalyzer::new();
        let path = PathBuf::from("test.ps1");
        analyzer.analyze_source(&path, code).unwrap()
    }

    #[test]
    fn test_structural_feature() {
        let code = r#"Write-Host "Hello""#;
        let report = analyze_ps_code(code);
        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/powershell"));
    }

    #[test]
    fn test_detect_invoke_expression() {
        let code = r#"Invoke-Expression $code"#;
        let report = analyze_ps_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/script/eval"));
    }

    #[test]
    fn test_detect_encoded_command() {
        let code = r#"powershell -EncodedCommand JABjAG8AZABlAA=="#;
        let report = analyze_ps_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/base64"));
    }
}
