use crate::analyzers::Analyzer;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// PowerShell analyzer using tree-sitter
pub struct PowerShellAnalyzer {
    parser: RefCell<Parser>,
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
        }
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
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        report.structure.push(StructuralFeature {
            id: "source/language/powershell".to_string(),
            description: "PowerShell script".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-powershell".to_string(),
                value: "powershell".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        self.detect_capabilities(&root, content.as_bytes(), &mut report);
        self.detect_string_patterns(content, &mut report);
        self.extract_functions(&root, content.as_bytes(), &mut report);

        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-powershell".to_string()];

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

            if matches!(node.kind(), "command" | "command_expression" | "pipeline") {
                self.analyze_command(&node, source, report);
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
            report.capabilities.push(Capability {
                id: cap_id.to_string(),
                description: desc.to_string(),
                confidence: conf,
                criticality,
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
                traits: Vec::new(),
                referenced_paths: None,
                referenced_directories: None,
            });
        }
    }

    fn detect_string_patterns(&self, content: &str, report: &mut AnalysisReport) {
        let content_lower = content.to_lowercase();

        // Base64 encoded commands
        if content_lower.contains("-encodedcommand") || content_lower.contains("-enc ") {
            report.capabilities.push(Capability {
                id: "anti-analysis/obfuscation/base64".to_string(),
                description: "Base64 encoded command".to_string(),
                confidence: 0.95,
                criticality: Criticality::Suspicious,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "pattern".to_string(),
                    source: "string-search".to_string(),
                    value: "-EncodedCommand".to_string(),
                    location: None,
                }],
                traits: Vec::new(),
                referenced_paths: None,
                referenced_directories: None,
            });
        }

        // Stealthy execution pattern
        if content_lower.contains("-nop") && content_lower.contains("-w hidden") {
            report.capabilities.push(Capability {
                id: "evasion/stealthy-execution".to_string(),
                description: "Stealthy execution flags".to_string(),
                confidence: 0.95,
                criticality: Criticality::Hostile,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "pattern".to_string(),
                    source: "string-search".to_string(),
                    value: "-nop -w hidden".to_string(),
                    location: None,
                }],
                traits: Vec::new(),
                referenced_paths: None,
                referenced_directories: None,
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

    fn calculate_sha256(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

impl Analyzer for PowerShellAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = fs::read_to_string(file_path)?;
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
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "exec/script/eval"));
    }

    #[test]
    fn test_detect_encoded_command() {
        let code = r#"powershell -EncodedCommand JABjAG8AZABlAA=="#;
        let report = analyze_ps_code(code);
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/base64"));
    }
}
