use crate::analyzers::Analyzer;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// Perl analyzer using tree-sitter
pub struct PerlAnalyzer {
    parser: RefCell<Parser>,
}

impl Default for PerlAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl PerlAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_perl::LANGUAGE.into())
            .expect("Failed to load Perl grammar");

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
            .context("Failed to parse Perl source")?;

        let root = tree.root_node();

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "perl".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        report.structure.push(StructuralFeature {
            id: "source/language/perl".to_string(),
            description: "Perl source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-perl".to_string(),
                value: "perl".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        self.detect_capabilities(&root, content.as_bytes(), &mut report);
        self.detect_string_patterns(content, &mut report);
        self.extract_functions(&root, content.as_bytes(), &mut report);

        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-perl".to_string()];

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
                "function_call" | "method_call" => {
                    self.analyze_call(&node, source, report);
                }
                "backtick_string" | "command_string" => {
                    self.analyze_backtick(&node, source, report);
                }
                "use_statement" | "require_statement" => {
                    self.analyze_use(&node, source, report);
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
        if text.starts_with("system") || text.starts_with("exec") {
            capabilities.push((
                "exec/command/shell",
                "Command execution",
                "system/exec",
                0.95,
                Criticality::Suspicious,
            ));
        }

        // Code execution
        if text.starts_with("eval") {
            capabilities.push((
                "exec/script/eval",
                "Dynamic code execution",
                "eval",
                0.95,
                Criticality::Suspicious,
            ));
        }

        // File operations with pipe (command execution)
        if text.starts_with("open")
            && (text.contains('|') || text.contains("|-") || text.contains("-|"))
        {
            capabilities.push((
                "exec/command/pipe",
                "Pipe open (command execution)",
                "open|",
                0.95,
                Criticality::Suspicious,
            ));
        }

        // Network operations
        if text.contains("socket") || text.contains("IO::Socket") {
            capabilities.push((
                "net/socket/create",
                "Socket creation",
                "socket",
                0.85,
                Criticality::Suspicious,
            ));
        }

        // File operations
        if text.starts_with("unlink") || text.starts_with("rmdir") {
            capabilities.push((
                "fs/delete",
                "File/directory deletion",
                "unlink/rmdir",
                0.85,
                Criticality::Notable,
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
                    source: "tree-sitter-perl".to_string(),
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

    fn analyze_backtick(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        report.capabilities.push(Capability {
            id: "exec/command/shell".to_string(),
            description: "Backtick command execution".to_string(),
            confidence: 0.95,
            criticality: Criticality::Suspicious,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "ast".to_string(),
                source: "tree-sitter-perl".to_string(),
                value: node.utf8_text(source).unwrap_or("``").to_string(),
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

    fn analyze_use(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        let text = node.utf8_text(source).unwrap_or("");

        if text.contains("IO::Socket") {
            report.capabilities.push(Capability {
                id: "net/socket/import".to_string(),
                description: "Socket module import".to_string(),
                confidence: 0.8,
                criticality: Criticality::Notable,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "import".to_string(),
                    source: "tree-sitter-perl".to_string(),
                    value: "IO::Socket".to_string(),
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
        // Command execution: system(), exec()
        if content.contains("system(") || content.contains("exec(") {
            report.capabilities.push(Capability {
                id: "exec/command/shell".to_string(),
                description: "Command execution".to_string(),
                confidence: 0.95,
                criticality: Criticality::Suspicious,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "pattern".to_string(),
                    source: "string-search".to_string(),
                    value: "system/exec".to_string(),
                    location: None,
                }],
                traits: Vec::new(),
                referenced_paths: None,
                referenced_directories: None,
            });
        }

        // eval()
        if content.contains("eval(") || content.contains("eval $") {
            report.capabilities.push(Capability {
                id: "exec/script/eval".to_string(),
                description: "Dynamic code execution".to_string(),
                confidence: 0.95,
                criticality: Criticality::Suspicious,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "pattern".to_string(),
                    source: "string-search".to_string(),
                    value: "eval".to_string(),
                    location: None,
                }],
                traits: Vec::new(),
                referenced_paths: None,
                referenced_directories: None,
            });
        }

        // Backticks
        if content.contains('`') {
            report.capabilities.push(Capability {
                id: "exec/command/shell".to_string(),
                description: "Backtick command execution".to_string(),
                confidence: 0.95,
                criticality: Criticality::Suspicious,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "pattern".to_string(),
                    source: "string-search".to_string(),
                    value: "backticks".to_string(),
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

            if node.kind() == "subroutine_declaration" || node.kind() == "function_definition" {
                let name = self
                    .extract_function_name(&node, source)
                    .unwrap_or_else(|| "anonymous".to_string());

                report.functions.push(Function {
                    name,
                    offset: Some(format!("0x{:x}", node.start_byte())),
                    size: Some((node.end_byte() - node.start_byte()) as u64),
                    complexity: None,
                    calls: Vec::new(),
                    source: "tree-sitter-perl".to_string(),
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
                if child.kind() == "identifier" || child.kind() == "name" {
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

impl Analyzer for PerlAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = fs::read_to_string(file_path)?;
        self.analyze_source(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        matches!(
            file_path.extension().and_then(|e| e.to_str()),
            Some("pl" | "pm" | "t")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn analyze_perl_code(code: &str) -> AnalysisReport {
        let analyzer = PerlAnalyzer::new();
        let path = PathBuf::from("test.pl");
        analyzer.analyze_source(&path, code).unwrap()
    }

    #[test]
    fn test_structural_feature() {
        let code = r#"#!/usr/bin/perl
print "Hello\n";
"#;
        let report = analyze_perl_code(code);
        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/perl"));
    }

    #[test]
    fn test_detect_system() {
        let code = r#"system("whoami");"#;
        let report = analyze_perl_code(code);
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_backticks() {
        let code = r#"my $out = `ls -la`;"#;
        let report = analyze_perl_code(code);
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_eval() {
        let code = r#"eval($code);"#;
        let report = analyze_perl_code(code);
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "exec/script/eval"));
    }
}
