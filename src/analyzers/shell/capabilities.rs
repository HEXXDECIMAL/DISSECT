//! Shell capability detection.

use crate::types::*;
use tree_sitter;

impl super::ShellAnalyzer {
    pub(super) fn detect_capabilities(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let mut cursor = node.walk();

        // Walk the AST looking for command invocations
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
                "command" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        if let Ok(cmd_name) = name_node.utf8_text(source) {
                            self.analyze_command(cmd_name, &node, source, report);
                        }
                    }
                }
                "function_definition" => {
                    // Already handled by extract_functions
                }
                "variable_assignment" => {
                    self.check_obfuscation(&node, source, report);
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

    fn analyze_command(
        &self,
        cmd: &str,
        node: &tree_sitter::Node,
        _source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let capability = match cmd {
            "curl" | "wget" => Some((
                "net/http/client",
                "Download files via HTTP",
                Criticality::Notable,
            )),
            "nc" | "netcat" => Some((
                "net/socket/connect",
                "Network socket connections",
                Criticality::Notable,
            )),
            "exec" | "eval" => Some((
                "exec/script/eval",
                "Execute dynamic code",
                Criticality::Notable,
            )),
            "sh" | "bash" | "zsh" => Some((
                "exec/command/shell",
                "Execute shell commands",
                Criticality::Notable,
            )),
            "rm" | "unlink" => Some(("fs/delete", "Delete files", Criticality::Notable)),
            "chmod" | "chown" => Some((
                "fs/permissions",
                "Modify file permissions",
                Criticality::Notable,
            )),
            "crontab" => Some((
                "persistence/cron",
                "Schedule tasks with cron",
                Criticality::Notable,
            )),
            "systemctl" | "service" => Some((
                "persistence/service",
                "Manage system services",
                Criticality::Notable,
            )),
            "sudo" => Some((
                "privilege/escalation",
                "Execute with elevated privileges",
                Criticality::Notable,
            )),
            _ => None,
        };

        if let Some((cap_id, description, criticality)) = capability {
            // Check if we already have this capability
            if !report.findings.iter().any(|c| c.id == cap_id) {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: cap_id.to_string(),
                    desc: description.to_string(),
                    conf: 1.0,
                    crit: criticality,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-bash".to_string(),
                        value: cmd.to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }
        }
    }

    fn check_obfuscation(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        if let Ok(text) = node.utf8_text(source) {
            // Check for base64 encoding patterns
            if (text.contains("base64") || text.contains("b64decode"))
                && !report
                    .findings
                    .iter()
                    .any(|c| c.id == "anti-analysis/obfuscation/base64")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/obfuscation/base64".to_string(),
                    desc: "Uses base64 encoding/decoding".to_string(),
                    conf: 0.9,
                    crit: Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "pattern".to_string(),
                        source: "tree-sitter-bash".to_string(),
                        value: "base64".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }

            // Check for hex encoding
            if text.contains("\\x")
                && text.matches("\\x").count() > 3
                && !report
                    .findings
                    .iter()
                    .any(|c| c.id == "anti-analysis/obfuscation/hex")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/obfuscation/hex".to_string(),
                    desc: "Uses hex-encoded strings".to_string(),
                    conf: 0.9,
                    crit: Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "pattern".to_string(),
                        source: "tree-sitter-bash".to_string(),
                        value: "hex_encoding".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }

            // Check for eval with variable (dynamic code execution)
            if (text.contains("eval") || text.contains("exec"))
                && text.contains("$")
                && !report
                    .findings
                    .iter()
                    .any(|c| c.id == "anti-analysis/obfuscation/dynamic-eval")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/obfuscation/dynamic-eval".to_string(),
                    desc: "Executes dynamically constructed code".to_string(),
                    conf: 0.95,
                    crit: Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "pattern".to_string(),
                        source: "tree-sitter-bash".to_string(),
                        value: "eval_with_variable".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }
        }
    }

}
