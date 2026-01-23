use crate::analyzers::Analyzer;
use crate::analyzers::{
    comment_metrics::{self, CommentStyle},
    function_metrics::{self, FunctionInfo},
    identifier_metrics, string_metrics, text_metrics,
};
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// JavaScript/Node.js analyzer using tree-sitter
pub struct JavaScriptAnalyzer {
    parser: RefCell<Parser>,
    capability_mapper: CapabilityMapper,
}

impl JavaScriptAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
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

        // Parse the JavaScript
        let tree = self
            .parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse JavaScript")?;

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "javascript".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "source/language/javascript".to_string(),
            description: "JavaScript source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-javascript".to_string(),
                value: "javascript".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        // Detect capabilities and obfuscation
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Check for cross-statement obfuscation patterns
        self.check_global_obfuscation(content, &mut report);

        // Check for supply chain attack patterns
        self.check_supply_chain_patterns(content, &mut report);

        // Check for npm malware patterns (obfuscator signatures, C2, etc.)
        self.check_npm_malware_patterns(content, &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        // Detect JavaScript idioms
        let javascript_idioms = self.detect_javascript_idioms(&root, content.as_bytes());

        // Add idioms to source code metrics if they exist
        if let Some(ref mut metrics) = report.source_code_metrics {
            metrics.javascript_idioms = Some(javascript_idioms);
        }

        // === Compute metrics for ML analysis (BEFORE trait evaluation) ===
        let metrics = self.compute_metrics(&root, content);
        report.metrics = Some(metrics);

        // Evaluate trait definitions and composite rules
        let trait_findings = self
            .capability_mapper
            .evaluate_traits(&report, content.as_bytes());
        let composite_findings = self
            .capability_mapper
            .evaluate_composite_rules(&report, content.as_bytes());

        // Add all findings
        for f in trait_findings
            .into_iter()
            .chain(composite_findings.into_iter())
        {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-javascript".to_string()];

        Ok(report)
    }

    /// Compute all metrics for JavaScript code
    fn compute_metrics(&self, root: &tree_sitter::Node, content: &str) -> Metrics {
        let source = content.as_bytes();
        let total_lines = content.lines().count() as u32;

        // Universal text metrics
        let text = text_metrics::analyze_text(content);

        // Extract identifiers from AST
        let identifiers = self.extract_identifiers(root, source);
        let ident_refs: Vec<&str> = identifiers.iter().map(|s| s.as_str()).collect();
        let identifier_metrics = identifier_metrics::analyze_identifiers(&ident_refs);

        // Extract strings from AST
        let strings = self.extract_string_literals(root, source);
        let str_refs: Vec<&str> = strings.iter().map(|s| s.as_str()).collect();
        let string_metrics = string_metrics::analyze_strings(&str_refs);

        // Comment metrics (C-style comments for JS)
        let comment_metrics = comment_metrics::analyze_comments(content, CommentStyle::CStyle);

        // Function metrics
        let func_infos = self.extract_function_info(root, source);
        let func_metrics = function_metrics::analyze_functions(&func_infos, total_lines);

        // JavaScript-specific metrics
        let js_metrics = self.compute_javascript_metrics(root, source, content);

        Metrics {
            text: Some(text),
            identifiers: Some(identifier_metrics),
            strings: Some(string_metrics),
            comments: Some(comment_metrics),
            functions: Some(func_metrics),
            javascript: Some(js_metrics),
            ..Default::default()
        }
    }

    /// Extract function information from the AST for metrics
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

            // Function declarations and expressions
            if kind == "function_declaration"
                || kind == "function_expression"
                || kind == "method_definition"
                || kind == "arrow_function"
                || kind == "generator_function"
                || kind == "generator_function_declaration"
            {
                let mut info = FunctionInfo::default();

                // Get function name
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(source) {
                        info.name = name.to_string();
                    }
                }

                // Arrow functions and function expressions are anonymous if no name
                if kind == "arrow_function" || kind == "function_expression" {
                    if info.name.is_empty() {
                        info.is_anonymous = true;
                    }
                }

                // Check for async
                if let Ok(text) = node.utf8_text(source) {
                    if text.starts_with("async ") {
                        info.is_async = true;
                    }
                }

                // Check for generator
                if kind.contains("generator") {
                    info.is_generator = true;
                }

                // Get parameters
                if let Some(params_node) = node.child_by_field_name("parameters") {
                    let mut param_cursor = params_node.walk();
                    if param_cursor.goto_first_child() {
                        loop {
                            let param = param_cursor.node();
                            let param_kind = param.kind();
                            if param_kind == "identifier" {
                                if let Ok(param_name) = param.utf8_text(source) {
                                    info.param_names.push(param_name.to_string());
                                    info.param_count += 1;
                                }
                            } else if param_kind == "assignment_pattern"
                                || param_kind == "rest_pattern"
                            {
                                // Get left side of default parameter
                                if let Some(left) = param.child_by_field_name("left") {
                                    if let Ok(name) = left.utf8_text(source) {
                                        info.param_names.push(name.to_string());
                                        info.param_count += 1;
                                    }
                                } else if let Ok(text) = param.utf8_text(source) {
                                    let name = text.trim_start_matches("...");
                                    if let Some(name) = name.split('=').next() {
                                        let name = name.trim();
                                        if !name.is_empty() {
                                            info.param_names.push(name.to_string());
                                            info.param_count += 1;
                                        }
                                    }
                                }
                            }
                            if !param_cursor.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }

                // Line count
                info.start_line = node.start_position().row as u32;
                info.end_line = node.end_position().row as u32;
                info.line_count = info.end_line.saturating_sub(info.start_line) + 1;
                info.nesting_depth = depth;

                // Check for nested functions
                if let Some(body) = node.child_by_field_name("body") {
                    let body_text = body.utf8_text(source).unwrap_or("");
                    if body_text.contains("function ")
                        || body_text.contains("function(")
                        || body_text.contains("=>")
                    {
                        info.contains_nested_functions = true;
                    }
                }

                functions.push(info);
            }

            // Recurse with increased depth for function bodies
            let new_depth = if kind == "function_declaration"
                || kind == "function_expression"
                || kind == "arrow_function"
                || kind == "method_definition"
            {
                depth + 1
            } else {
                depth
            };

            if cursor.goto_first_child() {
                self.walk_for_function_info(cursor, source, functions, new_depth);
                cursor.goto_parent();
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    /// Extract all identifiers from the AST
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

            if node.kind() == "identifier" || node.kind() == "property_identifier" {
                if let Ok(text) = node.utf8_text(source) {
                    identifiers.push(text.to_string());
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

    /// Extract all string literals from the AST
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

            if node.kind() == "string" || node.kind() == "template_string" {
                if let Ok(text) = node.utf8_text(source) {
                    // Strip quotes if present
                    let s = text.trim_matches(|c| c == '"' || c == '\'' || c == '`');
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

    /// Compute JavaScript-specific metrics
    fn compute_javascript_metrics(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
        content: &str,
    ) -> JavaScriptMetrics {
        let mut metrics = JavaScriptMetrics::default();
        let mut cursor = root.walk();
        self.walk_for_js_metrics(&mut cursor, source, &mut metrics);

        // Additional pattern-based detection
        metrics.eval_count += content.matches("eval(").count() as u32;
        if content.contains("new Function(") {
            metrics.function_constructor += 1;
        }

        metrics
    }

    fn walk_for_js_metrics(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        metrics: &mut JavaScriptMetrics,
    ) {
        loop {
            let node = cursor.node();

            match node.kind() {
                "call_expression" => {
                    if let Ok(text) = node.utf8_text(source) {
                        // Dynamic execution
                        if text.starts_with("eval(") {
                            metrics.eval_count += 1;
                        }
                        if text.contains("setTimeout") && text.contains("\"") {
                            metrics.settimeout_string += 1;
                        }
                        if text.contains("setInterval") && text.contains("\"") {
                            metrics.setinterval_string += 1;
                        }
                        if text.contains("document.write") {
                            metrics.document_write += 1;
                        }
                        if text.contains("innerHTML") {
                            metrics.innerhtml_writes += 1;
                        }
                        if text.contains("fromCharCode") {
                            metrics.from_char_code_count += 1;
                        }
                        if text.contains("charCodeAt") {
                            metrics.char_code_at_count += 1;
                        }
                        if text.contains("atob(") || text.contains("btoa(") {
                            metrics.atob_btoa_count += 1;
                        }
                        if text.contains("decodeURIComponent") {
                            metrics.decode_uri_component += 1;
                        }
                        if text.contains(".join(") {
                            metrics.array_join_strings += 1;
                        }
                    }
                }
                "arrow_function" => {
                    metrics.arrow_function_count += 1;
                }
                "function_declaration" | "function_expression" => {
                    // Count functions
                }
                "new_expression" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("new Function(") {
                            metrics.function_constructor += 1;
                        }
                    }
                }
                "class_declaration" | "class_expression" => {
                    // Class counted for structural analysis
                }
                "debugger_statement" => {
                    metrics.debugger_statements += 1;
                }
                "with_statement" => {
                    metrics.with_statement += 1;
                }
                _ => {}
            }

            if cursor.goto_first_child() {
                self.walk_for_js_metrics(cursor, source, metrics);
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
        self.walk_ast(&mut cursor, source, report, 0);
    }

    fn walk_ast(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        report: &mut AnalysisReport,
        _depth: u32,
    ) {
        // Fully iterative traversal to avoid stack overflow on deeply nested ASTs
        // (common in obfuscated/minified JS which can have thousands of nesting levels)
        let mut current_depth: u32 = 0;
        let mut max_depth: u32 = 0;
        let mut deep_ast_reported = false;

        loop {
            let node = cursor.node();

            if current_depth > max_depth {
                max_depth = current_depth;
            }

            // Report extremely deep AST as obfuscation indicator (only once)
            if !deep_ast_reported && max_depth > 500 {
                deep_ast_reported = true;
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/obfuscation/deep-ast".to_string(),
                    description: "Extremely deep AST nesting (>500 levels)".to_string(),
                    confidence: 0.95,
                    criticality: Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-javascript".to_string(),
                        value: format!("depth:{}", max_depth),
                        location: None,
                    }],
                });
            }

            match node.kind() {
                "call_expression" => {
                    self.analyze_call(&node, source, report);
                }
                "import_statement" => {
                    self.analyze_import(&node, source, report);
                }
                "variable_declarator" => {
                    self.check_obfuscation(&node, source, report);
                }
                _ => {}
            }

            // Depth-first traversal without recursion:
            // 1. Try to go to first child
            // 2. If no child, try next sibling
            // 3. If no sibling, walk up looking for an ancestor with a sibling
            if cursor.goto_first_child() {
                current_depth += 1;
                continue;
            }

            if cursor.goto_next_sibling() {
                continue;
            }

            // Walk back up the tree looking for a sibling
            loop {
                if !cursor.goto_parent() {
                    return; // Done - back at root with no more siblings
                }
                current_depth = current_depth.saturating_sub(1);
                if cursor.goto_next_sibling() {
                    break; // Found a sibling, continue outer loop
                }
            }
        }
    }

    fn analyze_call(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            let capability = if text.contains("eval(") {
                Some((
                    "exec/script/eval",
                    "Evaluates dynamic code",
                    "eval",
                    Criticality::Notable,
                ))
            } else if text.contains("Function(") {
                Some((
                    "exec/script/eval",
                    "Dynamic function constructor",
                    "Function",
                    Criticality::Notable,
                ))
            } else if text.contains("child_process.exec")
                || text.contains("child_process.execSync")
                || (text.starts_with("exec(") || text.contains(" exec("))
            {
                Some((
                    "exec/command/shell",
                    "Execute shell commands",
                    "exec",
                    Criticality::Notable,
                ))
            } else if text.contains("child_process.spawn")
                || text.contains("child_process.spawnSync")
                || (text.starts_with("spawn(") || text.contains(" spawn("))
            {
                Some((
                    "exec/command/direct",
                    "Spawn child process",
                    "spawn",
                    Criticality::Notable,
                ))
            } else if text.contains("require(")
                && !text.contains("require('")
                && !text.contains("require(\"")
            {
                // Dynamic require with variable
                Some((
                    "anti-analysis/obfuscation/dynamic-import",
                    "Dynamic require",
                    "require(variable)",
                    Criticality::Suspicious,
                ))
            } else if text.contains("fs.writeFile") || text.contains("fs.writeFileSync") {
                Some((
                    "fs/write",
                    "Write files",
                    "fs.writeFile",
                    Criticality::Notable,
                ))
            // Note: fs/file/delete detection moved to traits/fs/file/delete/javascript.yaml
            } else if text.contains("fs.chmod") || text.contains("fs.chmodSync") {
                Some((
                    "fs/permissions",
                    "Change file permissions",
                    "fs.chmod",
                    Criticality::Notable,
                ))
            } else if text.contains("http.request") || text.contains("https.request") {
                Some((
                    "net/http/client",
                    "HTTP client operations",
                    "http.request",
                    Criticality::Notable,
                ))
            } else if text.contains("net.connect") || text.contains("net.createConnection") {
                Some((
                    "net/socket/connect",
                    "Network socket connection",
                    "net.connect",
                    Criticality::Notable,
                ))
            } else if text.contains("net.createServer") {
                Some((
                    "net/socket/listen",
                    "Create network server",
                    "net.createServer",
                    Criticality::Notable,
                ))
            } else if text.contains("Buffer.from") && text.contains("'base64'") {
                Some((
                    "anti-analysis/obfuscation/base64",
                    "Base64 decoding",
                    "Buffer.from",
                    Criticality::Suspicious,
                ))
            } else if text.contains("atob(") {
                Some((
                    "anti-analysis/obfuscation/base64",
                    "Base64 decoding (browser)",
                    "atob",
                    Criticality::Suspicious,
                ))
            } else {
                None
            };

            if let Some((cap_id, description, pattern, criticality)) = capability {
                if !report.findings.iter().any(|c| c.id == cap_id) {
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: cap_id.to_string(),
                        description: description.to_string(),
                        confidence: 1.0,
                        criticality,
                        mbc: None,
                        attack: None,
                        evidence: vec![Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-javascript".to_string(),
                            value: pattern.to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }
            }
        }
    }

    fn analyze_import(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            // Detect suspicious imports
            let suspicious_modules = [
                (
                    "child_process",
                    "exec/command/shell",
                    "Child process execution",
                    Criticality::Notable,
                ),
                (
                    "fs",
                    "fs/access",
                    "Filesystem operations",
                    Criticality::Notable,
                ),
                (
                    "net",
                    "net/socket/create",
                    "Network sockets",
                    Criticality::Notable,
                ),
                (
                    "http",
                    "net/http/client",
                    "HTTP client",
                    Criticality::Notable,
                ),
                (
                    "https",
                    "net/http/client",
                    "HTTPS client",
                    Criticality::Notable,
                ),
                (
                    "crypto",
                    "crypto/operation",
                    "Cryptographic operations",
                    Criticality::Notable,
                ),
                (
                    "vm",
                    "exec/script/eval",
                    "Virtual machine (code execution)",
                    Criticality::Notable,
                ),
            ];

            for (module, cap_id, description, criticality) in suspicious_modules {
                if text.contains(module) && !report.findings.iter().any(|c| c.id == cap_id) {
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: cap_id.to_string(),
                        description: description.to_string(),
                        confidence: 0.7, // Import alone is not definitive
                        criticality,
                        mbc: None,
                        attack: None,
                        evidence: vec![Evidence {
                            method: "import".to_string(),
                            source: "tree-sitter-javascript".to_string(),
                            value: module.to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }
            }
        }
    }

    fn check_global_obfuscation(&self, content: &str, report: &mut AnalysisReport) {
        // Check for base64 + eval pattern across the entire file
        let has_base64 = content.contains("Buffer.from") && content.contains("base64")
            || content.contains("atob(");
        let has_eval = content.contains("eval(") || content.contains("Function(");

        if has_base64
            && has_eval
            && !report
                .findings
                .iter()
                .any(|c| c.id == "anti-analysis/obfuscation/base64-eval")
        {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "anti-analysis/obfuscation/base64-eval".to_string(),
                description: "Base64 decode followed by eval (obfuscation)".to_string(),
                confidence: 0.95,
                criticality: Criticality::Suspicious,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "pattern".to_string(),
                    source: "tree-sitter-javascript".to_string(),
                    value: "base64+eval".to_string(),
                    location: None,
                }],
            });
        }
    }

    /// Check for supply chain attack patterns (tj-actions style)
    fn check_supply_chain_patterns(&self, content: &str, report: &mut AnalysisReport) {
        // 1. GitHub Actions exec patterns with bash
        if (content.contains("getExecOutput") || content.contains("exec.exec"))
            && content.contains("bash")
        {
            self.add_capability_if_missing(
                report,
                "exec/ci-pipeline/shell",
                "CI/CD pipeline shell execution",
                Criticality::Suspicious,
                "getExecOutput+bash",
            );
        }

        // 2. Silent/stealth execution (hiding output)
        if content.contains("silent: true") || content.contains("silent:true") {
            self.add_capability_if_missing(
                report,
                "evasion/stealth-execution",
                "Stealth execution (output hidden)",
                Criticality::Suspicious,
                "silent:true",
            );
        }

        // 3. Long base64-encoded strings (potential encoded payloads)
        // Look for strings that appear to be base64 and are suspiciously long
        // Also decode and scan for malicious patterns
        for line in content.lines() {
            // Find quoted strings that look like base64 (alphanumeric + /+=)
            if let Some(start) = line.find('"') {
                if let Some(end) = line[start + 1..].find('"') {
                    let potential_b64 = &line[start + 1..start + 1 + end];
                    if potential_b64.len() > 100
                        && potential_b64
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
                    {
                        // Flag long base64 strings
                        if potential_b64.len() > 200 {
                            self.add_capability_if_missing(
                                report,
                                "anti-analysis/obfuscation/long-base64",
                                "Long base64-encoded payload detected",
                                Criticality::Suspicious,
                                &format!(
                                    "{}... ({} chars)",
                                    &potential_b64[..50.min(potential_b64.len())],
                                    potential_b64.len()
                                ),
                            );
                        }

                        // Try to decode and scan for malicious content
                        use base64::Engine;
                        if let Ok(decoded_bytes) = BASE64_STANDARD.decode(potential_b64) {
                            if let Ok(decoded) = String::from_utf8(decoded_bytes) {
                                // Scan decoded content for supply chain attack patterns
                                self.scan_decoded_payload(&decoded, report);
                            }
                        }
                    }
                }
            }
        }

        // 4. Shell commands embedded in strings (supply chain indicators)
        let shell_indicators = [
            (
                "curl ",
                "net/download/curl",
                "Curl download command in string",
            ),
            (
                "wget ",
                "net/download/wget",
                "Wget download command in string",
            ),
            (
                "sudo ",
                "privesc/sudo",
                "Sudo privilege escalation in string",
            ),
            (
                "base64 -d",
                "anti-analysis/decode/base64-cli",
                "Base64 CLI decoding",
            ),
            (
                "| python",
                "exec/pipe-to-interpreter",
                "Piping to Python interpreter",
            ),
            ("| bash", "exec/pipe-to-shell", "Piping to bash shell"),
            ("| sh", "exec/pipe-to-shell", "Piping to shell"),
        ];

        for (pattern, cap_id, description) in shell_indicators {
            if content.contains(pattern) {
                self.add_capability_if_missing(
                    report,
                    cap_id,
                    description,
                    Criticality::Hostile,
                    pattern,
                );
            }
        }

        // 5. Secret/credential access patterns in CI context
        if content.contains("isSecret") && content.contains("true") {
            self.add_capability_if_missing(
                report,
                "data/secret-access",
                "Accessing secrets/credentials",
                Criticality::Suspicious,
                "isSecret:true",
            );
        }

        // 6. External gist/pastebin downloads (common exfil/C2 pattern)
        let external_code_hosts = [
            "gist.githubusercontent.com",
            "pastebin.com",
            "paste.ee",
            "hastebin.com",
            "dpaste.org",
        ];
        for host in external_code_hosts {
            if content.contains(host) {
                self.add_capability_if_missing(
                    report,
                    "c2/external-code-host",
                    "Downloads from external code hosting",
                    Criticality::Hostile,
                    host,
                );
            }
        }
    }

    /// Check for npm malware patterns that can't be expressed in YAML
    /// Counting patterns (obfuscator variables, hex literals) are now in YAML with search_raw: true
    fn check_npm_malware_patterns(&self, content: &str, report: &mut AnalysisReport) {
        // Hardcoded IP addresses (potential C2 servers)
        // This requires regex with capture groups and filtering, which YAML can't express
        let ip_pattern =
            regex::Regex::new(r#"["']?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?["']?"#).unwrap();
        // Version string patterns that look like IPs (Chrome/100.0.0.0, Safari/537.36, etc.)
        let version_pattern = regex::Regex::new(
            r#"(?i)(?:Chrome|Safari|Firefox|Edge|Opera|Chromium|Version|AppleWebKit|KHTML|Gecko|Trident|OPR|Mobile|MSIE|rv:|v)/\d+\.\d+\.\d+\.\d+"#,
        )
        .unwrap();

        for cap in ip_pattern.captures_iter(content) {
            let ip = &cap[1];
            let match_str = &cap[0];

            // Skip localhost and private ranges that might be benign
            if ip.starts_with("127.")
                || ip.starts_with("10.")
                || ip.starts_with("192.168.")
                || ip.starts_with("0.")
            {
                continue;
            }

            // Skip version strings that look like IPs
            // Find the position of this match and check surrounding context
            if let Some(pos) = content.find(match_str) {
                let start = pos.saturating_sub(50);
                let end = (pos + match_str.len() + 10).min(content.len());
                let context = &content[start..end];
                if version_pattern.is_match(context) {
                    continue;
                }
            }

            // Validate octets are valid (0-255)
            let octets: Vec<&str> = ip.split('.').collect();
            let valid_octets = octets
                .iter()
                .all(|o| o.parse::<u32>().map(|v| v <= 255).unwrap_or(false));
            if !valid_octets {
                continue;
            }

            // NOTE: Standalone IP in JS is suspicious not hostile
            // Data libraries like faker.js have example IPs
            // Real C2 requires additional context (network calls, etc.)
            self.add_capability_if_missing(
                report,
                "c2/hardcoded-ip",
                "Hardcoded IP address (potential C2 server)",
                Criticality::Suspicious,
                match_str,
            );
            break; // Only report once
        }
    }

    fn add_capability_if_missing(
        &self,
        report: &mut AnalysisReport,
        cap_id: &str,
        description: &str,
        criticality: Criticality,
        evidence_value: &str,
    ) {
        if !report.findings.iter().any(|c| c.id == cap_id) {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: cap_id.to_string(),
                description: description.to_string(),
                confidence: 0.9,
                criticality,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "pattern".to_string(),
                    source: "npm-malware-detector".to_string(),
                    value: evidence_value.to_string(),
                    location: None,
                }],
            });
        }
    }

    /// Scan decoded base64 payload for malicious patterns
    fn scan_decoded_payload(&self, decoded: &str, report: &mut AnalysisReport) {
        // Patterns that indicate supply chain attacks when found in decoded payloads
        let payload_indicators = [
            (
                "curl ",
                "net/download/curl-encoded",
                "Curl command in encoded payload",
            ),
            (
                "wget ",
                "net/download/wget-encoded",
                "Wget command in encoded payload",
            ),
            ("sudo ", "privesc/sudo-encoded", "Sudo in encoded payload"),
            (
                "python3",
                "exec/python-encoded",
                "Python execution in encoded payload",
            ),
            (
                "python ",
                "exec/python-encoded",
                "Python execution in encoded payload",
            ),
            (
                "gist.githubusercontent.com",
                "c2/gist-download",
                "Downloads from GitHub Gist",
            ),
            (
                "pastebin.com",
                "c2/pastebin-download",
                "Downloads from Pastebin",
            ),
            (
                "isSecret",
                "data/secret-exfil",
                "Secret extraction in encoded payload",
            ),
            (
                "base64 -w 0",
                "exfil/base64-encode",
                "Base64 encoding for exfiltration",
            ),
            (
                "/etc/passwd",
                "recon/passwd-access",
                "Accessing password file",
            ),
            (
                "/etc/shadow",
                "credential/shadow-access",
                "Accessing shadow file",
            ),
        ];

        for (pattern, cap_id, description) in payload_indicators {
            if decoded.contains(pattern) {
                self.add_capability_if_missing(
                    report,
                    cap_id,
                    description,
                    Criticality::Hostile,
                    &format!("[decoded] {}", pattern),
                );
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
            // Detect base64 + eval pattern
            if ((text.contains("Buffer.from") && text.contains("base64")) || text.contains("atob("))
                && (text.contains("eval(") || text.contains("Function("))
                && !report
                    .findings
                    .iter()
                    .any(|c| c.id == "anti-analysis/obfuscation/base64-eval")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/obfuscation/base64-eval".to_string(),
                    description: "Base64 decode followed by eval (obfuscation)".to_string(),
                    confidence: 0.95,
                    criticality: Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "pattern".to_string(),
                        source: "tree-sitter-javascript".to_string(),
                        value: "base64+eval".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }

            // Detect hex string construction
            if text.contains("\\x")
                && text.matches("\\x").count() > 5
                && !report
                    .findings
                    .iter()
                    .any(|c| c.id == "anti-analysis/obfuscation/hex")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/obfuscation/hex".to_string(),
                    description: "Hex-encoded strings".to_string(),
                    confidence: 0.9,
                    criticality: Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "pattern".to_string(),
                        source: "tree-sitter-javascript".to_string(),
                        value: "hex_encoding".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }

            // Detect string manipulation obfuscation
            if text.contains(".split(")
                && text.contains(".reverse()")
                && text.contains(".join(")
                && !report
                    .findings
                    .iter()
                    .any(|c| c.id == "anti-analysis/obfuscation/string-construct")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/obfuscation/string-construct".to_string(),
                    description: "String manipulation obfuscation".to_string(),
                    confidence: 0.9,
                    criticality: Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "pattern".to_string(),
                        source: "tree-sitter-javascript".to_string(),
                        value: "split_reverse_join".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }

            // Detect charAt obfuscation
            if text.contains(".charAt(")
                && text.matches(".charAt(").count() > 5
                && !report
                    .findings
                    .iter()
                    .any(|c| c.id == "anti-analysis/obfuscation/string-construct")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/obfuscation/string-construct".to_string(),
                    description: "Character-by-character string construction".to_string(),
                    confidence: 0.85,
                    criticality: Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "pattern".to_string(),
                        source: "tree-sitter-javascript".to_string(),
                        value: "charAt_pattern".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }
        }
    }

    /// Calculate cyclomatic complexity for a JavaScript function
    /// CC = decision points + 1
    fn calculate_cyclomatic_complexity(&self, node: &tree_sitter::Node, source: &[u8]) -> u32 {
        let mut complexity = 1; // Base complexity
        let mut cursor = node.walk();

        loop {
            let current = cursor.node();
            match current.kind() {
                "if_statement" => complexity += 1,
                "switch_case" => complexity += 1,
                "for_statement" | "for_in_statement" => complexity += 1,
                "while_statement" | "do_statement" => complexity += 1,
                "catch_clause" => complexity += 1,
                "ternary_expression" => complexity += 1,
                "binary_expression" => {
                    if let Ok(text) = current.utf8_text(source) {
                        if text.contains("&&") || text.contains("||") {
                            complexity += 1;
                        }
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

    /// Analyze function signature (params, arrow vs regular, async, etc.)
    fn analyze_function_signature(
        &self,
        node: &tree_sitter::Node,
        _source: &[u8],
    ) -> FunctionSignature {
        let mut param_count = 0u32;
        let mut default_param_count = 0u32;
        let mut has_var_positional = false; // rest params
        let has_type_hints = false; // TypeScript
        let has_return_type = false; // TypeScript
        let mut is_async = false;
        let is_generator = false;
        let is_lambda = node.kind() == "arrow_function";

        // Check for async
        if let Some(parent) = node.parent() {
            if parent.kind() == "function_declaration" || parent.kind() == "method_definition" {
                let mut cursor = parent.walk();
                for child in parent.children(&mut cursor) {
                    if child.kind() == "async" {
                        is_async = true;
                        break;
                    }
                }
            }
        }
        // Also check if node itself has async
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "async" {
                is_async = true;
                break;
            }
        }

        // Extract parameters
        if let Some(params_node) = node.child_by_field_name("parameters") {
            let mut param_cursor = params_node.walk();
            for child in params_node.children(&mut param_cursor) {
                match child.kind() {
                    "identifier" | "required_parameter" | "optional_parameter" => {
                        param_count += 1;
                    }
                    "assignment_pattern" => {
                        param_count += 1;
                        default_param_count += 1;
                    }
                    "rest_pattern" => {
                        has_var_positional = true;
                        param_count += 1;
                    }
                    _ => {}
                }
            }
        }

        FunctionSignature {
            param_count,
            default_param_count,
            has_var_positional,
            has_var_keyword: false, // JavaScript doesn't have **kwargs
            has_type_hints,
            has_return_type,
            decorators: Vec::new(), // JavaScript doesn't have decorators (except TS experimental)
            is_async,
            is_generator,
            is_lambda,
        }
    }

    /// Calculate nesting depth of control structures (iterative to avoid stack overflow)
    fn calculate_nesting_depth(&self, node: &tree_sitter::Node) -> NestingMetrics {
        let mut max_depth = 0u32;
        let mut depths = Vec::new();
        let mut deep_nest_count = 0u32;

        // Use explicit stack: (node_id, depth) - we track by byte range since Node isn't easily stored
        let mut cursor = node.walk();
        let mut depth_stack: Vec<u32> = vec![0]; // Track depth as we traverse

        loop {
            let current = cursor.node();
            let current_depth = *depth_stack.last().unwrap_or(&0);

            // Check if this node increases nesting depth
            let new_depth = match current.kind() {
                "if_statement" | "for_statement" | "for_in_statement" | "while_statement"
                | "do_statement" | "switch_statement" | "try_statement" => {
                    let d = current_depth + 1;
                    depths.push(d);
                    if d > max_depth {
                        max_depth = d;
                    }
                    if d > 4 {
                        deep_nest_count += 1;
                    }
                    d
                }
                _ => current_depth,
            };

            // Depth-first traversal
            if cursor.goto_first_child() {
                depth_stack.push(new_depth);
                continue;
            }

            if cursor.goto_next_sibling() {
                continue;
            }

            // Walk back up
            loop {
                if !cursor.goto_parent() {
                    // Done traversing
                    return NestingMetrics {
                        max_depth,
                        avg_depth: if !depths.is_empty() {
                            depths.iter().sum::<u32>() as f32 / depths.len() as f32
                        } else {
                            0.0
                        },
                        deep_nest_count,
                    };
                }
                depth_stack.pop();
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Analyze call patterns (promise chains, callbacks, recursion, dynamic calls)
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
        let mut chained_calls = 0u32;
        let mut max_chain_length = 0u32;

        let mut cursor = node.walk();
        loop {
            let current = cursor.node();
            if current.kind() == "call_expression" {
                call_count += 1;

                if let Some(func_node) = current.child_by_field_name("function") {
                    if let Ok(func_text) = func_node.utf8_text(source) {
                        let func_str = func_text.to_string();
                        callees.push(func_str.clone());

                        // Check recursion
                        if func_str == func_name || func_str.ends_with(&format!(".{}", func_name)) {
                            recursive_calls += 1;
                        }

                        // Check dynamic calls
                        if ["eval", "Function", "setTimeout", "setInterval"]
                            .iter()
                            .any(|&d| func_str.contains(d))
                        {
                            dynamic_calls += 1;
                        }

                        // Count method chaining
                        let chain_length = func_str.matches('.').count() as u32;
                        if chain_length > 0 {
                            chained_calls += 1;
                            if chain_length > max_chain_length {
                                max_chain_length = chain_length;
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
                    // Deduplicate callees
                    callees.sort();
                    callees.dedup();

                    return CallPatternMetrics {
                        call_count,
                        unique_callees: callees.len() as u32,
                        chained_calls,
                        max_chain_length,
                        recursive_calls,
                        dynamic_calls,
                    };
                }
            }
        }
    }

    /// Detect JavaScript-specific idioms
    fn detect_javascript_idioms(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
    ) -> JavaScriptIdioms {
        let mut arrow_function_count = 0u32;
        let mut promise_count = 0u32;
        let mut async_await_count = 0u32;
        let mut template_literal_count = 0u32;
        let mut destructuring_count = 0u32;
        let mut spread_operator_count = 0u32;
        let mut class_count = 0u32;
        let mut callback_count = 0u32;
        let mut iife_count = 0u32;
        let object_shorthand_count = 0u32;
        let mut optional_chaining_count = 0u32;
        let mut nullish_coalescing_count = 0u32;

        let mut cursor = root.walk();
        loop {
            let node = cursor.node();
            match node.kind() {
                "arrow_function" => {
                    arrow_function_count += 1;
                    // Check if it's a callback (passed as argument)
                    if let Some(parent) = node.parent() {
                        if parent.kind() == "arguments" {
                            callback_count += 1;
                        }
                    }
                }
                "class_declaration" => {
                    class_count += 1;
                }
                "template_string" => {
                    template_literal_count += 1;
                }
                "spread_element" => {
                    spread_operator_count += 1;
                }
                "object_pattern" | "array_pattern" => {
                    destructuring_count += 1;
                }
                "optional_chain" => {
                    optional_chaining_count += 1;
                }
                "call_expression" => {
                    if let Ok(text) = node.utf8_text(source) {
                        // Promise detection
                        if text.contains("new Promise")
                            || text.contains(".then(")
                            || text.contains(".catch(")
                            || text.contains(".finally(")
                        {
                            promise_count += 1;
                        }
                        // IIFE detection
                        if text.starts_with("(function") || text.starts_with("(async function") {
                            iife_count += 1;
                        }
                    }
                }
                "function_declaration" | "method_definition" => {
                    // Check for async
                    let mut func_cursor = node.walk();
                    for child in node.children(&mut func_cursor) {
                        if child.kind() == "async" {
                            async_await_count += 1;
                            break;
                        }
                    }
                }
                "binary_expression" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("??") {
                            nullish_coalescing_count += 1;
                        }
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
                    return JavaScriptIdioms {
                        arrow_function_count,
                        promise_count,
                        async_await_count,
                        template_literal_count,
                        destructuring_count,
                        spread_operator_count,
                        class_count,
                        callback_count,
                        iife_count,
                        object_shorthand_count,
                        optional_chaining_count,
                        nullish_coalescing_count,
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

            // Match both function declarations and arrow functions
            if matches!(
                node.kind(),
                "function_declaration" | "arrow_function" | "function" | "method_definition"
            ) {
                let func_name = if let Some(name_node) = node.child_by_field_name("name") {
                    name_node
                        .utf8_text(source)
                        .unwrap_or("<unnamed>")
                        .to_string()
                } else {
                    "<anonymous>".to_string()
                };

                // Calculate all metrics
                let complexity = self.calculate_cyclomatic_complexity(&node, source);
                let signature = self.analyze_function_signature(&node, source);
                let nesting = self.calculate_nesting_depth(&node);
                let call_patterns = self.analyze_call_patterns(&node, source, &func_name);

                // Extract actual function calls
                let mut calls = Vec::new();
                let mut call_cursor = node.walk();
                loop {
                    let call_node = call_cursor.node();
                    if call_node.kind() == "call_expression" {
                        if let Some(func_node) = call_node.child_by_field_name("function") {
                            if let Ok(func_text) = func_node.utf8_text(source) {
                                calls.push(func_text.to_string());
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
                    basic_blocks: complexity, // Approximation: CC relates to BBs
                    edges: if complexity > 1 { complexity + 1 } else { 1 },
                    cyclomatic_complexity: complexity,
                    max_block_size: 0, // Not easily calculated from tree-sitter
                    avg_block_size: 0.0,
                    is_linear: complexity == 1,
                    loop_count: 0, // Could count for/while nodes if needed
                    branch_density: 0.0,
                    in_degree: 0, // Would need global call graph analysis
                    out_degree: call_patterns.unique_callees,
                };

                // Build properties
                let properties = FunctionProperties {
                    is_pure: false, // Hard to determine from AST alone
                    is_noreturn: false,
                    is_recursive: call_patterns.recursive_calls > 0,
                    stack_frame: 0, // Not applicable to JavaScript
                    local_vars: 0,  // Could count variable declarations if needed
                    args: signature.param_count,
                    is_leaf: call_patterns.call_count == 0,
                };

                report.functions.push(Function {
                    name: func_name,
                    offset: Some(format!("line:{}", node.start_position().row + 1)),
                    size: Some((node.end_byte() - node.start_byte()) as u64),
                    complexity: Some(complexity),
                    calls,
                    source: "tree-sitter-javascript".to_string(),
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

impl Default for JavaScriptAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for JavaScriptAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = fs::read_to_string(file_path).context("Failed to read JavaScript file")?;

        self.analyze_script(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            matches!(ext.to_str(), Some("js") | Some("mjs") | Some("cjs"))
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze_js_code(code: &str) -> AnalysisReport {
        let analyzer = JavaScriptAnalyzer::new();
        analyzer.analyze_script(Path::new("test.js"), code).unwrap()
    }

    #[test]
    fn test_simple_script() {
        let script = r#"
            const fs = require('fs');
            const { exec } = require('child_process');

            exec('rm -rf /tmp/test', (error, stdout, stderr) => {
                console.log(stdout);
            });

            fs.writeFileSync('/tmp/malicious.txt', 'payload');
        "#;

        let report = analyze_js_code(script);

        // Should detect exec and fs imports
        assert!(!report.findings.is_empty());

        // Should detect shell execution
        assert!(report
            .findings
            .iter()
            .any(|c| c.id.contains("exec/command")));

        // Should detect file write
        assert!(report.findings.iter().any(|c| c.id.contains("fs/write")));
    }

    #[test]
    fn test_obfuscated_script() {
        let script = r#"
            const payload = Buffer.from('Y3VybCBldmlsLmNvbQ==', 'base64').toString();
            eval(payload);
        "#;

        let report = analyze_js_code(script);

        // Should detect base64 + eval obfuscation
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/base64-eval"));
    }

    #[test]
    fn test_detect_eval() {
        let code = "eval('console.log(\"hello\")');";
        let report = analyze_js_code(code);

        assert!(report.findings.iter().any(|c| c.id == "exec/script/eval"));
    }

    #[test]
    fn test_detect_function_constructor() {
        let code = "const fn = Function('return 1+1');";
        let report = analyze_js_code(code);

        assert!(report.findings.iter().any(|c| c.id == "exec/script/eval"));
    }

    #[test]
    fn test_detect_exec() {
        let code = "const { exec } = require('child_process'); exec('ls -la');";
        let report = analyze_js_code(code);

        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_spawn() {
        let code = "const { spawn } = require('child_process'); spawn('sh', ['-c', 'ls']);";
        let report = analyze_js_code(code);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "exec/command/direct"));
    }

    #[test]
    fn test_detect_fs_write() {
        let code = "const fs = require('fs'); fs.writeFileSync('test.txt', 'data');";
        let report = analyze_js_code(code);

        assert!(report.findings.iter().any(|c| c.id == "fs/write"));
    }

    // Note: fs/file/delete detection moved to traits/fs/file/delete/javascript.yaml

    #[test]
    fn test_detect_fs_chmod() {
        let code = "const fs = require('fs'); fs.chmodSync('script.sh', 0o755);";
        let report = analyze_js_code(code);

        assert!(report.findings.iter().any(|c| c.id == "fs/permissions"));
    }

    #[test]
    fn test_detect_http_request() {
        let code = "const https = require('https'); https.request('https://example.com', cb);";
        let report = analyze_js_code(code);

        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
    }

    #[test]
    fn test_detect_net_connect() {
        let code = "const net = require('net'); net.connect(4444, 'example.com');";
        let report = analyze_js_code(code);

        assert!(report.findings.iter().any(|c| c.id == "net/socket/connect"));
    }

    #[test]
    fn test_detect_net_server() {
        let code = "const net = require('net'); net.createServer((socket) => {});";
        let report = analyze_js_code(code);

        assert!(report.findings.iter().any(|c| c.id == "net/socket/listen"));
    }

    #[test]
    fn test_detect_buffer_base64() {
        let code = "const data = Buffer.from('aGVsbG8=', 'base64');";
        let report = analyze_js_code(code);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/base64"));
    }

    #[test]
    fn test_detect_atob() {
        let code = "const decoded = atob('aGVsbG8=');";
        let report = analyze_js_code(code);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/base64"));
    }

    #[test]
    fn test_detect_dynamic_require() {
        let code = "const moduleName = 'fs'; const fs = require(moduleName);";
        let report = analyze_js_code(code);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/dynamic-import"));
    }

    #[test]
    fn test_structural_feature() {
        let code = "console.log('hello');";
        let report = analyze_js_code(code);

        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/javascript"));
    }

    #[test]
    fn test_extract_functions() {
        let code = r#"
function hello() {
    return 'world';
}

const goodbye = () => {
    console.log('bye');
};
"#;
        let report = analyze_js_code(code);

        assert!(!report.functions.is_empty());
        assert!(report.functions.iter().any(|f| f.name == "hello"));
    }

    #[test]
    fn test_multiple_capabilities() {
        let code = r#"
const fs = require('fs');
const { exec } = require('child_process');
const https = require('https');

exec('whoami');
fs.writeFileSync('/tmp/data', 'test');
https.request('https://evil.com');
"#;
        let report = analyze_js_code(code);

        assert!(report.findings.len() >= 3);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
        assert!(report.findings.iter().any(|c| c.id == "fs/write"));
        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
    }
}
