//! PHP script analyzer.

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

/// PHP analyzer using tree-sitter
pub struct PhpAnalyzer {
    parser: RefCell<Parser>,
    capability_mapper: CapabilityMapper,
}

impl Default for PhpAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl PhpAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .expect("Failed to load PHP grammar");

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

    fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        if std::env::var("DISSECT_DEBUG").is_ok() {
            eprintln!("[DEBUG] PHP Analyzer: parsing {}", file_path.display());
            let preview = content.chars().take(100).collect::<String>();
            eprintln!("[DEBUG] PHP Content preview: {:?}", preview);
        }

        let tree = self
            .parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse PHP source")?;

        let root = tree.root_node();

        if std::env::var("DISSECT_DEBUG").is_ok() {
            let mut node_count = 0;
            let mut error_count = 0;
            let mut cursor = root.walk();

            loop {
                node_count += 1;
                if cursor.node().is_error() {
                    error_count += 1;
                }

                if cursor.goto_first_child() {
                    continue;
                }

                if cursor.goto_next_sibling() {
                    continue;
                }

                loop {
                    if !cursor.goto_parent() {
                        break;
                    }
                    if cursor.goto_next_sibling() {
                        break;
                    }
                }

                if cursor.node() == root {
                    break;
                }
            }

            eprintln!(
                "[DEBUG] PHP AST: root kind={}, has_error={}, total_nodes={}, error_nodes={}",
                root.kind(),
                root.has_error(),
                node_count,
                error_count
            );
        }

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "php".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        report.structure.push(StructuralFeature {
            id: "source/language/php".to_string(),
            desc: "PHP source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-php".to_string(),
                value: "php".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        self.detect_capabilities(&root, content.as_bytes(), &mut report);
        self.extract_functions(&root, content.as_bytes(), &mut report);

        // Extract function calls as symbols for symbol-based rule matching
        symbol_extraction::extract_symbols(
            content,
            tree_sitter_php::LANGUAGE_PHP.into(),
            &["function_call_expression"],
            &mut report,
        );

        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);

        // Compute metrics for ML analysis
        let metrics = self.compute_metrics(&root, content, &mut report);
        report.metrics = Some(metrics);

        // Evaluate trait definitions and composite rules (includes inline YARA)
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
        report.metadata.tools_used = vec!["tree-sitter-php".to_string()];

        Ok(report)
    }

    /// Compute all metrics for PHP code
    fn compute_metrics(
        &self,
        root: &tree_sitter::Node,
        content: &str,
        report: &mut AnalysisReport,
    ) -> Metrics {
        let source = content.as_bytes();
        let total_lines = content.lines().count() as u32;

        // Universal text metrics
        let text = text_metrics::analyze_text(content);

        // Extract identifiers from AST
        let identifiers = self.extract_identifiers(root, source, report);
        let ident_refs: Vec<&str> = identifiers.iter().map(|s| s.as_str()).collect();
        let identifier_metrics = identifier_metrics::analyze_identifiers(&ident_refs);

        // Extract strings from AST
        let strings = self.extract_string_literals(root, source);
        let str_refs: Vec<&str> = strings.iter().map(|s| s.as_str()).collect();
        let string_metrics = string_metrics::analyze_strings(&str_refs);

        // Comment metrics (C-style and hash comments for PHP)
        let comment_metrics = comment_metrics::analyze_comments(content, CommentStyle::CStyle);

        // Function metrics
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

    /// Extract identifiers from PHP AST
    fn extract_identifiers(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) -> Vec<String> {
        let mut identifiers = Vec::new();
        let mut cursor = root.walk();
        self.walk_for_identifiers(&mut cursor, source, &mut identifiers, report);
        identifiers
    }

    fn walk_for_identifiers(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        identifiers: &mut Vec<String>,
        report: &mut AnalysisReport,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            if node.kind() == "name" || node.kind() == "variable_name" {
                if let Ok(text) = node.utf8_text(source) {
                    let name = text.trim_start_matches('$');
                    if !name.is_empty() {
                        identifiers.push(name.to_string());

                        // Detect unusually long variable names (potential obfuscation)
                        if name.len() > 15 {
                            report.findings.push(Finding {
                                kind: FindingKind::Capability,
                                trait_refs: vec![],
                                id: "anti-analysis/obfuscation/long-identifier".to_string(),
                                desc: "Unusually long identifier (potential obfuscation)"
                                    .to_string(),
                                conf: 0.8,
                                crit: Criticality::Notable,
                                mbc: None,
                                attack: None,
                                evidence: vec![Evidence {
                                    method: "ast".to_string(),
                                    source: "tree-sitter-php".to_string(),
                                    value: name.to_string(),
                                    location: Some(format!(
                                        "{}:{}",
                                        node.start_position().row + 1,
                                        node.start_position().column
                                    )),
                                }],
                            });
                        }
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

    /// Extract string literals from PHP AST
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

            if node.kind() == "string" || node.kind() == "encapsed_string" {
                if let Ok(text) = node.utf8_text(source) {
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
        self.walk_for_func_info(&mut cursor, source, &mut functions, 0);
        functions
    }

    fn walk_for_func_info(
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

            if kind == "function_definition" || kind == "method_declaration" {
                let mut info = FunctionInfo::default();

                // Get function name
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
                            if param.kind() == "simple_parameter"
                                || param.kind() == "variadic_parameter"
                            {
                                info.param_count += 1;
                                // Try to get variable name
                                if let Some(var_node) = param.child_by_field_name("name") {
                                    if let Ok(var_text) = var_node.utf8_text(source) {
                                        let name = var_text.trim_start_matches('$');
                                        if !name.is_empty() {
                                            info.param_names.push(name.to_string());
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

                functions.push(info);
            }

            if cursor.goto_first_child() {
                if kind == "function_definition" || kind == "method_declaration" {
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
                if parent_kind == "function_definition" || parent_kind == "method_declaration" {
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
                "function_call_expression" => {
                    self.analyze_call(&node, source, report);
                }
                "include_expression"
                | "include_once_expression"
                | "require_expression"
                | "require_once_expression" => {
                    self.analyze_include(&node, source, report);
                }
                "object_creation_expression" => {
                    self.analyze_object_creation(&node, source, report);
                }
                "member_call_expression" => {
                    self.analyze_method_call(&node, source, report);
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

    fn analyze_call(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        let Some(func_node) = node.child_by_field_name("function") else {
            return;
        };

        let mut is_dynamic = false;
        let mut func_name = String::new();

        if let Ok(text) = func_node.utf8_text(source) {
            func_name = text.to_string();
            // In tree-sitter-php, function can be a name, variable, or even a subscript expression
            if func_node.kind() == "variable_name" || func_node.kind() == "subscript_expression" {
                is_dynamic = true;
            }
        }

        if std::env::var("DISSECT_DEBUG").is_ok() {
            eprintln!("[DEBUG] PHP analyze_call: func_name={}", func_name);
        }

        // Detect non-ASCII function names (obfuscation)
        if !func_name.is_ascii() {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "anti-analysis/obfuscation/non-ascii-call".to_string(),
                desc: "Function call with non-ASCII name (obfuscation)".to_string(),
                conf: 0.98,
                crit: Criticality::Hostile,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "ast".to_string(),
                    source: "tree-sitter-php".to_string(),
                    value: func_name.clone(),
                    location: Some(format!(
                        "{}:{}",
                        node.start_position().row + 1,
                        node.start_position().column
                    )),
                }],
            });
        }

        if is_dynamic {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "exec/dynamic-call".to_string(),
                desc: "Dynamic function call (potential webshell indicator)".to_string(),
                conf: 0.9,
                crit: Criticality::Suspicious,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "ast".to_string(),
                    source: "tree-sitter-php".to_string(),
                    value: func_name.clone(),
                    location: Some(format!(
                        "{}:{}",
                        node.start_position().row + 1,
                        node.start_position().column
                    )),
                }],
            });
        }

        let func_lower = func_name.to_lowercase();
        let text = node.utf8_text(source).unwrap_or("");

        let mut capabilities: Vec<(&str, &str, &str, f32, Criticality)> = Vec::new();

        // Command execution functions
        match func_lower.as_str() {
            "exec" | "shell_exec" | "system" | "passthru" | "popen" | "proc_open" => {
                capabilities.push((
                    "exec/command/shell",
                    "Command execution",
                    &func_name,
                    0.95,
                    Criticality::Suspicious,
                ));
            }
            "pcntl_exec" => {
                capabilities.push((
                    "exec/command/direct",
                    "Direct process execution",
                    &func_name,
                    0.95,
                    Criticality::Suspicious,
                ));
            }
            _ => {}
        }

        // Code execution
        if func_lower == "eval" {
            capabilities.push((
                "exec/script/eval",
                "Dynamic code execution",
                &func_name,
                0.95,
                Criticality::Suspicious,
            ));
        }
        if func_lower == "assert" && text.contains('$') {
            capabilities.push((
                "exec/script/eval",
                "Assert with variable (potential code exec)",
                &func_name,
                0.85,
                Criticality::Notable,
            ));
        }
        if func_lower == "create_function" {
            capabilities.push((
                "exec/script/eval",
                "Dynamic function creation",
                &func_name,
                0.9,
                Criticality::Suspicious,
            ));
        }
        if func_lower == "call_user_func" || func_lower == "call_user_func_array" {
            capabilities.push((
                "exec/dynamic-call",
                "Dynamic function call",
                &func_name,
                0.8,
                Criticality::Notable,
            ));
        }

        // Obfuscation patterns
        if func_lower == "base64_decode" {
            capabilities.push((
                "anti-analysis/obfuscation/base64",
                "Base64 decoding",
                &func_name,
                0.7,
                Criticality::Notable,
            ));
        }
        if func_lower == "gzinflate" || func_lower == "gzuncompress" || func_lower == "gzdecode" {
            capabilities.push((
                "anti-analysis/obfuscation/compression",
                "Compressed data decoding",
                &func_name,
                0.75,
                Criticality::Notable,
            ));
        }
        if func_lower == "str_rot13" {
            capabilities.push((
                "anti-analysis/obfuscation/rot13",
                "ROT13 encoding",
                &func_name,
                0.7,
                Criticality::Notable,
            ));
        }
        if func_lower == "chr" || func_lower == "ord" {
            capabilities.push((
                "anti-analysis/obfuscation/char-encoding",
                "Character code manipulation",
                &func_name,
                0.5,
                Criticality::Inert,
            ));
        }

        // Deserialization
        if func_lower == "unserialize" {
            capabilities.push((
                "anti-analysis/deserialization",
                "PHP object deserialization",
                &func_name,
                0.9,
                Criticality::Suspicious,
            ));
        }

        // File operations
        match func_lower.as_str() {
            "file_get_contents" | "fopen" | "fread" | "readfile" | "file" => {
                capabilities.push((
                    "fs/read",
                    "File read operation",
                    &func_name,
                    0.8,
                    Criticality::Notable,
                ));
            }
            "file_put_contents" | "fwrite" | "fputs" => {
                capabilities.push((
                    "fs/write",
                    "File write operation",
                    &func_name,
                    0.85,
                    Criticality::Notable,
                ));
            }
            "unlink" | "rmdir" => {
                capabilities.push((
                    "fs/delete",
                    "File/directory deletion",
                    &func_name,
                    0.85,
                    Criticality::Notable,
                ));
            }
            "chmod" | "chown" | "chgrp" => {
                capabilities.push((
                    "fs/permissions",
                    "File permission change",
                    &func_name,
                    0.85,
                    Criticality::Notable,
                ));
            }
            "copy" | "rename" | "move_uploaded_file" => {
                capabilities.push((
                    "fs/modify",
                    "File modification",
                    &func_name,
                    0.8,
                    Criticality::Notable,
                ));
            }
            _ => {}
        }

        // Network operations
        match func_lower.as_str() {
            "curl_init" | "curl_exec" => {
                capabilities.push((
                    "net/http/client",
                    "HTTP client (cURL)",
                    &func_name,
                    0.85,
                    Criticality::Notable,
                ));
            }
            "fsockopen" | "pfsockopen" | "socket_create" => {
                capabilities.push((
                    "net/socket/create",
                    "Socket creation",
                    &func_name,
                    0.85,
                    Criticality::Suspicious,
                ));
            }
            "stream_socket_client" | "stream_socket_server" => {
                capabilities.push((
                    "net/socket/stream",
                    "Stream socket operation",
                    &func_name,
                    0.85,
                    Criticality::Suspicious,
                ));
            }
            "gethostbyname" | "dns_get_record" => {
                capabilities.push((
                    "net/dns/resolve",
                    "DNS lookup",
                    &func_name,
                    0.8,
                    Criticality::Inert,
                ));
            }
            _ => {}
        }

        // Database operations
        match func_lower.as_str() {
            "mysqli_query" | "mysql_query" | "pg_query" => {
                capabilities.push((
                    "database/query",
                    "Database query",
                    &func_name,
                    0.8,
                    Criticality::Notable,
                ));
            }
            "mysqli_connect" | "mysql_connect" | "pg_connect" => {
                capabilities.push((
                    "database/connect",
                    "Database connection",
                    &func_name,
                    0.8,
                    Criticality::Notable,
                ));
            }
            _ => {}
        }

        // Mail
        if func_lower == "mail" {
            capabilities.push((
                "net/email/send",
                "Email sending",
                &func_name,
                0.85,
                Criticality::Notable,
            ));
        }

        // Cryptography
        match func_lower.as_str() {
            "openssl_encrypt" | "openssl_decrypt" | "mcrypt_encrypt" | "mcrypt_decrypt" => {
                capabilities.push((
                    "crypto/encrypt",
                    "Encryption operation",
                    &func_name,
                    0.8,
                    Criticality::Notable,
                ));
            }
            "md5" | "sha1" | "hash" => {
                capabilities.push((
                    "crypto/hash",
                    "Hashing operation",
                    &func_name,
                    0.7,
                    Criticality::Inert,
                ));
            }
            _ => {}
        }

        // Environment/system info
        match func_lower.as_str() {
            "getenv" | "putenv" => {
                capabilities.push((
                    "env/access",
                    "Environment variable access",
                    &func_name,
                    0.7,
                    Criticality::Inert,
                ));
            }
            "phpinfo" => {
                capabilities.push((
                    "discovery/system-info",
                    "System information disclosure",
                    &func_name,
                    0.85,
                    Criticality::Notable,
                ));
            }
            "php_uname" | "posix_uname" => {
                capabilities.push((
                    "discovery/system-info",
                    "OS information gathering",
                    &func_name,
                    0.8,
                    Criticality::Notable,
                ));
            }
            "ini_set" | "ini_get" => {
                capabilities.push((
                    "config/php-ini",
                    "PHP configuration manipulation",
                    &func_name,
                    0.75,
                    Criticality::Notable,
                ));
            }
            _ => {}
        }

        // Reflection
        if func_lower == "get_defined_functions"
            || func_lower == "get_defined_vars"
            || func_lower == "get_defined_constants"
        {
            capabilities.push((
                "anti-analysis/reflection",
                "Runtime introspection",
                &func_name,
                0.7,
                Criticality::Notable,
            ));
        }

        // preg_replace with /e modifier (PHP < 7.0)
        if func_lower == "preg_replace" && text.contains("/e") {
            capabilities.push((
                "exec/script/eval",
                "preg_replace with /e modifier (code execution)",
                &func_name,
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
                    source: "tree-sitter-php".to_string(),
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

    fn analyze_include(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let text = node.utf8_text(source).unwrap_or("");
        let kind = node.kind();

        let mut criticality = Criticality::Notable;
        let mut confidence = 0.7_f32;

        // Check for dynamic includes (more dangerous)
        if text.contains("$_GET")
            || text.contains("$_POST")
            || text.contains("$_REQUEST")
            || text.contains("$_COOKIE")
        {
            criticality = Criticality::Hostile;
            confidence = 0.95;
        } else if text.contains('$') {
            criticality = Criticality::Suspicious;
            confidence = 0.85;
        }

        let include_type = match kind {
            "include_expression" => "include",
            "include_once_expression" => "include_once",
            "require_expression" => "require",
            "require_once_expression" => "require_once",
            _ => "include",
        };

        report.findings.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "fs/include".to_string(),
            desc: format!("File inclusion ({})", include_type),
            conf: confidence,
            crit: criticality,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "ast".to_string(),
                source: "tree-sitter-php".to_string(),
                value: include_type.to_string(),
                location: Some(format!(
                    "{}:{}",
                    node.start_position().row + 1,
                    node.start_position().column
                )),
            }],
        });
    }

    fn analyze_object_creation(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let text = node.utf8_text(source).unwrap_or("");
        let mut capabilities: Vec<(&str, &str, &str, f32, Criticality)> = Vec::new();

        if text.contains("PDO") {
            capabilities.push((
                "database/pdo",
                "PDO database connection",
                "PDO",
                0.8,
                Criticality::Notable,
            ));
        }
        if text.contains("mysqli") {
            capabilities.push((
                "database/mysqli",
                "MySQLi database connection",
                "mysqli",
                0.8,
                Criticality::Notable,
            ));
        }
        if text.contains("ReflectionClass") || text.contains("ReflectionMethod") {
            capabilities.push((
                "anti-analysis/reflection",
                "PHP reflection",
                "Reflection",
                0.8,
                Criticality::Notable,
            ));
        }
        if text.contains("SoapClient") {
            capabilities.push((
                "net/soap/client",
                "SOAP client",
                "SoapClient",
                0.8,
                Criticality::Notable,
            ));
        }
        if text.contains("ZipArchive") {
            capabilities.push((
                "archive/zip",
                "ZIP archive manipulation",
                "ZipArchive",
                0.75,
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
                    source: "tree-sitter-php".to_string(),
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

    fn analyze_method_call(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let text = node.utf8_text(source).unwrap_or("");

        // PDO prepared statements
        if text.contains("->prepare(") || text.contains("->execute(") {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "database/query".to_string(),
                desc: "Database prepared statement".to_string(),
                conf: 0.8,
                crit: Criticality::Notable,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "ast".to_string(),
                    source: "tree-sitter-php".to_string(),
                    value: "PDO::prepare".to_string(),
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

            if node.kind() == "function_definition" || node.kind() == "method_declaration" {
                let name = self
                    .extract_function_name(&node, source)
                    .unwrap_or_else(|| "anonymous".to_string());

                report.functions.push(Function {
                    name,
                    offset: Some(format!("0x{:x}", node.start_byte())),
                    size: Some((node.end_byte() - node.start_byte()) as u64),
                    complexity: None,
                    calls: Vec::new(),
                    source: "tree-sitter-php".to_string(),
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
                if child.kind() == "name" {
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

impl Analyzer for PhpAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let bytes = fs::read(file_path).context("Failed to read PHP file")?;
        let content = String::from_utf8_lossy(&bytes);
        self.analyze_source(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path.extension().and_then(|e| e.to_str()) == Some("php")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn analyze_php_code(code: &str) -> AnalysisReport {
        let analyzer = PhpAnalyzer::new();
        let path = PathBuf::from("test.php");
        analyzer.analyze_source(&path, code).unwrap()
    }

    #[test]
    fn test_structural_feature() {
        let code = r#"<?php echo "Hello"; ?>"#;
        let report = analyze_php_code(code);
        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/php"));
    }

    #[test]
    fn test_detect_exec() {
        let code = r#"<?php exec("whoami"); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_shell_exec() {
        let code = r#"<?php $out = shell_exec("ls -la"); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_system() {
        let code = r#"<?php system($_GET['cmd']); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_eval() {
        let code = r#"<?php eval($code); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/script/eval"));
    }

    #[test]
    fn test_detect_base64_decode() {
        let code = r#"<?php $x = base64_decode($encoded); ?>"#;
        let report = analyze_php_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/base64"));
    }

    #[test]
    fn test_detect_unserialize() {
        let code = r#"<?php $obj = unserialize($data); ?>"#;
        let report = analyze_php_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/deserialization"));
    }

    #[test]
    fn test_detect_file_operations() {
        let code = r#"<?php
            $content = file_get_contents("config.php");
            file_put_contents("shell.php", $payload);
        ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "fs/read"));
        assert!(report.findings.iter().any(|c| c.id == "fs/write"));
    }

    #[test]
    fn test_detect_curl() {
        let code = r#"<?php
            $ch = curl_init("http://evil.com");
            curl_exec($ch);
        ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
    }

    #[test]
    fn test_detect_socket() {
        let code = r#"<?php $sock = fsockopen("evil.com", 4444); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/socket/create"));
    }

    #[test]
    fn test_detect_include() {
        let code = r#"<?php include("config.php"); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "fs/include"));
    }

    #[test]
    fn test_detect_dynamic_include_hostile() {
        let code = r#"<?php include($_GET['page']); ?>"#;
        let report = analyze_php_code(code);
        let cap = report
            .findings
            .iter()
            .find(|c| c.id == "fs/include")
            .unwrap();
        assert_eq!(cap.crit, Criticality::Hostile);
    }

    #[test]
    fn test_detect_pdo() {
        let code = r#"<?php $pdo = new PDO("mysql:host=localhost", "user", "pass"); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "database/pdo"));
    }

    #[test]
    fn test_detect_mail() {
        let code = r#"<?php mail("admin@example.com", "Subject", "Body"); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/email/send"));
    }

    #[test]
    fn test_extract_functions() {
        let code = r#"<?php
            function hello($name) {
                return "Hello, " . $name;
            }
            function goodbye() {
                echo "Bye";
            }
        ?>"#;
        let report = analyze_php_code(code);
        assert_eq!(report.functions.len(), 2);
        assert!(report.functions.iter().any(|f| f.name == "hello"));
        assert!(report.functions.iter().any(|f| f.name == "goodbye"));
    }

    #[test]
    fn test_detect_dynamic_call() {
        let code = r#"<?php $func = "system"; $func("whoami"); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/dynamic-call"));
    }

    #[test]
    fn test_detect_non_ascii_call() {
        let code = "<?php $ִ('payload'); ?>";
        let report = analyze_php_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/non-ascii-call"));
    }

    #[test]
    fn test_detect_long_identifier() {
        let code = "<?php $unusually_long_variable_name_for_obfuscation = 1; ?>";
        let report = analyze_php_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/long-identifier"));
    }

    #[test]
    fn test_lossy_utf8_reading() {
        let analyzer = PhpAnalyzer::new();
        let invalid_utf8 = vec![
            0x3c, 0x3f, 0x70, 0x68, 0x70, 0x20, 0xff, 0xfe, 0xfd, 0x20, 0x3f, 0x3e,
        ];
        let content = String::from_utf8_lossy(&invalid_utf8);
        let path = PathBuf::from("test_invalid.php");
        let report = analyzer.analyze_source(&path, &content).unwrap();
        assert_eq!(report.target.file_type, "php");
    }
}
