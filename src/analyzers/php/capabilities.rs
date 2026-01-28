//! PHP capability detection.

use crate::types::*;
use tree_sitter;

impl super::PhpAnalyzer {
    pub(super) fn detect_capabilities(
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
}
