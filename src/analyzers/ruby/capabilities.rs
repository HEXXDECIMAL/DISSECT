//! Ruby capability detection.

use crate::types::*;
use tree_sitter;

impl super::RubyAnalyzer {
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
                "call" | "method_call" => {
                    self.analyze_call(&node, source, report);
                }
                "command" => {
                    self.analyze_command(&node, source, report);
                }
                "require" | "require_relative" => {
                    self.analyze_require(&node, source, report);
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
        if let Ok(text) = node.utf8_text(source) {
            // Most detection is now handled by YAML traits
            // Keep only a few critical patterns that need AST-level analysis
            let mut capabilities = Vec::new();

            // Command execution in Ruby - suspicious but common in legitimate scripts
            if text.contains("system(") || text.contains("system ") {
                capabilities.push((
                    "exec/command/shell",
                    "system() command execution",
                    "system",
                    0.9,
                    Criticality::Suspicious,
                ));
            }
            if text.contains("exec(") || text.contains("exec ") {
                capabilities.push((
                    "exec/command/shell",
                    "exec() replaces current process",
                    "exec",
                    0.85,
                    Criticality::Suspicious,
                ));
            }
            if text.contains("spawn(") || text.contains("spawn ") {
                capabilities.push((
                    "exec/command/shell",
                    "spawn() command execution",
                    "spawn",
                    0.9,
                    Criticality::Notable,
                ));
            }
            if text.contains("IO.popen") || text.contains("popen") {
                capabilities.push((
                    "exec/command/shell",
                    "popen command execution",
                    "popen",
                    0.95,
                    Criticality::Notable,
                ));
            }
            if text.contains("`") || text.contains("%x") {
                capabilities.push((
                    "exec/command/shell",
                    "Backtick command execution",
                    "backticks",
                    0.95,
                    Criticality::Notable,
                ));
            }

            // Dynamic code execution (eval family)
            if text.contains("eval(") || text.contains("eval ") {
                capabilities.push((
                    "exec/eval",
                    "eval() dynamic code execution",
                    "eval",
                    0.95,
                    Criticality::Notable,
                ));
            }
            if text.contains("instance_eval") {
                capabilities.push((
                    "exec/eval",
                    "instance_eval dynamic execution",
                    "instance_eval",
                    0.9,
                    Criticality::Notable,
                ));
            }
            if text.contains("class_eval") || text.contains("module_eval") {
                capabilities.push((
                    "exec/eval",
                    "class/module_eval dynamic execution",
                    "class_eval",
                    0.9,
                    Criticality::Notable,
                ));
            }
            if text.contains("Binding.eval") {
                capabilities.push((
                    "exec/eval",
                    "Binding.eval execution",
                    "Binding.eval",
                    0.9,
                    Criticality::Notable,
                ));
            }

            // Deserialization (Marshal)
            if text.contains("Marshal.load") || text.contains("Marshal.restore") {
                capabilities.push((
                    "anti-analysis/deserialization",
                    "Marshal deserialization",
                    "Marshal.load",
                    0.95,
                    Criticality::Notable,
                ));
            }
            if text.contains("YAML.load") && !text.contains("YAML.safe_load") {
                capabilities.push((
                    "anti-analysis/deserialization",
                    "YAML unsafe deserialization",
                    "YAML.load",
                    0.9,
                    Criticality::Notable,
                ));
            }

            // Network operations - HTTP GET (malware dropper pattern)
            if text.contains("Net::HTTP.get_response") || text.contains("Net::HTTP.get") {
                capabilities.push((
                    "exfil/network/http-get",
                    "HTTP GET request",
                    "Net::HTTP.get_response",
                    0.95,
                    Criticality::Notable,
                ));
            }
            if text.contains("Net::HTTP.post") {
                capabilities.push((
                    "exfil/network/http-post",
                    "HTTP POST request",
                    "Net::HTTP.post",
                    0.9,
                    Criticality::Notable,
                ));
            }
            if text.contains("Net::HTTP") {
                capabilities.push((
                    "net/http/client",
                    "HTTP client",
                    "Net::HTTP",
                    0.8,
                    Criticality::Notable,
                ));
            }
            if text.contains("TCPSocket") {
                capabilities.push((
                    "net/socket/create",
                    "TCP socket",
                    "TCPSocket",
                    0.9,
                    Criticality::Notable,
                ));
            }
            if text.contains("TCPServer") {
                capabilities.push((
                    "net/socket/server",
                    "TCP server",
                    "TCPServer",
                    0.9,
                    Criticality::Notable,
                ));
            }
            if text.contains("UDPSocket") {
                capabilities.push((
                    "net/socket/create",
                    "UDP socket",
                    "UDPSocket",
                    0.9,
                    Criticality::Notable,
                ));
            }

            // DNS resolution (often precedes C2 connection)
            if text.contains("Resolv.getaddress") || text.contains("Resolv.getname") {
                capabilities.push((
                    "intel/discover/system/hostname",
                    "DNS resolution",
                    "Resolv.getaddress",
                    0.9,
                    Criticality::Notable,
                ));
            }

            // Base64 encoding/decoding (often obfuscation)
            if text.contains("Base64.decode64") || text.contains("Base64.strict_decode64") {
                capabilities.push((
                    "anti-analysis/obfuscation/base64",
                    "Base64 decode",
                    "Base64.decode64",
                    0.85,
                    Criticality::Notable,
                ));
            }
            if text.contains("Base64.encode64") || text.contains("Base64.strict_encode64") {
                capabilities.push((
                    "anti-analysis/obfuscation/base64",
                    "Base64 encode",
                    "Base64.encode64",
                    0.75,
                    Criticality::Notable,
                ));
            }

            // File operations - HOSTILE when writing executables or in /tmp
            if text.contains("File.open")
                && (text.contains("'wb")
                    || text.contains("\"wb")
                    || text.contains("'wb+")
                    || text.contains("\"wb+"))
            {
                capabilities.push((
                    "fs/write-binary",
                    "Write binary file",
                    "File.open(wb)",
                    0.95,
                    Criticality::Notable,
                ));
            }
            if text.contains("/tmp/") && text.contains("File.") {
                capabilities.push((
                    "fs/write-tmp",
                    "Write to /tmp directory",
                    "/tmp/",
                    0.9,
                    Criticality::Notable,
                ));
            }
            if text.contains("File.chmod") || text.contains(".chmod(") {
                capabilities.push((
                    "fs/permission-modify",
                    "Modify file permissions",
                    "chmod",
                    0.95,
                    Criticality::Notable,
                ));
            }
            // Highly suspicious: chmod 0777 (rwxrwxrwx)
            if text.contains("chmod(0777)")
                || text.contains("chmod 0777")
                || text.contains("chmod(0o777)")
            {
                capabilities.push((
                    "fs/permission-modify/world-executable",
                    "Make file world-executable",
                    "chmod 0777",
                    0.98,
                    Criticality::Hostile,
                ));
            }
            if text.contains(".binmode") {
                capabilities.push((
                    "fs/write-binary/binmode",
                    "Binary file mode",
                    "binmode",
                    0.9,
                    Criticality::Notable,
                ));
            }
            if text.contains("FileUtils.rm_rf") {
                capabilities.push((
                    "fs/delete",
                    "Recursive directory deletion",
                    "rm_rf",
                    0.95,
                    Criticality::Notable,
                ));
            }
            if text.contains("File.delete") || text.contains("File.unlink") {
                capabilities.push((
                    "fs/delete",
                    "Delete file",
                    "File.delete",
                    0.9,
                    Criticality::Notable,
                ));
            }

            // Malware dropper pattern: HTTP + /tmp + chmod + system
            if text.contains("Net::HTTP") && text.contains("/tmp/") {
                capabilities.push((
                    "c2/dropper/download-tmp",
                    "Download to /tmp",
                    "HTTP+/tmp",
                    0.95,
                    Criticality::Hostile,
                ));
            }
            if text.contains("chmod") && text.contains("system(") {
                capabilities.push((
                    "c2/dropper/chmod-exec",
                    "Make downloaded file executable",
                    "chmod+system",
                    0.98,
                    Criticality::Hostile,
                ));
            }

            // Reverse shell pattern
            if (text.contains("TCPSocket") || text.contains("socket"))
                && (text.contains("system") || text.contains("exec") || text.contains("/bin/sh"))
            {
                capabilities.push((
                    "c2/shells/reverse",
                    "Reverse shell connection",
                    "socket+exec",
                    0.98,
                    Criticality::Hostile,
                ));
            }

            // Reflection/Metaprogramming
            if text.contains(".send(") || text.contains(".send ") {
                capabilities.push((
                    "anti-analysis/reflection",
                    "Dynamic method invocation",
                    "send",
                    0.85,
                    Criticality::Notable,
                ));
            }
            if text.contains("const_get") {
                capabilities.push((
                    "anti-analysis/reflection",
                    "Dynamic constant access",
                    "const_get",
                    0.85,
                    Criticality::Notable,
                ));
            }
            if text.contains("const_set") {
                capabilities.push((
                    "anti-analysis/reflection",
                    "Dynamic constant definition",
                    "const_set",
                    0.85,
                    Criticality::Notable,
                ));
            }
            if text.contains("define_method") {
                capabilities.push((
                    "anti-analysis/reflection",
                    "Dynamic method definition",
                    "define_method",
                    0.85,
                    Criticality::Notable,
                ));
            }

            // Process manipulation
            if text.contains("Process.setuid") || text.contains("Process.setgid") {
                capabilities.push((
                    "privilege/setuid",
                    "Set user/group ID",
                    "setuid/setgid",
                    0.95,
                    Criticality::Notable,
                ));
            }
            if text.contains("Process.kill") {
                capabilities.push((
                    "process/terminate",
                    "Kill process",
                    "Process.kill",
                    0.9,
                    Criticality::Notable,
                ));
            }
            if text.contains("Process.daemon") {
                capabilities.push((
                    "process/daemonize",
                    "Daemonize process",
                    "Process.daemon",
                    0.9,
                    Criticality::Notable,
                ));
            }

            // Environment variable access
            if text.contains("ENV[") || text.contains("ENV.fetch") {
                capabilities.push((
                    "os/env/read",
                    "Read environment variables",
                    "ENV",
                    0.8,
                    Criticality::Notable,
                ));
            }

            // Add capabilities
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
                        source: "tree-sitter-ruby".to_string(),
                        value: method.to_string(),
                        location: Some(format!(
                            "{}:{}",
                            node.start_position().row,
                            node.start_position().column
                        )),
                    }],
                });
            }
        }
    }

    fn analyze_command(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        // Ruby command nodes (backticks, %x, etc.)
        if let Ok(_text) = node.utf8_text(source) {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "exec/command/shell".to_string(),
                desc: "Shell command execution".to_string(),
                conf: 0.95,
                crit: Criticality::Notable,

                mbc: None,

                attack: None,

                evidence: vec![Evidence {
                    method: "ast".to_string(),
                    source: "tree-sitter-ruby".to_string(),
                    value: "command".to_string(),
                    location: Some(format!(
                        "{}:{}",
                        node.start_position().row,
                        node.start_position().column
                    )),
                }],
            });
        }
    }

    fn analyze_require(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        if let Ok(text) = node.utf8_text(source) {
            let mut capabilities = Vec::new();

            // Network libraries (critical when combined with other suspicious behavior)
            if text.contains("'net/http'") || text.contains("\"net/http\"") {
                capabilities.push((
                    "net/http/client",
                    "HTTP client library",
                    "net/http",
                    0.8,
                    Criticality::Notable,
                ));
            }
            if text.contains("'socket'") || text.contains("\"socket\"") {
                capabilities.push((
                    "net/socket/create",
                    "Socket library",
                    "socket",
                    0.8,
                    Criticality::Notable,
                ));
            }
            if text.contains("'open-uri'") || text.contains("\"open-uri\"") {
                capabilities.push((
                    "net/http/client",
                    "Open-URI library",
                    "open-uri",
                    0.75,
                    Criticality::Notable,
                ));
            }
            if text.contains("'uri'") || text.contains("\"uri\"") {
                capabilities.push((
                    "net/url",
                    "URI parsing library",
                    "uri",
                    0.7,
                    Criticality::Notable,
                ));
            }

            // Encoding/decoding libraries (obfuscation)
            if text.contains("'base64'") || text.contains("\"base64\"") {
                capabilities.push((
                    "anti-analysis/obfuscation/base64",
                    "Base64 library",
                    "base64",
                    0.8,
                    Criticality::Notable,
                ));
            }
            if text.contains("'digest'") || text.contains("\"digest\"") {
                capabilities.push((
                    "crypto/hash",
                    "Digest library",
                    "digest",
                    0.7,
                    Criticality::Notable,
                ));
            }

            // DNS resolution
            if text.contains("'resolv'") || text.contains("\"resolv\"") {
                capabilities.push((
                    "intel/discover/system/hostname",
                    "DNS resolution library",
                    "resolv",
                    0.85,
                    Criticality::Notable,
                ));
            }

            // File operations
            if text.contains("'fileutils'") || text.contains("\"fileutils\"") {
                capabilities.push((
                    "fs/write",
                    "File utilities library",
                    "fileutils",
                    0.7,
                    Criticality::Notable,
                ));
            }
            if text.contains("'tempfile'") || text.contains("\"tempfile\"") {
                capabilities.push((
                    "fs/write-tmp",
                    "Temporary file library",
                    "tempfile",
                    0.75,
                    Criticality::Notable,
                ));
            }

            // Process/system interaction
            if text.contains("'pty'") || text.contains("\"pty\"") {
                capabilities.push((
                    "exec/terminal",
                    "PTY (pseudo-terminal) library",
                    "pty",
                    0.85,
                    Criticality::Notable,
                ));
            }
            if text.contains("'etc'") || text.contains("\"etc\"") {
                capabilities.push((
                    "intel/discover/system",
                    "System information library",
                    "etc",
                    0.7,
                    Criticality::Notable,
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
                        method: "import".to_string(),
                        source: "tree-sitter-ruby".to_string(),
                        value: method.to_string(),
                        location: Some(format!(
                            "{}:{}",
                            node.start_position().row,
                            node.start_position().column
                        )),
                    }],
                });
            }
        }
    }
}
