//! Capability detection for Go source code.
//!
//! Analyzes Go AST for malicious patterns including:
//! - Command execution
//! - Network operations
//! - Crypto operations (ransomware indicators)
//! - File operations
//! - Reflection/obfuscation
//! - Container/cloud operations

use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};

impl super::GoAnalyzer {
    pub(super) fn detect_capabilities(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let mut cursor = node.walk();
        self.walk_ast(&mut cursor, source, report);
    }

    pub(super) fn walk_ast(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
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
            for (cap_id, description, pattern, conf, criticality) in capabilities {
                if !report.findings.iter().any(|c| c.id == cap_id) {
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: cap_id.to_string(),
                        desc: description.to_string(),
                        conf,
                        crit: criticality,
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
                ("syscall", "sys/syscall", "Direct system call access", 0.85),
                ("unsafe", "unsafe/pointer", "Unsafe operations", 0.8),
                ("plugin", "exec/dylib/load", "Dynamic plugin loading", 0.85),
                ("reflect", "anti-analysis/reflection", "Reflection capabilities", 0.75),
            ];

            for (import_name, cap_id, description, conf) in &suspicious_imports {
                if text.contains(import_name)
                    && !report.findings.iter().any(|c| c.id == *cap_id) {
                        report.findings.push(Finding {
                            kind: FindingKind::Capability,
                            trait_refs: vec![],
                            id: cap_id.to_string(),
                            desc: description.to_string(),
                            conf: *conf,
                            crit: Criticality::Notable,
                            mbc: None,
                            attack: None,
                            evidence: vec![Evidence {
                                method: "import".to_string(),
                                source: "tree-sitter-go".to_string(),
                                value: import_name.to_string(),
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
            // Detect Base64/Hex decoding as potential obfuscation
            if (text.contains("base64.StdEncoding.DecodeString")
                || text.contains("base64.URLEncoding.DecodeString"))
                && !report
                    .findings
                    .iter()
                    .any(|c| c.id == "anti-analysis/obfuscation/base64")
                {
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: "anti-analysis/obfuscation/base64".to_string(),
                        desc: "Base64 decoding".to_string(),
                        conf: 0.85,
                        crit: Criticality::Suspicious,
                        mbc: None,
                        attack: None,
                        evidence: vec![Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-go".to_string(),
                            value: "base64 decode".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }

            if text.contains("hex.DecodeString")
                && !report
                    .findings
                    .iter()
                    .any(|c| c.id == "anti-analysis/obfuscation/hex")
                {
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: "anti-analysis/obfuscation/hex".to_string(),
                        desc: "Hex decoding".to_string(),
                        conf: 0.8,
                        crit: Criticality::Suspicious,
                        mbc: None,
                        attack: None,
                        evidence: vec![Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-go".to_string(),
                            value: "hex decode".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }

            // Detect XOR operations on byte arrays (common obfuscation)
            if text.contains("^") && (text.contains("byte") || text.contains("[]uint8"))
                && !report
                    .findings
                    .iter()
                    .any(|c| c.id == "anti-analysis/obfuscation/xor")
                {
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: "anti-analysis/obfuscation/xor".to_string(),
                        desc: "XOR operations on byte arrays".to_string(),
                        conf: 0.75,
                        crit: Criticality::Suspicious,
                        mbc: None,
                        attack: None,
                        evidence: vec![Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-go".to_string(),
                            value: "xor bytes".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }
        }
    }
}
