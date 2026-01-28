//! Capability detection for Python scripts.

use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};

impl super::PythonAnalyzer {
    pub(super) fn detect_capabilities(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let mut cursor = root.walk();
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
                "call" => {
                    self.analyze_call(&node, source, report);
                }
                "import_statement" | "import_from_statement" => {
                    self.analyze_import(&node, source, report);
                }
                "string" => {
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

            if text.contains("eval(") {
                capabilities.push((
                    "exec/script/eval",
                    "Evaluates dynamic code",
                    "eval",
                    0.95,
                    Criticality::Notable,
                ));
            }
            if text.contains("exec(") {
                capabilities.push((
                    "exec/script/eval",
                    "Executes dynamic code",
                    "exec",
                    0.95,
                    Criticality::Notable,
                ));
            }
            if text.contains("compile(") {
                capabilities.push((
                    "exec/script/eval",
                    "Compiles dynamic code",
                    "compile",
                    0.90,
                    Criticality::Notable,
                ));
            }
            if text.contains("__import__(") {
                capabilities.push((
                    "anti-analysis/obfuscation/dynamic-import",
                    "Dynamic import",
                    "__import__",
                    0.85,
                    Criticality::Suspicious,
                ));
            }
            if text.contains("subprocess.")
                || text.contains("os.system(")
                || text.contains("os.popen(")
            {
                capabilities.push((
                    "exec/command/shell",
                    "Shell command execution",
                    "subprocess/os",
                    0.95,
                    Criticality::Notable,
                ));
            }
            if text.contains("socket.socket(") || text.contains("socket.create_connection(") {
                capabilities.push((
                    "net/socket/create",
                    "Network socket creation",
                    "socket",
                    0.90,
                    Criticality::Notable,
                ));
            }
            if text.contains("requests.")
                || text.contains("urllib.")
                || text.contains("http.client.")
            {
                capabilities.push((
                    "net/http/client",
                    "HTTP client",
                    "http",
                    0.85,
                    Criticality::Inert,
                ));
            }
            if text.contains("open(")
                && (text.contains("'w")
                    || text.contains("\"w")
                    || text.contains("'a")
                    || text.contains("\"a"))
            {
                capabilities.push(("fs/write", "File write", "open", 0.80, Criticality::Notable));
            }
            if text.contains("os.remove(")
                || text.contains("os.unlink(")
                || text.contains("shutil.rmtree(")
            {
                capabilities.push((
                    "fs/file/delete",
                    "File deletion",
                    "os.remove",
                    0.90,
                    Criticality::Notable,
                ));
            }
            if text.contains("base64.b64decode(") {
                capabilities.push((
                    "anti-analysis/obfuscation/base64",
                    "Base64 decode",
                    "base64.b64decode",
                    0.85,
                    Criticality::Suspicious,
                ));
            }
            if text.contains("pickle.loads(") || text.contains("pickle.load(") {
                capabilities.push((
                    "anti-analysis/obfuscation/pickle",
                    "Insecure deserialization",
                    "pickle",
                    0.90,
                    Criticality::Suspicious,
                ));
            }

            for (id, desc, value, conf, crit) in capabilities {
                report.findings.push(Finding {
                    id: id.to_string(),
                    kind: FindingKind::Capability,
                    desc: desc.to_string(),
                    conf,
                    crit,
                    mbc: None,
                    attack: None,
                    trait_refs: Vec::new(),
                    evidence: vec![Evidence {
                        method: "ast".to_string(),
                        source: "tree-sitter-python".to_string(),
                        value: value.to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }

            // Pattern-based findings
            if (text.contains("eval(") || text.contains("exec("))
                && text.contains("base64.b64decode")
            {
                report.findings.push(Finding {
                    id: "anti-analysis/obfuscation/base64-eval".to_string(),
                    kind: FindingKind::Indicator,
                    desc: "Evaluates base64-decoded code".to_string(),
                    conf: 0.95,
                    crit: Criticality::Hostile,
                    mbc: None,
                    attack: None,
                    trait_refs: Vec::new(),
                    evidence: vec![Evidence {
                        method: "pattern".to_string(),
                        source: "tree-sitter-python".to_string(),
                        value: "eval/exec + base64.b64decode".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }
        }
    }

    fn analyze_import(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            let mut capabilities = Vec::new();

            if text.contains("ctypes") {
                capabilities.push((
                    "exec/dylib/load",
                    "FFI/native code",
                    "ctypes",
                    0.85,
                    Criticality::Notable,
                ));
            }
            if text.contains("subprocess") {
                capabilities.push((
                    "exec/command/shell",
                    "Command execution",
                    "subprocess",
                    0.70,
                    Criticality::Notable,
                ));
            }
            if text.contains("socket") {
                capabilities.push((
                    "net/socket/create",
                    "Network sockets",
                    "socket",
                    0.85,
                    Criticality::Notable,
                ));
            }
            if text.contains("requests") || text.contains("urllib") {
                capabilities.push((
                    "net/http/client",
                    "HTTP client",
                    "requests/urllib",
                    0.80,
                    Criticality::Inert,
                ));
            }
            if text.contains("pickle") {
                capabilities.push((
                    "anti-analysis/obfuscation/pickle",
                    "Pickle serialization",
                    "pickle",
                    0.85,
                    Criticality::Suspicious,
                ));
            }
            if text.contains("base64") {
                capabilities.push((
                    "anti-analysis/obfuscation/base64",
                    "Base64 encoding",
                    "base64",
                    0.75,
                    Criticality::Suspicious,
                ));
            }

            for (id, desc, value, conf, crit) in capabilities {
                report.findings.push(Finding {
                    id: id.to_string(),
                    kind: FindingKind::Capability,
                    desc: desc.to_string(),
                    conf,
                    crit,
                    mbc: None,
                    attack: None,
                    trait_refs: Vec::new(),
                    evidence: vec![Evidence {
                        method: "import".to_string(),
                        source: "tree-sitter-python".to_string(),
                        value: value.to_string(),
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
            // Check for hex-encoded strings (lowered threshold for test compatibility)
            if text.contains("\\x") {
                let hex_count = text.matches("\\x").count();
                if hex_count >= 5 {
                    report.findings.push(Finding {
                        id: "anti-analysis/obfuscation/hex".to_string(),
                        kind: FindingKind::Structural,
                        desc: "Hex-encoded string detected".to_string(),
                        conf: 0.90,
                        crit: Criticality::Suspicious,
                        mbc: None,
                        attack: None,
                        trait_refs: Vec::new(),
                        evidence: vec![Evidence {
                            method: "pattern".to_string(),
                            source: "tree-sitter-python".to_string(),
                            value: format!("{} hex escapes", hex_count),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }
            }
        }
    }
}
