//! Pattern analysis and detection for JavaScript code
//!
//! This module implements pattern matching for:
//! - Function call analysis (eval, exec, file operations)
//! - Import/require statement analysis
//! - Obfuscation detection (base64, hex encoding, string manipulation)
//! - Decoded payload scanning

use crate::types::*;

use super::JavaScriptAnalyzer;

/// Analyze function call expressions for capabilities
pub(crate) fn analyze_call(
    _analyzer: &JavaScriptAnalyzer,
    node: &tree_sitter::Node,
    source: &[u8],
    report: &mut AnalysisReport,
) {
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
                    desc: description.to_string(),
                    conf: 1.0,
                    crit: criticality,
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

/// Analyze import/require statements
pub(crate) fn analyze_import(
    _analyzer: &JavaScriptAnalyzer,
    node: &tree_sitter::Node,
    source: &[u8],
    report: &mut AnalysisReport,
) {
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
                    desc: description.to_string(),
                    conf: 0.7, // Import alone is not definitive
                    crit: criticality,
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

/// Check for obfuscation patterns in variable declarations
pub(crate) fn check_obfuscation(
    _analyzer: &JavaScriptAnalyzer,
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
                desc: "Base64 decode followed by eval (obfuscation)".to_string(),
                conf: 0.95,
                crit: Criticality::Suspicious,
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
                desc: "Hex-encoded strings".to_string(),
                conf: 0.9,
                crit: Criticality::Suspicious,
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
                desc: "String manipulation obfuscation".to_string(),
                conf: 0.9,
                crit: Criticality::Suspicious,
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
                desc: "Character-by-character string construction".to_string(),
                conf: 0.85,
                crit: Criticality::Suspicious,
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

/// Helper to add capability if not already present
pub(crate) fn add_capability_if_missing(
    report: &mut AnalysisReport,
    cap_id: &str,
    desc: &str,
    crit: Criticality,
    evidence_value: &str,
) {
    if !report.findings.iter().any(|c| c.id == cap_id) {
        report.findings.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: cap_id.to_string(),
            desc: desc.to_string(),
            conf: 0.9,
            crit,
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
pub(crate) fn scan_decoded_payload(decoded: &str, report: &mut AnalysisReport) {
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
            add_capability_if_missing(
                report,
                cap_id,
                description,
                Criticality::Hostile,
                &format!("[decoded] {}", pattern),
            );
        }
    }
}
