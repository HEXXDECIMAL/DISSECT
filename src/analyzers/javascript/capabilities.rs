//! Capability detection for JavaScript code
//!
//! This module implements AST traversal and pattern matching to detect:
//! - Dangerous APIs (eval, exec, file system operations)
//! - Network operations (HTTP, sockets)
//! - Obfuscation patterns (base64, string manipulation)
//! - Supply chain attack indicators
//! - NPM malware signatures

use crate::types::*;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use super::JavaScriptAnalyzer;
use super::patterns::{add_capability_if_missing, analyze_call, analyze_import, check_obfuscation, scan_decoded_payload};

/// Detect capabilities by walking the AST
pub(crate) fn detect_capabilities(
    analyzer: &JavaScriptAnalyzer,
    node: &tree_sitter::Node,
    source: &[u8],
    report: &mut AnalysisReport,
) {
    let mut cursor = node.walk();
    walk_ast(analyzer, &mut cursor, source, report, 0);
}

/// Walk AST iteratively to detect malware patterns
///
/// Uses fully iterative traversal to avoid stack overflow on deeply nested ASTs
/// (common in obfuscated/minified JS which can have thousands of nesting levels)
pub(crate) fn walk_ast(
    analyzer: &JavaScriptAnalyzer,
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    report: &mut AnalysisReport,
    _depth: u32,
) {
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
                desc: "Extremely deep AST nesting (>500 levels)".to_string(),
                conf: 0.95,
                crit: Criticality::Suspicious,
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
                analyze_call(analyzer, &node, source, report);
            }
            "import_statement" => {
                analyze_import(analyzer, &node, source, report);
            }
            "variable_declarator" => {
                check_obfuscation(analyzer, &node, source, report);
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

/// Check for cross-statement obfuscation patterns
pub(crate) fn check_global_obfuscation(
    _analyzer: &JavaScriptAnalyzer,
    content: &str,
    report: &mut AnalysisReport,
) {
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
            desc: "Base64 decode followed by eval (obfuscation)".to_string(),
            conf: 0.95,
            crit: Criticality::Suspicious,
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
pub(crate) fn check_supply_chain_patterns(
    _analyzer: &JavaScriptAnalyzer,
    content: &str,
    report: &mut AnalysisReport,
) {
    // 1. GitHub Actions exec patterns with bash
    if (content.contains("getExecOutput") || content.contains("exec.exec"))
        && content.contains("bash")
    {
        add_capability_if_missing(
            report,
            "exec/ci-pipeline/shell",
            "CI/CD pipeline shell execution",
            Criticality::Notable,
            "getExecOutput+bash",
        );
    }

    // 2. Silent/stealth execution (hiding output)
    if content.contains("silent: true") || content.contains("silent:true") {
        add_capability_if_missing(
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
                        add_capability_if_missing(
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
                            scan_decoded_payload(&decoded, report);
                        }
                    }
                }
            }
        }
    }

    // 5. Secret/credential access patterns in CI context
    if content.contains("isSecret") && content.contains("true") {
        add_capability_if_missing(
            report,
            "data/secret-access",
            "Accessing secrets/credentials",
            Criticality::Suspicious,
            "isSecret:true",
        );
    }
}

/// Check for npm malware patterns that can't be expressed in YAML
///
/// Counting patterns (obfuscator variables, hex literals) are now in YAML with search_raw: true
pub(crate) fn check_npm_malware_patterns(
    _analyzer: &JavaScriptAnalyzer,
    content: &str,
    report: &mut AnalysisReport,
) {
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
        add_capability_if_missing(
            report,
            "c2/hardcoded-ip",
            "Hardcoded IP address (potential C2 server)",
            Criticality::Suspicious,
            match_str,
        );
        break; // Only report once
    }
}
