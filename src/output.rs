//! Output formatting and reporting.
//!
//! This module handles formatting analysis results for different output modes:
//! - Human-readable terminal output with colors
//! - JSON output for machine consumption
//! - Summary classification for quick triage
//!
//! # Output Modes
//!
//! - Default: Human-readable with colored output
//! - `--json`: Full JSON report
//! - `--summary`: Quick classification only

use crate::types::{AnalysisReport, Criticality, Finding, FindingKind, YaraMatch};
use anyhow::Result;
use colored::Colorize;
use std::collections::HashMap;

/// Program summary for quick classification
pub struct ProgramSummary {
    /// Classification: "infostealer", "ransomware", "backdoor", "cryptominer", "legitimate", "unknown"
    pub classification: String,
    /// Malware family if detected (e.g., "AMOS", "Mirai", "XMRig")
    pub malware_family: Option<String>,
    /// Overall risk level
    pub risk_level: Criticality,
    /// Key capabilities (top 3-5)
    pub key_capabilities: Vec<String>,
    /// Brief description of what this program does
    pub desc: String,
}

/// Extract directory path from trait ID (everything except the last component)
/// e.g., "exec/command/subprocess/popen" -> "exec/command/subprocess"
/// e.g., "malware/cryptominer/monero/wallet-address" -> "malware/cryptominer/monero"
pub fn get_directory_path(id: &str) -> String {
    let parts: Vec<&str> = id.split('/').collect();
    if parts.len() > 1 {
        parts[..parts.len() - 1].join("/")
    } else {
        id.to_string()
    }
}

/// Aggregated finding for a directory path
#[derive(Clone)]
struct AggregatedFinding {
    /// The directory path (e.g., "exec/command/subprocess")
    directory: String,
    /// The best (highest criticality) finding
    best: Finding,
    /// All trait IDs that matched in this directory
    matched_traits: Vec<String>,
}

/// Aggregate findings by directory path, keeping highest criticality (then highest conf)
/// Returns findings with IDs set to directory paths and trait_refs containing all matched trait IDs
pub fn aggregate_findings_by_directory(findings: &[Finding]) -> Vec<Finding> {
    let mut aggregated: HashMap<String, AggregatedFinding> = HashMap::new();

    for finding in findings {
        let dir_path = get_directory_path(&finding.id);

        match aggregated.get_mut(&dir_path) {
            None => {
                aggregated.insert(
                    dir_path.clone(),
                    AggregatedFinding {
                        directory: dir_path,
                        best: finding.clone(),
                        matched_traits: vec![finding.id.clone()],
                    },
                );
            }
            Some(agg) => {
                // Add this trait ID to the list
                if !agg.matched_traits.contains(&finding.id) {
                    agg.matched_traits.push(finding.id.clone());
                }

                // Keep the one with higher criticality
                // If criticality is same, keep the one with higher confidence
                let should_replace = finding.crit > agg.best.crit
                    || (finding.crit == agg.best.crit && finding.conf > agg.best.conf);

                if should_replace {
                    agg.best = finding.clone();
                }
            }
        }
    }

    // Convert aggregated findings to Finding structs with directory as ID
    aggregated
        .into_values()
        .map(|agg| {
            let mut result = agg.best;
            result.id = agg.directory;
            result.trait_refs = agg.matched_traits;
            result
        })
        .collect()
}

/// Convert YARA matches to findings for unified display
fn yara_to_findings(yara_matches: &[YaraMatch]) -> Vec<Finding> {
    yara_matches
        .iter()
        .map(|m| {
            let criticality = match m.severity.as_str() {
                "critical" | "high" => Criticality::Hostile,
                "medium" => Criticality::Suspicious,
                "low" => Criticality::Notable,
                _ => Criticality::Inert,
            };

            // Extract namespace for finding ID (e.g., "traits.intel.discover" -> "intel/discover")
            let id = if m.namespace.starts_with("traits.") {
                m.namespace[7..].replace('.', "/") + "/" + &m.rule
            } else if m.namespace.starts_with("third_party.") {
                "3P/".to_string() + &m.rule
            } else {
                m.namespace.clone() + "/" + &m.rule
            };

            let evidence = m
                .matched_strings
                .iter()
                .take(3)
                .map(|ms| crate::types::Evidence {
                    method: "yara".to_string(),
                    source: "yara-x".to_string(),
                    value: ms.value.clone(),
                    location: Some(format!("0x{:x}", ms.offset)),
                })
                .collect();

            Finding {
                id,
                kind: FindingKind::Indicator,
                desc: m.desc.clone(),
                conf: 0.7, // Default for YARA matches
                crit: criticality,
                mbc: None,
                attack: None,
                trait_refs: vec![],
                evidence,
            }
        })
        .collect()
}

/// Get risk emoji based on criticality
fn risk_emoji(crit: &Criticality) -> &'static str {
    match crit {
        Criticality::Filtered => "⬜",
        Criticality::Inert => "⚪",
        Criticality::Notable => "🔵",
        Criticality::Suspicious => "🟡",
        Criticality::Hostile => "🛑",
    }
}

/// Get risk level name
/// Split trait ID into namespace and rest (e.g., "intel/discover/process/getuid" -> ("intel", "discover/process/getuid"))
/// For IDs without a slash, use the ID itself as both namespace and rest
fn split_trait_id(id: &str) -> (String, String) {
    let parts: Vec<&str> = id.split('/').collect();
    if parts.len() > 1 {
        (parts[0].to_string(), parts[1..].join("/"))
    } else {
        (id.to_string(), id.to_string())
    }
}

/// Convert namespace to long name, falling back to original if no mapping exists
fn namespace_long_name(ns: &str) -> &str {
    match ns {
        "c2" => "C2",
        "intel" => "discovery",
        "crypto" => "crypto",
        "exfil" => "exfiltration",
        "exec" => "execution",
        "fs" => "filesystem",
        "hw" => "hardware",
        "net" => "network",
        "os" => "OS",
        "3P" => "third-party",
        "persistence" => "persistence",
        "anti-analysis" => "anti-analysis",
        "anti-static" => "static evasion",
        "evasion" => "evasion",
        "privesc" => "privilege escalation",
        "process" => "process",
        "mem" => "memory",
        "data" => "data",
        "impact" => "impact",
        "access" => "access",
        "credential" => "credentials",
        "cred" => "credentials",
        "lateral" => "lateral movement",
        "kernel" => "kernel",
        "reflect" => "reflection",
        "archive" => "archive",
        "comm" => "network",
        "collect" => "collection",
        "feat" => "features",
        "known-malware" => "known malware",
        _ => ns,
    }
}

/// Format evidence string (minimal, deduplicated)
/// Maximum width for evidence display (truncate if longer)
const EVIDENCE_MAX_WIDTH: usize = 80;

/// Make descriptions more terse by removing redundant explanatory parentheticals
fn terse_description(desc: &str) -> String {
    // Remove common verbose patterns that are redundant given the context
    desc.replace(" (timing attacks or sandbox detection)", "")
        .replace(" (C2 communication pattern)", "")
        .replace(" (comprehensive stealer)", "")
        .replace(" (monolithic multicall binary)", "")
        .replace(" (packer pattern)", "")
        .replace(" (potential stealer)", "")
        .replace(" (potential keylogger)", "")
        .replace(" (hardcoded alphabet + decode table)", "")
        .replace(" reveals directory contents", "")
        .replace(" (opendir + readdir + stat)", "")
        .replace(".DS_Store ", "")
        .replace(" (excluding known legitimate)", "")
        .trim()
        .to_string()
}

fn format_evidence(finding: &Finding) -> String {
    let mut seen = std::collections::HashSet::new();
    let values: Vec<String> = finding
        .evidence
        .iter()
        .filter_map(|e| {
            // Skip if evidence is already in the description
            if finding.desc.contains(&e.value) {
                None
            } else {
                Some(e.value.clone())
            }
        })
        .filter(|v| seen.insert(v.clone()))
        .take(5)
        .collect();

    if values.is_empty() {
        return String::new();
    }

    let joined = values.join(", ");

    // Truncate if too long for display
    if joined.len() > EVIDENCE_MAX_WIDTH {
        format!("{}...", &joined[..EVIDENCE_MAX_WIDTH - 3])
    } else {
        joined
    }
}

/// V2 JSON output structure - flat file-centric format
#[derive(serde::Serialize, serde::Deserialize)]
struct JsonOutputV2 {
    schema_version: String,
    analysis_timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    scanned_path: Option<String>,
    #[serde(default)]
    files: Vec<crate::types::FileAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    summary: Option<crate::types::ReportSummary>,
    metadata: crate::types::AnalysisMetadata,
}

/// Format analysis report as JSON (v2 format)
pub fn format_json(report: &AnalysisReport) -> Result<String> {
    let output = JsonOutputV2 {
        schema_version: report.schema_version.clone(),
        analysis_timestamp: report.analysis_timestamp,
        scanned_path: report.scanned_path.clone(),
        files: report.files.clone(),
        summary: report.summary.clone(),
        metadata: report.metadata.clone(),
    };
    Ok(serde_json::to_string_pretty(&output)?)
}

// =============================================================================
// JSONL (Newline-Delimited JSON) Output for Streaming
// =============================================================================

/// JSONL file entry - emitted for each file as it's analyzed
#[derive(serde::Serialize)]
struct JsonlFileEntry<'a> {
    #[serde(rename = "type")]
    entry_type: &'static str,
    #[serde(flatten)]
    file: &'a crate::types::FileAnalysis,
}

/// JSONL summary entry - emitted at the end of streaming output
#[derive(serde::Serialize)]
struct JsonlSummary {
    #[serde(rename = "type")]
    entry_type: &'static str,
    files_analyzed: u32,
    hostile: u32,
    suspicious: u32,
    notable: u32,
    analysis_duration_ms: u64,
}

/// Format a single file analysis as a JSONL line
pub fn format_jsonl_line(file: &crate::types::FileAnalysis) -> Result<String> {
    let entry = JsonlFileEntry {
        entry_type: "file",
        file,
    };
    Ok(serde_json::to_string(&entry)?)
}

/// Format the summary as a JSONL line (for end of streaming output)
pub fn format_jsonl_summary(report: &AnalysisReport) -> Result<String> {
    let summary = report.summary.as_ref();
    let counts = summary.map(|s| &s.counts);

    let entry = JsonlSummary {
        entry_type: "summary",
        files_analyzed: summary
            .map(|s| s.files_analyzed)
            .unwrap_or(report.files.len() as u32),
        hostile: counts.map(|c| c.hostile).unwrap_or(0),
        suspicious: counts.map(|c| c.suspicious).unwrap_or(0),
        notable: counts.map(|c| c.notable).unwrap_or(0),
        analysis_duration_ms: report.metadata.analysis_duration_ms,
    };
    Ok(serde_json::to_string(&entry)?)
}

/// Format entire report as JSONL (for non-streaming output)
pub fn format_jsonl(report: &AnalysisReport) -> Result<String> {
    let mut lines = Vec::with_capacity(report.files.len() + 1);

    // Emit each file as a line
    for file in &report.files {
        lines.push(format_jsonl_line(file)?);
    }

    // Emit summary at end
    lines.push(format_jsonl_summary(report)?);

    Ok(lines.join("\n"))
}

/// Parse v2 JSON back to AnalysisReport
pub fn parse_json_v2(json: &str) -> Result<AnalysisReport> {
    let v2: JsonOutputV2 = serde_json::from_str(json)?;

    // Create a minimal AnalysisReport with the v2 data
    let target = if let Some(first_file) = v2.files.first() {
        crate::types::TargetInfo {
            path: first_file.path.clone(),
            file_type: first_file.file_type.clone(),
            sha256: first_file.sha256.clone(),
            size_bytes: first_file.size,
            architectures: None,
        }
    } else {
        crate::types::TargetInfo {
            path: "unknown".to_string(),
            file_type: "unknown".to_string(),
            sha256: String::new(),
            size_bytes: 0,
            architectures: None,
        }
    };

    let mut report = AnalysisReport::new_with_timestamp(target, v2.analysis_timestamp);
    report.schema_version = v2.schema_version;
    report.scanned_path = v2.scanned_path;
    report.files = v2.files;
    report.summary = v2.summary;
    report.metadata = v2.metadata;

    Ok(report)
}

/// Format analysis report for terminal display (malcontent-style)
/// Uses the v2 flat files array structure.
pub fn format_terminal(report: &AnalysisReport) -> Result<String> {
    let mut output = String::new();

    // Iterate over files that have findings
    for file in &report.files {
        // Skip files with no findings
        if file.findings.is_empty() {
            continue;
        }

        // File header with risk indicator
        let risk_indicator = match file.risk {
            Some(Criticality::Hostile) => "🛑".to_string(),
            Some(Criticality::Suspicious) => "🟡".to_string(),
            Some(Criticality::Notable) => "🔵".to_string(),
            _ => "".to_string(),
        };

        output.push_str(&format!(
            "├─ {} {}\n",
            file.path.bright_white(),
            risk_indicator
        ));
        output.push_str("│\n");

        // Aggregate findings by directory path
        let aggregated = aggregate_findings_by_directory(&file.findings);

        // Filter: remove criticality=none and confidence<0.5
        let filtered: Vec<Finding> = aggregated
            .into_iter()
            .filter(|f| f.crit != Criticality::Inert && f.conf >= 0.5)
            .collect();

        if filtered.is_empty() {
            continue;
        }

        // Group by namespace
        let mut by_namespace: HashMap<String, Vec<&Finding>> = HashMap::new();
        let mut ns_max_crit: HashMap<String, Criticality> = HashMap::new();

        for finding in &filtered {
            let (ns, _) = split_trait_id(&finding.id);
            let current_max = ns_max_crit.get(&ns).unwrap_or(&Criticality::Inert);
            if &finding.crit > current_max {
                ns_max_crit.insert(ns.clone(), finding.crit);
            }
            by_namespace.entry(ns).or_default().push(finding);
        }

        // Sort namespaces by criticality then name
        let mut namespaces: Vec<String> = by_namespace.keys().cloned().collect();
        namespaces.sort_by(|a, b| {
            let crit_a = ns_max_crit.get(a).unwrap_or(&Criticality::Inert);
            let crit_b = ns_max_crit.get(b).unwrap_or(&Criticality::Inert);
            crit_b
                .cmp(crit_a)
                .then_with(|| namespace_long_name(a).cmp(namespace_long_name(b)))
        });

        // Render each namespace
        for ns in &namespaces {
            let findings = by_namespace.get(ns).unwrap();
            output.push_str(&format!("│     ≡ {}\n", namespace_long_name(ns)));

            let mut sorted_findings = findings.clone();
            sorted_findings.sort_by(|a, b| b.crit.cmp(&a.crit).then_with(|| a.id.cmp(&b.id)));

            for finding in sorted_findings {
                let (_, rest) = split_trait_id(&finding.id);
                let emoji = risk_emoji(&finding.crit);
                let evidence = format_evidence(finding);
                let desc = terse_description(&finding.desc);

                let content = match finding.crit {
                    Criticality::Hostile => format!("{} {} — {}", emoji, rest, desc).bright_red(),
                    Criticality::Suspicious => {
                        format!("{} {} — {}", emoji, rest, desc).bright_yellow()
                    }
                    _ => format!("{} {} — {}", emoji, rest, desc).bright_cyan(),
                };

                if evidence.is_empty() {
                    output.push_str(&format!("│       {}\n", content));
                } else {
                    // Strip ANSI codes for accurate length measurement
                    let ansi_re = regex::Regex::new(r"\x1b\[[0-9;]*m").unwrap();
                    let display_len = ansi_re
                        .replace_all(&format!("{}: {}", content, evidence), "")
                        .len();
                    if display_len > 120 {
                        output.push_str(&format!("│       {}\n", content));
                        output.push_str(&format!("│           {}\n", evidence.bright_black()));
                    } else {
                        output.push_str(&format!(
                            "│       {}{} {}\n",
                            content,
                            ":".bright_black(),
                            evidence.bright_black()
                        ));
                    }
                }
            }
            output.push_str("│\n");
        }
    }

    // If no files had findings, show a simple message
    if output.is_empty() {
        output.push_str(&format!("├─ {}\n", report.target.path.bright_white()));
        output.push_str("│  No findings\n");
    }

    output.push_str("│\n");
    Ok(output)
}

/// Calculate overall risk level for a report
fn calculate_overall_risk(report: &AnalysisReport) -> Criticality {
    let mut max = Criticality::Inert;

    for finding in &report.findings {
        if finding.crit > max {
            max = finding.crit;
        }
    }

    for yara_match in &report.yara_matches {
        let crit = match yara_match.severity.as_str() {
            "critical" | "high" => Criticality::Hostile,
            "medium" => Criticality::Suspicious,
            "low" => Criticality::Notable,
            _ => Criticality::Inert,
        };
        if crit > max {
            max = crit;
        }
    }

    max
}

/// Generate a program summary from analysis findings
pub fn generate_summary(report: &AnalysisReport) -> ProgramSummary {
    let mut classification = "unknown".to_string();
    let mut malware_family: Option<String> = None;
    let mut key_capabilities: Vec<String> = Vec::new();
    let mut description_parts: Vec<String> = Vec::new();

    let risk_level = calculate_overall_risk(report);

    // Combine all findings
    let mut all_findings: Vec<&Finding> = report.findings.iter().collect();
    let yara_findings: Vec<Finding> = yara_to_findings(&report.yara_matches);
    let yara_refs: Vec<&Finding> = yara_findings.iter().collect();
    all_findings.extend(yara_refs);

    // Check for malware family detection
    for finding in &all_findings {
        let id_lower = finding.id.to_lowercase();

        // Detect malware families
        if id_lower.contains("malware/stealer/amos") {
            classification = "macOS Infostealer".to_string();
            malware_family = Some("AMOS Stealer".to_string());
            description_parts
                .push("Steals browser credentials and cryptocurrency wallets".to_string());
        } else if id_lower.contains("malware/stealer/poseidon") {
            classification = "macOS Infostealer".to_string();
            malware_family = Some("Poseidon Stealer".to_string());
            description_parts.push("Steals browser credentials".to_string());
        } else if id_lower.contains("malware/botnet/mirai") {
            classification = "IoT Botnet".to_string();
            malware_family = Some("Mirai".to_string());
            description_parts.push("DDoS botnet targeting IoT devices".to_string());
        } else if id_lower.contains("malware/cryptominer/xmrig") {
            classification = "Cryptominer".to_string();
            malware_family = Some("XMRig".to_string());
            description_parts.push("Mines Monero cryptocurrency".to_string());
        } else if id_lower.contains("malware/ransomware") {
            classification = "Ransomware".to_string();
            if id_lower.contains("conti") {
                malware_family = Some("Conti".to_string());
            } else if id_lower.contains("mallox") {
                malware_family = Some("Mallox".to_string());
            }
            description_parts.push("Encrypts files for ransom".to_string());
        } else if id_lower.contains("malware/backdoor") {
            classification = "Backdoor".to_string();
            description_parts.push("Provides remote access".to_string());
        }

        // Collect key capabilities (hostile/suspicious only)
        if finding.crit >= Criticality::Suspicious {
            let cap = format_capability_short(&finding.id);
            if !key_capabilities.contains(&cap) && key_capabilities.len() < 5 {
                key_capabilities.push(cap);
            }
        }
    }

    // If no malware detected, classify based on capabilities
    if classification == "unknown" {
        classification = match risk_level {
            Criticality::Hostile => "Potentially Malicious".to_string(),
            Criticality::Suspicious => "Suspicious Program".to_string(),
            Criticality::Notable => "Notable Program".to_string(),
            _ => "Legitimate Program".to_string(),
        };
    }

    // Generate description if we don't have one
    if description_parts.is_empty() && !key_capabilities.is_empty() {
        description_parts.push(format!(
            "Program with {} notable capabilities",
            key_capabilities.len()
        ));
    }

    ProgramSummary {
        classification,
        malware_family,
        risk_level,
        key_capabilities,
        desc: description_parts.join("; "),
    }
}

/// Format a capability ID into a short human-readable form
fn format_capability_short(id: &str) -> String {
    let parts: Vec<&str> = id.split('/').collect();
    if parts.len() >= 2 {
        match parts[0] {
            "exec" => format!("Execute {}", parts.last().unwrap_or(&"code")),
            "c2" => "Command & Control".to_string(),
            "credential" => "Credential Access".to_string(),
            "exfil" => "Data Exfiltration".to_string(),
            "persistence" => "Persistence".to_string(),
            "evasion" => "Defense Evasion".to_string(),
            "malware" => {
                if parts.len() >= 3 {
                    format!("{} {}", parts[1], parts[2])
                } else {
                    "Malware".to_string()
                }
            }
            _ => parts.join(" "),
        }
    } else {
        id.to_string()
    }
}

/// Format the program summary for terminal display
pub fn format_summary(summary: &ProgramSummary) -> String {
    let mut output = String::new();

    // Risk emoji
    let risk_emoji = match summary.risk_level {
        Criticality::Hostile => "🛑",
        Criticality::Suspicious => "🟡",
        Criticality::Notable => "🔵",
        _ => "⚪",
    };

    // Classification header
    output.push_str("│\n");
    output.push_str(&format!(
        "│  {} {}\n",
        risk_emoji,
        summary.classification.bright_white().bold()
    ));

    // Malware family if detected
    if let Some(family) = &summary.malware_family {
        output.push_str(&format!(
            "│  Family:  {} (detected with high conf)\n",
            family.bright_red().bold()
        ));
    }

    // Risk level
    let risk_color = match summary.risk_level {
        Criticality::Hostile => "HOSTILE".bright_red().bold(),
        Criticality::Suspicious => "SUSPICIOUS".bright_yellow().bold(),
        Criticality::Notable => "NOTABLE".bright_cyan(),
        _ => "INERT".normal(),
    };
    output.push_str(&format!("│  Risk:    {}\n", risk_color));

    // Description
    if !summary.desc.is_empty() {
        output.push_str("│\n");
        output.push_str(&format!("│  {}\n", summary.desc.italic()));
    }

    // Key capabilities
    if !summary.key_capabilities.is_empty() {
        output.push_str("│\n");
        output.push_str(&format!("│  {}\n", "Key Capabilities:".bright_white()));
        for cap in &summary.key_capabilities {
            output.push_str(&format!("│  • {}\n", cap));
        }
    }

    output.push_str("│\n");
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AnalysisReport, Evidence, TargetInfo};
    use chrono::Utc;

    fn create_test_report(findings: Vec<Finding>, yara_matches: Vec<YaraMatch>) -> AnalysisReport {
        let mut report = AnalysisReport {
            schema_version: "2.0".to_string(),
            analysis_timestamp: Utc::now(),
            target: TargetInfo {
                path: "/test/sample.bin".to_string(),
                file_type: "ELF".to_string(),
                size_bytes: 12345,
                sha256: "def456abc".to_string(),
                architectures: Some(vec!["x86_64".to_string()]),
            },
            findings,
            traits: vec![],
            structure: vec![],
            functions: vec![],
            strings: vec![],
            decoded_strings: vec![],
            sections: vec![],
            imports: vec![],
            exports: vec![],
            yara_matches,
            syscalls: vec![],
            binary_properties: None,
            code_metrics: None,
            source_code_metrics: None,
            overlay_metrics: None,
            metrics: None,
            paths: vec![],
            directories: vec![],
            env_vars: vec![],
            archive_contents: vec![],
            scanned_path: None,
            files: vec![],
            summary: None,
            metadata: crate::types::AnalysisMetadata {
                analysis_duration_ms: 100,
                tools_used: vec!["test".to_string()],
                errors: vec![],
            },
        };
        // Convert to v2 format to populate files array
        report.convert_to_v2(true);
        report
    }

    #[test]
    fn test_aggregate_findings_empty() {
        let findings: Vec<Finding> = vec![];
        let aggregated = aggregate_findings_by_directory(&findings);
        assert_eq!(aggregated.len(), 0);
    }

    #[test]
    fn test_aggregate_findings_different_directories() {
        let findings = vec![
            Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "exec/shell/bash".to_string(),
                desc: "Execute bash".to_string(),
                conf: 0.9,
                crit: Criticality::Hostile,
                mbc: None,
                attack: None,
                evidence: vec![],
            },
            Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "net/http/get".to_string(),
                desc: "HTTP GET request".to_string(),
                conf: 0.8,
                crit: Criticality::Suspicious,
                mbc: None,
                attack: None,
                evidence: vec![],
            },
        ];
        let aggregated = aggregate_findings_by_directory(&findings);
        assert_eq!(aggregated.len(), 2);
        // IDs should be directory paths
        let ids: Vec<_> = aggregated.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"exec/shell"));
        assert!(ids.contains(&"net/http"));
    }

    #[test]
    fn test_aggregate_findings_same_directory_keeps_highest_criticality() {
        let findings = vec![
            Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "exec/shell/bash".to_string(),
                desc: "Execute bash".to_string(),
                conf: 0.7,
                crit: Criticality::Suspicious,
                mbc: None,
                attack: None,
                evidence: vec![],
            },
            Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "exec/shell/sh".to_string(),
                desc: "Execute sh".to_string(),
                conf: 0.7,
                crit: Criticality::Hostile,
                mbc: None,
                attack: None,
                evidence: vec![],
            },
        ];
        let aggregated = aggregate_findings_by_directory(&findings);
        assert_eq!(aggregated.len(), 1);
        assert_eq!(aggregated[0].id, "exec/shell");
        assert_eq!(aggregated[0].crit, Criticality::Hostile);
        // Should have both trait IDs in trait_refs
        assert_eq!(aggregated[0].trait_refs.len(), 2);
    }

    #[test]
    fn test_aggregate_findings_same_directory_keeps_highest_confidence() {
        let findings = vec![
            Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "exec/shell/bash".to_string(),
                desc: "Execute bash".to_string(),
                conf: 0.6,
                crit: Criticality::Hostile,
                mbc: None,
                attack: None,
                evidence: vec![],
            },
            Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "exec/shell/sh".to_string(),
                desc: "Execute sh".to_string(),
                conf: 0.9,
                crit: Criticality::Hostile,
                mbc: None,
                attack: None,
                evidence: vec![],
            },
        ];
        let aggregated = aggregate_findings_by_directory(&findings);
        assert_eq!(aggregated.len(), 1);
        assert_eq!(aggregated[0].id, "exec/shell");
        assert_eq!(aggregated[0].conf, 0.9);
    }

    #[test]
    fn test_yara_to_findings_high_severity() {
        let yara_matches = vec![YaraMatch {
            namespace: "traits.intel.discover".to_string(),
            rule: "process_info".to_string(),
            desc: "Get process info".to_string(),
            severity: "high".to_string(),
            matched_strings: vec![],
            is_capability: false,
            mbc: None,
            attack: None,
        }];
        let traits = yara_to_findings(&yara_matches);
        assert_eq!(traits.len(), 1);
        assert_eq!(traits[0].id, "intel/discover/process_info");
        assert_eq!(traits[0].crit, Criticality::Hostile);
    }

    #[test]
    fn test_yara_to_findings_medium_severity() {
        let yara_matches = vec![YaraMatch {
            namespace: "traits.net.http".to_string(),
            rule: "client".to_string(),
            desc: "HTTP client".to_string(),
            severity: "medium".to_string(),
            matched_strings: vec![],
            is_capability: false,
            mbc: None,
            attack: None,
        }];
        let traits = yara_to_findings(&yara_matches);
        assert_eq!(traits[0].crit, Criticality::Suspicious);
    }

    #[test]
    fn test_yara_to_findings_third_party() {
        let yara_matches = vec![YaraMatch {
            namespace: "third_party.mitre".to_string(),
            rule: "apt29".to_string(),
            desc: "APT29 indicator".to_string(),
            severity: "critical".to_string(),
            matched_strings: vec![],
            is_capability: false,
            mbc: None,
            attack: None,
        }];
        let traits = yara_to_findings(&yara_matches);
        assert_eq!(traits[0].id, "3P/apt29");
    }

    #[test]
    fn test_risk_emoji() {
        assert_eq!(risk_emoji(&Criticality::Inert), "⚪");
        assert_eq!(risk_emoji(&Criticality::Notable), "🔵");
        assert_eq!(risk_emoji(&Criticality::Suspicious), "🟡");
        assert_eq!(risk_emoji(&Criticality::Hostile), "🛑");
    }

    #[test]
    fn test_split_trait_id() {
        let (ns, rest) = split_trait_id("intel/discover/process");
        assert_eq!(ns, "intel");
        assert_eq!(rest, "discover/process");
    }

    #[test]
    fn test_split_trait_id_no_namespace() {
        let (ns, rest) = split_trait_id("test");
        assert_eq!(ns, "test");
        assert_eq!(rest, "test");
    }

    #[test]
    fn test_namespace_long_name() {
        assert_eq!(namespace_long_name("c2"), "C2");
        assert_eq!(namespace_long_name("intel"), "discovery");
        assert_eq!(namespace_long_name("crypto"), "crypto");
        assert_eq!(namespace_long_name("3P"), "third-party");
        assert_eq!(namespace_long_name("credential"), "credentials");
        assert_eq!(namespace_long_name("cred"), "credentials");
        assert_eq!(namespace_long_name("anti-static"), "static evasion");
        assert_eq!(namespace_long_name("comm"), "network");
        assert_eq!(namespace_long_name("collect"), "collection");
        assert_eq!(namespace_long_name("impact"), "impact");
        assert_eq!(namespace_long_name("unknown"), "unknown");
    }

    #[test]
    fn test_format_evidence_empty() {
        let trait_item = Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "test".to_string(),
            desc: "Test trait".to_string(),
            conf: 0.8,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            evidence: vec![],
        };
        assert_eq!(format_evidence(&trait_item), "");
    }

    #[test]
    fn test_format_evidence_with_values() {
        let trait_item = Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "test".to_string(),
            desc: "Test".to_string(),
            conf: 0.8,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            evidence: vec![
                Evidence {
                    method: "yara".to_string(),
                    source: "test".to_string(),
                    value: "cmd.exe".to_string(),
                    location: None,
                },
                Evidence {
                    method: "yara".to_string(),
                    source: "test".to_string(),
                    value: "powershell".to_string(),
                    location: None,
                },
            ],
        };
        let formatted = format_evidence(&trait_item);
        assert!(formatted.contains("cmd.exe"));
        assert!(formatted.contains("powershell"));
    }

    #[test]
    fn test_format_json() {
        let report = create_test_report(vec![], vec![]);
        let json = format_json(&report).unwrap();
        assert!(json.contains("schema_version"));
        assert!(json.contains("2.0"));
    }

    #[test]
    fn test_format_terminal_empty_report() {
        let report = create_test_report(vec![], vec![]);
        let output = format_terminal(&report).unwrap();
        assert!(output.contains("/test/sample.bin"));
    }

    #[test]
    fn test_format_terminal_with_capabilities() {
        let capabilities = vec![Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "exec/shell".to_string(),
            desc: "Execute shell commands".to_string(),
            conf: 0.9,
            crit: Criticality::Hostile,
            mbc: None,
            attack: None,
            evidence: vec![],
        }];
        let report = create_test_report(capabilities, vec![]);
        let output = format_terminal(&report).unwrap();
        assert!(output.contains("exec/shell") || output.contains("shell"));
    }

    #[test]
    fn test_calculate_overall_risk_routine() {
        let report = create_test_report(vec![], vec![]);
        let risk = calculate_overall_risk(&report);
        assert_eq!(risk, Criticality::Inert);
    }

    #[test]
    fn test_calculate_overall_risk_from_capabilities() {
        let capabilities = vec![Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "test".to_string(),
            desc: "Test".to_string(),
            conf: 0.8,
            crit: Criticality::Hostile,
            mbc: None,
            attack: None,
            evidence: vec![],
        }];
        let report = create_test_report(capabilities, vec![]);
        let risk = calculate_overall_risk(&report);
        assert_eq!(risk, Criticality::Hostile);
    }

    #[test]
    fn test_calculate_overall_risk_from_yara() {
        let yara_matches = vec![YaraMatch {
            namespace: "test".to_string(),
            rule: "dangerous".to_string(),
            desc: "Dangerous pattern".to_string(),
            severity: "high".to_string(),
            matched_strings: vec![],
            is_capability: false,
            mbc: None,
            attack: None,
        }];
        let report = create_test_report(vec![], yara_matches);
        let risk = calculate_overall_risk(&report);
        assert_eq!(risk, Criticality::Hostile);
    }
}
