use crate::types::{AnalysisReport, Criticality, Trait, YaraMatch};
use anyhow::Result;
use colored::Colorize;
use std::collections::HashMap;

/// Deduplicate traits by ID, keeping highest criticality (then highest confidence)
fn deduplicate_traits(traits: &[Trait]) -> Vec<&Trait> {
    let mut best_matches: HashMap<String, &Trait> = HashMap::new();

    for trait_item in traits {
        match best_matches.get(&trait_item.id) {
            None => {
                best_matches.insert(trait_item.id.clone(), trait_item);
            }
            Some(existing) => {
                // Keep the one with higher criticality
                // If criticality is same, keep the one with higher confidence
                let should_replace = trait_item.criticality > existing.criticality
                    || (trait_item.criticality == existing.criticality
                        && trait_item.confidence > existing.confidence);

                if should_replace {
                    best_matches.insert(trait_item.id.clone(), trait_item);
                }
            }
        }
    }

    best_matches.into_values().collect()
}

/// Convert YARA matches to traits for unified display
fn yara_to_traits(yara_matches: &[YaraMatch]) -> Vec<Trait> {
    yara_matches
        .iter()
        .map(|m| {
            let criticality = match m.severity.as_str() {
                "critical" | "high" => Criticality::Hostile,
                "medium" => Criticality::Suspicious,
                "low" => Criticality::Notable,
                _ => Criticality::Inert,
            };

            // Extract namespace for trait ID (e.g., "traits.intel.discover" -> "intel/discover")
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

            Trait {
                id,
                description: m.description.clone(),
                confidence: 0.7, // Default for YARA matches
                criticality,
                capability: true,
                mbc: None,
                attack: None,
                language: None,
                platforms: Vec::new(),
                evidence,
                referenced_paths: None,
                referenced_directories: None,
            }
        })
        .collect()
}

/// Get risk emoji based on criticality
fn risk_emoji(criticality: &Criticality) -> &'static str {
    match criticality {
        Criticality::Filtered => "⬜",
        Criticality::Inert => "⚪",
        Criticality::Notable => "🔵",
        Criticality::Suspicious => "🟡",
        Criticality::Hostile => "🛑",
    }
}

/// Get risk level name
fn risk_name(criticality: &Criticality) -> &'static str {
    match criticality {
        Criticality::Filtered => "FILT",
        Criticality::Inert => "NONE",
        Criticality::Notable => "LOW",
        Criticality::Suspicious => "MED",
        Criticality::Hostile => "HIGH",
    }
}

/// Split trait ID into namespace and rest (e.g., "intel/discover/process/getuid" -> ("intel", "discover/process/getuid"))
fn split_trait_id(id: &str) -> (String, String) {
    let parts: Vec<&str> = id.split('/').collect();
    if parts.len() > 1 {
        (parts[0].to_string(), parts[1..].join("/"))
    } else {
        ("other".to_string(), id.to_string())
    }
}

/// Convert namespace to long name (malcontent-style)
fn namespace_long_name(ns: &str) -> &'static str {
    match ns {
        "c2" => "command & control",
        "intel" => "discovery",
        "crypto" => "cryptography",
        "exfil" => "exfiltration",
        "exec" => "execution",
        "fs" => "filesystem",
        "hw" => "hardware",
        "net" => "networking",
        "os" => "operating-system",
        "3P" => "third-party",
        "persistence" => "persistence",
        "anti-analysis" => "anti-analysis",
        "anti-static" => "anti-static analysis",
        "evasion" => "defense evasion",
        "privesc" => "privilege escalation",
        "process" => "process",
        "mem" => "memory",
        "data" => "data",
        "impact" => "impact",
        "access" => "access",
        "credential" => "credential access",
        "lateral" => "lateral movement",
        "kernel" => "kernel",
        "reflect" => "reflection",
        "archive" => "archive",
        _ => "other",
    }
}

/// Format evidence string (minimal)
fn format_evidence(trait_item: &Trait) -> String {
    let values: Vec<String> = trait_item
        .evidence
        .iter()
        .filter_map(|e| {
            if e.value.len() <= 50 && !trait_item.description.contains(&e.value) {
                Some(e.value.clone())
            } else {
                None
            }
        })
        .take(3)
        .collect();

    if values.is_empty() {
        String::new()
    } else {
        values.join(", ")
    }
}

/// Format size in human-readable format
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Format analysis report as JSON
pub fn format_json(report: &AnalysisReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

/// Format analysis report for terminal display (malcontent-style)
pub fn format_terminal(report: &AnalysisReport) -> Result<String> {
    let mut output = String::new();

    // File path with risk emoji
    let overall_risk = calculate_overall_risk(report);
    output.push_str(&format!(
        "├─ {} {} {}\n",
        risk_emoji(&overall_risk),
        report.target.path.bright_white(),
        format!("[{}]", risk_name(&overall_risk)).bright_black()
    ));

    // Combine traits from report (stored as capabilities) and YARA matches
    let mut all_traits: Vec<Trait> = report
        .capabilities
        .iter()
        .map(|cap| Trait {
            id: cap.id.clone(),
            description: cap.description.clone(),
            confidence: cap.confidence,
            criticality: cap.criticality,
            capability: true, // Capabilities are high-level behaviors
            mbc: cap.mbc.clone(),
            attack: cap.attack.clone(),
            language: None,
            platforms: Vec::new(),
            evidence: cap.evidence.clone(),
            referenced_paths: cap.referenced_paths.clone(),
            referenced_directories: cap.referenced_directories.clone(),
        })
        .collect();
    all_traits.extend(yara_to_traits(&report.yara_matches));

    // Deduplicate
    let deduped = deduplicate_traits(&all_traits);

    // Filter: remove criticality=none and confidence<0.5
    let filtered: Vec<&Trait> = deduped
        .into_iter()
        .filter(|t| t.criticality != Criticality::Inert && t.confidence >= 0.5)
        .collect();

    if filtered.is_empty() {
        output.push_str("│\n");
        return Ok(output);
    }

    // Group by namespace
    let mut by_namespace: HashMap<String, Vec<&Trait>> = HashMap::new();
    let mut ns_max_criticality: HashMap<String, Criticality> = HashMap::new();

    for trait_item in &filtered {
        let (ns, _) = split_trait_id(&trait_item.id);

        // Update max criticality for namespace
        let current_max = ns_max_criticality.get(&ns).unwrap_or(&Criticality::Inert);
        if &trait_item.criticality > current_max {
            ns_max_criticality.insert(ns.clone(), trait_item.criticality);
        }

        by_namespace.entry(ns).or_default().push(*trait_item);
    }

    // Sort namespaces by long name
    let mut namespaces: Vec<String> = by_namespace.keys().cloned().collect();
    namespaces.sort_by_key(|ns| namespace_long_name(ns));

    // Render each namespace
    for ns in &namespaces {
        let traits = by_namespace.get(ns).unwrap();
        let max_crit = ns_max_criticality.get(ns).unwrap_or(&Criticality::Inert);

        // Namespace header
        output.push_str(&format!(
            "│     ≡ {} {}\n",
            namespace_long_name(ns),
            format!("[{}]", risk_name(max_crit)).bright_black()
        ));

        // Sort traits by criticality (highest first), then ID
        let mut sorted_traits = traits.clone();
        sorted_traits.sort_by(|a, b| {
            b.criticality
                .cmp(&a.criticality)
                .then_with(|| a.id.cmp(&b.id))
        });

        // Render each trait
        for trait_item in sorted_traits {
            let (_, rest) = split_trait_id(&trait_item.id);
            let emoji = risk_emoji(&trait_item.criticality);
            let evidence = format_evidence(trait_item);

            // Colorize based on criticality
            let content = match trait_item.criticality {
                Criticality::Hostile => {
                    format!("{} {} — {}", emoji, rest, trait_item.description).bright_red()
                }
                Criticality::Suspicious => {
                    format!("{} {} — {}", emoji, rest, trait_item.description).bright_yellow()
                }
                _ => format!("{} {} — {}", emoji, rest, trait_item.description).bright_cyan(),
            };

            if evidence.is_empty() {
                output.push_str(&format!("│       {}\n", content));
            } else {
                output.push_str(&format!(
                    "│       {}{} {}\n",
                    content,
                    ":".bright_black(),
                    evidence.white()
                ));
            }
        }
    }

    output.push_str("│\n");
    Ok(output)
}

/// Calculate overall risk level for a report
fn calculate_overall_risk(report: &AnalysisReport) -> Criticality {
    let mut max = Criticality::Inert;

    for cap in &report.capabilities {
        if cap.criticality > max {
            max = cap.criticality;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AnalysisReport, Capability, Evidence, TargetInfo};
    use chrono::Utc;

    fn create_test_report(
        capabilities: Vec<Capability>,
        yara_matches: Vec<YaraMatch>,
    ) -> AnalysisReport {
        AnalysisReport {
            schema_version: "1.0".to_string(),
            analysis_timestamp: Utc::now(),
            target: TargetInfo {
                path: "/test/sample.bin".to_string(),
                file_type: "ELF".to_string(),
                size_bytes: 12345,
                sha256: "def456abc".to_string(),
                architectures: Some(vec!["x86_64".to_string()]),
            },
            traits: vec![],
            capabilities,
            structure: vec![],
            functions: vec![],
            strings: vec![],
            sections: vec![],
            imports: vec![],
            exports: vec![],
            yara_matches,
            binary_properties: None,
            code_metrics: None,
            source_code_metrics: None,
            overlay_metrics: None,
            paths: vec![],
            directories: vec![],
            env_vars: vec![],
            metadata: crate::types::AnalysisMetadata {
                analysis_duration_ms: 100,
                tools_used: vec!["test".to_string()],
                errors: vec![],
            },
        }
    }

    #[test]
    fn test_deduplicate_traits_empty() {
        let traits: Vec<Trait> = vec![];
        let deduped = deduplicate_traits(&traits);
        assert_eq!(deduped.len(), 0);
    }

    #[test]
    fn test_deduplicate_traits_no_duplicates() {
        let traits = vec![
            Trait {
                id: "exec/shell".to_string(),
                description: "Execute shell".to_string(),
                confidence: 0.9,
                criticality: Criticality::Hostile,
                capability: true,
                mbc: None,
                attack: None,
                language: None,
                platforms: vec![],
                evidence: vec![],
                referenced_paths: None,
                referenced_directories: None,
            },
            Trait {
                id: "net/http".to_string(),
                description: "HTTP request".to_string(),
                confidence: 0.8,
                criticality: Criticality::Suspicious,
                capability: true,
                mbc: None,
                attack: None,
                language: None,
                platforms: vec![],
                evidence: vec![],
                referenced_paths: None,
                referenced_directories: None,
            },
        ];
        let deduped = deduplicate_traits(&traits);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_deduplicate_traits_keeps_highest_criticality() {
        let traits = vec![
            Trait {
                id: "exec/shell".to_string(),
                description: "Execute shell".to_string(),
                confidence: 0.7,
                criticality: Criticality::Suspicious,
                capability: true,
                mbc: None,
                attack: None,
                language: None,
                platforms: vec![],
                evidence: vec![],
                referenced_paths: None,
                referenced_directories: None,
            },
            Trait {
                id: "exec/shell".to_string(),
                description: "Execute shell".to_string(),
                confidence: 0.7,
                criticality: Criticality::Hostile,
                capability: true,
                mbc: None,
                attack: None,
                language: None,
                platforms: vec![],
                evidence: vec![],
                referenced_paths: None,
                referenced_directories: None,
            },
        ];
        let deduped = deduplicate_traits(&traits);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].criticality, Criticality::Hostile);
    }

    #[test]
    fn test_deduplicate_traits_keeps_highest_confidence() {
        let traits = vec![
            Trait {
                id: "exec/shell".to_string(),
                description: "Execute shell".to_string(),
                confidence: 0.6,
                criticality: Criticality::Hostile,
                capability: true,
                mbc: None,
                attack: None,
                language: None,
                platforms: vec![],
                evidence: vec![],
                referenced_paths: None,
                referenced_directories: None,
            },
            Trait {
                id: "exec/shell".to_string(),
                description: "Execute shell".to_string(),
                confidence: 0.9,
                criticality: Criticality::Hostile,
                capability: true,
                mbc: None,
                attack: None,
                language: None,
                platforms: vec![],
                evidence: vec![],
                referenced_paths: None,
                referenced_directories: None,
            },
        ];
        let deduped = deduplicate_traits(&traits);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].confidence, 0.9);
    }

    #[test]
    fn test_yara_to_traits_high_severity() {
        let yara_matches = vec![YaraMatch {
            namespace: "traits.intel.discover".to_string(),
            rule: "process_info".to_string(),
            description: "Get process info".to_string(),
            severity: "high".to_string(),
            matched_strings: vec![],
            is_capability: false,
            mbc: None,
            attack: None,
        }];
        let traits = yara_to_traits(&yara_matches);
        assert_eq!(traits.len(), 1);
        assert_eq!(traits[0].id, "intel/discover/process_info");
        assert_eq!(traits[0].criticality, Criticality::Hostile);
    }

    #[test]
    fn test_yara_to_traits_medium_severity() {
        let yara_matches = vec![YaraMatch {
            namespace: "traits.net.http".to_string(),
            rule: "client".to_string(),
            description: "HTTP client".to_string(),
            severity: "medium".to_string(),
            matched_strings: vec![],
            is_capability: false,
            mbc: None,
            attack: None,
        }];
        let traits = yara_to_traits(&yara_matches);
        assert_eq!(traits[0].criticality, Criticality::Suspicious);
    }

    #[test]
    fn test_yara_to_traits_third_party() {
        let yara_matches = vec![YaraMatch {
            namespace: "third_party.mitre".to_string(),
            rule: "apt29".to_string(),
            description: "APT29 indicator".to_string(),
            severity: "critical".to_string(),
            matched_strings: vec![],
            is_capability: false,
            mbc: None,
            attack: None,
        }];
        let traits = yara_to_traits(&yara_matches);
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
    fn test_risk_name() {
        assert_eq!(risk_name(&Criticality::Inert), "NONE");
        assert_eq!(risk_name(&Criticality::Notable), "LOW");
        assert_eq!(risk_name(&Criticality::Suspicious), "MED");
        assert_eq!(risk_name(&Criticality::Hostile), "HIGH");
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
        assert_eq!(ns, "other");
        assert_eq!(rest, "test");
    }

    #[test]
    fn test_namespace_long_name() {
        assert_eq!(namespace_long_name("c2"), "command & control");
        assert_eq!(namespace_long_name("intel"), "discovery");
        assert_eq!(namespace_long_name("crypto"), "cryptography");
        assert_eq!(namespace_long_name("3P"), "third-party");
        assert_eq!(namespace_long_name("credential"), "credential access");
        assert_eq!(namespace_long_name("impact"), "impact");
        assert_eq!(namespace_long_name("unknown"), "other");
    }

    #[test]
    fn test_format_evidence_empty() {
        let trait_item = Trait {
            id: "test".to_string(),
            description: "Test trait".to_string(),
            confidence: 0.8,
            criticality: Criticality::Notable,
            capability: true,
            mbc: None,
            attack: None,
            language: None,
            platforms: vec![],
            evidence: vec![],
            referenced_paths: None,
            referenced_directories: None,
        };
        assert_eq!(format_evidence(&trait_item), "");
    }

    #[test]
    fn test_format_evidence_with_values() {
        let trait_item = Trait {
            id: "test".to_string(),
            description: "Test".to_string(),
            confidence: 0.8,
            criticality: Criticality::Notable,
            capability: true,
            mbc: None,
            attack: None,
            language: None,
            platforms: vec![],
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
            referenced_paths: None,
            referenced_directories: None,
        };
        let formatted = format_evidence(&trait_item);
        assert!(formatted.contains("cmd.exe"));
        assert!(formatted.contains("powershell"));
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(format_size(2560), "2.5 KB");
    }

    #[test]
    fn test_format_json() {
        let report = create_test_report(vec![], vec![]);
        let json = format_json(&report).unwrap();
        assert!(json.contains("schema_version"));
        assert!(json.contains("1.0"));
    }

    #[test]
    fn test_format_terminal_empty_report() {
        let report = create_test_report(vec![], vec![]);
        let output = format_terminal(&report).unwrap();
        assert!(output.contains("/test/sample.bin"));
    }

    #[test]
    fn test_format_terminal_with_capabilities() {
        let capabilities = vec![Capability {
            id: "exec/shell".to_string(),
            description: "Execute shell commands".to_string(),
            confidence: 0.9,
            criticality: Criticality::Hostile,
            mbc: None,
            attack: None,
            evidence: vec![],
            traits: vec![],
            referenced_paths: None,
            referenced_directories: None,
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
        let capabilities = vec![Capability {
            id: "test".to_string(),
            description: "Test".to_string(),
            confidence: 0.8,
            criticality: Criticality::Hostile,
            mbc: None,
            attack: None,
            evidence: vec![],
            traits: vec![],
            referenced_paths: None,
            referenced_directories: None,
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
            description: "Dangerous pattern".to_string(),
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
