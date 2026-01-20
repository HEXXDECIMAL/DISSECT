use crate::types::AnalysisReport;
use anyhow::Result;

/// Format analysis report as JSON
pub fn format_json(report: &AnalysisReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

/// Format analysis report for terminal display
pub fn format_terminal(report: &AnalysisReport) -> Result<String> {
    let mut output = String::new();

    // Header
    output.push_str(&format!("\n=== DISSECT Analysis ===\n\n"));

    // File info section
    output.push_str("📋 File Information\n");
    output.push_str(&format!("  Path: {}\n", report.target.path));
    output.push_str(&format!("  Type: {}\n", report.target.file_type));
    output.push_str(&format!("  Size: {}\n", format_size(report.target.size_bytes)));

    if let Some(archs) = &report.target.architectures {
        output.push_str(&format!("  Architectures: {}\n", archs.join(", ")));
    }

    output.push_str(&format!("  SHA-256: {}...\n", &report.target.sha256[..16]));
    output.push('\n');

    // Structure section
    if !report.structure.is_empty() {
        output.push_str("🏗️  Structure\n");
        for feat in &report.structure {
            let icon = match feat.id.as_str() {
                id if id.contains("signed") => "✓",
                id if id.contains("stripped") => "⚠️",
                id if id.contains("entropy/high") => "🔴",
                _ => "•",
            };
            output.push_str(&format!("  {} {}\n", icon, feat.id));
        }
        output.push('\n');
    }

    // Capabilities section (main focus)
    if !report.capabilities.is_empty() {
        output.push_str(&format!("🎯 Capabilities ({})\n", report.capabilities.len()));

        // Group by risk level (based on category)
        let mut high_risk = Vec::new();
        let mut medium_risk = Vec::new();
        let mut low_risk = Vec::new();

        for cap in &report.capabilities {
            let risk_level = classify_risk(&cap.id);
            match risk_level {
                RiskLevel::High => high_risk.push(cap),
                RiskLevel::Medium => medium_risk.push(cap),
                RiskLevel::Low => low_risk.push(cap),
            }
        }

        // Display by risk level
        for cap in high_risk {
            output.push_str(&format!(
                "  🔴 {} {} ({})\n",
                cap.id,
                format_confidence(cap.confidence),
                cap.evidence[0].method
            ));
        }

        for cap in medium_risk {
            output.push_str(&format!(
                "  🟡 {} {} ({})\n",
                cap.id,
                format_confidence(cap.confidence),
                cap.evidence[0].method
            ));
        }

        for cap in low_risk {
            output.push_str(&format!(
                "  🔵 {} {} ({})\n",
                cap.id,
                format_confidence(cap.confidence),
                cap.evidence[0].method
            ));
        }
        output.push('\n');
    } else {
        output.push_str("🎯 Capabilities: None detected\n\n");
    }

    // Functions (if present and interesting)
    if !report.functions.is_empty() {
        let complex_functions: Vec<_> = report.functions.iter()
            .filter(|f| f.complexity.unwrap_or(0) > 10)
            .collect();

        if !complex_functions.is_empty() {
            output.push_str(&format!("⚙️  Complex Functions ({}/{})\n", complex_functions.len(), report.functions.len()));
            for func in complex_functions.iter().take(5) {
                output.push_str(&format!(
                    "  • {} (complexity: {})\n",
                    func.name,
                    func.complexity.unwrap_or(0)
                ));
            }
            if complex_functions.len() > 5 {
                output.push_str(&format!("  ... and {} more\n", complex_functions.len() - 5));
            }
            output.push('\n');
        }
    }

    // YARA matches (if present)
    if !report.yara_matches.is_empty() {
        let critical: Vec<_> = report.yara_matches.iter()
            .filter(|m| m.severity == "critical" || m.severity == "high")
            .collect();

        if !critical.is_empty() {
            output.push_str(&format!("⚠️  YARA Matches ({} critical/high)\n", critical.len()));
            for m in critical.iter().take(5) {
                output.push_str(&format!("  • {} [{}]\n", m.rule, m.severity.to_uppercase()));
                if !m.description.is_empty() {
                    output.push_str(&format!("    {}\n", clean_description(&m.description)));
                }
            }
            if critical.len() > 5 {
                output.push_str(&format!("  ... and {} more\n", critical.len() - 5));
            }
            output.push('\n');
        }
    }

    // Entropy warnings
    if let Some(high_entropy) = report.sections.iter().find(|s| s.entropy > 7.2) {
        output.push_str("⚠️  High Entropy Detected\n");
        output.push_str(&format!(
            "  Section '{}' has entropy {:.2} (possibly packed/encrypted)\n\n",
            high_entropy.name, high_entropy.entropy
        ));
    }

    // Footer
    output.push_str(&format!(
        "🔍 Analysis: {}ms using {}\n",
        report.metadata.analysis_duration_ms,
        report.metadata.tools_used.join(", ")
    ));

    if !report.metadata.errors.is_empty() {
        output.push_str(&format!("⚠️  {} errors occurred\n", report.metadata.errors.len()));
    }

    output.push('\n');
    Ok(output)
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn format_confidence(conf: f32) -> String {
    if conf >= 1.0 {
        "✓".to_string()
    } else if conf >= 0.9 {
        "~".to_string()
    } else {
        "?".to_string()
    }
}

#[derive(PartialEq, PartialOrd)]
enum RiskLevel {
    Low,
    Medium,
    High,
}

fn classify_risk(capability: &str) -> RiskLevel {
    if capability.contains("exec/")
        || capability.contains("privilege/")
        || capability.contains("anti-analysis/")
        || capability.contains("persistence/")
        || capability.contains("inject")
    {
        RiskLevel::High
    } else if capability.contains("net/")
        || capability.contains("credential/")
        || capability.contains("fs/delete")
        || capability.contains("fs/permissions")
    {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

fn clean_description(desc: &str) -> String {
    desc.trim_matches('"')
        .replace("String(\"", "")
        .replace("\")", "")
        .trim()
        .to_string()
}
