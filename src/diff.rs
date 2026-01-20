use crate::analyzers::{archive::ArchiveAnalyzer, detect_file_type, Analyzer};
use crate::types::*;
use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Diff analyzer for detecting supply chain attacks (xzutils scenario)
pub struct DiffAnalyzer {
    baseline_path: PathBuf,
    target_path: PathBuf,
}

impl DiffAnalyzer {
    pub fn new(baseline: impl AsRef<Path>, target: impl AsRef<Path>) -> Self {
        Self {
            baseline_path: baseline.as_ref().to_path_buf(),
            target_path: target.as_ref().to_path_buf(),
        }
    }

    pub fn analyze(&self) -> Result<DiffReport> {
        let start = std::time::Instant::now();

        println!("Analyzing baseline: {}", self.baseline_path.display());
        println!("Analyzing target:   {}", self.target_path.display());

        // Determine if we're comparing files or directories
        let is_baseline_dir = self.baseline_path.is_dir();
        let is_target_dir = self.target_path.is_dir();

        let diff_report = if is_baseline_dir && is_target_dir {
            self.analyze_directories()?
        } else if !is_baseline_dir && !is_target_dir {
            self.analyze_files()?
        } else {
            anyhow::bail!("Baseline and target must both be files or both be directories");
        };

        println!("Diff analysis complete in {}ms", start.elapsed().as_millis());

        Ok(diff_report)
    }

    fn analyze_files(&self) -> Result<DiffReport> {
        println!("  Mode: File comparison");

        // Analyze both files
        let baseline_report = self.analyze_single_file(&self.baseline_path)?;
        let target_report = self.analyze_single_file(&self.target_path)?;

        // Compare
        let analysis = self.compare_reports(
            &self.baseline_path.display().to_string(),
            &baseline_report,
            &target_report,
        );

        let mut modified_analysis = Vec::new();
        if analysis.new_capabilities.len() > 0 || analysis.removed_capabilities.len() > 0 {
            modified_analysis.push(analysis);
        }

        Ok(DiffReport {
            schema_version: "1.0".to_string(),
            analysis_timestamp: Utc::now(),
            diff_mode: true,
            baseline: self.baseline_path.display().to_string(),
            target: self.target_path.display().to_string(),
            changes: FileChanges {
                added: vec![],
                removed: vec![],
                modified: if modified_analysis.is_empty() { vec![] } else { vec![self.target_path.display().to_string()] },
            },
            modified_analysis,
            metadata: AnalysisMetadata {
                analysis_duration_ms: 0,
                tools_used: vec!["diff_analyzer".to_string()],
                errors: vec![],
            },
        })
    }

    fn analyze_directories(&self) -> Result<DiffReport> {
        println!("  Mode: Directory comparison");

        // Get all files in both directories
        let baseline_files = self.collect_files(&self.baseline_path)?;
        let target_files = self.collect_files(&self.target_path)?;

        println!("  Baseline files: {}", baseline_files.len());
        println!("  Target files:   {}", target_files.len());

        // Determine what changed
        let baseline_set: HashSet<_> = baseline_files.keys().collect();
        let target_set: HashSet<_> = target_files.keys().collect();

        let added: Vec<String> = target_set.difference(&baseline_set)
            .map(|s| s.to_string())
            .collect();
        let removed: Vec<String> = baseline_set.difference(&target_set)
            .map(|s| s.to_string())
            .collect();
        let modified_candidates: Vec<String> = baseline_set.intersection(&target_set)
            .map(|s| s.to_string())
            .collect();

        println!("  Added files:    {}", added.len());
        println!("  Removed files:  {}", removed.len());
        println!("  Checking:       {} common files", modified_candidates.len());

        // Analyze modified files
        let mut modified_analysis = Vec::new();
        let mut actually_modified = Vec::new();

        for relative_path in modified_candidates {
            let baseline_file = baseline_files.get(&relative_path).unwrap();
            let target_file = target_files.get(&relative_path).unwrap();

            // Quick check: if sizes match and content matches, skip
            if let (Ok(baseline_meta), Ok(target_meta)) = (fs::metadata(baseline_file), fs::metadata(target_file)) {
                if baseline_meta.len() == target_meta.len() {
                    if let (Ok(baseline_content), Ok(target_content)) = (fs::read(baseline_file), fs::read(target_file)) {
                        if baseline_content == target_content {
                            continue; // Files are identical
                        }
                    }
                }
            }

            // Files differ - analyze both
            match (self.analyze_single_file(baseline_file), self.analyze_single_file(target_file)) {
                (Ok(baseline_report), Ok(target_report)) => {
                    let analysis = self.compare_reports(&relative_path, &baseline_report, &target_report);

                    if !analysis.new_capabilities.is_empty() || !analysis.removed_capabilities.is_empty() {
                        println!("  🔍 Modified: {}", relative_path);
                        if !analysis.new_capabilities.is_empty() {
                            println!("      ➕ New capabilities: {:?}", analysis.new_capabilities);
                        }
                        if !analysis.removed_capabilities.is_empty() {
                            println!("      ➖ Removed capabilities: {:?}", analysis.removed_capabilities);
                        }
                        if analysis.risk_increase {
                            println!("      ⚠️  RISK INCREASED");
                        }

                        actually_modified.push(relative_path.clone());
                        modified_analysis.push(analysis);
                    }
                }
                _ => {
                    // Failed to analyze, skip
                }
            }
        }

        // Report on new/removed files
        if !added.is_empty() {
            println!("\n  ➕ Added files:");
            for file in &added {
                println!("      {}", file);
            }
        }

        if !removed.is_empty() {
            println!("\n  ➖ Removed files:");
            for file in &removed {
                println!("      {}", file);
            }
        }

        Ok(DiffReport {
            schema_version: "1.0".to_string(),
            analysis_timestamp: Utc::now(),
            diff_mode: true,
            baseline: self.baseline_path.display().to_string(),
            target: self.target_path.display().to_string(),
            changes: FileChanges {
                added,
                removed,
                modified: actually_modified,
            },
            modified_analysis,
            metadata: AnalysisMetadata {
                analysis_duration_ms: 0,
                tools_used: vec!["diff_analyzer".to_string()],
                errors: vec![],
            },
        })
    }

    fn collect_files(&self, dir: &Path) -> Result<HashMap<String, PathBuf>> {
        let mut files = HashMap::new();

        for entry in WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let relative = path.strip_prefix(dir)
                .context("Failed to get relative path")?
                .to_string_lossy()
                .to_string();

            files.insert(relative, path.to_path_buf());
        }

        Ok(files)
    }

    fn analyze_single_file(&self, path: &Path) -> Result<AnalysisReport> {
        let file_type = detect_file_type(path)?;

        match file_type {
            crate::analyzers::FileType::MachO => {
                let analyzer = crate::analyzers::macho::MachOAnalyzer::new();
                analyzer.analyze(path)
            }
            crate::analyzers::FileType::Elf => {
                let analyzer = crate::analyzers::elf::ElfAnalyzer::new();
                analyzer.analyze(path)
            }
            crate::analyzers::FileType::Pe => {
                let analyzer = crate::analyzers::pe::PEAnalyzer::new();
                analyzer.analyze(path)
            }
            crate::analyzers::FileType::ShellScript => {
                let analyzer = crate::analyzers::shell::ShellAnalyzer::new();
                analyzer.analyze(path)
            }
            crate::analyzers::FileType::Python => {
                let analyzer = crate::analyzers::python::PythonAnalyzer::new();
                analyzer.analyze(path)
            }
            crate::analyzers::FileType::JavaScript => {
                let analyzer = crate::analyzers::javascript::JavaScriptAnalyzer::new();
                analyzer.analyze(path)
            }
            crate::analyzers::FileType::Archive => {
                let analyzer = ArchiveAnalyzer::new();
                analyzer.analyze(path)
            }
            _ => {
                anyhow::bail!("Unsupported file type for diff analysis")
            }
        }
    }

    fn compare_reports(&self, file_path: &str, baseline: &AnalysisReport, target: &AnalysisReport) -> ModifiedFileAnalysis {
        let baseline_caps: HashSet<String> = baseline.capabilities.iter()
            .map(|c| c.id.clone())
            .collect();

        let target_caps: HashSet<String> = target.capabilities.iter()
            .map(|c| c.id.clone())
            .collect();

        let new_capabilities: Vec<String> = target_caps.difference(&baseline_caps)
            .cloned()
            .collect();

        let removed_capabilities: Vec<String> = baseline_caps.difference(&target_caps)
            .cloned()
            .collect();

        // Risk assessment
        let risk_increase = self.assess_risk_increase(&new_capabilities, &removed_capabilities);

        ModifiedFileAnalysis {
            file: file_path.to_string(),
            new_capabilities,
            removed_capabilities,
            capability_delta: target_caps.len() as i32 - baseline_caps.len() as i32,
            risk_increase,
        }
    }

    fn assess_risk_increase(&self, new_caps: &[String], removed_caps: &[String]) -> bool {
        // High-risk capability categories
        let high_risk_prefixes = [
            "exec/",
            "anti-analysis/",
            "privilege/",
            "persistence/",
            "injection/",
            "registry/write",
            "registry/delete",
            "service/create",
        ];

        // Check if new capabilities are high-risk
        let new_high_risk_count = new_caps.iter()
            .filter(|cap| high_risk_prefixes.iter().any(|prefix| cap.starts_with(prefix)))
            .count();

        // Check if removed capabilities were high-risk
        let removed_high_risk_count = removed_caps.iter()
            .filter(|cap| high_risk_prefixes.iter().any(|prefix| cap.starts_with(prefix)))
            .count();

        // Risk increases if:
        // 1. New high-risk capabilities added
        // 2. More high-risk capabilities than were removed
        new_high_risk_count > 0 && new_high_risk_count > removed_high_risk_count
    }
}

/// Format diff report as human-readable output
pub fn format_diff_terminal(report: &DiffReport) -> String {
    let mut output = String::new();

    output.push_str("=== DISSECT Diff Analysis ===\n\n");
    output.push_str(&format!("📂 Baseline: {}\n", report.baseline));
    output.push_str(&format!("📂 Target:   {}\n", report.target));
    output.push_str(&format!("📅 Analyzed: {}\n\n", report.analysis_timestamp.format("%Y-%m-%d %H:%M:%S UTC")));

    // Summary
    output.push_str("📊 Summary\n");
    output.push_str(&format!("  Files added:    {}\n", report.changes.added.len()));
    output.push_str(&format!("  Files removed:  {}\n", report.changes.removed.len()));
    output.push_str(&format!("  Files modified: {}\n", report.changes.modified.len()));

    // Risk assessment
    let high_risk_changes = report.modified_analysis.iter()
        .filter(|a| a.risk_increase)
        .count();

    if high_risk_changes > 0 {
        output.push_str(&format!("\n⚠️  {} high-risk changes detected!\n", high_risk_changes));
    }

    // Modified files details
    if !report.modified_analysis.is_empty() {
        output.push_str("\n🔍 Modified Files\n");
        for analysis in &report.modified_analysis {
            output.push_str(&format!("\n  📄 {}\n", analysis.file));

            if !analysis.new_capabilities.is_empty() {
                output.push_str("    ➕ New capabilities:\n");
                for cap in &analysis.new_capabilities {
                    let risk_marker = if is_high_risk(cap) { "🔴" } else if is_medium_risk(cap) { "🟡" } else { "🔵" };
                    output.push_str(&format!("       {} {}\n", risk_marker, cap));
                }
            }

            if !analysis.removed_capabilities.is_empty() {
                output.push_str("    ➖ Removed capabilities:\n");
                for cap in &analysis.removed_capabilities {
                    output.push_str(&format!("       {}\n", cap));
                }
            }

            if analysis.risk_increase {
                output.push_str("    ⚠️  RISK INCREASED\n");
            }
        }
    }

    // New files
    if !report.changes.added.is_empty() {
        output.push_str("\n➕ Added Files\n");
        for file in &report.changes.added {
            output.push_str(&format!("  {}\n", file));
        }
    }

    // Removed files
    if !report.changes.removed.is_empty() {
        output.push_str("\n➖ Removed Files\n");
        for file in &report.changes.removed {
            output.push_str(&format!("  {}\n", file));
        }
    }

    output.push('\n');
    output
}

fn is_high_risk(capability: &str) -> bool {
    capability.starts_with("exec/") ||
    capability.starts_with("anti-analysis/") ||
    capability.starts_with("privilege/") ||
    capability.starts_with("persistence/") ||
    capability.starts_with("injection/")
}

fn is_medium_risk(capability: &str) -> bool {
    capability.starts_with("net/") ||
    capability.starts_with("credential/") ||
    capability.starts_with("registry/") ||
    capability.starts_with("service/")
}
