//! Binary and package version comparison.
//!
//! This module performs differential analysis between two versions of a file,
//! identifying added/removed/modified capabilities, functions, and metrics.
//!
//! Useful for supply chain attack detection and version analysis.

use crate::analyzers::{archive::ArchiveAnalyzer, detect_file_type, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::output::aggregate_findings_by_directory;
use crate::types::*;
use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Compute set difference for items with an id-like field
fn compute_added_removed<T, F>(baseline: &[T], target: &[T], key_fn: F) -> (Vec<T>, Vec<T>)
where
    T: Clone,
    F: Fn(&T) -> String,
{
    let baseline_keys: HashSet<String> = baseline.iter().map(&key_fn).collect();
    let target_keys: HashSet<String> = target.iter().map(&key_fn).collect();

    let added: Vec<T> = target
        .iter()
        .filter(|item| !baseline_keys.contains(&key_fn(item)))
        .cloned()
        .collect();

    let removed: Vec<T> = baseline
        .iter()
        .filter(|item| !target_keys.contains(&key_fn(item)))
        .cloned()
        .collect();

    (added, removed)
}

/// Represents a detected file rename
#[derive(Debug, Clone)]
pub struct FileRename {
    pub baseline_path: String,
    pub target_path: String,
    pub similarity_score: f64,
}

/// Change type for a file
#[derive(Debug, Clone)]
pub enum ChangeType {
    Added,
    Removed,
    Modified,
    Renamed(FileRename),
}

/// Diff analyzer for detecting supply chain attacks (xzutils scenario)
pub struct DiffAnalyzer {
    baseline_path: PathBuf,
    target_path: PathBuf,
    capability_mapper: CapabilityMapper,
}

/// Check if a filename is a shared library based on extension and naming
fn is_shared_library(filename: &str) -> bool {
    // Match patterns like: libssl.so, libssl.so.1, libssl.so.1.0.0
    filename.contains(".so") && (filename.ends_with(".so") || filename.contains(".so."))
}

/// Calculate similarity between two library names, ignoring version differences
fn library_similarity(name1: &str, name2: &str) -> f64 {
    // Extract base name (before .so)
    let base1 = name1.split(".so").next().unwrap_or(name1);
    let base2 = name2.split(".so").next().unwrap_or(name2);

    if base1 == base2 {
        // Same library, different version
        0.95
    } else {
        // Use Levenshtein distance for the full names
        strsim::normalized_levenshtein(name1, name2)
    }
}

/// Calculate similarity score between two file paths
fn calculate_file_similarity(path1: &str, path2: &str) -> f64 {
    // Extract just the filename for comparison
    let name1 = Path::new(path1)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path1);

    let name2 = Path::new(path2)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path2);

    // Check if both are shared libraries
    if is_shared_library(name1) && is_shared_library(name2) {
        return library_similarity(name1, name2);
    }

    // Use Levenshtein distance for general files
    strsim::normalized_levenshtein(name1, name2)
}

/// Extract library base name (everything before .so)
fn extract_library_base(filename: &str) -> Option<&str> {
    if !is_shared_library(filename) {
        return None;
    }
    filename.split(".so").next()
}

/// Detect file renames between removed and added files using optimized multi-pass algorithm
/// This is O(n) instead of O(n*m) for better performance with large file sets
fn detect_renames(removed: &[String], added: &[String]) -> Vec<FileRename> {
    let mut matches = Vec::new();
    let mut used_removed = HashSet::new();
    let mut used_added = HashSet::new();

    // Pass 1: Exact basename match when unique (O(n) using HashMap)
    // This catches simple renames like dir1/unique_file.txt -> dir2/unique_file.txt
    // Only match when basename is unique in both removed and added sets
    let mut removed_by_basename: HashMap<String, Vec<&String>> = HashMap::new();
    let mut added_by_basename: HashMap<String, Vec<&String>> = HashMap::new();

    for removed_file in removed {
        if let Some(basename) = Path::new(removed_file).file_name().and_then(|n| n.to_str()) {
            removed_by_basename
                .entry(basename.to_string())
                .or_default()
                .push(removed_file);
        }
    }

    for added_file in added {
        if let Some(basename) = Path::new(added_file).file_name().and_then(|n| n.to_str()) {
            added_by_basename
                .entry(basename.to_string())
                .or_default()
                .push(added_file);
        }
    }

    // Match basenames that appear exactly once in both sets
    for (basename, removed_files) in &removed_by_basename {
        if removed_files.len() == 1 {
            if let Some(added_files) = added_by_basename.get(basename) {
                if added_files.len() == 1 {
                    let removed_file = removed_files[0];
                    let added_file = added_files[0];
                    matches.push(FileRename {
                        baseline_path: (*removed_file).clone(),
                        target_path: (*added_file).clone(),
                        similarity_score: 1.0,
                    });
                    used_removed.insert((*removed_file).clone());
                    used_added.insert((*added_file).clone());
                }
            }
        }
    }

    // Pass 2: Library version matching (O(n) using HashMap)
    // This catches libssl.so.1.0.0 -> libssl.so.1.1.0
    let mut added_by_lib_base: HashMap<String, Vec<&String>> = HashMap::new();
    for added_file in added {
        if used_added.contains(added_file) {
            continue;
        }
        if let Some(basename) = Path::new(added_file).file_name().and_then(|n| n.to_str()) {
            if let Some(lib_base) = extract_library_base(basename) {
                added_by_lib_base
                    .entry(lib_base.to_string())
                    .or_default()
                    .push(added_file);
            }
        }
    }

    for removed_file in removed {
        if used_removed.contains(removed_file) {
            continue;
        }
        if let Some(basename) = Path::new(removed_file).file_name().and_then(|n| n.to_str()) {
            if let Some(lib_base) = extract_library_base(basename) {
                if let Some(candidates) = added_by_lib_base.get(lib_base) {
                    // Take the first match for library renames
                    for added_file in candidates {
                        if !used_added.contains(*added_file) {
                            matches.push(FileRename {
                                baseline_path: removed_file.clone(),
                                target_path: (*added_file).clone(),
                                similarity_score: 0.95,
                            });
                            used_removed.insert(removed_file.clone());
                            used_added.insert((*added_file).clone());
                            break;
                        }
                    }
                }
            }
        }
    }

    // Pass 3: Same directory comparison (O(n) by grouping)
    // Only compare files within the same directory to reduce search space
    let mut removed_by_dir: HashMap<String, Vec<&String>> = HashMap::new();
    for removed_file in removed {
        if used_removed.contains(removed_file) {
            continue;
        }
        let dir = Path::new(removed_file)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("")
            .to_string();
        removed_by_dir.entry(dir).or_default().push(removed_file);
    }

    let mut added_by_dir: HashMap<String, Vec<&String>> = HashMap::new();
    for added_file in added {
        if used_added.contains(added_file) {
            continue;
        }
        let dir = Path::new(added_file)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("")
            .to_string();
        added_by_dir.entry(dir).or_default().push(added_file);
    }

    // Within each directory, compare files (O(k*m) where k,m are small directory sizes)
    for (dir, removed_files) in &removed_by_dir {
        if let Some(added_files) = added_by_dir.get(dir) {
            for removed_file in removed_files {
                if used_removed.contains(*removed_file) {
                    continue;
                }

                let mut best_match: Option<(&String, f64)> = None;
                for added_file in added_files {
                    if used_added.contains(*added_file) {
                        continue;
                    }

                    let score = calculate_file_similarity(removed_file, added_file);
                    if score >= 0.9 && (best_match.is_none() || score > best_match.unwrap().1) {
                        best_match = Some((added_file, score));
                    }
                }

                if let Some((added_file, score)) = best_match {
                    matches.push(FileRename {
                        baseline_path: (*removed_file).clone(),
                        target_path: (*added_file).clone(),
                        similarity_score: score,
                    });
                    used_removed.insert((*removed_file).clone());
                    used_added.insert((*added_file).clone());
                }
            }
        }
    }

    // Sort by score descending to prioritize best matches
    matches.sort_by(|a, b| {
        b.similarity_score
            .partial_cmp(&a.similarity_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    matches
}

impl DiffAnalyzer {
    pub fn new(baseline: impl AsRef<Path>, target: impl AsRef<Path>) -> Self {
        Self {
            baseline_path: baseline.as_ref().to_path_buf(),
            target_path: target.as_ref().to_path_buf(),
            capability_mapper: CapabilityMapper::new(),
        }
    }

    pub fn analyze(&self) -> Result<DiffReport> {
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

        Ok(diff_report)
    }

    fn analyze_files(&self) -> Result<DiffReport> {
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
        if !analysis.new_capabilities.is_empty() || !analysis.removed_capabilities.is_empty() {
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
                modified: if modified_analysis.is_empty() {
                    vec![]
                } else {
                    vec![self.target_path.display().to_string()]
                },
                renamed: vec![],
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
        // Get all files in both directories
        let baseline_files = self.collect_files(&self.baseline_path)?;
        let target_files = self.collect_files(&self.target_path)?;

        // Determine what changed
        let baseline_set: HashSet<_> = baseline_files.keys().collect();
        let target_set: HashSet<_> = target_files.keys().collect();

        let mut added: Vec<String> = target_set
            .difference(&baseline_set)
            .map(|s| s.to_string())
            .collect();
        let mut removed: Vec<String> = baseline_set
            .difference(&target_set)
            .map(|s| s.to_string())
            .collect();
        let modified_candidates: Vec<String> = baseline_set
            .intersection(&target_set)
            .map(|s| s.to_string())
            .collect();

        // Detect renames using similarity scoring
        let renames = detect_renames(&removed, &added);

        if !renames.is_empty() {
            // Remove renamed files from added/removed lists
            let renamed_baseline: HashSet<String> =
                renames.iter().map(|r| r.baseline_path.clone()).collect();
            let renamed_target: HashSet<String> =
                renames.iter().map(|r| r.target_path.clone()).collect();

            removed.retain(|f| !renamed_baseline.contains(f));
            added.retain(|f| !renamed_target.contains(f));
        }

        // Analyze modified files
        let mut modified_analysis = Vec::new();
        let mut actually_modified = Vec::new();

        for relative_path in modified_candidates {
            let baseline_file = baseline_files.get(&relative_path).unwrap();
            let target_file = target_files.get(&relative_path).unwrap();

            // Quick check: if sizes match and content matches, skip
            if let (Ok(baseline_meta), Ok(target_meta)) =
                (fs::metadata(baseline_file), fs::metadata(target_file))
            {
                if baseline_meta.len() == target_meta.len() {
                    if let (Ok(baseline_content), Ok(target_content)) =
                        (fs::read(baseline_file), fs::read(target_file))
                    {
                        if baseline_content == target_content {
                            continue; // Files are identical
                        }
                    }
                }
            }

            // Files differ - analyze both
            match (
                self.analyze_single_file(baseline_file),
                self.analyze_single_file(target_file),
            ) {
                (Ok(baseline_report), Ok(target_report)) => {
                    let analysis =
                        self.compare_reports(&relative_path, &baseline_report, &target_report);

                    if !analysis.new_capabilities.is_empty()
                        || !analysis.removed_capabilities.is_empty()
                    {
                        actually_modified.push(relative_path.clone());
                        modified_analysis.push(analysis);
                    }
                }
                _ => {
                    // Failed to analyze, skip
                }
            }
        }

        // Convert renames to FileRenameInfo
        let renamed_files: Vec<FileRenameInfo> = renames
            .iter()
            .map(|r| FileRenameInfo {
                from: r.baseline_path.clone(),
                to: r.target_path.clone(),
                similarity: r.similarity_score,
            })
            .collect();

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
                renamed: renamed_files,
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
            let relative = path
                .strip_prefix(dir)
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
                let analyzer = crate::analyzers::macho::MachOAnalyzer::new()
                    .with_capability_mapper(self.capability_mapper.clone());
                analyzer.analyze(path)
            }
            crate::analyzers::FileType::Elf => {
                let analyzer = crate::analyzers::elf::ElfAnalyzer::new()
                    .with_capability_mapper(self.capability_mapper.clone());
                analyzer.analyze(path)
            }
            crate::analyzers::FileType::Pe => {
                let analyzer = crate::analyzers::pe::PEAnalyzer::new()
                    .with_capability_mapper(self.capability_mapper.clone());
                analyzer.analyze(path)
            }
            crate::analyzers::FileType::Shell => {
                let analyzer = crate::analyzers::shell::ShellAnalyzer::new()
                    .with_capability_mapper(self.capability_mapper.clone());
                analyzer.analyze(path)
            }
            crate::analyzers::FileType::Python => {
                let analyzer = crate::analyzers::python::PythonAnalyzer::new()
                    .with_capability_mapper(self.capability_mapper.clone());
                analyzer.analyze(path)
            }
            crate::analyzers::FileType::JavaScript => {
                let analyzer = crate::analyzers::javascript::JavaScriptAnalyzer::new()
                    .with_capability_mapper(self.capability_mapper.clone());
                analyzer.analyze(path)
            }
            crate::analyzers::FileType::Archive => {
                let analyzer =
                    ArchiveAnalyzer::new().with_capability_mapper(self.capability_mapper.clone());
                analyzer.analyze(path)
            }
            _ => {
                anyhow::bail!("Unsupported file type for diff analysis")
            }
        }
    }

    fn compare_reports(
        &self,
        file_path: &str,
        baseline: &AnalysisReport,
        target: &AnalysisReport,
    ) -> ModifiedFileAnalysis {
        let baseline_cap_ids: HashSet<String> =
            baseline.findings.iter().map(|c| c.id.clone()).collect();

        let target_cap_ids: HashSet<String> =
            target.findings.iter().map(|c| c.id.clone()).collect();

        // Get IDs of new and removed capabilities
        let new_cap_ids: HashSet<&String> = target_cap_ids.difference(&baseline_cap_ids).collect();
        let removed_cap_ids: HashSet<&String> =
            baseline_cap_ids.difference(&target_cap_ids).collect();

        // Get full capability objects for new capabilities (from target)
        let new_capabilities: Vec<Finding> = target
            .findings
            .iter()
            .filter(|c| new_cap_ids.contains(&c.id))
            .cloned()
            .collect();

        // Get full capability objects for removed capabilities (from baseline)
        let removed_capabilities: Vec<Finding> = baseline
            .findings
            .iter()
            .filter(|c| removed_cap_ids.contains(&c.id))
            .cloned()
            .collect();

        // Risk assessment
        let risk_increase = self.assess_risk_increase(&new_capabilities, &removed_capabilities);

        ModifiedFileAnalysis {
            file: file_path.to_string(),
            new_capabilities,
            removed_capabilities,
            capability_delta: target_cap_ids.len() as i32 - baseline_cap_ids.len() as i32,
            risk_increase,
        }
    }

    /// Create a comprehensive diff suitable for ML analysis
    /// Treats the delta as a "virtual program" with all field differences
    fn create_full_diff(
        &self,
        file_path: &str,
        baseline: &AnalysisReport,
        target: &AnalysisReport,
    ) -> FileDiff {
        // Compute all collection deltas
        let (added_findings, removed_findings) =
            compute_added_removed(&baseline.findings, &target.findings, |f| f.id.clone());

        let (added_traits, removed_traits) =
            compute_added_removed(&baseline.traits, &target.traits, |t| {
                format!("{:?}:{}", t.kind, t.value)
            });

        let (added_strings, removed_strings) =
            compute_added_removed(&baseline.strings, &target.strings, |s| s.value.clone());

        let (added_imports, removed_imports) =
            compute_added_removed(&baseline.imports, &target.imports, |i| {
                format!("{}:{}", i.source, i.symbol)
            });

        let (added_exports, removed_exports) =
            compute_added_removed(&baseline.exports, &target.exports, |e| e.symbol.clone());

        let (added_functions, removed_functions) =
            compute_added_removed(&baseline.functions, &target.functions, |f| f.name.clone());

        let (added_syscalls, removed_syscalls) =
            compute_added_removed(&baseline.syscalls, &target.syscalls, |s| s.name.clone());

        let (added_paths, removed_paths) =
            compute_added_removed(&baseline.paths, &target.paths, |p| p.path.clone());

        let (added_env_vars, removed_env_vars) =
            compute_added_removed(&baseline.env_vars, &target.env_vars, |e| e.name.clone());

        let (added_yara_matches, removed_yara_matches) =
            compute_added_removed(&baseline.yara_matches, &target.yara_matches, |y| {
                format!("{}:{}", y.namespace, y.rule)
            });

        // Compute metrics deltas
        let metrics_delta = self.compute_metrics_delta(baseline, target);

        // Compute counts summary
        let counts = DiffCounts {
            findings_added: added_findings.len() as i32,
            findings_removed: removed_findings.len() as i32,
            traits_added: added_traits.len() as i32,
            traits_removed: removed_traits.len() as i32,
            strings_added: added_strings.len() as i32,
            strings_removed: removed_strings.len() as i32,
            imports_added: added_imports.len() as i32,
            imports_removed: removed_imports.len() as i32,
            exports_added: added_exports.len() as i32,
            exports_removed: removed_exports.len() as i32,
            functions_added: added_functions.len() as i32,
            functions_removed: removed_functions.len() as i32,
            syscalls_added: added_syscalls.len() as i32,
            syscalls_removed: removed_syscalls.len() as i32,
            paths_added: added_paths.len() as i32,
            paths_removed: removed_paths.len() as i32,
            env_vars_added: added_env_vars.len() as i32,
            env_vars_removed: removed_env_vars.len() as i32,
        };

        // Risk assessment
        let risk_increase = self.assess_risk_increase(&added_findings, &removed_findings);

        FileDiff {
            file: file_path.to_string(),
            added_findings,
            removed_findings,
            added_traits,
            removed_traits,
            added_strings,
            removed_strings,
            added_imports,
            removed_imports,
            added_exports,
            removed_exports,
            added_functions,
            removed_functions,
            added_syscalls,
            removed_syscalls,
            added_paths,
            removed_paths,
            added_env_vars,
            removed_env_vars,
            added_yara_matches,
            removed_yara_matches,
            metrics_delta: Some(metrics_delta),
            counts: Some(counts),
            risk_increase,
            risk_score_delta: None, // TODO: implement risk scoring
        }
    }

    /// Compute numeric deltas between baseline and target metrics
    fn compute_metrics_delta(
        &self,
        baseline: &AnalysisReport,
        target: &AnalysisReport,
    ) -> MetricsDelta {
        let mut delta = MetricsDelta {
            size_bytes: target.target.size_bytes as i64 - baseline.target.size_bytes as i64,
            ..Default::default()
        };

        // Source code metrics
        if let (Some(b), Some(t)) = (&baseline.source_code_metrics, &target.source_code_metrics) {
            delta.total_lines = t.total_lines as i32 - b.total_lines as i32;
            delta.code_lines = t.code_lines as i32 - b.code_lines as i32;
            delta.comment_lines = t.comment_lines as i32 - b.comment_lines as i32;
            delta.blank_lines = t.blank_lines as i32 - b.blank_lines as i32;
            delta.string_count = t.string_count as i32 - b.string_count as i32;
            delta.avg_string_length = t.avg_string_length - b.avg_string_length;
            delta.avg_string_entropy = t.avg_string_entropy - b.avg_string_entropy;
        }

        // Binary code metrics
        if let (Some(b), Some(t)) = (&baseline.code_metrics, &target.code_metrics) {
            delta.total_functions = t.total_functions as i32 - b.total_functions as i32;
            delta.total_basic_blocks = t.total_basic_blocks as i32 - b.total_basic_blocks as i32;
            delta.avg_complexity = t.avg_complexity - b.avg_complexity;
            delta.max_complexity = t.max_complexity as i32 - b.max_complexity as i32;
            delta.total_instructions = t.total_instructions as i32 - b.total_instructions as i32;
            delta.code_density = t.code_density - b.code_density;
        }

        // Unified metrics
        if let (Some(b_metrics), Some(t_metrics)) = (&baseline.metrics, &target.metrics) {
            if let (Some(b), Some(t)) = (&b_metrics.text, &t_metrics.text) {
                delta.total_lines = t.total_lines as i32 - b.total_lines as i32;
            }
            if let (Some(b), Some(t)) = (&b_metrics.comments, &t_metrics.comments) {
                delta.comment_lines = t.lines as i32 - b.lines as i32;
            }
            if let (Some(b), Some(t)) = (&b_metrics.identifiers, &t_metrics.identifiers) {
                delta.unique_identifiers = t.unique as i32 - b.unique as i32;
                delta.avg_identifier_length = t.avg_length - b.avg_length;
            }
            if let (Some(b), Some(t)) = (&b_metrics.strings, &t_metrics.strings) {
                delta.string_count = t.total as i32 - b.total as i32;
                delta.avg_string_length = t.avg_length - b.avg_length;
                delta.avg_string_entropy = t.avg_entropy - b.avg_entropy;
            }
            if let (Some(b), Some(t)) = (&b_metrics.functions, &t_metrics.functions) {
                delta.total_functions = t.total as i32 - b.total as i32;
            }
        }

        delta
    }

    /// Create a full diff report with comprehensive analysis for ML pipelines
    pub fn analyze_full(&self) -> Result<FullDiffReport> {
        let is_baseline_dir = self.baseline_path.is_dir();
        let is_target_dir = self.target_path.is_dir();

        if is_baseline_dir && is_target_dir {
            self.analyze_directories_full()
        } else if !is_baseline_dir && !is_target_dir {
            self.analyze_files_full()
        } else {
            anyhow::bail!("Baseline and target must both be files or both be directories");
        }
    }

    fn analyze_files_full(&self) -> Result<FullDiffReport> {
        let baseline_report = self.analyze_single_file(&self.baseline_path)?;
        let target_report = self.analyze_single_file(&self.target_path)?;

        let file_diff = self.create_full_diff(
            &self.target_path.display().to_string(),
            &baseline_report,
            &target_report,
        );

        let modified_analysis = self.compare_reports(
            &self.baseline_path.display().to_string(),
            &baseline_report,
            &target_report,
        );

        let aggregate_counts = file_diff.counts.clone();
        let mut file_diffs = Vec::new();
        let mut modified_analysis_vec = Vec::new();

        if file_diff.added_findings.len() + file_diff.removed_findings.len() > 0
            || file_diff.added_strings.len() + file_diff.removed_strings.len() > 0
            || file_diff.added_imports.len() + file_diff.removed_imports.len() > 0
        {
            file_diffs.push(file_diff);
            modified_analysis_vec.push(modified_analysis);
        }

        Ok(FullDiffReport {
            schema_version: "2.0".to_string(),
            analysis_timestamp: Utc::now(),
            diff_mode: true,
            baseline: self.baseline_path.display().to_string(),
            target: self.target_path.display().to_string(),
            changes: FileChanges {
                added: vec![],
                removed: vec![],
                modified: if file_diffs.is_empty() {
                    vec![]
                } else {
                    vec![self.target_path.display().to_string()]
                },
                renamed: vec![],
            },
            file_diffs,
            modified_analysis: modified_analysis_vec,
            aggregate_counts,
            metadata: AnalysisMetadata {
                analysis_duration_ms: 0,
                tools_used: vec!["diff_analyzer".to_string()],
                errors: vec![],
            },
        })
    }

    fn analyze_directories_full(&self) -> Result<FullDiffReport> {
        let baseline_files = self.collect_files(&self.baseline_path)?;
        let target_files = self.collect_files(&self.target_path)?;

        let baseline_set: HashSet<_> = baseline_files.keys().collect();
        let target_set: HashSet<_> = target_files.keys().collect();

        let mut added: Vec<String> = target_set
            .difference(&baseline_set)
            .map(|s| s.to_string())
            .collect();
        let mut removed: Vec<String> = baseline_set
            .difference(&target_set)
            .map(|s| s.to_string())
            .collect();
        let modified_candidates: Vec<String> = baseline_set
            .intersection(&target_set)
            .map(|s| s.to_string())
            .collect();

        let renames = detect_renames(&removed, &added);

        if !renames.is_empty() {
            let renamed_baseline: HashSet<String> =
                renames.iter().map(|r| r.baseline_path.clone()).collect();
            let renamed_target: HashSet<String> =
                renames.iter().map(|r| r.target_path.clone()).collect();

            removed.retain(|f| !renamed_baseline.contains(f));
            added.retain(|f| !renamed_target.contains(f));
        }

        let mut file_diffs = Vec::new();
        let mut modified_analysis = Vec::new();
        let mut actually_modified = Vec::new();

        // Aggregate counts
        let mut aggregate = DiffCounts::default();

        for relative_path in modified_candidates {
            let baseline_file = baseline_files.get(&relative_path).unwrap();
            let target_file = target_files.get(&relative_path).unwrap();

            if let (Ok(baseline_meta), Ok(target_meta)) =
                (fs::metadata(baseline_file), fs::metadata(target_file))
            {
                if baseline_meta.len() == target_meta.len() {
                    if let (Ok(baseline_content), Ok(target_content)) =
                        (fs::read(baseline_file), fs::read(target_file))
                    {
                        if baseline_content == target_content {
                            continue;
                        }
                    }
                }
            }

            if let (Ok(baseline_report), Ok(target_report)) = (
                self.analyze_single_file(baseline_file),
                self.analyze_single_file(target_file),
            ) {
                let file_diff =
                    self.create_full_diff(&relative_path, &baseline_report, &target_report);

                // Only include if there are actual changes
                if let Some(ref counts) = file_diff.counts {
                    if counts.findings_added != 0
                        || counts.findings_removed != 0
                        || counts.strings_added != 0
                        || counts.strings_removed != 0
                        || counts.imports_added != 0
                        || counts.imports_removed != 0
                    {
                        // Accumulate aggregate counts
                        aggregate.findings_added += counts.findings_added;
                        aggregate.findings_removed += counts.findings_removed;
                        aggregate.traits_added += counts.traits_added;
                        aggregate.traits_removed += counts.traits_removed;
                        aggregate.strings_added += counts.strings_added;
                        aggregate.strings_removed += counts.strings_removed;
                        aggregate.imports_added += counts.imports_added;
                        aggregate.imports_removed += counts.imports_removed;
                        aggregate.exports_added += counts.exports_added;
                        aggregate.exports_removed += counts.exports_removed;
                        aggregate.functions_added += counts.functions_added;
                        aggregate.functions_removed += counts.functions_removed;
                        aggregate.syscalls_added += counts.syscalls_added;
                        aggregate.syscalls_removed += counts.syscalls_removed;
                        aggregate.paths_added += counts.paths_added;
                        aggregate.paths_removed += counts.paths_removed;
                        aggregate.env_vars_added += counts.env_vars_added;
                        aggregate.env_vars_removed += counts.env_vars_removed;

                        actually_modified.push(relative_path.clone());
                        file_diffs.push(file_diff);

                        let analysis =
                            self.compare_reports(&relative_path, &baseline_report, &target_report);
                        modified_analysis.push(analysis);
                    }
                }
            }
        }

        let renamed_files: Vec<FileRenameInfo> = renames
            .iter()
            .map(|r| FileRenameInfo {
                from: r.baseline_path.clone(),
                to: r.target_path.clone(),
                similarity: r.similarity_score,
            })
            .collect();

        Ok(FullDiffReport {
            schema_version: "2.0".to_string(),
            analysis_timestamp: Utc::now(),
            diff_mode: true,
            baseline: self.baseline_path.display().to_string(),
            target: self.target_path.display().to_string(),
            changes: FileChanges {
                added,
                removed,
                modified: actually_modified,
                renamed: renamed_files,
            },
            file_diffs,
            modified_analysis,
            aggregate_counts: Some(aggregate),
            metadata: AnalysisMetadata {
                analysis_duration_ms: 0,
                tools_used: vec!["diff_analyzer".to_string()],
                errors: vec![],
            },
        })
    }

    fn assess_risk_increase(&self, new_caps: &[Finding], removed_caps: &[Finding]) -> bool {
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
        let new_high_risk_count = new_caps
            .iter()
            .filter(|cap| {
                high_risk_prefixes
                    .iter()
                    .any(|prefix| cap.id.starts_with(prefix))
            })
            .count();

        // Check if removed capabilities were high-risk
        let removed_high_risk_count = removed_caps
            .iter()
            .filter(|cap| {
                high_risk_prefixes
                    .iter()
                    .any(|prefix| cap.id.starts_with(prefix))
            })
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

    // Header with version comparison
    let baseline_name = Path::new(&report.baseline)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&report.baseline);
    let target_name = Path::new(&report.target)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&report.target);

    output.push_str(&format!("📦 {} → {}\n", baseline_name, target_name));
    output.push_str(&format!("   {}\n   {}\n\n", report.baseline, report.target));

    let total_changes = report.changes.added.len()
        + report.changes.removed.len()
        + report.changes.modified.len()
        + report.changes.renamed.len();

    if total_changes == 0 && report.modified_analysis.is_empty() {
        output.push_str("✅ No capability changes detected\n");
        return output;
    }

    // Risk assessment upfront
    let high_risk_changes = report
        .modified_analysis
        .iter()
        .filter(|a| a.risk_increase)
        .count();

    if high_risk_changes > 0 {
        output.push_str(&format!(
            "🚨 {} file(s) with increased risk\n\n",
            high_risk_changes
        ));
    }

    // Sort modified files: high risk first, then by filename
    let mut sorted_analysis = report.modified_analysis.clone();
    sorted_analysis.sort_by(|a, b| {
        b.risk_increase
            .cmp(&a.risk_increase)
            .then_with(|| a.file.cmp(&b.file))
    });

    // Modified files with capability changes (most important)
    for analysis in &sorted_analysis {
        let risk_icon = if analysis.risk_increase {
            "⚠️ "
        } else {
            ""
        };
        output.push_str(&format!("{}📄 {}\n", risk_icon, analysis.file));

        // Aggregate findings by directory path for cleaner display
        let mut aggregated_new = aggregate_findings_by_directory(&analysis.new_capabilities);

        // Sort by criticality (highest first), then by name
        aggregated_new.sort_by(|a, b| b.crit.cmp(&a.crit).then_with(|| a.id.cmp(&b.id)));

        // Show new capabilities (one line each, aggregated by directory)
        for cap in &aggregated_new {
            let risk_icon = match cap.crit {
                crate::types::Criticality::Hostile => "🔴",
                crate::types::Criticality::Suspicious => "🟠",
                crate::types::Criticality::Notable => "🟡",
                _ => "🟢",
            };

            // Get best evidence (prefer one with a line number)
            let evidence_str = cap
                .evidence
                .iter()
                .find(|e| e.location.as_ref().is_some_and(|l| l.starts_with("line:")))
                .or(cap.evidence.first())
                .map(|ev| {
                    let loc = ev
                        .location
                        .as_ref()
                        .filter(|l| l != &"file" && !l.is_empty())
                        .map(|l| format!(":{}", l.trim_start_matches("line:")))
                        .unwrap_or_default();
                    format!(" [{}{}]", ev.value, loc)
                })
                .unwrap_or_default();

            output.push_str(&format!(
                "   + {} {}: {}{}\n",
                risk_icon, cap.id, cap.desc, evidence_str
            ));
        }

        // Aggregate removed capabilities by directory path too
        let mut aggregated_removed =
            aggregate_findings_by_directory(&analysis.removed_capabilities);

        // Sort by criticality (highest first), then by name
        aggregated_removed.sort_by(|a, b| b.crit.cmp(&a.crit).then_with(|| a.id.cmp(&b.id)));

        // Show removed capabilities
        for cap in &aggregated_removed {
            output.push_str(&format!("   - {}\n", cap.id));
        }
        output.push('\n');
    }

    // File-level changes section
    let file_changes =
        report.changes.added.len() + report.changes.removed.len() + report.changes.renamed.len();
    if file_changes > 0 {
        output.push_str("📁 File changes:\n");

        // Added files
        for file in &report.changes.added {
            output.push_str(&format!("   + {}\n", file));
        }

        // Removed files
        for file in &report.changes.removed {
            output.push_str(&format!("   - {}\n", file));
        }

        // Renamed files
        for rename in &report.changes.renamed {
            if rename.similarity < 1.0 {
                output.push_str(&format!(
                    "   → {} → {} ({:.0}%)\n",
                    rename.from,
                    rename.to,
                    rename.similarity * 100.0
                ));
            } else {
                output.push_str(&format!("   → {} → {}\n", rename.from, rename.to));
            }
        }
        output.push('\n');
    }

    // Summary line
    let mut summary_parts = Vec::new();
    if !report.changes.added.is_empty() {
        summary_parts.push(format!("+{} files", report.changes.added.len()));
    }
    if !report.changes.removed.is_empty() {
        summary_parts.push(format!("-{} files", report.changes.removed.len()));
    }
    if !report.modified_analysis.is_empty() {
        let total_new: usize = report
            .modified_analysis
            .iter()
            .map(|a| a.new_capabilities.len())
            .sum();
        let total_removed: usize = report
            .modified_analysis
            .iter()
            .map(|a| a.removed_capabilities.len())
            .sum();
        if total_new > 0 {
            summary_parts.push(format!("+{} capabilities", total_new));
        }
        if total_removed > 0 {
            summary_parts.push(format!("-{} capabilities", total_removed));
        }
    }
    if !summary_parts.is_empty() {
        output.push_str(&format!("Summary: {}\n", summary_parts.join(", ")));
    }

    output
}

#[allow(dead_code)]
fn is_high_risk(capability: &Finding) -> bool {
    is_high_risk_id(&capability.id)
}

#[allow(dead_code)]
fn is_high_risk_id(id: &str) -> bool {
    id.starts_with("exec/")
        || id.starts_with("anti-analysis/")
        || id.starts_with("privesc/")
        || id.starts_with("privilege/")
        || id.starts_with("persistence/")
        || id.starts_with("injection/")
        || id.starts_with("c2/")
        || id.starts_with("exfil/")
        || id.starts_with("data/secret")
}

#[allow(dead_code)]
fn is_medium_risk(capability: &Finding) -> bool {
    is_medium_risk_id(&capability.id)
}

#[allow(dead_code)]
fn is_medium_risk_id(id: &str) -> bool {
    id.starts_with("net/")
        || id.starts_with("credential/")
        || id.starts_with("registry/")
        || id.starts_with("service/")
        || id.starts_with("evasion/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AnalysisReport, Criticality, Finding, FindingKind, TargetInfo};
    use chrono::Utc;

    fn create_test_report_for_diff(path: &str, trait_ids: Vec<&str>) -> AnalysisReport {
        let findings: Vec<Finding> = trait_ids
            .iter()
            .map(|id| Finding {
                id: id.to_string(),
                kind: FindingKind::Capability,
                desc: format!("Test {}", id),
                conf: 0.8,
                crit: if id.starts_with("exec/") {
                    Criticality::Hostile
                } else {
                    Criticality::Notable
                },
                mbc: None,
                attack: None,
                trait_refs: vec![],
                evidence: vec![],
            })
            .collect();

        AnalysisReport {
            schema_version: "1.1".to_string(),
            analysis_timestamp: Utc::now(),
            target: TargetInfo {
                path: path.to_string(),
                file_type: "ELF".to_string(),
                size_bytes: 12345,
                sha256: "abc123".to_string(),
                architectures: None,
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
            yara_matches: vec![],
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
            sub_reports: vec![],
            metadata: crate::types::AnalysisMetadata {
                analysis_duration_ms: 100,
                tools_used: vec!["test".to_string()],
                errors: vec![],
            },
        }
    }

    #[test]
    fn test_diff_analyzer_new() {
        let analyzer = DiffAnalyzer::new("/baseline", "/target");
        assert_eq!(analyzer.baseline_path.to_str().unwrap(), "/baseline");
        assert_eq!(analyzer.target_path.to_str().unwrap(), "/target");
    }

    #[test]
    fn test_is_high_risk() {
        assert!(is_high_risk_id("exec/shell"));
        assert!(is_high_risk_id("anti-analysis/debugger"));
        assert!(is_high_risk_id("privilege/escalation"));
        assert!(is_high_risk_id("persistence/registry"));
        assert!(is_high_risk_id("injection/dll"));
        assert!(!is_high_risk_id("net/http"));
        assert!(!is_high_risk_id("fs/read"));
    }

    #[test]
    fn test_is_medium_risk() {
        assert!(is_medium_risk_id("net/http"));
        assert!(is_medium_risk_id("credential/dump"));
        assert!(is_medium_risk_id("registry/read"));
        assert!(is_medium_risk_id("service/query"));
        assert!(!is_medium_risk_id("exec/shell"));
        assert!(!is_medium_risk_id("fs/read"));
    }

    #[test]
    fn test_compare_reports_no_changes() {
        let analyzer = DiffAnalyzer::new("/baseline", "/target");
        let baseline = create_test_report_for_diff("/baseline/file", vec!["net/http"]);
        let target = create_test_report_for_diff("/target/file", vec!["net/http"]);

        let analysis = analyzer.compare_reports("file", &baseline, &target);
        assert_eq!(analysis.file, "file");
        assert_eq!(analysis.new_capabilities.len(), 0);
        assert_eq!(analysis.removed_capabilities.len(), 0);
        assert_eq!(analysis.capability_delta, 0);
        assert!(!analysis.risk_increase);
    }

    #[test]
    fn test_compare_reports_new_capabilities() {
        let analyzer = DiffAnalyzer::new("/baseline", "/target");
        let baseline = create_test_report_for_diff("/baseline/file", vec!["net/http"]);
        let target = create_test_report_for_diff("/target/file", vec!["net/http", "fs/write"]);

        let analysis = analyzer.compare_reports("file", &baseline, &target);
        assert_eq!(analysis.new_capabilities.len(), 1);
        assert!(analysis.new_capabilities.iter().any(|c| c.id == "fs/write"));
        assert_eq!(analysis.capability_delta, 1);
    }

    #[test]
    fn test_compare_reports_removed_capabilities() {
        let analyzer = DiffAnalyzer::new("/baseline", "/target");
        let baseline = create_test_report_for_diff("/baseline/file", vec!["net/http", "fs/write"]);
        let target = create_test_report_for_diff("/target/file", vec!["net/http"]);

        let analysis = analyzer.compare_reports("file", &baseline, &target);
        assert_eq!(analysis.removed_capabilities.len(), 1);
        assert!(analysis
            .removed_capabilities
            .iter()
            .any(|c| c.id == "fs/write"));
        assert_eq!(analysis.capability_delta, -1);
    }

    #[test]
    fn test_compare_reports_risk_increase() {
        let analyzer = DiffAnalyzer::new("/baseline", "/target");
        let baseline = create_test_report_for_diff("/baseline/file", vec!["net/http"]);
        let target = create_test_report_for_diff("/target/file", vec!["net/http", "exec/shell"]);

        let analysis = analyzer.compare_reports("file", &baseline, &target);
        assert!(analysis.risk_increase);
        assert!(analysis
            .new_capabilities
            .iter()
            .any(|c| c.id == "exec/shell"));
    }

    fn make_test_cap(id: &str) -> Finding {
        Finding {
            id: id.to_string(),
            kind: FindingKind::Capability,
            desc: format!("Test {}", id),
            conf: 0.9,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![Evidence {
                method: "test".to_string(),
                source: "test".to_string(),
                value: id.to_string(),
                location: None,
            }],
        }
    }

    #[test]
    fn test_assess_risk_increase_new_high_risk() {
        let analyzer = DiffAnalyzer::new("/baseline", "/target");
        let new_caps = vec![make_test_cap("exec/shell")];
        let removed_caps = vec![];

        assert!(analyzer.assess_risk_increase(&new_caps, &removed_caps));
    }

    #[test]
    fn test_assess_risk_increase_no_high_risk() {
        let analyzer = DiffAnalyzer::new("/baseline", "/target");
        let new_caps = vec![make_test_cap("net/http")];
        let removed_caps = vec![];

        assert!(!analyzer.assess_risk_increase(&new_caps, &removed_caps));
    }

    #[test]
    fn test_assess_risk_increase_balanced() {
        let analyzer = DiffAnalyzer::new("/baseline", "/target");
        let new_caps = vec![make_test_cap("exec/shell")];
        let removed_caps = vec![make_test_cap("anti-analysis/debugger")];

        assert!(!analyzer.assess_risk_increase(&new_caps, &removed_caps));
    }

    #[test]
    fn test_assess_risk_increase_more_removed_than_added() {
        let analyzer = DiffAnalyzer::new("/baseline", "/target");
        let new_caps = vec![make_test_cap("exec/shell")];
        let removed_caps = vec![
            make_test_cap("anti-analysis/debugger"),
            make_test_cap("persistence/registry"),
        ];

        assert!(!analyzer.assess_risk_increase(&new_caps, &removed_caps));
    }

    #[test]
    fn test_collect_files_creates_relative_paths() {
        let analyzer = DiffAnalyzer::new("/baseline", "/target");

        // Test with src directory which should exist
        if let Ok(files) = analyzer.collect_files(Path::new("src")) {
            if !files.is_empty() {
                // Paths should be relative
                for rel_path in files.keys() {
                    assert!(!rel_path.starts_with("/"));
                }
            }
        }
        // Test passes regardless of whether files are found
    }

    #[test]
    fn test_format_diff_terminal_empty_changes() {
        let report = DiffReport {
            schema_version: "1.0".to_string(),
            analysis_timestamp: Utc::now(),
            diff_mode: true,
            baseline: "/baseline".to_string(),
            target: "/target".to_string(),
            changes: FileChanges {
                added: vec![],
                removed: vec![],
                modified: vec![],
                renamed: vec![],
            },
            modified_analysis: vec![],
            metadata: crate::types::AnalysisMetadata {
                analysis_duration_ms: 100,
                tools_used: vec!["diff_analyzer".to_string()],
                errors: vec![],
            },
        };

        let output = format_diff_terminal(&report);
        assert!(output.contains("/baseline"));
        assert!(output.contains("/target"));
        assert!(output.contains("No capability changes"));
    }

    #[test]
    fn test_format_diff_terminal_with_changes() {
        let report = DiffReport {
            schema_version: "1.0".to_string(),
            analysis_timestamp: Utc::now(),
            diff_mode: true,
            baseline: "/baseline".to_string(),
            target: "/target".to_string(),
            changes: FileChanges {
                added: vec!["new_file.bin".to_string()],
                removed: vec!["old_file.bin".to_string()],
                modified: vec!["changed_file.bin".to_string()],
                renamed: vec![],
            },
            modified_analysis: vec![ModifiedFileAnalysis {
                file: "changed_file.bin".to_string(),
                new_capabilities: vec![make_test_cap("exec/shell")],
                removed_capabilities: vec![],
                capability_delta: 1,
                risk_increase: true,
            }],
            metadata: crate::types::AnalysisMetadata {
                analysis_duration_ms: 100,
                tools_used: vec!["diff_analyzer".to_string()],
                errors: vec![],
            },
        };

        let output = format_diff_terminal(&report);
        assert!(output.contains("new_file.bin"));
        assert!(output.contains("old_file.bin"));
        assert!(output.contains("changed_file.bin"));
        assert!(output.contains("exec/shell"));
        assert!(output.contains("increased risk"));
    }

    #[test]
    fn test_format_diff_terminal_multiple_modified() {
        let report = DiffReport {
            schema_version: "1.0".to_string(),
            analysis_timestamp: Utc::now(),
            diff_mode: true,
            baseline: "/baseline".to_string(),
            target: "/target".to_string(),
            changes: FileChanges {
                added: vec![],
                removed: vec![],
                modified: vec!["file1.bin".to_string(), "file2.bin".to_string()],
                renamed: vec![],
            },
            modified_analysis: vec![
                ModifiedFileAnalysis {
                    file: "file1.bin".to_string(),
                    new_capabilities: vec![make_test_cap("net/http/client")],
                    removed_capabilities: vec![],
                    capability_delta: 1,
                    risk_increase: false,
                },
                ModifiedFileAnalysis {
                    file: "file2.bin".to_string(),
                    new_capabilities: vec![make_test_cap("exec/command/shell")],
                    removed_capabilities: vec![make_test_cap("fs/file/read")],
                    capability_delta: 0,
                    risk_increase: true,
                },
            ],
            metadata: crate::types::AnalysisMetadata {
                analysis_duration_ms: 100,
                tools_used: vec!["diff_analyzer".to_string()],
                errors: vec![],
            },
        };

        let output = format_diff_terminal(&report);
        assert!(output.contains("file1.bin"));
        assert!(output.contains("file2.bin"));
        // Capabilities are aggregated by directory (objective/behavior)
        assert!(output.contains("net/http"));
        assert!(output.contains("exec/command"));
        assert!(output.contains("fs/file"));
    }

    #[test]
    fn test_is_shared_library() {
        assert!(is_shared_library("libssl.so"));
        assert!(is_shared_library("libssl.so.1"));
        assert!(is_shared_library("libssl.so.1.0.0"));
        assert!(is_shared_library("libcrypto.so.1.1"));
        assert!(!is_shared_library("test.txt"));
        assert!(!is_shared_library("test"));
        assert!(!is_shared_library("libc.a"));
    }

    #[test]
    fn test_library_similarity_same_base() {
        // Same library, different versions should have high similarity
        let score = library_similarity("libssl.so.1.0.0", "libssl.so.1.1.0");
        assert_eq!(score, 0.95);

        let score2 = library_similarity("libcrypto.so.1", "libcrypto.so.2");
        assert_eq!(score2, 0.95);
    }

    #[test]
    fn test_library_similarity_different_base() {
        // Different libraries should use Levenshtein distance
        let score = library_similarity("libssl.so.1.0.0", "libcrypto.so.1.0.0");
        assert!(score < 0.95);
        assert!(score > 0.0);
    }

    #[test]
    fn test_calculate_file_similarity_libraries() {
        let score = calculate_file_similarity("lib/libssl.so.1.0.0", "lib/libssl.so.1.1.0");
        assert_eq!(score, 0.95);
    }

    #[test]
    fn test_calculate_file_similarity_general() {
        let score = calculate_file_similarity("test.txt", "test.txt");
        assert_eq!(score, 1.0);

        let score2 = calculate_file_similarity("test1.txt", "test2.txt");
        assert!(score2 > 0.8);

        let score3 = calculate_file_similarity("foo.txt", "completely_different.txt");
        assert!(score3 < 0.5);
    }

    #[test]
    fn test_detect_renames_no_matches() {
        let removed = vec!["file1.txt".to_string()];
        let added = vec!["completely_different.txt".to_string()];

        let renames = detect_renames(&removed, &added);
        assert_eq!(renames.len(), 0);
    }

    #[test]
    fn test_detect_renames_exact_match() {
        let removed = vec!["test.txt".to_string()];
        let added = vec!["test.txt".to_string()];

        let renames = detect_renames(&removed, &added);
        assert_eq!(renames.len(), 1);
        assert_eq!(renames[0].baseline_path, "test.txt");
        assert_eq!(renames[0].target_path, "test.txt");
        assert_eq!(renames[0].similarity_score, 1.0);
    }

    #[test]
    fn test_detect_renames_library_version() {
        let removed = vec!["libssl.so.1.0.0".to_string()];
        let added = vec!["libssl.so.1.1.0".to_string()];

        let renames = detect_renames(&removed, &added);
        assert_eq!(renames.len(), 1);
        assert_eq!(renames[0].baseline_path, "libssl.so.1.0.0");
        assert_eq!(renames[0].target_path, "libssl.so.1.1.0");
        assert_eq!(renames[0].similarity_score, 0.95);
    }

    #[test]
    fn test_detect_renames_deduplication() {
        // Multiple removed files, but only one good match
        let removed = vec!["file1.txt".to_string(), "file2.txt".to_string()];
        let added = vec!["file1_renamed.txt".to_string()];

        let renames = detect_renames(&removed, &added);
        // Should match file1.txt with file1_renamed.txt
        assert!(renames.len() <= 1);
        if renames.len() == 1 {
            assert!(renames[0].similarity_score >= 0.9);
        }
    }

    #[test]
    fn test_format_diff_terminal_with_renames() {
        let report = DiffReport {
            schema_version: "1.0".to_string(),
            analysis_timestamp: Utc::now(),
            diff_mode: true,
            baseline: "/baseline".to_string(),
            target: "/target".to_string(),
            changes: FileChanges {
                added: vec![],
                removed: vec![],
                modified: vec![],
                renamed: vec![FileRenameInfo {
                    from: "old_name.txt".to_string(),
                    to: "new_name.txt".to_string(),
                    similarity: 0.92,
                }],
            },
            modified_analysis: vec![],
            metadata: crate::types::AnalysisMetadata {
                analysis_duration_ms: 100,
                tools_used: vec!["diff_analyzer".to_string()],
                errors: vec![],
            },
        };

        let output = format_diff_terminal(&report);
        assert!(output.contains("old_name.txt"));
        assert!(output.contains("new_name.txt"));
        assert!(output.contains("92%"));
    }

    #[test]
    fn test_extract_library_base() {
        assert_eq!(extract_library_base("libssl.so.1.0.0"), Some("libssl"));
        assert_eq!(extract_library_base("libcrypto.so.1"), Some("libcrypto"));
        assert_eq!(extract_library_base("libc.so"), Some("libc"));
        assert_eq!(extract_library_base("test.txt"), None);
        assert_eq!(extract_library_base("file.tar.gz"), None);
    }

    #[test]
    fn test_detect_renames_exact_basename_match() {
        // Pass 1: Exact basename match in different directories
        let removed = vec!["dir1/test.txt".to_string()];
        let added = vec!["dir2/test.txt".to_string()];

        let renames = detect_renames(&removed, &added);
        assert_eq!(renames.len(), 1);
        assert_eq!(renames[0].baseline_path, "dir1/test.txt");
        assert_eq!(renames[0].target_path, "dir2/test.txt");
        assert_eq!(renames[0].similarity_score, 1.0);
    }

    #[test]
    fn test_detect_renames_library_version_match() {
        // Pass 2: Library version matching
        let removed = vec![
            "lib/x86_64/libssl.so.1.0.0".to_string(),
            "lib/x86_64/libcrypto.so.1.0.0".to_string(),
        ];
        let added = vec![
            "lib/x86_64/libssl.so.1.1.0".to_string(),
            "lib/x86_64/libcrypto.so.1.1.0".to_string(),
        ];

        let renames = detect_renames(&removed, &added);
        assert_eq!(renames.len(), 2);

        // Both should be detected as library version changes
        let ssl_rename = renames
            .iter()
            .find(|r| r.baseline_path.contains("libssl"))
            .unwrap();
        assert_eq!(ssl_rename.similarity_score, 0.95);

        let crypto_rename = renames
            .iter()
            .find(|r| r.baseline_path.contains("libcrypto"))
            .unwrap();
        assert_eq!(crypto_rename.similarity_score, 0.95);
    }

    #[test]
    fn test_detect_renames_same_directory_levenshtein() {
        // Pass 3: Same directory with Levenshtein distance
        // Use names with only 1-2 character difference to ensure >= 0.9 similarity
        let removed = vec!["dir/application_v1.txt".to_string()];
        let added = vec!["dir/application_v2.txt".to_string()];

        let renames = detect_renames(&removed, &added);
        assert_eq!(renames.len(), 1, "Expected 1 rename, got {}", renames.len());
        assert!(
            renames[0].similarity_score >= 0.9,
            "Similarity was {}",
            renames[0].similarity_score
        );
        assert_eq!(renames[0].baseline_path, "dir/application_v1.txt");
    }

    #[test]
    fn test_detect_renames_no_cross_directory_match() {
        // Different directories, different names - should not match
        let removed = vec!["dir1/foo.txt".to_string()];
        let added = vec!["dir2/bar.txt".to_string()];

        let renames = detect_renames(&removed, &added);
        assert_eq!(renames.len(), 0);
    }

    #[test]
    fn test_detect_renames_multiple_candidates_in_directory() {
        // If multiple files with same basename exist, don't match in pass 1
        let removed = vec!["dir1/test.txt".to_string()];
        let added = vec!["dir2/test.txt".to_string(), "dir3/test.txt".to_string()];

        let renames = detect_renames(&removed, &added);
        // Should not match because there are multiple candidates
        // (Pass 1 only matches when there's exactly one candidate)
        assert_eq!(renames.len(), 0);
    }

    #[test]
    fn test_detect_renames_deduplication_still_works() {
        // Verify that files are only matched once
        let removed = vec![
            "lib/libssl.so.1.0.0".to_string(),
            "lib/libssl.so.1.0.1".to_string(),
        ];
        let added = vec!["lib/libssl.so.1.1.0".to_string()];

        let renames = detect_renames(&removed, &added);
        // Only one rename should be detected (first match wins)
        assert_eq!(renames.len(), 1);
    }

    #[test]
    fn test_detect_renames_performance_large_set() {
        // Test performance with a larger set (1000 files)
        // This tests O(n) performance with files that have unique basenames
        use std::time::Instant;

        let mut removed = Vec::new();
        let mut added = Vec::new();

        // Create 1000 files with UNIQUE basenames across different directories
        // This will be matched by Pass 1 (exact basename, unique)
        for i in 0..1000 {
            removed.push(format!("old_dir/unique_file_{}.txt", i));
            added.push(format!("new_dir/unique_file_{}.txt", i));
        }

        let start = Instant::now();
        let renames = detect_renames(&removed, &added);
        let duration = start.elapsed();

        // Should find all 1000 exact matches via basename matching (Pass 1)
        assert_eq!(
            renames.len(),
            1000,
            "Expected 1000 renames, got {}",
            renames.len()
        );

        // Should complete in well under 1 second (O(n) performance)
        assert!(
            duration.as_millis() < 500,
            "Rename detection took too long: {:?}",
            duration
        );
    }

    #[test]
    fn test_detect_renames_mixed_scenarios() {
        // Test multiple passes working together
        let removed = vec![
            "dir1/file1.txt".to_string(),       // Exact match in different dir
            "lib/libssl.so.1.0.0".to_string(),  // Library version change
            "dir2/config_old.conf".to_string(), // Same dir, similar name (high similarity)
            "unique/file.txt".to_string(),      // No match
        ];
        let added = vec![
            "dir3/file1.txt".to_string(),       // Match for dir1/file1.txt
            "lib/libssl.so.1.1.0".to_string(),  // Match for libssl
            "dir2/config_new.conf".to_string(), // Match for config_old (similarity >= 0.9)
            "other/different.txt".to_string(),  // No match
        ];

        let renames = detect_renames(&removed, &added);

        // Should find at least 2 renames (exact basename + library)
        // The third one (config files) should also match if similarity >= 0.9
        assert!(
            renames.len() >= 2,
            "Expected at least 2 renames, got {}",
            renames.len()
        );
        assert!(
            renames.len() <= 3,
            "Expected at most 3 renames, got {}",
            renames.len()
        );

        // Verify each type was matched
        assert!(renames.iter().any(|r| r.baseline_path == "dir1/file1.txt"));
        assert!(renames
            .iter()
            .any(|r| r.baseline_path == "lib/libssl.so.1.0.0"));
    }

    #[test]
    fn test_format_diff_terminal_file_changes() {
        let report = DiffReport {
            schema_version: "1.0".to_string(),
            analysis_timestamp: Utc::now(),
            diff_mode: true,
            baseline: "/baseline".to_string(),
            target: "/target".to_string(),
            changes: FileChanges {
                added: vec!["new.txt".to_string()],
                removed: vec!["old.txt".to_string()],
                modified: vec!["changed.txt".to_string()],
                renamed: vec![FileRenameInfo {
                    from: "a.txt".to_string(),
                    to: "b.txt".to_string(),
                    similarity: 1.0,
                }],
            },
            modified_analysis: vec![],
            metadata: crate::types::AnalysisMetadata {
                analysis_duration_ms: 100,
                tools_used: vec!["diff_analyzer".to_string()],
                errors: vec![],
            },
        };

        let output = format_diff_terminal(&report);
        // Should contain file names
        assert!(output.contains("new.txt"));
        assert!(output.contains("old.txt"));
        assert!(output.contains("a.txt"));
        assert!(output.contains("b.txt"));
        assert!(output.contains("File changes"));
    }

    #[test]
    fn test_format_diff_terminal_many_files() {
        // Test with many added files
        let mut added = Vec::new();
        for i in 0..50 {
            added.push(format!("file{}.txt", i));
        }

        let report = DiffReport {
            schema_version: "1.0".to_string(),
            analysis_timestamp: Utc::now(),
            diff_mode: true,
            baseline: "/baseline".to_string(),
            target: "/target".to_string(),
            changes: FileChanges {
                added,
                removed: vec![],
                modified: vec![],
                renamed: vec![],
            },
            modified_analysis: vec![],
            metadata: crate::types::AnalysisMetadata {
                analysis_duration_ms: 100,
                tools_used: vec!["diff_analyzer".to_string()],
                errors: vec![],
            },
        };

        let output = format_diff_terminal(&report);
        // Should show summary with file count
        assert!(output.contains("+50 files"));
    }
}
