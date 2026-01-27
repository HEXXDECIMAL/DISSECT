//! Archive content analysis functions.
//!
//! This module contains the core analysis logic for different archive types:
//! - JAR/WAR/APK archives (Java bytecode optimized)
//! - Generic archives (all other formats)
//! - Individual extracted file analysis with timeout protection
//! - File type routing to appropriate analyzers
//!
//! # JAR Analysis Optimization
//!
//! JAR archives often contain thousands of .class files. Decompiling all of them
//! is prohibitively expensive, so we use a three-phase approach:
//! 1. YARA scan ALL classes in parallel (fast, just pattern matching)
//! 2. Full analysis on interesting classes (main class, YARA hits, samples)
//! 3. Analyze non-class files (scripts, configs, manifests)
//!
//! This balances thoroughness with performance.

use super::utils::{calculate_sha256, find_main_class, is_benign_java_path};
use super::ArchiveAnalyzer;
use crate::analyzers::{detect_file_type, Analyzer};
use crate::types::*;
use anyhow::Result;
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

const MAX_FILE_ANALYSIS_TIME_SECS: u64 = 10;

impl ArchiveAnalyzer {
    /// Analyze JAR-like archives (JAR, WAR, EAR, APK, AAR) with optimized class file handling.
    ///
    /// JAR analysis is optimized with a three-phase approach:
    /// 1. YARA scan ALL .class files in parallel (fast)
    /// 2. Full analysis on interesting classes (main class, YARA-flagged, sample)
    /// 3. Analyze non-class files (scripts, configs, manifests)
    ///
    /// This avoids full decompilation of thousands of benign library classes while
    /// ensuring suspicious classes are thoroughly analyzed.
    ///
    /// # Arguments
    /// * `temp_dir` - Extracted archive directory
    /// * `report` - Mutable report to aggregate findings into
    /// * `start` - Analysis start time for duration tracking
    pub(super) fn analyze_jar_archive(
        &self,
        temp_dir: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
    ) -> Result<()> {
        // Find main class from MANIFEST.MF
        let main_class = find_main_class(temp_dir);
        if let Some(ref mc) = main_class {
            eprintln!("  Main-Class: {}", mc);
        }

        // Collect all files
        let all_files: Vec<_> = walkdir::WalkDir::new(temp_dir)
            .min_depth(1)
            .max_depth(10)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .collect();

        // Separate class files from non-class files
        let (class_files, other_files): (Vec<_>, Vec<_>) = all_files
            .into_iter()
            .partition(|e| e.path().extension().is_some_and(|ext| ext == "class"));

        let total_class_files = class_files.len();
        eprintln!("  Found {} .class files", total_class_files);

        // Phase 1: Run YARA on ALL class files in parallel (fast)
        let yara_flagged_classes = Arc::new(Mutex::new(HashSet::new()));
        let yara_matches = Arc::new(Mutex::new(Vec::new()));

        if let Some(ref yara_engine) = self.yara_engine {
            let yara_start = std::time::Instant::now();
            class_files.par_iter().for_each(|entry| {
                if let Ok(matches) = yara_engine.scan_file(entry.path()) {
                    if !matches.is_empty() {
                        // This class triggered YARA rules - mark for full analysis
                        yara_flagged_classes
                            .lock()
                            .unwrap()
                            .insert(entry.path().to_path_buf());

                        // Record the YARA matches
                        let mut all_matches = yara_matches.lock().unwrap();
                        for yara_match in matches {
                            if !all_matches
                                .iter()
                                .any(|m: &YaraMatch| m.rule == yara_match.rule)
                            {
                                all_matches.push(yara_match);
                            }
                        }
                    }
                }
            });
            eprintln!(
                "  YARA scan completed in {:.2}s",
                yara_start.elapsed().as_secs_f64()
            );
        }

        let flagged_classes = Arc::try_unwrap(yara_flagged_classes)
            .expect("YARA scan should be done")
            .into_inner()
            .unwrap();
        let collected_yara_matches = Arc::try_unwrap(yara_matches)
            .expect("YARA scan should be done")
            .into_inner()
            .unwrap();

        // Add collected YARA matches to report
        for ym in collected_yara_matches {
            if !report.yara_matches.iter().any(|m| m.rule == ym.rule) {
                report.yara_matches.push(ym);
            }
        }

        eprintln!("  {} classes flagged by YARA", flagged_classes.len());

        // Phase 2: Run full JavaClassAnalyzer only on interesting classes
        // - Main class
        // - YARA-flagged classes
        // - Non-benign classes (limited sample)
        let interesting_classes: Vec<_> = class_files
            .iter()
            .filter(|e| {
                let path = e.path();
                let path_str = path.to_string_lossy();

                // Always analyze main class
                if let Some(ref mc) = main_class {
                    let class_path = mc.replace('.', "/") + ".class";
                    if path_str.ends_with(&class_path) {
                        return true;
                    }
                }

                // Always analyze YARA-flagged classes
                if flagged_classes.contains(path) {
                    return true;
                }

                // Skip benign library packages
                if is_benign_java_path(path) {
                    return false;
                }

                // For non-flagged, non-benign classes, just take a sample
                false
            })
            .collect();

        // Also include a small sample of non-benign, non-flagged classes
        let sample_classes: Vec<_> = class_files
            .iter()
            .filter(|e| !is_benign_java_path(e.path()) && !flagged_classes.contains(e.path()))
            .take(20) // Limit to 20 non-flagged classes
            .collect();

        let classes_to_analyze: Vec<_> = interesting_classes
            .into_iter()
            .chain(sample_classes)
            .collect();

        eprintln!("  Full analysis on {} classes", classes_to_analyze.len());

        // Run full analysis on selected classes
        let files_analyzed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let total_capabilities = Arc::new(Mutex::new(HashSet::new()));
        let total_traits = Arc::new(Mutex::new(HashSet::new()));
        let collected_traits = Arc::new(Mutex::new(Vec::<Finding>::new()));
        let collected_yara = Arc::new(Mutex::new(Vec::<YaraMatch>::new()));
        let collected_strings = Arc::new(Mutex::new(Vec::<StringInfo>::new()));
        let collected_archive_entries = Arc::new(Mutex::new(Vec::<ArchiveEntry>::new()));
        let collected_sub_reports = Arc::new(Mutex::new(Vec::<Box<AnalysisReport>>::new()));

        classes_to_analyze.par_iter().for_each(|entry| {
            let relative_path = entry
                .path()
                .strip_prefix(temp_dir)
                .unwrap_or(entry.path())
                .display()
                .to_string();
            let entry_path = self.format_entry_path(&relative_path);
            let archive_location = self.format_evidence_location(&relative_path);

            // Collect archive entry metadata
            if let Ok(file_data) = std::fs::read(entry.path()) {
                let entry_metadata = ArchiveEntry {
                    path: entry_path.clone(),
                    file_type: detect_file_type(entry.path())
                        .map(|ft| format!("{:?}", ft).to_lowercase())
                        .unwrap_or_else(|_| "unknown".to_string()),
                    sha256: calculate_sha256(&file_data),
                    size_bytes: file_data.len() as u64,
                };
                collected_archive_entries
                    .lock()
                    .unwrap()
                    .push(entry_metadata);
            }

            if let Ok(mut file_report) = self.analyze_extracted_file_with_timeout(entry.path()) {
                files_analyzed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let mut caps = total_capabilities.lock().unwrap();
                let mut traits = total_traits.lock().unwrap();
                let mut all_traits = collected_traits.lock().unwrap();
                let mut all_yara = collected_yara.lock().unwrap();
                let mut all_strings = collected_strings.lock().unwrap();
                let mut all_archive_entries = collected_archive_entries.lock().unwrap();
                let mut all_sub_reports = collected_sub_reports.lock().unwrap();

                // Aggregate findings
                for f in &file_report.findings {
                    traits.insert(f.id.clone());
                    caps.insert(f.id.clone());
                    if !all_traits.iter().any(|existing| existing.id == f.id) {
                        let mut new_finding = f.clone();
                        for evidence in &mut new_finding.evidence {
                            // Prefix location with archive path
                            // - If no location: set to archive path
                            // - If location starts with "archive:": already from nested, leave it
                            // - Otherwise: prefix with archive path (e.g., "line:3" -> "archive:file.sh:line:3")
                            match &evidence.location {
                                None => {
                                    evidence.location = Some(archive_location.clone());
                                }
                                Some(loc) if !loc.starts_with("archive:") => {
                                    evidence.location =
                                        Some(format!("{}:{}", archive_location, loc));
                                }
                                _ => {} // Already has archive: prefix from nested analysis
                            }
                        }
                        all_traits.push(new_finding);
                    }
                }

                // Aggregate YARA matches
                for yara_match in &file_report.yara_matches {
                    if !all_yara.iter().any(|m| m.rule == yara_match.rule) {
                        all_yara.push(yara_match.clone());
                    }
                }

                // Aggregate interesting strings
                for string in &file_report.strings {
                    if matches!(
                        string.string_type,
                        StringType::Url | StringType::Ip | StringType::Base64
                    ) {
                        all_strings.push(string.clone());
                    }
                }

                // Merge archive_contents from nested archives
                for nested_entry in &file_report.archive_contents {
                    all_archive_entries.push(nested_entry.clone());
                }

                // Store full report for per-file ML classification
                // Update the target path to show it's from within the archive
                // Use std::mem::take to extract sub_reports before moving file_report
                let nested_sub_reports = std::mem::take(&mut file_report.sub_reports);
                let mut sub_report = file_report;

                // Merge sub_reports from nested archives
                for nested_sub in nested_sub_reports {
                    all_sub_reports.push(nested_sub);
                }
                sub_report.target.path = entry_path.clone();
                all_sub_reports.push(Box::new(sub_report));
            }
        });

        // Phase 3: Analyze non-class files (scripts, configs, etc.)
        let non_class_files: Vec<_> = other_files
            .into_iter()
            .filter(|e| !is_benign_java_path(e.path()))
            .filter(|e| {
                // Only analyze potentially interesting files
                let path_str = e.path().to_string_lossy().to_lowercase();
                !path_str.contains("meta-inf/")
                    || path_str.ends_with("manifest.mf")
                    || path_str.ends_with(".xml")
            })
            .take(100)
            .collect();

        non_class_files.par_iter().for_each(|entry| {
            let relative_path = entry
                .path()
                .strip_prefix(temp_dir)
                .unwrap_or(entry.path())
                .display()
                .to_string();
            let entry_path = self.format_entry_path(&relative_path);
            let archive_location = self.format_evidence_location(&relative_path);

            // Collect archive entry metadata
            if let Ok(file_data) = std::fs::read(entry.path()) {
                let entry_metadata = ArchiveEntry {
                    path: entry_path.clone(),
                    file_type: detect_file_type(entry.path())
                        .map(|ft| format!("{:?}", ft).to_lowercase())
                        .unwrap_or_else(|_| "unknown".to_string()),
                    sha256: calculate_sha256(&file_data),
                    size_bytes: file_data.len() as u64,
                };
                collected_archive_entries
                    .lock()
                    .unwrap()
                    .push(entry_metadata);
            }

            // Run YARA on non-class files
            if let Some(ref yara_engine) = self.yara_engine {
                if let Ok(matches) = yara_engine.scan_file(entry.path()) {
                    let mut all_yara = collected_yara.lock().unwrap();
                    for yara_match in matches {
                        if !all_yara.iter().any(|m| m.rule == yara_match.rule) {
                            all_yara.push(yara_match);
                        }
                    }
                }
            }

            // Run file-type-specific analysis
            if let Ok(mut file_report) = self.analyze_extracted_file_with_timeout(entry.path()) {
                files_analyzed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let mut caps = total_capabilities.lock().unwrap();
                let mut traits = total_traits.lock().unwrap();
                let mut all_traits = collected_traits.lock().unwrap();
                let mut all_yara = collected_yara.lock().unwrap();
                let mut all_strings = collected_strings.lock().unwrap();
                let mut all_archive_entries = collected_archive_entries.lock().unwrap();
                let mut all_sub_reports = collected_sub_reports.lock().unwrap();

                // Aggregate findings
                for f in &file_report.findings {
                    traits.insert(f.id.clone());
                    caps.insert(f.id.clone());
                    if !all_traits.iter().any(|existing| existing.id == f.id) {
                        let mut new_finding = f.clone();
                        for evidence in &mut new_finding.evidence {
                            // Prefix location with archive path
                            match &evidence.location {
                                None => {
                                    evidence.location = Some(archive_location.clone());
                                }
                                Some(loc) if !loc.starts_with("archive:") => {
                                    evidence.location =
                                        Some(format!("{}:{}", archive_location, loc));
                                }
                                _ => {} // Already has archive: prefix from nested analysis
                            }
                        }
                        all_traits.push(new_finding);
                    }
                }

                // Aggregate YARA matches
                for yara_match in &file_report.yara_matches {
                    if !all_yara.iter().any(|m| m.rule == yara_match.rule) {
                        all_yara.push(yara_match.clone());
                    }
                }

                // Aggregate interesting strings
                for string in &file_report.strings {
                    if matches!(
                        string.string_type,
                        StringType::Url | StringType::Ip | StringType::Base64
                    ) {
                        all_strings.push(string.clone());
                    }
                }

                // Merge archive_contents from nested archives
                for nested_entry in &file_report.archive_contents {
                    all_archive_entries.push(nested_entry.clone());
                }

                // Store full report for per-file ML classification
                let nested_sub_reports = std::mem::take(&mut file_report.sub_reports);
                let mut sub_report = file_report;
                sub_report.target.path = entry_path.clone();

                // Merge sub_reports from nested archives
                for nested_sub in nested_sub_reports {
                    all_sub_reports.push(nested_sub);
                }

                all_sub_reports.push(Box::new(sub_report));
            }
        });

        // Merge collected results into the report
        let total_capabilities = Arc::try_unwrap(total_capabilities)
            .expect("All parallel tasks should be done")
            .into_inner()
            .unwrap();
        let total_traits = Arc::try_unwrap(total_traits)
            .expect("All parallel tasks should be done")
            .into_inner()
            .unwrap();
        let files_analyzed = files_analyzed.load(std::sync::atomic::Ordering::Relaxed);

        for t in Arc::try_unwrap(collected_traits)
            .expect("done")
            .into_inner()
            .unwrap()
        {
            if !report.findings.iter().any(|existing| existing.id == t.id) {
                report.findings.push(t);
            }
        }
        for ym in Arc::try_unwrap(collected_yara)
            .expect("done")
            .into_inner()
            .unwrap()
        {
            if !report.yara_matches.iter().any(|m| m.rule == ym.rule) {
                report.yara_matches.push(ym);
            }
        }
        report.strings.extend(
            Arc::try_unwrap(collected_strings)
                .expect("done")
                .into_inner()
                .unwrap(),
        );
        report.archive_contents.extend(
            Arc::try_unwrap(collected_archive_entries)
                .expect("done")
                .into_inner()
                .unwrap(),
        );
        report.sub_reports.extend(
            Arc::try_unwrap(collected_sub_reports)
                .expect("done")
                .into_inner()
                .unwrap(),
        );

        // Add metadata about archive contents
        report.metadata.errors.push(format!(
            "JAR archive: {} total classes, {} YARA-flagged, {} fully analyzed, {} traits and {} capabilities detected",
            total_class_files,
            flagged_classes.len(),
            files_analyzed,
            total_traits.len(),
            total_capabilities.len()
        ));

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec![
            "archive_analyzer".to_string(),
            "yara".to_string(),
            "java_class_analyzer".to_string(),
        ];

        Ok(())
    }

    /// Analyze generic archives (non-JAR formats).
    ///
    /// Performs comprehensive analysis of all extracted files including:
    /// - YARA scanning for known malicious patterns
    /// - File-type-specific analysis (scripts, binaries, configs)
    /// - Archive entry metadata collection
    /// - Nested archive handling
    ///
    /// Files are analyzed in parallel for performance, with progress tracking
    /// for large archives.
    ///
    /// # Arguments
    /// * `temp_dir` - Extracted archive directory
    /// * `report` - Mutable report to aggregate findings into
    /// * `start` - Analysis start time for duration tracking
    pub(super) fn analyze_generic_archive(
        &self,
        temp_dir: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
    ) -> Result<()> {
        use tracing::{debug, trace};

        debug!(
            "Analyzing generic archive, scanning temp dir: {:?}",
            temp_dir
        );

        // Collect all files to analyze
        let all_entries: Vec<_> = walkdir::WalkDir::new(temp_dir)
            .min_depth(1)
            .max_depth(10)
            .into_iter()
            .filter_map(|e| e.ok())
            .collect();

        trace!("Found {} total entries in archive", all_entries.len());

        let files: Vec<_> = all_entries
            .into_iter()
            .filter(|e| {
                let is_file = e.file_type().is_file();
                if !is_file {
                    trace!("Skipping directory: {:?}", e.path());
                }
                is_file
            })
            .take(500)
            .collect();

        let total_files = files.len();
        debug!("Found {} files to analyze", total_files);
        eprintln!("  Analyzing {} files", total_files);

        // Create thread-safe containers for aggregated results
        let files_processed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let files_analyzed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let total_capabilities = Arc::new(Mutex::new(HashSet::new()));
        let total_traits = Arc::new(Mutex::new(HashSet::new()));
        let collected_traits = Arc::new(Mutex::new(Vec::<Finding>::new()));
        let collected_yara = Arc::new(Mutex::new(Vec::<YaraMatch>::new()));
        let collected_strings = Arc::new(Mutex::new(Vec::<StringInfo>::new()));
        let collected_archive_entries = Arc::new(Mutex::new(Vec::<ArchiveEntry>::new()));
        let collected_sub_reports = Arc::new(Mutex::new(Vec::<Box<AnalysisReport>>::new()));
        let last_progress = Arc::new(Mutex::new(std::time::Instant::now()));

        // Analyze files in parallel
        files.par_iter().for_each(|entry| {
            // Track progress
            let processed = files_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if let Ok(mut last) = last_progress.try_lock() {
                if last.elapsed() > std::time::Duration::from_secs(1) {
                    let analyzed = files_analyzed.load(std::sync::atomic::Ordering::Relaxed);
                    eprintln!(
                        "  Progress: {}/{} files processed, {} analyzed",
                        processed, total_files, analyzed
                    );
                    *last = std::time::Instant::now();
                }
            }

            let relative_path = entry
                .path()
                .strip_prefix(temp_dir)
                .unwrap_or(entry.path())
                .display()
                .to_string();
            let entry_path = self.format_entry_path(&relative_path);
            let archive_location = self.format_evidence_location(&relative_path);

            // Collect archive entry metadata
            if let Ok(file_data) = std::fs::read(entry.path()) {
                let entry_metadata = ArchiveEntry {
                    path: entry_path.clone(),
                    file_type: detect_file_type(entry.path())
                        .map(|ft| format!("{:?}", ft).to_lowercase())
                        .unwrap_or_else(|_| "unknown".to_string()),
                    sha256: calculate_sha256(&file_data),
                    size_bytes: file_data.len() as u64,
                };
                collected_archive_entries
                    .lock()
                    .unwrap()
                    .push(entry_metadata);
            }

            // Run YARA scan on extracted file if engine is available
            if let Some(ref yara_engine) = self.yara_engine {
                if let Ok(matches) = yara_engine.scan_file(entry.path()) {
                    let mut all_yara = collected_yara.lock().unwrap();
                    for yara_match in matches {
                        if !all_yara.iter().any(|m| m.rule == yara_match.rule) {
                            all_yara.push(yara_match);
                        }
                    }
                }
            }

            if let Ok(mut file_report) = self.analyze_extracted_file_with_timeout(entry.path()) {
                files_analyzed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let mut caps = total_capabilities.lock().unwrap();
                let mut traits = total_traits.lock().unwrap();
                let mut all_traits = collected_traits.lock().unwrap();
                let mut all_yara = collected_yara.lock().unwrap();
                let mut all_strings = collected_strings.lock().unwrap();
                let mut all_archive_entries = collected_archive_entries.lock().unwrap();
                let mut all_sub_reports = collected_sub_reports.lock().unwrap();

                // Aggregate findings
                for f in &file_report.findings {
                    traits.insert(f.id.clone());
                    caps.insert(f.id.clone());
                    if !all_traits.iter().any(|existing| existing.id == f.id) {
                        let mut new_finding = f.clone();
                        for evidence in &mut new_finding.evidence {
                            // Prefix location with archive path
                            match &evidence.location {
                                None => {
                                    evidence.location = Some(archive_location.clone());
                                }
                                Some(loc) if !loc.starts_with("archive:") => {
                                    evidence.location =
                                        Some(format!("{}:{}", archive_location, loc));
                                }
                                _ => {} // Already has archive: prefix from nested analysis
                            }
                        }
                        all_traits.push(new_finding);
                    }
                }

                // Aggregate YARA matches
                for yara_match in &file_report.yara_matches {
                    if !all_yara.iter().any(|m| m.rule == yara_match.rule) {
                        all_yara.push(yara_match.clone());
                    }
                }

                // Aggregate interesting strings
                for string in &file_report.strings {
                    if matches!(
                        string.string_type,
                        StringType::Url | StringType::Ip | StringType::Base64
                    ) {
                        all_strings.push(string.clone());
                    }
                }

                // Merge archive_contents from nested archives
                for nested_entry in &file_report.archive_contents {
                    all_archive_entries.push(nested_entry.clone());
                }

                // Store full report for per-file ML classification
                let nested_sub_reports = std::mem::take(&mut file_report.sub_reports);
                let mut sub_report = file_report;
                sub_report.target.path = entry_path.clone();

                // Merge sub_reports from nested archives
                for nested_sub in nested_sub_reports {
                    all_sub_reports.push(nested_sub);
                }

                all_sub_reports.push(Box::new(sub_report));
            }
        });

        // Merge collected results into the report
        let total_capabilities = Arc::try_unwrap(total_capabilities)
            .expect("All parallel tasks should be done")
            .into_inner()
            .unwrap();
        let total_traits = Arc::try_unwrap(total_traits)
            .expect("All parallel tasks should be done")
            .into_inner()
            .unwrap();
        let files_analyzed = files_analyzed.load(std::sync::atomic::Ordering::Relaxed);

        for t in Arc::try_unwrap(collected_traits)
            .expect("done")
            .into_inner()
            .unwrap()
        {
            if !report.findings.iter().any(|existing| existing.id == t.id) {
                report.findings.push(t);
            }
        }
        for ym in Arc::try_unwrap(collected_yara)
            .expect("done")
            .into_inner()
            .unwrap()
        {
            if !report.yara_matches.iter().any(|m| m.rule == ym.rule) {
                report.yara_matches.push(ym);
            }
        }
        report.strings.extend(
            Arc::try_unwrap(collected_strings)
                .expect("done")
                .into_inner()
                .unwrap(),
        );
        report.archive_contents.extend(
            Arc::try_unwrap(collected_archive_entries)
                .expect("done")
                .into_inner()
                .unwrap(),
        );
        report.sub_reports.extend(
            Arc::try_unwrap(collected_sub_reports)
                .expect("done")
                .into_inner()
                .unwrap(),
        );

        // Add metadata about archive contents
        report.metadata.errors.push(format!(
            "Archive contains {} files analyzed, {} traits and {} capabilities detected",
            files_analyzed,
            total_traits.len(),
            total_capabilities.len()
        ));

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["archive_analyzer".to_string(), "walkdir".to_string()];

        Ok(())
    }

    /// Analyze an extracted file with a timeout to prevent analysis hangs.
    ///
    /// Some files (especially obfuscated or malformed ones) can cause analysis
    /// to hang indefinitely. This wrapper spawns analysis in a thread with a
    /// 10-second timeout. If timeout occurs, returns a report with a timeout
    /// finding instead of hanging forever.
    ///
    /// # Arguments
    /// * `file_path` - Path to the extracted file
    ///
    /// # Returns
    /// * `Ok(AnalysisReport)` - Normal analysis or timeout report
    /// * `Err` - Only if thread crashes (not timeout)
    pub(super) fn analyze_extracted_file_with_timeout(&self, file_path: &Path) -> Result<AnalysisReport> {
        use std::sync::mpsc;
        use std::time::Duration;

        let timeout = Duration::from_secs(MAX_FILE_ANALYSIS_TIME_SECS);
        let file_path_clone = file_path.to_path_buf();

        // Clone self for thread (we need to move capability_mapper and yara_engine)
        let capability_mapper = self.capability_mapper.clone();
        let yara_engine = self.yara_engine.clone();
        let zip_passwords = self.zip_passwords.clone();
        let current_depth = self.current_depth;
        let max_depth = self.max_depth;
        let archive_path_prefix = self.archive_path_prefix.clone();

        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            // Recreate analyzer in thread
            let analyzer = ArchiveAnalyzer {
                max_depth,
                current_depth,
                archive_path_prefix,
                capability_mapper,
                yara_engine,
                zip_passwords,
            };

            let result = analyzer.analyze_extracted_file(&file_path_clone);
            let _ = tx.send(result);
        });

        match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Analysis timed out - create a report with timeout finding
                let file_data = fs::read(file_path).unwrap_or_default();
                let target = TargetInfo {
                    path: file_path.display().to_string(),
                    file_type: detect_file_type(file_path)
                        .map(|ft| format!("{:?}", ft).to_lowercase())
                        .unwrap_or_else(|_| "unknown".to_string()),
                    size_bytes: file_data.len() as u64,
                    sha256: calculate_sha256(&file_data),
                    architectures: None,
                };

                let mut report = AnalysisReport::new(target);
                report.findings.push(Finding {
                    kind: FindingKind::Indicator,
                    trait_refs: vec![],
                    id: "anti-analysis/timeout/analysis-timeout".to_string(),
                    desc: format!(
                        "File analysis exceeded {}s timeout (possible anti-analysis)",
                        MAX_FILE_ANALYSIS_TIME_SECS
                    ),
                    conf: 0.8,
                    crit: Criticality::Suspicious,
                    mbc: Some("B0001".to_string()),
                    attack: None,
                    evidence: vec![Evidence {
                        method: "timeout".to_string(),
                        source: "archive_analyzer".to_string(),
                        value: format!("timeout:{}s", MAX_FILE_ANALYSIS_TIME_SECS),
                        location: Some(file_path.display().to_string()),
                    }],
                });

                Ok(report)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(anyhow::anyhow!("Analysis thread crashed"))
            }
        }
    }

    /// Route an extracted file to the appropriate analyzer based on file type.
    ///
    /// Detects the file type and delegates to specialized analyzers:
    /// - MachO, ELF, PE: Binary analyzers
    /// - Shell, Python, JavaScript, etc.: Script analyzers
    /// - JavaClass: Bytecode analyzer
    /// - Archive: Recursive archive analysis (with depth limit)
    ///
    /// Passes along capability mapper and YARA engine to child analyzers.
    ///
    /// # Arguments
    /// * `file_path` - Path to the extracted file
    ///
    /// # Returns
    /// * `Ok(AnalysisReport)` - Analysis report from appropriate analyzer
    /// * `Err` - If file type unsupported or analysis fails
    pub(super) fn analyze_extracted_file(&self, file_path: &Path) -> Result<AnalysisReport> {
        // Detect file type
        let file_type = detect_file_type(file_path)?;

        // Route to appropriate analyzer with capability mapper if available
        match file_type {
            crate::analyzers::FileType::MachO => {
                let mut analyzer = crate::analyzers::macho::MachOAnalyzer::new();
                if let Some(ref mapper) = self.capability_mapper {
                    analyzer = analyzer.with_capability_mapper(mapper.clone());
                }
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::Elf => {
                let mut analyzer = crate::analyzers::elf::ElfAnalyzer::new();
                if let Some(ref mapper) = self.capability_mapper {
                    analyzer = analyzer.with_capability_mapper(mapper.clone());
                }
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::Pe => {
                let mut analyzer = crate::analyzers::pe::PEAnalyzer::new();
                if let Some(ref mapper) = self.capability_mapper {
                    analyzer = analyzer.with_capability_mapper(mapper.clone());
                }
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::Shell => {
                let mut analyzer = crate::analyzers::shell::ShellAnalyzer::new();
                if let Some(ref mapper) = self.capability_mapper {
                    analyzer = analyzer.with_capability_mapper(mapper.clone());
                }
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::Python => {
                let mut analyzer = crate::analyzers::python::PythonAnalyzer::new();
                if let Some(ref mapper) = self.capability_mapper {
                    analyzer = analyzer.with_capability_mapper(mapper.clone());
                }
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::JavaScript => {
                let mut analyzer = crate::analyzers::javascript::JavaScriptAnalyzer::new();
                if let Some(ref mapper) = self.capability_mapper {
                    analyzer = analyzer.with_capability_mapper(mapper.clone());
                }
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::JavaClass => {
                let mut analyzer = crate::analyzers::java_class::JavaClassAnalyzer::new();
                if let Some(ref mapper) = self.capability_mapper {
                    analyzer = analyzer.with_capability_mapper(mapper.clone());
                }
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::Java => {
                let analyzer = crate::analyzers::java::JavaAnalyzer::new();
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::Ruby => {
                let analyzer = crate::analyzers::ruby::RubyAnalyzer::new();
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::VsixManifest => {
                let mut analyzer = crate::analyzers::vsix_manifest::VsixManifestAnalyzer::new();
                if let Some(ref mapper) = self.capability_mapper {
                    analyzer = analyzer.with_capability_mapper(mapper.clone());
                }
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::Archive => {
                // Recursively analyze nested archives
                if self.current_depth + 1 >= self.max_depth {
                    return Err(anyhow::anyhow!(
                        "Nested archive at max depth ({})",
                        self.max_depth
                    ));
                }

                // Build the prefix for nested paths
                let file_name = file_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("nested");
                let nested_prefix = match &self.archive_path_prefix {
                    Some(prefix) => format!("{}!{}", prefix, file_name),
                    None => file_name.to_string(),
                };

                // Create nested analyzer with incremented depth and path prefix
                let mut nested = ArchiveAnalyzer::new()
                    .with_depth(self.current_depth + 1)
                    .with_archive_prefix(nested_prefix);

                // Propagate configuration
                if let Some(ref mapper) = self.capability_mapper {
                    nested = nested.with_capability_mapper(mapper.clone());
                }
                if let Some(ref engine) = self.yara_engine {
                    nested = nested.with_yara_arc(engine.clone());
                }
                if !self.zip_passwords.is_empty() {
                    nested = nested.with_zip_passwords(self.zip_passwords.clone());
                }

                nested.analyze(file_path)
            }
            _ => {
                // Skip unknown files
                Err(anyhow::anyhow!("Unsupported file type"))
            }
        }
    }
}
