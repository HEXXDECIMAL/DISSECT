use crate::analyzers::{detect_file_type, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Cursor, Read, Seek};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// =============================================================================
// Archive Bomb Protection Constants
// =============================================================================

/// Maximum size of a single decompressed file (100 MB)
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Maximum total extraction size (1 GB)
const MAX_TOTAL_SIZE: u64 = 1024 * 1024 * 1024;

/// Maximum number of files to extract
const MAX_FILE_COUNT: usize = 10_000;

/// Maximum compression ratio before considering it suspicious (100:1)
const MAX_COMPRESSION_RATIO: u64 = 100;

/// Reasons an archive may be considered hostile
#[derive(Debug, Clone)]
pub enum HostileArchiveReason {
    PathTraversal(String),
    ZipBomb { compressed: u64, uncompressed: u64 },
    ExcessiveFileCount(usize),
    ExcessiveTotalSize(u64),
    ExcessiveFileSize { file: String, size: u64 },
    SymlinkEscape(String),
    MalformedEntry(String),
    ExtractionError(String),
}

/// Archive analyzer for .zip, .tar.gz, .tgz, language-specific packages (.egg, .whl, .gem, .phar, .nupkg, .crate),
/// application packages (.vsix, .xpi, .crx, .ipa, .epub, .7z), and system packages (.pkg, .deb, .rpm)
pub struct ArchiveAnalyzer {
    max_depth: usize,
    current_depth: usize,
    /// Path prefix for nested archives (e.g., "inner.tar.gz" becomes "outer.zip!inner.tar.gz")
    archive_path_prefix: Option<String>,
    capability_mapper: Option<CapabilityMapper>,
    yara_engine: Option<Arc<YaraEngine>>,
    /// Passwords to try for encrypted zip files
    zip_passwords: Vec<String>,
}

/// Tracks extraction limits and detects hostile patterns
struct ExtractionGuard {
    total_bytes: AtomicU64,
    file_count: AtomicUsize,
    hostile_reasons: Mutex<Vec<HostileArchiveReason>>,
}

impl ExtractionGuard {
    fn new() -> Self {
        Self {
            total_bytes: AtomicU64::new(0),
            file_count: AtomicUsize::new(0),
            hostile_reasons: Mutex::new(Vec::new()),
        }
    }

    fn add_hostile_reason(&self, reason: HostileArchiveReason) {
        if let Ok(mut reasons) = self.hostile_reasons.lock() {
            reasons.push(reason);
        }
    }

    fn take_reasons(&self) -> Vec<HostileArchiveReason> {
        self.hostile_reasons
            .lock()
            .map(|mut r| std::mem::take(&mut *r))
            .unwrap_or_default()
    }

    /// Check if we can extract another file, returns false if limits exceeded
    fn check_file_count(&self) -> bool {
        let count = self.file_count.fetch_add(1, Ordering::Relaxed) + 1;
        if count > MAX_FILE_COUNT {
            self.add_hostile_reason(HostileArchiveReason::ExcessiveFileCount(count));
            return false;
        }
        true
    }

    /// Check and track bytes, returns false if limits exceeded
    fn check_bytes(&self, bytes: u64, file_name: &str) -> bool {
        // Check single file size
        if bytes > MAX_FILE_SIZE {
            self.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                file: file_name.to_string(),
                size: bytes,
            });
            return false;
        }

        // Check total size
        let total = self.total_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if total > MAX_TOTAL_SIZE {
            self.add_hostile_reason(HostileArchiveReason::ExcessiveTotalSize(total));
            return false;
        }
        true
    }

    /// Check compression ratio for zip bomb detection
    fn check_compression_ratio(&self, compressed: u64, uncompressed: u64) -> bool {
        if compressed > 0 && uncompressed / compressed > MAX_COMPRESSION_RATIO {
            self.add_hostile_reason(HostileArchiveReason::ZipBomb {
                compressed,
                uncompressed,
            });
            return false;
        }
        true
    }
}

/// Sanitize archive entry path to prevent path traversal attacks (zip slip)
fn sanitize_entry_path(entry_name: &str, dest_dir: &Path) -> Option<PathBuf> {
    let path = Path::new(entry_name);

    // Reject absolute paths
    if path.is_absolute() {
        return None;
    }

    // Build path component by component, rejecting dangerous ones
    let mut result = dest_dir.to_path_buf();
    for component in path.components() {
        match component {
            Component::Normal(c) => result.push(c),
            Component::CurDir => {} // Skip "."
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                // Reject "..", drive prefixes, and root
                return None;
            }
        }
    }

    // Final check: ensure result is still under dest_dir
    if !result.starts_with(dest_dir) {
        return None;
    }

    Some(result)
}

/// Size-limited reader that stops after a maximum number of bytes
struct LimitedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R: Read> LimitedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::other("size limit exceeded"));
        }
        let max_read = buf.len().min(self.remaining as usize);
        let n = self.inner.read(&mut buf[..max_read])?;
        self.remaining = self.remaining.saturating_sub(n as u64);
        Ok(n)
    }
}

impl ArchiveAnalyzer {
    pub fn new() -> Self {
        Self {
            max_depth: 3,
            current_depth: 0,
            archive_path_prefix: None,
            capability_mapper: None,
            yara_engine: None,
            zip_passwords: Vec::new(),
        }
    }

    pub fn with_depth(mut self, depth: usize) -> Self {
        self.current_depth = depth;
        self
    }

    /// Set the path prefix for nested archive paths (used for recursion)
    pub fn with_archive_prefix(mut self, prefix: String) -> Self {
        self.archive_path_prefix = Some(prefix);
        self
    }

    pub fn with_capability_mapper(mut self, mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Some(mapper);
        self
    }

    pub fn with_yara(mut self, engine: YaraEngine) -> Self {
        self.yara_engine = Some(Arc::new(engine));
        self
    }

    /// Set YARA engine from an existing Arc (for nested analyzers)
    pub fn with_yara_arc(mut self, engine: Arc<YaraEngine>) -> Self {
        self.yara_engine = Some(engine);
        self
    }

    /// Set passwords to try for encrypted zip files
    pub fn with_zip_passwords(mut self, passwords: Vec<String>) -> Self {
        self.zip_passwords = passwords;
        self
    }

    /// Format a relative path with nesting prefix (for ArchiveEntry.path)
    /// - Single level: "lib/foo.so"
    /// - Nested: "inner.tar.gz!lib/foo.so"
    fn format_entry_path(&self, relative_path: &str) -> String {
        match &self.archive_path_prefix {
            Some(prefix) => format!("{}!{}", prefix, relative_path),
            None => relative_path.to_string(),
        }
    }

    /// Format a location for Evidence.location (includes archive: prefix)
    /// - Single level: "archive:lib/foo.so"
    /// - Nested: "archive:inner.tar.gz!lib/foo.so"
    fn format_evidence_location(&self, relative_path: &str) -> String {
        match &self.archive_path_prefix {
            Some(prefix) => format!("archive:{}!{}", prefix, relative_path),
            None => format!("archive:{}", relative_path),
        }
    }

    fn analyze_archive(&self, file_path: &Path) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Prevent infinite recursion
        if self.current_depth >= self.max_depth {
            anyhow::bail!("Maximum archive depth ({}) exceeded", self.max_depth);
        }

        // Create temporary directory for extraction
        let temp_dir = tempfile::tempdir().context("Failed to create temporary directory")?;

        // Create extraction guard to track limits and detect hostile patterns
        let guard = ExtractionGuard::new();

        // Extract archive with protection
        // For complete failures (wrong password, corrupt archive), propagate the error
        // For partial failures (some hostile files skipped), emit findings but continue
        let extraction_result = self.extract_archive_safe(file_path, temp_dir.path(), &guard);

        // Check if any files were extracted - if zero files and error, propagate error
        let hostile_reasons = guard.take_reasons();
        let _has_hostile_patterns = !hostile_reasons.is_empty();

        // If extraction completely failed (no files extracted), return the error
        // This handles cases like wrong password, corrupt archive, etc.
        if let Err(e) = extraction_result {
            // Check if we at least extracted some files (partial success)
            let extracted_count = walkdir::WalkDir::new(temp_dir.path())
                .min_depth(1)
                .into_iter()
                .filter_map(|e| e.ok())
                .count();

            if extracted_count == 0 {
                // Complete failure - return the error
                return Err(e);
            }
            // Partial failure - continue with what we extracted but record the error
        }

        // Create target info
        let file_data = fs::read(file_path)?;
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: self.detect_archive_type(file_path).to_string(),
            size_bytes: file_data.len() as u64,
            sha256: self.calculate_sha256(&file_data),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Emit findings for any hostile archive behaviors
        for reason in hostile_reasons {
            let (id, desc, evidence_value) = match &reason {
                HostileArchiveReason::PathTraversal(path) => (
                    "anti-analysis/archive/path-traversal",
                    "Archive contains path traversal attempt (zip slip)",
                    format!("path:{}", path),
                ),
                HostileArchiveReason::ZipBomb {
                    compressed,
                    uncompressed,
                } => (
                    "anti-analysis/archive/zip-bomb",
                    "Archive has suspicious compression ratio (potential zip bomb)",
                    format!(
                        "ratio:{}:1 ({}B -> {}B)",
                        uncompressed / (*compressed).max(1),
                        compressed,
                        uncompressed
                    ),
                ),
                HostileArchiveReason::ExcessiveFileCount(count) => (
                    "anti-analysis/archive/excessive-files",
                    "Archive contains excessive number of files",
                    format!("count:{} (limit:{})", count, MAX_FILE_COUNT),
                ),
                HostileArchiveReason::ExcessiveTotalSize(size) => (
                    "anti-analysis/archive/excessive-size",
                    "Archive expands to excessive total size",
                    format!("size:{} bytes (limit:{})", size, MAX_TOTAL_SIZE),
                ),
                HostileArchiveReason::ExcessiveFileSize { file, size } => (
                    "anti-analysis/archive/large-file",
                    "Archive contains excessively large file",
                    format!("file:{} size:{} (limit:{})", file, size, MAX_FILE_SIZE),
                ),
                HostileArchiveReason::SymlinkEscape(path) => (
                    "anti-analysis/archive/symlink-escape",
                    "Archive contains symlink that may escape extraction directory",
                    format!("symlink:{}", path),
                ),
                HostileArchiveReason::MalformedEntry(msg) => (
                    "anti-analysis/archive/malformed",
                    "Archive contains malformed entry",
                    msg.clone(),
                ),
                HostileArchiveReason::ExtractionError(msg) => (
                    "anti-analysis/archive/extraction-failed",
                    "Archive extraction failed (potentially malformed or hostile)",
                    msg.clone(),
                ),
            };

            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: id.to_string(),
                desc: desc.to_string(),
                conf: 0.9,
                crit: Criticality::Suspicious,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "archive_extraction".to_string(),
                    source: "archive_analyzer".to_string(),
                    value: evidence_value,
                    location: None,
                }],
            });
        }

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: format!("archive/{}", self.detect_archive_type(file_path)),
            desc: format!("{} archive", self.detect_archive_type(file_path)),
            evidence: vec![Evidence {
                method: "extension".to_string(),
                source: "archive_analyzer".to_string(),
                value: file_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
                location: None,
            }],
        });

        // Check if this is a JAR-like archive
        let is_jar = file_path.to_string_lossy().to_lowercase().ends_with(".jar")
            || file_path.to_string_lossy().to_lowercase().ends_with(".war")
            || file_path.to_string_lossy().to_lowercase().ends_with(".ear")
            || file_path.to_string_lossy().to_lowercase().ends_with(".apk")
            || file_path.to_string_lossy().to_lowercase().ends_with(".aar");

        if is_jar {
            self.analyze_jar_archive(temp_dir.path(), &mut report, start)?;
        } else {
            self.analyze_generic_archive(temp_dir.path(), &mut report, start)?;
        }

        Ok(report)
    }

    /// Analyze a JAR-like archive using YARA-first approach
    /// Only runs full Java bytecode parser on main class and YARA-flagged classes
    fn analyze_jar_archive(
        &self,
        temp_dir: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
    ) -> Result<()> {
        // Find main class from MANIFEST.MF
        let main_class = self.find_main_class(temp_dir);
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
                if Self::is_benign_java_path(path) {
                    return false;
                }

                // For non-flagged, non-benign classes, just take a sample
                false
            })
            .collect();

        // Also include a small sample of non-benign, non-flagged classes
        let sample_classes: Vec<_> = class_files
            .iter()
            .filter(|e| !Self::is_benign_java_path(e.path()) && !flagged_classes.contains(e.path()))
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
                    sha256: self.calculate_sha256(&file_data),
                    size_bytes: file_data.len() as u64,
                };
                collected_archive_entries
                    .lock()
                    .unwrap()
                    .push(entry_metadata);
            }

            if let Ok(mut file_report) = self.analyze_extracted_file(entry.path()) {
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
            .filter(|e| !Self::is_benign_java_path(e.path()))
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
                    sha256: self.calculate_sha256(&file_data),
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
            if let Ok(mut file_report) = self.analyze_extracted_file(entry.path()) {
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

    /// Analyze a generic (non-JAR) archive
    fn analyze_generic_archive(
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
                    sha256: self.calculate_sha256(&file_data),
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

            if let Ok(mut file_report) = self.analyze_extracted_file(entry.path()) {
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

    /// Extract main class from META-INF/MANIFEST.MF
    fn find_main_class(&self, temp_dir: &Path) -> Option<String> {
        let manifest_path = temp_dir.join("META-INF/MANIFEST.MF");
        if !manifest_path.exists() {
            return None;
        }

        let file = File::open(&manifest_path).ok()?;
        let reader = BufReader::new(file);

        for line in reader.lines().map_while(Result::ok) {
            if line.starts_with("Main-Class:") {
                return Some(line.trim_start_matches("Main-Class:").trim().to_string());
            }
        }
        None
    }

    /// Safe archive extraction with bomb protection
    fn extract_archive_safe(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        guard: &ExtractionGuard,
    ) -> Result<()> {
        let archive_type = self.detect_archive_type(archive_path);

        match archive_type {
            "zip" => self.extract_zip_safe(archive_path, dest_dir, guard),
            "crx" => self.extract_crx_safe(archive_path, dest_dir, guard),
            "7z" => self.extract_7z_safe(archive_path, dest_dir, guard),
            "tar" => self.extract_tar_safe(archive_path, dest_dir, None, guard),
            "tar.gz" | "tgz" => self.extract_tar_safe(archive_path, dest_dir, Some("gzip"), guard),
            "tar.bz2" | "tbz" | "tbz2" => {
                self.extract_tar_safe(archive_path, dest_dir, Some("bzip2"), guard)
            }
            "tar.xz" | "txz" => self.extract_tar_safe(archive_path, dest_dir, Some("xz"), guard),
            "xz" => self.extract_compressed_safe(archive_path, dest_dir, "xz", guard),
            "gz" => self.extract_compressed_safe(archive_path, dest_dir, "gzip", guard),
            "bz2" => self.extract_compressed_safe(archive_path, dest_dir, "bzip2", guard),
            "deb" => self.extract_deb_safe(archive_path, dest_dir, guard),
            "rpm" => self.extract_rpm(archive_path, dest_dir), // TODO: add guard
            "pkg" => self.extract_pkg_safe(archive_path, dest_dir, guard),
            "rar" => self.extract_rar(archive_path, dest_dir), // TODO: add guard
            _ => anyhow::bail!("Unsupported archive type: {}", archive_type),
        }
    }

    fn extract_compressed_safe(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        compression: &str,
        guard: &ExtractionGuard,
    ) -> Result<()> {
        let file = File::open(archive_path)?;
        let compressed_size = file.metadata()?.len();

        // Determine output filename by stripping the compression extension
        let stem = archive_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("extracted");
        let output_path = dest_dir.join(stem);

        if !guard.check_file_count() {
            anyhow::bail!("File count limit exceeded");
        }

        let mut output_file = File::create(&output_path).context("Failed to create output file")?;

        // Use LimitedReader to prevent decompression bombs
        let bytes_written = match compression {
            "xz" => {
                let decoder = xz2::read::XzDecoder::new(file);
                let mut limited = LimitedReader::new(decoder, MAX_FILE_SIZE);
                std::io::copy(&mut limited, &mut output_file)
                    .context("Failed to decompress XZ file")?
            }
            "gzip" => {
                let decoder = flate2::read::GzDecoder::new(file);
                let mut limited = LimitedReader::new(decoder, MAX_FILE_SIZE);
                std::io::copy(&mut limited, &mut output_file)
                    .context("Failed to decompress GZ file")?
            }
            "bzip2" => {
                let decoder = bzip2::read::BzDecoder::new(file);
                let mut limited = LimitedReader::new(decoder, MAX_FILE_SIZE);
                std::io::copy(&mut limited, &mut output_file)
                    .context("Failed to decompress BZ2 file")?
            }
            _ => anyhow::bail!("Unsupported compression: {}", compression),
        };

        // Check compression ratio
        guard.check_compression_ratio(compressed_size, bytes_written);
        guard.check_bytes(bytes_written, stem);

        Ok(())
    }

    fn extract_zip_safe(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        guard: &ExtractionGuard,
    ) -> Result<()> {
        use tracing::{debug, info, trace};

        let file = File::open(archive_path)?;
        let mut archive = zip::ZipArchive::new(file).context("Failed to read ZIP archive")?;

        debug!(
            "Opening ZIP archive: {:?} ({} entries)",
            archive_path,
            archive.len()
        );

        // Check if the archive is encrypted by finding the first file (not directory)
        // Directories in zips often have encrypted=false even if files are encrypted
        let is_encrypted = if !archive.is_empty() {
            let mut found_encrypted = false;
            for i in 0..archive.len().min(10) {
                // Check first 10 entries
                match archive.by_index(i) {
                    Ok(entry) => {
                        // Skip directories, check actual files
                        if !entry.is_dir() {
                            let encrypted = entry.encrypted();
                            trace!("Entry {} ({}) encrypted: {}", i, entry.name(), encrypted);
                            if encrypted {
                                found_encrypted = true;
                                break;
                            }
                        } else {
                            trace!("Entry {} is directory, skipping encryption check", i);
                        }
                    }
                    Err(_) => {
                        debug!("Cannot read entry {}, assuming encrypted", i);
                        found_encrypted = true;
                        break;
                    }
                }
            }
            found_encrypted
        } else {
            debug!("Empty archive");
            false
        };

        if is_encrypted {
            info!(
                "ZIP archive is encrypted, attempting {} passwords",
                self.zip_passwords.len()
            );

            if self.zip_passwords.is_empty() {
                anyhow::bail!("Archive is encrypted but no passwords configured");
            }

            // Try each password
            for (idx, password) in self.zip_passwords.iter().enumerate() {
                debug!(
                    "Trying password {}/{}: '{}'",
                    idx + 1,
                    self.zip_passwords.len(),
                    password
                );

                // Re-open the archive for each password attempt
                let file = File::open(archive_path)?;
                let mut archive =
                    zip::ZipArchive::new(file).context("Failed to read ZIP archive")?;

                match self.extract_zip_entries_safe(
                    &mut archive,
                    dest_dir,
                    Some(password.as_bytes()),
                    guard,
                ) {
                    Ok(()) => {
                        info!("✓ Decrypted with password: {}", password);
                        eprintln!("  Decrypted with password: {}", password);
                        return Ok(());
                    }
                    Err(e) => {
                        debug!("Password '{}' failed: {}", password, e);
                        continue;
                    }
                }
            }
            anyhow::bail!(
                "Password required to decrypt file (tried {} passwords)",
                self.zip_passwords.len()
            );
        } else {
            debug!("Archive is not encrypted, extracting directly");
        }

        // Try without password
        self.extract_zip_entries_safe(&mut archive, dest_dir, None, guard)
    }

    fn extract_zip_entries_safe<R: Read + Seek>(
        &self,
        archive: &mut zip::ZipArchive<R>,
        dest_dir: &Path,
        password: Option<&[u8]>,
        guard: &ExtractionGuard,
    ) -> Result<()> {
        use tracing::{debug, trace};

        let password_display = password.map(|_| "***").unwrap_or("none");
        debug!(
            "Extracting {} entries with password: {}",
            archive.len(),
            password_display
        );

        for i in 0..archive.len() {
            // Check file count limit
            if !guard.check_file_count() {
                anyhow::bail!("Exceeded maximum file count ({})", MAX_FILE_COUNT);
            }

            trace!("Processing entry {}/{}", i + 1, archive.len());

            let mut entry = match password {
                Some(pw) => match archive.by_index_decrypt(i, pw) {
                    Ok(file) => {
                        trace!("Entry {} decrypted successfully", i);
                        file
                    }
                    Err(e) => {
                        debug!("Failed to decrypt entry {}: {}", i, e);
                        return Err(e.into());
                    }
                },
                None => archive.by_index(i)?,
            };

            let entry_name = entry.name().to_string();
            trace!("Entry {}: {}", i, entry_name);

            // Sanitize path to prevent zip slip
            let outpath = match sanitize_entry_path(&entry_name, dest_dir) {
                Some(p) => p,
                None => {
                    guard.add_hostile_reason(HostileArchiveReason::PathTraversal(entry_name));
                    continue; // Skip this file but continue extraction
                }
            };

            // Check for symlinks (zip files can contain them via external attributes)
            // S_IFLNK = 0o120000, S_IFMT = 0o170000
            if let Some(mode) = entry.unix_mode() {
                if mode & 0o170000 == 0o120000 {
                    guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(entry_name));
                    continue;
                }
            }

            if entry.is_dir() {
                fs::create_dir_all(&outpath)?;
            } else {
                // Check compression ratio before extraction (zip bomb detection)
                let compressed = entry.compressed_size();
                let uncompressed = entry.size();
                if !guard.check_compression_ratio(compressed, uncompressed) {
                    continue; // Skip but continue
                }

                // Check if this single file would exceed limits
                if uncompressed > MAX_FILE_SIZE {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                        file: entry_name.clone(),
                        size: uncompressed,
                    });
                    continue;
                }

                if let Some(parent) = outpath.parent() {
                    fs::create_dir_all(parent)?;
                }

                // Extract with size limit
                let mut outfile = File::create(&outpath)?;
                let mut limited = LimitedReader::new(&mut entry, MAX_FILE_SIZE);
                let written = std::io::copy(&mut limited, &mut outfile)
                    .with_context(|| format!("Failed to extract: {}", entry_name))?;

                // Track total bytes
                if !guard.check_bytes(written, &entry_name) {
                    anyhow::bail!("Exceeded maximum total extraction size");
                }
            }
        }
        Ok(())
    }

    /// Extract Chrome extension (.crx) files
    /// CRX format: "Cr24" magic (4) + version (4) + pubkey_len (4) + sig_len (4) + pubkey + sig + ZIP
    fn extract_crx_safe(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        guard: &ExtractionGuard,
    ) -> Result<()> {
        let mut file = File::open(archive_path)?;
        let mut header = [0u8; 16];

        // Read CRX header
        std::io::Read::read_exact(&mut file, &mut header).context("Failed to read CRX header")?;

        // Verify magic number "Cr24"
        if &header[0..4] != b"Cr24" {
            anyhow::bail!("Invalid CRX magic number");
        }

        // Parse header fields (little-endian)
        let pubkey_len =
            u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
        let sig_len = u32::from_le_bytes([header[12], header[13], header[14], header[15]]) as usize;

        // Skip public key and signature to get to ZIP data
        let zip_offset = 16 + pubkey_len + sig_len;

        // Read the entire file into memory (needed for ZipArchive)
        let mut file_data = Vec::new();
        std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(0))?;
        std::io::Read::read_to_end(&mut file, &mut file_data)?;

        // Extract just the ZIP portion
        if file_data.len() < zip_offset {
            anyhow::bail!("CRX file truncated (expected {} bytes)", zip_offset);
        }

        let zip_data = &file_data[zip_offset..];
        let cursor = Cursor::new(zip_data);

        // Create ZipArchive from the ZIP portion
        let mut archive = zip::ZipArchive::new(cursor).context("Failed to read ZIP from CRX")?;

        // Use the same extraction logic as regular ZIP (but without password support for now)
        self.extract_zip_entries_safe(&mut archive, dest_dir, None, guard)
    }

    /// Extract 7z archive files
    fn extract_7z_safe(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        guard: &ExtractionGuard,
    ) -> Result<()> {
        use sevenz_rust::{Password, SevenZReader};
        use std::io::Read;

        // Check magic bytes - file might be mislabeled (e.g., ZIP with .7z extension)
        let mut file = File::open(archive_path)?;
        let mut magic = [0u8; 4];
        if file.read_exact(&mut magic).is_ok() && magic == [0x50, 0x4B, 0x03, 0x04] {
            // This is actually a ZIP file (PK\x03\x04), redirect to ZIP handler
            return self.extract_zip_safe(archive_path, dest_dir, guard);
        }

        // Re-open for 7z processing
        let file = File::open(archive_path)?;
        let file_len = file.metadata()?.len();
        let mut sz = SevenZReader::new(file, file_len, Password::empty())
            .context("Failed to read 7z archive")?;

        // Iterate through entries
        sz.for_each_entries(|entry, reader| {
            // Check file count limit
            if !guard.check_file_count() {
                return Err(sevenz_rust::Error::other("Exceeded maximum file count"));
            }

            let name = entry.name();

            // Skip entries with empty names
            if name.is_empty() {
                return Ok(true);
            }

            // Sanitize path to prevent path traversal
            let outpath = match sanitize_entry_path(name, dest_dir) {
                Some(p) => p,
                None => {
                    guard.add_hostile_reason(HostileArchiveReason::PathTraversal(name.to_string()));
                    return Ok(true); // Continue extraction
                }
            };

            // Check if entry is a directory
            if entry.is_directory() {
                fs::create_dir_all(&outpath)
                    .map_err(|e| sevenz_rust::Error::other(format!("mkdir failed: {}", e)))?;
                return Ok(true);
            }

            // Check size limits
            let uncompressed = entry.size();
            if uncompressed > MAX_FILE_SIZE {
                guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                    file: name.to_string(),
                    size: uncompressed,
                });
                return Ok(true); // Skip but continue
            }

            // Create parent directory
            if let Some(parent) = outpath.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| sevenz_rust::Error::other(format!("mkdir failed: {}", e)))?;
            }

            // Extract file with size limiting
            let mut limited_reader = LimitedReader::new(reader, uncompressed);
            let mut output = File::create(&outpath)
                .map_err(|e| sevenz_rust::Error::other(format!("create file failed: {}", e)))?;

            let written = std::io::copy(&mut limited_reader, &mut output)
                .map_err(|e| sevenz_rust::Error::other(format!("copy failed: {}", e)))?;

            // Track total bytes
            if !guard.check_bytes(written, name) {
                return Err(sevenz_rust::Error::other(
                    "Exceeded maximum total extraction size",
                ));
            }

            Ok(true) // Continue
        })
        .context("Failed to extract 7z archive")
    }

    /// Extract macOS PKG files (XAR archives)
    fn extract_pkg_safe(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        guard: &ExtractionGuard,
    ) -> Result<()> {
        let file = File::open(archive_path)?;
        let mut xar =
            apple_xar::reader::XarReader::new(file).context("Failed to read PKG (XAR) archive")?;

        // Get all files in the archive
        let files = xar.files().context("Failed to list XAR files")?;

        for (path, file_entry) in files {
            if !guard.check_file_count() {
                anyhow::bail!("Exceeded maximum file count");
            }

            // Sanitize path
            let out_path = match sanitize_entry_path(&path, dest_dir) {
                Some(p) => p,
                None => {
                    guard.add_hostile_reason(HostileArchiveReason::PathTraversal(path.clone()));
                    continue;
                }
            };

            // Check file size
            if let Some(size) = file_entry.size {
                if size > MAX_FILE_SIZE {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                        file: path.clone(),
                        size,
                    });
                    continue;
                }
            }

            // Skip symlinks and hardlinks
            use apple_xar::table_of_contents::FileType as XarFileType;
            if matches!(
                file_entry.file_type,
                XarFileType::Link | XarFileType::HardLink
            ) {
                guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(path.clone()));
                continue;
            }

            // Create parent directories
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }

            // Extract file
            let mut output = File::create(&out_path)?;
            let written =
                xar.write_file_data_decoded_from_file(&file_entry, &mut output)
                    .context(format!("Failed to extract file: {}", path))? as u64;

            if !guard.check_bytes(written, &path) {
                anyhow::bail!("Exceeded maximum total extraction size");
            }
        }

        Ok(())
    }

    fn extract_tar_safe(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        compression: Option<&str>,
        guard: &ExtractionGuard,
    ) -> Result<()> {
        let file = File::open(archive_path)?;

        let reader: Box<dyn Read> = match compression {
            Some("gzip") => Box::new(flate2::read::GzDecoder::new(file)),
            Some("bzip2") => Box::new(bzip2::read::BzDecoder::new(file)),
            Some("xz") => Box::new(xz2::read::XzDecoder::new(file)),
            None => Box::new(file),
            _ => anyhow::bail!("Unsupported compression: {:?}", compression),
        };

        let mut archive = tar::Archive::new(reader);

        for entry_result in archive.entries()? {
            // Check file count
            if !guard.check_file_count() {
                anyhow::bail!("Exceeded maximum file count");
            }

            let mut entry = entry_result.context("Failed to read tar entry")?;
            let entry_path = entry.path()?;
            let entry_name = entry_path.to_string_lossy().to_string();

            // Sanitize path
            let outpath = match sanitize_entry_path(&entry_name, dest_dir) {
                Some(p) => p,
                None => {
                    guard.add_hostile_reason(HostileArchiveReason::PathTraversal(entry_name));
                    continue;
                }
            };

            // Check for symlinks
            let entry_type = entry.header().entry_type();
            if entry_type.is_symlink() || entry_type.is_hard_link() {
                guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(entry_name));
                continue;
            }

            let size = entry.header().size()?;

            if entry_type.is_dir() {
                fs::create_dir_all(&outpath)?;
            } else if entry_type.is_file() {
                // Check file size
                if size > MAX_FILE_SIZE {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                        file: entry_name.clone(),
                        size,
                    });
                    continue;
                }

                if let Some(parent) = outpath.parent() {
                    fs::create_dir_all(parent)?;
                }

                // Extract with limit
                let mut outfile = File::create(&outpath)?;
                let mut limited = LimitedReader::new(&mut entry, MAX_FILE_SIZE);
                let written = std::io::copy(&mut limited, &mut outfile)
                    .with_context(|| format!("Failed to extract: {}", entry_name))?;

                if !guard.check_bytes(written, &entry_name) {
                    anyhow::bail!("Exceeded maximum total extraction size");
                }
            }
            // Skip other entry types (devices, fifos, etc.)
        }

        Ok(())
    }

    /// Extract a Debian package (.deb) with bomb protection
    fn extract_deb_safe(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        guard: &ExtractionGuard,
    ) -> Result<()> {
        let file = File::open(archive_path)?;
        let mut archive = ar::Archive::new(file);

        while let Some(entry_result) = archive.next_entry() {
            let mut entry = entry_result.context("Failed to read AR entry")?;
            let name = String::from_utf8_lossy(entry.header().identifier()).to_string();

            // We're mainly interested in data.tar.* which contains the actual files
            if name.starts_with("data.tar") {
                let sub_dest = dest_dir.join("data");
                fs::create_dir_all(&sub_dest)?;

                if name.ends_with(".gz") {
                    let decoder = flate2::read::GzDecoder::new(&mut entry);
                    self.extract_tar_entries_safe(decoder, &sub_dest, guard)?;
                } else if name.ends_with(".xz") {
                    let decoder = xz2::read::XzDecoder::new(&mut entry);
                    self.extract_tar_entries_safe(decoder, &sub_dest, guard)?;
                } else if name.ends_with(".zst") {
                    let decoder = zstd::stream::read::Decoder::new(&mut entry)
                        .context("Failed to create zstd decoder")?;
                    self.extract_tar_entries_safe(decoder, &sub_dest, guard)?;
                } else if name == "data.tar" {
                    self.extract_tar_entries_safe(&mut entry, &sub_dest, guard)?;
                } else if name.ends_with(".bz2") {
                    let decoder = bzip2::read::BzDecoder::new(&mut entry);
                    self.extract_tar_entries_safe(decoder, &sub_dest, guard)?;
                }
            } else if name.starts_with("control.tar") {
                // Also extract control files for analysis
                let sub_dest = dest_dir.join("control");
                fs::create_dir_all(&sub_dest)?;

                if name.ends_with(".gz") {
                    let decoder = flate2::read::GzDecoder::new(&mut entry);
                    self.extract_tar_entries_safe(decoder, &sub_dest, guard)?;
                } else if name.ends_with(".xz") {
                    let decoder = xz2::read::XzDecoder::new(&mut entry);
                    self.extract_tar_entries_safe(decoder, &sub_dest, guard)?;
                } else if name.ends_with(".zst") {
                    let decoder = zstd::stream::read::Decoder::new(&mut entry)
                        .context("Failed to create zstd decoder")?;
                    self.extract_tar_entries_safe(decoder, &sub_dest, guard)?;
                } else if name == "control.tar" {
                    self.extract_tar_entries_safe(&mut entry, &sub_dest, guard)?;
                }
            }
        }

        Ok(())
    }

    /// Helper to extract tar entries with guard protection
    fn extract_tar_entries_safe<R: Read>(
        &self,
        reader: R,
        dest_dir: &Path,
        guard: &ExtractionGuard,
    ) -> Result<()> {
        let mut archive = tar::Archive::new(reader);

        for entry_result in archive.entries()? {
            if !guard.check_file_count() {
                anyhow::bail!("Exceeded maximum file count");
            }

            let mut entry = entry_result.context("Failed to read tar entry")?;
            let entry_path = entry.path()?;
            let entry_name = entry_path.to_string_lossy().to_string();

            let outpath = match sanitize_entry_path(&entry_name, dest_dir) {
                Some(p) => p,
                None => {
                    guard.add_hostile_reason(HostileArchiveReason::PathTraversal(entry_name));
                    continue;
                }
            };

            let entry_type = entry.header().entry_type();
            if entry_type.is_symlink() || entry_type.is_hard_link() {
                guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(entry_name));
                continue;
            }

            let size = entry.header().size()?;

            if entry_type.is_dir() {
                fs::create_dir_all(&outpath)?;
            } else if entry_type.is_file() {
                if size > MAX_FILE_SIZE {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                        file: entry_name.clone(),
                        size,
                    });
                    continue;
                }

                if let Some(parent) = outpath.parent() {
                    fs::create_dir_all(parent)?;
                }

                let mut outfile = File::create(&outpath)?;
                let mut limited = LimitedReader::new(&mut entry, MAX_FILE_SIZE);
                let written = std::io::copy(&mut limited, &mut outfile)
                    .with_context(|| format!("Failed to extract: {}", entry_name))?;

                if !guard.check_bytes(written, &entry_name) {
                    anyhow::bail!("Exceeded maximum total extraction size");
                }
            }
        }

        Ok(())
    }

    /// Extract an RPM package (.rpm)
    /// RPM packages contain a lead, signature, header, and CPIO archive
    fn extract_rpm(&self, archive_path: &Path, dest_dir: &Path) -> Result<()> {
        let file = File::open(archive_path)?;
        let mut reader = BufReader::new(file);

        // RPM magic: 0xedabeedb
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if magic != [0xed, 0xab, 0xee, 0xdb] {
            anyhow::bail!("Not a valid RPM file (invalid magic)");
        }

        // Read RPM lead (96 bytes total, we already read 4)
        let mut lead_rest = [0u8; 92];
        reader.read_exact(&mut lead_rest)?;

        // Skip signature header and get its size
        let sig_size = self.skip_rpm_header(&mut reader)?;

        // Align to 8-byte boundary after signature
        let pos = sig_size;
        let padding = (8 - (pos % 8)) % 8;
        if padding > 0 {
            let mut pad = vec![0u8; padding];
            reader.read_exact(&mut pad)?;
        }

        // Skip main header
        self.skip_rpm_header(&mut reader)?;

        // The rest is the CPIO archive, possibly compressed
        // Try to detect compression by reading first bytes
        let mut peek = [0u8; 6];
        reader.read_exact(&mut peek)?;

        // Create a chain reader with the peeked bytes
        let peek_cursor = std::io::Cursor::new(peek.to_vec());
        let chained = peek_cursor.chain(reader);

        // Detect compression and extract
        if peek[0..2] == [0x1f, 0x8b] {
            // gzip
            let decoder = flate2::read::GzDecoder::new(chained);
            self.extract_cpio(decoder, dest_dir)?;
        } else if peek[0..3] == [0xfd, 0x37, 0x7a] {
            // xz
            let decoder = xz2::read::XzDecoder::new(chained);
            self.extract_cpio(decoder, dest_dir)?;
        } else if peek[0..4] == [0x28, 0xb5, 0x2f, 0xfd] {
            // zstd
            let decoder = zstd::stream::read::Decoder::new(chained)
                .context("Failed to create zstd decoder")?;
            self.extract_cpio(decoder, dest_dir)?;
        } else if peek[0..3] == [0x42, 0x5a, 0x68] {
            // bzip2
            let decoder = bzip2::read::BzDecoder::new(chained);
            self.extract_cpio(decoder, dest_dir)?;
        } else if peek[0..2] == [0x5d, 0x00] {
            // LZMA (legacy) - try xz decoder
            let decoder = xz2::read::XzDecoder::new(chained);
            self.extract_cpio(decoder, dest_dir)?;
        } else {
            // Uncompressed CPIO
            self.extract_cpio(chained, dest_dir)?;
        }

        Ok(())
    }

    fn skip_rpm_header<R: Read>(&self, reader: &mut R) -> Result<usize> {
        // Header magic
        let mut magic = [0u8; 3];
        reader.read_exact(&mut magic)?;
        if magic != [0x8e, 0xad, 0xe8] {
            anyhow::bail!("Invalid RPM header magic");
        }

        let mut version = [0u8; 1];
        reader.read_exact(&mut version)?;

        // Reserved
        let mut reserved = [0u8; 4];
        reader.read_exact(&mut reserved)?;

        // Number of index entries (big-endian)
        let mut nindex = [0u8; 4];
        reader.read_exact(&mut nindex)?;
        let nindex = u32::from_be_bytes(nindex);

        // Size of data section (big-endian)
        let mut hsize = [0u8; 4];
        reader.read_exact(&mut hsize)?;
        let hsize = u32::from_be_bytes(hsize);

        // Skip index entries (16 bytes each)
        let index_size = nindex as usize * 16;
        let mut index_data = vec![0u8; index_size];
        reader.read_exact(&mut index_data)?;

        // Skip data section
        let mut data = vec![0u8; hsize as usize];
        reader.read_exact(&mut data)?;

        // Return total header size (16 for header + index + data)
        Ok(16 + index_size + hsize as usize)
    }

    fn extract_cpio<R: Read>(&self, mut reader: R, dest_dir: &Path) -> Result<()> {
        loop {
            // Try to read next CPIO entry
            let entry_reader = match cpio::newc::Reader::new(&mut reader) {
                Ok(r) => r,
                Err(e) => {
                    // End of archive or invalid entry
                    if e.kind() == std::io::ErrorKind::InvalidData {
                        break;
                    }
                    return Err(e.into());
                }
            };

            let entry = entry_reader.entry();
            let name = entry.name().to_string();

            if name == "TRAILER!!!" {
                break;
            }

            // Skip . and empty entries
            if name.is_empty() || name == "." {
                // Consume remaining data to advance reader
                let mut sink = std::io::sink();
                std::io::copy(&mut { entry_reader }, &mut sink).ok();
                continue;
            }

            // Clean up path (remove leading ./ or /)
            let clean_name = name.trim_start_matches("./").trim_start_matches('/');
            if clean_name.is_empty() {
                let mut sink = std::io::sink();
                std::io::copy(&mut { entry_reader }, &mut sink).ok();
                continue;
            }

            let out_path = dest_dir.join(clean_name);
            let mode = entry.mode();

            if mode & 0o170000 == 0o040000 {
                // Directory
                fs::create_dir_all(&out_path).ok();
                // Consume remaining data
                let mut sink = std::io::sink();
                std::io::copy(&mut { entry_reader }, &mut sink).ok();
            } else if mode & 0o170000 == 0o100000 {
                // Regular file
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut file = File::create(&out_path)?;
                std::io::copy(&mut { entry_reader }, &mut file)?;
            } else {
                // Skip other types (symlinks, devices, etc.)
                let mut sink = std::io::sink();
                std::io::copy(&mut { entry_reader }, &mut sink).ok();
            }
        }

        Ok(())
    }

    /// Extract a RAR archive (.rar)
    fn extract_rar(&self, archive_path: &Path, dest_dir: &Path) -> Result<()> {
        let mut archive = unrar::Archive::new(archive_path)
            .open_for_processing()
            .context("Failed to open RAR archive")?;

        loop {
            // Read the next header
            let header_result = archive.read_header();
            match header_result {
                Ok(Some(file_archive)) => {
                    let header = file_archive.entry();

                    if header.is_file() {
                        // Determine output path
                        let filename = header.filename.to_string_lossy();
                        let out_path = dest_dir.join(filename.as_ref());

                        // Create parent directories
                        if let Some(parent) = out_path.parent() {
                            fs::create_dir_all(parent)?;
                        }

                        // Extract the file
                        archive = file_archive
                            .extract_to(&out_path)
                            .context("Failed to extract RAR entry")?;
                    } else if header.is_directory() {
                        let dirname = header.filename.to_string_lossy();
                        let dir_path = dest_dir.join(dirname.as_ref());
                        fs::create_dir_all(&dir_path)?;
                        archive = file_archive
                            .skip()
                            .context("Failed to skip RAR directory")?;
                    } else {
                        archive = file_archive.skip().context("Failed to skip RAR entry")?;
                    }
                }
                Ok(None) => break, // No more entries
                Err(e) => return Err(e.into()),
            }
        }

        Ok(())
    }

    fn analyze_extracted_file(&self, file_path: &Path) -> Result<AnalysisReport> {
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

    /// Check if a path is from a known benign Java package (common libraries)
    fn is_benign_java_path(path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        // Skip common library packages
        path_str.contains("/com/google/")
            || path_str.contains("/org/apache/")
            || path_str.contains("/org/slf4j/")
            || path_str.contains("/org/json/")
            || path_str.contains("/org/xml/")
            || path_str.contains("/javax/")
            || path_str.contains("/org/w3c/")
            || path_str.contains("/org/bouncycastle/")
            || path_str.contains("/org/junit/")
            || path_str.contains("/org/mockito/")
            || path_str.contains("/com/fasterxml/")
            || path_str.contains("/org/gradle/")
            || path_str.contains("/org/jetbrains/")
            || path_str.contains("/kotlin/")
            || path_str.contains("/scala/")
            || path_str.contains("/io/netty/")
            || path_str.contains("/okhttp3/")
            || path_str.contains("/okio/")
            || path_str.contains("/com/squareup/")
            || path_str.contains("/org/springframework/")
            || path_str.contains("/ch/qos/")
            || path_str.contains("/org/hibernate/")
            || path_str.contains("/com/sun/")
            || path_str.contains("/sun/")
            || path_str.contains("/jdk/")
            || path_str.contains("/java/")
            || path_str.contains("/com/oracle/")
            || path_str.contains("/io/grpc/")
            || path_str.contains("/com/amazonaws/")
            || path_str.contains("/software/amazon/")
            || path_str.contains("/org/eclipse/")
            || path_str.contains("/groovy/")
            || path_str.contains("/org/codehaus/")
            || path_str.contains("/io/micrometer/")
            || path_str.contains("/org/reactivestreams/")
            || path_str.contains("/reactor/")
            || path_str.contains("/org/yaml/")
            || path_str.contains("/org/hamcrest/")
            || path_str.contains("/org/assertj/")
            || path_str.contains("/org/objectweb/")
            || path_str.contains("/net/bytebuddy/")
            || path_str.contains("/org/objenesis/")
            || path_str.contains("/antlr/")
            || path_str.contains("/org/antlr/")
            || path_str.contains("/org/checkerframework/")
            || path_str.contains("/META-INF/")
            || path_str.contains("/joptsimple/")
            || path_str.contains("/oshi/")
            || path_str.contains("/com/typesafe/")
            || path_str.contains("/io/prometheus/")
            || path_str.contains("/javassist/")
            || path_str.contains("/net/java/")
            || path_str.contains("/ibm/icu/")
            || path_str.contains("/com/ibm/")
    }

    fn detect_archive_type(&self, path: &Path) -> &str {
        let path_str = path.to_string_lossy().to_lowercase();

        if path_str.ends_with(".tar.gz") {
            "tar.gz"
        } else if path_str.ends_with(".tgz") {
            "tgz"
        } else if path_str.ends_with(".tar.bz2") {
            "tar.bz2"
        } else if path_str.ends_with(".tbz2") || path_str.ends_with(".tbz") {
            "tbz"
        } else if path_str.ends_with(".tar.xz") {
            "tar.xz"
        } else if path_str.ends_with(".txz") {
            "txz"
        } else if path_str.ends_with(".tar") {
            "tar"
        } else if path_str.ends_with(".zip")
            || path_str.ends_with(".jar")
            || path_str.ends_with(".war")
            || path_str.ends_with(".ear")
            || path_str.ends_with(".apk")
            || path_str.ends_with(".aar")
            || path_str.ends_with(".egg")
            || path_str.ends_with(".whl")
            || path_str.ends_with(".phar")
            || path_str.ends_with(".nupkg")
            || path_str.ends_with(".vsix")
            || path_str.ends_with(".xpi")
            || path_str.ends_with(".ipa")
            || path_str.ends_with(".epub")
        {
            "zip"
        } else if path_str.ends_with(".crx") {
            "crx"
        } else if path_str.ends_with(".7z") {
            "7z"
        } else if path_str.ends_with(".gem") || path_str.ends_with(".crate") {
            "tar.gz"
        } else if path_str.ends_with(".xz") {
            "xz"
        } else if path_str.ends_with(".gz") {
            "gz"
        } else if path_str.ends_with(".bz2") {
            "bz2"
        } else if path_str.ends_with(".deb") {
            "deb"
        } else if path_str.ends_with(".rpm") {
            "rpm"
        } else if path_str.ends_with(".pkg") {
            "pkg"
        } else if path_str.ends_with(".rar") {
            "rar"
        } else {
            "unknown"
        }
    }

    fn calculate_sha256(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

impl Default for ArchiveAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for ArchiveAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        self.analyze_archive(file_path)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        let path_str = file_path.to_string_lossy().to_lowercase();
        path_str.ends_with(".zip")
            || path_str.ends_with(".jar")
            || path_str.ends_with(".war")
            || path_str.ends_with(".ear")
            || path_str.ends_with(".apk")
            || path_str.ends_with(".aar")
            || path_str.ends_with(".egg")
            || path_str.ends_with(".whl")
            || path_str.ends_with(".phar")
            || path_str.ends_with(".nupkg")
            || path_str.ends_with(".vsix")
            || path_str.ends_with(".xpi")
            || path_str.ends_with(".crx")
            || path_str.ends_with(".ipa")
            || path_str.ends_with(".epub")
            || path_str.ends_with(".gem")
            || path_str.ends_with(".crate")
            || path_str.ends_with(".tar")
            || path_str.ends_with(".tar.gz")
            || path_str.ends_with(".tgz")
            || path_str.ends_with(".tar.bz2")
            || path_str.ends_with(".tbz2")
            || path_str.ends_with(".tar.xz")
            || path_str.ends_with(".txz")
            || (path_str.ends_with(".xz") && !path_str.ends_with(".tar.xz"))
            || (path_str.ends_with(".gz") && !path_str.ends_with(".tar.gz"))
            || (path_str.ends_with(".bz2") && !path_str.ends_with(".tar.bz2"))
            || path_str.ends_with(".deb")
            || path_str.ends_with(".rpm")
            || path_str.ends_with(".pkg")
            || path_str.ends_with(".rar")
            || path_str.ends_with(".7z")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_new() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(analyzer.max_depth, 3);
        assert_eq!(analyzer.current_depth, 0);
    }

    #[test]
    fn test_default() {
        let analyzer = ArchiveAnalyzer::default();
        assert_eq!(analyzer.max_depth, 3);
        assert_eq!(analyzer.current_depth, 0);
    }

    #[test]
    fn test_with_depth() {
        let analyzer = ArchiveAnalyzer::new().with_depth(5);
        assert_eq!(analyzer.current_depth, 5);
    }

    #[test]
    fn test_can_analyze_zip() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.zip")));
        assert!(analyzer.can_analyze(Path::new("TEST.ZIP")));
    }

    #[test]
    fn test_can_analyze_jar() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.jar")));
        assert!(analyzer.can_analyze(Path::new("TEST.JAR")));
        assert!(analyzer.can_analyze(Path::new("test.war")));
        assert!(analyzer.can_analyze(Path::new("test.apk")));
    }

    #[test]
    fn test_detect_archive_type_jar() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(analyzer.detect_archive_type(Path::new("test.jar")), "zip");
        assert_eq!(analyzer.detect_archive_type(Path::new("test.war")), "zip");
        assert_eq!(analyzer.detect_archive_type(Path::new("test.apk")), "zip");
    }

    #[test]
    fn test_can_analyze_tar() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.tar")));
        assert!(analyzer.can_analyze(Path::new("test.tar.gz")));
        assert!(analyzer.can_analyze(Path::new("test.tgz")));
    }

    #[test]
    fn test_can_analyze_tar_bz2() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.tar.bz2")));
        assert!(analyzer.can_analyze(Path::new("test.tbz2")));
    }

    #[test]
    fn test_can_analyze_tar_xz() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.tar.xz")));
        assert!(analyzer.can_analyze(Path::new("test.txz")));
    }

    #[test]
    fn test_cannot_analyze_other() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(!analyzer.can_analyze(Path::new("test.txt")));
        assert!(!analyzer.can_analyze(Path::new("test.elf")));
    }

    #[test]
    fn test_detect_archive_type_zip() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(analyzer.detect_archive_type(Path::new("test.zip")), "zip");
    }

    #[test]
    fn test_detect_archive_type_tar() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(analyzer.detect_archive_type(Path::new("test.tar")), "tar");
    }

    #[test]
    fn test_detect_archive_type_tar_gz() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(
            analyzer.detect_archive_type(Path::new("test.tar.gz")),
            "tar.gz"
        );
        assert_eq!(analyzer.detect_archive_type(Path::new("test.tgz")), "tgz");
    }

    #[test]
    fn test_detect_archive_type_tar_bz2() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(
            analyzer.detect_archive_type(Path::new("test.tar.bz2")),
            "tar.bz2"
        );
        assert_eq!(analyzer.detect_archive_type(Path::new("test.tbz2")), "tbz");
        assert_eq!(analyzer.detect_archive_type(Path::new("test.tbz")), "tbz");
    }

    #[test]
    fn test_detect_archive_type_tar_xz() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(
            analyzer.detect_archive_type(Path::new("test.tar.xz")),
            "tar.xz"
        );
        assert_eq!(analyzer.detect_archive_type(Path::new("test.txz")), "txz");
    }

    #[test]
    fn test_detect_archive_type_deb() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(analyzer.detect_archive_type(Path::new("test.deb")), "deb");
        assert_eq!(
            analyzer.detect_archive_type(Path::new("package.deb")),
            "deb"
        );
    }

    #[test]
    fn test_detect_archive_type_rpm() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(analyzer.detect_archive_type(Path::new("test.rpm")), "rpm");
        assert_eq!(
            analyzer.detect_archive_type(Path::new("package.rpm")),
            "rpm"
        );
    }

    #[test]
    fn test_detect_archive_type_rar() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(analyzer.detect_archive_type(Path::new("test.rar")), "rar");
        assert_eq!(
            analyzer.detect_archive_type(Path::new("archive.rar")),
            "rar"
        );
    }

    #[test]
    fn test_can_analyze_deb() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.deb")));
        assert!(analyzer.can_analyze(Path::new("TEST.DEB")));
    }

    #[test]
    fn test_can_analyze_rpm() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.rpm")));
        assert!(analyzer.can_analyze(Path::new("TEST.RPM")));
    }

    #[test]
    fn test_can_analyze_rar() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.rar")));
        assert!(analyzer.can_analyze(Path::new("TEST.RAR")));
    }

    #[test]
    fn test_can_analyze_python_packages() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("package.egg")));
        assert!(analyzer.can_analyze(Path::new("PACKAGE.EGG")));
        assert!(analyzer.can_analyze(Path::new("package.whl")));
        assert!(analyzer.can_analyze(Path::new("PACKAGE.WHL")));
    }

    #[test]
    fn test_detect_archive_type_python_packages() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(
            analyzer.detect_archive_type(Path::new("package.egg")),
            "zip"
        );
        assert_eq!(
            analyzer.detect_archive_type(Path::new("package.whl")),
            "zip"
        );
    }

    #[test]
    fn test_can_analyze_ruby_gem() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("rails.gem")));
        assert!(analyzer.can_analyze(Path::new("RAILS.GEM")));
    }

    #[test]
    fn test_detect_archive_type_gem() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(
            analyzer.detect_archive_type(Path::new("rails.gem")),
            "tar.gz"
        );
    }

    #[test]
    fn test_can_analyze_php_phar() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("composer.phar")));
        assert!(analyzer.can_analyze(Path::new("COMPOSER.PHAR")));
    }

    #[test]
    fn test_detect_archive_type_phar() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(
            analyzer.detect_archive_type(Path::new("composer.phar")),
            "zip"
        );
    }

    #[test]
    fn test_can_analyze_nuget() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("package.nupkg")));
        assert!(analyzer.can_analyze(Path::new("PACKAGE.NUPKG")));
    }

    #[test]
    fn test_detect_archive_type_nupkg() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(
            analyzer.detect_archive_type(Path::new("package.nupkg")),
            "zip"
        );
    }

    #[test]
    fn test_can_analyze_rust_crate() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("serde.crate")));
        assert!(analyzer.can_analyze(Path::new("SERDE.CRATE")));
    }

    #[test]
    fn test_detect_archive_type_crate() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(
            analyzer.detect_archive_type(Path::new("serde.crate")),
            "tar.gz"
        );
    }

    #[test]
    fn test_can_analyze_vscode_extensions() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("extension.vsix")));
        assert!(analyzer.can_analyze(Path::new("EXTENSION.VSIX")));
    }

    #[test]
    fn test_detect_archive_type_vsix() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(
            analyzer.detect_archive_type(Path::new("extension.vsix")),
            "zip"
        );
    }

    #[test]
    fn test_can_analyze_firefox_extensions() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("addon.xpi")));
        assert!(analyzer.can_analyze(Path::new("ADDON.XPI")));
    }

    #[test]
    fn test_detect_archive_type_xpi() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(analyzer.detect_archive_type(Path::new("addon.xpi")), "zip");
    }

    #[test]
    fn test_can_analyze_chrome_extensions() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("extension.crx")));
        assert!(analyzer.can_analyze(Path::new("EXTENSION.CRX")));
    }

    #[test]
    fn test_detect_archive_type_crx() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(
            analyzer.detect_archive_type(Path::new("extension.crx")),
            "crx"
        );
    }

    #[test]
    fn test_can_analyze_ios_apps() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("app.ipa")));
        assert!(analyzer.can_analyze(Path::new("APP.IPA")));
    }

    #[test]
    fn test_detect_archive_type_ipa() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(analyzer.detect_archive_type(Path::new("app.ipa")), "zip");
    }

    #[test]
    fn test_can_analyze_epub() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("book.epub")));
        assert!(analyzer.can_analyze(Path::new("BOOK.EPUB")));
    }

    #[test]
    fn test_detect_archive_type_epub() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(analyzer.detect_archive_type(Path::new("book.epub")), "zip");
    }

    #[test]
    fn test_can_analyze_7z() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("archive.7z")));
        assert!(analyzer.can_analyze(Path::new("ARCHIVE.7Z")));
    }

    #[test]
    fn test_detect_archive_type_7z() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(analyzer.detect_archive_type(Path::new("archive.7z")), "7z");
    }

    #[test]
    fn test_can_analyze_macos_pkg() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("installer.pkg")));
        assert!(analyzer.can_analyze(Path::new("INSTALLER.PKG")));
    }

    #[test]
    fn test_detect_archive_type_pkg() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(
            analyzer.detect_archive_type(Path::new("installer.pkg")),
            "pkg"
        );
    }

    #[test]
    fn test_detect_archive_type_unknown() {
        let analyzer = ArchiveAnalyzer::new();
        assert_eq!(
            analyzer.detect_archive_type(Path::new("test.txt")),
            "unknown"
        );
    }

    #[test]
    fn test_calculate_sha256() {
        let analyzer = ArchiveAnalyzer::new();
        let data = b"test data";
        let hash = analyzer.calculate_sha256(data);
        assert_eq!(hash.len(), 64); // SHA256 is 64 hex characters
        assert_eq!(
            hash,
            "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
    }

    #[test]
    fn test_analyze_zip_with_shell_script() {
        // Create a test ZIP with a shell script inside
        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("test.zip");

        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);

        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("test.sh", options).unwrap();
        zip.write_all(b"#!/bin/sh\necho 'hello'").unwrap();
        zip.finish().unwrap();

        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&zip_path);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.target.file_type, "zip");
        assert!(report
            .structure
            .iter()
            .any(|s| s.id.starts_with("archive/")));
    }

    #[test]
    fn test_max_depth_exceeded() {
        let analyzer = ArchiveAnalyzer::new().with_depth(3);

        // Create a temporary ZIP file
        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("test.zip");

        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("dummy.txt", options).unwrap();
        zip.write_all(b"test").unwrap();
        zip.finish().unwrap();

        let result = analyzer.analyze(&zip_path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Maximum archive depth"));
    }

    #[test]
    fn test_with_zip_passwords() {
        let passwords = vec!["pass1".to_string(), "pass2".to_string()];
        let analyzer = ArchiveAnalyzer::new().with_zip_passwords(passwords.clone());
        assert_eq!(analyzer.zip_passwords, passwords);
    }

    #[test]
    fn test_with_zip_passwords_empty_by_default() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.zip_passwords.is_empty());
    }

    #[test]
    fn test_encrypted_zip_with_correct_password() {
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("encrypted.zip");

        // Create encrypted zip with password "secret"
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"secret");
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"hello world").unwrap();
        zip.finish().unwrap();

        // Analyze with correct password
        let analyzer = ArchiveAnalyzer::new().with_zip_passwords(vec!["secret".to_string()]);
        let result = analyzer.analyze(&zip_path);
        assert!(result.is_ok(), "Should decrypt with correct password");
    }

    #[test]
    fn test_encrypted_zip_with_wrong_password() {
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("encrypted.zip");

        // Create encrypted zip with password "secret"
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"secret");
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"hello world").unwrap();
        zip.finish().unwrap();

        // Analyze with wrong password
        let analyzer = ArchiveAnalyzer::new().with_zip_passwords(vec!["wrongpass".to_string()]);
        let result = analyzer.analyze(&zip_path);
        assert!(result.is_err(), "Should fail with wrong password");
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("tried 1 passwords"));
    }

    #[test]
    fn test_encrypted_zip_no_passwords_configured() {
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("encrypted.zip");

        // Create encrypted zip
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"secret");
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"hello world").unwrap();
        zip.finish().unwrap();

        // Analyze with no passwords (default)
        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&zip_path);
        assert!(result.is_err(), "Should fail when no passwords configured");
    }

    #[test]
    fn test_encrypted_zip_multiple_passwords_finds_correct() {
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("encrypted.zip");

        // Create encrypted zip with password "correct"
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"correct");
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"hello world").unwrap();
        zip.finish().unwrap();

        // Analyze with multiple passwords, correct one is third
        let analyzer = ArchiveAnalyzer::new().with_zip_passwords(vec![
            "wrong1".to_string(),
            "wrong2".to_string(),
            "correct".to_string(),
            "wrong3".to_string(),
        ]);
        let result = analyzer.analyze(&zip_path);
        assert!(
            result.is_ok(),
            "Should find correct password among multiple"
        );
    }

    #[test]
    fn test_unencrypted_zip_works_with_passwords_configured() {
        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("unencrypted.zip");

        // Create unencrypted zip
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"hello world").unwrap();
        zip.finish().unwrap();

        // Should work even with passwords configured
        let analyzer = ArchiveAnalyzer::new()
            .with_zip_passwords(vec!["pass1".to_string(), "pass2".to_string()]);
        let result = analyzer.analyze(&zip_path);
        assert!(
            result.is_ok(),
            "Unencrypted zip should work with passwords configured"
        );
    }

    #[test]
    fn test_extract_zip_with_password_helper() {
        use std::io::Write;
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("encrypted.zip");
        let extract_dir = temp_dir.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        // Create encrypted zip
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"testpass");
        zip.start_file("data.txt", options).unwrap();
        zip.write_all(b"secret data").unwrap();
        zip.finish().unwrap();

        // Test the extract helper directly
        let analyzer = ArchiveAnalyzer::new();
        let guard = ExtractionGuard::new();
        let file = File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        let result = analyzer.extract_zip_entries_safe(
            &mut archive,
            &extract_dir,
            Some(b"testpass"),
            &guard,
        );
        assert!(result.is_ok(), "Should extract with correct password");

        // Verify file was extracted
        let extracted_file = extract_dir.join("data.txt");
        assert!(extracted_file.exists(), "Extracted file should exist");
        let bytes = fs::read(&extracted_file).unwrap();
        let content = String::from_utf8_lossy(&bytes);
        assert_eq!(content, "secret data");
    }

    #[test]
    fn test_path_traversal_detection() {
        // Test that path traversal attempts are detected
        assert!(sanitize_entry_path("../etc/passwd", Path::new("/tmp/test")).is_none());
        assert!(sanitize_entry_path("foo/../../etc/passwd", Path::new("/tmp/test")).is_none());
        assert!(sanitize_entry_path("/etc/passwd", Path::new("/tmp/test")).is_none());

        // Valid paths should work
        assert!(sanitize_entry_path("foo/bar.txt", Path::new("/tmp/test")).is_some());
        assert!(sanitize_entry_path("./foo/bar.txt", Path::new("/tmp/test")).is_some());
    }

    #[test]
    fn test_extraction_guard_limits() {
        let guard = ExtractionGuard::new();

        // File count tracking
        for _ in 0..MAX_FILE_COUNT {
            assert!(guard.check_file_count());
        }
        assert!(!guard.check_file_count()); // Should fail on next

        // Verify hostile reason was recorded
        let reasons = guard.take_reasons();
        assert!(reasons
            .iter()
            .any(|r| matches!(r, HostileArchiveReason::ExcessiveFileCount(_))));
    }

    #[test]
    fn test_compression_ratio_detection() {
        let guard = ExtractionGuard::new();

        // Normal ratio should pass
        assert!(guard.check_compression_ratio(1000, 2000)); // 2:1

        // Suspicious ratio should fail
        assert!(!guard.check_compression_ratio(100, 100_000)); // 1000:1

        let reasons = guard.take_reasons();
        assert!(reasons
            .iter()
            .any(|r| matches!(r, HostileArchiveReason::ZipBomb { .. })));
    }
    #[test]
    fn test_nested_archive_zip_containing_tar_gz() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use tar::Builder;

        let temp_dir = tempfile::tempdir().unwrap();
        let outer_zip_path = temp_dir.path().join("outer.zip");

        // Create inner.tar.gz with a shell script
        let inner_tar_gz_data = {
            let mut tar_data = Vec::new();
            {
                let enc = GzEncoder::new(&mut tar_data, Compression::default());
                let mut tar_builder = Builder::new(enc);

                // Add a shell script
                let script_content = b"#!/bin/sh\necho hello\ncurl http://example.com";
                let mut header = tar::Header::new_gnu();
                header.set_path("script.sh").unwrap();
                header.set_size(script_content.len() as u64);
                header.set_mode(0o755);
                header.set_cksum();
                tar_builder.append(&header, &script_content[..]).unwrap();
                tar_builder.finish().unwrap();
            }
            tar_data
        };

        // Create outer.zip containing inner.tar.gz
        {
            let file = File::create(&outer_zip_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::FileOptions::<()>::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("inner.tar.gz", options).unwrap();
            std::io::Write::write_all(&mut zip, &inner_tar_gz_data).unwrap();
            zip.finish().unwrap();
        }

        // Analyze the nested archive
        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&outer_zip_path);
        assert!(result.is_ok(), "Should analyze nested archive");

        let report = result.unwrap();

        // Check archive_contents includes both inner.tar.gz and nested file
        assert!(
            !report.archive_contents.is_empty(),
            "Should have archive_contents"
        );

        // Should have entry for inner.tar.gz
        let has_inner = report
            .archive_contents
            .iter()
            .any(|e| e.path == "inner.tar.gz");
        assert!(has_inner, "Should have inner.tar.gz entry");

        // Should have entry for nested script with ! separator
        let has_nested = report
            .archive_contents
            .iter()
            .any(|e| e.path == "inner.tar.gz!script.sh");
        assert!(
            has_nested,
            "Should have nested entry with ! separator: {:?}",
            report.archive_contents
        );
    }

    #[test]
    fn test_nested_archive_path_format() {
        let analyzer = ArchiveAnalyzer::new();

        // Test format_entry_path without prefix
        assert_eq!(analyzer.format_entry_path("file.txt"), "file.txt");

        // Test format_evidence_location without prefix
        assert_eq!(
            analyzer.format_evidence_location("file.txt"),
            "archive:file.txt"
        );

        // Test with prefix
        let nested_analyzer = ArchiveAnalyzer::new().with_archive_prefix("inner.zip".to_string());
        assert_eq!(
            nested_analyzer.format_entry_path("file.txt"),
            "inner.zip!file.txt"
        );
        assert_eq!(
            nested_analyzer.format_evidence_location("file.txt"),
            "archive:inner.zip!file.txt"
        );
    }

    #[test]
    fn test_nested_archive_max_depth() {
        // Create analyzer at max depth
        let at_max = ArchiveAnalyzer::new().with_depth(3);
        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("test.zip");

        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("test.txt", options).unwrap();
        std::io::Write::write_all(&mut zip, b"hello").unwrap();
        zip.finish().unwrap();

        // Should fail because we're at max depth
        let result = at_max.analyze(&zip_path);
        assert!(result.is_err(), "Should fail at max depth");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Maximum archive depth"),
            "Error should mention depth"
        );
    }

    // =========================================================================
    // Extraction tests for new archive formats
    // =========================================================================

    #[test]
    fn test_extract_vsix() {
        // Create a VSIX (VS Code extension) with typical content
        let temp_dir = tempfile::tempdir().unwrap();
        let vsix_path = temp_dir.path().join("extension.vsix");

        let file = File::create(&vsix_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Deflated);

        // Add typical VSIX files
        zip.start_file("extension.vsixmanifest", options).unwrap();
        std::io::Write::write_all(&mut zip, b"<?xml version=\"1.0\"?>").unwrap();

        zip.start_file("package.json", options).unwrap();
        std::io::Write::write_all(&mut zip, b"{\"name\": \"test-extension\"}").unwrap();

        zip.start_file("extension/index.js", options).unwrap();
        std::io::Write::write_all(&mut zip, b"console.log('malicious code');").unwrap();

        zip.finish().unwrap();

        // Analyze the VSIX
        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&vsix_path);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.target.file_type, "zip");
        assert!(!report.archive_contents.is_empty());

        // Verify files were extracted and analyzed
        assert!(report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("package.json")));
        assert!(report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("index.js")));
    }

    #[test]
    fn test_extract_xpi() {
        // Create an XPI (Firefox extension)
        let temp_dir = tempfile::tempdir().unwrap();
        let xpi_path = temp_dir.path().join("addon.xpi");

        let file = File::create(&xpi_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Deflated);

        zip.start_file("manifest.json", options).unwrap();
        std::io::Write::write_all(&mut zip, b"{\"manifest_version\": 2}").unwrap();

        zip.start_file("background.js", options).unwrap();
        std::io::Write::write_all(&mut zip, b"// suspicious script\nfetch('http://evil.com');")
            .unwrap();

        zip.finish().unwrap();

        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&xpi_path);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(!report.archive_contents.is_empty());
        assert!(report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("background.js")));
    }

    #[test]
    fn test_extract_ipa() {
        // Create an IPA (iOS app)
        let temp_dir = tempfile::tempdir().unwrap();
        let ipa_path = temp_dir.path().join("app.ipa");

        let file = File::create(&ipa_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Deflated);

        zip.start_file("Payload/App.app/Info.plist", options)
            .unwrap();
        std::io::Write::write_all(&mut zip, b"<?xml version=\"1.0\"?>").unwrap();

        zip.start_file("Payload/App.app/executable", options)
            .unwrap();
        std::io::Write::write_all(&mut zip, b"\x00\x00\x00\x00").unwrap();

        zip.finish().unwrap();

        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&ipa_path);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("Info.plist")));
    }

    #[test]
    fn test_extract_epub() {
        // Create an EPUB (eBook)
        let temp_dir = tempfile::tempdir().unwrap();
        let epub_path = temp_dir.path().join("book.epub");

        let file = File::create(&epub_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);

        // EPUB requires specific structure
        zip.start_file("mimetype", options).unwrap();
        std::io::Write::write_all(&mut zip, b"application/epub+zip").unwrap();

        zip.start_file("META-INF/container.xml", options).unwrap();
        std::io::Write::write_all(&mut zip, b"<?xml version=\"1.0\"?>").unwrap();

        zip.start_file("OEBPS/content.opf", options).unwrap();
        std::io::Write::write_all(&mut zip, b"<?xml version=\"1.0\"?>").unwrap();

        zip.finish().unwrap();

        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&epub_path);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.archive_contents.iter().any(|e| e.path == "mimetype"));
    }

    #[test]
    fn test_extract_crx() {
        // Create a CRX (Chrome extension) - ZIP with special header
        let temp_dir = tempfile::tempdir().unwrap();
        let crx_path = temp_dir.path().join("extension.crx");

        // Create a ZIP first
        let zip_data = {
            let mut buf = Vec::new();
            let mut zip = zip::ZipWriter::new(Cursor::new(&mut buf));
            let options = zip::write::FileOptions::<()>::default();

            zip.start_file("manifest.json", options).unwrap();
            std::io::Write::write_all(&mut zip, b"{\"manifest_version\": 3}").unwrap();

            zip.start_file("background.js", options).unwrap();
            std::io::Write::write_all(&mut zip, b"console.log('loaded');").unwrap();

            zip.finish().unwrap();
            buf
        };

        // Write CRX file with header
        let mut crx_file = File::create(&crx_path).unwrap();

        // CRX3 header: "Cr24" + version (4 bytes) + pubkey_len (4 bytes) + sig_len (4 bytes)
        std::io::Write::write_all(&mut crx_file, b"Cr24").unwrap(); // Magic
        std::io::Write::write_all(&mut crx_file, &3u32.to_le_bytes()).unwrap(); // Version
        std::io::Write::write_all(&mut crx_file, &32u32.to_le_bytes()).unwrap(); // Pubkey len
        std::io::Write::write_all(&mut crx_file, &64u32.to_le_bytes()).unwrap(); // Sig len

        // Fake public key (32 bytes)
        std::io::Write::write_all(&mut crx_file, &[0u8; 32]).unwrap();

        // Fake signature (64 bytes)
        std::io::Write::write_all(&mut crx_file, &[0u8; 64]).unwrap();

        // ZIP data
        std::io::Write::write_all(&mut crx_file, &zip_data).unwrap();

        // Analyze the CRX
        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&crx_path);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.target.file_type, "crx");
        assert!(!report.archive_contents.is_empty());
        assert!(report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("manifest.json")));
    }

    #[test]
    fn test_vsix_path_traversal_protection() {
        // Create a malicious VSIX with path traversal attempt
        let temp_dir = tempfile::tempdir().unwrap();
        let vsix_path = temp_dir.path().join("malicious.vsix");

        let file = File::create(&vsix_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default();

        // Try to escape with ../
        zip.start_file("../../../etc/evil.sh", options).unwrap();
        std::io::Write::write_all(&mut zip, b"#!/bin/sh\nrm -rf /").unwrap();

        zip.start_file("package.json", options).unwrap();
        std::io::Write::write_all(&mut zip, b"{}").unwrap();

        zip.finish().unwrap();

        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&vsix_path);

        // Should succeed but flag the hostile entry
        assert!(result.is_ok());
        let report = result.unwrap();

        // Path traversal file should not be in archive_contents
        assert!(!report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("etc/evil")));

        // Should have detected path traversal
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "anti-analysis/archive/path-traversal"
                && f.desc.contains("path traversal")));
    }

    #[test]
    fn test_extract_python_packages() {
        // Test .egg and .whl extraction
        let temp_dir = tempfile::tempdir().unwrap();

        // Create .whl file
        let whl_path = temp_dir.path().join("package.whl");
        let file = File::create(&whl_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default();

        zip.start_file("package/__init__.py", options).unwrap();
        std::io::Write::write_all(&mut zip, b"import os; os.system('evil')").unwrap();

        zip.start_file("package-1.0.0.dist-info/METADATA", options)
            .unwrap();
        std::io::Write::write_all(&mut zip, b"Name: package").unwrap();

        zip.finish().unwrap();

        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&whl_path);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(!report.archive_contents.is_empty());
        assert!(report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("__init__.py")));
    }

    #[test]
    fn test_extract_7z() {
        // Create a 7z archive
        let temp_dir = tempfile::tempdir().unwrap();
        let sz_path = temp_dir.path().join("archive.7z");

        // Create a simple file to compress
        let src_dir = temp_dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        let test_file = src_dir.join("test.txt");
        fs::write(&test_file, b"test content").unwrap();

        // Use sevenz_rust to create the archive
        use sevenz_rust::SevenZWriter;
        let mut sz = SevenZWriter::create(&sz_path).unwrap();
        // Push the source directory to get proper paths
        sz.push_source_path(&src_dir, |_| true).unwrap();
        sz.finish().unwrap();

        // Analyze the 7z
        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&sz_path);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.target.file_type, "7z");
        assert!(!report.archive_contents.is_empty());
        assert!(report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("test.txt")));
    }

    #[test]
    fn test_7z_mislabeled_zip() {
        // Test that a ZIP file with .7z extension is handled correctly
        let temp_dir = tempfile::tempdir().unwrap();
        let mislabeled_path = temp_dir.path().join("actually_a_zip.7z");

        // Create a ZIP archive but save it with .7z extension
        let file = File::create(&mislabeled_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"test content from zip").unwrap();
        zip.finish().unwrap();

        // Verify the file starts with ZIP magic bytes
        let mut file = File::open(&mislabeled_path).unwrap();
        let mut magic = [0u8; 4];
        std::io::Read::read_exact(&mut file, &mut magic).unwrap();
        assert_eq!(magic, [0x50, 0x4B, 0x03, 0x04]); // PK\x03\x04

        // Analyze the mislabeled archive - should succeed
        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&mislabeled_path);

        assert!(
            result.is_ok(),
            "Failed to analyze mislabeled .7z: {:?}",
            result.err()
        );
        let report = result.unwrap();
        assert!(!report.archive_contents.is_empty());
        assert!(report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("test.txt")));
    }

    #[test]
    fn test_7z_size_limit_protection() {
        // Test that 7z respects file size limits
        let temp_dir = tempfile::tempdir().unwrap();
        let sz_path = temp_dir.path().join("large.7z");

        // Create a file that's too large (> 100MB would be caught)
        let src_dir = temp_dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        let large_file = src_dir.join("huge.bin");

        // Create a 101MB file
        let large_data = vec![0u8; 101 * 1024 * 1024];
        fs::write(&large_file, large_data).unwrap();

        use sevenz_rust::SevenZWriter;
        let mut sz = SevenZWriter::create(&sz_path).unwrap();
        // Push the directory to properly archive the large file
        sz.push_source_path(&src_dir, |_| true).unwrap();
        sz.finish().unwrap();

        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&sz_path);

        // Should succeed but flag the oversized file
        assert!(result.is_ok());
        let report = result.unwrap();

        // Should have detected excessive file size
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "anti-analysis/archive/large-file"
                && f.desc.contains("excessively large file")));
    }
}
