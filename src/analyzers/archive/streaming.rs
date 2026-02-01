//! Streaming archive analysis with in-memory extraction.
//!
//! This module provides streaming analysis of archives where files are extracted
//! to memory (for files under MAX_MEMORY_FILE_SIZE) and analyzed in parallel via
//! a producer-consumer pattern.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐   bounded channel    ┌─────────────────┐     ┌────────┐
//! │    Extractor    │ ── ExtractedFile ──→ │   Rayon Pool    │ ──→ │ Output │
//! │   (1 thread)    │    (32 capacity)     │  (N analyzers)  │     │        │
//! └─────────────────┘                      └─────────────────┘     └────────┘
//! ```
//!
//! Files under 256MB are extracted to memory buffers, avoiding disk I/O for 99%
//! of typical files. Larger files are extracted to temp files.

use crate::analyzers::{detect_file_type, Analyzer, FileType};
use crate::types::*;
use anyhow::Result;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::guards::{sanitize_entry_path, ExtractionGuard, HostileArchiveReason, MAX_FILE_SIZE};
use super::utils::calculate_sha256;
use super::ArchiveAnalyzer;

/// Maximum file size to keep in memory (256 MB)
pub const MAX_MEMORY_FILE_SIZE: u64 = 256 * 1024 * 1024;

/// Extracted file ready for analysis
#[derive(Debug)]
pub enum ExtractedFile {
    /// File extracted to memory buffer (most files)
    InMemory {
        /// Relative path in archive (e.g., "lib/foo.so")
        path: String,
        /// File contents
        data: Vec<u8>,
        /// Detected file type
        file_type: FileType,
    },
    /// Large file or nested archive extracted to disk
    OnDisk {
        /// Relative path in archive
        path: String,
        /// Temp file location
        temp_path: PathBuf,
        /// Detected file type
        file_type: FileType,
    },
}

impl ExtractedFile {
    /// Get the relative path within the archive
    pub fn path(&self) -> &str {
        match self {
            ExtractedFile::InMemory { path, .. } => path,
            ExtractedFile::OnDisk { path, .. } => path,
        }
    }

    /// Get the file type
    pub fn file_type(&self) -> &FileType {
        match self {
            ExtractedFile::InMemory { file_type, .. } => file_type,
            ExtractedFile::OnDisk { file_type, .. } => file_type,
        }
    }

    /// Get the data if in-memory, None if on-disk
    pub fn data(&self) -> Option<&[u8]> {
        match self {
            ExtractedFile::InMemory { data, .. } => Some(data),
            ExtractedFile::OnDisk { .. } => None,
        }
    }
}

/// Result of analyzing a single file within an archive
#[derive(Debug)]
pub struct StreamingFileResult {
    /// Relative path within archive
    pub path: String,
    /// File analysis converted to FileAnalysis for v2 schema
    pub file_analysis: FileAnalysis,
    /// Any nested files (from nested archives)
    pub nested_files: Vec<FileAnalysis>,
}

impl ArchiveAnalyzer {
    /// Analyze file from in-memory buffer (no disk I/O).
    ///
    /// This is the core analysis function for streaming. It operates entirely
    /// on the provided byte buffer, using YARA's scan_bytes, tree-sitter parsing
    /// on byte slices, and string extraction on raw bytes.
    pub fn analyze_in_memory(
        &self,
        relative_path: &str,
        data: &[u8],
        file_type: &FileType,
    ) -> Result<StreamingFileResult> {
        let sha256 = calculate_sha256(data);
        let size = data.len() as u64;

        // Create base FileAnalysis
        let mut file_analysis = FileAnalysis::new(
            0, // ID will be assigned later when aggregating
            self.format_entry_path(relative_path),
            format!("{:?}", file_type).to_lowercase(),
            sha256,
            size,
        );
        file_analysis.depth = (self.current_depth + 1) as u32;

        let mut nested_files = Vec::new();

        // Run YARA scan on bytes if engine is available
        if let Some(ref yara_engine) = self.yara_engine {
            match yara_engine.scan_bytes(data) {
                Ok(matches) => {
                    file_analysis.yara_matches = matches;
                }
                Err(e) => {
                    tracing::debug!("YARA scan failed for {}: {}", relative_path, e);
                }
            }
        }

        // Route to appropriate analyzer based on file type
        match file_type {
            // Source code files - use unified analyzer with in-memory parsing
            FileType::Shell
            | FileType::Batch
            | FileType::Python
            | FileType::JavaScript
            | FileType::TypeScript
            | FileType::Go
            | FileType::Rust
            | FileType::Java
            | FileType::Ruby
            | FileType::C
            | FileType::Php
            | FileType::Swift
            | FileType::ObjectiveC
            | FileType::Scala
            | FileType::Lua
            | FileType::Perl
            | FileType::PowerShell
            | FileType::CSharp
            | FileType::Groovy
            | FileType::Zig
            | FileType::Elixir
            | FileType::AppleScript => {
                // Use the unified analyzer for source code
                if let Some(mapper) = &self.capability_mapper {
                    // Create a temporary file for analysis since unified analyzer needs a path
                    // TODO: Refactor unified analyzer to support in-memory analysis
                    let temp = tempfile::NamedTempFile::new()?;
                    std::fs::write(temp.path(), data)?;

                    if let Some(analyzer) =
                        crate::analyzers::analyzer_for_file_type(file_type, Some(mapper.clone()))
                    {
                        if let Ok(report) = analyzer.analyze(temp.path()) {
                            // Extract findings and other info from report
                            file_analysis.findings = report.findings;
                            file_analysis.strings = report.strings;
                            file_analysis.imports = report.imports;
                            file_analysis.exports = report.exports;
                            file_analysis.functions = report.functions;
                        }
                    }
                }
            }

            // Binary files - need temp file for goblin parsing
            FileType::Elf | FileType::MachO | FileType::Pe => {
                if let Some(mapper) = &self.capability_mapper {
                    let temp = tempfile::NamedTempFile::new()?;
                    std::fs::write(temp.path(), data)?;

                    if let Some(analyzer) =
                        crate::analyzers::analyzer_for_file_type(file_type, Some(mapper.clone()))
                    {
                        if let Ok(report) = analyzer.analyze(temp.path()) {
                            file_analysis.findings = report.findings;
                            file_analysis.strings = report.strings;
                            file_analysis.imports = report.imports;
                            file_analysis.exports = report.exports;
                            file_analysis.functions = report.functions;
                            file_analysis.sections = report.sections;
                            file_analysis.syscalls = report.syscalls;
                        }
                    }
                }
            }

            // Java class files
            FileType::JavaClass => {
                if let Some(mapper) = &self.capability_mapper {
                    let temp = tempfile::NamedTempFile::new()?;
                    std::fs::write(temp.path(), data)?;

                    let analyzer = crate::analyzers::java_class::JavaClassAnalyzer::new()
                        .with_capability_mapper(mapper.clone());
                    if let Ok(report) = analyzer.analyze(temp.path()) {
                        file_analysis.findings = report.findings;
                        file_analysis.strings = report.strings;
                        file_analysis.imports = report.imports;
                    }
                }
            }

            // Nested archives - need recursive handling
            FileType::Archive | FileType::Jar => {
                if self.current_depth + 1 < self.max_depth {
                    // For nested archives, we need to write to temp and recurse
                    // In-memory parsing of archives is complex due to seeking requirements
                    let temp = tempfile::NamedTempFile::new()?;
                    std::fs::write(temp.path(), data)?;

                    let nested_prefix = match &self.archive_path_prefix {
                        Some(prefix) => format!("{}!{}", prefix, relative_path),
                        None => relative_path.to_string(),
                    };

                    let mut nested_analyzer = ArchiveAnalyzer::new()
                        .with_depth(self.current_depth + 1)
                        .with_archive_prefix(nested_prefix);

                    if let Some(ref mapper) = self.capability_mapper {
                        nested_analyzer = nested_analyzer.with_capability_mapper(mapper.clone());
                    }
                    if let Some(ref engine) = self.yara_engine {
                        nested_analyzer = nested_analyzer.with_yara_arc(engine.clone());
                    }
                    if !self.zip_passwords.is_empty() {
                        nested_analyzer =
                            nested_analyzer.with_zip_passwords(self.zip_passwords.clone());
                    }

                    if let Ok(report) = nested_analyzer.analyze(temp.path()) {
                        // Merge nested findings
                        file_analysis.findings = report.findings;

                        // Add nested files to results
                        for nested_file in report.files {
                            nested_files.push(nested_file);
                        }
                    }
                }
            }

            // Package manifests
            FileType::PackageJson => {
                if let Some(mapper) = &self.capability_mapper {
                    let temp = tempfile::NamedTempFile::new()?;
                    std::fs::write(temp.path(), data)?;

                    let analyzer = crate::analyzers::package_json::PackageJsonAnalyzer::new()
                        .with_capability_mapper(mapper.clone());
                    if let Ok(report) = analyzer.analyze(temp.path()) {
                        file_analysis.findings = report.findings;
                    }
                }
            }

            FileType::VsixManifest => {
                if let Some(mapper) = &self.capability_mapper {
                    let temp = tempfile::NamedTempFile::new()?;
                    std::fs::write(temp.path(), data)?;

                    let analyzer = crate::analyzers::vsix_manifest::VsixManifestAnalyzer::new()
                        .with_capability_mapper(mapper.clone());
                    if let Ok(report) = analyzer.analyze(temp.path()) {
                        file_analysis.findings = report.findings;
                    }
                }
            }

            // Unknown/unsupported - just extract strings
            FileType::Unknown => {
                // Extract basic strings using our string extractor
                let extractor = crate::strings::StringExtractor::new().with_min_length(6);
                file_analysis.strings = extractor.extract_smart(data);
            }
        }

        // Compute summary
        file_analysis.compute_summary();

        Ok(StreamingFileResult {
            path: relative_path.to_string(),
            file_analysis,
            nested_files,
        })
    }

    /// Extract a TAR entry to memory, returning an ExtractedFile.
    ///
    /// If the entry is larger than MAX_MEMORY_FILE_SIZE or is a nested archive,
    /// it will be written to a temp file instead.
    pub(crate) fn extract_tar_entry_to_memory<R: Read>(
        entry: &mut tar::Entry<R>,
        entry_name: &str,
        temp_dir: &Path,
        guard: &ExtractionGuard,
    ) -> Result<Option<ExtractedFile>> {
        let size = entry.header().size()?;

        // Check file size limit
        if size > MAX_FILE_SIZE {
            guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                file: entry_name.to_string(),
                size,
            });
            return Ok(None);
        }

        // Check if this is a directory or special file
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            return Ok(None);
        }
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(entry_name.to_string()));
            return Ok(None);
        }
        if !entry_type.is_file() {
            return Ok(None);
        }

        // Detect file type from name first (we'll verify with magic bytes)
        let path = Path::new(entry_name);
        let file_type = detect_file_type(path).unwrap_or(FileType::Unknown);

        // Decide: in-memory or on-disk?
        let use_disk =
            size > MAX_MEMORY_FILE_SIZE || matches!(file_type, FileType::Archive | FileType::Jar);

        if use_disk {
            // Extract to temp file
            let sanitized = sanitize_entry_path(entry_name, temp_dir);
            if sanitized.is_none() {
                guard.add_hostile_reason(HostileArchiveReason::PathTraversal(
                    entry_name.to_string(),
                ));
                return Ok(None);
            }
            let out_path = sanitized.unwrap();

            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let mut outfile = std::fs::File::create(&out_path)?;
            std::io::copy(entry, &mut outfile)?;

            // Track bytes
            if !guard.check_bytes(size, entry_name) {
                return Ok(None);
            }

            Ok(Some(ExtractedFile::OnDisk {
                path: entry_name.to_string(),
                temp_path: out_path,
                file_type,
            }))
        } else {
            // Extract to memory
            let mut data = Vec::with_capacity(size as usize);
            entry.read_to_end(&mut data)?;

            // Track bytes
            if !guard.check_bytes(data.len() as u64, entry_name) {
                return Ok(None);
            }

            // Re-detect file type with actual data (magic bytes)
            let actual_type = if data.len() >= 4 {
                detect_file_type_from_magic(&data).unwrap_or(file_type)
            } else {
                file_type
            };

            Ok(Some(ExtractedFile::InMemory {
                path: entry_name.to_string(),
                data,
                file_type: actual_type,
            }))
        }
    }

    /// Extract a ZIP entry to memory, returning an ExtractedFile.
    pub(crate) fn extract_zip_entry_to_memory(
        entry: &mut zip::read::ZipFile<'_>,
        temp_dir: &Path,
        guard: &ExtractionGuard,
    ) -> Result<Option<ExtractedFile>> {
        let entry_name = entry.name().to_string();
        let size = entry.size();

        // Check if directory
        if entry.is_dir() {
            return Ok(None);
        }

        // Check file size limit
        if size > MAX_FILE_SIZE {
            guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                file: entry_name.clone(),
                size,
            });
            return Ok(None);
        }

        // Check for symlinks via unix mode
        if let Some(mode) = entry.unix_mode() {
            if mode & 0o170000 == 0o120000 {
                guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(entry_name.clone()));
                return Ok(None);
            }
        }

        // Check compression ratio (zip bomb detection)
        let compressed = entry.compressed_size();
        if !guard.check_compression_ratio(compressed, size) {
            return Ok(None);
        }

        // Detect file type from name
        let path = Path::new(&entry_name);
        let file_type = detect_file_type(path).unwrap_or(FileType::Unknown);

        // Decide: in-memory or on-disk?
        let use_disk =
            size > MAX_MEMORY_FILE_SIZE || matches!(file_type, FileType::Archive | FileType::Jar);

        if use_disk {
            // Extract to temp file
            let sanitized = sanitize_entry_path(&entry_name, temp_dir);
            if sanitized.is_none() {
                guard.add_hostile_reason(HostileArchiveReason::PathTraversal(entry_name.clone()));
                return Ok(None);
            }
            let out_path = sanitized.unwrap();

            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let mut outfile = std::fs::File::create(&out_path)?;
            std::io::copy(entry, &mut outfile)?;

            // Track bytes
            if !guard.check_bytes(size, &entry_name) {
                return Ok(None);
            }

            Ok(Some(ExtractedFile::OnDisk {
                path: entry_name,
                temp_path: out_path,
                file_type,
            }))
        } else {
            // Extract to memory
            let mut data = Vec::with_capacity(size as usize);
            entry.read_to_end(&mut data)?;

            // Track bytes
            if !guard.check_bytes(data.len() as u64, &entry_name) {
                return Ok(None);
            }

            // Re-detect file type with actual data
            let actual_type = if data.len() >= 4 {
                detect_file_type_from_magic(&data).unwrap_or(file_type)
            } else {
                file_type
            };

            Ok(Some(ExtractedFile::InMemory {
                path: entry_name,
                data,
                file_type: actual_type,
            }))
        }
    }

    /// Analyze a TAR archive with streaming extraction and parallel analysis.
    ///
    /// Uses a producer-consumer pattern:
    /// - Producer thread: Reads TAR entries sequentially, extracts to memory
    /// - Consumer pool: Rayon parallel iterator analyzes files concurrently
    ///
    /// The callback `on_file` is invoked for each file as it completes analysis,
    /// enabling real-time streaming output.
    ///
    /// # Arguments
    /// * `archive_path` - Path to the TAR archive (may be compressed)
    /// * `on_file` - Callback invoked for each analyzed file
    ///
    /// # Returns
    /// An ArchiveSummary with aggregate statistics
    pub fn analyze_tar_streaming<F>(
        &self,
        archive_path: &Path,
        on_file: F,
    ) -> Result<ArchiveSummary>
    where
        F: Fn(StreamingFileResult) + Send + Sync,
    {
        use crossbeam_channel::bounded;
        use rayon::prelude::*;
        use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

        let start = std::time::Instant::now();

        // Detect compression type
        let compression = super::utils::detect_tar_compression(archive_path);

        // Create temp dir for large files
        let temp_dir = tempfile::tempdir()?;

        // Create extraction guard
        let guard = ExtractionGuard::new();

        // Bounded channel (32 items) for backpressure
        let (tx, rx) = bounded::<ExtractedFile>(32);

        // Statistics
        let files_analyzed = AtomicU32::new(0);
        let hostile_count = AtomicU32::new(0);
        let suspicious_count = AtomicU32::new(0);
        let notable_count = AtomicU32::new(0);
        let total_bytes = AtomicU64::new(0);

        // Clone self for the producer thread
        let archive_path = archive_path.to_path_buf();
        let temp_dir_path = temp_dir.path().to_path_buf();

        // Spawn extractor thread
        let extractor_handle = std::thread::spawn(move || -> Result<Vec<HostileArchiveReason>> {
            let file = std::fs::File::open(&archive_path)?;

            let reader: Box<dyn Read + Send> = match compression.as_deref() {
                Some("gzip") => Box::new(flate2::read::GzDecoder::new(file)),
                Some("bzip2") => Box::new(bzip2::read::BzDecoder::new(file)),
                Some("xz") => Box::new(xz2::read::XzDecoder::new(file)),
                _ => Box::new(file),
            };

            let mut archive = tar::Archive::new(reader);

            for entry_result in archive.entries()? {
                // Check file count limit
                if !guard.check_file_count() {
                    break;
                }

                let mut entry = match entry_result {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::debug!("Failed to read TAR entry: {}", e);
                        continue;
                    }
                };

                let entry_name = match entry.path() {
                    Ok(p) => p.to_string_lossy().to_string(),
                    Err(e) => {
                        tracing::debug!("Failed to get entry path: {}", e);
                        continue;
                    }
                };

                // Extract to memory or disk
                match ArchiveAnalyzer::extract_tar_entry_to_memory(
                    &mut entry,
                    &entry_name,
                    &temp_dir_path,
                    &guard,
                ) {
                    Ok(Some(extracted)) => {
                        // Send to analysis pool - if channel is full, this blocks (backpressure)
                        if tx.send(extracted).is_err() {
                            // Receiver dropped, stop extraction
                            break;
                        }
                    }
                    Ok(None) => {
                        // Skipped (directory, symlink, etc.)
                    }
                    Err(e) => {
                        tracing::debug!("Failed to extract {}: {}", entry_name, e);
                    }
                }
            }

            // Drop sender to signal completion
            drop(tx);

            Ok(guard.take_reasons())
        });

        // Analyze files in parallel using rayon
        let on_file_ref = &on_file;
        let files_analyzed_ref = &files_analyzed;
        let hostile_count_ref = &hostile_count;
        let suspicious_count_ref = &suspicious_count;
        let notable_count_ref = &notable_count;
        let total_bytes_ref = &total_bytes;

        rx.into_iter().par_bridge().for_each(|file| {
            // Analyze the file
            let result = match &file {
                ExtractedFile::InMemory {
                    path,
                    data,
                    file_type,
                } => {
                    total_bytes_ref.fetch_add(data.len() as u64, Ordering::Relaxed);
                    self.analyze_in_memory(path, data, file_type)
                }
                ExtractedFile::OnDisk {
                    path,
                    temp_path,
                    file_type,
                } => {
                    // Read from disk and analyze
                    match std::fs::read(temp_path) {
                        Ok(data) => {
                            total_bytes_ref.fetch_add(data.len() as u64, Ordering::Relaxed);
                            self.analyze_in_memory(path, &data, file_type)
                        }
                        Err(e) => Err(anyhow::anyhow!("Failed to read temp file: {}", e)),
                    }
                }
            };

            match result {
                Ok(file_result) => {
                    files_analyzed_ref.fetch_add(1, Ordering::Relaxed);

                    // Update statistics from findings
                    if let Some(risk) = &file_result.file_analysis.risk {
                        match risk {
                            crate::types::Criticality::Hostile => {
                                hostile_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            crate::types::Criticality::Suspicious => {
                                suspicious_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            crate::types::Criticality::Notable => {
                                notable_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {}
                        }
                    }

                    // Invoke callback for streaming output
                    on_file_ref(file_result);
                }
                Err(e) => {
                    tracing::debug!("Failed to analyze {}: {}", file.path(), e);
                }
            }
        });

        // Wait for extractor to finish and get hostile reasons
        let hostile_reasons = extractor_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Extractor thread panicked"))??;

        Ok(ArchiveSummary {
            files_analyzed: files_analyzed.load(Ordering::Relaxed),
            hostile: hostile_count.load(Ordering::Relaxed),
            suspicious: suspicious_count.load(Ordering::Relaxed),
            notable: notable_count.load(Ordering::Relaxed),
            total_bytes: total_bytes.load(Ordering::Relaxed),
            hostile_reasons,
            analysis_duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Analyze a ZIP archive with streaming extraction and parallel analysis.
    ///
    /// Uses the same producer-consumer pattern as TAR streaming.
    /// Note: ZIP requires reading the central directory first, so there's
    /// a small initial delay before streaming begins.
    pub fn analyze_zip_streaming<F>(
        &self,
        archive_path: &Path,
        on_file: F,
    ) -> Result<ArchiveSummary>
    where
        F: Fn(StreamingFileResult) + Send + Sync,
    {
        use crossbeam_channel::bounded;
        use rayon::prelude::*;
        use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

        let start = std::time::Instant::now();

        // Create temp dir for large files
        let temp_dir = tempfile::tempdir()?;

        // Create extraction guard
        let guard = ExtractionGuard::new();

        // Bounded channel (32 items) for backpressure
        let (tx, rx) = bounded::<ExtractedFile>(32);

        // Statistics
        let files_analyzed = AtomicU32::new(0);
        let hostile_count = AtomicU32::new(0);
        let suspicious_count = AtomicU32::new(0);
        let notable_count = AtomicU32::new(0);
        let total_bytes = AtomicU64::new(0);

        // Clone for the producer thread
        let archive_path = archive_path.to_path_buf();
        let temp_dir_path = temp_dir.path().to_path_buf();
        let zip_passwords = self.zip_passwords.clone();

        // Spawn extractor thread
        let extractor_handle = std::thread::spawn(move || -> Result<Vec<HostileArchiveReason>> {
            let file = std::fs::File::open(&archive_path)?;
            let mut archive = zip::ZipArchive::new(file)?;

            // Try to determine if encrypted
            let password = if !archive.is_empty() {
                let mut found_password: Option<&[u8]> = None;
                for i in 0..archive.len().min(5) {
                    if let Ok(entry) = archive.by_index(i) {
                        if entry.encrypted() {
                            // Use the first password if available
                            if let Some(pw) = zip_passwords.first() {
                                found_password = Some(pw.as_bytes());
                            }
                            break;
                        }
                    }
                }
                found_password
            } else {
                None
            };

            for i in 0..archive.len() {
                // Check file count limit
                if !guard.check_file_count() {
                    break;
                }

                let mut entry = match password {
                    Some(pw) => match archive.by_index_decrypt(i, pw) {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::debug!("Failed to decrypt ZIP entry {}: {}", i, e);
                            continue;
                        }
                    },
                    None => match archive.by_index(i) {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::debug!("Failed to read ZIP entry {}: {}", i, e);
                            continue;
                        }
                    },
                };

                // Extract to memory or disk
                match ArchiveAnalyzer::extract_zip_entry_to_memory(
                    &mut entry,
                    &temp_dir_path,
                    &guard,
                ) {
                    Ok(Some(extracted)) => {
                        if tx.send(extracted).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!("Failed to extract ZIP entry: {}", e);
                    }
                }
            }

            drop(tx);
            Ok(guard.take_reasons())
        });

        // Analyze files in parallel
        let on_file_ref = &on_file;
        let files_analyzed_ref = &files_analyzed;
        let hostile_count_ref = &hostile_count;
        let suspicious_count_ref = &suspicious_count;
        let notable_count_ref = &notable_count;
        let total_bytes_ref = &total_bytes;

        rx.into_iter().par_bridge().for_each(|file| {
            let result = match &file {
                ExtractedFile::InMemory {
                    path,
                    data,
                    file_type,
                } => {
                    total_bytes_ref.fetch_add(data.len() as u64, Ordering::Relaxed);
                    self.analyze_in_memory(path, data, file_type)
                }
                ExtractedFile::OnDisk {
                    path,
                    temp_path,
                    file_type,
                } => match std::fs::read(temp_path) {
                    Ok(data) => {
                        total_bytes_ref.fetch_add(data.len() as u64, Ordering::Relaxed);
                        self.analyze_in_memory(path, &data, file_type)
                    }
                    Err(e) => Err(anyhow::anyhow!("Failed to read temp file: {}", e)),
                },
            };

            match result {
                Ok(file_result) => {
                    files_analyzed_ref.fetch_add(1, Ordering::Relaxed);

                    if let Some(risk) = &file_result.file_analysis.risk {
                        match risk {
                            crate::types::Criticality::Hostile => {
                                hostile_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            crate::types::Criticality::Suspicious => {
                                suspicious_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            crate::types::Criticality::Notable => {
                                notable_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {}
                        }
                    }

                    on_file_ref(file_result);
                }
                Err(e) => {
                    tracing::debug!("Failed to analyze {}: {}", file.path(), e);
                }
            }
        });

        let hostile_reasons = extractor_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Extractor thread panicked"))??;

        Ok(ArchiveSummary {
            files_analyzed: files_analyzed.load(Ordering::Relaxed),
            hostile: hostile_count.load(Ordering::Relaxed),
            suspicious: suspicious_count.load(Ordering::Relaxed),
            notable: notable_count.load(Ordering::Relaxed),
            total_bytes: total_bytes.load(Ordering::Relaxed),
            hostile_reasons,
            analysis_duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}

/// Summary of streaming archive analysis
#[derive(Debug)]
pub struct ArchiveSummary {
    /// Number of files successfully analyzed
    pub files_analyzed: u32,
    /// Count of files with hostile findings
    pub hostile: u32,
    /// Count of files with suspicious findings
    pub suspicious: u32,
    /// Count of files with notable findings
    pub notable: u32,
    /// Total bytes analyzed
    pub total_bytes: u64,
    /// Any hostile archive reasons detected during extraction
    pub hostile_reasons: Vec<HostileArchiveReason>,
    /// Total analysis duration in milliseconds
    pub analysis_duration_ms: u64,
}

/// Detect file type from magic bytes (first 4+ bytes of data)
fn detect_file_type_from_magic(data: &[u8]) -> Option<FileType> {
    if data.len() < 4 {
        return None;
    }

    // Check magic bytes
    // Note: 0xCAFEBABE is used by both Java class files and Mach-O FAT binaries
    // Java class files have a major/minor version in bytes 6-7 that is non-zero
    // Mach-O FAT has the number of architectures in bytes 4-7
    if data.len() >= 8 && data[0..4] == [0xca, 0xfe, 0xba, 0xbe] {
        // Check if this looks like Java (version bytes are reasonable)
        let major = u16::from_be_bytes([data[6], data[7]]);
        // Java class files have major versions like 45-65 (Java 1.1 to Java 21)
        // Mach-O FAT would have very small values (number of architectures, typically 1-4)
        if (45..=70).contains(&major) {
            return Some(FileType::JavaClass);
        } else {
            return Some(FileType::MachO);
        }
    }

    match &data[0..4] {
        // ELF
        [0x7f, b'E', b'L', b'F'] => Some(FileType::Elf),
        // Mach-O
        [0xfe, 0xed, 0xfa, 0xce] | [0xce, 0xfa, 0xed, 0xfe] => Some(FileType::MachO),
        // Mach-O 64-bit
        [0xfe, 0xed, 0xfa, 0xcf] | [0xcf, 0xfa, 0xed, 0xfe] => Some(FileType::MachO),
        // Mach-O FAT (reversed)
        [0xbe, 0xba, 0xfe, 0xca] => Some(FileType::MachO),
        // PE
        [b'M', b'Z', ..] => Some(FileType::Pe),
        // ZIP/JAR
        [b'P', b'K', 0x03, 0x04] | [b'P', b'K', 0x05, 0x06] => {
            // Could be ZIP or JAR - check extension or contents
            Some(FileType::Archive)
        }
        // Gzip
        [0x1f, 0x8b, ..] => Some(FileType::Archive),
        // XZ
        [0xfd, b'7', b'z', b'X'] => Some(FileType::Archive),
        // Bzip2
        [b'B', b'Z', b'h', ..] => Some(FileType::Archive),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_file_type_from_magic() {
        // ELF
        let elf_data = [0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        assert_eq!(detect_file_type_from_magic(&elf_data), Some(FileType::Elf));

        // MachO 32-bit
        let macho32_data = [0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 0];
        assert_eq!(
            detect_file_type_from_magic(&macho32_data),
            Some(FileType::MachO)
        );

        // PE
        let pe_data = [b'M', b'Z', 0, 0, 0, 0, 0, 0];
        assert_eq!(detect_file_type_from_magic(&pe_data), Some(FileType::Pe));

        // ZIP
        let zip_data = [b'P', b'K', 0x03, 0x04, 0, 0, 0, 0];
        assert_eq!(
            detect_file_type_from_magic(&zip_data),
            Some(FileType::Archive)
        );

        // Unknown
        let unknown_data = [0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(detect_file_type_from_magic(&unknown_data), None);
    }
}
