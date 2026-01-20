use crate::analyzers::{detect_file_type, Analyzer};
use crate::types::*;
use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Archive analyzer for .zip, .tar.gz, .tgz, etc.
pub struct ArchiveAnalyzer {
    max_depth: usize,
    current_depth: usize,
}

impl ArchiveAnalyzer {
    pub fn new() -> Self {
        Self {
            max_depth: 3,
            current_depth: 0,
        }
    }

    pub fn with_depth(mut self, depth: usize) -> Self {
        self.current_depth = depth;
        self
    }

    fn analyze_archive(&self, file_path: &Path) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Prevent infinite recursion
        if self.current_depth >= self.max_depth {
            anyhow::bail!("Maximum archive depth ({}) exceeded", self.max_depth);
        }

        // Create temporary directory for extraction
        let temp_dir = tempfile::tempdir()
            .context("Failed to create temporary directory")?;

        // Extract archive
        self.extract_archive(file_path, temp_dir.path())?;

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

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: format!("archive/{}", self.detect_archive_type(file_path)),
            description: format!("{} archive", self.detect_archive_type(file_path)),
            evidence: vec![Evidence {
                method: "extension".to_string(),
                source: "archive_analyzer".to_string(),
                value: file_path.extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
                location: None,
            }],
        });

        // Recursively analyze extracted files
        let mut files_analyzed = 0;
        let mut total_capabilities = std::collections::HashSet::new();

        for entry in walkdir::WalkDir::new(temp_dir.path())
            .min_depth(1)
            .max_depth(10)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                if let Ok(file_report) = self.analyze_extracted_file(entry.path()) {
                    files_analyzed += 1;

                    // Aggregate capabilities
                    for cap in &file_report.capabilities {
                        total_capabilities.insert(cap.id.clone());

                        // Add to report if not already present
                        if !report.capabilities.iter().any(|c| c.id == cap.id) {
                            let mut new_cap = cap.clone();
                            // Update evidence to show it came from within the archive
                            for evidence in &mut new_cap.evidence {
                                evidence.location = Some(format!(
                                    "archive:{}",
                                    entry.path().strip_prefix(temp_dir.path())
                                        .unwrap_or(entry.path())
                                        .display()
                                ));
                            }
                            report.capabilities.push(new_cap);
                        }
                    }

                    // Aggregate strings (limit to interesting ones)
                    for string in file_report.strings {
                        if matches!(string.string_type, StringType::Url | StringType::Ip | StringType::Base64) {
                            report.strings.push(string);
                        }
                    }
                }
            }
        }

        // Add metadata about archive contents
        report.metadata.errors.push(format!(
            "Archive contains {} files analyzed, {} unique capabilities detected",
            files_analyzed, total_capabilities.len()
        ));

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["archive_analyzer".to_string(), "walkdir".to_string()];

        Ok(report)
    }

    fn extract_archive(&self, archive_path: &Path, dest_dir: &Path) -> Result<()> {
        let archive_type = self.detect_archive_type(archive_path);

        match archive_type {
            "zip" => self.extract_zip(archive_path, dest_dir),
            "tar" => self.extract_tar(archive_path, dest_dir, None),
            "tar.gz" | "tgz" => self.extract_tar(archive_path, dest_dir, Some("gzip")),
            "tar.bz2" | "tbz" | "tbz2" => self.extract_tar(archive_path, dest_dir, Some("bzip2")),
            "tar.xz" | "txz" => self.extract_tar(archive_path, dest_dir, Some("xz")),
            _ => anyhow::bail!("Unsupported archive type: {}", archive_type),
        }
    }

    fn extract_zip(&self, archive_path: &Path, dest_dir: &Path) -> Result<()> {
        let file = File::open(archive_path)?;
        let mut archive = zip::ZipArchive::new(file)
            .context("Failed to read ZIP archive")?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let outpath = dest_dir.join(file.name());

            if file.is_dir() {
                fs::create_dir_all(&outpath)?;
            } else {
                if let Some(parent) = outpath.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut outfile = File::create(&outpath)?;
                std::io::copy(&mut file, &mut outfile)?;
            }
        }

        Ok(())
    }

    fn extract_tar(&self, archive_path: &Path, dest_dir: &Path, compression: Option<&str>) -> Result<()> {
        let file = File::open(archive_path)?;

        let mut archive: tar::Archive<Box<dyn Read>> = match compression {
            Some("gzip") => {
                let decoder = flate2::read::GzDecoder::new(file);
                tar::Archive::new(Box::new(decoder))
            }
            Some("bzip2") => {
                let decoder = bzip2::read::BzDecoder::new(file);
                tar::Archive::new(Box::new(decoder))
            }
            Some("xz") => {
                let decoder = xz2::read::XzDecoder::new(file);
                tar::Archive::new(Box::new(decoder))
            }
            None => tar::Archive::new(Box::new(file)),
            _ => anyhow::bail!("Unsupported compression: {:?}", compression),
        };

        archive.unpack(dest_dir)
            .context("Failed to extract TAR archive")?;

        Ok(())
    }

    fn analyze_extracted_file(&self, file_path: &Path) -> Result<AnalysisReport> {
        // Detect file type
        let file_type = detect_file_type(file_path)?;

        // Route to appropriate analyzer
        match file_type {
            crate::analyzers::FileType::MachO => {
                let analyzer = crate::analyzers::macho::MachOAnalyzer::new();
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::Elf => {
                let analyzer = crate::analyzers::elf::ElfAnalyzer::new();
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::Pe => {
                let analyzer = crate::analyzers::pe::PEAnalyzer::new();
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::ShellScript => {
                let analyzer = crate::analyzers::shell::ShellAnalyzer::new();
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::Python => {
                let analyzer = crate::analyzers::python::PythonAnalyzer::new();
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::JavaScript => {
                let analyzer = crate::analyzers::javascript::JavaScriptAnalyzer::new();
                analyzer.analyze(file_path)
            }
            _ => {
                // Skip unknown files
                Err(anyhow::anyhow!("Unsupported file type"))
            }
        }
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
        } else if path_str.ends_with(".zip") {
            "zip"
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
        path_str.ends_with(".zip") ||
        path_str.ends_with(".tar") ||
        path_str.ends_with(".tar.gz") ||
        path_str.ends_with(".tgz") ||
        path_str.ends_with(".tar.bz2") ||
        path_str.ends_with(".tbz2") ||
        path_str.ends_with(".tar.xz") ||
        path_str.ends_with(".txz")
    }
}
