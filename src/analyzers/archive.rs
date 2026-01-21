use crate::analyzers::{detect_file_type, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

/// Archive analyzer for .zip, .tar.gz, .tgz, etc.
pub struct ArchiveAnalyzer {
    max_depth: usize,
    current_depth: usize,
    capability_mapper: Option<CapabilityMapper>,
    yara_engine: Option<Arc<YaraEngine>>,
}

impl ArchiveAnalyzer {
    pub fn new() -> Self {
        Self {
            max_depth: 3,
            current_depth: 0,
            capability_mapper: None,
            yara_engine: None,
        }
    }

    pub fn with_depth(mut self, depth: usize) -> Self {
        self.current_depth = depth;
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

    fn analyze_archive(&self, file_path: &Path) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Prevent infinite recursion
        if self.current_depth >= self.max_depth {
            anyhow::bail!("Maximum archive depth ({}) exceeded", self.max_depth);
        }

        // Create temporary directory for extraction
        let temp_dir = tempfile::tempdir().context("Failed to create temporary directory")?;

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
                value: file_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
                location: None,
            }],
        });

        // Recursively analyze extracted files
        let mut files_analyzed = 0;
        let mut total_capabilities = std::collections::HashSet::new();
        let mut total_traits = std::collections::HashSet::new();

        for entry in walkdir::WalkDir::new(temp_dir.path())
            .min_depth(1)
            .max_depth(10)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let archive_location = format!(
                    "archive:{}",
                    entry
                        .path()
                        .strip_prefix(temp_dir.path())
                        .unwrap_or(entry.path())
                        .display()
                );

                // Run YARA scan on extracted file if engine is available
                if let Some(ref yara_engine) = self.yara_engine {
                    if let Ok(matches) = yara_engine.scan_file(entry.path()) {
                        for yara_match in matches {
                            if !report
                                .yara_matches
                                .iter()
                                .any(|m| m.rule == yara_match.rule)
                            {
                                report.yara_matches.push(yara_match);
                            }
                        }
                    }
                }

                if let Ok(file_report) = self.analyze_extracted_file(entry.path()) {
                    files_analyzed += 1;

                    // Aggregate traits (from capability mapper)
                    for t in &file_report.traits {
                        total_traits.insert(t.id.clone());

                        // Add to report if not already present
                        if !report.traits.iter().any(|existing| existing.id == t.id) {
                            let mut new_trait = t.clone();
                            // Update evidence to show it came from within the archive
                            for evidence in &mut new_trait.evidence {
                                evidence.location = Some(archive_location.clone());
                            }
                            report.traits.push(new_trait);
                        }
                    }

                    // Aggregate capabilities (from YARA rules)
                    for cap in &file_report.capabilities {
                        total_capabilities.insert(cap.id.clone());

                        // Add to report if not already present
                        if !report.capabilities.iter().any(|c| c.id == cap.id) {
                            let mut new_cap = cap.clone();
                            // Update evidence to show it came from within the archive
                            for evidence in &mut new_cap.evidence {
                                evidence.location = Some(archive_location.clone());
                            }
                            report.capabilities.push(new_cap);
                        }
                    }

                    // Aggregate YARA matches from file report
                    for yara_match in &file_report.yara_matches {
                        if !report
                            .yara_matches
                            .iter()
                            .any(|m| m.rule == yara_match.rule)
                        {
                            report.yara_matches.push(yara_match.clone());
                        }
                    }

                    // Aggregate strings (limit to interesting ones)
                    for string in file_report.strings {
                        if matches!(
                            string.string_type,
                            StringType::Url | StringType::Ip | StringType::Base64
                        ) {
                            report.strings.push(string);
                        }
                    }
                }
            }
        }

        // Add metadata about archive contents
        report.metadata.errors.push(format!(
            "Archive contains {} files analyzed, {} traits and {} capabilities detected",
            files_analyzed,
            total_traits.len(),
            total_capabilities.len()
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
            "xz" => self.extract_compressed(archive_path, dest_dir, "xz"),
            "gz" => self.extract_compressed(archive_path, dest_dir, "gzip"),
            "bz2" => self.extract_compressed(archive_path, dest_dir, "bzip2"),
            _ => anyhow::bail!("Unsupported archive type: {}", archive_type),
        }
    }

    fn extract_compressed(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        compression: &str,
    ) -> Result<()> {
        let file = File::open(archive_path)?;

        // Determine output filename by stripping the compression extension
        let stem = archive_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("extracted");
        let output_path = dest_dir.join(stem);

        let mut output_file = File::create(&output_path).context("Failed to create output file")?;

        match compression {
            "xz" => {
                let mut decoder = xz2::read::XzDecoder::new(file);
                std::io::copy(&mut decoder, &mut output_file)
                    .context("Failed to decompress XZ file")?;
            }
            "gzip" => {
                let mut decoder = flate2::read::GzDecoder::new(file);
                std::io::copy(&mut decoder, &mut output_file)
                    .context("Failed to decompress GZ file")?;
            }
            "bzip2" => {
                let mut decoder = bzip2::read::BzDecoder::new(file);
                std::io::copy(&mut decoder, &mut output_file)
                    .context("Failed to decompress BZ2 file")?;
            }
            _ => anyhow::bail!("Unsupported compression: {}", compression),
        }

        Ok(())
    }

    fn extract_zip(&self, archive_path: &Path, dest_dir: &Path) -> Result<()> {
        let file = File::open(archive_path)?;
        let mut archive = zip::ZipArchive::new(file).context("Failed to read ZIP archive")?;

        for i in 0..archive.len() {
            // Note: ZipArchive requires index-based access as it doesn't implement Iterator
            let mut entry = archive.by_index(i)?;
            let outpath = dest_dir.join(entry.name());

            if entry.is_dir() {
                fs::create_dir_all(&outpath)?;
            } else {
                if let Some(parent) = outpath.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut outfile = File::create(&outpath)?;
                std::io::copy(&mut entry, &mut outfile)?;
            }
        }

        Ok(())
    }

    fn extract_tar(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        compression: Option<&str>,
    ) -> Result<()> {
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

        archive
            .unpack(dest_dir)
            .context("Failed to extract TAR archive")?;

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
            crate::analyzers::FileType::ShellScript => {
                let analyzer = crate::analyzers::shell::ShellAnalyzer::new();
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::Python => {
                let analyzer = crate::analyzers::python::PythonAnalyzer::new();
                analyzer.analyze(file_path)
            }
            crate::analyzers::FileType::JavaScript => {
                let mut analyzer = crate::analyzers::javascript::JavaScriptAnalyzer::new();
                if let Some(ref mapper) = self.capability_mapper {
                    analyzer = analyzer.with_capability_mapper(mapper.clone());
                }
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
        } else if path_str.ends_with(".zip")
            || path_str.ends_with(".jar")
            || path_str.ends_with(".war")
            || path_str.ends_with(".ear")
            || path_str.ends_with(".apk")
            || path_str.ends_with(".aar")
        {
            "zip"
        } else if path_str.ends_with(".xz") {
            "xz"
        } else if path_str.ends_with(".gz") {
            "gz"
        } else if path_str.ends_with(".bz2") {
            "bz2"
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
}
