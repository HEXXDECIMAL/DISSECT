use crate::config::{validation, ArchiveLimits};
use crate::error::{DivineError, Result};
use std::fs::File;
use std::path::{Component, Path};
use tempfile::TempDir;
use tracing::{debug, warn};

/// Secure archive extractor with protection against common archive vulnerabilities
pub struct ArchiveExtractor {
    temp_dir: TempDir,
    limits: ArchiveLimits,
    files_extracted: usize,
    total_size_extracted: u64,
    current_depth: usize,
}

impl ArchiveExtractor {
    /// Create a new archive extractor with default security limits
    pub fn new() -> Result<Self> {
        Self::with_limits(ArchiveLimits::default())
    }

    /// Create an archive extractor with custom security limits
    pub fn with_limits(limits: ArchiveLimits) -> Result<Self> {
        Ok(Self {
            temp_dir: TempDir::new()
                .map_err(|e| DivineError::archive_extraction(format!("Failed to create temporary directory: {e}")))?,
            limits,
            files_extracted: 0,
            total_size_extracted: 0,
            current_depth: 0,
        })
    }

    /// Validate and sanitize a filename for extraction
    fn sanitize_filename(&self, filename: &str) -> Result<String> {
        validation::validate_filename(filename)?;

        let mut sanitized = String::new();
        for component in Path::new(filename).components() {
            match component {
                Component::Normal(name) => {
                    let name_str = name.to_string_lossy();
                    if sanitized.is_empty() {
                        sanitized = name_str.into();
                    } else {
                        sanitized.push('_');
                        sanitized.push_str(&name_str);
                    }
                }
                Component::ParentDir => {
                    return Err(DivineError::directory_traversal(format!(
                        "Directory traversal attempt in filename: {filename}"
                    )));
                }
                _ => {
                    // Skip root, current dir, etc.
                }
            }
        }

        if sanitized.is_empty() {
            sanitized = format!("file_{}", self.files_extracted);
        }

        // Ensure filename isn't too long
        if sanitized.len() > 200 {
            sanitized.truncate(200);
            sanitized.push('_');
            sanitized.push_str(&self.files_extracted.to_string());
        }

        Ok(sanitized)
    }

    /// Check security limits before extraction
    fn check_extraction_limits(&self, file_size: u64) -> Result<()> {
        self.limits.check_limits(
            self.files_extracted + 1,
            self.total_size_extracted + file_size,
            self.current_depth,
        )?;

        validation::validate_file_size(file_size, self.limits.max_file_size)?;

        Ok(())
    }

    /// Update extraction state after successful extraction
    fn update_extraction_state(&mut self, file_size: u64) {
        self.files_extracted += 1;
        self.total_size_extracted += file_size;
        debug!(
            "Extracted file {}: {} bytes (total: {} bytes, {} files)",
            self.files_extracted, file_size, self.total_size_extracted, self.files_extracted
        );
    }

    pub fn extract_zip<P: AsRef<Path>>(&mut self, zip_path: P) -> Result<Vec<String>> {
        let zip_path = zip_path.as_ref();
        debug!("Extracting ZIP archive: {}", zip_path.display());

        let file = File::open(zip_path).map_err(|e| {
            DivineError::archive_extraction(format!("Failed to open ZIP file {}: {e}", zip_path.display()))
        })?;

        let mut archive = zip::ZipArchive::new(file).map_err(|e| {
            DivineError::archive_extraction(format!("Failed to read ZIP archive {}: {e}", zip_path.display()))
        })?;

        let mut extracted_files = Vec::new();

        for i in 0..archive.len() {
            let mut zip_file = archive.by_index(i).map_err(|e| {
                DivineError::archive_extraction(format!("Failed to access file {i} in ZIP archive: {e}"))
            })?;

            if zip_file.is_file() {
                let file_size = zip_file.size();

                // Check security limits before extraction
                self.check_extraction_limits(file_size)?;

                // Sanitize the filename to prevent directory traversal
                let safe_filename = self.sanitize_filename(zip_file.name())?;
                let file_path = self.temp_dir.path().join(&safe_filename);

                debug!("Extracting ZIP file: {} -> {} ({} bytes)", zip_file.name(), safe_filename, file_size);

                let mut out_file = File::create(&file_path).map_err(|e| {
                    DivineError::archive_extraction(format!(
                        "Failed to create extracted file {}: {e}",
                        file_path.display()
                    ))
                })?;

                // Use limited copy to prevent zip bombs
                let mut limited_reader = std::io::Read::take(&mut zip_file, self.limits.max_file_size);
                let bytes_copied = std::io::copy(&mut limited_reader, &mut out_file)
                    .map_err(|e| DivineError::archive_extraction(format!("Failed to extract file from ZIP: {e}")))?;

                if bytes_copied != file_size {
                    warn!("File size mismatch during extraction: expected {}, got {}", file_size, bytes_copied);
                }

                self.update_extraction_state(bytes_copied);
                extracted_files.push(file_path.to_string_lossy().to_string());
            }
        }

        debug!("ZIP extraction completed: {} files, {} total bytes", self.files_extracted, self.total_size_extracted);
        Ok(extracted_files)
    }

    pub fn extract_tar<P: AsRef<Path>>(&mut self, tar_path: P) -> Result<Vec<String>> {
        let tar_path = tar_path.as_ref();
        let file = File::open(tar_path).map_err(|e| {
            DivineError::archive_extraction(format!("Failed to open TAR file {}: {e}", tar_path.display()))
        })?;

        let mut archive = tar::Archive::new(file);
        let mut extracted_files = Vec::new();

        for (i, entry) in archive
            .entries()
            .map_err(|e| DivineError::archive_extraction(format!("Failed to read TAR entries: {e}")))?
            .enumerate()
        {
            let mut entry =
                entry.map_err(|e| DivineError::archive_extraction(format!("Failed to process TAR entry: {e}")))?;

            if entry.header().entry_type().is_file() {
                let safe_path = format!("tar_file_{i}");
                let file_path = self.temp_dir.path().join(safe_path);

                entry
                    .unpack(&file_path)
                    .map_err(|e| DivineError::archive_extraction(format!("Failed to extract TAR file {i}: {e}")))?;

                extracted_files.push(file_path.to_string_lossy().to_string());
            }
        }

        Ok(extracted_files)
    }

    pub fn extract_tar_gz<P: AsRef<Path>>(&mut self, tar_gz_path: P) -> Result<Vec<String>> {
        let tar_gz_path = tar_gz_path.as_ref();
        let file = File::open(tar_gz_path).map_err(|e| {
            DivineError::archive_extraction(format!("Failed to open TAR.GZ file {}: {e}", tar_gz_path.display()))
        })?;

        let gz_decoder = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(gz_decoder);
        let mut extracted_files = Vec::new();

        for (i, entry) in archive
            .entries()
            .map_err(|e| DivineError::archive_extraction(format!("Failed to read TAR.GZ entries: {e}")))?
            .enumerate()
        {
            let mut entry =
                entry.map_err(|e| DivineError::archive_extraction(format!("Failed to process TAR.GZ entry: {e}")))?;

            if entry.header().entry_type().is_file() {
                let safe_path = format!("targz_file_{i}");
                let file_path = self.temp_dir.path().join(safe_path);

                entry
                    .unpack(&file_path)
                    .map_err(|e| DivineError::archive_extraction(format!("Failed to extract TAR.GZ file {i}: {e}")))?;

                extracted_files.push(file_path.to_string_lossy().to_string());
            }
        }

        Ok(extracted_files)
    }

    pub fn extract_archive<P: AsRef<Path>>(&mut self, archive_path: P) -> Result<Vec<String>> {
        let archive_path = archive_path.as_ref();

        archive_path.extension().and_then(|e| e.to_str()).map_or_else(
            || Err(DivineError::unsupported_format("unknown", archive_path.display().to_string())),
            |ext| match ext.to_lowercase().as_str() {
                "zip" => self.extract_zip(archive_path),
                "tar" => self.extract_tar(archive_path),
                "gz" if archive_path.to_string_lossy().ends_with(".tar.gz") => self.extract_tar_gz(archive_path),
                _ => Err(DivineError::unsupported_format(ext, archive_path.display().to_string())),
            },
        )
    }

    #[must_use]
    pub fn temp_path(&self) -> &Path {
        self.temp_dir.path()
    }
}
