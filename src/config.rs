use crate::error::{DivineError, Result};
use crate::report::RiskLevel;
use std::time::Duration;

/// Security and performance limits for file scanning operations
pub const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100MB
pub const MAX_ARCHIVE_FILES: usize = 10_000;
pub const MAX_ARCHIVE_TOTAL_SIZE: u64 = 1_024 * 1024 * 1024; // 1GB
pub const MAX_ARCHIVE_DEPTH: usize = 10;
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for archive extraction with security limits
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveLimits {
    /// Maximum number of files that can be extracted from an archive
    pub max_files: usize,
    /// Maximum total size of all extracted files combined
    pub max_total_size: u64,
    /// Maximum nesting depth for archive-within-archive extraction
    pub max_depth: usize,
    /// Maximum size of any individual file within an archive
    pub max_file_size: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_files: MAX_ARCHIVE_FILES,
            max_total_size: MAX_ARCHIVE_TOTAL_SIZE,
            max_depth: MAX_ARCHIVE_DEPTH,
            max_file_size: MAX_FILE_SIZE,
        }
    }
}

impl ArchiveLimits {
    /// Create new archive limits with validation
    pub fn new(max_files: usize, max_total_size: u64, max_depth: usize, max_file_size: u64) -> Result<Self> {
        if max_files == 0 {
            return Err(DivineError::configuration("max_files must be greater than 0"));
        }
        if max_total_size == 0 {
            return Err(DivineError::configuration("max_total_size must be greater than 0"));
        }
        if max_depth == 0 {
            return Err(DivineError::configuration("max_depth must be greater than 0"));
        }
        if max_file_size == 0 {
            return Err(DivineError::configuration("max_file_size must be greater than 0"));
        }

        Ok(Self { max_files, max_total_size, max_depth, max_file_size })
    }

    /// Check if current extraction state violates limits
    pub fn check_limits(&self, files_extracted: usize, total_size_extracted: u64, current_depth: usize) -> Result<()> {
        if files_extracted >= self.max_files {
            return Err(DivineError::archive_limits_exceeded(format!(
                "too many files: {} >= {}",
                files_extracted, self.max_files
            )));
        }

        if total_size_extracted >= self.max_total_size {
            return Err(DivineError::archive_limits_exceeded(format!(
                "total size too large: {} >= {} bytes",
                total_size_extracted, self.max_total_size
            )));
        }

        if current_depth >= self.max_depth {
            return Err(DivineError::archive_limits_exceeded(format!(
                "extraction depth too deep: {} >= {}",
                current_depth, self.max_depth
            )));
        }

        Ok(())
    }
}

/// Configuration for the scanner with validation and security defaults
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub min_risk: RiskLevel,
    pub include_data_files: bool,
    pub max_file_size: u64,
    pub max_concurrent_files: usize,
    pub archive_limits: ArchiveLimits,
    pub scan_timeout: Duration,
    pub follow_symlinks: bool,
    pub scan_hidden_files: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            min_risk: RiskLevel::Low,
            include_data_files: false,
            max_file_size: MAX_FILE_SIZE,
            max_concurrent_files: std::thread::available_parallelism().map(std::num::NonZero::get).unwrap_or(1),
            archive_limits: ArchiveLimits::default(),
            scan_timeout: DEFAULT_TIMEOUT,
            follow_symlinks: false, // Security: don't follow symlinks by default
            scan_hidden_files: false,
        }
    }
}

impl ScanConfig {
    /// Create a new scan configuration with validation
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate the configuration and return errors for invalid settings
    pub fn validate(&self) -> Result<()> {
        if self.max_file_size == 0 {
            return Err(DivineError::configuration("max_file_size must be greater than 0"));
        }

        if self.max_concurrent_files == 0 {
            return Err(DivineError::configuration("max_concurrent_files must be greater than 0"));
        }

        if self.scan_timeout.is_zero() {
            return Err(DivineError::configuration("scan_timeout must be greater than 0"));
        }

        // Validate archive limits
        self.archive_limits.check_limits(0, 0, 0)?;

        Ok(())
    }

    /// Create a high-security configuration with stricter limits
    #[must_use]
    pub const fn high_security() -> Self {
        Self {
            min_risk: RiskLevel::Medium,
            include_data_files: false,
            max_file_size: 10 * 1024 * 1024, // 10MB
            max_concurrent_files: 2,
            archive_limits: ArchiveLimits {
                max_files: 1_000,
                max_total_size: 100 * 1024 * 1024, // 100MB
                max_depth: 3,
                max_file_size: 10 * 1024 * 1024, // 10MB
            },
            scan_timeout: Duration::from_secs(10),
            follow_symlinks: false,
            scan_hidden_files: false,
        }
    }

    /// Create a performance-oriented configuration with relaxed limits
    #[must_use]
    pub fn high_performance() -> Self {
        Self {
            min_risk: RiskLevel::High,
            include_data_files: true,
            max_file_size: 500 * 1024 * 1024, // 500MB
            max_concurrent_files: std::thread::available_parallelism().map(|p| p.get() * 2).unwrap_or(4),
            archive_limits: ArchiveLimits {
                max_files: 50_000,
                max_total_size: 5 * 1024 * 1024 * 1024, // 5GB
                max_depth: 20,
                max_file_size: 500 * 1024 * 1024, // 500MB
            },
            scan_timeout: Duration::from_secs(120),
            follow_symlinks: true,
            scan_hidden_files: true,
        }
    }
}

/// Validation utilities for paths and filenames
pub mod validation {
    use crate::error::{DivineError, Result};
    use std::path::{Component, Path};

    /// Validate that a path is safe and doesn't contain directory traversal attempts
    pub fn validate_path<P: AsRef<Path>>(path: P) -> Result<()> {
        let path = path.as_ref();

        // Check for dangerous path components
        for component in path.components() {
            match component {
                Component::ParentDir => {
                    return Err(DivineError::directory_traversal(format!(
                        "Path contains '..' component: {}",
                        path.display()
                    )));
                }
                Component::Normal(name) => {
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with('.') && name_str.len() > 1 && name_str != "." {
                        // Allow some common dotfiles but be restrictive
                        let allowed_dotfiles = [".gitignore", ".dockerignore", ".env.example"];
                        if !allowed_dotfiles.contains(&name_str.as_ref()) {
                            return Err(DivineError::security_violation(format!(
                                "Potentially dangerous dotfile: {}",
                                name_str
                            )));
                        }
                    }
                }
                _ => {} // Root, CurDir are generally safe
            }
        }

        // Check for excessively long paths (potential DoS)
        if path.as_os_str().len() > 4096 {
            return Err(DivineError::invalid_path(path, "Path too long (> 4096 characters)"));
        }

        Ok(())
    }

    /// Validate filename for archive extraction
    pub fn validate_filename(name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(DivineError::invalid_path(name, "Empty filename"));
        }

        if name.len() > 255 {
            return Err(DivineError::invalid_path(name, "Filename too long (> 255 characters)"));
        }

        // Check for dangerous characters
        let dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '\0'];
        for ch in dangerous_chars {
            if name.contains(ch) {
                return Err(DivineError::invalid_path(name, format!("Filename contains dangerous character: {}", ch)));
            }
        }

        // Check for reserved names on Windows
        let reserved_names = [
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1",
            "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];

        let name_upper = name.to_uppercase();
        for reserved in &reserved_names {
            if name_upper == *reserved || name_upper.starts_with(&format!("{}.", reserved)) {
                return Err(DivineError::invalid_path(name, format!("Reserved filename: {}", name)));
            }
        }

        Ok(())
    }

    /// Validate file size against limits
    pub fn validate_file_size(size: u64, limit: u64) -> Result<()> {
        if size > limit {
            return Err(DivineError::file_too_large(size, limit));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_archive_limits_validation() {
        let limits = ArchiveLimits::default();

        // Should pass with default limits
        assert!(limits.check_limits(0, 0, 0).is_ok());
        assert!(limits.check_limits(100, 1000, 1).is_ok());

        // Should fail when limits exceeded
        assert!(limits.check_limits(MAX_ARCHIVE_FILES + 1, 0, 0).is_err());
        assert!(limits.check_limits(0, MAX_ARCHIVE_TOTAL_SIZE + 1, 0).is_err());
        assert!(limits.check_limits(0, 0, MAX_ARCHIVE_DEPTH + 1).is_err());
    }

    #[test]
    fn test_scan_config_validation() {
        let config = ScanConfig::default();
        assert!(config.validate().is_ok());

        let bad_config = ScanConfig { max_file_size: 0, ..ScanConfig::default() };
        assert!(bad_config.validate().is_err());
    }

    #[test]
    fn test_path_validation() {
        use validation::*;

        // Valid paths
        assert!(validate_path("normal_file.txt").is_ok());
        assert!(validate_path("subdir/file.txt").is_ok());
        assert!(validate_path(".gitignore").is_ok());

        // Invalid paths
        assert!(validate_path("../../../etc/passwd").is_err());
        assert!(validate_path("dir/../file.txt").is_err());
    }

    #[test]
    fn test_filename_validation() {
        use validation::*;

        // Valid filenames
        assert!(validate_filename("normal.txt").is_ok());
        assert!(validate_filename("file_with_underscores.dat").is_ok());

        // Invalid filenames
        assert!(validate_filename("").is_err());
        assert!(validate_filename("file<script>").is_err());
        assert!(validate_filename("CON").is_err());
        assert!(validate_filename("COM1.txt").is_err());
    }
}
