use std::path::PathBuf;
use thiserror::Error;

/// Divine's custom error types for better error handling and user experience.
#[derive(Debug, Error)]
pub enum DivineError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("YARA compilation failed: {message}")]
    YaraCompilation { message: String },

    #[error("YARA scan failed for {path}: {message}")]
    YaraScan { path: String, message: String },

    #[error("Archive extraction failed: {message}")]
    ArchiveExtraction { message: String },

    #[error("File too large: {size} bytes exceeds limit of {limit} bytes")]
    FileTooLarge { size: u64, limit: u64 },

    #[error("Archive extraction would exceed limits: {violation}")]
    ArchiveLimitsExceeded { violation: String },

    #[error("Invalid path: {path} - {reason}")]
    InvalidPath { path: PathBuf, reason: String },

    #[error("Security violation: {violation}")]
    SecurityViolation { violation: String },

    #[error("Rule loading failed: {message}")]
    RuleLoading { message: String },

    #[error("Configuration error: {message}")]
    Configuration { message: String },

    #[error("Unsupported file format: {format} for path {path}")]
    UnsupportedFormat { format: String, path: String },

    #[error("Path does not exist: {path}")]
    PathNotFound { path: PathBuf },

    #[error("Permission denied accessing: {path}")]
    PermissionDenied { path: PathBuf },

    #[error("Directory traversal attempt detected: {path}")]
    DirectoryTraversal { path: String },
}

pub type Result<T> = std::result::Result<T, DivineError>;

impl DivineError {
    pub fn yara_compilation<S: Into<String>>(message: S) -> Self {
        Self::YaraCompilation { message: message.into() }
    }

    pub fn yara_scan<S: Into<String>>(path: S, message: S) -> Self {
        Self::YaraScan { path: path.into(), message: message.into() }
    }

    pub fn archive_extraction<S: Into<String>>(message: S) -> Self {
        Self::ArchiveExtraction { message: message.into() }
    }

    pub fn file_too_large(size: u64, limit: u64) -> Self {
        Self::FileTooLarge { size, limit }
    }

    pub fn archive_limits_exceeded<S: Into<String>>(violation: S) -> Self {
        Self::ArchiveLimitsExceeded { violation: violation.into() }
    }

    pub fn invalid_path<P: Into<PathBuf>, S: Into<String>>(path: P, reason: S) -> Self {
        Self::InvalidPath { path: path.into(), reason: reason.into() }
    }

    pub fn security_violation<S: Into<String>>(violation: S) -> Self {
        Self::SecurityViolation { violation: violation.into() }
    }

    pub fn rule_loading<S: Into<String>>(message: S) -> Self {
        Self::RuleLoading { message: message.into() }
    }

    pub fn invalid_input<S: Into<String>>(message: S) -> Self {
        Self::Configuration { message: message.into() }
    }

    pub fn serialization<S: Into<String>>(message: S) -> Self {
        Self::Configuration { message: message.into() }
    }

    pub fn io<S: Into<String>>(message: S) -> Self {
        Self::Configuration { message: message.into() }
    }

    pub fn configuration<S: Into<String>>(message: S) -> Self {
        Self::Configuration { message: message.into() }
    }

    pub fn unsupported_format<S1: Into<String>, S2: Into<String>>(format: S1, path: S2) -> Self {
        Self::UnsupportedFormat { format: format.into(), path: path.into() }
    }

    pub fn path_not_found<P: Into<PathBuf>>(path: P) -> Self {
        Self::PathNotFound { path: path.into() }
    }

    pub fn permission_denied<P: Into<PathBuf>>(path: P) -> Self {
        Self::PermissionDenied { path: path.into() }
    }

    pub fn directory_traversal<S: Into<String>>(path: S) -> Self {
        Self::DirectoryTraversal { path: path.into() }
    }

    /// Returns true if the error is recoverable and scanning can continue
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::FileTooLarge { .. }
                | Self::UnsupportedFormat { .. }
                | Self::PermissionDenied { .. }
                | Self::InvalidPath { .. }
        )
    }

    /// Returns true if the error indicates a security issue
    pub fn is_security_related(&self) -> bool {
        matches!(
            self,
            Self::SecurityViolation { .. } | Self::DirectoryTraversal { .. } | Self::ArchiveLimitsExceeded { .. }
        )
    }
}

