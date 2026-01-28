//! Container and archive metrics (tar, npm packages, etc.)

use serde::{Deserialize, Serialize};

use super::{is_false, is_zero_f32, is_zero_u32, is_zero_u64};

// =============================================================================
// CONTAINER/ARCHIVE METRICS
// =============================================================================

/// Archive metrics (ZIP, TAR, etc.)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArchiveMetrics {
    // === Structure ===
    /// File count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub file_count: u32,
    /// Directory count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub directory_count: u32,
    /// Total uncompressed size
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub total_uncompressed: u64,
    /// Total compressed size
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub total_compressed: u64,
    /// Compression ratio
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub compression_ratio: f32,

    // === Suspicious Patterns ===
    /// Path traversal attempts (../)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub path_traversal_count: u32,
    /// Symlink count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub symlink_count: u32,
    /// Symlinks targeting outside archive
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub symlink_escape_count: u32,
    /// Hidden files (.dotfiles)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hidden_files: u32,
    /// Executable files
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub executable_count: u32,
    /// Script files
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub script_count: u32,

    // === Filename Analysis ===
    /// Maximum filename length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_filename_length: u32,
    /// Unicode filenames
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unicode_filenames: u32,
    /// Homoglyph filenames (lookalike chars)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub homoglyph_filenames: u32,
    /// Double extension files (file.txt.exe)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub double_extension_count: u32,
    /// Right-to-left override chars
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub rtlo_filenames: u32,

    // === Content Analysis ===
    /// Nested archives
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nested_archive_count: u32,
    /// Executables in unexpected locations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub misplaced_executables: u32,
    /// High entropy files
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_files: u32,

    // === ZIP-specific ===
    /// Encrypted entries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub encrypted_entries: u32,
    /// Zip bomb indicator (extreme ratio)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub zip_bomb_ratio: f32,
    /// ZIP64 format
    #[serde(default, skip_serializing_if = "is_false")]
    pub zip64_format: bool,
    /// Comment present
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_comment: bool,
    /// Extra field total size
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub extra_field_size: u64,
}

/// package.json metrics for npm supply chain analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PackageJsonMetrics {
    // === Dependencies ===
    /// Dependency count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dependency_count: u32,
    /// Dev dependency count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dev_dependency_count: u32,
    /// Peer dependency count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub peer_dependency_count: u32,
    /// Optional dependency count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub optional_dependency_count: u32,

    // === Lifecycle Scripts (high risk) ===
    /// Has preinstall script
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_preinstall: bool,
    /// Has postinstall script
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_postinstall: bool,
    /// Has preuninstall script
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_preuninstall: bool,
    /// Total script count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub script_count: u32,
    /// Scripts with curl/wget
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub scripts_with_download: u32,
    /// Scripts with eval
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub scripts_with_eval: u32,
    /// Scripts with base64
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub scripts_with_base64: u32,
    /// Total script character count
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub script_total_chars: u64,
    /// High entropy scripts (obfuscated)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub obfuscated_scripts: u32,

    // === Non-Registry Dependencies ===
    /// Git URL dependencies
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub git_dependencies: u32,
    /// GitHub shorthand dependencies
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub github_dependencies: u32,
    /// HTTP URL dependencies
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub url_dependencies: u32,
    /// Local file dependencies
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub local_dependencies: u32,
    /// No semver ("*" or "latest")
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub wildcard_dependencies: u32,

    // === Suspicious Patterns ===
    /// Typosquat likelihood score (0-1)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub typosquat_score: f32,
    /// Package name entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub name_entropy: f32,
    /// Missing author
    #[serde(default, skip_serializing_if = "is_false")]
    pub missing_author: bool,
    /// Missing repository
    #[serde(default, skip_serializing_if = "is_false")]
    pub missing_repository: bool,
    /// Missing license
    #[serde(default, skip_serializing_if = "is_false")]
    pub missing_license: bool,
    /// Suspicious bin names
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub suspicious_bin_names: u32,
}

// =============================================================================
// COMPOSITE SCORES
// =============================================================================
