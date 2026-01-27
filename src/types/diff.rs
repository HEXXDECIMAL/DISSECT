//! Diff analysis types for comparing file versions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::radare2::SyscallInfo;
use super::{is_zero_f32, is_zero_i32, is_zero_i64};
use super::binary::{AnalysisMetadata, Export, Function, Import, StringInfo, YaraMatch};
use super::paths_env::{EnvVarInfo, PathInfo};
use super::traits_findings::{Finding, Trait};

/// Diff-specific report for comparing old vs new versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub schema_version: String,
    pub analysis_timestamp: DateTime<Utc>,
    pub diff_mode: bool,
    pub baseline: String,
    pub target: String,
    pub changes: FileChanges,
    pub modified_analysis: Vec<ModifiedFileAnalysis>,
    pub metadata: AnalysisMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChanges {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub renamed: Vec<FileRenameInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRenameInfo {
    pub from: String,
    pub to: String,
    pub similarity: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModifiedFileAnalysis {
    pub file: String,
    /// Full capability objects for new capabilities (includes description/evidence)
    pub new_capabilities: Vec<Finding>,
    /// Full capability objects for removed capabilities
    pub removed_capabilities: Vec<Finding>,
    pub capability_delta: i32,
    pub risk_increase: bool,
}

/// Comprehensive diff for a single file - can be treated as a "virtual program" for ML
/// Contains all deltas: added/removed collections and numeric changes
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileDiff {
    pub file: String,

    // === Collection deltas (added/removed) ===
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_findings: Vec<Finding>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_traits: Vec<Trait>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_traits: Vec<Trait>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_strings: Vec<StringInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_strings: Vec<StringInfo>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_imports: Vec<Import>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_imports: Vec<Import>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_exports: Vec<Export>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_exports: Vec<Export>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_functions: Vec<Function>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_functions: Vec<Function>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_syscalls: Vec<SyscallInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_syscalls: Vec<SyscallInfo>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_paths: Vec<PathInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_paths: Vec<PathInfo>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_env_vars: Vec<EnvVarInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_env_vars: Vec<EnvVarInfo>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_yara_matches: Vec<YaraMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_yara_matches: Vec<YaraMatch>,

    // === Numeric deltas (target - baseline) ===
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_delta: Option<MetricsDelta>,

    // === Counts summary (for quick ML feature extraction) ===
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<DiffCounts>,

    // === Risk assessment ===
    pub risk_increase: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_score_delta: Option<f32>,
}

/// Summary counts for quick ML feature extraction
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiffCounts {
    pub findings_added: i32,
    pub findings_removed: i32,
    pub traits_added: i32,
    pub traits_removed: i32,
    pub strings_added: i32,
    pub strings_removed: i32,
    pub imports_added: i32,
    pub imports_removed: i32,
    pub exports_added: i32,
    pub exports_removed: i32,
    pub functions_added: i32,
    pub functions_removed: i32,
    pub syscalls_added: i32,
    pub syscalls_removed: i32,
    pub paths_added: i32,
    pub paths_removed: i32,
    pub env_vars_added: i32,
    pub env_vars_removed: i32,
}

/// Numeric deltas for metrics (target - baseline)
/// Positive = increased, Negative = decreased
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsDelta {
    // === Size deltas ===
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub size_bytes: i64,

    // === Text metrics deltas ===
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub total_lines: i32,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub code_lines: i32,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub comment_lines: i32,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub blank_lines: i32,

    // === Complexity deltas ===
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_complexity: f32,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub max_complexity: i32,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub total_functions: i32,

    // === String metrics deltas ===
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub string_count: i32,
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_string_length: f32,
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_string_entropy: f32,

    // === Identifier metrics deltas ===
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub unique_identifiers: i32,
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_identifier_length: f32,

    // === Binary metrics deltas (for compiled code) ===
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub total_basic_blocks: i32,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub total_instructions: i32,
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub code_density: f32,
}


/// Extended diff report with full analysis for ML pipelines
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullDiffReport {
    pub schema_version: String,
    pub analysis_timestamp: DateTime<Utc>,
    pub diff_mode: bool,
    pub baseline: String,
    pub target: String,
    pub changes: FileChanges,
    /// Comprehensive per-file diffs (for ML: treat each as a "virtual program")
    pub file_diffs: Vec<FileDiff>,
    /// Legacy format for backwards compatibility
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modified_analysis: Vec<ModifiedFileAnalysis>,
    /// Aggregate counts across all files
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregate_counts: Option<DiffCounts>,
    pub metadata: AnalysisMetadata,
}
