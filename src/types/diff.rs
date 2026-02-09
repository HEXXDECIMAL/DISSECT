//! Diff analysis types for comparing file versions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::binary::{AnalysisMetadata, Export, Function, Import, StringInfo, YaraMatch};
use super::paths_env::{EnvVarInfo, PathInfo};
use super::traits_findings::{Finding, Trait};
use super::{is_zero_f32, is_zero_i32, is_zero_i64};
use crate::radare2::SyscallInfo;

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

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== FileDiff Tests ====================

    #[test]
    fn test_file_diff_default() {
        let diff = FileDiff::default();
        assert_eq!(diff.file, "");
        assert!(diff.added_findings.is_empty());
        assert!(diff.removed_findings.is_empty());
        assert!(diff.added_traits.is_empty());
        assert!(diff.removed_traits.is_empty());
        assert!(!diff.risk_increase);
        assert!(diff.risk_score_delta.is_none());
    }

    #[test]
    fn test_file_diff_with_file() {
        let diff = FileDiff {
            file: "test.py".to_string(),
            ..Default::default()
        };
        assert_eq!(diff.file, "test.py");
    }

    #[test]
    fn test_file_diff_collections_empty() {
        let diff = FileDiff::default();
        assert!(diff.added_strings.is_empty());
        assert!(diff.removed_strings.is_empty());
        assert!(diff.added_imports.is_empty());
        assert!(diff.removed_imports.is_empty());
        assert!(diff.added_exports.is_empty());
        assert!(diff.removed_exports.is_empty());
        assert!(diff.added_functions.is_empty());
        assert!(diff.removed_functions.is_empty());
    }

    #[test]
    fn test_file_diff_syscalls_and_paths() {
        let diff = FileDiff::default();
        assert!(diff.added_syscalls.is_empty());
        assert!(diff.removed_syscalls.is_empty());
        assert!(diff.added_paths.is_empty());
        assert!(diff.removed_paths.is_empty());
        assert!(diff.added_env_vars.is_empty());
        assert!(diff.removed_env_vars.is_empty());
    }

    #[test]
    fn test_file_diff_yara_matches() {
        let diff = FileDiff::default();
        assert!(diff.added_yara_matches.is_empty());
        assert!(diff.removed_yara_matches.is_empty());
    }

    #[test]
    fn test_file_diff_optional_fields() {
        let diff = FileDiff::default();
        assert!(diff.metrics_delta.is_none());
        assert!(diff.counts.is_none());
    }

    #[test]
    fn test_file_diff_risk_increase() {
        let diff = FileDiff {
            risk_increase: true,
            risk_score_delta: Some(0.5),
            ..Default::default()
        };
        assert!(diff.risk_increase);
        assert_eq!(diff.risk_score_delta, Some(0.5));
    }

    // ==================== DiffCounts Tests ====================

    #[test]
    fn test_diff_counts_default() {
        let counts = DiffCounts::default();
        assert_eq!(counts.findings_added, 0);
        assert_eq!(counts.findings_removed, 0);
        assert_eq!(counts.traits_added, 0);
        assert_eq!(counts.traits_removed, 0);
    }

    #[test]
    fn test_diff_counts_strings() {
        let counts = DiffCounts {
            strings_added: 10,
            strings_removed: 5,
            ..Default::default()
        };
        assert_eq!(counts.strings_added, 10);
        assert_eq!(counts.strings_removed, 5);
    }

    #[test]
    fn test_diff_counts_imports_exports() {
        let counts = DiffCounts {
            imports_added: 3,
            imports_removed: 1,
            exports_added: 2,
            exports_removed: 0,
            ..Default::default()
        };
        assert_eq!(counts.imports_added, 3);
        assert_eq!(counts.imports_removed, 1);
        assert_eq!(counts.exports_added, 2);
        assert_eq!(counts.exports_removed, 0);
    }

    #[test]
    fn test_diff_counts_functions_syscalls() {
        let counts = DiffCounts {
            functions_added: 5,
            functions_removed: 2,
            syscalls_added: 8,
            syscalls_removed: 3,
            ..Default::default()
        };
        assert_eq!(counts.functions_added, 5);
        assert_eq!(counts.functions_removed, 2);
        assert_eq!(counts.syscalls_added, 8);
        assert_eq!(counts.syscalls_removed, 3);
    }

    #[test]
    fn test_diff_counts_paths_env_vars() {
        let counts = DiffCounts {
            paths_added: 4,
            paths_removed: 1,
            env_vars_added: 2,
            env_vars_removed: 0,
            ..Default::default()
        };
        assert_eq!(counts.paths_added, 4);
        assert_eq!(counts.paths_removed, 1);
        assert_eq!(counts.env_vars_added, 2);
        assert_eq!(counts.env_vars_removed, 0);
    }

    // ==================== MetricsDelta Tests ====================

    #[test]
    fn test_metrics_delta_default() {
        let delta = MetricsDelta::default();
        assert_eq!(delta.size_bytes, 0);
        assert_eq!(delta.total_lines, 0);
        assert_eq!(delta.code_lines, 0);
    }

    #[test]
    fn test_metrics_delta_size() {
        let delta = MetricsDelta {
            size_bytes: 1024,
            ..Default::default()
        };
        assert_eq!(delta.size_bytes, 1024);
    }

    #[test]
    fn test_metrics_delta_negative() {
        let delta = MetricsDelta {
            size_bytes: -500,
            total_lines: -100,
            code_lines: -80,
            ..Default::default()
        };
        assert_eq!(delta.size_bytes, -500);
        assert_eq!(delta.total_lines, -100);
        assert_eq!(delta.code_lines, -80);
    }

    #[test]
    fn test_metrics_delta_lines() {
        let delta = MetricsDelta {
            total_lines: 100,
            code_lines: 80,
            comment_lines: 10,
            blank_lines: 10,
            ..Default::default()
        };
        assert_eq!(delta.total_lines, 100);
        assert_eq!(delta.code_lines, 80);
        assert_eq!(delta.comment_lines, 10);
        assert_eq!(delta.blank_lines, 10);
    }

    #[test]
    fn test_metrics_delta_complexity() {
        let delta = MetricsDelta {
            avg_complexity: 2.5,
            max_complexity: 15,
            total_functions: 10,
            ..Default::default()
        };
        assert!((delta.avg_complexity - 2.5).abs() < f32::EPSILON);
        assert_eq!(delta.max_complexity, 15);
        assert_eq!(delta.total_functions, 10);
    }

    #[test]
    fn test_metrics_delta_strings() {
        let delta = MetricsDelta {
            string_count: 50,
            avg_string_length: 15.5,
            avg_string_entropy: 3.2,
            ..Default::default()
        };
        assert_eq!(delta.string_count, 50);
        assert!((delta.avg_string_length - 15.5).abs() < f32::EPSILON);
        assert!((delta.avg_string_entropy - 3.2).abs() < f32::EPSILON);
    }

    #[test]
    fn test_metrics_delta_identifiers() {
        let delta = MetricsDelta {
            unique_identifiers: 200,
            avg_identifier_length: 12.3,
            ..Default::default()
        };
        assert_eq!(delta.unique_identifiers, 200);
        assert!((delta.avg_identifier_length - 12.3).abs() < f32::EPSILON);
    }

    #[test]
    fn test_metrics_delta_binary() {
        let delta = MetricsDelta {
            total_basic_blocks: 500,
            total_instructions: 5000,
            code_density: 0.85,
            ..Default::default()
        };
        assert_eq!(delta.total_basic_blocks, 500);
        assert_eq!(delta.total_instructions, 5000);
        assert!((delta.code_density - 0.85).abs() < f32::EPSILON);
    }

    // ==================== FileRenameInfo Tests ====================

    #[test]
    fn test_file_rename_info_creation() {
        let rename = FileRenameInfo {
            from: "old_name.py".to_string(),
            to: "new_name.py".to_string(),
            similarity: 0.95,
        };
        assert_eq!(rename.from, "old_name.py");
        assert_eq!(rename.to, "new_name.py");
        assert!((rename.similarity - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn test_file_rename_info_high_similarity() {
        let rename = FileRenameInfo {
            from: "module.rs".to_string(),
            to: "module_v2.rs".to_string(),
            similarity: 1.0,
        };
        assert!((rename.similarity - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_file_rename_info_low_similarity() {
        let rename = FileRenameInfo {
            from: "a.txt".to_string(),
            to: "completely_different.txt".to_string(),
            similarity: 0.3,
        };
        assert!((rename.similarity - 0.3).abs() < f64::EPSILON);
    }

    // ==================== FileChanges Tests ====================

    #[test]
    fn test_file_changes_empty() {
        let changes = FileChanges {
            added: vec![],
            removed: vec![],
            modified: vec![],
            renamed: vec![],
        };
        assert!(changes.added.is_empty());
        assert!(changes.removed.is_empty());
        assert!(changes.modified.is_empty());
        assert!(changes.renamed.is_empty());
    }

    #[test]
    fn test_file_changes_with_files() {
        let changes = FileChanges {
            added: vec!["new_file.py".to_string()],
            removed: vec!["old_file.py".to_string()],
            modified: vec!["changed.py".to_string()],
            renamed: vec![],
        };
        assert_eq!(changes.added.len(), 1);
        assert_eq!(changes.removed.len(), 1);
        assert_eq!(changes.modified.len(), 1);
    }

    #[test]
    fn test_file_changes_with_renames() {
        let changes = FileChanges {
            added: vec![],
            removed: vec![],
            modified: vec![],
            renamed: vec![FileRenameInfo {
                from: "old.py".to_string(),
                to: "new.py".to_string(),
                similarity: 0.9,
            }],
        };
        assert_eq!(changes.renamed.len(), 1);
        assert_eq!(changes.renamed[0].from, "old.py");
    }

    // ==================== ModifiedFileAnalysis Tests ====================

    #[test]
    fn test_modified_file_analysis_creation() {
        let analysis = ModifiedFileAnalysis {
            file: "test.py".to_string(),
            new_capabilities: vec![],
            removed_capabilities: vec![],
            capability_delta: 0,
            risk_increase: false,
        };
        assert_eq!(analysis.file, "test.py");
        assert_eq!(analysis.capability_delta, 0);
        assert!(!analysis.risk_increase);
    }

    #[test]
    fn test_modified_file_analysis_positive_delta() {
        let analysis = ModifiedFileAnalysis {
            file: "malicious.py".to_string(),
            new_capabilities: vec![],
            removed_capabilities: vec![],
            capability_delta: 5,
            risk_increase: true,
        };
        assert_eq!(analysis.capability_delta, 5);
        assert!(analysis.risk_increase);
    }

    #[test]
    fn test_modified_file_analysis_negative_delta() {
        let analysis = ModifiedFileAnalysis {
            file: "cleaned.py".to_string(),
            new_capabilities: vec![],
            removed_capabilities: vec![],
            capability_delta: -3,
            risk_increase: false,
        };
        assert_eq!(analysis.capability_delta, -3);
        assert!(!analysis.risk_increase);
    }
}
