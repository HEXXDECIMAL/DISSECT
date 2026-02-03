//! Type definitions for DISSECT analysis reports
//!
//! This module provides all the type definitions used throughout DISSECT for
//! representing analysis results, metrics, and findings.

// Helper functions for serde skip_serializing_if (like Go's omitempty)
pub(crate) fn is_false(b: &bool) -> bool {
    !*b
}

pub(crate) fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

pub(crate) fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

pub(crate) fn is_zero_f32(n: &f32) -> bool {
    *n == 0.0
}

pub(crate) fn is_zero_f64(n: &f64) -> bool {
    *n == 0.0
}

pub(crate) fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

pub(crate) fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

// Module declarations
pub mod binary;
pub mod binary_metrics;
pub mod code_structure;
pub mod container_metrics;
pub mod core;
pub mod diff;
pub mod file_analysis;
pub mod language_metrics;
pub mod ml_features;
pub mod paths_env;
pub mod scores;
pub mod text_metrics;
pub mod traits_findings;

// Re-export all public types to maintain API compatibility
// These re-exports are part of the public library API even if not used directly in the binary
#[allow(unused_imports)]
pub use core::{AnalysisReport, ArchiveEntry, Criticality, TargetInfo};

#[allow(unused_imports)]
pub use file_analysis::{
    encode_archive_path, encode_decoded_path, parse_file_path, FileAnalysis, FindingCounts,
    ParsedPath, ReportSummary, ARCHIVE_DELIMITER, ENCODING_DELIMITER,
};

#[allow(unused_imports)]
pub use traits_findings::{Evidence, Finding, FindingKind, StructuralFeature, Trait, TraitKind};

#[allow(unused_imports)]
pub use paths_env::{
    DirectoryAccess, DirectoryAccessPattern, EnvVarAccessType, EnvVarCategory, EnvVarInfo,
    PathAccessType, PathCategory, PathInfo, PathType,
};

#[allow(unused_imports)]
pub use binary::{
    AnalysisMetadata, DecodedString, Export, Function, Import, MatchedString, Section, StringInfo,
    StringType, YaraMatch,
};

pub use diff::{
    DiffCounts, DiffReport, FileChanges, FileDiff, FileRenameInfo, FullDiffReport, MetricsDelta,
    ModifiedFileAnalysis,
};

#[allow(unused_imports)]
pub use ml_features::{
    CallPatternMetrics, ControlFlowMetrics, DecodedValue, EmbeddedConstant, FunctionProperties,
    FunctionSignature, InstructionAnalysis, InstructionCategories, NestingMetrics,
};

#[allow(unused_imports)]
pub use code_structure::{
    BinaryAnomaly, BinaryProperties, CodeMetrics, GoIdioms, JavaScriptIdioms, LinkingInfo,
    SecurityFeatures, ShellIdioms, SourceCodeMetrics,
};

pub use text_metrics::{
    CommentMetrics, FunctionMetrics, IdentifierMetrics, StringMetrics, TextMetrics,
};

#[allow(unused_imports)]
pub use language_metrics::{
    GoMetrics, JavaScriptMetrics, PythonMetrics, RustMetrics, ShellMetrics,
};

pub use binary_metrics::BinaryMetrics;

pub use scores::Metrics;

use std::path::PathBuf;

/// Configuration for optional sample extraction (--sample-dir flag)
///
/// When configured, analyzed files matching the risk criteria are written to
/// a directory for external tools (radare2, objdump) to analyze.
#[derive(Debug, Clone)]
pub struct SampleExtractionConfig {
    /// Directory to write extracted samples
    pub sample_dir: PathBuf,
    /// Maximum risk level to extract (files at this level or below)
    pub max_risk: Criticality,
}

impl SampleExtractionConfig {
    /// Create a new extraction config
    pub fn new(sample_dir: PathBuf, max_risk: Criticality) -> Self {
        Self {
            sample_dir,
            max_risk,
        }
    }

    /// Check if a file should be extracted based on its risk level
    pub fn should_extract(&self, risk: Option<Criticality>) -> bool {
        let file_risk = risk.unwrap_or(Criticality::Inert);
        file_risk <= self.max_risk
    }

    /// Extract file data to sample directory, returning the path if successful
    /// Uses SHA256 as filename for automatic deduplication
    pub fn extract(&self, sha256: &str, data: &[u8]) -> Option<PathBuf> {
        let path = self.sample_dir.join(sha256);
        // Only write if file doesn't exist (deduplication)
        if !path.exists() {
            if let Err(e) = std::fs::write(&path, data) {
                tracing::warn!("Failed to extract sample {}: {}", sha256, e);
                return None;
            }
        }
        Some(path)
    }
}

#[cfg(test)]
mod tests;
