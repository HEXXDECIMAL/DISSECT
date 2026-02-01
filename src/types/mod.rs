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

#[cfg(test)]
mod tests;
