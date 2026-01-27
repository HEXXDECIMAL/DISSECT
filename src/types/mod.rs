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
mod core;
mod traits_findings;
mod paths_env;
mod binary;
mod diff;
mod ml_features;
mod code_structure;
mod text_metrics;
mod language_metrics;
mod binary_metrics;
mod container_metrics;
mod scores;

// Re-export all public types to maintain API compatibility
pub use core::{AnalysisReport, ArchiveEntry, Criticality, TargetInfo};

pub use traits_findings::{Evidence, Finding, FindingKind, StructuralFeature, Trait, TraitKind};

pub use paths_env::{
    DirectoryAccess, DirectoryAccessPattern, EnvVarAccessType, EnvVarCategory, EnvVarInfo,
    PathAccessType, PathCategory, PathInfo, PathType,
};

pub use binary::{
    AnalysisMetadata, DecodedString, Export, Function, Import, MatchedString, Section, StringInfo,
    StringType, YaraMatch,
};

pub use diff::{
    DiffCounts, DiffReport, FileChanges, FileRenameInfo, FileDiff, FullDiffReport, MetricsDelta,
    ModifiedFileAnalysis,
};

pub use ml_features::{
    CallPatternMetrics, ControlFlowMetrics, DecodedValue, EmbeddedConstant, FunctionProperties,
    FunctionSignature, InstructionAnalysis, InstructionCategories, NestingMetrics, RegisterUsage,
};

pub use code_structure::{
    BinaryAnomaly, BinaryProperties, CodeMetrics, GoIdioms,
    JavaScriptIdioms, LinkingInfo, SecurityFeatures, ShellIdioms,
    SourceCodeMetrics,
};

pub use text_metrics::{
    CommentMetrics, FunctionMetrics, IdentifierMetrics, StringMetrics, TextMetrics,
};

pub use language_metrics::{
    GoMetrics, JavaScriptMetrics, PythonMetrics, RustMetrics,
    ShellMetrics,
};

pub use binary_metrics::BinaryMetrics;


pub use scores::Metrics;

#[cfg(test)]
mod tests;
