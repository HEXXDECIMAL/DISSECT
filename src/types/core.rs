//! Core analysis types - the foundation of DISSECT reports

use crate::radare2::SyscallInfo;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::binary::{
    AnalysisMetadata, DecodedString, Export, Function, Import, Section, StringInfo, YaraMatch,
};
use super::code_structure::{BinaryProperties, CodeMetrics, OverlayMetrics, SourceCodeMetrics};
use super::paths_env::{DirectoryAccess, EnvVarInfo, PathInfo};
use super::scores::Metrics;
use super::traits_findings::{Finding, StructuralFeature, Trait};

/// Criticality level for traits and capabilities
/// - Filtered (−1): Matched but wrong file type, preserved for ML analysis
/// - Inert (0): Universal baseline noise, low analytical signal
/// - Notable (1): Defines program purpose, flag in diffs for supply chain security
/// - Suspicious (2): Unusual/evasive behavior, investigate immediately
/// - Hostile (3): Almost certainly malicious, very rare
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    Filtered,
    #[default]
    Inert,
    Notable,
    Suspicious,
    Hostile,
}

/// Main analysis output structure
#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub schema_version: String,
    pub analysis_timestamp: DateTime<Utc>,
    pub target: TargetInfo,

    // ========================================================================
    // Traits + Findings model
    // ========================================================================
    /// Observable characteristics (strings, paths, symbols, IPs, etc.)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub traits: Vec<Trait>,
    /// Findings - interpretive conclusions based on traits (capabilities, threats, etc.)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub findings: Vec<Finding>,

    pub structure: Vec<StructuralFeature>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub functions: Vec<Function>,
    #[serde(skip_serializing, default)]
    pub strings: Vec<StringInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sections: Vec<Section>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub imports: Vec<Import>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub exports: Vec<Export>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub yara_matches: Vec<YaraMatch>,
    /// Syscalls detected via binary analysis (ELF, Mach-O)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub syscalls: Vec<SyscallInfo>,
    /// Decoded strings (base64, xor, etc.) extracted during analysis
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub decoded_strings: Vec<DecodedString>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub binary_properties: Option<BinaryProperties>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub code_metrics: Option<CodeMetrics>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub source_code_metrics: Option<SourceCodeMetrics>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub overlay_metrics: Option<OverlayMetrics>,
    /// Unified metrics container for ML analysis
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub metrics: Option<Metrics>,
    /// Raw paths discovered (complete list)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub paths: Vec<PathInfo>,
    /// Paths grouped by directory (analysis view)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub directories: Vec<DirectoryAccess>,
    /// Environment variables accessed
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub env_vars: Vec<EnvVarInfo>,
    /// Files contained within archives (for archive targets only)
    /// Paths match those used in Evidence.location fields (without "archive:" prefix)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub archive_contents: Vec<ArchiveEntry>,
    /// Full analysis reports for files within archives (for per-file ML classification)
    /// Each report has its own file_type, findings, metrics, etc.
    /// Box is required to break the recursive type (AnalysisReport contains sub_reports)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    #[allow(clippy::vec_box)]
    pub sub_reports: Vec<Box<AnalysisReport>>,
    pub metadata: AnalysisMetadata,
}

impl AnalysisReport {
    pub fn new(target: TargetInfo) -> Self {
        Self::new_with_timestamp(target, Utc::now())
    }

    pub fn new_with_timestamp(target: TargetInfo, timestamp: chrono::DateTime<Utc>) -> Self {
        Self {
            schema_version: "1.1".to_string(),
            analysis_timestamp: timestamp,
            target,
            traits: Vec::new(),
            findings: Vec::new(),
            structure: Vec::new(),
            functions: Vec::new(),
            strings: Vec::new(),
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            yara_matches: Vec::new(),
            syscalls: Vec::new(),
            decoded_strings: Vec::new(),
            binary_properties: None,
            code_metrics: None,
            source_code_metrics: None,
            overlay_metrics: None,
            metrics: None,
            paths: Vec::new(),
            directories: Vec::new(),
            env_vars: Vec::new(),
            archive_contents: Vec::new(),
            sub_reports: Vec::new(),
            metadata: AnalysisMetadata::default(),
        }
    }

    /// Add a trait and return its index for reference
    pub fn add_trait(&mut self, t: Trait) -> usize {
        let idx = self.traits.len();
        self.traits.push(t);
        idx
    }

    /// Add a finding
    pub fn add_finding(&mut self, finding: Finding) {
        if !self.findings.iter().any(|f| f.id == finding.id) {
            self.findings.push(finding);
        }
    }

    /// Add a finding that references specific traits by ID
    pub fn add_finding_with_refs(&mut self, mut finding: Finding, trait_ids: Vec<String>) {
        finding.trait_refs = trait_ids;
        self.add_finding(finding);
    }

    /// Get the highest criticality level from findings in this report (excluding sub-reports)
    /// Returns None if there are no findings
    pub fn highest_criticality(&self) -> Option<Criticality> {
        self.findings.iter().map(|f| f.crit).max()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TargetInfo {
    pub path: String,
    #[serde(rename = "type")]
    pub file_type: String,
    pub size_bytes: u64,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub architectures: Option<Vec<String>>,
}

/// Metadata about a file contained within an archive
/// The path field matches Evidence.location without the "archive:" prefix.
/// For nested archives, uses `!` separator: "inner.tar.gz!path/to/file.txt"
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ArchiveEntry {
    /// Path within the archive. For nested archives, uses `!` separator.
    /// Examples: "lib/utils.so", "inner.tar.gz!malware/script.sh"
    pub path: String,
    /// Detected file type (e.g., "java-class", "shell", "elf")
    #[serde(rename = "type")]
    pub file_type: String,
    /// SHA256 hash of the file contents
    pub sha256: String,
    /// File size in bytes
    pub size_bytes: u64,
}
