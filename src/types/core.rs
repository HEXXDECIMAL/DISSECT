//! Core analysis types - the foundation of DISSECT reports

use crate::radare2::SyscallInfo;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::binary::{AnalysisMetadata, Export, Function, Import, Section, StringInfo, YaraMatch};
use super::code_structure::{BinaryProperties, CodeMetrics, OverlayMetrics, SourceCodeMetrics};
use super::file_analysis::{FileAnalysis, ReportSummary};
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

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub structure: Vec<StructuralFeature>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub functions: Vec<Function>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
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

    // ========================================================================
    // V2 Schema fields (flat file-centric structure)
    // ========================================================================
    /// Path that was scanned (for directory scans)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scanned_path: Option<String>,

    /// Flat array of all analyzed files (v2 schema)
    /// Includes root file, archive members, and decoded payloads
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub files: Vec<FileAnalysis>,

    /// Report-level summary (v2 schema)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub summary: Option<ReportSummary>,

    pub metadata: AnalysisMetadata,
}

impl AnalysisReport {
    pub fn new(target: TargetInfo) -> Self {
        Self::new_with_timestamp(target, Utc::now())
    }

    pub fn new_with_timestamp(target: TargetInfo, timestamp: chrono::DateTime<Utc>) -> Self {
        Self {
            schema_version: "2.0".to_string(),
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
            binary_properties: None,
            code_metrics: None,
            source_code_metrics: None,
            overlay_metrics: None,
            metrics: None,
            paths: Vec::new(),
            directories: Vec::new(),
            env_vars: Vec::new(),
            archive_contents: Vec::new(),
            scanned_path: None,
            files: Vec::new(),
            summary: None,
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

    /// Convert to v2 flat files array format
    ///
    /// This ensures the files array is properly populated for JSON output.
    /// Adds the root file entry at position 0 and renumbers child file IDs.
    pub fn convert_to_v2(&mut self, verbose: bool) {
        // Create the root file entry
        let mut root_file = self.to_file_analysis(0, verbose);
        root_file.path = self.target.path.clone();
        root_file.depth = 0;
        root_file.parent_id = None;
        root_file.compute_summary();

        if self.files.is_empty() {
            // Simple case: just the root file
            self.files.push(root_file);
        } else {
            // Files were pre-populated by archive/payload analyzers
            // Renumber IDs and insert root file at position 0
            let root_path = self.target.path.clone();
            for (idx, file) in self.files.iter_mut().enumerate() {
                file.id = (idx + 1) as u32; // Shift IDs to make room for root
                if file.depth == 1 && file.parent_id.is_none() {
                    file.parent_id = Some(0); // Point to root
                }
                // Ensure paths have proper archive prefix (!! for archives, ## for decoded)
                if !file.path.contains("!!")
                    && !file.path.contains("##")
                    && !file.path.starts_with(&root_path)
                {
                    file.path = super::file_analysis::encode_archive_path(&root_path, &file.path);
                }
            }
            self.files.insert(0, root_file);
        }

        // Compute report summary
        self.summary = Some(ReportSummary::from_files(&self.files));

        // Clear verbose fields if not in verbose mode
        if !verbose {
            for file in &mut self.files {
                file.minimize();
            }
        }
    }

    /// Create a FileAnalysis from this report's data
    ///
    /// This is used internally by convert_to_v2() and by archive analyzers
    /// to convert per-file reports into the flat files array structure.
    pub fn to_file_analysis(&self, id: u32, verbose: bool) -> FileAnalysis {
        let mut file = FileAnalysis::new(
            id,
            self.target.path.clone(),
            self.target.file_type.clone(),
            self.target.sha256.clone(),
            self.target.size_bytes,
        );

        file.findings = self.findings.clone();

        if verbose {
            file.traits = self.traits.clone();
            file.structure = self.structure.clone();
            file.functions = self.functions.clone();
            file.strings = self.strings.clone();
            file.sections = self.sections.clone();
            file.imports = self.imports.clone();
            file.exports = self.exports.clone();
            file.yara_matches = self.yara_matches.clone();
            file.syscalls = self.syscalls.clone();
            file.binary_properties = self.binary_properties.clone();
            file.source_code_metrics = self.source_code_metrics.clone();
            file.metrics = self.metrics.clone();
            file.paths = self.paths.clone();
            file.directories = self.directories.clone();
            file.env_vars = self.env_vars.clone();
        }

        file
    }

    /// Minimize the report for non-verbose output
    /// Keeps only findings and summary data
    pub fn minimize(&mut self) {
        self.traits.clear();
        self.structure.clear();
        self.functions.clear();
        self.strings.clear();
        self.sections.clear();
        self.imports.clear();
        self.exports.clear();
        self.yara_matches.clear();
        self.syscalls.clear();
        self.binary_properties = None;
        self.code_metrics = None;
        self.source_code_metrics = None;
        self.overlay_metrics = None;
        self.metrics = None;
        self.paths.clear();
        self.directories.clear();
        self.env_vars.clear();
        self.archive_contents.clear();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::traits_findings::FindingKind;

    fn test_target() -> TargetInfo {
        TargetInfo {
            path: "/test/sample.bin".to_string(),
            file_type: "elf".to_string(),
            size_bytes: 1024,
            sha256: "abc123".to_string(),
            architectures: Some(vec!["x86_64".to_string()]),
        }
    }

    fn test_finding(id: &str, crit: Criticality) -> Finding {
        Finding {
            id: id.to_string(),
            kind: FindingKind::Capability,
            desc: format!("Test finding {}", id),
            conf: 0.9,
            crit,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![],
            source_file: None,
        }
    }

    // ==================== Criticality Tests ====================

    #[test]
    fn test_criticality_ordering() {
        assert!(Criticality::Filtered < Criticality::Inert);
        assert!(Criticality::Inert < Criticality::Notable);
        assert!(Criticality::Notable < Criticality::Suspicious);
        assert!(Criticality::Suspicious < Criticality::Hostile);
    }

    #[test]
    fn test_criticality_max() {
        let crits = vec![
            Criticality::Inert,
            Criticality::Hostile,
            Criticality::Notable,
        ];
        assert_eq!(crits.into_iter().max(), Some(Criticality::Hostile));
    }

    #[test]
    fn test_criticality_default() {
        assert_eq!(Criticality::default(), Criticality::Inert);
    }

    #[test]
    fn test_criticality_equality() {
        assert_eq!(Criticality::Hostile, Criticality::Hostile);
        assert_ne!(Criticality::Hostile, Criticality::Suspicious);
    }

    // ==================== AnalysisReport::new Tests ====================

    #[test]
    fn test_analysis_report_new() {
        let report = AnalysisReport::new(test_target());

        assert_eq!(report.schema_version, "2.0");
        assert_eq!(report.target.path, "/test/sample.bin");
        assert!(report.findings.is_empty());
        assert!(report.traits.is_empty());
        assert!(report.strings.is_empty());
    }

    #[test]
    fn test_analysis_report_new_with_timestamp() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();
        let report = AnalysisReport::new_with_timestamp(test_target(), ts);

        assert_eq!(report.analysis_timestamp, ts);
    }

    // ==================== add_finding Tests ====================

    #[test]
    fn test_add_finding_basic() {
        let mut report = AnalysisReport::new(test_target());
        let finding = test_finding("test/cap1", Criticality::Notable);

        report.add_finding(finding);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].id, "test/cap1");
    }

    #[test]
    fn test_add_finding_dedup() {
        let mut report = AnalysisReport::new(test_target());

        report.add_finding(test_finding("test/cap1", Criticality::Notable));
        report.add_finding(test_finding("test/cap1", Criticality::Hostile)); // Same ID

        // Should deduplicate - only one finding
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn test_add_finding_different_ids() {
        let mut report = AnalysisReport::new(test_target());

        report.add_finding(test_finding("test/cap1", Criticality::Notable));
        report.add_finding(test_finding("test/cap2", Criticality::Hostile));

        assert_eq!(report.findings.len(), 2);
    }

    // ==================== add_finding_with_refs Tests ====================

    #[test]
    fn test_add_finding_with_refs() {
        let mut report = AnalysisReport::new(test_target());
        let finding = test_finding("test/cap1", Criticality::Notable);

        report.add_finding_with_refs(finding, vec!["trait1".to_string(), "trait2".to_string()]);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].trait_refs.len(), 2);
        assert!(report.findings[0]
            .trait_refs
            .contains(&"trait1".to_string()));
    }

    // ==================== add_trait Tests ====================

    #[test]
    fn test_add_trait_returns_index() {
        use crate::types::traits_findings::TraitKind;

        let mut report = AnalysisReport::new(test_target());

        let trait1 = Trait {
            kind: TraitKind::String,
            value: "test_string_1".to_string(),
            offset: Some("0x100".to_string()),
            encoding: Some("utf8".to_string()),
            section: None,
            source: "strings".to_string(),
        };
        let trait2 = Trait {
            kind: TraitKind::Import,
            value: "malloc".to_string(),
            offset: None,
            encoding: None,
            section: None,
            source: "imports".to_string(),
        };

        let idx1 = report.add_trait(trait1);
        let idx2 = report.add_trait(trait2);

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(report.traits.len(), 2);
    }

    // ==================== highest_criticality Tests ====================

    #[test]
    fn test_highest_criticality_empty() {
        let report = AnalysisReport::new(test_target());
        assert_eq!(report.highest_criticality(), None);
    }

    #[test]
    fn test_highest_criticality_single() {
        let mut report = AnalysisReport::new(test_target());
        report.add_finding(test_finding("test/cap1", Criticality::Notable));

        assert_eq!(report.highest_criticality(), Some(Criticality::Notable));
    }

    #[test]
    fn test_highest_criticality_multiple() {
        let mut report = AnalysisReport::new(test_target());
        report.add_finding(test_finding("test/cap1", Criticality::Inert));
        report.add_finding(test_finding("test/cap2", Criticality::Hostile));
        report.add_finding(test_finding("test/cap3", Criticality::Notable));

        assert_eq!(report.highest_criticality(), Some(Criticality::Hostile));
    }

    // ==================== minimize Tests ====================

    #[test]
    fn test_minimize_clears_fields() {
        use crate::types::binary::StringType;
        use crate::types::traits_findings::TraitKind;

        let mut report = AnalysisReport::new(test_target());

        // Add some data
        report.traits.push(Trait {
            kind: TraitKind::String,
            value: "test".to_string(),
            offset: None,
            encoding: None,
            section: None,
            source: "strings".to_string(),
            source_file: None,
        });
        report.strings.push(StringInfo {
            value: "test_string".to_string(),
            offset: Some(0x100),
            encoding: "utf8".to_string(),
            string_type: StringType::Plain,
            section: None,
            encoding_chain: vec![],
            fragments: None,
            source_file: None,
        });
        report.imports.push(Import {
            symbol: "malloc".to_string(),
            library: Some("libc".to_string()),
            source: "elf".to_string(),
            source_file: None,
        });
        report.add_finding(test_finding("test/cap1", Criticality::Notable));

        report.minimize();

        // Verbose fields should be cleared
        assert!(report.traits.is_empty());
        assert!(report.strings.is_empty());
        assert!(report.imports.is_empty());

        // Findings should remain
        assert_eq!(report.findings.len(), 1);
    }

    // ==================== TargetInfo Tests ====================

    #[test]
    fn test_target_info_creation() {
        let target = TargetInfo {
            path: "/path/to/file".to_string(),
            file_type: "macho".to_string(),
            size_bytes: 2048,
            sha256: "deadbeef".to_string(),
            architectures: Some(vec!["arm64".to_string(), "x86_64".to_string()]),
        };

        assert_eq!(target.path, "/path/to/file");
        assert_eq!(target.file_type, "macho");
        assert_eq!(target.size_bytes, 2048);
        assert_eq!(target.architectures.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_target_info_no_architectures() {
        let target = TargetInfo {
            path: "/path/to/script.py".to_string(),
            file_type: "python".to_string(),
            size_bytes: 512,
            sha256: "abc123".to_string(),
            architectures: None,
        };

        assert!(target.architectures.is_none());
    }

    // ==================== ArchiveEntry Tests ====================

    #[test]
    fn test_archive_entry_simple_path() {
        let entry = ArchiveEntry {
            path: "lib/utils.so".to_string(),
            file_type: "elf".to_string(),
            sha256: "abc123".to_string(),
            size_bytes: 4096,
        };

        assert_eq!(entry.path, "lib/utils.so");
        assert!(!entry.path.contains('!'));
    }

    #[test]
    fn test_archive_entry_nested_path() {
        let entry = ArchiveEntry {
            path: "inner.tar.gz!malware/script.sh".to_string(),
            file_type: "shell".to_string(),
            sha256: "def456".to_string(),
            size_bytes: 256,
        };

        assert!(entry.path.contains('!'));
    }
}
