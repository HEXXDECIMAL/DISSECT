//! File analysis types for JSON v2 schema
//!
//! This module provides the flat file-centric output structure that replaces
//! the nested sub_reports approach. Each file (including archive members and
//! decoded payloads) gets its own FileAnalysis entry.

use serde::{Deserialize, Serialize};

use super::binary::{DecodedString, Export, Function, Import, Section, StringInfo, YaraMatch};
use super::code_structure::{BinaryProperties, SourceCodeMetrics};
use super::core::Criticality;
use super::paths_env::{DirectoryAccess, EnvVarInfo, PathInfo};
use super::scores::Metrics;
use super::traits_findings::{Finding, StructuralFeature, Trait};
use crate::radare2::SyscallInfo;

/// Path delimiter for archive members (e.g., "archive.zip!!inner/file.py")
pub const ARCHIVE_DELIMITER: &str = "!!";

/// Path delimiter for decoded content (e.g., "file.py##base64+gzip@1234")
pub const ENCODING_DELIMITER: &str = "##";

/// Per-file analysis - the core unit in v2 schema
///
/// Each file (root, archive member, or decoded payload) gets its own entry.
/// This replaces the recursive sub_reports structure with a flat array.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAnalysis {
    /// Unique ID within this report (sequential, 0-based)
    pub id: u32,

    /// Full path including archive/encoding context
    /// Format: "root.zip!!inner/file.py##base64+gzip@1234"
    pub path: String,

    /// Parent file ID (null for root files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<u32>,

    /// Nesting depth (0 = root, 1 = archive member, 2 = decoded content, etc.)
    pub depth: u32,

    /// Detected file type (e.g., "python", "elf", "archive")
    pub file_type: String,

    /// SHA256 hash of file contents
    pub sha256: String,

    /// File size in bytes
    pub size: u64,

    // === Per-file summary (for easy filtering) ===
    /// Maximum criticality of findings in this file (null if no findings)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<Criticality>,

    /// Finding counts by criticality
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counts: Option<FindingCounts>,

    // === Layer info (for decoded content) ===
    /// Encoding chain for decoded content (e.g., ["base64", "gzip"])
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<Vec<String>>,

    // === Analysis results ===
    /// Findings for this file
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub findings: Vec<Finding>,

    // === Verbose fields (omitted in minimal mode) ===
    /// Traits discovered in this file
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub traits: Vec<Trait>,

    /// Structural features
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub structure: Vec<StructuralFeature>,

    /// Functions defined in this file
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub functions: Vec<Function>,

    /// Strings extracted from this file
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub strings: Vec<StringInfo>,

    /// Sections (for binaries)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sections: Vec<Section>,

    /// Imports
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub imports: Vec<Import>,

    /// Exports
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub exports: Vec<Export>,

    /// YARA matches
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub yara_matches: Vec<YaraMatch>,

    /// Syscalls (for binaries)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub syscalls: Vec<SyscallInfo>,

    /// Decoded strings (base64, xor, etc.)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub decoded_strings: Vec<DecodedString>,

    /// Binary properties
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub binary_properties: Option<BinaryProperties>,

    /// Source code metrics
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub source_code_metrics: Option<SourceCodeMetrics>,

    /// Unified metrics container
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub metrics: Option<Metrics>,

    /// Paths discovered
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub paths: Vec<PathInfo>,

    /// Directories accessed
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub directories: Vec<DirectoryAccess>,

    /// Environment variables accessed
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub env_vars: Vec<EnvVarInfo>,

    /// Path to extracted sample file on disk (set when --sample-dir is used)
    /// Allows external tools (radare2, objdump, strings) to analyze the file directly
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extracted_path: Option<String>,
}

impl FileAnalysis {
    /// Create a new FileAnalysis with minimal required fields
    pub fn new(id: u32, path: String, file_type: String, sha256: String, size: u64) -> Self {
        Self {
            id,
            path,
            parent_id: None,
            depth: 0,
            file_type,
            sha256,
            size,
            risk: None,
            counts: None,
            encoding: None,
            findings: Vec::new(),
            traits: Vec::new(),
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
            source_code_metrics: None,
            metrics: None,
            paths: Vec::new(),
            directories: Vec::new(),
            env_vars: Vec::new(),
            extracted_path: None,
        }
    }

    /// Set parent relationship
    pub fn with_parent(mut self, parent_id: u32, depth: u32) -> Self {
        self.parent_id = Some(parent_id);
        self.depth = depth;
        self
    }

    /// Set encoding chain (for decoded content)
    pub fn with_encoding(mut self, encoding: Vec<String>) -> Self {
        self.encoding = Some(encoding);
        self
    }

    /// Compute risk and counts from findings
    pub fn compute_summary(&mut self) {
        if self.findings.is_empty() {
            self.risk = None;
            self.counts = None;
            return;
        }

        let mut counts = FindingCounts::default();
        let mut max_crit = Criticality::Inert;

        for finding in &self.findings {
            match finding.crit {
                Criticality::Hostile => counts.hostile += 1,
                Criticality::Suspicious => counts.suspicious += 1,
                Criticality::Notable => counts.notable += 1,
                _ => {}
            }
            if finding.crit > max_crit {
                max_crit = finding.crit;
            }
        }

        self.risk = if max_crit > Criticality::Inert {
            Some(max_crit)
        } else {
            None
        };

        self.counts = if counts.hostile > 0 || counts.suspicious > 0 || counts.notable > 0 {
            Some(counts)
        } else {
            None
        };
    }

    /// Strip verbose fields for minimal output
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
        self.decoded_strings.clear();
        self.binary_properties = None;
        self.source_code_metrics = None;
        self.metrics = None;
        self.paths.clear();
        self.directories.clear();
        self.env_vars.clear();
    }
}

/// Finding counts by criticality
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingCounts {
    #[serde(default, skip_serializing_if = "is_zero")]
    pub hostile: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub suspicious: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub notable: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// Report-level summary
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReportSummary {
    /// Number of files analyzed
    pub files_analyzed: u32,
    /// Maximum nesting depth encountered
    pub max_depth: u32,
    /// Aggregate finding counts
    pub counts: FindingCounts,
}

impl ReportSummary {
    /// Compute summary from files array
    pub fn from_files(files: &[FileAnalysis]) -> Self {
        let mut summary = Self {
            files_analyzed: files.len() as u32,
            max_depth: 0,
            counts: FindingCounts::default(),
        };

        for file in files {
            if file.depth > summary.max_depth {
                summary.max_depth = file.depth;
            }
            if let Some(counts) = &file.counts {
                summary.counts.hostile += counts.hostile;
                summary.counts.suspicious += counts.suspicious;
                summary.counts.notable += counts.notable;
            }
        }

        summary
    }
}

// =============================================================================
// Path encoding utilities
// =============================================================================

/// Encode an archive member path
///
/// Example: encode_archive_path("foo.zip", "inner/file.py") -> "foo.zip!!inner/file.py"
pub fn encode_archive_path(parent: &str, member: &str) -> String {
    format!("{}{}{}", parent, ARCHIVE_DELIMITER, member)
}

/// Encode a decoded content path
///
/// Example: encode_decoded_path("file.py", &["base64", "gzip"], 1234) -> "file.py##base64+gzip@1234"
pub fn encode_decoded_path(parent: &str, encoding: &[String], offset: usize) -> String {
    let encoding_str = encoding.join("+");
    format!(
        "{}{}{}@{}",
        parent, ENCODING_DELIMITER, encoding_str, offset
    )
}

/// Parsed path components
#[derive(Debug, Clone)]
pub struct ParsedPath {
    /// The root file path
    pub root: String,
    /// Archive member path components (split by !!)
    pub archive_parts: Vec<String>,
    /// Encoding info if present (encoding chain, offset)
    pub encoding: Option<(Vec<String>, usize)>,
}

/// Parse a file path into components
///
/// Example: "a.zip!!b.tar!!c.py##base64+gzip@1234"
/// -> ParsedPath { root: "a.zip", archive_parts: ["b.tar", "c.py"], encoding: Some((["base64", "gzip"], 1234)) }
pub fn parse_file_path(path: &str) -> ParsedPath {
    // First split off encoding part if present
    let (path_part, encoding) = if let Some(idx) = path.find(ENCODING_DELIMITER) {
        let encoding_str = &path[idx + ENCODING_DELIMITER.len()..];
        let parsed_encoding = parse_encoding_suffix(encoding_str);
        (&path[..idx], parsed_encoding)
    } else {
        (path, None)
    };

    // Split by archive delimiter
    let parts: Vec<&str> = path_part.split(ARCHIVE_DELIMITER).collect();
    let root = parts[0].to_string();
    let archive_parts = parts[1..].iter().map(|s| s.to_string()).collect();

    ParsedPath {
        root,
        archive_parts,
        encoding,
    }
}

/// Parse encoding suffix like "base64+gzip@1234"
fn parse_encoding_suffix(s: &str) -> Option<(Vec<String>, usize)> {
    let parts: Vec<&str> = s.split('@').collect();
    if parts.len() != 2 {
        return None;
    }

    let encoding: Vec<String> = parts[0].split('+').map(|s| s.to_string()).collect();
    let offset: usize = parts[1].parse().ok()?;

    Some((encoding, offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_archive_path() {
        assert_eq!(
            encode_archive_path("foo.zip", "inner/file.py"),
            "foo.zip!!inner/file.py"
        );
    }

    #[test]
    fn test_encode_archive_path_nested() {
        let p1 = encode_archive_path("a.zip", "b.tar");
        let p2 = encode_archive_path(&p1, "c.py");
        assert_eq!(p2, "a.zip!!b.tar!!c.py");
    }

    #[test]
    fn test_encode_decoded_path() {
        assert_eq!(
            encode_decoded_path("file.py", &["base64".to_string(), "gzip".to_string()], 1234),
            "file.py##base64+gzip@1234"
        );
    }

    #[test]
    fn test_parse_simple_path() {
        let parsed = parse_file_path("file.py");
        assert_eq!(parsed.root, "file.py");
        assert!(parsed.archive_parts.is_empty());
        assert!(parsed.encoding.is_none());
    }

    #[test]
    fn test_parse_archive_path() {
        let parsed = parse_file_path("archive.zip!!inner/file.py");
        assert_eq!(parsed.root, "archive.zip");
        assert_eq!(parsed.archive_parts, vec!["inner/file.py"]);
        assert!(parsed.encoding.is_none());
    }

    #[test]
    fn test_parse_nested_archive_path() {
        let parsed = parse_file_path("a.zip!!b.tar!!c.py");
        assert_eq!(parsed.root, "a.zip");
        assert_eq!(parsed.archive_parts, vec!["b.tar", "c.py"]);
        assert!(parsed.encoding.is_none());
    }

    #[test]
    fn test_parse_decoded_path() {
        let parsed = parse_file_path("file.py##base64+gzip@1234");
        assert_eq!(parsed.root, "file.py");
        assert!(parsed.archive_parts.is_empty());
        let (encoding, offset) = parsed.encoding.unwrap();
        assert_eq!(encoding, vec!["base64", "gzip"]);
        assert_eq!(offset, 1234);
    }

    #[test]
    fn test_parse_full_path() {
        let parsed = parse_file_path("a.zip!!b.tar!!c.py##base64+gzip@1234");
        assert_eq!(parsed.root, "a.zip");
        assert_eq!(parsed.archive_parts, vec!["b.tar", "c.py"]);
        let (encoding, offset) = parsed.encoding.unwrap();
        assert_eq!(encoding, vec!["base64", "gzip"]);
        assert_eq!(offset, 1234);
    }

    #[test]
    fn test_finding_counts() {
        let mut file = FileAnalysis::new(
            0,
            "test.py".to_string(),
            "python".to_string(),
            "abc123".to_string(),
            100,
        );

        file.findings.push(
            Finding::capability("test/hostile".to_string(), "Test".to_string(), 0.9)
                .with_criticality(Criticality::Hostile),
        );

        file.findings.push(
            Finding::capability("test/suspicious".to_string(), "Test".to_string(), 0.8)
                .with_criticality(Criticality::Suspicious),
        );

        file.compute_summary();

        assert_eq!(file.risk, Some(Criticality::Hostile));
        let counts = file.counts.unwrap();
        assert_eq!(counts.hostile, 1);
        assert_eq!(counts.suspicious, 1);
        assert_eq!(counts.notable, 0);
    }

    #[test]
    fn test_report_summary() {
        let mut file1 = FileAnalysis::new(
            0,
            "a.py".to_string(),
            "python".to_string(),
            "abc".to_string(),
            100,
        );
        file1.depth = 0;
        file1.counts = Some(FindingCounts {
            hostile: 1,
            suspicious: 2,
            notable: 0,
        });

        let mut file2 = FileAnalysis::new(
            1,
            "b.py".to_string(),
            "python".to_string(),
            "def".to_string(),
            200,
        );
        file2.depth = 2;
        file2.counts = Some(FindingCounts {
            hostile: 0,
            suspicious: 1,
            notable: 3,
        });

        let summary = ReportSummary::from_files(&[file1, file2]);
        assert_eq!(summary.files_analyzed, 2);
        assert_eq!(summary.max_depth, 2);
        assert_eq!(summary.counts.hostile, 1);
        assert_eq!(summary.counts.suspicious, 3);
        assert_eq!(summary.counts.notable, 3);
    }
}
