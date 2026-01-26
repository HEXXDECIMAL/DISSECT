use crate::radare2::SyscallInfo;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// Helper functions for serde skip_serializing_if (like Go's omitempty)
fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

fn is_zero_f32(n: &f32) -> bool {
    *n == 0.0
}

fn is_zero_f64(n: &f64) -> bool {
    *n == 0.0
}

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
            binary_properties: None,
            code_metrics: None,
            source_code_metrics: None,
            overlay_metrics: None,
            metrics: None,
            paths: Vec::new(),
            directories: Vec::new(),
            env_vars: Vec::new(),
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

// ========================================================================
// Traits + Findings Model
// ========================================================================

/// Kind of trait - observable characteristics of a file
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TraitKind {
    /// String literal extracted from binary or source
    String,
    /// File or directory path
    Path,
    /// Environment variable reference
    EnvVar,
    /// Imported symbol (function/variable from external library)
    Import,
    /// Exported symbol (function/variable exposed by this file)
    Export,
    /// IP address (v4 or v6)
    Ip,
    /// URL or URI
    Url,
    /// Domain name
    Domain,
    /// Email address
    Email,
    /// Base64-encoded data
    Base64,
    /// Cryptographic hash
    Hash,
    /// Registry key (Windows)
    Registry,
    /// Function or method name
    Function,
}

/// Observable characteristic of a file - a fact without interpretation
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Trait {
    /// Kind of trait
    pub kind: TraitKind,
    /// The raw value discovered
    pub value: String,
    /// Offset in file (hex format like "0x1234")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub offset: Option<String>,
    /// Encoding for strings (utf8, utf16le, utf16be, ascii)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub encoding: Option<String>,
    /// Section where found (for binaries: .text, .data, .rodata)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub section: Option<String>,
    /// Source tool that discovered this trait
    pub source: String,
}

impl Trait {
    pub fn new(kind: TraitKind, value: String, source: String) -> Self {
        Self {
            kind,
            value,
            offset: None,
            encoding: None,
            section: None,
            source,
        }
    }

    pub fn with_offset(mut self, offset: String) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn with_encoding(mut self, encoding: String) -> Self {
        self.encoding = Some(encoding);
        self
    }

    pub fn with_section(mut self, section: String) -> Self {
        self.section = Some(section);
        self
    }
}

/// Kind of finding - what type of conclusion this represents
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FindingKind {
    /// What the code CAN do (behavioral) - e.g., net/socket, fs/write, exec/eval, anti-debug
    #[default]
    Capability,
    /// How the file is built/hidden - e.g., obfuscation, packing, high entropy, missing security features
    Structural,
    /// Signs of malicious intent (threat signals) - e.g., C2 patterns, malware signatures
    Indicator,
    /// Security vulnerabilities - e.g., SQL injection, buffer overflow
    Weakness,
}

/// A finding - an interpretive conclusion based on traits
/// Findings represent what we CONCLUDE from traits (capabilities, threats, behaviors)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Finding {
    /// Finding identifier using / delimiter (e.g., "c2/hardcoded-ip", "net/socket")
    pub id: String,
    /// Kind of finding (capability, structural, indicator, weakness)
    #[serde(default)]
    pub kind: FindingKind,
    /// Human-readable description
    pub desc: String,
    /// Confidence score (0.5 = heuristic, 1.0 = definitive)
    #[serde(alias = "confidence")]
    pub conf: f32,
    /// Criticality level
    #[serde(default)]
    pub crit: Criticality,
    /// MBC (Malware Behavior Catalog) ID
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mbc: Option<String>,
    /// MITRE ATT&CK Technique ID
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attack: Option<String>,
    /// Trait IDs that contributed to this finding (for aggregated findings)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub trait_refs: Vec<String>,
    /// Additional evidence (for findings not tied to specific traits)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub evidence: Vec<Evidence>,
}

impl Finding {
    pub fn new(id: String, kind: FindingKind, desc: String, conf: f32) -> Self {
        Self {
            id,
            kind,
            desc,
            conf,
            crit: Criticality::Inert,
            mbc: None,
            attack: None,
            trait_refs: Vec::new(),
            evidence: Vec::new(),
        }
    }

    /// Create a capability finding
    pub fn capability(id: String, desc: String, conf: f32) -> Self {
        Self::new(id, FindingKind::Capability, desc, conf)
    }

    /// Create a structural finding (obfuscation, packing, etc.)
    pub fn structural(id: String, desc: String, conf: f32) -> Self {
        Self::new(id, FindingKind::Structural, desc, conf)
    }

    /// Create an indicator finding (threat signals)
    pub fn indicator(id: String, desc: String, conf: f32) -> Self {
        Self::new(id, FindingKind::Indicator, desc, conf)
    }

    /// Create a weakness finding (vulnerabilities)
    pub fn weakness(id: String, desc: String, conf: f32) -> Self {
        Self::new(id, FindingKind::Weakness, desc, conf)
    }

    pub fn with_criticality(mut self, crit: Criticality) -> Self {
        self.crit = crit;
        self
    }

    pub fn with_mbc(mut self, mbc: String) -> Self {
        self.mbc = Some(mbc);
        self
    }

    pub fn with_attack(mut self, attack: String) -> Self {
        self.attack = Some(attack);
        self
    }

    pub fn with_trait_refs(mut self, refs: Vec<String>) -> Self {
        self.trait_refs = refs;
        self
    }

    pub fn with_evidence(mut self, evidence: Vec<Evidence>) -> Self {
        self.evidence = evidence;
        self
    }
}

/// Legacy trait structure - being replaced by Artifact + Finding model
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StructuralFeature {
    /// Feature identifier using / delimiter (e.g., "binary/format/macho")
    pub id: String,
    /// Human-readable description
    pub desc: String,
    /// Evidence supporting this feature
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Evidence {
    /// Detection method (symbol, yara, tree-sitter, radare2, entropy, magic, etc.)
    pub method: String,
    /// Source tool (goblin, yara-x, radare2, tree-sitter-bash, etc.)
    pub source: String,
    /// Value discovered (symbol name, pattern match, etc.)
    pub value: String,
    /// Optional location context
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub location: Option<String>,
}

/// File system path discovered in binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathInfo {
    /// The path string as found
    pub path: String,

    /// Classification of path format
    #[serde(rename = "type")]
    pub path_type: PathType,

    /// Semantic category
    pub category: PathCategory,

    /// How the path is accessed (if determinable)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub access_type: Option<PathAccessType>,

    /// Where discovered (strings, yara, function_analysis)
    pub source: String,

    /// Evidence for this path
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub evidence: Vec<Evidence>,

    /// Trait IDs that reference this path (back-reference)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub referenced_by_traits: Vec<String>,
}

/// Path type classification
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PathType {
    /// Absolute path (/etc/passwd)
    Absolute,
    /// Relative path (../../etc/passwd)
    Relative,
    /// Dynamic path with variables (/home/%s, /tmp/file-%d, ${HOME}/.config)
    Dynamic,
}

/// Semantic category of path
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum PathCategory {
    /// System directories (/bin/, /sbin/, /usr/bin/)
    System,
    /// Configuration files (/etc/, *.conf, .config/)
    Config,
    /// Temporary files (/tmp/, /var/tmp/, /dev/shm/)
    Temp,
    /// Log files (/var/log/)
    Log,
    /// Home directories (/home/, ~/)
    Home,
    /// Device/mount points (/dev/, /mnt/, /proc/, /sys/)
    Device,
    /// Runtime files (/var/run/, /run/)
    Runtime,
    /// Hidden files (.* files/directories)
    Hidden,
    /// Network configuration (/etc/hosts, /etc/resolv.conf)
    Network,
    /// Other/unknown
    Other,
}

/// How a path is accessed
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum PathAccessType {
    Read,
    Write,
    Execute,
    Delete,
    Create,
    Unknown,
}

/// Directory with multiple file accesses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryAccess {
    /// The directory path
    pub directory: String,

    /// Files within this directory (just filenames)
    pub files: Vec<String>,

    /// Number of files
    pub file_count: usize,

    /// Pattern of access
    pub access_pattern: DirectoryAccessPattern,

    /// Categories of files in this directory
    pub categories: Vec<PathCategory>,

    /// Whether directory itself was enumerated (opendir/readdir)
    #[serde(default, skip_serializing_if = "is_false")]
    pub enumerated: bool,

    /// Trait IDs generated from this directory pattern
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub generated_traits: Vec<String>,
}

/// Pattern of directory access
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryAccessPattern {
    /// Single hardcoded file
    SingleFile,

    /// Multiple specific files (hardcoded list)
    MultipleSpecific { count: usize },

    /// Directory enumeration (opendir/readdir/glob)
    Enumeration { pattern: Option<String> },

    /// Batch operations (multiple files, same operation)
    BatchOperation { operation: String, count: usize },

    /// User enumeration (/home/* pattern)
    UserEnumeration,
}

/// Environment variable discovered in binary or script
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVarInfo {
    /// Environment variable name (e.g., "PATH", "HOME")
    pub name: String,

    /// How the env var is accessed
    pub access_type: EnvVarAccessType,

    /// Where discovered (getenv, setenv, strings, ast)
    pub source: String,

    /// Semantic category
    pub category: EnvVarCategory,

    /// Evidence for this environment variable access
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub evidence: Vec<Evidence>,

    /// Trait IDs that reference this env var (back-reference)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub referenced_by_traits: Vec<String>,
}

/// How environment variable is accessed
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum EnvVarAccessType {
    /// Reading variable value (getenv)
    Read,
    /// Setting variable value (setenv, putenv)
    Write,
    /// Removing variable (unsetenv)
    Delete,
    /// Unknown access type
    Unknown,
}

/// Semantic category of environment variable
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum EnvVarCategory {
    /// System paths (PATH, LD_LIBRARY_PATH, PYTHONPATH)
    Path,
    /// User information (USER, USERNAME, HOME, USERPROFILE)
    User,
    /// System information (HOSTNAME, SHELL, TERM)
    System,
    /// Temporary directories (TEMP, TMP, TMPDIR)
    Temp,
    /// Display/UI (DISPLAY, WAYLAND_DISPLAY)
    Display,
    /// Security/credentials (API_KEY, TOKEN, PASSWORD, AWS_*, GITHUB_TOKEN)
    Credential,
    /// Language runtimes (PYTHONPATH, NODE_PATH, RUBYLIB, GOPATH)
    Runtime,
    /// Platform-specific (ANDROID_*, IOS_*)
    Platform,
    /// Injection/evasion (LD_PRELOAD, DYLD_INSERT_LIBRARIES)
    Injection,
    /// Locale/language (LANG, LC_*, LANGUAGE)
    Locale,
    /// Network (http_proxy, https_proxy, no_proxy)
    Network,
    /// Other/unknown
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub offset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub complexity: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub calls: Vec<String>,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub control_flow: Option<ControlFlowMetrics>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub instruction_analysis: Option<InstructionAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub register_usage: Option<RegisterUsage>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub constants: Vec<EmbeddedConstant>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub properties: Option<FunctionProperties>,
    /// Function signature (source code languages)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signature: Option<FunctionSignature>,
    /// Nesting depth metrics
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nesting: Option<NestingMetrics>,
    /// Call pattern analysis
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub call_patterns: Option<CallPatternMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringInfo {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub offset: Option<String>,
    pub encoding: String,
    #[serde(rename = "type")]
    pub string_type: StringType,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub section: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum StringType {
    Url,
    Ip,
    Path,
    Email,
    Base64,
    Import,
    Export,
    Function,
    Plain,
    /// String literal from source code
    Literal,
    /// Comment from source code
    Comment,
    /// Docstring/documentation comment
    Docstring,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub size: u64,
    pub entropy: f64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub permissions: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub library: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub offset: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub severity: String,
    pub desc: String,
    #[serde(default)]
    pub matched_strings: Vec<MatchedString>,
    /// Whether this match should be upgraded to a capability
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_capability: bool,
    /// Optional MBC code from metadata
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mbc: Option<String>,
    /// Optional ATT&CK technique from metadata
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attack: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedString {
    pub identifier: String,
    pub offset: u64,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisMetadata {
    pub analysis_duration_ms: u64,
    pub tools_used: Vec<String>,
    pub errors: Vec<String>,
}

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

fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
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

// ========================================================================
// ML-Ready Feature Extraction Structures
// ========================================================================

/// Control flow graph metrics for a function
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ControlFlowMetrics {
    /// Number of basic blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub basic_blocks: u32,
    /// Number of control flow edges
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub edges: u32,
    /// Cyclomatic complexity (McCabe)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cyclomatic_complexity: u32,
    /// Maximum instructions in any basic block
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_block_size: u32,
    /// Average instructions per basic block
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_block_size: f32,
    /// Whether function has linear control flow (no branches)
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_linear: bool,
    /// Number of loops detected
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub loop_count: u32,
    /// Branch density (branches per instruction)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub branch_density: f32,
    /// Call graph in-degree (callers)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub in_degree: u32,
    /// Call graph out-degree (callees)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub out_degree: u32,
}

/// Instruction-level analysis for ML features
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InstructionAnalysis {
    /// Total instruction count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_instructions: u32,
    /// CPU cycle cost estimate
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub instruction_cost: u32,
    /// Instruction density (instructions per byte)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub instruction_density: f32,
    /// Instruction categories and counts
    pub categories: InstructionCategories,
    /// Top 5 most used opcodes
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub top_opcodes: Vec<OpcodeFrequency>,
    /// Unusual/suspicious instructions detected
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unusual_instructions: Vec<String>,
}

/// Categorized instruction counts for behavioral analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InstructionCategories {
    /// Arithmetic operations (add, sub, mul, div, inc, dec)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub arithmetic: u32,
    /// Logical operations (and, or, xor, not, test)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub logic: u32,
    /// Memory operations (mov, lea, push, pop, load, store)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub memory: u32,
    /// Control flow (jmp, jne, call, ret, loop)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub control: u32,
    /// System calls and interrupts (syscall, int, sysenter)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub system: u32,
    /// FPU/SIMD operations (fadd, fmul, xmm, etc)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fpu_simd: u32,
    /// String operations (movs, cmps, scas, stos)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub string_ops: u32,
    /// Privileged instructions (cli, sti, hlt, in, out)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub privileged: u32,
    /// Crypto-related instructions (aes, sha, etc)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub crypto: u32,
}

/// Opcode frequency for pattern detection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpcodeFrequency {
    pub opcode: String,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub count: u32,
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub percentage: f32,
}

/// Register usage patterns
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegisterUsage {
    /// Registers read in function
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read: Vec<String>,
    /// Registers written in function
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub written: Vec<String>,
    /// Registers preserved across call
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preserved: Vec<String>,
    /// Registers used in function (legacy, kept for compatibility)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registers_used: Vec<String>,
    /// Non-standard register usage (unusual for the architecture)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub non_standard_usage: Vec<String>,
    /// Stack pointer manipulation detected
    #[serde(default, skip_serializing_if = "is_false")]
    pub stack_pointer_manipulation: bool,
    /// Frame pointer usage
    #[serde(default, skip_serializing_if = "is_false")]
    pub uses_frame_pointer: bool,
    /// Maximum local variables (Java bytecode)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_locals: Option<u32>,
    /// Maximum operand stack depth (Java bytecode)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_stack: Option<u32>,
}

/// Embedded constant with decoded information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EmbeddedConstant {
    /// Raw value as hex string
    pub value: String,
    /// Constant type (qword, dword, word, byte)
    pub constant_type: String,
    /// Possible decoded interpretations
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decoded: Vec<DecodedValue>,
}

/// Decoded constant value interpretations
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DecodedValue {
    /// Type of decoded value (ip_address, port, url, key, etc)
    pub value_type: String,
    /// Human-readable decoded value
    pub decoded_value: String,
    /// Confidence in this interpretation (0.0-1.0)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub conf: f32,
}

/// Function-level properties
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionProperties {
    /// Function is side-effect free (pure)
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_pure: bool,
    /// Function never returns
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_noreturn: bool,
    /// Function is recursive
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_recursive: bool,
    /// Stack frame size in bytes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stack_frame: u32,
    /// Number of local variables
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub local_vars: u32,
    /// Number of arguments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub args: u32,
    /// Function is a leaf (calls nothing)
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_leaf: bool,
}

/// Function signature analysis (source code languages)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionSignature {
    /// Parameter count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub param_count: u32,
    /// Parameters with default values
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub default_param_count: u32,
    /// Has *args (variadic positional)
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_var_positional: bool,
    /// Has **kwargs (variadic keyword)
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_var_keyword: bool,
    /// Has type annotations/hints
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_type_hints: bool,
    /// Return type annotation present
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_return_type: bool,
    /// Decorators applied
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decorators: Vec<String>,
    /// Is async function
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_async: bool,
    /// Is generator (contains yield)
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_generator: bool,
    /// Is lambda/anonymous
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_lambda: bool,
}

/// Nesting depth metrics for control structures
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NestingMetrics {
    /// Maximum nesting depth in function
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_depth: u32,
    /// Average nesting depth
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_depth: f32,
    /// Locations with deep nesting (depth > 4)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub deep_nest_count: u32,
}

/// Call pattern analysis for source code
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CallPatternMetrics {
    /// Total function calls in this function
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub call_count: u32,
    /// Unique functions called
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unique_callees: u32,
    /// Chained method calls (e.g., obj.a().b().c())
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chained_calls: u32,
    /// Maximum chain length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_chain_length: u32,
    /// Recursive calls (self-reference)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub recursive_calls: u32,
    /// Dynamic calls (eval, exec, __import__, getattr)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dynamic_calls: u32,
}

/// Binary-wide properties for ML analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BinaryProperties {
    /// Security features present/absent
    pub security: SecurityFeatures,
    /// Linking and dependencies
    pub linking: LinkingInfo,
    /// Anomalies detected
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anomalies: Vec<BinaryAnomaly>,
}

/// Security hardening features
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityFeatures {
    /// Stack canary present
    #[serde(default, skip_serializing_if = "is_false")]
    pub canary: bool,
    /// No-execute (NX/DEP) enabled
    #[serde(default, skip_serializing_if = "is_false")]
    pub nx: bool,
    /// Position independent code
    #[serde(default, skip_serializing_if = "is_false")]
    pub pic: bool,
    /// RELRO protection level (none, partial, full)
    #[serde(default)]
    pub relro: String,
    /// Binary is stripped
    #[serde(default, skip_serializing_if = "is_false")]
    pub stripped: bool,
    /// Uses cryptographic functions
    #[serde(default, skip_serializing_if = "is_false")]
    pub uses_crypto: bool,
    /// Code signature present
    #[serde(default, skip_serializing_if = "is_false")]
    pub signed: bool,
}

/// Binary linking information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LinkingInfo {
    /// Statically linked
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_static: bool,
    /// Dynamic libraries used
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub libraries: Vec<String>,
    /// RPATH/RUNPATH settings
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpath: Vec<String>,
}

/// Structural anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BinaryAnomaly {
    /// Anomaly type (no_section_header, overlapping_functions, etc)
    pub anomaly_type: String,
    /// Description
    pub desc: String,
    /// Severity (low, medium, high)
    pub severity: String,
}

/// Overlay/appended data metrics for supply chain attack detection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OverlayMetrics {
    /// Size of overlay in bytes
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub size_bytes: u64,
    /// Overlay as ratio of total file size (0.0-1.0)
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub ratio_of_file: f64,
    /// Average entropy of overlay data
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub avg_entropy: f64,
    /// Variance in entropy across chunks (indicates mixed content)
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub entropy_variance: f64,
    /// Count of embedded files found via magic bytes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub embedded_file_count: u32,
    /// Types of embedded files found (zstd, gzip, elf, etc)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub embedded_for: Vec<String>,
    /// Offset where overlay begins
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub overlay_start: u64,
    /// Suspicion score (0.0-1.0)
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub suspicion_score: f64,
}

/// Aggregate code metrics across entire binary
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CodeMetrics {
    /// Total number of functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_functions: u32,
    /// Total basic blocks across all functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_basic_blocks: u32,
    /// Average cyclomatic complexity
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_complexity: f32,
    /// Maximum complexity seen
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_complexity: u32,
    /// Total instruction count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_instructions: u32,
    /// Code-to-data ratio
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub code_density: f32,
    /// Functions with loops
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub functions_with_loops: u32,
    /// Functions with unusual patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub functions_with_anomalies: u32,
}

/// Source code metrics for scripts (Python, JavaScript, etc.)
/// Useful for ML analysis and behavioral profiling
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SourceCodeMetrics {
    /// Total lines in file
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_lines: u32,
    /// Lines of code (excluding blanks and comments)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub code_lines: u32,
    /// Comment lines (including inline and block comments)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub comment_lines: u32,
    /// Blank lines
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub blank_lines: u32,
    /// Docstring lines
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub docstring_lines: u32,

    // Comment density metrics
    /// Ratio of comments to code (comment_lines / code_lines)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub comment_to_code_ratio: f32,
    /// Ratio of comments to total lines
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub comment_density: f32,

    // String metrics
    /// Total number of string literals
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub string_count: u32,
    /// Average string length
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_string_length: f32,
    /// Maximum string length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_string_length: u32,
    /// Average string entropy (0.0-8.0, higher = more random/obfuscated)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_string_entropy: f32,
    /// String density (strings per line of code)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub string_density: f32,

    // Function metrics
    /// Total number of functions/methods defined
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub function_count: u32,
    /// Average function size in lines
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_function_size: f32,
    /// Maximum function size
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_function_size: u32,

    // Import metrics
    /// Total import statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub import_count: u32,
    /// Standard library imports
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stdlib_imports: u32,
    /// Third-party imports
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub third_party_imports: u32,
    /// Local/relative imports
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub local_imports: u32,

    // Complexity indicators
    /// Lines with eval/exec/compile
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dynamic_execution_count: u32,
    /// Obfuscation indicators (base64, hex strings, etc.)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub obfuscation_indicators: u32,
    /// High-entropy strings (entropy > 5.0)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_strings: u32,

    // Code structure (Phase 2)
    /// Code structure metrics
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub code_structure: Option<CodeStructureMetrics>,

    // Language-specific idioms (Phase 3)
    /// Python-specific idioms
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub python_idioms: Option<PythonIdioms>,

    /// JavaScript-specific idioms
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub javascript_idioms: Option<JavaScriptIdioms>,

    /// Shell script idioms
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub shell_idioms: Option<ShellIdioms>,

    /// Go idioms
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub go_idioms: Option<GoIdioms>,
}

/// Code structure metrics for ML analysis (Phase 2)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CodeStructureMetrics {
    /// Global variables defined
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub global_var_count: u32,
    /// Class definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_count: u32,
    /// Maximum inheritance depth
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_inheritance_depth: u32,
    /// Try/except blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exception_handler_count: u32,
    /// Empty except blocks (suspicious - error suppression)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub empty_except_count: u32,
    /// Assert statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub assert_count: u32,
    /// Main guard present (if __name__ == "__main__":)
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_main_guard: bool,
    /// Assignment statements (variable definitions)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub assignment_count: u32,
}

/// Python-specific language idioms (Phase 3)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PythonIdioms {
    /// List/dict/set comprehensions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub comprehension_count: u32,
    /// Generator expressions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub generator_expression_count: u32,
    /// Context managers (with statements)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub context_manager_count: u32,
    /// Lambda functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lambda_count: u32,
    /// Async/await usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub async_count: u32,
    /// Yield statements (generators)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub yield_count: u32,
    /// Class definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_count: u32,
    /// Dunder methods (__init__, __str__, etc.)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dunder_method_count: u32,
    /// Total decorator usage (all contexts)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_decorator_count: u32,
    /// F-strings (formatted string literals)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fstring_count: u32,
    /// Walrus operator usage (:=)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub walrus_operator_count: u32,
}

/// JavaScript-specific language idioms
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JavaScriptIdioms {
    /// Arrow functions (=>)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub arrow_function_count: u32,
    /// Promise usage (new Promise, .then, .catch)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub promise_count: u32,
    /// Async/await usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub async_await_count: u32,
    /// Template literals (`string ${expr}`)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub template_literal_count: u32,
    /// Destructuring assignments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub destructuring_count: u32,
    /// Spread operator usage (...)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub spread_operator_count: u32,
    /// Class definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_count: u32,
    /// Callback patterns (function passed as argument)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub callback_count: u32,
    /// IIFE (Immediately Invoked Function Expression)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub iife_count: u32,
    /// Object literal shorthand
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub object_shorthand_count: u32,
    /// Optional chaining (?.)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub optional_chaining_count: u32,
    /// Nullish coalescing (??)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nullish_coalescing_count: u32,
}

/// Shell script specific idioms
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShellIdioms {
    /// Pipe usage (|)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pipe_count: u32,
    /// Output redirections (>, >>)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub redirect_count: u32,
    /// Input redirections (<, <<)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub input_redirect_count: u32,
    /// Command substitutions ($(), backticks)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub command_substitution_count: u32,
    /// Here documents (<<EOF)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub heredoc_count: u32,
    /// Case statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub case_statement_count: u32,
    /// Test expressions ([ ], [[ ]], test)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub test_expression_count: u32,
    /// While read loops
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub while_read_count: u32,
    /// Subshells (commands in parentheses)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub subshell_count: u32,
    /// For loops
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub for_loop_count: u32,
    /// Background jobs (&)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub background_job_count: u32,
    /// Process substitution (<(), >())
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub process_substitution_count: u32,
}

/// Go-specific language idioms
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GoIdioms {
    /// Goroutine launches (go keyword)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub goroutine_count: u32,
    /// Channel operations (chan, <-)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub channel_count: u32,
    /// Defer statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub defer_count: u32,
    /// Select statements (channel multiplexing)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub select_statement_count: u32,
    /// Interface type assertions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub type_assertion_count: u32,
    /// Method declarations (with receivers)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub method_count: u32,
    /// Interface definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub interface_count: u32,
    /// Range loops (for...range)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub range_loop_count: u32,
    /// Error handling returns (func ... error)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub error_return_count: u32,
    /// Panic/recover usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub panic_recover_count: u32,
    /// CGo usage (import "C")
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cgo_count: u32,
    /// Unsafe pointer operations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unsafe_count: u32,
}

// =============================================================================
// UNIFIED METRICS SYSTEM
// =============================================================================

/// Unified metrics container - all measurements in one place
/// Sections are only present when applicable to the file type
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Metrics {
    // === Universal text metrics (all text files) ===
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<TextMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifiers: Option<IdentifierMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strings: Option<StringMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<CommentMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub functions: Option<FunctionMetrics>,

    // === Language-specific metrics (mutually exclusive) ===
    #[serde(skip_serializing_if = "Option::is_none")]
    pub python: Option<PythonMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub javascript: Option<JavaScriptMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub powershell: Option<PowerShellMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<ShellMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub php: Option<PhpMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruby: Option<RubyMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perl: Option<PerlMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub go_metrics: Option<GoMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rust_metrics: Option<RustMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_metrics: Option<CMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub java: Option<JavaSourceMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lua: Option<LuaMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csharp: Option<CSharpMetrics>,

    // === Binary-specific metrics ===
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<BinaryMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elf: Option<ElfMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pe: Option<PeMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub macho: Option<MachoMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub java_class: Option<JavaClassMetrics>,

    // === Container/Archive metrics ===
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive: Option<ArchiveMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_json: Option<PackageJsonMetrics>,

    // === Composite scores ===
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfuscation: Option<ObfuscationScore>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packing: Option<PackingScore>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supply_chain: Option<SupplyChainScore>,
}

// =============================================================================
// UNIVERSAL TEXT METRICS (All text files)
// =============================================================================

/// Text-level metrics computed on raw file content
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TextMetrics {
    // === Character Distribution ===
    /// Shannon entropy of character distribution (0-8, normal code ~4.5)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub char_entropy: f32,
    /// Number of distinct characters used
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unique_chars: u32,
    /// Most frequent non-whitespace character
    #[serde(skip_serializing_if = "Option::is_none")]
    pub most_common_char: Option<char>,
    /// Ratio of most common char to total (0-1)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub most_common_ratio: f32,

    // === Byte-Level Analysis ===
    /// Ratio of non-ASCII bytes (0-1)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub non_ascii_ratio: f32,
    /// Ratio of non-printable control characters
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub non_printable_ratio: f32,
    /// Count of null bytes (binary in text file?)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub null_byte_count: u32,
    /// Ratio of bytes > 0x7F
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub high_byte_ratio: f32,

    // === Line Statistics ===
    /// Total lines in file
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_lines: u32,
    /// Average line length in characters
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_line_length: f32,
    /// Maximum line length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_line_length: u32,
    /// Standard deviation of line lengths
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub line_length_stddev: f32,
    /// Lines over 200 characters
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lines_over_200: u32,
    /// Lines over 500 characters
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lines_over_500: u32,
    /// Lines over 1000 characters (strong obfuscation signal)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lines_over_1000: u32,
    /// Ratio of empty lines to total
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub empty_line_ratio: f32,

    // === Whitespace Forensics ===
    /// Ratio of whitespace to total characters
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub whitespace_ratio: f32,
    /// Tab characters count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub tab_count: u32,
    /// Space characters count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub space_count: u32,
    /// Mixed tabs and spaces for indentation
    #[serde(default, skip_serializing_if = "is_false")]
    pub mixed_indent: bool,
    /// Lines with trailing whitespace
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub trailing_whitespace_lines: u32,
    /// Unicode whitespace chars (zero-width, non-breaking, etc.)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unusual_whitespace: u32,

    // === Escape Sequences ===
    /// Hex escape sequences (\xNN)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hex_escape_count: u32,
    /// Unicode escapes (\uNNNN, \UNNNNNNNN)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unicode_escape_count: u32,
    /// Octal escapes (\NNN)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub octal_escape_count: u32,
    /// Escape sequences per 100 characters
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub escape_density: f32,

    // === Suspicious Text Patterns ===
    /// Tokens over 100 chars without spaces
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub long_token_count: u32,
    /// Repeated character sequences (>10 same char)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub repeated_char_sequences: u32,
    /// Ratio of digits to alphanumeric characters
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub digit_ratio: f32,
    /// Visible ASCII art or banner patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ascii_art_lines: u32,
}

/// Identifier/naming metrics from AST analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentifierMetrics {
    // === Counts ===
    /// Total identifier occurrences
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total: u32,
    /// Unique identifiers
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unique: u32,
    /// Reuse ratio (unique/total, low = repetitive)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub reuse_ratio: f32,

    // === Length Analysis ===
    /// Average identifier length
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_length: f32,
    /// Minimum identifier length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub min_length: u32,
    /// Maximum identifier length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_length: u32,
    /// Standard deviation of lengths
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub length_stddev: f32,
    /// Single-character identifiers (a, b, x, i)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub single_char_count: u32,
    /// Ratio of single-char to total (high = obfuscation)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub single_char_ratio: f32,

    // === Entropy/Randomness ===
    /// Average entropy per identifier name
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_entropy: f32,
    /// Identifiers with entropy > 3.5 (random-looking)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_count: u32,
    /// Ratio of high-entropy identifiers
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub high_entropy_ratio: f32,

    // === Naming Patterns ===
    /// All lowercase identifiers ratio
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub all_lowercase_ratio: f32,
    /// All uppercase identifiers ratio
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub all_uppercase_ratio: f32,
    /// Identifiers containing digits
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub has_digit_ratio: f32,
    /// Underscore-prefixed identifiers (_var, __var)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub underscore_prefix_count: u32,
    /// Double-underscore identifiers (__dunder__)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub double_underscore_count: u32,
    /// Numeric suffix patterns (var1, var2, var3)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub numeric_suffix_count: u32,

    // === Suspicious Patterns ===
    /// Names that look like hex (deadbeef, cafebabe)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hex_like_names: u32,
    /// Names matching base64 character set
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_like_names: u32,
    /// Sequential patterns (a, b, c or var1, var2)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sequential_names: u32,
    /// Keyboard patterns (qwerty, asdf)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub keyboard_pattern_names: u32,
    /// Names that are just repeated chars (aaa, xxx)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub repeated_char_names: u32,
}

/// String literal metrics from AST analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StringMetrics {
    // === Counts & Sizes ===
    /// Total string literals
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total: u32,
    /// Total bytes in all strings
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub total_bytes: u64,
    /// Average string length
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_length: f32,
    /// Maximum string length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_length: u32,
    /// Empty string count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub empty_count: u32,

    // === Entropy Analysis ===
    /// Average entropy across all strings
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_entropy: f32,
    /// Standard deviation of string entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub entropy_stddev: f32,
    /// Strings with entropy > 5.0
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_count: u32,
    /// Strings with entropy > 6.5 (encrypted/compressed)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub very_high_entropy_count: u32,

    // === Encoding Patterns ===
    /// Strings matching base64 pattern
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_candidates: u32,
    /// Pure hexadecimal strings
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hex_strings: u32,
    /// URL-encoded strings (%XX patterns)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub url_encoded_strings: u32,
    /// Strings with many unicode escapes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unicode_heavy_strings: u32,

    // === Content Categories ===
    /// URL strings detected
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub url_count: u32,
    /// File path strings
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub path_count: u32,
    /// IP address strings
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ip_count: u32,
    /// Email address strings
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub email_count: u32,
    /// Domain name strings
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub domain_count: u32,

    // === Construction Patterns (from AST) ===
    /// String concatenation operations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub concat_operations: u32,
    /// Format strings (f-strings, .format, sprintf)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub format_strings: u32,
    /// Character-by-character construction (chr/fromCharCode)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub char_construction: u32,
    /// Array join construction ([].join)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub array_join_construction: u32,

    // === Suspicious Patterns ===
    /// Very long strings (> 1000 chars)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub very_long_strings: u32,
    /// Strings containing code-like patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub embedded_code_candidates: u32,
    /// Strings with shell command patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub shell_command_strings: u32,
    /// Strings with SQL patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sql_strings: u32,
}

/// Comment and documentation metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CommentMetrics {
    /// Total comment count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total: u32,
    /// Lines that are comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lines: u32,
    /// Total characters in comments
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub chars: u64,
    /// Comment to code ratio
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub to_code_ratio: f32,

    // === Comment Patterns ===
    /// TODO comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub todo_count: u32,
    /// FIXME comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fixme_count: u32,
    /// HACK comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hack_count: u32,
    /// XXX comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub xxx_count: u32,
    /// Empty comments (// or /* */)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub empty_comments: u32,

    // === Suspicious Patterns ===
    /// High-entropy comments (random-looking)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_comments: u32,
    /// Comments containing code
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub code_in_comments: u32,
    /// URLs in comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub url_in_comments: u32,
    /// Base64 in comments (hidden payloads)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_in_comments: u32,
}

/// Function/method metrics from AST analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionMetrics {
    // === Counts ===
    /// Total functions/methods
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total: u32,
    /// Anonymous functions (lambdas, closures)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub anonymous: u32,
    /// Async functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub async_count: u32,
    /// Generator functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub generator_count: u32,

    // === Size Analysis ===
    /// Average function length (lines)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_length_lines: f32,
    /// Maximum function length (lines)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_length_lines: u32,
    /// Minimum function length (lines)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub min_length_lines: u32,
    /// Standard deviation of function lengths
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub length_stddev: f32,
    /// Functions over 100 lines
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub over_100_lines: u32,
    /// Functions over 500 lines (very suspicious)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub over_500_lines: u32,
    /// One-liner functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub one_liners: u32,

    // === Parameter Analysis ===
    /// Average parameter count
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_params: f32,
    /// Maximum parameter count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_params: u32,
    /// Functions with no parameters
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub no_params_count: u32,
    /// Functions with many parameters (>7)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub many_params_count: u32,
    /// Average parameter name length
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_param_name_length: f32,
    /// Single-char parameter names (x, y, a)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub single_char_params: u32,

    // === Naming Analysis ===
    /// Average function name length
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_name_length: f32,
    /// Single-char function names
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub single_char_names: u32,
    /// High entropy function names (random-looking)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_names: u32,
    /// Numeric-suffix function names (func1, func2)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub numeric_suffix_names: u32,

    // === Nesting & Complexity ===
    /// Maximum nesting depth across all functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_nesting_depth: u32,
    /// Average nesting depth
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_nesting_depth: f32,
    /// Nested function definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nested_functions: u32,
    /// Recursive functions detected
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub recursive_count: u32,

    // === Density ===
    /// Functions per 100 lines of code
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub density_per_100_lines: f32,
    /// Code to function ratio (lines in functions / total lines)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub code_in_functions_ratio: f32,
}

// =============================================================================
// LANGUAGE-SPECIFIC METRICS
// =============================================================================

/// Python-specific metrics for obfuscation/malware detection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PythonMetrics {
    // === Dynamic Execution ===
    /// eval() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_count: u32,
    /// exec() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_count: u32,
    /// compile() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub compile_count: u32,
    /// __import__() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dunder_import_count: u32,
    /// importlib usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub importlib_count: u32,
    /// getattr/setattr/delattr calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub attr_manipulation_count: u32,

    // === Obfuscation Patterns ===
    /// chr() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chr_calls: u32,
    /// ord() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ord_calls: u32,
    /// Lambda expressions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lambda_count: u32,
    /// Nested lambdas (lambda inside lambda)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nested_lambda_count: u32,
    /// Maximum comprehension nesting depth
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub comprehension_depth_max: u32,
    /// Walrus operator usage (:=)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub walrus_operator_count: u32,

    // === Reflection/Introspection ===
    /// globals()/locals() access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub globals_locals_access: u32,
    /// __builtins__ access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub builtins_access: u32,
    /// type() calls (metaclass tricks)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub type_calls: u32,
    /// __class__ access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_access: u32,
    /// vars() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub vars_calls: u32,
    /// dir() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dir_calls: u32,

    // === Serialization (RCE vectors) ===
    /// pickle usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pickle_usage: u32,
    /// marshal usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub marshal_usage: u32,
    /// yaml.load (unsafe)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub yaml_load_unsafe: u32,
    /// shelve usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub shelve_usage: u32,

    // === Decorators ===
    /// Total decorators
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub decorator_count: u32,
    /// Max decorators stacked on one function
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stacked_decorators_max: u32,

    // === Magic Methods ===
    /// Dunder method definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dunder_method_count: u32,
    /// __getattribute__ override
    #[serde(default, skip_serializing_if = "is_false")]
    pub getattribute_override: bool,
    /// __new__ override
    #[serde(default, skip_serializing_if = "is_false")]
    pub new_override: bool,
    /// Descriptor protocol (__get__, __set__)
    #[serde(default, skip_serializing_if = "is_false")]
    pub descriptor_protocol: bool,

    // === Encoding/Decoding ===
    /// base64 module calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_calls: u32,
    /// codecs module calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub codecs_calls: u32,
    /// zlib/gzip calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub compression_calls: u32,
    /// rot13 usage
    #[serde(default, skip_serializing_if = "is_false")]
    pub rot13_usage: bool,

    // === Control Flow ===
    /// try/except blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub try_except_count: u32,
    /// Bare except (except:)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub bare_except_count: u32,
    /// except Exception (too broad)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub broad_except_count: u32,
    /// Maximum nesting depth
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_nesting_depth: u32,

    // === Additional Structural Metrics ===
    /// vars() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub vars_access: u32,
    /// type() manipulation (3-arg form)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub type_manipulation: u32,
    /// __code__ object access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub code_object_access: u32,
    /// Frame access (sys._getframe, inspect.currentframe)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub frame_access: u32,
    /// Class definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_count: u32,
    /// Metaclass usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub metaclass_usage: u32,
    /// with statement count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub with_statement_count: u32,
    /// assert statement count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub assert_count: u32,
}

/// JavaScript/TypeScript metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JavaScriptMetrics {
    // === Dynamic Execution ===
    /// eval() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_count: u32,
    /// new Function() constructor
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub function_constructor: u32,
    /// setTimeout with string argument
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub settimeout_string: u32,
    /// setInterval with string argument
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub setinterval_string: u32,
    /// document.write calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub document_write: u32,

    // === Obfuscation Patterns ===
    /// String.fromCharCode calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub from_char_code_count: u32,
    /// charCodeAt calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub char_code_at_count: u32,
    /// Array.join for string building
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub array_join_strings: u32,
    /// split().reverse().join() patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub split_reverse_join: u32,
    /// Chained .replace() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub replace_chain_count: u32,
    /// Computed property access obj[var]
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub computed_property_access: u32,

    // === Encoding ===
    /// atob/btoa calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub atob_btoa_count: u32,
    /// escape/unescape calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub escape_unescape: u32,
    /// decodeURIComponent calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub decode_uri_component: u32,

    // === Suspicious Constructs ===
    /// with statements (deprecated)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub with_statement: u32,
    /// debugger statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub debugger_statements: u32,
    /// arguments.caller/callee access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub caller_callee_access: u32,
    /// Prototype pollution patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub prototype_pollution_patterns: u32,
    /// __proto__ access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub proto_access: u32,

    // === Functions & Closures ===
    /// IIFE count (function(){})()
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub iife_count: u32,
    /// Maximum nested IIFE depth
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nested_iife_depth: u32,
    /// Arrow function count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub arrow_function_count: u32,
    /// Maximum closure depth
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub closure_depth_max: u32,

    // === Array/Object Patterns ===
    /// Large array literals (>100 elements)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub large_array_literals: u32,
    /// Computed object keys {[expr]: val}
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub computed_key_count: u32,
    /// Excessive spread operator usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub spread_count: u32,

    // === DOM Manipulation ===
    /// innerHTML assignments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub innerhtml_writes: u32,
    /// Script element creation
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub script_element_creation: u32,
    /// Event handler strings (onclick="...")
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub event_handler_strings: u32,
    /// XHR/fetch usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub network_requests: u32,
}

/// Shell script metrics (bash/sh/zsh)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShellMetrics {
    // === Command Execution ===
    /// eval usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_count: u32,
    /// source or . command
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub source_count: u32,
    /// exec command
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_count: u32,
    /// bash -c usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub bash_c_count: u32,
    /// xargs usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub xargs_count: u32,

    // === Network Operations ===
    /// curl/wget usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub curl_wget_count: u32,
    /// nc/netcat usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nc_netcat_count: u32,
    /// /dev/tcp or /dev/udp usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dev_tcp_count: u32,
    /// DNS exfiltration patterns (dig, nslookup abuse)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dns_exfil_patterns: u32,
    /// ssh/scp usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ssh_scp_count: u32,

    // === Encoding/Decoding ===
    /// base64 decode usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_decode_count: u32,
    /// xxd usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub xxd_count: u32,
    /// printf with hex escapes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub printf_hex_count: u32,
    /// openssl encryption usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub openssl_enc_count: u32,
    /// gzip/gunzip usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub gzip_count: u32,

    // === Pipes & Redirection ===
    /// Pipe count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pipe_count: u32,
    /// Maximum pipe chain depth
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pipe_depth_max: u32,
    /// Here-doc count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub here_doc_count: u32,
    /// Process substitution <() >()
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub process_substitution: u32,
    /// File descriptor redirection
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fd_redirection: u32,

    // === Anti-Forensics ===
    /// History manipulation (unset HISTFILE, etc.)
    #[serde(default, skip_serializing_if = "is_false")]
    pub history_manipulation: bool,
    /// Background job usage (&)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub background_jobs: u32,
    /// nohup/disown usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nohup_disown_count: u32,
    /// cron/at manipulation
    #[serde(default, skip_serializing_if = "is_false")]
    pub cron_at_manipulation: bool,
    /// chmod +x usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chmod_x_count: u32,
    /// shred/rm -rf usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub secure_delete_count: u32,

    // === Variable Tricks ===
    /// Indirect variable expansion ${!var}
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub indirect_vars: u32,
    /// eval with variable expansion
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_expansion: u32,
    /// IFS manipulation
    #[serde(default, skip_serializing_if = "is_false")]
    pub ifs_manipulation: bool,
    /// PATH manipulation
    #[serde(default, skip_serializing_if = "is_false")]
    pub path_manipulation: bool,

    // === Timing/Evasion ===
    /// sleep commands
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sleep_count: u32,
    /// timeout command
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub timeout_count: u32,
    /// trap commands (signal handling)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub trap_count: u32,

    // === System Modification ===
    /// dd usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dd_usage: u32,
    /// mkfifo/mknod usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub special_file_creation: u32,
    /// iptables/firewall manipulation
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub firewall_manipulation: u32,
}

/// PowerShell metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PowerShellMetrics {
    // === Execution ===
    /// Invoke-Expression (IEX) count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub invoke_expression_count: u32,
    /// Invoke-Command count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub invoke_command_count: u32,
    /// Start-Process count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub start_process_count: u32,
    /// -EncodedCommand usage
    #[serde(default, skip_serializing_if = "is_false")]
    pub encoded_command_usage: bool,
    /// & call operator abuse
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub call_operator_count: u32,

    // === Download Cradles ===
    /// Net.WebClient usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub webclient_count: u32,
    /// Invoke-WebRequest
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub webrequest_count: u32,
    /// DownloadString calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub downloadstring_count: u32,
    /// DownloadFile calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub downloadfile_count: u32,
    /// BitsTransfer usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub bitstransfer_count: u32,

    // === Obfuscation Techniques ===
    /// Tick character obfuscation (`s`t`r)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub tick_obfuscation: u32,
    /// Caret obfuscation (^s^t^r)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub caret_obfuscation: u32,
    /// String concatenation ("str" + "ing")
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub concat_obfuscation: u32,
    /// Format string obfuscation ("{0}{1}" -f)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub format_obfuscation: u32,
    /// -replace obfuscation
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub replace_obfuscation: u32,
    /// [char[]] array usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub char_array_count: u32,
    /// Variable substitution tricks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub variable_substitution: u32,

    // === Reflection/Bypass ===
    /// [Reflection.Assembly] usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub reflection_assembly: u32,
    /// Add-Type count (compile C#)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub add_type_count: u32,
    /// Type accelerators [type]::method
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub type_accelerators: u32,
    /// AMSI bypass indicators
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub amsi_bypass_indicators: u32,
    /// ETW bypass indicators
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub etw_bypass_indicators: u32,
    /// Execution policy bypass
    #[serde(default, skip_serializing_if = "is_false")]
    pub execution_policy_bypass: bool,

    // === Suspicious Cmdlets ===
    /// Get-Process usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub get_process_count: u32,
    /// Get-WmiObject/Get-CimInstance
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub wmi_cim_count: u32,
    /// New-Object count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub new_object_count: u32,
    /// Registry access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub registry_access: u32,
    /// Credential access patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub credential_access: u32,

    // === Encoding ===
    /// Base64 patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_patterns: u32,
    /// Gzip decompression
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub gzip_decompress: u32,
    /// SecureString usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub securestring_usage: u32,
}

/// PHP metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PhpMetrics {
    // === Dangerous Functions ===
    /// eval() usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_count: u32,
    /// assert() with string
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub assert_string_count: u32,
    /// create_function() usage (deprecated)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub create_function_count: u32,
    /// preg_replace with /e modifier
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub preg_replace_e_count: u32,
    /// call_user_func usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub call_user_func_count: u32,

    // === Command Execution ===
    /// system() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub system_count: u32,
    /// exec() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_count: u32,
    /// shell_exec() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub shell_exec_count: u32,
    /// passthru() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub passthru_count: u32,
    /// Backtick execution
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub backtick_count: u32,
    /// proc_open() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub proc_open_count: u32,
    /// popen() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub popen_count: u32,

    // === File Operations ===
    /// Dynamic include/require
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub include_require_dynamic: u32,
    /// file_get_contents usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub file_get_contents_count: u32,
    /// file_put_contents usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub file_put_contents_count: u32,
    /// fwrite usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fwrite_count: u32,

    // === Obfuscation ===
    /// Variable variables ($$var)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub variable_variables: u32,
    /// extract() usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub extract_count: u32,
    /// chr/pack usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chr_pack_count: u32,
    /// base64_decode usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_decode_count: u32,
    /// gzinflate usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub gzinflate_count: u32,
    /// gzuncompress usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub gzuncompress_count: u32,
    /// str_rot13 usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub str_rot13_count: u32,
    /// hex2bin usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hex2bin_count: u32,

    // === Network ===
    /// curl usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub curl_count: u32,
    /// fsockopen usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fsockopen_count: u32,
    /// stream_socket usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub stream_socket_count: u32,

    // === Suspicious Patterns ===
    /// @ error suppression
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub error_suppression: u32,
    /// ini_set calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ini_set_count: u32,
    /// $GLOBALS access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub globals_access: u32,
    /// $_REQUEST/$_GET/$_POST access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub superglobal_input: u32,
}

/// Ruby metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RubyMetrics {
    // === Dynamic Execution ===
    /// eval usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_count: u32,
    /// instance_eval usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub instance_eval_count: u32,
    /// class_eval/module_eval usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_module_eval_count: u32,
    /// send/public_send usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub send_count: u32,
    /// method_missing definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub method_missing_count: u32,
    /// define_method usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub define_method_count: u32,

    // === Command Execution ===
    /// system() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub system_count: u32,
    /// exec() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_count: u32,
    /// Backtick/x{} execution
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub backtick_count: u32,
    /// Open3/spawn usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub spawn_popen_count: u32,

    // === Serialization ===
    /// Marshal.load usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub marshal_load_count: u32,
    /// YAML.load usage (unsafe)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub yaml_load_count: u32,

    // === Metaprogramming ===
    /// const_get/const_set usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub const_manipulation: u32,
    /// binding usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub binding_usage: u32,
    /// ObjectSpace usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub objectspace_usage: u32,

    // === Obfuscation ===
    /// pack/unpack usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pack_unpack_count: u32,
    /// chr/ord usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chr_ord_count: u32,
}

/// Perl metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerlMetrics {
    // === Dynamic Execution ===
    /// eval STRING usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_string_count: u32,
    /// eval BLOCK usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub eval_block_count: u32,
    /// do FILE usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub do_count: u32,
    /// Dynamic require
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub require_dynamic: u32,

    // === Command Execution ===
    /// system() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub system_count: u32,
    /// exec() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_count: u32,
    /// Backtick/qx execution
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub backtick_qx_count: u32,
    /// open() with pipe
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub open_pipe_count: u32,

    // === Obfuscation ===
    /// pack/unpack usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pack_unpack_count: u32,
    /// chr/ord usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub chr_ord_count: u32,
    /// Symbolic dereferencing ($$var)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub symbolic_deref_count: u32,
    /// Regex code execution (?{})
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub regex_code_count: u32,

    // === Special Blocks ===
    /// BEGIN/END/CHECK/INIT blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub special_block_count: u32,
    /// tie usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub tie_usage: u32,
    /// AUTOLOAD definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub autoload_count: u32,
}

/// Go-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GoMetrics {
    // === Dangerous Packages ===
    /// unsafe package usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unsafe_usage: u32,
    /// reflect package usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub reflect_usage: u32,
    /// CGo usage (import "C")
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cgo_usage: u32,
    /// plugin package usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub plugin_usage: u32,
    /// syscall direct usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub syscall_direct: u32,

    // === Execution ===
    /// exec.Command usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_command_count: u32,
    /// os.StartProcess usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub os_startprocess_count: u32,

    // === Network ===
    /// net.Dial usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub net_dial_count: u32,
    /// http client/server usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub http_usage: u32,
    /// Raw socket usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub raw_socket_count: u32,

    // === Embedding ===
    /// //go:embed directives
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub embed_directive_count: u32,
    /// Embedded binary data size
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub embedded_binary_size: u64,

    // === Build Configuration ===
    /// //go:linkname usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub linkname_count: u32,
    /// //go:noescape usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub noescape_count: u32,
    /// #cgo directives
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cgo_directives: u32,

    // === Patterns ===
    /// init() function count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub init_function_count: u32,
    /// Blank imports (import _ "pkg")
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub blank_import_count: u32,
}

/// Rust-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RustMetrics {
    // === Unsafe ===
    /// unsafe blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unsafe_block_count: u32,
    /// unsafe fn declarations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unsafe_fn_count: u32,
    /// Raw pointer operations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub raw_pointer_count: u32,
    /// std::mem::transmute usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub transmute_count: u32,

    // === FFI ===
    /// extern fn declarations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub extern_fn_count: u32,
    /// extern blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub extern_block_count: u32,
    /// #[link] attributes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub link_attribute_count: u32,

    // === Execution ===
    /// std::process::Command usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub command_count: u32,
    /// Shell execution patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub shell_count: u32,

    // === Embedding ===
    /// include_bytes! macro usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub include_bytes_count: u32,
    /// include_str! macro usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub include_str_count: u32,
    /// Embedded data size
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub embedded_size: u64,

    // === Macros ===
    /// Procedural macro usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub proc_macro_count: u32,
    /// macro_rules! definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub macro_rules_count: u32,
    /// asm! macro usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub asm_macro_count: u32,
}

/// C/C++ metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CMetrics {
    // === Dangerous Constructs ===
    /// Inline assembly
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub inline_asm_count: u32,
    /// goto statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub goto_count: u32,
    /// setjmp/longjmp usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub setjmp_longjmp_count: u32,
    /// Computed goto (goto *ptr)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub computed_goto_count: u32,

    // === Function Pointers ===
    /// Function pointer declarations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fn_pointer_count: u32,
    /// Function pointer arrays
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fn_pointer_array_count: u32,

    // === Memory Operations ===
    /// malloc/free calls (for ratio)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub malloc_count: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub free_count: u32,
    /// void pointer usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub void_pointer_count: u32,
    /// Type casts
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cast_count: u32,
    /// memcpy/memmove usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub memcpy_count: u32,

    // === Preprocessor ===
    /// Macro definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub macro_count: u32,
    /// Conditional compilation (#ifdef)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub conditional_compile_count: u32,
    /// #pragma directives
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pragma_count: u32,

    // === Suspicious Patterns ===
    /// Shellcode-like byte arrays
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub shellcode_arrays: u32,
    /// XOR operation loops
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub xor_loops: u32,
    /// VirtualAlloc/mmap with EXEC
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exec_memory_alloc: u32,
}

/// Java source metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JavaSourceMetrics {
    // === Reflection ===
    /// Class.forName usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_forname_count: u32,
    /// getMethod/getDeclaredMethod usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub get_method_count: u32,
    /// invoke() calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub invoke_count: u32,
    /// setAccessible(true) calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub set_accessible_count: u32,

    // === Execution ===
    /// Runtime.exec usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub runtime_exec_count: u32,
    /// ProcessBuilder usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub processbuilder_count: u32,

    // === ClassLoading ===
    /// URLClassLoader usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub urlclassloader_count: u32,
    /// defineClass usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub defineclass_count: u32,
    /// Custom ClassLoader
    #[serde(default, skip_serializing_if = "is_false")]
    pub custom_classloader: bool,

    // === Serialization ===
    /// ObjectInputStream usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub objectinputstream_count: u32,
    /// readObject override
    #[serde(default, skip_serializing_if = "is_false")]
    pub readobject_override: bool,

    // === Scripting ===
    /// ScriptEngine usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub scriptengine_count: u32,

    // === JNI ===
    /// native method declarations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub native_method_count: u32,
    /// System.loadLibrary calls
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub load_library_count: u32,
}

/// Lua metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LuaMetrics {
    /// loadstring/load usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub loadstring_count: u32,
    /// dofile usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dofile_count: u32,
    /// loadfile usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub loadfile_count: u32,
    /// os.execute usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub os_execute_count: u32,
    /// io.popen usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub io_popen_count: u32,
    /// debug library usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub debug_library_usage: u32,
    /// setfenv/getfenv usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub setfenv_count: u32,
    /// rawset/rawget usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub rawset_rawget_count: u32,
    /// string.dump (bytecode generation)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub string_dump_count: u32,
}

/// C# metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CSharpMetrics {
    // === P/Invoke ===
    /// DllImport declarations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dllimport_count: u32,
    /// Marshal class usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub marshal_usage: u32,

    // === Reflection ===
    /// Assembly.Load* usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub assembly_load_count: u32,
    /// Activator.CreateInstance usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub activator_count: u32,
    /// Type.GetMethod usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub reflection_invoke: u32,

    // === Execution ===
    /// Process.Start usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub process_start_count: u32,

    // === Network ===
    /// WebClient/HttpClient usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub web_client_count: u32,
    /// Socket usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub socket_count: u32,

    // === Unsafe ===
    /// unsafe blocks
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unsafe_block_count: u32,
    /// fixed statements
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fixed_statement_count: u32,

    // === Suspicious ===
    /// CryptoStream usage
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub crypto_usage: u32,
    /// Registry access
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub registry_access: u32,
}

// =============================================================================
// BINARY METRICS
// =============================================================================

/// Universal binary metrics (ELF/PE/Mach-O)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BinaryMetrics {
    // === Entropy ===
    /// Overall file entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub overall_entropy: f32,
    /// Code section entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub code_entropy: f32,
    /// Data section entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub data_entropy: f32,
    /// Entropy variance across sections
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub entropy_variance: f32,
    /// High entropy regions (>7.5)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_regions: u32,

    // === Sections ===
    /// Total section count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub section_count: u32,
    /// Executable sections
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub executable_sections: u32,
    /// Writable sections
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub writable_sections: u32,
    /// W+X sections (self-modifying)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub wx_sections: u32,
    /// Section name entropy (random names = packer)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub section_name_entropy: f32,
    /// Largest section ratio to file size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub largest_section_ratio: f32,

    // === Imports/Exports ===
    /// Import count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub import_count: u32,
    /// Export count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub export_count: u32,
    /// Import name entropy (randomness)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub import_entropy: f32,

    // === Strings ===
    /// String count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub string_count: u32,
    /// Average string entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_string_entropy: f32,
    /// High entropy strings
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_strings: u32,
    /// Strings in code sections (unusual)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub strings_in_code: u32,

    // === Functions ===
    /// Function count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub function_count: u32,
    /// Average function size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_function_size: f32,
    /// Tiny functions (<16 bytes)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub tiny_functions: u32,
    /// Huge functions (>64KB)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub huge_functions: u32,
    /// Indirect call instructions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub indirect_calls: u32,
    /// Indirect jump instructions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub indirect_jumps: u32,

    // === Complexity (from radare2 analysis) ===
    /// Average cyclomatic complexity
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_complexity: f32,
    /// Maximum cyclomatic complexity
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_complexity: u32,
    /// Functions with high complexity (>50)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_complexity_functions: u32,
    /// Names of high complexity functions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub high_complexity_function_names: Vec<String>,
    /// Functions with very high complexity (>100)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub very_high_complexity_functions: u32,
    /// Names of very high complexity functions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub very_high_complexity_function_names: Vec<String>,

    // === Control Flow ===
    /// Total basic blocks across all functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_basic_blocks: u32,
    /// Average basic blocks per function
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_basic_blocks: f32,
    /// Linear functions (no branches)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub linear_functions: u32,
    /// Recursive functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub recursive_functions: u32,
    /// Non-returning functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub noreturn_functions: u32,
    /// Leaf functions (make no calls)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub leaf_functions: u32,

    // === Stack ===
    /// Average stack frame size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_stack_frame: f32,
    /// Maximum stack frame size
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_stack_frame: u32,
    /// Functions with large stack (>4KB)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub large_stack_functions: u32,
    /// Names of large stack functions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub large_stack_function_names: Vec<String>,

    // === Overlay ===
    /// Has overlay data
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_overlay: bool,
    /// Overlay size in bytes
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub overlay_size: u64,
    /// Overlay ratio to file size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub overlay_ratio: f32,
    /// Overlay entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub overlay_entropy: f32,
}

/// ELF-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ElfMetrics {
    // === Header ===
    /// Entry point not in .text
    #[serde(default, skip_serializing_if = "is_false")]
    pub entry_not_in_text: bool,
    /// Entry point section name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_section: Option<String>,

    // === Dynamic Linking ===
    /// Number of needed libraries
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub needed_libs: u32,
    /// RPATH set
    #[serde(default, skip_serializing_if = "is_false")]
    pub rpath_set: bool,
    /// RUNPATH set
    #[serde(default, skip_serializing_if = "is_false")]
    pub runpath_set: bool,
    /// DT_INIT_ARRAY count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub init_array_count: u32,
    /// DT_FINI_ARRAY count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fini_array_count: u32,

    // === Symbols ===
    /// Stripped (no symbols)
    #[serde(default, skip_serializing_if = "is_false")]
    pub stripped: bool,
    /// Hidden visibility symbols
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hidden_symbols: u32,
    /// GNU hash present
    #[serde(default, skip_serializing_if = "is_false")]
    pub gnu_hash_present: bool,

    // === Security Features ===
    /// RELRO status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relro: Option<String>,
    /// TEXTREL present (bad)
    #[serde(default, skip_serializing_if = "is_false")]
    pub textrel_present: bool,
    /// Stack canary
    #[serde(default, skip_serializing_if = "is_false")]
    pub stack_canary: bool,
    /// NX (non-executable stack)
    #[serde(default, skip_serializing_if = "is_false")]
    pub nx_enabled: bool,
    /// PIE enabled
    #[serde(default, skip_serializing_if = "is_false")]
    pub pie_enabled: bool,

    // === Special Sections ===
    /// Has .plt
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_plt: bool,
    /// Has .got
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_got: bool,
    /// Has .eh_frame
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_eh_frame: bool,
    /// Has .note section
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_note: bool,
}

/// PE-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeMetrics {
    // === Header Anomalies ===
    /// Timestamp anomaly (future or ancient)
    #[serde(default, skip_serializing_if = "is_false")]
    pub timestamp_anomaly: bool,
    /// Checksum valid
    #[serde(default, skip_serializing_if = "is_false")]
    pub checksum_valid: bool,
    /// Rich header present
    #[serde(default, skip_serializing_if = "is_false")]
    pub rich_header_present: bool,
    /// DOS stub modified
    #[serde(default, skip_serializing_if = "is_false")]
    pub dos_stub_modified: bool,

    // === Sections ===
    /// Resource section size
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub rsrc_size: u64,
    /// Resource section entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub rsrc_entropy: f32,
    /// Unusual section alignment
    #[serde(default, skip_serializing_if = "is_false")]
    pub unusual_alignment: bool,

    // === Imports ===
    /// Delay-load imports
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub delay_load_imports: u32,
    /// Ordinal-only imports
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ordinal_imports: u32,
    /// API hashing indicators
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub api_hashing_indicators: u32,
    /// Suspicious import combo (VirtualAlloc+Write+Protect)
    #[serde(default, skip_serializing_if = "is_false")]
    pub suspicious_import_combo: bool,

    // === Exports ===
    /// Export forwarders
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub export_forwarders: u32,

    // === Resources ===
    /// Resource count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub resource_count: u32,
    /// Embedded PE files
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub embedded_pe_count: u32,
    /// Version info present
    #[serde(default, skip_serializing_if = "is_false")]
    pub version_info_present: bool,
    /// Manifest present
    #[serde(default, skip_serializing_if = "is_false")]
    pub manifest_present: bool,
    /// Icon count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub icon_count: u32,

    // === .NET ===
    /// Is .NET assembly
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_dotnet: bool,
    /// CLR version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clr_version: Option<String>,
    /// Mixed mode (native + .NET)
    #[serde(default, skip_serializing_if = "is_false")]
    pub mixed_mode: bool,

    // === TLS ===
    /// TLS callback count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub tls_callbacks: u32,

    // === Authenticode ===
    /// Has digital signature
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_signature: bool,
    /// Signature valid
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_valid: Option<bool>,
}

/// Mach-O specific metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MachoMetrics {
    // === Structure ===
    /// Universal (fat) binary
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_universal: bool,
    /// Slice count (for universal)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub slice_count: u32,

    // === Load Commands ===
    /// Load command count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub load_command_count: u32,
    /// Has code signature
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_code_signature: bool,
    /// Signature valid
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_valid: Option<bool>,

    // === Segments ===
    /// Segment count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub segment_count: u32,
    /// __LINKEDIT size
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub linkedit_size: u64,
    /// __TEXT segment entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub text_entropy: f32,

    // === Symbols ===
    /// Symbol count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub symbol_count: u32,
    /// Indirect symbol count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub indirect_symbol_count: u32,
    /// Stripped
    #[serde(default, skip_serializing_if = "is_false")]
    pub stripped: bool,

    // === Entitlements ===
    /// Has entitlements
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_entitlements: bool,
    /// Dangerous entitlement count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dangerous_entitlements: u32,

    // === dyld ===
    /// dylib dependency count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub dylib_count: u32,
    /// Weak dylib count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub weak_dylib_count: u32,
    /// @rpath count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub rpath_count: u32,

    // === Hardened Runtime ===
    /// Hardened runtime enabled
    #[serde(default, skip_serializing_if = "is_false")]
    pub hardened_runtime: bool,
    /// Allow unsigned executable memory
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_jit: bool,
}

/// Java class file metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JavaClassMetrics {
    // === Version ===
    /// Major version number
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub major_version: u32,
    /// Minor version number
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub minor_version: u32,
    /// Java version string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub java_version: Option<String>,

    // === Constant Pool ===
    /// Constant pool size
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub constant_pool_size: u32,
    /// UTF8 constants
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub utf8_constants: u32,
    /// Class references
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub class_refs: u32,
    /// Method references
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub method_refs: u32,
    /// String constant entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub string_constant_entropy: f32,
    /// Obfuscated string count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub obfuscated_strings: u32,

    // === Methods ===
    /// Method count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub method_count: u32,
    /// Native methods
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub native_methods: u32,
    /// Synthetic (compiler-generated) methods
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub synthetic_methods: u32,
    /// Average method size
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_method_size: f32,
    /// Maximum method size
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_method_size: u32,

    // === Bytecode ===
    /// invokedynamic count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub invokedynamic_count: u32,
    /// Reflection patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub reflection_patterns: u32,

    // === Debug Info ===
    /// Has source file attribute
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_source_file: bool,
    /// Has line numbers
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_line_numbers: bool,
    /// Has local variable info
    #[serde(default, skip_serializing_if = "is_false")]
    pub has_local_vars: bool,
    /// Inner class count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub inner_class_count: u32,
}

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

/// Composite obfuscation score for source code
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObfuscationScore {
    /// Overall obfuscation score (0.0-1.0)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub score: f32,
    /// Confidence in the score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub conf: f32,

    // === Component Scores ===
    /// Naming obfuscation score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub naming_score: f32,
    /// String obfuscation score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub string_score: f32,
    /// Structure obfuscation score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub structure_score: f32,
    /// Encoding obfuscation score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub encoding_score: f32,
    /// Dynamic execution score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub dynamic_score: f32,

    /// Human-readable contributing signals
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<String>,
}

/// Composite packing score for binaries
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PackingScore {
    /// Overall packing score (0.0-1.0)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub score: f32,
    /// Confidence in the score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub conf: f32,

    // === Component Scores ===
    /// Entropy-based score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub entropy_score: f32,
    /// Import analysis score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub import_score: f32,
    /// String analysis score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub string_score: f32,
    /// Section analysis score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub section_score: f32,

    /// Known packer name if detected
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_packer: Option<String>,
    /// Human-readable contributing signals
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<String>,
}

/// Supply chain risk score for packages/archives
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SupplyChainScore {
    /// Overall risk score (0.0-1.0)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub score: f32,
    /// Confidence in the score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub conf: f32,

    // === Component Scores ===
    /// Install script risk
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub install_script_score: f32,
    /// Dependency risk
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub dependency_score: f32,
    /// Metadata completeness score
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub metadata_score: f32,
    /// Typosquatting risk
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub typosquat_score: f32,

    /// Human-readable contributing signals
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_criticality_enum() {
        assert!(Criticality::Inert < Criticality::Notable);
        assert!(Criticality::Notable < Criticality::Suspicious);
        assert!(Criticality::Suspicious < Criticality::Hostile);
    }

    #[test]
    fn test_criticality_default() {
        assert_eq!(Criticality::default(), Criticality::Inert);
    }

    #[test]
    fn test_criticality_serialization() {
        let crit = Criticality::Hostile;
        let json = serde_json::to_string(&crit).unwrap();
        assert_eq!(json, "\"hostile\"");

        let deserialized: Criticality = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, Criticality::Hostile);
    }

    #[test]
    fn test_path_type_enum_variants() {
        let types = [PathType::Absolute, PathType::Relative, PathType::Dynamic];
        assert_eq!(types.len(), 3);
    }

    #[test]
    fn test_path_category_enum_variants() {
        let categories = vec![
            PathCategory::System,
            PathCategory::Config,
            PathCategory::Temp,
            PathCategory::Log,
            PathCategory::Home,
            PathCategory::Device,
            PathCategory::Runtime,
            PathCategory::Hidden,
            PathCategory::Network,
            PathCategory::Other,
        ];
        assert_eq!(categories.len(), 10);
    }

    #[test]
    fn test_path_access_type_enum() {
        let access_types = [
            PathAccessType::Read,
            PathAccessType::Write,
            PathAccessType::Execute,
            PathAccessType::Delete,
            PathAccessType::Create,
            PathAccessType::Unknown,
        ];
        assert_eq!(access_types.len(), 6);
    }

    #[test]
    fn test_string_type_enum_variants() {
        let types = vec![
            StringType::Url,
            StringType::Ip,
            StringType::Path,
            StringType::Email,
            StringType::Base64,
            StringType::Plain,
            StringType::Literal,
            StringType::Comment,
            StringType::Docstring,
        ];
        assert_eq!(types.len(), 9);
    }

    #[test]
    fn test_env_var_access_type_enum() {
        let access_types = [
            EnvVarAccessType::Read,
            EnvVarAccessType::Write,
            EnvVarAccessType::Delete,
            EnvVarAccessType::Unknown,
        ];
        assert_eq!(access_types.len(), 4);
    }

    #[test]
    fn test_env_var_category_enum() {
        let categories = vec![
            EnvVarCategory::Path,
            EnvVarCategory::User,
            EnvVarCategory::System,
            EnvVarCategory::Temp,
            EnvVarCategory::Display,
            EnvVarCategory::Credential,
            EnvVarCategory::Runtime,
            EnvVarCategory::Platform,
            EnvVarCategory::Injection,
            EnvVarCategory::Locale,
            EnvVarCategory::Network,
            EnvVarCategory::Other,
        ];
        assert_eq!(categories.len(), 12);
    }

    #[test]
    fn test_directory_access_pattern_enum() {
        let _pattern1 = DirectoryAccessPattern::SingleFile;
        let _pattern2 = DirectoryAccessPattern::MultipleSpecific { count: 3 };
        let _pattern3 = DirectoryAccessPattern::Enumeration {
            pattern: Some("*.txt".to_string()),
        };
        let _pattern4 = DirectoryAccessPattern::BatchOperation {
            operation: "delete".to_string(),
            count: 5,
        };
        let _pattern5 = DirectoryAccessPattern::UserEnumeration;
    }

    #[test]
    fn test_target_info_creation() {
        let target = TargetInfo {
            path: "/bin/ls".to_string(),
            file_type: "elf".to_string(),
            size_bytes: 12345,
            sha256: "abc123".to_string(),
            architectures: Some(vec!["x86_64".to_string()]),
        };

        assert_eq!(target.path, "/bin/ls");
        assert_eq!(target.file_type, "elf");
        assert_eq!(target.size_bytes, 12345);
        assert!(target.architectures.is_some());
    }

    #[test]
    fn test_analysis_report_new() {
        let target = TargetInfo {
            path: "/test".to_string(),
            file_type: "elf".to_string(),
            size_bytes: 100,
            sha256: "test".to_string(),
            architectures: None,
        };

        let report = AnalysisReport::new(target);

        assert_eq!(report.schema_version, "1.1");
        assert_eq!(report.target.path, "/test");
        assert!(report.findings.is_empty());
        assert!(report.strings.is_empty());
    }

    #[test]
    fn test_analysis_report_new_with_timestamp() {
        let target = TargetInfo {
            path: "/test".to_string(),
            file_type: "elf".to_string(),
            size_bytes: 100,
            sha256: "test".to_string(),
            architectures: None,
        };

        let timestamp = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let report = AnalysisReport::new_with_timestamp(target, timestamp);

        assert_eq!(report.schema_version, "1.1");
        assert_eq!(report.target.path, "/test");
        assert_eq!(report.analysis_timestamp, timestamp);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_trait_new_constructor() {
        let trait_obj = Trait::new(
            TraitKind::String,
            "test_value".to_string(),
            "test_source".to_string(),
        );

        assert_eq!(trait_obj.kind, TraitKind::String);
        assert_eq!(trait_obj.value, "test_value");
        assert_eq!(trait_obj.source, "test_source");
    }

    #[test]
    fn test_finding_constructor() {
        let evidence = vec![Evidence {
            method: "symbol".to_string(),
            source: "goblin".to_string(),
            value: "socket".to_string(),
            location: Some("0x1000".to_string()),
        }];

        let finding = Finding {
            id: "net/socket".to_string(),
            kind: FindingKind::Capability,
            desc: "Network socket".to_string(),
            conf: 1.0,
            crit: Criticality::Inert,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence,
        };

        assert_eq!(finding.id, "net/socket");
        assert_eq!(finding.conf, 1.0);
        assert!(finding.evidence.len() == 1);
    }

    #[test]
    fn test_evidence_creation() {
        let evidence = Evidence {
            method: "symbol".to_string(),
            source: "goblin".to_string(),
            value: "socket".to_string(),
            location: Some("0x1000".to_string()),
        };

        assert_eq!(evidence.method, "symbol");
        assert_eq!(evidence.source, "goblin");
        assert_eq!(evidence.value, "socket");
        assert_eq!(evidence.location, Some("0x1000".to_string()));
    }

    #[test]
    fn test_path_info_creation() {
        let path = PathInfo {
            path: "/etc/passwd".to_string(),
            path_type: PathType::Absolute,
            category: PathCategory::Config,
            access_type: Some(PathAccessType::Read),
            source: "strings".to_string(),
            evidence: vec![],
            referenced_by_traits: vec![],
        };

        assert_eq!(path.path, "/etc/passwd");
        assert_eq!(path.path_type, PathType::Absolute);
        assert_eq!(path.category, PathCategory::Config);
        assert_eq!(path.access_type, Some(PathAccessType::Read));
    }

    #[test]
    fn test_env_var_info_creation() {
        let env_var = EnvVarInfo {
            name: "USER".to_string(),
            category: EnvVarCategory::User,
            access_type: EnvVarAccessType::Read,
            source: "tree-sitter".to_string(),
            evidence: vec![],
            referenced_by_traits: vec![],
        };

        assert_eq!(env_var.name, "USER");
        assert_eq!(env_var.category, EnvVarCategory::User);
        assert_eq!(env_var.access_type, EnvVarAccessType::Read);
    }

    #[test]
    fn test_function_creation() {
        let func = Function {
            name: "main".to_string(),
            offset: Some("0x1000".to_string()),
            size: Some(256),
            complexity: Some(5),
            calls: vec!["printf".to_string()],
            source: "radare2".to_string(),
            control_flow: None,
            instruction_analysis: None,
            register_usage: None,
            constants: vec![],
            properties: None,
            signature: None,
            nesting: None,
            call_patterns: None,
        };

        assert_eq!(func.name, "main");
        assert_eq!(func.size, Some(256));
        assert_eq!(func.calls.len(), 1);
        assert_eq!(func.source, "radare2");
    }

    #[test]
    fn test_string_info_creation() {
        let string = StringInfo {
            value: "http://example.com".to_string(),
            offset: Some("0x2000".to_string()),
            encoding: "utf8".to_string(),
            string_type: StringType::Url,
            section: Some(".rodata".to_string()),
        };

        assert_eq!(string.value, "http://example.com");
        assert_eq!(string.string_type, StringType::Url);
        assert_eq!(string.encoding, "utf8");
    }

    #[test]
    fn test_section_creation() {
        let section = Section {
            name: ".text".to_string(),
            size: 4096,
            entropy: 6.5,
            permissions: Some("r-x".to_string()),
        };

        assert_eq!(section.name, ".text");
        assert_eq!(section.size, 4096);
        assert_eq!(section.entropy, 6.5);
    }

    #[test]
    fn test_import_creation() {
        let import = Import {
            symbol: "printf".to_string(),
            library: Some("libc.so.6".to_string()),
            source: "goblin".to_string(),
        };

        assert_eq!(import.symbol, "printf");
        assert_eq!(import.library, Some("libc.so.6".to_string()));
        assert_eq!(import.source, "goblin");
    }

    #[test]
    fn test_export_creation() {
        let export = Export {
            symbol: "my_function".to_string(),
            offset: Some("0x1500".to_string()),
            source: "goblin".to_string(),
        };

        assert_eq!(export.symbol, "my_function");
        assert_eq!(export.offset, Some("0x1500".to_string()));
        assert_eq!(export.source, "goblin");
    }

    #[test]
    fn test_yara_match_creation() {
        let yara_match = YaraMatch {
            rule: "malware_rule".to_string(),
            namespace: "malware".to_string(),
            severity: "high".to_string(),
            desc: "Malware detected".to_string(),
            matched_strings: vec![],
            is_capability: false,
            mbc: None,
            attack: None,
        };

        assert_eq!(yara_match.rule, "malware_rule");
        assert_eq!(yara_match.namespace, "malware");
        assert_eq!(yara_match.severity, "high");
    }

    #[test]
    fn test_analysis_metadata_default() {
        let metadata = AnalysisMetadata::default();

        assert!(metadata.tools_used.is_empty());
        assert_eq!(metadata.analysis_duration_ms, 0);
        assert!(metadata.errors.is_empty());
    }

    #[test]
    fn test_structural_feature_serialization() {
        let feature = StructuralFeature {
            id: "binary/stripped".to_string(),
            desc: "Binary is stripped".to_string(),
            evidence: vec![],
        };

        let json = serde_json::to_string(&feature).unwrap();
        let deserialized: StructuralFeature = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, "binary/stripped");
        assert_eq!(deserialized.desc, "Binary is stripped");
    }

    #[test]
    fn test_target_info_serialization() {
        let target = TargetInfo {
            path: "/bin/test".to_string(),
            file_type: "elf".to_string(),
            size_bytes: 1024,
            sha256: "abc123".to_string(),
            architectures: Some(vec!["arm64".to_string()]),
        };

        let json = serde_json::to_string(&target).unwrap();
        let deserialized: TargetInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.path, "/bin/test");
        assert_eq!(deserialized.size_bytes, 1024);
    }

    #[test]
    fn test_directory_access_creation() {
        let dir_access = DirectoryAccess {
            directory: "/tmp".to_string(),
            files: vec!["file1.txt".to_string(), "file2.txt".to_string()],
            file_count: 2,
            access_pattern: DirectoryAccessPattern::MultipleSpecific { count: 2 },
            categories: vec![PathCategory::Temp],
            enumerated: false,
            generated_traits: vec![],
        };

        assert_eq!(dir_access.directory, "/tmp");
        assert_eq!(dir_access.file_count, 2);
        assert_eq!(dir_access.files.len(), 2);
        assert!(!dir_access.enumerated);
    }

    #[test]
    fn test_code_metrics_creation() {
        let metrics = CodeMetrics {
            total_functions: 50,
            total_basic_blocks: 200,
            avg_complexity: 3.5,
            max_complexity: 12,
            total_instructions: 5000,
            code_density: 0.75,
            functions_with_loops: 15,
            functions_with_anomalies: 2,
        };

        assert_eq!(metrics.total_functions, 50);
        assert_eq!(metrics.avg_complexity, 3.5);
        assert_eq!(metrics.max_complexity, 12);
    }
}
