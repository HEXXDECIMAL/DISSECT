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
    pub description: String,
    /// Confidence score (0.5 = heuristic, 1.0 = definitive)
    pub confidence: f32,
    /// Criticality level
    #[serde(default)]
    pub criticality: Criticality,
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
    pub fn new(id: String, kind: FindingKind, description: String, confidence: f32) -> Self {
        Self {
            id,
            kind,
            description,
            confidence,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            trait_refs: Vec::new(),
            evidence: Vec::new(),
        }
    }

    /// Create a capability finding
    pub fn capability(id: String, description: String, confidence: f32) -> Self {
        Self::new(id, FindingKind::Capability, description, confidence)
    }

    /// Create a structural finding (obfuscation, packing, etc.)
    pub fn structural(id: String, description: String, confidence: f32) -> Self {
        Self::new(id, FindingKind::Structural, description, confidence)
    }

    /// Create an indicator finding (threat signals)
    pub fn indicator(id: String, description: String, confidence: f32) -> Self {
        Self::new(id, FindingKind::Indicator, description, confidence)
    }

    /// Create a weakness finding (vulnerabilities)
    pub fn weakness(id: String, description: String, confidence: f32) -> Self {
        Self::new(id, FindingKind::Weakness, description, confidence)
    }

    pub fn with_criticality(mut self, criticality: Criticality) -> Self {
        self.criticality = criticality;
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
    pub description: String,
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StringType {
    Url,
    Ip,
    Path,
    Email,
    Base64,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Import {
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub library: Option<String>,
    pub source: String,
}

#[derive(Debug, Serialize, Deserialize)]
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
    pub description: String,
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
    pub confidence: f32,
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
    pub description: String,
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
    pub embedded_file_types: Vec<String>,
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
            description: "Network socket".to_string(),
            confidence: 1.0,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence,
        };

        assert_eq!(finding.id, "net/socket");
        assert_eq!(finding.confidence, 1.0);
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
            description: "Malware detected".to_string(),
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
            description: "Binary is stripped".to_string(),
            evidence: vec![],
        };

        let json = serde_json::to_string(&feature).unwrap();
        let deserialized: StructuralFeature = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, "binary/stripped");
        assert_eq!(deserialized.description, "Binary is stripped");
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
