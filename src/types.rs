use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Criticality level for traits and capabilities
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    None,
    Low,
    Medium,
    High,
}

impl Default for Criticality {
    fn default() -> Self {
        Criticality::None
    }
}

/// Main analysis output structure
#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub schema_version: String,
    pub analysis_timestamp: DateTime<Utc>,
    pub target: TargetInfo,
    /// Atomic observable characteristics (used to derive capabilities)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub traits: Vec<Trait>,
    /// High-level behavioral capabilities (derived from traits)
    pub capabilities: Vec<Capability>,
    pub structure: Vec<StructuralFeature>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<Function>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub strings: Vec<StringInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<Import>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exports: Vec<Export>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub yara_matches: Vec<YaraMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_properties: Option<BinaryProperties>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_metrics: Option<CodeMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_code_metrics: Option<SourceCodeMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay_metrics: Option<OverlayMetrics>,
    /// Raw paths discovered (complete list)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<PathInfo>,
    /// Paths grouped by directory (analysis view)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub directories: Vec<DirectoryAccess>,
    /// Environment variables accessed
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env_vars: Vec<EnvVarInfo>,
    pub metadata: AnalysisMetadata,
}

impl AnalysisReport {
    pub fn new(target: TargetInfo) -> Self {
        Self {
            schema_version: "1.0".to_string(),
            analysis_timestamp: Utc::now(),
            target,
            traits: Vec::new(),
            capabilities: Vec::new(),
            structure: Vec::new(),
            functions: Vec::new(),
            strings: Vec::new(),
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            yara_matches: Vec::new(),
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TargetInfo {
    pub path: String,
    #[serde(rename = "type")]
    pub file_type: String,
    pub size_bytes: u64,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architectures: Option<Vec<String>>,
}

/// Atomic observable characteristic (e.g., "uses socket API", "contains eval")
/// Traits are combined to form capabilities
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Trait {
    /// Trait identifier using / delimiter (e.g., "net/api/socket", "exec/eval")
    pub id: String,
    /// Human-readable description
    pub description: String,
    /// Confidence score (0.5 = heuristic, 1.0 = definitive)
    pub confidence: f32,
    /// Criticality level (none = internal only, low/medium/high = shown in output)
    #[serde(default)]
    pub criticality: Criticality,
    /// MBC (Malware Behavior Catalog) ID (e.g., "B0036.002", "E1082")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mbc_id: Option<String>,
    /// MITRE ATT&CK Technique ID (e.g., "T1082", "T1059")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_id: Option<String>,
    /// Evidence supporting this trait
    pub evidence: Vec<Evidence>,
    /// Specific paths supporting this trait
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referenced_paths: Option<Vec<String>>,
    /// Directories supporting this trait
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referenced_directories: Option<Vec<String>>,
}

/// High-level behavioral capability (derived from trait combinations)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Capability {
    /// Capability identifier using / delimiter (e.g., "exec/command/shell")
    pub id: String,
    /// Human-readable description
    pub description: String,
    /// Confidence score (0.5 = heuristic, 1.0 = definitive)
    pub confidence: f32,
    /// Criticality level (none/low/medium/high)
    #[serde(default)]
    pub criticality: Criticality,
    /// MBC (Malware Behavior Catalog) ID (e.g., "B0036", "E1082")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mbc_id: Option<String>,
    /// MITRE ATT&CK Technique ID (e.g., "T1082", "T1059")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_id: Option<String>,
    /// Evidence supporting this capability
    pub evidence: Vec<Evidence>,
    /// Traits that contributed to this capability
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub traits: Vec<String>,
    /// Specific paths supporting this capability
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referenced_paths: Option<Vec<String>>,
    /// Directories supporting this capability
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referenced_directories: Option<Vec<String>>,
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_type: Option<PathAccessType>,

    /// Where discovered (strings, yara, function_analysis)
    pub source: String,

    /// Evidence for this path
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,

    /// Trait IDs that reference this path (back-reference)
    #[serde(skip_serializing_if = "Vec::is_empty")]
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
    pub enumerated: bool,

    /// Trait IDs generated from this directory pattern
    #[serde(skip_serializing_if = "Vec::is_empty")]
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,

    /// Trait IDs that reference this env var (back-reference)
    #[serde(skip_serializing_if = "Vec::is_empty")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complexity: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<String>,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_flow: Option<ControlFlowMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_analysis: Option<InstructionAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub register_usage: Option<RegisterUsage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub constants: Vec<EmbeddedConstant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<FunctionProperties>,
    /// Function signature (source code languages)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<FunctionSignature>,
    /// Nesting depth metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nesting: Option<NestingMetrics>,
    /// Call pattern analysis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_patterns: Option<CallPatternMetrics>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StringInfo {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
    pub encoding: String,
    #[serde(rename = "type")]
    pub string_type: StringType,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Import {
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    pub source: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Export {
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub severity: String,
    pub description: String,
    pub matched_strings: Vec<MatchedString>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModifiedFileAnalysis {
    pub file: String,
    pub new_capabilities: Vec<String>,
    pub removed_capabilities: Vec<String>,
    pub capability_delta: i32,
    pub risk_increase: bool,
}

// ========================================================================
// ML-Ready Feature Extraction Structures
// ========================================================================

/// Control flow graph metrics for a function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowMetrics {
    /// Number of basic blocks
    pub basic_blocks: u32,
    /// Number of control flow edges
    pub edges: u32,
    /// Cyclomatic complexity (McCabe)
    pub cyclomatic_complexity: u32,
    /// Maximum instructions in any basic block
    pub max_block_size: u32,
    /// Average instructions per basic block
    pub avg_block_size: f32,
    /// Whether function has linear control flow (no branches)
    pub is_linear: bool,
    /// Number of loops detected
    pub loop_count: u32,
    /// Branch density (branches per instruction)
    pub branch_density: f32,
    /// Call graph in-degree (callers)
    pub in_degree: u32,
    /// Call graph out-degree (callees)
    pub out_degree: u32,
}

/// Instruction-level analysis for ML features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionAnalysis {
    /// Total instruction count
    pub total_instructions: u32,
    /// CPU cycle cost estimate
    pub instruction_cost: u32,
    /// Instruction density (instructions per byte)
    pub instruction_density: f32,
    /// Instruction categories and counts
    pub categories: InstructionCategories,
    /// Top 5 most used opcodes
    pub top_opcodes: Vec<OpcodeFrequency>,
    /// Unusual/suspicious instructions detected
    pub unusual_instructions: Vec<String>,
}

/// Categorized instruction counts for behavioral analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionCategories {
    /// Arithmetic operations (add, sub, mul, div, inc, dec)
    pub arithmetic: u32,
    /// Logical operations (and, or, xor, not, test)
    pub logic: u32,
    /// Memory operations (mov, lea, push, pop, load, store)
    pub memory: u32,
    /// Control flow (jmp, jne, call, ret, loop)
    pub control: u32,
    /// System calls and interrupts (syscall, int, sysenter)
    pub system: u32,
    /// FPU/SIMD operations (fadd, fmul, xmm, etc)
    pub fpu_simd: u32,
    /// String operations (movs, cmps, scas, stos)
    pub string_ops: u32,
    /// Privileged instructions (cli, sti, hlt, in, out)
    pub privileged: u32,
    /// Crypto-related instructions (aes, sha, etc)
    pub crypto: u32,
}

/// Opcode frequency for pattern detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcodeFrequency {
    pub opcode: String,
    pub count: u32,
    pub percentage: f32,
}

/// Register usage patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterUsage {
    /// Registers used in function
    pub registers_used: Vec<String>,
    /// Non-standard register usage (unusual for the architecture)
    pub non_standard_usage: Vec<String>,
    /// Stack pointer manipulation detected
    pub stack_pointer_manipulation: bool,
    /// Frame pointer usage
    pub uses_frame_pointer: bool,
}

/// Embedded constant with decoded information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedConstant {
    /// Raw value as hex string
    pub value: String,
    /// Constant type (qword, dword, word, byte)
    pub constant_type: String,
    /// Possible decoded interpretations
    pub decoded: Vec<DecodedValue>,
}

/// Decoded constant value interpretations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedValue {
    /// Type of decoded value (ip_address, port, url, key, etc)
    pub value_type: String,
    /// Human-readable decoded value
    pub decoded_value: String,
    /// Confidence in this interpretation (0.0-1.0)
    pub confidence: f32,
}

/// Function-level properties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionProperties {
    /// Function is side-effect free (pure)
    pub is_pure: bool,
    /// Function never returns
    pub is_noreturn: bool,
    /// Function is recursive
    pub is_recursive: bool,
    /// Stack frame size in bytes
    pub stack_frame: u32,
    /// Number of local variables
    pub local_vars: u32,
    /// Number of arguments
    pub args: u32,
    /// Function is a leaf (calls nothing)
    pub is_leaf: bool,
}

/// Function signature analysis (source code languages)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    /// Parameter count
    pub param_count: u32,
    /// Parameters with default values
    pub default_param_count: u32,
    /// Has *args (variadic positional)
    pub has_var_positional: bool,
    /// Has **kwargs (variadic keyword)
    pub has_var_keyword: bool,
    /// Has type annotations/hints
    pub has_type_hints: bool,
    /// Return type annotation present
    pub has_return_type: bool,
    /// Decorators applied
    pub decorators: Vec<String>,
    /// Is async function
    pub is_async: bool,
    /// Is generator (contains yield)
    pub is_generator: bool,
    /// Is lambda/anonymous
    pub is_lambda: bool,
}

/// Nesting depth metrics for control structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestingMetrics {
    /// Maximum nesting depth in function
    pub max_depth: u32,
    /// Average nesting depth
    pub avg_depth: f32,
    /// Locations with deep nesting (depth > 4)
    pub deep_nest_count: u32,
}

/// Call pattern analysis for source code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallPatternMetrics {
    /// Total function calls in this function
    pub call_count: u32,
    /// Unique functions called
    pub unique_callees: u32,
    /// Chained method calls (e.g., obj.a().b().c())
    pub chained_calls: u32,
    /// Maximum chain length
    pub max_chain_length: u32,
    /// Recursive calls (self-reference)
    pub recursive_calls: u32,
    /// Dynamic calls (eval, exec, __import__, getattr)
    pub dynamic_calls: u32,
}

/// Binary-wide properties for ML analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryProperties {
    /// Security features present/absent
    pub security: SecurityFeatures,
    /// Linking and dependencies
    pub linking: LinkingInfo,
    /// Anomalies detected
    pub anomalies: Vec<BinaryAnomaly>,
}

/// Security hardening features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFeatures {
    /// Stack canary present
    pub canary: bool,
    /// No-execute (NX/DEP) enabled
    pub nx: bool,
    /// Position independent code
    pub pic: bool,
    /// RELRO protection level (none, partial, full)
    pub relro: String,
    /// Binary is stripped
    pub stripped: bool,
    /// Uses cryptographic functions
    pub uses_crypto: bool,
    /// Code signature present
    pub signed: bool,
}

/// Binary linking information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkingInfo {
    /// Statically linked
    pub is_static: bool,
    /// Dynamic libraries used
    pub libraries: Vec<String>,
    /// RPATH/RUNPATH settings
    pub rpath: Vec<String>,
}

/// Structural anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryAnomaly {
    /// Anomaly type (no_section_header, overlapping_functions, etc)
    pub anomaly_type: String,
    /// Description
    pub description: String,
    /// Severity (low, medium, high)
    pub severity: String,
}

/// Overlay/appended data metrics for supply chain attack detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayMetrics {
    /// Size of overlay in bytes
    pub size_bytes: u64,
    /// Overlay as ratio of total file size (0.0-1.0)
    pub ratio_of_file: f64,
    /// Average entropy of overlay data
    pub avg_entropy: f64,
    /// Variance in entropy across chunks (indicates mixed content)
    pub entropy_variance: f64,
    /// Count of embedded files found via magic bytes
    pub embedded_file_count: u32,
    /// Types of embedded files found (zstd, gzip, elf, etc)
    pub embedded_file_types: Vec<String>,
    /// Offset where overlay begins
    pub overlay_start: u64,
    /// Suspicion score (0.0-1.0)
    pub suspicion_score: f64,
}

/// Aggregate code metrics across entire binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeMetrics {
    /// Total number of functions
    pub total_functions: u32,
    /// Total basic blocks across all functions
    pub total_basic_blocks: u32,
    /// Average cyclomatic complexity
    pub avg_complexity: f32,
    /// Maximum complexity seen
    pub max_complexity: u32,
    /// Total instruction count
    pub total_instructions: u32,
    /// Code-to-data ratio
    pub code_density: f32,
    /// Functions with loops
    pub functions_with_loops: u32,
    /// Functions with unusual patterns
    pub functions_with_anomalies: u32,
}

/// Source code metrics for scripts (Python, JavaScript, etc.)
/// Useful for ML analysis and behavioral profiling
#[derive(Debug, Serialize, Deserialize)]
pub struct SourceCodeMetrics {
    /// Total lines in file
    pub total_lines: u32,
    /// Lines of code (excluding blanks and comments)
    pub code_lines: u32,
    /// Comment lines (including inline and block comments)
    pub comment_lines: u32,
    /// Blank lines
    pub blank_lines: u32,
    /// Docstring lines
    pub docstring_lines: u32,

    // Comment density metrics
    /// Ratio of comments to code (comment_lines / code_lines)
    pub comment_to_code_ratio: f32,
    /// Ratio of comments to total lines
    pub comment_density: f32,

    // String metrics
    /// Total number of string literals
    pub string_count: u32,
    /// Average string length
    pub avg_string_length: f32,
    /// Maximum string length
    pub max_string_length: u32,
    /// Average string entropy (0.0-8.0, higher = more random/obfuscated)
    pub avg_string_entropy: f32,
    /// String density (strings per line of code)
    pub string_density: f32,

    // Function metrics
    /// Total number of functions/methods defined
    pub function_count: u32,
    /// Average function size in lines
    pub avg_function_size: f32,
    /// Maximum function size
    pub max_function_size: u32,

    // Import metrics
    /// Total import statements
    pub import_count: u32,
    /// Standard library imports
    pub stdlib_imports: u32,
    /// Third-party imports
    pub third_party_imports: u32,
    /// Local/relative imports
    pub local_imports: u32,

    // Complexity indicators
    /// Lines with eval/exec/compile
    pub dynamic_execution_count: u32,
    /// Obfuscation indicators (base64, hex strings, etc.)
    pub obfuscation_indicators: u32,
    /// High-entropy strings (entropy > 5.0)
    pub high_entropy_strings: u32,

    // Code structure (Phase 2)
    /// Code structure metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_structure: Option<CodeStructureMetrics>,

    // Language-specific idioms (Phase 3)
    /// Python-specific idioms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub python_idioms: Option<PythonIdioms>,

    /// JavaScript-specific idioms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub javascript_idioms: Option<JavaScriptIdioms>,

    /// Shell script idioms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell_idioms: Option<ShellIdioms>,

    /// Go idioms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub go_idioms: Option<GoIdioms>,
}

/// Code structure metrics for ML analysis (Phase 2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeStructureMetrics {
    /// Global variables defined
    pub global_var_count: u32,
    /// Class definitions
    pub class_count: u32,
    /// Maximum inheritance depth
    pub max_inheritance_depth: u32,
    /// Try/except blocks
    pub exception_handler_count: u32,
    /// Empty except blocks (suspicious - error suppression)
    pub empty_except_count: u32,
    /// Assert statements
    pub assert_count: u32,
    /// Main guard present (if __name__ == "__main__":)
    pub has_main_guard: bool,
    /// Assignment statements (variable definitions)
    pub assignment_count: u32,
}

/// Python-specific language idioms (Phase 3)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PythonIdioms {
    /// List/dict/set comprehensions
    pub comprehension_count: u32,
    /// Generator expressions
    pub generator_expression_count: u32,
    /// Context managers (with statements)
    pub context_manager_count: u32,
    /// Lambda functions
    pub lambda_count: u32,
    /// Async/await usage
    pub async_count: u32,
    /// Yield statements (generators)
    pub yield_count: u32,
    /// Class definitions
    pub class_count: u32,
    /// Dunder methods (__init__, __str__, etc.)
    pub dunder_method_count: u32,
    /// Total decorator usage (all contexts)
    pub total_decorator_count: u32,
    /// F-strings (formatted string literals)
    pub fstring_count: u32,
    /// Walrus operator usage (:=)
    pub walrus_operator_count: u32,
}

/// JavaScript-specific language idioms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaScriptIdioms {
    /// Arrow functions (=>)
    pub arrow_function_count: u32,
    /// Promise usage (new Promise, .then, .catch)
    pub promise_count: u32,
    /// Async/await usage
    pub async_await_count: u32,
    /// Template literals (`string ${expr}`)
    pub template_literal_count: u32,
    /// Destructuring assignments
    pub destructuring_count: u32,
    /// Spread operator usage (...)
    pub spread_operator_count: u32,
    /// Class definitions
    pub class_count: u32,
    /// Callback patterns (function passed as argument)
    pub callback_count: u32,
    /// IIFE (Immediately Invoked Function Expression)
    pub iife_count: u32,
    /// Object literal shorthand
    pub object_shorthand_count: u32,
    /// Optional chaining (?.)
    pub optional_chaining_count: u32,
    /// Nullish coalescing (??)
    pub nullish_coalescing_count: u32,
}

/// Shell script specific idioms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellIdioms {
    /// Pipe usage (|)
    pub pipe_count: u32,
    /// Output redirections (>, >>)
    pub redirect_count: u32,
    /// Input redirections (<, <<)
    pub input_redirect_count: u32,
    /// Command substitutions ($(), backticks)
    pub command_substitution_count: u32,
    /// Here documents (<<EOF)
    pub heredoc_count: u32,
    /// Case statements
    pub case_statement_count: u32,
    /// Test expressions ([ ], [[ ]], test)
    pub test_expression_count: u32,
    /// While read loops
    pub while_read_count: u32,
    /// Subshells (commands in parentheses)
    pub subshell_count: u32,
    /// For loops
    pub for_loop_count: u32,
    /// Background jobs (&)
    pub background_job_count: u32,
    /// Process substitution (<(), >())
    pub process_substitution_count: u32,
}

/// Go-specific language idioms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoIdioms {
    /// Goroutine launches (go keyword)
    pub goroutine_count: u32,
    /// Channel operations (chan, <-)
    pub channel_count: u32,
    /// Defer statements
    pub defer_count: u32,
    /// Select statements (channel multiplexing)
    pub select_statement_count: u32,
    /// Interface type assertions
    pub type_assertion_count: u32,
    /// Method declarations (with receivers)
    pub method_count: u32,
    /// Interface definitions
    pub interface_count: u32,
    /// Range loops (for...range)
    pub range_loop_count: u32,
    /// Error handling returns (func ... error)
    pub error_return_count: u32,
    /// Panic/recover usage
    pub panic_recover_count: u32,
    /// CGo usage (import "C")
    pub cgo_count: u32,
    /// Unsafe pointer operations
    pub unsafe_count: u32,
}
