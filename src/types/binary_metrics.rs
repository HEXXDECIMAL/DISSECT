//! Binary format-specific metrics (ELF, PE, Mach-O, Java class files)

use serde::{Deserialize, Serialize};

use super::{is_false, is_zero_f32, is_zero_u32, is_zero_u64};

// =============================================================================
// BINARY-SPECIFIC METRICS
// =============================================================================

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

