//! Composite scoring metrics and unified metrics container

use serde::{Deserialize, Serialize};

use super::binary_metrics::{BinaryMetrics, ElfMetrics, JavaClassMetrics, MachoMetrics, PeMetrics};
use super::container_metrics::{ArchiveMetrics, PackageJsonMetrics};
use super::is_zero_f32;
use super::language_metrics::{
    CMetrics, CSharpMetrics, GoMetrics, JavaScriptMetrics, JavaSourceMetrics, LuaMetrics,
    PerlMetrics, PhpMetrics, PowerShellMetrics, PythonMetrics, RubyMetrics, RustMetrics,
    ShellMetrics,
};
use super::text_metrics::{
    CommentMetrics, FunctionMetrics, IdentifierMetrics, StringMetrics, TextMetrics,
};

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
