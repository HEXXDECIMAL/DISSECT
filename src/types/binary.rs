//! Binary analysis types - functions, strings, sections, imports/exports

use serde::{Deserialize, Serialize};

use super::is_false;
use super::ml_features::{
    CallPatternMetrics, ControlFlowMetrics, EmbeddedConstant, FunctionProperties,
    FunctionSignature, InstructionAnalysis, NestingMetrics, RegisterUsage,
};

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

/// Maximum size for string values (4KB)
const MAX_STRING_VALUE_SIZE: usize = 4096;

/// Serialize string value, truncating to MAX_STRING_VALUE_SIZE
fn serialize_truncated_string<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if value.len() <= MAX_STRING_VALUE_SIZE {
        serializer.serialize_str(value)
    } else {
        // Truncate at a valid UTF-8 boundary
        let truncated = truncate_str_at_boundary(value, MAX_STRING_VALUE_SIZE - 12);
        let with_marker = format!("{}...[truncated]", truncated);
        serializer.serialize_str(&with_marker)
    }
}

/// Truncate a string at a valid UTF-8 char boundary
fn truncate_str_at_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringInfo {
    #[serde(serialize_with = "serialize_truncated_string")]
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub offset: Option<String>,
    pub encoding: String,
    #[serde(rename = "type")]
    pub string_type: StringType,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub section: Option<String>,
}

/// Decoded string (base64, xor-decoded, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedString {
    /// The decoded plaintext value
    #[serde(serialize_with = "serialize_truncated_string")]
    pub value: String,
    /// Original encoded value (truncated to 4KB)
    #[serde(serialize_with = "serialize_truncated_string")]
    pub encoded: String,
    /// Encoding method (base64, xor, etc.)
    pub method: String,
    /// Optional: XOR key used (for xor method)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub key: Option<String>,
    /// Offset in file where encoded string was found
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub offset: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(serialize_with = "serialize_truncated_string")]
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisMetadata {
    pub analysis_duration_ms: u64,
    pub tools_used: Vec<String>,
    pub errors: Vec<String>,
}
