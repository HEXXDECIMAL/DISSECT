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

/// Serialize offset as hex string for JSON output (e.g., "0x1234")
fn serialize_hex_offset<S>(offset: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match offset {
        Some(o) => serializer.serialize_str(&format!("{:#x}", o)),
        None => serializer.serialize_none(),
    }
}

/// Deserialize offset from either hex string or integer
fn deserialize_hex_offset<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};

    struct HexOrIntVisitor;

    impl<'de> Visitor<'de> for HexOrIntVisitor {
        type Value = Option<u64>;

        fn expecting<'a>(&self, formatter: &mut std::fmt::Formatter<'a>) -> std::fmt::Result {
            formatter.write_str("a hex string like '0x1234' or an integer")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
            Ok(Some(v))
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if v >= 0 {
                Ok(Some(v as u64))
            } else {
                Err(de::Error::custom("offset cannot be negative"))
            }
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let s = v.trim().trim_start_matches("0x").trim_start_matches("0X");
            u64::from_str_radix(s, 16)
                .map(Some)
                .map_err(|_| de::Error::custom(format!("invalid hex offset: {}", v)))
        }
    }

    deserializer.deserialize_any(HexOrIntVisitor)
}

/// Decoded string (base64, xor-decoded, etc.)
/// Deprecated: Use StringInfo with encoding_chain instead.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringInfo {
    #[serde(serialize_with = "serialize_truncated_string")]
    pub value: String,
    /// File offset where string was found (serialized as hex, e.g., "0x1234")
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        serialize_with = "serialize_hex_offset",
        deserialize_with = "deserialize_hex_offset"
    )]
    pub offset: Option<u64>,
    pub encoding: String,
    #[serde(rename = "type")]
    pub string_type: StringType,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub section: Option<String>,
    /// Encoding layers applied to this string (e.g., ["base64", "zlib"])
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub encoding_chain: Vec<String>,
    /// Fragments if this is a stack-constructed string
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub fragments: Option<Vec<String>>,
}

// Re-export stng's StringKind as StringType for compatibility
// DISSECT-specific source code types (Literal, Comment, Docstring) map to stng::StringKind::Const
// StackString is detected via StringMethod, not as a separate kind
pub use stng::StringKind as StringType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub address: Option<u64>,
    pub size: u64,
    pub entropy: f64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub permissions: Option<String>,
}

/// Normalize a symbol name by stripping leading underscores.
/// This is done at load time for consistent matching.
/// Examples: "_malloc" -> "malloc", "__libc_start_main" -> "libc_start_main"
#[inline]
pub fn normalize_symbol(symbol: &str) -> String {
    symbol.trim_start_matches('_').trim_start_matches('_').to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub library: Option<String>,
    pub source: String,
}

impl Import {
    /// Create a new Import with normalized symbol name
    pub fn new(
        symbol: impl Into<String>,
        library: Option<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            symbol: normalize_symbol(&symbol.into()),
            library,
            source: source.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub offset: Option<String>,
    pub source: String,
}

impl Export {
    /// Create a new Export with normalized symbol name
    pub fn new(
        symbol: impl Into<String>,
        offset: Option<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            symbol: normalize_symbol(&symbol.into()),
            offset,
            source: source.into(),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== normalize_symbol Tests ====================

    #[test]
    fn test_normalize_symbol_single_underscore() {
        assert_eq!(normalize_symbol("_malloc"), "malloc");
    }

    #[test]
    fn test_normalize_symbol_double_underscore() {
        assert_eq!(normalize_symbol("__libc_start_main"), "libc_start_main");
    }

    #[test]
    fn test_normalize_symbol_no_underscore() {
        assert_eq!(normalize_symbol("printf"), "printf");
    }

    #[test]
    fn test_normalize_symbol_many_underscores() {
        // trim_start_matches strips ALL leading underscores
        assert_eq!(normalize_symbol("___private"), "private");
    }

    #[test]
    fn test_normalize_symbol_empty() {
        assert_eq!(normalize_symbol(""), "");
    }

    #[test]
    fn test_normalize_symbol_only_underscores() {
        assert_eq!(normalize_symbol("__"), "");
    }

    #[test]
    fn test_normalize_symbol_middle_underscores_preserved() {
        assert_eq!(normalize_symbol("_my_function_name"), "my_function_name");
    }

    #[test]
    fn test_normalize_symbol_trailing_underscore() {
        assert_eq!(normalize_symbol("_foo_"), "foo_");
    }

    // ==================== Import::new Tests ====================

    #[test]
    fn test_import_new_basic() {
        let imp = Import::new("malloc", None, "symbols");
        assert_eq!(imp.symbol, "malloc");
        assert_eq!(imp.library, None);
        assert_eq!(imp.source, "symbols");
    }

    #[test]
    fn test_import_new_with_library() {
        let imp = Import::new("printf", Some("libc.so.6".to_string()), "imports");
        assert_eq!(imp.symbol, "printf");
        assert_eq!(imp.library, Some("libc.so.6".to_string()));
    }

    #[test]
    fn test_import_new_normalizes_symbol() {
        let imp = Import::new("_malloc", None, "symbols");
        assert_eq!(imp.symbol, "malloc");
    }

    #[test]
    fn test_import_new_normalizes_double_underscore() {
        let imp = Import::new("__errno_location", Some("libc.so.6".to_string()), "dynsym");
        assert_eq!(imp.symbol, "errno_location");
    }

    #[test]
    fn test_import_new_string_into() {
        let imp = Import::new(String::from("_read"), None, String::from("dynsym"));
        assert_eq!(imp.symbol, "read");
        assert_eq!(imp.source, "dynsym");
    }

    // ==================== Export::new Tests ====================

    #[test]
    fn test_export_new_basic() {
        let exp = Export::new("my_function", None, "exports");
        assert_eq!(exp.symbol, "my_function");
        assert_eq!(exp.offset, None);
        assert_eq!(exp.source, "exports");
    }

    #[test]
    fn test_export_new_with_offset() {
        let exp = Export::new("init", Some("0x1000".to_string()), "symbols");
        assert_eq!(exp.symbol, "init");
        assert_eq!(exp.offset, Some("0x1000".to_string()));
    }

    #[test]
    fn test_export_new_normalizes_symbol() {
        let exp = Export::new("_start", Some("0x400".to_string()), "entry");
        assert_eq!(exp.symbol, "start");
    }

    #[test]
    fn test_export_new_normalizes_double_underscore() {
        let exp = Export::new("__init_array_start", None, "symbols");
        assert_eq!(exp.symbol, "init_array_start");
    }

    // ==================== truncate_str_at_boundary Tests ====================

    #[test]
    fn test_truncate_str_at_boundary_short_string() {
        let s = "hello";
        assert_eq!(truncate_str_at_boundary(s, 10), "hello");
    }

    #[test]
    fn test_truncate_str_at_boundary_exact_length() {
        let s = "hello";
        assert_eq!(truncate_str_at_boundary(s, 5), "hello");
    }

    #[test]
    fn test_truncate_str_at_boundary_truncates() {
        let s = "hello world";
        assert_eq!(truncate_str_at_boundary(s, 5), "hello");
    }

    #[test]
    fn test_truncate_str_at_boundary_utf8_multibyte() {
        // 'é' is 2 bytes in UTF-8
        let s = "café";
        // Truncating at byte 4 would split 'é', so it backs off
        assert_eq!(truncate_str_at_boundary(s, 4), "caf");
    }

    #[test]
    fn test_truncate_str_at_boundary_utf8_emoji() {
        // '🦀' is 4 bytes in UTF-8
        let s = "hi🦀";
        // "hi" is 2 bytes, emoji is 4, total 6
        // Truncating at 3 would split emoji, backs off to 2
        assert_eq!(truncate_str_at_boundary(s, 3), "hi");
    }

    #[test]
    fn test_truncate_str_at_boundary_empty() {
        assert_eq!(truncate_str_at_boundary("", 10), "");
    }

    #[test]
    fn test_truncate_str_at_boundary_zero_max() {
        assert_eq!(truncate_str_at_boundary("hello", 0), "");
    }

    #[test]
    fn test_truncate_str_at_boundary_chinese() {
        // Each Chinese character is 3 bytes
        let s = "你好世界";
        // Truncate at 6 bytes = exactly 2 characters
        assert_eq!(truncate_str_at_boundary(s, 6), "你好");
    }

    // ==================== StringType Tests ====================

    #[test]
    fn test_string_type_equality() {
        assert_eq!(StringType::Url, StringType::Url);
        assert_ne!(StringType::Url, StringType::IP);
    }

    #[test]
    fn test_string_type_copy() {
        let st = StringType::Const;
        let st2 = st; // Copy
        assert_eq!(st, st2);
    }

    #[test]
    fn test_string_type_all_variants_distinct() {
        // Since StringType is now stng::StringKind, test the common malware-relevant variants
        // Note: Plain, Literal, Comment, Docstring all map to Const
        // StackString is detected via StringMethod, not as a separate kind
        let variants = vec![
            StringType::Url,
            StringType::IP,
            StringType::Path,
            StringType::Email,
            StringType::Base64,
            StringType::Import,
            StringType::Export,
            StringType::FuncName,
            StringType::Const,
            StringType::ShellCmd,
        ];
        for (i, v1) in variants.iter().enumerate() {
            for (j, v2) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(v1, v2, "Variant at index {} should equal itself", i);
                } else {
                    assert_ne!(
                        v1, v2,
                        "Variants at index {} and {} should be distinct",
                        i, j
                    );
                }
            }
        }
    }

    // ==================== AnalysisMetadata Tests ====================

    #[test]
    fn test_analysis_metadata_default() {
        let meta = AnalysisMetadata::default();
        assert_eq!(meta.analysis_duration_ms, 0);
        assert!(meta.tools_used.is_empty());
        assert!(meta.errors.is_empty());
    }

    #[test]
    fn test_analysis_metadata_creation() {
        let meta = AnalysisMetadata {
            analysis_duration_ms: 1500,
            tools_used: vec!["objdump".to_string(), "strings".to_string()],
            errors: vec![],
        };
        assert_eq!(meta.analysis_duration_ms, 1500);
        assert_eq!(meta.tools_used.len(), 2);
    }

    // ==================== StringInfo Tests ====================

    #[test]
    fn test_string_info_creation() {
        let info = StringInfo {
            value: "http://example.com".to_string(),
            offset: Some(0x1000),
            encoding: "utf-8".to_string(),
            string_type: StringType::Url,
            section: Some(".rodata".to_string()),
            encoding_chain: vec![],
            fragments: None,
        };
        assert_eq!(info.value, "http://example.com");
        assert_eq!(info.offset, Some(0x1000));
        assert_eq!(info.string_type, StringType::Url);
    }

    #[test]
    fn test_string_info_with_encoding_chain() {
        let info = StringInfo {
            value: "decoded text".to_string(),
            offset: None,
            encoding: "utf-8".to_string(),
            string_type: StringType::Const,
            section: None,
            encoding_chain: vec!["base64".to_string(), "zlib".to_string()],
            fragments: None,
        };
        assert_eq!(info.encoding_chain.len(), 2);
        assert_eq!(info.encoding_chain[0], "base64");
    }

    #[test]
    fn test_string_info_with_fragments() {
        let info = StringInfo {
            value: "stacked".to_string(),
            offset: Some(0x2000),
            encoding: "ascii".to_string(),
            string_type: StringType::StackString,
            section: Some(".text".to_string()),
            encoding_chain: vec![],
            fragments: Some(vec!["s".to_string(), "t".to_string(), "a".to_string()]),
        };
        assert_eq!(info.string_type, StringType::StackString);
        assert!(info.fragments.is_some());
        assert_eq!(info.fragments.unwrap().len(), 3);
    }

    // ==================== Section Tests ====================

    #[test]
    fn test_section_creation() {
        let section = Section {
            name: ".text".to_string(),
            address: None,
            size: 4096,
            entropy: 6.5,
            permissions: Some("r-x".to_string()),
        };
        assert_eq!(section.name, ".text");
        assert_eq!(section.size, 4096);
        assert!((section.entropy - 6.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_section_without_permissions() {
        let section = Section {
            name: ".data".to_string(),
            address: None,
            size: 1024,
            entropy: 3.2,
            permissions: None,
        };
        assert!(section.permissions.is_none());
    }

    // ==================== Function Tests ====================

    #[test]
    fn test_function_creation_minimal() {
        let func = Function {
            name: "main".to_string(),
            offset: None,
            size: None,
            complexity: None,
            calls: vec![],
            source: "symbols".to_string(),
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
        assert_eq!(func.source, "symbols");
    }

    #[test]
    fn test_function_with_calls() {
        let func = Function {
            name: "process".to_string(),
            offset: Some("0x1000".to_string()),
            size: Some(256),
            complexity: Some(10),
            calls: vec!["malloc".to_string(), "free".to_string()],
            source: "analysis".to_string(),
            control_flow: None,
            instruction_analysis: None,
            register_usage: None,
            constants: vec![],
            properties: None,
            signature: None,
            nesting: None,
            call_patterns: None,
        };
        assert_eq!(func.calls.len(), 2);
        assert_eq!(func.complexity, Some(10));
    }

    // ==================== YaraMatch Tests ====================

    #[test]
    fn test_yara_match_creation() {
        let yara = YaraMatch {
            rule: "malware_generic".to_string(),
            namespace: "malware".to_string(),
            severity: "high".to_string(),
            desc: "Generic malware signature".to_string(),
            matched_strings: vec![],
            is_capability: false,
            mbc: None,
            attack: None,
        };
        assert_eq!(yara.rule, "malware_generic");
        assert!(!yara.is_capability);
    }

    #[test]
    fn test_yara_match_with_capability() {
        let yara = YaraMatch {
            rule: "network_communication".to_string(),
            namespace: "capabilities".to_string(),
            severity: "medium".to_string(),
            desc: "Network communication capability".to_string(),
            matched_strings: vec![],
            is_capability: true,
            mbc: Some("C0021".to_string()),
            attack: Some("T1071".to_string()),
        };
        assert!(yara.is_capability);
        assert_eq!(yara.mbc, Some("C0021".to_string()));
        assert_eq!(yara.attack, Some("T1071".to_string()));
    }

    // ==================== MatchedString Tests ====================

    #[test]
    fn test_matched_string_creation() {
        let ms = MatchedString {
            identifier: "$a".to_string(),
            offset: 0x1234,
            value: "suspicious string".to_string(),
        };
        assert_eq!(ms.identifier, "$a");
        assert_eq!(ms.offset, 0x1234);
    }

    // ==================== DecodedString Tests ====================

    #[test]
    fn test_decoded_string_creation() {
        let ds = DecodedString {
            value: "hello world".to_string(),
            encoded: "aGVsbG8gd29ybGQ=".to_string(),
            method: "base64".to_string(),
            key: None,
            offset: Some("0x1000".to_string()),
        };
        assert_eq!(ds.value, "hello world");
        assert_eq!(ds.method, "base64");
        assert!(ds.key.is_none());
    }

    #[test]
    fn test_decoded_string_with_xor_key() {
        let ds = DecodedString {
            value: "decrypted".to_string(),
            encoded: "encrypted bytes".to_string(),
            method: "xor".to_string(),
            key: Some("0x55".to_string()),
            offset: None,
        };
        assert_eq!(ds.method, "xor");
        assert_eq!(ds.key, Some("0x55".to_string()));
    }
}
