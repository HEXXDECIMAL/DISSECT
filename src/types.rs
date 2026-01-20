use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Main analysis output structure
#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub schema_version: String,
    pub analysis_timestamp: DateTime<Utc>,
    pub target: TargetInfo,
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
    pub metadata: AnalysisMetadata,
}

impl AnalysisReport {
    pub fn new(target: TargetInfo) -> Self {
        Self {
            schema_version: "1.0".to_string(),
            analysis_timestamp: Utc::now(),
            target,
            capabilities: Vec::new(),
            structure: Vec::new(),
            functions: Vec::new(),
            strings: Vec::new(),
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            yara_matches: Vec::new(),
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Capability {
    /// Capability identifier using / delimiter (e.g., "exec/command/shell")
    pub id: String,
    /// Human-readable description
    pub description: String,
    /// Confidence score (0.5 = heuristic, 1.0 = definitive)
    pub confidence: f32,
    /// Evidence supporting this capability
    pub evidence: Vec<Evidence>,
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StringType {
    Url,
    Ip,
    Path,
    Email,
    Base64,
    Plain,
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

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AnalysisMetadata {
    pub analysis_duration_ms: u64,
    pub tools_used: Vec<String>,
    pub errors: Vec<String>,
}

/// Diff-specific report for comparing old vs new versions
#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct FileChanges {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModifiedFileAnalysis {
    pub file: String,
    pub new_capabilities: Vec<String>,
    pub removed_capabilities: Vec<String>,
    pub capability_delta: i32,
    pub risk_increase: bool,
}
