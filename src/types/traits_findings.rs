//! Traits and Findings - the core model for observable characteristics and interpretive conclusions

use serde::{Deserialize, Serialize};

use super::core::Criticality;

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
    /// The raw value discovered (truncated to 4KB on serialization)
    #[serde(serialize_with = "serialize_truncated_value")]
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

/// Maximum size for evidence value field (4KB)
const MAX_EVIDENCE_VALUE_SIZE: usize = 4096;

/// Serialize evidence value, truncating to MAX_EVIDENCE_VALUE_SIZE
fn serialize_truncated_value<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if value.len() <= MAX_EVIDENCE_VALUE_SIZE {
        serializer.serialize_str(value)
    } else {
        // Truncate at a valid UTF-8 boundary
        let truncated = truncate_str(value, MAX_EVIDENCE_VALUE_SIZE - 12);
        let with_marker = format!("{}...[truncated]", truncated);
        serializer.serialize_str(&with_marker)
    }
}

/// Truncate a string at a valid UTF-8 char boundary
fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    // Find the last valid char boundary at or before max_bytes
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Evidence {
    /// Detection method (symbol, yara, tree-sitter, radare2, entropy, magic, etc.)
    pub method: String,
    /// Source tool (goblin, yara-x, radare2, tree-sitter-bash, etc.)
    pub source: String,
    /// Value discovered (symbol name, pattern match, etc.) - truncated to 4KB on serialization
    #[serde(serialize_with = "serialize_truncated_value")]
    pub value: String,
    /// Optional location context
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub location: Option<String>,
}
