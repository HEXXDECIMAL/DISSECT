use serde::{Deserialize, Serialize};

/// Represents a parsed RTF document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtfDocument {
    pub header: RtfHeader,
    pub control_words: Vec<ControlWord>,
    pub embedded_objects: Vec<OleObject>,
    pub metadata: DocumentMetadata,
}

/// RTF header information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtfHeader {
    pub version: u32,
    pub charset: Option<String>,
    pub offset: usize,
}

/// Represents a control word in RTF (e.g., \object, \objdata)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlWord {
    pub name: String,
    pub parameter: Option<i32>,
    pub offset: usize,
}

/// Represents an embedded OLE object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OleObject {
    pub class_name: String,            // e.g., "Word.Document.8"
    pub objdata: Vec<u8>,              // Hex-decoded bytes
    pub ole_header: Option<OleHeader>, // If valid OLE header found
    pub offset: usize,                 // Position in RTF file
    pub suspicious_flags: Vec<SuspiciousFlag>,
}

/// OLE compound document header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OleHeader {
    pub magic: [u8; 8],      // Should be D0CF11E0A1B11AE1
    pub is_obfuscated: bool, // Whitespace in hex encoding
}

/// Suspicious patterns found in the document
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SuspiciousFlag {
    UncPath(String),     // \\host@SSL\path
    ObfuscatedOleHeader, // Whitespace in hex encoding
    ObjUpdateDirective,  // \objupdate detected
    MalformedHeader,     // Invalid RTF header
    ExcessiveNesting,    // Likely zip bomb
    WebdavPath,          // davwwwroot path
}

/// Document-level metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentMetadata {
    pub file_size: usize,
    pub object_count: usize,
    pub max_nesting_depth: usize,
    pub has_objupdate: bool,
    pub detected_charset: Option<String>,
}

/// Control word types for easy categorization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlWordType {
    Object,
    ObjEmbed,
    ObjData,
    ObjUpdate,
    Charset,
    ColTable,
    Font,
    Style,
    Other,
}

impl ControlWord {
    pub fn word_type(&self) -> ControlWordType {
        match self.name.as_str() {
            "object" => ControlWordType::Object,
            "objemb" => ControlWordType::ObjEmbed,
            "objdata" => ControlWordType::ObjData,
            "objupdate" => ControlWordType::ObjUpdate,
            "charset" => ControlWordType::Charset,
            "colortbl" => ControlWordType::ColTable,
            "fonttbl" => ControlWordType::Font,
            "stylesheet" => ControlWordType::Style,
            _ => ControlWordType::Other,
        }
    }
}
