//! RTF (Rich Text Format) parser with OLE object extraction
//!
//! This module provides a standalone RTF parser that can be used independently
//! or integrated with DISSECT. It focuses on security analysis of RTF documents,
//! particularly the extraction and analysis of embedded OLE objects.
//!
//! # Features
//!
//! - Parses RTF document structure and control words
//! - Extracts embedded OLE objects and their hex-encoded data
//! - Detects suspicious patterns (UNC paths, obfuscation, etc.)
//! - Anti-bomb protections (nesting depth, object count limits)
//! - Minimal dependencies (only `thiserror` and `hex`)
//!
//! # Example
//!
//! ```ignore
//! use rtf::RtfParser;
//! use std::fs;
//!
//! let data = fs::read("document.rtf")?;
//! let parser = RtfParser::new();
//! let doc = parser.parse(&data)?;
//!
//! println!("Found {} OLE objects", doc.embedded_objects.len());
//! for obj in &doc.embedded_objects {
//!     println!("  - {}: {} bytes", obj.class_name, obj.objdata.len());
//! }
//! ```

pub mod error;
pub mod hex_decoder;
pub mod ole_extractor;
pub mod parser;
pub mod types;

// Public API re-exports for convenience
// Used by external consumers of the rtf module
#[allow(unused_imports)]
pub use error::{RtfError, Result};
pub use parser::RtfParser;
#[allow(unused_imports)]
pub use types::{OleHeader, OleObject, RtfDocument, SuspiciousFlag};
