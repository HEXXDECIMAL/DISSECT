//! Extractors for encoded payloads (base64, zlib, etc.)
//!
//! This module extracts encoded payloads from files, decodes them,
//! and writes them to temp files for separate analysis.

pub mod encoded_payload;

pub use encoded_payload::extract_encoded_payloads;
