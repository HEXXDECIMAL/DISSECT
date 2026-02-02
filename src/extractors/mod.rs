//! Extractors for encoded payloads (base64, zlib, AES, etc.)
//!
//! This module extracts encoded payloads from files, decodes them,
//! and writes them to temp files for separate analysis.

pub mod aes_payload;
pub mod encoded_payload;

pub use aes_payload::extract_aes_payloads;
pub use encoded_payload::extract_encoded_payloads;
