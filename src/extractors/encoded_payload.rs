//! Encoded Payload Extractor
//!
//! Extracts base64-encoded payloads from files, decodes them (including zlib),
//! and writes them to temp files for separate analysis.

use std::io::Write;
use std::path::PathBuf;
use crate::analyzers::FileType;

/// Represents an extracted payload
#[derive(Debug)]
pub struct ExtractedPayload {
    /// Path to temp file containing decoded content
    pub temp_path: PathBuf,
    /// Chain of encodings (e.g., ["base64", "zlib"])
    pub encoding_chain: Vec<String>,
    /// Preview of content (first 40 chars, printable only)
    pub preview: String,
    /// Detected type of payload
    pub detected_type: FileType,
    /// Byte offset in original file
    pub original_offset: usize,
}

/// Types of extracted payloads
#[derive(Debug, PartialEq, Clone)]
pub enum PayloadType {
    Python,
    Shell,
    Binary,
    Unknown,
}

impl From<PayloadType> for FileType {
    fn from(pt: PayloadType) -> Self {
        match pt {
            PayloadType::Python => FileType::Python,
            PayloadType::Shell => FileType::Shell,
            PayloadType::Binary => FileType::Unknown, // Binary needs more detection
            PayloadType::Unknown => FileType::Unknown,
        }
    }
}

/// Maximum recursion depth for nested encoding
const MAX_RECURSION_DEPTH: usize = 3;
/// Minimum base64 string length to consider
const MIN_BASE64_LENGTH: usize = 50;

/// Check if a string is a valid base64 candidate
pub fn is_base64_candidate(s: &str) -> bool {
    // Check minimum length
    if s.len() < MIN_BASE64_LENGTH {
        return false;
    }
    
    // Check valid base64 characters
    let valid_chars: std::collections::HashSet<char> = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
            .chars()
            .collect();
    
    if !s.chars().all(|c| valid_chars.contains(&c)) {
        return false;
    }
    
    // Check padding
    let padding_count = s.chars().rev().take_while(|&c| c == '=').count();
    if padding_count > 2 {
        return false;
    }
    
    // Length should be multiple of 4 (with padding)
    if s.len() % 4 != 0 {
        return false;
    }
    
    true
}

/// Decode base64 string, checking for and decompressing zlib if present
pub fn decode_base64(encoded: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    
    // Try base64 decode
    let decoded = STANDARD.decode(encoded).ok()?;
    
    // Check for zlib magic bytes (78 9C = default compression)
    if decoded.len() > 2 && decoded[0] == 0x78 && decoded[1] == 0x9C {
        // Try zlib decompression using flate2
        use flate2::read::ZlibDecoder;
        use std::io::Read;
        
        let mut decoder = ZlibDecoder::new(&decoded[..]);
        let mut decompressed = Vec::new();
        if decoder.read_to_end(&mut decompressed).is_ok() {
            return Some(decompressed);
        }
    }
    
    Some(decoded)
}

/// Detect the type of payload from decoded content
pub fn detect_payload_type(data: &[u8]) -> PayloadType {
    // Check if it's valid UTF-8 (text) or binary
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return PayloadType::Binary,
    };
    
    // Check for Python indicators
    if text.contains("import ") && 
       (text.contains("def ") || 
        text.contains("class ") || 
        text.contains("print(") ||
        text.contains("exec(") ||
        text.contains("__name__")) {
        return PayloadType::Python;
    }
    
    // Check for shell script indicators
    if text.starts_with("#!/bin/bash") ||
       text.starts_with("#!/bin/sh") ||
       text.starts_with("#!/usr/bin/env bash") ||
       (text.contains("echo ") && text.contains("$")) ||
       text.contains("| ") {
        return PayloadType::Shell;
    }
    
    // Check for binary (ELF, Mach-O, PE)
    if data.len() > 4 {
        // ELF magic: 0x7F 'E' 'L' 'F'
        if data[0] == 0x7F && data[1] == b'E' && data[2] == b'L' && data[3] == b'F' {
            return PayloadType::Binary;
        }
        // Mach-O magic: 0xFEEDFACE or 0xFEEDFACF or 0xCAFEBABE
        if (data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFA && (data[3] == 0xCE || data[3] == 0xCF)) ||
           (data[0] == 0xCA && data[1] == 0xFE && data[2] == 0xBA && data[3] == 0xBE) {
            return PayloadType::Binary;
        }
        // PE magic: 'M' 'Z'
        if data[0] == b'M' && data[1] == b'Z' {
            return PayloadType::Binary;
        }
    }
    
    // High entropy suggests binary
    if calculate_entropy(data) > 7.5 {
        return PayloadType::Binary;
    }
    
    PayloadType::Unknown
}

/// Calculate Shannon entropy of data
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    
    let len = data.len() as f64;
    let mut entropy = 0.0;
    
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    
    entropy
}

/// Generate a preview string (first 40 chars, printable only)
pub fn generate_preview(data: &[u8]) -> String {
    // Check if data is printable ASCII
    let is_printable = data.iter().take(40).all(|&b| {
        b.is_ascii_alphanumeric() || 
        b.is_ascii_punctuation() || 
        b == b' ' || 
        b == b'\n' || 
        b == b'\r' || 
        b == b'\t'
    });
    
    if !is_printable {
        return "<binary data>".to_string();
    }
    
    // Take first 40 bytes and convert to string
    let preview_len = data.len().min(40);
    let preview = String::from_utf8_lossy(&data[..preview_len]);
    
    // Replace newlines with spaces for display
    preview.replace('\n', " ").replace('\r', "")
}

/// Generate virtual filename for extracted payload
pub fn generate_virtual_filename(original: &str, payload: &ExtractedPayload) -> String {
    let encoding = payload.encoding_chain.join("+");
    let index = 0; // TODO: Track index properly
    format!("{}!{}#{}", original, encoding, index)
}

/// Extract all encoded payloads from content
pub fn extract_encoded_payloads(content: &[u8]) -> Vec<ExtractedPayload> {
    let mut payloads = Vec::new();
    let content_str = String::from_utf8_lossy(content);
    
    // Find all potential base64 strings
    let base64_candidates = find_base64_strings(&content_str);
    
    for (offset, candidate) in base64_candidates {
        // Try to decode
        if let Some(decoded) = decode_base64(&candidate) {
            // Check for nested encoding (up to MAX_RECURSION_DEPTH)
            let (final_decoded, encoding_chain) = 
                decode_nested(&decoded, vec!["base64".to_string()], 1);
            
            // Detect type
            let payload_type = detect_payload_type(&final_decoded);
            
            // Write to temp file
            if let Ok(temp_file) = tempfile::NamedTempFile::new() {
                let temp_path = temp_file.path().to_path_buf();
                
                if let Ok(mut file) = std::fs::File::create(&temp_path) {
                    if file.write_all(&final_decoded).is_ok() {
                        // Keep temp file (don't drop)
                        let _ = temp_file.keep();
                        
                        payloads.push(ExtractedPayload {
                            temp_path,
                            encoding_chain,
                            preview: generate_preview(&final_decoded),
                            detected_type: payload_type.into(),
                            original_offset: offset,
                        });
                    }
                }
            }
        }
    }
    
    payloads
}

/// Find all base64 strings in content
fn find_base64_strings(content: &str) -> Vec<(usize, String)> {
    let mut results = Vec::new();
    
    // Simple regex-like scan for base64 patterns
    let chars: Vec<char> = content.chars().collect();
    let mut start = None;
    
    for (i, c) in chars.iter().enumerate() {
        let is_base64_char = c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=';
        
        if is_base64_char {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start {
            let candidate: String = chars[s..i].iter().collect();
            if is_base64_candidate(&candidate) {
                results.push((s, candidate));
            }
            start = None;
        }
    }
    
    // Check for trailing base64
    if let Some(s) = start {
        let candidate: String = chars[s..].iter().collect();
        if is_base64_candidate(&candidate) {
            results.push((s, candidate));
        }
    }
    
    results
}

/// Recursively decode nested encoding
fn decode_nested(data: &[u8], chain: Vec<String>, depth: usize) -> (Vec<u8>, Vec<String>) {
    if depth >= MAX_RECURSION_DEPTH {
        return (data.to_vec(), chain);
    }
    
    // Try to detect if data is base64 encoded
    if let Ok(text) = std::str::from_utf8(data) {
        if is_base64_candidate(text.trim()) {
            if let Some(decoded) = decode_base64(text.trim()) {
                let mut new_chain = chain.clone();
                if !chain.contains(&"base64".to_string()) {
                    new_chain.push("base64".to_string());
                }
                return decode_nested(&decoded, new_chain, depth + 1);
            }
        }
    }
    
    (data.to_vec(), chain)
}

#[cfg(test)]
mod tests;
