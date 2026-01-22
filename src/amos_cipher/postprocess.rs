//! Post-processing for AMOS decrypted payloads.
//!
//! AMOS uses a multi-layer encoding scheme:
//! 1. Cipher decryption produces hex-encoded string
//! 2. Hex decode produces custom Base64 encoded string
//! 3. Custom Base64 decode produces the final plaintext

use super::error::AMOSError;
use super::types::DecryptionQuality;

/// AMOS custom Base64 alphabet (64 characters).
const AMOS_BASE64_ALPHABET: &[u8; 64] =
    b"Hbe1MtN?UT9jksJIE7D=VK&-XBA*h6y2i%p<!PqFw#@lR+vo$(Qd>_gxcmzY3af4";

/// Decode AMOS payload: Hex decode -> Custom Base64 decode.
pub fn decode_amos_payload(data: &[u8]) -> Result<Vec<u8>, AMOSError> {
    // Step 1: Hex decode (cipher output is hex-encoded)
    let hex_decoded = decode_hex(data)?;

    // Step 2: Custom Base64 decode (hex output is Base64-encoded)
    decode_custom_base64(&hex_decoded)
}

/// Try to decode, returning original data if decoding fails.
pub fn try_decode_amos_payload(data: &[u8]) -> Vec<u8> {
    decode_amos_payload(data).unwrap_or_else(|_| data.to_vec())
}

/// Standard Base64 alphabet for translation.
const STANDARD_BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Decode using AMOS custom Base64 alphabet.
/// Works by translating AMOS characters to standard Base64 characters,
/// then using the standard base64 decoder.
pub fn decode_custom_base64(data: &[u8]) -> Result<Vec<u8>, AMOSError> {
    // Build translation table: AMOS char -> Standard char
    let mut translate_table = [0u8; 256];
    for i in 0..256 {
        translate_table[i] = i as u8; // Default: no translation
    }
    for (idx, &amos_char) in AMOS_BASE64_ALPHABET.iter().enumerate() {
        translate_table[amos_char as usize] = STANDARD_BASE64_ALPHABET[idx];
    }

    // Translate AMOS to standard Base64
    let translated: Vec<u8> = data.iter().map(|&b| translate_table[b as usize]).collect();

    // Filter to only valid Base64 characters
    let filtered: Vec<u8> = translated
        .iter()
        .filter(|&&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
        .copied()
        .collect();

    if filtered.is_empty() {
        return Ok(Vec::new());
    }

    // Pad to multiple of 4 if needed
    let mut padded = filtered;
    while padded.len() % 4 != 0 {
        padded.push(b'=');
    }

    // Use standard base64 decoder
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD
        .decode(&padded)
        .map_err(|e| AMOSError::Base64DecodeError(e.to_string()))
}

/// Decode hex-encoded data.
fn decode_hex(data: &[u8]) -> Result<Vec<u8>, AMOSError> {
    // Filter to only hex characters
    let mut hex_chars: Vec<u8> = data
        .iter()
        .filter(|&&b| b.is_ascii_hexdigit())
        .copied()
        .collect();

    if hex_chars.is_empty() {
        return Ok(Vec::new());
    }

    // Handle odd-length hex data by truncating the last character
    if hex_chars.len() % 2 != 0 {
        hex_chars.pop();
    }

    hex::decode(&hex_chars).map_err(|e| AMOSError::HexDecodeError(e.to_string()))
}

/// Validate decoded output quality.
pub fn validate_decryption(plaintext: &[u8]) -> DecryptionQuality {
    if plaintext.is_empty() {
        return DecryptionQuality::LowConfidence;
    }

    // Check for printable ASCII ratio
    let printable_count = plaintext
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();

    let ratio = printable_count as f32 / plaintext.len() as f32;

    if ratio > 0.9 {
        DecryptionQuality::HighConfidence
    } else if ratio > 0.5 {
        DecryptionQuality::MediumConfidence
    } else if has_null_terminated_strings(plaintext) {
        // Could be binary data with embedded strings
        DecryptionQuality::MediumConfidence
    } else {
        DecryptionQuality::LowConfidence
    }
}

/// Check if data contains null-terminated strings (indicates valid data).
fn has_null_terminated_strings(data: &[u8]) -> bool {
    let mut in_string = false;
    let mut string_count = 0;
    let mut current_len = 0;

    for &byte in data {
        if byte == 0 {
            if in_string && current_len >= 4 {
                string_count += 1;
            }
            in_string = false;
            current_len = 0;
        } else if byte.is_ascii_graphic() || byte.is_ascii_whitespace() {
            in_string = true;
            current_len += 1;
        } else {
            in_string = false;
            current_len = 0;
        }
    }

    string_count >= 3
}

/// Check if decryption output looks like garbage.
pub fn is_garbage_output(plaintext: &[u8]) -> bool {
    if plaintext.is_empty() {
        return true;
    }

    let printable = plaintext
        .iter()
        .filter(|&&b| {
            (0x20..=0x7e).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' || b == 0
        })
        .count();

    let ratio = printable as f32 / plaintext.len() as f32;

    // For valid AMOS output, expect high printable ratio
    ratio < 0.3 && !has_structure_markers(plaintext)
}

/// Check for common file signatures that indicate valid binary data.
fn has_structure_markers(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    data.starts_with(b"PK")     // ZIP
        || data.starts_with(b"MZ")     // PE
        || data.starts_with(b"\x7fELF") // ELF
        || data.starts_with(b"<?xml")  // XML
        || data.starts_with(b"{")      // JSON
        || data.starts_with(b"#!")     // Shebang
        || data.starts_with(b"tell ")  // AppleScript
        || data.starts_with(b"on ")    // AppleScript
        || data.starts_with(b"set ") // AppleScript
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_base64_alphabet_length() {
        assert_eq!(AMOS_BASE64_ALPHABET.len(), 64);
    }

    #[test]
    fn test_custom_base64_first_last() {
        assert_eq!(AMOS_BASE64_ALPHABET[0], b'H');
        assert_eq!(AMOS_BASE64_ALPHABET[63], b'4');
    }

    #[test]
    fn test_decode_empty() {
        let result = decode_custom_base64(b"");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_validate_high_confidence() {
        let good = b"This is a valid decrypted string with normal text!";
        assert_eq!(validate_decryption(good), DecryptionQuality::HighConfidence);
    }

    #[test]
    fn test_validate_garbage() {
        let bad: Vec<u8> = (0..100).map(|i| ((i * 7) % 256) as u8).collect();
        assert_eq!(validate_decryption(&bad), DecryptionQuality::LowConfidence);
    }

    #[test]
    fn test_is_garbage_on_printable() {
        let good = b"Hello, World!";
        assert!(!is_garbage_output(good));
    }

    #[test]
    fn test_has_structure_markers() {
        assert!(has_structure_markers(b"#!/bin/bash"));
        assert!(has_structure_markers(b"tell application"));
        assert!(has_structure_markers(b"{\"key\": \"value\"}"));
        assert!(!has_structure_markers(b"\x00\x01\x02\x03"));
    }

    #[test]
    fn test_decode_hex_valid() {
        let hex = b"48656c6c6f"; // "Hello" in hex
        let result = decode_hex(hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"Hello");
    }

    #[test]
    fn test_decode_hex_odd_length() {
        // Odd length hex should truncate last char
        let hex = b"48656c6c6f5"; // Extra '5' at end
        let result = decode_hex(hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"Hello");
    }

    #[test]
    fn test_decode_hex_with_whitespace() {
        // Should filter non-hex characters
        let hex = b"48 65 6c 6c 6f";
        let result = decode_hex(hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"Hello");
    }

    #[test]
    fn test_decode_hex_empty() {
        let result = decode_hex(b"");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_decode_hex_no_hex_chars() {
        // Use characters that are definitely not hex (no a-f)
        let result = decode_hex(b"xyz!");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_custom_base64_decode_simple() {
        // AMOS alphabet: 'H' = 0, 'b' = 1, 'e' = 2, '1' = 3
        // In standard base64: 'A' = 0, 'B' = 1, 'C' = 2, 'D' = 3
        // So AMOS "Hbe1" should translate to standard "ABCD"
        // "ABCD" decodes to 0x00, 0x10, 0x83 in standard base64
        let amos = b"Hbe1";
        let result = decode_custom_base64(amos);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_medium_confidence() {
        // Mix of printable and some non-printable
        let mut data = b"Hello World! This is mostly text.".to_vec();
        data.extend_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        let quality = validate_decryption(&data);
        assert!(quality == DecryptionQuality::HighConfidence || quality == DecryptionQuality::MediumConfidence);
    }

    #[test]
    fn test_is_garbage_on_binary() {
        // Use bytes outside printable ASCII range (control chars and high bytes)
        // Avoiding 0x20-0x7e, 0x00, 0x09, 0x0A, 0x0D
        let garbage: Vec<u8> = (1u8..32)
            .filter(|&b| b != 9 && b != 10 && b != 13)
            .chain(128u8..255)
            .collect();
        assert!(is_garbage_output(&garbage));
    }

    #[test]
    fn test_is_garbage_empty() {
        assert!(is_garbage_output(b""));
    }

    #[test]
    fn test_structure_markers_zip() {
        assert!(has_structure_markers(b"PK\x03\x04"));
    }

    #[test]
    fn test_structure_markers_pe() {
        assert!(has_structure_markers(b"MZ\x90\x00"));
    }

    #[test]
    fn test_structure_markers_elf() {
        assert!(has_structure_markers(b"\x7fELF\x02\x01"));
    }

    #[test]
    fn test_null_terminated_strings_detection() {
        // Data with embedded null-terminated strings
        let data = b"string1\0string2\0string3\0string4\0";
        assert!(has_null_terminated_strings(data));
    }

    #[test]
    fn test_null_terminated_strings_short() {
        // Strings too short don't count
        let data = b"ab\0cd\0ef\0";
        assert!(!has_null_terminated_strings(data));
    }
}
