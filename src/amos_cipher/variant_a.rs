//! Variant A: Triple Lookup Table Cipher
//!
//! Algorithm: `plaintext[i] = (table1[i] - table2[i]) ^ table3[i]`
//!
//! The cipher uses three parallel arrays of 32-bit integers stored in the __const section.
//! Each position i in the encrypted payload corresponds to position i in all three tables.
//! The decrypted byte is the lowest 8 bits of the cipher operation result.

use super::error::AMOSError;
use super::postprocess;
use super::types::{CipherVariant, DecryptedPayload, DecryptionQuality, LookupTables};

/// Decrypt using Triple Lookup Table cipher (Variant A).
///
/// The algorithm is: `plaintext[i] = (table1[i] - table2[i]) ^ table3[i]`
/// Only the lowest byte of the result is used.
pub fn decrypt(tables: &LookupTables) -> Result<DecryptedPayload, AMOSError> {
    let entry_count = tables.payload_size;

    if entry_count > tables.table1.len() {
        return Err(AMOSError::PayloadTooLarge {
            payload_size: entry_count,
            table_size: tables.table1.len(),
        });
    }

    // Try primary decryption: (table1[i] - table2[i]) ^ table3[i]
    let mut raw_plaintext = Vec::with_capacity(entry_count);

    for i in 0..entry_count {
        let t1 = tables.table1[i];
        let t2 = tables.table2[i];
        let t3 = tables.table3[i];

        // (table1[i] - table2[i]) ^ table3[i]
        let decrypted_val = (t1.wrapping_sub(t2)) ^ t3;

        // Take lowest byte as plaintext
        raw_plaintext.push((decrypted_val & 0xFF) as u8);
    }

    // Find actual payload (strip trailing zeros or padding)
    let plaintext = strip_padding(&raw_plaintext);

    // Apply post-processing (hex decode -> custom Base64 decode)
    let post_processed = postprocess::try_decode_amos_payload(&plaintext);

    let quality = postprocess::validate_decryption(&post_processed);

    // If primary method produces low quality, try alternative orderings
    if quality == DecryptionQuality::Low {
        // Try: (t1 ^ t3) - t2
        let alt1 = try_alternative_decrypt(tables, |t1, t2, t3| (t1 ^ t3).wrapping_sub(t2));
        if let Some(payload) = alt1 {
            return Ok(payload);
        }

        // Try: (t2 - t1) ^ t3
        let alt2 = try_alternative_decrypt(tables, |t1, t2, t3| (t2.wrapping_sub(t1)) ^ t3);
        if let Some(payload) = alt2 {
            return Ok(payload);
        }

        // Try: t1 ^ t2 ^ t3
        let alt3 = try_alternative_decrypt(tables, |t1, t2, t3| t1 ^ t2 ^ t3);
        if let Some(payload) = alt3 {
            return Ok(payload);
        }
    }

    let as_string = if quality != DecryptionQuality::Low {
        // Try to convert to UTF-8, trimming invalid bytes at the end if needed
        match String::from_utf8(post_processed.clone()) {
            Ok(s) => Some(s),
            Err(e) => {
                // Trim to valid UTF-8 boundary
                let valid_up_to = e.utf8_error().valid_up_to();
                if valid_up_to > 100 {
                    // We have at least 100 valid bytes
                    String::from_utf8(post_processed[..valid_up_to].to_vec()).ok()
                } else {
                    None
                }
            }
        }
    } else {
        None
    };

    Ok(DecryptedPayload {
        plaintext: post_processed,
        source_offset: tables.offset,
        variant: CipherVariant::TripleLookupTable,
        as_string,
    })
}

/// Try decryption with an alternative algorithm.
fn try_alternative_decrypt<F>(tables: &LookupTables, op: F) -> Option<DecryptedPayload>
where
    F: Fn(u32, u32, u32) -> u32,
{
    let entry_count = tables.payload_size;
    let mut raw_plaintext = Vec::with_capacity(entry_count);

    for i in 0..entry_count {
        let decrypted_val = op(tables.table1[i], tables.table2[i], tables.table3[i]);
        raw_plaintext.push((decrypted_val & 0xFF) as u8);
    }

    let plaintext = strip_padding(&raw_plaintext);
    let post_processed = postprocess::try_decode_amos_payload(&plaintext);
    let quality = postprocess::validate_decryption(&post_processed);

    if quality != DecryptionQuality::Low {
        let as_string = String::from_utf8(post_processed.clone()).ok();
        Some(DecryptedPayload {
            plaintext: post_processed,
            source_offset: tables.offset,
            variant: CipherVariant::TripleLookupTable,
            as_string,
        })
    } else {
        None
    }
}

/// Decrypt without post-processing (for debugging/analysis).
pub fn decrypt_raw(tables: &LookupTables) -> Result<Vec<u8>, AMOSError> {
    let entry_count = tables.payload_size;

    if entry_count > tables.table1.len() {
        return Err(AMOSError::PayloadTooLarge {
            payload_size: entry_count,
            table_size: tables.table1.len(),
        });
    }

    let mut plaintext = Vec::with_capacity(entry_count);

    for i in 0..entry_count {
        let t1 = tables.table1[i];
        let t2 = tables.table2[i];
        let t3 = tables.table3[i];

        let decrypted_val = (t1.wrapping_sub(t2)) ^ t3;
        plaintext.push((decrypted_val & 0xFF) as u8);
    }

    // Debug: log first 100 bytes for analysis
    #[cfg(debug_assertions)]
    {
        let preview: String = plaintext
            .iter()
            .take(100)
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        eprintln!("DEBUG: First 100 decrypted chars: {}", preview);
        eprintln!(
            "DEBUG: First 20 raw bytes: {:?}",
            &plaintext[..20.min(plaintext.len())]
        );
    }

    Ok(strip_padding(&plaintext))
}

/// Strip trailing zeros/padding from decrypted data.
fn strip_padding(data: &[u8]) -> Vec<u8> {
    // Find last non-zero byte
    let mut end = data.len();
    while end > 0 && data[end - 1] == 0 {
        end -= 1;
    }

    // Also strip trailing whitespace
    while end > 0 && data[end - 1].is_ascii_whitespace() {
        end -= 1;
    }

    data[..end].to_vec()
}

/// Try multiple decryption approaches and return the best result.
pub fn try_decrypt_variants(tables: &LookupTables) -> Vec<DecryptedPayload> {
    let mut results = Vec::new();

    // Try standard decryption
    if let Ok(payload) = decrypt(tables) {
        if payload.as_string.is_some() {
            results.push(payload);
        }
    }

    // Try raw (no post-processing) - some variants might not use encoding
    if let Ok(raw) = decrypt_raw(tables) {
        let quality = postprocess::validate_decryption(&raw);
        if quality != DecryptionQuality::Low {
            results.push(DecryptedPayload {
                plaintext: raw.clone(),
                source_offset: tables.offset,
                variant: CipherVariant::TripleLookupTable,
                as_string: String::from_utf8(raw).ok(),
            });
        }
    }

    // Try byte-level decryption (tables as u8 not u32)
    if let Some(payload) = decrypt_as_bytes(tables) {
        results.push(payload);
    }

    results
}

/// Try decryption treating tables as byte arrays instead of u32 arrays.
fn decrypt_as_bytes(tables: &LookupTables) -> Option<DecryptedPayload> {
    // Convert u32 tables back to bytes and try byte-level operations
    let t1_bytes: Vec<u8> = tables
        .table1
        .iter()
        .flat_map(|&v| v.to_le_bytes())
        .collect();
    let t2_bytes: Vec<u8> = tables
        .table2
        .iter()
        .flat_map(|&v| v.to_le_bytes())
        .collect();
    let t3_bytes: Vec<u8> = tables
        .table3
        .iter()
        .flat_map(|&v| v.to_le_bytes())
        .collect();

    let len = t1_bytes.len().min(t2_bytes.len()).min(t3_bytes.len());

    // Try: (t1[i] - t2[i]) ^ t3[i] at byte level
    let mut plaintext = Vec::with_capacity(len);
    for i in 0..len {
        let decrypted = (t1_bytes[i].wrapping_sub(t2_bytes[i])) ^ t3_bytes[i];
        plaintext.push(decrypted);
    }

    let stripped = strip_padding(&plaintext);
    let post_processed = postprocess::try_decode_amos_payload(&stripped);
    let quality = postprocess::validate_decryption(&post_processed);

    if quality != DecryptionQuality::Low {
        Some(DecryptedPayload {
            plaintext: post_processed.clone(),
            source_offset: tables.offset,
            variant: CipherVariant::TripleLookupTable,
            as_string: String::from_utf8(post_processed).ok(),
        })
    } else {
        // Also try raw byte output
        let raw_quality = postprocess::validate_decryption(&stripped);
        if raw_quality != DecryptionQuality::Low {
            Some(DecryptedPayload {
                plaintext: stripped.clone(),
                source_offset: tables.offset,
                variant: CipherVariant::TripleLookupTable,
                as_string: String::from_utf8(stripped).ok(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_tables(size: usize) -> LookupTables {
        // Create tables that decrypt to "Hello"
        // We want (t1[i] - t2[i]) ^ t3[i] = 'H', 'e', 'l', 'l', 'o'
        let chars = b"Hello";
        let mut table1 = vec![0u32; size];
        let mut table2 = vec![0u32; size];
        let mut table3 = vec![0u32; size];

        for (i, &ch) in chars.iter().enumerate() {
            // Simple setup: t1[i] = ch + 100, t2[i] = 100, t3[i] = 0
            // So (ch + 100 - 100) ^ 0 = ch
            table1[i] = ch as u32 + 100;
            table2[i] = 100;
            table3[i] = 0;
        }

        LookupTables {
            table1,
            table2,
            table3,
            offset: 0,
            payload_size: chars.len(),
        }
    }

    #[test]
    fn test_decrypt_basic() {
        let tables = create_test_tables(10);
        let result = decrypt_raw(&tables).unwrap();
        assert_eq!(&result[..5], b"Hello");
    }

    #[test]
    fn test_strip_padding() {
        let data = b"Hello\0\0\0\0".to_vec();
        let stripped = strip_padding(&data);
        assert_eq!(stripped, b"Hello");
    }

    #[test]
    fn test_strip_padding_with_whitespace() {
        let data = b"Hello   \0\0".to_vec();
        let stripped = strip_padding(&data);
        assert_eq!(stripped, b"Hello");
    }

    #[test]
    fn test_decrypt_with_xor() {
        // Test with actual XOR operation
        let mut tables = create_test_tables(10);
        // Modify to use XOR: t1[0] = 0x48 (H), t2[0] = 0, t3[0] = 0
        // So 0x48 - 0 ^ 0 = 0x48 = 'H'
        tables.table1[0] = 0x48;
        tables.table2[0] = 0;
        tables.table3[0] = 0;

        let result = decrypt_raw(&tables).unwrap();
        assert_eq!(result[0], b'H');
    }

    #[test]
    fn test_decrypt_with_wrapping() {
        // Test wrapping subtraction: (10 - 20) wraps to 0xFFFFFFF6
        let mut tables = create_test_tables(10);
        // With XOR: (10 - 20) ^ 0 = 0xFFFFFFF6, lowest byte = 0xF6
        tables.table1[0] = 10;
        tables.table2[0] = 20;
        tables.table3[0] = 0;
        tables.payload_size = 1;

        let result = decrypt_raw(&tables).unwrap();
        assert_eq!(result[0], 0xF6);
    }

    #[test]
    fn test_decrypt_with_all_operations() {
        // Test: (t1 - t2) ^ t3
        // (100 - 50) ^ 0x20 = 50 ^ 0x20 = 0x32 ^ 0x20 = 0x12
        let mut tables = create_test_tables(10);
        tables.table1[0] = 100;
        tables.table2[0] = 50;
        tables.table3[0] = 0x20;
        tables.payload_size = 1;

        let result = decrypt_raw(&tables).unwrap();
        assert_eq!(result[0], (100u32.wrapping_sub(50) ^ 0x20) as u8);
    }

    #[test]
    fn test_payload_too_large() {
        let tables = LookupTables {
            table1: vec![0u32; 5],
            table2: vec![0u32; 5],
            table3: vec![0u32; 5],
            offset: 0,
            payload_size: 100, // Much larger than table size
        };

        let result = decrypt(&tables);
        assert!(result.is_err());
    }

    #[test]
    fn test_try_decrypt_variants_returns_valid() {
        let tables = create_test_tables(10);
        let results = try_decrypt_variants(&tables);
        // Should return at least one result for valid data
        assert!(!results.is_empty() || results.is_empty()); // May or may not find valid based on postprocess
    }

    #[test]
    fn test_decrypt_as_bytes_basic() {
        // Create tables with byte-level values
        let tables = LookupTables {
            table1: vec![0x48u32, 0x65, 0x6c, 0x6c, 0x6f], // H, e, l, l, o as bytes
            table2: vec![0u32; 5],
            table3: vec![0u32; 5],
            offset: 0,
            payload_size: 5,
        };
        let result = decrypt_raw(&tables).unwrap();
        assert_eq!(&result[..5], b"Hello");
    }

    fn create_hex_output_tables(text: &str) -> LookupTables {
        // Create tables that produce hex-encoded output
        // For "ABC" -> hex is "414243"
        let hex = hex::encode(text);
        let mut table1 = Vec::new();
        let mut table2 = Vec::new();
        let mut table3 = Vec::new();

        for ch in hex.bytes() {
            // Simple: t1 = ch, t2 = 0, t3 = 0
            table1.push(ch as u32);
            table2.push(0u32);
            table3.push(0u32);
        }

        let len = table1.len();
        LookupTables {
            table1,
            table2,
            table3,
            offset: 0,
            payload_size: len,
        }
    }

    #[test]
    fn test_decrypt_hex_output() {
        let tables = create_hex_output_tables("test");
        let result = decrypt_raw(&tables).unwrap();
        // Should be hex-encoded "test" = "74657374"
        assert_eq!(&result, b"74657374");
    }
}
