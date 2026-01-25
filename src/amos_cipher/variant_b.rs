//! Variant B: PRNG-based Stream Cipher
//!
//! This variant uses a more complex algorithm with multi-stage bit manipulation.
//! Key constants were identified through reverse engineering:
//! - 0x555555555 - Alternating bit pattern mask
//! - 0x71d67fffeda60000 - PRNG mixing mask
//! - 0x7ffbf77 - Non-linear transformation mask
//! - 0xb5026f5aa96619e9 - PRNG state multiplier
//! - Post-XOR addition of 0x5

use super::error::AMOSError;
use super::types::{CipherVariant, DecryptedPayload, DecryptionQuality};

/// Key constants for PRNG state evolution.
const PRNG_CONST_1: u64 = 0x555555555;
const PRNG_CONST_2: u64 = 0x71d67fffeda60000;
const PRNG_CONST_3: u64 = 0x7ffbf77;
const PRNG_CONST_4: u64 = 0xb5026f5aa96619e9;
const POST_XOR_ADDEND: u8 = 0x5;

/// PRNG state structure for stream cipher.
struct PRNGState {
    state: u64,
    counter: usize,
}

impl PRNGState {
    fn new(seed: u64) -> Self {
        Self {
            state: seed,
            counter: 0,
        }
    }

    /// Generate next keystream byte using AMOS PRNG algorithm.
    fn next(&mut self) -> u8 {
        let mut x = self.state;

        // Multi-stage bit manipulation (matches AMOS disassembly)
        // Stage 1: XOR with right-shifted value masked by alternating bits
        x ^= (x >> 29) & PRNG_CONST_1;

        // Stage 2: XOR with left-shifted value masked
        x ^= (x << 17) & PRNG_CONST_2;

        // Stage 3: Non-linear transformation
        x ^= (x << 37) & PRNG_CONST_3;

        // Stage 4: Final mixing
        x ^= x >> 43;

        // Update state with multiplication
        self.state = x.wrapping_mul(PRNG_CONST_4);
        self.counter += 1;

        // Extract byte and apply post-addition
        x.wrapping_add(POST_XOR_ADDEND as u64) as u8
    }
}

/// Decrypt using PRNG-based stream cipher (Variant B).
pub fn decrypt(encrypted: &[u8], seed: u64) -> Result<DecryptedPayload, AMOSError> {
    let mut prng = PRNGState::new(seed);
    let mut plaintext = Vec::with_capacity(encrypted.len());

    for &byte in encrypted {
        let key_byte = prng.next();
        plaintext.push(byte ^ key_byte);
    }

    // Strip trailing padding
    let plaintext = strip_padding(&plaintext);

    let quality = validate_quality(&plaintext);
    let as_string = if quality != DecryptionQuality::Low {
        String::from_utf8(plaintext.clone()).ok()
    } else {
        None
    };

    Ok(DecryptedPayload {
        plaintext,
        source_offset: 0,
        variant: CipherVariant::PRNGStreamCipher,
        as_string,
    })
}

/// Try to find the PRNG seed from the binary.
pub fn find_seed(data: &[u8], payload_offset: usize) -> Option<u64> {
    // Seeds are typically stored near the encrypted payload
    let search_range = 512;
    let start = payload_offset.saturating_sub(search_range);
    let end = (payload_offset + search_range).min(data.len().saturating_sub(8));

    let mut candidates = Vec::new();

    // Look for 64-bit values that could be seeds
    for offset in (start..end).step_by(8) {
        if offset + 8 > data.len() {
            break;
        }

        let candidate = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);

        if is_plausible_seed(candidate) {
            candidates.push((offset, candidate));
        }
    }

    // Return first plausible seed
    candidates.first().map(|&(_, seed)| seed)
}

/// Check if a value could be a PRNG seed.
fn is_plausible_seed(value: u64) -> bool {
    // Seeds typically have moderate entropy (not all 0s or 1s)
    let ones = value.count_ones();
    value != 0 && value != u64::MAX && ones > 10 && ones < 54
}

/// Try multiple seeds and return the best decryption result.
pub fn try_decrypt_with_seeds(
    encrypted: &[u8],
    candidate_seeds: &[u64],
) -> Option<DecryptedPayload> {
    for &seed in candidate_seeds {
        if let Ok(payload) = decrypt(encrypted, seed) {
            let quality = validate_quality(&payload.plaintext);
            if quality != DecryptionQuality::Low {
                return Some(payload);
            }
        }
    }
    None
}

/// Strip trailing zeros/padding.
fn strip_padding(data: &[u8]) -> Vec<u8> {
    let mut end = data.len();
    while end > 0 && data[end - 1] == 0 {
        end -= 1;
    }
    data[..end].to_vec()
}

/// Validate decryption quality.
fn validate_quality(data: &[u8]) -> DecryptionQuality {
    if data.is_empty() {
        return DecryptionQuality::Low;
    }

    let printable = data
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace() || b == 0)
        .count();

    let ratio = printable as f32 / data.len() as f32;

    if ratio > 0.9 {
        DecryptionQuality::High
    } else if ratio > 0.5 {
        DecryptionQuality::Medium
    } else {
        DecryptionQuality::Low
    }
}

/// Check if binary contains PRNG constants (detection helper).
/// Uses SIMD-accelerated memmem for fast searching instead of byte-by-byte scan.
pub fn contains_prng_constants(data: &[u8]) -> Vec<(usize, u64)> {
    use memchr::memmem::Finder;

    let constants = [PRNG_CONST_1, PRNG_CONST_2, PRNG_CONST_3, PRNG_CONST_4];
    let mut found = Vec::new();

    // Pre-build finders for each constant's byte pattern
    for constant in &constants {
        let pattern = constant.to_le_bytes();
        let finder = Finder::new(&pattern);

        for offset in finder.find_iter(data) {
            // Only count 4-byte aligned matches (typical for compiled code)
            if offset % 4 == 0 {
                found.push((offset, *constant));
            }
        }
    }

    // Sort by offset for consistent ordering
    found.sort_by_key(|(offset, _)| *offset);
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prng_state_deterministic() {
        let mut prng1 = PRNGState::new(12345);
        let mut prng2 = PRNGState::new(12345);

        for _ in 0..100 {
            assert_eq!(prng1.next(), prng2.next());
        }
    }

    #[test]
    fn test_prng_different_seeds() {
        let mut prng1 = PRNGState::new(12345);
        let mut prng2 = PRNGState::new(54321);

        // Different seeds should produce different output
        let mut same_count = 0;
        for _ in 0..100 {
            if prng1.next() == prng2.next() {
                same_count += 1;
            }
        }
        // Statistically, should have very few matches
        assert!(same_count < 10);
    }

    #[test]
    fn test_is_plausible_seed() {
        assert!(!is_plausible_seed(0));
        assert!(!is_plausible_seed(u64::MAX));
        assert!(is_plausible_seed(0x123456789abcdef0));
    }

    #[test]
    fn test_decrypt_roundtrip() {
        let seed = 0x123456789abcdef0u64;
        let plaintext = b"Hello, World!";

        // Encrypt
        let mut prng = PRNGState::new(seed);
        let encrypted: Vec<u8> = plaintext.iter().map(|&b| b ^ prng.next()).collect();

        // Decrypt
        let result = decrypt(&encrypted, seed).unwrap();
        assert_eq!(&result.plaintext, plaintext);
    }

    #[test]
    fn test_contains_prng_constants() {
        let mut data = vec![0u8; 100];
        // Embed a constant at 4-byte aligned offset (search uses step_by(4))
        let const_bytes = PRNG_CONST_2.to_le_bytes();
        data[48..56].copy_from_slice(&const_bytes);

        let found = contains_prng_constants(&data);
        assert!(!found.is_empty());
        assert_eq!(found[0].1, PRNG_CONST_2);
    }
}
