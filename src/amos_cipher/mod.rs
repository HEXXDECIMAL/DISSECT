//! AMOS Cipher Detection and Decryption Module
//!
//! This module provides automated detection and decryption of AMOS stealer
//! encrypted payloads in Mach-O binaries.
//!
//! # Supported Cipher Variants
//!
//! ## Variant A: Triple Lookup Table Cipher
//! - Algorithm: `plaintext[i] = (table1[i] - table2[i]) ^ table3[i]`
//! - Three parallel arrays of 32-bit integers in __const section
//! - Post-processing: Custom Base64 → Hex decode
//!
//! ## Variant B: PRNG-based Stream Cipher
//! - Multi-stage XOR with bit manipulation
//! - Uses characteristic constants: 0x555555555, 0x71d67fffeda60000, etc.
//!
//! # Example
//!
//! ```ignore
//! use dissect::amos_cipher::AMOSCipherAnalyzer;
//!
//! let data = std::fs::read("malware.macho")?;
//! let analyzer = AMOSCipherAnalyzer::new();
//!
//! if let Ok(detection) = analyzer.detect(&data) {
//!     if detection.detected {
//!         println!("AMOS cipher detected: {:?}", detection.variant);
//!
//!         if let Ok(payloads) = analyzer.decrypt(&data) {
//!             for payload in payloads {
//!                 if let Some(script) = payload.as_string {
//!                     println!("Decrypted: {}", script);
//!                 }
//!             }
//!         }
//!     }
//! }
//! ```

mod detection;
mod error;
mod postprocess;
mod table_extractor;
mod types;
mod variant_a;
mod variant_b;

pub use error::AMOSError;
pub use types::{AMOSDetectionResult, CipherVariant, DecryptedPayload, DecryptionQuality};

/// Main entry point for AMOS cipher analysis.
pub struct AMOSCipherAnalyzer;

impl Default for AMOSCipherAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl AMOSCipherAnalyzer {
    /// Create a new analyzer instance.
    pub fn new() -> Self {
        Self
    }

    /// Detect if a Mach-O binary contains AMOS cipher signatures.
    ///
    /// Returns detection result with variant info and confidence score.
    pub fn detect(&self, data: &[u8]) -> Result<AMOSDetectionResult, AMOSError> {
        detection::detect(data)
    }

    /// Attempt to decrypt all payloads in a Mach-O binary.
    ///
    /// Automatically detects variant and applies appropriate decryption.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<DecryptedPayload>, AMOSError> {
        let detection = self.detect(data)?;

        if !detection.detected {
            return Err(AMOSError::NotAMOSEncrypted);
        }

        match detection.variant {
            Some(CipherVariant::TripleLookupTable) => self.decrypt_variant_a(data),
            Some(CipherVariant::PRNGStreamCipher) => self.decrypt_variant_b(data, &detection),
            None => Err(AMOSError::NotAMOSEncrypted),
        }
    }

    /// Decrypt using Variant A (Triple Lookup Table).
    fn decrypt_variant_a(&self, data: &[u8]) -> Result<Vec<DecryptedPayload>, AMOSError> {
        let mut all_payloads = Vec::new();

        // Try multi-table extraction first (finds all encrypted strings)
        if let Ok(table_sets) = table_extractor::extract_all_table_sets(data) {
            for addresses in &table_sets {
                if let Ok(tables) = table_extractor::load_tables_at_addresses(data, addresses) {
                    let payloads = variant_a::try_decrypt_variants(&tables);
                    all_payloads.extend(payloads);
                }
            }
        }

        // Fallback to original method if multi-table extraction fails
        if all_payloads.is_empty() {
            if let Ok(tables) = table_extractor::extract_tables(data) {
                let payloads = variant_a::try_decrypt_variants(&tables);

                if payloads.is_empty() {
                    // Try standard decryption even if quality is low
                    let payload = variant_a::decrypt(&tables)?;
                    all_payloads.push(payload);
                } else {
                    all_payloads.extend(payloads);
                }
            }
        }

        if all_payloads.is_empty() {
            Err(AMOSError::NotAMOSEncrypted)
        } else {
            Ok(all_payloads)
        }
    }

    /// Decrypt using Variant B (PRNG Stream Cipher).
    fn decrypt_variant_b(
        &self,
        data: &[u8],
        detection: &AMOSDetectionResult,
    ) -> Result<Vec<DecryptedPayload>, AMOSError> {
        let mut payloads = Vec::new();

        for &(offset, size) in &detection.payload_locations {
            if offset + size > data.len() {
                continue;
            }

            let encrypted = &data[offset..offset + size];

            // Try to find seed
            if let Some(seed) = variant_b::find_seed(data, offset) {
                if let Ok(mut payload) = variant_b::decrypt(encrypted, seed) {
                    payload.source_offset = offset;
                    payloads.push(payload);
                }
            }

            // Try common seed values as fallback
            let common_seeds = [0u64, 1, 0x12345678, 0xdeadbeef];
            if let Some(mut payload) = variant_b::try_decrypt_with_seeds(encrypted, &common_seeds) {
                payload.source_offset = offset;
                payloads.push(payload);
            }
        }

        if payloads.is_empty() {
            Err(AMOSError::SeedNotFound)
        } else {
            Ok(payloads)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = AMOSCipherAnalyzer::new();
        // Should not panic
        let _ = analyzer.detect(&[]);
    }

    #[test]
    fn test_default_impl() {
        let analyzer: AMOSCipherAnalyzer = Default::default();
        let _ = analyzer.detect(&[]); // Just verify it works
    }
}
