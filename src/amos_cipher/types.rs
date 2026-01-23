//! AMOS cipher type definitions.

/// Cipher variant identified in the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherVariant {
    /// Variant A: Triple lookup table cipher `(table1[i] - table2[i]) ^ table3[i]`
    TripleLookupTable,
    /// Variant B: PRNG-based stream cipher with 64-bit state
    PRNGStreamCipher,
}

/// Result of AMOS detection scan.
#[derive(Debug)]
pub struct AMOSDetectionResult {
    /// Whether AMOS cipher was detected.
    pub detected: bool,
    /// Detected cipher variant (if any).
    pub variant: Option<CipherVariant>,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f32,
    /// Location of encrypted payload(s) as (offset, size) pairs.
    pub payload_locations: Vec<(usize, usize)>,
    /// Additional detection evidence for reporting.
    pub evidence: Vec<DetectionEvidence>,
}

/// Evidence supporting AMOS detection.
#[derive(Debug, Clone)]
pub struct DetectionEvidence {
    pub indicator: String,
    pub value: String,
    pub offset: Option<usize>,
}

/// Decrypted payload with metadata.
#[derive(Debug)]
pub struct DecryptedPayload {
    /// The decrypted plaintext.
    pub plaintext: Vec<u8>,
    /// Original offset in binary.
    pub source_offset: usize,
    /// Size of encrypted data.
    pub encrypted_size: usize,
    /// Cipher variant used for decryption.
    pub variant: CipherVariant,
    /// Whether post-processing (Base64/hex) was applied.
    pub post_processed: bool,
    /// Decrypted string (if valid UTF-8).
    pub as_string: Option<String>,
}

/// Extracted lookup tables from __const section.
#[derive(Debug, Clone)]
pub struct LookupTables {
    /// Table 1: first operand in subtraction.
    pub table1: Vec<u32>,
    /// Table 2: second operand in subtraction.
    pub table2: Vec<u32>,
    /// Table 3: XOR key.
    pub table3: Vec<u32>,
    /// Starting offset of tables in binary.
    pub offset: usize,
    /// Total size of encrypted payload (entries count).
    pub payload_size: usize,
}

/// Information about a decrypted AMOS string.
#[derive(Debug)]
pub struct DecryptedString {
    /// Index of this string (0-based).
    pub index: usize,
    /// Table offsets used for decryption.
    pub table1_offset: usize,
    pub table2_offset: usize,
    pub table3_offset: usize,
    /// Raw decrypted bytes.
    pub raw_bytes: Vec<u8>,
    /// Decoded string (if successful).
    pub decoded: Option<String>,
    /// Whether this is the main payload.
    pub is_main_payload: bool,
}

/// Quality assessment of decryption output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptionQuality {
    High,
    Medium,
    Low,
}

impl DecryptedPayload {
    /// Assess the quality of the decryption based on content analysis.
    pub fn quality(&self) -> DecryptionQuality {
        if self.plaintext.is_empty() {
            return DecryptionQuality::Low;
        }

        // Check printable ratio
        let printable = self
            .plaintext
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace() || b == 0)
            .count();

        let ratio = printable as f32 / self.plaintext.len() as f32;

        if ratio > 0.9 {
            DecryptionQuality::High
        } else if ratio > 0.5 {
            DecryptionQuality::Medium
        } else {
            DecryptionQuality::Low
        }
    }
}
