//! AMOS cipher variant detection.
//!
//! Uses heuristics to determine which cipher variant is present in a Mach-O binary.

use super::error::AMOSError;
use super::table_extractor;
use super::types::{AMOSDetectionResult, CipherVariant, DetectionEvidence};
use super::variant_b;
use goblin::mach::Mach;

/// Minimum __const section size to consider for AMOS (500KB).
const MIN_CONST_SECTION_SIZE: usize = 500_000;

/// Detection confidence threshold.
const DETECTION_THRESHOLD: f32 = 0.5;

/// Mach-O magic numbers for quick format detection.
const MH_MAGIC: u32 = 0xfeedface; // 32-bit
const MH_MAGIC_64: u32 = 0xfeedfacf; // 64-bit
const MH_CIGAM: u32 = 0xcefaedfe; // 32-bit swapped
const MH_CIGAM_64: u32 = 0xcffaedfe; // 64-bit swapped
const FAT_MAGIC: u32 = 0xcafebabe; // Fat/universal
const FAT_CIGAM: u32 = 0xbebafeca; // Fat swapped

/// Quick check if data looks like a Mach-O binary.
/// This avoids expensive parsing for non-Mach-O files.
#[inline]
fn is_macho(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    matches!(
        magic,
        MH_MAGIC | MH_MAGIC_64 | MH_CIGAM | MH_CIGAM_64 | FAT_MAGIC | FAT_CIGAM
    )
}

/// Detect AMOS cipher variant in binary data.
pub fn detect(data: &[u8]) -> Result<AMOSDetectionResult, AMOSError> {
    // Quick check: AMOS only targets Mach-O binaries
    // Skip analysis for non-Mach-O to save significant CPU time
    if !is_macho(data) {
        return Ok(AMOSDetectionResult {
            detected: false,
            variant: None,
            confidence: 0.0,
            payload_locations: vec![],
            evidence: vec![],
        });
    }

    let mut evidence = Vec::new();
    let mut variant_a_score = 0.0f32;
    let mut variant_b_score = 0.0f32;

    // Parse Mach-O (or extract from fat binary)
    let const_size = table_extractor::get_const_section_size(data);

    // === Variant A Detection ===

    // 1. Check for large __const section (>500KB indicates lookup tables)
    if let Some(size) = const_size {
        if size >= MIN_CONST_SECTION_SIZE {
            variant_a_score += 0.3;
            evidence.push(DetectionEvidence {
                indicator: "large_const_section".to_string(),
                value: format!("{} bytes", size),
                offset: None,
            });
        }

        // 2. Check if section size suggests three parallel tables
        // Each table ~240KB = 60K entries * 4 bytes
        if (700_000..=850_000).contains(&size) {
            variant_a_score += 0.2;
            evidence.push(DetectionEvidence {
                indicator: "triple_table_size".to_string(),
                value: format!("{} bytes (~3 tables)", size),
                offset: None,
            });
        }
    }

    // 3. Check for "/dev/urandom" string (strong indicator for Variant A)
    if let Some(offset) = find_string(data, b"/dev/urandom") {
        variant_a_score += 0.2;
        evidence.push(DetectionEvidence {
            indicator: "dev_urandom_string".to_string(),
            value: "/dev/urandom".to_string(),
            offset: Some(offset),
        });
    }

    // 4. Low string density (AMOS encrypts most strings)
    let string_density = calculate_string_density(data);
    if string_density < 0.001 {
        variant_a_score += 0.1;
        variant_b_score += 0.1;
        evidence.push(DetectionEvidence {
            indicator: "low_string_density".to_string(),
            value: format!("{:.4}%", string_density * 100.0),
            offset: None,
        });
    }

    // 5. Try to extract tables (validates Variant A structure)
    if table_extractor::extract_tables(data).is_ok() {
        variant_a_score += 0.2;
        evidence.push(DetectionEvidence {
            indicator: "valid_triple_tables".to_string(),
            value: "tables extracted successfully".to_string(),
            offset: None,
        });
    }

    // === Variant B Detection ===

    // 1. Check for PRNG magic constants
    let prng_constants = variant_b::contains_prng_constants(data);
    for (offset, constant) in &prng_constants {
        variant_b_score += 0.15;
        evidence.push(DetectionEvidence {
            indicator: "prng_constant".to_string(),
            value: format!("0x{:x}", constant),
            offset: Some(*offset),
        });
    }

    // 2. Check for characteristic bit shift patterns in code
    if has_characteristic_shifts(data) {
        variant_b_score += 0.2;
        evidence.push(DetectionEvidence {
            indicator: "prng_bit_shifts".to_string(),
            value: "shifts by 29/17/37/43 detected".to_string(),
            offset: None,
        });
    }

    // Clamp scores to reasonable bounds before comparison
    // Cap variant_b_score from PRNG constants (random data can trigger false positives)
    variant_b_score = variant_b_score.min(0.9);

    // Determine final result - prefer Variant A if tables were successfully extracted
    // since that's a much stronger indicator than finding magic constants in data
    let (detected, variant, confidence) = if variant_a_score >= DETECTION_THRESHOLD {
        // If we could extract valid tables, it's definitely Variant A
        // regardless of any PRNG constants found (which are likely false positives)
        let has_valid_tables = evidence
            .iter()
            .any(|e| e.indicator == "valid_triple_tables");
        if has_valid_tables || variant_a_score > variant_b_score {
            (
                true,
                Some(CipherVariant::TripleLookupTable),
                variant_a_score.min(1.0),
            )
        } else if variant_b_score >= DETECTION_THRESHOLD {
            (
                true,
                Some(CipherVariant::PRNGStreamCipher),
                variant_b_score.min(1.0),
            )
        } else {
            (
                true,
                Some(CipherVariant::TripleLookupTable),
                variant_a_score.min(1.0),
            )
        }
    } else if variant_b_score >= DETECTION_THRESHOLD {
        (
            true,
            Some(CipherVariant::PRNGStreamCipher),
            variant_b_score.min(1.0),
        )
    } else {
        (false, None, 0.0)
    };

    // Find payload locations
    let payload_locations = if detected {
        find_payload_locations(data, variant)
    } else {
        Vec::new()
    };

    Ok(AMOSDetectionResult {
        detected,
        variant,
        confidence,
        payload_locations,
        evidence,
    })
}

/// Find a byte string in data using SIMD-accelerated search.
fn find_string(data: &[u8], pattern: &[u8]) -> Option<usize> {
    memchr::memmem::find(data, pattern)
}

/// Calculate readable string density in binary.
fn calculate_string_density(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut printable_runs = 0;
    let mut in_run = false;
    let mut run_length = 0;

    for &byte in data {
        if byte.is_ascii_graphic() || byte == b' ' {
            if !in_run {
                in_run = true;
                run_length = 0;
            }
            run_length += 1;
        } else {
            if in_run && run_length >= 4 {
                printable_runs += run_length;
            }
            in_run = false;
            run_length = 0;
        }
    }

    // Don't forget trailing run
    if in_run && run_length >= 4 {
        printable_runs += run_length;
    }

    printable_runs as f32 / data.len() as f32
}

/// Check for characteristic bit shift patterns (Variant B).
fn has_characteristic_shifts(data: &[u8]) -> bool {
    // Look for immediate values 29, 17, 37, 43 which are used in PRNG
    // These appear as shift amounts in x86_64 instructions
    let shift_values = [29u8, 17, 37, 43];
    let mut found_count = 0;

    // Search for these values in instruction-like contexts
    for window in data.windows(3) {
        // Common x86 shift patterns: shr/shl reg, imm8
        if (window[0] == 0xC1 || window[0] == 0xC0) && shift_values.contains(&window[2]) {
            found_count += 1;
        }
        // Also check for these as standalone bytes near each other
    }

    found_count >= 2
}

/// Find encrypted payload locations in the binary.
fn find_payload_locations(data: &[u8], variant: Option<CipherVariant>) -> Vec<(usize, usize)> {
    let mut locations = Vec::new();

    match variant {
        Some(CipherVariant::TripleLookupTable) => {
            // For Variant A, payload is the __const section
            if let Ok(tables) = table_extractor::extract_tables(data) {
                let total_size = tables.payload_size * 4 * 3;
                locations.push((tables.offset, total_size));
            }
        }
        Some(CipherVariant::PRNGStreamCipher) => {
            // For Variant B, need to find encrypted regions
            // This is harder without knowing the exact layout
            if let Some(size) = table_extractor::get_const_section_size(data) {
                // Assume encrypted payload is in __const
                // Get offset by parsing
                if let Ok(Mach::Binary(macho)) = Mach::parse(data) {
                    for segment in &macho.segments {
                        if segment.name().unwrap_or("") == "__TEXT" {
                            if let Ok(sections) = segment.sections() {
                                for (section, _) in sections {
                                    if section.name().unwrap_or("") == "__const" {
                                        locations.push((section.offset as usize, size));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None => {}
    }

    locations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_string() {
        let data = b"hello world /dev/urandom test";
        let pos = find_string(data, b"/dev/urandom");
        assert_eq!(pos, Some(12));
    }

    #[test]
    fn test_find_string_not_found() {
        let data = b"hello world test";
        let pos = find_string(data, b"/dev/urandom");
        assert_eq!(pos, None);
    }

    #[test]
    fn test_string_density_high() {
        let data = b"This is a normal text file with lots of readable content.";
        let density = calculate_string_density(data);
        assert!(density > 0.5);
    }

    #[test]
    fn test_string_density_low() {
        // Generate mostly non-printable data (high bytes > 127)
        let data: Vec<u8> = (0..1000).map(|i| (128 + (i % 128)) as u8).collect();
        let density = calculate_string_density(&data);
        assert!(density < 0.1);
    }
}
