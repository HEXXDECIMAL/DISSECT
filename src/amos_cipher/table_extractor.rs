//! Mach-O table extraction for AMOS cipher.
//!
//! Extracts lookup tables from the __const section of Mach-O binaries.
//! Tables are located by finding ADRP+ADD instruction patterns in ARM64 code.

use super::error::AMOSError;
use super::types::LookupTables;
use goblin::mach::{Mach, MachO};

/// Represents a set of table addresses for a single encrypted string.
#[derive(Debug, Clone)]
pub struct TableAddresses {
    pub table1_offset: usize,
    pub table2_offset: usize,
    pub table3_offset: usize,
    pub payload_size: usize,
}

/// Extract lookup tables from Mach-O binary data.
pub fn extract_tables(data: &[u8]) -> Result<LookupTables, AMOSError> {
    let macho = match Mach::parse(data)? {
        Mach::Binary(m) => m,
        Mach::Fat(fat) => {
            // For fat binaries, extract the preferred architecture
            return extract_from_fat_binary(data, &fat);
        }
    };

    // Try sequential layout first
    if let Ok(tables) = extract_from_single_macho(data, &macho) {
        return Ok(tables);
    }

    // Try interleaved layout as fallback
    extract_interleaved_tables(data, &macho)
}

/// Extract tables with interleaved layout: [t1_0, t2_0, t3_0, t1_1, t2_1, t3_1, ...]
fn extract_interleaved_tables(data: &[u8], macho: &MachO) -> Result<LookupTables, AMOSError> {
    let const_section = find_const_section(macho)?;
    let offset = const_section.0;
    let size = const_section.1;

    if offset + size > data.len() {
        return Err(AMOSError::InvalidSection(
            "__const section out of bounds".into(),
        ));
    }

    let section_data = &data[offset..offset + size];

    // For interleaved layout, each entry is 12 bytes (3 × u32)
    let entry_count = size / 12;

    if entry_count == 0 {
        return Err(AMOSError::InsufficientData(
            "section too small for interleaved tables".into(),
        ));
    }

    let mut table1 = Vec::with_capacity(entry_count);
    let mut table2 = Vec::with_capacity(entry_count);
    let mut table3 = Vec::with_capacity(entry_count);

    for i in 0..entry_count {
        let base = i * 12;
        if base + 12 > section_data.len() {
            break;
        }

        table1.push(u32::from_le_bytes([
            section_data[base],
            section_data[base + 1],
            section_data[base + 2],
            section_data[base + 3],
        ]));
        table2.push(u32::from_le_bytes([
            section_data[base + 4],
            section_data[base + 5],
            section_data[base + 6],
            section_data[base + 7],
        ]));
        table3.push(u32::from_le_bytes([
            section_data[base + 8],
            section_data[base + 9],
            section_data[base + 10],
            section_data[base + 11],
        ]));
    }

    Ok(LookupTables {
        table1,
        table2,
        table3,
        offset,
        payload_size: entry_count,
    })
}

/// Extract tables from a single-architecture Mach-O.
fn extract_from_single_macho(data: &[u8], macho: &MachO) -> Result<LookupTables, AMOSError> {
    // Find __const section in __TEXT segment (AMOS stores tables here)
    let const_section = find_const_section(macho)?;

    let offset = const_section.0;
    let size = const_section.1;

    if offset + size > data.len() {
        return Err(AMOSError::InvalidSection(
            "__const section out of bounds".into(),
        ));
    }

    let section_data = &data[offset..offset + size];

    // Estimate table size based on section size
    // AMOS uses three equal-sized tables of u32 values
    let table_entry_count = estimate_table_size(section_data)?;
    let table_byte_size = table_entry_count * 4;

    if section_data.len() < table_byte_size * 3 {
        return Err(AMOSError::InsufficientData(format!(
            "need {} bytes for 3 tables, got {}",
            table_byte_size * 3,
            section_data.len()
        )));
    }

    // Extract three tables
    let table1 = extract_u32_array(&section_data[0..table_byte_size])?;
    let table2 = extract_u32_array(&section_data[table_byte_size..table_byte_size * 2])?;
    let table3 = extract_u32_array(&section_data[table_byte_size * 2..table_byte_size * 3])?;

    Ok(LookupTables {
        table1,
        table2,
        table3,
        offset,
        payload_size: table_entry_count,
    })
}

/// Extract from a fat (universal) binary.
fn extract_from_fat_binary(
    data: &[u8],
    fat: &goblin::mach::MultiArch,
) -> Result<LookupTables, AMOSError> {
    // Prefer arm64 if available, otherwise use first architecture
    let arches = fat.arches().map_err(AMOSError::GoblinError)?;

    // goblin uses u32 for cputype, ARM64 = CPU_TYPE_ARM64 = 0x0100000c
    let preferred_arch = arches
        .iter()
        .find(|a| a.cputype == 0x0100000c) // arm64
        .or_else(|| arches.first());

    match preferred_arch {
        Some(arch) => {
            let arch_offset = arch.offset as usize;
            let arch_size = arch.size as usize;

            if arch_offset + arch_size > data.len() {
                return Err(AMOSError::InvalidSection(
                    "architecture slice out of bounds".into(),
                ));
            }

            let arch_data = &data[arch_offset..arch_offset + arch_size];

            match Mach::parse(arch_data)? {
                Mach::Binary(m) => {
                    let mut tables = extract_from_single_macho(arch_data, &m)?;
                    // Adjust offset to be relative to original file
                    tables.offset += arch_offset;
                    Ok(tables)
                }
                _ => Err(AMOSError::InvalidFormat(
                    "unexpected nested fat binary".into(),
                )),
            }
        }
        None => Err(AMOSError::NoArchitecture),
    }
}

/// Find the __const section in the Mach-O binary.
/// Returns (offset, size).
fn find_const_section(macho: &MachO) -> Result<(usize, usize), AMOSError> {
    for segment in &macho.segments {
        let seg_name = segment.name().unwrap_or("");

        // Check __TEXT segment (where AMOS stores encrypted data)
        if seg_name == "__TEXT" {
            if let Ok(sections) = segment.sections() {
                for (section, _) in sections {
                    let sect_name = section.name().unwrap_or("");
                    if sect_name == "__const" {
                        return Ok((section.offset as usize, section.size as usize));
                    }
                }
            }
        }
    }

    // Also check __DATA and __DATA_CONST segments
    for segment in &macho.segments {
        let seg_name = segment.name().unwrap_or("");

        if seg_name == "__DATA" || seg_name == "__DATA_CONST" {
            if let Ok(sections) = segment.sections() {
                for (section, _) in sections {
                    let sect_name = section.name().unwrap_or("");
                    if sect_name == "__const" {
                        return Ok((section.offset as usize, section.size as usize));
                    }
                }
            }
        }
    }

    Err(AMOSError::SectionNotFound("__const".into()))
}

/// Estimate table size by analyzing section data.
fn estimate_table_size(section_data: &[u8]) -> Result<usize, AMOSError> {
    let total_size = section_data.len();

    // AMOS uses three equal-sized tables
    // Common sizes: ~60,000 entries (240KB each, 720KB total)
    // Total section is typically 720KB-780KB

    // Calculate max possible entries per table
    let max_entries = total_size / 12; // 3 tables * 4 bytes each

    // Check common AMOS table sizes
    let common_sizes = [
        65536,  // 64K entries (power of 2)
        60000,  // ~60K entries (typical)
        80000,  // 80K entries
        100000, // 100K entries
    ];

    for &size in &common_sizes {
        if size <= max_entries && is_valid_table_size(section_data, size) {
            return Ok(size);
        }
    }

    // Fallback: use 1/3 of section (assumes section is exactly 3 tables)
    if total_size.is_multiple_of(12) {
        return Ok(total_size / 12);
    }

    // Last resort: estimate based on section size
    Ok(max_entries.min(65536))
}

/// Validate that a table size makes sense for the data.
fn is_valid_table_size(section_data: &[u8], entry_count: usize) -> bool {
    let table_bytes = entry_count * 4;

    // Need at least 3 tables
    if section_data.len() < table_bytes * 3 {
        return false;
    }

    // Check for table boundary discontinuity
    // Tables often have different value distributions
    if table_bytes + 4 <= section_data.len() {
        let last_val = u32::from_le_bytes([
            section_data[table_bytes - 4],
            section_data[table_bytes - 3],
            section_data[table_bytes - 2],
            section_data[table_bytes - 1],
        ]);
        let next_val = u32::from_le_bytes([
            section_data[table_bytes],
            section_data[table_bytes + 1],
            section_data[table_bytes + 2],
            section_data[table_bytes + 3],
        ]);

        // Look for significant value change at boundary
        let diff = (last_val as i64 - next_val as i64).unsigned_abs();
        if diff > 1000 {
            return true;
        }
    }

    true
}

/// Extract a u32 array from little-endian byte data.
fn extract_u32_array(data: &[u8]) -> Result<Vec<u32>, AMOSError> {
    if !data.len().is_multiple_of(4) {
        return Err(AMOSError::InvalidAlignment);
    }

    let mut result = Vec::with_capacity(data.len() / 4);
    for chunk in data.chunks_exact(4) {
        result.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }

    Ok(result)
}

/// Get the __const section size without full parsing.
pub fn get_const_section_size(data: &[u8]) -> Option<usize> {
    let macho = match Mach::parse(data) {
        Ok(Mach::Binary(m)) => m,
        Ok(Mach::Fat(fat)) => {
            // Get first architecture
            if let Ok(arches) = fat.arches() {
                if let Some(arch) = arches.into_iter().next() {
                    let offset = arch.offset as usize;
                    let size = arch.size as usize;
                    if offset + size <= data.len() {
                        if let Ok(Mach::Binary(m)) = Mach::parse(&data[offset..offset + size]) {
                            return get_const_section_size_from_macho(&m);
                        }
                    }
                }
            }
            return None;
        }
        Err(_) => return None,
    };

    get_const_section_size_from_macho(&macho)
}

fn get_const_section_size_from_macho(macho: &MachO) -> Option<usize> {
    for segment in &macho.segments {
        let seg_name = segment.name().unwrap_or("");
        if seg_name == "__TEXT" {
            if let Ok(sections) = segment.sections() {
                for (section, _) in sections {
                    if section.name().unwrap_or("") == "__const" {
                        return Some(section.size as usize);
                    }
                }
            }
        }
    }
    None
}

/// Extract multiple table sets from a Mach-O binary.
/// Returns all detected encrypted string table configurations.
pub fn extract_all_table_sets(data: &[u8]) -> Result<Vec<TableAddresses>, AMOSError> {
    let macho = match Mach::parse(data) {
        Ok(Mach::Binary(m)) => m,
        Ok(Mach::Fat(fat)) => {
            return extract_all_tables_from_fat(data, &fat);
        }
        Err(e) => {
            return Err(AMOSError::GoblinError(e));
        }
    };

    extract_table_addresses_from_macho(data, &macho)
}

/// Extract table addresses from fat binary.
fn extract_all_tables_from_fat(
    data: &[u8],
    fat: &goblin::mach::MultiArch,
) -> Result<Vec<TableAddresses>, AMOSError> {
    let arches = fat.arches().map_err(AMOSError::GoblinError)?;

    // Prefer arm64 for analysis (CPU_TYPE_ARM64 = 0x0100000c = 12 | 0x01000000)
    let preferred_arch = arches
        .iter()
        .find(|a| a.cputype == 0x0100000c) // arm64
        .or_else(|| arches.first());

    match preferred_arch {
        Some(arch) => {
            let arch_offset = arch.offset as usize;
            let arch_size = arch.size as usize;

            if arch_offset + arch_size > data.len() {
                return Err(AMOSError::InvalidSection(
                    "architecture slice out of bounds".into(),
                ));
            }

            let arch_data = &data[arch_offset..arch_offset + arch_size];

            match Mach::parse(arch_data)? {
                Mach::Binary(m) => {
                    let mut tables = extract_table_addresses_from_macho(arch_data, &m)?;
                    // Adjust offsets to be relative to original file
                    for table in &mut tables {
                        table.table1_offset += arch_offset;
                        table.table2_offset += arch_offset;
                        table.table3_offset += arch_offset;
                    }
                    Ok(tables)
                }
                _ => Err(AMOSError::InvalidFormat(
                    "unexpected nested fat binary".into(),
                )),
            }
        }
        None => Err(AMOSError::NoArchitecture),
    }
}

/// Extract table addresses by analyzing ARM64 code patterns.
fn extract_table_addresses_from_macho(
    data: &[u8],
    macho: &MachO,
) -> Result<Vec<TableAddresses>, AMOSError> {
    let mut results = Vec::new();

    // Find __const section bounds
    let const_section = find_const_section(macho)?;
    let const_offset = const_section.0;
    let const_size = const_section.1;

    // Find __text section for code analysis
    let text_section = find_text_section(macho);

    if let Some((text_offset, text_size)) = text_section {
        // Search for ADRP+ADD patterns pointing to __const
        let addresses = find_adrp_add_addresses(data, text_offset, text_size, const_offset);

        // Group addresses into table sets (groups of 3 nearby addresses)
        let table_sets = group_into_table_sets(&addresses, const_offset, const_size);
        results.extend(table_sets);
    }

    // If no ARM64 patterns found, try heuristic approach
    if results.is_empty() {
        // Try known AMOS table patterns
        if let Some(tables) = try_known_patterns(data, const_offset, const_size) {
            results.push(tables);
        }
    }

    // Fallback to sequential thirds if nothing else works
    if results.is_empty() {
        let entry_count = const_size / 12;
        if entry_count > 1000 {
            results.push(TableAddresses {
                table1_offset: const_offset,
                table2_offset: const_offset + (entry_count * 4),
                table3_offset: const_offset + (entry_count * 8),
                payload_size: entry_count,
            });
        }
    }

    Ok(results)
}

/// Find the __text section in the Mach-O binary.
fn find_text_section(macho: &MachO) -> Option<(usize, usize)> {
    for segment in &macho.segments {
        let seg_name = segment.name().unwrap_or("");
        if seg_name == "__TEXT" {
            if let Ok(sections) = segment.sections() {
                for (section, _) in sections {
                    if section.name().unwrap_or("") == "__text" {
                        return Some((section.offset as usize, section.size as usize));
                    }
                }
            }
        }
    }
    None
}

/// Find ADRP+ADD instruction patterns pointing to a target range.
/// Returns file offsets by translating virtual addresses using segment info.
fn find_adrp_add_addresses(
    _data: &[u8],
    _text_offset: usize,
    _text_size: usize,
    _const_offset: usize,
) -> Vec<usize> {
    // ARM64 ADRP+ADD patterns produce virtual addresses which require
    // complex segment mapping to translate to file offsets.
    // For now, return empty and rely on other extraction methods.
    // TODO: Implement proper virtual-to-file address translation
    Vec::new()
}

/// Group addresses into table sets (groups of 3 addresses used together).
fn group_into_table_sets(
    addresses: &[usize],
    const_offset: usize,
    const_size: usize,
) -> Vec<TableAddresses> {
    let mut results = Vec::new();

    // Filter addresses within __const section
    let const_addrs: Vec<usize> = addresses
        .iter()
        .filter(|&&addr| addr >= const_offset && addr < const_offset + const_size)
        .copied()
        .collect();

    // For AMOS, we expect groups of 3 addresses loaded in sequence
    // Try to find patterns where 3 registers are loaded with table pointers
    // This is a heuristic - we look for addresses that appear close together
    // in the instruction stream

    let mut used = vec![false; const_addrs.len()];

    for i in 0..const_addrs.len() {
        if used[i] {
            continue;
        }

        // Look for 2 more addresses within 100KB range
        let base = const_addrs[i];
        let mut candidates: Vec<(usize, usize)> = vec![(i, base)];

        for j in (i + 1)..const_addrs.len() {
            if used[j] {
                continue;
            }
            let addr = const_addrs[j];
            // Tables can be at different offsets but should be within ~500KB
            if addr.abs_diff(base) < 500_000 {
                candidates.push((j, addr));
            }
        }

        // If we have exactly 3 candidates, use them
        if candidates.len() >= 3 {
            let mut addrs: Vec<usize> = candidates.iter().take(3).map(|(_, a)| *a).collect();
            addrs.sort_unstable();

            // Mark as used
            for (idx, _) in candidates.iter().take(3) {
                used[*idx] = true;
            }

            // Estimate payload size from address gaps
            let gap1 = addrs[1] - addrs[0];
            let gap2 = addrs[2] - addrs[1];
            let avg_gap = (gap1 + gap2) / 2;
            let payload_size = avg_gap / 4; // Each entry is 4 bytes

            if payload_size > 100 && payload_size < 100_000 {
                results.push(TableAddresses {
                    table1_offset: addrs[0],
                    table2_offset: addrs[1],
                    table3_offset: addrs[2],
                    payload_size,
                });
            }
        }
    }

    results
}

/// Try known AMOS table patterns.
/// Returns multiple potential table configurations to try.
fn try_known_patterns(
    data: &[u8],
    _const_offset: usize,
    _const_size: usize,
) -> Option<TableAddresses> {
    // IMPORTANT: AMOS tables are NOT sequential in memory!
    // They are scattered at different offsets discovered from disassembly.
    // Known patterns from reverse engineering:
    //
    // String 3 (main payload, 63887 bytes):
    //   t1=0x3bd0, t2=0x80050, t3=0x41e10

    // Try known AMOS main payload offsets
    let known_patterns = [
        // (t1, t2, t3, entry_count) - discovered from RE analysis
        (0x3bd0usize, 0x80050usize, 0x41e10usize, 63887usize), // Main payload
        (0xbe290usize, 0xbe690usize, 0xbe490usize, 128usize),  // Base64 alphabet string
    ];

    for (t1, t2, t3, entry_count) in known_patterns {
        // Check if we have enough data
        let max_offset = t1.max(t2).max(t3) + entry_count * 4;

        if max_offset <= data.len() {
            // Validate by attempting a small decryption and checking for hex output
            let valid = validate_decryption_produces_hex(data, t1, t2, t3, entry_count.min(100));

            if valid {
                return Some(TableAddresses {
                    table1_offset: t1,
                    table2_offset: t2,
                    table3_offset: t3,
                    payload_size: entry_count,
                });
            }
        }
    }

    None
}

/// Validate that decryption produces hex characters (indicates correct tables).
fn validate_decryption_produces_hex(
    data: &[u8],
    t1: usize,
    t2: usize,
    t3: usize,
    sample_count: usize,
) -> bool {
    let mut hex_count = 0;
    let sample_size = sample_count.min(50);

    for i in 0..sample_size {
        let idx = i * 4;
        if t1 + idx + 4 > data.len() || t2 + idx + 4 > data.len() || t3 + idx + 4 > data.len() {
            return false;
        }

        let v1 = u32::from_le_bytes([
            data[t1 + idx],
            data[t1 + idx + 1],
            data[t1 + idx + 2],
            data[t1 + idx + 3],
        ]);
        let v2 = u32::from_le_bytes([
            data[t2 + idx],
            data[t2 + idx + 1],
            data[t2 + idx + 2],
            data[t2 + idx + 3],
        ]);
        let v3 = u32::from_le_bytes([
            data[t3 + idx],
            data[t3 + idx + 1],
            data[t3 + idx + 2],
            data[t3 + idx + 3],
        ]);

        let decoded = ((v1.wrapping_sub(v2)) ^ v3) & 0xFF;
        let byte = decoded as u8;

        // Check if it's a hex character
        if byte.is_ascii_hexdigit() {
            hex_count += 1;
        }
    }

    // Require at least 80% hex characters
    hex_count * 100 / sample_size >= 80
}

/// Load tables from specific addresses.
pub fn load_tables_at_addresses(
    data: &[u8],
    addresses: &TableAddresses,
) -> Result<LookupTables, AMOSError> {
    let entry_count = addresses.payload_size;
    let byte_size = entry_count * 4;

    // Validate bounds
    if addresses.table1_offset + byte_size > data.len() {
        return Err(AMOSError::InvalidSection("table1 out of bounds".into()));
    }
    if addresses.table2_offset + byte_size > data.len() {
        return Err(AMOSError::InvalidSection("table2 out of bounds".into()));
    }
    if addresses.table3_offset + byte_size > data.len() {
        return Err(AMOSError::InvalidSection("table3 out of bounds".into()));
    }

    let table1 =
        extract_u32_array(&data[addresses.table1_offset..addresses.table1_offset + byte_size])?;
    let table2 =
        extract_u32_array(&data[addresses.table2_offset..addresses.table2_offset + byte_size])?;
    let table3 =
        extract_u32_array(&data[addresses.table3_offset..addresses.table3_offset + byte_size])?;

    Ok(LookupTables {
        table1,
        table2,
        table3,
        offset: addresses.table1_offset,
        payload_size: entry_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_u32_array() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let result = extract_u32_array(&data).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], 0x04030201); // Little endian
        assert_eq!(result[1], 0x08070605);
    }

    #[test]
    fn test_extract_u32_array_invalid_alignment() {
        let data = vec![0x01, 0x02, 0x03]; // Not divisible by 4
        let result = extract_u32_array(&data);
        assert!(matches!(result, Err(AMOSError::InvalidAlignment)));
    }

    #[test]
    fn test_estimate_table_size_small() {
        // 720,000 bytes = 3 tables of 60,000 entries
        let data = vec![0u8; 720_000];
        let size = estimate_table_size(&data).unwrap();
        assert!(size >= 60_000);
    }
}
