//! Go string extraction.
//!
//! Go strings are represented as `{ptr: *byte, len: int}` structures (16 bytes on 64-bit).
//! The string data is typically stored in `.rodata` (ELF) or `__rodata` (Mach-O) sections,
//! while the pointer+length structures are scattered throughout data sections.
//!
//! For inline literals (function arguments, map keys/values), we also perform
//! instruction pattern analysis to extract strings that don't have stored structures.

use super::common::{
    extract_from_structures, find_string_structures, BinaryInfo, ExtractedString, StringMethod,
};
use super::instr::{extract_inline_strings_amd64, extract_inline_strings_arm64};
use goblin::elf::Elf;
use goblin::mach::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};
use goblin::mach::MachO;
use goblin::pe::PE;
use std::collections::HashSet;

/// Extracts strings from Go binaries using structure analysis.
pub struct GoStringExtractor {
    min_length: usize,
}

impl GoStringExtractor {
    pub fn new(min_length: usize) -> Self {
        Self { min_length }
    }

    /// Extract strings from a Mach-O binary.
    pub fn extract_macho(&self, macho: &MachO, _data: &[u8]) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        // Mach-O is always little-endian on modern systems (x86_64, ARM64)
        let info = BinaryInfo::from_macho(macho.is_64);

        // Find __rodata section in __TEXT segment (contains string data)
        let mut rodata_info: Option<(u64, &[u8])> = None;
        let mut text_info: Option<(u64, &[u8])> = None;

        for seg in &macho.segments {
            let seg_name = seg.name().unwrap_or("");
            if seg_name == "__TEXT" {
                if let Ok(sections) = seg.sections() {
                    for (section, section_data) in sections {
                        let name = section.name().unwrap_or("");
                        if name == "__rodata" {
                            rodata_info = Some((section.addr, section_data));
                        }
                        if name == "__text" {
                            text_info = Some((section.addr, section_data));
                        }
                    }
                }
            }
        }

        let Some((rodata_addr, rodata_data)) = rodata_info else {
            return strings;
        };

        // Search all sections for string structures pointing into __rodata
        let mut all_structs = Vec::new();

        for seg in &macho.segments {
            if let Ok(sections) = seg.sections() {
                for (section, section_data) in sections {
                    let structs = find_string_structures(
                        section_data,
                        section.addr,
                        rodata_addr,
                        rodata_data.len() as u64,
                        &info,
                    );
                    all_structs.extend(structs);
                }
            }
        }

        // Extract strings using structure boundaries
        let structured = extract_from_structures(
            rodata_data,
            rodata_addr,
            &all_structs,
            Some("__rodata".to_string()),
        );

        // Filter by minimum length
        for s in structured {
            if s.value.len() >= self.min_length {
                strings.push(s);
            }
        }

        // Perform instruction pattern analysis for inline literals
        if let Some((text_addr, text_data)) = text_info {
            let inline_strings = match macho.header.cputype() {
                CPU_TYPE_ARM64 => extract_inline_strings_arm64(
                    text_data,
                    text_addr,
                    rodata_data,
                    rodata_addr,
                    self.min_length,
                ),
                CPU_TYPE_X86_64 => extract_inline_strings_amd64(
                    text_data,
                    text_addr,
                    rodata_data,
                    rodata_addr,
                    self.min_length,
                ),
                _ => Vec::new(),
            };

            // Deduplicate against already found strings
            let existing: HashSet<String> = strings.iter().map(|s| s.value.clone()).collect();
            for s in inline_strings {
                if !existing.contains(&s.value) {
                    strings.push(s);
                }
            }
        }

        // Also extract from __gopclntab (function/file names)
        for seg in &macho.segments {
            if let Ok(sections) = seg.sections() {
                for (section, section_data) in sections {
                    let name = section.name().unwrap_or("");
                    if name == "__gopclntab" {
                        let gopclntab_strings =
                            self.extract_raw_strings(section_data, Some(name.to_string()));
                        strings.extend(gopclntab_strings);
                    }
                }
            }
        }

        strings
    }

    /// Extract strings from an ELF binary.
    pub fn extract_elf(&self, elf: &Elf, data: &[u8]) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        // Use actual endianness from ELF header
        let info = BinaryInfo::from_elf(elf.is_64, elf.little_endian);

        // Find .rodata and .text sections
        let mut rodata_info: Option<(u64, usize, usize)> = None;
        let mut text_info: Option<(u64, usize, usize)> = None;

        for sh in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if name == ".rodata" {
                rodata_info = Some((sh.sh_addr, sh.sh_offset as usize, sh.sh_size as usize));
            }
            if name == ".text" {
                text_info = Some((sh.sh_addr, sh.sh_offset as usize, sh.sh_size as usize));
            }
        }

        let Some((rodata_addr, rodata_offset, rodata_size)) = rodata_info else {
            return strings;
        };

        if rodata_offset + rodata_size > data.len() {
            return strings;
        }

        let rodata_data = &data[rodata_offset..rodata_offset + rodata_size];

        // Search all sections for string structures
        let mut all_structs = Vec::new();

        for sh in &elf.section_headers {
            if sh.sh_type == goblin::elf::section_header::SHT_NOBITS || sh.sh_size == 0 {
                continue;
            }

            let offset = sh.sh_offset as usize;
            let size = sh.sh_size as usize;

            if offset + size > data.len() {
                continue;
            }

            let section_data = &data[offset..offset + size];
            let structs = find_string_structures(
                section_data,
                sh.sh_addr,
                rodata_addr,
                rodata_size as u64,
                &info,
            );
            all_structs.extend(structs);
        }

        // Extract strings using structure boundaries
        let structured = extract_from_structures(
            rodata_data,
            rodata_addr,
            &all_structs,
            Some(".rodata".to_string()),
        );

        for s in structured {
            if s.value.len() >= self.min_length {
                strings.push(s);
            }
        }

        // Perform instruction pattern analysis for inline literals
        if let Some((text_addr, text_offset, text_size)) = text_info {
            if text_offset + text_size <= data.len() {
                let text_data = &data[text_offset..text_offset + text_size];

                // Determine architecture from ELF machine type
                let inline_strings = match elf.header.e_machine {
                    goblin::elf::header::EM_X86_64 => extract_inline_strings_amd64(
                        text_data,
                        text_addr,
                        rodata_data,
                        rodata_addr,
                        self.min_length,
                    ),
                    goblin::elf::header::EM_AARCH64 => extract_inline_strings_arm64(
                        text_data,
                        text_addr,
                        rodata_data,
                        rodata_addr,
                        self.min_length,
                    ),
                    _ => Vec::new(),
                };

                // Deduplicate against already found strings
                let existing: HashSet<String> = strings.iter().map(|s| s.value.clone()).collect();
                for s in inline_strings {
                    if !existing.contains(&s.value) {
                        strings.push(s);
                    }
                }
            }
        }

        // Also extract from .gopclntab
        for sh in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if name == ".gopclntab" {
                let offset = sh.sh_offset as usize;
                let size = sh.sh_size as usize;

                if offset + size <= data.len() {
                    let section_data = &data[offset..offset + size];
                    let gopclntab_strings =
                        self.extract_raw_strings(section_data, Some(name.to_string()));
                    strings.extend(gopclntab_strings);
                }
            }
        }

        strings
    }

    /// Extract strings from a PE binary.
    pub fn extract_pe(&self, pe: &PE, data: &[u8]) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        // PE is always little-endian
        let info = BinaryInfo::from_pe(pe.is_64);

        // Find .rdata section (contains string data in PE Go binaries)
        let mut rdata_info: Option<(u64, usize, usize)> = None;

        for section in &pe.sections {
            let name = String::from_utf8_lossy(&section.name);
            let name = name.trim_end_matches('\0');
            if name == ".rdata" {
                let base = pe
                    .header
                    .optional_header
                    .map(|h| h.windows_fields.image_base)
                    .unwrap_or(0);
                rdata_info = Some((
                    base + section.virtual_address as u64,
                    section.pointer_to_raw_data as usize,
                    section.size_of_raw_data as usize,
                ));
                break;
            }
        }

        let Some((rdata_addr, rdata_offset, rdata_size)) = rdata_info else {
            return strings;
        };

        if rdata_offset + rdata_size > data.len() {
            return strings;
        }

        let rdata_data = &data[rdata_offset..rdata_offset + rdata_size];

        // Search all sections for string structures
        let mut all_structs = Vec::new();

        for section in &pe.sections {
            let offset = section.pointer_to_raw_data as usize;
            let size = section.size_of_raw_data as usize;

            if offset + size > data.len() {
                continue;
            }

            let base = pe
                .header
                .optional_header
                .map(|h| h.windows_fields.image_base)
                .unwrap_or(0);

            let section_data = &data[offset..offset + size];
            let section_addr = base + section.virtual_address as u64;

            let structs = find_string_structures(
                section_data,
                section_addr,
                rdata_addr,
                rdata_size as u64,
                &info,
            );
            all_structs.extend(structs);
        }

        // Extract strings using structure boundaries
        let structured = extract_from_structures(
            rdata_data,
            rdata_addr,
            &all_structs,
            Some(".rdata".to_string()),
        );

        for s in structured {
            if s.value.len() >= self.min_length {
                strings.push(s);
            }
        }

        strings
    }

    /// Extract raw strings (null-terminated fallback) from a section.
    fn extract_raw_strings(
        &self,
        data: &[u8],
        section_name: Option<String>,
    ) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut current = Vec::new();
        let mut start_offset = 0usize;

        for (i, &byte) in data.iter().enumerate() {
            if byte == 0 {
                if current.len() >= self.min_length {
                    if let Ok(s) = std::str::from_utf8(&current) {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() && !seen.contains(trimmed) {
                            seen.insert(trimmed.to_string());
                            strings.push(ExtractedString {
                                value: trimmed.to_string(),
                                data_offset: start_offset as u64,
                                section: section_name.clone(),
                                method: StringMethod::RawScan,
                            });
                        }
                    }
                }
                current.clear();
            } else if byte.is_ascii_graphic() || byte.is_ascii_whitespace() {
                if current.is_empty() {
                    start_offset = i;
                }
                current.push(byte);
            } else {
                current.clear();
            }
        }

        strings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang_strings::common::StringStruct;

    #[test]
    fn test_find_string_structures() {
        let info = BinaryInfo::new_64bit_le();

        // Create test data with a string structure
        // ptr = 0x1000, len = 5
        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        section_data[8..16].copy_from_slice(&5u64.to_le_bytes());

        let structs = find_string_structures(
            &section_data,
            0x2000, // section_addr
            0x1000, // blob_addr
            0x100,  // blob_size
            &info,
        );

        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].ptr, 0x1000);
        assert_eq!(structs[0].len, 5);
    }

    #[test]
    fn test_extract_from_structures() {
        let blob = b"HelloWorld";
        let structs = vec![
            StringStruct {
                struct_offset: 0,
                ptr: 0x1000,
                len: 5,
            },
            StringStruct {
                struct_offset: 16,
                ptr: 0x1005,
                len: 5,
            },
        ];

        let strings = extract_from_structures(blob, 0x1000, &structs, Some("test".to_string()));

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].value, "Hello");
        assert_eq!(strings[1].value, "World");
    }
}
