//! Rust string extraction.
//!
//! Rust strings use similar fat pointer representations:
//! - `&str`: `{ptr: *u8, len: usize}` (16 bytes on 64-bit)
//! - `String`: `{ptr: *u8, len: usize, cap: usize}` (24 bytes on 64-bit)
//!
//! Rust binaries are harder to analyze than Go because:
//! 1. No dedicated sections like .gopclntab
//! 2. More aggressive inlining and optimization
//! 3. String data may be in .rodata or .data.rel.ro
//!
//! For inline literals, we also perform instruction pattern analysis.

use super::common::{
    extract_from_structures, find_string_structures, BinaryInfo, ExtractedString, StringMethod,
};
use super::instr::{extract_inline_strings_amd64, extract_inline_strings_arm64};
use goblin::elf::Elf;
use goblin::mach::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};
use goblin::mach::MachO;
use regex::Regex;
use std::collections::HashSet;

/// Extracts strings from Rust binaries using structure analysis.
pub struct RustStringExtractor {
    min_length: usize,
}

impl RustStringExtractor {
    pub fn new(min_length: usize) -> Self {
        Self { min_length }
    }

    /// Extract strings from a Mach-O binary.
    ///
    /// Rust Mach-O binaries typically store strings in:
    /// - `__cstring` in `__TEXT` segment (null-terminated C strings)
    /// - `__const` in `__TEXT` segment (constants, often packed)
    /// - `__const` in `__DATA_CONST` segment (ptr+len structures)
    ///
    /// Rust stores &str slice structures (ptr+len) in `__DATA_CONST`,
    /// while the actual string data is in `__TEXT,__const` or `__cstring`.
    pub fn extract_macho(&self, macho: &MachO, _data: &[u8]) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        let info = BinaryInfo::from_macho(macho.is_64);

        // Collect sections by type
        let mut cstring_info: Option<(u64, &[u8])> = None;
        let mut text_const_info: Option<(u64, &[u8])> = None;
        let mut data_const_info: Option<(u64, &[u8])> = None;
        let mut text_info: Option<(u64, &[u8])> = None;

        for seg in &macho.segments {
            let seg_name = seg.name().unwrap_or("");
            if let Ok(sections) = seg.sections() {
                for (section, section_data) in sections {
                    let name = section.name().unwrap_or("");
                    match (seg_name, name) {
                        ("__TEXT", "__cstring") => {
                            cstring_info = Some((section.addr, section_data))
                        }
                        ("__TEXT", "__const") => {
                            text_const_info = Some((section.addr, section_data))
                        }
                        ("__DATA_CONST", "__const") => {
                            data_const_info = Some((section.addr, section_data))
                        }
                        ("__TEXT", "__text") => text_info = Some((section.addr, section_data)),
                        _ => {}
                    }
                }
            }
        }

        // PHASE 1: Extract from __DATA_CONST structures pointing to string sections
        // This is the primary method for Rust - it stores &str slices here
        if let Some((data_const_addr, data_const_data)) = data_const_info {
            // Target sections to look for pointers to
            let targets: Vec<(u64, &[u8], &str)> = [
                cstring_info.map(|(a, d)| (a, d, "__cstring")),
                text_const_info.map(|(a, d)| (a, d, "__TEXT,__const")),
            ]
            .into_iter()
            .flatten()
            .collect();

            for (target_addr, target_data, section_name) in targets {
                let structs = find_string_structures(
                    data_const_data,
                    data_const_addr,
                    target_addr,
                    target_data.len() as u64,
                    &info,
                );

                let structured = extract_from_structures(
                    target_data,
                    target_addr,
                    &structs,
                    Some(section_name.to_string()),
                );

                let existing: HashSet<String> = strings
                    .iter()
                    .map(|s: &ExtractedString| s.value.clone())
                    .collect();
                for s in structured {
                    if s.value.len() >= self.min_length && !existing.contains(&s.value) {
                        strings.push(s);
                    }
                }
            }
        }

        // PHASE 2: Raw extraction from __cstring (null-terminated strings)
        if let Some((_, cstring_data)) = cstring_info {
            let raw = self.extract_raw_strings(cstring_data, Some("__cstring".to_string()));
            let existing: HashSet<String> = strings
                .iter()
                .map(|s: &ExtractedString| s.value.clone())
                .collect();
            for s in raw {
                if s.value.len() >= self.min_length && !existing.contains(&s.value) {
                    strings.push(s);
                }
            }
        }

        // PHASE 3: Heuristic extraction from __TEXT,__const for packed strings
        // Rust often packs format strings without structures
        if let Some((text_const_addr, text_const_data)) = text_const_info {
            let heuristic =
                self.extract_packed_strings(text_const_data, Some("__TEXT,__const".to_string()));
            let existing: HashSet<String> = strings
                .iter()
                .map(|s: &ExtractedString| s.value.clone())
                .collect();
            for s in heuristic {
                if s.value.len() >= self.min_length && !existing.contains(&s.value) {
                    strings.push(ExtractedString {
                        value: s.value,
                        data_offset: text_const_addr + s.data_offset,
                        section: s.section,
                        method: StringMethod::Heuristic,
                    });
                }
            }
        }

        // PHASE 4: Instruction pattern analysis
        if let Some((text_addr, text_data)) = text_info {
            let targets: Vec<(u64, &[u8], &str)> = [
                cstring_info.map(|(a, d)| (a, d, "__cstring")),
                text_const_info.map(|(a, d)| (a, d, "__TEXT,__const")),
            ]
            .into_iter()
            .flatten()
            .collect();

            for (section_addr, section_data, section_name) in targets {
                let inline_strings = match macho.header.cputype() {
                    CPU_TYPE_ARM64 => extract_inline_strings_arm64(
                        text_data,
                        text_addr,
                        section_data,
                        section_addr,
                        self.min_length,
                    ),
                    CPU_TYPE_X86_64 => extract_inline_strings_amd64(
                        text_data,
                        text_addr,
                        section_data,
                        section_addr,
                        self.min_length,
                    ),
                    _ => Vec::new(),
                };

                let existing: HashSet<String> = strings
                    .iter()
                    .map(|s: &ExtractedString| s.value.clone())
                    .collect();
                for mut s in inline_strings {
                    if !existing.contains(&s.value) {
                        s.section = Some(section_name.to_string());
                        strings.push(s);
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

        // Rust uses multiple sections for string data
        let string_sections = [".rodata", ".data.rel.ro", ".data.rel.ro.local"];

        for section_name in &string_sections {
            if let Some(extracted) = self.extract_from_section(elf, data, section_name, &info) {
                strings.extend(extracted);
            }
        }

        // Perform instruction pattern analysis for inline literals
        let text_info = self.find_section(elf, data, ".text");
        let rodata_info = self.find_section(elf, data, ".rodata");

        if let (Some((text_addr, text_data)), Some((rodata_addr, rodata_data))) =
            (text_info, rodata_info)
        {
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

            strings.extend(inline_strings);
        }

        // Deduplicate
        let mut seen: HashSet<String> = HashSet::new();
        strings.retain(|s| {
            if seen.contains(&s.value) {
                false
            } else {
                seen.insert(s.value.clone());
                true
            }
        });

        strings
    }

    /// Helper to find a section by name and return its address and data.
    fn find_section<'a>(
        &self,
        elf: &Elf,
        data: &'a [u8],
        section_name: &str,
    ) -> Option<(u64, &'a [u8])> {
        for sh in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if name == section_name {
                let offset = sh.sh_offset as usize;
                let size = sh.sh_size as usize;
                if offset + size <= data.len() {
                    return Some((sh.sh_addr, &data[offset..offset + size]));
                }
            }
        }
        None
    }

    fn extract_from_section(
        &self,
        elf: &Elf,
        data: &[u8],
        target_section: &str,
        info: &BinaryInfo,
    ) -> Option<Vec<ExtractedString>> {
        // Find the target section
        let mut section_info: Option<(u64, usize, usize)> = None;

        for sh in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            if name == target_section {
                section_info = Some((sh.sh_addr, sh.sh_offset as usize, sh.sh_size as usize));
                break;
            }
        }

        let (section_addr, section_offset, section_size) = section_info?;

        if section_offset + section_size > data.len() {
            return None;
        }

        let section_data = &data[section_offset..section_offset + section_size];

        // Search all sections for string structures pointing into this section
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

            let search_data = &data[offset..offset + size];
            let structs = find_string_structures(
                search_data,
                sh.sh_addr,
                section_addr,
                section_size as u64,
                info,
            );
            all_structs.extend(structs);
        }

        if all_structs.is_empty() {
            return None;
        }

        // Extract strings using structure boundaries
        let mut extracted = extract_from_structures(
            section_data,
            section_addr,
            &all_structs,
            Some(target_section.to_string()),
        );

        // Filter by minimum length
        extracted.retain(|s| s.value.len() >= self.min_length);

        Some(extracted)
    }

    /// Extract raw strings as fallback.
    #[allow(dead_code)]
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

    /// Extract strings from packed data using heuristic pattern matching.
    ///
    /// Rust often packs format strings and literals together without null
    /// terminators or pointer structures. This method uses pattern recognition
    /// to split and extract meaningful strings.
    fn extract_packed_strings(
        &self,
        data: &[u8],
        section_name: Option<String>,
    ) -> Vec<ExtractedString> {
        let mut strings = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        // Convert bytes to text, marking non-printable bytes
        let mut text = String::with_capacity(data.len());
        for &b in data {
            if (32..127).contains(&b) {
                text.push(b as char);
            } else if b == 10 {
                // Newline is a real delimiter
                text.push('\n');
            } else if b == 0 {
                text.push('\0');
            } else {
                // Non-printable marker
                text.push('\x01');
            }
        }

        // Split on nulls and non-printables first
        for segment in text.split(|c| c == '\0' || c == '\x01') {
            if segment.len() < self.min_length {
                continue;
            }

            // Extract patterns from each segment
            self.extract_patterns_from_segment(segment, &section_name, &mut strings, &mut seen);
        }

        strings
    }

    /// Extract recognizable patterns from a text segment.
    fn extract_patterns_from_segment(
        &self,
        segment: &str,
        section_name: &Option<String>,
        strings: &mut Vec<ExtractedString>,
        seen: &mut HashSet<String>,
    ) {
        // Pattern 1: URLs (highest priority, clear boundaries)
        for cap in
            Regex::new(r"(https?|ftp|postgresql|mysql|redis|mongodb)://[a-zA-Z0-9._:/@\-?=&%]+")
                .unwrap()
                .find_iter(segment)
        {
            let url = cap
                .as_str()
                .trim_end_matches(|c| c == '.' || c == ',' || c == ';');
            self.add_if_valid(url, section_name, strings, seen);
        }

        // Pattern 2: Unix file paths
        for cap in Regex::new(r"/[a-zA-Z0-9_./\-]+")
            .unwrap()
            .find_iter(segment)
        {
            let path = cap.as_str();
            if path.contains('/') && path.len() >= self.min_length {
                self.add_if_valid(path, section_name, strings, seen);
            }
        }

        // Pattern 3: Environment variable names (UPPER_CASE_WITH_UNDERSCORES)
        for cap in Regex::new(r"[A-Z][A-Z0-9_]{3,}")
            .unwrap()
            .find_iter(segment)
        {
            let env_var = cap.as_str();
            if env_var.contains('_') && env_var.len() >= self.min_length {
                self.add_if_valid(env_var, section_name, strings, seen);
            }
        }

        // Pattern 4: snake_case identifiers
        for cap in Regex::new(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+")
            .unwrap()
            .find_iter(segment)
        {
            let ident = cap.as_str();
            if ident.len() >= self.min_length {
                self.add_if_valid(ident, section_name, strings, seen);
            }
        }

        // Pattern 5: Domain names
        for cap in Regex::new(r"[a-z][a-z0-9]*\.[a-z][a-z0-9.]+")
            .unwrap()
            .find_iter(segment)
        {
            let domain = cap.as_str();
            if domain.len() >= self.min_length {
                self.add_if_valid(domain, section_name, strings, seen);
            }
        }

        // Pattern 6: Split on boundary patterns and extract remaining identifiers
        // Split before UPPER_CASE sequences of 4+ chars
        let parts: Vec<&str> = segment
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.' && c != '-')
            .filter(|s| s.len() >= self.min_length)
            .collect();

        for part in parts {
            // Split on case transitions: lowercase followed by 4+ uppercase
            let mut last_idx = 0;
            let chars: Vec<char> = part.chars().collect();
            for i in 1..chars.len().saturating_sub(3) {
                if chars[i - 1].is_ascii_lowercase()
                    && chars[i].is_ascii_uppercase()
                    && chars.get(i + 1).is_some_and(|c| c.is_ascii_uppercase())
                    && chars.get(i + 2).is_some_and(|c| c.is_ascii_uppercase())
                {
                    let sub: String = chars[last_idx..i].iter().collect();
                    if sub.len() >= self.min_length {
                        self.add_if_valid(&sub, section_name, strings, seen);
                    }
                    last_idx = i;
                }
            }
            // Add remaining part
            if last_idx < chars.len() {
                let sub: String = chars[last_idx..].iter().collect();
                if sub.len() >= self.min_length {
                    self.add_if_valid(&sub, section_name, strings, seen);
                }
            }
        }
    }

    /// Add a string if it passes validation.
    fn add_if_valid(
        &self,
        s: &str,
        section_name: &Option<String>,
        strings: &mut Vec<ExtractedString>,
        seen: &mut HashSet<String>,
    ) {
        let trimmed = s.trim();
        if trimmed.len() < self.min_length {
            return;
        }
        if seen.contains(trimmed) {
            return;
        }
        // Skip if mostly digits
        let digit_count = trimmed.chars().filter(|c| c.is_ascii_digit()).count();
        if digit_count > trimmed.len() * 7 / 10 {
            return;
        }
        // Skip if looks like hex
        if trimmed.len() <= 16
            && trimmed
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == 'x' || c == 'X')
        {
            return;
        }

        seen.insert(trimmed.to_string());
        strings.push(ExtractedString {
            value: trimmed.to_string(),
            data_offset: 0, // Will be adjusted by caller
            section: section_name.clone(),
            method: StringMethod::Heuristic,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_extractor_creation() {
        let extractor = RustStringExtractor::new(4);
        assert_eq!(extractor.min_length, 4);
    }

    #[test]
    fn test_raw_string_extraction() {
        let extractor = RustStringExtractor::new(4);
        let data = b"Hello\0World\0foo\0";

        let strings = extractor.extract_raw_strings(data, Some(".rodata".to_string()));

        assert_eq!(strings.len(), 2); // "Hello" and "World", "foo" is < 4 chars
        assert!(strings.iter().any(|s| s.value == "Hello"));
        assert!(strings.iter().any(|s| s.value == "World"));
    }

    #[test]
    fn test_raw_string_deduplication() {
        let extractor = RustStringExtractor::new(4);
        let data = b"Hello\0Hello\0World\0";

        let strings = extractor.extract_raw_strings(data, None);

        // Should deduplicate
        assert_eq!(strings.iter().filter(|s| s.value == "Hello").count(), 1);
    }

    #[test]
    fn test_raw_string_min_length() {
        let extractor = RustStringExtractor::new(6);
        let data = b"Hello\0World\0";

        let strings = extractor.extract_raw_strings(data, None);

        // "Hello" is 5 chars, "World" is 5 chars - both < 6
        assert!(strings.is_empty());
    }
}
