//! Common types and utilities for language-aware string extraction.

use std::collections::HashSet;

/// Represents a string structure found in binary (pointer + length pair).
#[derive(Debug, Clone)]
pub struct StringStruct {
    /// Offset in the section where this structure was found
    pub struct_offset: u64,
    /// Virtual address of the string data
    pub ptr: u64,
    /// Length of the string
    pub len: u64,
}

/// An extracted string with metadata.
#[derive(Debug, Clone)]
pub struct ExtractedString {
    /// The string value
    pub value: String,
    /// Offset in the binary where the string data is located
    pub data_offset: u64,
    /// Section name where the string was found
    pub section: Option<String>,
    /// How the string was found
    pub method: StringMethod,
}

/// Method used to extract the string.
#[derive(Debug, Clone, PartialEq)]
pub enum StringMethod {
    /// Found via pointer+length structure analysis
    Structure,
    /// Found via instruction pattern analysis (inline literals)
    InstructionPattern,
    /// Found via traditional null-terminated/ASCII scan (fallback)
    RawScan,
    /// Found via heuristic pattern matching (Rust packed strings)
    Heuristic,
}

/// Binary information needed for string extraction.
#[derive(Debug)]
pub struct BinaryInfo {
    pub is_64bit: bool,
    pub is_little_endian: bool,
    pub ptr_size: usize,
}

impl BinaryInfo {
    pub fn new_64bit_le() -> Self {
        Self {
            is_64bit: true,
            is_little_endian: true,
            ptr_size: 8,
        }
    }

    pub fn new_32bit_le() -> Self {
        Self {
            is_64bit: false,
            is_little_endian: true,
            ptr_size: 4,
        }
    }

    pub fn new_64bit_be() -> Self {
        Self {
            is_64bit: true,
            is_little_endian: false,
            ptr_size: 8,
        }
    }

    pub fn new_32bit_be() -> Self {
        Self {
            is_64bit: false,
            is_little_endian: false,
            ptr_size: 4,
        }
    }

    /// Create BinaryInfo from ELF header information
    pub fn from_elf(is_64bit: bool, is_little_endian: bool) -> Self {
        Self {
            is_64bit,
            is_little_endian,
            ptr_size: if is_64bit { 8 } else { 4 },
        }
    }

    /// Create BinaryInfo from Mach-O (always little-endian on modern systems)
    pub fn from_macho(is_64bit: bool) -> Self {
        Self {
            is_64bit,
            is_little_endian: true, // All modern Mach-O is LE
            ptr_size: if is_64bit { 8 } else { 4 },
        }
    }

    /// Create BinaryInfo from PE (always little-endian)
    pub fn from_pe(is_64bit: bool) -> Self {
        Self {
            is_64bit,
            is_little_endian: true, // PE is always LE
            ptr_size: if is_64bit { 8 } else { 4 },
        }
    }
}

/// Find pointer+length structures that point into a data blob.
///
/// This scans section data looking for consecutive pointer+length pairs
/// where the pointer falls within the target blob's address range.
pub fn find_string_structures(
    section_data: &[u8],
    section_addr: u64,
    blob_addr: u64,
    blob_size: u64,
    info: &BinaryInfo,
) -> Vec<StringStruct> {
    let mut structs = Vec::new();
    let struct_size = info.ptr_size * 2;

    if section_data.len() < struct_size {
        return structs;
    }

    for i in (0..=section_data.len() - struct_size).step_by(info.ptr_size) {
        let (ptr, len) = if info.is_64bit {
            if info.is_little_endian {
                let ptr = u64::from_le_bytes(section_data[i..i + 8].try_into().unwrap());
                let len = u64::from_le_bytes(section_data[i + 8..i + 16].try_into().unwrap());
                (ptr, len)
            } else {
                let ptr = u64::from_be_bytes(section_data[i..i + 8].try_into().unwrap());
                let len = u64::from_be_bytes(section_data[i + 8..i + 16].try_into().unwrap());
                (ptr, len)
            }
        } else if info.is_little_endian {
            let ptr = u64::from(u32::from_le_bytes(
                section_data[i..i + 4].try_into().unwrap(),
            ));
            let len = u64::from(u32::from_le_bytes(
                section_data[i + 4..i + 8].try_into().unwrap(),
            ));
            (ptr, len)
        } else {
            let ptr = u64::from(u32::from_be_bytes(
                section_data[i..i + 4].try_into().unwrap(),
            ));
            let len = u64::from(u32::from_be_bytes(
                section_data[i + 4..i + 8].try_into().unwrap(),
            ));
            (ptr, len)
        };

        // Check if this looks like a valid string structure
        if ptr >= blob_addr
            && ptr < blob_addr + blob_size
            && len > 0
            && len < 1024 * 1024 // Max 1MB string
            && ptr + len <= blob_addr + blob_size
        {
            structs.push(StringStruct {
                struct_offset: section_addr + i as u64,
                ptr,
                len,
            });
        }
    }

    structs
}

/// Extract strings from a data blob using string structures as boundaries.
pub fn extract_from_structures(
    blob: &[u8],
    blob_addr: u64,
    structs: &[StringStruct],
    section_name: Option<String>,
) -> Vec<ExtractedString> {
    let mut result = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for s in structs {
        if s.ptr < blob_addr {
            continue;
        }

        let offset = (s.ptr - blob_addr) as usize;
        let end = offset + s.len as usize;

        if end > blob.len() {
            continue;
        }

        let bytes = &blob[offset..end];

        // Validate UTF-8
        if let Ok(string) = std::str::from_utf8(bytes) {
            // Skip duplicates
            if seen.contains(string) {
                continue;
            }

            // Skip strings that are mostly non-printable
            let printable_count = string
                .chars()
                .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                .count();

            if printable_count * 2 < string.len() {
                continue;
            }

            seen.insert(string.to_string());
            result.push(ExtractedString {
                value: string.to_string(),
                data_offset: s.ptr,
                section: section_name.clone(),
                method: StringMethod::Structure,
            });
        }
    }

    result
}

/// Check if a byte sequence looks like valid UTF-8 with reasonable content.
pub fn is_valid_string(bytes: &[u8], min_length: usize) -> bool {
    if bytes.len() < min_length {
        return false;
    }

    match std::str::from_utf8(bytes) {
        Ok(s) => {
            // Check printability
            let printable = s
                .chars()
                .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                .count();
            printable * 2 >= s.len()
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== BinaryInfo Tests ====================

    #[test]
    fn test_binary_info_64bit_le() {
        let info = BinaryInfo::new_64bit_le();
        assert!(info.is_64bit);
        assert!(info.is_little_endian);
        assert_eq!(info.ptr_size, 8);
    }

    #[test]
    fn test_binary_info_32bit_le() {
        let info = BinaryInfo::new_32bit_le();
        assert!(!info.is_64bit);
        assert!(info.is_little_endian);
        assert_eq!(info.ptr_size, 4);
    }

    #[test]
    fn test_binary_info_64bit_be() {
        let info = BinaryInfo::new_64bit_be();
        assert!(info.is_64bit);
        assert!(!info.is_little_endian);
        assert_eq!(info.ptr_size, 8);
    }

    #[test]
    fn test_binary_info_32bit_be() {
        let info = BinaryInfo::new_32bit_be();
        assert!(!info.is_64bit);
        assert!(!info.is_little_endian);
        assert_eq!(info.ptr_size, 4);
    }

    #[test]
    fn test_binary_info_from_elf() {
        // 64-bit LE (common: x86_64, ARM64)
        let info = BinaryInfo::from_elf(true, true);
        assert!(info.is_64bit);
        assert!(info.is_little_endian);
        assert_eq!(info.ptr_size, 8);

        // 32-bit LE (common: x86, ARM)
        let info = BinaryInfo::from_elf(false, true);
        assert!(!info.is_64bit);
        assert!(info.is_little_endian);
        assert_eq!(info.ptr_size, 4);

        // 64-bit BE (rare: s390x, SPARC64)
        let info = BinaryInfo::from_elf(true, false);
        assert!(info.is_64bit);
        assert!(!info.is_little_endian);
        assert_eq!(info.ptr_size, 8);

        // 32-bit BE (rare: MIPS, PowerPC)
        let info = BinaryInfo::from_elf(false, false);
        assert!(!info.is_64bit);
        assert!(!info.is_little_endian);
        assert_eq!(info.ptr_size, 4);
    }

    #[test]
    fn test_binary_info_from_macho() {
        // Mach-O is always LE (x86_64, ARM64)
        let info = BinaryInfo::from_macho(true);
        assert!(info.is_64bit);
        assert!(info.is_little_endian);
        assert_eq!(info.ptr_size, 8);

        let info = BinaryInfo::from_macho(false);
        assert!(!info.is_64bit);
        assert!(info.is_little_endian);
        assert_eq!(info.ptr_size, 4);
    }

    #[test]
    fn test_binary_info_from_pe() {
        // PE is always LE
        let info = BinaryInfo::from_pe(true);
        assert!(info.is_64bit);
        assert!(info.is_little_endian);
        assert_eq!(info.ptr_size, 8);

        let info = BinaryInfo::from_pe(false);
        assert!(!info.is_64bit);
        assert!(info.is_little_endian);
        assert_eq!(info.ptr_size, 4);
    }

    // ==================== StringMethod Tests ====================

    #[test]
    fn test_string_method_equality() {
        assert_eq!(StringMethod::Structure, StringMethod::Structure);
        assert_eq!(
            StringMethod::InstructionPattern,
            StringMethod::InstructionPattern
        );
        assert_eq!(StringMethod::RawScan, StringMethod::RawScan);
        assert_ne!(StringMethod::Structure, StringMethod::RawScan);
    }

    #[test]
    fn test_string_method_clone() {
        let method = StringMethod::Structure;
        let cloned = method.clone();
        assert_eq!(method, cloned);
    }

    // ==================== StringStruct Tests ====================

    #[test]
    fn test_string_struct_clone() {
        let ss = StringStruct {
            struct_offset: 100,
            ptr: 0x1000,
            len: 10,
        };
        let cloned = ss.clone();
        assert_eq!(cloned.struct_offset, 100);
        assert_eq!(cloned.ptr, 0x1000);
        assert_eq!(cloned.len, 10);
    }

    #[test]
    fn test_string_struct_debug() {
        let ss = StringStruct {
            struct_offset: 100,
            ptr: 0x1000,
            len: 10,
        };
        let debug_str = format!("{:?}", ss);
        assert!(debug_str.contains("StringStruct"));
    }

    // ==================== ExtractedString Tests ====================

    #[test]
    fn test_extracted_string_clone() {
        let es = ExtractedString {
            value: "test".to_string(),
            data_offset: 0x1000,
            section: Some(".rodata".to_string()),
            method: StringMethod::Structure,
        };
        let cloned = es.clone();
        assert_eq!(cloned.value, "test");
        assert_eq!(cloned.data_offset, 0x1000);
        assert_eq!(cloned.section, Some(".rodata".to_string()));
        assert_eq!(cloned.method, StringMethod::Structure);
    }

    #[test]
    fn test_extracted_string_no_section() {
        let es = ExtractedString {
            value: "test".to_string(),
            data_offset: 0x1000,
            section: None,
            method: StringMethod::RawScan,
        };
        assert!(es.section.is_none());
    }

    // ==================== find_string_structures Tests ====================

    #[test]
    fn test_find_string_structures_64bit_le() {
        let info = BinaryInfo::new_64bit_le();

        // Create section with one valid string structure
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
        assert_eq!(structs[0].struct_offset, 0x2000);
    }

    #[test]
    fn test_find_string_structures_32bit_le() {
        let info = BinaryInfo::new_32bit_le();

        // Create section with one valid string structure
        // ptr = 0x1000, len = 5
        let mut section_data = vec![0u8; 16];
        section_data[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
        section_data[4..8].copy_from_slice(&5u32.to_le_bytes());

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].ptr, 0x1000);
        assert_eq!(structs[0].len, 5);
    }

    #[test]
    fn test_find_string_structures_64bit_be() {
        let info = BinaryInfo {
            is_64bit: true,
            is_little_endian: false,
            ptr_size: 8,
        };

        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x1000u64.to_be_bytes());
        section_data[8..16].copy_from_slice(&5u64.to_be_bytes());

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].ptr, 0x1000);
        assert_eq!(structs[0].len, 5);
    }

    #[test]
    fn test_find_string_structures_32bit_be() {
        let info = BinaryInfo {
            is_64bit: false,
            is_little_endian: false,
            ptr_size: 4,
        };

        let mut section_data = vec![0u8; 16];
        section_data[0..4].copy_from_slice(&0x1000u32.to_be_bytes());
        section_data[4..8].copy_from_slice(&5u32.to_be_bytes());

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert_eq!(structs.len(), 1);
        assert_eq!(structs[0].ptr, 0x1000);
        assert_eq!(structs[0].len, 5);
    }

    #[test]
    fn test_find_string_structures_multiple() {
        let info = BinaryInfo::new_64bit_le();

        // Two valid structures
        let mut section_data = vec![0u8; 48];
        // First: ptr=0x1000, len=5
        section_data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        section_data[8..16].copy_from_slice(&5u64.to_le_bytes());
        // Second: ptr=0x1010, len=10
        section_data[16..24].copy_from_slice(&0x1010u64.to_le_bytes());
        section_data[24..32].copy_from_slice(&10u64.to_le_bytes());

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert_eq!(structs.len(), 2);
    }

    #[test]
    fn test_find_string_structures_ptr_out_of_range() {
        let info = BinaryInfo::new_64bit_le();

        // ptr outside blob range
        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x5000u64.to_le_bytes()); // Not in 0x1000..0x1100
        section_data[8..16].copy_from_slice(&5u64.to_le_bytes());

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert!(structs.is_empty());
    }

    #[test]
    fn test_find_string_structures_len_zero() {
        let info = BinaryInfo::new_64bit_le();

        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        section_data[8..16].copy_from_slice(&0u64.to_le_bytes()); // len = 0

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert!(structs.is_empty());
    }

    #[test]
    fn test_find_string_structures_len_too_large() {
        let info = BinaryInfo::new_64bit_le();

        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        section_data[8..16].copy_from_slice(&(2 * 1024 * 1024u64).to_le_bytes()); // 2MB > 1MB limit

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert!(structs.is_empty());
    }

    #[test]
    fn test_find_string_structures_ptr_plus_len_exceeds_blob() {
        let info = BinaryInfo::new_64bit_le();

        let mut section_data = vec![0u8; 32];
        section_data[0..8].copy_from_slice(&0x1050u64.to_le_bytes()); // ptr near end
        section_data[8..16].copy_from_slice(&0x100u64.to_le_bytes()); // len would exceed

        let structs = find_string_structures(
            &section_data,
            0x2000,
            0x1000,
            0x100, // blob ends at 0x1100, but ptr+len = 0x1150
            &info,
        );

        assert!(structs.is_empty());
    }

    #[test]
    fn test_find_string_structures_section_too_small() {
        let info = BinaryInfo::new_64bit_le();

        // Section smaller than one structure (16 bytes for 64-bit)
        let section_data = vec![0u8; 8];

        let structs = find_string_structures(&section_data, 0x2000, 0x1000, 0x100, &info);

        assert!(structs.is_empty());
    }

    #[test]
    fn test_find_string_structures_empty_section() {
        let info = BinaryInfo::new_64bit_le();

        let structs = find_string_structures(&[], 0x2000, 0x1000, 0x100, &info);

        assert!(structs.is_empty());
    }

    // ==================== extract_from_structures Tests ====================

    #[test]
    fn test_extract_from_structures_basic() {
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
        assert_eq!(strings[0].method, StringMethod::Structure);
    }

    #[test]
    fn test_extract_from_structures_deduplication() {
        let blob = b"HelloHello";
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

        let strings = extract_from_structures(blob, 0x1000, &structs, None);

        // Should deduplicate "Hello"
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "Hello");
    }

    #[test]
    fn test_extract_from_structures_ptr_before_blob() {
        let blob = b"Hello";
        let structs = vec![
            StringStruct {
                struct_offset: 0,
                ptr: 0x500,
                len: 5,
            }, // Before blob_addr
        ];

        let strings = extract_from_structures(blob, 0x1000, &structs, None);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_from_structures_end_exceeds_blob() {
        let blob = b"Hello";
        let structs = vec![
            StringStruct {
                struct_offset: 0,
                ptr: 0x1003,
                len: 10,
            }, // Would exceed blob
        ];

        let strings = extract_from_structures(blob, 0x1000, &structs, None);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_from_structures_invalid_utf8() {
        let blob = &[0xFF, 0xFE, 0x00, 0x01, 0x02]; // Invalid UTF-8
        let structs = vec![StringStruct {
            struct_offset: 0,
            ptr: 0x1000,
            len: 5,
        }];

        let strings = extract_from_structures(blob, 0x1000, &structs, None);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_from_structures_mostly_nonprintable() {
        // Mostly control characters (>50% non-printable)
        let blob = &[0x01, 0x02, 0x03, b'H', b'i'];
        let structs = vec![StringStruct {
            struct_offset: 0,
            ptr: 0x1000,
            len: 5,
        }];

        let strings = extract_from_structures(blob, 0x1000, &structs, None);

        // Should be filtered out because >50% non-printable
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_from_structures_section_name() {
        let blob = b"Hello";
        let structs = vec![StringStruct {
            struct_offset: 0,
            ptr: 0x1000,
            len: 5,
        }];

        let strings = extract_from_structures(blob, 0x1000, &structs, Some(".rodata".to_string()));

        assert_eq!(strings[0].section, Some(".rodata".to_string()));
    }

    #[test]
    fn test_extract_from_structures_data_offset() {
        let blob = b"Hello";
        let structs = vec![StringStruct {
            struct_offset: 0,
            ptr: 0x1000,
            len: 5,
        }];

        let strings = extract_from_structures(blob, 0x1000, &structs, None);

        assert_eq!(strings[0].data_offset, 0x1000);
    }

    #[test]
    fn test_extract_from_structures_empty_structs() {
        let blob = b"Hello";
        let structs: Vec<StringStruct> = vec![];

        let strings = extract_from_structures(blob, 0x1000, &structs, None);

        assert!(strings.is_empty());
    }

    // ==================== is_valid_string Tests ====================

    #[test]
    fn test_is_valid_string_basic() {
        assert!(is_valid_string(b"Hello World", 4));
    }

    #[test]
    fn test_is_valid_string_too_short() {
        assert!(!is_valid_string(b"Hi", 4));
    }

    #[test]
    fn test_is_valid_string_exactly_min_length() {
        assert!(is_valid_string(b"Test", 4));
    }

    #[test]
    fn test_is_valid_string_invalid_utf8() {
        assert!(!is_valid_string(&[0xFF, 0xFE, 0x00, 0x01], 2));
    }

    #[test]
    fn test_is_valid_string_mostly_printable() {
        // "Hello" is all printable
        assert!(is_valid_string(b"Hello", 4));
    }

    #[test]
    fn test_is_valid_string_mostly_nonprintable() {
        // Mostly control characters
        assert!(!is_valid_string(&[0x01, 0x02, 0x03, b'H'], 2));
    }

    #[test]
    fn test_is_valid_string_with_whitespace() {
        // Whitespace counts as printable
        assert!(is_valid_string(b"Hello World\n\t", 4));
    }

    #[test]
    fn test_is_valid_string_empty() {
        // Empty string with min_length=0 is technically valid (passes UTF-8 and printability checks)
        // But with any min_length > 0, it fails
        assert!(!is_valid_string(b"", 1));
        assert!(!is_valid_string(b"", 4));
    }

    #[test]
    fn test_is_valid_string_unicode() {
        // Valid UTF-8 unicode
        assert!(is_valid_string("Hello 世界".as_bytes(), 4));
    }
}
