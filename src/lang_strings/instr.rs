//! Instruction pattern analysis for inline string extraction.
//!
//! Inline literals (function arguments, map keys/values) don't create stored
//! pointer+length structures. Instead, compilers pass string addresses and lengths
//! through registers. We extract these by pattern matching instruction sequences.

use super::common::{ExtractedString, StringMethod};
use std::collections::HashSet;

/// Extracts inline strings from ARM64 executable code.
///
/// Scans for BL (branch with link) instructions and looks backwards for
/// ADRP+ADD patterns (string address) and MOV/ORR patterns (string length).
pub fn extract_inline_strings_arm64(
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let rodata_end = rodata_addr + rodata_data.len() as u64;

    // Scan through __text looking for BL instructions (ARM64 instructions are 4 bytes)
    let mut i = 0;
    while i + 4 <= text_data.len() {
        let inst = u32::from_le_bytes(text_data[i..i + 4].try_into().unwrap());

        // Check for BL (branch with link) instruction: 0x94xxxxxx
        if (inst & 0xFC000000) != 0x94000000 {
            i += 4;
            continue;
        }

        // Found a BL - extract string patterns for different register pairs
        // R0/R1 - first argument (common for function calls)
        extract_arm64_string_pattern(
            i,
            text_data,
            text_addr,
            rodata_data,
            rodata_addr,
            rodata_end,
            0, // address register
            1, // length register
            min_length,
            &mut strings,
            &mut seen,
        );

        // R2/R3 - second argument (map keys in runtime.mapassign_faststr)
        extract_arm64_string_pattern(
            i,
            text_data,
            text_addr,
            rodata_data,
            rodata_addr,
            rodata_end,
            2,
            3,
            min_length,
            &mut strings,
            &mut seen,
        );

        i += 4;
    }

    strings
}

/// Extract a string from ARM64 ADRP+ADD+MOV pattern targeting specific registers.
fn extract_arm64_string_pattern(
    bl_pos: usize,
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    rodata_end: u64,
    addr_reg: u32,
    len_reg: u32,
    min_length: usize,
    strings: &mut Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    let max_lookback = bl_pos.min(20 * 4);

    let mut lookback = 8;
    while lookback <= max_lookback {
        let pos = bl_pos - lookback;
        if pos + 12 > text_data.len() {
            break;
        }

        let inst1 = u32::from_le_bytes(text_data[pos..pos + 4].try_into().unwrap());
        let inst2 = u32::from_le_bytes(text_data[pos + 4..pos + 8].try_into().unwrap());

        // Check for ADRP Rx
        let target_reg = inst1 & 0x1F;
        let is_adrp = ((inst1 & 0x9F000000) == 0x90000000) && target_reg == addr_reg;

        if !is_adrp {
            lookback += 4;
            continue;
        }

        // Check for ADD Rx, Rx, #imm
        let is_add = ((inst2 & 0xFF000000) == 0x91000000)
            && ((inst2 & 0x1F) == addr_reg)
            && (((inst2 >> 5) & 0x1F) == addr_reg);

        if !is_add {
            lookback += 4;
            continue;
        }

        // Search for MOV/ORR Ry within next few instructions
        let mut inst3 = 0u32;
        let mut found_mov = false;

        let mut offset = 8;
        while offset <= 20 && pos + offset + 4 <= text_data.len() {
            let inst3_candidate = u32::from_le_bytes(
                text_data[pos + offset..pos + offset + 4]
                    .try_into()
                    .unwrap(),
            );
            let reg_num = inst3_candidate & 0x1F;

            // Check for ORR or MOVD targeting length register
            let is_mov = ((inst3_candidate & 0xB2000000) == 0xB2000000
                || (inst3_candidate & 0xFF000000) == 0xD2000000)
                && reg_num == len_reg;

            if is_mov {
                inst3 = inst3_candidate;
                found_mov = true;
                break;
            }
            offset += 4;
        }

        if !found_mov {
            lookback += 4;
            continue;
        }

        // Decode and extract the string
        if let Some(s) = decode_arm64_string(
            inst1,
            inst2,
            inst3,
            pos,
            text_addr,
            rodata_data,
            rodata_addr,
            rodata_end,
        ) {
            if s.len() >= min_length && !seen.contains(&s) {
                seen.insert(s.clone());
                strings.push(ExtractedString {
                    value: s,
                    data_offset: rodata_addr,
                    section: Some("__rodata".to_string()),
                    method: StringMethod::InstructionPattern,
                });
            }
        }

        return;
    }
}

/// Decode ARM64 ADRP+ADD instructions to extract string address and length.
fn decode_arm64_string(
    inst1: u32,
    inst2: u32,
    inst3: u32,
    pos: usize,
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    rodata_end: u64,
) -> Option<String> {
    // Decode ADRP: extract page address
    let immlo = (inst1 >> 29) & 0x3;
    let immhi = (inst1 >> 5) & 0x7FFFF;
    let mut page_offset = ((immhi << 2) | immlo) as i64;
    if (page_offset & 0x100000) != 0 {
        page_offset |= !0x1FFFFF_i64;
    }

    let pc = text_addr as i64 + pos as i64;
    let pc_page = pc & !0xFFF_i64;
    let page_addr = pc_page + (page_offset << 12);

    // Decode ADD: extract immediate
    let add_imm = (inst2 >> 10) & 0xFFF;
    let str_addr = (page_addr as u64).wrapping_add(add_imm as u64);

    // Decode MOV/ORR: extract length
    let str_len = decode_arm_mov_immediate(inst3)?;

    // Validate
    if str_addr < rodata_addr || str_addr >= rodata_end {
        return None;
    }

    if str_len == 0 || str_len > 1000 {
        return None;
    }

    let rodata_offset = (str_addr - rodata_addr) as usize;
    if rodata_offset + str_len as usize > rodata_data.len() {
        return None;
    }

    let bytes = &rodata_data[rodata_offset..rodata_offset + str_len as usize];
    let s = std::str::from_utf8(bytes).ok()?;

    if is_valid_utf8_string(s) {
        Some(s.to_string())
    } else {
        None
    }
}

/// Decode ARM64 MOV/ORR immediate value.
fn decode_arm_mov_immediate(inst: u32) -> Option<u64> {
    // Check for MOVZ/MOVK (D2xxxxxx)
    if (inst & 0xFF000000) == 0xD2000000 {
        let imm16 = ((inst >> 5) & 0xFFFF) as u64;
        let shift = (((inst >> 21) & 0x3) * 16) as u64;
        return Some(imm16 << shift);
    }

    // Check for ORR with bitmask immediate (B2xxxxxx)
    if (inst & 0xB2000000) == 0xB2000000 && (inst & 0xFF000000) != 0xD2000000 {
        return decode_arm_bitmask_immediate(inst);
    }

    None
}

/// Decode ARM64 bitmask immediate encoding used in ORR/AND instructions.
fn decode_arm_bitmask_immediate(inst: u32) -> Option<u64> {
    let sf = (inst >> 31) & 0x1;
    let n = (inst >> 22) & 0x1;
    let immr = (inst >> 16) & 0x3F;
    let imms = (inst >> 10) & 0x3F;

    let size = if sf == 1 { 64u32 } else { 32u32 };

    // Find element size
    let elem_len = if n == 1 {
        6 // 64-bit element
    } else if (imms & 0x20) == 0 {
        5 // 32-bit element
    } else if (imms & 0x10) == 0 {
        4 // 16-bit element
    } else if (imms & 0x08) == 0 {
        3 // 8-bit element
    } else if (imms & 0x04) == 0 {
        2 // 4-bit element
    } else {
        return None; // Invalid
    };

    let esize = 1u32 << elem_len;
    if esize > size {
        return None;
    }

    // Bounds check to prevent overflow
    if elem_len > 6 || esize > 64 {
        return None;
    }

    let levels = (1u32 << elem_len) - 1;
    let s = imms & levels;
    let r = immr & levels;

    let welem = s + 1;
    if welem > 63 {
        return None;
    }
    let mut pattern = (1u64 << welem) - 1;

    if r != 0 && r < esize {
        let mask = if esize >= 64 {
            u64::MAX
        } else {
            (1u64 << esize) - 1
        };
        pattern = ((pattern >> r) | (pattern << (esize - r))) & mask;
    }

    let mut value = 0u64;
    let mut i = 0u32;
    while i < size && i < 64 {
        value |= pattern << i;
        i += esize;
    }

    if value > 0 && value <= 1000 {
        Some(value)
    } else {
        None
    }
}

/// Extracts inline strings from AMD64 executable code.
///
/// Scans for CALL instructions and looks for LEAQ addr(RIP) patterns
/// (string address) and MOVL/MOVQ patterns (string length).
pub fn extract_inline_strings_amd64(
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let rodata_end = rodata_addr + rodata_data.len() as u64;

    // Scan through text looking for CALL instructions
    let mut i = 0;
    while i < text_data.len().saturating_sub(5) {
        // Check for CALL instruction (E8 xx xx xx xx)
        if text_data[i] != 0xE8 {
            i += 1;
            continue;
        }

        // Extract first argument strings (RDI/RSI)
        extract_amd64_first_arg_string(
            i,
            text_data,
            text_addr,
            rodata_data,
            rodata_addr,
            rodata_end,
            min_length,
            &mut strings,
            &mut seen,
        );

        // Extract second argument strings (RSI/RDX)
        extract_amd64_key_string(
            i,
            text_data,
            text_addr,
            rodata_data,
            rodata_addr,
            rodata_end,
            min_length,
            &mut strings,
            &mut seen,
        );

        // Extract value strings after CALL
        extract_amd64_value_string(
            i,
            text_data,
            text_addr,
            rodata_data,
            rodata_addr,
            rodata_end,
            min_length,
            &mut strings,
            &mut seen,
        );

        i += 1;
    }

    strings
}

/// Extract first argument string (LEAQ addr(RIP), RDI + MOVL $len, RSI).
fn extract_amd64_first_arg_string(
    call_pos: usize,
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    rodata_end: u64,
    min_length: usize,
    strings: &mut Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    let max_lookback = call_pos.min(50);

    for lookback in 5..=max_lookback {
        let pos = call_pos - lookback;
        if pos + 7 > text_data.len() {
            break;
        }

        // Check for LEAQ xxx(RIP), RDI (48 8D 3D xx xx xx xx)
        if text_data[pos] == 0x48 && text_data[pos + 1] == 0x8D && text_data[pos + 2] == 0x3D {
            let offset = i32::from_le_bytes(text_data[pos + 3..pos + 7].try_into().unwrap());
            let rip_addr = text_addr + (pos + 7) as u64;
            let str_addr = (rip_addr as i64 + offset as i64) as u64;

            // Look for MOVL/MOVQ $len, RSI
            let mut str_len = 0u64;
            let mut found_len = false;

            for off in 7..=20 {
                if pos + off + 5 > text_data.len() {
                    break;
                }

                // MOVL $imm32, ESI (BE xx xx xx xx)
                if text_data[pos + off] == 0xBE {
                    str_len = u32::from_le_bytes(
                        text_data[pos + off + 1..pos + off + 5].try_into().unwrap(),
                    ) as u64;
                    found_len = true;
                    break;
                }

                // MOVQ $imm32, RSI (48 C7 C6 xx xx xx xx)
                if pos + off + 7 <= text_data.len()
                    && text_data[pos + off] == 0x48
                    && text_data[pos + off + 1] == 0xC7
                    && text_data[pos + off + 2] == 0xC6
                {
                    str_len = u32::from_le_bytes(
                        text_data[pos + off + 3..pos + off + 7].try_into().unwrap(),
                    ) as u64;
                    found_len = true;
                    break;
                }
            }

            if !found_len || str_len == 0 || str_len > 1000 {
                continue;
            }

            if str_addr < rodata_addr || str_addr >= rodata_end {
                continue;
            }

            let rodata_offset = (str_addr - rodata_addr) as usize;
            if rodata_offset + str_len as usize > rodata_data.len() {
                continue;
            }

            if let Ok(s) =
                std::str::from_utf8(&rodata_data[rodata_offset..rodata_offset + str_len as usize])
            {
                if is_valid_utf8_string(s) && s.len() >= min_length && !seen.contains(s) {
                    seen.insert(s.to_string());
                    strings.push(ExtractedString {
                        value: s.to_string(),
                        data_offset: str_addr,
                        section: Some(".rodata".to_string()),
                        method: StringMethod::InstructionPattern,
                    });
                }
            }

            return;
        }
    }
}

/// Extract key string (LEAQ addr(RIP), RSI + MOVL $len, RDX).
fn extract_amd64_key_string(
    call_pos: usize,
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    rodata_end: u64,
    min_length: usize,
    strings: &mut Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    let max_lookback = call_pos.min(50);

    for lookback in 5..=max_lookback {
        let pos = call_pos - lookback;
        if pos + 7 > text_data.len() {
            break;
        }

        // LEAQ xxx(RIP), RSI (48 8D 35 xx xx xx xx)
        if text_data[pos] == 0x48 && text_data[pos + 1] == 0x8D && text_data[pos + 2] == 0x35 {
            let offset = i32::from_le_bytes(text_data[pos + 3..pos + 7].try_into().unwrap());
            let rip_addr = text_addr + (pos + 7) as u64;
            let str_addr = (rip_addr as i64 + offset as i64) as u64;

            // Find MOVL $len, EDX (BA xx xx xx xx)
            let mut str_len = 0u64;
            let mut found_len = false;

            for off in 7..=20 {
                if pos + off + 5 > text_data.len() {
                    break;
                }

                if text_data[pos + off] == 0xBA {
                    str_len = u32::from_le_bytes(
                        text_data[pos + off + 1..pos + off + 5].try_into().unwrap(),
                    ) as u64;
                    found_len = true;
                    break;
                }
            }

            if !found_len || str_len == 0 || str_len > 1000 {
                continue;
            }

            if str_addr < rodata_addr || str_addr >= rodata_end {
                continue;
            }

            let rodata_offset = (str_addr - rodata_addr) as usize;
            if rodata_offset + str_len as usize > rodata_data.len() {
                continue;
            }

            if let Ok(s) =
                std::str::from_utf8(&rodata_data[rodata_offset..rodata_offset + str_len as usize])
            {
                if is_valid_utf8_string(s) && s.len() >= min_length && !seen.contains(s) {
                    seen.insert(s.to_string());
                    strings.push(ExtractedString {
                        value: s.to_string(),
                        data_offset: str_addr,
                        section: Some(".rodata".to_string()),
                        method: StringMethod::InstructionPattern,
                    });
                }
            }

            return;
        }
    }
}

/// Extract value string from after CALL (LEAQ + MOVQ pattern).
fn extract_amd64_value_string(
    call_pos: usize,
    text_data: &[u8],
    text_addr: u64,
    rodata_data: &[u8],
    rodata_addr: u64,
    rodata_end: u64,
    min_length: usize,
    strings: &mut Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    let max_lookforward = (text_data.len() - call_pos - 5).min(80);

    // Find MOVQ $len, 8(RAX) (48 C7 40 08 xx xx xx xx)
    let mut str_len = 0u64;
    let mut found_len = false;

    for offset in 5..=max_lookforward {
        if call_pos + offset + 8 > text_data.len() {
            break;
        }

        if text_data[call_pos + offset] == 0x48
            && text_data[call_pos + offset + 1] == 0xC7
            && text_data[call_pos + offset + 2] == 0x40
            && text_data[call_pos + offset + 3] == 0x08
        {
            str_len = u32::from_le_bytes(
                text_data[call_pos + offset + 4..call_pos + offset + 8]
                    .try_into()
                    .unwrap(),
            ) as u64;
            found_len = true;
            break;
        }
    }

    if !found_len || str_len == 0 || str_len > 1000 {
        return;
    }

    // Find LEAQ addr(RIP), RCX (48 8D 0D xx xx xx xx)
    for offset in 5..=max_lookforward {
        if call_pos + offset + 7 > text_data.len() {
            break;
        }

        if text_data[call_pos + offset] == 0x48
            && text_data[call_pos + offset + 1] == 0x8D
            && text_data[call_pos + offset + 2] == 0x0D
        {
            let rip_offset = i32::from_le_bytes(
                text_data[call_pos + offset + 3..call_pos + offset + 7]
                    .try_into()
                    .unwrap(),
            );
            let rip_addr = text_addr + (call_pos + offset + 7) as u64;
            let str_addr = (rip_addr as i64 + rip_offset as i64) as u64;

            if str_addr < rodata_addr || str_addr >= rodata_end {
                continue;
            }

            let rodata_offset = (str_addr - rodata_addr) as usize;
            if rodata_offset + str_len as usize > rodata_data.len() {
                continue;
            }

            if let Ok(s) =
                std::str::from_utf8(&rodata_data[rodata_offset..rodata_offset + str_len as usize])
            {
                if is_valid_utf8_string(s) && s.len() >= min_length && !seen.contains(s) {
                    seen.insert(s.to_string());
                    strings.push(ExtractedString {
                        value: s.to_string(),
                        data_offset: str_addr,
                        section: Some(".rodata".to_string()),
                        method: StringMethod::InstructionPattern,
                    });
                }
            }

            return;
        }
    }
}

/// Check if a string is valid UTF-8 with reasonable content.
fn is_valid_utf8_string(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    // Check that it's mostly printable
    let printable = s
        .chars()
        .filter(|&c| (c >= '\x20' && c <= '\x7E') || c >= '\u{80}')
        .count();

    (printable as f64 / s.chars().count() as f64) > 0.5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_utf8_string() {
        assert!(is_valid_utf8_string("hello"));
        assert!(is_valid_utf8_string("Hello World!"));
        assert!(!is_valid_utf8_string(""));
        assert!(!is_valid_utf8_string("\x01\x02\x03"));
    }

    #[test]
    fn test_decode_arm_mov_immediate() {
        // MOVZ X0, #5 would be: D2 80 00 A0 (0xD28000A0)
        // imm16 = 5, shift = 0
        let inst = 0xD28000A0;
        let result = decode_arm_mov_immediate(inst);
        assert_eq!(result, Some(5));
    }

    #[test]
    fn test_decode_arm_bitmask_immediate_simple() {
        // Test that valid patterns return Some
        // Note: actual values depend on encoding
    }
}
