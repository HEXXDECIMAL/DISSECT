//! Parsing utilities for radare2/rizin output.
//!
//! This module contains helper functions for parsing various formats of output
//! from radare2/rizin commands, including:
//! - Disassembly output parsing
//! - Search result parsing
//! - Syscall number extraction from assembly

pub(super) fn calculate_char_entropy(chars: &[char]) -> f32 {
    if chars.is_empty() {
        return 0.0;
    }

    let mut freq: std::collections::HashMap<char, u32> = std::collections::HashMap::new();
    for &c in chars {
        *freq.entry(c).or_insert(0) += 1;
    }

    let total = chars.len() as f32;
    let mut entropy: f32 = 0.0;
    for &count in freq.values() {
        let p = count as f32 / total;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Parse syscall number from disassembly output
pub(super) fn parse_syscall_number_from_disasm(disasm: &str, arch: &str) -> Option<u32> {
    match arch {
        "mips" => {
            // MIPS o32: syscall number in v0 ($2)
            for line in disasm.lines().rev() {
                let line_lower = line.to_lowercase();
                if (line_lower.contains("addiu") || line_lower.contains("li"))
                    && (line_lower.contains("v0") || line_lower.contains("$2"))
                {
                    if let Some(num) = extract_hex_or_decimal(line) {
                        if (4000..6000).contains(&num) || (6000..8000).contains(&num) {
                            return Some(num);
                        }
                    }
                }
            }
        },
        "x86" | "x86_64" => {
            // x86: syscall number in eax/rax
            for line in disasm.lines().rev() {
                let line_lower = line.to_lowercase();
                if line_lower.contains("mov")
                    && (line_lower.contains("eax") || line_lower.contains("rax"))
                {
                    if let Some(num) = extract_hex_or_decimal(line) {
                        if num < 1000 {
                            return Some(num);
                        }
                    }
                }
            }
        },
        "arm" | "aarch64" => {
            let reg = if arch == "arm" { "r7" } else { "x8" };
            for line in disasm.lines().rev() {
                let line_lower = line.to_lowercase();
                if line_lower.contains("mov") && line_lower.contains(reg) {
                    if let Some(num) = extract_hex_or_decimal(line) {
                        if num < 1000 {
                            return Some(num);
                        }
                    }
                }
            }
        },
        "ppc" => {
            for line in disasm.lines().rev() {
                let line_lower = line.to_lowercase();
                if line_lower.contains("li") && line_lower.contains("r0") {
                    if let Some(num) = extract_hex_or_decimal(line) {
                        if num < 1000 {
                            return Some(num);
                        }
                    }
                }
            }
        },
        _ => {},
    }
    None
}

/// Parse radare2 search results to extract addresses
pub(super) fn parse_search_results(output: &str) -> Vec<u64> {
    let mut addrs = Vec::new();
    for line in output.lines() {
        // r2 search output format: "0x00400123 hit0_0 ..."
        if let Some(addr_str) = line.split_whitespace().next() {
            if let Some(hex) = addr_str.strip_prefix("0x") {
                if let Ok(addr) = u64::from_str_radix(hex, 16) {
                    addrs.push(addr);
                }
            }
        }
    }
    addrs
}

/// Extract hex or decimal number from disassembly line
/// Returns the LAST valid syscall number found (to skip addresses at start of line)
pub(super) fn extract_hex_or_decimal(line: &str) -> Option<u32> {
    let mut last_valid: Option<u32> = None;

    // Try to find hex numbers like 0x1234 or plain decimal
    for word in line.split(|c: char| !c.is_alphanumeric() && c != 'x') {
        if let Some(hex) = word.strip_prefix("0x") {
            if let Ok(num) = u32::from_str_radix(hex, 16) {
                // Keep track of all valid syscall-range numbers
                // MIPS syscalls are 4000-6000, x86/ARM are 0-1000
                if num < 10000 {
                    last_valid = Some(num);
                }
            }
        } else if word.chars().all(|c| c.is_ascii_digit()) && !word.is_empty() {
            if let Ok(num) = word.parse::<u32>() {
                // Filter out likely non-syscall numbers (addresses, large constants)
                if num > 0 && num < 10000 {
                    last_valid = Some(num);
                }
            }
        }
    }
    last_valid
}
