//! Radare2/rizin integration for binary analysis.
//!
//! This module provides deep binary analysis using radare2/rizin, including:
//! - Function extraction with control flow metrics
//! - String extraction
//! - Symbol/import/export analysis
//! - Syscall detection
//! - Section analysis with entropy calculation
//! - Batched analysis for performance
//!
//! # Architecture
//! - `models`: Data structures for R2 output and conversions
//! - `parsing`: Parsing utilities for disassembly and search results
//! - `cache`: Filesystem caching with zstd compression
//!
//! # Performance Optimizations
//! - Single r2 session for batched analysis (extract_batched)
//! - Zstd-compressed caching by file SHA256
//! - Skip expensive analysis for large binaries (>20MB)
//! - Architecture-aware syscall detection

mod cache;
mod models;
mod parsing;

// Re-export public types from models
pub use models::{R2Export, R2Function, R2Import, R2Section, R2String, R2Symbol};

// Import parsing utilities for use in this module
use parsing::{parse_search_results, parse_syscall_number_from_disasm};

use crate::syscall_names::{syscall_description, syscall_name};
use crate::types::{BinaryMetrics, Function};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

/// Global flag to disable radare2 analysis
static RADARE2_DISABLED: AtomicBool = AtomicBool::new(false);

/// Cached result of radare2 availability check (avoids subprocess per file)
static RADARE2_AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Disable radare2 analysis globally
pub fn disable_radare2() {
    RADARE2_DISABLED.store(true, Ordering::SeqCst);
}

/// Check if radare2 is disabled
pub fn is_disabled() -> bool {
    RADARE2_DISABLED.load(Ordering::SeqCst)
}

/// Syscall information extracted from binary
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyscallInfo {
    /// Address where syscall instruction occurs
    pub address: u64,
    /// Syscall number (architecture-dependent)
    pub number: u32,
    /// Resolved syscall name (e.g., "read", "write", "socket")
    pub name: String,
    /// Brief description of what this syscall does
    pub desc: String,
    /// Architecture (e.g., "x86", "x86_64", "mips", "arm")
    pub arch: String,
}

/// Batched analysis result containing all data from a single r2 session
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BatchedAnalysis {
    pub functions: Vec<R2Function>,
    pub sections: Vec<R2Section>,
    pub strings: Vec<R2String>,
}

/// Radare2 integration for deep binary analysis
pub struct Radare2Analyzer {
    timeout_seconds: u64,
}

impl Radare2Analyzer {
    pub fn new() -> Self {
        Self {
            timeout_seconds: 30,
        }
    }

    /// Check if radare2 is available (and not disabled)
    /// Result is cached after first check to avoid subprocess spawn per file.
    pub fn is_available() -> bool {
        if is_disabled() {
            return false;
        }
        *RADARE2_AVAILABLE.get_or_init(|| Command::new("rizin").arg("-v").output().is_ok())
    }

    /// Extract functions with complexity metrics
    /// Uses 'aa' (basic analysis) instead of 'aaa' (full analysis) for speed
    pub fn extract_functions(&self, file_path: &Path) -> Result<Vec<Function>> {
        let r2_functions = self.extract_r2_functions(file_path)?;
        Ok(r2_functions.into_iter().map(|f| f.into()).collect())
    }

    /// Extract raw R2Function structs for metrics computation
    pub fn extract_r2_functions(&self, file_path: &Path) -> Result<Vec<R2Function>> {
        let output = Command::new("rizin")
            .arg("-q")
            .arg("-e")
            .arg("scr.color=0") // Disable ANSI colors
            .arg("-e")
            .arg("log.level=0") // Disable log messages
            .arg("-c")
            .arg("aa; aflj") // Basic analysis (faster than aaa), list functions as JSON
            .arg(file_path)
            .output()
            .context("Failed to execute radare2")?;

        if !output.status.success() {
            return Ok(Vec::new()); // Return empty if analysis fails
        }

        let json_str = String::from_utf8_lossy(&output.stdout);

        // radare2 might still output warnings/errors before JSON
        // Find the start of JSON array
        if let Some(json_start) = json_str.find('[') {
            let json_only = &json_str[json_start..];
            let r2_functions: Vec<R2Function> = serde_json::from_str(json_only).unwrap_or_default();
            return Ok(r2_functions);
        }

        Ok(Vec::new())
    }

    /// Extract strings from binary
    /// For large binaries (>20MB), returns empty to avoid slow r2 startup
    /// stng already provides good string extraction for Go/Rust binaries
    pub fn extract_strings(&self, file_path: &Path) -> Result<Vec<R2String>> {
        // Skip r2 string extraction for large binaries - stng handles these well
        const MAX_SIZE_FOR_R2_STRINGS: u64 = 20 * 1024 * 1024; // 20MB

        let file_size = std::fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);

        if file_size > MAX_SIZE_FOR_R2_STRINGS {
            return Ok(Vec::new());
        }

        let output = Command::new("rizin")
            .arg("-q")
            .arg("-e")
            .arg("scr.color=0")
            .arg("-e")
            .arg("log.level=0")
            .arg("-c")
            .arg("izj") // List strings as JSON
            .arg(file_path)
            .output()
            .context("Failed to execute radare2")?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let json_str = String::from_utf8_lossy(&output.stdout);

        // Find JSON start
        if let Some(json_start) = json_str.find('[') {
            let json_only = &json_str[json_start..];
            let strings: Vec<R2String> = serde_json::from_str(json_only).unwrap_or_default();
            return Ok(strings);
        }

        Ok(Vec::new())
    }

    /// Extract imports
    pub fn extract_imports(&self, file_path: &Path) -> Result<Vec<R2Import>> {
        let output = Command::new("rizin")
            .arg("-q")
            .arg("-c")
            .arg("iij") // List imports as JSON
            .arg(file_path)
            .output()
            .context("Failed to execute radare2")?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let json_str = String::from_utf8_lossy(&output.stdout);
        let imports: Vec<R2Import> = serde_json::from_str(&json_str).unwrap_or_default();

        Ok(imports)
    }

    /// Extract exports
    pub fn extract_exports(&self, file_path: &Path) -> Result<Vec<R2Export>> {
        let output = Command::new("rizin")
            .arg("-q")
            .arg("-c")
            .arg("iEj") // List exports as JSON
            .arg(file_path)
            .output()
            .context("Failed to execute radare2")?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let json_str = String::from_utf8_lossy(&output.stdout);
        let exports: Vec<R2Export> = serde_json::from_str(&json_str).unwrap_or_default();

        Ok(exports)
    }

    /// Extract section information with entropy
    pub fn extract_sections(&self, file_path: &Path) -> Result<Vec<R2Section>> {
        let output = Command::new("rizin")
            .arg("-q")
            .arg("-c")
            .arg("iSj") // List sections as JSON
            .arg(file_path)
            .output()
            .context("Failed to execute radare2")?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let json_str = String::from_utf8_lossy(&output.stdout);
        let sections: Vec<R2Section> = serde_json::from_str(&json_str).unwrap_or_default();

        Ok(sections)
    }

    /// Extract all symbols (imports, exports, and internal symbols) in a single session
    pub fn extract_all_symbols(
        &self,
        file_path: &Path,
    ) -> Result<(Vec<R2Import>, Vec<R2Export>, Vec<R2Symbol>)> {
        let output = Command::new("rizin")
            .arg("-q")
            .arg("-e")
            .arg("scr.color=0")
            .arg("-e")
            .arg("log.level=0")
            .arg("-c")
            .arg("iij; echo SEPARATOR; iEj; echo SEPARATOR; isj") // Batched imports, exports, and symbols
            .arg(file_path)
            .output()
            .context("Failed to execute radare2")?;

        if !output.status.success() {
            return Ok((Vec::new(), Vec::new(), Vec::new()));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = output_str.split("SEPARATOR").collect();

        let imports = parts
            .first()
            .and_then(|p| {
                let json_start = p.find('[')?;
                serde_json::from_str(&p[json_start..]).ok()
            })
            .unwrap_or_default();

        let exports = parts
            .get(1)
            .and_then(|p| {
                let json_start = p.find('[')?;
                serde_json::from_str(&p[json_start..]).ok()
            })
            .unwrap_or_default();

        let symbols = parts
            .get(2)
            .and_then(|p| {
                let json_start = p.find('[')?;
                serde_json::from_str(&p[json_start..]).ok()
            })
            .unwrap_or_default();

        Ok((imports, exports, symbols))
    }

    /// Extract syscalls from binary using architecture-aware analysis
    /// Returns detected syscalls with their numbers and resolved names
    /// Optimized to use a SINGLE r2 session for all operations
    pub fn extract_syscalls(&self, file_path: &Path) -> Result<Vec<SyscallInfo>> {
        // Build a batched command that gets arch info and searches for syscall patterns
        // We'll run a single r2 session and parse all results at once
        let output = Command::new("rizin")
            .arg("-q")
            .arg("-e")
            .arg("scr.color=0")
            .arg("-e")
            .arg("log.level=0")
            .arg("-c")
            // Batched commands: get arch info, then search for common syscall patterns
            .arg("iIj; echo SEPARATOR; /x 0f05; echo SEPARATOR; /x cd80; echo SEPARATOR; /x 010000d4")
            .arg(file_path)
            .output()
            .context("Failed to execute radare2")?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = output_str.split("SEPARATOR").collect();

        // Parse architecture from first part
        let arch = if let Some(arch_part) = parts.first() {
            if let Some(json_start) = arch_part.find('{') {
                if let Ok(info) =
                    serde_json::from_str::<serde_json::Value>(&arch_part[json_start..])
                {
                    let arch_str = info.get("arch").and_then(|v| v.as_str()).unwrap_or("");
                    let bits = info.get("bits").and_then(|v| v.as_u64()).unwrap_or(32);
                    match (arch_str, bits) {
                        ("x86", 64) => "x86_64",
                        ("x86", _) => "x86",
                        ("arm", 64) => "aarch64",
                        ("arm", _) => "arm",
                        ("mips", _) => "mips",
                        ("ppc", _) => "ppc",
                        _ => "",
                    }
                } else {
                    ""
                }
            } else {
                ""
            }
        } else {
            ""
        };

        if arch.is_empty() {
            return Ok(Vec::new());
        }

        // Parse syscall addresses from search results (parts 1-3)
        let mut syscall_addrs = Vec::new();
        for part in parts.iter().skip(1) {
            syscall_addrs.extend(parse_search_results(part));
        }

        if syscall_addrs.is_empty() {
            return Ok(Vec::new());
        }

        // Deduplicate
        syscall_addrs.sort_unstable();
        syscall_addrs.dedup();

        // Limit to first 20 syscalls to avoid excessive analysis time
        syscall_addrs.truncate(20);

        // Build a second batched command to disassemble around each syscall address
        let disasm_cmds: Vec<String> =
            syscall_addrs.iter().map(|addr| format!("pd -10 @ {:#x}", addr)).collect();

        if disasm_cmds.is_empty() {
            return Ok(Vec::new());
        }

        let disasm_output = Command::new("rizin")
            .arg("-q")
            .arg("-e")
            .arg("scr.color=0")
            .arg("-e")
            .arg("log.level=0")
            .arg("-c")
            .arg(disasm_cmds.join("; echo ADDR_SEP; "))
            .arg(file_path)
            .output()
            .context("Failed to execute radare2")?;

        let disasm_str = String::from_utf8_lossy(&disasm_output.stdout);
        let disasm_parts: Vec<&str> = disasm_str.split("ADDR_SEP").collect();

        // Parse syscall numbers from disassembly
        let mut syscalls = Vec::new();
        for (i, disasm) in disasm_parts.iter().enumerate() {
            if i >= syscall_addrs.len() {
                break;
            }
            if let Some(num) = parse_syscall_number_from_disasm(disasm, arch) {
                let name = syscall_name(arch, num);
                let description = syscall_description(&name);
                syscalls.push(SyscallInfo {
                    address: syscall_addrs[i],
                    number: num,
                    name,
                    desc: description,
                    arch: arch.to_string(),
                });
            }
        }

        Ok(syscalls)
    }

    /// Get architecture string from binary
    fn get_architecture(&self, file_path: &Path) -> Result<String> {
        let output = Command::new("rizin")
            .arg("-q")
            .arg("-e")
            .arg("scr.color=0")
            .arg("-e")
            .arg("log.level=0")
            .arg("-c")
            .arg("iIj") // Binary info as JSON
            .arg(file_path)
            .output()
            .context("Failed to execute radare2")?;

        if !output.status.success() {
            return Ok(String::new());
        }

        let json_str = String::from_utf8_lossy(&output.stdout);
        if let Some(json_start) = json_str.find('{') {
            if let Ok(info) = serde_json::from_str::<serde_json::Value>(&json_str[json_start..]) {
                if let Some(arch) = info.get("arch").and_then(|v| v.as_str()) {
                    // Normalize architecture names
                    let bits = info.get("bits").and_then(|v| v.as_u64()).unwrap_or(32);
                    return Ok(match (arch, bits) {
                        ("x86", 64) => "x86_64".to_string(),
                        ("x86", _) => "x86".to_string(),
                        ("arm", 64) => "aarch64".to_string(),
                        ("arm", _) => "arm".to_string(),
                        ("mips", _) => "mips".to_string(),
                        ("ppc", _) => "ppc".to_string(),
                        (other, _) => other.to_string(),
                    });
                }
            }
        }

        Ok(String::new())
    }

    /// Find syscall instruction addresses based on architecture
    fn find_syscall_instructions(&self, file_path: &Path, arch: &str) -> Result<Vec<u64>> {
        // Architecture-specific syscall instruction patterns
        let pattern = match arch {
            "x86" => "/x cd80",            // int 0x80
            "x86_64" => "/x 0f05",         // syscall
            "arm" => "/x 00 00 00 ef",     // svc #0 (ARM mode)
            "aarch64" => "/x 01 00 00 d4", // svc #0 (AArch64)
            "mips" => "/x 00 00 00 0c",    // syscall (big-endian)
            "ppc" => "/x 44 00 00 02",     // sc
            _ => return Ok(Vec::new()),
        };

        // Also search for little-endian MIPS variant
        let le_pattern = if arch == "mips" {
            Some("/x 0c 00 00 00") // syscall (little-endian)
        } else if arch == "arm" {
            Some("/x ef 00 00 00") // svc #0 (Thumb might differ)
        } else {
            None
        };

        let output = Command::new("rizin")
            .arg("-q")
            .arg("-e")
            .arg("scr.color=0")
            .arg("-e")
            .arg("log.level=0")
            .arg("-c")
            .arg(pattern)
            .arg(file_path)
            .output()
            .context("Failed to execute radare2")?;

        let mut addrs = parse_search_results(&String::from_utf8_lossy(&output.stdout));

        // Also try alternate pattern if applicable
        if let Some(alt_pattern) = le_pattern {
            let alt_output = Command::new("rizin")
                .arg("-q")
                .arg("-e")
                .arg("scr.color=0")
                .arg("-e")
                .arg("log.level=0")
                .arg("-c")
                .arg(alt_pattern)
                .arg(file_path)
                .output()
                .context("Failed to execute radare2")?;

            addrs.extend(parse_search_results(&String::from_utf8_lossy(
                &alt_output.stdout,
            )));
        }

        // Deduplicate and sort
        addrs.sort_unstable();
        addrs.dedup();

        Ok(addrs)
    }

    /// Find syscall number by backtracking from syscall instruction
    fn find_syscall_number(&self, file_path: &Path, arch: &str, addr: u64) -> Result<Option<u32>> {
        // Disassemble backwards to find the register load
        let output = Command::new("rizin")
            .arg("-q")
            .arg("-e")
            .arg("scr.color=0")
            .arg("-e")
            .arg("log.level=0")
            .arg("-c")
            .arg(format!("pd -15 @ {:#x}", addr)) // 15 instructions before syscall
            .arg(file_path)
            .output()
            .context("Failed to execute radare2")?;

        let disasm = String::from_utf8_lossy(&output.stdout);

        // Parse based on architecture using parsing module function
        Ok(parse_syscall_number_from_disasm(&disasm, arch))
    }

    /// Extract functions, sections, and strings in a SINGLE r2 session
    /// This significantly reduces overhead compared to calling each method separately.
    /// Results are cached by SHA256 with zstd compression.
    pub fn extract_batched(&self, file_path: &Path) -> Result<BatchedAnalysis> {
        use tracing::{debug, trace, warn};
        let _t_start = std::time::Instant::now();

        debug!("Running radare2 batched analysis on {:?}", file_path);

        // Compute SHA256 for cache lookup
        let sha256 = Self::compute_file_sha256(file_path);

        // Check cache first
        if let Some(ref hash) = sha256 {
            if let Some(cached) = Self::load_from_cache(hash) {
                debug!("radare2 cache hit for {}", hash);
                return Ok(cached);
            } else {
                trace!("radare2 cache miss for {}", hash);
            }
        }

        // Check file size - skip expensive function analysis for large binaries
        // Binaries >20MB take minutes to analyze with 'aa'
        // We can still get useful section/entropy data without function analysis
        const MAX_SIZE_FOR_FULL_ANALYSIS: u64 = 20 * 1024 * 1024; // 20MB

        let file_size = std::fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);

        let skip_function_analysis = file_size > MAX_SIZE_FOR_FULL_ANALYSIS;

        if skip_function_analysis {
            debug!(
                "File size {} MB > 20 MB, skipping function analysis but extracting strings for stng",
                file_size / 1024 / 1024
            );
        }

        // SINGLE r2 spawn with ALL data extraction
        // Commands separated by "echo SEP" for parsing:
        // - aa: analyze (only for small binaries)
        // - aflj: functions as JSON
        // - iSj: sections as JSON
        // - izj: strings as JSON
        let command = if skip_function_analysis {
            // Large binary: skip function analysis (aa/aflj) but keep string extraction (izj)
            // String extraction is slow but cached, and provides additional context to stng
            "iSj; echo SEP; izj"
        } else {
            // Small binary: full analysis + all data
            "aa; aflj; echo SEP; iSj; echo SEP; izj"
        };

        trace!("Executing rizin with command: {}", command);

        let output = Command::new("rizin")
            .arg("-q")
            .arg("-e")
            .arg("scr.color=0")
            .arg("-e")
            .arg("log.level=0")
            .arg("-c")
            .arg(command)
            .arg(file_path)
            .output()
            .context("Failed to execute radare2")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("radare2 exited with status {}: {}", output.status, stderr);
            anyhow::bail!("radare2 failed with status {}: {}", output.status, stderr);
        }

        debug!("radare2 completed successfully");

        let output_str = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = output_str.split("SEP").collect();

        // Helper to parse JSON from a part
        let parse_json = |part: Option<&&str>| -> Option<String> {
            part.and_then(|p| {
                let start = p.find('[')?;
                let end = p.rfind(']')?;
                Some(p[start..=end].to_string())
            })
        };

        let (functions, sections, strings) = if skip_function_analysis {
            // Large binary: sections and strings (no functions)
            // String extraction is slow but cached, provides context for stng deduplication
            let sections: Vec<R2Section> = parse_json(parts.first())
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();
            let strings: Vec<R2String> = parse_json(parts.get(1))
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();
            (Vec::new(), sections, strings)
        } else {
            // Small binary: functions, sections, strings
            let functions: Vec<R2Function> = parse_json(parts.first())
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();
            let sections: Vec<R2Section> = parse_json(parts.get(1))
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();
            let strings: Vec<R2String> = parse_json(parts.get(2))
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();
            (functions, sections, strings)
        };

        let result = BatchedAnalysis {
            functions,
            sections,
            strings,
        };

        // Save to cache
        if let Some(ref hash) = sha256 {
            Self::save_to_cache(hash, &result);
        }

        Ok(result)
    }

    /// Compute binary metrics from pre-extracted batched analysis
    /// Much faster than compute_binary_metrics as it doesn't spawn new r2 processes
    pub fn compute_metrics_from_batched(&self, batched: &BatchedAnalysis) -> BinaryMetrics {
        use parsing::calculate_char_entropy;

        let mut metrics = BinaryMetrics {
            section_count: batched.sections.len() as u32,
            ..Default::default()
        };
        let mut entropies: Vec<f32> = Vec::new();
        let mut total_size: u64 = 0;
        let mut largest_size: u64 = 0;
        let mut section_name_chars: Vec<char> = Vec::new();
        let mut code_size: u64 = 0;

        for section in &batched.sections {
            metrics.section_count += 1;

            let entropy = section.entropy as f32;
            entropies.push(entropy);
            total_size += section.size;

            if section.size > largest_size {
                largest_size = section.size;
            }

            if let Some(ref perm) = section.perm {
                // Workaround for radare2 bug: __const sections are marked as r-x but should not be counted as code
                // Extract just the section name (after the last dot)
                let section_name = section.name.rsplit('.').next().unwrap_or(&section.name);
                let is_data_only = section_name == "__const"
                    || section_name == "__cstring"
                    || section_name == "__gcc_except_tab"
                    || section_name == "__unwind_info"
                    || section_name == "__eh_frame"
                    || section_name == "__rodata";

                if perm.contains('x') && !is_data_only {
                    metrics.executable_sections += 1;
                    code_size += section.size;
                }
                if perm.contains('w') {
                    metrics.writable_sections += 1;
                }
                if perm.contains('x') && perm.contains('w') {
                    metrics.wx_sections += 1;
                }
            }

            if entropy > 7.5 {
                metrics.high_entropy_regions += 1;
            }

            section_name_chars.extend(section.name.chars());

            if section.name == ".text" || section.name.contains("code") {
                metrics.code_entropy = entropy;
            }
            if section.name == ".data" || section.name == ".rodata" {
                metrics.data_entropy = entropy;
            }
        }

        if !entropies.is_empty() {
            metrics.overall_entropy = entropies.iter().sum::<f32>() / entropies.len() as f32;
            let mean = metrics.overall_entropy;
            let variance: f32 =
                entropies.iter().map(|e| (e - mean).powi(2)).sum::<f32>() / entropies.len() as f32;
            metrics.entropy_variance = variance.sqrt();
        }

        if !section_name_chars.is_empty() {
            metrics.section_name_entropy = calculate_char_entropy(&section_name_chars);
        }

        if total_size > 0 {
            metrics.largest_section_ratio = largest_size as f32 / total_size as f32;
        }

        // Size metrics
        metrics.file_size = total_size;
        metrics.code_size = code_size;
        if total_size > 0 {
            let data_size = total_size.saturating_sub(code_size);
            if data_size > 0 {
                metrics.code_to_data_ratio = code_size as f32 / data_size as f32;
            }
        }

        // Average section size
        if !batched.sections.is_empty() {
            metrics.avg_section_size = total_size as f32 / batched.sections.len() as f32;
        }

        // String metrics
        metrics.string_count = batched.strings.len() as u32;
        if !batched.strings.is_empty() {
            let mut total_length: u64 = 0;
            let mut max_length: u32 = 0;
            let mut wide_count: u32 = 0;

            for s in &batched.strings {
                let len = s.string.len() as u32;
                total_length += len as u64;
                if len > max_length {
                    max_length = len;
                }
                // Check if wide string (type contains "wide" or "utf16")
                if s.string_type.to_lowercase().contains("wide")
                    || s.string_type.to_lowercase().contains("utf16")
                {
                    wide_count += 1;
                }
            }

            metrics.avg_string_length = total_length as f32 / batched.strings.len() as f32;
            metrics.max_string_length = max_length;
            metrics.wide_string_count = wide_count;
        }

        // Function metrics
        metrics.function_count = batched.functions.len() as u32;

        let mut complexities: Vec<u32> = Vec::new();
        let mut bb_counts: Vec<u32> = Vec::new();
        let mut edge_counts: Vec<u32> = Vec::new();

        for func in &batched.functions {
            if let Some(cc) = func.complexity {
                complexities.push(cc);
            }
            if let Some(nbbs) = func.nbbs {
                bb_counts.push(nbbs);
            }
            if let Some(edges) = func.edges {
                edge_counts.push(edges);
            }
        }

        if !complexities.is_empty() {
            metrics.avg_complexity =
                complexities.iter().sum::<u32>() as f32 / complexities.len() as f32;
            metrics.max_complexity = *complexities.iter().max().unwrap_or(&0);
        }

        if !bb_counts.is_empty() {
            metrics.avg_basic_blocks =
                bb_counts.iter().sum::<u32>() as f32 / bb_counts.len() as f32;
            metrics.total_basic_blocks = bb_counts.iter().sum::<u32>();
        }

        // Note: edge_counts collected but not used (no avg_cfg_edges field in BinaryMetrics)
        let _ = edge_counts;

        // Compute ratio metrics (these depend on multiple fields)
        Self::compute_ratio_metrics(&mut metrics);

        metrics
    }

    /// Compute ratio and normalized metrics from already-populated base metrics
    /// This should be called after all base counters are set
    pub fn compute_ratio_metrics(metrics: &mut BinaryMetrics) {
        let code_kb = metrics.code_size as f32 / 1024.0;

        // Density ratios (per KB of code)
        if code_kb > 0.0 {
            metrics.import_density = metrics.import_count as f32 / code_kb;
            metrics.string_density = metrics.string_count as f32 / code_kb;
            metrics.function_density = metrics.function_count as f32 / code_kb;
            metrics.relocation_density = metrics.relocation_count as f32 / code_kb;
            metrics.complexity_per_kb = metrics.avg_complexity * 1024.0 / metrics.code_size as f32;
        }

        // Export to import ratio
        if metrics.import_count > 0 {
            metrics.export_to_import_ratio =
                metrics.export_count as f32 / metrics.import_count as f32;
        }

        // Normalized metrics (size-independent)
        if metrics.file_size > 0 {
            let file_size_sqrt = (metrics.file_size as f32).sqrt();
            metrics.normalized_import_count = metrics.import_count as f32 / file_size_sqrt;
            metrics.normalized_export_count = metrics.export_count as f32 / file_size_sqrt;

            let file_size_log = (metrics.file_size as f32).log2();
            if file_size_log > 0.0 {
                metrics.normalized_section_count = metrics.section_count as f32 / file_size_log;
            }
        }

        if metrics.code_size > 0 {
            let code_size_sqrt = (metrics.code_size as f32).sqrt();
            metrics.normalized_string_count = metrics.string_count as f32 / code_size_sqrt;
        }

        // Code section ratio
        if metrics.section_count > 0 {
            metrics.code_section_ratio =
                metrics.executable_sections as f32 / metrics.section_count as f32;
        }
    }

    /// Compute binary metrics by running fresh radare2 analysis
    /// Slower than compute_metrics_from_batched - prefer that when possible
    pub fn compute_binary_metrics(&self, file_path: &Path) -> Result<BinaryMetrics> {
        let batched = self.extract_batched(file_path)?;
        Ok(self.compute_metrics_from_batched(&batched))
    }
}

impl Default for Radare2Analyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let analyzer = Radare2Analyzer::default();
        assert_eq!(analyzer.timeout_seconds, 30);
    }

    #[test]
    fn test_new() {
        let analyzer = Radare2Analyzer::new();
        assert_eq!(analyzer.timeout_seconds, 30);
    }

    #[test]
    fn test_syscall_info_serialize() {
        let info = SyscallInfo {
            address: 0x1000,
            number: 1,
            name: "write".to_string(),
            desc: "Write to file descriptor".to_string(),
            arch: "x86_64".to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("write"));
        assert!(json.contains("0x1000") || json.contains("4096")); // address can be in different formats

        let deserialized: SyscallInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.number, 1);
        assert_eq!(deserialized.name, "write");
    }

    #[test]
    fn test_compute_metrics_sets_file_size() {
        use crate::radare2::models::R2Section;

        let analyzer = Radare2Analyzer::new();

        // Create batched analysis with sections of known sizes
        let batched = BatchedAnalysis {
            functions: vec![],
            sections: vec![
                R2Section {
                    name: ".text".to_string(),
                    size: 1000,
                    vsize: Some(1000),
                    perm: Some("r-x".to_string()),
                    entropy: 6.5,
                },
                R2Section {
                    name: ".data".to_string(),
                    size: 500,
                    vsize: Some(500),
                    perm: Some("rw-".to_string()),
                    entropy: 4.0,
                },
                R2Section {
                    name: ".rodata".to_string(),
                    size: 300,
                    vsize: Some(300),
                    perm: Some("r--".to_string()),
                    entropy: 5.0,
                },
            ],
            strings: vec![],
        };

        let metrics = analyzer.compute_metrics_from_batched(&batched);

        // file_size should be the sum of all section sizes
        assert_eq!(
            metrics.file_size, 1800,
            "file_size should equal sum of section sizes"
        );

        // code_size should be the size of executable sections only
        assert_eq!(
            metrics.code_size, 1000,
            "code_size should equal size of .text section"
        );

        // code_size should never exceed file_size
        assert!(
            metrics.code_size <= metrics.file_size,
            "code_size ({}) should never exceed file_size ({})",
            metrics.code_size,
            metrics.file_size
        );
    }
}
