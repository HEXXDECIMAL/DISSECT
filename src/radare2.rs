use crate::syscall_names::{syscall_description, syscall_name};
use crate::types::{ControlFlowMetrics, Function, FunctionProperties, InstructionAnalysis};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

/// Global flag to disable radare2 analysis
static RADARE2_DISABLED: AtomicBool = AtomicBool::new(false);

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
    pub description: String,
    /// Architecture (e.g., "x86", "x86_64", "mips", "arm")
    pub arch: String,
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
    pub fn is_available() -> bool {
        if is_disabled() {
            return false;
        }
        Command::new("r2").arg("-v").output().is_ok()
    }

    /// Extract functions with complexity metrics
    pub fn extract_functions(&self, file_path: &Path) -> Result<Vec<Function>> {
        let output = Command::new("r2")
            .arg("-q")
            .arg("-e")
            .arg("scr.color=0") // Disable ANSI colors
            .arg("-e")
            .arg("log.level=0") // Disable log messages
            .arg("-c")
            .arg("aaa; aflj") // Analyze all, list functions as JSON
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

            return Ok(r2_functions.into_iter().map(|f| f.into()).collect());
        }

        Ok(Vec::new())
    }

    /// Extract strings from binary
    pub fn extract_strings(&self, file_path: &Path) -> Result<Vec<R2String>> {
        let output = Command::new("r2")
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
        let output = Command::new("r2")
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
        let output = Command::new("r2")
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
        let output = Command::new("r2")
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

    /// Extract syscalls from binary using architecture-aware analysis
    /// Returns detected syscalls with their numbers and resolved names
    pub fn extract_syscalls(&self, file_path: &Path) -> Result<Vec<SyscallInfo>> {
        // Get architecture info first
        let arch = self.get_architecture(file_path)?;
        if arch.is_empty() {
            return Ok(Vec::new());
        }

        // Find syscall instruction addresses based on architecture
        let syscall_addrs = self.find_syscall_instructions(file_path, &arch)?;
        if syscall_addrs.is_empty() {
            return Ok(Vec::new());
        }

        // For each syscall instruction, try to resolve the syscall number
        let mut syscalls = Vec::new();
        for addr in syscall_addrs {
            if let Some(num) = self.find_syscall_number(file_path, &arch, addr)? {
                let name = syscall_name(&arch, num);
                let description = syscall_description(&name);
                syscalls.push(SyscallInfo {
                    address: addr,
                    number: num,
                    name,
                    description,
                    arch: arch.clone(),
                });
            }
        }

        Ok(syscalls)
    }

    /// Get architecture string from binary
    fn get_architecture(&self, file_path: &Path) -> Result<String> {
        let output = Command::new("r2")
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
            "x86" => "/x cd80",               // int 0x80
            "x86_64" => "/x 0f05",            // syscall
            "arm" => "/x 00 00 00 ef",        // svc #0 (ARM mode)
            "aarch64" => "/x 01 00 00 d4",    // svc #0 (AArch64)
            "mips" => "/x 00 00 00 0c",       // syscall (big-endian)
            "ppc" => "/x 44 00 00 02",        // sc
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

        let output = Command::new("r2")
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
            let alt_output = Command::new("r2")
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
        let output = Command::new("r2")
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

        // Parse based on architecture
        match arch {
            "mips" => {
                // MIPS o32: syscall number in v0 ($2)
                // Look for: addiu v0, zero, 0xNNN or li v0, 0xNNN
                for line in disasm.lines().rev() {
                    let line_lower = line.to_lowercase();
                    if (line_lower.contains("addiu") || line_lower.contains("li"))
                        && (line_lower.contains("v0") || line_lower.contains("$2"))
                    {
                        if let Some(num) = extract_hex_or_decimal(line) {
                            // MIPS o32 syscalls start at 4000, n32/n64 at 6000
                            if (4000..6000).contains(&num) || (6000..8000).contains(&num) {
                                return Ok(Some(num));
                            }
                        }
                    }
                }
            }
            "x86" | "x86_64" => {
                // x86: syscall number in eax/rax
                // Look for: mov eax, NNN or mov rax, NNN
                for line in disasm.lines().rev() {
                    let line_lower = line.to_lowercase();
                    if line_lower.contains("mov")
                        && (line_lower.contains("eax") || line_lower.contains("rax"))
                    {
                        if let Some(num) = extract_hex_or_decimal(line) {
                            // Reasonable syscall number range
                            if num < 1000 {
                                return Ok(Some(num));
                            }
                        }
                    }
                }
            }
            "arm" | "aarch64" => {
                // ARM32: syscall number in r7
                // AArch64: syscall number in x8
                let reg = if arch == "arm" { "r7" } else { "x8" };
                for line in disasm.lines().rev() {
                    let line_lower = line.to_lowercase();
                    if line_lower.contains("mov") && line_lower.contains(reg) {
                        if let Some(num) = extract_hex_or_decimal(line) {
                            if num < 1000 {
                                return Ok(Some(num));
                            }
                        }
                    }
                }
            }
            "ppc" => {
                // PowerPC: syscall number in r0
                for line in disasm.lines().rev() {
                    let line_lower = line.to_lowercase();
                    if line_lower.contains("li") && line_lower.contains("r0") {
                        if let Some(num) = extract_hex_or_decimal(line) {
                            if num < 1000 {
                                return Ok(Some(num));
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        Ok(None)
    }
}

/// Parse radare2 search results to extract addresses
fn parse_search_results(output: &str) -> Vec<u64> {
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
fn extract_hex_or_decimal(line: &str) -> Option<u32> {
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

impl Default for Radare2Analyzer {
    fn default() -> Self {
        Self::new()
    }
}

// Radare2 JSON output structures

#[derive(Debug, Deserialize, Serialize)]
pub struct R2Function {
    pub name: String,
    #[serde(rename = "addr")]
    pub offset: u64,
    pub size: Option<u64>,
    #[serde(rename = "cc")]
    pub complexity: Option<u32>, // Cyclomatic complexity
    #[serde(default)]
    pub calls: Vec<R2Call>,

    // Additional fields from aflj (Phase 1: Free features!)
    #[serde(default)]
    pub nbbs: Option<u32>, // Number of basic blocks
    #[serde(default)]
    pub edges: Option<u32>, // Control flow edges
    #[serde(default)]
    pub ninstrs: Option<u32>, // Total instructions
    #[serde(default)]
    pub recursive: Option<bool>, // Is recursive
    #[serde(default)]
    pub noreturn: Option<bool>, // Doesn't return
    #[serde(default)]
    pub stackframe: Option<i32>, // Stack frame size
    #[serde(rename = "is-lineal", default)]
    pub is_lineal: Option<bool>, // No branches (straight-line code)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct R2Call {
    pub name: String,
}

impl From<R2Function> for Function {
    fn from(r2_func: R2Function) -> Self {
        use crate::types::InstructionCategories;

        // Build control flow metrics from aflj data
        let control_flow = if r2_func.nbbs.is_some() || r2_func.edges.is_some() {
            let nbbs = r2_func.nbbs.unwrap_or(1);
            let edges = r2_func.edges.unwrap_or(0);
            let ninstr = r2_func.ninstrs.unwrap_or(0);

            Some(ControlFlowMetrics {
                basic_blocks: nbbs,
                edges,
                cyclomatic_complexity: r2_func.complexity.unwrap_or(1),
                max_block_size: if nbbs > 0 { ninstr / nbbs } else { 0 },
                avg_block_size: if nbbs > 0 {
                    ninstr as f32 / nbbs as f32
                } else {
                    0.0
                },
                is_linear: r2_func.is_lineal.unwrap_or(false),
                loop_count: if edges >= nbbs { edges - nbbs + 1 } else { 0 },
                branch_density: if ninstr > 0 {
                    edges as f32 / ninstr as f32
                } else {
                    0.0
                },
                in_degree: 0, // Not available without call graph
                out_degree: r2_func.calls.len() as u32,
            })
        } else {
            None
        };

        // Build instruction analysis from aflj data
        let instruction_analysis = if r2_func.ninstrs.is_some() {
            Some(InstructionAnalysis {
                total_instructions: r2_func.ninstrs.unwrap_or(0),
                instruction_cost: r2_func.ninstrs.unwrap_or(0), // Rough estimate
                instruction_density: if let Some(size) = r2_func.size {
                    if size > 0 {
                        r2_func.ninstrs.unwrap_or(0) as f32 / size as f32
                    } else {
                        0.0
                    }
                } else {
                    0.0
                },
                categories: InstructionCategories {
                    arithmetic: 0,
                    logic: 0,
                    memory: 0,
                    control: r2_func.edges.unwrap_or(0),
                    system: 0,
                    fpu_simd: 0,
                    string_ops: 0,
                    privileged: 0,
                    crypto: 0,
                },
                top_opcodes: Vec::new(),          // Would need pdfj
                unusual_instructions: Vec::new(), // Would need pdfj
            })
        } else {
            None
        };

        // Build function properties from aflj data
        let properties = Some(FunctionProperties {
            is_pure: false, // Not in aflj
            is_noreturn: r2_func.noreturn.unwrap_or(false),
            is_recursive: r2_func.recursive.unwrap_or(false),
            stack_frame: r2_func.stackframe.unwrap_or(0).max(0) as u32,
            local_vars: 0, // Not in aflj
            args: 0,       // Not in aflj
            is_leaf: r2_func.calls.is_empty(),
        });

        Function {
            name: r2_func.name,
            offset: Some(format!("0x{:x}", r2_func.offset)),
            size: r2_func.size,
            complexity: r2_func.complexity,
            calls: r2_func.calls.into_iter().map(|c| c.name).collect(),
            source: "radare2".to_string(),
            control_flow,
            instruction_analysis,
            register_usage: None,  // Would need pdfj
            constants: Vec::new(), // Would need pdfj
            properties,
            call_patterns: None,
            nesting: None,
            signature: None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct R2String {
    pub vaddr: u64,
    pub paddr: u64,
    pub length: u32,
    pub size: u32,
    pub string: String,
    #[serde(rename = "type")]
    pub string_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct R2Import {
    pub name: String,
    #[serde(rename = "libname")]
    pub lib_name: Option<String>,
    pub ordinal: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct R2Export {
    pub name: String,
    pub vaddr: u64,
    pub paddr: u64,
    #[serde(rename = "type")]
    pub export_type: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct R2Section {
    pub name: String,
    pub size: u64,
    pub vsize: Option<u64>,
    pub perm: Option<String>,
    #[serde(default)]
    pub entropy: f64,
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
    fn test_r2_function_minimal_json() {
        let json = r#"{"name": "main", "addr": 4096}"#;
        let func: R2Function = serde_json::from_str(json).unwrap();
        assert_eq!(func.name, "main");
        assert_eq!(func.offset, 4096);
        assert_eq!(func.size, None);
        assert_eq!(func.complexity, None);
        assert!(func.calls.is_empty());
    }

    #[test]
    fn test_r2_function_full_json() {
        let json = r#"{
            "name": "calculate",
            "addr": 8192,
            "size": 256,
            "cc": 5,
            "nbbs": 10,
            "edges": 12,
            "ninstrs": 50,
            "recursive": true,
            "noreturn": false,
            "stackframe": 64,
            "is-lineal": false,
            "calls": [{"name": "helper1"}, {"name": "helper2"}]
        }"#;
        let func: R2Function = serde_json::from_str(json).unwrap();
        assert_eq!(func.name, "calculate");
        assert_eq!(func.offset, 8192);
        assert_eq!(func.size, Some(256));
        assert_eq!(func.complexity, Some(5));
        assert_eq!(func.nbbs, Some(10));
        assert_eq!(func.edges, Some(12));
        assert_eq!(func.ninstrs, Some(50));
        assert_eq!(func.recursive, Some(true));
        assert_eq!(func.noreturn, Some(false));
        assert_eq!(func.stackframe, Some(64));
        assert_eq!(func.is_lineal, Some(false));
        assert_eq!(func.calls.len(), 2);
        assert_eq!(func.calls[0].name, "helper1");
    }

    #[test]
    fn test_r2_function_to_function_minimal() {
        let r2_func = R2Function {
            name: "test".to_string(),
            offset: 4096,
            size: None,
            complexity: None,
            calls: vec![],
            nbbs: None,
            edges: None,
            ninstrs: None,
            recursive: None,
            noreturn: None,
            stackframe: None,
            is_lineal: None,
        };

        let func: Function = r2_func.into();
        assert_eq!(func.name, "test");
        assert_eq!(func.offset, Some("0x1000".to_string()));
        assert_eq!(func.source, "radare2");
        assert!(func.control_flow.is_none());
        assert!(func.instruction_analysis.is_none());
        assert!(func.properties.is_some());
    }

    #[test]
    fn test_r2_function_to_function_with_control_flow() {
        let r2_func = R2Function {
            name: "complex_func".to_string(),
            offset: 8192,
            size: Some(256),
            complexity: Some(5),
            calls: vec![R2Call {
                name: "helper".to_string(),
            }],
            nbbs: Some(10),
            edges: Some(12),
            ninstrs: Some(50),
            recursive: Some(true),
            noreturn: Some(false),
            stackframe: Some(64),
            is_lineal: Some(false),
        };

        let func: Function = r2_func.into();
        assert_eq!(func.name, "complex_func");

        let cf = func.control_flow.unwrap();
        assert_eq!(cf.basic_blocks, 10);
        assert_eq!(cf.edges, 12);
        assert_eq!(cf.cyclomatic_complexity, 5);
        assert_eq!(cf.max_block_size, 5); // 50 / 10
        assert_eq!(cf.avg_block_size, 5.0);
        assert!(!cf.is_linear);
        assert_eq!(cf.loop_count, 3); // 12 - 10 + 1
        assert_eq!(cf.out_degree, 1);

        let ia = func.instruction_analysis.unwrap();
        assert_eq!(ia.total_instructions, 50);
        assert_eq!(ia.instruction_cost, 50);
        assert!((ia.instruction_density - 0.1953).abs() < 0.001); // 50 / 256

        let props = func.properties.unwrap();
        assert!(props.is_recursive);
        assert!(!props.is_noreturn);
        assert_eq!(props.stack_frame, 64);
        assert!(!props.is_leaf);
    }

    #[test]
    fn test_r2_function_linear_code() {
        let r2_func = R2Function {
            name: "linear".to_string(),
            offset: 1000,
            size: Some(100),
            complexity: Some(1),
            calls: vec![],
            nbbs: Some(1),
            edges: Some(0),
            ninstrs: Some(20),
            recursive: None,
            noreturn: None,
            stackframe: None,
            is_lineal: Some(true),
        };

        let func: Function = r2_func.into();
        let cf = func.control_flow.unwrap();
        assert!(cf.is_linear);
        assert_eq!(cf.loop_count, 0);
        assert_eq!(cf.basic_blocks, 1);
        assert_eq!(cf.edges, 0);
    }

    #[test]
    fn test_r2_function_no_instructions() {
        let r2_func = R2Function {
            name: "empty".to_string(),
            offset: 2000,
            size: Some(0),
            complexity: None,
            calls: vec![],
            nbbs: Some(0),
            edges: Some(0),
            ninstrs: Some(0),
            recursive: None,
            noreturn: None,
            stackframe: None,
            is_lineal: None,
        };

        let func: Function = r2_func.into();
        let cf = func.control_flow.unwrap();
        assert_eq!(cf.max_block_size, 0);
        assert_eq!(cf.avg_block_size, 0.0);
        assert_eq!(cf.branch_density, 0.0);
    }

    #[test]
    fn test_r2_function_negative_stackframe() {
        let r2_func = R2Function {
            name: "negative_stack".to_string(),
            offset: 3000,
            size: None,
            complexity: None,
            calls: vec![],
            nbbs: None,
            edges: None,
            ninstrs: None,
            recursive: None,
            noreturn: None,
            stackframe: Some(-10),
            is_lineal: None,
        };

        let func: Function = r2_func.into();
        let props = func.properties.unwrap();
        assert_eq!(props.stack_frame, 0); // Negative values become 0
    }

    #[test]
    fn test_r2_string_json() {
        let json = r#"{
            "vaddr": 4096,
            "paddr": 2048,
            "length": 11,
            "size": 12,
            "string": "hello world",
            "type": "ascii"
        }"#;
        let s: R2String = serde_json::from_str(json).unwrap();
        assert_eq!(s.vaddr, 4096);
        assert_eq!(s.paddr, 2048);
        assert_eq!(s.length, 11);
        assert_eq!(s.size, 12);
        assert_eq!(s.string, "hello world");
        assert_eq!(s.string_type, "ascii");
    }

    #[test]
    fn test_r2_import_minimal_json() {
        let json = r#"{"name": "printf"}"#;
        let import: R2Import = serde_json::from_str(json).unwrap();
        assert_eq!(import.name, "printf");
        assert_eq!(import.lib_name, None);
        assert_eq!(import.ordinal, None);
    }

    #[test]
    fn test_r2_import_full_json() {
        let json = r#"{
            "name": "printf",
            "libname": "libc.so.6",
            "ordinal": 42
        }"#;
        let import: R2Import = serde_json::from_str(json).unwrap();
        assert_eq!(import.name, "printf");
        assert_eq!(import.lib_name, Some("libc.so.6".to_string()));
        assert_eq!(import.ordinal, Some(42));
    }

    #[test]
    fn test_r2_export_minimal_json() {
        let json = r#"{
            "name": "my_function",
            "vaddr": 8192,
            "paddr": 4096
        }"#;
        let export: R2Export = serde_json::from_str(json).unwrap();
        assert_eq!(export.name, "my_function");
        assert_eq!(export.vaddr, 8192);
        assert_eq!(export.paddr, 4096);
        assert_eq!(export.export_type, None);
    }

    #[test]
    fn test_r2_export_with_type() {
        let json = r#"{
            "name": "exported_func",
            "vaddr": 12288,
            "paddr": 8192,
            "type": "FUNC"
        }"#;
        let export: R2Export = serde_json::from_str(json).unwrap();
        assert_eq!(export.name, "exported_func");
        assert_eq!(export.export_type, Some("FUNC".to_string()));
    }

    #[test]
    fn test_r2_section_minimal_json() {
        let json = r#"{
            "name": ".text",
            "size": 4096
        }"#;
        let section: R2Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.name, ".text");
        assert_eq!(section.size, 4096);
        assert_eq!(section.vsize, None);
        assert_eq!(section.perm, None);
        assert_eq!(section.entropy, 0.0); // Default
    }

    #[test]
    fn test_r2_section_full_json() {
        let json = r#"{
            "name": ".data",
            "size": 2048,
            "vsize": 4096,
            "perm": "rw-",
            "entropy": 7.95
        }"#;
        let section: R2Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.name, ".data");
        assert_eq!(section.size, 2048);
        assert_eq!(section.vsize, Some(4096));
        assert_eq!(section.perm, Some("rw-".to_string()));
        assert_eq!(section.entropy, 7.95);
    }

    #[test]
    fn test_r2_function_branch_density_calculation() {
        let r2_func = R2Function {
            name: "branchy".to_string(),
            offset: 5000,
            size: Some(200),
            complexity: Some(8),
            calls: vec![],
            nbbs: Some(15),
            edges: Some(20),
            ninstrs: Some(100),
            recursive: None,
            noreturn: None,
            stackframe: None,
            is_lineal: Some(false),
        };

        let func: Function = r2_func.into();
        let cf = func.control_flow.unwrap();
        assert_eq!(cf.branch_density, 0.2); // 20 / 100
    }

    #[test]
    fn test_r2_function_leaf_function() {
        let r2_func = R2Function {
            name: "leaf".to_string(),
            offset: 6000,
            size: Some(50),
            complexity: Some(1),
            calls: vec![],
            nbbs: Some(1),
            edges: Some(0),
            ninstrs: Some(10),
            recursive: None,
            noreturn: None,
            stackframe: None,
            is_lineal: Some(true),
        };

        let func: Function = r2_func.into();
        let props = func.properties.unwrap();
        assert!(props.is_leaf);
    }

    #[test]
    fn test_r2_function_non_leaf_function() {
        let r2_func = R2Function {
            name: "caller".to_string(),
            offset: 7000,
            size: Some(100),
            complexity: Some(2),
            calls: vec![
                R2Call {
                    name: "callee1".to_string(),
                },
                R2Call {
                    name: "callee2".to_string(),
                },
            ],
            nbbs: Some(5),
            edges: Some(6),
            ninstrs: Some(30),
            recursive: None,
            noreturn: None,
            stackframe: None,
            is_lineal: None,
        };

        let func: Function = r2_func.into();
        let props = func.properties.unwrap();
        assert!(!props.is_leaf);
        assert_eq!(func.calls.len(), 2);
        assert_eq!(func.calls[0], "callee1");
        assert_eq!(func.calls[1], "callee2");
    }

    #[test]
    fn test_r2_function_offset_formatting() {
        let r2_func = R2Function {
            name: "test".to_string(),
            offset: 0xdeadbeef,
            size: None,
            complexity: None,
            calls: vec![],
            nbbs: None,
            edges: None,
            ninstrs: None,
            recursive: None,
            noreturn: None,
            stackframe: None,
            is_lineal: None,
        };

        let func: Function = r2_func.into();
        assert_eq!(func.offset, Some("0xdeadbeef".to_string()));
    }

    #[test]
    fn test_r2_function_array_deserialization() {
        let json = r#"[
            {"name": "func1", "addr": 1000},
            {"name": "func2", "addr": 2000}
        ]"#;
        let funcs: Vec<R2Function> = serde_json::from_str(json).unwrap();
        assert_eq!(funcs.len(), 2);
        assert_eq!(funcs[0].name, "func1");
        assert_eq!(funcs[1].name, "func2");
    }

    #[test]
    fn test_syscall_info_serialize() {
        let syscall = SyscallInfo {
            address: 0x400123,
            number: 4004,
            name: "write".to_string(),
            description: "writes to file".to_string(),
            arch: "mips".to_string(),
        };
        let json = serde_json::to_string(&syscall).unwrap();
        assert!(json.contains("\"address\":4194595"));
        assert!(json.contains("\"number\":4004"));
        assert!(json.contains("\"name\":\"write\""));
        assert!(json.contains("\"description\":\"writes to file\""));
        assert!(json.contains("\"arch\":\"mips\""));
    }

    #[test]
    fn test_parse_search_results_valid() {
        let output = "0x00400123 hit0_0 cd80\n0x00400456 hit0_1 cd80\n";
        let addrs = parse_search_results(output);
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], 0x400123);
        assert_eq!(addrs[1], 0x400456);
    }

    #[test]
    fn test_parse_search_results_empty() {
        let output = "";
        let addrs = parse_search_results(output);
        assert!(addrs.is_empty());
    }

    #[test]
    fn test_parse_search_results_no_hex() {
        let output = "No results found\n";
        let addrs = parse_search_results(output);
        assert!(addrs.is_empty());
    }

    #[test]
    fn test_extract_hex_or_decimal_hex() {
        let line = "mov eax, 0x3b";
        let num = extract_hex_or_decimal(line);
        assert_eq!(num, Some(59)); // 0x3b = 59
    }

    #[test]
    fn test_extract_hex_or_decimal_decimal() {
        let line = "addiu v0, zero, 4004";
        let num = extract_hex_or_decimal(line);
        assert_eq!(num, Some(4004));
    }

    #[test]
    fn test_extract_hex_or_decimal_none() {
        let line = "nop";
        let num = extract_hex_or_decimal(line);
        assert_eq!(num, None);
    }

    #[test]
    fn test_extract_hex_or_decimal_large_number_filtered() {
        // Large numbers (addresses) should be filtered out
        let line = "call 0x401234";
        let num = extract_hex_or_decimal(line);
        // 0x401234 = 4198964 which is > 10000, so it should be filtered
        assert_eq!(num, None);
    }

    #[test]
    fn test_extract_hex_or_decimal_mips_disasm() {
        // Test MIPS disassembly line - should extract the operand, not the address
        let line = "0x0040b730      24020fd7       addiu v0, zero, 0xfd7";
        let num = extract_hex_or_decimal(line);
        // 0xfd7 = 4055 which is a MIPS syscall number
        assert_eq!(num, Some(0xfd7));
    }

    #[test]
    fn test_extract_hex_or_decimal_x86_disasm() {
        // Test x86 disassembly line
        let line = "0x00401234      mov eax, 0x3b";
        let num = extract_hex_or_decimal(line);
        // 0x3b = 59 (execve on x86_64)
        assert_eq!(num, Some(0x3b));
    }
}
