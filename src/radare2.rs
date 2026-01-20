use crate::types::{Function, ControlFlowMetrics, InstructionAnalysis, FunctionProperties};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

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

    /// Check if radare2 is available
    pub fn is_available() -> bool {
        Command::new("r2").arg("-v").output().is_ok()
    }

    /// Extract functions with complexity metrics
    pub fn extract_functions(&self, file_path: &Path) -> Result<Vec<Function>> {
        let output = Command::new("r2")
            .arg("-q")
            .arg("-e")
            .arg("scr.color=0")  // Disable ANSI colors
            .arg("-e")
            .arg("log.level=0")  // Disable log messages
            .arg("-c")
            .arg("aaa; aflj")  // Analyze all, list functions as JSON
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
            let r2_functions: Vec<R2Function> = serde_json::from_str(json_only)
                .unwrap_or_default();

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
            .arg("izj")  // List strings as JSON
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
            let strings: Vec<R2String> = serde_json::from_str(json_only)
                .unwrap_or_default();
            return Ok(strings);
        }

        Ok(Vec::new())
    }

    /// Extract imports
    pub fn extract_imports(&self, file_path: &Path) -> Result<Vec<R2Import>> {
        let output = Command::new("r2")
            .arg("-q")
            .arg("-c")
            .arg("iij")  // List imports as JSON
            .arg(file_path)
            .output()
            .context("Failed to execute radare2")?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let json_str = String::from_utf8_lossy(&output.stdout);
        let imports: Vec<R2Import> = serde_json::from_str(&json_str)
            .unwrap_or_default();

        Ok(imports)
    }

    /// Extract exports
    pub fn extract_exports(&self, file_path: &Path) -> Result<Vec<R2Export>> {
        let output = Command::new("r2")
            .arg("-q")
            .arg("-c")
            .arg("iEj")  // List exports as JSON
            .arg(file_path)
            .output()
            .context("Failed to execute radare2")?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let json_str = String::from_utf8_lossy(&output.stdout);
        let exports: Vec<R2Export> = serde_json::from_str(&json_str)
            .unwrap_or_default();

        Ok(exports)
    }

    /// Extract section information with entropy
    pub fn extract_sections(&self, file_path: &Path) -> Result<Vec<R2Section>> {
        let output = Command::new("r2")
            .arg("-q")
            .arg("-c")
            .arg("iSj")  // List sections as JSON
            .arg(file_path)
            .output()
            .context("Failed to execute radare2")?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let json_str = String::from_utf8_lossy(&output.stdout);
        let sections: Vec<R2Section> = serde_json::from_str(&json_str)
            .unwrap_or_default();

        Ok(sections)
    }
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
    pub complexity: Option<u32>,  // Cyclomatic complexity
    #[serde(default)]
    pub calls: Vec<R2Call>,

    // Additional fields from aflj (Phase 1: Free features!)
    #[serde(default)]
    pub nbbs: Option<u32>,  // Number of basic blocks
    #[serde(default)]
    pub edges: Option<u32>,  // Control flow edges
    #[serde(default)]
    pub ninstrs: Option<u32>,  // Total instructions
    #[serde(default)]
    pub recursive: Option<bool>,  // Is recursive
    #[serde(default)]
    pub noreturn: Option<bool>,  // Doesn't return
    #[serde(default)]
    pub stackframe: Option<i32>,  // Stack frame size
    #[serde(rename = "is-lineal", default)]
    pub is_lineal: Option<bool>,  // No branches (straight-line code)
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
                avg_block_size: if nbbs > 0 { ninstr as f32 / nbbs as f32 } else { 0.0 },
                is_linear: r2_func.is_lineal.unwrap_or(false),
                loop_count: if edges >= nbbs { edges - nbbs + 1 } else { 0 },
                branch_density: if ninstr > 0 { edges as f32 / ninstr as f32 } else { 0.0 },
                in_degree: 0,  // Not available without call graph
                out_degree: r2_func.calls.len() as u32,
            })
        } else {
            None
        };

        // Build instruction analysis from aflj data
        let instruction_analysis = if r2_func.ninstrs.is_some() {
            Some(InstructionAnalysis {
                total_instructions: r2_func.ninstrs.unwrap_or(0),
                instruction_cost: r2_func.ninstrs.unwrap_or(0),  // Rough estimate
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
                top_opcodes: Vec::new(),  // Would need pdfj
                unusual_instructions: Vec::new(),  // Would need pdfj
            })
        } else {
            None
        };

        // Build function properties from aflj data
        let properties = Some(FunctionProperties {
            is_pure: false,  // Not in aflj
            is_noreturn: r2_func.noreturn.unwrap_or(false),
            is_recursive: r2_func.recursive.unwrap_or(false),
            stack_frame: r2_func.stackframe.unwrap_or(0).max(0) as u32,
            local_vars: 0,  // Not in aflj
            args: 0,  // Not in aflj
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
            constants: Vec::new(),  // Would need pdfj
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
