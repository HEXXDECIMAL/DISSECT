use crate::types::Function;
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
            .arg("-c")
            .arg("aaa; aflj")  // Analyze all, list functions as JSON
            .arg(file_path)
            .output()
            .context("Failed to execute radare2")?;

        if !output.status.success() {
            return Ok(Vec::new()); // Return empty if analysis fails
        }

        let json_str = String::from_utf8_lossy(&output.stdout);
        let r2_functions: Vec<R2Function> = serde_json::from_str(&json_str)
            .unwrap_or_default();

        Ok(r2_functions.into_iter().map(|f| f.into()).collect())
    }

    /// Extract strings from binary
    pub fn extract_strings(&self, file_path: &Path) -> Result<Vec<R2String>> {
        let output = Command::new("r2")
            .arg("-q")
            .arg("-c")
            .arg("izj")  // List strings as JSON
            .arg(file_path)
            .output()
            .context("Failed to execute radare2")?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let json_str = String::from_utf8_lossy(&output.stdout);
        let strings: Vec<R2String> = serde_json::from_str(&json_str)
            .unwrap_or_default();

        Ok(strings)
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
    pub offset: u64,
    pub size: Option<u64>,
    #[serde(rename = "cc")]
    pub complexity: Option<u32>,  // Cyclomatic complexity
    #[serde(default)]
    pub calls: Vec<R2Call>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct R2Call {
    pub name: String,
}

impl From<R2Function> for Function {
    fn from(r2_func: R2Function) -> Self {
        Function {
            name: r2_func.name,
            offset: Some(format!("0x{:x}", r2_func.offset)),
            size: r2_func.size,
            complexity: r2_func.complexity,
            calls: r2_func.calls.into_iter().map(|c| c.name).collect(),
            source: "radare2".to_string(),
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
