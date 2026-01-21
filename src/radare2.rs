use crate::types::{ControlFlowMetrics, Function, FunctionProperties, InstructionAnalysis};
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
        assert_eq!(cf.is_linear, false);
        assert_eq!(cf.loop_count, 3); // 12 - 10 + 1
        assert_eq!(cf.out_degree, 1);

        let ia = func.instruction_analysis.unwrap();
        assert_eq!(ia.total_instructions, 50);
        assert_eq!(ia.instruction_cost, 50);
        assert!((ia.instruction_density - 0.1953).abs() < 0.001); // 50 / 256

        let props = func.properties.unwrap();
        assert_eq!(props.is_recursive, true);
        assert_eq!(props.is_noreturn, false);
        assert_eq!(props.stack_frame, 64);
        assert_eq!(props.is_leaf, false);
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
        assert_eq!(cf.is_linear, true);
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
        assert_eq!(props.is_leaf, true);
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
        assert_eq!(props.is_leaf, false);
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
}
