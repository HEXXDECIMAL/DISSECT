//! PE (Portable Executable) analyzer for Windows binaries.

use crate::analyzers::Analyzer;
use crate::capabilities::CapabilityMapper;
use crate::entropy::{calculate_entropy, EntropyLevel};
use crate::radare2::Radare2Analyzer;
use crate::strings::StringExtractor;
use crate::types::*;
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use goblin::pe::PE;
use std::fs;
use std::path::Path;

/// Analyzer for Windows PE binaries (executables, DLLs, drivers)
pub struct PEAnalyzer {
    capability_mapper: CapabilityMapper,
    radare2: Radare2Analyzer,
    string_extractor: StringExtractor,
    yara_engine: Option<YaraEngine>,
}

impl PEAnalyzer {
    /// Creates a new PE analyzer with default configuration
    pub fn new() -> Self {
        Self {
            capability_mapper: CapabilityMapper::empty(),
            radare2: Radare2Analyzer::new(),
            string_extractor: StringExtractor::new(),
            yara_engine: None,
        }
    }

    /// Create analyzer with YARA rules loaded
    pub fn with_yara(mut self, yara_engine: YaraEngine) -> Self {
        self.yara_engine = Some(yara_engine);
        self
    }

    /// Create analyzer with pre-existing capability mapper (avoids duplicate loading)
    pub fn with_capability_mapper(mut self, capability_mapper: CapabilityMapper) -> Self {
        self.capability_mapper = capability_mapper;
        self
    }

    fn analyze_pe(&self, file_path: &Path, data: &[u8]) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse with goblin
        let pe = PE::parse(data)?;

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "pe".to_string(),
            size_bytes: data.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(data),
            architectures: Some(vec![self.arch_name(&pe)]),
        };

        let mut report = AnalysisReport::new(target);
        let mut tools_used = vec!["goblin".to_string()];

        // Analyze header and structure
        self.analyze_structure(&pe, &mut report)?;

        // Extract imports and map to capabilities
        self.analyze_imports(&pe, &mut report)?;

        // Analyze exports
        self.analyze_exports(&pe, &mut report)?;

        // Analyze sections and entropy
        self.analyze_sections(&pe, data, &mut report)?;

        // Use radare2 for deep analysis if available - SINGLE r2 spawn for all data
        let r2_strings = if Radare2Analyzer::is_available() {
            tools_used.push("radare2".to_string());

            // Use batched extraction - single r2 session for functions, sections, strings, imports
            if let Ok(batched) = self.radare2.extract_batched(file_path) {
                // Compute metrics from batched data
                let binary_metrics = self.radare2.compute_metrics_from_batched(&batched);
                report.metrics = Some(Metrics {
                    binary: Some(binary_metrics),
                    ..Default::default()
                });

                // Convert R2Functions to Functions for the report
                report.functions = batched.functions.into_iter().map(Function::from).collect();

                // Use strings from batched data (no extra r2 spawn)
                Some(batched.strings)
            } else {
                None
            }
        } else {
            None
        };

        // Extract strings using language-aware extraction (Go/Rust) with pre-parsed PE
        report.strings = self.string_extractor.extract_from_pe(&pe, data, r2_strings);
        tools_used.push("strangs".to_string());

        // Run YARA scan if engine is loaded
        if let Some(yara_engine) = &self.yara_engine {
            if yara_engine.is_loaded() {
                tools_used.push("yara-x".to_string());
                // Filter for PE-specific rules
                let file_types = &["pe", "exe", "dll", "bat", "ps1"];
                match yara_engine.scan_bytes_filtered(data, Some(file_types)) {
                    Ok(matches) => {
                        report.yara_matches = matches.clone();

                        for yara_match in &matches {
                            if let Some(cap_id) = self
                                .capability_mapper
                                .yara_rule_to_capability(&yara_match.rule)
                            {
                                report.findings.push(Finding {
                                    kind: FindingKind::Capability,
                                    trait_refs: vec![],
                                    id: cap_id.clone(),
                                    desc: format!("Matched YARA rule: {}", yara_match.rule),
                                    conf: 0.95,
                                    crit: Criticality::Inert,
                                    mbc: None,
                                    attack: None,
                                    evidence: vec![Evidence {
                                        method: "yara".to_string(),
                                        source: "yara-x".to_string(),
                                        value: yara_match.rule.clone(),
                                        location: None,
                                    }],
                                });
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("YARA scan error: {:?}", e);
                    }
                }
            }
        }

        // Evaluate trait definitions from YAML
        let trait_findings = self.capability_mapper.evaluate_traits(&report, data);
        for f in trait_findings {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }

        // Evaluate composite rules (after traits are merged)
        let composite_findings = self
            .capability_mapper
            .evaluate_composite_rules(&report, data);
        for f in composite_findings {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = tools_used;

        Ok(report)
    }

    fn analyze_structure(&self, pe: &PE, report: &mut AnalysisReport) -> Result<()> {
        report.structure.push(StructuralFeature {
            id: "pe/header".to_string(),
            desc: format!(
                "PE file (machine: {}, subsystem: {:?})",
                self.arch_name(pe),
                pe.header
                    .optional_header
                    .as_ref()
                    .map(|h| h.windows_fields.subsystem)
            ),
            evidence: vec![Evidence {
                method: "header".to_string(),
                source: "goblin".to_string(),
                value: "PE".to_string(),
                location: None,
            }],
        });

        // Check if DLL
        if pe.is_lib {
            report.structure.push(StructuralFeature {
                id: "pe/dll".to_string(),
                desc: "Dynamic Link Library (DLL)".to_string(),
                evidence: vec![Evidence {
                    method: "header".to_string(),
                    source: "goblin".to_string(),
                    value: "DLL".to_string(),
                    location: None,
                }],
            });
        }

        // Check for .NET
        if pe.header.optional_header.is_some() {
            report.structure.push(StructuralFeature {
                id: "pe/optional_header".to_string(),
                desc: "Has optional header (standard Windows executable)".to_string(),
                evidence: vec![Evidence {
                    method: "header".to_string(),
                    source: "goblin".to_string(),
                    value: "OptionalHeader".to_string(),
                    location: None,
                }],
            });
        }

        Ok(())
    }

    fn analyze_imports(&self, pe: &PE, report: &mut AnalysisReport) -> Result<()> {
        for import in &pe.imports {
            report.imports.push(Import {
                symbol: import.name.to_string(),
                library: Some(import.dll.to_string()),
                source: "goblin".to_string(),
            });

            if let Some(capability) = self.capability_mapper.lookup(&import.name, "goblin") {
                if !report.findings.iter().any(|c| c.id == capability.id) {
                    report.findings.push(capability);
                }
            }
        }

        Ok(())
    }

    fn analyze_exports(&self, pe: &PE, report: &mut AnalysisReport) -> Result<()> {
        for export in &pe.exports {
            if let Some(name) = export.name {
                report.exports.push(Export {
                    symbol: name.to_string(),
                    offset: Some(format!("{:#x}", export.rva)),
                    source: "goblin".to_string(),
                });
            }
        }

        Ok(())
    }

    fn analyze_sections(&self, pe: &PE, data: &[u8], report: &mut AnalysisReport) -> Result<()> {
        for section in &pe.sections {
            let name = String::from_utf8_lossy(&section.name).to_string();
            let size = section.size_of_raw_data as u64;
            let offset = section.pointer_to_raw_data as u64;

            let characteristics = section.characteristics;
            let is_executable = (characteristics & 0x20000000) != 0;
            let is_writable = (characteristics & 0x80000000) != 0;
            let is_readable = (characteristics & 0x40000000) != 0;

            let permissions = format!(
                "{}{}{}",
                if is_readable { "r" } else { "-" },
                if is_writable { "w" } else { "-" },
                if is_executable { "x" } else { "-" }
            );

            let entropy = if offset < data.len() as u64 {
                let end = ((offset + size) as usize).min(data.len());
                let section_data = &data[offset as usize..end];
                calculate_entropy(section_data)
            } else {
                0.0
            };

            let entropy_level = if entropy > 7.2 {
                EntropyLevel::High
            } else if entropy > 6.0 {
                EntropyLevel::Elevated
            } else if entropy > 4.0 {
                EntropyLevel::Normal
            } else {
                EntropyLevel::VeryLow
            };

            report.sections.push(Section {
                name: name.clone(),
                size,
                entropy,
                permissions: Some(permissions.clone()),
            });

            if matches!(entropy_level, EntropyLevel::High) && is_executable {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/packing".to_string(),
                    desc: format!(
                        "High entropy ({:.2}) in executable section '{}' (possible packing)",
                        entropy, name
                    ),
                    conf: 0.85,
                    crit: Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "entropy".to_string(),
                        source: "section_analysis".to_string(),
                        value: format!("{:.2}", entropy),
                        location: Some(name.clone()),
                    }],
                });
            }

            if is_writable && is_executable {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "exec/memory/wx".to_string(),
                    desc: format!("Writable+executable section '{}'", name),
                    conf: 1.0,
                    crit: Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "section_flags".to_string(),
                        source: "goblin".to_string(),
                        value: permissions,
                        location: Some(name),
                    }],
                });
            }
        }

        Ok(())
    }

    fn arch_name(&self, pe: &PE) -> String {
        match pe.header.coff_header.machine {
            0x014c => "x86".to_string(),
            0x8664 => "x86_64".to_string(),
            0x01c0 => "ARM".to_string(),
            0xaa64 => "ARM64".to_string(),
            _ => format!("unknown-{:#x}", pe.header.coff_header.machine),
        }
    }

}

impl Default for PEAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for PEAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = fs::read(file_path).context("Failed to read file")?;
        self.analyze_pe(file_path, &data)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Ok(data) = fs::read(file_path) {
            goblin::pe::PE::parse(&data).is_ok()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_pe_path() -> PathBuf {
        PathBuf::from("tests/fixtures/test.exe")
    }

    #[test]
    fn test_can_analyze_pe() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if test_file.exists() {
            assert!(analyzer.can_analyze(&test_file));
        }
    }

    #[test]
    fn test_cannot_analyze_non_pe() {
        let analyzer = PEAnalyzer::new();
        assert!(!analyzer.can_analyze(&PathBuf::from("/dev/null")));
        assert!(!analyzer.can_analyze(&PathBuf::from("tests/fixtures/test.elf")));
    }

    #[test]
    fn test_analyze_pe_file() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let result = analyzer.analyze(&test_file);
        assert!(result.is_ok());

        let report = result.unwrap();
        assert_eq!(report.target.file_type, "pe");
        assert!(report.target.size_bytes > 0);
        assert!(!report.target.sha256.is_empty());
    }

    #[test]
    fn test_pe_has_structure() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.structure.is_empty());
    }

    #[test]
    fn test_pe_architecture_detected() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.target.architectures.is_some());
        let archs = report.target.architectures.unwrap();
        assert!(!archs.is_empty());
    }

    #[test]
    fn test_pe_sections_analyzed() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.sections.is_empty());
    }

    #[test]
    fn test_pe_has_imports() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.imports.is_empty());
    }

    #[test]
    fn test_pe_capabilities_detected() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        // Capabilities may or may not be detected depending on the binary
        // Just verify the analysis completes successfully
        let _ = &report.traits;
    }

    #[test]
    fn test_pe_strings_extracted() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.strings.is_empty());
    }

    #[test]
    fn test_pe_tools_used() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.metadata.tools_used.contains(&"goblin".to_string()));
    }

    #[test]
    fn test_pe_analysis_duration() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.metadata.analysis_duration_ms > 0);
    }
}
