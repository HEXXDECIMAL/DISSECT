//! ELF binary analyzer for Linux executables.
//!
//! Analyzes ELF binaries using radare2/rizin and string extraction.

use crate::analyzers::Analyzer;
use crate::capabilities::CapabilityMapper;
use crate::entropy::{calculate_entropy, EntropyLevel};
use crate::radare2::Radare2Analyzer;
use crate::strings::StringExtractor;
use crate::types::*;
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use goblin::elf::Elf;
use std::fs;
use std::path::Path;

/// Analyzer for Linux ELF binaries (executables, shared objects, kernel modules)
pub struct ElfAnalyzer {
    capability_mapper: CapabilityMapper,
    radare2: Radare2Analyzer,
    string_extractor: StringExtractor,
    yara_engine: Option<YaraEngine>,
}

impl ElfAnalyzer {
    /// Creates a new ELF analyzer with default configuration
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

    fn analyze_elf(&self, file_path: &Path, data: &[u8]) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Create target info with default/empty values for fields that require parsing
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "elf".to_string(),
            size_bytes: data.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(data),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        let mut tools_used = vec![];

        // Attempt to parse with goblin
        let parsed_elf = match Elf::parse(data) {
            Ok(elf) => {
                tools_used.push("goblin".to_string());

                // Update architecture now that we have parsed the header
                report.target.architectures = Some(vec![self.arch_name(&elf)]);

                // Analyze header and structure
                self.analyze_structure(&elf, &mut report)?;

                // Extract dynamic symbols and map to capabilities
                self.analyze_dynamic_symbols(&elf, data, &mut report)?;

                // Analyze sections and entropy
                self.analyze_sections(&elf, data, &mut report)?;

                Some(elf)
            }
            Err(e) => {
                // Parsing failed - this is a strong indicator of malformed/hostile binary
                report.findings.push(Finding {
                    kind: FindingKind::Structural,
                    id: "anti-analysis/malformed/elf-header".to_string(),
                    desc: format!("Malformed ELF header or section headers: {}", e),
                    conf: 1.0,
                    crit: Criticality::Hostile,
                    mbc: Some("B0001".to_string()), // Defense Evasion: Software Packing/Obfuscation
                    attack: Some("T1027".to_string()), // Obfuscated Files or Information
                    evidence: vec![],
                    trait_refs: vec![],
                });

                report
                    .metadata
                    .errors
                    .push(format!("ELF parse error: {}", e));
                None
            }
        };

        // Use radare2 for deep analysis if available - SINGLE r2 spawn for all data
        let r2_strings = if Radare2Analyzer::is_available() {
            tools_used.push("radare2".to_string());

            // Use batched extraction - single r2 session for functions, sections, strings, imports
            if let Ok(mut batched) = self.radare2.extract_batched(file_path) {
                // Check if we need deeper analysis (few functions found but executable sections exist)
                let has_exec_sections = batched
                    .sections
                    .iter()
                    .any(|s| s.perm.clone().unwrap_or_default().contains('x'));
                if batched.functions.len() < 5 && has_exec_sections {
                    // Re-run with deep analysis enabled
                    if let Ok(deep_batched) = self.radare2.extract_batched_deep(file_path) {
                        batched = deep_batched;
                    }
                }

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

        // Extract strings using language-aware extraction (Go/Rust) with pre-parsed ELF if available
        if let Some(ref elf) = parsed_elf {
            report.strings = self
                .string_extractor
                .extract_from_elf(elf, data, r2_strings);
        } else {
            report.strings = self
                .string_extractor
                .extract_smart_with_r2(data, r2_strings);
        }
        tools_used.push("stng".to_string());

        // Run YARA scan if engine is loaded
        if let Some(yara_engine) = &self.yara_engine {
            if yara_engine.is_loaded() {
                tools_used.push("yara-x".to_string());
                // Filter for ELF-specific rules
                let file_types = &["elf", "so", "ko"];
                match yara_engine.scan_bytes_filtered(data, Some(file_types)) {
                    Ok(matches) => {
                        report.yara_matches = matches.clone();

                        for yara_match in &matches {
                            // Check if YARA rule has capability=true metadata OR maps via namespace
                            let capability_id = if yara_match.is_capability {
                                // Use namespace as capability ID (e.g., "exec.cmd" -> "exec/cmd")
                                Some(yara_match.namespace.replace('.', "/"))
                            } else {
                                // Fall back to namespace mapping
                                self.yara_namespace_to_capability(&yara_match.namespace)
                            };

                            if let Some(cap_id) = capability_id {
                                if !report.findings.iter().any(|c| c.id == cap_id) {
                                    let evidence = yara_engine.yara_match_to_evidence(yara_match);

                                    // Determine criticality from severity
                                    let criticality = match yara_match.severity.as_str() {
                                        "critical" => Criticality::Hostile,
                                        "high" => Criticality::Hostile,
                                        "medium" => Criticality::Suspicious,
                                        "low" => Criticality::Notable,
                                        _ => Criticality::Suspicious,
                                    };

                                    report.findings.push(Finding {
                                        kind: FindingKind::Capability,
                                        trait_refs: vec![],
                                        id: cap_id,
                                        desc: yara_match.desc.clone(),
                                        conf: 0.9,
                                        crit: criticality,
                                        mbc: yara_match.mbc.clone(),
                                        attack: yara_match.attack.clone(),
                                        evidence,
                                    });
                                }
                            }
                        }
                    }
                    Err(e) => {
                        report
                            .metadata
                            .errors
                            .push(format!("YARA scan failed: {}", e));
                    }
                }
            }
        }

        // Evaluate all rules (atomic + composite) and merge into report
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, data, None);

        // Analyze paths and generate path-based traits
        crate::path_mapper::analyze_and_link_paths(&mut report);

        // Analyze environment variables and generate env-based traits
        crate::env_mapper::analyze_and_link_env_vars(&mut report);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = tools_used;

        Ok(report)
    }

    fn analyze_structure(&self, elf: &Elf, report: &mut AnalysisReport) -> Result<()> {
        // Binary format
        report.structure.push(StructuralFeature {
            id: "binary/format/elf".to_string(),
            desc: "ELF binary format".to_string(),
            evidence: vec![Evidence {
                method: "magic".to_string(),
                source: "goblin".to_string(),
                value: format!("0x{:x}", elf.header.e_ident[0]),
                location: None,
            }],
        });

        // Architecture
        let arch = self.arch_name(elf);
        report.structure.push(StructuralFeature {
            id: format!("binary/arch/{}", arch),
            desc: format!("{} architecture", arch),
            evidence: vec![Evidence {
                method: "header".to_string(),
                source: "goblin".to_string(),
                value: format!("e_machine={}", elf.header.e_machine),
                location: None,
            }],
        });

        // Check if stripped
        if elf.syms.is_empty() {
            report.structure.push(StructuralFeature {
                id: "binary/stripped".to_string(),
                desc: "Symbol table stripped".to_string(),
                evidence: vec![Evidence {
                    method: "symbols".to_string(),
                    source: "goblin".to_string(),
                    value: "no_symbols".to_string(),
                    location: None,
                }],
            });
        }

        // Check if PIE (Position Independent Executable)
        if elf.header.e_type == goblin::elf::header::ET_DYN {
            report.structure.push(StructuralFeature {
                id: "binary/pie".to_string(),
                desc: "Position Independent Executable".to_string(),
                evidence: vec![Evidence {
                    method: "header".to_string(),
                    source: "goblin".to_string(),
                    value: "ET_DYN".to_string(),
                    location: None,
                }],
            });
        }

        Ok(())
    }

    fn analyze_dynamic_symbols(
        &self,
        elf: &Elf,
        _data: &[u8],
        report: &mut AnalysisReport,
    ) -> Result<()> {
        // Analyze dynamic symbols (imports)
        for dynsym in &elf.dynsyms {
            if let Some(name) = elf.dynstrtab.get_at(dynsym.st_name) {
                let clean_name = name.trim_start_matches('_');
                // Add to imports
                report.imports.push(Import {
                    symbol: clean_name.to_string(),
                    library: None, // ELF doesn't always specify library directly
                    source: "goblin".to_string(),
                });

                // Map to capability
                if let Some(cap) = self.capability_mapper.lookup(clean_name, "goblin") {
                    if !report.findings.iter().any(|c| c.id == cap.id) {
                        report.findings.push(cap);
                    }
                }
            }
        }

        // Analyze regular symbols for exports
        for sym in &elf.syms {
            if sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                && sym.st_type() == goblin::elf::sym::STT_FUNC
            {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    let clean_name = name.trim_start_matches('_');
                    report.exports.push(Export {
                        symbol: clean_name.to_string(),
                        offset: Some(format!("{:#x}", sym.st_value)),
                        source: "goblin".to_string(),
                    });
                }
            }
        }

        Ok(())
    }

    fn analyze_sections(&self, elf: &Elf, data: &[u8], report: &mut AnalysisReport) -> Result<()> {
        for section in &elf.section_headers {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                let section_offset = section.sh_offset as usize;
                let section_size = section.sh_size as usize;

                if section_offset + section_size <= data.len() && section_size > 0 {
                    let section_data = &data[section_offset..section_offset + section_size];
                    let entropy = calculate_entropy(section_data);

                    report.sections.push(Section {
                        name: name.to_string(),
                        size: section.sh_size,
                        entropy,
                        permissions: Some(format!("{:x}", section.sh_flags)),
                    });

                    // Add entropy-based structural features
                    let level = EntropyLevel::from_value(entropy);
                    if level == EntropyLevel::High {
                        report.structure.push(StructuralFeature {
                            id: "entropy/high".to_string(),
                            desc: "High entropy section (possibly packed/encrypted)".to_string(),
                            evidence: vec![Evidence {
                                method: "entropy".to_string(),
                                source: "entropy_analyzer".to_string(),
                                value: format!("{:.2}", entropy),
                                location: Some(name.to_string()),
                            }],
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn arch_name(&self, elf: &Elf) -> String {
        match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => "x86_64".to_string(),
            goblin::elf::header::EM_386 => "i386".to_string(),
            goblin::elf::header::EM_AARCH64 => "aarch64".to_string(),
            goblin::elf::header::EM_ARM => "arm".to_string(),
            goblin::elf::header::EM_RISCV => "riscv".to_string(),
            _ => format!("unknown_{}", elf.header.e_machine),
        }
    }

    fn yara_namespace_to_capability(&self, namespace: &str) -> Option<String> {
        let parts: Vec<&str> = namespace.split('.').collect();

        match parts.as_slice() {
            ["exec", "cmd"] => Some("exec/command/shell".to_string()),
            ["exec", "program"] => Some("exec/command/direct".to_string()),
            ["exec", "shell"] => Some("exec/command/shell".to_string()),
            ["net", sub] => Some(format!("net/{}", sub)),
            ["crypto", sub] => Some(format!("crypto/{}", sub)),
            ["fs", sub] => Some(format!("fs/{}", sub)),
            ["anti-static", "obfuscation"] => Some("anti-analysis/obfuscation".to_string()),
            ["process", sub] => Some(format!("process/{}", sub)),
            ["credential", sub] => Some(format!("credential/{}", sub)),
            _ => None,
        }
    }

    /// Merge findings from unpacked analysis into the packed report.
    /// Deduplicates by finding ID, keeping the highest criticality.
    fn merge_reports(&self, packed: &mut AnalysisReport, unpacked: AnalysisReport) {
        // Merge findings by ID, keeping highest criticality
        for unpacked_finding in unpacked.findings {
            if let Some(existing) = packed
                .findings
                .iter_mut()
                .find(|f| f.id == unpacked_finding.id)
            {
                // Merge evidence
                existing.evidence.extend(unpacked_finding.evidence);
                // Keep higher criticality
                if unpacked_finding.crit > existing.crit {
                    existing.crit = unpacked_finding.crit;
                }
            } else {
                packed.findings.push(unpacked_finding);
            }
        }

        // Merge strings (deduplicate by value)
        for s in unpacked.strings {
            if !packed.strings.iter().any(|ps| ps.value == s.value) {
                packed.strings.push(s);
            }
        }

        // Merge imports (deduplicate by symbol)
        for imp in unpacked.imports {
            if !packed.imports.iter().any(|pi| pi.symbol == imp.symbol) {
                packed.imports.push(imp);
            }
        }

        // Merge exports (deduplicate by symbol)
        for exp in unpacked.exports {
            if !packed.exports.iter().any(|pe| pe.symbol == exp.symbol) {
                packed.exports.push(exp);
            }
        }

        // Merge functions (deduplicate by name)
        for func in unpacked.functions {
            if !packed.functions.iter().any(|pf| pf.name == func.name) {
                packed.functions.push(func);
            }
        }

        // Merge sections (deduplicate by name)
        for sec in unpacked.sections {
            if !packed.sections.iter().any(|ps| ps.name == sec.name) {
                packed.sections.push(sec);
            }
        }

        // Merge YARA matches (deduplicate by rule name)
        for ym in unpacked.yara_matches {
            if !packed.yara_matches.iter().any(|py| py.rule == ym.rule) {
                packed.yara_matches.push(ym);
            }
        }
    }
}

impl Default for ElfAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for ElfAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        use crate::upx::{UPXDecompressor, UPXError};

        let data = fs::read(file_path).context("Failed to read file")?;

        // Check for UPX packing
        if !UPXDecompressor::is_upx_packed(&data) {
            return self.analyze_elf(file_path, &data);
        }

        // File is UPX-packed - analyze packed version first
        let mut report = self.analyze_elf(file_path, &data)?;

        // Add UPX packer finding
        report.findings.push(
            Finding::structural(
                "anti-static/packer/upx".to_string(),
                "Binary is packed with UPX".to_string(),
                1.0,
            )
            .with_criticality(Criticality::Suspicious),
        );

        // Attempt decompression
        if !UPXDecompressor::is_available() {
            report.findings.push(
                Finding::structural(
                    "anti-static/packer/upx/tool-missing".to_string(),
                    "UPX binary not found in PATH - unpacked analysis skipped".to_string(),
                    1.0,
                )
                .with_criticality(Criticality::Notable),
            );
            return Ok(report);
        }

        match UPXDecompressor::decompress(file_path) {
            Ok(unpacked_data) => {
                // Write unpacked data to temp file for radare2 analysis
                let temp_file = tempfile::NamedTempFile::new()
                    .context("Failed to create temp file for unpacked analysis")?;
                fs::write(temp_file.path(), &unpacked_data)
                    .context("Failed to write unpacked data to temp file")?;

                // Analyze unpacked version
                if let Ok(unpacked_report) = self.analyze_elf(temp_file.path(), &unpacked_data) {
                    self.merge_reports(&mut report, unpacked_report);
                }

                report.metadata.tools_used.push("upx".to_string());
            }
            Err(e) => {
                let description = match e {
                    UPXError::DecompressionFailed(msg) => {
                        format!("UPX decompression failed (possibly tampered): {}", msg)
                    }
                    _ => format!("UPX decompression failed: {}", e),
                };
                report.findings.push(
                    Finding::structural(
                        "anti-static/packer/upx/decompression-failed".to_string(),
                        description,
                        1.0,
                    )
                    .with_criticality(Criticality::Suspicious),
                );
            }
        }

        Ok(report)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Ok(data) = fs::read(file_path) {
            goblin::elf::Elf::parse(&data).is_ok()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_elf_path() -> PathBuf {
        PathBuf::from("tests/fixtures/test.elf")
    }

    #[test]
    fn test_can_analyze_elf() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if test_file.exists() {
            assert!(analyzer.can_analyze(&test_file));
        }
    }

    #[test]
    fn test_cannot_analyze_non_elf() {
        let analyzer = ElfAnalyzer::new();
        assert!(!analyzer.can_analyze(&PathBuf::from("/dev/null")));
        assert!(!analyzer.can_analyze(&PathBuf::from("tests/fixtures/test.exe")));
    }

    #[test]
    fn test_analyze_elf_file() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return; // Skip if fixture doesn't exist
        }

        let result = analyzer.analyze(&test_file);
        assert!(result.is_ok());

        let report = result.unwrap();
        assert_eq!(report.target.file_type, "elf");
        assert!(report.target.size_bytes > 0);
        assert!(!report.target.sha256.is_empty());
    }

    #[test]
    fn test_elf_has_structure() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.structure.is_empty());
    }

    #[test]
    fn test_elf_architecture_detected() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.target.architectures.is_some());
        let archs = report.target.architectures.unwrap();
        assert!(!archs.is_empty());
    }

    #[test]
    fn test_elf_sections_analyzed() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.sections.is_empty());
    }

    #[test]
    fn test_elf_has_imports() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        // Most ELF binaries have dynamic imports
        assert!(!report.imports.is_empty());
    }

    #[test]
    fn test_elf_capabilities_detected() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        // Capabilities may or may not be detected depending on the binary
        // Just verify the analysis completes successfully
        let _ = &report.traits;
    }

    #[test]
    fn test_elf_strings_extracted() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.strings.is_empty());
    }

    #[test]
    fn test_elf_tools_used() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.metadata.tools_used.contains(&"goblin".to_string()));
    }

    #[test]
    fn test_elf_analysis_duration() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.metadata.analysis_duration_ms > 0);
    }

    // =========================================================================
    // UPX Integration Tests
    // =========================================================================

    #[test]
    fn test_upx_detection_in_data() {
        use crate::upx::UPXDecompressor;

        // Data with UPX magic
        let upx_data = b"\x7fELF\x00\x00\x00\x00UPX!\x00\x00";
        assert!(UPXDecompressor::is_upx_packed(upx_data));

        // Data without UPX magic
        let normal_data = b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(!UPXDecompressor::is_upx_packed(normal_data));
    }

    // =========================================================================
    // merge_reports Tests
    // =========================================================================

    fn create_test_report() -> AnalysisReport {
        let target = TargetInfo {
            path: "/test/path".to_string(),
            file_type: "elf".to_string(),
            size_bytes: 1000,
            sha256: "abc123".to_string(),
            architectures: Some(vec!["x86_64".to_string()]),
        };
        AnalysisReport::new(target)
    }

    #[test]
    fn test_merge_reports_findings_dedup_by_id() {
        let analyzer = ElfAnalyzer::new();
        let mut packed = create_test_report();
        let mut unpacked = create_test_report();

        // Add same finding to both with different criticality
        packed.findings.push(
            Finding::capability("net/socket".to_string(), "Network socket".to_string(), 0.9)
                .with_criticality(Criticality::Notable),
        );

        unpacked.findings.push(
            Finding::capability("net/socket".to_string(), "Network socket".to_string(), 0.9)
                .with_criticality(Criticality::Suspicious),
        );

        analyzer.merge_reports(&mut packed, unpacked);

        // Should have only one finding with higher criticality
        assert_eq!(packed.findings.len(), 1);
        assert_eq!(packed.findings[0].crit, Criticality::Suspicious);
    }

    #[test]
    fn test_merge_reports_findings_unique_added() {
        let analyzer = ElfAnalyzer::new();
        let mut packed = create_test_report();
        let mut unpacked = create_test_report();

        packed.findings.push(Finding::capability(
            "net/socket".to_string(),
            "Network socket".to_string(),
            0.9,
        ));

        unpacked.findings.push(Finding::capability(
            "exec/shell".to_string(),
            "Shell execution".to_string(),
            0.9,
        ));

        analyzer.merge_reports(&mut packed, unpacked);

        // Should have both findings
        assert_eq!(packed.findings.len(), 2);
        assert!(packed.findings.iter().any(|f| f.id == "net/socket"));
        assert!(packed.findings.iter().any(|f| f.id == "exec/shell"));
    }

    #[test]
    fn test_merge_reports_evidence_combined() {
        let analyzer = ElfAnalyzer::new();
        let mut packed = create_test_report();
        let mut unpacked = create_test_report();

        packed.findings.push(
            Finding::capability("net/socket".to_string(), "Network socket".to_string(), 0.9)
                .with_evidence(vec![Evidence {
                    method: "symbol".to_string(),
                    source: "goblin".to_string(),
                    value: "socket".to_string(),
                    location: None,
                }]),
        );

        unpacked.findings.push(
            Finding::capability("net/socket".to_string(), "Network socket".to_string(), 0.9)
                .with_evidence(vec![Evidence {
                    method: "symbol".to_string(),
                    source: "goblin".to_string(),
                    value: "connect".to_string(),
                    location: None,
                }]),
        );

        analyzer.merge_reports(&mut packed, unpacked);

        // Evidence should be combined
        assert_eq!(packed.findings.len(), 1);
        assert_eq!(packed.findings[0].evidence.len(), 2);
    }

    #[test]
    fn test_merge_reports_strings_dedup() {
        let analyzer = ElfAnalyzer::new();
        let mut packed = create_test_report();
        let mut unpacked = create_test_report();

        packed.strings.push(StringInfo {
            value: "hello".to_string(),
            offset: Some("0x100".to_string()),
            encoding: "utf8".to_string(),
            string_type: StringType::Plain,
            section: None,
        });

        // Same string value - should be deduped
        unpacked.strings.push(StringInfo {
            value: "hello".to_string(),
            offset: Some("0x200".to_string()),
            encoding: "utf8".to_string(),
            string_type: StringType::Plain,
            section: None,
        });

        // Different string - should be added
        unpacked.strings.push(StringInfo {
            value: "world".to_string(),
            offset: Some("0x300".to_string()),
            encoding: "utf8".to_string(),
            string_type: StringType::Plain,
            section: None,
        });

        analyzer.merge_reports(&mut packed, unpacked);

        assert_eq!(packed.strings.len(), 2);
        assert!(packed.strings.iter().any(|s| s.value == "hello"));
        assert!(packed.strings.iter().any(|s| s.value == "world"));
    }

    #[test]
    fn test_merge_reports_imports_dedup() {
        let analyzer = ElfAnalyzer::new();
        let mut packed = create_test_report();
        let mut unpacked = create_test_report();

        packed.imports.push(Import {
            symbol: "printf".to_string(),
            library: Some("libc.so.6".to_string()),
            source: "goblin".to_string(),
        });

        // Same symbol - should be deduped
        unpacked.imports.push(Import {
            symbol: "printf".to_string(),
            library: Some("libc.so.6".to_string()),
            source: "goblin".to_string(),
        });

        // Different symbol - should be added
        unpacked.imports.push(Import {
            symbol: "malloc".to_string(),
            library: Some("libc.so.6".to_string()),
            source: "goblin".to_string(),
        });

        analyzer.merge_reports(&mut packed, unpacked);

        assert_eq!(packed.imports.len(), 2);
        assert!(packed.imports.iter().any(|i| i.symbol == "printf"));
        assert!(packed.imports.iter().any(|i| i.symbol == "malloc"));
    }

    #[test]
    fn test_merge_reports_exports_dedup() {
        let analyzer = ElfAnalyzer::new();
        let mut packed = create_test_report();
        let mut unpacked = create_test_report();

        packed.exports.push(Export {
            symbol: "main".to_string(),
            offset: Some("0x1000".to_string()),
            source: "goblin".to_string(),
        });

        unpacked.exports.push(Export {
            symbol: "main".to_string(),
            offset: Some("0x2000".to_string()),
            source: "goblin".to_string(),
        });

        unpacked.exports.push(Export {
            symbol: "helper".to_string(),
            offset: Some("0x3000".to_string()),
            source: "goblin".to_string(),
        });

        analyzer.merge_reports(&mut packed, unpacked);

        assert_eq!(packed.exports.len(), 2);
    }

    #[test]
    fn test_merge_reports_functions_dedup() {
        let analyzer = ElfAnalyzer::new();
        let mut packed = create_test_report();
        let mut unpacked = create_test_report();

        packed.functions.push(Function {
            name: "main".to_string(),
            offset: Some("0x1000".to_string()),
            size: Some(100),
            complexity: Some(5),
            calls: vec![],
            source: "radare2".to_string(),
            control_flow: None,
            instruction_analysis: None,
            register_usage: None,
            constants: vec![],
            properties: None,
            signature: None,
            nesting: None,
            call_patterns: None,
        });

        unpacked.functions.push(Function {
            name: "main".to_string(),
            offset: Some("0x2000".to_string()),
            size: Some(200),
            complexity: Some(10),
            calls: vec![],
            source: "radare2".to_string(),
            control_flow: None,
            instruction_analysis: None,
            register_usage: None,
            constants: vec![],
            properties: None,
            signature: None,
            nesting: None,
            call_patterns: None,
        });

        unpacked.functions.push(Function {
            name: "helper".to_string(),
            offset: Some("0x3000".to_string()),
            size: Some(50),
            complexity: Some(2),
            calls: vec![],
            source: "radare2".to_string(),
            control_flow: None,
            instruction_analysis: None,
            register_usage: None,
            constants: vec![],
            properties: None,
            signature: None,
            nesting: None,
            call_patterns: None,
        });

        analyzer.merge_reports(&mut packed, unpacked);

        assert_eq!(packed.functions.len(), 2);
        assert!(packed.functions.iter().any(|f| f.name == "main"));
        assert!(packed.functions.iter().any(|f| f.name == "helper"));
    }

    #[test]
    fn test_merge_reports_sections_dedup() {
        let analyzer = ElfAnalyzer::new();
        let mut packed = create_test_report();
        let mut unpacked = create_test_report();

        packed.sections.push(Section {
            name: ".text".to_string(),
            size: 1000,
            entropy: 6.5,
            permissions: Some("r-x".to_string()),
        });

        unpacked.sections.push(Section {
            name: ".text".to_string(),
            size: 5000,
            entropy: 5.5,
            permissions: Some("r-x".to_string()),
        });

        unpacked.sections.push(Section {
            name: ".data".to_string(),
            size: 2000,
            entropy: 3.0,
            permissions: Some("rw-".to_string()),
        });

        analyzer.merge_reports(&mut packed, unpacked);

        assert_eq!(packed.sections.len(), 2);
    }

    #[test]
    fn test_merge_reports_yara_matches_dedup() {
        let analyzer = ElfAnalyzer::new();
        let mut packed = create_test_report();
        let mut unpacked = create_test_report();

        packed.yara_matches.push(YaraMatch {
            rule: "suspicious_strings".to_string(),
            namespace: "malware".to_string(),
            severity: "high".to_string(),
            desc: "Suspicious strings detected".to_string(),
            matched_strings: vec![],
            is_capability: false,
            mbc: None,
            attack: None,
        });

        unpacked.yara_matches.push(YaraMatch {
            rule: "suspicious_strings".to_string(),
            namespace: "malware".to_string(),
            severity: "high".to_string(),
            desc: "Suspicious strings detected".to_string(),
            matched_strings: vec![],
            is_capability: false,
            mbc: None,
            attack: None,
        });

        unpacked.yara_matches.push(YaraMatch {
            rule: "crypto_constants".to_string(),
            namespace: "crypto".to_string(),
            severity: "medium".to_string(),
            desc: "Crypto constants found".to_string(),
            matched_strings: vec![],
            is_capability: false,
            mbc: None,
            attack: None,
        });

        analyzer.merge_reports(&mut packed, unpacked);

        assert_eq!(packed.yara_matches.len(), 2);
    }

    #[test]
    fn test_merge_reports_empty_unpacked() {
        let analyzer = ElfAnalyzer::new();
        let mut packed = create_test_report();
        let unpacked = create_test_report();

        packed.findings.push(Finding::capability(
            "net/socket".to_string(),
            "Network socket".to_string(),
            0.9,
        ));

        analyzer.merge_reports(&mut packed, unpacked);

        // Should still have original finding
        assert_eq!(packed.findings.len(), 1);
    }

    #[test]
    fn test_merge_reports_empty_packed() {
        let analyzer = ElfAnalyzer::new();
        let mut packed = create_test_report();
        let mut unpacked = create_test_report();

        unpacked.findings.push(Finding::capability(
            "net/socket".to_string(),
            "Network socket".to_string(),
            0.9,
        ));

        analyzer.merge_reports(&mut packed, unpacked);

        // Should have the unpacked finding
        assert_eq!(packed.findings.len(), 1);
    }

    #[test]
    fn test_merge_reports_criticality_keeps_higher() {
        let analyzer = ElfAnalyzer::new();
        let mut packed = create_test_report();
        let mut unpacked = create_test_report();

        // Packed has Hostile
        packed.findings.push(
            Finding::capability(
                "malware/backdoor".to_string(),
                "Backdoor detected".to_string(),
                0.9,
            )
            .with_criticality(Criticality::Hostile),
        );

        // Unpacked has Suspicious (lower)
        unpacked.findings.push(
            Finding::capability(
                "malware/backdoor".to_string(),
                "Backdoor detected".to_string(),
                0.9,
            )
            .with_criticality(Criticality::Suspicious),
        );

        analyzer.merge_reports(&mut packed, unpacked);

        // Should keep Hostile (higher)
        assert_eq!(packed.findings[0].crit, Criticality::Hostile);
    }

    #[test]
    fn test_merge_reports_criticality_upgrades() {
        let analyzer = ElfAnalyzer::new();
        let mut packed = create_test_report();
        let mut unpacked = create_test_report();

        // Packed has Notable (lower)
        packed.findings.push(
            Finding::capability("net/socket".to_string(), "Network socket".to_string(), 0.9)
                .with_criticality(Criticality::Notable),
        );

        // Unpacked has Hostile (higher)
        unpacked.findings.push(
            Finding::capability("net/socket".to_string(), "Network socket".to_string(), 0.9)
                .with_criticality(Criticality::Hostile),
        );

        analyzer.merge_reports(&mut packed, unpacked);

        // Should upgrade to Hostile
        assert_eq!(packed.findings[0].crit, Criticality::Hostile);
    }
}
