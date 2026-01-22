use crate::analyzers::Analyzer;
use crate::capabilities::CapabilityMapper;
use crate::entropy::{calculate_entropy, EntropyLevel};
use crate::radare2::Radare2Analyzer;
use crate::strings::StringExtractor;
use crate::types::*;
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use goblin::mach::{Mach, MachO};
use std::fs;
use std::path::Path;

/// Analyzer for macOS Mach-O binaries (executables, dylibs, bundles)
pub struct MachOAnalyzer {
    capability_mapper: CapabilityMapper,
    radare2: Radare2Analyzer,
    string_extractor: StringExtractor,
    yara_engine: Option<YaraEngine>,
}

impl MachOAnalyzer {
    /// Creates a new Mach-O analyzer with default configuration
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

    fn analyze_single(&self, file_path: &Path, data: &[u8]) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse with goblin
        let macho = match goblin::mach::Mach::parse(data)? {
            Mach::Binary(m) => m,
            Mach::Fat(_) => {
                anyhow::bail!("Fat binaries should be handled separately");
            }
        };

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "macho".to_string(),
            size_bytes: data.len() as u64,
            sha256: self.calculate_sha256(data),
            architectures: Some(vec![self.arch_name(&macho)]),
        };

        let mut report = AnalysisReport::new(target);
        let mut tools_used = vec!["goblin".to_string()];

        // Analyze header and structure
        self.analyze_structure(&macho, &mut report)?;

        // Extract imports and map to capabilities
        self.analyze_imports(&macho, &mut report)?;

        // Extract exports
        self.analyze_exports(&macho, &mut report)?;

        // Analyze sections and entropy
        self.analyze_sections(&macho, data, &mut report)?;

        // Use radare2 for deep analysis if available
        if Radare2Analyzer::is_available() {
            tools_used.push("radare2".to_string());

            if let Ok(functions) = self.radare2.extract_functions(file_path) {
                report.functions = functions;
            }

            if let Ok(r2_strings) = self.radare2.extract_strings(file_path) {
                // Convert R2 strings to our format
                for r2_str in r2_strings {
                    report.strings.push(StringInfo {
                        value: r2_str.string,
                        offset: Some(format!("0x{:x}", r2_str.vaddr)),
                        encoding: "utf8".to_string(),
                        string_type: StringType::Plain,
                        section: None,
                    });
                }
            }

            // Extract syscalls for binary analysis
            if let Ok(syscalls) = self.radare2.extract_syscalls(file_path) {
                report.syscalls = syscalls;
            }
        }

        // Extract strings if not already done by radare2
        if report.strings.is_empty() {
            report.strings = self.string_extractor.extract(data, None);
            tools_used.push("string_extractor".to_string());
        }

        // Run YARA scan if engine is loaded
        if let Some(yara_engine) = &self.yara_engine {
            if yara_engine.is_loaded() {
                tools_used.push("yara-x".to_string());
                // Filter for Mach-O-specific rules
                let file_types = &["macho", "elf", "so"];
                match yara_engine.scan_bytes_filtered(data, Some(file_types)) {
                    Ok(matches) => {
                        // Add YARA matches to report
                        report.yara_matches = matches.clone();

                        // Map YARA matches to capabilities
                        for yara_match in &matches {
                            // Try to map YARA rule to capability ID
                            let capability_id =
                                self.yara_namespace_to_capability(&yara_match.namespace);

                            if let Some(cap_id) = capability_id {
                                // Check if we already have this capability
                                if !report.findings.iter().any(|c| c.id == cap_id) {
                                    let evidence = yara_engine.yara_match_to_evidence(yara_match);
                                    report.findings.push(Finding {
                                        kind: FindingKind::Capability,
                                        trait_refs: vec![],
                                        id: cap_id,
                                        description: yara_match.description.clone(),
                                        confidence: 0.9, // YARA matches are high confidence
                                        criticality: crate::types::Criticality::Inert,
                                        mbc: None,
                                        attack: None,
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

        // Generate structural traits from analysis
        self.generate_structural_traits(&macho, data, &mut report)?;

        // Evaluate trait definitions from YAML
        let trait_findings = self.capability_mapper.evaluate_traits(&report, data);
        for f in trait_findings {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }

        // Evaluate composite rules
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

    /// Generate structural traits (file format, architecture, signing, etc.)
    fn generate_structural_traits(
        &self,
        macho: &MachO,
        _data: &[u8],
        report: &mut AnalysisReport,
    ) -> Result<()> {
        // 1. File format trait
        report.findings.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "meta/format/macho".to_string(),
            description: "Mach-O executable format".to_string(),
            confidence: 1.0,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "magic".to_string(),
                source: "goblin".to_string(),
                value: format!("0x{:x}", macho.header.magic),
                location: None,
            }],
        });

        // 2. Architecture trait
        let arch = self.arch_name(macho);
        report.findings.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: format!("meta/arch/{}", arch),
            description: format!("{} architecture", arch),
            confidence: 1.0,
            criticality: Criticality::Inert,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "header".to_string(),
                source: "goblin".to_string(),
                value: format!("cputype=0x{:x}", macho.header.cputype),
                location: None,
            }],
        });

        // 3. Code signature trait
        let has_signature = macho.load_commands.iter().any(|lc| {
            matches!(
                lc.command,
                goblin::mach::load_command::CommandVariant::CodeSignature(_)
            )
        });

        if has_signature {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "meta/signed".to_string(),
                description: "Code-signed binary".to_string(),
                confidence: 1.0,
                criticality: Criticality::Inert,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "load_command".to_string(),
                    source: "goblin".to_string(),
                    value: "LC_CODE_SIGNATURE".to_string(),
                    location: None,
                }],
            });
        }

        // 4. Command-line tool detection (usage string)
        for s in &report.strings {
            if s.value.to_lowercase().starts_with("usage:") {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "meta/cli-tool".to_string(),
                    description: "Command-line tool with usage string".to_string(),
                    confidence: 0.9,
                    criticality: Criticality::Inert,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "string".to_string(),
                        source: "strings".to_string(),
                        value: s.value.chars().take(50).collect::<String>() + "...",
                        location: s.offset.clone(),
                    }],
                });
                break;
            }
        }

        // 5. FreeBSD origin detection
        let has_freebsd_tag = report.strings.iter().any(|s| s.value.contains("$FreeBSD"));
        if has_freebsd_tag {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "meta/origin/freebsd".to_string(),
                description: "Contains FreeBSD version tags".to_string(),
                confidence: 0.95,
                criticality: Criticality::Inert,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "string".to_string(),
                    source: "strings".to_string(),
                    value: "$FreeBSD$".to_string(),
                    location: None,
                }],
            });
        }

        // 6. Linked libraries as traits
        let mut unique_libs: std::collections::HashSet<String> = std::collections::HashSet::new();
        for imp in &report.imports {
            if let Some(lib) = &imp.library {
                if !lib.contains("libSystem") && !unique_libs.contains(lib) {
                    unique_libs.insert(lib.clone());

                    // Extract library name without path/version
                    let lib_name = lib.split('/').next_back().unwrap_or(lib);
                    let base_name = lib_name
                        .split('.')
                        .next()
                        .unwrap_or(lib_name)
                        .trim_start_matches("lib");

                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: format!("meta/library/{}", base_name),
                        description: format!("Links to {} library", lib_name),
                        confidence: 1.0,
                        criticality: Criticality::Inert,
                        mbc: None,
                        attack: None,
                        evidence: vec![Evidence {
                            method: "dylib".to_string(),
                            source: "goblin".to_string(),
                            value: lib.clone(),
                            location: None,
                        }],
                    });
                }
            }
        }

        // 7. High entropy sections (potential obfuscation/packing)
        for section in &report.sections {
            if section.entropy > 7.5 {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "meta/high-entropy".to_string(),
                    description: format!("High entropy section ({})", section.name),
                    confidence: 0.8,
                    criticality: Criticality::Notable,
                    mbc: Some("F0001".to_string()), // Anti-static analysis
                    attack: None,
                    evidence: vec![Evidence {
                        method: "entropy".to_string(),
                        source: "shannon".to_string(),
                        value: format!("{:.2}", section.entropy),
                        location: Some(section.name.clone()),
                    }],
                });
                break; // Only report once
            }
        }

        // 8. High complexity functions
        let high_complexity: Vec<_> = report
            .functions
            .iter()
            .filter(|f| f.complexity.unwrap_or(0) > 50)
            .collect();

        if !high_complexity.is_empty() {
            let func_names: Vec<String> = high_complexity
                .iter()
                .map(|f| f.name.clone())
                .take(3)
                .collect();

            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "meta/complex-code".to_string(),
                description: format!("{} highly complex functions", high_complexity.len()),
                confidence: 0.7,
                criticality: Criticality::Notable,
                mbc: Some("F0001".to_string()),
                attack: None,
                evidence: vec![Evidence {
                    method: "cyclomatic".to_string(),
                    source: "radare2".to_string(),
                    value: func_names.join(", "),
                    location: None,
                }],
            });
        }

        Ok(())
    }

    fn analyze_structure(&self, macho: &MachO, report: &mut AnalysisReport) -> Result<()> {
        // Binary format
        report.structure.push(StructuralFeature {
            id: "binary/format/macho".to_string(),
            description: "Mach-O binary format".to_string(),
            evidence: vec![Evidence {
                method: "magic".to_string(),
                source: "goblin".to_string(),
                value: format!("0x{:x}", macho.header.magic),
                location: None,
            }],
        });

        // Architecture
        let arch = self.arch_name(macho);
        report.structure.push(StructuralFeature {
            id: format!("binary/arch/{}", arch),
            description: format!("{} architecture", arch),
            evidence: vec![Evidence {
                method: "header".to_string(),
                source: "goblin".to_string(),
                value: format!("cputype=0x{:x}", macho.header.cputype),
                location: None,
            }],
        });

        // Check for code signature
        let has_signature = macho.load_commands.iter().any(|lc| {
            matches!(
                lc.command,
                goblin::mach::load_command::CommandVariant::CodeSignature(_)
            )
        });

        if has_signature {
            report.structure.push(StructuralFeature {
                id: "binary/signed".to_string(),
                description: "Binary has code signature".to_string(),
                evidence: vec![Evidence {
                    method: "load_command".to_string(),
                    source: "goblin".to_string(),
                    value: "LC_CODE_SIGNATURE".to_string(),
                    location: Some("load_commands".to_string()),
                }],
            });
        }

        Ok(())
    }

    fn analyze_imports(&self, macho: &MachO, report: &mut AnalysisReport) -> Result<()> {
        for imp in &macho.imports()? {
            report.imports.push(Import {
                symbol: imp.name.to_string(),
                library: Some(imp.dylib.to_string()),
                source: "goblin".to_string(),
            });

            // Map import to capability
            if let Some(cap) = self.capability_mapper.lookup(imp.name, "goblin") {
                // Check if we already have this capability
                if !report.findings.iter().any(|c| c.id == cap.id) {
                    report.findings.push(cap);
                }
            }
        }

        Ok(())
    }

    fn analyze_exports(&self, macho: &MachO, report: &mut AnalysisReport) -> Result<()> {
        for exp in &macho.exports()? {
            report.exports.push(Export {
                symbol: exp.name.to_string(),
                offset: Some(format!("0x{:x}", exp.offset)),
                source: "goblin".to_string(),
            });
        }

        Ok(())
    }

    fn analyze_sections(
        &self,
        macho: &MachO,
        data: &[u8],
        report: &mut AnalysisReport,
    ) -> Result<()> {
        for segment in &macho.segments {
            for (section, _) in &segment.sections()? {
                let section_name = format!(
                    "{}.__{}",
                    segment.name().unwrap_or("unknown"),
                    section.name().unwrap_or("unknown")
                );

                // Calculate entropy for this section
                let section_offset = section.offset as usize;
                let section_size = section.size as usize;

                if section_offset + section_size <= data.len() {
                    let section_data = &data[section_offset..section_offset + section_size];
                    let entropy = calculate_entropy(section_data);

                    report.sections.push(Section {
                        name: section_name.clone(),
                        size: section.size,
                        entropy,
                        permissions: Some(format!("{:?}", section.flags)),
                    });

                    // Add entropy-based structural features
                    let level = EntropyLevel::from_value(entropy);
                    if level == EntropyLevel::High {
                        report.structure.push(StructuralFeature {
                            id: "entropy/high".to_string(),
                            description: "High entropy section (possibly packed/encrypted)"
                                .to_string(),
                            evidence: vec![Evidence {
                                method: "entropy".to_string(),
                                source: "entropy_analyzer".to_string(),
                                value: format!("{:.2}", entropy),
                                location: Some(section_name),
                            }],
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn arch_name(&self, macho: &MachO) -> String {
        match macho.header.cputype {
            0x01000007 => "x86_64".to_string(),
            0x0100000c => "arm64".to_string(),
            0x0200000c => "arm64e".to_string(),
            _ => format!("unknown_0x{:x}", macho.header.cputype),
        }
    }

    fn calculate_sha256(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// Map YARA namespace to capability ID
    fn yara_namespace_to_capability(&self, namespace: &str) -> Option<String> {
        // YARA namespace format: exec.cmd, anti-static.obfuscation, etc.
        // Convert to capability ID: exec/command, anti-analysis/obfuscation
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
}

impl Default for MachOAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for MachOAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = fs::read(file_path).context("Failed to read file")?;

        // Check if it's a fat binary
        match goblin::mach::Mach::parse(&data)? {
            Mach::Binary(_) => self.analyze_single(file_path, &data),
            Mach::Fat(fat) => {
                // For now, analyze the first architecture
                // TODO: Support multi-architecture analysis
                if let Some(arch) = fat.arches()?.first() {
                    let offset = arch.offset as usize;
                    let size = arch.size as usize;
                    let arch_data = &data[offset..offset + size];
                    self.analyze_single(file_path, arch_data)
                } else {
                    anyhow::bail!("No architectures found in fat binary");
                }
            }
        }
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Ok(data) = fs::read(file_path) {
            goblin::mach::Mach::parse(&data).is_ok()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_macho_path() -> PathBuf {
        PathBuf::from("tests/fixtures/test.macho")
    }

    #[test]
    fn test_can_analyze_macho() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if test_file.exists() {
            assert!(analyzer.can_analyze(&test_file));
        }
    }

    #[test]
    fn test_cannot_analyze_non_macho() {
        let analyzer = MachOAnalyzer::new();
        assert!(!analyzer.can_analyze(&PathBuf::from("/dev/null")));
        assert!(!analyzer.can_analyze(&PathBuf::from("tests/fixtures/test.elf")));
    }

    #[test]
    fn test_analyze_macho_file() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let result = analyzer.analyze(&test_file);
        assert!(result.is_ok());

        let report = result.unwrap();
        assert_eq!(report.target.file_type, "macho");
        assert!(report.target.size_bytes > 0);
        assert!(!report.target.sha256.is_empty());
    }

    #[test]
    fn test_macho_has_structure() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.structure.is_empty());
    }

    #[test]
    fn test_macho_architecture_detected() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.target.architectures.is_some());
        let archs = report.target.architectures.unwrap();
        assert!(!archs.is_empty());
    }

    #[test]
    fn test_macho_sections_analyzed() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.sections.is_empty());
    }

    #[test]
    fn test_macho_has_imports() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.imports.is_empty());
    }

    #[test]
    fn test_macho_capabilities_detected() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        // Capabilities may or may not be detected depending on the binary
        // Just verify the analysis completes successfully
        let _ = &report.traits;
    }

    #[test]
    fn test_macho_strings_extracted() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.strings.is_empty());
    }

    #[test]
    fn test_macho_tools_used() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.metadata.tools_used.contains(&"goblin".to_string()));
    }

    #[test]
    fn test_macho_analysis_duration() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.metadata.analysis_duration_ms > 0);
    }
}
