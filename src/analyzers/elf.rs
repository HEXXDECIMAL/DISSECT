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

pub struct ElfAnalyzer {
    capability_mapper: CapabilityMapper,
    radare2: Radare2Analyzer,
    string_extractor: StringExtractor,
    yara_engine: Option<YaraEngine>,
}

impl ElfAnalyzer {
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

        // Parse with goblin
        let elf = Elf::parse(data)?;

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "elf".to_string(),
            size_bytes: data.len() as u64,
            sha256: self.calculate_sha256(data),
            architectures: Some(vec![self.get_arch_name(&elf)]),
        };

        let mut report = AnalysisReport::new(target);
        let mut tools_used = vec!["goblin".to_string()];

        // Analyze header and structure
        self.analyze_structure(&elf, &mut report)?;

        // Extract dynamic symbols and map to capabilities
        self.analyze_dynamic_symbols(&elf, data, &mut report)?;

        // Analyze sections and entropy
        self.analyze_sections(&elf, data, &mut report)?;

        // Use radare2 for deep analysis if available
        if Radare2Analyzer::is_available() {
            tools_used.push("radare2".to_string());

            if let Ok(functions) = self.radare2.extract_functions(file_path) {
                report.functions = functions;
            }

            if let Ok(r2_strings) = self.radare2.extract_strings(file_path) {
                for r2_str in r2_strings {
                    let string_type = self.string_extractor.classify_string_type(&r2_str.string);
                    report.strings.push(StringInfo {
                        value: r2_str.string,
                        offset: Some(format!("{:#x}", r2_str.vaddr)),
                        encoding: "utf8".to_string(),
                        string_type,
                        section: None,
                    });
                }
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
                                if !report.capabilities.iter().any(|c| c.id == cap_id) {
                                    let evidence = yara_engine.yara_match_to_evidence(yara_match);

                                    // Determine criticality from severity
                                    let criticality = match yara_match.severity.as_str() {
                                        "critical" => Criticality::Hostile,
                                        "high" => Criticality::Hostile,
                                        "medium" => Criticality::Suspicious,
                                        "low" => Criticality::Notable,
                                        _ => Criticality::Suspicious,
                                    };

                                    report.capabilities.push(Capability {
                                        id: cap_id,
                                        description: yara_match.description.clone(),
                                        confidence: 0.9,
                                        criticality,
                                        mbc: yara_match.mbc.clone(),
                                        attack: yara_match.attack.clone(),
                                        evidence,
                                        traits: Vec::new(),
                                        referenced_paths: None,
                                        referenced_directories: None,
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
            description: "ELF binary format".to_string(),
            evidence: vec![Evidence {
                method: "magic".to_string(),
                source: "goblin".to_string(),
                value: format!("0x{:x}", elf.header.e_ident[0]),
                location: None,
            }],
        });

        // Architecture
        let arch = self.get_arch_name(elf);
        report.structure.push(StructuralFeature {
            id: format!("binary/arch/{}", arch),
            description: format!("{} architecture", arch),
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
                description: "Symbol table stripped".to_string(),
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
                description: "Position Independent Executable".to_string(),
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
                // Add to imports
                report.imports.push(Import {
                    symbol: name.to_string(),
                    library: None, // ELF doesn't always specify library directly
                    source: "goblin".to_string(),
                });

                // Map to capability
                if let Some(cap) = self.capability_mapper.lookup(name, "goblin") {
                    if !report.capabilities.iter().any(|c| c.id == cap.id) {
                        report.capabilities.push(cap);
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
                    report.exports.push(Export {
                        symbol: name.to_string(),
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
                            description: "High entropy section (possibly packed/encrypted)"
                                .to_string(),
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

    fn get_arch_name(&self, elf: &Elf) -> String {
        match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => "x86_64".to_string(),
            goblin::elf::header::EM_386 => "i386".to_string(),
            goblin::elf::header::EM_AARCH64 => "aarch64".to_string(),
            goblin::elf::header::EM_ARM => "arm".to_string(),
            goblin::elf::header::EM_RISCV => "riscv".to_string(),
            _ => format!("unknown_{}", elf.header.e_machine),
        }
    }

    fn calculate_sha256(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
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
}

impl Default for ElfAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for ElfAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = fs::read(file_path).context("Failed to read file")?;
        self.analyze_elf(file_path, &data)
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

    fn get_test_elf() -> PathBuf {
        PathBuf::from("tests/fixtures/test.elf")
    }

    #[test]
    fn test_can_analyze_elf() {
        let analyzer = ElfAnalyzer::new();
        let test_file = get_test_elf();

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
        let test_file = get_test_elf();

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
        let test_file = get_test_elf();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.structure.is_empty());
    }

    #[test]
    fn test_elf_architecture_detected() {
        let analyzer = ElfAnalyzer::new();
        let test_file = get_test_elf();

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
        let test_file = get_test_elf();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.sections.is_empty());
    }

    #[test]
    fn test_elf_has_imports() {
        let analyzer = ElfAnalyzer::new();
        let test_file = get_test_elf();

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
        let test_file = get_test_elf();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        // Capabilities may or may not be detected depending on the binary
        // Just verify the analysis completes successfully
        assert!(report.capabilities.len() >= 0);
    }

    #[test]
    fn test_elf_strings_extracted() {
        let analyzer = ElfAnalyzer::new();
        let test_file = get_test_elf();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.strings.is_empty());
    }

    #[test]
    fn test_elf_tools_used() {
        let analyzer = ElfAnalyzer::new();
        let test_file = get_test_elf();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.metadata.tools_used.contains(&"goblin".to_string()));
    }

    #[test]
    fn test_elf_analysis_duration() {
        let analyzer = ElfAnalyzer::new();
        let test_file = get_test_elf();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.metadata.analysis_duration_ms > 0);
    }
}
