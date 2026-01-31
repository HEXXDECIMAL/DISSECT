//! Mach-O binary analyzer for macOS executables.

use crate::amos_cipher::AMOSCipherAnalyzer;
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
use std::sync::Arc;

/// Analyzer for macOS Mach-O binaries (executables, dylibs, bundles)
pub struct MachOAnalyzer {
    capability_mapper: CapabilityMapper,
    radare2: Radare2Analyzer,
    string_extractor: StringExtractor,
    yara_engine: Option<Arc<YaraEngine>>,
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

    /// Create analyzer with YARA rules loaded (takes ownership, wraps in Arc)
    pub fn with_yara(mut self, yara_engine: YaraEngine) -> Self {
        self.yara_engine = Some(Arc::new(yara_engine));
        self
    }

    /// Create analyzer with shared YARA engine
    pub fn with_yara_arc(mut self, yara_engine: Arc<YaraEngine>) -> Self {
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
        let timing = std::env::var("DISSECT_TIMING").is_ok();

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
            sha256: crate::analyzers::utils::calculate_sha256(data),
            architectures: Some(vec![self.arch_name(&macho)]),
        };

        let mut report = AnalysisReport::new(target);
        let mut tools_used = vec!["goblin".to_string()];

        // Analyze header and structure
        self.analyze_structure(&macho, &mut report)?;

        // Extract imports and map to capabilities
        self.analyze_imports(file_path, &macho, &mut report)?;

        // Extract exports
        self.analyze_exports(&macho, &mut report)?;

        // Analyze sections and entropy
        self.analyze_sections(&macho, data, &mut report)?;

        // AMOS cipher detection and decryption
        self.analyze_amos_cipher(data, &mut report, &mut tools_used);

        // Use radare2 for deep analysis if available - SINGLE r2 spawn for all data
        let t_r2 = std::time::Instant::now();
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
                if timing {
                    eprintln!("[TIMING] radare2 batched analysis: {:?}", t_r2.elapsed());
                }
                Some(batched.strings)
            } else {
                if timing {
                    eprintln!("[TIMING] radare2 batched analysis: {:?}", t_r2.elapsed());
                }
                None
            }
        } else {
            None
        };

        // Extract strings using language-aware extraction (Go/Rust) with pre-parsed Mach-O
        report.strings = self
            .string_extractor
            .extract_from_macho(&macho, data, r2_strings);
        tools_used.push("stng".to_string());

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
                                        desc: yara_match.desc.clone(),
                                        conf: 0.9, // YARA matches are high confidence
                                        crit: crate::types::Criticality::Inert,
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

        // Evaluate all rules (atomic + composite) and merge into report
        let t_eval = std::time::Instant::now();
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, data, None);
        if timing {
            eprintln!(
                "[TIMING] evaluate_and_merge_findings: {:?}",
                t_eval.elapsed()
            );
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = tools_used;

        Ok(report)
    }

    /// Generate structural traits (file format, architecture, signing, etc.)
    #[allow(dead_code)]
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
            desc: "Mach-O executable format".to_string(),
            conf: 1.0,
            crit: Criticality::Inert,
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
            desc: format!("{} architecture", arch),
            conf: 1.0,
            crit: Criticality::Inert,
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
                desc: "Code-signed binary".to_string(),
                conf: 1.0,
                crit: Criticality::Inert,
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
                    desc: "Command-line tool with usage string".to_string(),
                    conf: 0.9,
                    crit: Criticality::Inert,
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
                desc: "Contains FreeBSD version tags".to_string(),
                conf: 0.95,
                crit: Criticality::Inert,
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
                        desc: format!("Links to {} library", lib_name),
                        conf: 1.0,
                        crit: Criticality::Inert,
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
                    desc: format!("High entropy section ({})", section.name),
                    conf: 0.8,
                    crit: Criticality::Notable,
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
                desc: format!("{} highly complex functions", high_complexity.len()),
                conf: 0.7,
                crit: Criticality::Notable,
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
            desc: "Mach-O binary format".to_string(),
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
            desc: format!("{} architecture", arch),
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
                desc: "Binary has code signature".to_string(),
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

    fn analyze_imports(
        &self,
        file_path: &Path,
        macho: &MachO,
        report: &mut AnalysisReport,
    ) -> Result<()> {
        let imports = macho.imports()?;

        // Fallback: use symbol table and radare2 if imports() is empty
        if imports.is_empty() {
            // If we have radare2, use it to get library names for imports
            if Radare2Analyzer::is_available() {
                if let Ok(r2_imports) = self.radare2.extract_imports(file_path) {
                    for imp in r2_imports {
                        let name = imp.name.trim_start_matches('_');
                        report.imports.push(Import {
                            symbol: name.to_string(),
                            library: imp.lib_name.clone(),
                            source: "radare2".to_string(),
                        });

                        // Map import to capability
                        if let Some(cap) = self.capability_mapper.lookup(name, "radare2") {
                            if !report.findings.iter().any(|c| c.id == cap.id) {
                                report.findings.push(cap);
                            }
                        }
                    }
                }
            }

            // Also try symbol table for basic names (catch anything r2 missed)
            if let Some(syms) = &macho.symbols {
                for (name, sym) in syms.iter().flatten() {
                    // N_EXT (external) and N_UNDF (undefined) means it's an import
                    if (sym.n_type & 0x01 != 0) && (sym.n_type & 0x0e == 0) {
                        // Strip leading underscore
                        let clean_name = name.trim_start_matches('_');
                        // Only add if not already added by radare2
                        if !report.imports.iter().any(|i| i.symbol == clean_name) {
                            report.imports.push(Import {
                                symbol: clean_name.to_string(),
                                library: None,
                                source: "goblin_symtab".to_string(),
                            });
                        }
                    }
                }
            }
        } else {
            for imp in &imports {
                // Strip leading underscore for consistency with source code analysis
                let name = imp.name.trim_start_matches('_');
                report.imports.push(Import {
                    symbol: name.to_string(),
                    library: Some(imp.dylib.to_string()),
                    source: "goblin".to_string(),
                });

                // Map import to capability
                if let Some(cap) = self.capability_mapper.lookup(name, "goblin") {
                    // Check if we already have this capability
                    if !report.findings.iter().any(|c| c.id == cap.id) {
                        report.findings.push(cap);
                    }
                }
            }
        }

        Ok(())
    }

    fn analyze_exports(&self, macho: &MachO, report: &mut AnalysisReport) -> Result<()> {
        for exp in &macho.exports()? {
            let name = exp.name.trim_start_matches('_');
            report.exports.push(Export {
                symbol: name.to_string(),
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
                            desc: "High entropy section (possibly packed/encrypted)".to_string(),
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

    /// Analyze for AMOS cipher encryption and attempt decryption
    fn analyze_amos_cipher(
        &self,
        data: &[u8],
        report: &mut AnalysisReport,
        tools_used: &mut Vec<String>,
    ) {
        let amos_analyzer = AMOSCipherAnalyzer::new();

        // Detect AMOS cipher
        let detection = match amos_analyzer.detect(data) {
            Ok(d) => d,
            Err(_) => return,
        };

        if !detection.detected {
            return;
        }

        tools_used.push("amos_cipher".to_string());

        // Add detection finding
        let variant_name = match &detection.variant {
            Some(crate::amos_cipher::CipherVariant::TripleLookupTable) => {
                "Triple Lookup Table (Variant A)"
            }
            Some(crate::amos_cipher::CipherVariant::PRNGStreamCipher) => {
                "PRNG Stream Cipher (Variant B)"
            }
            None => "Unknown",
        };

        // Build evidence from detection
        let mut evidence: Vec<Evidence> = detection
            .evidence
            .iter()
            .map(|e| Evidence {
                method: e.indicator.clone(),
                source: "amos_cipher".to_string(),
                value: e.value.clone(),
                location: e.offset.map(|o| format!("0x{:x}", o)),
            })
            .collect();

        // Add payload location evidence
        for (offset, size) in &detection.payload_locations {
            evidence.push(Evidence {
                method: "payload_location".to_string(),
                source: "amos_cipher".to_string(),
                value: format!("{} bytes", size),
                location: Some(format!("0x{:x}", offset)),
            });
        }

        report.findings.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: "malware/stealer/amos/encrypted".to_string(),
            desc: format!(
                "AMOS stealer encrypted payload detected ({}), conf: {:.0}%",
                variant_name,
                detection.conf * 100.0
            ),
            conf: detection.conf,
            crit: Criticality::Hostile,
            mbc: Some("C0027".to_string()), // Obfuscated Files or Information
            attack: Some("T1027".to_string()),
            evidence: evidence.clone(),
        });

        // Attempt decryption
        match amos_analyzer.decrypt(data) {
            Ok(payloads) => {
                for payload in payloads {
                    // Add decrypted payload finding
                    let quality_str = match payload.quality() {
                        crate::amos_cipher::DecryptionQuality::High => "high",
                        crate::amos_cipher::DecryptionQuality::Medium => "medium",
                        crate::amos_cipher::DecryptionQuality::Low => "low",
                    };

                    let mut decrypt_evidence = vec![
                        Evidence {
                            method: "decryption".to_string(),
                            source: "amos_cipher".to_string(),
                            value: format!(
                                "{} bytes decrypted (quality: {})",
                                payload.plaintext.len(),
                                quality_str
                            ),
                            location: Some(format!("0x{:x}", payload.source_offset)),
                        },
                        Evidence {
                            method: "variant".to_string(),
                            source: "amos_cipher".to_string(),
                            value: format!("{:?}", payload.variant),
                            location: None,
                        },
                    ];

                    // Identify payload type based on content
                    let payload_type = identify_payload_type(&payload.plaintext);
                    decrypt_evidence.push(Evidence {
                        method: "payload_type".to_string(),
                        source: "amos_cipher".to_string(),
                        value: payload_type.clone(),
                        location: None,
                    });

                    // Add decrypted string preview if available
                    if let Some(ref script) = payload.as_string {
                        let preview: String = script.chars().take(500).collect();
                        decrypt_evidence.push(Evidence {
                            method: "decrypted_content".to_string(),
                            source: "amos_cipher".to_string(),
                            value: if script.len() > 500 {
                                format!("{}...", preview)
                            } else {
                                preview
                            },
                            location: None,
                        });
                    }

                    // Extract strings from decrypted payload using standard extractor
                    // This enables full trait analysis on the decrypted content
                    let decrypted_strings = self
                        .string_extractor
                        .extract(&payload.plaintext, Some("AMOS decrypted".to_string()));

                    for mut string_info in decrypted_strings {
                        // Mark strings as from decrypted content
                        string_info.offset =
                            Some(format!("decrypted:0x{:x}", payload.source_offset));
                        if !report.strings.iter().any(|s| s.value == string_info.value) {
                            report.strings.push(string_info);
                        }
                    }

                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: "malware/stealer/amos/decrypted".to_string(),
                        desc: format!(
                            "AMOS payload decrypted successfully ({} bytes)",
                            payload.plaintext.len()
                        ),
                        conf: match payload.quality() {
                            crate::amos_cipher::DecryptionQuality::High => 0.95,
                            crate::amos_cipher::DecryptionQuality::Medium => 0.75,
                            crate::amos_cipher::DecryptionQuality::Low => 0.5,
                        },
                        crit: Criticality::Hostile,
                        mbc: Some("C0027".to_string()),
                        attack: Some("T1027".to_string()),
                        evidence: decrypt_evidence,
                    });
                }
            }
            Err(e) => {
                report
                    .metadata
                    .errors
                    .push(format!("AMOS decryption failed: {}", e));
            }
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
                // Prefer arm64, fall back to first architecture
                let arches = fat.arches()?;
                let preferred_arch = arches
                    .iter()
                    .find(|a| a.cputype == 0x0100000c) // CPU_TYPE_ARM64
                    .or_else(|| arches.first());

                if let Some(arch) = preferred_arch {
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

/// Identify the type of decrypted payload based on content signatures.
fn identify_payload_type(data: &[u8]) -> String {
    // Check for common script/file signatures
    if data.starts_with(b"#!/") {
        // Shebang - identify interpreter
        if let Some(line_end) = data.iter().position(|&b| b == b'\n') {
            let shebang = String::from_utf8_lossy(&data[..line_end]);
            if shebang.contains("bash") || shebang.contains("/sh") {
                return "Shell script (bash/sh)".to_string();
            } else if shebang.contains("python") {
                return "Python script".to_string();
            } else if shebang.contains("perl") {
                return "Perl script".to_string();
            } else if shebang.contains("ruby") {
                return "Ruby script".to_string();
            }
            return format!("Script ({})", shebang.trim());
        }
    }

    // AppleScript indicators (common in AMOS)
    if data.starts_with(b"tell ") || data.starts_with(b"on ") || data.starts_with(b"set ") {
        return "AppleScript".to_string();
    }

    // osascript execution (inline AppleScript)
    if data.starts_with(b"osascript") {
        return "AppleScript (via osascript)".to_string();
    }

    // JSON
    if (data.starts_with(b"{") || data.starts_with(b"["))
        && data.iter().filter(|&&b| b == b'{' || b == b'}').count() >= 2
    {
        return "JSON".to_string();
    }

    // XML/Plist
    if data.starts_with(b"<?xml") || data.starts_with(b"<!DOCTYPE plist") {
        return "XML/Plist".to_string();
    }

    // Binary signatures
    if data.starts_with(b"MZ") {
        return "PE executable".to_string();
    }
    if data.starts_with(b"\x7fELF") {
        return "ELF executable".to_string();
    }
    if data.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) || data.starts_with(&[0xFE, 0xED, 0xFA, 0xCF]) {
        return "Mach-O executable".to_string();
    }
    if data.starts_with(b"PK") {
        return "ZIP archive".to_string();
    }

    // Check for high ASCII printable ratio (text content)
    let printable = data
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t')
        .count();
    let ratio = printable as f32 / data.len().max(1) as f32;

    if ratio > 0.85 {
        // Likely text - check for common patterns
        let text = String::from_utf8_lossy(data);
        if text.contains("curl ") || text.contains("wget ") {
            return "Shell commands (downloader)".to_string();
        }
        if text.contains("function ") || text.contains("var ") || text.contains("const ") {
            return "JavaScript".to_string();
        }
        if text.contains("def ") || text.contains("import ") {
            return "Python script".to_string();
        }
        return "Text/script".to_string();
    } else if ratio > 0.5 {
        return "Mixed text/binary".to_string();
    }

    "Binary data".to_string()
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

    // Tests for identify_payload_type function

    #[test]
    fn test_identify_payload_type_shell_script() {
        let data = b"#!/bin/bash\necho 'Hello World'";
        assert_eq!(identify_payload_type(data), "Shell script (bash/sh)");

        let data2 = b"#!/bin/sh\nls -la";
        assert_eq!(identify_payload_type(data2), "Shell script (bash/sh)");
    }

    #[test]
    fn test_identify_payload_type_python() {
        let data = b"#!/usr/bin/python3\nimport os";
        assert_eq!(identify_payload_type(data), "Python script");
    }

    #[test]
    fn test_identify_payload_type_applescript() {
        let data = b"tell application \"Finder\"";
        assert_eq!(identify_payload_type(data), "AppleScript");

        let data2 = b"on run\n  display dialog";
        assert_eq!(identify_payload_type(data2), "AppleScript");

        let data3 = b"set myVar to true";
        assert_eq!(identify_payload_type(data3), "AppleScript");
    }

    #[test]
    fn test_identify_payload_type_osascript() {
        let data = b"osascript -e 'tell application'";
        assert_eq!(identify_payload_type(data), "AppleScript (via osascript)");
    }

    #[test]
    fn test_identify_payload_type_json() {
        let data = b"{\"key\": \"value\"}";
        assert_eq!(identify_payload_type(data), "JSON");
    }

    #[test]
    fn test_identify_payload_type_xml() {
        let data = b"<?xml version=\"1.0\"?><root/>";
        assert_eq!(identify_payload_type(data), "XML/Plist");
    }

    #[test]
    fn test_identify_payload_type_pe() {
        let data = b"MZ\x90\x00\x03\x00";
        assert_eq!(identify_payload_type(data), "PE executable");
    }

    #[test]
    fn test_identify_payload_type_elf() {
        let data = b"\x7fELF\x02\x01\x01";
        assert_eq!(identify_payload_type(data), "ELF executable");
    }

    #[test]
    fn test_identify_payload_type_macho() {
        // Little-endian Mach-O magic
        let data = &[0xCF, 0xFA, 0xED, 0xFE, 0x07, 0x00];
        assert_eq!(identify_payload_type(data), "Mach-O executable");
    }

    #[test]
    fn test_identify_payload_type_zip() {
        let data = b"PK\x03\x04\x14\x00";
        assert_eq!(identify_payload_type(data), "ZIP archive");
    }

    #[test]
    fn test_identify_payload_type_downloader() {
        let data = b"curl -o /tmp/file https://example.com";
        assert_eq!(identify_payload_type(data), "Shell commands (downloader)");
    }

    #[test]
    fn test_identify_payload_type_javascript() {
        let data = b"function test() { var x = 1; }";
        assert_eq!(identify_payload_type(data), "JavaScript");
    }

    #[test]
    fn test_identify_payload_type_binary() {
        // Mostly non-printable data (control characters and high bytes)
        let data: Vec<u8> = (0u8..32).chain(128u8..255).cycle().take(100).collect();
        assert_eq!(identify_payload_type(&data), "Binary data");
    }

    #[test]
    fn test_identify_payload_type_text() {
        let data = b"This is just plain text without any specific markers.";
        assert_eq!(identify_payload_type(data), "Text/script");
    }

    #[test]
    fn test_identify_payload_type_mixed() {
        // ~60% printable
        let mut data = b"Some text here...".to_vec();
        data.extend_from_slice(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        ]);
        assert_eq!(identify_payload_type(&data), "Mixed text/binary");
    }
}
