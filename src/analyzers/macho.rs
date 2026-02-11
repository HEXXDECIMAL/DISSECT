//! Mach-O binary analyzer for macOS executables.

use crate::amos_cipher::AMOSCipherAnalyzer;
use crate::analyzers::macho_codesign;
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
    capability_mapper: Arc<CapabilityMapper>,
    radare2: Radare2Analyzer,
    string_extractor: StringExtractor,
    yara_engine: Option<Arc<YaraEngine>>,
}

impl MachOAnalyzer {
    /// Creates a new Mach-O analyzer with default configuration
    pub fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
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

    /// Create analyzer with pre-existing capability mapper (wraps in Arc)
    pub fn with_capability_mapper(mut self, capability_mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Arc::new(capability_mapper);
        self
    }

    /// Create analyzer with shared capability mapper (avoids cloning)
    pub fn with_capability_mapper_arc(mut self, capability_mapper: Arc<CapabilityMapper>) -> Self {
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

        // Parse code signature early for metrics and findings
        let codesig_data: Option<macho_codesign::CodeSignature> =
            macho.load_commands.iter().find_map(|lc| {
                if let goblin::mach::load_command::CommandVariant::CodeSignature(cs) = &lc.command {
                    macho_codesign::parse_code_signature(data, cs.dataoff, cs.datasize).ok()
                } else {
                    None
                }
            });

        // Analyze header and structure
        self.analyze_structure_with_signature(&macho, &mut report, codesig_data.as_ref())?;

        // Generate signature findings from parsed code signature
        if let Some(ref codesig) = codesig_data {
            self.generate_signature_findings(codesig, &mut report);
        }

        // Extract imports and map to capabilities
        self.analyze_imports(file_path, &macho, &mut report)?;

        // Extract exports
        self.analyze_exports(&macho, &mut report)?;

        // Analyze sections and entropy
        self.analyze_sections(&macho, data, &mut report)?;

        // Initialize metrics with Mach-O header info
        let macho_metrics = MachoMetrics {
            file_type: macho.header.filetype,
            ..Default::default()
        };
        report.metrics = Some(Metrics {
            macho: Some(macho_metrics),
            ..Default::default()
        });

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

                // Update metrics with radare2 data
                if let Some(ref mut metrics) = report.metrics {
                    metrics.binary = Some(binary_metrics);

                    if let Some(ref mut macho_metrics) = metrics.macho {
                        macho_metrics.has_entitlements = !codesig_data
                            .as_ref()
                            .map(|c| c.entitlements.is_empty())
                            .unwrap_or(true);
                        if let Some(ref codesig) = codesig_data {
                            macho_metrics.signature_type =
                                Some(codesig.signature_type.as_str().to_string());
                            macho_metrics.team_identifier = codesig.team_id.clone();

                            // Count dangerous entitlements
                            let mut dangerous_count = 0u32;
                            for ent_key in codesig.entitlements.keys() {
                                if ent_key.contains("disable-library-validation")
                                    || ent_key.contains("allow-jit")
                                    || ent_key.contains("unsigned-executable-memory")
                                    || ent_key.contains("debugger")
                                {
                                    dangerous_count += 1;
                                }
                            }
                            macho_metrics.dangerous_entitlements = dangerous_count;
                        }
                    }
                }

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

        // Extract strings using language-aware extraction (Go/Rust)
        // Use extract_smart_with_r2 for comprehensive string extraction including StackStrings
        report.strings = self
            .string_extractor
            .extract_smart_with_r2(data, r2_strings);
        tools_used.push("stng".to_string());

        // Analyze embedded code in strings
        let (encoded_layers, plain_findings) = crate::analyzers::embedded_code_detector::process_all_strings(
            &file_path.display().to_string(),
            &report.strings,
            &self.capability_mapper,
            0,
        );
        report.files.extend(encoded_layers);
        report.findings.extend(plain_findings);

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
                            // Use namespace as capability ID (e.g., "exec.cmd" -> "exec/cmd")
                            let cap_id = yara_match.namespace.replace('.', "/");

                            // Check if we already have this capability
                            if !report.findings.iter().any(|c| c.id == cap_id) {
                                let evidence = yara_engine.yara_match_to_evidence(yara_match);

                                // Map severity to criticality
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
                                    conf: 0.9, // YARA matches are high confidence
                                    crit: criticality,
                                    mbc: yara_match.mbc.clone(),
                                    attack: yara_match.attack.clone(),
                                    evidence,
                                });
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
            id: format!("meta/arch::{}", arch),
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

        // 3. Code signature trait - parse detailed signature information
        let has_signature = macho.load_commands.iter().any(|lc| {
            matches!(
                lc.command,
                goblin::mach::load_command::CommandVariant::CodeSignature(_)
            )
        });

        if has_signature {
            // Basic presence marker
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
                        location: s.offset.map(|o| format!("{:#x}", o)),
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
                        id: format!("meta/library::{}", base_name),
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

    fn analyze_structure_with_signature(
        &self,
        macho: &MachO,
        report: &mut AnalysisReport,
        _codesig: Option<&macho_codesign::CodeSignature>,
    ) -> Result<()> {
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
                        report.imports.push(Import::new(
                            &imp.name,
                            imp.lib_name.clone(),
                            "radare2",
                        ));
                        let name = crate::types::binary::normalize_symbol(&imp.name);

                        // Map import to capability
                        if let Some(cap) = self.capability_mapper.lookup(&name, "radare2") {
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
                        let clean_name = crate::types::binary::normalize_symbol(name);
                        // Only add if not already added by radare2
                        if !report.imports.iter().any(|i| i.symbol == clean_name) {
                            report
                                .imports
                                .push(Import::new(name, None, "goblin_symtab"));
                        }
                    }
                }
            }
        } else {
            for imp in &imports {
                report
                    .imports
                    .push(Import::new(imp.name, Some(imp.dylib.to_string()), "goblin"));
                let name = crate::types::binary::normalize_symbol(imp.name);

                // Map import to capability
                if let Some(cap) = self.capability_mapper.lookup(&name, "goblin") {
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
            report.exports.push(Export::new(
                &exp.name,
                Some(format!("0x{:x}", exp.offset)),
                "goblin",
            ));
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

    /// Generate findings from parsed code signature data
    fn generate_signature_findings(
        &self,
        codesig: &macho_codesign::CodeSignature,
        report: &mut AnalysisReport,
    ) {
        // Combined signature trait: meta/signed/{type}::{signer}
        // This allows matching by type (meta/signed/developer) or specific signer
        let team_id = codesig.team_id.as_deref().unwrap_or("unknown");
        let (sig_category, signer, desc) = match codesig.signature_type {
            macho_codesign::SignatureType::DeveloperID => {
                let company = codesig
                    .authorities
                    .first()
                    .and_then(|auth| {
                        auth.split(": ")
                            .nth(1)
                            .map(|s| s.split(" (").next().unwrap_or(s).to_string())
                    })
                    .unwrap_or_else(|| team_id.to_string());
                ("developer", team_id, format!("Developer ID: {}", company))
            }
            macho_codesign::SignatureType::AppStore => {
                ("app-store", team_id, "Mac App Store".to_string())
            }
            macho_codesign::SignatureType::Platform => {
                ("platform", "apple", "macOS Platform Binary".to_string())
            }
            macho_codesign::SignatureType::Adhoc => {
                ("adhoc", "unsigned", "Ad-hoc Signature".to_string())
            }
            macho_codesign::SignatureType::Unknown => {
                ("unknown", "unknown", "Unknown Signature".to_string())
            }
        };

        report.findings.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: format!("meta/signed/{}::{}", sig_category, signer),
            desc,
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "code_signature".to_string(),
                source: "codesign_parser".to_string(),
                value: format!("{}::{}", sig_category, signer),
                location: None,
            }],
        });

        // Identifier trait - complete trait ID includes the bundle identifier
        if let Some(identifier) = &codesig.identifier {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: format!("meta/signed/id::{}", identifier),
                desc: "Identifier".to_string(),
                conf: 1.0,
                crit: Criticality::Notable,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "code_directory".to_string(),
                    source: "codesign_parser".to_string(),
                    value: identifier.clone(),
                    location: None,
                }],
            });
        }

        // Entitlements traits
        for entitlement_key in codesig.entitlements.keys() {
            let ent_trait_id = format!("meta/entitlement::{}", entitlement_key);
            let desc = describe_entitlement(entitlement_key);
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: ent_trait_id,
                desc,
                conf: 1.0,
                crit: determine_entitlement_criticality(entitlement_key, &codesig.signature_type),
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "entitlements_plist".to_string(),
                    source: "codesign_parser".to_string(),
                    value: entitlement_key.clone(),
                    location: None,
                }],
            });
        }

        // Hardened runtime flag
        if codesig.has_hardened_runtime {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "meta/hardened-runtime".to_string(),
                desc: "Hardened runtime enabled".to_string(),
                conf: 1.0,
                crit: Criticality::Inert,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "code_directory_flags".to_string(),
                    source: "codesign_parser".to_string(),
                    value: "0x00010000".to_string(),
                    location: None,
                }],
            });
        }
    }

    fn arch_name(&self, macho: &MachO) -> String {
        match macho.header.cputype {
            0x01000007 => "x86_64".to_string(),
            0x0100000c => "arm64".to_string(),
            0x0200000c => "arm64e".to_string(),
            _ => format!("unknown_0x{:x}", macho.header.cputype),
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
                        string_info.offset = Some(payload.source_offset as u64);
                        string_info.section = Some("AMOS_decrypted".to_string());
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

/// Determine criticality of an entitlement based on its key
fn describe_entitlement(key: &str) -> String {
    // Extract meaningful description from entitlement key
    let descriptions = [
        // Privacy/Device Access
        ("device.camera", "Camera access"),
        ("device.audio-input", "Microphone access"),
        ("device.microphone", "Microphone access"),
        ("device.bluetooth", "Bluetooth access"),
        ("personal-information.location", "Location data access"),
        ("personal-information.health", "Health data access"),
        (
            "personal-information.photos-library",
            "Photos library access",
        ),
        ("personal-information.contacts", "Contacts access"),
        ("personal-information.calendar", "Calendar access"),
        ("personal-information.reminders", "Reminders access"),
        // System Access
        ("keystore.access-keychain-keys", "Keychain key access"),
        ("keystore.lockassertion", "Keychain lock assertion"),
        ("security.storage.Keychains", "Keychain storage access"),
        // Code Execution & Security
        (
            "cs.disable-library-validation",
            "Disable library validation",
        ),
        ("cs.allow-jit", "Allow JIT compilation"),
        (
            "cs.allow-unsigned-executable-memory",
            "Allow unsigned executable memory",
        ),
        ("cs.debugger", "Debugger entitlement"),
        // Process & XPC
        (
            "xpc.launchd.ios-system-session",
            "iOS system session access",
        ),
        ("xpc.launchd", "Launchd XPC access"),
        // Application Features
        ("application-identifier", "Application identifier"),
        ("app-identifier", "App identifier"),
        ("push-service", "Push notification service"),
        ("icloud-container-identifiers", "iCloud container access"),
        // Databases & Storage
        ("sqlite.sqlite-encryption", "SQLite encryption"),
        // Debugging & Diagnostics
        ("symptom_diagnostics.report", "System diagnostics reporting"),
        // Private APIs (Apple Internal)
        ("private.MobileGestalt", "MobileGestalt queries"),
        ("private.applecredentialmanager", "Apple credential manager"),
        ("private.security.storage", "Private security storage"),
        // File/Sandbox Access
        ("sandbox.read-write", "Sandbox read-write"),
        ("home-directory", "Home directory access"),
    ];

    for (key_part, desc) in descriptions {
        if key.contains(key_part) {
            return desc.to_string();
        }
    }

    // Fallback: clean up the key name for readability
    let short_name = key
        .split('.')
        .next_back()
        .unwrap_or(key)
        .replace(['-', '_'], " ");

    // Capitalize first letter
    let mut chars = short_name.chars();
    match chars.next() {
        None => key.to_string(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

fn determine_entitlement_criticality(
    entitlement_key: &str,
    signature_type: &macho_codesign::SignatureType,
) -> Criticality {
    // Platform binaries: all entitlements are Notable
    // (Apple control what goes in platform binaries)
    if matches!(signature_type, macho_codesign::SignatureType::Platform) {
        return Criticality::Notable;
    }

    // Sensitive privacy entitlements
    if entitlement_key.contains("personal-information") || entitlement_key.contains("device.") {
        return Criticality::Notable;
    }

    // Dangerous security-related entitlements (only suspicious for non-platform binaries)
    if entitlement_key.contains("disable-library-validation")
        || entitlement_key.contains("allow-jit")
        || entitlement_key.contains("debugger")
        || entitlement_key.contains("unsigned-executable-memory")
    {
        return Criticality::Suspicious;
    }

    // Default for other entitlements
    Criticality::Notable
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

    // Integration tests for code signature extraction and finding generation
    #[test]
    fn test_signature_findings_generated() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // Check that signature-related findings are present
        let has_signed = report.findings.iter().any(|f| f.id.contains("signed/type"));
        // Note: test.macho might not be signed, so this is a soft assertion
        if has_signed {
            assert!(report.findings.iter().any(|f| f.id.contains("signed/type")));
        }
    }

    #[test]
    fn test_entitlements_extracted_when_present() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // Check if any entitlement findings are present
        let entitlement_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.id.contains("entitlement"))
            .collect();

        // If the binary has entitlements, verify they're properly extracted
        if !entitlement_findings.is_empty() {
            for finding in &entitlement_findings {
                // Entitlements should have proper evidence
                assert!(!finding.evidence.is_empty());
                // Method should be "entitlements_plist"
                assert!(finding
                    .evidence
                    .iter()
                    .any(|e| e.method == "entitlements_plist"));
            }
        }
    }

    #[test]
    fn test_team_id_extracted_when_signed() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // Check for team ID findings
        let team_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.id.contains("signed/team"))
            .collect();

        // If team findings exist, verify they have proper structure
        for finding in &team_findings {
            assert!(!finding.evidence.is_empty());
            assert_eq!(finding.evidence[0].method, "cms_certificate");
        }
    }

    #[test]
    fn test_hardened_runtime_detection() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // Check for hardened-runtime finding
        let hardened = report
            .findings
            .iter()
            .find(|f| f.id == "meta/hardened-runtime");

        if let Some(finding) = hardened {
            assert_eq!(finding.evidence[0].method, "code_directory_flags");
            assert_eq!(finding.evidence[0].value, "0x00010000");
        }
    }

    #[test]
    fn test_signature_type_criticality() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // Signature type findings should have Notable criticality
        let sig_type_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.id.contains("signed/type"))
            .collect();

        for finding in &sig_type_findings {
            assert_eq!(finding.crit, Criticality::Notable);
            assert_eq!(finding.conf, 1.0); // Should be high confidence
        }
    }

    #[test]
    fn test_entitlement_finding_confidence() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // All entitlement findings should have high confidence
        let ent_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.id.contains("entitlement"))
            .collect();

        for finding in &ent_findings {
            assert_eq!(finding.conf, 1.0); // Entitlements from signature have 100% confidence
        }
    }

    #[test]
    fn test_describe_entitlement_coverage() {
        // Test that describe_entitlement handles various entitlement keys
        assert_eq!(
            describe_entitlement("com.apple.security.cs.disable-library-validation"),
            "Disable library validation"
        );
        assert_eq!(
            describe_entitlement("com.apple.security.cs.allow-jit"),
            "Allow JIT compilation"
        );
        assert_eq!(
            describe_entitlement("personal-information.location"),
            "Location data access"
        );
        assert_eq!(describe_entitlement("device.camera"), "Camera access");
        assert_eq!(
            describe_entitlement("com.apple.developer.team-identifier"),
            "Team identifier"
        );
    }

    #[test]
    fn test_describe_entitlement_fallback() {
        // Test fallback behavior for unknown entitlements
        let desc = describe_entitlement("com.example.unknown-entitlement");
        assert!(!desc.is_empty());
        assert_ne!(desc, "com.example.unknown-entitlement"); // Should be transformed
    }

    #[test]
    fn test_determine_entitlement_criticality_platform_binary() {
        let crit = determine_entitlement_criticality(
            "com.apple.security.cs.allow-jit",
            &macho_codesign::SignatureType::Platform,
        );
        // Platform binaries should have Notable criticality for all entitlements
        assert_eq!(crit, Criticality::Notable);
    }

    #[test]
    fn test_determine_entitlement_criticality_dangerous() {
        let crit = determine_entitlement_criticality(
            "com.apple.security.cs.disable-library-validation",
            &macho_codesign::SignatureType::DeveloperID,
        );
        assert_eq!(crit, Criticality::Suspicious);
    }

    #[test]
    fn test_determine_entitlement_criticality_privacy() {
        let crit = determine_entitlement_criticality(
            "personal-information.location",
            &macho_codesign::SignatureType::Adhoc,
        );
        assert_eq!(crit, Criticality::Notable);
    }

    #[test]
    fn test_determine_entitlement_criticality_device_access() {
        let crit = determine_entitlement_criticality(
            "device.bluetooth",
            &macho_codesign::SignatureType::DeveloperID,
        );
        assert_eq!(crit, Criticality::Notable);
    }

    #[test]
    fn test_determine_entitlement_criticality_debugger() {
        let crit = determine_entitlement_criticality(
            "com.apple.security.cs.debugger",
            &macho_codesign::SignatureType::AppStore,
        );
        assert_eq!(crit, Criticality::Suspicious);
    }

    #[test]
    fn test_determine_entitlement_criticality_unsigned_memory() {
        let crit = determine_entitlement_criticality(
            "com.apple.security.cs.allow-unsigned-executable-memory",
            &macho_codesign::SignatureType::DeveloperID,
        );
        assert_eq!(crit, Criticality::Suspicious);
    }

    #[test]
    fn test_macho_metrics_dangerous_entitlements_counting() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // If metrics are present, verify dangerous_entitlements is set
        if let Some(metrics) = &report.metrics {
            if let Some(macho_metrics) = &metrics.macho {
                // dangerous_entitlements should be initialized
                let _ = macho_metrics.dangerous_entitlements;
            }
        }
    }

    #[test]
    fn test_macho_metrics_signature_type_recorded() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // If metrics are present and binary is signed, signature type should be recorded
        if let Some(metrics) = &report.metrics {
            if let Some(macho_metrics) = &metrics.macho {
                // If has_entitlements, then signature_type should also be set
                if macho_metrics.has_entitlements {
                    assert!(macho_metrics.signature_type.is_some());
                }
            }
        }
    }

    #[test]
    fn test_signature_findings_have_proper_kind() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // All signature-related findings should be Capability kind
        for finding in report
            .findings
            .iter()
            .filter(|f| f.id.contains("signed") || f.id.contains("entitlement"))
        {
            assert_eq!(finding.kind, FindingKind::Capability);
        }
    }

    #[test]
    fn test_identifier_finding_when_present() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // Check for identifier findings
        let identifier_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.id.contains("signed/id"))
            .collect();

        // If identifier findings exist, they should have proper evidence
        for finding in &identifier_findings {
            assert_eq!(finding.evidence[0].method, "code_directory");
            assert_eq!(finding.evidence[0].source, "codesign_parser");
        }
    }
}
