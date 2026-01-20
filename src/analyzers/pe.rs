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

pub struct PEAnalyzer {
    capability_mapper: CapabilityMapper,
    radare2: Radare2Analyzer,
    string_extractor: StringExtractor,
    yara_engine: Option<YaraEngine>,
}

impl PEAnalyzer {
    pub fn new() -> Self {
        Self {
            capability_mapper: CapabilityMapper::new(),
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

    fn analyze_pe(&self, file_path: &Path, data: &[u8]) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse with goblin
        let pe = PE::parse(data)?;

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "pe".to_string(),
            size_bytes: data.len() as u64,
            sha256: self.calculate_sha256(data),
            architectures: Some(vec![self.get_arch_name(&pe)]),
        };

        let mut report = AnalysisReport::new(target);
        let mut tools_used = vec!["goblin".to_string()];

        // Analyze header and structure
        self.analyze_structure(&pe, &mut report)?;

        // Extract imports and map to capabilities
        self.analyze_imports(&pe, &mut report)?;

        // Extract exports
        self.analyze_exports(&pe, &mut report)?;

        // Analyze sections and entropy
        self.analyze_sections(&pe, data, &mut report)?;

        // Use radare2 for deep analysis if available
        if Radare2Analyzer::is_available() {
            tools_used.push("radare2".to_string());

            if let Ok(functions) = self.radare2.extract_functions(file_path) {
                report.functions = functions;
            }

            if let Ok(r2_strings) = self.radare2.extract_strings(file_path) {
                for r2_str in r2_strings {
                    report.strings.push(StringInfo {
                        value: r2_str.string,
                        offset: Some(format!("{:#x}", r2_str.vaddr)),
                        encoding: "utf8".to_string(),
                        string_type: StringType::Plain,
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
                match yara_engine.scan_bytes(data) {
                    Ok(matches) => {
                        report.yara_matches = matches.clone();

                        for yara_match in &matches {
                            let capability_id = self.yara_namespace_to_capability(&yara_match.namespace);

                            if let Some(cap_id) = capability_id {
                                if !report.capabilities.iter().any(|c| c.id == cap_id) {
                                    let evidence = yara_engine.yara_match_to_evidence(yara_match);
                                    report.capabilities.push(Capability {
                                        id: cap_id,
                                        description: yara_match.description.clone(),
                                        confidence: 0.9,
                                        evidence,
                                    });
                                }
                            }
                        }
                    }
                    Err(e) => {
                        report.metadata.errors.push(format!("YARA scan failed: {}", e));
                    }
                }
            }
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = tools_used;

        Ok(report)
    }

    fn analyze_structure(&self, pe: &PE, report: &mut AnalysisReport) -> Result<()> {
        // Binary format
        report.structure.push(StructuralFeature {
            id: "binary/format/pe".to_string(),
            description: "PE binary format".to_string(),
            evidence: vec![Evidence {
                method: "magic".to_string(),
                source: "goblin".to_string(),
                value: "MZ".to_string(),
                location: None,
            }],
        });

        // Architecture
        let arch = self.get_arch_name(pe);
        report.structure.push(StructuralFeature {
            id: format!("binary/arch/{}", arch),
            description: format!("{} architecture", arch),
            evidence: vec![Evidence {
                method: "header".to_string(),
                source: "goblin".to_string(),
                value: format!("machine={:#x}", pe.header.coff_header.machine),
                location: None,
            }],
        });

        // Check if DLL
        if pe.is_lib {
            report.structure.push(StructuralFeature {
                id: "binary/dll".to_string(),
                description: "Dynamic Link Library".to_string(),
                evidence: vec![Evidence {
                    method: "header".to_string(),
                    source: "goblin".to_string(),
                    value: "DLL".to_string(),
                    location: None,
                }],
            });
        }

        // Check for ASLR (Address Space Layout Randomization)
        if let Some(characteristics) = pe.header.optional_header.as_ref().map(|h| h.windows_fields.dll_characteristics) {
            if characteristics & 0x40 != 0 {
                report.structure.push(StructuralFeature {
                    id: "binary/aslr".to_string(),
                    description: "Address Space Layout Randomization enabled".to_string(),
                    evidence: vec![Evidence {
                        method: "header".to_string(),
                        source: "goblin".to_string(),
                        value: "DYNAMIC_BASE".to_string(),
                        location: None,
                    }],
                });
            }

            // Check for DEP (Data Execution Prevention)
            if characteristics & 0x100 != 0 {
                report.structure.push(StructuralFeature {
                    id: "binary/dep".to_string(),
                    description: "Data Execution Prevention enabled".to_string(),
                    evidence: vec![Evidence {
                        method: "header".to_string(),
                        source: "goblin".to_string(),
                        value: "NX_COMPAT".to_string(),
                        location: None,
                    }],
                });
            }
        }

        // Check for code signing
        if !pe.certificates.is_empty() {
            report.structure.push(StructuralFeature {
                id: "binary/signed".to_string(),
                description: "Code-signed binary".to_string(),
                evidence: vec![Evidence {
                    method: "certificates".to_string(),
                    source: "goblin".to_string(),
                    value: format!("{} certificates", pe.certificates.len()),
                    location: None,
                }],
            });
        }

        Ok(())
    }

    fn analyze_imports(&self, pe: &PE, report: &mut AnalysisReport) -> Result<()> {
        // Analyze imports from PE import table
        for import in &pe.imports {
            let library = import.dll.to_string();
            let symbol = import.name.to_string();

            // Add to imports
            report.imports.push(Import {
                symbol: symbol.clone(),
                library: Some(library.clone()),
                source: "goblin".to_string(),
            });

            // Map Windows API calls to capabilities
            if let Some(cap) = self.windows_api_to_capability(&symbol, &library) {
                if !report.capabilities.iter().any(|c| c.id == cap.id) {
                    report.capabilities.push(cap);
                }
            }

            // Also check capability mapper for generic symbol mapping
            if let Some(cap) = self.capability_mapper.lookup(&symbol, "goblin") {
                if !report.capabilities.iter().any(|c| c.id == cap.id) {
                    report.capabilities.push(cap);
                }
            }
        }

        Ok(())
    }

    fn analyze_exports(&self, pe: &PE, report: &mut AnalysisReport) -> Result<()> {
        // Analyze exports
        for export in &pe.exports {
            if let Some(name) = &export.name {
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
            let name = section.name().unwrap_or("unknown");
            let size = section.size_of_raw_data as u64;

            // Calculate entropy for section
            let section_offset = section.pointer_to_raw_data as usize;
            let section_size = section.size_of_raw_data as usize;

            let entropy = if section_offset + section_size <= data.len() && section_size > 0 {
                let section_data = &data[section_offset..section_offset + section_size];
                calculate_entropy(section_data)
            } else {
                0.0
            };

            report.sections.push(Section {
                name: name.to_string(),
                size,
                entropy,
                permissions: Some(format!("{:#x}", section.characteristics)),
            });

            // Add entropy-based structural features
            let level = EntropyLevel::from_value(entropy);
            if level == EntropyLevel::High {
                report.structure.push(StructuralFeature {
                    id: "entropy/high".to_string(),
                    description: "High entropy section (possibly packed/encrypted)".to_string(),
                    evidence: vec![Evidence {
                        method: "entropy".to_string(),
                        source: "entropy_analyzer".to_string(),
                        value: format!("{:.2}", entropy),
                        location: Some(name.to_string()),
                    }],
                });
            }
        }

        Ok(())
    }

    fn get_arch_name(&self, pe: &PE) -> String {
        match pe.header.coff_header.machine {
            0x014c => "i386".to_string(),
            0x8664 => "x86_64".to_string(),
            0x01c4 => "arm".to_string(),
            0xaa64 => "aarch64".to_string(),
            _ => format!("unknown_{:#x}", pe.header.coff_header.machine),
        }
    }

    fn windows_api_to_capability(&self, symbol: &str, library: &str) -> Option<Capability> {
        // Map Windows API calls to capabilities
        let (cap_id, description, confidence) = match (library.to_lowercase().as_str(), symbol) {
            // Process execution
            (lib, sym) if lib.contains("kernel32") && (sym == "CreateProcessA" || sym == "CreateProcessW") => {
                ("exec/process/create", "Create new process", 1.0)
            }
            (lib, sym) if lib.contains("kernel32") && (sym == "WinExec" || sym == "ShellExecuteA" || sym == "ShellExecuteW") => {
                ("exec/command/shell", "Execute shell commands", 1.0)
            }

            // Registry operations
            (lib, sym) if lib.contains("advapi32") && sym.starts_with("Reg") => {
                if sym.contains("Query") || sym.contains("Get") {
                    ("registry/read", "Read Windows Registry", 0.9)
                } else if sym.contains("Set") || sym.contains("Create") {
                    ("registry/write", "Write Windows Registry", 0.9)
                } else if sym.contains("Delete") {
                    ("registry/delete", "Delete Registry keys", 0.9)
                } else {
                    ("registry/access", "Access Windows Registry", 0.8)
                }
            }

            // Service manipulation
            (lib, sym) if lib.contains("advapi32") && sym.contains("Service") => {
                if sym.contains("Create") {
                    ("service/create", "Create Windows service", 1.0)
                } else if sym.contains("Start") {
                    ("service/start", "Start Windows service", 1.0)
                } else if sym.contains("Delete") {
                    ("service/delete", "Delete Windows service", 1.0)
                } else {
                    ("service/manage", "Manage Windows services", 0.9)
                }
            }

            // Network operations
            (lib, sym) if (lib.contains("ws2_32") || lib.contains("wsock32")) && sym == "socket" => {
                ("net/socket/create", "Create network socket", 1.0)
            }
            (lib, sym) if (lib.contains("ws2_32") || lib.contains("wsock32")) && sym == "connect" => {
                ("net/socket/connect", "Connect to remote host", 1.0)
            }
            (lib, sym) if (lib.contains("ws2_32") || lib.contains("wsock32")) && sym == "bind" => {
                ("net/socket/bind", "Bind network socket", 1.0)
            }
            (lib, sym) if lib.contains("wininet") || lib.contains("winhttp") => {
                ("net/http/client", "HTTP client operations", 0.9)
            }

            // File operations
            (lib, sym) if lib.contains("kernel32") && (sym == "CreateFileA" || sym == "CreateFileW") => {
                ("fs/access", "File operations", 0.7)
            }
            (lib, sym) if lib.contains("kernel32") && (sym == "WriteFile" || sym == "WriteFileEx") => {
                ("fs/write", "Write files", 0.9)
            }
            (lib, sym) if lib.contains("kernel32") && (sym == "DeleteFileA" || sym == "DeleteFileW") => {
                ("fs/delete", "Delete files", 1.0)
            }

            // Memory manipulation
            (lib, sym) if lib.contains("kernel32") && (sym == "VirtualAlloc" || sym == "VirtualAllocEx") => {
                ("memory/allocate", "Allocate virtual memory", 0.9)
            }
            (lib, sym) if lib.contains("kernel32") && (sym == "WriteProcessMemory" || sym == "ReadProcessMemory") => {
                ("memory/process", "Access process memory", 1.0)
            }

            // Crypto operations
            (lib, sym) if lib.contains("advapi32") || lib.contains("bcrypt") || lib.contains("crypt32") => {
                if sym.contains("Encrypt") {
                    ("crypto/encrypt", "Encryption operations", 0.9)
                } else if sym.contains("Decrypt") {
                    ("crypto/decrypt", "Decryption operations", 0.9)
                } else if sym.contains("Hash") {
                    ("crypto/hash", "Hashing operations", 0.8)
                } else {
                    ("crypto/operation", "Cryptographic operations", 0.7)
                }
            }

            // Privilege operations
            (lib, sym) if lib.contains("advapi32") && (sym == "AdjustTokenPrivileges" || sym == "OpenProcessToken") => {
                ("privilege/token", "Token manipulation", 1.0)
            }

            // DLL injection
            (lib, sym) if lib.contains("kernel32") && (sym == "LoadLibraryA" || sym == "LoadLibraryW") => {
                ("exec/dylib/load", "Load dynamic library", 0.8)
            }
            (lib, sym) if lib.contains("kernel32") && (sym == "CreateRemoteThread" || sym == "CreateThread") => {
                ("exec/thread/create", "Create thread", 0.9)
            }

            // Anti-analysis
            (lib, sym) if lib.contains("kernel32") && (sym == "IsDebuggerPresent" || sym == "CheckRemoteDebuggerPresent") => {
                ("anti-analysis/debugger-detect", "Debugger detection", 1.0)
            }

            _ => return None,
        };

        Some(Capability {
            id: cap_id.to_string(),
            description: description.to_string(),
            confidence,
            evidence: vec![Evidence {
                method: "symbol".to_string(),
                source: "goblin".to_string(),
                value: format!("{}!{}", library, symbol),
                location: None,
            }],
        })
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
            ["registry", sub] => Some(format!("registry/{}", sub)),
            ["service", sub] => Some(format!("service/{}", sub)),
            _ => None,
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
