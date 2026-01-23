use crate::analyzers::Analyzer;
use crate::capabilities::CapabilityMapper;
use crate::strings::StringExtractor;
use crate::types::*;
use anyhow::Result;
use std::path::Path;
use std::fs;

pub struct AppleScriptAnalyzer {
    capability_mapper: CapabilityMapper,
    string_extractor: StringExtractor,
}

impl AppleScriptAnalyzer {
    pub fn new() -> Self {
        Self {
            capability_mapper: CapabilityMapper::new(),
            string_extractor: StringExtractor::new(),
        }
    }

    pub fn with_capability_mapper(mut self, capability_mapper: CapabilityMapper) -> Self {
        self.capability_mapper = capability_mapper;
        self
    }
}

impl Default for AppleScriptAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for AppleScriptAnalyzer {
    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Ok(metadata) = fs::metadata(file_path) {
            if metadata.is_file() {
                // Check for compiled AppleScript magic bytes "Fasd" or file extension
                if let Ok(mut file) = fs::File::open(file_path) {
                    use std::io::Read;
                    let mut magic = [0u8; 4];
                    if file.read_exact(&mut magic).is_ok() {
                        if &magic == b"Fasd" {
                            return true;
                        }
                    }
                }
                
                if let Some(ext) = file_path.extension() {
                    return ext == "scpt";
                }
            }
        }
        false
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = fs::read(file_path)?;
        
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "applescript".to_string(),
            size_bytes: data.len() as u64,
            sha256: calculate_sha256(&data),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        
        // Use intelligent string extraction
        report.strings = self.string_extractor.extract_smart(&data);
        
        // Evaluate trait definitions from YAML
        let trait_findings = self.capability_mapper.evaluate_traits(&report, &data);
        for f in trait_findings {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }

        // Evaluate composite rules (after traits are merged)
        let composite_findings = self
            .capability_mapper
            .evaluate_composite_rules(&report, &data);
        for f in composite_findings {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }

        Ok(report)
    }
}

fn calculate_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
