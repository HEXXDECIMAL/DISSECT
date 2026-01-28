//! Java bytecode (.class) analyzer.

use crate::analyzers::Analyzer;
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use anyhow::Result;
use std::path::Path;

mod parsing;
mod capabilities;
mod helpers;
mod tests;

pub use parsing::ClassInfo;

pub struct JavaClassAnalyzer {
    capability_mapper: CapabilityMapper,
}

impl JavaClassAnalyzer {
    pub fn new() -> Self {
        Self {
            capability_mapper: CapabilityMapper::empty(),
        }
    }

    pub fn with_capability_mapper(mut self, capability_mapper: CapabilityMapper) -> Self {
        self.capability_mapper = capability_mapper;
        self
    }

    fn calculate_sha256(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    fn analyze_class(&self, file_path: &Path, data: &[u8]) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();
        let class_info = self.parse_class_file(data)?;

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "java_class".to_string(),
            size_bytes: data.len() as u64,
            sha256: self.calculate_sha256(data),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        report.structure.push(StructuralFeature {
            id: "source/language/java".to_string(),
            desc: "Java bytecode".to_string(),
            evidence: vec![Evidence {
                method: "magic".to_string(),
                source: "class-parser".to_string(),
                value: "CAFEBABE".to_string(),
                location: Some("0x0".to_string()),
            }],
        });

        self.detect_capabilities(&class_info, &mut report);
        self.capability_mapper.evaluate_traits(&mut report, data);
        self.capability_mapper.evaluate_composite_rules(&mut report, data);

        let elapsed = start.elapsed().as_millis() as u64;
        report.metadata.analysis_duration_ms = elapsed;

        Ok(report)
    }
}

impl Analyzer for JavaClassAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        self.analyze_class(file_path, &data)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            ext == "class"
        } else {
            false
        }
    }
}

impl Default for JavaClassAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
