use crate::analyzers::Analyzer;
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// VSCode extension.vsixmanifest analyzer
pub struct VsixManifestAnalyzer {
    capability_mapper: CapabilityMapper,
}

impl VsixManifestAnalyzer {
    pub fn new() -> Self {
        Self {
            capability_mapper: CapabilityMapper::empty(),
        }
    }

    pub fn with_capability_mapper(mut self, mapper: CapabilityMapper) -> Self {
        self.capability_mapper = mapper;
        self
    }

    fn analyze_manifest(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        let doc =
            roxmltree::Document::parse(content).context("Failed to parse .vsixmanifest XML")?;

        let mut identity = String::new();
        if let Some(node) = doc.descendants().find(|n| n.has_tag_name("Identity")) {
            let id = node.attribute("Id").unwrap_or("unknown");
            let publisher = node.attribute("Publisher").unwrap_or("unknown");
            let version = node.attribute("Version").unwrap_or("unknown");
            identity = format!("{}.{} v{}", publisher, id, version);
        }

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "vsix_manifest".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "manifest/vscode/vsixmanifest".to_string(),
            description: format!("VSCode extension manifest: {}", identity),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "roxmltree".to_string(),
                value: identity,
                location: None,
            }],
        });

        // Check for interesting properties
        for property in doc.descendants().filter(|n| n.has_tag_name("Property")) {
            if let (Some(id), Some(value)) = (property.attribute("Id"), property.attribute("Value"))
            {
                if id == "Microsoft.VisualStudio.Code.ExecutesCode" && value == "true" {
                    report.add_finding(
                        Finding::capability(
                            "eco/vscode/manifest/executes-code".to_string(),
                            "Extension explicitly marks that it executes code".to_string(),
                            1.0,
                        )
                        .with_criticality(Criticality::Notable)
                        .with_evidence(vec![Evidence {
                            method: "xml_attr".to_string(),
                            source: "vsixmanifest".to_string(),
                            value: "ExecutesCode=true".to_string(),
                            location: None,
                        }]),
                    );
                }
            }
        }

        // Evaluate trait definitions from YAML
        let trait_findings = self
            .capability_mapper
            .evaluate_traits(&report, content.as_bytes());
        let composite_findings = self
            .capability_mapper
            .evaluate_composite_rules(&report, content.as_bytes());

        for f in trait_findings.into_iter().chain(composite_findings) {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["roxmltree".to_string()];

        Ok(report)
    }

    fn calculate_sha256(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

impl Default for VsixManifestAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for VsixManifestAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let bytes = fs::read(file_path).context("Failed to read .vsixmanifest file")?;
        let content = String::from_utf8_lossy(&bytes);
        self.analyze_manifest(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path
            .file_name()
            .map(|n| {
                n.to_string_lossy()
                    .to_lowercase()
                    .ends_with(".vsixmanifest")
            })
            .unwrap_or(false)
    }
}
