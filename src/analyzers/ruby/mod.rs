//! Ruby script analyzer.

use crate::analyzers::Analyzer;
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::path::Path;
use tree_sitter::Parser;

mod capabilities;
mod extraction;
mod metrics;
mod tests;

/// Ruby analyzer using tree-sitter
pub struct RubyAnalyzer {
    parser: RefCell<Parser>,
    capability_mapper: CapabilityMapper,
}

impl Default for RubyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl RubyAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_ruby::LANGUAGE.into())
            .unwrap();

        Self {
            parser: RefCell::new(parser),
            capability_mapper: CapabilityMapper::empty(),
        }
    }

    /// Create analyzer with pre-existing capability mapper (avoids duplicate loading)
    pub fn with_capability_mapper(mut self, capability_mapper: CapabilityMapper) -> Self {
        self.capability_mapper = capability_mapper;
        self
    }

    pub(super) fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the Ruby source
        let tree = self
            .parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse Ruby source")?;

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "ruby".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "source/language/ruby".to_string(),
            desc: "Ruby source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-ruby".to_string(),
                value: "ruby".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        // Detect capabilities and patterns
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        // Extract method calls as symbols for symbol-based rule matching
        crate::analyzers::symbol_extraction::extract_symbols(
            content,
            tree_sitter_ruby::LANGUAGE.into(),
            &["call", "method_call"],
            &mut report,
        );

        // Compute metrics for ML analysis (BEFORE trait evaluation)
        let metrics = self.compute_metrics(&root, content);
        report.metrics = Some(metrics);

        // Evaluate trait definitions and composite rules
        let trait_findings = self
            .capability_mapper
            .evaluate_traits(&report, content.as_bytes());
        let composite_findings = self
            .capability_mapper
            .evaluate_composite_rules(&report, content.as_bytes());

        // Add all findings
        for f in trait_findings
            .into_iter()
            .chain(composite_findings.into_iter())
        {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-ruby".to_string()];

        Ok(report)
    }

    fn calculate_sha256(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

impl Analyzer for RubyAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = std::fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read file: {}", file_path.display()))?;
        self.analyze_source(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            ext == "rb"
        } else {
            false
        }
    }
}
