//! PHP script analyzer using tree-sitter.

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

pub struct PhpAnalyzer {
    parser: RefCell<Parser>,
    capability_mapper: CapabilityMapper,
}

impl PhpAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .unwrap();

        Self {
            parser: RefCell::new(parser),
            capability_mapper: CapabilityMapper::empty(),
        }
    }

    pub fn with_capability_mapper(mut self, capability_mapper: CapabilityMapper) -> Self {
        self.capability_mapper = capability_mapper;
        self
    }

    pub(super) fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        let tree = self
            .parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse PHP script")?;

        let root = tree.root_node();

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "php".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        report.structure.push(StructuralFeature {
            id: "source/language/php".to_string(),
            desc: "PHP script".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-php".to_string(),
                value: "php".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        self.detect_capabilities(&root, content.as_bytes(), &mut report);
        self.extract_functions(&root, content.as_bytes(), &mut report);

        crate::analyzers::symbol_extraction::extract_symbols(
            content,
            tree_sitter_php::LANGUAGE_PHP.into(),
            &["function_call_expression"],
            &mut report,
        );

        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);

        let metrics = self.compute_metrics(&root, content, &mut report);
        report.metrics = Some(metrics);

        self.capability_mapper.evaluate_traits(&mut report, content.as_bytes());
        self.capability_mapper.evaluate_composite_rules(&mut report, content.as_bytes());

        let elapsed = start.elapsed().as_millis() as u64;
        report.metadata.analysis_duration_ms = elapsed;

        Ok(report)
    }

    fn calculate_sha256(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

impl Analyzer for PhpAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = std::fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read file: {}", file_path.display()))?;
        self.analyze_source(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            ext == "php" || ext == "phtml" || ext == "php3" || ext == "php4" || ext == "php5"
        } else {
            false
        }
    }
}

impl Default for PhpAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
