//! Python script analyzer using tree-sitter.

use crate::analyzers::Analyzer;
use crate::capabilities::CapabilityMapper;
use crate::types::{AnalysisReport, TargetInfo};
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::path::Path;
use tree_sitter::Parser;

mod capabilities;
mod extraction;
mod metrics;
mod tests;

pub struct PythonAnalyzer {
    parser: RefCell<Parser>,
    capability_mapper: CapabilityMapper,
}

impl PythonAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
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

    fn analyze_script(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        let tree = self
            .parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse Python script")?;

        let root = tree.root_node();

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "python_script".to_string(),
            size_bytes: content.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        report
            .structure
            .push(crate::analyzers::utils::create_language_feature(
                "python",
                "tree-sitter-python",
                "Python script",
            ));

        self.detect_capabilities(&root, content.as_bytes(), &mut report);
        self.extract_functions(&root, content.as_bytes(), &mut report);

        crate::analyzers::symbol_extraction::extract_symbols(
            content,
            tree_sitter_python::LANGUAGE.into(),
            &["call"],
            &mut report,
        );

        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);

        let metrics = self.compute_metrics(&root, content);
        report.metrics = Some(metrics);

        // Evaluate all rules (atomic + composite) and merge into report
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, content.as_bytes(), Some(&tree));

        let elapsed = start.elapsed().as_millis() as u64;
        report.metadata.analysis_duration_ms = elapsed;

        Ok(report)
    }
}

impl Analyzer for PythonAnalyzer {
    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            let ext_str = ext.to_str().unwrap_or("");
            ext_str == "py" || ext_str == "pyw" || ext_str == "pyi"
        } else {
            false
        }
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = std::fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read file: {}", file_path.display()))?;
        self.analyze_script(file_path, &content)
    }
}

impl PythonAnalyzer {
    pub fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        self.analyze_script(file_path, content)
    }
}

impl Default for PythonAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
