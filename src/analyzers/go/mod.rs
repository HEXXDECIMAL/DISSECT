//! Go source code analyzer.
//!
//! Analyzes Go source files for malicious patterns and capabilities using tree-sitter.
//!
//! # Architecture
//! - `capabilities`: Capability detection (network, crypto, exec, etc.)
//! - `functions`: Function analysis, complexity metrics
//! - `idioms`: Go-specific idiom detection (goroutines, channels, defer)
//! - `metrics`: Code metrics computation
//! - `extraction`: AST traversal utilities
//!
//! # Capabilities Detected
//! - Command execution (exec.Command, syscall.Exec)
//! - Network operations (net.Dial, http.Get, etc.)
//! - Crypto operations (AES, RSA - ransomware indicators)
//! - File operations (os.Create, filepath.Walk)
//! - Container/cloud operations (docker, kubernetes)
//! - Anti-analysis techniques (reflection, obfuscation)

mod capabilities;
mod extraction;
mod functions;
mod idioms;
mod metrics;

use crate::analyzers::Analyzer;
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// Go analyzer using tree-sitter
pub struct GoAnalyzer {
    parser: RefCell<Parser>,
    capability_mapper: CapabilityMapper,
}

impl GoAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
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

    fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the Go source
        let tree = self
            .parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse Go source")?;

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "go".to_string(),
            size_bytes: content.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report
            .structure
            .push(crate::analyzers::utils::create_language_feature(
                "go",
                "tree-sitter-go",
                "Go source code",
            ));

        // Detect capabilities and patterns
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        // Extract function calls as symbols for symbol-based rule matching
        crate::analyzers::symbol_extraction::extract_symbols(
            content,
            tree_sitter_go::LANGUAGE.into(),
            &["call_expression"],
            &mut report,
        );

        // Detect Go idioms
        let go_idioms = self.detect_go_idioms(&root, content.as_bytes());

        // Add idioms to source code metrics if they exist
        if let Some(ref mut metrics) = report.source_code_metrics {
            metrics.go_idioms = Some(go_idioms);
        }

        // Compute metrics for ML analysis
        let metrics = self.compute_metrics(&root, content);
        report.metrics = Some(metrics);

        // Timing
        let elapsed = start.elapsed().as_millis() as u64;
        report.metadata.analysis_duration_ms = elapsed;

        Ok(report)
    }
}

impl Default for GoAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for GoAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read file: {}", file_path.display()))?;
        self.analyze_source(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e == "go")
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests;
