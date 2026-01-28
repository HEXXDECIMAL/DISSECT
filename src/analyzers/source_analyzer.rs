//! Template for source code analyzers to ensure consistency.
//!
//! This module provides a standard pipeline that all tree-sitter based analyzers
//! should use. It ensures that all analyzers have the same feature support and
//! follow the same analysis steps in the correct order.
//!
//! ## Usage
//!
//! Instead of manually implementing the analysis pipeline, language analyzers
//! should implement the `SourceAnalyzer` trait and call `analyze_with_treesitter()`
//! which handles the standard pipeline automatically.

use crate::capabilities::CapabilityMapper;
use crate::types::{AnalysisReport, Metrics, TargetInfo};
use anyhow::{Context, Result};
use std::path::Path;
use tree_sitter::{Language, Node, Parser};

/// Configuration for a language analyzer
pub struct LanguageConfig {
    /// Language identifier (e.g., "python", "ruby", "javascript")
    pub language: &'static str,
    /// Parser name (e.g., "tree-sitter-python")
    pub parser_name: &'static str,
    /// Human-readable description (e.g., "Python script")
    pub description: &'static str,
    /// File type identifier (e.g., "python_script", "ruby")
    pub file_type: &'static str,
    /// Tree-sitter language
    pub tree_sitter_language: Language,
    /// Node types for symbol extraction (e.g., ["call", "method_call"])
    pub symbol_node_types: &'static [&'static str],
}

/// Trait for language-specific analysis operations.
///
/// Implementers only need to provide the language-specific parts:
/// - Capability detection
/// - Function extraction
/// - Metrics computation
/// - Language configuration
///
/// The standard pipeline (paths, env, traits, composite rules, etc.) is
/// handled automatically by `analyze_with_treesitter()`.
pub trait SourceAnalyzer {
    /// Get the capability mapper for this analyzer
    fn capability_mapper(&self) -> &CapabilityMapper;

    /// Get language configuration
    fn language_config(&self) -> LanguageConfig;

    /// Detect language-specific capabilities
    ///
    /// This is where you implement malware pattern detection specific to
    /// the language (e.g., `eval()`, `exec()`, dangerous API calls).
    fn detect_capabilities(&self, root: &Node, source: &[u8], report: &mut AnalysisReport);

    /// Extract function metadata
    ///
    /// Extract function names, signatures, and metadata from the AST.
    fn extract_functions(&self, root: &Node, source: &[u8], report: &mut AnalysisReport);

    /// Compute language-specific metrics
    ///
    /// Calculate code metrics like complexity, entropy, etc.
    fn compute_metrics(&self, root: &Node, content: &str, report: &mut AnalysisReport) -> Metrics;

    /// Analyze source code using the standard tree-sitter pipeline.
    ///
    /// This is the main entry point that orchestrates the entire analysis:
    /// 1. Parse with tree-sitter
    /// 2. Create target info
    /// 3. Add language structural feature
    /// 4. Detect capabilities (language-specific)
    /// 5. Extract functions (language-specific)
    /// 6. Extract symbols for rule matching
    /// 7. Analyze paths and environment variables
    /// 8. Compute metrics (language-specific)
    /// 9. Evaluate traits
    /// 10. Evaluate composite rules
    /// 11. Record analysis duration
    ///
    /// This ensures ALL analyzers follow the same pipeline and don't miss steps.
    fn analyze_with_treesitter(
        &self,
        parser: &mut Parser,
        file_path: &Path,
        content: &str,
    ) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();
        let config = self.language_config();

        // Step 1: Parse with tree-sitter
        let tree = parser
            .parse(content, None)
            .with_context(|| format!("Failed to parse {} script", config.language))?;

        let root = tree.root_node();

        // Step 2: Create target info with standard SHA256
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: config.file_type.to_string(),
            size_bytes: content.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Step 3: Add language structural feature (standard format)
        report
            .structure
            .push(crate::analyzers::utils::create_language_feature(
                config.language,
                config.parser_name,
                config.description,
            ));

        // Step 4: Detect capabilities (language-specific implementation)
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Step 5: Extract functions (language-specific implementation)
        self.extract_functions(&root, content.as_bytes(), &mut report);

        // Step 6: Extract symbols for rule matching (ALWAYS DONE)
        crate::analyzers::symbol_extraction::extract_symbols(
            content,
            config.tree_sitter_language,
            config.symbol_node_types,
            &mut report,
        );

        // Step 7: Analyze paths and environment variables (ALWAYS DONE)
        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);

        // Step 8: Compute metrics (language-specific implementation)
        let metrics = self.compute_metrics(&root, content, &mut report);
        report.metrics = Some(metrics);

        // Step 9: Evaluate all rules (atomic + composite) and merge into report
        self.capability_mapper()
            .evaluate_and_merge_findings(&mut report, content.as_bytes(), Some(&tree));

        // Step 10: Record analysis duration
        let elapsed = start.elapsed().as_millis() as u64;
        report.metadata.analysis_duration_ms = elapsed;

        Ok(report)
    }
}

/// Helper to create a parser for a given tree-sitter language
pub fn create_parser(language: Language) -> Parser {
    let mut parser = Parser::new();
    parser.set_language(&language).unwrap();
    parser
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_config_creation() {
        // Just ensure the types compile
        let _config = LanguageConfig {
            language: "test",
            parser_name: "tree-sitter-test",
            description: "Test language",
            file_type: "test",
            tree_sitter_language: tree_sitter_python::LANGUAGE.into(),
            symbol_node_types: &["call"],
        };
    }
}
