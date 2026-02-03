//! Evaluation context and result types for composite rules.

use super::types::{FileType, Platform};
use crate::types::{AnalysisReport, Evidence, Finding};
use rustc_hash::FxHashSet;

/// Context for evaluating composite rules
pub struct EvaluationContext<'a> {
    pub report: &'a AnalysisReport,
    pub binary_data: &'a [u8],
    pub file_type: FileType,
    pub platform: Platform,
    /// Additional findings from previous evaluation iterations (for composite chaining)
    pub additional_findings: Option<&'a [Finding]>,
    /// Cached parsed AST (to avoid re-parsing for each ast_pattern trait)
    pub cached_ast: Option<&'a tree_sitter::Tree>,
    /// Cached index of finding IDs for fast O(1) trait lookups
    pub finding_id_index: Option<FxHashSet<String>>,
}

impl<'a> EvaluationContext<'a> {
    /// Create a new evaluation context
    pub fn new(
        report: &'a AnalysisReport,
        binary_data: &'a [u8],
        file_type: FileType,
        platform: Platform,
        additional_findings: Option<&'a [Finding]>,
        cached_ast: Option<&'a tree_sitter::Tree>,
    ) -> Self {
        // Build finding ID index for fast O(1) trait lookups
        let mut index = FxHashSet::default();
        for finding in &report.findings {
            index.insert(finding.id.clone());
        }
        if let Some(additional) = additional_findings {
            for finding in additional {
                index.insert(finding.id.clone());
            }
        }

        Self {
            report,
            binary_data,
            file_type,
            platform,
            additional_findings,
            cached_ast,
            finding_id_index: Some(index),
        }
    }

    /// Check if a finding ID exists (exact match only, O(1))
    pub fn has_finding_exact(&self, id: &str) -> bool {
        if let Some(ref index) = self.finding_id_index {
            index.contains(id)
        } else {
            // Fallback to linear search if index not built
            self.report.findings.iter().any(|f| f.id == id)
                || self
                    .additional_findings
                    .map(|af| af.iter().any(|f| f.id == id))
                    .unwrap_or(false)
        }
    }
}

/// Warning types for anti-analysis detection
#[derive(Debug, Clone)]
#[allow(dead_code, clippy::enum_variant_names)] // Infrastructure for future anti-analysis findings
pub enum AnalysisWarning {
    /// AST depth limit hit - potential recursion bomb
    AstTooDeep { max_depth: usize },
    /// Nesting depth limit hit in control flow
    NestingTooDeep { max_depth: u32 },
    /// Archive nesting depth limit hit
    ArchiveTooDeep { max_depth: usize },
}

/// Result of evaluating a condition
#[allow(dead_code)]
#[derive(Debug)]
pub struct ConditionResult {
    pub matched: bool,
    pub evidence: Vec<Evidence>,
    pub traits: Vec<String>, // Trait IDs referenced
    /// Anti-analysis warnings (recursion bombs, etc.)
    pub warnings: Vec<AnalysisWarning>,
    /// Precision points contributed by this condition (higher = more specific)
    pub precision: f32,
}

impl Default for ConditionResult {
    fn default() -> Self {
        Self {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
            warnings: Vec::new(),
            precision: 0.0,
        }
    }
}

#[allow(dead_code)]
impl ConditionResult {
    pub fn no_match() -> Self {
        Self {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
            warnings: Vec::new(),
            precision: 0.0,
        }
    }

    pub fn matched_with(evidence: Vec<Evidence>) -> Self {
        Self {
            matched: true,
            evidence,
            traits: Vec::new(),
            warnings: Vec::new(),
            precision: 0.0,
        }
    }

    pub fn with_warning(mut self, warning: AnalysisWarning) -> Self {
        self.warnings.push(warning);
        self
    }

    pub fn with_precision(mut self, precision: f32) -> Self {
        self.precision = precision;
        self
    }
}

/// Parameters for string condition evaluation (reduces argument count)
pub struct StringParams<'a> {
    pub exact: Option<&'a String>,
    pub substr: Option<&'a String>,
    pub regex: Option<&'a String>,
    pub word: Option<&'a String>,
    pub case_insensitive: bool,
    pub exclude_patterns: Option<&'a Vec<String>>,
    pub min_count: usize,
    pub compiled_regex: Option<&'a regex::Regex>,
    pub compiled_excludes: &'a [regex::Regex],
}
