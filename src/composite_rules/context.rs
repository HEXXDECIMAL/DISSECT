//! Evaluation context and result types for composite rules.

use super::types::{FileType, Platform};
use crate::types::{AnalysisReport, Evidence, Finding};

/// Context for evaluating composite rules
pub struct EvaluationContext<'a> {
    pub report: &'a AnalysisReport,
    pub binary_data: &'a [u8],
    pub file_type: FileType,
    pub platform: Platform,
    /// Additional findings from previous evaluation iterations (for composite chaining)
    pub additional_findings: Option<&'a [Finding]>,
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
#[derive(Debug, Default)]
pub struct ConditionResult {
    pub matched: bool,
    pub evidence: Vec<Evidence>,
    pub traits: Vec<String>, // Trait IDs referenced
    /// Anti-analysis warnings (recursion bombs, etc.)
    pub warnings: Vec<AnalysisWarning>,
}

#[allow(dead_code)]
impl ConditionResult {
    pub fn no_match() -> Self {
        Self {
            matched: false,
            evidence: Vec::new(),
            traits: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn matched_with(evidence: Vec<Evidence>) -> Self {
        Self {
            matched: true,
            evidence,
            traits: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn with_warning(mut self, warning: AnalysisWarning) -> Self {
        self.warnings.push(warning);
        self
    }
}

/// Parameters for string condition evaluation (reduces argument count)
pub struct StringParams<'a> {
    pub exact: Option<&'a String>,
    pub regex: Option<&'a String>,
    pub word: Option<&'a String>,
    pub case_insensitive: bool,
    pub exclude_patterns: Option<&'a Vec<String>>,
    pub min_count: usize,
    pub search_raw: bool,
    pub compiled_regex: Option<&'a regex::Regex>,
    pub compiled_excludes: &'a [regex::Regex],
}
