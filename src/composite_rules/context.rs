//! Evaluation context and result types for composite rules.

use super::debug::DebugCollector;
use super::section_map::SectionMap;
use super::types::{FileType, Platform};
use crate::types::{AnalysisReport, Evidence, Finding};
use rustc_hash::{FxHashSet, FxHasher};
use std::hash::{Hash, Hasher};

/// Compute a fast hash of a string for deduplication.
#[inline]
fn hash_str(s: &str) -> u64 {
    let mut hasher = FxHasher::default();
    s.hash(&mut hasher);
    hasher.finish()
}

/// Context for evaluating composite rules
#[derive(Debug)]
pub struct EvaluationContext<'a> {
    pub report: &'a AnalysisReport,
    pub binary_data: &'a [u8],
    pub file_type: FileType,
    /// Platform filter(s) from CLI - rules match if their platforms intersect with these
    pub platforms: Vec<Platform>,
    /// Additional findings from previous evaluation iterations (for composite chaining)
    pub additional_findings: Option<&'a [Finding]>,
    /// Cached parsed AST (to avoid re-parsing for each ast_pattern trait)
    pub cached_ast: Option<&'a tree_sitter::Tree>,
    /// Cached index of finding ID hashes for fast O(1) trait lookups.
    /// Stores u64 hashes instead of String to avoid cloning finding IDs.
    pub finding_id_index: Option<FxHashSet<u64>>,
    /// Optional debug collector - None for hot path, Some during test-rules
    /// When present, evaluation records detailed debug info
    pub debug_collector: Option<&'a DebugCollector>,
    /// Section map for location-constrained matching (lazy-initialized)
    pub section_map: Option<SectionMap>,
}

impl<'a> EvaluationContext<'a> {
    /// Create a new evaluation context
    pub fn new(
        report: &'a AnalysisReport,
        binary_data: &'a [u8],
        file_type: FileType,
        platforms: Vec<Platform>,
        additional_findings: Option<&'a [Finding]>,
        cached_ast: Option<&'a tree_sitter::Tree>,
    ) -> Self {
        // Build finding ID hash index for fast O(1) trait lookups.
        // We store hashes instead of cloning the full ID strings.
        let mut index = FxHashSet::default();
        for finding in &report.findings {
            index.insert(hash_str(&finding.id));
        }
        if let Some(additional) = additional_findings {
            for finding in additional {
                index.insert(hash_str(&finding.id));
            }
        }

        Self {
            report,
            binary_data,
            file_type,
            platforms,
            additional_findings,
            cached_ast,
            finding_id_index: Some(index),
            debug_collector: None,
            section_map: None,
        }
    }

    /// Create a new evaluation context with a debug collector
    pub fn with_debug_collector(mut self, collector: &'a DebugCollector) -> Self {
        self.debug_collector = Some(collector);
        self
    }

    /// Set section map for location-constrained matching
    pub fn with_section_map(mut self, section_map: SectionMap) -> Self {
        self.section_map = Some(section_map);
        self
    }

    /// Check if a finding ID exists (exact match only, O(1))
    pub fn has_finding_exact(&self, id: &str) -> bool {
        if let Some(ref index) = self.finding_id_index {
            index.contains(&hash_str(id))
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
    /// Rule evaluation timeout - potentially malicious input causing slowdown
    RuleTimeout {
        rule_id: String,
        duration_ms: u64,
        timeout_ms: u64,
    },
}

impl std::fmt::Display for AnalysisWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AstTooDeep { max_depth } => {
                write!(f, "AST nesting limit hit (depth: {})", max_depth)
            },
            Self::NestingTooDeep { max_depth } => {
                write!(f, "Control flow nesting limit hit (depth: {})", max_depth)
            },
            Self::ArchiveTooDeep { max_depth } => {
                write!(f, "Archive nesting limit hit (depth: {})", max_depth)
            },
            Self::RuleTimeout {
                rule_id,
                duration_ms,
                timeout_ms,
            } => {
                write!(
                    f,
                    "Rule evaluation timeout for '{}' ({}ms > {}ms limit)",
                    rule_id, duration_ms, timeout_ms
                )
            },
        }
    }
}

/// Result of evaluating a condition
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
    pub compiled_regex: Option<&'a regex::Regex>,
    pub compiled_excludes: &'a [regex::Regex],
    /// When true, require matched string to contain a valid external IP address
    pub external_ip: bool,
    /// Section constraint: only match strings in this section (supports fuzzy names)
    pub section: Option<&'a String>,
    /// Absolute file offset: only match at this exact byte position (negative = from end)
    pub offset: Option<i64>,
    /// Absolute offset range: [start, end) (negative values resolved from file end)
    pub offset_range: Option<(i64, Option<i64>)>,
    /// Section-relative offset: only match at this offset within the section
    pub section_offset: Option<i64>,
    /// Section-relative offset range: [start, end) within section bounds
    pub section_offset_range: Option<(i64, Option<i64>)>,
}
