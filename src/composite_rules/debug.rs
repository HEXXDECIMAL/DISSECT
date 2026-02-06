//! Debug types for rule evaluation tracing.
//!
//! This module provides types for collecting debug information during rule evaluation.
//! When a debug collector is present in `EvaluationContext`, evaluation records detailed
//! information about why rules matched or failed. When absent (production), there is
//! zero overhead.

use super::types::{FileType, Platform};
use crate::types::{Criticality, Evidence};
use std::sync::RwLock;

/// Why a rule was skipped before condition evaluation
#[derive(Debug, Clone)]
pub enum SkipReason {
    /// Rule requires different platform(s) than current context
    PlatformMismatch {
        rule: Vec<Platform>,
        context: Vec<Platform>,
    },
    /// Rule requires different file type(s) than current context
    FileTypeMismatch { rule: Vec<FileType>, context: FileType },
    /// File is smaller than rule's minimum size
    SizeTooSmall { actual: usize, min: usize },
    /// File is larger than rule's maximum size
    SizeTooLarge { actual: usize, max: usize },
    /// An 'unless' condition matched, skipping the rule
    UnlessConditionMatched { condition_desc: String },
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipReason::PlatformMismatch { rule, context } => {
                write!(
                    f,
                    "Platform mismatch: rule requires {:?}, context has {:?}",
                    rule, context
                )
            }
            SkipReason::FileTypeMismatch { rule, context } => {
                write!(
                    f,
                    "File type mismatch: rule requires {:?}, file is {:?}",
                    rule, context
                )
            }
            SkipReason::SizeTooSmall { actual, min } => {
                write!(
                    f,
                    "Size too small (actual: {} bytes, min: {} bytes)",
                    actual, min
                )
            }
            SkipReason::SizeTooLarge { actual, max } => {
                write!(
                    f,
                    "Size too large (actual: {} bytes, max: {} bytes)",
                    actual, max
                )
            }
            SkipReason::UnlessConditionMatched { condition_desc } => {
                write!(f, "Skipped by 'unless' condition: {}", condition_desc)
            }
        }
    }
}

/// Debug info for a single condition evaluation
#[derive(Debug, Clone, Default)]
pub struct ConditionDebug {
    /// Description of the condition being evaluated
    pub desc: String,
    /// Whether the condition matched
    pub matched: bool,
    /// Evidence collected if matched
    pub evidence: Vec<Evidence>,
    /// Additional details about the evaluation
    pub details: Vec<String>,
    /// Sub-conditions (for nested conditions like all/any/none)
    pub sub_conditions: Vec<ConditionDebug>,
    /// Precision score for this condition
    pub precision: f32,
}

impl ConditionDebug {
    /// Create a new condition debug with description
    pub fn new(desc: impl Into<String>) -> Self {
        Self {
            desc: desc.into(),
            ..Default::default()
        }
    }

    /// Set the matched flag
    pub fn with_matched(mut self, matched: bool) -> Self {
        self.matched = matched;
        self
    }

    /// Add a detail string
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.details.push(detail.into());
        self
    }

    /// Set evidence
    pub fn with_evidence(mut self, evidence: Vec<Evidence>) -> Self {
        self.evidence = evidence;
        self
    }

    /// Set precision
    pub fn with_precision(mut self, precision: f32) -> Self {
        self.precision = precision;
        self
    }
}

/// Debug info for proximity constraint evaluation
#[derive(Debug, Clone)]
pub struct ProximityDebug {
    /// Type of constraint: "near_lines" or "near_bytes"
    pub constraint_type: String,
    /// Maximum span allowed
    pub max_span: usize,
    /// Minimum number of matches required
    pub min_required: usize,
    /// Whether the constraint was satisfied
    pub satisfied: bool,
    /// Positions of evidence items (line numbers or byte offsets)
    pub positions: Vec<usize>,
}

/// Debug info for downgrade evaluation
#[derive(Debug, Clone)]
pub struct DowngradeDebug {
    /// Original criticality before downgrade
    pub original_crit: Criticality,
    /// Final criticality after downgrade (may be same if not triggered)
    pub final_crit: Criticality,
    /// Whether the downgrade was triggered
    pub triggered: bool,
    /// Conditions evaluated for the downgrade
    pub conditions: Vec<ConditionDebug>,
}

/// Type of rule being evaluated
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleType {
    /// Atomic trait definition
    Trait,
    /// Composite rule (boolean combination)
    Composite,
}

impl std::fmt::Display for RuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleType::Trait => write!(f, "trait"),
            RuleType::Composite => write!(f, "composite"),
        }
    }
}

/// Complete debug output for a rule evaluation
#[derive(Debug, Clone)]
pub struct EvaluationDebug {
    /// Rule ID being evaluated
    pub rule_id: String,
    /// Rule description
    pub rule_desc: String,
    /// Type of rule (trait or composite)
    pub rule_type: RuleType,
    /// Whether the rule matched
    pub matched: bool,
    /// Reason the rule was skipped (if applicable)
    pub skip_reason: Option<SkipReason>,
    /// Results from condition evaluations
    pub condition_results: Vec<ConditionDebug>,
    /// Proximity constraint debug (if applicable)
    pub proximity: Option<ProximityDebug>,
    /// Downgrade debug (if applicable)
    pub downgrade: Option<DowngradeDebug>,
    /// Final precision score
    pub precision: f32,
}

impl EvaluationDebug {
    /// Create a new evaluation debug for a rule
    pub fn new(rule_id: impl Into<String>, rule_type: RuleType) -> Self {
        Self {
            rule_id: rule_id.into(),
            rule_desc: String::new(),
            rule_type,
            matched: false,
            skip_reason: None,
            condition_results: Vec::new(),
            proximity: None,
            downgrade: None,
            precision: 0.0,
        }
    }

    /// Set the rule description
    pub fn with_desc(mut self, desc: impl Into<String>) -> Self {
        self.rule_desc = desc.into();
        self
    }

    /// Record a skip reason
    pub fn record_skip(&mut self, reason: SkipReason) {
        self.skip_reason = Some(reason);
    }

    /// Add a condition result
    pub fn add_condition(&mut self, condition: ConditionDebug) {
        self.condition_results.push(condition);
    }

    /// Set the proximity debug info
    pub fn set_proximity(&mut self, proximity: ProximityDebug) {
        self.proximity = Some(proximity);
    }

    /// Set the downgrade debug info
    pub fn set_downgrade(&mut self, downgrade: DowngradeDebug) {
        self.downgrade = Some(downgrade);
    }
}

/// Debug collector that can be optionally attached to EvaluationContext.
/// When present, evaluation records debug info. When absent, zero overhead.
/// Uses RwLock for thread-safety with rayon parallel evaluation.
pub type DebugCollector = RwLock<EvaluationDebug>;

/// Helper to record condition debug info if a collector is present
#[inline]
pub fn record_condition(collector: Option<&DebugCollector>, debug: ConditionDebug) {
    if let Some(c) = collector {
        if let Ok(mut guard) = c.write() {
            guard.condition_results.push(debug);
        }
    }
}

/// Helper to check if debug collection is enabled
#[inline]
pub fn is_debug_enabled(collector: Option<&DebugCollector>) -> bool {
    collector.is_some()
}
