//! Composite rules module for trait-based detection.
//!
//! This module provides the infrastructure for defining and evaluating
//! composite detection rules using a YAML-based DSL.
//!
//! ## Module Structure
//!
//! - `types`: Core enums (Platform, FileType)
//! - `condition`: Condition enum for detection logic
//! - `context`: Evaluation context and result types
//! - `evaluators`: Condition evaluation functions
//! - `traits`: TraitDefinition and CompositeTrait structs

pub mod condition;
pub mod context;
mod evaluators;
pub mod traits;
pub mod types;

// Re-export public API
pub use condition::{Condition, NotException};
pub use context::EvaluationContext;
pub use traits::{CompositeTrait, DowngradeRules, TraitDefinition};
pub use types::{FileType, Platform};

#[cfg(test)]
mod tests;
