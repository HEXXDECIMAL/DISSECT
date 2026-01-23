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

mod condition;
mod context;
mod evaluators;
mod traits;
mod types;

// Re-export public API
pub use condition::Condition;
pub use context::EvaluationContext;
pub use traits::{CompositeTrait, TraitDefinition};
pub use types::{FileType, Platform};

#[cfg(test)]
mod tests;
