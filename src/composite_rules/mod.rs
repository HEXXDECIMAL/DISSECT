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
//! - `ast_kinds`: Abstract AST kind to tree-sitter node type mapping

pub mod ast_kinds;
pub mod condition;
pub mod context;
pub mod evaluators;
pub mod traits;
pub mod types;

// Re-export public API
pub use condition::Condition;
pub use context::EvaluationContext;
pub use evaluators::eval_trait;
pub use traits::{CompositeTrait, DowngradeConditions, TraitDefinition};
pub use types::{FileType, Platform};

#[cfg(test)]
mod tests;
