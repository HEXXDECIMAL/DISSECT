//! Rule evaluation module
//!
//! This module contains the types and evaluation logic for DISSECT rules.
//!
//! # Structure
//! - `types`: Core type definitions (Platform, FileType, Condition, etc.)
//! - `evaluators`: Condition evaluation functions
//! - `composite`: CompositeTrait evaluation logic
//! - `traits`: TraitDefinition evaluation logic

mod composite;
pub mod evaluators;
mod traits;
pub mod types;

#[cfg(test)]
mod tests;
