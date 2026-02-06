//! Condition evaluators for composite rules.
//!
//! This module contains evaluation functions for different condition types:
//! - **symbol_string**: Symbol and string matching (imports, exports, strings, decoded content)
//! - **binary**: Binary analysis (sections, imports, syscalls)
//! - **ast**: AST pattern and query evaluation for source code
//! - **metrics**: Metric-based thresholds (code metrics, binary metrics)
//! - **yara**: YARA rules and hex patterns
//! - **misc**: Miscellaneous evaluators (structure, traits, filesize)
//!
//! ## Performance Optimizations
//! - Regex patterns are cached globally to avoid recompilation
//! - YARA scanners are cached thread-locally for ~5x speedup
//! - Hex pattern matching uses atom extraction for efficient searching

use dashmap::DashMap;
use regex::Regex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::OnceLock;

// Re-export all evaluator modules
mod ast;
mod binary;
mod kv;
mod metrics;
mod misc;
mod symbol_string;
mod yara;

pub use ast::*;
pub use binary::*;
pub use kv::*;
pub use metrics::*;
pub use misc::*;
pub use symbol_string::*;
pub use yara::*;

// Test modules
#[cfg(test)]
mod ast_tests;
#[cfg(test)]
mod binary_tests;
#[cfg(test)]
mod metrics_tests;
#[cfg(test)]
mod misc_tests;
#[cfg(test)]
mod symbol_string_tests;

// =============================================================================
// Shared Utilities
// =============================================================================

/// Global cache for compiled regex patterns to avoid repeated compilation.
/// Key is (pattern, case_insensitive), value is compiled Regex.
static REGEX_CACHE: OnceLock<DashMap<(String, bool), Regex>> = OnceLock::new();

pub(crate) fn regex_cache() -> &'static DashMap<(String, bool), Regex> {
    REGEX_CACHE.get_or_init(DashMap::new)
}

// Thread-local cache for YARA Scanners to avoid expensive Scanner::new() calls.
// Scanner creation involves wasmtime VM instantiation which is expensive (~200µs).
// Reusing scanners provides ~5x speedup.
thread_local! {
    pub(crate) static SCANNER_CACHE: RefCell<HashMap<usize, yara_x::Scanner<'static>>> =
        RefCell::new(HashMap::new());
}

/// Get or create a Scanner for the given Rules, using thread-local caching.
///
/// # Safety
/// The Rules pointer must remain valid for the duration of Scanner use.
/// This is guaranteed because Rules is behind Arc<Rules> held by TraitDefinitions.
#[allow(clippy::mut_from_ref)] // Intentional: mutable Scanner from thread-local cache
pub(crate) fn get_or_create_scanner<'a>(rules: &'a yara_x::Rules) -> &'a mut yara_x::Scanner<'a> {
    let key = rules as *const yara_x::Rules as usize;

    SCANNER_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();

        // Get or insert scanner for these rules
        // SAFETY: We extend the lifetime to 'static for storage in the thread-local.
        // This is safe because:
        // 1. Rules is behind Arc<Rules> in TraitDefinition, living for program duration
        // 2. We only use the Scanner while Rules is valid (within eval_yara_inline)
        // 3. Thread-local storage means no cross-thread access
        let scanner = cache.entry(key).or_insert_with(|| {
            let scanner = yara_x::Scanner::new(rules);
            unsafe { std::mem::transmute(scanner) }
        });

        // Transmute lifetime back to caller's lifetime
        // SAFETY: We're returning a reference with the caller's lifetime 'a,
        // which is valid since we only call this while rules is valid.
        unsafe {
            std::mem::transmute::<&mut yara_x::Scanner<'static>, &mut yara_x::Scanner<'a>>(scanner)
        }
    })
}

/// Check if a symbol matches a pattern (supports exact match or regex).
/// Uses cached regex compilation for patterns with metacharacters.
pub fn symbol_matches(symbol: &str, pattern: &str) -> bool {
    // Clean symbol (remove leading underscores)
    let clean = symbol.trim_start_matches('_').trim_start_matches("__");

    // Try exact match first
    if clean == pattern || symbol == pattern {
        return true;
    }

    // Try as regex if pattern contains regex metacharacters
    if pattern.contains('|') || pattern.contains('*') || pattern.contains('[') {
        if let Ok(re) = build_regex(pattern, false) {
            return re.is_match(clean) || re.is_match(symbol);
        }
    }

    false
}

/// Build a regex with optional case insensitivity.
/// Results are cached globally for reuse across files.
pub fn build_regex(pattern: &str, case_insensitive: bool) -> anyhow::Result<Regex> {
    let cache = regex_cache();
    let key = (pattern.to_string(), case_insensitive);

    // Check cache first
    if let Some(re) = cache.get(&key) {
        return Ok(re.value().clone());
    }

    // Compile and cache
    let regex = if case_insensitive {
        Regex::new(&format!("(?i){}", pattern))?
    } else {
        Regex::new(pattern)?
    };
    cache.insert(key, regex.clone());
    Ok(regex)
}

/// Truncate evidence string to max length for display.
pub fn truncate_evidence(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(max_len).collect::<String>())
    }
}
