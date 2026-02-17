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
pub(crate) mod ast;
pub(crate) mod binary;
pub(crate) mod kv;
pub(crate) mod metrics;
pub(crate) mod misc;
pub(crate) mod symbol_string;
pub(crate) mod yara;

pub(crate) use ast::*;
pub(crate) use binary::*;
pub(crate) use kv::*;
pub(crate) use metrics::*;
pub(crate) use misc::*;
pub(crate) use symbol_string::*;
pub(crate) use yara::*;

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

/// Access the global regex cache, initializing it on first call
pub(crate) fn regex_cache() -> &'static DashMap<(String, bool), Regex> {
    REGEX_CACHE.get_or_init(DashMap::new)
}

// Thread-local cache for YARA Scanners to avoid expensive Scanner::new() calls.
// Scanner creation involves wasmtime VM instantiation which is expensive (~200µs).
// Reusing scanners provides ~5x speedup.
thread_local! {
    /// Thread-local YARA scanner cache keyed by Rules pointer address
    pub static SCANNER_CACHE: RefCell<HashMap<usize, yara_x::Scanner<'static>>> =
        RefCell::new(HashMap::new());
}

/// Get or create a Scanner for the given Rules, using thread-local caching.
///
/// # Safety
/// The Rules pointer must remain valid for the duration of Scanner use.
/// This is guaranteed because Rules is behind Arc<Rules> held by TraitDefinitions.
#[allow(clippy::mut_from_ref)] // Intentional: mutable Scanner from thread-local cache
#[must_use] 
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
/// Note: Symbols are normalized (leading underscores stripped) at load time.
#[must_use] 
pub(crate) fn symbol_matches(symbol: &str, pattern: &str) -> bool {
    // Try exact match first
    if symbol == pattern {
        return true;
    }

    // Try as regex if pattern contains regex metacharacters
    if pattern.contains('|') || pattern.contains('*') || pattern.contains('[') {
        if let Ok(re) = build_regex(pattern, false) {
            return re.is_match(symbol);
        }
    }

    false
}

/// Build a regex with optional case insensitivity.
/// Results are cached globally for reuse across files.
pub(crate) fn build_regex(pattern: &str, case_insensitive: bool) -> anyhow::Result<Regex> {
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
#[must_use] 
pub(crate) fn truncate_evidence(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(max_len).collect::<String>())
    }
}

/// Parameters for location-constrained content evaluation.
#[derive(Debug, Clone, Default)]
pub(crate) struct ContentLocationParams {
    /// Binary section name constraint (e.g., ".text", "TEXT")
    pub section: Option<String>,
    /// Absolute file offset constraint (negative = from end of file)
    pub offset: Option<i64>,
    /// Absolute file offset range [start, end)
    pub offset_range: Option<(i64, Option<i64>)>,
    /// Offset relative to the section start
    pub section_offset: Option<i64>,
    /// Offset range relative to the section start
    pub section_offset_range: Option<(i64, Option<i64>)>,
}

/// Resolve the effective byte range for content search based on location constraints.
/// Returns (start, end) as absolute offsets into binary data.
#[must_use] 
pub(crate) fn resolve_effective_range<'a>(
    location: &ContentLocationParams,
    ctx: &crate::composite_rules::context::EvaluationContext<'a>,
) -> (usize, usize) {
    let file_size = ctx.binary_data.len();

    // If no location constraints, return full file range
    if location.section.is_none()
        && location.offset.is_none()
        && location.offset_range.is_none()
        && location.section_offset.is_none()
        && location.section_offset_range.is_none()
    {
        return (0, file_size);
    }

    // Use SectionMap to resolve the range if available
    if let Some(ref section_map) = ctx.section_map {
        if let Some((start, end)) = section_map.resolve_range(
            location.section.as_deref(),
            location.offset,
            location.offset_range,
            location.section_offset,
            location.section_offset_range,
        ) {
            return (start as usize, end as usize);
        }
    }

    // Fallback: resolve absolute offset constraints without SectionMap
    match (location.offset, &location.offset_range) {
        (Some(off), None) => {
            // Single offset - search starts at that position
            let resolved = if off < 0 {
                (file_size as i64 + off).max(0) as usize
            } else {
                off as usize
            };
            (resolved, file_size)
        },
        (None, Some((start, end_opt))) => {
            let file_size_i64 = file_size as i64;
            let resolved_start = if *start < 0 {
                (file_size_i64 + *start).max(0) as usize
            } else {
                *start as usize
            };
            let resolved_end = match end_opt {
                Some(end) if *end < 0 => (file_size_i64 + *end).max(0) as usize,
                Some(end) => *end as usize,
                None => file_size,
            };
            (resolved_start, resolved_end)
        },
        _ => (0, file_size), // Section constraints without SectionMap - no filtering
    }
}

/// Resolve effective range as Option for string offset filtering.
/// Returns None if no location constraints (no filtering needed).
#[must_use] 
pub(crate) fn resolve_effective_range_opt<'a>(
    location: &ContentLocationParams,
    ctx: &crate::composite_rules::context::EvaluationContext<'a>,
) -> Option<(u64, u64)> {
    // If no location constraints, return None (no filtering)
    if location.section.is_none()
        && location.offset.is_none()
        && location.offset_range.is_none()
        && location.section_offset.is_none()
        && location.section_offset_range.is_none()
    {
        return None;
    }

    let (start, end) = resolve_effective_range(location, ctx);
    Some((start as u64, end as u64))
}


