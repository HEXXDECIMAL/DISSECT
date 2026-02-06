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
/// Note: Symbols are normalized (leading underscores stripped) at load time.
pub fn symbol_matches(symbol: &str, pattern: &str) -> bool {
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

/// Parameters for count constraint checking.
#[derive(Debug, Clone, Default)]
pub struct CountConstraints {
    /// Minimum match count required (default: 1)
    pub count_min: usize,
    /// Maximum match count allowed (None = unlimited)
    pub count_max: Option<usize>,
    /// Minimum matches per kilobyte of file size
    pub per_kb_min: Option<f64>,
    /// Maximum matches per kilobyte of file size
    pub per_kb_max: Option<f64>,
}

impl CountConstraints {
    /// Create constraints with just a minimum count.
    pub fn with_min(count_min: usize) -> Self {
        Self {
            count_min,
            ..Default::default()
        }
    }

    /// Create constraints from all parameters.
    pub fn new(
        count_min: usize,
        count_max: Option<usize>,
        per_kb_min: Option<f64>,
        per_kb_max: Option<f64>,
    ) -> Self {
        Self {
            count_min,
            count_max,
            per_kb_min,
            per_kb_max,
        }
    }
}

/// Check if a match count satisfies count and density constraints.
///
/// # Arguments
/// * `match_count` - Number of matches found
/// * `file_size` - Size of the file in bytes
/// * `constraints` - Count and density constraints to check
///
/// # Returns
/// `true` if all constraints are satisfied, `false` otherwise.
///
/// # Example
/// ```ignore
/// let constraints = CountConstraints::new(5, Some(100), Some(0.5), None);
/// let satisfied = check_count_constraints(10, 4096, &constraints);
/// // 10 matches in 4KB = 2.5 per KB, satisfies count_min=5, count_max=100, per_kb_min=0.5
/// ```
pub fn check_count_constraints(
    match_count: usize,
    file_size: usize,
    constraints: &CountConstraints,
) -> bool {
    // Check minimum count
    if match_count < constraints.count_min {
        return false;
    }

    // Check maximum count
    if let Some(max) = constraints.count_max {
        if match_count > max {
            return false;
        }
    }

    // Calculate density (matches per KB)
    // Avoid division by zero - treat empty files as having infinite density
    let per_kb = if file_size > 0 {
        (match_count as f64) / (file_size as f64 / 1024.0)
    } else if match_count > 0 {
        f64::INFINITY
    } else {
        0.0
    };

    // Check minimum density
    if let Some(min_density) = constraints.per_kb_min {
        if per_kb < min_density {
            return false;
        }
    }

    // Check maximum density
    if let Some(max_density) = constraints.per_kb_max {
        if per_kb > max_density {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod count_constraint_tests {
    use super::*;

    #[test]
    fn test_count_min_only() {
        let constraints = CountConstraints::with_min(5);
        assert!(!check_count_constraints(4, 1024, &constraints));
        assert!(check_count_constraints(5, 1024, &constraints));
        assert!(check_count_constraints(100, 1024, &constraints));
    }

    #[test]
    fn test_count_max() {
        let constraints = CountConstraints::new(1, Some(10), None, None);
        assert!(check_count_constraints(1, 1024, &constraints));
        assert!(check_count_constraints(10, 1024, &constraints));
        assert!(!check_count_constraints(11, 1024, &constraints));
    }

    #[test]
    fn test_per_kb_min() {
        // 10 matches in 10KB = 1.0 per KB
        let constraints = CountConstraints::new(1, None, Some(0.5), None);
        assert!(check_count_constraints(10, 10240, &constraints)); // 1.0 >= 0.5
        assert!(!check_count_constraints(2, 10240, &constraints)); // 0.2 < 0.5
    }

    #[test]
    fn test_per_kb_max() {
        // 100 matches in 10KB = 10.0 per KB
        let constraints = CountConstraints::new(1, None, None, Some(5.0));
        assert!(check_count_constraints(50, 10240, &constraints)); // 5.0 <= 5.0
        assert!(!check_count_constraints(100, 10240, &constraints)); // 10.0 > 5.0
    }

    #[test]
    fn test_combined_constraints() {
        // Require: 5-50 matches, 0.5-5.0 per KB
        let constraints = CountConstraints::new(5, Some(50), Some(0.5), Some(5.0));

        // 10 matches in 4KB = 2.5 per KB - satisfies all
        assert!(check_count_constraints(10, 4096, &constraints));

        // 3 matches - fails count_min
        assert!(!check_count_constraints(3, 4096, &constraints));

        // 60 matches - fails count_max
        assert!(!check_count_constraints(60, 4096, &constraints));

        // 10 matches in 100KB = 0.1 per KB - fails per_kb_min
        assert!(!check_count_constraints(10, 102400, &constraints));

        // 10 matches in 1KB = 10.0 per KB - fails per_kb_max
        assert!(!check_count_constraints(10, 1024, &constraints));
    }

    #[test]
    fn test_empty_file() {
        let constraints = CountConstraints::new(1, None, Some(0.5), None);
        // Empty file with 1 match has infinite density
        assert!(check_count_constraints(1, 0, &constraints));
        // Empty file with 0 matches has zero density
        assert!(!check_count_constraints(0, 0, &constraints));
    }
}
