//! Identifier/naming metrics analyzer
//!
//! Analyzes identifier naming patterns for obfuscation detection.
//! Can work from AST-extracted identifiers or heuristic text extraction.

use crate::types::IdentifierMetrics;
use std::collections::{HashMap, HashSet};

/// Keyboard row patterns for detecting keyboard-walk names
const KEYBOARD_PATTERNS: &[&str] = &[
    "qwerty", "qwert", "asdf", "asdfg", "zxcv", "zxcvb", "qazwsx", "qaz", "wsx", "edc", "rfv",
    "ytrewq", "fdsa", "gfdsa", "vcxz",
];

/// Analyze a collection of identifiers
pub fn analyze_identifiers(identifiers: &[&str]) -> IdentifierMetrics {
    let mut metrics = IdentifierMetrics::default();

    if identifiers.is_empty() {
        return metrics;
    }

    // === Basic Counts ===
    metrics.total = identifiers.len() as u32;
    let unique: HashSet<&str> = identifiers.iter().copied().collect();
    metrics.unique_count = unique.len() as u32;
    metrics.reuse_ratio = if metrics.total > 0 {
        metrics.unique_count as f32 / metrics.total as f32
    } else {
        0.0
    };

    // === Length Analysis ===
    let lengths: Vec<usize> = unique.iter().map(|s| s.len()).collect();
    if !lengths.is_empty() {
        let total_len: usize = lengths.iter().sum();
        metrics.avg_length = total_len as f32 / lengths.len() as f32;
        metrics.min_length = *lengths.iter().min().unwrap_or(&0) as u32;
        metrics.max_length = *lengths.iter().max().unwrap_or(&0) as u32;

        // Standard deviation
        let mean = metrics.avg_length;
        let variance: f32 = lengths
            .iter()
            .map(|&len| {
                let diff = len as f32 - mean;
                diff * diff
            })
            .sum::<f32>()
            / lengths.len() as f32;
        metrics.length_stddev = variance.sqrt();
    }

    // === Pattern Analysis ===
    let mut single_char = 0u32;
    let mut all_lowercase = 0u32;
    let mut all_uppercase = 0u32;
    let mut has_digit = 0u32;
    let mut underscore_prefix = 0u32;
    let mut double_underscore = 0u32;
    let mut numeric_suffix = 0u32;
    let mut hex_like = 0u32;
    let mut base64_like = 0u32;
    let mut sequential = 0u32;
    let mut keyboard_pattern = 0u32;
    let mut repeated_char = 0u32;
    let mut high_entropy = 0u32;
    let mut entropy_sum = 0.0f32;

    for ident in unique.iter() {
        let s = *ident;
        let len = s.len();

        // Single character
        if len == 1 {
            single_char += 1;
        }

        // Case patterns
        if s.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            all_lowercase += 1;
        }
        if s.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
            all_uppercase += 1;
        }

        // Has digit
        if s.chars().any(|c| c.is_ascii_digit()) {
            has_digit += 1;
        }

        // Underscore patterns
        if s.starts_with('_') {
            underscore_prefix += 1;
        }
        if s.starts_with("__") && s.ends_with("__") && len > 4 {
            double_underscore += 1;
        }

        // Numeric suffix (var1, item2, etc.)
        if len > 1
            && s.chars().last().is_some_and(|c| c.is_ascii_digit())
            && s.chars().take(len - 1).any(|c| c.is_ascii_alphabetic())
        {
            numeric_suffix += 1;
        }

        // Hex-like names (looks like hex data)
        if is_hex_like(s) {
            hex_like += 1;
        }

        // Base64-like (high proportion of base64 charset)
        if is_base64_like(s) {
            base64_like += 1;
        }

        // Sequential names (a, b, c or x1, x2, x3)
        if is_sequential(s) {
            sequential += 1;
        }

        // Keyboard patterns
        let lower = s.to_ascii_lowercase();
        if KEYBOARD_PATTERNS.iter().any(|p| lower.contains(p)) {
            keyboard_pattern += 1;
        }

        // Repeated character names (aaa, xxx, etc.)
        if len >= 3 && s.chars().all(|c| c == s.chars().next().unwrap()) {
            repeated_char += 1;
        }

        // Entropy calculation
        let entropy = calculate_string_entropy(s);
        entropy_sum += entropy;
        if entropy > 3.5 {
            high_entropy += 1;
        }
    }

    let unique_count = unique.len() as f32;
    metrics.single_char_count = single_char;
    metrics.single_char_ratio = if unique_count > 0.0 {
        single_char as f32 / unique_count
    } else {
        0.0
    };
    metrics.all_lowercase_ratio = if unique_count > 0.0 {
        all_lowercase as f32 / unique_count
    } else {
        0.0
    };
    metrics.all_uppercase_ratio = if unique_count > 0.0 {
        all_uppercase as f32 / unique_count
    } else {
        0.0
    };
    metrics.has_digit_ratio = if unique_count > 0.0 {
        has_digit as f32 / unique_count
    } else {
        0.0
    };
    metrics.underscore_prefix_count = underscore_prefix;
    metrics.double_underscore_count = double_underscore;
    metrics.numeric_suffix_count = numeric_suffix;
    metrics.hex_like_names = hex_like;
    metrics.base64_like_names = base64_like;
    metrics.sequential_names = sequential;
    metrics.keyboard_pattern_names = keyboard_pattern;
    metrics.repeated_char_names = repeated_char;

    metrics.avg_entropy = if unique_count > 0.0 {
        entropy_sum / unique_count
    } else {
        0.0
    };
    metrics.high_entropy_count = high_entropy;
    metrics.high_entropy_ratio = if unique_count > 0.0 {
        high_entropy as f32 / unique_count
    } else {
        0.0
    };

    metrics
}

/// Calculate Shannon entropy of a string
fn calculate_string_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    let total = s.chars().count();

    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    freq.values()
        .map(|&count| {
            let p = count as f32 / total as f32;
            if p > 0.0 {
                -p * p.log2()
            } else {
                0.0
            }
        })
        .sum()
}

/// Check if string looks like hex data
fn is_hex_like(s: &str) -> bool {
    if s.len() < 6 {
        return false;
    }

    // Must be entirely hex characters (a-f, A-F, 0-9)
    let hex_chars = s.chars().filter(|c| c.is_ascii_hexdigit()).count();
    let ratio = hex_chars as f32 / s.len() as f32;

    // High proportion of hex chars and even length suggests hex encoding
    ratio > 0.9 && s.len().is_multiple_of(2)
}

/// Check if string looks like base64-encoded data
fn is_base64_like(s: &str) -> bool {
    if s.len() < 8 {
        return false;
    }

    // Base64 charset: A-Z, a-z, 0-9, +, /, =
    let base64_chars = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();

    let ratio = base64_chars as f32 / s.len() as f32;

    // High proportion of base64 chars and mixed case
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());

    ratio > 0.95 && has_upper && has_lower && has_digit
}

/// Check for sequential naming patterns
fn is_sequential(s: &str) -> bool {
    // Single letter followed by optional digit
    if s.len() <= 2 {
        let chars: Vec<char> = s.chars().collect();
        if chars.len() == 1 && chars[0].is_ascii_alphabetic() {
            return true; // a, b, c, etc.
        }
        if chars.len() == 2 && chars[0].is_ascii_alphabetic() && chars[1].is_ascii_digit() {
            return true; // a1, b2, etc.
        }
    }

    // Pattern like var1, var2, item3
    if s.len() >= 2 {
        let last = s.chars().last().unwrap();
        if last.is_ascii_digit() {
            let prefix: String = s.chars().take(s.len() - 1).collect();
            // Common sequential prefixes
            let common = [
                "var", "tmp", "temp", "arg", "param", "item", "val", "x", "y", "z", "i", "j", "k",
            ];
            if common.iter().any(|p| prefix.eq_ignore_ascii_case(p)) {
                return true;
            }
        }
    }

    false
}

/// Extract identifiers from source code using simple heuristics
/// This is a fallback when AST parsing isn't available
pub fn extract_identifiers_heuristic(content: &str) -> Vec<String> {
    let mut identifiers = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut string_char = '"';
    let mut prev_char = ' ';

    for c in content.chars() {
        // Track string state
        if !in_string && (c == '"' || c == '\'') {
            in_string = true;
            string_char = c;
            prev_char = c;
            continue;
        }
        if in_string {
            if c == string_char && prev_char != '\\' {
                in_string = false;
            }
            prev_char = c;
            continue;
        }

        // Build identifier
        if c.is_ascii_alphanumeric() || c == '_' {
            current.push(c);
        } else if !current.is_empty() {
            // Filter out pure numbers and very common keywords
            let first = current.chars().next().unwrap();
            if (first.is_ascii_alphabetic() || first == '_') && !is_common_keyword(&current) {
                identifiers.push(current.clone());
            }
            current.clear();
        }
        prev_char = c;
    }

    // Don't forget the last identifier
    if !current.is_empty() {
        let first = current.chars().next().unwrap();
        if (first.is_ascii_alphabetic() || first == '_') && !is_common_keyword(&current) {
            identifiers.push(current);
        }
    }

    identifiers
}

/// Check if a word is a common programming keyword (should be excluded)
fn is_common_keyword(word: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        // Control flow
        "if",
        "else",
        "elif",
        "for",
        "while",
        "do",
        "switch",
        "case",
        "break",
        "continue",
        "return",
        "goto",
        "try",
        "catch",
        "finally",
        "throw",
        "default",
        "match",
        "when",
        "unless",
        "until",
        "loop",
        // Declarations
        "def",
        "fn",
        "func",
        "function",
        "class",
        "struct",
        "enum",
        "interface",
        "trait",
        "impl",
        "type",
        "var",
        "let",
        "const",
        "static",
        "mut",
        "public",
        "private",
        "protected",
        "internal",
        "extern",
        "abstract",
        "virtual",
        "override",
        "final",
        "sealed",
        // Types
        "int",
        "float",
        "double",
        "bool",
        "boolean",
        "string",
        "str",
        "char",
        "void",
        "null",
        "nil",
        "none",
        "true",
        "false",
        "undefined",
        // Imports
        "import",
        "from",
        "require",
        "include",
        "use",
        "using",
        "package",
        "module",
        "export",
        "as",
        "with",
        // Other
        "and",
        "or",
        "not",
        "in",
        "is",
        "new",
        "delete",
        "this",
        "self",
        "super",
        "async",
        "await",
        "yield",
        "lambda",
        "where",
        "sizeof",
        "typeof",
        "instanceof",
        "extends",
        "implements",
    ];

    KEYWORDS.contains(&word.to_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_identifiers() {
        let metrics = analyze_identifiers(&[]);
        assert_eq!(metrics.total, 0);
        assert_eq!(metrics.unique_count, 0);
    }

    #[test]
    fn test_basic_identifiers() {
        let idents = vec!["foo", "bar", "baz", "foo"];
        let metrics = analyze_identifiers(&idents);
        assert_eq!(metrics.total, 4);
        assert_eq!(metrics.unique_count, 3);
    }

    #[test]
    fn test_single_char_detection() {
        let idents = vec!["a", "b", "c", "x", "y", "longName"];
        let metrics = analyze_identifiers(&idents);
        assert_eq!(metrics.single_char_count, 5);
    }

    #[test]
    fn test_numeric_suffix_detection() {
        let idents = vec!["var1", "var2", "item3", "normalName"];
        let metrics = analyze_identifiers(&idents);
        assert_eq!(metrics.numeric_suffix_count, 3);
    }

    #[test]
    fn test_hex_like_detection() {
        let idents = vec!["deadbeef", "cafebabe", "normalName"];
        let metrics = analyze_identifiers(&idents);
        assert_eq!(metrics.hex_like_names, 2);
    }

    #[test]
    fn test_keyboard_pattern_detection() {
        let idents = vec!["qwerty", "asdfPassword", "normalName"];
        let metrics = analyze_identifiers(&idents);
        assert_eq!(metrics.keyboard_pattern_names, 2);
    }

    #[test]
    fn test_heuristic_extraction() {
        let code = r#"function hello(name) { let x = "string"; return x + name; }"#;
        let idents = extract_identifiers_heuristic(code);
        // Should extract: hello, name, x (filtering keywords and strings)
        assert!(idents.contains(&"hello".to_string()));
        assert!(idents.contains(&"name".to_string()));
        assert!(idents.contains(&"x".to_string()));
        // Should NOT contain keywords
        assert!(!idents.contains(&"function".to_string()));
        assert!(!idents.contains(&"let".to_string()));
        assert!(!idents.contains(&"return".to_string()));
    }

    #[test]
    fn test_repeated_char_names() {
        let idents = vec!["aaa", "xxx", "zzz", "normal"];
        let metrics = analyze_identifiers(&idents);
        assert_eq!(metrics.repeated_char_names, 3);
    }
}
