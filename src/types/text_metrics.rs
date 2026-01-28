//! Universal text metrics for all text files

use serde::{Deserialize, Serialize};

use super::{is_false, is_zero_f32, is_zero_u32, is_zero_u64};

// =============================================================================
// UNIVERSAL TEXT METRICS (All text files)
// =============================================================================

// =============================================================================

/// Text-level metrics computed on raw file content
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TextMetrics {
    // === Character Distribution ===
    /// Shannon entropy of character distribution (0-8, normal code ~4.5)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub char_entropy: f32,
    /// Number of distinct characters used
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unique_chars: u32,
    /// Most frequent non-whitespace character
    #[serde(skip_serializing_if = "Option::is_none")]
    pub most_common_char: Option<char>,
    /// Ratio of most common char to total (0-1)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub most_common_ratio: f32,

    // === Byte-Level Analysis ===
    /// Ratio of non-ASCII bytes (0-1)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub non_ascii_ratio: f32,
    /// Ratio of non-printable control characters
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub non_printable_ratio: f32,
    /// Count of null bytes (binary in text file?)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub null_byte_count: u32,
    /// Ratio of bytes > 0x7F
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub high_byte_ratio: f32,

    // === Line Statistics ===
    /// Total lines in file
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total_lines: u32,
    /// Average line length in characters
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_line_length: f32,
    /// Maximum line length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_line_length: u32,
    /// Standard deviation of line lengths
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub line_length_stddev: f32,
    /// Lines over 200 characters
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lines_over_200: u32,
    /// Lines over 500 characters
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lines_over_500: u32,
    /// Lines over 1000 characters (strong obfuscation signal)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lines_over_1000: u32,
    /// Ratio of empty lines to total
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub empty_line_ratio: f32,

    // === Whitespace Forensics ===
    /// Ratio of whitespace to total characters
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub whitespace_ratio: f32,
    /// Tab characters count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub tab_count: u32,
    /// Space characters count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub space_count: u32,
    /// Mixed tabs and spaces for indentation
    #[serde(default, skip_serializing_if = "is_false")]
    pub mixed_indent: bool,
    /// Lines with trailing whitespace
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub trailing_whitespace_lines: u32,
    /// Unicode whitespace chars (zero-width, non-breaking, etc.)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unusual_whitespace: u32,

    // === Escape Sequences ===
    /// Hex escape sequences (\xNN)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hex_escape_count: u32,
    /// Unicode escapes (\uNNNN, \UNNNNNNNN)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unicode_escape_count: u32,
    /// Octal escapes (\NNN)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub octal_escape_count: u32,
    /// Escape sequences per 100 characters
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub escape_density: f32,

    // === Suspicious Text Patterns ===
    /// Tokens over 100 chars without spaces
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub long_token_count: u32,
    /// Repeated character sequences (>10 same char)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub repeated_char_sequences: u32,
    /// Ratio of digits to alphanumeric characters
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub digit_ratio: f32,
    /// Visible ASCII art or banner patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ascii_art_lines: u32,
}

/// Identifier/naming metrics from AST analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentifierMetrics {
    // === Counts ===
    /// Total identifier occurrences
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total: u32,
    /// Unique identifiers
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unique: u32,
    /// Reuse ratio (unique/total, low = repetitive)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub reuse_ratio: f32,

    // === Length Analysis ===
    /// Average identifier length
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_length: f32,
    /// Minimum identifier length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub min_length: u32,
    /// Maximum identifier length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_length: u32,
    /// Standard deviation of lengths
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub length_stddev: f32,
    /// Single-character identifiers (a, b, x, i)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub single_char_count: u32,
    /// Ratio of single-char to total (high = obfuscation)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub single_char_ratio: f32,

    // === Entropy/Randomness ===
    /// Average entropy per identifier name
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_entropy: f32,
    /// Identifiers with entropy > 3.5 (random-looking)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_count: u32,
    /// Ratio of high-entropy identifiers
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub high_entropy_ratio: f32,

    // === Naming Patterns ===
    /// All lowercase identifiers ratio
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub all_lowercase_ratio: f32,
    /// All uppercase identifiers ratio
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub all_uppercase_ratio: f32,
    /// Identifiers containing digits
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub has_digit_ratio: f32,
    /// Underscore-prefixed identifiers (_var, __var)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub underscore_prefix_count: u32,
    /// Double-underscore identifiers (__dunder__)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub double_underscore_count: u32,
    /// Numeric suffix patterns (var1, var2, var3)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub numeric_suffix_count: u32,

    // === Suspicious Patterns ===
    /// Names that look like hex (deadbeef, cafebabe)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hex_like_names: u32,
    /// Names matching base64 character set
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_like_names: u32,
    /// Sequential patterns (a, b, c or var1, var2)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sequential_names: u32,
    /// Keyboard patterns (qwerty, asdf)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub keyboard_pattern_names: u32,
    /// Names that are just repeated chars (aaa, xxx)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub repeated_char_names: u32,
}

/// String literal metrics from AST analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StringMetrics {
    // === Counts & Sizes ===
    /// Total string literals
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total: u32,
    /// Total bytes in all strings
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub total_bytes: u64,
    /// Average string length
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_length: f32,
    /// Maximum string length
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_length: u32,
    /// Empty string count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub empty_count: u32,

    // === Entropy Analysis ===
    /// Average entropy across all strings
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_entropy: f32,
    /// Standard deviation of string entropy
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub entropy_stddev: f32,
    /// Strings with entropy > 5.0
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_count: u32,
    /// Strings with entropy > 6.5 (encrypted/compressed)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub very_high_entropy_count: u32,

    // === Encoding Patterns ===
    /// Strings matching base64 pattern
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_candidates: u32,
    /// Pure hexadecimal strings
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hex_strings: u32,
    /// URL-encoded strings (%XX patterns)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub url_encoded_strings: u32,
    /// Strings with many unicode escapes
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unicode_heavy_strings: u32,

    // === Content Categories ===
    /// URL strings detected
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub url_count: u32,
    /// File path strings
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub path_count: u32,
    /// IP address strings
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub ip_count: u32,
    /// Email address strings
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub email_count: u32,
    /// Domain name strings
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub domain_count: u32,

    // === Construction Patterns (from AST) ===
    /// String concatenation operations
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub concat_operations: u32,
    /// Format strings (f-strings, .format, sprintf)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub format_strings: u32,
    /// Character-by-character construction (chr/fromCharCode)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub char_construction: u32,
    /// Array join construction ([].join)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub array_join_construction: u32,

    // === Suspicious Patterns ===
    /// Very long strings (> 1000 chars)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub very_long_strings: u32,
    /// Strings containing code-like patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub embedded_code_candidates: u32,
    /// Strings with shell command patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub shell_command_strings: u32,
    /// Strings with SQL patterns
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub sql_strings: u32,
}

/// Comment and documentation metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CommentMetrics {
    /// Total comment count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total: u32,
    /// Lines that are comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub lines: u32,
    /// Total characters in comments
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub chars: u64,
    /// Comment to code ratio
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub to_code_ratio: f32,

    // === Comment Patterns ===
    /// TODO comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub todo_count: u32,
    /// FIXME comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub fixme_count: u32,
    /// HACK comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub hack_count: u32,
    /// XXX comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub xxx_count: u32,
    /// Empty comments (// or /* */)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub empty_comments: u32,

    // === Suspicious Patterns ===
    /// High-entropy comments (random-looking)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_comments: u32,
    /// Comments containing code
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub code_in_comments: u32,
    /// URLs in comments
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub url_in_comments: u32,
    /// Base64 in comments (hidden payloads)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub base64_in_comments: u32,
}

/// Function/method metrics from AST analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionMetrics {
    // === Counts ===
    /// Total functions/methods
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub total: u32,
    /// Anonymous functions (lambdas, closures)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub anonymous: u32,
    /// Async functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub async_count: u32,
    /// Generator functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub generator_count: u32,

    // === Size Analysis ===
    /// Average function length (lines)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_length_lines: f32,
    /// Maximum function length (lines)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_length_lines: u32,
    /// Minimum function length (lines)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub min_length_lines: u32,
    /// Standard deviation of function lengths
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub length_stddev: f32,
    /// Functions over 100 lines
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub over_100_lines: u32,
    /// Functions over 500 lines (very suspicious)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub over_500_lines: u32,
    /// One-liner functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub one_liners: u32,

    // === Parameter Analysis ===
    /// Average parameter count
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_params: f32,
    /// Maximum parameter count
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_params: u32,
    /// Functions with no parameters
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub no_params_count: u32,
    /// Functions with many parameters (>7)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub many_params_count: u32,
    /// Average parameter name length
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_param_name_length: f32,
    /// Single-char parameter names (x, y, a)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub single_char_params: u32,

    // === Naming Analysis ===
    /// Average function name length
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_name_length: f32,
    /// Single-char function names
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub single_char_names: u32,
    /// High entropy function names (random-looking)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub high_entropy_names: u32,
    /// Numeric-suffix function names (func1, func2)
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub numeric_suffix_names: u32,

    // === Nesting & Complexity ===
    /// Maximum nesting depth across all functions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_nesting_depth: u32,
    /// Average nesting depth
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub avg_nesting_depth: f32,
    /// Nested function definitions
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub nested_functions: u32,
    /// Recursive functions detected
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub recursive_count: u32,

    // === Density ===
    /// Functions per 100 lines of code
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub density_per_100_lines: f32,
    /// Code to function ratio (lines in functions / total lines)
    #[serde(default, skip_serializing_if = "is_zero_f32")]
    pub code_in_functions_ratio: f32,
}

// =============================================================================
// LANGUAGE-SPECIFIC METRICS
// =============================================================================
