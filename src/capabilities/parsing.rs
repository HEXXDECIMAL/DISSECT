//! YAML data processing and default application.
//!
//! This module handles:
//! - Applying file-level defaults to raw trait and composite rule definitions
//! - Parsing string fields into typed enums (FileType, Platform, Criticality)
//! - Supporting the "none" keyword to explicitly unset defaults

use crate::composite_rules::{CompositeTrait, FileType as RuleFileType, Platform, TraitDefinition};
use crate::types::Criticality;
use std::collections::HashSet;

use super::models::{RawCompositeRule, RawTraitDefinition, TraitDefaults};

/// Check if a string value is the special "none" keyword to unset a default
pub(crate) fn is_unset(value: &Option<String>) -> bool {
    value.as_ref().map(|v| v.eq_ignore_ascii_case("none")).unwrap_or(false)
}

/// Apply default for Option<String> fields, supporting "none" to unset
/// - If raw is Some("none"), return None (explicit unset)
/// - If raw is Some(value), return Some(value)
/// - If raw is None, return default
pub(crate) fn apply_string_default(
    raw: Option<String>,
    default: &Option<String>,
) -> Option<String> {
    match &raw {
        Some(v) if v.eq_ignore_ascii_case("none") => None,
        Some(_) => raw,
        None => default.clone(),
    }
}

/// Apply default for Vec<String> fields (file_types, platforms), supporting "none" to unset
/// - If raw contains "none", return empty/default behavior
/// - If raw is Some with values, use those
/// - If raw is None, use default
pub(crate) fn apply_vec_default(
    raw: Option<Vec<String>>,
    default: &Option<Vec<String>>,
) -> Option<Vec<String>> {
    match &raw {
        Some(v) if v.iter().any(|s| s.eq_ignore_ascii_case("none")) => None,
        Some(_) => raw,
        None => default.clone(),
    }
}

/// Convert a raw trait definition to a final TraitDefinition, applying file-level defaults
/// Collects warnings into the provided vector instead of printing them.
pub(crate) fn apply_trait_defaults(
    raw: RawTraitDefinition,
    defaults: &TraitDefaults,
    warnings: &mut Vec<String>,
    path: &std::path::Path,
) -> TraitDefinition {
    // Parse file_types: use trait-specific if present (unless "none"), else defaults, else [All]
    let file_types = apply_vec_default(raw.file_types, &defaults.r#for)
        .map(|types| parse_file_types(&types, warnings))
        .unwrap_or_else(|| vec![RuleFileType::All]);

    // Parse platforms: use trait-specific if present (unless "none"), else defaults, else [All]
    let platforms = apply_vec_default(raw.platforms, &defaults.platforms)
        .map(|plats| parse_platforms(&plats))
        .unwrap_or_else(|| vec![Platform::All]);

    // Parse criticality: "none" means Inert
    let mut criticality = match &raw.crit {
        Some(v) if v.eq_ignore_ascii_case("none") => Criticality::Inert,
        Some(v) => match parse_criticality(v) {
            Ok(crit) => crit,
            Err(e) => {
                warnings.push(format!("Trait '{}': {}", raw.id, e));
                Criticality::Inert
            },
        },
        None => match defaults.crit.as_deref() {
            Some(v) => match parse_criticality(v) {
                Ok(crit) => crit,
                Err(e) => {
                    warnings.push(format!("Default criticality: {}", e));
                    Criticality::Inert
                },
            },
            None => Criticality::Inert,
        },
    };

    // Stricter validation for HOSTILE traits: atomic traits cannot be HOSTILE
    if criticality == Criticality::Hostile {
        warnings.push(format!(
            "Trait '{}' is atomic but marked HOSTILE. Atomic traits cannot be HOSTILE.",
            raw.id
        ));
        criticality = Criticality::Suspicious;
    }

    // Additional strictness for SUSPICIOUS/HOSTILE traits
    if criticality >= Criticality::Suspicious && raw.desc.len() < 15 {
        warnings.push(format!(
            "Trait '{}' has an overly short description for its criticality.",
            raw.id
        ));
    }

    // Warn about overly long descriptions (> 7 words)
    let word_count = raw.desc.split_whitespace().count();
    if word_count > 7 {
        warnings.push(format!(
            "Trait '{}' has an overly long description ({} words, max 7 recommended).",
            raw.id, word_count
        ));
    }

    // For size-only traits without a condition, create a synthetic "always-true" condition
    // This uses a basename regex that matches everything
    let mut condition_with_filters =
        raw.condition.unwrap_or_else(|| crate::composite_rules::ConditionWithFilters {
            condition: crate::composite_rules::Condition::Basename {
                exact: None,
                substr: None,
                regex: Some(".".to_string()),
                case_insensitive: false,
            },
            size_min: None,
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
        });

    // Auto-fix: Convert literal regex patterns to substr for better performance
    // If a regex pattern contains only alphanumeric chars and underscores, it's a literal
    fix_literal_regex_patterns(&mut condition_with_filters.condition);

    // Support backwards compatibility: if size_min/size_max are at trait level,
    // copy them to the condition wrapper (unless already set in the if: block)
    if condition_with_filters.size_min.is_none() {
        condition_with_filters.size_min = raw.size_min;
    }
    if condition_with_filters.size_max.is_none() {
        condition_with_filters.size_max = raw.size_max;
    }

    let mut trait_def = TraitDefinition {
        id: raw.id,
        desc: raw.desc,
        conf: raw.conf.or(defaults.conf).unwrap_or(1.0),
        crit: criticality,
        mbc: apply_string_default(raw.mbc, &defaults.mbc),
        attack: apply_string_default(raw.attack, &defaults.attack),
        platforms,
        r#for: file_types,
        r#if: condition_with_filters,
        not: raw.not,
        unless: raw.unless,
        downgrade: raw.downgrade,
        defined_in: path.to_path_buf(),
        precision: None,
    };

    // Calculate and store precision immediately
    trait_def.precision = Some(super::validation::calculate_trait_precision(&trait_def));

    trait_def
}

/// Parse file type strings into FileType enum
/// Collects warnings about unknown file types into the provided vector.
pub(crate) fn parse_file_types(types: &[String], warnings: &mut Vec<String>) -> Vec<RuleFileType> {
    let mut inclusions = HashSet::new();
    let mut exclusions = HashSet::new();
    let mut has_explicit_inclusion = false;

    for type_str in types {
        for part in type_str.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (is_exclusion, name) = if let Some(stripped) = part.strip_prefix('!') {
                (true, stripped)
            } else {
                (false, part)
            };

            let variants = match name.to_lowercase().as_str() {
                "all" | "*" => {
                    if is_exclusion {
                        vec![]
                    } else {
                        vec![RuleFileType::All]
                    }
                },
                // Groups
                "binaries" => vec![
                    RuleFileType::Elf,
                    RuleFileType::Macho,
                    RuleFileType::Pe,
                    RuleFileType::Dylib,
                    RuleFileType::So,
                    RuleFileType::Dll,
                    RuleFileType::Class,
                ],
                "scripts" => vec![
                    RuleFileType::Shell,
                    RuleFileType::Batch,
                    RuleFileType::Python,
                    RuleFileType::JavaScript,
                    RuleFileType::TypeScript,
                    RuleFileType::Ruby,
                    RuleFileType::Php,
                    RuleFileType::Perl,
                    RuleFileType::Lua,
                    RuleFileType::PowerShell,
                    RuleFileType::AppleScript,
                ],
                // Binary formats
                "elf" => vec![RuleFileType::Elf],
                "macho" => vec![RuleFileType::Macho],
                "pe" => vec![RuleFileType::Pe],
                "dylib" => vec![RuleFileType::Dylib],
                "so" => vec![RuleFileType::So],
                "dll" => vec![RuleFileType::Dll],
                // Scripting languages (fullname + extension)
                "shell" | "sh" => vec![RuleFileType::Shell],
                "batch" | "bat" | "cmd" => vec![RuleFileType::Batch],
                "python" | "py" => vec![RuleFileType::Python],
                "javascript" | "js" => vec![RuleFileType::JavaScript],
                "typescript" | "ts" => vec![RuleFileType::TypeScript],
                "ruby" | "rb" => vec![RuleFileType::Ruby],
                "php" => vec![RuleFileType::Php],
                "perl" | "pl" => vec![RuleFileType::Perl],
                "powershell" | "ps1" => vec![RuleFileType::PowerShell],
                "lua" => vec![RuleFileType::Lua],
                "applescript" | "scpt" => vec![RuleFileType::AppleScript],
                "vbs" => vec![RuleFileType::Vbs],
                "html" | "htm" => vec![RuleFileType::Html],
                // Compiled languages (fullname + extension)
                "java" => vec![RuleFileType::Java],
                "class" => vec![RuleFileType::Class],
                "c" => vec![RuleFileType::C],
                "cpp" | "c++" | "cc" | "cxx" => vec![RuleFileType::Cpp],
                "rust" => vec![RuleFileType::Rust],
                "go" => vec![RuleFileType::Go],
                "csharp" | "cs" => vec![RuleFileType::CSharp],
                "swift" => vec![RuleFileType::Swift],
                "objective-c" | "objc" => vec![RuleFileType::ObjectiveC],
                "groovy" => vec![RuleFileType::Groovy],
                "scala" => vec![RuleFileType::Scala],
                "zig" => vec![RuleFileType::Zig],
                "elixir" => vec![RuleFileType::Elixir],
                // Specific filenames
                "package.json" => vec![RuleFileType::PackageJson],
                "cargo.toml" => vec![RuleFileType::CargoToml],
                "pyproject.toml" => vec![RuleFileType::PyProjectToml],
                "composer.json" => vec![RuleFileType::ComposerJson],
                // Logical types with hyphens
                "chrome-manifest" => vec![RuleFileType::ChromeManifest],
                "manifest.json" => vec![RuleFileType::ChromeManifest], // Chrome extension manifest
                "github-actions" => vec![RuleFileType::GithubActions],
                // Archive/installer formats
                "ipa" => vec![RuleFileType::Ipa],
                // Generic formats
                "text" | "txt" => vec![RuleFileType::Text],
                // Image formats
                "jpeg" | "jpg" => vec![RuleFileType::Jpeg],
                "png" => vec![RuleFileType::Png],
                // Other formats
                "plist" => vec![RuleFileType::Plist],
                "pkginfo" => vec![RuleFileType::PkgInfo],
                "rtf" => vec![RuleFileType::Rtf],
                _ => {
                    // Unknown file type - add warning (file path will be added by caller)
                    warnings.push(format!("Unknown file type: '{}'", name));
                    vec![]
                },
            };

            if name == "*" || name.eq_ignore_ascii_case("all") {
                if !is_exclusion {
                    has_explicit_inclusion = true;
                    inclusions.insert(RuleFileType::All);
                } else {
                    for v in RuleFileType::all_concrete_variants() {
                        exclusions.insert(v);
                    }
                }
                continue;
            }

            for v in variants {
                if is_exclusion {
                    exclusions.insert(v);
                } else {
                    has_explicit_inclusion = true;
                    inclusions.insert(v);
                }
            }
        }
    }

    let mut final_set: HashSet<RuleFileType>;

    if inclusions.contains(&RuleFileType::All)
        || (!has_explicit_inclusion && !exclusions.is_empty())
    {
        final_set = RuleFileType::all_concrete_variants().into_iter().collect();
    } else {
        final_set = inclusions.clone();
    }

    for exc in &exclusions {
        final_set.remove(exc);
    }

    if !exclusions.is_empty() {
        let mut v: Vec<_> = final_set.into_iter().collect();
        v.sort();
        v
    } else if inclusions.contains(&RuleFileType::All) {
        vec![RuleFileType::All]
    } else {
        let mut v: Vec<_> = final_set.into_iter().collect();
        v.sort();
        v
    }
}

/// Parse platform strings into Platform enum
pub(crate) fn parse_platforms(platforms: &[String]) -> Vec<Platform> {
    platforms
        .iter()
        .filter_map(|p| match p.to_lowercase().as_str() {
            "all" => Some(Platform::All),
            "linux" => Some(Platform::Linux),
            "macos" => Some(Platform::MacOS),
            "windows" => Some(Platform::Windows),
            "unix" => Some(Platform::Unix),
            "android" => Some(Platform::Android),
            "ios" => Some(Platform::Ios),
            _ => None,
        })
        .collect()
}

/// Parse criticality string into Criticality enum
/// Returns an error for invalid criticality values instead of silently defaulting
pub(crate) fn parse_criticality(s: &str) -> Result<Criticality, String> {
    match s.to_lowercase().as_str() {
        "inert" => Ok(Criticality::Inert),
        "notable" => Ok(Criticality::Notable),
        "suspicious" => Ok(Criticality::Suspicious),
        "hostile" | "malicious" => Ok(Criticality::Hostile),
        unknown => Err(format!(
            "Invalid criticality '{}'. Valid values: inert, notable, suspicious, hostile, malicious",
            unknown
        )),
    }
}

/// Convert a raw composite rule to a final CompositeTrait, applying file-level defaults
/// Collects warnings into the provided vector instead of printing them.
pub(crate) fn apply_composite_defaults(
    raw: RawCompositeRule,
    defaults: &TraitDefaults,
    warnings: &mut Vec<String>,
    path: &std::path::Path,
) -> CompositeTrait {
    // Parse file_types: use rule-specific if present (unless "none"), else defaults, else [All]
    let file_types = apply_vec_default(raw.file_types, &defaults.r#for)
        .map(|types| parse_file_types(&types, warnings))
        .unwrap_or_else(|| vec![RuleFileType::All]);

    // Parse platforms: use rule-specific if present (unless "none"), else defaults, else [All]
    let platforms = apply_vec_default(raw.platforms, &defaults.platforms)
        .map(|plats| parse_platforms(&plats))
        .unwrap_or_else(|| vec![Platform::All]);

    // Parse criticality: "none" means Inert
    let criticality = match &raw.crit {
        Some(v) if v.eq_ignore_ascii_case("none") => Criticality::Inert,
        Some(v) => match parse_criticality(v) {
            Ok(crit) => crit,
            Err(e) => {
                warnings.push(format!("Composite rule '{}': {}", raw.id, e));
                Criticality::Inert
            },
        },
        None => match defaults.crit.as_deref() {
            Some(v) => match parse_criticality(v) {
                Ok(crit) => crit,
                Err(e) => {
                    warnings.push(format!("Default criticality: {}", e));
                    Criticality::Inert
                },
            },
            None => Criticality::Inert,
        },
    };

    // Handle single condition by converting to requires_all
    let requires_all = raw.all.or_else(|| raw.condition.map(|c| vec![c]));

    CompositeTrait {
        id: raw.id,
        desc: raw.desc,
        conf: raw.conf.or(defaults.conf).unwrap_or(1.0),
        crit: criticality,
        mbc: apply_string_default(raw.mbc, &defaults.mbc),
        attack: apply_string_default(raw.attack, &defaults.attack),
        platforms,
        r#for: file_types,
        size_min: raw.size_min,
        size_max: raw.size_max,
        all: requires_all,
        any: raw.any,
        needs: raw.needs,
        none: raw.none,
        near_lines: raw.near_lines,
        near_bytes: raw.near_bytes,
        unless: raw.unless,
        not: raw.not,
        downgrade: raw.downgrade,
        defined_in: path.to_path_buf(),
        precision: None,
    }
}

/// Auto-fix literal regex patterns by converting them to substr.
/// A pattern is considered literal if it contains only alphanumeric chars and underscores.
/// This provides better performance than regex matching for simple string searches.
fn fix_literal_regex_patterns(condition: &mut crate::composite_rules::Condition) {
    use crate::composite_rules::Condition;

    // Helper to check if a pattern is a literal (no regex metacharacters)
    // Regex metacharacters: . * + ? ^ $ ( ) [ ] { } | \
    let is_literal = |pattern: &str| -> bool {
        !pattern.is_empty()
            && !pattern.chars().any(|c| {
                matches!(
                    c,
                    '.' | '*'
                        | '+'
                        | '?'
                        | '^'
                        | '$'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '|'
                        | '\\'
                )
            })
    };

    match condition {
        Condition::String {
            regex: regex_opt,
            substr,
            ..
        } if substr.is_none() => {
            if let Some(pattern) = regex_opt {
                if is_literal(pattern) {
                    // Convert regex to substr
                    *substr = Some(pattern.clone());
                    *regex_opt = None;
                }
            }
        },
        Condition::Raw {
            regex: regex_opt,
            substr,
            ..
        } if substr.is_none() => {
            if let Some(pattern) = regex_opt {
                if is_literal(pattern) {
                    // Convert regex to substr
                    *substr = Some(pattern.clone());
                    *regex_opt = None;
                }
            }
        },
        Condition::Symbol {
            regex: regex_opt,
            substr,
            ..
        } if substr.is_none() => {
            if let Some(pattern) = regex_opt {
                if is_literal(pattern) {
                    // Convert regex to substr
                    *substr = Some(pattern.clone());
                    *regex_opt = None;
                }
            }
        },
        Condition::Basename {
            regex: regex_opt,
            substr,
            ..
        } if substr.is_none() => {
            if let Some(pattern) = regex_opt {
                if is_literal(pattern) {
                    // Convert regex to substr
                    *substr = Some(pattern.clone());
                    *regex_opt = None;
                }
            }
        },
        _ => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== is_unset Tests ====================

    #[test]
    fn test_is_unset_none_value() {
        assert!(!is_unset(&None));
    }

    #[test]
    fn test_is_unset_none_keyword_lowercase() {
        assert!(is_unset(&Some("none".to_string())));
    }

    #[test]
    fn test_is_unset_none_keyword_uppercase() {
        assert!(is_unset(&Some("NONE".to_string())));
    }

    #[test]
    fn test_is_unset_none_keyword_mixed() {
        assert!(is_unset(&Some("NoNe".to_string())));
    }

    #[test]
    fn test_is_unset_other_value() {
        assert!(!is_unset(&Some("something".to_string())));
    }

    // ==================== apply_string_default Tests ====================

    #[test]
    fn test_apply_string_default_raw_value() {
        let result = apply_string_default(Some("custom".to_string()), &Some("default".to_string()));
        assert_eq!(result, Some("custom".to_string()));
    }

    #[test]
    fn test_apply_string_default_uses_default() {
        let result = apply_string_default(None, &Some("default".to_string()));
        assert_eq!(result, Some("default".to_string()));
    }

    #[test]
    fn test_apply_string_default_none_unsets() {
        let result = apply_string_default(Some("none".to_string()), &Some("default".to_string()));
        assert_eq!(result, None);
    }

    #[test]
    fn test_apply_string_default_both_none() {
        let result = apply_string_default(None, &None);
        assert_eq!(result, None);
    }

    // ==================== apply_vec_default Tests ====================

    #[test]
    fn test_apply_vec_default_raw_value() {
        let result = apply_vec_default(
            Some(vec!["a".to_string(), "b".to_string()]),
            &Some(vec!["default".to_string()]),
        );
        assert_eq!(result, Some(vec!["a".to_string(), "b".to_string()]));
    }

    #[test]
    fn test_apply_vec_default_uses_default() {
        let result = apply_vec_default(None, &Some(vec!["default".to_string()]));
        assert_eq!(result, Some(vec!["default".to_string()]));
    }

    #[test]
    fn test_apply_vec_default_none_unsets() {
        let result = apply_vec_default(
            Some(vec!["none".to_string()]),
            &Some(vec!["default".to_string()]),
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_apply_vec_default_none_mixed() {
        // If "none" appears anywhere in the vec, it unsets
        let result = apply_vec_default(
            Some(vec!["value".to_string(), "NONE".to_string()]),
            &Some(vec!["default".to_string()]),
        );
        assert_eq!(result, None);
    }

    // ==================== parse_criticality Tests ====================

    #[test]
    fn test_parse_criticality_inert() {
        assert_eq!(parse_criticality("inert").unwrap(), Criticality::Inert);
        assert_eq!(parse_criticality("INERT").unwrap(), Criticality::Inert);
    }

    #[test]
    fn test_parse_criticality_notable() {
        assert_eq!(parse_criticality("notable").unwrap(), Criticality::Notable);
        assert_eq!(parse_criticality("NOTABLE").unwrap(), Criticality::Notable);
    }

    #[test]
    fn test_parse_criticality_suspicious() {
        assert_eq!(
            parse_criticality("suspicious").unwrap(),
            Criticality::Suspicious
        );
        assert_eq!(
            parse_criticality("SUSPICIOUS").unwrap(),
            Criticality::Suspicious
        );
    }

    #[test]
    fn test_parse_criticality_hostile() {
        assert_eq!(parse_criticality("hostile").unwrap(), Criticality::Hostile);
        assert_eq!(parse_criticality("HOSTILE").unwrap(), Criticality::Hostile);
        assert_eq!(
            parse_criticality("malicious").unwrap(),
            Criticality::Hostile
        );
    }

    #[test]
    fn test_parse_criticality_unknown_returns_error() {
        assert!(parse_criticality("unknown").is_err());
        assert!(parse_criticality("").is_err());
        assert!(parse_criticality("high").is_err());
        assert!(parse_criticality("critical").is_err());
        assert!(parse_criticality("dangerous").is_err());

        // Check error message
        let err = parse_criticality("dangerous").unwrap_err();
        assert!(err.contains("dangerous"));
        assert!(err.contains("inert"));
        assert!(err.contains("hostile"));
    }

    // ==================== parse_platforms Tests ====================

    #[test]
    fn test_parse_platforms_all() {
        let result = parse_platforms(&["all".to_string()]);
        assert_eq!(result, vec![Platform::All]);
    }

    #[test]
    fn test_parse_platforms_multiple() {
        let result = parse_platforms(&[
            "linux".to_string(),
            "macos".to_string(),
            "windows".to_string(),
        ]);
        assert!(result.contains(&Platform::Linux));
        assert!(result.contains(&Platform::MacOS));
        assert!(result.contains(&Platform::Windows));
    }

    #[test]
    fn test_parse_platforms_case_insensitive() {
        let result = parse_platforms(&["LINUX".to_string(), "MacOS".to_string()]);
        assert!(result.contains(&Platform::Linux));
        assert!(result.contains(&Platform::MacOS));
    }

    #[test]
    fn test_parse_platforms_unknown_ignored() {
        let result = parse_platforms(&["linux".to_string(), "unknown".to_string()]);
        assert_eq!(result.len(), 1);
        assert!(result.contains(&Platform::Linux));
    }

    #[test]
    fn test_parse_platforms_unix_android_ios() {
        let result =
            parse_platforms(&["unix".to_string(), "android".to_string(), "ios".to_string()]);
        assert!(result.contains(&Platform::Unix));
        assert!(result.contains(&Platform::Android));
        assert!(result.contains(&Platform::Ios));
    }

    // ==================== parse_file_types Tests ====================

    #[test]
    fn test_parse_file_types_all() {
        let mut warnings = Vec::new();
        let result = parse_file_types(&["all".to_string()], &mut warnings);
        assert_eq!(result, vec![RuleFileType::All]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_star() {
        let mut warnings = Vec::new();
        let result = parse_file_types(&["*".to_string()], &mut warnings);
        assert_eq!(result, vec![RuleFileType::All]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_specific() {
        let mut warnings = Vec::new();
        let result = parse_file_types(
            &["python".to_string(), "javascript".to_string()],
            &mut warnings,
        );
        assert!(result.contains(&RuleFileType::Python));
        assert!(result.contains(&RuleFileType::JavaScript));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_aliases() {
        let mut warnings = Vec::new();
        let result = parse_file_types(
            &[
                "py".to_string(),
                "js".to_string(),
                "ts".to_string(),
                "rb".to_string(),
            ],
            &mut warnings,
        );
        assert!(result.contains(&RuleFileType::Python));
        assert!(result.contains(&RuleFileType::JavaScript));
        assert!(result.contains(&RuleFileType::TypeScript));
        assert!(result.contains(&RuleFileType::Ruby));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_binaries() {
        let mut warnings = Vec::new();
        let result = parse_file_types(&["binaries".to_string()], &mut warnings);
        assert!(result.contains(&RuleFileType::Elf));
        assert!(result.contains(&RuleFileType::Macho));
        assert!(result.contains(&RuleFileType::Pe));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_scripts() {
        let mut warnings = Vec::new();
        let result = parse_file_types(&["scripts".to_string()], &mut warnings);
        assert!(result.contains(&RuleFileType::Shell));
        assert!(result.contains(&RuleFileType::Python));
        assert!(result.contains(&RuleFileType::JavaScript));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_exclusion() {
        let mut warnings = Vec::new();
        let result = parse_file_types(&["all".to_string(), "!python".to_string()], &mut warnings);
        assert!(!result.contains(&RuleFileType::Python));
        assert!(result.contains(&RuleFileType::JavaScript));
        assert!(result.contains(&RuleFileType::Shell));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_comma_separated() {
        let mut warnings = Vec::new();
        let result = parse_file_types(&["python,javascript,ruby".to_string()], &mut warnings);
        assert!(result.contains(&RuleFileType::Python));
        assert!(result.contains(&RuleFileType::JavaScript));
        assert!(result.contains(&RuleFileType::Ruby));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_case_insensitive() {
        let mut warnings = Vec::new();
        let result = parse_file_types(
            &["PYTHON".to_string(), "JavaScript".to_string()],
            &mut warnings,
        );
        assert!(result.contains(&RuleFileType::Python));
        assert!(result.contains(&RuleFileType::JavaScript));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_package_files() {
        let mut warnings = Vec::new();
        let result = parse_file_types(
            &[
                "package.json".to_string(),
                "cargo.toml".to_string(),
                "pyproject.toml".to_string(),
            ],
            &mut warnings,
        );
        assert!(result.contains(&RuleFileType::PackageJson));
        assert!(result.contains(&RuleFileType::CargoToml));
        assert!(result.contains(&RuleFileType::PyProjectToml));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_image_formats() {
        let mut warnings = Vec::new();
        let result = parse_file_types(&["jpeg".to_string(), "png".to_string()], &mut warnings);
        assert!(result.contains(&RuleFileType::Jpeg));
        assert!(result.contains(&RuleFileType::Png));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_exclusion_only() {
        // When only exclusions are provided, start with all and remove
        let mut warnings = Vec::new();
        let result = parse_file_types(
            &["!python".to_string(), "!javascript".to_string()],
            &mut warnings,
        );
        assert!(!result.contains(&RuleFileType::Python));
        assert!(!result.contains(&RuleFileType::JavaScript));
        assert!(result.contains(&RuleFileType::Shell));
        assert!(result.contains(&RuleFileType::Ruby));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_unknown_type() {
        let mut warnings = Vec::new();
        let result = parse_file_types(
            &["python".to_string(), "invalid_type".to_string()],
            &mut warnings,
        );
        assert!(result.contains(&RuleFileType::Python));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0], "Unknown file type: 'invalid_type'");
    }

    #[test]
    fn test_parse_file_types_multiple_unknown() {
        let mut warnings = Vec::new();
        let result = parse_file_types(
            &["pyton".to_string(), "javascrpt".to_string()],
            &mut warnings,
        );
        assert!(result.is_empty());
        assert_eq!(warnings.len(), 2);
        assert!(warnings.contains(&"Unknown file type: 'pyton'".to_string()));
        assert!(warnings.contains(&"Unknown file type: 'javascrpt'".to_string()));
    }
}

#[test]
fn test_parse_file_types_ipa() {
    let mut warnings = Vec::new();
    let result = parse_file_types(&["ipa".to_string()], &mut warnings);
    assert!(result.contains(&RuleFileType::Ipa));
    assert!(warnings.is_empty());
}
