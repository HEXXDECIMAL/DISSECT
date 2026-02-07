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
#[allow(dead_code)]
pub(crate) fn is_unset(value: &Option<String>) -> bool {
    value
        .as_ref()
        .map(|v| v.eq_ignore_ascii_case("none"))
        .unwrap_or(false)
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
) -> TraitDefinition {
    // Parse file_types: use trait-specific if present (unless "none"), else defaults, else [All]
    let file_types = apply_vec_default(raw.file_types, &defaults.r#for)
        .map(|types| parse_file_types(&types))
        .unwrap_or_else(|| vec![RuleFileType::All]);

    // Parse platforms: use trait-specific if present (unless "none"), else defaults, else [All]
    let platforms = apply_vec_default(raw.platforms, &defaults.platforms)
        .map(|plats| parse_platforms(&plats))
        .unwrap_or_else(|| vec![Platform::All]);

    // Parse criticality: "none" means Inert
    let mut criticality = match &raw.crit {
        Some(v) if v.eq_ignore_ascii_case("none") => Criticality::Inert,
        Some(v) => parse_criticality(v),
        None => defaults
            .crit
            .as_deref()
            .map(parse_criticality)
            .unwrap_or(Criticality::Inert),
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

    TraitDefinition {
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
        r#if: raw.condition,
        not: raw.not,
        unless: raw.unless,
        downgrade: raw.downgrade,
    }
}

/// Parse file type strings into FileType enum
pub(crate) fn parse_file_types(types: &[String]) -> Vec<RuleFileType> {
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
                "binaries" | "binary" => vec![
                    RuleFileType::Elf, RuleFileType::Macho, RuleFileType::Pe, 
                    RuleFileType::Dylib, RuleFileType::So, RuleFileType::Dll, RuleFileType::Class
                ],
                "scripts" | "scripting" | "script" => vec![
                    RuleFileType::Shell, RuleFileType::Batch, RuleFileType::Python, 
                    RuleFileType::JavaScript, RuleFileType::TypeScript, RuleFileType::Ruby, 
                    RuleFileType::Php, RuleFileType::Perl, RuleFileType::Lua, 
                    RuleFileType::PowerShell, RuleFileType::AppleScript
                ],
                "elf" => vec![RuleFileType::Elf],
                "macho" => vec![RuleFileType::Macho],
                "pe" => vec![RuleFileType::Pe],
                "dylib" => vec![RuleFileType::Dylib],
                "so" => vec![RuleFileType::So],
                "dll" => vec![RuleFileType::Dll],
                "shell" | "shellscript" => vec![RuleFileType::Shell],
                "batch" | "bat" | "cmd" => vec![RuleFileType::Batch],
                "python" | "py" => vec![RuleFileType::Python],
                "javascript" | "js" => vec![RuleFileType::JavaScript],
                "typescript" | "ts" => vec![RuleFileType::TypeScript],
                "java" => vec![RuleFileType::Java],
                "class" => vec![RuleFileType::Class],
                "c" => vec![RuleFileType::C],
                "rust" => vec![RuleFileType::Rust],
                "go" => vec![RuleFileType::Go],
                "ruby" | "rb" => vec![RuleFileType::Ruby],
                "php" => vec![RuleFileType::Php],
                "csharp" | "cs" => vec![RuleFileType::CSharp],
                "lua" => vec![RuleFileType::Lua],
                "perl" | "pl" => vec![RuleFileType::Perl],
                "powershell" | "ps1" => vec![RuleFileType::PowerShell],
                "swift" => vec![RuleFileType::Swift],
                "objectivec" | "objc" => vec![RuleFileType::ObjectiveC],
                "groovy" => vec![RuleFileType::Groovy],
                "scala" => vec![RuleFileType::Scala],
                "zig" => vec![RuleFileType::Zig],
                "elixir" => vec![RuleFileType::Elixir],
                "applescript" | "scpt" => vec![RuleFileType::AppleScript],
                "packagejson" | "package.json" => vec![RuleFileType::PackageJson],
                "chrome-manifest" | "chromemanifest" => vec![RuleFileType::ChromeManifest],
                "cargo-toml" | "cargotoml" | "cargo.toml" => vec![RuleFileType::CargoToml],
                "pyproject-toml" | "pyprojecttoml" | "pyproject.toml" => vec![RuleFileType::PyProjectToml],
                "github-actions" | "githubactions" => vec![RuleFileType::GithubActions],
                "composer-json" | "composerjson" | "composer.json" => vec![RuleFileType::ComposerJson],
                "jpeg" | "jpg" => vec![RuleFileType::Jpeg],
                "png" => vec![RuleFileType::Png],
                _ => vec![],
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

    if inclusions.contains(&RuleFileType::All) || (!has_explicit_inclusion && !exclusions.is_empty()) {
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
pub(crate) fn parse_criticality(s: &str) -> Criticality {
    match s.to_lowercase().as_str() {
        "inert" => Criticality::Inert,
        "notable" => Criticality::Notable,
        "suspicious" => Criticality::Suspicious,
        "hostile" | "malicious" => Criticality::Hostile,
        _ => Criticality::Inert,
    }
}

/// Convert a raw composite rule to a final CompositeTrait, applying file-level defaults
pub(crate) fn apply_composite_defaults(
    raw: RawCompositeRule,
    defaults: &TraitDefaults,
) -> CompositeTrait {
    // Parse file_types: use rule-specific if present (unless "none"), else defaults, else [All]
    let file_types = apply_vec_default(raw.file_types, &defaults.r#for)
        .map(|types| parse_file_types(&types))
        .unwrap_or_else(|| vec![RuleFileType::All]);

    // Parse platforms: use rule-specific if present (unless "none"), else defaults, else [All]
    let platforms = apply_vec_default(raw.platforms, &defaults.platforms)
        .map(|plats| parse_platforms(&plats))
        .unwrap_or_else(|| vec![Platform::All]);

    // Parse criticality: "none" means Inert
    let criticality = match &raw.crit {
        Some(v) if v.eq_ignore_ascii_case("none") => Criticality::Inert,
        Some(v) => parse_criticality(v),
        None => defaults
            .crit
            .as_deref()
            .map(parse_criticality)
            .unwrap_or(Criticality::Inert),
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
    }
}
