//! YAML data processing and default application.
//!
//! This module handles:
//! - Applying file-level defaults to raw trait and composite rule definitions
//! - Parsing string fields into typed enums (FileType, Platform, Criticality)
//! - Supporting the "none" keyword to explicitly unset defaults

use crate::composite_rules::{CompositeTrait, FileType as RuleFileType, Platform, TraitDefinition};
use crate::types::Criticality;

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
pub(crate) fn apply_trait_defaults(
    raw: RawTraitDefinition,
    defaults: &TraitDefaults,
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
        eprintln!(
            "⚠️  WARNING: Trait '{}' is atomic but marked HOSTILE. Downgrading to SUSPICIOUS.",
            raw.id
        );
        criticality = Criticality::Suspicious;
    }

    // Additional strictness for SUSPICIOUS/HOSTILE traits
    if criticality >= Criticality::Suspicious && raw.desc.len() < 15 {
        eprintln!(
            "⚠️  WARNING: Trait '{}' has an overly short description for its criticality.",
            raw.id
        );
    }

    // Warn about overly long descriptions (> 5 words)
    let word_count = raw.desc.split_whitespace().count();
    if word_count > 5 {
        eprintln!(
            "⚠️  WARNING: Trait '{}' has an overly long description ({} words, max 5 recommended).",
            raw.id, word_count
        );
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
        not: None,
        unless: None,
        downgrade: None,
    }
}

/// Parse file type strings into FileType enum
pub(crate) fn parse_file_types(types: &[String]) -> Vec<RuleFileType> {
    types
        .iter()
        .flat_map(|ft| {
            // Handle "*" separately (exact match), then lowercase for the rest
            if ft == "*" {
                return vec![RuleFileType::All];
            }
            match ft.to_lowercase().as_str() {
                "all" => vec![RuleFileType::All],
                "compiled" => vec![RuleFileType::Elf, RuleFileType::Macho, RuleFileType::Pe],
                "elf" => vec![RuleFileType::Elf],
                "macho" => vec![RuleFileType::Macho],
                "pe" => vec![RuleFileType::Pe],
                "dylib" => vec![RuleFileType::Dylib],
                "so" => vec![RuleFileType::So],
                "dll" => vec![RuleFileType::Dll],
                "shell" | "shellscript" => vec![RuleFileType::Shell],
                "batch" | "bat" | "cmd" => vec![RuleFileType::Batch],
                "python" => vec![RuleFileType::Python],
                "javascript" | "js" => vec![RuleFileType::JavaScript],
                "typescript" | "ts" => vec![RuleFileType::TypeScript],
                "java" => vec![RuleFileType::Java],
                "class" => vec![RuleFileType::Class],
                "c" => vec![RuleFileType::C],
                "rust" => vec![RuleFileType::Rust],
                "go" => vec![RuleFileType::Go],
                "ruby" => vec![RuleFileType::Ruby],
                "php" => vec![RuleFileType::Php],
                "csharp" | "cs" => vec![RuleFileType::CSharp],
                "packagejson" | "package.json" => vec![RuleFileType::PackageJson],
                _ => vec![],
            }
        })
        .collect()
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
        count_exact: raw.count_exact,
        count_min: raw.count_min,
        count_max: raw.count_max,
        none: raw.none,
        unless: raw.unless,
    }
}
