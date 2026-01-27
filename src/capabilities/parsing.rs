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
pub(crate) fn apply_string_default(raw: Option<String>, default: &Option<String>) -> Option<String> {
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
pub(crate) fn apply_trait_defaults(raw: RawTraitDefinition, defaults: &TraitDefaults) -> TraitDefinition {
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

    TraitDefinition {
        id: raw.id,
        desc: raw.desc,
        conf: raw.conf.or(defaults.conf).unwrap_or(1.0),
        crit: criticality,
        mbc: apply_string_default(raw.mbc, &defaults.mbc),
        attack: apply_string_default(raw.attack, &defaults.attack),
        platforms,
        r#for: file_types,
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
        .filter_map(|ft| {
            // Handle "*" separately (exact match), then lowercase for the rest
            if ft == "*" {
                return Some(RuleFileType::All);
            }
            match ft.to_lowercase().as_str() {
                "all" => Some(RuleFileType::All),
                "elf" => Some(RuleFileType::Elf),
                "macho" => Some(RuleFileType::Macho),
                "pe" => Some(RuleFileType::Pe),
                "dylib" => Some(RuleFileType::Dylib),
                "so" => Some(RuleFileType::So),
                "dll" => Some(RuleFileType::Dll),
                "shell" | "shellscript" => Some(RuleFileType::Shell),
                "batch" | "bat" | "cmd" => Some(RuleFileType::Batch),
                "python" => Some(RuleFileType::Python),
                "javascript" | "js" => Some(RuleFileType::JavaScript),
                "typescript" | "ts" => Some(RuleFileType::TypeScript),
                "java" => Some(RuleFileType::Java),
                "class" => Some(RuleFileType::Class),
                "c" => Some(RuleFileType::C),
                "rust" => Some(RuleFileType::Rust),
                "go" => Some(RuleFileType::Go),
                "ruby" => Some(RuleFileType::Ruby),
                "php" => Some(RuleFileType::Php),
                "csharp" | "cs" => Some(RuleFileType::CSharp),
                "packagejson" | "package.json" => Some(RuleFileType::PackageJson),
                _ => None,
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
pub(crate) fn apply_composite_defaults(raw: RawCompositeRule, defaults: &TraitDefaults) -> CompositeTrait {
    // Parse file_types: use rule-specific if present (unless "none"), else defaults, else [All]
    let file_types = apply_vec_default(raw.file_types, &defaults.r#for)
        .map(|types| parse_file_types(&types))
        .unwrap_or_else(|| vec![RuleFileType::All]);

    // Parse platforms: use rule-specific if present (unless "none"), else defaults, else [All]
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

    // Stricter validation for HOSTILE traits: must have complexity >= 4
    // Complexity calculation:
    // - Each direct condition (Symbol, String, etc.) = 1
    // - Each Trait reference = complexity of that trait (recursive)
    // - File type filter (not "all") = 1
    // This ensures HOSTILE requires substantive evidence (e.g., 3 traits + filetype)
    if criticality == Criticality::Hostile {
        let has_file_type_filter = !file_types.contains(&RuleFileType::All);

        // Start with filetype filter counting as 1 if present
        let mut complexity = if has_file_type_filter { 1 } else { 0 };

        // Count direct conditions (non-Trait conditions count as 1 each)
        if let Some(ref c) = raw.all {
            complexity += c.len();
        }
        if let Some(ref c) = raw.any {
            complexity += c.len();
        }
        if let Some(ref c) = raw.none {
            complexity += c.len();
        }
        if raw.condition.is_some() {
            complexity += 1;
        }

        // Note: We count all conditions as 1 for now. In the future, we could:
        // - Recursively expand Trait references to their underlying complexity
        // - Weight different condition types differently
        // For now, this simpler approach ensures rules have multiple substantive checks

        if complexity < 4 {
            eprintln!(
                "⚠️  WARNING: Composite trait '{}' is marked HOSTILE but does not meet strictness requirements (complexity={}, need 4). Downgrading to SUSPICIOUS.",
                raw.id, complexity
            );
            criticality = Criticality::Suspicious;
        }
    }

    // Additional strictness for SUSPICIOUS/HOSTILE composite rules
    if criticality >= Criticality::Suspicious {
        if raw.desc.len() < 15 {
            eprintln!(
                "⚠️  WARNING: Composite trait '{}' has an overly short description for its criticality.",
                raw.id
            );
        }
        if criticality >= Criticality::Hostile
            && raw.mbc.is_none()
            && raw.attack.is_none()
            && defaults.mbc.is_none()
            && defaults.attack.is_none()
        {
            eprintln!(
                "⚠️  WARNING: Composite trait '{}' is marked {:?} but lacks an MBC or MITRE ATT&CK mapping.",
                raw.id, criticality
            );
        }
    }

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
        all: requires_all,
        any: raw.any,
        count: raw.count,
        min_count: raw.min_count,
        max_count: raw.max_count,
        none: raw.none,
    }
}
