//! Integration tests for AMOS-related traits
//!
//! These tests verify that the new traits for AMOS stealer detection
//! are valid YAML and contain expected structure.

use std::fs;
use std::path::Path;

/// Read a trait YAML file and verify it parses correctly
fn verify_trait_file(path: &str) -> serde_yaml::Value {
    let content =
        fs::read_to_string(path).unwrap_or_else(|_| panic!("Failed to read trait file: {}", path));
    serde_yaml::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse YAML in {}: {}", path, e))
}

/// Check that a trait file has expected structure
fn verify_trait_structure(yaml: &serde_yaml::Value, expected_ids: &[&str]) {
    // Check for traits section
    if let Some(traits) = yaml.get("traits") {
        if let Some(traits_arr) = traits.as_sequence() {
            for expected_id in expected_ids {
                let found = traits_arr.iter().any(|t| {
                    t.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| id.contains(expected_id))
                        .unwrap_or(false)
                });
                assert!(
                    found,
                    "Expected to find trait containing '{}' in traits section",
                    expected_id
                );
            }
        }
    }

    // Check for composite_rules section if expected
    if let Some(rules) = yaml.get("composite_rules") {
        assert!(rules.is_sequence(), "composite_rules should be a sequence");
    }
}

#[test]
fn test_applescript_traits_yaml_valid() {
    let yaml = verify_trait_file("traits/evasion/applescript/traits.yaml");

    // Verify expected traits exist
    verify_trait_structure(
        &yaml,
        &[
            "hide-window",
            "osascript",
            "do-shell-script",
            "password-dialog",
        ],
    );
}

#[test]
fn test_desktop_wallet_traits_yaml_valid() {
    let yaml = verify_trait_file("traits/cred/wallet/desktop/traits.yaml");

    // Verify expected traits exist
    verify_trait_structure(
        &yaml,
        &[
            "electrum",
            "coinomi",
            "exodus",
            "atomic",
            "binance",
            "tonkeeper",
        ],
    );
}

#[test]
fn test_macos_validation_traits_yaml_valid() {
    let yaml = verify_trait_file("traits/cred/macos/validation/traits.yaml");

    // Verify expected traits exist
    verify_trait_structure(&yaml, &["dscl-authonly", "dscl-read", "dscl-list"]);
}

#[test]
fn test_macos_archive_traits_yaml_valid() {
    let yaml = verify_trait_file("traits/collect/archive/macos/traits.yaml");

    // Verify expected traits exist
    verify_trait_structure(&yaml, &["ditto-compress", "hdiutil-create", "tar-compress"]);
}

#[test]
fn test_exfil_stealer_traits_yaml_valid() {
    let yaml = verify_trait_file("traits/exfil/stealer/traits.yaml");

    // Verify expected traits exist
    verify_trait_structure(
        &yaml,
        &["curl-post-headers", "bot-headers", "gate-url", "zip-upload"],
    );
}

#[test]
fn test_applescript_traits_have_attack_mapping() {
    let yaml = verify_trait_file("traits/evasion/applescript/traits.yaml");

    if let Some(defaults) = yaml.get("defaults") {
        assert!(
            defaults.get("attack").is_some(),
            "AppleScript traits should have default ATT&CK mapping"
        );
    }
}

#[test]
fn test_desktop_wallet_traits_have_criticality() {
    let yaml = verify_trait_file("traits/cred/wallet/desktop/traits.yaml");

    if let Some(traits) = yaml.get("traits").and_then(|t| t.as_sequence()) {
        for trait_def in traits {
            assert!(
                trait_def.get("criticality").is_some()
                    || yaml
                        .get("defaults")
                        .and_then(|d| d.get("criticality"))
                        .is_some(),
                "Each wallet trait should have criticality set"
            );
        }
    }
}

#[test]
fn test_exfil_stealer_has_composite_rules() {
    let yaml = verify_trait_file("traits/exfil/stealer/traits.yaml");

    assert!(
        yaml.get("composite_rules").is_some(),
        "Exfil stealer traits should have composite rules"
    );
}

#[test]
fn test_all_new_trait_files_exist() {
    let trait_files = [
        "traits/evasion/applescript/traits.yaml",
        "traits/cred/wallet/desktop/traits.yaml",
        "traits/cred/macos/validation/traits.yaml",
        "traits/collect/archive/macos/traits.yaml",
        "traits/exfil/stealer/traits.yaml",
    ];

    for file in trait_files {
        assert!(
            Path::new(file).exists(),
            "Trait file should exist: {}",
            file
        );
    }
}

#[test]
fn test_trait_ids_are_short_format() {
    // Verify trait IDs use short format (no path prefix)
    // The Rust loader auto-prefixes based on directory path
    let checks = [
        "traits/evasion/applescript/traits.yaml",
        "traits/cred/wallet/desktop/traits.yaml",
        "traits/exfil/stealer/traits.yaml",
    ];

    for file_path in checks {
        let yaml = verify_trait_file(file_path);

        if let Some(traits) = yaml.get("traits").and_then(|t| t.as_sequence()) {
            for trait_def in traits {
                if let Some(id) = trait_def.get("id").and_then(|i| i.as_str()) {
                    // Short format IDs should not contain slashes (unless they're sub-paths within the directory)
                    // They should be simple names like "electrum", "password-dialog", etc.
                    let slash_count = id.matches('/').count();
                    assert!(
                        slash_count <= 1,
                        "Trait ID '{}' in {} should be short format (got {} slashes)",
                        id,
                        file_path,
                        slash_count
                    );
                }
            }
        }
    }
}
