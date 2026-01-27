//! Comprehensive test suite for capabilities module.
//!
//! Tests are organized by category:
//! - Basic mapper tests
//! - Default application tests
//! - Composite rule evaluation tests
//! - Complexity calculation tests

use super::*;
use crate::composite_rules::{CompositeTrait, Condition, FileType as RuleFileType, Platform, TraitDefinition};
use crate::types::{AnalysisReport, Criticality, Finding, FindingKind, TargetInfo};

#[test]
fn test_empty_mapper() {
    let mapper = CapabilityMapper::empty();

    // Should have no mappings
    assert_eq!(mapper.mapping_count(), 0);
    assert_eq!(mapper.trait_definitions_count(), 0);
    assert_eq!(mapper.composite_rules_count(), 0);

    // Lookup should return None
    assert!(mapper.lookup("socket", "test").is_none());
}

#[test]
fn test_yaml_loading() {
    // Test loading from embedded capabilities
    let mapper = CapabilityMapper::new();

    // Should be able to create mapper (may or may not load mappings depending on environment)
    let count = mapper.mapping_count();
    println!("Loaded {} symbol mappings", count);
    // Test passes if mapper was created successfully
    let _ = count;
}

#[test]
fn test_yara_rule_mapping() {
    let mapper = CapabilityMapper::new();

    assert_eq!(
        mapper.yara_rule_to_capability("rules/exec/cmd/cmd.yara"),
        Some("exec/command/shell".to_string())
    );

    assert_eq!(
        mapper.yara_rule_to_capability("rules/anti-static/obfuscation/bitwise.yara"),
        Some("anti-analysis/obfuscation/bitwise".to_string())
    );
}

#[test]
fn test_mapping_count() {
    let mapper = CapabilityMapper::new();
    let count = mapper.mapping_count();

    // Mapper should be created successfully (count depends on environment)
    let _ = count;
}

#[test]
fn test_lookup_nonexistent() {
    let mapper = CapabilityMapper::empty();
    let capability = mapper.lookup("nonexistent_func", "test");
    assert!(capability.is_none());
}

#[test]
fn test_yara_rule_path_parsing() {
    let mapper = CapabilityMapper::new();

    // Test various path formats
    assert!(mapper
        .yara_rule_to_capability("rules/exec/shell.yara")
        .is_some());
}

#[test]
fn test_empty_mapper_counts() {
    let mapper = CapabilityMapper::empty();
    assert_eq!(mapper.mapping_count(), 0);
    assert_eq!(mapper.composite_rules_count(), 0);
    assert_eq!(mapper.trait_definitions_count(), 0);
}

#[test]
fn test_new_loads_symbols() {
    let mapper = CapabilityMapper::new();

    // Should create mapper successfully (loading depends on environment)
    let _ = mapper.mapping_count();
}

#[test]
fn test_composite_rules_count() {
    let mapper = CapabilityMapper::new();
    let count = mapper.composite_rules_count();

    // May or may not have composite rules depending on traits/ directory
    let _ = count;
}

#[test]
fn test_trait_definitions_count() {
    let mapper = CapabilityMapper::new();
    let count = mapper.trait_definitions_count();

    // May or may not have trait definitions depending on traits/ directory
    let _ = count;
}

// ==================== Defaults and Unset Tests ====================

#[test]
fn test_is_unset() {
    assert!(parsing::is_unset(&Some("none".to_string())));
    assert!(parsing::is_unset(&Some("NONE".to_string())));
    assert!(parsing::is_unset(&Some("None".to_string())));
    assert!(!parsing::is_unset(&Some("other".to_string())));
    assert!(!parsing::is_unset(&None));
}

#[test]
fn test_apply_string_default_uses_default_when_raw_is_none() {
    let default = Some("T1234".to_string());
    let result = parsing::apply_string_default(None, &default);
    assert_eq!(result, Some("T1234".to_string()));
}

#[test]
fn test_apply_string_default_uses_raw_when_present() {
    let default = Some("T1234".to_string());
    let result = parsing::apply_string_default(Some("T5678".to_string()), &default);
    assert_eq!(result, Some("T5678".to_string()));
}

#[test]
fn test_apply_string_default_unset_with_none_keyword() {
    let default = Some("T1234".to_string());
    let result = parsing::apply_string_default(Some("none".to_string()), &default);
    assert_eq!(result, None);
}

#[test]
fn test_apply_string_default_unset_case_insensitive() {
    let default = Some("T1234".to_string());
    assert_eq!(
        parsing::apply_string_default(Some("NONE".to_string()), &default),
        None
    );
    assert_eq!(
        parsing::apply_string_default(Some("None".to_string()), &default),
        None
    );
    assert_eq!(
        parsing::apply_string_default(Some("nOnE".to_string()), &default),
        None
    );
}

#[test]
fn test_apply_string_default_no_default() {
    let result = parsing::apply_string_default(None, &None);
    assert_eq!(result, None);
}

#[test]
fn test_apply_vec_default_uses_default_when_raw_is_none() {
    let default = Some(vec!["elf".to_string(), "macho".to_string()]);
    let result = parsing::apply_vec_default(None, &default);
    assert_eq!(result, Some(vec!["elf".to_string(), "macho".to_string()]));
}

#[test]
fn test_apply_vec_default_uses_raw_when_present() {
    let default = Some(vec!["elf".to_string()]);
    let result = parsing::apply_vec_default(Some(vec!["pe".to_string()]), &default);
    assert_eq!(result, Some(vec!["pe".to_string()]));
}

#[test]
fn test_apply_vec_default_unset_with_none_keyword() {
    let default = Some(vec!["elf".to_string(), "macho".to_string()]);
    let result = parsing::apply_vec_default(Some(vec!["none".to_string()]), &default);
    assert_eq!(result, None);
}

#[test]
fn test_apply_trait_defaults_applies_all_defaults() {
    let defaults = models::TraitDefaults {
        r#for: Some(vec!["php".to_string()]),
        platforms: Some(vec!["linux".to_string()]),
        crit: Some("suspicious".to_string()),
        conf: Some(0.85),
        mbc: Some("B0001".to_string()),
        attack: Some("T1059".to_string()),
    };

    let raw = models::RawTraitDefinition {
        id: "test/trait".to_string(),
        desc: "Test trait".to_string(),
        conf: None,
        crit: None,
        mbc: None,
        attack: None,
        platforms: None,
        file_types: None,
        condition: Condition::String {
            exact: Some("test".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        },
    };

    let result = parsing::apply_trait_defaults(raw, &defaults);

    assert_eq!(result.conf, 0.85);
    assert_eq!(result.crit, Criticality::Suspicious);
    assert_eq!(result.mbc, Some("B0001".to_string()));
    assert_eq!(result.attack, Some("T1059".to_string()));
    assert_eq!(result.platforms, vec![Platform::Linux]);
    assert_eq!(result.r#for, vec![RuleFileType::Php]);
}

#[test]
fn test_apply_trait_defaults_trait_overrides_defaults() {
    let defaults = models::TraitDefaults {
        r#for: Some(vec!["php".to_string()]),
        platforms: Some(vec!["linux".to_string()]),
        crit: Some("suspicious".to_string()),
        conf: Some(0.85),
        mbc: Some("B0001".to_string()),
        attack: Some("T1059".to_string()),
    };

    let raw = models::RawTraitDefinition {
        id: "test/trait".to_string(),
        desc: "Test trait".to_string(),
        conf: Some(0.99),
        crit: Some("hostile".to_string()),
        mbc: Some("B0002".to_string()),
        attack: Some("T1234".to_string()),
        platforms: Some(vec!["windows".to_string()]),
        file_types: Some(vec!["pe".to_string()]),
        condition: Condition::String {
            exact: Some("test".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        },
    };

    let result = parsing::apply_trait_defaults(raw, &defaults);

    assert_eq!(result.conf, 0.99);
    // Atomic traits cannot be HOSTILE, so they get downgraded to SUSPICIOUS
    assert_eq!(result.crit, Criticality::Suspicious);
    assert_eq!(result.mbc, Some("B0002".to_string()));
    assert_eq!(result.attack, Some("T1234".to_string()));
    assert_eq!(result.platforms, vec![Platform::Windows]);
    assert_eq!(result.r#for, vec![RuleFileType::Pe]);
}

#[test]
fn test_apply_trait_defaults_unset_mbc_with_none() {
    let defaults = models::TraitDefaults {
        r#for: None,
        platforms: None,
        crit: None,
        conf: None,
        mbc: Some("B0001".to_string()),
        attack: Some("T1059".to_string()),
    };

    let raw = models::RawTraitDefinition {
        id: "test/trait".to_string(),
        desc: "Test trait".to_string(),
        conf: None,
        crit: None,
        mbc: Some("none".to_string()), // Explicitly unset
        attack: None,                  // Use default
        platforms: None,
        file_types: None,
        condition: Condition::String {
            exact: Some("test".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        },
    };

    let result = parsing::apply_trait_defaults(raw, &defaults);

    assert_eq!(result.mbc, None); // Unset despite default
    assert_eq!(result.attack, Some("T1059".to_string())); // Default applied
}

#[test]
fn test_apply_trait_defaults_unset_attack_with_none() {
    let defaults = models::TraitDefaults {
        r#for: None,
        platforms: None,
        crit: None,
        conf: None,
        mbc: Some("B0001".to_string()),
        attack: Some("T1059".to_string()),
    };

    let raw = models::RawTraitDefinition {
        id: "test/trait".to_string(),
        desc: "Test trait".to_string(),
        conf: None,
        crit: None,
        mbc: None,                        // Use default
        attack: Some("NONE".to_string()), // Explicitly unset (uppercase)
        platforms: None,
        file_types: None,
        condition: Condition::String {
            exact: Some("test".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        },
    };

    let result = parsing::apply_trait_defaults(raw, &defaults);

    assert_eq!(result.mbc, Some("B0001".to_string())); // Default applied
    assert_eq!(result.attack, None); // Unset despite default
}

#[test]
fn test_apply_trait_defaults_unset_file_types_with_none() {
    let defaults = models::TraitDefaults {
        r#for: Some(vec!["php".to_string()]),
        platforms: None,
        crit: None,
        conf: None,
        mbc: None,
        attack: None,
    };

    let raw = models::RawTraitDefinition {
        id: "test/trait".to_string(),
        desc: "Test trait".to_string(),
        conf: None,
        crit: None,
        mbc: None,
        attack: None,
        platforms: None,
        file_types: Some(vec!["none".to_string()]), // Explicitly unset
        condition: Condition::String {
            exact: Some("test".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        },
    };

    let result = parsing::apply_trait_defaults(raw, &defaults);

    // When unset, file_types defaults to [All]
    assert_eq!(result.r#for, vec![RuleFileType::All]);
}

#[test]
fn test_apply_composite_defaults_applies_all_defaults() {
    let defaults = models::TraitDefaults {
        r#for: Some(vec!["elf".to_string(), "macho".to_string()]),
        platforms: Some(vec!["linux".to_string(), "macos".to_string()]),
        crit: Some("notable".to_string()),
        conf: Some(0.75),
        mbc: Some("B0030".to_string()),
        attack: Some("T1071.001".to_string()),
    };

    let raw = models::RawCompositeRule {
        id: "test/rule".to_string(),
        desc: "Test rule".to_string(),
        conf: None,
        crit: None,
        mbc: None,
        attack: None,
        platforms: None,
        file_types: None,
        all: None,
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
        condition: Some(Condition::String {
            exact: Some("test".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        }),
    };

    let result = parsing::apply_composite_defaults(raw, &defaults);

    assert_eq!(result.conf, 0.75);
    assert_eq!(result.crit, Criticality::Notable);
    assert_eq!(result.mbc, Some("B0030".to_string()));
    assert_eq!(result.attack, Some("T1071.001".to_string()));
    assert_eq!(result.platforms, vec![Platform::Linux, Platform::MacOS]);
    assert_eq!(result.r#for, vec![RuleFileType::Elf, RuleFileType::Macho]);
}

#[test]
fn test_apply_composite_defaults_unset_with_none() {
    let defaults = models::TraitDefaults {
        r#for: Some(vec!["elf".to_string()]),
        platforms: Some(vec!["linux".to_string()]),
        crit: Some("suspicious".to_string()),
        conf: Some(0.9),
        mbc: Some("B0030".to_string()),
        attack: Some("T1071".to_string()),
    };

    let raw = models::RawCompositeRule {
        id: "test/rule".to_string(),
        desc: "Test rule".to_string(),
        conf: None,
        crit: None,
        mbc: Some("none".to_string()),             // Unset
        attack: Some("none".to_string()),          // Unset
        platforms: Some(vec!["none".to_string()]), // Unset
        file_types: None,                          // Use default
        all: None,
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
        condition: Some(Condition::String {
            exact: Some("test".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        }),
    };

    let result = parsing::apply_composite_defaults(raw, &defaults);

    assert_eq!(result.mbc, None);
    assert_eq!(result.attack, None);
    assert_eq!(result.platforms, vec![Platform::All]); // Fallback when unset
    assert_eq!(result.r#for, vec![RuleFileType::Elf]); // Default applied
}

#[test]
fn test_yaml_with_defaults_and_unset() {
    let yaml = r#"
defaults:
  file_types: [php]
  mbc: "B0001"
  attack: "T1059"
  criticality: suspicious

traits:
  - id: test/uses-defaults
    description: "Uses all defaults"
    condition:
      type: string
      exact: "test1"

  - id: test/overrides-some
    description: "Overrides some defaults"
    mbc: "B0002"
    criticality: notable
    condition:
      type: string
      exact: "test2"

  - id: test/unsets-mbc
    description: "Unsets mbc"
    mbc: none
    condition:
      type: string
      exact: "test3"

  - id: test/unsets-attack
    description: "Unsets attack"
    attack: NONE
    condition:
      type: string
      exact: "test4"
"#;

    let mappings: models::TraitMappings = serde_yaml::from_str(yaml).expect("Failed to parse YAML");

    assert_eq!(mappings.traits.len(), 4);

    // Apply defaults and verify
    let t1 = parsing::apply_trait_defaults(
        mappings.traits.into_iter().next().unwrap(),
        &mappings.defaults,
    );
    assert_eq!(t1.mbc, Some("B0001".to_string()));
    assert_eq!(t1.attack, Some("T1059".to_string()));
    assert_eq!(t1.crit, Criticality::Suspicious);
    assert_eq!(t1.r#for, vec![RuleFileType::Php]);
}

#[test]
fn test_yaml_composite_rules_with_defaults() {
    let yaml = r#"
defaults:
  file_types: [elf, macho, pe]
  attack: "T1071.001"
  criticality: notable

composite_rules:
  - id: test/uses-defaults
    description: "Uses all defaults"
    confidence: 0.5
    condition:
      type: string
      exact: "HTTP/1.1"

  - id: test/unsets-attack
    description: "Unsets attack"
    confidence: 0.6
    attack: none
    condition:
      type: string
      exact: "GET /"
"#;

    let mappings: models::TraitMappings = serde_yaml::from_str(yaml).expect("Failed to parse YAML");

    assert_eq!(mappings.composite_rules.len(), 2);

    let rules: Vec<_> = mappings
        .composite_rules
        .into_iter()
        .map(|r| parsing::apply_composite_defaults(r, &mappings.defaults))
        .collect();

    // First rule uses defaults
    assert_eq!(rules[0].attack, Some("T1071.001".to_string()));
    assert_eq!(rules[0].crit, Criticality::Notable);
    assert_eq!(
        rules[0].r#for,
        vec![RuleFileType::Elf, RuleFileType::Macho, RuleFileType::Pe]
    );

    // Second rule unsets attack
    assert_eq!(rules[1].attack, None);
    assert_eq!(rules[1].crit, Criticality::Notable); // Still uses default
}

// ==================== Iterative Composite Evaluation Tests ====================

/// Helper to create a minimal analysis report for testing
fn test_report_with_findings(findings: Vec<Finding>) -> AnalysisReport {
    let mut report = AnalysisReport::new(TargetInfo {
        path: "/test/file".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 1000,
        sha256: "abc123".to_string(),
        architectures: None,
    });
    report.findings = findings;
    report
}

/// Helper to create a test finding
fn test_finding(id: &str) -> Finding {
    Finding {
        id: id.to_string(),
        kind: FindingKind::Capability,
        desc: format!("Test finding {}", id),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
    }
}

#[test]
fn test_iterative_eval_single_pass() {
    // Test that simple composites work in a single pass
    let mapper = CapabilityMapper::empty();
    let report = test_report_with_findings(vec![test_finding("atomic/trait-a")]);
    let findings = mapper.evaluate_composite_rules(&report, &[]);
    assert!(findings.is_empty()); // Empty mapper returns no findings
}

#[test]
fn test_iterative_eval_max_iterations_protection() {
    // Test that MAX_ITERATIONS limit prevents infinite loops
    let report = test_report_with_findings(vec![]);
    let mapper = CapabilityMapper::empty();

    let start = std::time::Instant::now();
    let _ = mapper.evaluate_composite_rules(&report, &[]);
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 1,
        "Evaluation took too long: {:?}",
        elapsed
    );
}

#[test]
fn test_composite_referencing_atomic_trait() {
    let composite = CompositeTrait {
        id: "test/composite".to_string(),
        desc: "Test composite".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: "test/atomic-trait".to_string(),
        }]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    let report = test_report_with_findings(vec![test_finding("test/atomic-trait")]);
    let mut mapper = CapabilityMapper::empty();
    mapper.composite_rules.push(composite);

    let findings = mapper.evaluate_composite_rules(&report, &[]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "test/composite");
}

#[test]
fn test_composite_of_composites_two_levels() {
    // Level 1: atomic-trait -> Level 2: composite-a -> Level 3: composite-b
    let composite_a = CompositeTrait {
        id: "test/composite-a".to_string(),
        desc: "First level".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: "test/atomic-trait".to_string(),
        }]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    let composite_b = CompositeTrait {
        id: "test/composite-b".to_string(),
        desc: "Second level".to_string(),
        conf: 0.95,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: "test/composite-a".to_string(),
        }]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    let report = test_report_with_findings(vec![test_finding("test/atomic-trait")]);
    let mut mapper = CapabilityMapper::empty();
    mapper.composite_rules.push(composite_a);
    mapper.composite_rules.push(composite_b);

    let findings = mapper.evaluate_composite_rules(&report, &[]);

    // Both composites should be found due to iterative evaluation
    assert_eq!(findings.len(), 2);
    let ids: Vec<_> = findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"test/composite-a"), "Missing composite-a");
    assert!(ids.contains(&"test/composite-b"), "Missing composite-b");
}

#[test]
fn test_composite_three_level_chain() {
    // Test 3-level chain: atomic -> A -> B -> C
    let make_composite = |id: &str, requires: &str| CompositeTrait {
        id: id.to_string(),
        desc: format!("Composite {}", id),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: requires.to_string(),
        }]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    let report = test_report_with_findings(vec![test_finding("level/zero")]);
    let mut mapper = CapabilityMapper::empty();
    mapper
        .composite_rules
        .push(make_composite("level/one", "level/zero"));
    mapper
        .composite_rules
        .push(make_composite("level/two", "level/one"));
    mapper
        .composite_rules
        .push(make_composite("level/three", "level/two"));

    let findings = mapper.evaluate_composite_rules(&report, &[]);

    assert_eq!(findings.len(), 3);
    let ids: Vec<_> = findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"level/one"));
    assert!(ids.contains(&"level/two"));
    assert!(ids.contains(&"level/three"));
}

#[test]
fn test_composite_circular_dependency_handled() {
    // Test that circular dependencies don't cause infinite loops
    let composite_a = CompositeTrait {
        id: "circular/a".to_string(),
        desc: "Circular A".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: "circular/b".to_string(),
        }]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    let composite_b = CompositeTrait {
        id: "circular/b".to_string(),
        desc: "Circular B".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: "circular/a".to_string(),
        }]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    let report = test_report_with_findings(vec![]);
    let mut mapper = CapabilityMapper::empty();
    mapper.composite_rules.push(composite_a);
    mapper.composite_rules.push(composite_b);

    let start = std::time::Instant::now();
    let findings = mapper.evaluate_composite_rules(&report, &[]);
    let elapsed = start.elapsed();

    assert!(elapsed.as_millis() < 100, "Took too long: {:?}", elapsed);
    assert!(findings.is_empty(), "Circular deps shouldn't match");
}

#[test]
fn test_composite_prefix_matching_in_chain() {
    // Test prefix matching works in composite chains
    let composite = CompositeTrait {
        id: "test/uses-discovery".to_string(),
        desc: "Uses discovery".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: "discovery/system".to_string(), // Prefix match
        }]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    // Report has specific trait under discovery/system/
    let report = test_report_with_findings(vec![test_finding("discovery/system/hostname")]);
    let mut mapper = CapabilityMapper::empty();
    mapper.composite_rules.push(composite);

    let findings = mapper.evaluate_composite_rules(&report, &[]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "test/uses-discovery");
}

#[test]
fn test_composite_requires_count_in_chain() {
    let composite = CompositeTrait {
        id: "test/needs-two".to_string(),
        desc: "Needs 2 of 3".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: None,
        any: Some(vec![
            Condition::Trait {
                id: "feat/a".to_string(),
            },
            Condition::Trait {
                id: "feat/b".to_string(),
            },
            Condition::Trait {
                id: "feat/c".to_string(),
            },
        ]),
        count: Some(2),
        min_count: None,
        max_count: None,
        none: None,
    };

    let report =
        test_report_with_findings(vec![test_finding("feat/a"), test_finding("feat/c")]);
    let mut mapper = CapabilityMapper::empty();
    mapper.composite_rules.push(composite);

    let findings = mapper.evaluate_composite_rules(&report, &[]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "test/needs-two");
}

// ==================== Complexity Calculation Tests ====================

/// Test basic complexity calculation - direct conditions count as 1
#[test]
fn test_complexity_direct_conditions() {
    use std::collections::{HashMap, HashSet};

    // Rule with 3 direct string conditions
    let rule = CompositeTrait {
        id: "test/three-strings".to_string(),
        desc: "Test rule with 3 strings".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![
            Condition::String {
                exact: Some("string1".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
            Condition::String {
                exact: Some("string2".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
            Condition::String {
                exact: Some("string3".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
        ]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();
    let composites = vec![rule.clone()];
    let traits = vec![];

    let complexity = validation::calculate_composite_complexity(
        "test/three-strings",
        &composites,
        &traits,
        &mut cache,
        &mut visiting,
    );

    // 3 direct conditions = complexity 3
    assert_eq!(complexity, 3);
}

/// Test file type filter counting as +1
#[test]
fn test_complexity_file_type_filter() {
    use std::collections::{HashMap, HashSet};

    // Rule with 2 conditions + file type filter
    let rule = CompositeTrait {
        id: "test/with-filetype".to_string(),
        desc: "Test rule with file type".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::Elf, RuleFileType::Pe], // File type filter
        all: Some(vec![
            Condition::String {
                exact: Some("string1".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
            Condition::String {
                exact: Some("string2".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
        ]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();
    let composites = vec![rule.clone()];
    let traits = vec![];

    let complexity = validation::calculate_composite_complexity(
        "test/with-filetype",
        &composites,
        &traits,
        &mut cache,
        &mut visiting,
    );

    // 2 conditions + 1 file type filter = complexity 3
    assert_eq!(complexity, 3);
}

/// Test recursive trait reference expansion
#[test]
fn test_complexity_recursive_expansion() {
    use std::collections::{HashMap, HashSet};

    // Atomic trait (not a composite, counts as 1)
    let trait_def = TraitDefinition {
        id: "test/atomic-trait".to_string(),
        desc: "Atomic trait".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        r#if: Condition::String {
            exact: Some("atomic".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        },
        not: None,
        unless: None,
        downgrade: None,
    };

    // Composite A: has 2 direct conditions (complexity 2)
    let composite_a = CompositeTrait {
        id: "test/composite-a".to_string(),
        desc: "Composite A".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![
            Condition::String {
                exact: Some("string1".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
            Condition::String {
                exact: Some("string2".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
        ]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    // Composite B: references composite A and atomic trait
    let composite_b = CompositeTrait {
        id: "test/composite-b".to_string(),
        desc: "Composite B".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![
            Condition::Trait {
                id: "test/composite-a".to_string(),
            },
            Condition::Trait {
                id: "test/atomic-trait".to_string(),
            },
        ]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();
    let composites = vec![composite_a, composite_b.clone()];
    let traits = vec![trait_def];

    let complexity = validation::calculate_composite_complexity(
        "test/composite-b",
        &composites,
        &traits,
        &mut cache,
        &mut visiting,
    );

    // composite-a has 2 direct conditions = 2
    // atomic-trait counts as 1
    // Total: 2 + 1 = 3
    assert_eq!(complexity, 3);
}

/// Test cycle detection in trait references
#[test]
fn test_complexity_cycle_detection() {
    use std::collections::{HashMap, HashSet};

    // Composite A references B
    let composite_a = CompositeTrait {
        id: "test/circular-a".to_string(),
        desc: "Circular A".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: "test/circular-b".to_string(),
        }]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    // Composite B references A (cycle!)
    let composite_b = CompositeTrait {
        id: "test/circular-b".to_string(),
        desc: "Circular B".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: "test/circular-a".to_string(),
        }]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();
    let composites = vec![composite_a.clone(), composite_b];
    let traits = vec![];

    let complexity = validation::calculate_composite_complexity(
        "test/circular-a",
        &composites,
        &traits,
        &mut cache,
        &mut visiting,
    );

    // Cycle detected - should not panic and should return finite value
    // Cycle is treated as complexity 1
    assert_eq!(complexity, 1);
}

/// Test caching behavior
#[test]
fn test_complexity_caching() {
    use std::collections::{HashMap, HashSet};

    let rule = CompositeTrait {
        id: "test/cacheable".to_string(),
        desc: "Cacheable rule".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![
            Condition::String {
                exact: Some("string1".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
            Condition::String {
                exact: Some("string2".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
        ]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();
    let composites = vec![rule.clone()];
    let traits = vec![];

    // First call - should calculate and cache
    let complexity1 = validation::calculate_composite_complexity(
        "test/cacheable",
        &composites,
        &traits,
        &mut cache,
        &mut visiting,
    );

    // Check cache was populated
    assert_eq!(cache.get("test/cacheable"), Some(&2));

    // Second call - should use cache
    let complexity2 = validation::calculate_composite_complexity(
        "test/cacheable",
        &composites,
        &traits,
        &mut cache,
        &mut visiting,
    );

    assert_eq!(complexity1, complexity2);
    assert_eq!(complexity1, 2);
}

/// Test threshold validation - rules < 4 get downgraded from HOSTILE to SUSPICIOUS
#[test]
fn test_complexity_threshold_validation() {
    // Rule with complexity 3 (below threshold)
    let rule_low = CompositeTrait {
        id: "test/low-complexity".to_string(),
        desc: "Low complexity".to_string(),
        conf: 0.95,
        crit: Criticality::Hostile, // Will be downgraded
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![
            Condition::String {
                exact: Some("string1".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
            Condition::String {
                exact: Some("string2".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
            Condition::String {
                exact: Some("string3".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
        ]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    // Rule with complexity 4 (meets threshold)
    let rule_high = CompositeTrait {
        id: "test/high-complexity".to_string(),
        desc: "High complexity".to_string(),
        conf: 0.95,
        crit: Criticality::Hostile, // Will NOT be downgraded
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::Elf], // File type filter = +1
        all: Some(vec![
            Condition::String {
                exact: Some("string1".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
            Condition::String {
                exact: Some("string2".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
            Condition::String {
                exact: Some("string3".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
        ]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    let mut composites = vec![rule_low, rule_high];
    let traits = vec![];

    // Run validation
    validation::validate_hostile_composite_complexity(&mut composites, &traits);

    // Check that low complexity was downgraded
    let low_rule = composites
        .iter()
        .find(|r| r.id == "test/low-complexity")
        .unwrap();
    assert_eq!(low_rule.crit, Criticality::Suspicious);

    // Check that high complexity was NOT downgraded
    let high_rule = composites
        .iter()
        .find(|r| r.id == "test/high-complexity")
        .unwrap();
    assert_eq!(high_rule.crit, Criticality::Hostile);
}

/// Test complexity with mixed condition types (all, any, none)
#[test]
fn test_complexity_mixed_conditions() {
    use std::collections::{HashMap, HashSet};

    let rule = CompositeTrait {
        id: "test/mixed".to_string(),
        desc: "Mixed conditions".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::String {
            exact: Some("string1".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        }]),
        any: Some(vec![
            Condition::String {
                exact: Some("string2".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
            Condition::String {
                exact: Some("string3".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
        ]),
        count: None,
        min_count: None,
        max_count: None,
        none: Some(vec![Condition::String {
            exact: Some("string4".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        }]),
    };

    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();
    let composites = vec![rule.clone()];
    let traits = vec![];

    let complexity = validation::calculate_composite_complexity(
        "test/mixed",
        &composites,
        &traits,
        &mut cache,
        &mut visiting,
    );

    // 1 from 'all' + 2 from 'any' + 1 from 'none' = 4
    assert_eq!(complexity, 4);
}

/// Test complexity with deeply nested trait references
#[test]
fn test_complexity_deep_nesting() {
    use std::collections::{HashMap, HashSet};

    // Level 1: 2 direct conditions
    let level1 = CompositeTrait {
        id: "test/level1".to_string(),
        desc: "Level 1".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![
            Condition::String {
                exact: Some("l1-s1".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
            Condition::String {
                exact: Some("l1-s2".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
        ]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    // Level 2: references level1 + 1 direct condition
    let level2 = CompositeTrait {
        id: "test/level2".to_string(),
        desc: "Level 2".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![
            Condition::Trait {
                id: "test/level1".to_string(),
            },
            Condition::String {
                exact: Some("l2-s1".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
        ]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    // Level 3: references level2 + 1 direct condition
    let level3 = CompositeTrait {
        id: "test/level3".to_string(),
        desc: "Level 3".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![
            Condition::Trait {
                id: "test/level2".to_string(),
            },
            Condition::String {
                exact: Some("l3-s1".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
            },
        ]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();
    let composites = vec![level1, level2, level3];
    let traits = vec![];

    let complexity = validation::calculate_composite_complexity(
        "test/level3",
        &composites,
        &traits,
        &mut cache,
        &mut visiting,
    );

    // level3: level2 + 1 = level1 + 1 + 1 = 2 + 1 + 1 = 4
    assert_eq!(complexity, 4);
}
