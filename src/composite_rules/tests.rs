//! Tests for composite rules module.

use super::*;
use crate::composite_rules::condition::NotException;
use crate::composite_rules::traits::DowngradeConditions;
use crate::types::{
    AnalysisReport, Criticality, Finding, FindingKind, Import, StringInfo, TargetInfo,
};

fn create_test_context() -> (AnalysisReport, Vec<u8>) {
    let target = TargetInfo {
        path: "/test".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 1024,
        sha256: "test".to_string(),
        architectures: Some(vec!["x86_64".to_string()]),
    };

    let mut report = AnalysisReport::new(target);

    // Add some test imports
    report.imports.push(Import {
        symbol: "socket".to_string(),
        library: None,
        source: "test".to_string(),
    });

    report.imports.push(Import {
        symbol: "connect".to_string(),
        library: None,
        source: "test".to_string(),
    });

    // Add some test strings
    report.strings.push(StringInfo {
        value: "/bin/sh".to_string(),
        offset: Some("0x1000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Path,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    (report, vec![])
}

#[test]
fn test_symbol_condition() {
    let (report, data) = create_test_context();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    let rule = CompositeTrait {
        id: "test/capability".to_string(),
        desc: "Test".to_string(),
        conf: 0.9,
        crit: Criticality::Inert,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            compiled_regex: None,
        }]),
        any: None,



        none: None,
        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_some());

    let cap = result.unwrap();
    assert_eq!(cap.id, "test/capability");
    assert!(!cap.evidence.is_empty());
}

#[test]
fn test_all() {
    let (report, data) = create_test_context();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    let rule = CompositeTrait {
        id: "net/reverse-shell".to_string(),
        desc: "Reverse shell".to_string(),
        conf: 0.9,
        crit: Criticality::Inert,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        all: Some(vec![
            Condition::Symbol {
                exact: None,
                substr: None,
                regex: Some("socket".to_string()),
                platforms: None,
                compiled_regex: None,
            },
            Condition::String {
                exact: Some("/bin/sh".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
        ]),
        any: None,



        none: None,
        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_some());
}

#[test]
fn test_count() {
    let (report, data) = create_test_context();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    let rule = CompositeTrait {
        id: "test/multi".to_string(),
        desc: "Multiple conditions".to_string(),
        conf: 0.85,
        crit: Criticality::Inert,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        all: None,
        any: Some(vec![
            Condition::Symbol {
                exact: None,
                substr: None,
                regex: Some("socket".to_string()),
                platforms: None,
                compiled_regex: None,
            },
            Condition::Symbol {
                exact: None,
                substr: None,
                regex: Some("connect".to_string()),
                platforms: None,
                compiled_regex: None,
            },
            Condition::Symbol {
                exact: None,
                substr: None,
                regex: Some("nonexistent".to_string()),
                platforms: None,
                compiled_regex: None,
            },
        ]),
        none: None,
        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_some());
}

#[test]
fn test_string_exact_condition() {
    let (report, data) = create_test_context();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    let rule = CompositeTrait {
        id: "test/string-exact".to_string(),
        desc: "Exact string match".to_string(),
        conf: 0.9,
        crit: Criticality::Inert,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::String {
            exact: Some("/bin/sh".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        }]),
        any: None,



        none: None,
        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_some());
}

#[test]
fn test_any() {
    let (report, data) = create_test_context();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    let rule = CompositeTrait {
        id: "test/requires-any".to_string(),
        desc: "Requires any condition".to_string(),
        conf: 0.9,
        crit: Criticality::Inert,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        all: None,
        any: Some(vec![
            Condition::Symbol {
                exact: None,
                substr: None,
                regex: Some("nonexistent".to_string()),
                platforms: None,
                compiled_regex: None,
            },
            Condition::Symbol {
                exact: None,
                substr: None,
                regex: Some("socket".to_string()),
                platforms: None,
                compiled_regex: None,
            },
        ]),



        none: None,
        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_some());
}

// ============================================================================
// Tests for new directives: not:, unless:, downgrade:
// ============================================================================

#[test]
fn test_not_directive_shorthand() {
    let (mut report, data) = create_test_context();

    // Add multiple domain strings
    report.strings.push(StringInfo {
        value: "apple.com".to_string(),
        offset: Some("0x2000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Url,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: "evil.com".to_string(),
        offset: Some("0x3000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Url,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    let trait_def = TraitDefinition {
        id: "test/domains".to_string(),
        desc: "Domain detection".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        r#if: Condition::String {
            exact: None,
            substr: None,
            regex: Some(r"[a-z]+\.com".to_string()),
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        },
        not: Some(vec![NotException::Shorthand("apple.com".to_string())]),
        unless: None,
        downgrade: None,
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());

    let finding = result.unwrap();
    // Should only have evil.com, not apple.com
    assert_eq!(finding.evidence.len(), 1);
    assert!(finding.evidence[0].value.contains("evil.com"));
}

#[test]
fn test_not_directive_exact() {
    let (mut report, data) = create_test_context();

    report.strings.push(StringInfo {
        value: "github.com".to_string(),
        offset: Some("0x2000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Url,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: "bad.com".to_string(),
        offset: Some("0x3000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Url,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    let trait_def = TraitDefinition {
        id: "test/domains".to_string(),
        desc: "Domain detection".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        r#if: Condition::String {
            exact: None,
            substr: None,
            regex: Some(r"[a-z]+\.com".to_string()),
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        },
        not: Some(vec![NotException::Structured {
            exact: Some("github.com".to_string()),
            substr: None,
            regex: None,
        }]),
        unless: None,
        downgrade: None,
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());

    let finding = result.unwrap();
    assert_eq!(finding.evidence.len(), 1);
    assert!(finding.evidence[0].value.contains("bad.com"));
}

#[test]
fn test_not_directive_regex() {
    let (mut report, data) = create_test_context();

    // Add IP addresses
    report.strings.push(StringInfo {
        value: "192.168.1.1".to_string(),
        offset: Some("0x2000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Ip,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: "8.8.8.8".to_string(),
        offset: Some("0x3000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Ip,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    let trait_def = TraitDefinition {
        id: "test/ips".to_string(),
        desc: "IP detection".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        r#if: Condition::String {
            exact: None,
            substr: None,
            regex: Some(r"\d+\.\d+\.\d+\.\d+".to_string()),
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        },
        not: Some(vec![NotException::Structured {
            exact: None,
            substr: None,
            regex: Some(r"^192\.168\.".to_string()),
        }]),
        unless: None,
        downgrade: None,
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());

    let finding = result.unwrap();
    // Should only have 8.8.8.8, not 192.168.1.1
    assert_eq!(finding.evidence.len(), 1);
    assert!(finding.evidence[0].value.contains("8.8.8.8"));
}

#[test]
fn test_unless_directive_skips_trait() {
    let (report, data) = create_test_context();

    // Add a finding that would trigger unless condition
    let findings = vec![Finding {
        id: "file/signed/apple".to_string(),
        kind: FindingKind::Capability,
        desc: "Apple signed binary".to_string(),
        conf: 1.0,
        crit: Criticality::Inert,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
    }];

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: Some(&findings),
        cached_ast: None,
        finding_id_index: None,
    };

    let trait_def = TraitDefinition {
        id: "test/network".to_string(),
        desc: "Network activity".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        r#if: Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            compiled_regex: None,
        },
        not: None,
        unless: Some(vec![Condition::Trait {
            id: "file/signed/apple".to_string(),
        }]),
        downgrade: None,
    };

    // Should return None because unless condition matches
    let result = trait_def.evaluate(&ctx);
    assert!(result.is_none());
}

#[test]
fn test_unless_directive_allows_trait() {
    let (report, data) = create_test_context();

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    let trait_def = TraitDefinition {
        id: "test/network".to_string(),
        desc: "Network activity".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        r#if: Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            compiled_regex: None,
        },
        not: None,
        unless: Some(vec![Condition::Trait {
            id: "file/signed/apple".to_string(),
        }]),
        downgrade: None,
    };

    // Should return Some because unless condition doesn't match
    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
}

#[test]
fn test_downgrade_to_notable() {
    let (report, data) = create_test_context();

    // Add finding for downgrade condition
    let findings = vec![Finding {
        id: "file/type/shell-script".to_string(),
        kind: FindingKind::Capability,
        desc: "Shell script".to_string(),
        conf: 1.0,
        crit: Criticality::Inert,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
    }];

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: Some(&findings),
        cached_ast: None,
        finding_id_index: None,
    };

    let trait_def = TraitDefinition {
        id: "test/curl-pipe".to_string(),
        desc: "Curl pipe to bash".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        r#if: Condition::String {
            exact: Some("/bin/sh".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        },
        not: None,
        unless: None,
        downgrade: Some(DowngradeConditions {
            any: Some(vec![Condition::Trait {
                id: "file/type/shell-script".to_string(),
            }]),
            all: None,
            none: None,
            needs: None,
        }),
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());

    let finding = result.unwrap();
    // Should be downgraded one level: Suspicious → Notable
    assert_eq!(finding.crit, Criticality::Notable);
}

#[test]
fn test_downgrade_one_level() {
    let (report, data) = create_test_context();

    let findings = vec![Finding {
        id: "file/path/test-fixtures".to_string(),
        kind: FindingKind::Capability,
        desc: "Test fixture".to_string(),
        conf: 1.0,
        crit: Criticality::Inert,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
    }];

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: Some(&findings),
        cached_ast: None,
        finding_id_index: None,
    };

    let trait_def = TraitDefinition {
        id: "test/network".to_string(),
        desc: "Network call".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        r#if: Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            compiled_regex: None,
        },
        not: None,
        unless: None,
        downgrade: Some(DowngradeConditions {
            any: Some(vec![Condition::Trait {
                id: "file/path/test-fixtures".to_string(),
            }]),
            all: None,
            none: None,
            needs: None,
        }),
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());

    let finding = result.unwrap();
    // Should be downgraded one level: Notable → Inert
    assert_eq!(finding.crit, Criticality::Inert);
}

#[test]
fn test_downgrade_no_match_keeps_original() {
    let (report, data) = create_test_context();

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    let trait_def = TraitDefinition {
        id: "test/network".to_string(),
        desc: "Network call".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        r#if: Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            compiled_regex: None,
        },
        not: None,
        unless: None,
        downgrade: Some(DowngradeConditions {
            any: Some(vec![Condition::Trait {
                id: "file/signed/apple".to_string(),
            }]),
            all: None,
            none: None,
            needs: None,
        }),
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());

    let finding = result.unwrap();
    // Should keep original Suspicious (downgrade condition didn't match)
    assert_eq!(finding.crit, Criticality::Suspicious);
}

#[test]
fn test_downgrade_from_hostile() {
    let (report, data) = create_test_context();

    // Add finding that will trigger downgrade
    let findings = vec![Finding {
        id: "file/type/shell-script".to_string(),
        kind: FindingKind::Capability,
        desc: "Shell script".to_string(),
        conf: 1.0,
        crit: Criticality::Inert,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
    }];

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: Some(&findings),
        cached_ast: None,
        finding_id_index: None,
    };

    let trait_def = TraitDefinition {
        id: "test/network".to_string(),
        desc: "Network call".to_string(),
        conf: 1.0,
        crit: Criticality::Hostile,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        r#if: Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            compiled_regex: None,
        },
        not: None,
        unless: None,
        downgrade: Some(DowngradeConditions {
            any: Some(vec![Condition::Trait {
                id: "file/type/shell-script".to_string(),
            }]),
            all: None,
            none: None,
            needs: None,
        }),
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());

    let finding = result.unwrap();
    // Should be downgraded one level: Hostile → Suspicious
    assert_eq!(finding.crit, Criticality::Suspicious);
}

#[test]
fn test_all_three_directives_combined() {
    let (mut report, data) = create_test_context();

    // Add strings
    report.strings.push(StringInfo {
        value: "apple.com".to_string(),
        offset: Some("0x2000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Url,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: "evil.com".to_string(),
        offset: Some("0x3000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Url,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    // Add finding for downgrade
    let findings = vec![Finding {
        id: "file/type/test".to_string(),
        kind: FindingKind::Capability,
        desc: "Test file".to_string(),
        conf: 1.0,
        crit: Criticality::Inert,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
    }];

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: Some(&findings),
        cached_ast: None,
        finding_id_index: None,
    };

    let trait_def = TraitDefinition {
        id: "test/domains".to_string(),
        desc: "Domain detection".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        r#if: Condition::String {
            exact: None,
            substr: None,
            regex: Some(r"[a-z]+\.com".to_string()),
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        },
        not: Some(vec![NotException::Shorthand("apple.com".to_string())]),
        unless: None,
        downgrade: Some(DowngradeConditions {
            any: Some(vec![Condition::Trait {
                id: "file/type/test".to_string(),
            }]),
            all: None,
            none: None,
            needs: None,
        }),
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());

    let finding = result.unwrap();
    // Should filter apple.com (not:)
    assert_eq!(finding.evidence.len(), 1);
    assert!(finding.evidence[0].value.contains("evil.com"));
    // Should be downgraded one level: Suspicious → Notable
    assert_eq!(finding.crit, Criticality::Notable);
}

// ===== Tests for exact vs substr vs regex match modes =====

#[test]
fn test_string_exact_match_requires_full_equality() {
    let (mut report, data) = create_test_context();

    // Add test strings
    report.strings.push(StringInfo {
        value: "hello".to_string(),
        offset: Some("0x1000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Plain,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: "hello world".to_string(),
        offset: Some("0x2000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Plain,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    // exact: "hello" should match only "hello", not "hello world"
    let trait_def = TraitDefinition {
        id: "test/exact".to_string(),
        desc: "Exact match test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        r#if: Condition::String {
            exact: Some("hello".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        },
        not: None,
        unless: None,
        downgrade: None,
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    // Should only match "hello", not "hello world"
    assert_eq!(finding.evidence.len(), 1);
    assert_eq!(finding.evidence[0].value, "hello");
}

#[test]
fn test_string_substr_matches_substrings() {
    let (mut report, data) = create_test_context();

    // Add test strings
    report.strings.push(StringInfo {
        value: "hello".to_string(),
        offset: Some("0x1000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Plain,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: "hello world".to_string(),
        offset: Some("0x2000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Plain,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    // substr: "hello" should match both "hello" and "hello world"
    let trait_def = TraitDefinition {
        id: "test/substr".to_string(),
        desc: "Substr match test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        r#if: Condition::String {
            exact: None,
            substr: Some("hello".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        },
        not: None,
        unless: None,
        downgrade: None,
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    // Should match both strings
    assert_eq!(finding.evidence.len(), 2);
}

#[test]
fn test_symbol_exact_vs_substr() {
    let (mut report, data) = create_test_context();

    // Add test symbols
    report.imports.push(Import {
        symbol: "read".to_string(),
        library: None,
        source: "test".to_string(),
    });
    report.imports.push(Import {
        symbol: "readlink".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    // exact: "read" should match only "read", not "readlink"
    let trait_exact = TraitDefinition {
        id: "test/symbol-exact".to_string(),
        desc: "Symbol exact test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        r#if: Condition::Symbol {
            exact: Some("read".to_string()),
            substr: None,
            regex: None,
            platforms: None,
            compiled_regex: None,
        },
        not: None,
        unless: None,
        downgrade: None,
    };

    let result = trait_exact.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    assert_eq!(finding.evidence.len(), 1);
    assert_eq!(finding.evidence[0].value, "read");

    // substr: "read" should match both "read" and "readlink"
    let trait_substr = TraitDefinition {
        id: "test/symbol-substr".to_string(),
        desc: "Symbol substr test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        r#if: Condition::Symbol {
            exact: None,
            substr: Some("read".to_string()),
            regex: None,
            platforms: None,
            compiled_regex: None,
        },
        not: None,
        unless: None,
        downgrade: None,
    };

    let result = trait_substr.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    assert_eq!(finding.evidence.len(), 2);
}

#[test]
fn test_string_case_insensitive_exact() {
    let (mut report, data) = create_test_context();

    report.strings.push(StringInfo {
        value: "HELLO".to_string(),
        offset: Some("0x1000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Plain,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    // Case-insensitive exact match
    let trait_def = TraitDefinition {
        id: "test/case-insensitive".to_string(),
        desc: "Case insensitive test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        r#if: Condition::String {
            exact: Some("hello".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: true,
            exclude_patterns: None,
            min_count: 1,
            compiled_regex: None,
            compiled_excludes: Vec::new(),
        },
        not: None,
        unless: None,
        downgrade: None,
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
}

#[test]
fn test_string_word_boundary_match() {
    let (mut report, data) = create_test_context();

    report.strings.push(StringInfo {
        value: "the cat sat".to_string(),
        offset: Some("0x1000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Plain,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: "category".to_string(),
        offset: Some("0x2000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Plain,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    // word: "cat" should match "the cat sat" but not "category"
    let trait_def = TraitDefinition {
        id: "test/word".to_string(),
        desc: "Word boundary test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        r#if: Condition::String {
            exact: None,
            substr: None,
            regex: None,
            word: Some("cat".to_string()),
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            compiled_regex: Some(regex::Regex::new(r"\bcat\b").unwrap()),
            compiled_excludes: Vec::new(),
        },
        not: None,
        unless: None,
        downgrade: None,
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    // Should only match "the cat sat", not "category"
    assert_eq!(finding.evidence.len(), 1);
    assert!(finding.evidence[0].value.contains("cat"));
}

#[test]
fn test_string_regex_match() {
    let (mut report, data) = create_test_context();

    report.strings.push(StringInfo {
        value: "192.168.1.1".to_string(),
        offset: Some("0x1000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Ip,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: "10.0.0.1".to_string(),
        offset: Some("0x2000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Ip,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: "not an ip".to_string(),
        offset: Some("0x3000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Plain,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    // regex for IP addresses
    let trait_def = TraitDefinition {
        id: "test/regex".to_string(),
        desc: "Regex test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        r#if: Condition::String {
            exact: None,
            substr: None,
            regex: Some(r"\d+\.\d+\.\d+\.\d+".to_string()),
            word: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            compiled_regex: Some(regex::Regex::new(r"\d+\.\d+\.\d+\.\d+").unwrap()),
            compiled_excludes: Vec::new(),
        },
        not: None,
        unless: None,
        downgrade: None,
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    // Should match both IP addresses
    assert_eq!(finding.evidence.len(), 2);
}

#[test]
fn test_content_exact_vs_substr() {
    let data = b"hello world this is a test".to_vec();
    let (mut report, _) = create_test_context();
    report.strings.clear(); // Clear existing strings so we fall through to content check

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Shell,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    // exact: should match only if entire content equals the pattern (won't match)
    let result = super::evaluators::eval_raw(
        Some(&"hello".to_string()),
        None,
        None,
        None,
        false,
        1,
        None,
        &ctx,
    );
    // Exact match against whole content should fail (content is "hello world..." not "hello")
    assert!(!result.matched);

    // substr: should match because "hello" appears in the content
    let result = super::evaluators::eval_raw(
        None,
        Some(&"hello".to_string()),
        None,
        None,
        false,
        1,
        None,
        &ctx,
    );
    assert!(result.matched);
}

#[test]
fn test_base64_decoded_matching() {
    let (mut report, data) = create_test_context();

    // Add decoded base64 strings
    report.strings.push(StringInfo {
        value: "secret".to_string(),
        offset: Some("0x2000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Plain,
        section: None,
        encoding_chain: vec!["base64".to_string()],
        fragments: None,
    });

    report.strings.push(StringInfo {
        value: "secret password".to_string(),
        offset: Some("0x3000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Plain,
        section: None,
        encoding_chain: vec!["base64".to_string()],
        fragments: None,
    });

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    // exact: should match only "secret", not "secret password"
    let result =
        super::evaluators::eval_base64(Some(&"secret".to_string()), None, None, false, 1, &ctx);
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);

    // substr: should match both
    let result =
        super::evaluators::eval_base64(None, Some(&"secret".to_string()), None, false, 1, &ctx);
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 2);
}

#[test]
fn test_xor_decoded_matching() {
    let (mut report, data) = create_test_context();

    // Add decoded XOR strings
    report.strings.push(StringInfo {
        value: "http://evil.com".to_string(),
        offset: Some("0x4000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Url,
        section: None,
        encoding_chain: vec!["xor".to_string()],
        fragments: None,
    });

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    // exact: should match full URL
    let result = super::evaluators::eval_xor(
        None,
        Some(&"http://evil.com".to_string()),
        None,
        None,
        false,
        1,
        &ctx,
    );
    assert!(result.matched);

    // substr: should match partial
    let result =
        super::evaluators::eval_xor(None, None, Some(&"evil".to_string()), None, false, 1, &ctx);
    assert!(result.matched);

    // regex: should match pattern
    let result = super::evaluators::eval_xor(
        None,
        None,
        None,
        Some(&r"https?://".to_string()),
        false,
        1,
        &ctx,
    );
    assert!(result.matched);
}

// ============================================================================
// Tests for basename condition
// ============================================================================

fn create_test_context_with_path(path: &str) -> (AnalysisReport, Vec<u8>) {
    let target = TargetInfo {
        path: path.to_string(),
        file_type: "python".to_string(),
        size_bytes: 1024,
        sha256: "test".to_string(),
        architectures: None,
    };

    let report = AnalysisReport::new(target);
    (report, vec![])
}

#[test]
fn test_basename_exact_match() {
    let (report, data) = create_test_context_with_path("/home/user/project/__init__.py");

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Python,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    // exact: "__init__.py" should match
    let result =
        super::evaluators::eval_basename(Some(&"__init__.py".to_string()), None, None, false, &ctx);
    assert!(result.matched);
    assert_eq!(result.evidence[0].value, "__init__.py");
}

#[test]
fn test_basename_exact_no_match() {
    let (report, data) = create_test_context_with_path("/home/user/project/main.py");

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Python,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    // exact: "__init__.py" should not match "main.py"
    let result =
        super::evaluators::eval_basename(Some(&"__init__.py".to_string()), None, None, false, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_basename_substr_match() {
    let (report, data) = create_test_context_with_path("/home/user/project/setup_tools.py");

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Python,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    // substr: "setup" should match "setup_tools.py"
    let result =
        super::evaluators::eval_basename(None, Some(&"setup".to_string()), None, false, &ctx);
    assert!(result.matched);
}

#[test]
fn test_basename_regex_match() {
    let (report, data) = create_test_context_with_path("/home/user/project/test_utils.py");

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Python,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    // regex: "^test_" should match files starting with "test_"
    let result =
        super::evaluators::eval_basename(None, None, Some(&"^test_".to_string()), false, &ctx);
    assert!(result.matched);
}

#[test]
fn test_basename_case_insensitive() {
    let (report, data) = create_test_context_with_path("/home/user/project/README.md");

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::All,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    // exact: "readme.md" should match "README.md" with case_insensitive
    let result = super::evaluators::eval_basename(
        Some(&"readme.md".to_string()),
        None,
        None,
        true, // case_insensitive
        &ctx,
    );
    assert!(result.matched);
}

#[test]
fn test_basename_in_trait_definition() {
    let (report, data) = create_test_context_with_path("/home/user/project/__init__.py");

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Python,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    let trait_def = TraitDefinition {
        id: "test/init-file".to_string(),
        desc: "Python init file".to_string(),
        conf: 1.0,
        crit: Criticality::Inert,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::Python],
        size_min: None,
        size_max: None,
        r#if: Condition::Basename {
            exact: Some("__init__.py".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
        },
        not: None,
        unless: None,
        downgrade: None,
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    assert_eq!(finding.id, "test/init-file");
}

#[test]
fn test_basename_in_composite_rule() {
    let (report, data) = create_test_context_with_path("/home/user/project/setup.py");

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Python,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    let rule = CompositeTrait {
        id: "test/setup-file".to_string(),
        desc: "Python setup file".to_string(),
        conf: 0.9,
        crit: Criticality::Inert,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::Python],
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Basename {
            exact: None,
            substr: None,
            regex: Some("^setup\\.py$".to_string()),
            case_insensitive: false,
        }]),
        any: None,
        none: None,
        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_some());
}

// ============================================================================
// Tests for unless directive on CompositeTrait
// ============================================================================

#[test]
fn test_composite_unless_skips_rule() {
    let (report, data) = create_test_context();

    // Add a finding that would trigger the unless condition
    let findings = vec![Finding {
        id: "file/signed/apple".to_string(),
        kind: FindingKind::Capability,
        desc: "Apple signed binary".to_string(),
        conf: 1.0,
        crit: Criticality::Inert,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
    }];

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: Some(&findings),
        cached_ast: None,
        finding_id_index: None,
    };

    // Composite rule with unless condition
    let rule = CompositeTrait {
        id: "test/network-composite".to_string(),
        desc: "Network activity composite".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            compiled_regex: None,
        }]),
        any: None,
        none: None,
        unless: Some(vec![Condition::Trait {
            id: "file/signed/apple".to_string(),
        }]),
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
    };

    // Should return None because unless condition matches
    let result = rule.evaluate(&ctx);
    assert!(
        result.is_none(),
        "Composite rule should be skipped when unless condition matches"
    );
}

#[test]
fn test_composite_unless_allows_rule() {
    let (report, data) = create_test_context();

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None, // No findings that would match unless
        cached_ast: None,
        finding_id_index: None,
    };

    let rule = CompositeTrait {
        id: "test/network-composite".to_string(),
        desc: "Network activity composite".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            compiled_regex: None,
        }]),
        any: None,
        none: None,
        unless: Some(vec![Condition::Trait {
            id: "file/signed/apple".to_string(),
        }]),
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
    };

    // Should return Some because unless condition doesn't match
    let result = rule.evaluate(&ctx);
    assert!(
        result.is_some(),
        "Composite rule should match when unless condition doesn't match"
    );
}

#[test]
fn test_composite_unless_with_basename() {
    // Test the libX11.so case that was the original bug report
    let (report, data) = create_test_context_with_path("/usr/lib/libX11.so.6");

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    let rule = CompositeTrait {
        id: "test/x11-keylog".to_string(),
        desc: "X11 keylogger pattern".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::Elf],
        size_min: None,
        size_max: None,
        any: Some(vec![Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("XQueryKeymap".to_string()),
            platforms: None,
            compiled_regex: None,
        }]),
        all: None,
        none: None,
        // Skip if this looks like libX11 itself
        unless: Some(vec![Condition::Basename {
            exact: None,
            substr: None,
            regex: Some(r"^libX11(\\.so|\\.dylib).*".to_string()),
            case_insensitive: false,
        }]),
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
    };

    // Should return None because the basename matches libX11.so
    let result = rule.evaluate(&ctx);
    assert!(
        result.is_none(),
        "Composite rule should be skipped for libX11.so (unless basename condition should match)"
    );
}

#[test]
fn test_composite_unless_multiple_conditions_any_matches() {
    let (mut report, data) = create_test_context();

    // Add a string that will match one of the unless conditions
    report.strings.push(StringInfo {
        value: "X.Org Foundation".to_string(),
        offset: Some("0x4000".to_string()),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Plain,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
    };

    let rule = CompositeTrait {
        id: "test/multi-unless".to_string(),
        desc: "Rule with multiple unless conditions".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![FileType::All],
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            compiled_regex: None,
        }]),
        any: None,
        none: None,
        // Multiple unless conditions - any match should skip the rule
        unless: Some(vec![
            Condition::Basename {
                exact: Some("system-library.so".to_string()),
                substr: None,
                regex: None,
                case_insensitive: false,
            },
            Condition::String {
                exact: None,
                substr: None,
                regex: Some(r"X\.Org".to_string()),
                word: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
        ]),
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
    };

    // Should return None because the second unless condition (string regex) matches
    let result = rule.evaluate(&ctx);
    assert!(
        result.is_none(),
        "Composite rule should be skipped when ANY unless condition matches"
    );
}
