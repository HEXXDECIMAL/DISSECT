//! Tests for composite rules module.

use super::*;
use crate::types::{AnalysisReport, Criticality, Import, StringInfo, TargetInfo};

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
        all: Some(vec![Condition::Symbol {
            pattern: "socket".to_string(),
            platforms: None,
        }]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
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
        all: Some(vec![
            Condition::Symbol {
                pattern: "socket".to_string(),
                platforms: None,
            },
            Condition::String {
                exact: Some("/bin/sh".to_string()),
                regex: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            },
        ]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
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
        all: None,
        any: Some(vec![
            Condition::Symbol {
                pattern: "socket".to_string(),
                platforms: None,
            },
            Condition::Symbol {
                pattern: "connect".to_string(),
                platforms: None,
            },
            Condition::Symbol {
                pattern: "nonexistent".to_string(),
                platforms: None,
            },
        ]),
        count: Some(2),
        min_count: None,
        max_count: None,
        none: None,
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
        all: Some(vec![Condition::String {
            exact: Some("/bin/sh".to_string()),
            regex: None,
            case_insensitive: false,
            exclude_patterns: None,
            min_count: 1,
            search_raw: false,
        }]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
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
        all: None,
        any: Some(vec![
            Condition::Symbol {
                pattern: "nonexistent".to_string(),
                platforms: None,
            },
            Condition::Symbol {
                pattern: "socket".to_string(),
                platforms: None,
            },
        ]),
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_some());
}
