//! Tests for rule evaluation
//!
//! Comprehensive tests for condition evaluation, composite rules, and trait definitions.

use super::evaluators::*;
use super::types::*;
use crate::radare2::SyscallInfo;
use crate::types::{
    AnalysisReport, Criticality, Export, Import, StringInfo, StringType, TargetInfo,
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

    report.exports.push(Export {
        symbol: "main".to_string(),
        offset: Some("0x1000".to_string()),
        source: "test".to_string(),
    });

    (report, b"test binary data".to_vec())
}

#[test]
fn test_symbol_match_exact() {
    let (report, data) = create_test_context();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    let result = eval_symbol("socket", None, &ctx);
    assert!(result.matched);
    assert!(!result.evidence.is_empty());
}

#[test]
fn test_symbol_match_regex() {
    let (report, data) = create_test_context();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    let result = eval_symbol("socket|connect", None, &ctx);
    assert!(result.matched);
    assert!(result.evidence.len() >= 2);
}

#[test]
fn test_symbol_no_match() {
    let (report, data) = create_test_context();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    let result = eval_symbol("nonexistent_symbol", None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_string_exact_match() {
    let (mut report, data) = create_test_context();
    report.strings.push(StringInfo {
        value: "test string".to_string(),
        offset: Some("0x1000".to_string()),
        encoding: "utf8".to_string(),
        string_type: StringType::Plain,
        section: None,
    });

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    let params = StringParams {
        exact: Some(&"test string".to_string()),
        regex: None,
        case_insensitive: false,
        exclude_patterns: None,
        min_count: 1,
        search_raw: false,
    };

    let result = eval_string(&params, &ctx);
    assert!(result.matched);
}

#[test]
fn test_imports_count() {
    let (report, data) = create_test_context();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    // Should have exactly 2 imports
    let result = eval_imports_count(Some(2), Some(2), None, &ctx);
    assert!(result.matched);

    // Should fail with min 3
    let result = eval_imports_count(Some(3), None, None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_composite_requires_all() {
    let (report, data) = create_test_context();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    let rule = CompositeTrait {
        id: "test/requires-all".to_string(),
        desc: "Test requires all".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        for: vec![FileType::All],
        scope: ScopeLevel::None,
        near: None,
        near_lines: None,
        within: None,
        all: Some(vec![
            Condition::Symbol {
                pattern: "socket".to_string(),
                platforms: None,
            },
            Condition::Symbol {
                pattern: "connect".to_string(),
                platforms: None,
            },
        ]),
        any: None,
        count: None,
        any: None,
        none: None,
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_some());
}

#[test]
fn test_composite_requires_any() {
    let (report, data) = create_test_context();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    let rule = CompositeTrait {
        id: "test/requires-any".to_string(),
        desc: "Test requires any".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        for: vec![FileType::All],
        scope: ScopeLevel::None,
        near: None,
        near_lines: None,
        within: None,
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
        any: None,
        none: None,
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_some());
}

#[test]
fn test_composite_requires_none() {
    let (report, data) = create_test_context();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    // Should fail because socket IS present
    let rule = CompositeTrait {
        id: "test/requires-none".to_string(),
        desc: "Test requires none".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        for: vec![FileType::All],
        scope: ScopeLevel::None,
        near: None,
        near_lines: None,
        within: None,
        all: None,
        any: None,
        count: None,
        any: None,
        none: Some(vec![Condition::Symbol {
            pattern: "socket".to_string(),
            platforms: None,
        }]),
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_none());
}

#[test]
fn test_ast_pattern_c() {
    let c_code = r#"
int main() {
    system("ls -la");
    return 0;
}
"#;
    let (report, _) = create_test_context();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: c_code.as_bytes(),
        file_type: FileType::C,
        platform: Platform::Linux,
    };

    let result = eval_ast_pattern("call_expression", "system", false, false, &ctx);
    assert!(result.matched);
}

#[test]
fn test_ast_pattern_python() {
    let python_code = r#"
import os
os.system("whoami")
"#;
    let (report, _) = create_test_context();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: python_code.as_bytes(),
        file_type: FileType::Python,
        platform: Platform::Linux,
    };

    let result = eval_ast_pattern("call", "system", false, false, &ctx);
    assert!(result.matched);
}

#[test]
fn test_trait_definition() {
    let c_code = r#"
int main() {
    system("whoami");
    return 0;
}
"#;
    let (report, _) = create_test_context();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: c_code.as_bytes(),
        file_type: FileType::C,
        platform: Platform::Linux,
    };

    let trait_def = TraitDefinition {
        id: "exec/command/system".to_string(),
        desc: "System command execution".to_string(),
        conf: 0.95,
        crit: Criticality::Suspicious,
        mbc: Some("E1059".to_string()),
        attack: Some("T1059".to_string()),
        platforms: vec![Platform::All],
        for: vec![FileType::C],
        if: Condition::AstPattern {
            node_type: "call_expression".to_string(),
            pattern: "system".to_string(),
            regex: false,
            case_insensitive: false,
        },
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    assert_eq!(finding.id, "exec/command/system");
}

// ============================================================================
// Syscall condition tests
// ============================================================================

fn create_test_context_with_syscalls() -> (AnalysisReport, Vec<u8>) {
    use crate::radare2::SyscallInfo;

    let target = TargetInfo {
        path: "/test/malware.elf".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 4096,
        sha256: "deadbeef".to_string(),
        architectures: Some(vec!["mips".to_string()]),
    };

    let mut report = AnalysisReport::new(target);

    // Add typical malware syscalls
    report.syscalls = vec![
        SyscallInfo {
            address: 0x400100,
            number: 4183,
            name: "socket".to_string(),
            arch: "mips".to_string(),
        },
        SyscallInfo {
            address: 0x400200,
            number: 4170,
            name: "connect".to_string(),
            arch: "mips".to_string(),
        },
        SyscallInfo {
            address: 0x400300,
            number: 4002,
            name: "fork".to_string(),
            arch: "mips".to_string(),
        },
        SyscallInfo {
            address: 0x400400,
            number: 4066,
            name: "setsid".to_string(),
            arch: "mips".to_string(),
        },
        SyscallInfo {
            address: 0x400500,
            number: 4011,
            name: "execve".to_string(),
            arch: "mips".to_string(),
        },
        SyscallInfo {
            address: 0x400600,
            number: 4063,
            name: "dup2".to_string(),
            arch: "mips".to_string(),
        },
    ];

    (report, b"test binary".to_vec())
}

#[test]
fn test_syscall_condition_match_by_name() {
    let (report, data) = create_test_context_with_syscalls();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    let params = SyscallParams {
        name: Some(&vec!["socket".to_string()]),
        number: None,
        arch: None,
        min_count: None,
    };

    let result = eval_syscall(&params, &ctx);
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);
    assert!(result.evidence[0].value.contains("socket"));
}

#[test]
fn test_syscall_condition_match_by_number() {
    let (report, data) = create_test_context_with_syscalls();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    let params = SyscallParams {
        name: None,
        number: Some(&vec![4002]), // fork
        arch: None,
        min_count: None,
    };

    let result = eval_syscall(&params, &ctx);
    assert!(result.matched);
    assert!(result.evidence[0].value.contains("fork"));
}

#[test]
fn test_syscall_condition_match_by_arch() {
    let (report, data) = create_test_context_with_syscalls();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    let params = SyscallParams {
        name: None,
        number: None,
        arch: Some(&vec!["mips".to_string()]),
        min_count: None,
    };

    let result = eval_syscall(&params, &ctx);
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 6); // All 6 syscalls are MIPS
}

#[test]
fn test_syscall_condition_no_match() {
    let (report, data) = create_test_context_with_syscalls();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    let params = SyscallParams {
        name: Some(&vec!["nonexistent_syscall".to_string()]),
        number: None,
        arch: None,
        min_count: None,
    };

    let result = eval_syscall(&params, &ctx);
    assert!(!result.matched);
    assert!(result.evidence.is_empty());
}

#[test]
fn test_syscall_condition_min_count() {
    let (report, data) = create_test_context_with_syscalls();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    // Should pass: we have 6 syscalls
    let params = SyscallParams {
        name: None,
        number: None,
        arch: None,
        min_count: Some(3),
    };
    let result = eval_syscall(&params, &ctx);
    assert!(result.matched);

    // Should fail: we only have 6 syscalls
    let params = SyscallParams {
        name: None,
        number: None,
        arch: None,
        min_count: Some(10),
    };
    let result = eval_syscall(&params, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_syscall_condition_multiple_names() {
    let (report, data) = create_test_context_with_syscalls();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    let params = SyscallParams {
        name: Some(&vec!["socket".to_string(), "connect".to_string()]),
        number: None,
        arch: None,
        min_count: None,
    };

    let result = eval_syscall(&params, &ctx);
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 2); // socket + connect
}

#[test]
fn test_syscall_condition_combined_filters() {
    let (report, data) = create_test_context_with_syscalls();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    // Match by name AND arch
    let params = SyscallParams {
        name: Some(&vec!["execve".to_string()]),
        number: None,
        arch: Some(&vec!["mips".to_string()]),
        min_count: None,
    };

    let result = eval_syscall(&params, &ctx);
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);
}

#[test]
fn test_syscall_condition_empty_syscalls() {
    let (mut report, data) = create_test_context_with_syscalls();
    report.syscalls.clear(); // Empty syscalls

    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    let params = SyscallParams {
        name: Some(&vec!["socket".to_string()]),
        number: None,
        arch: None,
        min_count: None,
    };

    let result = eval_syscall(&params, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_syscall_condition_via_eval_condition() {
    let (report, data) = create_test_context_with_syscalls();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    // Test through the generic eval_condition interface
    let condition = Condition::Syscall {
        name: Some(vec!["fork".to_string(), "setsid".to_string()]),
        number: None,
        arch: None,
        min_count: None,
    };

    let result = eval_condition(&condition, &ctx);
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 2);
}

#[test]
fn test_truncate_evidence_multibyte() {
    let s = "ִ payload";
    // "ִ" is 2 bytes, "" is 3 bytes. Total 5 bytes for first 2 chars.
    let truncated = truncate_evidence(s, 2);
    assert_eq!(truncated, "ִ...");
}

#[test]
fn test_ast_pattern_php() {
    let php_code = r#"<?php system("whoami"); ?>"#;
    let (report, _) = create_test_context();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: php_code.as_bytes(),
        file_type: FileType::Php,
        platform: Platform::Linux,
    };

    let result = eval_ast_pattern("function_call_expression", "system", false, false, &ctx);
    assert!(result.matched);
}

#[test]
fn test_syscall_trait_definition() {
    let (report, data) = create_test_context_with_syscalls();
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &data,
        file_type: FileType::Elf,
        platform: Platform::Linux,
    };

    let trait_def = TraitDefinition {
        id: "syscall/process/daemon".to_string(),
        desc: "Daemon behavior via syscalls".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: Some("T1543".to_string()),
        platforms: vec![Platform::Linux],
        for: vec![FileType::Elf],
        if: Condition::Syscall {
            name: Some(vec!["fork".to_string(), "setsid".to_string()]),
            number: None,
            arch: None,
            min_count: None,
        },
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    assert_eq!(finding.id, "syscall/process/daemon");
    assert_eq!(finding.criticality, Criticality::Suspicious);
}

#[test]
fn test_syscall_condition_deserialization() {
    let yaml = r#"
type: syscall
name:
  - socket
  - connect
arch:
  - mips
  - x86_64
min_count: 2
"#;
    let if: Condition = serde_yaml::from_str(yaml).unwrap();
    match condition {
        Condition::Syscall {
            name,
            number,
            arch,
            min_count,
        } => {
            assert_eq!(name, Some(vec!["socket".to_string(), "connect".to_string()]));
            assert_eq!(number, None);
            assert_eq!(arch, Some(vec!["mips".to_string(), "x86_64".to_string()]));
            assert_eq!(min_count, Some(2));
        }
        _ => panic!("Expected Syscall condition"),
    }
}

#[test]
fn test_syscall_condition_deserialization_minimal() {
    let yaml = r#"
type: syscall
name:
  - execve
"#;
    let if: Condition = serde_yaml::from_str(yaml).unwrap();
    match condition {
        Condition::Syscall {
            name,
            number,
            arch,
            min_count,
        } => {
            assert_eq!(name, Some(vec!["execve".to_string()]));
            assert_eq!(number, None);
            assert_eq!(arch, None);
            assert_eq!(min_count, None);
        }
        _ => panic!("Expected Syscall condition"),
    }
}
