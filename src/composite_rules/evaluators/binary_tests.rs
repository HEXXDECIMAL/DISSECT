//! Tests for binary analysis condition evaluators.

use super::*;
use crate::composite_rules::context::EvaluationContext;
use crate::composite_rules::types::{FileType, Platform};
use crate::radare2::SyscallInfo;
use crate::types::{AnalysisReport, Export, Import, Section, TargetInfo};

fn create_test_report() -> AnalysisReport {
    let target = TargetInfo {
        path: "/test/binary".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 1024,
        sha256: "abc123".to_string(),
        architectures: Some(vec!["x86_64".to_string()]),
    };
    AnalysisReport::new(target)
}

fn create_test_context<'a>(report: &'a AnalysisReport, data: &'a [u8]) -> EvaluationContext<'a> {
    EvaluationContext {
        report,
        binary_data: data,
        file_type: FileType::Elf,
        platforms: vec![Platform::Linux],
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
        debug_collector: None,
        section_map: None,
    }
}

// =============================================================================
// eval_imports_count tests
// =============================================================================

#[test]
fn test_eval_imports_count_min() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "socket".to_string(),
        library: None,
        source: "libc".to_string(),
    });
    report.imports.push(Import {
        symbol: "connect".to_string(),
        library: None,
        source: "libc".to_string(),
    });
    report.imports.push(Import {
        symbol: "send".to_string(),
        library: None,
        source: "libc".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_imports_count(Some(2), None, None, &ctx);
    assert!(result.matched);

    let result = eval_imports_count(Some(5), None, None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_imports_count_max() {
    let mut report = create_test_report();
    for i in 0..10 {
        report.imports.push(Import {
            symbol: format!("func_{}", i),
            library: None,
            source: "lib".to_string(),
        });
    }
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_imports_count(None, Some(15), None, &ctx);
    assert!(result.matched);

    let result = eval_imports_count(None, Some(5), None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_imports_count_range() {
    let mut report = create_test_report();
    for i in 0..10 {
        report.imports.push(Import {
            symbol: format!("func_{}", i),
            library: None,
            source: "lib".to_string(),
        });
    }
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_imports_count(Some(5), Some(15), None, &ctx);
    assert!(result.matched);

    let result = eval_imports_count(Some(15), Some(20), None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_imports_count_with_filter() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "CreateFile".to_string(),
        library: Some("kernel32.dll".to_string()),
        source: "pe".to_string(),
    });
    report.imports.push(Import {
        symbol: "CreateProcess".to_string(),
        library: Some("kernel32.dll".to_string()),
        source: "pe".to_string(),
    });
    report.imports.push(Import {
        symbol: "VirtualAlloc".to_string(),
        library: Some("kernel32.dll".to_string()),
        source: "pe".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Filter for "Create" imports
    let result = eval_imports_count(Some(2), None, Some(&"Create".to_string()), &ctx);
    assert!(result.matched);

    // Filter for something that doesn't exist enough
    let result = eval_imports_count(Some(2), None, Some(&"Virtual".to_string()), &ctx);
    assert!(!result.matched); // Only 1 Virtual import
}

#[test]
fn test_eval_imports_count_evidence() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "socket".to_string(),
        library: None,
        source: "libc".to_string(),
    });
    report.imports.push(Import {
        symbol: "connect".to_string(),
        library: None,
        source: "libc".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_imports_count(Some(1), None, None, &ctx);
    assert!(result.matched);
    assert!(!result.evidence.is_empty());
    assert!(result.evidence[0].value.contains("(2)")); // Count in evidence
}

// =============================================================================
// eval_exports_count tests
// =============================================================================

#[test]
fn test_eval_exports_count_min() {
    let mut report = create_test_report();
    report.exports.push(Export {
        symbol: "init".to_string(),
        offset: Some("0x1000".to_string()),
        source: "elf".to_string(),
    });
    report.exports.push(Export {
        symbol: "main".to_string(),
        offset: Some("0x2000".to_string()),
        source: "elf".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_exports_count(Some(1), None, &ctx);
    assert!(result.matched);

    let result = eval_exports_count(Some(5), None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_exports_count_max() {
    let mut report = create_test_report();
    for i in 0..3 {
        report.exports.push(Export {
            symbol: format!("export_{}", i),
            offset: Some(format!("0x{:x}", i * 0x1000)),
            source: "elf".to_string(),
        });
    }
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_exports_count(None, Some(5), &ctx);
    assert!(result.matched);

    let result = eval_exports_count(None, Some(2), &ctx);
    assert!(!result.matched);
}

// =============================================================================
// eval_section_ratio tests
// =============================================================================

#[test]
fn test_eval_section_ratio_vs_total() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        size: 500,
        entropy: 6.5,
        permissions: Some("rx".to_string()),
    });
    report.sections.push(Section {
        name: ".data".to_string(),
        size: 300,
        entropy: 4.0,
        permissions: Some("rw".to_string()),
    });
    report.sections.push(Section {
        name: ".rodata".to_string(),
        size: 200,
        entropy: 5.0,
        permissions: Some("r".to_string()),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // .text is 500/1000 = 50% of total
    let result = eval_section_ratio(
        r"\.text",
        "total",
        Some(0.4), // min 40%
        Some(0.6), // max 60%
        &ctx,
    );
    assert!(result.matched);
    assert!(result.evidence[0].value.contains("50.0%"));
}

#[test]
fn test_eval_section_ratio_vs_another_section() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        size: 1000,
        entropy: 6.5,
        permissions: Some("rx".to_string()),
    });
    report.sections.push(Section {
        name: ".data".to_string(),
        size: 500,
        entropy: 4.0,
        permissions: Some("rw".to_string()),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // .text is 1000/500 = 2.0x .data
    let result = eval_section_ratio(r"\.text", r"\.data", Some(1.5), Some(2.5), &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_section_ratio_no_matching_section() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        size: 1000,
        entropy: 6.5,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_section_ratio(r"\.nonexistent", "total", Some(0.1), None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_section_ratio_invalid_regex() {
    let report = create_test_report();
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_section_ratio("[invalid regex", "total", Some(0.1), None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_section_ratio_multiple_matching_sections() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        size: 400,
        entropy: 6.5,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".text2".to_string(),
        size: 100,
        entropy: 6.0,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".data".to_string(),
        size: 500,
        entropy: 4.0,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // .text + .text2 = 500 / 1000 = 50%
    let result = eval_section_ratio(
        r"\.text", // Matches both .text and .text2
        "total",
        Some(0.4),
        Some(0.6),
        &ctx,
    );
    assert!(result.matched);
}

// =============================================================================
// eval_section_entropy tests
// =============================================================================

#[test]
fn test_eval_section_entropy_min() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        size: 1000,
        entropy: 7.5, // High entropy (compressed/encrypted)
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_section_entropy(
        r"\.text",
        Some(7.0), // min entropy
        None,
        &ctx,
    );
    assert!(result.matched);
}

#[test]
fn test_eval_section_entropy_max() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".data".to_string(),
        size: 1000,
        entropy: 3.5, // Low entropy
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_section_entropy(
        r"\.data",
        None,
        Some(4.0), // max entropy
        &ctx,
    );
    assert!(result.matched);
}

#[test]
fn test_eval_section_entropy_range() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        size: 1000,
        entropy: 6.5,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Normal code entropy range
    let result = eval_section_entropy(r"\.text", Some(5.0), Some(7.0), &ctx);
    assert!(result.matched);

    // Outside range
    let result = eval_section_entropy(r"\.text", Some(7.0), Some(8.0), &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_section_entropy_multiple_sections() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: "UPX0".to_string(),
        size: 1000,
        entropy: 7.9,
        permissions: None,
    });
    report.sections.push(Section {
        name: "UPX1".to_string(),
        size: 500,
        entropy: 7.8,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Both UPX sections have high entropy
    let result = eval_section_entropy(r"^UPX", Some(7.5), None, &ctx);
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 2);
}

#[test]
fn test_eval_section_entropy_evidence() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        size: 1000,
        entropy: 6.5,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_section_entropy(r"\.text", Some(6.0), None, &ctx);
    assert!(result.matched);
    assert!(result.evidence[0].value.contains("entropy"));
    assert!(result.evidence[0].value.contains("6.5"));
}

// =============================================================================
// eval_section_name tests
// =============================================================================

#[test]
fn test_eval_section_name_regex() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: "UPX0".to_string(),
        size: 1000,
        entropy: 7.5,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_section_name(r"^UPX", true, &ctx);
    assert!(result.matched);
    assert_eq!(result.evidence[0].value, "UPX0");
}

#[test]
fn test_eval_section_name_contains() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".packed_data".to_string(),
        size: 1000,
        entropy: 7.5,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_section_name("packed", false, &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_section_name_no_match() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        size: 1000,
        entropy: 6.5,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_section_name("UPX", false, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_section_name_multiple_matches() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        size: 500,
        entropy: 6.5,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".text.plt".to_string(),
        size: 100,
        entropy: 6.0,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_section_name(".text", false, &ctx);
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 2);
}

// =============================================================================
// eval_import_combination tests
// =============================================================================

#[test]
fn test_eval_import_combination_required_only() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "VirtualAlloc".to_string(),
        library: Some("kernel32.dll".to_string()),
        source: "pe".to_string(),
    });
    report.imports.push(Import {
        symbol: "WriteProcessMemory".to_string(),
        library: Some("kernel32.dll".to_string()),
        source: "pe".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let required = vec!["VirtualAlloc".to_string(), "WriteProcessMemory".to_string()];

    let result = eval_import_combination(Some(&required), None, None, None, &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_import_combination_required_missing() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "VirtualAlloc".to_string(),
        library: Some("kernel32.dll".to_string()),
        source: "pe".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let required = vec![
        "VirtualAlloc".to_string(),
        "WriteProcessMemory".to_string(), // Missing!
    ];

    let result = eval_import_combination(Some(&required), None, None, None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_import_combination_suspicious() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "VirtualAlloc".to_string(),
        library: Some("kernel32.dll".to_string()),
        source: "pe".to_string(),
    });
    report.imports.push(Import {
        symbol: "CreateRemoteThread".to_string(),
        library: Some("kernel32.dll".to_string()),
        source: "pe".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let required = vec!["VirtualAlloc".to_string()];
    let suspicious = vec![
        "CreateRemoteThread".to_string(),
        "NtUnmapViewOfSection".to_string(),
    ];

    let result = eval_import_combination(
        Some(&required),
        Some(&suspicious),
        Some(1), // At least 1 suspicious
        None,
        &ctx,
    );
    assert!(result.matched);
}

#[test]
fn test_eval_import_combination_min_suspicious() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "VirtualAlloc".to_string(),
        library: None,
        source: "pe".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let required = vec!["VirtualAlloc".to_string()];
    let suspicious = vec![
        "CreateRemoteThread".to_string(),
        "NtUnmapViewOfSection".to_string(),
    ];

    // Require 1 suspicious but have 0
    let result = eval_import_combination(Some(&required), Some(&suspicious), Some(1), None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_import_combination_max_total() {
    let mut report = create_test_report();
    for i in 0..20 {
        report.imports.push(Import {
            symbol: format!("func_{}", i),
            library: None,
            source: "lib".to_string(),
        });
    }
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Max 10 imports but we have 20
    let result = eval_import_combination(None, None, None, Some(10), &ctx);
    assert!(!result.matched);

    // Max 30 imports
    let result = eval_import_combination(None, None, None, Some(30), &ctx);
    assert!(result.matched);
}

// =============================================================================
// eval_syscall tests
// =============================================================================

#[test]
fn test_eval_syscall_by_name() {
    let mut report = create_test_report();
    report.syscalls.push(SyscallInfo {
        name: "execve".to_string(),
        number: 59,
        address: 0x1000,
        desc: "Execute program".to_string(),
        arch: "x86_64".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_syscall(Some(&vec!["execve".to_string()]), None, None, None, &ctx);
    assert!(result.matched);
    assert!(result.evidence[0].value.contains("execve"));
}

#[test]
fn test_eval_syscall_by_number() {
    let mut report = create_test_report();
    report.syscalls.push(SyscallInfo {
        name: "socket".to_string(),
        number: 41,
        address: 0x2000,
        desc: "Create socket".to_string(),
        arch: "x86_64".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_syscall(None, Some(&vec![41]), None, None, &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_syscall_by_arch() {
    let mut report = create_test_report();
    report.syscalls.push(SyscallInfo {
        name: "exit".to_string(),
        number: 60,
        address: 0x3000,
        desc: "Exit process".to_string(),
        arch: "x86_64".to_string(),
    });
    report.syscalls.push(SyscallInfo {
        name: "exit".to_string(),
        number: 1,
        address: 0x4000,
        desc: "Exit process".to_string(),
        arch: "aarch64".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_syscall(
        Some(&vec!["exit".to_string()]),
        None,
        Some(&vec!["x86_64".to_string()]),
        None,
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1); // Only x86_64 match
}

#[test]
fn test_eval_syscall_min_count() {
    let mut report = create_test_report();
    report.syscalls.push(SyscallInfo {
        name: "read".to_string(),
        number: 0,
        address: 0x1000,
        desc: "Read from file".to_string(),
        arch: "x86_64".to_string(),
    });
    report.syscalls.push(SyscallInfo {
        name: "read".to_string(),
        number: 0,
        address: 0x2000,
        desc: "Read from file".to_string(),
        arch: "x86_64".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_syscall(
        Some(&vec!["read".to_string()]),
        None,
        None,
        Some(2), // Require 2 occurrences
        &ctx,
    );
    assert!(result.matched);

    let result = eval_syscall(
        Some(&vec!["read".to_string()]),
        None,
        None,
        Some(5), // Require 5 occurrences
        &ctx,
    );
    assert!(!result.matched);
}

#[test]
fn test_eval_syscall_no_match() {
    let mut report = create_test_report();
    report.syscalls.push(SyscallInfo {
        name: "read".to_string(),
        number: 0,
        address: 0x1000,
        desc: "Read from file".to_string(),
        arch: "x86_64".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_syscall(Some(&vec!["ptrace".to_string()]), None, None, None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_syscall_combined_filters() {
    let mut report = create_test_report();
    report.syscalls.push(SyscallInfo {
        name: "socket".to_string(),
        number: 41,
        address: 0x1000,
        desc: "Create socket".to_string(),
        arch: "x86_64".to_string(),
    });
    report.syscalls.push(SyscallInfo {
        name: "socket".to_string(),
        number: 198, // Different syscall number on aarch64
        address: 0x2000,
        desc: "Create socket".to_string(),
        arch: "aarch64".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Match socket syscall #41 on x86_64
    let result = eval_syscall(
        Some(&vec!["socket".to_string()]),
        Some(&vec![41]),
        Some(&vec!["x86_64".to_string()]),
        None,
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);
}
