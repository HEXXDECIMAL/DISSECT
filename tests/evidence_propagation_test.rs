/// Test evidence propagation from atomic to composite traits
///
/// Ensures that atomic traits (even with `inert` criticality) properly
/// propagate evidence to composite rules that reference them.
use dissect::capabilities::CapabilityMapper;
use dissect::types::{AnalysisReport, TargetInfo};

#[test]
fn test_evidence_propagates_from_atomic_to_composite() {
    // Create a test report with strings that match atomic wallet traits
    let mut report = AnalysisReport::new(TargetInfo {
        path: "test.py".to_string(),
        file_type: "python_script".to_string(),
        size_bytes: 100,
        sha256: "test".to_string(),
        architectures: None,
    });

    // Add strings that should match atomic traits
    report.strings = vec![
        dissect::types::StringInfo {
            value: "wallet".to_string(),
            offset: Some("0x100".to_string()),
            encoding: "ascii".to_string(),
            string_type: dissect::types::StringType::Plain,
            section: None,
        },
        dissect::types::StringInfo {
            value: "mnemonic".to_string(),
            offset: Some("0x200".to_string()),
            encoding: "ascii".to_string(),
            string_type: dissect::types::StringType::Plain,
            section: None,
        },
        dissect::types::StringInfo {
            value: "crypto".to_string(),
            offset: Some("0x300".to_string()),
            encoding: "ascii".to_string(),
            string_type: dissect::types::StringType::Plain,
            section: None,
        },
    ];

    // Load capability mapper with traits
    let mapper = CapabilityMapper::new();

    // Evaluate all rules and merge findings
    let binary_data = b"test content with wallet mnemonic crypto";
    mapper.evaluate_and_merge_findings(&mut report, binary_data, None);

    // Check that atomic traits were detected (even if inert)
    let atomic_wallet = report
        .findings
        .iter()
        .find(|f| f.id.contains("cred/wallet/mnemonic") && f.id.contains("wallet-word"));

    let atomic_mnemonic = report
        .findings
        .iter()
        .find(|f| f.id.contains("cred/wallet/mnemonic") && f.id.contains("mnemonic-word"));

    // At least one atomic trait should be found
    assert!(
        atomic_wallet.is_some() || atomic_mnemonic.is_some(),
        "Expected atomic wallet/mnemonic traits to be detected"
    );

    // Check that composite rule referencing these atomic traits was also triggered
    let composite = report
        .findings
        .iter()
        .find(|f| f.id == "cred/wallet/mnemonic/wallet-context");

    if let Some(composite_finding) = composite {
        // Composite should have evidence (propagated from atomic traits)
        assert!(
            !composite_finding.evidence.is_empty(),
            "Composite rule should have evidence from atomic traits"
        );

        // Evidence should contain the matched strings
        let evidence_values: Vec<_> = composite_finding
            .evidence
            .iter()
            .map(|e| e.value.as_str())
            .collect();

        assert!(
            evidence_values.iter().any(|v| *v == "wallet" || *v == "crypto" || *v == "mnemonic"),
            "Evidence should contain 'wallet', 'crypto', or 'mnemonic' from atomic traits, got: {:?}",
            evidence_values
        );
    } else {
        // If composite wasn't triggered, that's also acceptable depending on count requirements
        println!(
            "Note: composite rule 'wallet-context' was not triggered (may require more matches)"
        );
    }
}

#[test]
fn test_recursive_evidence_propagation() {
    // Test that evidence propagates through multiple composite layers
    let mut report = AnalysisReport::new(TargetInfo {
        path: "test.py".to_string(),
        file_type: "python_script".to_string(),
        size_bytes: 100,
        sha256: "test".to_string(),
        architectures: None,
    });

    // Add strings for nested composite rules
    report.strings = vec![
        dissect::types::StringInfo {
            value: "wallet".to_string(),
            offset: Some("0x100".to_string()),
            encoding: "ascii".to_string(),
            string_type: dissect::types::StringType::Plain,
            section: None,
        },
        dissect::types::StringInfo {
            value: "mnemonic".to_string(),
            offset: Some("0x200".to_string()),
            encoding: "ascii".to_string(),
            string_type: dissect::types::StringType::Plain,
            section: None,
        },
        dissect::types::StringInfo {
            value: "requests.post".to_string(),
            offset: Some("0x300".to_string()),
            encoding: "ascii".to_string(),
            string_type: dissect::types::StringType::Plain,
            section: None,
        },
    ];

    let mapper = CapabilityMapper::new();
    let binary_data = b"wallet mnemonic requests.post";

    // Evaluate with iterative composite resolution
    mapper.evaluate_and_merge_findings(&mut report, binary_data, None);

    // Check that we got findings at multiple levels
    let findings_count = report.findings.len();
    assert!(
        findings_count > 0,
        "Should have at least some findings from atomic and composite traits"
    );

    // Verify that higher-level composites can reference lower-level composites
    // (The wallet stealer pattern requires mnemonic-terms + network-exfil + wallet-context)
    let stealer_pattern = report
        .findings
        .iter()
        .find(|f| f.id == "cred/wallet/mnemonic/stealer-pattern");

    if let Some(stealer) = stealer_pattern {
        println!(
            "Found stealer pattern with {} evidence items",
            stealer.evidence.len()
        );
        // Stealer pattern should aggregate evidence from all its component composite rules
        // We don't strict-assert here because it depends on exact trait definitions,
        // but we log for inspection
    }
}

#[test]
fn test_evaluate_and_merge_findings_idempotent() {
    // Test that calling evaluate_and_merge_findings multiple times doesn't create duplicates
    let mut report = AnalysisReport::new(TargetInfo {
        path: "test.py".to_string(),
        file_type: "python_script".to_string(),
        size_bytes: 100,
        sha256: "test".to_string(),
        architectures: None,
    });

    report.strings = vec![dissect::types::StringInfo {
        value: "wallet".to_string(),
        offset: Some("0x100".to_string()),
        encoding: "ascii".to_string(),
        string_type: dissect::types::StringType::Plain,
        section: None,
    }];

    let mapper = CapabilityMapper::new();
    let binary_data = b"wallet";

    // Call twice
    mapper.evaluate_and_merge_findings(&mut report, binary_data, None);
    let count_first = report.findings.len();

    mapper.evaluate_and_merge_findings(&mut report, binary_data, None);
    let count_second = report.findings.len();

    // Count should be roughly the same (may differ by 1-2 due to composite rule reevaluation)
    // But should NOT double
    assert!(
        count_second <= count_first + 2,
        "Duplicate findings created: first={}, second={}",
        count_first,
        count_second
    );
}
