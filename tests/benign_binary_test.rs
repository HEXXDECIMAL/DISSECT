/// Integration test for analyzing benign system binaries.
///
/// Ensures that legitimate system binaries like /bin/ls are correctly
/// classified as inert/notable without false positive hostile/suspicious findings.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::time::Duration;

#[test]
fn test_analyze_bin_ls_json_output() {
    let mut cmd = Command::cargo_bin("dissect").unwrap();

    let output = cmd
        .args(["--json", "/bin/ls"])
        .timeout(Duration::from_secs(10))
        .output()
        .expect("Failed to execute dissect");

    // Should succeed
    assert!(
        output.status.success(),
        "dissect should successfully analyze /bin/ls"
    );

    // Parse JSON output from stdout
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Filter out any stderr content (warnings appear before JSON)
    let json_start = stdout.find('[').expect("Should find JSON array start");
    let json_output = &stdout[json_start..];

    let parsed: Value = serde_json::from_str(json_output)
        .expect("Output should be valid JSON");

    // Should be an array with at least one report
    let reports = parsed.as_array().expect("Output should be JSON array");
    assert!(!reports.is_empty(), "Should have at least one analysis report");

    let report = &reports[0];
    let findings = report["findings"]
        .as_array()
        .expect("Report should have findings array");

    // Verify all findings are only inert or notable (no hostile/suspicious)
    let mut hostile_count = 0;
    let mut suspicious_count = 0;
    let mut notable_count = 0;
    let mut inert_count = 0;

    for finding in findings {
        let crit = finding["crit"]
            .as_str()
            .expect("Finding should have criticality");

        match crit {
            "hostile" => hostile_count += 1,
            "suspicious" => suspicious_count += 1,
            "notable" => notable_count += 1,
            "inert" => inert_count += 1,
            _ => panic!("Unknown criticality: {}", crit),
        }
    }

    // /bin/ls is a legitimate binary - should have no hostile/suspicious findings
    assert_eq!(
        hostile_count, 0,
        "/bin/ls should not have hostile findings (found {})",
        hostile_count
    );
    assert_eq!(
        suspicious_count, 0,
        "/bin/ls should not have suspicious findings (found {})",
        suspicious_count
    );

    // Should have some notable and inert findings
    assert!(
        notable_count > 0 || inert_count > 0,
        "Should have at least some notable or inert findings (notable={}, inert={})",
        notable_count,
        inert_count
    );

    println!(
        "✅ /bin/ls analysis: {} inert, {} notable, 0 suspicious, 0 hostile",
        inert_count, notable_count
    );
}

#[test]
fn test_analyze_bin_ls_completes_quickly() {
    let mut cmd = Command::cargo_bin("dissect").unwrap();

    let start = std::time::Instant::now();

    let output = cmd
        .args(["--json", "/bin/ls"])
        .timeout(Duration::from_secs(10))
        .output()
        .expect("Failed to execute dissect");

    let elapsed = start.elapsed();

    assert!(
        output.status.success(),
        "dissect should successfully analyze /bin/ls"
    );

    assert!(
        elapsed < Duration::from_secs(10),
        "Analysis should complete within 10 seconds (took {:?})",
        elapsed
    );

    println!("✅ /bin/ls analyzed in {:?}", elapsed);
}
