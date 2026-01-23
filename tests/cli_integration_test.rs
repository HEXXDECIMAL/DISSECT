use predicates::prelude::*;

use std::fs;
use tempfile::TempDir;

/// Test that the binary runs and shows help
#[test]

fn test_help_command() {
    assert_cmd::cargo_bin_cmd!("dissect")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Deep static analysis tool"));
}

/// Test that the binary shows version
#[test]

fn test_version_command() {
    assert_cmd::cargo_bin_cmd!("dissect")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("dissect"));
}

/// Test analyze command with nonexistent file
#[test]

fn test_analyze_nonexistent_file() {
    assert_cmd::cargo_bin_cmd!("dissect")
        .args(["analyze", "/nonexistent/file.bin"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

/// Test analyze command with a simple shell script
#[test]

fn test_analyze_shell_script() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.sh");

    fs::write(&script_path, "#!/bin/bash\necho 'hello'\n").unwrap();

    assert_cmd::cargo_bin_cmd!("dissect")
        .args(["analyze", script_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("test.sh"));
}

/// Test analyze command with JSON output
#[test]

fn test_analyze_json_output() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.sh");

    fs::write(&script_path, "#!/bin/bash\necho 'hello'\n").unwrap();

    assert_cmd::cargo_bin_cmd!("dissect")
        .args(["-f", "json", "analyze", script_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("schema_version"));
}

/// Test analyze command with output to file
#[test]

fn test_analyze_output_to_file() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.sh");
    let output_path = temp_dir.path().join("output.json");

    fs::write(&script_path, "#!/bin/bash\necho 'hello'\n").unwrap();

    assert_cmd::cargo_bin_cmd!("dissect")
        .args([
            "-f",
            "json",
            "-o",
            output_path.to_str().unwrap(),
            "analyze",
            script_path.to_str().unwrap(),
            // Third-party YARA is disabled by default (opt-in with --third-party-yara)
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Results written to"));

    // Verify output file was created and contains JSON
    let content = fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("schema_version"));
}

/// Test scan command with empty directory
#[test]

fn test_scan_empty_directory() {
    let temp_dir = TempDir::new().unwrap();

    assert_cmd::cargo_bin_cmd!("dissect")
        .args(["scan", temp_dir.path().to_str().unwrap()])
        .assert()
        .success();
}

/// Test scan command with multiple files
#[test]

fn test_scan_multiple_files() {
    let temp_dir = TempDir::new().unwrap();
    let script1 = temp_dir.path().join("test1.sh");
    let script2 = temp_dir.path().join("test2.sh");

    fs::write(&script1, "#!/bin/bash\necho 'test1'\n").unwrap();
    fs::write(&script2, "#!/bin/bash\necho 'test2'\n").unwrap();

    assert_cmd::cargo_bin_cmd!("dissect")
        .args(["scan", temp_dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("test1.sh"))
        .stdout(predicate::str::contains("test2.sh"));
}

/// Test diff command with nonexistent files
#[test]

fn test_diff_nonexistent_files() {
    assert_cmd::cargo_bin_cmd!("dissect")
        .args(["diff", "/nonexistent/old.bin", "/nonexistent/new.bin"])
        .assert()
        .failure();
}

/// Test diff command with identical files
#[test]

fn test_diff_identical_files() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("file1.sh");
    let file2 = temp_dir.path().join("file2.sh");

    let content = "#!/bin/bash\necho 'hello'\n";
    fs::write(&file1, content).unwrap();
    fs::write(&file2, content).unwrap();

    assert_cmd::cargo_bin_cmd!("dissect")
        .args(["diff", file1.to_str().unwrap(), file2.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("No capability changes"));
}

/// Test diff command with different files
#[test]

fn test_diff_different_files() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("old.sh");
    let file2 = temp_dir.path().join("new.sh");

    fs::write(&file1, "#!/bin/bash\necho 'old'\n").unwrap();
    fs::write(&file2, "#!/bin/bash\neval 'malicious'\n").unwrap();

    assert_cmd::cargo_bin_cmd!("dissect")
        .args(["diff", file1.to_str().unwrap(), file2.to_str().unwrap()])
        .assert()
        .success();
}

/// Test that missing subcommand fails
#[test]

fn test_missing_subcommand() {
    assert_cmd::cargo_bin_cmd!("dissect")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

/// Test invalid format argument
#[test]

fn test_invalid_format() {
    let temp_dir = TempDir::new().unwrap();
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\n").unwrap();

    assert_cmd::cargo_bin_cmd!("dissect")
        .args(["-f", "xml", "analyze", script.to_str().unwrap()])
        .assert()
        .failure();
}

/// Test verbose flag
#[test]

fn test_verbose_flag() {
    let temp_dir = TempDir::new().unwrap();
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\n").unwrap();

    assert_cmd::cargo_bin_cmd!("dissect")
        .args(["-v", "analyze", script.to_str().unwrap()])
        .assert()
        .success();
}

/// Test analyze with Python file
#[test]

fn test_analyze_python_file() {
    let temp_dir = TempDir::new().unwrap();
    let py_file = temp_dir.path().join("test.py");

    fs::write(&py_file, "print('hello')\n").unwrap();

    assert_cmd::cargo_bin_cmd!("dissect")
        .args(["analyze", py_file.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("test.py"));
}

/// Test analyze with JavaScript file
#[test]

fn test_analyze_javascript_file() {
    let temp_dir = TempDir::new().unwrap();
    let js_file = temp_dir.path().join("test.js");

    fs::write(&js_file, "console.log('hello');\n").unwrap();

    assert_cmd::cargo_bin_cmd!("dissect")
        .args(["analyze", js_file.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("test.js"));
}

/// Test scan with JSON output format
#[test]

fn test_scan_json_output() {
    let temp_dir = TempDir::new().unwrap();
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\n").unwrap();

    assert_cmd::cargo_bin_cmd!("dissect")
        .args(["-f", "json", "scan", temp_dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("["));
}

/// Test that --yara flag enables YARA (deprecated feature, disabled by default)
/// Ignored by default: YARA rules are slow to compile in debug builds
/// Run with: cargo test --release test_yara_flag -- --ignored
#[test]
#[ignore]
fn test_yara_flag() {
    let temp_dir = TempDir::new().unwrap();
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\n").unwrap();

    assert_cmd::cargo_bin_cmd!("dissect")
        .args(["analyze", script.to_str().unwrap(), "--yara"])
        .assert()
        .success();
}

/// Test that --third-party-yara enables third-party YARA rules
/// Ignored by default: YARA rules are slow to compile in debug builds
/// Run with: cargo test --release test_yara_third_party_flag -- --ignored
#[test]
#[ignore]
fn test_yara_third_party_flag() {
    let temp_dir = TempDir::new().unwrap();
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\n").unwrap();

    // Third-party YARA is opt-in (disabled by default)
    // This test verifies the --third-party-yara flag enables it
    assert_cmd::cargo_bin_cmd!("dissect")
        .args(["analyze", script.to_str().unwrap(), "--third-party-yara"])
        .assert()
        .success();
}
