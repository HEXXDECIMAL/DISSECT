use std::fs;
use std::process::Command;

// Note: These tests run cargo commands which can cause file lock contention
// Run with: cargo test --test directory_scan_test -- --test-threads=1

#[test]
fn test_analyze_command_handles_directory() {
    // Create test directory with files
    let test_dir = "/tmp/dissect-test-analyze-dir";
    let _ = fs::remove_dir_all(test_dir);
    fs::create_dir_all(format!("{}/subdir", test_dir)).unwrap();

    // Create test files
    fs::write(
        format!("{}/test1.sh", test_dir),
        "#!/bin/bash\necho 'test1'",
    )
    .unwrap();

    fs::write(
        format!("{}/subdir/test2.sh", test_dir),
        "#!/bin/bash\necho 'test2'",
    )
    .unwrap();

    // Run analyze command on directory
    let output = Command::new("cargo")
        .args(&["run", "--", "--format", "json", "analyze", test_dir])
        .output()
        .expect("Failed to execute command");

    // Should succeed (not return "Is a directory" error)
    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Should contain JSON output with multiple files
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("test1.sh") || stdout.contains("test2.sh"),
        "Output should contain scanned files"
    );

    // Cleanup
    let _ = fs::remove_dir_all(test_dir);
}

#[test]
fn test_analyze_command_handles_single_file() {
    // Create test file
    let test_file = "/tmp/dissect-test-single-file.sh";
    fs::write(test_file, "#!/bin/bash\necho 'hello'").unwrap();

    // Run analyze command on single file
    let output = Command::new("cargo")
        .args(&["run", "--", "--format", "json", "analyze", test_file])
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(test_file),
        "Output should contain file path"
    );

    // Cleanup
    let _ = fs::remove_file(test_file);
}

#[test]
fn test_scan_command_handles_multiple_paths() {
    // Create test directories
    let test_dir1 = "/tmp/dissect-test-scan-dir1";
    let test_dir2 = "/tmp/dissect-test-scan-dir2";
    let _ = fs::remove_dir_all(test_dir1);
    let _ = fs::remove_dir_all(test_dir2);
    fs::create_dir_all(test_dir1).unwrap();
    fs::create_dir_all(test_dir2).unwrap();

    fs::write(format!("{}/file1.sh", test_dir1), "#!/bin/bash\necho '1'").unwrap();
    fs::write(format!("{}/file2.sh", test_dir2), "#!/bin/bash\necho '2'").unwrap();

    // Run scan command on multiple directories
    let output = Command::new("cargo")
        .args(&[
            "run", "--", "--format", "json", "scan", test_dir1, test_dir2,
        ])
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Cleanup
    let _ = fs::remove_dir_all(test_dir1);
    let _ = fs::remove_dir_all(test_dir2);
}

#[test]
fn test_analyze_empty_directory() {
    // Create empty test directory
    let test_dir = "/tmp/dissect-test-empty-dir";
    let _ = fs::remove_dir_all(test_dir);
    fs::create_dir_all(test_dir).unwrap();

    // Run analyze command on empty directory
    let output = Command::new("cargo")
        .args(&["run", "--", "--format", "json", "analyze", test_dir])
        .output()
        .expect("Failed to execute command");

    // Should succeed even with no files
    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Cleanup
    let _ = fs::remove_dir_all(test_dir);
}

#[test]
fn test_analyze_directory_with_archive() {
    use std::io::Write;

    // Create test directory with an archive
    let test_dir = "/tmp/dissect-test-archive-dir";
    let _ = fs::remove_dir_all(test_dir);
    fs::create_dir_all(test_dir).unwrap();

    // Create a simple tar.gz archive
    let archive_path = format!("{}/test.tar.gz", test_dir);
    let file = fs::File::create(&archive_path).unwrap();
    let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut tar = tar::Builder::new(enc);

    // Add a file to the archive
    let mut header = tar::Header::new_gnu();
    header.set_path("test.sh").unwrap();
    header.set_size(19);
    header.set_cksum();
    tar.append(&header, b"#!/bin/bash\necho 'x'".as_ref())
        .unwrap();
    tar.finish().unwrap();

    // Run analyze command on directory containing archive
    let output = Command::new("cargo")
        .args(&["run", "--", "--format", "json", "analyze", test_dir])
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Should detect and analyze the archive
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("archive") || stderr.contains("Archive"),
        "Should mention archive processing"
    );

    // Cleanup
    let _ = fs::remove_dir_all(test_dir);
}

#[test]
fn test_analyze_nonexistent_path() {
    // Try to analyze a path that doesn't exist
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--",
            "analyze",
            "/tmp/dissect-nonexistent-path-12345",
        ])
        .output()
        .expect("Failed to execute command");

    // Should fail with appropriate error message
    assert!(!output.status.success(), "Should fail for nonexistent path");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not exist") || stderr.contains("not found"),
        "Error message should mention nonexistent path"
    );
}

#[test]
fn test_analyze_symlink_handling() {
    use std::os::unix::fs::symlink;

    // Create test file and symlink
    let test_file = "/tmp/dissect-test-symlink-target.sh";
    let test_link = "/tmp/dissect-test-symlink.sh";

    fs::write(test_file, "#!/bin/bash\necho 'target'").unwrap();
    let _ = fs::remove_file(test_link); // Remove if exists
    symlink(test_file, test_link).unwrap();

    // Analyze the symlink - should work but not follow into infinite loops
    let output = Command::new("cargo")
        .args(&["run", "--", "--format", "json", "analyze", test_link])
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Cleanup
    let _ = fs::remove_file(test_file);
    let _ = fs::remove_file(test_link);
}

#[test]
fn test_recursive_depth() {
    // Create deeply nested directory structure
    let test_dir = "/tmp/dissect-test-deep";
    let _ = fs::remove_dir_all(test_dir);

    // Create 5 levels deep
    let deep_path = format!("{}/a/b/c/d/e", test_dir);
    fs::create_dir_all(&deep_path).unwrap();
    fs::write(format!("{}/deep.sh", deep_path), "#!/bin/bash\necho 'deep'").unwrap();

    // Run analyze command
    let output = Command::new("cargo")
        .args(&["run", "--", "--format", "json", "analyze", test_dir])
        .output()
        .expect("Failed to execute command");

    assert!(
        output.status.success(),
        "Command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Should find the deeply nested file
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("deep.sh"), "Should find deeply nested file");

    // Cleanup
    let _ = fs::remove_dir_all(test_dir);
}
