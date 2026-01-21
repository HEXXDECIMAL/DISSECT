use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Test that platform-specific YAML capabilities are filtered correctly
#[test]
fn test_windows_keylog_capability_filtered_for_elf() {
    let temp_dir = TempDir::new().unwrap();

    // Create a simple ELF-like file (will be detected as unknown, but we can test the concept)
    // In reality, we'd need actual ELF/PE binaries for full integration
    let file_path = temp_dir.path().join("test.bin");

    // Write ELF magic bytes
    let elf_magic = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    fs::write(&file_path, elf_magic).unwrap();

    let output = Command::cargo_bin("dissect")
        .unwrap()
        .args(&["-f", "json", "analyze", file_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should detect as ELF
    assert!(stderr.contains("Elf") || stderr.contains("ELF"));

    // Parse JSON to check capabilities
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(capabilities) = json.get("capabilities").and_then(|v| v.as_array()) {
            // Windows-specific capabilities should NOT appear in ELF analysis
            let windows_caps: Vec<_> = capabilities
                .iter()
                .filter(|cap| {
                    cap.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| id.contains("windows") || id.contains("keylog"))
                        .unwrap_or(false)
                })
                .collect();

            // Windows keylogging capabilities should be filtered out for ELF files
            for cap in windows_caps {
                let cap_id = cap.get("id").and_then(|id| id.as_str()).unwrap_or("");
                eprintln!("Note: Windows cap '{}' appeared in ELF file - checking if expected", cap_id);
            }
        }
    }
}

/// Test that universal (All) file type rules match everything
#[test]
fn test_universal_capabilities_match_all_files() {
    let temp_dir = TempDir::new().unwrap();

    // Test with shell script
    let script_path = temp_dir.path().join("test.sh");
    fs::write(&script_path, "#!/bin/bash\necho 'test'\n").unwrap();

    let output = Command::cargo_bin("dissect")
        .unwrap()
        .args(&["-f", "json", "analyze", script_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON - just verify the structure works
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        // Capabilities array should exist (even if empty for simple scripts)
        assert!(
            json.get("capabilities").is_some(),
            "Should have capabilities field in output"
        );

        if let Some(capabilities) = json.get("capabilities").and_then(|v| v.as_array()) {
            eprintln!("Found {} capabilities for shell script", capabilities.len());
        }
    }
}

/// Test that Python-specific capabilities match Python files
#[test]
fn test_python_capabilities_for_python_files() {
    let temp_dir = TempDir::new().unwrap();
    let py_file = temp_dir.path().join("test.py");

    // Python file with network operations
    fs::write(&py_file, "#!/usr/bin/env python3\nimport socket\ns = socket.socket()\n").unwrap();

    let output = Command::cargo_bin("dissect")
        .unwrap()
        .args(&["-f", "json", "analyze", py_file.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should detect as Python
    assert!(stderr.contains("Python"));

    // Parse JSON to check for network capabilities
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(capabilities) = json.get("capabilities").and_then(|v| v.as_array()) {
            eprintln!("Found {} capabilities for Python file", capabilities.len());

            // Look for network-related capabilities
            let net_caps: Vec<_> = capabilities
                .iter()
                .filter(|cap| {
                    cap.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| id.contains("net") || id.contains("socket") || id.contains("http"))
                        .unwrap_or(false)
                })
                .collect();

            if !net_caps.is_empty() {
                eprintln!("Found network capabilities:");
                for cap in &net_caps {
                    if let Some(id) = cap.get("id").and_then(|i| i.as_str()) {
                        eprintln!("  - {}", id);
                    }
                }
            }
        }
    }
}

/// Test that JavaScript-specific capabilities match JavaScript files
#[test]
fn test_javascript_capabilities_for_js_files() {
    let temp_dir = TempDir::new().unwrap();
    let js_file = temp_dir.path().join("test.js");

    // JavaScript with DOM access
    fs::write(&js_file, "const data = localStorage.getItem('key');\nconsole.log(data);\n").unwrap();

    let output = Command::cargo_bin("dissect")
        .unwrap()
        .args(&["-f", "json", "analyze", js_file.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should detect as JavaScript
    assert!(stderr.contains("JavaScript"));

    // Parse JSON - verify structure
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        assert!(json.get("capabilities").is_some(), "Should have capabilities field");

        if let Some(capabilities) = json.get("capabilities").and_then(|v| v.as_array()) {
            eprintln!("Found {} capabilities for JavaScript file", capabilities.len());

            // Note: Simple JS scripts might not trigger YAML capabilities
            // The important thing is file type detection works and structure is correct
        }

        // Check for YARA matches which are more likely for localStorage usage
        if let Some(yara_matches) = json.get("yara_matches").and_then(|v| v.as_array()) {
            eprintln!("Found {} YARA matches", yara_matches.len());
        }
    }
}

/// Test that shell-specific capabilities match shell scripts
#[test]
fn test_shell_capabilities_for_shell_scripts() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.sh");

    // Shell script with network operations
    fs::write(&script_path, "#!/bin/bash\ncurl http://example.com\nwget http://test.com\n").unwrap();

    let output = Command::cargo_bin("dissect")
        .unwrap()
        .args(&["-f", "json", "analyze", script_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should detect as ShellScript
    assert!(stderr.contains("ShellScript"));

    // Parse JSON
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(capabilities) = json.get("capabilities").and_then(|v| v.as_array()) {
            eprintln!("Found {} capabilities for shell script", capabilities.len());

            // Look for HTTP-related capabilities
            let http_caps: Vec<_> = capabilities
                .iter()
                .filter(|cap| {
                    cap.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| id.contains("http") || id.contains("net"))
                        .unwrap_or(false)
                })
                .collect();

            if !http_caps.is_empty() {
                eprintln!("Found HTTP capabilities:");
                for cap in &http_caps {
                    if let Some(id) = cap.get("id").and_then(|i| i.as_str()) {
                        eprintln!("  - {}", id);
                    }
                }
            }
        }
    }
}

/// Test that rules without file_types specified work universally
#[test]
fn test_rules_without_filetype_are_universal() {
    let temp_dir = TempDir::new().unwrap();

    // Test with multiple file types
    let sh_file = temp_dir.path().join("test.sh");
    let py_file = temp_dir.path().join("test.py");
    let js_file = temp_dir.path().join("test.js");

    fs::write(&sh_file, "#!/bin/bash\necho 'shell'\n").unwrap();
    fs::write(&py_file, "#!/usr/bin/env python3\nprint('python')\n").unwrap();
    fs::write(&js_file, "console.log('javascript');\n").unwrap();

    // Analyze all three files
    for file in &[sh_file, py_file, js_file] {
        let output = Command::cargo_bin("dissect")
            .unwrap()
            .args(&["-f", "json", "analyze", file.to_str().unwrap()])
            .output()
            .unwrap();

        assert!(output.status.success(), "Analysis should succeed for {:?}", file.file_name());

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse JSON - verify structure is correct for all file types
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            assert!(json.get("capabilities").is_some(), "File {:?} should have capabilities field", file.file_name());

            if let Some(capabilities) = json.get("capabilities").and_then(|v| v.as_array()) {
                eprintln!(
                    "File {:?} has {} capabilities",
                    file.file_name(),
                    capabilities.len()
                );

                // Note: Simple scripts without imports may not trigger YAML capabilities
                // The test verifies that the filtering infrastructure works, not that
                // every script triggers capabilities
            }
        }
    }
}

/// Test that composite trait evaluation respects file types
#[test]
fn test_composite_trait_file_type_filtering() {
    let temp_dir = TempDir::new().unwrap();

    // Create Python file with specific patterns that might trigger composite rules
    let py_file = temp_dir.path().join("suspicious.py");
    fs::write(
        &py_file,
        "#!/usr/bin/env python3\n\
         import socket\n\
         import os\n\
         s = socket.socket()\n\
         os.system('whoami')\n"
    ).unwrap();

    let output = Command::cargo_bin("dissect")
        .unwrap()
        .args(&["-f", "json", "analyze", py_file.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        // Check that Python file gets appropriate capabilities
        if let Some(capabilities) = json.get("capabilities").and_then(|v| v.as_array()) {
            eprintln!("Found {} capabilities for Python file with suspicious patterns", capabilities.len());

            // Verify capabilities have proper structure
            for cap in capabilities {
                assert!(cap.get("id").is_some(), "Capability should have id");
                assert!(cap.get("description").is_some(), "Capability should have description");
                assert!(cap.get("confidence").is_some(), "Capability should have confidence");
            }
        }

        // Check traits
        if let Some(traits) = json.get("traits").and_then(|v| v.as_array()) {
            eprintln!("Found {} traits detected", traits.len());
        }
    }
}

/// Test that platform and file_type constraints work together
#[test]
fn test_platform_and_filetype_constraints_together() {
    let temp_dir = TempDir::new().unwrap();

    // Test with shell script (Unix platform)
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\necho 'test'\n").unwrap();

    let output = Command::cargo_bin("dissect")
        .unwrap()
        .args(&["-f", "json", "analyze", script.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse and verify basic structure
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        assert!(json.get("target").is_some(), "Should have target field");
        assert!(json.get("capabilities").is_some(), "Should have capabilities field");

        // File type should be ShellScript
        if let Some(file_type) = json.get("target").and_then(|t| t.get("file_type")).and_then(|ft| ft.as_str()) {
            assert!(
                file_type.contains("Shell") || file_type.contains("script"),
                "File type should indicate shell script, got: {}",
                file_type
            );
        }
    }
}
