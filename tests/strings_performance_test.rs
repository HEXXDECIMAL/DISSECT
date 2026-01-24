use assert_cmd::prelude::*;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;
use tempfile::TempDir;

#[test]
fn test_strings_subcommand_ls_accuracy_and_performance() {
    // This test only runs on systems with /bin/ls and nm
    let ls_path = Path::new("/bin/ls");
    if !ls_path.exists() {
        eprintln!("Skipping test: /bin/ls not found");
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let target_path = temp_dir.path().join("ls_copy");

    // Copy /bin/ls to avoid any permission issues
    fs::copy(ls_path, &target_path).expect("Failed to copy /bin/ls");

    // Get expected undefined symbols (imports) and their libraries using nm -u -m
    let nm_output = Command::new("nm")
        .args(["-u", "-m", target_path.to_str().unwrap()])
        .output()
        .expect("Failed to run nm");

    let nm_str = String::from_utf8_lossy(&nm_output.stdout);
    let mut expected_imports = std::collections::HashMap::new();

    // Format: (undefined) external _printf (from libSystem)
    for line in nm_str.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('/') || trimmed.contains(':') {
            continue;
        }

        if let Some(sym_start) = trimmed.find("external ") {
            let sym_part = &trimmed[sym_start + 9..];
            if let Some(lib_start) = sym_part.find(" (from ") {
                let sym = &sym_part[..lib_start];
                let lib_part = &sym_part[lib_start + 7..];
                let lib = lib_part.trim_end_matches(')');
                expected_imports.insert(sym.to_string(), lib.to_string());
            } else {
                let sym = sym_part.trim();
                expected_imports.insert(sym.to_string(), "unknown".to_string());
            }
        }
    }

    println!(
        "Found {} expected undefined symbols from nm",
        expected_imports.len()
    );

    let start = Instant::now();

    let mut cmd = Command::cargo_bin("dissect").unwrap();
    let output = cmd
        .arg("strings")
        .arg(target_path.to_str().unwrap())
        .arg("--min-length")
        .arg("3")
        .output()
        .expect("Failed to run dissect");

    let duration = start.elapsed();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify performance
    println!("Strings extraction on /bin/ls took: {:?}", duration);
    assert!(
        duration.as_secs() < 10,
        "Strings command was too slow: {:?} (expected < 10s)",
        duration
    );

    // Verify accuracy: Check that we found the expected imports
    let mut found_imports = std::collections::HashMap::new();
    let mut found_functions = 0;

    for line in stdout.lines() {
        if line.contains("Import") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let sym = parts[2];
                let mut lib = "unknown".to_string();

                if let Some(bracket_start) = line.rfind('[') {
                    if let Some(bracket_end) = line.rfind(']') {
                        if bracket_end > bracket_start {
                            lib = line[bracket_start + 1..bracket_end].to_string();
                        }
                    }
                }

                found_imports.insert(sym.to_string(), lib);
            }
        } else if line.contains("Function") {
            found_functions += 1;
        }
    }

    println!(
        "Found {} imports and {} functions in dissect output",
        found_imports.len(),
        found_functions
    );

    let mut matched_count = 0;

    for (expected_sym, _expected_lib) in &expected_imports {
        let mut actual_found_sym: Option<String> = None;

        if found_imports.contains_key(expected_sym) {
            actual_found_sym = Some(expected_sym.clone());
        } else if expected_sym.starts_with('_') && found_imports.contains_key(&expected_sym[1..]) {
            actual_found_sym = Some(expected_sym[1..].to_string());
        } else if !expected_sym.starts_with('_') {
            let prefixed = format!("_{}", expected_sym);
            if found_imports.contains_key(&prefixed) {
                actual_found_sym = Some(prefixed);
            }
        }

        if let Some(_) = actual_found_sym {
            matched_count += 1;
        }
    }

    if !expected_imports.is_empty() {
        let match_ratio = matched_count as f32 / expected_imports.len() as f32;
        println!(
            "Matched {}/{} import symbols ({:.2}%)",
            matched_count,
            expected_imports.len(),
            match_ratio * 100.0
        );

        assert!(
            match_ratio > 0.7,
            "Too many missing imports! Ratio: {:.2}%",
            match_ratio * 100.0
        );
    }
}
