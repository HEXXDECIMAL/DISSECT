use assert_cmd::Command;
use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

#[test]
fn test_multiverze_detection() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let elf_path = temp_dir.path().join("multiverze_variant.elf");

    let mut file = File::create(&elf_path)?;

    // ELF Header (x86_64)
    file.write_all(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")?;

    // 1. Suspicious Function Names (Symbol Table Simulation)
    file.write_all(b"encrypt_file\0")?;
    file.write_all(b"encrypt_directory\0")?;

    // 2. Suspicious Source File Name
    file.write_all(b"ransomware.c\0")?;

    // 3. Directory Traversal Symbols
    file.write_all(b"opendir\0")?;
    file.write_all(b"readdir\0")?;
    file.write_all(b"lstat\0")?;

    // 4. Ransom Note
    file.write_all(b"Encryption complete. Your files have been encrypted.\0")?;

    // Run dissect
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("dissect")?;
    cmd.arg("-v");
    cmd.arg(&elf_path);

    let cmd_assert = cmd.assert();
    let success = cmd_assert.success();
    let output = success.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);

    println!("Output: {}", stdout);

    // Verify Detections
    assert!(
        stdout.contains("Suspicious symbols or artifacts indicating ransomware activity"),
        "Missing ransomware symbol detection"
    );
    assert!(
        stdout.contains("Manual recursive directory traversal"),
        "Missing directory traversal detection"
    );
    assert!(
        stdout.contains("Generic ransom note string")
            || stdout.contains("Ransomware encryption patterns"),
        "Missing ransom note detection"
    );

    Ok(())
}
