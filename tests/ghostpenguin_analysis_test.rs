use assert_cmd::Command;
use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

#[test]
fn test_ghostpenguin_behavioral_detection() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let elf_path = temp_dir.path().join("ghostpenguin_variant.elf");

    let mut file = File::create(&elf_path)?;

    // ELF Header (x86_64)
    file.write_all(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")?;
    file.write_all(&[0u8; 50])?;

    // 1. Signature-Agnostic: Unique Format Strings
    // These are specific to the malware's logging/exfiltration format
    file.write_all(b"Bytes == %d\r\nLanIP:%s\r\n\r\n")?;
    file.write_all(b"Bytes == %d\r\nGateWay:%s\r\n\r\n")?;
    file.write_all(b"Bytes == %d\r\nOSInfo:%s\r\n\r\n")?;

    // 2. Signature-Agnostic: Internal Class Names
    // Even if stripped, RTTI or debug info might leak these, or they appear in strings
    file.write_all(b"CBasicInfoGather")?;
    file.write_all(b"CTool")?;
    file.write_all(b"CMyRC5")?;

    // 3. Signature-Agnostic: Direct Syscall Pattern (ARM64 style from previous analysis, though this is x86_64 elf)
    // The previous analysis found: 01 00 00 d4 (ARM64 svc 0)
    // We'll include that byte sequence to trigger the behavioral rule
    file.write_all(b"\x01\x00\x00\xd4")?;

    // Run dissect
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("dissect")?;
    cmd.arg(&elf_path);

    let cmd_assert = cmd.assert();
    let success = cmd_assert.success();
    let output = success.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify Detections

    // 1. Unique Format Strings
    assert!(
        stdout.contains("GhostPenguin unique format strings"),
        "Missing format string detection"
    );

    // 2. Class Names
    assert!(
        stdout.contains("GhostPenguin internal class names"),
        "Missing class name detection"
    );

    // 3. Direct Syscall (Behavioral)
    assert!(
        stdout.contains("Makes direct system calls"),
        "Missing direct syscall detection"
    );

    Ok(())
}
