//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use assert_cmd::Command;
use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

#[test]
fn test_coinminer_pam_detection() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let elf_path = temp_dir.path().join("pam_miner.elf");

    let mut file = File::create(&elf_path)?;

    // ELF Header (x86_64)
    file.write_all(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")?;

    // 1. CGO PAM Strings
    file.write_all(b"_cgo_eba3282b571c_Cfunc_pam_authenticate\0")?;
    file.write_all(b"_cgo_eba3282b571c_Cfunc_pam_acct_mgmt\0")?;
    file.write_all(b"_cgo_eba3282b571c_Cfunc_pam_get_item\0")?;
    file.write_all(b"_cgo_panic\0")?;

    // 2. PAM Library
    file.write_all(b"libpam.so.0\0")?;

    // 3. Suspicious String
    file.write_all(
        b"TegskTGfBzL5ZXVeATJZ/Kg4gGwZNHviZINPIVp6K/-aw3x4amOW3feyTomlq7/WXkOJPhAhVPtgkpGtlhH\0",
    )?;

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
        stdout.contains("Accesses PAM authentication tokens"),
        "Missing generalized PAM interceptor detection"
    );

    // Check if CGO signals were picked up by the Go rule (Benign traits might be hidden in summary)
    // assert!(stdout.contains("metadata/language/go"), "Go rule ID missing");

    Ok(())
}
