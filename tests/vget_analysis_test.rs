use assert_cmd::Command;
use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

#[test]
fn test_vget_detection() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let elf_path = temp_dir.path().join("vget_variant.elf");

    let mut file = File::create(&elf_path)?;

    // ELF Header (x86_64)
    file.write_all(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")?;

    // 1. Unique vGet strings
    file.write_all(b"ureq-2.12.1/src/body.rs\0")?;
    file.write_all(b"ureq-2.12.1/src/chunked/decoder.rs\0")?;
    file.write_all(b"/Users/cosmanking/.cargo/registry/src/\0")?;
    file.write_all(
        b"https://fixupcount.s3.dualstack.ap-northeast-1.amazonaws.com/wehn/rich.png\0",
    )?;

    // 2. Generic Rust Downloader strings
    file.write_all(b"ureq\0")?;
    file.write_all(b"https://\0")?;
    file.write_all(b"std::fs::File::create\0")?;

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
        stdout.contains("Rust-based downloader (ureq) with specific artifacts"),
        "Missing specific vget detection"
    );
    assert!(
        stdout.contains("Likely Rust-based stager"),
        "Missing likely stager detection"
    );

    Ok(())
}

#[test]
fn test_vget_generic_detection() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let elf_path = temp_dir.path().join("generic_downloader.elf");

    let mut file = File::create(&elf_path)?;

    // ELF Header (x86_64)
    file.write_all(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")?;

    // Generic Rust Downloader strings ONLY
    file.write_all(b"ureq\0")?;
    file.write_all(b"reqwest\0")?;
    file.write_all(b"https://\0")?;
    file.write_all(b"std::fs::File::create\0")?;
    file.write_all(b"std::process::Command\0")?;

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
        stdout.contains("Rust-based Downloader/Stager behavior detected"),
        "Missing generalized Rust stager behavior detection"
    );
    assert!(
        stdout.contains("Likely Rust-based stager"),
        "Missing likely stager detection"
    );

    Ok(())
}
