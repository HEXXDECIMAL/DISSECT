use assert_cmd::Command;
use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

#[test]
fn test_nodejs_backdoor_detection() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let elf_path = temp_dir.path().join("nodejs_backdoor.elf");

    let mut file = File::create(&elf_path)?;

    // ELF Header (x86_64)
    file.write_all(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")?;

    // 1. NodeJS Pkg Marker
    file.write_all(b"/snapshot/clients/index.js\0")?;

    // 2. Suspicious C2
    file.write_all(b"ws://securitytrails.pro:2052\0")?;

    // 3. Exfil indicators
    file.write_all(b"node_modules/ws/index.js\0")?;
    file.write_all(b"node_modules/archiver/index.js\0")?;

    // 4. New Behavioral Markers
    file.write_all(b"executeCommand\0")?;
    file.write_all(b"handleFileDownload\0")?;
    file.write_all(b"handleZipCreation\0")?;
    file.write_all(b"c2-client-temp\0")?;

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
        stdout.contains("NodeJS binary packaged with 'pkg'"),
        "Missing pkg marker detection"
    );
    assert!(
        stdout.contains("Function to execute remote commands"),
        "Missing executeCommand detection"
    );
    assert!(
        stdout.contains("Explicit 'c2-client' string marker"),
        "Missing c2-client detection"
    );
    assert!(
        stdout.contains("backdoor/nodejs"),
        "Missing NodeJS backdoor trait ID"
    );
    assert!(
        stdout.contains("Suspicious NodeJS C2 endpoint"),
        "Missing C2 detection"
    );

    Ok(())
}
