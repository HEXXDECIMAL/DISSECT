use assert_cmd::Command;
use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

#[test]
fn test_react2shell_detection() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let elf_path = temp_dir.path().join("react2shell_variant.elf");

    let mut file = File::create(&elf_path)?;
    
    // ELF Header (x86_64)
    file.write_all(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")?;
    
    // 1. Unique GoSocks paths
    file.write_all(b"src/mode/httpAndTcp/socket5Quick\0")?;
    file.write_all(b"src/mode/httpAndTcp/shell/ShellLinux.Exec_shell\0")?;
    file.write_all(b"src/mode/httpAndTcp/socket5Quick.StartProxy\0")?;

    // 2. Generalized Go Backdoor Strings
    file.write_all(b"StartWithSize\0")?;
    file.write_all(b"ptmx\0")?;
    file.write_all(b"/bin/bash\0")?;
    file.write_all(b"socksCommand\0")?;
    file.write_all(b"socksAddr\0")?;

    // Run dissect
    let mut cmd = Command::cargo_bin("dissect")?;
    cmd.arg("-v");
    cmd.arg(&elf_path);
    
    let cmd_assert = cmd.assert();
    let success = cmd_assert.success();
    let output = success.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);

    println!("Output: {}", stdout);

    // Verify Detections
    assert!(stdout.contains("Unique Go package path for SOCKS5/Shell logic"), "Missing unique path detection");
    assert!(stdout.contains("backdoor/gosocks"), "Missing GoSocks trait ID");
    
    // Generalized Detection
    assert!(stdout.contains("Go-based Reverse Shell with SOCKS Proxy"), "Missing generalized backdoor detection");

    Ok(())
}
