# Syscall Detection Plan for DISSECT

## Overview

This plan outlines how to implement reliable syscall detection using radare2, emitting detected syscalls as traits.

## Architecture Support

Syscalls are architecture-specific. We need to handle:

| Architecture | Syscall Instruction | Syscall Number Register | Base Number |
|--------------|---------------------|------------------------|-------------|
| x86 (32-bit) | `int 0x80` | eax | 0 |
| x86_64 | `syscall` | rax | 0 |
| ARM32 | `svc #0` | r7 | 0 |
| ARM64 | `svc #0` | x8 | 0 |
| MIPS (o32) | `syscall` | v0 ($2) | 4000 |
| MIPS (n32) | `syscall` | v0 ($2) | 6000 |
| PowerPC | `sc` | r0 | 0 |

## Implementation Steps

### Phase 1: Radare2 Syscall Extractor

Add to `src/radare2.rs`:

```rust
/// Syscall information extracted from binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallInfo {
    pub address: u64,
    pub number: u32,
    pub name: String,
    pub arch: String,
}

impl Radare2Analyzer {
    /// Extract syscalls from binary using architecture-aware analysis
    pub fn extract_syscalls(&self, file_path: &Path) -> Result<Vec<SyscallInfo>> {
        // 1. Get architecture info
        let arch = self.get_architecture(file_path)?;

        // 2. Find syscall instructions based on architecture
        let syscall_addrs = match arch.as_str() {
            "x86" => self.find_pattern(file_path, "cd 80")?,          // int 0x80
            "x86_64" => self.find_pattern(file_path, "0f 05")?,       // syscall
            "arm" => self.find_pattern(file_path, "00 00 00 ef")?,    // svc #0
            "aarch64" => self.find_pattern(file_path, "01 00 00 d4")?, // svc #0
            "mips" => self.find_pattern(file_path, "00 00 00 0c")?,   // syscall
            "ppc" => self.find_pattern(file_path, "44 00 00 02")?,    // sc
            _ => return Ok(Vec::new()),
        };

        // 3. For each syscall, backtrack to find number
        let mut syscalls = Vec::new();
        for addr in syscall_addrs {
            if let Some(num) = self.find_syscall_number(&arch, file_path, addr)? {
                let name = self.syscall_name(&arch, num);
                syscalls.push(SyscallInfo {
                    address: addr,
                    number: num,
                    name,
                    arch: arch.clone(),
                });
            }
        }

        Ok(syscalls)
    }

    /// Find syscall number by backtracking from syscall instruction
    fn find_syscall_number(&self, arch: &str, file_path: &Path, addr: u64) -> Result<Option<u32>> {
        // Disassemble backwards to find the register load
        let output = Command::new("r2")
            .arg("-q")
            .arg("-e").arg("scr.color=0")
            .arg("-c")
            .arg(format!("pd -10 @ {:#x}", addr))
            .arg(file_path)
            .output()?;

        let disasm = String::from_utf8_lossy(&output.stdout);

        // Parse based on architecture
        match arch {
            "mips" => {
                // Look for: addiu v0, zero, 0xNNN or li v0, 0xNNN
                for line in disasm.lines().rev() {
                    if line.contains("addiu") && line.contains("v0") && line.contains("zero") {
                        if let Some(num) = extract_hex_number(line) {
                            return Ok(Some(num));
                        }
                    }
                }
            }
            "x86" | "x86_64" => {
                // Look for: mov eax, NNN
                for line in disasm.lines().rev() {
                    if line.contains("mov") && (line.contains("eax") || line.contains("rax")) {
                        if let Some(num) = extract_hex_number(line) {
                            return Ok(Some(num));
                        }
                    }
                }
            }
            // ... other architectures
            _ => {}
        }

        Ok(None)
    }
}
```

### Phase 2: Syscall Name Mapping

Create `src/syscall_names.rs`:

```rust
/// Map syscall numbers to names by architecture
pub fn syscall_name(arch: &str, number: u32) -> String {
    match arch {
        "mips" => mips_syscall_name(number),
        "x86" => x86_syscall_name(number),
        "x86_64" => x86_64_syscall_name(number),
        "arm" => arm_syscall_name(number),
        "aarch64" => aarch64_syscall_name(number),
        _ => format!("syscall_{}", number),
    }
}

fn mips_syscall_name(number: u32) -> String {
    // MIPS o32 syscalls (base 4000)
    match number {
        4001 => "exit",
        4002 => "fork",
        4003 => "read",
        4004 => "write",
        4005 => "open",
        4006 => "close",
        // ... full table
        4037 => "kill",
        4066 => "setsid",
        4102 => "socketcall",
        // ... etc
        _ => return format!("syscall_{}", number),
    }.to_string()
}
```

### Phase 3: Integrate into ELF Analyzer

Modify `src/analyzers/elf.rs`:

```rust
fn analyze_elf(&self, file_path: &Path, data: &[u8]) -> Result<AnalysisReport> {
    // ... existing analysis ...

    // Extract syscalls
    if Radare2Analyzer::is_available() {
        if let Ok(syscalls) = self.radare2.extract_syscalls(file_path) {
            report.syscalls = syscalls;
        }
    }

    // ... rest of analysis ...
}
```

### Phase 4: Syscall Trait Condition Type

Add to `src/rules/types.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallCondition {
    /// Syscall name(s) to match
    #[serde(default)]
    pub name: Option<Vec<String>>,
    /// Syscall number(s) to match
    #[serde(default)]
    pub number: Option<Vec<u32>>,
    /// Architecture filter
    #[serde(default)]
    pub arch: Option<Vec<String>>,
    /// Minimum occurrences
    #[serde(default)]
    pub min_count: Option<u32>,
}
```

Add to `src/rules/evaluators.rs`:

```rust
pub fn eval_syscall(cond: &SyscallCondition, ctx: &EvaluationContext) -> ConditionResult {
    let syscalls = &ctx.report.syscalls;

    let matching: Vec<_> = syscalls.iter().filter(|sc| {
        // Match by name
        if let Some(names) = &cond.name {
            if !names.iter().any(|n| sc.name.contains(n)) {
                return false;
            }
        }
        // Match by number
        if let Some(nums) = &cond.number {
            if !nums.contains(&sc.number) {
                return false;
            }
        }
        // Match by arch
        if let Some(archs) = &cond.arch {
            if !archs.iter().any(|a| sc.arch.contains(a)) {
                return false;
            }
        }
        true
    }).collect();

    // Check min_count
    if let Some(min) = cond.min_count {
        if matching.len() < min as usize {
            return ConditionResult::no_match();
        }
    }

    if matching.is_empty() {
        return ConditionResult::no_match();
    }

    ConditionResult {
        matched: true,
        evidence: vec![Evidence {
            method: "syscall".to_string(),
            source: "radare2".to_string(),
            value: matching.iter().map(|s| s.name.clone()).collect::<Vec<_>>().join(", "),
            location: None,
            span: None,
            analysis_layer: None,
        }],
    }
}
```

### Phase 5: Create Syscall Trait Definitions

```yaml
# traits/syscall/network/socket.yaml
traits:
  - id: syscall/network/socket-create
    description: "Creates network socket"
    criticality: notable
    confidence: 0.8
    attack: "T1071"
    file_types: [elf, macho]
    condition:
      type: syscall
      name: ["socket", "socketcall"]

  - id: syscall/network/connect
    description: "Connects to remote host"
    criticality: notable
    confidence: 0.8
    attack: "T1071"
    file_types: [elf, macho]
    condition:
      type: syscall
      name: ["connect"]

# traits/syscall/process/daemon.yaml
traits:
  - id: syscall/process/fork
    description: "Forks child process"
    criticality: notable
    confidence: 0.7
    file_types: [elf, macho]
    condition:
      type: syscall
      name: ["fork", "vfork", "clone"]

  - id: syscall/process/setsid
    description: "Creates new session (daemon behavior)"
    criticality: notable
    confidence: 0.8
    attack: "T1543"
    file_types: [elf]
    condition:
      type: syscall
      name: ["setsid"]

# traits/syscall/exec/shell.yaml
traits:
  - id: syscall/exec/execve
    description: "Executes program"
    criticality: notable
    confidence: 0.7
    attack: "T1059"
    file_types: [elf, macho]
    condition:
      type: syscall
      name: ["execve", "execl", "execv"]

composite_rules:
  - id: syscall/reverse-shell
    description: "Reverse shell pattern (socket + dup2 + exec)"
    criticality: hostile
    confidence: 0.95
    attack: "T1059"
    file_types: [elf, macho]
    requires_all:
      - type: syscall
        name: ["socket", "socketcall"]
      - type: syscall
        name: ["dup2"]
      - type: syscall
        name: ["execve", "execl"]
```

## Testing Strategy

1. **Unit tests for syscall extraction**
   - Test MIPS syscall number extraction
   - Test x86/x86_64 syscall extraction
   - Test ARM syscall extraction

2. **Integration tests with real binaries**
   - Test against known IoT malware samples
   - Verify correct syscall names are emitted

3. **Trait evaluation tests**
   - Test syscall condition matching
   - Test composite rules with syscall conditions

## Performance Considerations

- Cache radare2 analysis results per binary
- Limit backtrack depth when searching for syscall numbers
- Consider timeout for very large binaries
- Option to disable deep syscall analysis for quick scans

## Future Enhancements

1. **Syscall argument analysis** - Extract what files/addresses are accessed
2. **Syscall sequence detection** - Detect patterns like fork→setsid→fork
3. **Dynamic syscall number resolution** - Handle indirect syscall numbers
4. **libc wrapper detection** - Map libc calls to underlying syscalls
