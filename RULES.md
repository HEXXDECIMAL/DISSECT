# DISSECT Rule Writing Guide

Rules are defined in YAML files within `traits/` following the taxonomy: `objective/behavior/kind`

```
traits/
├── exec/                    # Execution
│   ├── process/
│   │   ├── csharp.yaml     # Language-specific traits
│   │   └── combos.yaml     # Composite rules
├── c2/                      # Command & Control
├── anti-analysis/           # Anti-analysis techniques
└── data/                    # Data handling
```

---

## Trait Definitions

Traits are atomic detection patterns for a single behavior.

```yaml
traits:
  - id: terminate
    description: Process termination via Kill()
    criticality: suspicious       # inert, notable, suspicious, hostile
    confidence: 0.95              # 0.0 to 1.0
    mbc: "E1562"                  # Optional: MBC technique ID
    attack: "T1562"               # Optional: MITRE ATT&CK ID
    file_types: [csharp]          # Target file types
    platforms: [all]              # linux, macos, windows, unix, android, ios, all
    condition:
      type: ast_pattern
      node_type: invocation_expression
      pattern: ".Kill("
```

**File Types:** `all`, `elf`, `macho`, `pe`, `dll`, `so`, `dylib`, `shell`, `python`, `javascript`, `rust`, `java`, `class`, `ruby`, `c`, `go`, `csharp`, `php`

**Criticality:** `inert` (benign) → `notable` (interesting) → `suspicious` (investigate) → `hostile` (malicious)

---

## Condition Types

### ast_pattern
Match text patterns within AST node types (source code).

```yaml
condition:
  type: ast_pattern
  node_type: invocation_expression  # Tree-sitter node type
  pattern: "Process.Start"
  regex: false                      # Optional: treat as regex
  case_insensitive: false
```

**Common node types:**
| Language | Function Calls | Object Creation |
|----------|---------------|-----------------|
| C# | `invocation_expression` | `object_creation_expression` |
| Python | `call` | `call` |
| JavaScript | `call_expression` | `new_expression` |
| Java | `method_invocation` | `object_creation_expression` |
| Go | `call_expression` | `composite_literal` |

### ast_query
Full tree-sitter query syntax for complex patterns.

```yaml
condition:
  type: ast_query
  query: |
    (call_expression
      function: (member_expression
        object: (identifier) @obj
        property: (property_identifier) @method))
    (#eq? @method "exec")
```

### symbol
Match function imports/exports in binaries.

```yaml
condition:
  type: symbol
  pattern: "socket|connect|bind"    # Regex pattern
  platforms: [linux, macos]
```

### string
Match strings in binaries or source code.

```yaml
condition:
  type: string
  exact: "http://"                  # OR regex: "https?://[^/]+"
  case_insensitive: false
  min_count: 1
  exclude_patterns: ["localhost", "127.0.0.1"]
  search_raw: false                 # Search raw file content (for counting occurrences)
```

### yara / yara_match
Inline YARA rules or reference existing matches.

```yaml
# Inline YARA
condition:
  type: yara
  source: |
    rule detect_packed {
      strings: $upx = "UPX!"
      condition: $upx at 0
    }

# Reference YARA namespace
condition:
  type: yara_match
  namespace: "crypto"
  rule: "sha256_hash"               # Optional: specific rule
```

### structure
Match structural features.

```yaml
condition:
  type: structure
  feature: "executable/packed"
```

### imports_count
Count imports with optional filtering.

```yaml
condition:
  type: imports_count
  min: 10
  max: 50
  filter: "socket"                  # Optional regex
```

### exports_count
Count exports with min/max thresholds.

```yaml
condition:
  type: exports_count
  min: 1
  max: 100
```

### symbol_or_string
Convenience condition that matches if any pattern is found as either a symbol OR string.

```yaml
condition:
  type: symbol_or_string
  any: ["CreateProcess", "ShellExecute", "WinExec"]
```

---

## Binary Analysis Conditions

Deep analysis via radare2. Only applies to `elf`, `macho`, `pe`, `dll`, `so`, `dylib`.

### function_metrics
Match functions by complexity metrics.

```yaml
condition:
  type: function_metrics
  cyclomatic_complexity:
    min: 50
  basic_blocks:
    min: 100
  loops:
    min: 5
  instructions:
    min: 1000
  stack_frame:
    min: 256                        # Stack frame size in bytes
  is_recursive: true
  is_leaf: false
```

### entropy
Match sections by entropy (0.0-8.0). High entropy (>7.0) indicates encryption/packing.

```yaml
condition:
  type: entropy
  section: "^(\\.text|CODE)"        # Regex for section name
  min: 7.0
  max: 8.0
```

### binary
Match binary header properties extracted via goblin. Enables detection of packed, malformed, or suspicious binaries based on structural characteristics rather than content signatures.

```yaml
condition:
  type: binary
  section_count:
    max: 0                          # No section headers (packed/stripped)
  file_entropy:
    min: 7.0                        # High entropy (packed/encrypted)
  machine_type: [20, 8]             # PowerPC=20, MIPS=8 (IoT malware)
  is_big_endian: true               # Big-endian byte order
  is_64bit: false                   # 32-bit binary
  has_rwx_segments: true            # W^X violation
  has_interpreter: false            # No dynamic linker (static)
  overlay_size:
    min: 1000                       # Appended data after ELF
```

**Available fields:**

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `section_count` | min/max | `e_shnum` | Section header count. `max: 0` detects stripped/packed binaries |
| `segment_count` | min/max | `e_phnum` | Program header count. Unusual values indicate malformed ELF |
| `file_entropy` | min/max | calculated | Whole-file entropy (0.0-8.0). >7.0 suggests packing/encryption |
| `overlay_size` | min/max | calculated | Bytes appended after last segment (embedded payloads) |
| `machine_type` | list | `e_machine` | CPU architecture codes (see table below) |
| `is_big_endian` | bool | `e_ident[5]` | Big-endian byte order (MIPS, PPC, SPARC) |
| `is_64bit` | bool | `e_ident[4]` | 64-bit ELF class |
| `has_rwx_segments` | bool | `p_flags` | Any PT_LOAD with W+X (self-modifying code) |
| `has_interpreter` | bool | PT_INTERP | Has dynamic linker. `false` = statically linked |

**Machine type codes (e_machine):**

| Code | Architecture | Notes |
|------|--------------|-------|
| 3 | i386 | x86 32-bit |
| 62 | x86_64 | x86 64-bit |
| 40 | ARM | 32-bit ARM |
| 183 | AArch64 | 64-bit ARM |
| 8 | MIPS | Common in routers/IoT |
| 10 | MIPS RS3000 LE | Little-endian MIPS |
| 20 | PowerPC | Common in IoT (Mirai) |
| 21 | PowerPC64 | 64-bit PPC |
| 42 | SuperH | Embedded systems |
| 2, 43 | SPARC/V9 | Sun/Oracle systems |
| 243 | RISC-V | Emerging architecture |

**Detection patterns:**

```yaml
# Detect UPX-like packing (no sections + high entropy)
condition:
  type: binary
  section_count:
    max: 0
  file_entropy:
    min: 7.0

# Detect IoT malware architecture (Mirai targets)
condition:
  type: binary
  machine_type: [8, 10, 20, 40, 42]  # MIPS, PPC, ARM, SuperH

# Detect self-modifying code
condition:
  type: binary
  has_rwx_segments: true
```

---

## Composite Rules

Combine multiple traits using boolean logic.

```yaml
composite_rules:
  - id: time/trigger/logic-bomb
    description: "Time-triggered self-destruct"
    criticality: hostile
    confidence: 0.95
    mbc: "B0003"
    attack: "T1480.001"
    file_types: [csharp]

    requires_all:                   # AND - all must match
      - type: trait
        id: time/trigger/hardcoded-datetime
      - type: trait
        id: exec/process/terminate
```

### Boolean Operators

```yaml
# AND - all conditions must match
requires_all:
  - type: trait
    id: net/socket/create
  - type: trait
    id: net/socket/connect

# OR - at least one must match
requires_any:
  - type: trait
    id: exec/process/start
  - type: trait
    id: exec/shell/command

# N of M - at least N conditions must match
requires_count: 2
conditions:
  - type: trait
    id: crypto/aes
  - type: trait
    id: crypto/rsa
  - type: trait
    id: crypto/xor

# NOT - none can match
requires_none:
  - type: string
    exact: "test"
```

### Trait References

```yaml
- type: trait
  id: exec/process/terminate       # Full path
- type: trait
  id: terminate                    # Suffix match (any trait ending with /terminate)
```

---

## Proximity Constraints

### scope (Source Code)
Require traits within the same code scope.

```yaml
scope: method              # method, class, or block
requires_all:
  - type: trait
    id: exec/reflection/assembly-load
  - type: trait
    id: exec/reflection/invoke
```

### near (Bytes - Binary)
Require patterns within N bytes.

```yaml
near: 100
requires_all:
  - type: string
    regex: "socket|connect"
  - type: string
    regex: "\\d+\\.\\d+\\.\\d+\\.\\d+"
```

### near_lines (Lines - Source)
Require patterns within N lines.

```yaml
near_lines: 10
requires_all:
  - type: trait
    id: exec/process/start
  - type: trait
    id: fs/file/delete
```

### within (Containment)
Require all traits inside another trait's span.

```yaml
within: exec/eval
requires_all:
  - type: trait
    id: encoding/base64/decode
```

---

## Examples

### Reverse Shell Detection (Binary)

```yaml
composite_rules:
  - id: c2/binary-reverse-shell
    description: "Reverse shell: socket + dup2 + exec"
    criticality: hostile
    confidence: 0.95
    mbc: "B0022"
    attack: "T1059"
    file_types: [elf, macho]
    requires_all:
      - type: symbol
        pattern: "socket|connect"
      - type: symbol
        pattern: "dup2"
      - type: symbol
        pattern: "execve|execl|system"
```

### Packed Binary Detection

```yaml
composite_rules:
  - id: packing/encrypted-code
    description: "Encrypted or packed code section"
    criticality: suspicious
    mbc: "F0001"
    attack: "T1027.002"
    file_types: [elf, pe, macho]
    requires_all:
      - type: entropy
        section: "^(\\.text|CODE)"
        min: 7.0
      - type: imports_count
        max: 20
```

### Obfuscated Code Execution

```yaml
composite_rules:
  - id: exec/obfuscated-eval
    description: "Base64 decode followed by eval"
    criticality: hostile
    file_types: [python, javascript]
    requires_all:
      - type: ast_pattern
        node_type: call
        pattern: "base64"
      - type: ast_pattern
        node_type: call
        pattern: "eval"
```

---

## Testing

```bash
dissect /path/to/file              # Analyze file
dissect --format json /path/to/file  # JSON output
dissect -v /path/to/file           # Verbose
```

Output shows matched traits with criticality indicators.
