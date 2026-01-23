# DISSECT Rule Writing Guide

## Philosophy

**Traits are atomic observations.** A single detectable pattern: a symbol, string, or AST node.

**Composite rules are behavioral interpretations.** Traits combined to describe capabilities: reverse shell = `socket + dup2 + exec`.

**Criticality is independent of confidence.** A socket import is certain (confidence: 1.0) but benign (inert). A Telegram API match is uncertain (confidence: 0.8) but hostile.

## Taxonomy

Rules follow the path `objective/behavior/kind`:

| Level | Description | Examples |
|-------|-------------|----------|
| Objective | What the code achieves | `exec`, `net`, `c2`, `anti-analysis` |
| Behavior | How it achieves it | `command`, `socket`, `channels` |
| Kind | Specific implementation | `shell`, `connect`, `telegram` |

### Special Prefixes

| Prefix | Description | Examples |
|--------|-------------|----------|
| `malware/<family>/<variant>` | Malware families | `malware/stealer/amos`, `malware/rat/asyncrat` |
| `eco/<ecosystem>/<behavior>` | Package ecosystem patterns | `eco/npm/scripts/postinstall-hook`, `eco/vscode/malicious/dropper` |
| `supply-chain/<vector>/<type>` | Supply chain attacks | `supply-chain/typosquat/domain`, `supply-chain/install-time/execution` |
| `intel/<category>/<type>` | Discovery/reconnaissance | `intel/fingerprint/system`, `intel/discover/user` |
| `meta/<category>/<type>` | Binary metadata/provenance | `meta/language/go`, `meta/compiler/gcc`, `meta/build/cmake` |
| `data/<category>/<format>` | Data operations | `data/database/postgresql`, `data/encoding/protobuf` |
| `lib/<category>/<library>` | Library usage patterns | `lib/logging/syslog`, `lib/ipc/grpc` |
| `dev/<category>/<tool>` | Development artifacts | `dev/testing/gtest` |

### Ecosystem Traits (`eco/`)

Ecosystem-specific traits detect patterns unique to package managers and extension platforms:

```
traits/eco/
├── npm/              # npm packages (package.json)
│   ├── scripts.yaml  # Script hook patterns (preinstall, postinstall)
│   └── metadata.yaml # Package metadata anomalies
├── vscode/           # VSCode extensions
│   ├── api.yaml      # Extension API usage
│   └── malicious.yaml # Malicious extension patterns
├── chrome/           # Chrome extensions (future)
├── pypi/             # PyPI packages (future)
└── cargo/            # Rust crates (future)
```

## File Organization

```
traits/
├── exec/command/
│   ├── traits.yaml      # Primary trait definitions
│   ├── combos.yaml      # Composite rules
│   ├── linux.yaml       # Platform-specific
│   └── python.yaml      # Language-specific
```

**Trait IDs must be fully qualified paths** matching their file location:
```yaml
- id: exec/command/shell/system    # Correct
- id: system                        # Avoid
```

## Criticality Levels

```
Inert → Notable → Suspicious → Hostile
```

| Level | Description | Examples |
|-------|-------------|----------|
| `inert` | Universal baseline—every program has this | `open()`, `read()`, `malloc()`, `exit()` |
| `notable` | Defines program purpose | `socket()`, `exec()`, `eval()`, encryption |
| `suspicious` | Hides intent or crosses ethical boundaries | VM detection, obfuscation, credential access |
| `hostile` | Composite attack patterns with no legitimate use | Reverse shell, bind shell, ransomware patterns |

**Assignment guidelines:**
1. "Does every hello world have this?" → **Inert**
2. "Does this define what the program does?" → **Notable**
3. "Does this hide intent or cross ethical boundaries?" → **Suspicious**
4. "Is this a composite attack pattern with no legitimate use?" → **Hostile**

**When in doubt:** Notable > Inert, Notable > Suspicious, Suspicious > Hostile

---

## Trait Definitions

```yaml
traits:
  - id: exec/process/terminate
    description: Process termination via Kill()
    criticality: suspicious
    confidence: 0.95
    mbc: "E1562"                  # Optional: MBC ID
    attack: "T1562"               # Optional: ATT&CK ID
    file_types: [csharp]
    platforms: [all]             # linux, macos, windows, unix, android, ios, all
    condition:
      type: ast_pattern
      node_type: invocation_expression
      pattern: ".Kill("
```

**File types:** `all`, `elf`, `macho`, `pe`, `dll`, `so`, `dylib`, `shell`, `python`, `javascript`, `rust`, `java`, `class`, `ruby`, `c`, `go`, `csharp`, `php`

---

## Condition Types

### ast_pattern
Match text patterns within AST node types.

```yaml
condition:
  type: ast_pattern
  node_type: invocation_expression  # Tree-sitter node type
  pattern: "Process.Start"
  regex: false
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
Full tree-sitter query syntax. Optionally specify a `language` for validation.

```yaml
condition:
  type: ast_query
  language: javascript  # Optional: validates query syntax at load time
  query: |
    (call_expression
      function: (member_expression
        object: (identifier) @obj
        property: (property_identifier) @method))
    (#eq? @method "exec")
```

**Supported languages:** `c`, `python`, `javascript`/`js`, `typescript`/`ts`, `rust`, `go`, `java`, `ruby`, `shell`/`bash`, `php`, `csharp`/`c#`

**Note:** If `language` is omitted, validation is skipped at load time (query compiles at runtime against the file type).

### symbol
Match function imports/exports in binaries.

```yaml
condition:
  type: symbol
  pattern: "socket|connect|bind"    # Regex
  platforms: [linux, macos]
```

### string
Match strings in binaries or source.

```yaml
condition:
  type: string
  exact: "http://"                  # OR regex: "https?://[^/]+"
  case_insensitive: false
  min_count: 1
  exclude_patterns: ["localhost"]
  search_raw: false                 # Search raw file content
```

### symbol_or_string
Match if pattern found as either symbol OR string.

```yaml
condition:
  type: symbol_or_string
  any: ["CreateProcess", "ShellExecute", "WinExec"]
```

### yara / yara_match
Inline YARA or reference existing matches.

```yaml
# Inline
condition:
  type: yara
  source: |
    rule detect_packed { strings: $upx = "UPX!" condition: $upx at 0 }

# Reference
condition:
  type: yara_match
  namespace: "crypto"
  rule: "sha256_hash"
```

### structure
Match structural features.

```yaml
condition:
  type: structure
  feature: "executable/packed"
```

### imports_count / exports_count
Count imports or exports with thresholds.

```yaml
condition:
  type: imports_count
  min: 10
  max: 50
  filter: "socket"
```

---

## Binary Analysis Conditions

For `elf`, `macho`, `pe`, `dll`, `so`, `dylib` only.

### binary
Match binary header properties.

```yaml
condition:
  type: binary
  section_count:
    max: 0                          # No sections (packed/stripped)
  file_entropy:
    min: 7.0                        # High entropy (packed/encrypted)
  machine_type: [8, 20, 40]         # MIPS, PPC, ARM (IoT)
  is_big_endian: true
  is_64bit: false
  has_rwx_segments: true            # W^X violation
  has_interpreter: false            # Static binary
  overlay_size:
    min: 1000                       # Appended data
```

**Machine types:** 3=i386, 62=x86_64, 40=ARM, 183=AArch64, 8=MIPS, 20=PPC, 243=RISC-V

### entropy
Match sections by entropy (0.0-8.0). >7.0 indicates encryption/packing.

```yaml
condition:
  type: entropy
  section: "^(\\.text|CODE)"
  min: 7.0
```

### function_metrics
Match functions by complexity.

```yaml
condition:
  type: function_metrics
  cyclomatic_complexity:
    min: 50
  basic_blocks:
    min: 100
  instructions:
    min: 1000
  is_recursive: true
```

---

## Composite Rules

Combine traits using boolean logic.

```yaml
composite_rules:
  - id: c2/reverse-shell
    description: "Reverse shell: socket + dup2 + exec"
    criticality: hostile
    confidence: 0.95
    mbc: "B0022"
    attack: "T1059"
    file_types: [elf, macho]

    requires_all:                   # AND
      - type: symbol
        pattern: "socket|connect"
      - type: symbol
        pattern: "dup2"
      - type: symbol
        pattern: "execve|system"
```

### Boolean Operators

```yaml
requires_all:    # AND - all must match
requires_any:    # OR - at least one must match
requires_none:   # NOT - none can match

# N of M
requires_count: 2
conditions:
  - type: trait
    id: crypto/aes
  - type: trait
    id: crypto/rsa
  - type: trait
    id: crypto/xor
```

### Trait References

```yaml
- type: trait
  id: exec/process/terminate       # Full path
- type: trait
  id: terminate                    # Suffix match
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

### near (Bytes)
Require patterns within N bytes.

```yaml
near: 100
requires_all:
  - type: string
    regex: "socket"
  - type: string
    regex: "\\d+\\.\\d+\\.\\d+\\.\\d+"
```

### near_lines (Lines)
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
Require traits inside another trait's span.

```yaml
within: exec/eval
requires_all:
  - type: trait
    id: encoding/base64/decode
```

---

## MBC/ATT&CK Reference

| Prefix | Meaning | Example |
|--------|---------|---------|
| B0XXX | Behavioral objective | B0001 = Debugger Detection |
| E1XXX | Enterprise ATT&CK mapping | E1059 = Command Execution |
| C0XXX | Micro-behavior (atomic) | C0001 = Socket Communication |
| F0XXX | File/defense operations | F0001 = Packing |

---

## Testing

```bash
dissect /path/to/file              # Analyze
dissect --format json /path/to/file  # JSON output
dissect -v /path/to/file           # Verbose
```
