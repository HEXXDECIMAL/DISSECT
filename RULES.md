# DISSECT Rule Writing Guide

## Philosophy

**Traits are atomic observations.** A single detectable pattern: a symbol, string, or AST node.

**Composite rules are behavioral interpretations.** Traits combined to describe capabilities: reverse shell = `socket + dup2 + exec`.

**Criticality is independent of confidence.** A socket import is certain (confidence: 1.0) but benign (inert). A Telegram API match is uncertain (confidence: 0.8) but hostile.

## Taxonomy

Rules follow a three-tier hierarchy based on [MBC (Malware Behavior Catalog)](https://github.com/MBCProject/mbc-markdown). See [TAXONOMY.md](./TAXONOMY.md) for the complete structure.

| Tier | Prefix | Purpose | Criticality Range |
|------|--------|---------|-------------------|
| **Capabilities** | `cap/` | What code *can do* (value-neutral) | inert → notable → suspicious |
| **Objectives** | `obj/` | What code *likely wants* to do | notable → suspicious → hostile |
| **Known** | `known/` | Specific malware/tool signatures | suspicious → hostile |
| **Meta** | `meta/` | File properties (informational) | inert |

**Capabilities** (`cap/`) - MBC Micro-behaviors:

| Prefix | Description |
|---|---|
| `cap/comm/` | Network communication |
| `cap/crypto/` | Cryptography |
| `cap/data/` | Data transformation |
| `cap/exec/` | Code execution |
| `cap/fs/` | Filesystem access |
| `cap/hw/` | Hardware interaction |
| `cap/mem/` | Memory operations |
| `cap/os/` | OS integration |
| `cap/process/` | Process control |

**Objectives** (`obj/`) - MBC Objectives:

| Prefix | Description |
|---|---|
| `obj/anti-analysis/` | Evade dynamic analysis |
| `obj/anti-forensics/` | Cover tracks |
| `obj/anti-static/` | Evade static analysis |
| `obj/c2/` | Command & control |
| `obj/collect/` | Information gathering |
| `obj/creds/` | Credential theft |
| `obj/discovery/` | Environment reconnaissance |
| `obj/exfil/` | Data exfiltration |
| `obj/impact/` | Destructive operations |
| `obj/lateral/` | Lateral movement |
| `obj/persist/` | Persistence mechanisms |
| `obj/privesc/` | Privilege escalation |

**Known** (`known/`): Malware families (`known/malware/`) and security tools (`known/tools/`).

## Trait Placement (CRITICAL)

**Generic capabilities NEVER go in `known/`.** Only family-unique identifiers belong there.

```yaml
# known/malware/backdoor/examplebot/traits.yaml - CORRECT
traits:
  - id: marker  # Malware-specific only (auto-prefixed to known/malware/backdoor/examplebot/marker)
    if: { type: string, exact: "ExampleBot_v2.1" }

composite_rules:
  - id: detected
    all:
      - id: marker                       # Local reference
      - id: cap/exec/shell/bin-sh        # From cap/exec/shell/
      - id: cap/comm/proxy/socks5-proto  # From cap/comm/proxy/
```

## File Organization

```
traits/cap/exec/shell/
├── traits.yaml      # Primary definitions
├── combos.yaml      # Composite rules
├── linux.yaml       # Platform-specific
└── python.yaml      # Language-specific
```

**Trait IDs** are relative to directory (auto-prefixed). Use full path for cross-tier references: `cap/exec/shell/subprocess`

## Criticality Levels

| Level | Description | Examples |
|-------|-------------|----------|
| `inert` | Universal baseline | `open()`, `read()`, `malloc()` |
| `notable` | Defines program purpose | `socket()`, `exec()`, `eval()` |
| `suspicious` | Hides intent/crosses boundaries | VM detection, obfuscation |
| `hostile` | Attack patterns, no legitimate use | Reverse shell, ransomware |

**When in doubt:** Notable > Inert, Notable > Suspicious, Suspicious > Hostile

### HOSTILE Complexity Requirement

**HOSTILE composites require complexity ≥ 4** or they're downgraded to SUSPICIOUS.

**Complexity calculation:**
- `any:` → +1 (regardless of sub-pattern count)
- `all:` → +N (N = number of rules)
- `file_types:`/`filesize:` → +1 each
- Referenced composites with `all:` add recursively

```yaml
# Complexity = 4 ✓ HOSTILE maintained
- id: good-trojan
  crit: hostile
  file_types: [javascript]  # +1
  all:                       # +3
    - id: pattern-a
    - id: pattern-b
    - id: pattern-c
```

### Count Operators

| Operator | Description |
|----------|-------------|
| `count_min: N` | At least N must match |
| `count_max: N` | At most N can match |
| `count_exact: N` | Exactly N must match |

## Trait Definitions

```yaml
traits:
  - id: exec/process/terminate
    desc: Process termination         # Keep ≤5 words
    crit: suspicious
    conf: 0.95
    mbc: "E1562"                       # Optional
    attack: "T1562"                    # Optional
    for: [csharp]                      # File types
    platforms: [all]                   # linux, macos, windows, unix, all
    if:
      type: ast
      kind: call
      exact: ".Kill("
```

**File types:** `all`, `elf`, `macho`, `pe`, `dll`, `so`, `dylib`, `shell`, `python`, `javascript`, `rust`, `java`, `class`, `ruby`, `c`, `go`, `csharp`, `php`

## Condition Types

### ast

Match patterns in parsed source code.

```yaml
# Simple mode (recommended)
if:
  type: ast
  kind: call              # call, function, class, import, string, etc.
  exact: "eval"           # or regex:

# Advanced mode (tree-sitter query)
if:
  type: ast
  query: |
    (call_expression function: (identifier) @fn)
    (#eq? @fn "eval")
```

**Kinds:** `call`, `function`, `class`, `import`, `string`, `comment`, `assignment`, `argument`, `return`, `binary_op`, `identifier`, `attribute`, `subscript`, `conditional`, `loop`

### symbol

Match function imports/exports. Use `dissect symbols <file>` to preview.

```yaml
if:
  type: symbol
  exact: "socket"    # or regex:
```

### string

Match extracted strings. Use `dissect strings <file>` to preview.

```yaml
if:
  type: string
  substr: "http://"      # or exact:, regex:, word:
  min_count: 1
  case_insensitive: false
```

### hex

Match byte patterns with wildcards and gaps.

```yaml
if:
  type: hex
  pattern: "7F 45 4C 46"        # ELF magic
  pattern: "31 ?? 48 83"        # ?? = any byte
  pattern: "00 03 [4] 00 04"    # [N] = skip N bytes
  pattern: "00 03 [2-8] 00"     # [N-M] = variable gap
  offset: 0                      # Optional: only at position
```

### content

Search raw file bytes (less precise than `string`).

```yaml
if:
  type: content
  substr: "eval("          # or exact:, regex:
```

### yara

Use sparingly. Prefer traits + composites.

```yaml
if:
  type: yara
  source: |
    rule detect { strings: $a = "UPX!" condition: $a at 0 }
```

### section_name

Match binary section names.

```yaml
if:
  type: section_name
  pattern: "UPX"
  regex: true           # Optional
```

### filesize

```yaml
if:
  type: filesize
  min: 1000
  max: 10485760
```

### basename

Match basename (final path component). Useful for special files like `__init__.py`, `setup.py`.

```yaml
if:
  type: basename
  exact: "__init__.py"     # or substr:, regex:
  case_insensitive: false
```

### trait_glob

Match multiple traits by pattern.

```yaml
if:
  type: trait_glob
  pattern: "xdp-*"
  match: "any"    # any, all, or number
```

## Binary Analysis Conditions

For `elf`, `macho`, `pe` only.

### section_entropy

```yaml
if:
  type: section_entropy
  section: "^\\.text"
  min_entropy: 7.0    # >7.0 = encrypted/packed
```

### section_ratio

```yaml
if:
  type: section_ratio
  section: "^__const"
  compare_to: "total"
  min_ratio: 0.8
```

### import_combination

```yaml
if:
  type: import_combination
  required: ["kernel32.dll"]
  suspicious: ["VirtualAlloc", "WriteProcessMemory"]
  min_suspicious: 2
```

### metrics

```yaml
if:
  type: metrics
  field: "identifiers.avg_entropy"
  min: 3.5
  max: 5.0
```

## Composite Rules

Combine traits with boolean logic. Capabilities combine into objectives.

```yaml
# obj/c2/reverse-shell/combos.yaml
composite_rules:
  - id: reverse-shell
    desc: "Reverse shell"
    crit: hostile
    conf: 0.95
    for: [elf, macho]
    all:                    # AND - all must match
      - id: cap/comm/socket/create
      - id: cap/process/fd/dup2
      - id: cap/exec/shell
    any:                    # OR - at least one
      - id: pattern-a
      - id: pattern-b
    none:                   # NOT - none can match
      - id: legitimate-use
```

Composites can reference other composites. Circular dependencies handled gracefully.

## Exception Directives

### `not:` - String-Level Exceptions

Filter matched strings from evidence.

```yaml
- id: hardcoded-domain
  if: { type: string, regex: "\\b[a-z0-9]+\\.com\\b" }
  not:
    - "apple.com"              # Substring match
    - exact: "github.com"      # Full match
    - regex: "^192\\.168\\."   # Pattern
```

### `unless:` - File-Level Skip

Skip trait/composite if any condition matches. Supports trait references and inline conditions.

```yaml
- id: network-connect
  if: { type: symbol, pattern: "connect" }
  unless:
    - id: meta/format/system-binary    # Trait reference
    - type: basename                    # Inline condition
      regex: "^lib.*\\.so"
```

### `downgrade:` - Context-Based Criticality

Reduce criticality by one level when conditions match. Drops: hostile→suspicious→notable→inert.

```yaml
- id: bash-history
  crit: suspicious
  if: { type: string, substr: ".bash_history" }
  downgrade:
    any:                    # At least one must match
      - type: basename
        exact: "bash"
      - type: basename
        exact: "sh"
    # Also supports:
    # all: [...]           # All must match
    # none: [...]          # None can match
    # count_min: N         # At least N must match
```

Use for expected behavior: bash referencing `.bash_history`, chrome referencing `History`, ssh tools using `StrictHostKeyChecking=no`.

## Proximity Constraints

```yaml
scope: method      # Same code scope
near: 100          # Within N bytes
near_lines: 10     # Within N lines
within: exec/eval  # Inside another trait's span
```

## MBC/ATT&CK Reference

| Prefix | Meaning |
|--------|---------|
| B0XXX | Behavioral objective |
| E1XXX | Enterprise ATT&CK |
| C0XXX | Micro-behavior |
| F0XXX | File/defense ops |

## Testing & Debugging

```bash
dissect /path/to/file              # Analyze
dissect --json /path/to/file       # JSON output
dissect -v /path/to/file           # Verbose
dissect symbols <file>             # View extracted symbols
dissect strings <file>             # View extracted strings
```

### test-rules

Debug why rules match or fail.

```bash
dissect test-rules <FILE> --rules "rule1,rule2"
```

Shows: match status, complexity breakdown, condition evaluation, and all extracted strings/symbols.

### test-match

Test ad-hoc patterns without creating rules.

```bash
dissect test-match <FILE> --type string --method contains --pattern "http://"
dissect test-match <FILE> --type symbol --method exact --pattern "socket"
dissect test-match <FILE> --type content --method regex --pattern "eval\\("
```

Options: `--type` (string/symbol/content), `--method` (exact/contains/regex/word), `--file-type`, `--case-insensitive`
