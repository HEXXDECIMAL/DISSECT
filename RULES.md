# DISSECT Rule Writing Guide

## Philosophy

**Traits are atomic observations.** A single detectable pattern: a symbol, string, or AST node.

**Composite rules are behavioral interpretations.** Traits combined to describe capabilities: reverse shell = `socket + dup2 + exec`. Traits that a composite depends on should be organized properly within the taxonomy; often not in the same file.

**Criticality is independent of confidence.** A socket import is certain (confidence: 1.0) but benign (inert). A Telegram API match is uncertain (confidence: 0.8) but hostile.

## Taxonomy

Rules follow `objective/capability/kind` organization (inspired by MalwareBehaviorCatalog). Since this is static analysis, we detect **capabilities** not behaviors.

* **objective**: what a program could achieve
* **capability**: how it could achieve it
* **kind**: specific implementation

**Objectives taxonomy:**

|**Objective**|**Capabilities that could be used to ...**|
|---|---|
|[**anti-analysis**](./traits/anti-analysis)| evade behavior analysis |
|[**anti-static**](./traits/anti-static)| make static analysis more difficult |
|[**collect**](./traits/collect)| identify and gather information from a machine or network |
|[**c2**](./traits/c2)| communicate with compromised systems |
|[**cred**](./traits/cred)| steal account names and passwords |
|[**evasion**](./traits/evasion)| evade detection |
|[**discovery**](./traits/discovery)| gain knowledge about the environment.|
|[**exec**](./traits/exec)| execute code on a system.|
|[**exfil**](./traits/exec)| steal data.|
|[**xmpact**](./traits/impact)| manipulate, interrupt, or destroy systems or data.|
|[**lateral**](./traits/lateral)| propagate or otherwise move through an environment.|
|[**persist**](./traits/persist)| remain on a system.|
|[**privesc**](./traits/privesc)| obtain higher level permissions.|

Granularity: Supply-chain attacks should be obvious in trait diffs, but code refactors shouldn't cause diffs.

**Micro-traits** (`category/subcategory/kind/` - based on MBC MicroBehaviors):

|**Micro-trait**|**description**|
|---|---|
| [**comm**](./traits/comm) | communications (generally networking)
| [**crypto**](./traits/crypto) | cryptography (not cryptomining)
| [**data**](./traits/data) | data manipulation
| [**fs**](./traits/fs) | filesystem manipulation
| [**hw**](./traits/hw) | hardware manipulation
| [**mem**](./traits/mem) | memory manipulation
| [**process**](./traits/process) | process manipulation
| [**os**](./traits/os) | operating system (registry, env vars, console)
| [**feat**](./traits/feat) | program layout or features

**Known tools** ([**known-tools/**](./traits/known-malware), organized by STIX 2.1 Malware Type): Identifies specific malware families and security tools.

## Trait Placement Rules (CRITICAL)

**Generic micro-behaviors NEVER go in `known-tools/`.** Only family-unique identifiers belong there.

**In `known-tools/backdoor/<family>/`:** Unique family identifiers, C2 endpoints, family-specific configuration/marker strings

**NOT in `known-tools/`:** Generic shells (`/bin/sh`), system functions (`socket`, `fork`), protocols (`SOCKS5`), crypto algorithms (`AES`), or any behavior in legitimate software. Place these in `exec/`, `comm/`, `process/`, `crypto/`, etc.

**Pattern:**
```yaml
# known-tools/backdoor/examplebot/traits.yaml
traits:
  - id: backdoor/examplebot/marker  # Malware-specific only
    if:
      type: string
      exact: "ExampleBot_v2.1"

composite_rules:
  - id: backdoor/examplebot/detected  # Reference generic traits
    all:
      - id: backdoor/examplebot/marker  # Local (malware-specific)
      - id: bin-sh                       # From exec/command/shell/
      - id: socks5-proto                 # From comm/proxy/socks/
```

**Why:** ML pipelines use trait IDs for classification. Generic traits under `backdoor/systembc/` cause false positives.

## Example File Organization

```
traits/
├── exec/command/
│   ├── traits.yaml      # Primary trait definitions
│   ├── combos.yaml      # Composite rules
│   ├── linux.yaml       # Platform-specific
│   └── python.yaml      # Language-specific
```

**Trait IDs** are short and relative to the directory. For example, within exec/command/python.yaml you may see:

```yaml
- id: py_subprocess
```

If you need to rely on this rule from a rule outside of the directory, you will need to refer to it by it's full name: exec/command/py_subprocess

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

**When in doubt:** Notable > Inert, Notable > Suspicious, Suspicious > Hostile

---

## Trait Definitions

```yaml
traits:
  - id: exec/process/terminate
    desc: Process termination via Kill()
    crit: suspicious
    confidence: 0.95
    mbc: "E1562"                  # Optional: MBC ID
    attack: "T1562"               # Optional: ATT&CK ID
    for: [csharp]
    platforms: [all]             # linux, macos, windows, unix, android, ios, all
    if:
      type: ast_pattern
      node_type: invocation_expression
      pattern: ".Kill("
```

**File types:** `all` (or `*`), `elf`, `macho`, `pe`, `dll`, `so`, `dylib`, `shell`, `python`, `javascript`, `rust`, `java`, `class`, `ruby`, `c`, `go`, `csharp`, `php`

Use `for: [*]` to override restrictive defaults and match all file types.

---

## Condition Types

### ast_pattern
Match text patterns within AST node types.

```yaml
if:
  type: ast_pattern
  node_type: invocation_expression
  pattern: "Process.Start"
  regex: false  # Optional
  case_insensitive: false  # Optional
```

**Common node types:** `invocation_expression`/`call`/`call_expression`/`method_invocation` (calls), `object_creation_expression`/`new_expression`/`composite_literal` (object creation)

### ast_query
Full tree-sitter query syntax. Optional `language` field validates syntax at load time.

```yaml
if:
  type: ast_query
  language: javascript  # Optional
  query: |
    (call_expression
      function: (member_expression
        object: (identifier) @obj
        property: (property_identifier) @method))
    (#eq? @method "exec")
```

**Supported:** `c`, `python`, `javascript`/`js`, `typescript`/`ts`, `rust`, `go`, `java`, `ruby`, `shell`/`bash`, `php`, `csharp`/`c#`

### symbol
Match function imports/exports in binaries.

```yaml
# Exact match
if:
  type: symbol
  exact: "socket"
  platforms: [linux, macos]

# Regex pattern
if:
  type: symbol
  pattern: "socket.*connect.*bind"
  platforms: [linux, macos]
```

**Note:** Avoid `"a|b|c|d"` regexes. Create separate traits and combine with composite rules (better for ML pipelines).

### string
Match strings in binaries or source. Choose one pattern type:
- `exact: "pattern"` - Substring match
- `regex: "pattern"` - Full regex
- `word: "pattern"` - Word boundary (syntactic sugar for `regex: "\bpattern\b"`)

```yaml
if:
  type: string
  exact: "http://"  # or regex/word
  case_insensitive: false  # Optional
  min_count: 1  # Optional
  exclude_patterns: ["localhost"]  # Optional
  search_raw: false  # Optional: search raw file content
```

### hex

Match hex byte patterns in binary data. Supports wildcards and gaps.

```yaml
# Simple pattern (e.g., ELF magic)
if:
  type: hex
  pattern: "7F 45 4C 46"
  offset: 0                    # Only check at file start

# With wildcards (?? = any byte)
if:
  type: hex
  pattern: "31 ?? 48 83 ?? ??"

# With gaps ([N] = skip N bytes, [N-M] = skip N to M bytes)
if:
  type: hex
  pattern: "00 03 [4] 00 04"   # Fixed 4-byte gap
  pattern: "00 03 [2-8] 00 04" # Variable 2-8 byte gap

# Search within range
if:
  type: hex
  pattern: "50 4B 03 04"       # ZIP magic
  offset_range: [0, 1024]      # Only in first 1KB
  min_count: 1
```

**Performance:** Uses YARA-style atom extraction—extracts the longest fixed byte sequence, searches for that using fast `memmem`, then verifies the full pattern only at candidate positions.

### yara / yara_match

Use sparingly (lacks contextual accuracy). Prefer splitting YARA rules into traits + composite rules. Always specify filetypes.

```yaml
# Inline
if:
  type: yara
  source: |
    rule detect_packed { strings: $upx = "UPX!" if: $upx at 0 }

# Reference
if:
  type: yara_match
  namespace: "crypto"
  rule: "sha256_hash"
```

### structure
Match structural features.

```yaml
if:
  type: structure
  feature: "executable/packed"
```

### section_name
Match section names in binary files (PE, ELF, Mach-O). This replaces YARA patterns like `for any section in pe.sections : (section.name matches /^UPX/)`.

```yaml
# Simple substring match
if:
  type: section_name
  pattern: "UPX"

# Regex match for section names
if:
  type: section_name
  pattern: "^(UPX|\.vmp)"
  regex: true
```

### imports_count / exports_count
Count imports or exports with thresholds.

```yaml
if:
  type: imports_count
  min: 10
  max: 50
  filter: "socket"
```

### syscall
Match syscalls in binaries (ELF/Mach-O via binary analysis).

```yaml
if:
  type: syscall
  name: ["socket", "connect", "execve"]  # Optional
  number: [41, 42, 59]  # Optional: arch-dependent
  arch: ["x86_64"]  # Optional
  min_count: 2  # Optional
```

### raw
Search raw file content (for source files or across string boundaries in binaries). Unlike `type: string` which searches extracted strings, this searches raw bytes.

```yaml
if:
  type: raw
  exact: "eval("  # or regex/word
  case_insensitive: false  # Optional
  min_count: 1  # Optional
```

### filesize
Match file size constraints.

```yaml
if:
  type: filesize
  min: 1000  # Optional: bytes
  max: 10485760  # Optional: bytes (10MB)
```

### trait_glob
Match multiple traits by glob pattern.

```yaml
if:
  type: trait_glob
  pattern: "xdp-*"
  match: "any"  # "any" (default), "all", or number like "3"
```

---

## Binary Analysis Conditions

For `elf`, `macho`, `pe`, `dll`, `so`, `dylib` only.

### section_entropy
Match sections by entropy (0.0-8.0). >7.0 indicates encryption/packing.

```yaml
if:
  type: section_entropy
  section: "^(\\.text|CODE)"  # Regex
  min_entropy: 7.0  # Optional
  max_entropy: 8.0  # Optional
```

### section_ratio
Check section size ratio (e.g., data section is 80%+ of binary).

```yaml
if:
  type: section_ratio
  section: "^__const"  # Regex
  compare_to: "total"  # or another section pattern
  min_ratio: 0.8  # Optional (0.0-1.0)
  max_ratio: 1.0  # Optional
```

### import_combination
Match import patterns (required + suspicious combination).

```yaml
if:
  type: import_combination
  required: ["kernel32.dll"]  # Optional: all must be present
  suspicious: ["VirtualAlloc", "WriteProcessMemory"]  # Optional
  min_suspicious: 2  # Optional
  max_total: 50  # Optional: low import count is suspicious
```

### string_count
Match total string count (for detecting string concealment).

```yaml
if:
  type: string_count
  min: 10  # Optional
  max: 100  # Optional: low count = suspicious
  min_length: 4  # Optional: only count strings >= this length
```

### metrics
Match code metrics for obfuscation/anomaly detection.

```yaml
if:
  type: metrics
  field: "identifiers.avg_entropy"  # Metric path
  min: 3.5  # Optional
  max: 5.0  # Optional
  min_size: 1000  # Optional: only apply to files >= this size
  max_size: 1000000  # Optional
```

---

## Composite Rules

Combine traits using boolean logic.

```yaml
composite_rules:
  - id: c2/reverse-shell
    desc: "Reverse shell: socket + dup2 + exec"
    crit: hostile
    conf: 0.95
    mbc: "B0022"
    attack: "T1059"
    for: [elf, macho]
    all:  # AND - all must match
      - id: comm/socket/create
      - id: process/fd/dup2
      - id: exec/shell
```

**Boolean operators:**
```yaml
all:    # AND - all must match
any:    # OR - at least one
none:   # NOT - none can match
count: 2  # N of M threshold
any: [...]
```

**Trait references:** Full path (`exec/process/terminate`), suffix match (`terminate`), or prefix (`exec/process`)

### Composites Referencing Composites

Composites can reference other composites, enabling hierarchical detection. Engine uses iterative evaluation until fixed point (max 10 iterations).

```yaml
composite_rules:
  - id: fd-redirect
    all: [socket-create, dup2-call]

  - id: reverse-shell
    crit: hostile
    all: [fd-redirect, exec-call]  # References fd-redirect composite
```

**Notes:** Circular dependencies handled gracefully (don't match). Definition order doesn't matter.

---

## Proximity Constraints

```yaml
# Same code scope (method/class/block)
scope: method
all: [...]

# Within N bytes
near: 100
all: [...]

# Within N lines
near_lines: 10
all: [...]

# Inside another trait's span
within: exec/eval
all: [...]
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
