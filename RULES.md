# DISSECT Rule Writing Guide

## Philosophy

**Traits are atomic observations.** A single detectable pattern: a symbol, string, or AST node.

**Composite rules are behavioral interpretations.** Traits combined to describe capabilities: reverse shell = `socket + dup2 + exec`.

**Criticality is independent of confidence.** A socket import is certain (confidence: 1.0) but benign (inert). A Telegram API match is uncertain (confidence: 0.8) but hostile.

## Taxonomy

Most rules follow the organization of `objective/capability/kind`, inspired by the MalwareBehaviorCatalog, even if the capability isn't malicious, but could be performed by a malicious program. Since this is static analysis, we don't know what the true "behavior" of a program is, only it's capabilities.

* An **objective** is what a program could achieve
* A **capability** is how the program could achieve it
* A **kind** is a specific implementation of that capability

Here's the objectives taxonomy:

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

The "kind" directory should be granular enough that supply-chain attacks are obvious when you diff the list of new traits, but not so granular that code refactors would cause a diff.

We also support a seperate hierarchy of non-objective based micro-traits, which gets split based on: category/subcategory/kind/ - based on MBC MicroBehaviors

|**Micro-trait**|**description**|
|---|---|
| [**comm**](./traits/comm) | communications (generally networking)
| [**crypto**](./traits/crypto) | cryptography (not cryptomining)
| [**data**](./traits/data) | data manipulation
| [**fs**](./traits/fs) | filesystem manipulation
| [**hw**](./traits/hw) | hardware manipulation
| [**mem**](./traits/mem) | memory manipulation
| [**process**](./traits/process) | process manipulation
| [**os**](./traits/os) | operating system manipulation (registry access, env vars, console)
| [**feat**](./traits/feat) | the layout or features of a program

To help security engineers, we also have rules to identify of a limited number of popular malware families and security tools within the [**known-tools**](./traits/known-malware) directory (organized by STIX 2.1 Malware Type). Identifying malware by family is not a focus area for this project, but sometimes it's nice to have.

## Trait Placement Rules (CRITICAL)

**Generic micro-behaviors must NEVER be placed in `known-tools/` directories.** The `known-tools/` hierarchy is ONLY for traits that are unique to a specific malware family or tool.

### What belongs in `known-tools/backdoor/<family>/`:
- Unique malware family identifiers (e.g., `"systembc"`, `"melofee"`)
- Family-specific C2 endpoints or domains
- Unique configuration strings only found in that malware
- Family-specific marker strings

### What does NOT belong in `known-tools/`:
- Generic shell paths (`/bin/sh`, `/bin/bash`) → use `exec/command/shell/`
- Common system functions (`popen`, `socket`, `fork`) → use `exec/`, `comm/`, `process/`
- Protocol strings (`SOCKS5`, `HTTP`) → use `comm/proxy/`, `comm/http/`
- Encryption algorithms (`RC4`, `AES`) → use `crypto/`
- Any behavior that could appear in legitimate software

### Correct Pattern for `known-tools/`:

```yaml
# In known-tools/backdoor/examplebot/traits.yaml

traits:
  # ONLY malware-specific identifiers belong here
  - id: backdoor/examplebot/marker
    desc: ExampleBot unique identifier string
    crit: notable
    conf: 0.9
    condition:
      type: string
      exact: "ExampleBot_v2.1"

composite_rules:
  # Composite rules REFERENCE generic traits from proper locations
  - id: backdoor/examplebot/detected
    description: ExampleBot backdoor detected
    crit: hostile
    all:
      - type: trait
        id: backdoor/examplebot/marker  # Malware-specific (local)
      - type: trait
        id: bin-sh                       # Generic trait from exec/command/shell/
      - type: trait
        id: socks5-proto                 # Generic trait from comm/proxy/socks/
```

**Why this matters:** ML pipelines use trait IDs for classification. If `/bin/sh` is placed under `backdoor/systembc/bin-sh`, any program using `/bin/sh` would be flagged as potentially having SystemBC backdoor components, causing massive false positives.

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

Use `*` to explicitly override a restrictive default and match all file types:
```yaml
defaults:
  for: [elf, macho]  # Restrictive default for most rules

traits:
  - id: some-string-pattern
    for: [*]  # Override: this string can appear in any file type
    if:
      type: string
      exact: "suspicious.domain.com"
```

---

## Condition Types

### ast_pattern
Match text patterns within AST node types.

```yaml
if:
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
if:
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
if:
  type: symbol
  pattern: "socket.*connect.*bind"    # Regex
  platforms: [linux, macos]
```

NOTE: avoid using regexes like "a|b|c|d" to match multiple possible strings. Instead, make traits for each string and use composite rules to bring them together. These tiny traits easier to analyze using ML pipelines.

### string
Match strings in binaries or source.

```yaml
if:
  type: string
  exact: "http://"                  # Substring match
  # OR regex: "https?://[^/]+"     # Regex match
  # OR word: "socket"               # Word boundary match (same as regex: "\bsocket\b")
  case_insensitive: false
  min_count: 1
  exclude_patterns: ["localhost"]
  search_raw: false                 # Search raw file content
```

**Pattern options (choose one):**
- `exact: "pattern"` - Substring match (finds "pattern" anywhere)
- `regex: "pattern"` - Full regex match
- `word: "pattern"` - Word boundary match (finds "pattern" only as whole word)

The `word` field is syntactic sugar for `regex: "\bpattern\b"` with automatic escaping.

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

Inline YARA or reference existing matches.

YARA should be used sparingly due to its lack of contextual accuracy (symbols, go-string support), and only when it's not possible to define otherwise. Never use YARA just to tie strings together unless it's in a way unsupported by the composite rule language - and even then, consider improving the language, or splitting up the YARA rules and bringing them together using a composite rule.

YARA rules should always have filetypes associated to them.

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

---

## Binary Analysis Conditions

For `elf`, `macho`, `pe`, `dll`, `so`, `dylib` only.

### binary
Match binary header properties.

```yaml
if:
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
if:
  type: entropy
  section: "^(\\.text|CODE)"
  min: 7.0
```

### function_metrics
Match functions by complexity.

```yaml
if:
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
    desc: "Reverse shell: socket + dup2 + exec"
    crit: hostile
    confidence: 0.95
    mbc: "B0022"
    attack: "T1059"
    for: [elf, macho]

    all:                   # AND
      - ...
```

### Boolean Operators

```yaml
all:    # AND - all must match
any:    # OR - at least one must match
none:   # NOT - none can match

# N of M
count: 2
any:
  - type: trait
    id: crypto/aes
  - type: trait
    id: crypto/rsa
  - type: trait
    id: crypto/xor
```

### Trait References

When referring to a trait from another category, you specify it based on group name (directory):

```yaml
- type: trait
  id: exec/process/terminate
```

For relative trait references, use the short name:

```
- type: trait
  id: terminate                    # Suffix match
```

It is intentionally not possible to reference an exact trait in another directory.

### Composites Referencing Composites

Composite rules can reference other composite rules, enabling multi-level detection chains. The evaluation engine uses **iterative evaluation** to resolve dependencies:

1. Evaluate all composites against current findings
2. Add newly matched composites to the findings
3. Repeat until no new findings (fixed point)

This allows building hierarchical detection patterns:

```yaml
# Level 1: Atomic traits detect basic capabilities
traits:
  - id: socket-create
    if:
      type: symbol
      pattern: "socket
  - id: dup2-call
    if: {type: symbol, pattern: "dup2"}
  - id: exec-call
    if: {type: symbol, pattern: "execve"}

composite_rules:
  # Level 2: Combine atomics into behavioral pattern
  - id: fd-redirect
    desc: "File descriptor redirection"
    all:
      - {type: trait, id: socket-create}
      - {type: trait, id: dup2-call}

  # Level 3: Reference composite to build higher-level detection
  - id: reverse-shell
    desc: "Reverse shell pattern"
    crit: hostile
    all:
      - {type: trait, id: fd-redirect}  # References composite!
      - {type: trait, id: exec-call}
```

**Notes:**
- Circular dependencies are handled gracefully (they simply don't match)
- Maximum 10 iterations prevents infinite loops
- Order of rule definitions doesn't matter—dependencies resolve automatically

---

## Proximity Constraints

### scope (Source Code)
Require traits within the same code scope.

```yaml
scope: method              # method, class, or block
all:
  - type: trait
    id: exec/reflection/assembly-load
  - type: trait
    id: exec/reflection/invoke
```

### near (Bytes)
Require patterns within N bytes.

```yaml
near: 100
all:
  - type: string
    regex: "socket"
  - type: string
    regex: "\\d+\\.\\d+\\.\\d+\\.\\d+"
```

### near_lines (Lines)
Require patterns within N lines.

```yaml
near_lines: 10
all:
  - type: trait
    id: exec/process/start
  - type: trait
    id: fs/file/delete
```

### within (Containment)
Require traits inside another trait's span.

```yaml
within: exec/eval
all:
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
