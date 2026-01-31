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

### Composite Complexity Requirements

**HOSTILE composites require complexity ≥ 4** to maintain their criticality level. If complexity falls below 4, the composite is automatically downgraded to SUSPICIOUS.

#### What is Complexity?

Complexity measures the **structural depth** of a composite rule, not the number of matches. It's calculated based on the rule's logical structure:

**Complexity Contributions:**
- `any:` expression → **+1** complexity (regardless of how many sub-patterns it contains)
- `all:` expression → **+N** complexity (where N = number of rules in the `all:` block)
- `count_min:` / `count_max:` / `count_exact:` → same as `any:` (+1)
- `file_types:` constraint → **+1** complexity
- `filesize:` constraint → **+1** complexity
- **Recursive rules**: If you depend on a rule with an `all:`, those rules recursively add to complexity

#### Calculation Examples

**Example 1: Simple any (Complexity = 1)**
```yaml
composite_rules:
  - id: simple-trojan
    crit: hostile          # Requires complexity >= 4
    any:                   # +1 complexity
      - id: pattern-a
      - id: pattern-b
      - id: pattern-c
```
**Complexity**: 1 (just the `any:`)
**Result**: Downgraded to SUSPICIOUS (1 < 4)

**Example 2: Multiple all constraints (Complexity = 3)**
```yaml
composite_rules:
  - id: better-trojan
    crit: hostile
    all:                   # +3 complexity (3 rules in all:)
      - id: pattern-a
      - id: pattern-b
      - id: pattern-c
```
**Complexity**: 3
**Result**: Still downgraded to SUSPICIOUS (3 < 4)

**Example 3: Combined structure (Complexity = 4)**
```yaml
composite_rules:
  - id: good-trojan
    crit: hostile
    file_types: [javascript]  # +1 complexity
    all:                       # +3 complexity (3 rules)
      - id: pattern-a
      - id: pattern-b
      - id: pattern-c
```
**Complexity**: 4 (1 + 3)
**Result**: Remains HOSTILE ✓

**Example 4: Mixed structure (Complexity = 3)**
```yaml
composite_rules:
  - id: mixed-trojan
    crit: hostile
    all:                   # +2 complexity (2 rules in all:)
      - id: pattern-a
      - id: pattern-b
    any:                   # +1 complexity
      - id: pattern-c
      - id: pattern-d
```
**Complexity**: 3 (2 + 1)
**Result**: Downgraded to SUSPICIOUS (3 < 4)

#### Recursive Complexity

When a composite references another composite with `all:`, the referenced rules add to parent complexity:

```yaml
composite_rules:
  - id: string-deobfuscation
    all:                           # Has 3 rules
      - id: charAt-pattern
      - id: swap-pattern
      - id: join-pattern

  - id: advanced-trojan
    crit: hostile
    all:
      - id: string-deobfuscation   # +3 (recursive from all: above)
      - id: eval-pattern           # +1
```
**Complexity**: 4 (3 from recursive + 1 direct)
**Result**: Remains HOSTILE ✓

#### Match Count vs Complexity

**Important**: `count_min:` controls **how many patterns must match**, while complexity controls **structural depth**.

```yaml
composite_rules:
  - id: example
    crit: hostile
    count_min: 3           # Need 3+ patterns to match (matching requirement)
    any:                   # +1 complexity (structural depth)
      - id: pattern-a
      - id: pattern-b
      - id: pattern-c
      - id: pattern-d
      - id: pattern-e
```

If 5 patterns match:
- Match requirement: ✅ PASS (5 ≥ 3)
- Complexity: 1 (just the `any:`)
- Result: ❌ Downgraded to SUSPICIOUS (1 < 4)

To fix: Use `all:` instead or add constraints:
```yaml
composite_rules:
  - id: example-fixed
    crit: hostile
    file_types: [javascript]  # +1
    count_min: 3               # Matching requirement
    any:                       # +1
      - id: pattern-a
      - id: pattern-b
      - id: pattern-c
    all:                       # +2 (two required patterns)
      - id: required-1
      - id: required-2
```
**Complexity**: 4 (1 + 1 + 2)
**Result**: Remains HOSTILE ✓

#### Complexity Thresholds by Criticality

| Criticality | Minimum Complexity |
|-------------|-------------------|
| `inert`     | No requirement (any) |
| `notable`   | No requirement (any) |
| `suspicious`| No requirement (any) |
| `hostile`   | **4 or higher** |

#### Rationale

HOSTILE classification indicates attack patterns with "no legitimate use" (malware, trojans, ransomware). A complexity threshold of 4 ensures that:

1. **High confidence**: Multiple independent indicators confirm malicious intent
2. **Low false positives**: Legitimate code rarely triggers 4+ malware indicators
3. **Defense in depth**: Single failed pattern doesn't prevent detection
4. **Evidence strength**: More matched patterns = stronger case for malicious classification

#### Debugging Complexity Issues

If a HOSTILE composite is being downgraded:

```
⚠️  WARNING: Composite trait 'my-trojan' is marked HOSTILE but has
complexity 2 (need >=4). Downgrading to SUSPICIOUS.
```

**Diagnosis steps:**

1. **Check how many patterns matched**:
   ```bash
   # Look for traits in the same category
   dissect analyze file.js | grep "category-name"
   ```

2. **Verify sub-patterns work individually**:
   ```bash
   # Create minimal test files
   echo 'pattern_code_here' > test.js
   dissect analyze test.js
   ```

3. **Use symbols/strings subcommands to see what's extracted**:
   ```bash
   dissect symbols file.js    # See AST-extracted symbols
   dissect strings file.js    # See AST-extracted strings
   ```

4. **Review pattern definitions**: Ensure `type: symbol` patterns match extracted symbols exactly, or `type: content` regex patterns are correct

**Solutions:**

- **Option A**: Fix non-matching sub-patterns (recommended)
- **Option B**: Reduce `count_min:` requirement so more variations match
- **Option C**: Add `file_types:` or `filesize:` constraints to increase structural complexity
- **Option D**: Convert `any:` to `all:` for required patterns (increases complexity significantly)
- **Option E**: Accept SUSPICIOUS classification as adequate
- **Option F**: Add more `all:` constraints with reliable patterns

---

### Count Operators (Matching Requirements)

Use these to control how many patterns must match within an `any:` block:

```yaml
# count_min: At least N patterns must match
composite_rules:
  - id: example-min
    count_min: 3    # Need 3 or more
    any:
      - id: pattern-a
      - id: pattern-b
      - id: pattern-c
      - id: pattern-d

# count_max: At most N patterns can match
  - id: example-max
    count_max: 2    # Need 2 or fewer
    any:
      - id: pattern-a
      - id: pattern-b
      - id: pattern-c

# count_exact: Exactly N patterns must match
  - id: example-exact
    count_exact: 2  # Need exactly 2
    any:
      - id: pattern-a
      - id: pattern-b
      - id: pattern-c

# Can combine min and max
  - id: example-range
    count_min: 2
    count_max: 4    # Between 2 and 4 (inclusive)
    any:
      - id: pattern-a
      - id: pattern-b
      - id: pattern-c
      - id: pattern-d
      - id: pattern-e
```

**Note**: The deprecated `count: N` syntax (equivalent to `count_min: N`) should not be used in new rules.

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
      type: ast
      kind: call
      exact: ".Kill("
```

The description field should be short and clear: try to describe the capability in 4 or less words. 5 words maximum. The more words used, the more work an engineer has to do to scan through the text.

**File types:** `all` (or `*`), `elf`, `macho`, `pe`, `dll`, `so`, `dylib`, `shell`, `python`, `javascript`, `rust`, `java`, `class`, `ruby`, `c`, `go`, `csharp`, `php`

Use `for: [*]` to override restrictive defaults and match all file types.

---

## Condition Types

### ast

Match patterns in parsed source code (AST). Two modes: simple (recommended) and advanced.

#### Simple Mode: `kind` + `exact`/`regex`

Use abstract `kind` names—we map to language-specific node types internally.

```yaml
# Substring match
if:
  type: ast
  kind: call
  exact: "eval"

# Regex match
if:
  type: ast
  kind: call
  regex: "eval\\(.*\\)"
  case_insensitive: false  # Optional
  count_min: 1             # Optional: minimum matches
```

#### Kind Reference

| Kind | Matches | Examples |
|------|---------|----------|
| `call` | Function/method calls | `eval()`, `os.system()`, `require()` |
| `function` | Function definitions | `def foo():`, `function bar()`, `func main()` |
| `class` | Class definitions | `class Foo:`, `class Bar {}` |
| `import` | Import statements | `import os`, `require('fs')`, `#include` |
| `string` | String literals | `"hello"`, `'world'`, `` `template` `` |
| `comment` | Comments | `# note`, `// todo`, `/* block */` |
| `assignment` | Variable assignments | `x = 1`, `let y = 2`, `var z` |
| `argument` | Function arguments | args in `foo(x, y)` |
| `return` | Return statements | `return x`, `return;` |
| `binary_op` | Binary operations | `a + b`, `x && y`, `i < n` |
| `identifier` | Names/identifiers | variable names, function names |
| `attribute` | Attribute/member access | `obj.attr`, `foo.bar()` |
| `subscript` | Index access | `arr[0]`, `dict["key"]` |
| `conditional` | If/ternary | `if x:`, `x ? y : z` |
| `loop` | Loops | `for`, `while`, `do` |

#### Advanced Mode: `query`

Full tree-sitter S-expression syntax for complex structural matching.

```yaml
if:
  type: ast
  query: |
    (call_expression
      function: (member_expression
        object: (identifier) @obj
        property: (property_identifier) @method))
    (#eq? @method "exec")
  language: javascript  # Optional: validates at load time
```

**When to use:** Complex structural patterns, capture groups, predicates (`#eq?`, `#match?`).

**Supported languages:** `c`, `python`, `javascript`/`js`, `typescript`/`ts`, `rust`, `go`, `java`, `ruby`, `shell`/`bash`, `php`, `csharp`/`c#`

#### Raw Node Type (escape hatch)

For tree-sitter experts needing exact node types:

```yaml
if:
  type: ast
  node: call_expression    # Raw tree-sitter node type
  regex: "eval\\("
```

### symbol

Match function imports/exports in binaries or source code.

```yaml
# Exact match
if:
  type: symbol
  exact: "socket"
  platforms: [linux, macos]

# Regex pattern
if:
  type: symbol
  regex: "socket.*connect.*bind"
  platforms: [linux, macos]
```

You can use `dissect symbols <file>` to see what symbols are extracted from a program.

**Note:** Avoid `"a|b|c|d"` regexes. Create separate traits and combine with composite rules (better for ML pipelines).

**Backward compatibility:** The deprecated `pattern:` field is still accepted as an alias for `regex:`.

### string

Match extracted strings. Choose one pattern type:
- `contains: "pattern"` - Substring match
- `exact: "pattern"` - Full string match (entire string must equal)
- `regex: "pattern"` - Regular expression
- `word: "pattern"` - Word boundary (`\bpattern\b`)

```yaml
if:
  type: string
  contains: "http://"  # or exact/regex/word
  min_count: 1  # Optional
  case_insensitive: false  # Optional
```

**String extraction:**
- **Source:** AST parsing extracts only string literals (no comments/code)
- **Binaries:** stng extracts ASCII/UTF-8/UTF-16 strings
- Preview: `dissect strings <file>`

**For raw file content:** Use `type: content` (less precise).

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

### content

Searches raw file bytes instead of extracted strings. Less precise.

```yaml
if:
  type: content
  contains: "eval("  # or exact/regex/word
  case_insensitive: false  # Optional
  min_count: 1  # Optional
```

**Use sparingly:** Cross-boundary patterns, packed/obfuscated files. Prefer `type: string`.

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

# Threshold operators (use with any:)
count_min: 2   # At least N must match
count_max: 4   # At most N can match
count_exact: 3 # Exactly N must match
any: [...]
```

You can combine all: and any: directives within the same rule.

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

## Exception and Context Directives

Traits support three directives for filtering and context-aware behavior:

### `not:` - String-Level Exceptions

Filter matched strings from evidence. Use to exclude known-benign patterns.

**Syntax:**
- Bare strings default to case-insensitive substring match
- Explicit: `exact:` (full match), `contains:` (substring), `regex:` (pattern)

**Example:**
```yaml
- id: hardcoded-domain
  if:
    type: string
    regex: "\\b[a-z0-9]+\\.(com|org)\\b"
  not:
    - "apple.com"           # Shorthand: contains (case-insensitive)
    - exact: "github.com"   # Full string must match exactly
    - regex: "^192\\.168\\." # Private IP range
```

**Use cases:** Exclude known-legitimate strings, filter false positives, clean evidence.

---

### `unless:` - File-Level Skip

Skip entire trait if conditions match. Use for context-aware filtering.

**Syntax:**
- List of conditions (default 'any' semantics: skip if ANY matches)
- Can reference other traits via `{ id: trait-name }`

**Example:**
```yaml
- id: network-connect
  crit: suspicious
  if:
    type: symbol
    pattern: "connect"
  unless:
    - id: file/path/system-binary
    - id: compiler/go
```

**When to use:**
- Skip traits for system binaries (lower false positives)
- Exclude specific file types (configs, tests, mocks)
- Context-aware filtering based on other detected traits

---

### `downgrade:` - Context-Based Criticality

Reduce criticality level based on file context. Use when behavior is less concerning in specific contexts.

**Syntax:**
- Map of target criticality levels to composite conditions
- Levels: `hostile`, `suspicious`, `notable`, `inert`
- First matching level (in severity order) wins
- Can only downgrade (not upgrade) from base `crit`

**Example:**
```yaml
- id: suspicious-curl-pipe
  crit: suspicious
  if:
    type: string
    regex: "curl.*\\|.*bash"
  downgrade:
    notable:
      any:
        - id: file/type/shell-script
        - id: file/signed/apple
    inert:
      any:
        - id: file/type/zsh-history
        - id: file/path/test-fixtures
```

**When to use:**
- Lower severity for signed/trusted binaries
- Reduce noise from shell history files
- Context-aware risk assessment (tests vs production)

**Validation:** Tool warns if downgrade level >= base criticality (likely configuration error).

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

---

## Debugging Rules with `test-rules`

The `test-rules` command provides detailed debugging output for understanding why rules match or fail. This is essential for:
- Understanding why a composite rule doesn't trigger
- Debugging regex patterns that don't match
- Verifying complexity requirements are met
- Investigating false negatives

### Usage

```bash
dissect test-rules <FILE> --rules "rule1,rule2,rule3"
```

### Example Output

```
NOT MATCHED lateral/supply-chain/npm/obfuscated-trojan (composite)
  Obfuscated supply-chain trojan
  Requirements: all: 3 conditions

  Context: file_type=JavaScript, platform=All
  Strings: 28, Symbols: 8, Imports: 8, Exports: 0, Findings: 81

  Conditions:
    ✗ all: (1/3)
      ✗ trait: anti-static/obfuscation/code-metrics
          Trait 'anti-static/obfuscation/code-metrics' not found in definitions
      ✓ trait: anti-static/obfuscation/strings/js-version-marker
          Found in findings with 2 evidence items
      ✗ trait: anti-static/obfuscation/strings/js-charat-loop
          Trait did not match
        ✗ symbol: regex: /.*\.charAt/
            Total symbols: 8 (8 imports, 0 exports)
            Matching symbols: 0
            All symbols:
              "os.userInfo"
              "cp.exec"
              ...


MATCHED anti-static/obfuscation/strings/js-version-marker (trait)
  Malware version tracking pattern
  Requirements: Condition: string[regex]: /^[0-9]+-[a-z]{3,15}[0-9]{1,4}$/

  Context: file_type=JavaScript, platform=All
  Strings: 28, Symbols: 8, ...

  Conditions:
    ✓ string: regex: /^[0-9]+-[a-z]{3,15}[0-9]{1,4}$/ (min_count: 1)
        Total strings in file: 28
        Matching strings: 2
          Matched: "7-randuser84"
```

### What the Output Shows

1. **Match status** - `MATCHED` (green) or `NOT MATCHED` (red)
2. **Rule type** - `trait` (atomic pattern) or `composite` (combined patterns)
3. **Requirements** - What the rule expects (e.g., "all: 3 conditions")
4. **Context info** - File type, platform, counts of strings/symbols/findings
5. **Detailed condition evaluation**:
   - For composites: which `all`/`any`/`none` conditions matched
   - For string/symbol conditions: the regex pattern, match count, and matches
   - For trait references: whether the trait matched, and if not, why not
6. **Debug hints** - When strings/symbols are ≤20, lists them all for debugging

### Common Debugging Scenarios

**Regex doesn't match expected symbols:**
```bash
dissect test-rules file.js --rules "my-trait-with-symbol-match"
```
The output shows all extracted symbols, allowing you to verify:
- If the symbol exists in the file
- If the regex pattern is correct
- If the symbol format differs (e.g., `require.exec` vs `exec`)

**Composite complexity too low:**
```bash
dissect test-rules file.js --rules "my-hostile-composite"
```
Check the Requirements line - it shows complexity breakdown:
- `all: N conditions` → +N complexity
- `any: M conditions` → +1 complexity
- `file_types: [...]` → +1 complexity

**Trait not found:**
If you see "Trait 'X' not found in definitions", verify:
- The trait ID is spelled correctly
- The trait is defined in a loaded YAML file
- There are no typos in the path prefix

### Tips

- Use with comma-separated IDs to debug multiple related rules at once
- Works for both traits and composite rules
- Shows exactly what was extracted (strings, symbols) so you can tune your patterns
- Displays the regex pattern being used, making it easier to spot escaping issues
---

## Testing Pattern Matching with `test-match`

The `test-match` command allows you to test ad-hoc pattern matching against a file without creating a rule. This is useful for:
- Quickly verifying if a pattern exists in a file
- Determining the best search type (string, symbol, or content) for a pattern
- Finding the optimal match method (exact, contains, regex, or word)
- Testing how file type detection affects pattern matching

### Usage

```bash
dissect test-match <FILE> --type <TYPE> --method <METHOD> --pattern "<PATTERN>"
```

**Parameters:**
- `--type`: Search type - `string`, `symbol`, or `content` (default: string)
- `--method`: Match method - `exact`, `contains`, `regex`, or `word` (default: contains)
- `--pattern`: The pattern to search for (required)
- `--file-type`: Force a specific file type for analysis (e.g., `elf`, `pe`, `macho`, `java-script`, `python`, `go`, `shell`, `raw`)
- `--min-count`: Minimum matches required for string searches (default: 1)
- `--case-insensitive`: Enable case-insensitive matching

### Example Output

When a search fails, `test-match` provides intelligent suggestions:

```
NOT MATCHED
Total symbols: 3 (2 imports, 0 exports)

Suggestions:
  💡 Found in strings (2 substring matches) - try `--type string --method contains`
  💡 Found in content - try `--type content`

  Try different match methods:
    --method contains (substring match)
    --method regex (pattern match)

  File type analysis:
    Current file type: Go
    💡 Would match if file type was: ELF (strings: 106, symbols: 0)
```

### Common Use Cases

**Test if a symbol exists:**
```bash
dissect test-match binary.exe --type symbol --method exact --pattern "CreateProcessW"
```

**Find patterns in strings:**
```bash
dissect test-match script.js --type string --method regex --pattern "password.*="
```

**Search raw file content:**
```bash
dissect test-match malware.bin --type content --method contains --pattern "http://"
```

**Test word boundaries:**
```bash
dissect test-match code.py --type string --method word --pattern "exec"
```

**Force a specific file type:**
```bash
dissect test-match file.bin --type string --method contains --pattern "MZ" --file-type pe
```

### Tips

- Start with `--method contains` for substring matching, then refine to `exact` or `regex`
- Use `--type content` to search the raw binary data (useful for packed or obfuscated files)
- Pay attention to the file type suggestions - some patterns may only be extractable when analyzed as a specific file type
- Combine with `--case-insensitive` for broader pattern matching
- Use `--file-type` to override auto-detection and see how analysis differs across file types
