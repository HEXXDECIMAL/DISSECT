# DISSECT Rule Writing Guide

## Quick Overview

**Traits** = atomic observations (single pattern)
**Composites** = traits combined via boolean logic
**Criticality** = independent from confidence (1.0 certain but inert socket vs 0.8 uncertain but hostile Telegram API)

See [TAXONOMY.md](./TAXONOMY.md) for the complete tier structure and directory organization.

**Three-tier hierarchy:**
- `cap/*` - Observable capabilities (what code can do)
- `obj/*` - Attacker objectives (what code likely wants to do)
- `known/*` - Specific malware/tool signatures
- `meta/*` - Informational file properties

## Trait Placement

- Generic capabilities NEVER go in `known/` - only family-unique signatures there
- IDs are auto-prefixed by directory
- Cross-tier references use full paths: `cap/exec/shell/subprocess`
- Cross-directory match: `cap/exec/shell/` matches all in directory

## Criticality Levels

| Level | Use When |
|-------|----------|
| `inert` | Universal baseline (`open()`, `read()`, `malloc()`) |
| `notable` | Defines program purpose (`socket()`, `exec()`, `eval()`) |
| `suspicious` | Hides intent/crosses boundaries (VM detection, obfuscation) |
| `hostile` | Attack patterns, no legitimate use (reverse shell, ransomware) |

**HOSTILE composites require complexity ≥ 4**, else downgraded to SUSPICIOUS. Complexity: `any:` (+1), `all:` (+N), `file_types:`/`size_min:`/`size_max:` (+1 each).

## Trait Definition Fields

```yaml
traits:
  - id: exec/process/terminate          # Trait ID (relative to directory)
    desc: Process termination API call   # 4-6 words: what was detected, not why it's suspicious
    crit: suspicious                     # inert, notable, suspicious, hostile
    conf: 0.95                           # Confidence (0.0-1.0)
    mbc: "E1562"                         # Optional MBC code
    attack: "T1562"                      # Optional ATT&CK code
    for: [csharp]                        # File types: elf, macho, pe, dll, so, dylib, shell, python, javascript, rust, java, class, ruby, c, go, csharp, php, packagejson, chrome-manifest, cargo-toml, pyproject-toml, github-actions, composer-json, all
    platforms: [all]                     # linux, macos, windows, unix, all
    size_min: 1000                       # Minimum file size (bytes, optional)
    size_max: 10485760                   # Maximum file size (bytes, optional)
    if:                                  # Condition (see Condition Types section)
      type: ast
      kind: call
      exact: ".Kill("
```

Descriptions: concrete, 4-6 words, describe the observation (not the judgment).

## Condition Types Reference

**ast** - Parse source code. Kinds: call, function, class, import, string, comment, assignment, argument, return, binary_op, identifier, attribute, subscript, conditional, loop. Match with: `exact:`, `regex:`, or `query:` (tree-sitter).

**symbol** - Function imports/exports. Match with: `exact:`, `regex:`. Preview: `dissect symbols <file>`.

**string** - Extracted strings. Match with: `substr:`, `exact:`, `regex:`, `word:`. Modifiers: `min_count:`, `case_insensitive:`, `exclude_patterns:` (filter matches). Location: `section:`, `offset:`, `offset_range:`. Preview: `dissect strings <file>`.

**hex** - Byte patterns. Syntax: `7F 45 4C 46` (literals), `??` (any byte), `[N]` (skip N), `[N-M]` (gap range). Optional: `offset:`, `offset_range:`, `min_count:`, `extract_wildcards:`.

**content** - Raw file bytes. Match with: `substr:`, `exact:`, `regex:`. Location: `section:`, `offset:`, `offset_range:`. (Less precise than string.)

**kv** - Structured key-value data in JSON, YAML, and TOML manifests. Path syntax: `key`, `a.b.c` (nested), `[0]` (index), `[*]` (wildcard). Match with: `exact:`, `substr:`, `regex:`. Optional: `case_insensitive:`. Path-only = existence check. Useful for: `package.json` (npm), `manifest.json` (Chrome extensions), `Cargo.toml` (Rust), `pyproject.toml` (Python), GitHub Actions workflows, Docker Compose files.

**yara** - Yara rules. Use sparingly; prefer traits + composites.

**basename** - Filename match. Match with: `exact:`, `substr:`, `regex:`. Optional: `case_insensitive:`.

**trait_glob** - Match traits by pattern. Fields: `pattern:`, `match:` (any/all/number).

**base64** - Base64-decoded strings. Match with: `substr:`, `exact:`, `regex:`, `word:`. Modifiers: `min_count:`, `case_insensitive:`. Location: `section:`, `offset:`, `offset_range:`.

**xor** - XOR-decoded strings (with optional key). Match with: `substr:`, `exact:`, `regex:`, `word:`. Modifiers: `min_count:`, `case_insensitive:`. Location: `section:`, `offset:`, `offset_range:`.

**syscall** - Direct syscall usage patterns. Match with: `exact:`, `regex:`.

**section_name** - Binary section name matching. Match with: `exact:`, `substr:`, `regex:`. Optional: `case_insensitive:`.

**layer_path** - String encoding layer path matching. Match with: `exact:`, `regex:`.

**Binary-only** (elf/macho/pe): `section_entropy`, `section_ratio`, `import_combination`, `metrics`.

## Composite Rules

Combine traits with boolean logic (all/any/none). Example:

```yaml
composite_rules:
  - id: reverse-shell
    desc: Reverse shell pattern
    crit: hostile
    conf: 0.95
    for: [elf, macho]
    all:                              # AND
      - id: cap/comm/socket/create
      - id: cap/process/fd/dup2
      - id: cap/exec/shell
    any:                              # OR
      - id: pattern-a
      - id: pattern-b
    none:                             # NOT
      - id: legitimate-use
```

Composites can reference other composites. Circular dependencies are handled.

## Exception/Modifier Directives

**`not:`** - Filter matched strings. Match with: `exact:`, `regex:`, or substring.

**`unless:`** - Skip trait if condition matches. Accepts trait refs or inline conditions.

**`downgrade:`** - Reduce criticality one level if condition matches. Chain: hostile→suspicious→notable→inert.

**Proximity** - `near_bytes:` (evidence within N bytes), `near_lines:` (evidence within N lines).

**Counts** - `needs:` N (minimum from `any:` operator that must match).

## Count and Density Constraints

These constraints are available on `string`, `content`, `hex`, `base64`, and `xor` condition types:

| Field | Type | Description |
|-------|------|-------------|
| `count_min` | int | Minimum number of matches required (default: 1). Alias: `min_count` (deprecated). |
| `count_max` | int | Maximum number of matches allowed. Fails if exceeded. |
| `per_kb_min` | float | Minimum matches per kilobyte of file size (density floor). |
| `per_kb_max` | float | Maximum matches per kilobyte of file size (density ceiling). |

**Examples:**

```yaml
# Require at least 5 occurrences of "error"
- id: many-errors
  if:
    type: string
    substr: "error"
    count_min: 5

# Detect excessive base64 strings (obfuscation indicator)
- id: excessive-base64
  if:
    type: string
    regex: "^[A-Za-z0-9+/]{20,}={0,2}$"
    per_kb_min: 0.5    # At least 0.5 matches per KB

# Flag if too many IP-like patterns (C2 indicator)
- id: suspicious-ip-density
  if:
    type: content
    regex: "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
    count_min: 3       # At least 3 matches
    count_max: 50      # But not more than 50 (would be config file)

# Detect high-density hex patterns (shellcode)
- id: shellcode-density
  if:
    type: hex
    pattern: "90 90 90"   # NOP sled
    per_kb_min: 0.1       # High density indicates padding
    per_kb_max: 10.0      # But not entire file of NOPs
```

**Density Calculation:** `density = match_count / (file_size_bytes / 1024.0)`

## Location Constraints (Binary Section/Offset Filtering)

YARA-style location constraints allow you to restrict where patterns are searched within binary files. Available on `string`, `content`, `base64`, and `xor` condition types.

| Field | Type | Description |
|-------|------|-------------|
| `section` | string | Restrict search to named section. Supports fuzzy names (e.g., `text` matches `.text`, `__text`, `__TEXT,__text`). |
| `offset` | int | Search only at exact file offset. Negative values count from end (e.g., `-1024` = last 1024 bytes). |
| `offset_range` | [int, int?] | Search within byte range `[start, end)`. Use `null` for open-ended: `[-1024, null]` = last 1024 bytes to EOF. |
| `section_offset` | int | Offset relative to section start (requires `section`). |
| `section_offset_range` | [int, int?] | Range relative to section start (requires `section`). |

**Validation Rules:**
- `offset` and `offset_range` are mutually exclusive
- `section_offset` and `section_offset_range` are mutually exclusive
- `section_offset`/`section_offset_range` require `section` to be specified

**Fuzzy Section Names:**
| Fuzzy Name | Matches |
|------------|---------|
| `text` | `.text`, `__text`, `__TEXT,__text` |
| `data` | `.data`, `__data`, `__DATA,__data` |
| `rodata` | `.rodata`, `.rdata`, `__const`, `__DATA,__const`, `__TEXT,__const` |
| `bss` | `.bss`, `__bss`, `__DATA,__bss` |

**Examples:**

```yaml
# Search for magic bytes only in .text section
- id: shellcode-in-text
  if:
    type: content
    substr: "\x90\x90\x90\x90"
    section: text

# Search first 4KB of file for header patterns
- id: custom-header
  if:
    type: string
    substr: "MAGIC"
    offset_range: [0, 4096]

# Search last 1KB for trailer/footer
- id: custom-footer
  if:
    type: string
    substr: "END"
    offset_range: [-1024, null]

# Search first 512 bytes of .data section
- id: config-at-data-start
  if:
    type: string
    substr: "CONFIG="
    section: data
    section_offset_range: [0, 512]

# Exact offset match (e.g., PE header location)
- id: pe-signature
  if:
    type: content
    exact: "PE\x00\x00"
    offset: 0x3c

# Combine with density (matches per KB within the constrained range)
- id: dense-strings-in-rodata
  if:
    type: string
    regex: "[A-Za-z]{10,}"
    section: rodata
    per_kb_min: 5.0
```

**Notes:**
- When location constraints are specified, density calculations (`per_kb_min`/`per_kb_max`) use the effective range size, not full file size
- Location constraints add precision to the match (section: +1.0, offset: +1.5, ranges: +1.0)
- For non-binary files, section constraints are ignored (full file is searched)

## Reference Codes

- **ATT&CK**: `T1234` (technique) or `T1234.001` (sub-technique)
- **MBC**: `B0001` (behavior), `C0015` (micro-behavior), `E1234` (ATT&CK+MBC)

## KV Condition Examples (Manifest Analysis)

The `kv` condition type queries structured data in package manifests. Format is auto-detected from file extension or content.

**Supported formats:** JSON (`package.json`, `manifest.json`, `composer.json`), YAML (GitHub Actions, Docker Compose), TOML (`Cargo.toml`, `pyproject.toml`)

```yaml
# Chrome extension: dangerous permission
- id: permission-debugger
  for: [chrome-manifest]
  if:
    type: kv
    path: "permissions"
    exact: "debugger"

# Chrome extension: content script targets all URLs
- id: content-script-all-urls
  for: [chrome-manifest]
  if:
    type: kv
    path: "content_scripts[*].matches"    # [*] = any array element
    exact: "<all_urls>"

# npm: postinstall script with network access
- id: postinstall-curl
  for: [packagejson]
  if:
    type: kv
    path: "scripts.postinstall"
    regex: "curl|wget"

# npm: has postinstall hook (existence check - no matcher)
- id: has-postinstall
  for: [packagejson]
  if:
    type: kv
    path: "scripts.postinstall"

# Cargo.toml: has openssl dependency
- id: cargo-openssl
  for: [cargo-toml]
  if:
    type: kv
    path: "dependencies.openssl"

# GitHub Actions: step runs curl
- id: actions-curl
  for: [github-actions]
  if:
    type: kv
    path: "jobs.*.steps[*].run"           # Nested wildcards
    substr: "curl"
```

**Path syntax:**
- `key` - top-level key
- `a.b.c` - nested access
- `[0]` - array index
- `[*]` - all array elements (matches if any element matches)

## Debugging Commands

`dissect /path/to/file` - Analyze
`dissect symbols <file>` - View extracted symbols
`dissect strings <file>` - View extracted strings
`dissect test-rules <FILE> --rules "rule1,rule2"` - Debug rule matching
`dissect test-match <FILE> --type string|symbol|content --method exact|contains|regex --pattern "X"` - Test ad-hoc patterns

### test-match Options

Test pattern matching against a file with detailed output:

```bash
# Basic string search
dissect test-match myfile.bin --type string --method contains --pattern "eval"

# With count constraints
dissect test-match myfile.bin --type string --pattern "http://" \
    --count-min 3 --count-max 50

# With density constraints (matches per KB)
dissect test-match myfile.bin --type content --method regex --pattern "\\x90{4,}" \
    --per-kb-min 0.1 --per-kb-max 5.0

# Case-insensitive search
dissect test-match myfile.js --type string --pattern "password" --case-insensitive

# KV search in manifest files
dissect test-match package.json --type kv --kv-path "scripts.postinstall" --pattern "curl"
```

| Option | Description |
|--------|-------------|
| `--type` | Search type: `string`, `symbol`, `content`, `kv` |
| `--method` | Match method: `exact`, `contains`, `regex`, `word` |
| `--pattern` | Pattern to search for |
| `--count-min` | Minimum matches required (default: 1) |
| `--count-max` | Maximum matches allowed |
| `--per-kb-min` | Minimum matches per kilobyte |
| `--per-kb-max` | Maximum matches per kilobyte |
| `--case-insensitive` | Case-insensitive matching |
| `--kv-path` | Path for KV searches (e.g., "scripts.postinstall") |
| `--file-type` | Override auto-detection: elf, pe, macho, javascript, python, go, shell, raw |
