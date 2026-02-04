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
    for: [csharp]                        # File types: elf, macho, pe, dll, so, dylib, shell, python, javascript, rust, java, class, ruby, c, go, csharp, php, all
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

**string** - Extracted strings. Match with: `substr:`, `exact:`, `regex:`, `word:`. Modifiers: `min_count:`, `case_insensitive:`, `exclude_patterns:` (filter matches). Preview: `dissect strings <file>`.

**hex** - Byte patterns. Syntax: `7F 45 4C 46` (literals), `??` (any byte), `[N]` (skip N), `[N-M]` (gap range). Optional: `offset:`, `offset_range:`, `min_count:`, `extract_wildcards:`.

**content** - Raw file bytes. Match with: `substr:`, `exact:`, `regex:`. (Less precise than string.)

**yara** - Yara rules. Use sparingly; prefer traits + composites.

**basename** - Filename match. Match with: `exact:`, `substr:`, `regex:`. Optional: `case_insensitive:`.

**trait_glob** - Match traits by pattern. Fields: `pattern:`, `match:` (any/all/number).

**base64** - Base64-decoded strings. Match with: `substr:`, `exact:`, `regex:`, `word:`. Modifiers: `min_count:`, `case_insensitive:`.

**xor** - XOR-decoded strings (with optional key). Match with: `substr:`, `exact:`, `regex:`, `word:`. Modifiers: `min_count:`, `case_insensitive:`.

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

## Reference Codes

- **ATT&CK**: `T1234` (technique) or `T1234.001` (sub-technique)
- **MBC**: `B0001` (behavior), `C0015` (micro-behavior), `E1234` (ATT&CK+MBC)

## Debugging Commands

`dissect /path/to/file` - Analyze
`dissect symbols <file>` - View extracted symbols
`dissect strings <file>` - View extracted strings
`dissect test-rules <FILE> --rules "rule1,rule2"` - Debug rule matching
`dissect test-match <FILE> --type string|symbol|content --method exact|contains|regex --pattern "X"` - Test ad-hoc patterns
