# DISSECT Rule Writing Guide

## Quick Overview

**Traits** = atomic observations (single pattern)
**Composites** = traits combined via boolean logic
**Criticality** = independent from confidence

**Tier hierarchy:**
- `cap/*` - Observable capabilities (what code can do)
- `obj/*` - Attacker objectives (intent signals)
- `known/*` - Specific malware/tool signatures (family-unique only)
- `meta/*` - Informational file properties

See [TAXONOMY.md](./TAXONOMY.md) for complete tier structure.

**Tier dependencies:**
- `cap/` → can reference `cap/` and `meta/` only
- `obj/` → can reference `cap/`, `obj/`, and `meta/`
- `known/` → can reference `cap/`, `obj/`, `known/`, and `meta/`
- `meta/` → typically references `meta/` only

**Critical rules:**
- `cap/` must NOT reference `obj/` (capabilities are atomic, objectives infer intent)
- `cap/` must NOT use `crit: hostile` (hostile requires intent inference, belongs in `obj/`)

## Trait Placement & IDs

- IDs auto-prefixed by directory path (e.g., `traits/cap/exec/shell/` → prefix `cap/exec/shell`)
- **Filenames are NEVER part of trait IDs** - only the directory path is used for prefixing
  - A trait `foo` in `traits/cap/exec/shell/python.yaml` has ID `cap/exec/shell::foo`
  - NOT `cap/exec/shell/python::foo` or `cap/exec/shell/python/foo`
- Cross-tier references use full paths: `cap/exec/shell::subprocess`
- Directory match: `cap/exec/shell/` matches all traits in that directory
- Generic capabilities NEVER go in `known/`

## Criticality Levels

| Level | Use When |
|-------|----------|
| `inert` | Universal baseline (`read`, `malloc`, 'stat') |
| `notable` | Defines program purpose (`socket`, 'readdir', 'chmod', `exec`, `eval`, `sysctl`) |
| `suspicious` | Hides intent/crosses boundaries (VM detection, obfuscation) |
| `hostile` | Attack patterns, no legitimate use (reverse shell, ransomware) |

**HOSTILE composites require precision ≥ 4.0**, else downgraded. See [PRECISION.md](./PRECISION.md) for the calculation algorithm and authoring guidelines.

## Trait Definition

```yaml
traits:
  - id: exec/process/terminate          # ID relative to directory
    desc: Process termination API call   # 4-6 words, what was detected
    crit: suspicious                     # inert|notable|suspicious|hostile
    conf: 0.95                           # 0.0-1.0
    mbc: "E1562"                         # Optional MBC code
    attack: "T1562"                      # Optional ATT&CK code
    for: [csharp]                        # File types (see below)
    platforms: [linux, macos, windows]   # Optional platform filter
    size_min: 1000                       # Optional min file size (bytes)
    size_max: 10485760                   # Optional max file size
    if:                                  # Condition (see below)
      type: string
      substr: ".Kill("
```

**File types:** `elf`, `macho`, `pe`, `dll`, `so`, `dylib`, `shell`, `python`, `javascript`, `typescript`, `rust`, `java`, `class`, `ruby`, `c`, `go`, `csharp`, `php`, `packagejson`, `chrome-manifest`, `cargo-toml`, `pyproject-toml`, `github-actions`, `composer-json`, `all`.

**Groups:** `binaries` (or `binary`), `scripts` (or `script`, `scripting`).
**Exclusions:** Prefix with `!` (e.g., `!php`, `scripts,!python`).

## Condition Types

### Pattern Matching

| Type | Purpose | Matchers | Modifiers |
|------|---------|----------|-----------|
| `string` | Extracted strings | `exact`, `substr`, `regex`, `word` | count, density, location, `case_insensitive`, `exclude_patterns`, `external_ip` |
| `content` | Raw file bytes | `exact`, `substr`, `regex`, `word` | count, density, location, `case_insensitive`, `external_ip` |
| `symbol` | Imports/exports | `exact`, `substr`, `regex` | `platforms` |
| `hex` | Byte patterns (wildcards always extracted) | pattern string | count, density, `offset`, `offset_range` |
| `encoded` | **All decoded strings** | `exact`, `substr`, `regex`, `word` | count, density, location, `encoding`, `case_insensitive` |
| `base64` | Base64-decoded *(deprecated - use `encoded`)* | `exact`, `substr`, `regex` | count, density, location, `case_insensitive` |
| `xor` | XOR-decoded *(deprecated - use `encoded`)* | `exact`, `substr`, `regex` | count, density, location, `key`, `case_insensitive` |
| `kv` | Manifest data | `exact`, `substr`, `regex` | `path`, `case_insensitive` |
| `basename` | Filename | `exact`, `substr`, `regex` | `case_insensitive` |

### Structural

| Type | Purpose | Fields |
|------|---------|--------|
| `ast` | Parse source | `kind`/`node`, `exact`/`substr`/`regex`/`query` |
| `syscall` | Direct syscalls | `name`, `number`, `arch`, `count_min`, `count_max`, `per_kb_min`, `per_kb_max` |
| `section` | Binary sections | `exact`, `substr`, `regex`, `word`, `case_insensitive` |
| `section_entropy` | Section entropy | `section`, `min`, `max` |
| `section_ratio` | Section size ratio | `section`, `compare_to`, `min`, `max` |
| `import_combination` | Import patterns | `required`, `suspicious`, `min_suspicious` |
| `metrics` | Code metrics | `field`, `min`, `max`, `min_size` |
| `trait_glob` | Match traits | `pattern`, `match` (any/all/N) |
| `filesize` | File size | `min`, `max` |
| `yara` | YARA rule | `source` |

### Hex Pattern Syntax

```
7F 45 4C 46    # Literal bytes
??             # Any single byte
[4]            # Skip exactly 4 bytes
[2-8]          # Skip 2-8 bytes
```

### AST Kinds

`call`, `function`, `class`, `import`, `string`, `comment`, `assignment`, `argument`, `return`, `binary_op`, `identifier`, `attribute`, `subscript`, `conditional`, `loop`

## Count & Density Constraints

Available on `string`, `content`, `hex`, `encoded`, `base64`, `xor`:

| Field | Description |
|-------|-------------|
| `count_min` | Minimum matches required (default: 1) |
| `count_max` | Maximum matches allowed |
| `per_kb_min` | Minimum matches per KB |
| `per_kb_max` | Maximum matches per KB |

```yaml
- id: dense-chr-calls
  if:
    type: raw
    regex: "chr\\s*\\("
    count_min: 10
    per_kb_min: 2.0
```

## Location Constraints

Available on `string`, `content`, `encoded`, `base64`, `xor`. Hex supports `offset` and `offset_range`.

| Field | Description |
|-------|-------------|
| `section` | Restrict to named section (fuzzy: `text` → `.text`, `__text`) |
| `offset` | Exact file offset (negative = from end) |
| `offset_range` | `[start, end)` range (`null` = open-ended) |
| `section_offset` | Offset within section (requires `section`) |
| `section_offset_range` | Range within section (requires `section`) |

```yaml
# Last 1KB of file
- id: trailer-check
  if:
    type: string
    substr: "END"
    offset_range: [-1024, null]

# First 64 bytes (magic/header)
- id: magic-check
  if:
    type: hex
    pattern: "7F 45 4C 46"
    offset: 0
```

## Encoded Strings

The `encoded` type searches decoded/encoded strings with optional encoding filter. It unifies and replaces the deprecated `base64` and `xor` types with additional features:

- **Word boundary matching**: `word` parameter (not available in `base64`/`xor`)
- **Flexible encoding filter**: Single, multiple (OR), or omit (all)
- **Supports all encoding types**: base64, hex, xor, url, unicode-escape

### Encoding Filter

| Syntax | Behavior | Example |
|--------|----------|---------|
| Omit `encoding:` | Search **all** encoded strings | `type: encoded, substr: "eval"` |
| Single string | Search single encoding type | `encoding: base64` |
| Array | Search multiple types (OR) | `encoding: [base64, hex]` |

### Examples

```yaml
# Search ALL encoded strings for "password"
- id: encoded-password
  if:
    type: encoded
    word: password    # Word boundary match (NEW!)

# Search only base64 strings
- id: base64-url
  if:
    type: encoded
    encoding: base64
    regex: "https?://"

# Search base64 OR hex for suspicious patterns
- id: multi-encoding-check
  if:
    type: encoded
    encoding: [base64, hex]
    substr: "cmd.exe"
    count_min: 2

# Case-insensitive search in XOR-decoded strings
- id: xor-malware
  if:
    type: encoded
    encoding: xor
    substr: MALWARE
    case_insensitive: true

# Density check across all encoded strings
- id: dense-encoded
  if:
    type: encoded
    substr: eval
    count_min: 5
    per_kb_min: 3.0
```

### Migration from base64/xor

Replace deprecated types:

```yaml
# OLD (deprecated)
type: base64
substr: "secret"

# NEW (recommended)
type: encoded
encoding: base64
substr: "secret"

# OLD (deprecated)
type: xor
regex: "malware"

# NEW (recommended)
type: encoded
encoding: xor
regex: "malware"
```

**Advantage**: Use `encoded` without `encoding:` to search *all* decoded strings regardless of encoding type.

## Composite Rules

```yaml
composite_rules:
  - id: reverse-shell
    desc: Reverse shell pattern
    crit: hostile
    conf: 0.95
    for: [elf, macho]
    all:                              # AND (all must match)
      - id: cap/comm/socket/create
      - id: cap/process/fd/dup2
      - id: cap/exec/shell
    any:                              # OR (at least one)
      - id: pattern-a
      - id: pattern-b
    none:                             # NOT (none may match)
      - id: legitimate-use
    needs: 2                          # Min matches from `any:`
```

## Exception Directives

| Directive | Purpose |
|-----------|---------|
| `not:` | Filter matched strings (list of `exact`/`substr`/`regex`) |
| `unless:` | Skip if condition matches (trait refs or inline conditions) |
| `downgrade:` | Reduce criticality if condition matches |

**Proximity:** `near_bytes:`, `near_lines:` - require evidence within N bytes/lines

## KV Path Syntax

For JSON/YAML/TOML manifests (`package.json`, `manifest.json`, `Cargo.toml`, etc.):

```yaml
path: "key"                    # Top-level key
path: "a.b.c"                  # Nested access
path: "arr[0]"                 # Array index
path: "arr[*]"                 # Any array element
path: "scripts.postinstall"    # npm scripts
path: "permissions"            # Chrome extension
```

Path-only (no matcher) = existence check.

## CLI Reference

```bash
dissect /path/to/file                    # Analyze file
dissect symbols <file>                   # View symbols
dissect strings <file>                   # View strings
dissect test-rules <file> --rules "x,y"  # Debug rules
dissect test-match <file> --type string --pattern "eval"  # Test patterns
```

### test-match Options

| Option | Values |
|--------|--------|
| `--type` | `string`, `symbol`, `content`, `kv`, `hex`, `encoded`, `base64`, `xor` |
| `--method` | `exact`, `contains`, `regex`, `word` |
| `--pattern` | Search pattern |
| `--encoding` | Encoding filter for `encoded` type: `base64`, `base64,hex`, etc. |
| `--count-min`, `--count-max` | Match count bounds |
| `--per-kb-min`, `--per-kb-max` | Density bounds |
| `--section` | Restrict to section |
| `--offset`, `--offset-range` | Absolute position |
| `--section-offset`, `--section-offset-range` | Section-relative position |
| `--case-insensitive` | Case-insensitive match |
| `--kv-path` | Path for KV searches |
| `--file-type` | Override detection |

## Reference Codes

- **ATT&CK**: `T1234` or `T1234.001`
- **MBC**: `B0001` (behavior), `C0015` (micro-behavior), `E1234` (ATT&CK+MBC)
