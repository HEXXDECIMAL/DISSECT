# DISSECT

Deep static analysis for binaries and source code. Extracts behavioral capabilities and structural features for malware analysis, supply chain security, and threat hunting. Outputs structured JSON for ML pipelines or the DIVINE assessment tool.

## Supported Formats

**Binaries** (via goblin + radare2):
- Mach-O (macOS/iOS), ELF (Linux/*BSD), PE (Windows)

**Source Code** (via tree-sitter AST):
- Shell, Python, JavaScript, TypeScript, Go, Rust, Java, Ruby, C, PHP

**Archives** (recursive extraction):
- ZIP, TAR, tar.gz, tar.bz2, tar.xz

## Installation

```bash
# Requires Rust 1.70+
cargo build --release

# Optional: radare2 for deep binary analysis
brew install radare2  # macOS
```

## Usage

```bash
# Analyze files (subcommand optional)
dissect /bin/ls
dissect suspicious.py --json -o report.json

# Scan directories
dissect /path/to/files

# Extract symbols (imports, exports, functions with addresses)
dissect symbols /bin/ls
dissect symbols malware.exe --json

# Extract strings (language-aware string extraction)
dissect strings binary.bin
dissect strings firmware.bin -m 10  # minimum length 10

# Diff analysis (supply chain attack detection)
dissect diff package-v1.0/ package-v1.1/
```

## Output

Terminal output shows capabilities with risk indicators and confidence markers:

```
🎯 Capabilities (4)
  🔴 exec/command/shell ✓ (ast)
  🔴 anti-analysis/obfuscation/base64 ✓ (ast)
  🟡 net/socket/connect ? (import)
  🔵 fs/read ~ (symbol)
```

- 🔴 High risk (execution, anti-analysis, privilege escalation)
- 🟡 Medium risk (network, credentials, file ops)
- 🔵 Low risk
- ✓ Definitive (1.0) / ~ Probable (0.9) / ? Heuristic (0.7-0.8)

JSON schema v1.0 includes full attribution:

```json
{
  "capabilities": [{
    "id": "exec/command/shell",
    "confidence": 1.0,
    "evidence": [{
      "method": "ast",
      "source": "tree-sitter-python",
      "value": "subprocess.run",
      "location": "line:42"
    }]
  }]
}
```

## Detection Methods

| Method | Source | Use |
|--------|--------|-----|
| symbol | goblin | Binary imports/exports |
| ast | tree-sitter | Source code analysis |
| yara | yara-x | Pattern matching |
| radare2 | r2 | Deep binary analysis |
| entropy | built-in | Packing/encryption detection |
| pattern | regex | String classification |

## Taxonomy

Three-tier hierarchy based on [MBC (Malware Behavior Catalog)](https://github.com/MBCProject/mbc-markdown). See [TAXONOMY.md](./TAXONOMY.md) for the complete structure and MBC mappings.

| Tier | Prefix | Purpose |
|------|--------|---------|
| Capabilities | `cap/` | What code *can do* (value-neutral) |
| Objectives | `obj/` | What code *likely wants* to do (attacker goals) |
| Known | `known/` | Specific malware/tool signatures |

**Examples:**
- `cap/exec/shell` - Shell command execution capability
- `cap/comm/socket/create` - Socket creation capability
- `obj/c2/reverse-shell` - Reverse shell objective (hostile)
- `obj/creds/browser` - Browser credential theft objective
- `known/malware/rat/cobalt-strike` - Cobalt Strike detection

## Customization

Edit `capabilities.yaml` to add symbol-to-capability mappings:

```yaml
symbols:
  - symbol: sqlite3_open
    capability: database/sqlite/connect
    desc: Open SQLite database
    confidence: 1.0
```

Composite rules combine multiple traits:

```yaml
composite_rules:
  - id: backdoor/reverse-shell
    traits: [net/socket/connect, exec/command/shell, process/fork]
    min_matches: 3
```

## Diff Analysis

Detect xzutils-style supply chain attacks by comparing versions:

```bash
dissect diff old/ new/

# Output:
📄 compress.py
  ➕ New capabilities:
     🔴 anti-analysis/obfuscation/base64
     🔴 exec/command/shell
  ⚠️  RISK INCREASED
```

## Symbol & String Extraction

### Symbols Command

Extract imports, exports, and functions with memory addresses (similar to `nm` or `objdump -t`):

```bash
# Extract symbols from a binary
dissect symbols /bin/ls

# Output:
ADDRESS            TYPE         LIBRARY              NAME
0x1000042ac        function     -                    imp.__assert_rtn
0x1000042bc        function     -                    imp.__error
0x1000042cc        function     -                    imp.__maskrune

# Works with source code too (shows function calls)
dissect symbols script.py --json
```

The `symbols` command:
- Shows memory addresses for binary symbols (via radare2 or goblin)
- Extracts function calls from source code (via tree-sitter)
- Supports all binary formats (Mach-O, ELF, PE) and source languages
- Useful for understanding what functions a program imports/exports

### Strings Command

Language-aware string extraction:

```bash
# Source files: AST-extracted string literals only
dissect strings script.py

# Binaries: stng extraction with classification
dissect strings binary.bin -m 10  # min length 10

# Output:
OFFSET     TYPE           VALUE
0x4028     Literal        __PAGEZERO
0x41f0     Path           /usr/lib/system/libsystem_c.dylib
0x5200     Url            https://example.com/api
```

**Source files:** AST parsing extracts only string literals (no comments/code)
**Binaries:** stng extracts ASCII/UTF-8/UTF-16, classifies by type (URL, IP, path, email, base64)

## Architecture

```
File → Detect Type → Route to Analyzer → Aggregate Features → Output
                          ↓
              [MachO|ELF|PE|Python|Shell|...]
                          ↓
              [goblin|tree-sitter|radare2|yara]
```

## Development

```bash
cargo build              # Debug build
cargo test               # Run tests
cargo clippy && cargo fmt  # Lint
RUST_LOG=debug dissect analyze /bin/ls  # Verbose
```

## License

Apache-2.0
