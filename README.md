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
# Analyze single file
dissect analyze /bin/ls
dissect analyze suspicious.py --format json -o report.json

# Scan multiple files or directories
dissect scan /path/to/files

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
| yara | yara-x | Pattern matching (1000+ rules) |
| radare2 | r2 | Deep binary analysis |
| entropy | built-in | Packing/encryption detection |
| pattern | regex | String classification |

## Capability Taxonomy

Hierarchical `objective/behavior/kind` format based on [Malware Behavior Catalog](https://github.com/MBCProject/mbc-markdown). See [TAXONOMY.md](./TAXONOMY.md) for the complete Rosetta Stone mapping to CAPA, malcontent, and ATT&CK.

- `exec/command/shell` - Shell command execution
- `exec/dylib/load` - Dynamic library loading
- `net/socket/connect` - Network connections
- `fs/write`, `fs/delete` - File operations
- `crypto/encrypt/aes` - Cryptographic operations
- `anti-analysis/obfuscation/*` - Obfuscation techniques
- `persistence/cron` - Persistence mechanisms
- `credential/keychain` - Credential access

## Customization

Edit `capabilities.yaml` to add symbol-to-capability mappings:

```yaml
symbols:
  - symbol: sqlite3_open
    capability: database/sqlite/connect
    description: Open SQLite database
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
