# DISSECT

**Deep static analysis tool for extracting features from binaries and source code**

DISSECT is a comprehensive feature extraction tool designed for malware analysis, supply chain security, and behavioral analysis. It outputs structured JSON containing capabilities (behavioral features) and structure (static characteristics) for consumption by ML models or the DIVINE malice assessment tool.

## Features

- 🔬 **Cross-Platform Binary Analysis** - Full support for macOS (Mach-O), Linux (ELF), and Windows (PE) with goblin + radare2
- 🪟 **Windows API Detection** - Registry operations, service manipulation, debugger detection, memory operations
- 🌳 **Source Code Analysis** - Tree-sitter-based AST analysis for Shell, Python (more languages coming)
- 🎯 **Capability Detection** - Maps symbols/functions to behavioral capabilities (exec, net, fs, crypto, registry, etc.)
- 🛡️ **Obfuscation Detection** - Base64+eval chains, hex encoding, dynamic imports, string construction
- 📊 **Entropy Analysis** - Per-section and sliding window entropy for packing/encryption detection
- 🔤 **String Extraction** - Classifies URLs, IPs, paths, emails, base64
- 🎨 **Beautiful Output** - Color-coded terminal display with risk indicators (🔴🟡🔵) and confidence markers (✓~?)
- 🔄 **Diff Mode** - Compare old/new versions for supply chain attack detection (xzutils scenario)
- 🧬 **YARA Integration** - Pattern matching with 1,088 malcontent rules
- ⚡ **High Performance** - Fast Rust implementation, <2s per file with YARA
- 📝 **Structured Output** - JSON schema v1.0 with attribution tracking

## Use Cases

- **Malware Analysis**: Extract behavioral features for ML-based detection
- **Supply Chain Security**: Detect subtle attacks via diff analysis (inspired by xzutils backdoor)
- **Threat Hunting**: Identify suspicious capabilities in binaries/scripts
- **Code Review**: Automated behavioral analysis of open-source dependencies
- **Forensics**: Deep static analysis of unknown binaries

## Installation

### Prerequisites

- **Rust 1.70+** - Install from [rustup.rs](https://rustup.rs/)
- **radare2** (optional but recommended for deep binary analysis)

### Install radare2

#### macOS
```bash
brew install radare2
```

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get install radare2
```

#### From Source
```bash
git clone https://github.com/radareorg/radare2
cd radare2
sys/install.sh
```

### Build DISSECT

```bash
git clone <repository-url>
cd DISSECT
cargo build --release
```

The binary will be in `./target/release/dissect`.

### Install System-Wide (Optional)

```bash
cargo install --path .
```

## Usage

### Analyze a Single File

```bash
dissect analyze /bin/ls
```

Output: Colorful terminal report with capabilities, structure, functions, strings, etc.

### Save to File

```bash
dissect analyze /bin/ls -o ls_report.json
```

### Analyze JavaScript/npm Packages

```bash
# Analyze JavaScript file
dissect analyze malicious.js

# Analyze npm package
npm pack suspicious-package
dissect analyze suspicious-package-1.0.0.tgz

# Check package.json scripts for malicious behavior
dissect analyze package.json
```

### Analyze Archives

```bash
# Automatically extracts and analyzes contents
dissect analyze package.tar.gz
dissect analyze source.zip
dissect analyze app.tar.xz

# Aggregates capabilities from all files inside
```

### Scan Multiple Files

```bash
dissect scan /path/to/file1 /path/to/file2
```

### Scan Directory (Recursive)

```bash
dissect scan /path/to/directory
```

### Diff Analysis (Supply Chain Attack Detection)

Detect xzutils-style backdoors by comparing versions:

```bash
# Compare directory versions
dissect diff old_version/ new_version/

# Compare individual files
dissect diff app.py.old app.py.new

# Compare npm packages
npm pack old-package@1.0.0
npm pack new-package@1.1.0
dissect diff old-package-1.0.0.tgz new-package-1.1.0.tgz
```

**What it Detects:**
- ✅ New dangerous capabilities added (exec, eval, network)
- ✅ Added obfuscation patterns (base64+eval, hex encoding)
- ✅ Risk scoring (automatic "RISK INCREASED" flagging)
- ✅ File-level changes (added/removed/modified)
- ✅ Capability deltas (what behaviors changed)

**Example Output:**
```
=== DISSECT Diff Analysis ===

📂 Baseline: package-v1.0/
📂 Target:   package-v1.1/

⚠️  1 high-risk changes detected!

🔍 Modified Files

  📄 compress.py
    ➕ New capabilities:
       🔴 anti-analysis/obfuscation/base64
       🔴 exec/command/shell
       🔴 anti-analysis/obfuscation/dynamic-import
       🔴 exec/script/eval
    ⚠️  RISK INCREASED
```

**Use Cases:**
- Reviewing dependency updates before merging
- Detecting supply chain attacks (xzutils scenario)
- Security audits of software releases
- CI/CD pipeline integration for automatic checks

### Output Formats

- **Terminal** (default) - Human-readable, color-coded output with risk indicators
- `--format json` - Machine-readable JSON for tool integration

Examples:
```bash
# Default: colorful terminal output
dissect analyze malware.exe

# JSON output for tool pipelines
dissect analyze malware.exe --format json -o report.json
```

### Terminal Output Example

```
=== DISSECT Analysis ===

📋 File Information
  Path: /tmp/suspicious.py
  Type: python_script
  Size: 500 B

🏗️  Structure
  • source/language/python

🎯 Capabilities (7)
  🔴 exec/command/shell ? (import)
  🔴 anti-analysis/obfuscation/base64 ✓ (ast)
  🔴 exec/script/eval ✓ (ast)
  🔴 anti-analysis/obfuscation/dynamic-import ✓ (ast)
  🔴 anti-analysis/obfuscation/hex ~ (pattern)
  🟡 net/socket/create ? (import)
  🟡 fs/delete ✓ (ast)

⏱️  Analysis Time: <1ms
🔧 Tools: tree-sitter-python
```

**Legend:**
- 🔴 High risk (execution, privilege escalation, anti-analysis)
- 🟡 Medium risk (network, credentials, file operations)
- 🔵 Low risk (basic operations)
- ✓ Definitive (1.0 confidence)
- ~ Probable (0.9 confidence)
- ? Heuristic (0.7-0.8 confidence)

## JSON Output Schema

### Example Output for `/bin/ls`

```json
{
  "schema_version": "1.0",
  "analysis_timestamp": "2026-01-20T02:47:14Z",
  "target": {
    "path": "/bin/ls",
    "type": "macho",
    "size_bytes": 48112,
    "sha256": "d08dd08506722650...",
    "architectures": ["x86_64"]
  },
  "capabilities": [
    {
      "id": "fs/write",
      "description": "Write files",
      "confidence": 0.8,
      "evidence": [
        {
          "method": "symbol",
          "source": "goblin",
          "value": "_write",
          "location": null
        }
      ]
    }
  ],
  "structure": [
    {
      "id": "binary/format/macho",
      "description": "Mach-O binary format",
      "evidence": [...]
    },
    {
      "id": "binary/signed",
      "description": "Binary has code signature",
      "evidence": [...]
    }
  ],
  "functions": [...],
  "strings": [...],
  "sections": [...],
  "imports": [...],
  "exports": [...],
  "yara_matches": [...],
  "metadata": {
    "analysis_duration_ms": 234,
    "tools_used": ["goblin", "radare2", "string_extractor"],
    "errors": []
  }
}
```

## Capability Taxonomy

Capabilities use `/` delimiters based on the [Malware Behavior Catalog (MBC)](https://github.com/MBCProject/mbc-markdown):

### Behavioral Capabilities

- `exec/command/shell` - Execute shell commands (system(), sh -c)
- `exec/command/direct` - Execute programs directly (execve)
- `exec/dylib/load` - Load dynamic libraries
- `net/socket/listen` - Listen for network connections
- `net/socket/connect` - Connect to remote hosts
- `net/dns/resolve` - DNS lookups
- `net/http/client` - HTTP client operations
- `fs/read` - Read files
- `fs/write` - Write files
- `fs/delete` - Delete files
- `fs/permissions` - Change permissions
- `process/spawn` - Spawn child processes
- `process/inject` - Process injection
- `crypto/hash/md5` - MD5 hashing
- `crypto/encrypt/aes` - AES encryption
- `credential/keychain` - macOS Keychain access
- `persistence/cron` - Cron job installation
- `anti-analysis/obfuscation/bitwise` - Bitwise obfuscation

### Structural Features

- `binary/format/macho` - Mach-O binary
- `binary/arch/x86_64` - x86-64 architecture
- `binary/signed` - Code signature present
- `entropy/high` - High entropy (possibly packed)
- `source/language/shell` - Shell script
- `complexity/high` - High cyclomatic complexity

## Detection Attribution

Every feature includes evidence tracking the detection method and source tool:

- **Method**: `symbol`, `yara`, `tree-sitter`, `radare2`, `entropy`, `magic`
- **Source**: `goblin`, `yara-x`, `radare2`, `tree-sitter-bash`, `entropy_analyzer`
- **Value**: The actual discovered value (symbol name, pattern match, etc.)
- **Location**: Optional context (section name, file offset, etc.)

Example:
```json
{
  "method": "symbol",
  "source": "goblin",
  "value": "_execve",
  "location": "symbol_table"
}
```

This allows tracing back exactly how each capability was detected.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design documentation.

### Analysis Pipeline

```
File → Detect Type → Route to Analyzer(s) → Aggregate Features → JSON Output
```

### Supported File Types

#### Binary Formats (Complete)
- ✅ **Mach-O** binaries (macOS/iOS) - all architectures including Universal
- ✅ **ELF** binaries (Linux/*BSD) - x86_64, i386, arm, aarch64, riscv
- ✅ **PE** binaries (Windows) - x86, x86_64, arm, aarch64, DLLs

#### Source Code (Complete)
- ✅ **Shell scripts** - bash, sh, zsh with obfuscation detection
- ✅ **Python** - .py files with advanced obfuscation detection (base64+eval, hex, dynamic imports)
- ✅ **JavaScript/Node.js** - .js, .mjs, .cjs with npm package malware detection

#### Archive Formats (Complete)
- ✅ **ZIP** - .zip archives with recursive analysis
- ✅ **TAR** - .tar, .tar.gz, .tgz, .tar.bz2, .tar.xz with automatic extraction

#### Diff Analysis (Complete)
- ✅ **Supply Chain Attack Detection** - Compare versions to detect xzutils-style backdoors

#### Planned
- ⏳ **Go** - tree-sitter-go
- ⏳ **Rust** - tree-sitter-rust
- ⏳ **C/C++** - tree-sitter-c, tree-sitter-cpp
- ⏳ **Java** - tree-sitter-java
- ⏳ **PHP** - tree-sitter-php

## Customizing Capabilities

DISSECT uses `capabilities.yaml` to map function symbols to behavioral capabilities. This file can be easily edited to add new mappings or adjust confidence scores without recompiling.

### YAML Format

```yaml
symbols:
  - symbol: function_name
    capability: category/subcategory/specific
    description: Human-readable description
    confidence: 0.0-1.0
```

### Adding New Mappings

1. Edit `capabilities.yaml`
2. Add your symbol mapping following the format above
3. No recompilation needed - changes take effect immediately

### Example: Adding Database Symbols

```yaml
symbols:
  # ... existing mappings ...

  # Database operations
  - symbol: sqlite3_open
    capability: database/sqlite/connect
    description: Open SQLite database
    confidence: 1.0

  - symbol: PQconnectdb
    capability: database/postgres/connect
    description: PostgreSQL connection
    confidence: 1.0

  - symbol: mysql_real_connect
    capability: database/mysql/connect
    description: MySQL connection
    confidence: 1.0
```

### Confidence Levels

- **1.0**: Definitive - Symbol directly indicates capability
- **0.9**: High confidence - Strong indicator with minimal ambiguity
- **0.8**: Moderate - Likely but context-dependent
- **0.7 or lower**: Heuristic - Weak indicator, needs corroboration

### Current Mappings

The default `capabilities.yaml` includes 100+ mappings covering:
- **Execution**: system(), execve(), fork(), dlopen()
- **Network**: socket(), connect(), send(), recv(), DNS functions
- **Filesystem**: open(), write(), unlink(), chmod(), mkdir()
- **Cryptography**: MD5, SHA-256, AES, RSA, random functions
- **Credentials**: Keychain access, password files, environment variables
- **Process**: kill(), ptrace(), process injection (macOS)
- **Memory**: mmap(), mprotect(), malloc()
- **Persistence**: cron, launchd (macOS)
- **Data**: compression, decompression

### Testing Your Mappings

After editing `capabilities.yaml`, verify your changes:

```bash
# Run tests to check YAML syntax
cargo test

# Analyze a binary that uses your new symbols
dissect analyze /path/to/binary

# Check for your new capability in the output
dissect analyze /path/to/binary --format json | jq '.capabilities[] | select(.id=="your/new/capability")'
```

## Development

### Build Debug

```bash
cargo build
```

### Run Tests

```bash
cargo test
```

### Run with Logging

```bash
RUST_LOG=debug ./target/debug/dissect analyze /bin/ls
```

### Lint

```bash
cargo clippy
cargo fmt
```

## Performance

DISSECT is designed for both real-time scanning and deep forensic analysis:

- **Parallel processing** with rayon for multi-file analysis
- **Caching** planned for avoiding re-analysis of identical files (SHA-256 based)
- **Configurable timeouts** for radare2 analysis
- **Memory-efficient** streaming for large binaries

Typical analysis times on a MacBook Pro M1:
- Small binary (< 100KB): ~50-200ms
- Medium binary (1-5MB): ~500ms-2s
- Large binary (> 10MB): ~2-10s (depending on radare2 analysis depth)

## Integration with DIVINE

DISSECT outputs structured JSON that can be piped to DIVINE for malice assessment:

```bash
dissect analyze suspicious_binary.exe | divine --model embedded --threshold 0.7
```

DIVINE uses ML models (embedded ONNX), pattern matching, and optional LLM escalation to determine risk scores and recommendations based on DISSECT's extracted features.

## Compared to malcontent

DISSECT is a next-generation replacement for [malcontent](https://github.com/chainguard-dev/malcontent) with:

**Enhancements:**
- ✅ Multi-tool detection (goblin + radare2 + tree-sitter + YARA)
- ✅ Attribution tracking (know how each feature was detected)
- ✅ Entropy analysis (per-section and sliding window)
- ✅ Advanced string classification
- ✅ Function-level complexity metrics
- ✅ Diff-first design for supply chain attack detection
- ✅ Extensible analyzer architecture
- ✅ Reduced YARA dependency (native analyzers provide better structured detection)

**Retained:**
- ✅ MBC-based capability taxonomy (with `/` delimiters)
- ✅ YARA rule support (reuses ~/src/malcontent/rules)
- ✅ High-performance Rust implementation

## License

Apache License 2.0

## Contributing

Contributions welcome! Please see [ARCHITECTURE.md](ARCHITECTURE.md) for design details.

Key areas for contribution:
- ELF/PE binary analyzers
- Tree-sitter integration for more languages
- YARA rule improvements
- Performance optimizations
- Test coverage

## Roadmap

- [x] Phase 1: Mach-O + Shell (basic)
- [ ] Phase 2: Archives + Diff
- [ ] Phase 3: ELF + PE binaries
- [ ] Phase 4: C, Go, Rust, Python, JS, PHP, Java
- [ ] Phase 5: Performance optimization, caching, parallelization

## Credits

- Inspired by [malcontent](https://github.com/chainguard-dev/malcontent)
- Uses [goblin](https://github.com/m4b/goblin) for binary parsing
- Uses [radare2](https://github.com/radareorg/radare2) for deep analysis
- Uses [tree-sitter](https://tree-sitter.github.io/) for source code parsing
- Uses [YARA-X](https://github.com/VirusTotal/yara-x) for pattern matching
