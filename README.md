# Divine

**Divine** is a Rust port of [malcontent](https://github.com/chainguard-dev/malcontent), a malware detection tool that uses YARA rules to identify suspicious behaviors in files and executables.

## Features

- 🔍 **Fast scanning** with parallel processing using Rust's async/await and Rayon
- 🎯 **YARA rule engine** for flexible pattern matching with YARA-X
- 📦 **Archive support** for ZIP, TAR, and compressed files
- 🎨 **Multiple output formats** (terminal, JSON, YAML, brief)
- 📊 **Risk categorization** (Low, Medium, High, Critical)
- 🔧 **CLI interface** with scan and analyze modes
- ⚡ **Memory efficient** with streaming file processing
- 📋 **Detailed reporting** with behavior categorization

## Installation

### Prerequisites

- Rust 1.70 or later
- Cargo

### From Source

```bash
git clone https://github.com/chainguard-dev/malcontent
cd divine
make install
```

### Using Cargo

```bash
cargo install --path .
```

### Building

```bash
make build          # Debug build
make release        # Release build
```

## Usage

### Basic Scanning

Scan a single file:
```bash
divine scan /path/to/suspicious/file
```

Scan multiple files or directories:
```bash
divine scan /path/to/dir /another/file
```

Scan with archive extraction:
```bash
divine scan --archives /path/to/archive.zip
```

### Detailed Analysis

Analyze a single file with full details:
```bash
divine analyze /path/to/file
```

### Custom YARA Rules

Use custom rule files or directories:
```bash
divine scan --rules /path/to/custom/rules.yar /target
divine scan --rules /path/to/rules/directory/ /target
```

### Output Formats

- **Terminal** (default): Human-readable colored output
- **JSON**: Machine-readable JSON format
- **YAML**: YAML format for configuration
- **Brief**: Minimal output showing only findings

```bash
divine scan --format json /target
divine scan --format yaml /target > report.yaml
divine scan --format brief /target
```

### Risk Filtering

Filter results by minimum risk level:
```bash
divine scan --min-risk medium /target
divine scan --min-risk high /target
```

### Save Results

Save output to a file:
```bash
divine scan --output report.json --format json /target
```

## Example Output

### Terminal Output (Single File Analysis)
```
🔎 Scanning "suspicious_binary"
├─ 🟠 suspicious_binary [HIGH]
│     ≡ networking [HIGH]
│       🟠 net/url/embedded — Hardcoded URLs detected: http://malicious-site.com
│     ≡ execution [MEDIUM] 
│       🟡 os/terminal — Uses terminal/shell functionality
│     ≡ cryptography [LOW]
│       🔵 crypto/rc4 — RC4 encryption detected
│
```

### Terminal Output (Directory Scan)
```
📊 Divine Scan Report (1,234ms)

Files scanned: 150
Files skipped: 12
Malicious files: 3
Suspicious files: 8

┌─────────────────────────┬──────┬───────────┬──────────┐
│ path                    │ risk │ behaviors │ size     │
├─────────────────────────┼──────┼───────────┼──────────┤
│ malware/trojan.exe      │ CRIT │ 15        │ 2.3MB    │
│ scripts/backdoor.sh     │ HIGH │ 8         │ 1.2KB    │
│ tools/keylogger         │ HIGH │ 12        │ 856.7KB  │
└─────────────────────────┴──────┴───────────┴──────────┘
```

## Configuration

Divine uses embedded YARA rules by default, but supports custom rules:

### YARA Rule Format
```yara
rule suspicious_network_activity {
    meta:
        description = "Detects suspicious network connections"
        risk = "medium"
        author = "Security Team"
        
    strings:
        $http = "http://" nocase
        $connect = "connect(" nocase
        
    condition:
        any of them
}
```

## Development

### Building

```bash
make build          # Debug build
make release        # Release build
```

### Testing

```bash
make test           # Run tests
make test-verbose   # Run tests with output
make lint          # Run linting and formatting checks
```

### Code Quality

```bash
make fmt           # Format code
make audit         # Security audit
make doc           # Generate documentation
```

## Architecture

Divine is built with the following components:

- **Scanner**: Core scanning engine with YARA integration
- **Rules**: YARA rule loader and manager
- **Archive**: ZIP/TAR extraction with security limits
- **Report**: Risk assessment and behavior categorization
- **CLI**: Command-line interface and output formatting

### Performance

- Parallel file processing using Rayon
- Async I/O for large file operations
- Memory-mapped file reading for efficiency
- Configurable worker thread pools

## YARA Rules

Divine includes built-in YARA rules for common malware patterns:

- **Networking**: HTTP clients, socket operations, URL patterns
- **Execution**: Shell commands, process injection, code execution
- **Filesystem**: Directory traversal, file operations, path manipulation
- **Cryptography**: Encryption algorithms, hashing, key generation
- **Persistence**: Registry modification, service installation
- **Anti-Analysis**: Debug detection, VM evasion, obfuscation
- **Command & Control**: C2 communications, data exfiltration

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Run `make lint` and `make test`
5. Submit a pull request

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Related Projects

- [malcontent](https://github.com/chainguard-dev/malcontent) - Original Go implementation
- [YARA](https://virustotal.github.io/yara/) - Pattern matching engine
- [yara-x](https://github.com/VirusTotal/yara-x) - Rust YARA implementation