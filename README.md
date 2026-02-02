# DISSECT

*Deep static analysis that sees what others miss.*

DISSECT combines abstract syntax tree inspection with binary reverse engineering to detect threats across every format that matters. It's built for threat hunters, supply chain defenders, and anyone who needs to know what untrusted code actually does—before running it.

## The Problem It Solves

Most analysis tools treat code as text, using regex patterns that confuse `subprocess.call()` with a string literal containing those words. Others specialize: binaries only, or source only. DISSECT bridges that gap. It understands both AST semantics and binary internals, letting you detect supply chain attacks by diffing versions, analyze compiled code in three binary formats, and work with fifteen languages in a single pass.

## What DISSECT Analyzes

**Binaries**: Mach-O (macOS), ELF (Linux), PE (Windows)
**Source Code**: Shell, Python, JavaScript, TypeScript, Go, Rust, Java, Ruby, C, PHP, Lua, Perl, PowerShell, C#, Swift
**Package Metadata**: Chrome manifests, VSCode extensions (VSIX), npm packages
**Archives**: ZIP, TAR (and variants), 7z—unpacked and analyzed recursively
**Bytecode**: Java .class files and JAR archives via constant pool analysis

## Getting Started

```bash
cargo build --release

# Analyze a single binary or source file
dissect /bin/ls --json -o report.json
dissect suspicious.py

# Detect supply chain attacks
dissect diff old-version/ new-version/

# Deep inspection
dissect symbols malware.exe
dissect strings firmware.bin -m 10
```

## Smart Payload Detection

DISSECT automatically decodes obfuscated payloads: Base64, hex, AMOS cipher keys, AES constants, and XOR key material. This catches encrypted C2 communications and compressed malicious code that would slip past simpler tools.

## Understanding the Results

Results come as structured JSON—perfect for ML pipelines and integration with DIVINE assessments. In your terminal, findings appear color-coded (🔴 hostile, 🟡 suspicious, 🔵 notable) with confidence scores. A score of 1.0 means AST-level certainty; 0.7–0.9 indicates heuristic matching.

## Learn More

- [RULES.md](./RULES.md) — How to write detection rules and the philosophy behind them
- [TAXONOMY.md](./TAXONOMY.md) — The complete MBC-mapped capability taxonomy (791 traits)

## License

Apache-2.0
