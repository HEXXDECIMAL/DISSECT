# DISSECT (Experimental)

**Deep static analysis combining AST-based source code inspection with binary reverse engineering.** Unified detection engine for threat hunting, supply chain security, and malware analysis. Outputs structured JSON for ML pipelines or the DIVINE assessment tool.

## Why DISSECT?

**AST-driven accuracy** (not regex): Distinguishes `subprocess.call()` from string literals. Unified binary + source analysis detects supply chain attacks via diffing. Broad format support: 3 binary formats, 15 source languages, bytecode, extensions—vs. capa (PE/ELF only) or malcontent (source-only).

## Supported Formats

**Binaries** (goblin + radare2): Mach-O, ELF, PE
**Source** (tree-sitter): Shell, Python, JavaScript, TypeScript, Go, Rust, Java, Ruby, C, PHP, Lua, Perl, PowerShell, C#, Swift
**Extensions**: Google Chrome manifests, VSCode VSIX, npm package.json
**Archives**: ZIP, TAR variants, 7z (recursive extraction)
**Bytecode**: Java .class, JAR (constant pool analysis)

## Usage

```bash
cargo build --release

dissect /bin/ls --json -o report.json
dissect suspicious.py
dissect diff old-version/ new-version/   # Supply chain detection
dissect symbols malware.exe
dissect strings firmware.bin -m 10
```

## Payload Extraction

Automatic decoding: Base64/hex strings, AMOS cipher keys, AES constants, XOR keys via stng. Detects obfuscated malicious code and encrypted C2 communications.

## Output

JSON with full evidence chains: method (ast/symbol/yara), source analyzer, matched value, and location. Terminal shows risk-tiered findings (🔴🟡🔵) with confidence (1.0 = AST-definitive, 0.7-0.9 = heuristic).

## Documentation

- [RULES.md](./RULES.md) - Rule writing guide and design philosophy
- [TAXONOMY.md](./TAXONOMY.md) - Complete MBC-mapped capability taxonomy (791 traits)
- [ARCHITECTURE.md](./.claude/ARCHITECTURE.md) - Design and analyzer internals

## License

Apache-2.0
