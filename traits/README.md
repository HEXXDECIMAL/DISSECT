# DISSECT Capability Rules

This directory contains capability detection rules organized by the Malware Behavior Catalog (MBC) taxonomy.

## Organization

Each file corresponds to a top-level MBC category:

- **anti-analysis.yaml** - Anti-analysis, anti-debugging, anti-VM techniques
- **collection.yaml** - Data collection (keylogging, screen capture, etc.)
- **command-and-control.yaml** - C2 communications and protocols
- **credential-access.yaml** - Credential theft and dumping
- **crypto.yaml** - Cryptographic operations (hashing, encryption, etc.)
- **data.yaml** - Data manipulation (compress, encode, etc.)
- **defense-evasion.yaml** - Defense evasion techniques
- **discovery.yaml** - System and network discovery
- **execution.yaml** - Code execution capabilities
- **exfiltration.yaml** - Data exfiltration techniques
- **filesystem.yaml** - File system operations
- **impact.yaml** - System impact (ransomware, wiper, DoS, etc.)
- **lateral-movement.yaml** - Lateral movement techniques
- **network.yaml** - Network operations
- **persistence.yaml** - Persistence mechanisms
- **privilege-escalation.yaml** - Privilege escalation
- **process.yaml** - Process manipulation and injection

## Rule Types

### Simple Rules
Traditional 1:1 mappings from symbols to capabilities:
```yaml
simple_rules:
  - symbol: ptrace
    capability: process/debug/attach
    description: Attach debugger to processes
    confidence: 1.0
    platforms: [linux, macos]
```

### Composite Rules
Advanced rules combining multiple signals:
```yaml
composite_rules:
  - capability: net/reverse-shell
    description: Reverse shell behavior
    confidence: 0.9
    requires_all:
      - type: symbol
        pattern: socket
      - type: symbol
        pattern: dup2
      - type: string
        regex: '/bin/(sh|bash)'
```

## Contributing

When adding new rules:

1. **Choose the right file** - Place rules in the most specific category
2. **Start simple** - Use `simple_rules` for clear 1:1 mappings
3. **Add context** - Use `composite_rules` to reduce false positives
4. **Set confidence** - Be conservative with confidence scores
5. **Test thoroughly** - Verify rules against both malware and benign samples
6. **Document well** - Write clear descriptions for analysts

## Rule Validation

Run tests to validate rules:
```bash
make test
cargo test capability
```
