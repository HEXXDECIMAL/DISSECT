# DISSECT Taxonomy

A three-tier taxonomy following [MBC (Malware Behavior Catalog)](https://github.com/MBCProject/mbc-markdown) principles.

## Overview

| Tier | Purpose | Criticality Range | MBC Equivalent |
|------|---------|-------------------|----------------|
| **Capabilities** (`cap/`) | Observable mechanics (what code *can do*) | inert → notable → suspicious | [Micro-objectives](https://github.com/MBCProject/mbc-markdown/tree/master/micro-behaviors) |
| **Objectives** (`obj/`) | Attacker goals (why code *likely wants* to do something) | notable → suspicious → hostile | [Objectives](https://github.com/MBCProject/mbc-markdown#malware-objective-descriptions) |
| **Known Entities** (`known/`) | Specific signatures | suspicious → hostile | (MBC corpus) |
| **Meta** (`meta/`) | File-level properties (informational only) | inert | — |

## Tier 1: Capabilities (`cap/`)

Value-neutral observations about what code can do. High confidence from static analysis. Maps to MBC's [Micro-objectives](https://github.com/MBCProject/mbc-markdown/tree/master/micro-behaviors).

**Criticality guidance:**
- **inert** - Universal baseline (`open`, `read`, `malloc`)
- **notable** - Defines program purpose (`socket`, `exec`, `eval`)
- **suspicious** - Rarely legitimate (`shellcode-inject`, `process-hollow`)
- Never hostile (requires objective-level evidence)

### Directory Structure

Within obj/ - rules should be organized in the following directory structure: obj/OBJECTIVE/BEHAVIOR/METHOD/ - with invididual YAML files per platform or ecosystem within that directory. In some cases, you may need to add a sub-method subdirectory for methods with many options, for instance string obfuscation.

Within cap/ - rules should be organized by cap/CATEGORY/BEHAVIOR/METHOD/ - and if necessary, an additional level for  sub-methods. So for example, use cap/crypto/symmetric/aes/ruby.yaml rather than cap/crypto/symmetric/aes.yaml. Another example: cap/data/encode/base64/ 

```
cap/
├── comm/               # Network communication
│   ├── socket/         # Raw socket operations          → MBC: Communication
│   ├── http/           # HTTP client/server
│   ├── dns/            # DNS operations
│   ├── ipc/            # Inter-process communication
│   └── proxy/          # Proxy protocols (SOCKS, etc.)
│
├── crypto/             # Cryptographic operations       → MBC: Cryptography
│   ├── symmetric/      # AES, DES, etc.
│   ├── asymmetric/     # RSA, ECC, etc.
│   ├── hash/           # SHA, MD5, etc.
│   └── xor/            # XOR operations
│
├── data/               # Data transformation            → MBC: Data
│   ├── encode/         # Encoding operations
│   │   ├── base64/
│   │   ├── hex/
│   │   └── custom/
│   ├── compress/       # Zip, gzip, etc.
│   └── serialize/      # JSON, protobuf, pickle, etc.
│
├── exec/               # Code execution                 → MBC: Execution (micro)
│   ├── shell/          # Shell command execution
│   ├── eval/           # Dynamic code evaluation
│   └── load/           # Library/module loading
│
├── fs/                 # Filesystem access              → MBC: File System
│   ├── read/           # File reading
│   ├── write/          # File writing
│   ├── delete/         # File deletion
│   ├── enumerate/      # Directory listing
│   └── hide/           # Hidden file manipulation (suspicious)
│
├── hw/                 # Hardware interaction           → MBC: Hardware
│   ├── input/          # Keyboard, mouse
│   ├── display/        # Screenshot, screen access
│   ├── audio/          # Microphone, speakers
│   └── usb/            # USB devices
│
├── mem/                # Memory operations              → MBC: Memory
│   ├── alloc/          # Memory allocation
│   ├── protect/        # Memory protection changes
│   ├── map/            # Memory mapping
│   └── inject/         # Shellcode/code cave injection (same-process)
│
├── os/                 # OS integration                 → MBC: Operating System
│   ├── registry/       # Windows registry
│   ├── env/            # Environment variables
│   ├── service/        # System services
│   ├── user/           # User management
│   ├── syscall/        # Direct syscall invocation
│   ├── bpf/            # BPF/eBPF operations
│   └── info/           # Basic system queries (inert)
│
├── process/            # Process control                → MBC: Process
│   ├── create/         # Process creation
│   ├── inject/         # Cross-process injection
│   │   ├── dll/        # DLL injection
│   │   ├── thread/     # Thread injection
│   │   ├── apc/        # APC injection
│   │   └── atom-bombing/ # Atom bombing
│   ├── terminate/      # Process termination
│   ├── enumerate/      # Process listing
│   ├── hollow/         # Process hollowing
│   ├── hook/           # API/function hooking
│   └── fd/             # File descriptor manipulation (dup2, etc.)
│
└── time/               # Timing operations
    ├── sleep/          # Delays
    ├── schedule/       # Scheduled execution
    └── timer/          # Timers
```

## Tier 2: Objectives (`obj/`)

Attacker goals inferred from capability combinations. Implies *likely* intent - we can't be 100% certain from static analysis alone. Maps to MBC's [Objectives](https://github.com/MBCProject/mbc-markdown#malware-objective-descriptions).

**Criticality guidance:**
- **notable** - Objective pattern present but has common legitimate uses (anti-debug in games, discovery in installers)
- **suspicious** - Pattern suggests malicious intent, edge-case legitimate uses
- **hostile** - Clear attack pattern, no legitimate use (requires complexity >= 4)

### Directory Structure

```
obj/
├── anti-analysis/      # Evade dynamic analysis         → MBC: Anti-Behavioral Analysis
│   ├── vm-detect/      # Virtual machine detection        B0009
│   ├── sandbox-detect/ # Sandbox detection                B0007
│   ├── debugger-detect/# Debugger detection               B0001
│   ├── timing/         # Timing-based evasion             B0025
│   ├── kernel-hide/    # Kernel-level hiding (rootkit techniques)
│   └── security-bypass/# SELinux, AppArmor, AMSI bypass
│
├── anti-forensics/     # Cover tracks                   → MBC: Defense Evasion (partial)
│   ├── log-clear/      # Clear logs                       T1070
│   ├── timestomp/      # Modify timestamps                T1070.006
│   ├── self-delete/    # Remove self after execution
│   └── artifact-clean/ # Clean up artifacts
│
├── anti-static/        # Evade static analysis          → MBC: Anti-Static Analysis
│   ├── obfuscate/      # Code obfuscation                 B0032
│   │   ├── string-encrypt/
│   │   ├── control-flow/
│   │   ├── dead-code/
│   │   └── virtualize/   # Code virtualization            B0008
│   └── pack/           # Packing/compression
│
├── c2/                 # Command & control              → MBC: Command and Control
│   ├── beacon/         # Check-in patterns                B0030
│   ├── channel/        # Communication channels
│   └── reverse-shell/  # Reverse shell patterns
│
├── collect/            # Information gathering          → MBC: Collection
│   ├── keylog/         # Keystroke logging                T1056.001
│   ├── clipboard/      # Clipboard capture                T1115
│   ├── screenshot/     # Screen capture                   T1113
│   └── audio/          # Audio capture                    T1123
│
├── creds/              # Credential theft               → MBC: Credential Access
│   ├── browser/        # Browser credentials              T1555.003
│   ├── system/         # OS credentials                   T1003
│   ├── network/        # Network credentials
│   └── cloud/          # Cloud service credentials
│
├── discovery/          # Environment reconnaissance     → MBC: Discovery
│   ├── system/         # System information               T1082
│   ├── network/        # Network information              T1016
│   ├── user/           # User information                 T1033
│   └── software/       # Installed software               T1518
│
├── exfil/              # Data exfiltration              → MBC: Exfiltration
│   ├── http/           # HTTP-based exfil                 T1041
│   ├── dns/            # DNS-based exfil                  T1048
│   ├── email/          # SMTP-based exfil                 T1048
│   ├── cloud/          # Cloud storage exfil
│   └── staged/         # Staged exfiltration              T1074
│
├── impact/             # Destructive operations         → MBC: Impact
│   ├── destroy/        # Data destruction                 T1485
│   ├── encrypt/        # Ransomware encryption            T1486
│   ├── dos/            # Denial of service                B0033
│   └── deface/         # Defacement                       T1491
│
├── lateral/            # Lateral movement               → MBC: Lateral Movement
│   ├── remote-exec/    # Remote execution                 T1021
│   ├── exploit/        # Exploitation
│   └── pass-the-hash/  # Credential reuse                 T1550.002
│
├── persist/            # Persistence mechanisms         → MBC: Persistence
│   ├── startup/        # Startup entries                  T1547
│   ├── service/        # Service installation             T1543
│   ├── scheduled/      # Scheduled tasks                  T1053
│   ├── implant/        # Code implants
│   └── bootkit/        # Boot-level persistence           T1542
│
└── privesc/            # Privilege escalation           → MBC: Privilege Escalation
    ├── exploit/        # Local exploitation               T1068
    ├── uac-bypass/     # Windows UAC bypass               T1548.002
    └── abuse/          # Privilege abuse
```

## Tier 3: Known Entities (`known/`)

Specific identification of malware families and tools. Similar to MBC's [malware corpus](https://github.com/MBCProject/mbc-markdown/tree/master/xample-malware) but structured as detection rules.

### Directory Structure

```
known/malware/          # Malware family signatures
├── apt/                # APT/nation-state groups
├── backdoor/
├── botnet/
├── dropper/
├── exploit/
├── loader/
├── miner/              # Cryptominers
├── ransomware/
├── rat/                # Remote access trojans
├── rootkit/
├── stealer/
├── trojan/
├── virus/
└── worm/

known/tools/            # Legitimate tools often abused
├── offensive/          # Pentesting tools (Cobalt Strike, Metasploit)
├── sysadmin/           # Admin tools (PsExec, WMI)
└── dual-use/           # Dual-use utilities
```

## Meta Properties (`meta/`)

File-level traits that are purely informational (no behavioral implication).

```
meta/
├── format/             # File format (elf, pe, macho, script)
├── lang/               # Language/compiler detection
├── library/            # Library/framework detection (vue, jquery, react)
├── arch/               # Architecture (x86, x64, arm, arm64)
├── sign/               # Code signing status
├── quality/            # Code quality (logging, error handling, docs, tests)
└── hardening/          # Security hardening (sandbox, seccomp, pledge)
```

**Note:** `meta/hardening/` traits can be used in `downgrade:` rules to reduce criticality for security-conscious code.

## Decision Framework

```
Is it a specific malware/tool signature?
  └─→ known/malware/ or known/tools/

Can you infer attacker intent from capability combinations?
  └─→ obj/ (use composite rules)

Is it a single observable capability?
  └─→ cap/
      ├── Rarely legitimate? → suspicious
      ├── Defines purpose? → notable
      └── Universal baseline? → inert
```

## Composite Rules

Capabilities combine into objectives via composite rules:

```yaml
# obj/c2/reverse-shell/combos.yaml
composite_rules:
  - id: reverse-shell
    desc: "Reverse shell pattern"
    crit: hostile
    all:
      - id: cap/comm/socket/create
      - id: cap/process/fd/dup
      - id: cap/exec/shell
```

## Example Classifications

| Code Pattern | Tier | Path | Criticality |
|--------------|------|------|-------------|
| `socket()` call | Capability | `cap/comm/socket/create` | notable |
| `eval()` call | Capability | `cap/exec/eval/dynamic` | notable |
| Process hollowing | Capability | `cap/process/hollow` | suspicious |
| Screenshot API | Capability | `cap/hw/display/screenshot` | notable |
| Screenshot + timer + upload | Objective | `obj/collect/screenshot` | suspicious |
| Reverse shell pattern | Objective | `obj/c2/reverse-shell` | hostile |
| Cobalt Strike beacon | Known | `known/malware/rat/cobalt-strike` | hostile |

## MBC Identifier Reference

When adding ATT&CK or MBC identifiers to traits, use these formats:
- **ATT&CK Techniques**: `T1234` or `T1234.001` (sub-technique)
- **MBC Behaviors**: `B0001` (behavior), `C0015` (micro-behavior)
- **MBC Enhanced**: `E1234` (ATT&CK technique with MBC enhancements)

See [MBC Identifiers](https://github.com/MBCProject/mbc-markdown#identifiers) for the full specification.
