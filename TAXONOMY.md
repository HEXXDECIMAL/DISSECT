# DISSECT Capability Taxonomy

A behavioral capability catalog based on the [Malware Behavior Catalog (MBC)](https://github.com/MBCProject/mbc-markdown), designed for cross-framework interoperability with CAPA and malcontent.

## Philosophy

**Traits are atomic observations.** A trait represents a single, observable characteristic: a symbol import, a string pattern, an AST node. Traits are the building blocks.

**Capabilities are behavioral interpretations.** A capability combines traits to describe what code *can do*: execute commands, exfiltrate data, evade analysis. Capabilities answer "what is this program capable of?"

**Micro-behaviors are flattened.** Rather than deeply nested hierarchies, we use flat, reusable micro-behaviors (MBC C-series IDs). A reverse shell isn't a monolithic detection—it's `socket + connect + dup2 + /bin/sh` composed together.

**Criticality is independent of confidence.** A socket import is certain (confidence: 1.0) but benign (criticality: inert). A Telegram API regex match is uncertain (confidence: 0.8) but hostile (criticality: hostile).

## Taxonomy Format

```
objective/behavior/kind
```

| Level | Name | Description | Example |
|-------|------|-------------|---------|
| 1 | Objective | What the code is trying to achieve | `exec`, `net`, `c2` |
| 2 | Behavior | How it achieves it | `command`, `socket`, `channels` |
| 3 | Kind | Specific implementation | `shell`, `connect`, `telegram` |

Examples:
- `exec/command/shell` — Execute shell commands
- `net/socket/connect` — Establish network connection
- `c2/channels/telegram` — C2 via Telegram Bot API
- `anti-analysis/debugger/ptrace` — Debugger detection via ptrace

### Special Taxonomy: Malware Families

Known malware families use a separate taxonomy pattern:

```
malware/<kind>/<family>
```

| Level | Name | Description | Example |
|-------|------|-------------|---------|
| 1 | malware | Fixed prefix for known malware | `malware` |
| 2 | Kind | Category of malware | `botnet`, `ransomware`, `rootkit`, `stealer` |
| 3 | Family | Specific malware family name | `mirai`, `conti`, `diamorphine`, `amos` |

Malware kinds:
- `apt` — Advanced persistent threat tools
- `backdoor` — Remote access backdoors
- `botnet` — Bot/zombie network malware
- `c2-framework` — Command & control frameworks (Cobalt Strike, Sliver)
- `cryptominer` — Cryptocurrency mining malware
- `injector` — Code injection tools
- `proxyware` — Proxy/bandwidth hijacking
- `ransomware` — Encryption/extortion malware
- `rootkit` — Kernel/userland rootkits
- `scanner` — Network/vulnerability scanners
- `stealer` — Information stealing malware
- `virus` — Self-replicating file infectors

Examples:
- `malware/botnet/mirai` — Mirai IoT botnet
- `malware/ransomware/conti` — Conti ransomware
- `malware/rootkit/diamorphine` — Diamorphine Linux rootkit
- `malware/c2-framework/cobalt-strike` — Cobalt Strike beacon

## File Organization

### Trait Files

Files within taxonomy directories:

| Filename | Purpose |
|----------|---------|
| `traits.yaml` | Primary trait definitions |
| `combos.yaml` | Composite rules combining traits |
| `<platform>.yaml` | Platform-specific traits (linux, windows, macos, unix) |
| `<language>.yaml` | Language-specific traits (python, javascript, go, etc.)  |
| `generic.yaml` | Cross-platform/language traits |

### Trait ID Naming

**Trait IDs must be fully qualified paths** matching their file location:

```yaml
# In traits/exec/command/shell/traits.yaml
traits:
  - id: exec/command/shell/system    # ✓ Full path
  - id: system                        # ✗ Avoid short IDs
```

This ensures:
- Unique trait references across the codebase
- Clear provenance when traits are referenced in composite rules
- Consistent behavior when using suffix matching in `requires_*` conditions

## Criticality Levels

| DISSECT | malcontent | Description |
|---------|------------|-------------|
| `inert` | — | Universal baseline (socket, file read) |
| `notable` | `low` | Defines program purpose (crypto, database) |
| `suspicious` | `medium` | Unusual/evasive behavior (debugger checks, encoded payloads) |
| `hostile` | `high` | Almost certainly malicious (reverse shell, credential theft) |
| `filtered` | — | Matched but wrong file type (Windows API in ELF) |

## MBC ID Prefixes

| Prefix | Meaning | Example |
|--------|---------|---------|
| B0XXX | Behavioral objective | B0001 = Debugger Detection |
| E1XXX | Enterprise ATT&CK mapping | E1059 = Command Execution |
| C0XXX | Micro-behavior (atomic) | C0001 = Socket Communication |
| F0XXX | File/defense operations | F0001 = Packing |

## Rosetta Stone

Cross-reference between DISSECT, CAPA, malcontent, MBC, and ATT&CK frameworks.

### Execution

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `exec/command/shell` | `host-interaction/process/create` | `exec/shell` | E1059 | T1059.004 |
| `exec/command/powershell` | `host-interaction/process/create` | `exec/powershell` | E1059 | T1059.001 |
| `exec/dylib/load` | `load-code/pe` | `exec/dylib` | B0023 | T1129 |
| `exec/script/eval` | `host-interaction/process/create` | `exec/interpreter` | E1059 | T1059 |

### Process Manipulation

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `process/inject/memory` | `host-interaction/process/inject` | `process/inject` | B0033 | T1055 |
| `process/create/fork` | `host-interaction/process/create` | `process/spawn` | — | T1106 |
| `process/debug/ptrace` | `anti-analysis/anti-debugging` | `anti-behavior/ptrace` | B0001 | T1622 |
| `process/terminate` | `host-interaction/process/terminate` | `process/kill` | — | T1489 |

### Network

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `net/socket/connect` | `communication/socket` | `net/socket` | C0001 | T1071 |
| `net/socket/listen` | `communication/socket` | `net/listen` | C0001 | T1571 |
| `net/http/request` | `communication/http` | `net/http` | C0002 | T1071.001 |
| `net/dns/resolve` | `communication/dns` | `net/dns` | C0011 | T1071.004 |

### Command & Control

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `c2/channels/telegram` | `communication/*` | `c2/addr/telegram` | B0030 | T1567.001 |
| `c2/channels/discord` | `communication/*` | `c2/addr/discord` | B0030 | T1567.001 |
| `c2/beacon/interval` | `communication/c2` | `c2/beacon` | B0030.005 | T1071 |
| `c2/discovery/dga` | `communication/dns` | `c2/dga` | B0031 | T1568.002 |

### Exfiltration

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `exfil/network/http` | `collection/file-access` | `exfil/http` | B0030.001 | T1041 |
| `exfil/network/dns` | `communication/dns` | `exfil/dns` | B0030 | T1048.003 |
| `exfil/archive/compress` | `data-manipulation/compression` | `exfil/archive` | — | T1560 |
| `exfil/staging/temp` | `host-interaction/file-system` | `exfil/staging` | — | T1074 |

### Anti-Analysis

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `anti-analysis/debugger/detect` | `anti-analysis/anti-debugging` | `anti-behavior/debug` | B0001 | T1622 |
| `anti-analysis/vm/detect` | `anti-analysis/anti-vm` | `anti-behavior/vm` | B0009 | T1497.001 |
| `anti-analysis/sandbox/detect` | `anti-analysis/anti-behavioral-analysis` | `anti-behavior/sandbox` | B0007 | T1497 |
| `anti-analysis/timing/check` | `anti-analysis/anti-debugging` | `anti-behavior/timing` | B0001 | T1622 |

### Anti-Static Analysis

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `anti-static/packing/detect` | `executable/pe/section` | `anti-static/packer` | F0001 | T1027.002 |
| `anti-static/obfuscation/strings` | `data-manipulation/encoding` | `anti-static/obfuscate` | B0032 | T1027 |
| `anti-static/encryption/payload` | `data-manipulation/encryption` | `anti-static/encrypt` | B0032 | T1027 |
| `anti-static/base64/decode` | `data-manipulation/encoding` | `data/base64` | — | T1140 |

### Credentials

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `credential/keychain/access` | `collection/keychain` | `credential/keychain` | — | T1555.001 |
| `credential/browser/extract` | `collection/browser` | `credential/browser` | — | T1555.003 |
| `credential/keylog/capture` | `collection/keylog` | `collect/keylog` | B0036 | T1056.001 |
| `credential/dump/memory` | `collection/password` | `credential/dump` | — | T1003 |

### Cryptography

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `crypto/encrypt/aes` | `data-manipulation/encryption` | `crypto/aes` | C0027 | T1027 |
| `crypto/encrypt/rsa` | `data-manipulation/encryption` | `crypto/rsa` | C0027 | — |
| `crypto/hash/sha` | `data-manipulation/hashing` | `crypto/hash` | C0029 | — |
| `crypto/xor/encode` | `data-manipulation/encoding` | `crypto/xor` | C0026 | T1027 |

### Filesystem

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `fs/read/file` | `host-interaction/file-system/read` | `fs/file/read` | — | T1005 |
| `fs/write/file` | `host-interaction/file-system/write` | `fs/file/write` | — | T1105 |
| `fs/delete/file` | `host-interaction/file-system/delete` | `fs/file/delete` | — | T1070.004 |
| `fs/permission/modify` | `host-interaction/file-system` | `fs/permission` | — | T1222 |

### Persistence

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `persistence/cron/install` | `persistence/scheduled-task` | `persist/cron` | B0028 | T1053.003 |
| `persistence/launchd/install` | `persistence/launchd` | `persist/launchd` | B0028 | T1543.004 |
| `persistence/systemd/install` | `persistence/systemd` | `persist/systemd` | B0028 | T1543.002 |
| `persistence/registry/run` | `persistence/registry` | `persist/registry` | B0028 | T1547.001 |

### Privilege Escalation

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `privesc/setuid/exploit` | `host-interaction/process` | `privesc/setuid` | — | T1548.001 |
| `privesc/sudo/abuse` | `host-interaction/process` | `privesc/sudo` | — | T1548.003 |
| `privesc/capability/set` | `host-interaction/process` | `privesc/caps` | — | T1548 |
| `privesc/kernel/exploit` | `exploitation/*` | `privesc/kernel` | — | T1068 |

### Discovery/Intel

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `intel/system/info` | `host-interaction/os/info` | `discover/system` | — | T1082 |
| `intel/network/config` | `host-interaction/network` | `discover/network` | — | T1016 |
| `intel/process/list` | `host-interaction/process/list` | `discover/process` | — | T1057 |
| `intel/user/enumerate` | `host-interaction/account` | `discover/user` | — | T1087 |

### Memory

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `mem/allocate/executable` | `host-interaction/process/inject` | `mem/executable` | B0033 | T1055 |
| `mem/protect/modify` | `host-interaction/process/inject` | `mem/protect` | — | T1055 |
| `mem/map/file` | `load-code/*` | `mem/mmap` | — | T1106 |
| `mem/read/process` | `host-interaction/process/inject` | `mem/read` | — | T1055 |

### Kernel

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `kernel/module/load` | `load-code/kernel` | `kernel/module` | — | T1547.006 |
| `kernel/syscall/hook` | `anti-analysis/*` | `kernel/hook` | B0003 | T1014 |
| `kernel/memory/access` | `host-interaction/process` | `kernel/mem` | — | T1014 |
| `kernel/rootkit/hide` | `anti-analysis/*` | `kernel/rootkit` | B0003 | T1014 |

### Hardware

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `hw/usb/access` | `host-interaction/hardware` | `hw/usb` | — | T1200 |
| `hw/camera/capture` | `collection/screen-capture` | `hw/camera` | — | T1125 |
| `hw/microphone/record` | `collection/audio` | `hw/audio` | — | T1123 |
| `hw/gpu/compute` | `host-interaction/hardware` | `hw/gpu` | — | — |

### Impact

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `impact/encrypt/ransom` | `impact/encrypt` | `impact/ransom` | B0040 | T1486 |
| `impact/wipe/disk` | `impact/wipe` | `impact/wipe` | — | T1561 |
| `impact/dos/resource` | `impact/denial-of-service` | `impact/dos` | — | T1499 |
| `impact/corrupt/data` | `impact/*` | `impact/corrupt` | — | T1565 |

### Lateral Movement

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `lateral/ssh/connect` | `communication/ssh` | `lateral/ssh` | — | T1021.004 |
| `lateral/smb/access` | `communication/smb` | `lateral/smb` | — | T1021.002 |
| `lateral/remote/exec` | `host-interaction/process/create` | `lateral/remote` | — | T1021 |
| `lateral/spread/worm` | `communication/*` | `lateral/worm` | — | T1080 |

### Evasion

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `evasion/timestomp/modify` | `anti-analysis/anti-forensic` | `evasion/timestomp` | — | T1070.006 |
| `evasion/log/clear` | `anti-analysis/anti-forensic` | `evasion/log` | — | T1070.001 |
| `evasion/process/hollow` | `host-interaction/process/inject` | `evasion/hollow` | B0033 | T1055.012 |
| `evasion/unhook/api` | `anti-analysis/*` | `evasion/unhook` | B0003 | T1562 |

### Operating System

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `os/env/read` | `host-interaction/environment-variable` | `os/env` | — | T1082 |
| `os/registry/query` | `host-interaction/registry` | `os/registry` | — | T1012 |
| `os/service/control` | `host-interaction/service` | `os/service` | — | T1569 |
| `os/user/create` | `host-interaction/account` | `os/user` | — | T1136 |

### Data Manipulation

| DISSECT | CAPA | malcontent | MBC | ATT&CK |
|---------|------|------------|-----|--------|
| `data/encode/base64` | `data-manipulation/encoding` | `data/base64` | — | T1132 |
| `data/compress/gzip` | `data-manipulation/compression` | `data/compress` | — | T1560 |
| `data/serialize/json` | `data-manipulation/encoding` | `data/json` | — | — |
| `data/archive/tar` | `data-manipulation/compression` | `data/archive` | — | T1560 |

## Reference Sources

| Framework | Location | Format |
|-----------|----------|--------|
| MBC | https://github.com/MBCProject/mbc-markdown | Markdown taxonomy |
| CAPA | `~/src/capa-rules/` | YAML rules with namespace hierarchy |
| malcontent | `~/src/malcontent/rules/` | YARA rules with risk levels |
| ATT&CK | https://attack.mitre.org | STIX/JSON |

## Usage in Code

Traits are defined in `traits/<category>/<behavior>/traits.yaml`:

```yaml
traits:
  - id: exec/command/shell
    description: Shell command execution
    criticality: suspicious
    mbc: "E1059.004"
    attack: "T1059.004"
    condition:
      type: symbol
      pattern: system
```

Composite capabilities combine traits in `traits/<category>/<behavior>/combos.yaml`:

```yaml
capabilities:
  - id: c2/reverse-shell
    description: Reverse shell pattern
    criticality: hostile
    mbc: "B0033"
    attack: "T1059.004"
    requires_all:
      - type: trait
        id: net/socket/connect
      - type: trait
        id: exec/command/shell
```
