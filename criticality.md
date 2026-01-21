# Criticality Levels Guide

DISSECT assigns criticality levels to traits and capabilities to help analysts understand the significance of detected behaviors. The system is designed to answer: **"What makes this program do what it does?"** while filtering out universal noise.

## The Four Levels

```
Inert → Notable → Suspicious → Hostile
  0        1          2           3
```

## Level Definitions

### Inert (0) - Universal Baseline Noise
Capabilities that every binary has, regardless of purpose. These produce low analytical signal. When analyzing `/bin/ls`, these don't tell you it's a directory lister. **In diff mode, inert changes are still shown** (to catch edge cases), just categorized as low priority.

**Examples:**
- File reads: `open()`, `read()`, `fs.readFile()` (opening files is universal)
- Basic file metadata: `stat()`, `access()`, `realpath()` (without enumeration patterns)
- String/data operations: parsing, formatting, basic encoding
- Time queries: `time()`, `Date.now()`, `clock_gettime()` (not manipulation)
- Math operations: calculations, random numbers
- Process info: `getpid()`, `getuid()`, `getppid()` (basic queries)
- Memory allocation: `malloc()`, `new`, basic heap operations
- Standard library imports (without usage context): `import os`, `import sys`
- Exit/termination: `exit()`, `_exit()`, `abort()`

**In single binary analysis:** Filter from output to reduce noise
**In diff mode:** Show but de-emphasize (catches unusual patterns in baseline operations)

**Principle:** "This appears in every program from 'hello world' to complex systems - it tells me nothing about purpose"

### Notable (1) - Defines Program Purpose
Capabilities that define what a program actually does. These are the interesting behaviors that differentiate programs. When analyzing `/bin/ls`, these capabilities tell you it's a directory lister. When analyzing `/usr/bin/curl`, these tell you it's an HTTP client.

**Why Notable?** When a package **newly gains** these capabilities in a diff, it signals a fundamental change in purpose - a supply chain red flag.

**Execution:**
- Command execution: `subprocess`, `child_process.exec()`, `system()`
- Process spawning: `fork()`, `exec()`, `spawn()`
- Dynamic code: `eval()`, `exec()`, `Function()` (interpreters, REPLs, test runners)
- Script engines: `vm` module, `ScriptEngine`

**Network:**
- HTTP clients: `requests`, `axios`, `http.Get()` (defines networked programs)
- Sockets: `socket()`, `net.createConnection()` (defines network tools)
- HTTP servers: `http.createServer()`, `express()` (defines web services)
- DNS operations (defines DNS tools or network-aware programs)

**File System:**
- File writes: `write()`, `fs.writeFile()` (defines file creators/editors)
- File deletes: `unlink()`, `os.remove()` (defines file management tools)
- File permissions: `chmod()`, `chown()` (defines system administration tools)
- File enumeration: `os.walk()`, `fs.readdir()`, `filepath.Walk()` (defines directory tools like ls, find)
- Directory operations: `mkdir()`, `rmdir()` (defines file management utilities)
- Symbolic links: `symlink()`, `link()` (defines filesystem utilities)

**System Modification:**
- Environment variable writes: `setenv()`, `process.env.X = Y` (defines shell-like tools)
- Time manipulation: `utimes()`, `settimeofday()` (defines system tools, potential timestomping)
- Resource limits: `setrlimit()`, `getrlimit()` with modification (defines resource managers)
- Extended attributes: `setxattr()` (defines filesystem utilities)

**Security/Privileged Operations:**
- Memory operations: `mmap()`, `mprotect()` (defines JIT compilers, VMs, performance tools)
- Deserialization: `pickle.load`, `Marshal.load`, `ObjectInputStream` (defines data processors)
- Native code: FFI, JNI, inline assembly, CGo (defines system-level or performance tools)
- Reflection/dynamic loading: `__import__()`, `require()` with variables (defines plugin systems)
- setuid/setgid: (defines privileged system utilities)

**Cryptography:**
- Encryption/decryption: (defines security tools, password managers)
- Hashing/signing: (defines verification tools, package managers)
- TLS/SSL operations: (defines secure communication tools)

**Examples:**
- `/bin/ls`: File enumeration + file metadata = directory lister ✓
- `/usr/bin/curl`: HTTP client + sockets + TLS = HTTP transfer tool ✓
- `/usr/bin/make`: Command execution + file operations = build system ✓
- String parser library: Should have NO notable capabilities (just string operations = inert)

**Principle:** "These capabilities explain what the program is for - if they appear in a diff, the program's purpose has changed"

### Suspicious (2) - Investigate Immediately
Capabilities that are rare in legitimate software or actively hide intent. These cross ethical boundaries (transparency, privacy) and warrant immediate investigation. Legitimate software should be transparent about what it does.

**Obfuscation (Hiding Intent):**
- Base64/hex encoding + decoding (common in exploits, rare in legitimate code)
- String manipulation for code hiding (intentional obscurity)
- Compression + eval patterns (hiding executable code)
- Name mangling/obfuscation (hiding symbols)
- All forms of intentional code obfuscation

**Anti-Analysis (Active Evasion):**
- VM detection: VMware, VirtualBox, QEMU string checks (why does legitimate software check?)
- Debugger detection: `ptrace`, `IsDebuggerPresent`, `/proc/self/status` checks
- Sandbox detection: hostname/username checks, artifact scanning
- Sleep acceleration detection (timing-based evasion)
- Build tag obfuscation (hiding code behind conditional compilation)

**Credential Access (Privacy Violation):**
- Environment credential extraction: `$AWS_ACCESS_KEY`, `$GITHUB_TOKEN`, `$NPM_TOKEN`
- `/etc/passwd` reads with iteration (user enumeration)
- Shadow password functions: `getspnam()` (password hash access)
- Keychain access: `SecKeychainFind*`, `SecKeychainItemCopyContent` (stored password access)
- `/etc/shadow` reads (direct password hash access)
- Browser credential stores, password manager databases

**Why Suspicious?** Legitimate programs don't hide their code, evade analysis, or access credentials outside their documented scope.

**Principle:** "This crosses ethical boundaries or hides intent - investigate thoroughly before trusting"

### Hostile (3) - Almost Certainly Malicious (Very Rare)
Composite behaviors with virtually no legitimate use cases. These should trigger immediate alerts and blocking. This level should be **very rarely assigned** - only when confidence is extremely high.

**C2 Infrastructure:**
- Reverse shell patterns: socket + dup2 + exec combo (the classic backdoor pattern)
- Bind shell patterns: socket + bind + listen + exec combo (listening backdoor)

**Data Theft:**
- Keylogging: keyboard hooks, raw input capture, event tap APIs (no legitimate desktop app use)
- Credential exfiltration combos: shadow/keychain access + network send patterns
- C2 channels for exfil: Telegram/Discord APIs combined with credential/data extraction

**Direct Attacks:**
- Buffer overflow exploitation: `gets()` (literally deprecated, never use)
- Obfuscated execution combos: base64 + eval patterns (hiding malicious code execution)
- Ransomware patterns: encryption + file walk + key exfiltration combos
- Cloud exfiltration combos: AWS S3/GCP Storage + stolen credential upload patterns

**Why Hostile?** These are composite behaviors or APIs that have no reasonable legitimate purpose. They combine multiple suspicious elements into definitive attack patterns.

**Principle:** "This is definitively malicious with no reasonable alternative explanation - block immediately"

## Context: Scanning Real Software

This categorization is calibrated for analyzing legitimate software (Linux packages, npm modules, system utilities) where many capabilities are expected:
- Web servers legitimately use sockets and HTTP → **Notable**
- CLI tools legitimately use subprocess → **Notable**
- Build tools legitimately use file operations → **Notable** (writes) or **Inert** (reads)
- Package managers legitimately use crypto → **Notable**
- System utilities legitimately use privileged operations → **Notable**

**The Key Question:** "What makes this program do its job?"
- `/bin/ls` without file enumeration isn't `ls` → file enumeration is **Notable**
- A JSON parser with subprocess isn't just parsing → subprocess is **supply chain red flag**
- Any program with obfuscation is hiding intent → obfuscation is **Suspicious**

## Supply Chain Security Philosophy

The criticality system is designed for two use cases:

### 1. Single Binary Analysis
When analyzing `/bin/ls` or `/usr/bin/curl`, show:
- **Inert:** Filtered from output (universal noise)
- **Notable:** Displayed prominently (this is what the program does)
- **Suspicious:** Highlighted warnings (unexpected behaviors)
- **Hostile:** Critical alerts (malicious patterns)

### 2. Differential Analysis (Supply Chain)
When comparing package versions:
1. Scan version N → establish capability baseline
2. Scan version N+1 → detect new capabilities
3. **All changes shown**, categorized by criticality:
   - **Inert:** Low priority (universal operations, unlikely to be malicious)
   - **Notable:** Review required (purpose may have changed)
   - **Suspicious:** Investigation required (red flag)
   - **Hostile:** Block deployment (malware detected)

**Why show inert changes?** Even baseline operations can reveal attack patterns when changed:
- String operation change might indicate new obfuscation
- File read pattern change might indicate new data access
- Process info query change might indicate new evasion technique

## Assignment Guidelines

When assigning criticality to new traits:

1. **Ask: "Does every hello world program have this?"**
   - Yes → **Inert** (string ops, file reads, process info)
   - No → Continue to #2

2. **Ask: "Does this define what the program does?"**
   - Yes → **Notable** (command execution, network, file writes, crypto)
   - No → Continue to #3

3. **Ask: "Does this hide intent or cross ethical boundaries?"**
   - Yes → **Suspicious** (obfuscation, anti-analysis, credential access)
   - No → Continue to #4

4. **Ask: "Is this a composite attack pattern with no legitimate use?"**
   - Yes → **Hostile** (reverse shells, keyloggers, exfiltration combos)
   - No → Reassess, likely **Notable**

5. **When in doubt:**
   - Between Inert and Notable → Choose **Notable** (better to show than hide)
   - Between Notable and Suspicious → Choose **Notable** (context matters)
   - Between Suspicious and Hostile → Choose **Suspicious** (high bar for Hostile)

6. **Red flags for escalation:**
   - Obfuscation of ANY kind → **Suspicious** minimum
   - Anti-analysis techniques → **Suspicious** minimum
   - Composite patterns (A + B + C) → Consider escalating
   - High confidence malicious patterns → **Hostile** (rare)

## Edge Cases

**Command Execution:** Notable (not Routine)
- Legitimate automation tools use this
- But it's a prime supply chain attack vector
- **Always flag in diffs**

**Obfuscation:** Suspicious (not Notable)
- Legitimate software should be transparent
- Base64/hex encoding is common in exploits
- Even "simple" obfuscation warrants investigation

**Deserialization:** Notable (not Suspicious)
- Common in sessions, caching, IPC
- Can be exploited but has legitimate uses
- Context matters

**eval/exec:** Notable (not Suspicious)
- Used in REPLs, test runners, template engines
- Becomes Hostile when combined with obfuscation

## Revision History

- 2026-01-21: Initial version with Routine/Notable/Suspicious/Hostile levels
