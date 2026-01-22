# Criticality Levels

DISSECT assigns criticality levels to help analysts understand the significance of detected behaviors.

```
Inert (0) → Notable (1) → Suspicious (2) → Hostile (3)
```

---

## Inert — Universal Baseline

Capabilities every binary has regardless of purpose. Low analytical signal.

**Examples:** `open()`, `read()`, `stat()`, `time()`, `getpid()`, `malloc()`, `exit()`

**Principle:** "Every hello world program has this—it tells me nothing about purpose."

---

## Notable — Defines Program Purpose

Capabilities that define what a program does. When a package **newly gains** these in a diff, it signals a fundamental change in purpose—a supply chain red flag.

**Execution:** `subprocess`, `system()`, `fork()`, `exec()`, `eval()`, `Function()`

**Network:** `socket()`, `requests`, `axios`, `http.createServer()`

**File System:** `write()`, `unlink()`, `chmod()`, `os.walk()`, `mkdir()`, `symlink()`

**System:** `setenv()`, `utimes()`, `mmap()`, `mprotect()`, `setuid()`

**Crypto:** encryption, hashing, TLS/SSL operations

**Examples:**
- `/bin/ls`: File enumeration + metadata = directory lister
- `/usr/bin/curl`: HTTP client + sockets + TLS = transfer tool
- String parser library: Should have NO notable capabilities

**Principle:** "These explain what the program is for—if they appear in a diff, the program's purpose has changed."

---

## Suspicious — Investigate Immediately

Capabilities that hide intent or cross ethical boundaries. Rare in legitimate software.

**Obfuscation:** Base64/hex encoding patterns, string manipulation for code hiding, compression + eval

**Anti-Analysis:** VM detection (VMware, QEMU checks), debugger detection (`ptrace`, `IsDebuggerPresent`), sandbox detection, sleep acceleration detection

**Credential Access:** Environment credential extraction (`$AWS_ACCESS_KEY`, `$GITHUB_TOKEN`), `/etc/passwd` enumeration, keychain access, browser credential stores

**Principle:** "This crosses ethical boundaries or hides intent—investigate thoroughly."

---

## Hostile — Almost Certainly Malicious

Composite behaviors with virtually no legitimate use. Very rarely assigned.

**C2:** Reverse shell (socket + dup2 + exec), bind shell (socket + bind + listen + exec)

**Data Theft:** Keylogging, credential exfiltration combos, C2 channels + data extraction

**Attacks:** `gets()` usage, obfuscated execution (base64 + eval), ransomware patterns

**Principle:** "Definitively malicious with no reasonable alternative explanation—block immediately."

---

## Assignment Guidelines

1. **"Does every hello world have this?"** → Yes: **Inert**
2. **"Does this define what the program does?"** → Yes: **Notable**
3. **"Does this hide intent or cross ethical boundaries?"** → Yes: **Suspicious**
4. **"Is this a composite attack pattern with no legitimate use?"** → Yes: **Hostile**

**When in doubt:**
- Inert vs Notable → Choose **Notable** (better to show than hide)
- Notable vs Suspicious → Choose **Notable** (context matters)
- Suspicious vs Hostile → Choose **Suspicious** (high bar for Hostile)

**Red flags for escalation:**
- Any obfuscation → **Suspicious** minimum
- Anti-analysis techniques → **Suspicious** minimum
- Composite patterns (A + B + C) → Consider escalating

---

## Use Cases

### Single Binary Analysis
- **Inert:** Filtered (noise)
- **Notable:** Displayed (this is what the program does)
- **Suspicious:** Highlighted warnings
- **Hostile:** Critical alerts

### Differential Analysis (Supply Chain)
All changes shown, categorized by criticality:
- **Inert:** Low priority (unlikely malicious)
- **Notable:** Review required (purpose may have changed)
- **Suspicious:** Investigation required
- **Hostile:** Block deployment

**Why show inert changes?** Even baseline operations can reveal attack patterns when changed.
