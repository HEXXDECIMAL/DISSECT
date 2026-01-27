//! Pattern analysis for detecting suspicious and malicious C code patterns.
//!
//! This module contains specialized analyzers for different AST node types:
//! - Function calls (system calls, kernel functions, dangerous APIs)
//! - Include directives (kernel headers, suspicious libraries)
//! - Inline assembly (register manipulation, syscalls)
//! - Declarations (kernel structures, syscall tables)
//! - Expressions (privilege escalation, memory manipulation)
//! - Comments (explicit mentions of malicious intent)
//! - Preprocessor calls (MODULE_* macros, kernel macros)
//! - Function definitions (naming patterns, attributes)
//!
//! Each analyzer examines specific patterns and adds findings to the analysis report
//! with appropriate confidence scores and criticality levels.

use crate::types::*;

use super::CAnalyzer;

/// Analyze function call expressions for capability indicators.
///
/// This is the largest pattern analyzer, detecting:
/// - Kernel module operations (symbol lookup, credential manipulation)
/// - Command execution (system, popen, exec*)
/// - Buffer overflow risks (strcpy, gets, sprintf)
/// - Network operations (socket, connect, bind)
/// - Memory operations (mmap, mprotect, VirtualAlloc)
/// - Process manipulation (ptrace, kill, setuid)
/// - Dynamic loading (dlopen, LoadLibrary)
/// - Classic attack patterns (reverse shell, shellcode execution)
pub(crate) fn analyze_call(
    _analyzer: &CAnalyzer,
    node: &tree_sitter::Node,
    source: &[u8],
    report: &mut AnalysisReport,
) {
    if let Ok(text) = node.utf8_text(source) {
        let mut capabilities = Vec::new();

        // ============================================================
        // KERNEL MODULE / ROOTKIT DETECTION (CRITICAL)
        // ============================================================

        // Syscall table hooking - extremely hostile
        if text.contains("kallsyms_lookup_name(") {
            capabilities.push((
                "kernel/symbol-lookup",
                "Kernel symbol lookup (rootkit indicator)",
                "kallsyms_lookup_name",
                0.98,
                Criticality::Hostile,
            ));
        }

        // Credential manipulation - privilege escalation
        if text.contains("prepare_creds(") {
            capabilities.push((
                "kernel/credential-manipulation",
                "Prepare kernel credentials (privilege escalation)",
                "prepare_creds",
                0.98,
                Criticality::Hostile,
            ));
        }
        if text.contains("commit_creds(") {
            capabilities.push((
                "kernel/credential-manipulation",
                "Commit kernel credentials (privilege escalation)",
                "commit_creds",
                0.98,
                Criticality::Hostile,
            ));
        }

        // Kernel memory allocation
        if text.contains("kzalloc(") || text.contains("kmalloc(") || text.contains("vmalloc(") {
            capabilities.push((
                "kernel/memory-alloc",
                "Kernel memory allocation",
                "kzalloc/kmalloc/vmalloc",
                0.9,
                Criticality::Suspicious,
            ));
        }
        if text.contains("kfree(") || text.contains("vfree(") {
            capabilities.push((
                "kernel/memory-free",
                "Kernel memory deallocation",
                "kfree/vfree",
                0.85,
                Criticality::Notable,
            ));
        }

        // User/kernel space data transfer - rootkit data exfiltration
        if text.contains("copy_from_user(") {
            capabilities.push((
                "kernel/user-copy",
                "Copy data from user space to kernel",
                "copy_from_user",
                0.9,
                Criticality::Suspicious,
            ));
        }
        if text.contains("copy_to_user(") {
            capabilities.push((
                "kernel/user-copy",
                "Copy data from kernel to user space",
                "copy_to_user",
                0.9,
                Criticality::Suspicious,
            ));
        }

        // Module list manipulation - module hiding
        if text.contains("list_del(") {
            capabilities.push((
                "kernel/list-manipulation",
                "Kernel list deletion (module hiding)",
                "list_del",
                0.95,
                Criticality::Hostile,
            ));
        }
        if text.contains("list_add(") {
            capabilities.push((
                "kernel/list-manipulation",
                "Kernel list addition",
                "list_add",
                0.85,
                Criticality::Suspicious,
            ));
        }

        // CR0 register manipulation - memory protection bypass
        if text.contains("read_cr0(") {
            capabilities.push((
                "kernel/cr0-read",
                "Read CR0 register (memory protection bypass)",
                "read_cr0",
                0.98,
                Criticality::Hostile,
            ));
        }
        if text.contains("write_cr0(") {
            capabilities.push((
                "kernel/cr0-write",
                "Write CR0 register (disable write protection)",
                "write_cr0",
                0.99,
                Criticality::Hostile,
            ));
        }

        // Process iteration - process enumeration/hiding
        if text.contains("find_task(") || text.contains("find_task_by_vpid(") {
            capabilities.push((
                "kernel/task-lookup",
                "Find kernel task structure",
                "find_task",
                0.9,
                Criticality::Suspicious,
            ));
        }

        // String conversion in kernel (PID parsing for hiding)
        if text.contains("simple_strtoul(") || text.contains("kstrtoul(") {
            capabilities.push((
                "kernel/string-conversion",
                "Kernel string to number conversion",
                "simple_strtoul",
                0.7,
                Criticality::Notable,
            ));
        }

        // MODULE_* macros (parsed as function calls by tree-sitter)
        if text.contains("MODULE_LICENSE(") {
            capabilities.push((
                "kernel/module-metadata",
                "Kernel module license declaration",
                "MODULE_LICENSE",
                0.95,
                Criticality::Hostile,
            ));
        }
        if text.contains("MODULE_AUTHOR(") {
            capabilities.push((
                "kernel/module-metadata",
                "Kernel module author declaration",
                "MODULE_AUTHOR",
                0.9,
                Criticality::Suspicious,
            ));
        }
        if text.contains("MODULE_DESCRIPTION(") {
            capabilities.push((
                "kernel/module-metadata",
                "Kernel module description",
                "MODULE_DESCRIPTION",
                0.9,
                Criticality::Suspicious,
            ));
        }
        if text.contains("module_init(") {
            capabilities.push((
                "kernel/module-init",
                "Kernel module initialization function",
                "module_init",
                0.98,
                Criticality::Hostile,
            ));
        }
        if text.contains("module_exit(") {
            capabilities.push((
                "kernel/module-exit",
                "Kernel module exit function",
                "module_exit",
                0.95,
                Criticality::Hostile,
            ));
        }

        // for_each_process macro (process enumeration)
        if text.contains("for_each_process(") {
            capabilities.push((
                "kernel/process-enumeration",
                "Kernel process enumeration macro",
                "for_each_process",
                0.95,
                Criticality::Hostile,
            ));
        }

        // ============================================================
        // COMMAND EXECUTION
        // ============================================================

        // Command execution
        if text.contains("system(") {
            capabilities.push((
                "exec/command/shell",
                "system() command execution",
                "system",
                0.95,
                Criticality::Notable,
            ));
        }
        if text.contains("popen(") {
            capabilities.push((
                "exec/command/shell",
                "popen() command execution",
                "popen",
                0.9,
                Criticality::Notable,
            ));
        }
        if text.contains("execve(") || text.contains("execv(") || text.contains("execl(") {
            capabilities.push((
                "exec/program/direct",
                "exec family program execution",
                "exec*",
                0.9,
                Criticality::Notable,
            ));
        }

        // Buffer overflow risks (dangerous functions)
        if text.contains("strcpy(") {
            capabilities.push((
                "unsafe/buffer-overflow-risk",
                "strcpy buffer overflow risk",
                "strcpy",
                0.85,
                Criticality::Suspicious,
            ));
        }
        if text.contains("strcat(") {
            capabilities.push((
                "unsafe/buffer-overflow-risk",
                "strcat buffer overflow risk",
                "strcat",
                0.85,
                Criticality::Suspicious,
            ));
        }
        if text.contains("gets(") {
            capabilities.push((
                "unsafe/buffer-overflow-risk",
                "gets buffer overflow risk",
                "gets",
                0.95,
                Criticality::Hostile,
            ));
        }
        if text.contains("sprintf(") {
            capabilities.push((
                "unsafe/buffer-overflow-risk",
                "sprintf buffer overflow risk",
                "sprintf",
                0.85,
                Criticality::Suspicious,
            ));
        }
        if text.contains("vsprintf(") {
            capabilities.push((
                "unsafe/buffer-overflow-risk",
                "vsprintf buffer overflow risk",
                "vsprintf",
                0.85,
                Criticality::Suspicious,
            ));
        }

        // Network operations
        if text.contains("socket(") {
            capabilities.push((
                "net/socket/create",
                "Socket creation",
                "socket",
                0.9,
                Criticality::Notable,
            ));
        }
        if text.contains("connect(") {
            capabilities.push((
                "net/socket/create",
                "Socket connection",
                "connect",
                0.9,
                Criticality::Notable,
            ));
        }
        if text.contains("bind(") && text.contains("listen(") {
            capabilities.push((
                "net/socket/server",
                "Socket server",
                "bind+listen",
                0.9,
                Criticality::Notable,
            ));
        }

        // Memory operations (shellcode indicators)
        if text.contains("mmap(") {
            capabilities.push((
                "memory/map",
                "Memory mapping",
                "mmap",
                0.9,
                Criticality::Notable,
            ));
        }
        if text.contains("mprotect(") {
            capabilities.push((
                "memory/protect",
                "Change memory protection",
                "mprotect",
                0.95,
                Criticality::Notable,
            ));
        }
        if text.contains("VirtualAlloc(") {
            capabilities.push((
                "memory/map",
                "Virtual memory allocation (Windows)",
                "VirtualAlloc",
                0.9,
                Criticality::Notable,
            ));
        }
        if text.contains("VirtualProtect(") {
            capabilities.push((
                "memory/protect",
                "Change memory protection (Windows)",
                "VirtualProtect",
                0.95,
                Criticality::Notable,
            ));
        }

        // Classic reverse shell pattern (socket + dup2 + execve)
        if (text.contains("socket") || text.contains("connect"))
            && (text.contains("dup2") || text.contains("dup"))
            && (text.contains("execve") || text.contains("/bin/sh"))
        {
            capabilities.push((
                "c2/reverse-shell",
                "Classic reverse shell pattern",
                "socket+dup2+exec",
                0.98,
                Criticality::Hostile,
            ));
        }

        // Shellcode execution pattern (mmap + mprotect)
        if text.contains("mmap") && text.contains("mprotect") {
            capabilities.push((
                "exec/shellcode",
                "Shellcode execution pattern",
                "mmap+mprotect",
                0.95,
                Criticality::Hostile,
            ));
        }
        if text.contains("VirtualAlloc") && text.contains("VirtualProtect") {
            capabilities.push((
                "exec/shellcode",
                "Shellcode execution (Windows)",
                "VirtualAlloc+VirtualProtect",
                0.95,
                Criticality::Hostile,
            ));
        }

        // Process manipulation
        if text.contains("ptrace(") {
            capabilities.push((
                "process/debug/attach",
                "ptrace process debugging",
                "ptrace",
                0.95,
                Criticality::Hostile,
            ));
        }
        if text.contains("kill(") {
            capabilities.push((
                "process/manipulate",
                "Send signal to process",
                "kill",
                0.9,
                Criticality::Notable,
            ));
        }
        if text.contains("setuid(") || text.contains("setgid(") {
            capabilities.push((
                "privilege/setuid",
                "Set user/group ID",
                "setuid/setgid",
                0.95,
                Criticality::Hostile,
            ));
        }

        // Dynamic loading
        if text.contains("dlopen(") {
            capabilities.push((
                "exec/dylib/load",
                "Dynamic library loading",
                "dlopen",
                0.9,
                Criticality::Notable,
            ));
        }
        if text.contains("dlsym(") {
            capabilities.push((
                "exec/dylib/resolve",
                "Resolve dynamic symbol",
                "dlsym",
                0.85,
                Criticality::Notable,
            ));
        }
        if text.contains("LoadLibrary(") {
            capabilities.push((
                "exec/dylib/load",
                "Load library (Windows)",
                "LoadLibrary",
                0.9,
                Criticality::Notable,
            ));
        }
        if text.contains("GetProcAddress(") {
            capabilities.push((
                "exec/dylib/resolve",
                "Get procedure address (Windows)",
                "GetProcAddress",
                0.85,
                Criticality::Notable,
            ));
        }

        // File operations
        if text.contains("remove(") || text.contains("unlink(") {
            capabilities.push((
                "fs/delete",
                "Delete file",
                "remove/unlink",
                0.85,
                Criticality::Notable,
            ));
        }
        if text.contains("chmod(") {
            capabilities.push((
                "fs/permissions",
                "Change file permissions",
                "chmod",
                0.85,
                Criticality::Notable,
            ));
        }
        if text.contains("chown(") {
            capabilities.push((
                "fs/permissions",
                "Change file ownership",
                "chown",
                0.85,
                Criticality::Notable,
            ));
        }

        // Add capabilities
        for (cap_id, desc, method, conf, criticality) in capabilities {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: cap_id.to_string(),
                desc: desc.to_string(),
                conf,
                crit: criticality,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "ast".to_string(),
                    source: "tree-sitter-c".to_string(),
                    value: method.to_string(),
                    location: Some(format!(
                        "{}:{}",
                        node.start_position().row,
                        node.start_position().column
                    )),
                }],
            });
        }
    }
}

/// Analyze #include directives for suspicious headers.
///
/// Detects:
/// - Kernel module headers (linux/kernel.h, linux/module.h)
/// - Syscall-related headers (linux/syscalls.h, asm/unistd.h)
/// - Filesystem manipulation headers (linux/fs.h, linux/dirent.h)
/// - Credential headers (linux/cred.h)
/// - Hooking frameworks (ftrace_helper, kprobes)
/// - Standard suspicious headers (ptrace, mman, socket)
pub(crate) fn analyze_include(
    _analyzer: &CAnalyzer,
    node: &tree_sitter::Node,
    source: &[u8],
    report: &mut AnalysisReport,
) {
    if let Ok(text) = node.utf8_text(source) {
        let mut capabilities = Vec::new();

        // ============================================================
        // KERNEL MODULE HEADERS (EXTREMELY SUSPICIOUS)
        // ============================================================

        if text.contains("linux/kernel.h") {
            capabilities.push((
                "kernel/module",
                "Linux kernel header (kernel module)",
                "linux/kernel.h",
                0.95,
                Criticality::Hostile,
            ));
        }
        if text.contains("linux/module.h") {
            capabilities.push((
                "kernel/module",
                "Linux kernel module header (loadable kernel module)",
                "linux/module.h",
                0.98,
                Criticality::Hostile,
            ));
        }
        if text.contains("linux/syscalls.h") {
            capabilities.push((
                "kernel/syscall",
                "Linux syscall definitions (syscall hooking)",
                "linux/syscalls.h",
                0.95,
                Criticality::Hostile,
            ));
        }
        if text.contains("linux/dirent.h") {
            capabilities.push((
                "kernel/dirent",
                "Linux directory entry header (file hiding)",
                "linux/dirent.h",
                0.9,
                Criticality::Hostile,
            ));
        }
        if text.contains("linux/cred.h") {
            capabilities.push((
                "kernel/credentials",
                "Linux credentials header (privilege escalation)",
                "linux/cred.h",
                0.95,
                Criticality::Hostile,
            ));
        }
        if text.contains("linux/sched.h") {
            capabilities.push((
                "kernel/scheduler",
                "Linux scheduler header (process manipulation)",
                "linux/sched.h",
                0.85,
                Criticality::Suspicious,
            ));
        }
        if text.contains("linux/kallsyms.h") {
            capabilities.push((
                "kernel/symbol-access",
                "Linux kallsyms header (kernel symbol access)",
                "linux/kallsyms.h",
                0.98,
                Criticality::Hostile,
            ));
        }
        if text.contains("linux/ftrace.h") {
            capabilities.push((
                "kernel/ftrace",
                "Linux ftrace header (function tracing/hooking)",
                "linux/ftrace.h",
                0.95,
                Criticality::Hostile,
            ));
        }
        if text.contains("linux/kprobes.h") {
            capabilities.push((
                "kernel/kprobes",
                "Linux kprobes header (kernel probing/hooking)",
                "linux/kprobes.h",
                0.95,
                Criticality::Hostile,
            ));
        }
        if text.contains("linux/namei.h") {
            capabilities.push((
                "kernel/filesystem",
                "Linux namei header (filesystem manipulation)",
                "linux/namei.h",
                0.85,
                Criticality::Suspicious,
            ));
        }
        if text.contains("linux/fs.h") {
            capabilities.push((
                "kernel/filesystem",
                "Linux filesystem header (file operations)",
                "linux/fs.h",
                0.8,
                Criticality::Suspicious,
            ));
        }
        if text.contains("linux/proc_fs.h") || text.contains("linux/proc_ns.h") {
            capabilities.push((
                "kernel/procfs",
                "Linux procfs header (process hiding)",
                "linux/proc_fs.h",
                0.9,
                Criticality::Hostile,
            ));
        }

        // Custom rootkit helper libraries (common pattern)
        if text.contains("ftrace_helper") {
            capabilities.push((
                "kernel/rootkit-helper",
                "Ftrace helper library (common rootkit hooking library)",
                "ftrace_helper",
                0.99,
                Criticality::Hostile,
            ));
        }

        // ============================================================
        // STANDARD SUSPICIOUS HEADERS
        // ============================================================

        if text.contains("sys/socket.h") || text.contains("netinet/") {
            capabilities.push((
                "net/socket/create",
                "Network header include",
                "socket.h",
                0.7,
                Criticality::Notable,
            ));
        }
        if text.contains("sys/ptrace.h") {
            capabilities.push((
                "process/debug/attach",
                "ptrace header include",
                "ptrace.h",
                0.75,
                Criticality::Suspicious,
            ));
        }
        if text.contains("sys/mman.h") {
            capabilities.push((
                "memory/map",
                "Memory mapping header",
                "mman.h",
                0.7,
                Criticality::Notable,
            ));
        }
        if text.contains("openssl/") {
            capabilities.push((
                "crypto/cipher",
                "OpenSSL header include",
                "openssl",
                0.7,
                Criticality::Notable,
            ));
        }
        if text.contains("dlfcn.h") {
            capabilities.push((
                "exec/dylib/load",
                "Dynamic loading header",
                "dlfcn.h",
                0.7,
                Criticality::Notable,
            ));
        }
        if text.contains("asm/unistd.h") || text.contains("sys/syscall.h") {
            capabilities.push((
                "syscall/direct",
                "Direct syscall header (syscall bypass)",
                "unistd.h/syscall.h",
                0.85,
                Criticality::Suspicious,
            ));
        }

        for (cap_id, desc, method, conf, criticality) in capabilities {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: cap_id.to_string(),
                desc: desc.to_string(),
                conf,
                crit: criticality,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "include".to_string(),
                    source: "tree-sitter-c".to_string(),
                    value: method.to_string(),
                    location: Some(format!(
                        "{}:{}",
                        node.start_position().row,
                        node.start_position().column
                    )),
                }],
            });
        }
    }
}

/// Analyze inline assembly for low-level manipulation.
///
/// Detects manipulation of:
/// - CR0 register (memory protection bypass)
/// - CR3 register (page table manipulation)
/// - Debug registers (anti-debugging)
/// - MSR registers (model-specific registers)
/// - Interrupt flags (cli/sti)
/// - Descriptor tables (lgdt/lidt for hypervisor/rootkit)
/// - Direct syscalls (int 0x80, syscall, sysenter)
pub(crate) fn analyze_asm(
    _analyzer: &CAnalyzer,
    node: &tree_sitter::Node,
    source: &[u8],
    report: &mut AnalysisReport,
) {
    let asm_text = node.utf8_text(source).unwrap_or("");

    // Determine criticality based on ASM content
    let (criticality, description) = if asm_text.contains("cr0")
        || asm_text.contains("CR0")
        || asm_text.contains("%cr0")
    {
        (
            Criticality::Hostile,
            "Inline assembly manipulating CR0 register (memory protection bypass)",
        )
    } else if asm_text.contains("int $0x80")
        || asm_text.contains("syscall")
        || asm_text.contains("sysenter")
    {
        (
            Criticality::Suspicious,
            "Inline assembly with direct syscall invocation",
        )
    } else if asm_text.contains("cr3") || asm_text.contains("CR3") || asm_text.contains("%cr3") {
        (
            Criticality::Hostile,
            "Inline assembly manipulating CR3 register (page table manipulation)",
        )
    } else if asm_text.contains("dr") || asm_text.contains("DR") {
        (
            Criticality::Hostile,
            "Inline assembly manipulating debug registers (anti-debugging)",
        )
    } else if asm_text.contains("wrmsr") || asm_text.contains("rdmsr") {
        (
            Criticality::Hostile,
            "Inline assembly accessing model-specific registers",
        )
    } else if asm_text.contains("cli") || asm_text.contains("sti") {
        (
            Criticality::Hostile,
            "Inline assembly manipulating interrupt flags",
        )
    } else if asm_text.contains("lgdt") || asm_text.contains("lidt") {
        (
            Criticality::Hostile,
            "Inline assembly modifying descriptor tables (hypervisor/rootkit)",
        )
    } else {
        (Criticality::Notable, "Inline assembly")
    };

    report.findings.push(Finding {
        kind: FindingKind::Capability,
        trait_refs: vec![],
        id: "unsafe/inline-asm".to_string(),
        desc: description.to_string(),
        conf: 1.0,
        crit: criticality,
        mbc: None,
        attack: None,
        evidence: vec![Evidence {
            method: "ast".to_string(),
            source: "tree-sitter-c".to_string(),
            value: "asm".to_string(),
            location: Some(format!(
                "{}:{}",
                node.start_position().row,
                node.start_position().column
            )),
        }],
    });
}

/// Analyze variable and function declarations for suspicious patterns.
///
/// Detects:
/// - Syscall table pointer declarations
/// - Original syscall storage (hooking pattern)
/// - THIS_MODULE references (module hiding)
/// - Kernel structures (task_struct, cred, linux_dirent, pt_regs)
/// - Inode access patterns
/// - Asmlinkage calling convention
/// - Kernel list structures
pub(crate) fn analyze_declaration(
    _analyzer: &CAnalyzer,
    node: &tree_sitter::Node,
    source: &[u8],
    report: &mut AnalysisReport,
) {
    if let Ok(text) = node.utf8_text(source) {
        let mut capabilities = Vec::new();

        // Syscall table pointer declaration
        if text.contains("sys_call_table") || text.contains("__sys_call_table") {
            capabilities.push((
                "kernel/syscall-table",
                "Syscall table pointer (syscall hooking)",
                "sys_call_table",
                0.99,
                Criticality::Hostile,
            ));
        }

        // Original syscall storage (hooking pattern)
        if text.contains("orig_") && text.contains("t_syscall") {
            capabilities.push((
                "kernel/syscall-hook",
                "Original syscall storage (syscall hooking pattern)",
                "orig_syscall",
                0.95,
                Criticality::Hostile,
            ));
        }

        // THIS_MODULE reference (module manipulation)
        if text.contains("THIS_MODULE") {
            capabilities.push((
                "kernel/module-self-reference",
                "Kernel module self-reference (module hiding)",
                "THIS_MODULE",
                0.9,
                Criticality::Hostile,
            ));
        }

        // task_struct declaration (process manipulation)
        if text.contains("task_struct") {
            capabilities.push((
                "kernel/task-struct",
                "Task structure access (process manipulation)",
                "task_struct",
                0.9,
                Criticality::Suspicious,
            ));
        }

        // Credential structure
        if text.contains("struct cred") {
            capabilities.push((
                "kernel/cred-struct",
                "Credential structure access (privilege escalation)",
                "struct cred",
                0.95,
                Criticality::Hostile,
            ));
        }

        // linux_dirent structure (file hiding)
        if text.contains("linux_dirent") {
            capabilities.push((
                "kernel/dirent-struct",
                "Directory entry structure (file/process hiding)",
                "linux_dirent",
                0.95,
                Criticality::Hostile,
            ));
        }

        // pt_regs structure (syscall arguments)
        if text.contains("pt_regs") {
            capabilities.push((
                "kernel/ptregs",
                "Register state structure (syscall interception)",
                "pt_regs",
                0.85,
                Criticality::Suspicious,
            ));
        }

        // inode structure access
        if text.contains("struct inode") || text.contains("d_inode") {
            capabilities.push((
                "kernel/inode-access",
                "Inode structure access (filesystem manipulation)",
                "inode",
                0.8,
                Criticality::Suspicious,
            ));
        }

        // asmlinkage calling convention (syscall functions)
        if text.contains("asmlinkage") {
            capabilities.push((
                "kernel/asmlinkage",
                "Asmlinkage calling convention (syscall function)",
                "asmlinkage",
                0.9,
                Criticality::Suspicious,
            ));
        }

        // list_head structure (kernel list manipulation)
        if text.contains("list_head") {
            capabilities.push((
                "kernel/list-struct",
                "Kernel list structure (module/process hiding)",
                "list_head",
                0.85,
                Criticality::Suspicious,
            ));
        }

        for (cap_id, desc, method, conf, criticality) in capabilities {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: cap_id.to_string(),
                desc: desc.to_string(),
                conf,
                crit: criticality,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "declaration".to_string(),
                    source: "tree-sitter-c".to_string(),
                    value: method.to_string(),
                    location: Some(format!(
                        "{}:{}",
                        node.start_position().row,
                        node.start_position().column
                    )),
                }],
            });
        }
    }
}

/// Analyze expressions for privilege escalation and manipulation patterns.
///
/// Detects:
/// - UID/GID set to 0 (root privilege escalation)
/// - Task flags manipulation (process hiding)
/// - Directory entry size manipulation (file hiding)
/// - CR0 WP bit manipulation (memory protection bypass)
/// - Syscall number references (__NR_*)
/// - PROC_ROOT_INO references
/// - Module section attributes clearing (module hiding)
/// - THIS_MODULE references in expressions
pub(crate) fn analyze_expression(
    _analyzer: &CAnalyzer,
    node: &tree_sitter::Node,
    source: &[u8],
    report: &mut AnalysisReport,
) {
    if let Ok(text) = node.utf8_text(source) {
        let mut capabilities = Vec::new();

        // UID/GID set to 0 (privilege escalation)
        if (text.contains("uid") || text.contains("gid"))
            && text.contains("= 0")
            && !text.contains("== 0")
        {
            capabilities.push((
                "privilege/root-credentials",
                "Setting UID/GID to 0 (root privilege escalation)",
                "uid=0/gid=0",
                0.95,
                Criticality::Hostile,
            ));
        }

        // Task flags manipulation (process hiding)
        if (text.contains("task->flags") || text.contains("p->flags"))
            && (text.contains("0x10000000") || text.contains("^="))
        {
            capabilities.push((
                "kernel/task-flag-manipulation",
                "Task flags manipulation (process hiding)",
                "task->flags",
                0.98,
                Criticality::Hostile,
            ));
        }

        // d_reclen manipulation (directory entry hiding)
        if text.contains("d_reclen") && (text.contains("+=") || text.contains("-=")) {
            capabilities.push((
                "kernel/dirent-manipulation",
                "Directory entry size manipulation (file hiding)",
                "d_reclen",
                0.99,
                Criticality::Hostile,
            ));
        }

        // CR0 WP bit manipulation
        if text.contains("0x00010000") || text.contains("~0x00010000") {
            capabilities.push((
                "kernel/memory-protection-bypass",
                "CR0 write-protect bit manipulation",
                "CR0_WP",
                0.99,
                Criticality::Hostile,
            ));
        }

        // Syscall number references
        if text.contains("__NR_") {
            let syscall_name = if text.contains("__NR_getdents") {
                "getdents"
            } else if text.contains("__NR_kill") {
                "kill"
            } else if text.contains("__NR_read") {
                "read"
            } else if text.contains("__NR_write") {
                "write"
            } else if text.contains("__NR_open") {
                "open"
            } else if text.contains("__NR_execve") {
                "execve"
            } else {
                "unknown"
            };
            capabilities.push((
                "kernel/syscall-number",
                "Direct syscall number reference (syscall hooking)",
                syscall_name,
                0.9,
                Criticality::Hostile,
            ));
        }

        // PROC_ROOT_INO reference
        if text.contains("PROC_ROOT_INO") {
            capabilities.push((
                "kernel/procfs-root",
                "Proc filesystem root inode (process hiding)",
                "PROC_ROOT_INO",
                0.95,
                Criticality::Hostile,
            ));
        }

        // sect_attrs manipulation (module hiding)
        if text.contains("sect_attrs") && text.contains("NULL") {
            capabilities.push((
                "kernel/module-hiding",
                "Module section attributes cleared (module hiding)",
                "sect_attrs=NULL",
                0.98,
                Criticality::Hostile,
            ));
        }

        // THIS_MODULE reference in expressions (module manipulation)
        if text.contains("THIS_MODULE") {
            capabilities.push((
                "kernel/module-self-reference",
                "Kernel module self-reference (module hiding)",
                "THIS_MODULE",
                0.9,
                Criticality::Hostile,
            ));
        }

        for (cap_id, desc, method, conf, criticality) in capabilities {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: cap_id.to_string(),
                desc: desc.to_string(),
                conf,
                crit: criticality,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "expression".to_string(),
                    source: "tree-sitter-c".to_string(),
                    value: method.to_string(),
                    location: Some(format!(
                        "{}:{}",
                        node.start_position().row,
                        node.start_position().column
                    )),
                }],
            });
        }
    }
}

/// Analyze comments for explicit mentions of malicious intent.
///
/// Detects mentions of:
/// - Rootkit
/// - Malware/backdoor
/// - Keylogger
/// - Privilege escalation
/// - Stealth/hiding
/// - Syscall hooking
/// - Evasion techniques
/// - Polymorphic capabilities
/// - Attack techniques documentation
pub(crate) fn analyze_comment(
    _analyzer: &CAnalyzer,
    node: &tree_sitter::Node,
    source: &[u8],
    report: &mut AnalysisReport,
) {
    if let Ok(text) = node.utf8_text(source) {
        let text_lower = text.to_lowercase();
        let mut capabilities = Vec::new();

        // Explicit rootkit/malware mentions
        if text_lower.contains("rootkit") {
            capabilities.push((
                "meta/rootkit-mention",
                "Code explicitly mentions rootkit",
                "rootkit",
                1.0,
                Criticality::Hostile,
            ));
        }
        if text_lower.contains("malware") || text_lower.contains("backdoor") {
            capabilities.push((
                "meta/malware-mention",
                "Code explicitly mentions malware/backdoor",
                "malware",
                1.0,
                Criticality::Hostile,
            ));
        }
        if text_lower.contains("keylogger") || text_lower.contains("key logger") {
            capabilities.push((
                "meta/keylogger-mention",
                "Code explicitly mentions keylogger",
                "keylogger",
                1.0,
                Criticality::Hostile,
            ));
        }
        if text_lower.contains("privilege escalation") || text_lower.contains("privesc") {
            capabilities.push((
                "meta/privesc-mention",
                "Code explicitly mentions privilege escalation",
                "privilege_escalation",
                0.95,
                Criticality::Hostile,
            ));
        }
        if (text_lower.contains("stealth") || text_lower.contains("hidden"))
            && (text_lower.contains("process") || text_lower.contains("module"))
        {
            capabilities.push((
                "meta/stealth-mention",
                "Code mentions stealth/hiding capabilities",
                "stealth",
                0.9,
                Criticality::Hostile,
            ));
        }
        if text_lower.contains("syscall") && text_lower.contains("hook") {
            capabilities.push((
                "meta/syscall-hook-mention",
                "Code mentions syscall hooking",
                "syscall_hook",
                0.95,
                Criticality::Hostile,
            ));
        }
        if text_lower.contains("evasion") || text_lower.contains("evade") {
            capabilities.push((
                "meta/evasion-mention",
                "Code mentions evasion techniques",
                "evasion",
                0.9,
                Criticality::Hostile,
            ));
        }
        if text_lower.contains("polymorphic") {
            capabilities.push((
                "meta/polymorphic-mention",
                "Code mentions polymorphic capabilities",
                "polymorphic",
                0.95,
                Criticality::Hostile,
            ));
        }
        if text_lower.contains("corrupting syscall")
            || text_lower.contains("syscall table")
            || text_lower.contains("defeating memory protection")
        {
            capabilities.push((
                "meta/attack-technique",
                "Code documents attack techniques",
                "attack_doc",
                0.95,
                Criticality::Hostile,
            ));
        }

        for (cap_id, desc, method, conf, criticality) in capabilities {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: cap_id.to_string(),
                desc: desc.to_string(),
                conf,
                crit: criticality,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "comment".to_string(),
                    source: "tree-sitter-c".to_string(),
                    value: method.to_string(),
                    location: Some(format!(
                        "{}:{}",
                        node.start_position().row,
                        node.start_position().column
                    )),
                }],
            });
        }
    }
}

/// Analyze preprocessor calls for kernel module macros.
///
/// Detects:
/// - MODULE_LICENSE
/// - MODULE_AUTHOR
/// - MODULE_DESCRIPTION
/// - module_init
/// - module_exit
/// - for_each_process
pub(crate) fn analyze_preproc_call(
    _analyzer: &CAnalyzer,
    node: &tree_sitter::Node,
    source: &[u8],
    report: &mut AnalysisReport,
) {
    if let Ok(text) = node.utf8_text(source) {
        let mut capabilities = Vec::new();

        // MODULE_* macros (kernel module)
        if text.contains("MODULE_LICENSE") {
            capabilities.push((
                "kernel/module-metadata",
                "Kernel module license declaration",
                "MODULE_LICENSE",
                0.95,
                Criticality::Hostile,
            ));
        }
        if text.contains("MODULE_AUTHOR") {
            capabilities.push((
                "kernel/module-metadata",
                "Kernel module author declaration",
                "MODULE_AUTHOR",
                0.9,
                Criticality::Suspicious,
            ));
        }
        if text.contains("MODULE_DESCRIPTION") {
            capabilities.push((
                "kernel/module-metadata",
                "Kernel module description",
                "MODULE_DESCRIPTION",
                0.9,
                Criticality::Suspicious,
            ));
        }
        if text.contains("module_init") {
            capabilities.push((
                "kernel/module-init",
                "Kernel module initialization function",
                "module_init",
                0.98,
                Criticality::Hostile,
            ));
        }
        if text.contains("module_exit") {
            capabilities.push((
                "kernel/module-exit",
                "Kernel module exit function",
                "module_exit",
                0.95,
                Criticality::Hostile,
            ));
        }

        // for_each_process macro (process enumeration)
        if text.contains("for_each_process") {
            capabilities.push((
                "kernel/process-enumeration",
                "Kernel process enumeration macro",
                "for_each_process",
                0.95,
                Criticality::Hostile,
            ));
        }

        for (cap_id, desc, method, conf, criticality) in capabilities {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: cap_id.to_string(),
                desc: desc.to_string(),
                conf,
                crit: criticality,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "preproc".to_string(),
                    source: "tree-sitter-c".to_string(),
                    value: method.to_string(),
                    location: Some(format!(
                        "{}:{}",
                        node.start_position().row,
                        node.start_position().column
                    )),
                }],
            });
        }
    }
}

/// Analyze function definitions for suspicious attributes and naming patterns.
///
/// Detects:
/// - __init/__exit attributes (kernel module sections)
/// - Function names suggesting syscall hooking
/// - Function names suggesting hiding capability
/// - Function names suggesting privilege escalation
pub(crate) fn analyze_function_definition(
    analyzer: &CAnalyzer,
    node: &tree_sitter::Node,
    source: &[u8],
    report: &mut AnalysisReport,
) {
    if let Ok(text) = node.utf8_text(source) {
        let mut capabilities = Vec::new();

        // __init / __exit attributes (kernel module)
        if text.contains("__init") {
            capabilities.push((
                "kernel/init-section",
                "Kernel module init section attribute",
                "__init",
                0.95,
                Criticality::Hostile,
            ));
        }
        if text.contains("__exit") {
            capabilities.push((
                "kernel/exit-section",
                "Kernel module exit section attribute",
                "__exit",
                0.95,
                Criticality::Hostile,
            ));
        }

        // Function naming patterns suggesting rootkit behavior
        let name = extract_function_name_from_def(analyzer, node, source)
            .unwrap_or_default()
            .to_lowercase();

        if name.contains("hook") && (name.contains("sys") || name.contains("syscall")) {
            capabilities.push((
                "kernel/syscall-hook-function",
                "Function name suggests syscall hooking",
                &name,
                0.9,
                Criticality::Hostile,
            ));
        }
        if name.contains("hide") || name.contains("invisible") || name.contains("stealth") {
            capabilities.push((
                "evasion/hide-function",
                "Function name suggests hiding capability",
                &name,
                0.85,
                Criticality::Hostile,
            ));
        }
        if name.contains("root") && (name.contains("get") || name.contains("escalat")) {
            capabilities.push((
                "privilege/root-function",
                "Function name suggests privilege escalation",
                &name,
                0.9,
                Criticality::Hostile,
            ));
        }

        for (cap_id, desc, method, conf, criticality) in capabilities {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: cap_id.to_string(),
                desc: desc.to_string(),
                conf,
                crit: criticality,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "function".to_string(),
                    source: "tree-sitter-c".to_string(),
                    value: method.to_string(),
                    location: Some(format!(
                        "{}:{}",
                        node.start_position().row,
                        node.start_position().column
                    )),
                }],
            });
        }
    }
}

/// Helper to extract function name from a function definition node.
fn extract_function_name_from_def(
    _analyzer: &CAnalyzer,
    node: &tree_sitter::Node,
    source: &[u8],
) -> Option<String> {
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "function_declarator" {
                // Find identifier inside declarator
                let mut decl_cursor = child.walk();
                if decl_cursor.goto_first_child() {
                    loop {
                        let decl_child = decl_cursor.node();
                        if decl_child.kind() == "identifier" {
                            return decl_child.utf8_text(source).ok().map(|s| s.to_string());
                        }
                        if !decl_cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    None
}
