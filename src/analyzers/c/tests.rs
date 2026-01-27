//! Tests for the C analyzer.
//!
//! This module contains comprehensive tests covering:
//! - Basic capability detection (system calls, unsafe functions)
//! - Kernel module and rootkit detection
//! - Syscall hooking and manipulation
//! - Privilege escalation patterns
//! - File and process hiding techniques
//! - Memory protection bypass
//! - Credential manipulation
//! - Inline assembly analysis

use super::*;
use std::path::PathBuf;

/// Helper function to analyze C code for testing.
fn analyze_c_code(code: &str) -> AnalysisReport {
    let analyzer = CAnalyzer::new();
    let path = PathBuf::from("test.c");
    analyzer.analyze_source(&path, code).unwrap()
}

#[test]
fn test_detect_system() {
    let code = r#"
#include <stdlib.h>
int main() {
    system("ls -la");
}
"#;
    let report = analyze_c_code(code);
    assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
}

#[test]
fn test_detect_popen() {
    let code = r#"
#include <stdio.h>
int main() {
    FILE *fp = popen("whoami", "r");
}
"#;
    let report = analyze_c_code(code);
    assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
}

#[test]
fn test_detect_execve() {
    let code = r#"
#include <unistd.h>
int main() {
    char *argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);
}
"#;
    let report = analyze_c_code(code);
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "exec/program/direct"));
}

#[test]
fn test_detect_strcpy() {
    let code = r#"
#include <string.h>
int main() {
    char buf[10];
    strcpy(buf, "data");
}
"#;
    let report = analyze_c_code(code);
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "unsafe/buffer-overflow-risk"));
}

#[test]
fn test_detect_gets() {
    let code = r#"
#include <stdio.h>
int main() {
    char buf[100];
    gets(buf);
}
"#;
    let report = analyze_c_code(code);
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "unsafe/buffer-overflow-risk"));
    assert_eq!(
        report
            .findings
            .iter()
            .find(|c| c.id == "unsafe/buffer-overflow-risk")
            .unwrap()
            .conf,
        0.95
    );
}

#[test]
fn test_detect_sprintf() {
    let code = r#"
#include <stdio.h>
int main() {
    char buf[10];
    sprintf(buf, "%s", "data");
}
"#;
    let report = analyze_c_code(code);
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "unsafe/buffer-overflow-risk"));
}

#[test]
fn test_detect_socket() {
    let code = r#"
#include <sys/socket.h>
int main() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
}
"#;
    let report = analyze_c_code(code);
    assert!(report.findings.iter().any(|c| c.id == "net/socket/create"));
}

#[test]
fn test_detect_mmap() {
    let code = r#"
#include <sys/mman.h>
int main() {
    void *ptr = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE, -1, 0);
}
"#;
    let report = analyze_c_code(code);
    assert!(report.findings.iter().any(|c| c.id == "memory/map"));
}

#[test]
fn test_detect_mprotect() {
    let code = r#"
#include <sys/mman.h>
int main() {
    mprotect(ptr, 1024, PROT_READ | PROT_WRITE | PROT_EXEC);
}
"#;
    let report = analyze_c_code(code);
    assert!(report.findings.iter().any(|c| c.id == "memory/protect"));
}

#[test]
fn test_detect_shellcode_pattern() {
    let code = r#"
#include <sys/mman.h>
int main() {
    void *mem = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE, -1, 0);
    mprotect(mem, 1024, PROT_READ | PROT_WRITE | PROT_EXEC);
}
"#;
    let report = analyze_c_code(code);
    // Should detect both individual capabilities
    assert!(report.findings.iter().any(|c| c.id == "memory/map"));
    assert!(report.findings.iter().any(|c| c.id == "memory/protect"));
}

#[test]
fn test_detect_ptrace() {
    let code = r#"
#include <sys/ptrace.h>
int main() {
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
}
"#;
    let report = analyze_c_code(code);
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "process/debug/attach"));
}

#[test]
fn test_detect_setuid() {
    let code = r#"
#include <unistd.h>
int main() {
    setuid(0);
}
"#;
    let report = analyze_c_code(code);
    assert!(report.findings.iter().any(|c| c.id == "privilege/setuid"));
}

#[test]
fn test_structural_feature() {
    let code = "int main() { return 0; }";
    let report = analyze_c_code(code);
    assert!(report.structure.iter().any(|s| s.id == "source/language/c"));
}

#[test]
fn test_multiple_capabilities() {
    let code = r#"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

int main() {
    system("whoami");
    char buf[10];
    strcpy(buf, "overflow");
    socket(AF_INET, SOCK_STREAM, 0);
}
"#;
    let report = analyze_c_code(code);
    assert!(report.findings.len() >= 3);
    assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "unsafe/buffer-overflow-risk"));
    assert!(report.findings.iter().any(|c| c.id == "net/socket/create"));
}

#[test]
fn test_can_analyze_c_extension() {
    let analyzer = CAnalyzer::new();
    let path = PathBuf::from("test.c");
    assert!(analyzer.can_analyze(&path));
}

#[test]
fn test_cannot_analyze_other_extension() {
    let analyzer = CAnalyzer::new();
    let path = PathBuf::from("test.txt");
    assert!(!analyzer.can_analyze(&path));
}

// ============================================================
// KERNEL MODULE / ROOTKIT DETECTION TESTS
// ============================================================

#[test]
fn test_detect_kernel_module_headers() {
    let code = r#"
#include <linux/kernel.h>
#include <linux/module.h>
int init_module(void) { return 0; }
"#;
    let report = analyze_c_code(code);
    assert!(report.findings.iter().any(|c| c.id == "kernel/module"));
    // Should be Hostile criticality
    let cap = report
        .findings
        .iter()
        .find(|c| c.id == "kernel/module")
        .unwrap();
    assert_eq!(cap.crit, Criticality::Hostile);
}

#[test]
fn test_detect_kallsyms_lookup() {
    let code = r#"
unsigned long *syscall_table;
void init(void) {
    syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
}
"#;
    let report = analyze_c_code(code);
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "kernel/symbol-lookup"));
}

#[test]
fn test_detect_credential_manipulation() {
    let code = r#"
void get_root(void) {
    struct cred *creds;
    creds = prepare_creds();
    creds->uid = 0;
    commit_creds(creds);
}
"#;
    let report = analyze_c_code(code);
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "kernel/credential-manipulation"));
    assert!(report.findings.iter().any(|c| c.id == "kernel/cred-struct"));
}

#[test]
fn test_detect_module_hiding() {
    let code = r#"
static struct list_head *prev;
void hide_module(void) {
    prev = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}
"#;
    let report = analyze_c_code(code);
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "kernel/list-manipulation"));
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "kernel/module-self-reference"));
}

#[test]
fn test_detect_syscall_table_hooking() {
    let code = r#"
unsigned long *__sys_call_table;
static t_syscall orig_getdents;

void hook_syscalls(void) {
    __sys_call_table[__NR_getdents] = (unsigned long)hooked_getdents;
}
"#;
    let report = analyze_c_code(code);
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "kernel/syscall-table"));
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "kernel/syscall-number"));
}

#[test]
fn test_detect_dirent_manipulation() {
    let code = r#"
struct linux_dirent64 *dir;
int hide_file(void) {
    prev->d_reclen += dir->d_reclen;
    return 0;
}
"#;
    let report = analyze_c_code(code);
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "kernel/dirent-manipulation"));
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "kernel/dirent-struct"));
}

#[test]
fn test_detect_kernel_memory_ops() {
    let code = r#"
void process_data(void) {
    void *buf = kzalloc(1024, GFP_KERNEL);
    copy_from_user(buf, user_buf, len);
    copy_to_user(dest, buf, len);
    kfree(buf);
}
"#;
    let report = analyze_c_code(code);
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "kernel/memory-alloc"));
    assert!(report.findings.iter().any(|c| c.id == "kernel/user-copy"));
    assert!(report.findings.iter().any(|c| c.id == "kernel/memory-free"));
}

#[test]
fn test_detect_cr0_manipulation() {
    let code = r#"
void disable_wp(void) {
    unsigned long cr0 = read_cr0();
    cr0 &= ~0x00010000;
    write_cr0(cr0);
}
"#;
    let report = analyze_c_code(code);
    assert!(report.findings.iter().any(|c| c.id == "kernel/cr0-read"));
    assert!(report.findings.iter().any(|c| c.id == "kernel/cr0-write"));
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "kernel/memory-protection-bypass"));
}

#[test]
fn test_detect_task_struct_manipulation() {
    let code = r#"
struct task_struct *find_task(pid_t pid) {
    struct task_struct *p = current;
    for_each_process(p) {
        if (p->pid == pid) return p;
    }
    return NULL;
}
"#;
    let report = analyze_c_code(code);
    assert!(report.findings.iter().any(|c| c.id == "kernel/task-struct"));
}

#[test]
fn test_detect_rootkit_comment() {
    let code = r#"
/* This is a rootkit for educational purposes */
int main() { return 0; }
"#;
    let report = analyze_c_code(code);
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "meta/rootkit-mention"));
}

#[test]
fn test_detect_module_init_exit() {
    let code = r#"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("test");
module_init(my_init);
module_exit(my_exit);
"#;
    let report = analyze_c_code(code);
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "kernel/module-metadata"));
    assert!(report.findings.iter().any(|c| c.id == "kernel/module-init"));
    assert!(report.findings.iter().any(|c| c.id == "kernel/module-exit"));
}

#[test]
fn test_detect_ftrace_helper() {
    let code = r#"
#include "library/ftrace_helper.h"
int main() { return 0; }
"#;
    let report = analyze_c_code(code);
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "kernel/rootkit-helper"));
}

#[test]
fn test_detect_inline_asm_cr0() {
    let code = r#"
void modify_cr0(unsigned long val) {
    asm volatile("mov %0, %%cr0" : : "r"(val));
}
"#;
    let report = analyze_c_code(code);
    // Should detect inline ASM with CR0
    assert!(report.findings.iter().any(|c| c.id == "unsafe/inline-asm"));
}

#[test]
fn test_detect_procfs_manipulation() {
    let code = r#"
#include <linux/proc_fs.h>
int check_proc(struct inode *inode) {
    if (inode->i_ino == PROC_ROOT_INO) return 1;
    return 0;
}
"#;
    let report = analyze_c_code(code);
    assert!(report.findings.iter().any(|c| c.id == "kernel/procfs"));
    assert!(report.findings.iter().any(|c| c.id == "kernel/procfs-root"));
}

#[test]
fn test_detect_privilege_escalation_uid() {
    let code = r#"
void escalate(void) {
    creds->uid = 0;
    creds->gid = 0;
    creds->euid = 0;
}
"#;
    let report = analyze_c_code(code);
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "privilege/root-credentials"));
}

#[test]
fn test_detect_task_flags_manipulation() {
    let code = r#"
void hide_process(struct task_struct *task) {
    task->flags ^= 0x10000000;
}
"#;
    let report = analyze_c_code(code);
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "kernel/task-flag-manipulation"));
}

#[test]
fn test_detect_dirent_header() {
    let code = r#"
#include <linux/dirent.h>
int main() { return 0; }
"#;
    let report = analyze_c_code(code);
    assert!(report.findings.iter().any(|c| c.id == "kernel/dirent"));
}

#[test]
fn test_detect_evasion_mention() {
    let code = r#"
/* Evasion technique to avoid detection by antivirus */
int main() { return 0; }
"#;
    let report = analyze_c_code(code);
    assert!(report
        .findings
        .iter()
        .any(|c| c.id == "meta/evasion-mention"));
}
