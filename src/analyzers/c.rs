use crate::analyzers::Analyzer;
use crate::analyzers::{
    comment_metrics::{self, CommentStyle},
    function_metrics::{self, FunctionInfo},
    identifier_metrics, string_metrics, symbol_extraction, text_metrics,
};
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// C analyzer using tree-sitter
pub struct CAnalyzer {
    parser: RefCell<Parser>,
    capability_mapper: CapabilityMapper,
}

impl Default for CAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl CAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .unwrap();

        Self {
            parser: RefCell::new(parser),
            capability_mapper: CapabilityMapper::empty(),
        }
    }

    /// Create analyzer with pre-existing capability mapper (avoids duplicate loading)
    pub fn with_capability_mapper(mut self, capability_mapper: CapabilityMapper) -> Self {
        self.capability_mapper = capability_mapper;
        self
    }

    fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the C source
        let tree = self
            .parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse C source")?;

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "c".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "source/language/c".to_string(),
            description: "C source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-c".to_string(),
                value: "c".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        // Detect capabilities and patterns
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        // Extract function calls as symbols for symbol-based rule matching
        symbol_extraction::extract_symbols(
            content,
            tree_sitter_c::LANGUAGE.into(),
            &["call_expression"],
            &mut report,
        );

        // Compute metrics for ML analysis (BEFORE trait evaluation)
        let metrics = self.compute_metrics(&root, content);
        report.metrics = Some(metrics);

        // Evaluate YAML trait definitions first
        let trait_findings = self
            .capability_mapper
            .evaluate_traits(&report, content.as_bytes());

        // Add trait findings to report immediately so composite rules can see them
        for f in trait_findings {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }

        // Now evaluate composite rules (which can reference the traits above)
        let composite_findings = self
            .capability_mapper
            .evaluate_composite_rules(&report, content.as_bytes());

        // Add composite findings
        for f in composite_findings {
            if !report.findings.iter().any(|existing| existing.id == f.id) {
                report.findings.push(f);
            }
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-c".to_string()];

        Ok(report)
    }

    fn compute_metrics(&self, root: &tree_sitter::Node, content: &str) -> Metrics {
        let source = content.as_bytes();
        let total_lines = content.lines().count() as u32;

        let text = text_metrics::analyze_text(content);

        let identifiers = self.extract_identifiers(root, source);
        let ident_refs: Vec<&str> = identifiers.iter().map(|s| s.as_str()).collect();
        let identifier_metrics = identifier_metrics::analyze_identifiers(&ident_refs);

        let strings = self.extract_string_literals(root, source);
        let str_refs: Vec<&str> = strings.iter().map(|s| s.as_str()).collect();
        let string_metrics = string_metrics::analyze_strings(&str_refs);

        let comment_metrics = comment_metrics::analyze_comments(content, CommentStyle::CStyle);

        let func_infos = self.extract_function_info(root, source);
        let func_metrics = function_metrics::analyze_functions(&func_infos, total_lines);

        Metrics {
            text: Some(text),
            identifiers: Some(identifier_metrics),
            strings: Some(string_metrics),
            comments: Some(comment_metrics),
            functions: Some(func_metrics),
            ..Default::default()
        }
    }

    fn extract_identifiers(&self, root: &tree_sitter::Node, source: &[u8]) -> Vec<String> {
        let mut identifiers = Vec::new();
        let mut cursor = root.walk();
        self.walk_for_identifiers(&mut cursor, source, &mut identifiers);
        identifiers
    }

    fn walk_for_identifiers(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        identifiers: &mut Vec<String>,
    ) {
        loop {
            let node = cursor.node();
            if node.kind() == "identifier" || node.kind() == "field_identifier" {
                if let Ok(text) = node.utf8_text(source) {
                    if !text.is_empty() {
                        identifiers.push(text.to_string());
                    }
                }
            }
            if cursor.goto_first_child() {
                self.walk_for_identifiers(cursor, source, identifiers);
                cursor.goto_parent();
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn extract_string_literals(&self, root: &tree_sitter::Node, source: &[u8]) -> Vec<String> {
        let mut strings = Vec::new();
        let mut cursor = root.walk();
        self.walk_for_strings(&mut cursor, source, &mut strings);
        strings
    }

    fn walk_for_strings(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        strings: &mut Vec<String>,
    ) {
        loop {
            let node = cursor.node();
            if node.kind() == "string_literal" {
                if let Ok(text) = node.utf8_text(source) {
                    let s = text.trim_start_matches('"').trim_end_matches('"');
                    if !s.is_empty() {
                        strings.push(s.to_string());
                    }
                }
            }
            if cursor.goto_first_child() {
                self.walk_for_strings(cursor, source, strings);
                cursor.goto_parent();
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn extract_function_info(&self, root: &tree_sitter::Node, source: &[u8]) -> Vec<FunctionInfo> {
        let mut functions = Vec::new();
        let mut cursor = root.walk();
        self.walk_for_function_info(&mut cursor, source, &mut functions, 0);
        functions
    }

    fn walk_for_function_info(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        functions: &mut Vec<FunctionInfo>,
        depth: u32,
    ) {
        loop {
            let node = cursor.node();
            let kind = node.kind();

            if kind == "function_definition" {
                let mut info = FunctionInfo::default();
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    // Find the function name within the declarator
                    let mut decl_cursor = declarator.walk();
                    self.find_function_name(&mut decl_cursor, source, &mut info);
                }
                info.start_line = node.start_position().row as u32;
                info.end_line = node.end_position().row as u32;
                info.line_count = info.end_line.saturating_sub(info.start_line) + 1;
                info.nesting_depth = depth;
                functions.push(info);
            }

            if cursor.goto_first_child() {
                let new_depth = if kind == "function_definition" {
                    depth + 1
                } else {
                    depth
                };
                self.walk_for_function_info(cursor, source, functions, new_depth);
                cursor.goto_parent();
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn find_function_name(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        info: &mut FunctionInfo,
    ) {
        loop {
            let node = cursor.node();
            if node.kind() == "identifier" {
                if let Ok(name) = node.utf8_text(source) {
                    info.name = name.to_string();
                    return;
                }
            }
            if node.kind() == "parameter_list" {
                // Count parameters
                let mut param_cursor = node.walk();
                if param_cursor.goto_first_child() {
                    loop {
                        let param = param_cursor.node();
                        if param.kind() == "parameter_declaration" {
                            info.param_count += 1;
                        }
                        if !param_cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }
            if cursor.goto_first_child() {
                self.find_function_name(cursor, source, info);
                cursor.goto_parent();
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn detect_capabilities(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let mut cursor = node.walk();
        self.walk_ast(&mut cursor, source, report);
    }

    fn walk_ast(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        loop {
            let node = cursor.node();

            match node.kind() {
                "call_expression" => {
                    self.analyze_call(&node, source, report);
                }
                "preproc_include" => {
                    self.analyze_include(&node, source, report);
                }
                "asm_statement" | "gnu_asm_expression" => {
                    self.analyze_asm(&node, source, report);
                }
                "declaration" => {
                    self.analyze_declaration(&node, source, report);
                }
                "assignment_expression" | "update_expression" | "binary_expression" => {
                    self.analyze_expression(&node, source, report);
                }
                "comment" => {
                    self.analyze_comment(&node, source, report);
                }
                "preproc_call" | "preproc_function_def" | "expression_statement" => {
                    self.analyze_preproc_call(&node, source, report);
                }
                "function_definition" => {
                    self.analyze_function_definition(&node, source, report);
                }
                "subscript_expression" | "field_expression" => {
                    // Analyze array subscript for syscall table access
                    // and field access for THIS_MODULE, task->flags, etc.
                    self.analyze_expression(&node, source, report);
                }
                _ => {}
            }

            // Recurse
            if cursor.goto_first_child() {
                self.walk_ast(cursor, source, report);
                cursor.goto_parent();
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn analyze_call(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
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
                    description: desc.to_string(),
                    confidence: conf,
                    criticality,
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

    fn analyze_include(
        &self,
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
                    description: desc.to_string(),
                    confidence: conf,
                    criticality,
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

    fn analyze_asm(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
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
        } else if asm_text.contains("cr3") || asm_text.contains("CR3") || asm_text.contains("%cr3")
        {
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
            description: description.to_string(),
            confidence: 1.0,
            criticality,
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

    fn analyze_declaration(
        &self,
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
                    description: desc.to_string(),
                    confidence: conf,
                    criticality,
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

    fn analyze_expression(
        &self,
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
                    description: desc.to_string(),
                    confidence: conf,
                    criticality,
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

    fn analyze_comment(
        &self,
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
                    description: desc.to_string(),
                    confidence: conf,
                    criticality,
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

    fn analyze_preproc_call(
        &self,
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
                    description: desc.to_string(),
                    confidence: conf,
                    criticality,
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

    fn analyze_function_definition(
        &self,
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
            let name = self
                .extract_function_name(node, source)
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
                    description: desc.to_string(),
                    confidence: conf,
                    criticality,
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

    fn extract_functions(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let mut cursor = node.walk();
        self.walk_for_functions(&mut cursor, source, report);
    }

    fn walk_for_functions(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        loop {
            let node = cursor.node();

            if node.kind() == "function_definition" {
                if let Ok(_text) = node.utf8_text(source) {
                    // Extract function name
                    let name = self
                        .extract_function_name(&node, source)
                        .unwrap_or_else(|| "anonymous".to_string());

                    report.functions.push(Function {
                        name,
                        offset: Some(format!("0x{:x}", node.start_byte())),
                        size: Some((node.end_byte() - node.start_byte()) as u64),
                        complexity: None,
                        calls: Vec::new(),
                        source: "tree-sitter-c".to_string(),
                        control_flow: None,
                        instruction_analysis: None,
                        register_usage: None,
                        constants: Vec::new(),
                        properties: None,
                        signature: None,
                        nesting: None,
                        call_patterns: None,
                    });
                }
            }

            // Recurse
            if cursor.goto_first_child() {
                self.walk_for_functions(cursor, source, report);
                cursor.goto_parent();
            }

            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn extract_function_name(&self, node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
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

    fn calculate_sha256(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

impl Analyzer for CAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let bytes = fs::read(file_path).context("Failed to read C file")?;
        let content = String::from_utf8_lossy(&bytes);
        self.analyze_source(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path.extension().and_then(|e| e.to_str()) == Some("c")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
                .confidence,
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
        assert_eq!(cap.criticality, Criticality::Hostile);
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
}
