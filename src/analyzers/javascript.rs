use crate::analyzers::Analyzer;
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// JavaScript/Node.js analyzer using tree-sitter
pub struct JavaScriptAnalyzer {
    parser: RefCell<Parser>,
    capability_mapper: CapabilityMapper,
}

impl JavaScriptAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser.set_language(&tree_sitter_javascript::LANGUAGE.into()).unwrap();

        Self {
            parser: RefCell::new(parser),
            capability_mapper: CapabilityMapper::new(),
        }
    }

    fn analyze_script(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the JavaScript
        let tree = self.parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse JavaScript")?;

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "javascript".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "source/language/javascript".to_string(),
            description: "JavaScript source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-javascript".to_string(),
                value: "javascript".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        // Detect capabilities and obfuscation
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Check for cross-statement obfuscation patterns
        self.check_global_obfuscation(content, &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        // Detect JavaScript idioms
        let javascript_idioms = self.detect_javascript_idioms(&root, content.as_bytes());

        // Add idioms to source code metrics if they exist
        if let Some(ref mut metrics) = report.source_code_metrics {
            metrics.javascript_idioms = Some(javascript_idioms);
        }

        // Evaluate composite rules
        let composite_capabilities = self.capability_mapper.evaluate_composite_rules(&report, content.as_bytes());
        for cap in composite_capabilities {
            // Only add if not already present
            if !report.capabilities.iter().any(|c| c.id == cap.id) {
                report.capabilities.push(cap);
            }
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-javascript".to_string()];

        Ok(report)
    }

    fn detect_capabilities(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        let mut cursor = node.walk();
        self.walk_ast(&mut cursor, source, report);
    }

    fn walk_ast(&self, cursor: &mut tree_sitter::TreeCursor, source: &[u8], report: &mut AnalysisReport) {
        loop {
            let node = cursor.node();

            match node.kind() {
                "call_expression" => {
                    self.analyze_call(&node, source, report);
                }
                "import_statement" => {
                    self.analyze_import(&node, source, report);
                }
                "variable_declarator" => {
                    self.check_obfuscation(&node, source, report);
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
            let capability = if text.contains("eval(") {
                Some(("exec/script/eval", "Evaluates dynamic code", "eval"))
            } else if text.contains("Function(") {
                Some(("exec/script/eval", "Dynamic function constructor", "Function"))
            } else if text.contains("child_process.exec") || text.contains("child_process.execSync") ||
                      (text.starts_with("exec(") || text.contains(" exec(")) {
                Some(("exec/command/shell", "Execute shell commands", "exec"))
            } else if text.contains("child_process.spawn") || text.contains("child_process.spawnSync") ||
                      (text.starts_with("spawn(") || text.contains(" spawn(")) {
                Some(("exec/command/direct", "Spawn child process", "spawn"))
            } else if text.contains("require(") && !text.contains("require('") && !text.contains("require(\"") {
                // Dynamic require with variable
                Some(("anti-analysis/obfuscation/dynamic-import", "Dynamic require", "require(variable)"))
            } else if text.contains("fs.writeFile") || text.contains("fs.writeFileSync") {
                Some(("fs/write", "Write files", "fs.writeFile"))
            } else if text.contains("fs.unlink") || text.contains("fs.unlinkSync") || text.contains("fs.rm") {
                Some(("fs/delete", "Delete files", "fs.unlink"))
            } else if text.contains("fs.chmod") || text.contains("fs.chmodSync") {
                Some(("fs/permissions", "Change file permissions", "fs.chmod"))
            } else if text.contains("http.request") || text.contains("https.request") {
                Some(("net/http/client", "HTTP client operations", "http.request"))
            } else if text.contains("net.connect") || text.contains("net.createConnection") {
                Some(("net/socket/connect", "Network socket connection", "net.connect"))
            } else if text.contains("net.createServer") {
                Some(("net/socket/listen", "Create network server", "net.createServer"))
            } else if text.contains("Buffer.from") && text.contains("'base64'") {
                Some(("anti-analysis/obfuscation/base64", "Base64 decoding", "Buffer.from"))
            } else if text.contains("atob(") {
                Some(("anti-analysis/obfuscation/base64", "Base64 decoding (browser)", "atob"))
            } else {
                None
            };

            if let Some((cap_id, description, pattern)) = capability {
                if !report.capabilities.iter().any(|c| c.id == cap_id) {
                    report.capabilities.push(Capability {
                        id: cap_id.to_string(),
                        description: description.to_string(),
                        confidence: 1.0,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        evidence: vec![Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-javascript".to_string(),
                            value: pattern.to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                        traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                    });
                }
            }
        }
    }

    fn analyze_import(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            // Detect suspicious imports
            let suspicious_modules = [
                ("child_process", "exec/command/shell", "Child process execution"),
                ("fs", "fs/access", "Filesystem operations"),
                ("net", "net/socket/create", "Network sockets"),
                ("http", "net/http/client", "HTTP client"),
                ("https", "net/http/client", "HTTPS client"),
                ("crypto", "crypto/operation", "Cryptographic operations"),
                ("vm", "exec/script/eval", "Virtual machine (code execution)"),
            ];

            for (module, cap_id, description) in suspicious_modules {
                if text.contains(module) {
                    if !report.capabilities.iter().any(|c| c.id == cap_id) {
                        report.capabilities.push(Capability {
                            id: cap_id.to_string(),
                            description: description.to_string(),
                            confidence: 0.7, // Import alone is not definitive
                            criticality: Criticality::None,
                            mbc: None,
                            attack: None,
                            evidence: vec![Evidence {
                                method: "import".to_string(),
                                source: "tree-sitter-javascript".to_string(),
                                value: module.to_string(),
                                location: Some(format!("line:{}", node.start_position().row + 1)),
                            }],
                            traits: Vec::new(),
                        referenced_paths: None,
                        referenced_directories: None,
                        });
                    }
                }
            }
        }
    }

    fn check_global_obfuscation(&self, content: &str, report: &mut AnalysisReport) {
        // Check for base64 + eval pattern across the entire file
        let has_base64 = content.contains("Buffer.from") && content.contains("base64") || content.contains("atob(");
        let has_eval = content.contains("eval(") || content.contains("Function(");

        if has_base64 && has_eval {
            if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/base64-eval") {
                report.capabilities.push(Capability {
                    id: "anti-analysis/obfuscation/base64-eval".to_string(),
                    description: "Base64 decode followed by eval (obfuscation)".to_string(),
                    confidence: 0.95,
                    criticality: Criticality::None,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "pattern".to_string(),
                        source: "tree-sitter-javascript".to_string(),
                        value: "base64+eval".to_string(),
                        location: None,
                    }],
                traits: Vec::new(),
                referenced_paths: None,
                referenced_directories: None,
                });
            }
        }
    }

    fn check_obfuscation(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            // Detect base64 + eval pattern
            if (text.contains("Buffer.from") && text.contains("base64")) || text.contains("atob(") {
                if text.contains("eval(") || text.contains("Function(") {
                    if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/base64-eval") {
                        report.capabilities.push(Capability {
                            id: "anti-analysis/obfuscation/base64-eval".to_string(),
                            description: "Base64 decode followed by eval (obfuscation)".to_string(),
                            confidence: 0.95,
                            criticality: Criticality::None,
                            mbc: None,
                            attack: None,
                            evidence: vec![Evidence {
                                method: "pattern".to_string(),
                                source: "tree-sitter-javascript".to_string(),
                                value: "base64+eval".to_string(),
                                location: Some(format!("line:{}", node.start_position().row + 1)),
                            }],
                        traits: Vec::new(),
                        referenced_paths: None,
                        referenced_directories: None,
                        });
                    }
                }
            }

            // Detect hex string construction
            if text.contains("\\x") && text.matches("\\x").count() > 5 {
                if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/hex") {
                    report.capabilities.push(Capability {
                        id: "anti-analysis/obfuscation/hex".to_string(),
                        description: "Hex-encoded strings".to_string(),
                        confidence: 0.9,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        evidence: vec![Evidence {
                            method: "pattern".to_string(),
                            source: "tree-sitter-javascript".to_string(),
                            value: "hex_encoding".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                    });
                }
            }

            // Detect string manipulation obfuscation
            if text.contains(".split(") && text.contains(".reverse()") && text.contains(".join(") {
                if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/string-construct") {
                    report.capabilities.push(Capability {
                        id: "anti-analysis/obfuscation/string-construct".to_string(),
                        description: "String manipulation obfuscation".to_string(),
                        confidence: 0.9,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        evidence: vec![Evidence {
                            method: "pattern".to_string(),
                            source: "tree-sitter-javascript".to_string(),
                            value: "split_reverse_join".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                    });
                }
            }

            // Detect charAt obfuscation
            if text.contains(".charAt(") && text.matches(".charAt(").count() > 5 {
                if !report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/string-construct") {
                    report.capabilities.push(Capability {
                        id: "anti-analysis/obfuscation/string-construct".to_string(),
                        description: "Character-by-character string construction".to_string(),
                        confidence: 0.85,
                        criticality: Criticality::None,
                        mbc: None,
                        attack: None,
                        evidence: vec![Evidence {
                            method: "pattern".to_string(),
                            source: "tree-sitter-javascript".to_string(),
                            value: "charAt_pattern".to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
                    });
                }
            }
        }
    }

    /// Calculate cyclomatic complexity for a JavaScript function
    /// CC = decision points + 1
    fn calculate_cyclomatic_complexity(&self, node: &tree_sitter::Node, source: &[u8]) -> u32 {
        let mut complexity = 1; // Base complexity
        let mut cursor = node.walk();

        loop {
            let current = cursor.node();
            match current.kind() {
                "if_statement" => complexity += 1,
                "switch_case" => complexity += 1,
                "for_statement" | "for_in_statement" => complexity += 1,
                "while_statement" | "do_statement" => complexity += 1,
                "catch_clause" => complexity += 1,
                "ternary_expression" => complexity += 1,
                "binary_expression" => {
                    if let Ok(text) = current.utf8_text(source) {
                        if text.contains("&&") || text.contains("||") {
                            complexity += 1;
                        }
                    }
                }
                _ => {}
            }

            // Traverse
            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return complexity;
                }
            }
        }
    }

    /// Analyze function signature (params, arrow vs regular, async, etc.)
    fn analyze_function_signature(&self, node: &tree_sitter::Node, source: &[u8]) -> FunctionSignature {
        let mut param_count = 0u32;
        let mut default_param_count = 0u32;
        let mut has_var_positional = false; // rest params
        let mut has_type_hints = false; // TypeScript
        let mut has_return_type = false; // TypeScript
        let mut is_async = false;
        let is_generator = false;
        let is_lambda = node.kind() == "arrow_function";

        // Check for async
        if let Some(parent) = node.parent() {
            if parent.kind() == "function_declaration" || parent.kind() == "method_definition" {
                let mut cursor = parent.walk();
                for child in parent.children(&mut cursor) {
                    if child.kind() == "async" {
                        is_async = true;
                        break;
                    }
                }
            }
        }
        // Also check if node itself has async
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "async" {
                is_async = true;
                break;
            }
        }

        // Extract parameters
        if let Some(params_node) = node.child_by_field_name("parameters") {
            let mut param_cursor = params_node.walk();
            for child in params_node.children(&mut param_cursor) {
                match child.kind() {
                    "identifier" | "required_parameter" | "optional_parameter" => {
                        param_count += 1;
                    }
                    "assignment_pattern" => {
                        param_count += 1;
                        default_param_count += 1;
                    }
                    "rest_pattern" => {
                        has_var_positional = true;
                        param_count += 1;
                    }
                    _ => {}
                }
            }
        }

        FunctionSignature {
            param_count,
            default_param_count,
            has_var_positional,
            has_var_keyword: false, // JavaScript doesn't have **kwargs
            has_type_hints,
            has_return_type,
            decorators: Vec::new(), // JavaScript doesn't have decorators (except TS experimental)
            is_async,
            is_generator,
            is_lambda,
        }
    }

    /// Calculate nesting depth of control structures
    fn calculate_nesting_depth(&self, node: &tree_sitter::Node) -> NestingMetrics {
        let mut max_depth = 0u32;
        let mut depths = Vec::new();
        let mut deep_nest_count = 0u32;

        fn traverse(node: &tree_sitter::Node, current_depth: u32, max: &mut u32,
                    depths: &mut Vec<u32>, deep: &mut u32) {
            let mut depth = current_depth;
            match node.kind() {
                "if_statement" | "for_statement" | "for_in_statement" |
                "while_statement" | "do_statement" | "switch_statement" |
                "try_statement" => {
                    depth += 1;
                    depths.push(depth);
                    if depth > *max {
                        *max = depth;
                    }
                    if depth > 4 {
                        *deep += 1;
                    }
                }
                _ => {}
            }

            // Recurse through children
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                traverse(&child, depth, max, depths, deep);
            }
        }

        traverse(node, 0, &mut max_depth, &mut depths, &mut deep_nest_count);

        NestingMetrics {
            max_depth,
            avg_depth: if !depths.is_empty() {
                depths.iter().sum::<u32>() as f32 / depths.len() as f32
            } else {
                0.0
            },
            deep_nest_count,
        }
    }

    /// Analyze call patterns (promise chains, callbacks, recursion, dynamic calls)
    fn analyze_call_patterns(&self, node: &tree_sitter::Node, source: &[u8], func_name: &str) -> CallPatternMetrics {
        let mut call_count = 0u32;
        let mut callees: Vec<String> = Vec::new();
        let mut recursive_calls = 0u32;
        let mut dynamic_calls = 0u32;
        let mut chained_calls = 0u32;
        let mut max_chain_length = 0u32;

        let mut cursor = node.walk();
        loop {
            let current = cursor.node();
            if current.kind() == "call_expression" {
                call_count += 1;

                if let Some(func_node) = current.child_by_field_name("function") {
                    if let Ok(func_text) = func_node.utf8_text(source) {
                        let func_str = func_text.to_string();
                        callees.push(func_str.clone());

                        // Check recursion
                        if func_str == func_name || func_str.ends_with(&format!(".{}", func_name)) {
                            recursive_calls += 1;
                        }

                        // Check dynamic calls
                        if ["eval", "Function", "setTimeout", "setInterval"].iter().any(|&d| func_str.contains(d)) {
                            dynamic_calls += 1;
                        }

                        // Count method chaining
                        let chain_length = func_str.matches('.').count() as u32;
                        if chain_length > 0 {
                            chained_calls += 1;
                            if chain_length > max_chain_length {
                                max_chain_length = chain_length;
                            }
                        }
                    }
                }
            }

            // Traverse
            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    // Deduplicate callees
                    callees.sort();
                    callees.dedup();

                    return CallPatternMetrics {
                        call_count,
                        unique_callees: callees.len() as u32,
                        chained_calls,
                        max_chain_length,
                        recursive_calls,
                        dynamic_calls,
                    };
                }
            }
        }
    }

    /// Detect JavaScript-specific idioms
    fn detect_javascript_idioms(&self, root: &tree_sitter::Node, source: &[u8]) -> JavaScriptIdioms {
        let mut arrow_function_count = 0u32;
        let mut promise_count = 0u32;
        let mut async_await_count = 0u32;
        let mut template_literal_count = 0u32;
        let mut destructuring_count = 0u32;
        let mut spread_operator_count = 0u32;
        let mut class_count = 0u32;
        let mut callback_count = 0u32;
        let mut iife_count = 0u32;
        let mut object_shorthand_count = 0u32;
        let mut optional_chaining_count = 0u32;
        let mut nullish_coalescing_count = 0u32;

        let mut cursor = root.walk();
        loop {
            let node = cursor.node();
            match node.kind() {
                "arrow_function" => {
                    arrow_function_count += 1;
                    // Check if it's a callback (passed as argument)
                    if let Some(parent) = node.parent() {
                        if parent.kind() == "arguments" {
                            callback_count += 1;
                        }
                    }
                }
                "class_declaration" => {
                    class_count += 1;
                }
                "template_string" => {
                    template_literal_count += 1;
                }
                "spread_element" => {
                    spread_operator_count += 1;
                }
                "object_pattern" | "array_pattern" => {
                    destructuring_count += 1;
                }
                "optional_chain" => {
                    optional_chaining_count += 1;
                }
                "call_expression" => {
                    if let Ok(text) = node.utf8_text(source) {
                        // Promise detection
                        if text.contains("new Promise") || text.contains(".then(") ||
                           text.contains(".catch(") || text.contains(".finally(") {
                            promise_count += 1;
                        }
                        // IIFE detection
                        if text.starts_with("(function") || text.starts_with("(async function") {
                            iife_count += 1;
                        }
                    }
                }
                "function_declaration" | "method_definition" => {
                    // Check for async
                    let mut func_cursor = node.walk();
                    for child in node.children(&mut func_cursor) {
                        if child.kind() == "async" {
                            async_await_count += 1;
                            break;
                        }
                    }
                }
                "binary_expression" => {
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("??") {
                            nullish_coalescing_count += 1;
                        }
                    }
                }
                _ => {}
            }

            // Traverse
            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return JavaScriptIdioms {
                        arrow_function_count,
                        promise_count,
                        async_await_count,
                        template_literal_count,
                        destructuring_count,
                        spread_operator_count,
                        class_count,
                        callback_count,
                        iife_count,
                        object_shorthand_count,
                        optional_chaining_count,
                        nullish_coalescing_count,
                    };
                }
            }
        }
    }

    fn extract_functions(&self, root: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        let mut cursor = root.walk();

        loop {
            let node = cursor.node();

            // Match both function declarations and arrow functions
            if matches!(node.kind(), "function_declaration" | "arrow_function" | "function" | "method_definition") {
                let func_name = if let Some(name_node) = node.child_by_field_name("name") {
                    name_node.utf8_text(source).unwrap_or("<unnamed>").to_string()
                } else {
                    "<anonymous>".to_string()
                };

                // Calculate all metrics
                let complexity = self.calculate_cyclomatic_complexity(&node, source);
                let signature = self.analyze_function_signature(&node, source);
                let nesting = self.calculate_nesting_depth(&node);
                let call_patterns = self.analyze_call_patterns(&node, source, &func_name);

                // Extract actual function calls
                let mut calls = Vec::new();
                let mut call_cursor = node.walk();
                loop {
                    let call_node = call_cursor.node();
                    if call_node.kind() == "call_expression" {
                        if let Some(func_node) = call_node.child_by_field_name("function") {
                            if let Ok(func_text) = func_node.utf8_text(source) {
                                calls.push(func_text.to_string());
                            }
                        }
                    }
                    if call_cursor.goto_first_child() {
                        continue;
                    }
                    loop {
                        if call_cursor.goto_next_sibling() {
                            break;
                        }
                        if !call_cursor.goto_parent() {
                            break;
                        }
                    }
                    if call_cursor.node() == node {
                        break;
                    }
                }
                calls.sort();
                calls.dedup();

                // Build control flow metrics
                let control_flow = ControlFlowMetrics {
                    basic_blocks: complexity, // Approximation: CC relates to BBs
                    edges: if complexity > 1 { complexity + 1 } else { 1 },
                    cyclomatic_complexity: complexity,
                    max_block_size: 0, // Not easily calculated from tree-sitter
                    avg_block_size: 0.0,
                    is_linear: complexity == 1,
                    loop_count: 0, // Could count for/while nodes if needed
                    branch_density: 0.0,
                    in_degree: 0, // Would need global call graph analysis
                    out_degree: call_patterns.unique_callees,
                };

                // Build properties
                let properties = FunctionProperties {
                    is_pure: false, // Hard to determine from AST alone
                    is_noreturn: false,
                    is_recursive: call_patterns.recursive_calls > 0,
                    stack_frame: 0, // Not applicable to JavaScript
                    local_vars: 0, // Could count variable declarations if needed
                    args: signature.param_count,
                    is_leaf: call_patterns.call_count == 0,
                };

                report.functions.push(Function {
                    name: func_name,
                    offset: Some(format!("line:{}", node.start_position().row + 1)),
                    size: Some((node.end_byte() - node.start_byte()) as u64),
                    complexity: Some(complexity),
                    calls,
                    source: "tree-sitter-javascript".to_string(),
                    control_flow: Some(control_flow),
                    instruction_analysis: None,
                    register_usage: None,
                    constants: Vec::new(),
                    properties: Some(properties),
                    call_patterns: Some(call_patterns),
                    nesting: Some(nesting),
                    signature: Some(signature),
                });
            }

            // Recurse
            if cursor.goto_first_child() {
                continue;
            }

            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return;
                }
            }
        }
    }

    fn calculate_sha256(&self, data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

impl Default for JavaScriptAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for JavaScriptAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let content = fs::read_to_string(file_path)
            .context("Failed to read JavaScript file")?;

        self.analyze_script(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            matches!(ext.to_str(), Some("js") | Some("mjs") | Some("cjs"))
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_script() {
        let analyzer = JavaScriptAnalyzer::new();
        let script = r#"
            const fs = require('fs');
            const { exec } = require('child_process');

            exec('rm -rf /tmp/test', (error, stdout, stderr) => {
                console.log(stdout);
            });

            fs.writeFileSync('/tmp/malicious.txt', 'payload');
        "#;

        let report = analyzer.analyze_script(Path::new("test.js"), script).unwrap();

        // Should detect exec and fs imports
        assert!(!report.capabilities.is_empty());

        // Should detect shell execution
        assert!(report.capabilities.iter().any(|c| c.id.contains("exec/command")));

        // Should detect file write
        assert!(report.capabilities.iter().any(|c| c.id.contains("fs/write")));
    }

    #[test]
    fn test_obfuscated_script() {
        let analyzer = JavaScriptAnalyzer::new();
        let script = r#"
            const payload = Buffer.from('Y3VybCBldmlsLmNvbQ==', 'base64').toString();
            eval(payload);
        "#;

        let report = analyzer.analyze_script(Path::new("test.js"), script).unwrap();

        // Should detect base64 + eval obfuscation
        assert!(report.capabilities.iter().any(|c| c.id == "anti-analysis/obfuscation/base64-eval"));
    }
}
