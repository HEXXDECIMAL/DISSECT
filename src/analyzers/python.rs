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

/// Python analyzer using tree-sitter
pub struct PythonAnalyzer {
    parser: RefCell<Parser>,
    capability_mapper: CapabilityMapper,
}

impl PythonAnalyzer {
    /// Creates a new Python analyzer with tree-sitter Python parser
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
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

    fn analyze_script(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the Python script
        let tree = self
            .parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse Python script")?;

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "python_script".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "source/language/python".to_string(),
            desc: "Python script".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-python".to_string(),
                value: "python".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        // Detect capabilities and obfuscation
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        // Extract function calls as symbols for symbol-based rule matching
        symbol_extraction::extract_symbols(
            content,
            tree_sitter_python::LANGUAGE.into(),
            &["call"],
            &mut report,
        );

        // Analyze paths and generate path-based traits
        crate::path_mapper::analyze_and_link_paths(&mut report);

        // Analyze environment variables and generate env-based traits
        crate::env_mapper::analyze_and_link_env_vars(&mut report);

        // === Compute metrics for ML analysis (BEFORE trait evaluation) ===
        let metrics = self.compute_metrics(&root, content);
        report.metrics = Some(metrics);

        // Evaluate trait definitions first
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
        report.metadata.tools_used = vec!["tree-sitter-python".to_string()];

        Ok(report)
    }

    /// Compute all metrics for Python code
    fn compute_metrics(&self, root: &tree_sitter::Node, content: &str) -> Metrics {
        let source = content.as_bytes();
        let total_lines = content.lines().count() as u32;

        // Universal text metrics
        let text = text_metrics::analyze_text(content);

        // Extract identifiers from AST
        let identifiers = self.extract_identifiers(root, source);
        let ident_refs: Vec<&str> = identifiers.iter().map(|s| s.as_str()).collect();
        let identifier_metrics = identifier_metrics::analyze_identifiers(&ident_refs);

        // Extract strings from AST
        let strings = self.extract_string_literals(root, source);
        let str_refs: Vec<&str> = strings.iter().map(|s| s.as_str()).collect();
        let string_metrics = string_metrics::analyze_strings(&str_refs);

        // Comment metrics
        let comment_metrics = comment_metrics::analyze_comments(content, CommentStyle::Hash);

        // Function metrics
        let func_infos = self.extract_function_info(root, source);
        let func_metrics = function_metrics::analyze_functions(&func_infos, total_lines);

        // Python-specific metrics
        let python_metrics = self.compute_python_metrics(root, source, content);

        Metrics {
            text: Some(text),
            identifiers: Some(identifier_metrics),
            strings: Some(string_metrics),
            comments: Some(comment_metrics),
            functions: Some(func_metrics),
            python: Some(python_metrics),
            ..Default::default()
        }
    }

    /// Extract function information from the AST for metrics
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
        initial_depth: u32,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        let mut depth = initial_depth;
        loop {
            let node = cursor.node();

            if node.kind() == "function_definition" {
                let mut info = FunctionInfo::default();

                // Get function name
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(source) {
                        info.name = name.to_string();
                    }
                }

                // Get parameters
                if let Some(params_node) = node.child_by_field_name("parameters") {
                    let mut param_cursor = params_node.walk();
                    if param_cursor.goto_first_child() {
                        loop {
                            let param = param_cursor.node();
                            if param.kind() == "identifier" {
                                if let Ok(param_name) = param.utf8_text(source) {
                                    info.param_names.push(param_name.to_string());
                                    info.param_count += 1;
                                }
                            } else if param.kind() == "typed_parameter"
                                || param.kind() == "default_parameter"
                            {
                                // Extract name from typed/default parameter
                                if let Some(name_node) = param.child_by_field_name("name") {
                                    if let Ok(param_name) = name_node.utf8_text(source) {
                                        info.param_names.push(param_name.to_string());
                                        info.param_count += 1;
                                    }
                                } else if let Ok(text) = param.utf8_text(source) {
                                    // Fallback: get first identifier-like part
                                    if let Some(name) = text.split([':', '=']).next() {
                                        let name = name.trim();
                                        if !name.is_empty() {
                                            info.param_names.push(name.to_string());
                                            info.param_count += 1;
                                        }
                                    }
                                }
                            }
                            if !param_cursor.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }

                // Line count
                info.start_line = node.start_position().row as u32;
                info.end_line = node.end_position().row as u32;
                info.line_count = info.end_line.saturating_sub(info.start_line) + 1;

                // Check for async
                if let Ok(text) = node.utf8_text(source) {
                    if text.starts_with("async ") {
                        info.is_async = true;
                    }
                }

                info.nesting_depth = depth;

                // Check for nested functions
                if let Some(body) = node.child_by_field_name("body") {
                    let body_text = body.utf8_text(source).unwrap_or("");
                    if body_text.contains("def ") {
                        info.contains_nested_functions = true;
                    }
                }

                functions.push(info);
            } else if node.kind() == "lambda" {
                let mut info = FunctionInfo {
                    is_anonymous: true,
                    start_line: node.start_position().row as u32,
                    end_line: node.end_position().row as u32,
                    line_count: 1,
                    nesting_depth: depth,
                    ..Default::default()
                };

                // Count lambda parameters
                if let Some(params) = node.child_by_field_name("parameters") {
                    let mut param_cursor = params.walk();
                    if param_cursor.goto_first_child() {
                        loop {
                            if param_cursor.node().kind() == "identifier" {
                                if let Ok(name) = param_cursor.node().utf8_text(source) {
                                    info.param_names.push(name.to_string());
                                    info.param_count += 1;
                                }
                            }
                            if !param_cursor.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }

                functions.push(info);
            }

            // Increase depth when entering function bodies
            if node.kind() == "function_definition" || node.kind() == "lambda" {
                depth += 1;
            }

            if cursor.goto_first_child() {
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                // Decrease depth when leaving function bodies
                let parent = cursor.node();
                if parent.kind() == "function_definition" || parent.kind() == "lambda" {
                    depth = depth.saturating_sub(1);
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Extract all identifiers from the AST
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
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            if node.kind() == "identifier" {
                if let Ok(text) = node.utf8_text(source) {
                    identifiers.push(text.to_string());
                }
            }

            if cursor.goto_first_child() {
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Extract all string literals from the AST
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
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            if node.kind() == "string" || node.kind() == "string_content" {
                if let Ok(text) = node.utf8_text(source) {
                    // Strip quotes if present
                    let s = text.trim_matches(|c| c == '"' || c == '\'');
                    if !s.is_empty() {
                        strings.push(s.to_string());
                    }
                }
            }

            if cursor.goto_first_child() {
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    /// Compute Python-specific metrics
    fn compute_python_metrics(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
        content: &str,
    ) -> PythonMetrics {
        let mut metrics = PythonMetrics::default();
        let mut cursor = root.walk();
        self.walk_for_python_metrics(&mut cursor, source, &mut metrics);

        // Additional pattern-based detection
        metrics.chr_calls += content.matches("chr(").count() as u32;
        metrics.ord_calls += content.matches("ord(").count() as u32;

        metrics
    }

    fn walk_for_python_metrics(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        source: &[u8],
        metrics: &mut PythonMetrics,
    ) {
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            match node.kind() {
                "call" => {
                    if let Ok(text) = node.utf8_text(source) {
                        // Dynamic execution
                        if text.starts_with("eval(") {
                            metrics.eval_count += 1;
                        }
                        if text.starts_with("exec(") {
                            metrics.exec_count += 1;
                        }
                        if text.starts_with("compile(") {
                            metrics.compile_count += 1;
                        }
                        if text.starts_with("__import__(") {
                            metrics.dunder_import_count += 1;
                        }
                        if text.contains("importlib") {
                            metrics.importlib_count += 1;
                        }

                        // Attribute manipulation
                        if text.starts_with("getattr(")
                            || text.starts_with("setattr(")
                            || text.starts_with("delattr(")
                            || text.starts_with("hasattr(")
                        {
                            metrics.attr_manipulation_count += 1;
                        }

                        // Reflection
                        if text.starts_with("globals(") || text.starts_with("locals(") {
                            metrics.globals_locals_access += 1;
                        }
                        if text.starts_with("vars(") {
                            metrics.vars_access += 1;
                        }
                        if text.starts_with("type(") && text.contains(",") {
                            // type() with 3 args creates a class dynamically
                            metrics.type_manipulation += 1;
                        }

                        // Code manipulation
                        if text.contains(".__code__") || text.contains("__code__") {
                            metrics.code_object_access += 1;
                        }

                        // Frame access
                        if text.contains("sys._getframe") || text.contains("inspect.currentframe") {
                            metrics.frame_access += 1;
                        }

                        // Marshaling
                        if text.contains("marshal.loads") || text.contains("marshal.dumps") {
                            metrics.marshal_usage += 1;
                        }
                    }
                }
                "lambda" => {
                    metrics.lambda_count += 1;

                    // Check for nested lambda
                    if let Ok(text) = node.utf8_text(source) {
                        if text.matches("lambda").count() > 1 {
                            metrics.nested_lambda_count += 1;
                        }
                    }
                }
                "list_comprehension"
                | "dict_comprehension"
                | "set_comprehension"
                | "generator_expression" => {
                    // Count comprehension depth by nested fors
                    if let Ok(text) = node.utf8_text(source) {
                        let depth = text.matches(" for ").count() as u32;
                        if depth > metrics.comprehension_depth_max {
                            metrics.comprehension_depth_max = depth;
                        }
                    }
                }
                "named_expression" => {
                    // Walrus operator :=
                    metrics.walrus_operator_count += 1;
                }
                "decorator" => {
                    metrics.decorator_count += 1;
                }
                "class_definition" => {
                    metrics.class_count += 1;

                    // Check for metaclass
                    if let Ok(text) = node.utf8_text(source) {
                        if text.contains("metaclass=") {
                            metrics.metaclass_usage += 1;
                        }
                    }
                }
                "with_statement" => {
                    metrics.with_statement_count += 1;
                }
                "try_statement" => {
                    metrics.try_except_count += 1;
                }
                "assert_statement" => {
                    metrics.assert_count += 1;
                }
                _ => {}
            }

            if cursor.goto_first_child() {
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                if cursor.goto_next_sibling() {
                    break;
                }
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
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            match node.kind() {
                "call" => {
                    self.analyze_call(&node, source, report);
                    self.analyze_env_var_access(&node, source, report);
                }
                "import_statement" | "import_from_statement" => {
                    self.analyze_import(&node, source, report);
                }
                "assignment" => {
                    self.check_obfuscation(&node, source, report);
                    self.analyze_env_var_access(&node, source, report);
                }
                "subscript" => {
                    // This catches os.environ['VAR'] expressions
                    self.analyze_env_var_access(&node, source, report);
                }
                _ => {}
            }

            if cursor.goto_first_child() {
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                if cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    fn analyze_call(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            let capability = if text.contains("eval(") {
                Some((
                    "exec/script/eval",
                    "Evaluates dynamic code",
                    "eval",
                    Criticality::Notable,
                ))
            } else if text.contains("exec(") {
                Some((
                    "exec/script/eval",
                    "Executes dynamic code",
                    "exec",
                    Criticality::Notable,
                ))
            } else if text.contains("compile(") {
                Some((
                    "exec/script/eval",
                    "Compiles dynamic code",
                    "compile",
                    Criticality::Notable,
                ))
            } else if text.contains("__import__(") {
                Some((
                    "anti-analysis/obfuscation/dynamic-import",
                    "Dynamic module import",
                    "__import__",
                    Criticality::Suspicious,
                ))
            } else if text.contains("subprocess.")
                || text.contains("os.system")
                || text.contains("os.popen")
            {
                Some((
                    "exec/command/shell",
                    "Executes system commands",
                    "subprocess/system",
                    Criticality::Notable,
                ))
            } else if text.contains("requests.")
                || text.contains("urllib.")
                || text.contains("http.client")
            {
                Some((
                    "net/http/client",
                    "HTTP client operations",
                    "http_client",
                    Criticality::Notable,
                ))
            } else if text.contains("socket.") {
                Some((
                    "net/socket/create",
                    "Network socket operations",
                    "socket",
                    Criticality::Notable,
                ))
            } else if text.contains("open(") && (text.contains("'w'") || text.contains("\"w\"")) {
                Some((
                    "fs/write",
                    "Write files",
                    "open_write",
                    Criticality::Notable,
                ))
            } else if text.contains("base64.b64decode") {
                Some((
                    "anti-analysis/obfuscation/base64",
                    "Base64 decoding",
                    "b64decode",
                    Criticality::Suspicious,
                ))
            } else {
                None
            };

            if let Some((cap_id, description, pattern, criticality)) = capability {
                if !report.findings.iter().any(|c| c.id == cap_id) {
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: cap_id.to_string(),
                        desc: description.to_string(),
                        conf: 1.0,
                        crit: criticality,
                        mbc: None,
                        attack: None,
                        evidence: vec![Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-python".to_string(),
                            value: pattern.to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }
            }
        }
    }

    fn analyze_import(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            // Detect suspicious imports
            let suspicious_modules = [
                (
                    "subprocess",
                    "exec/command/shell",
                    "Shell command execution",
                    Criticality::Notable,
                ),
                (
                    "os",
                    "exec/command/shell",
                    "OS operations",
                    Criticality::Notable,
                ),
                (
                    "socket",
                    "net/socket/create",
                    "Network sockets",
                    Criticality::Notable,
                ),
                (
                    "requests",
                    "net/http/client",
                    "HTTP client",
                    Criticality::Notable,
                ),
                (
                    "pickle",
                    "anti-analysis/obfuscation/pickle",
                    "Pickle deserialization",
                    Criticality::Notable,
                ),
                (
                    "ctypes",
                    "exec/dylib/load",
                    "C library loading",
                    Criticality::Notable,
                ),
            ];

            for (module, cap_id, description, criticality) in suspicious_modules {
                if text.contains(module) && !report.findings.iter().any(|c| c.id == cap_id) {
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: cap_id.to_string(),
                        desc: description.to_string(),
                        conf: 0.7, // Import alone is not definitive
                        crit: criticality,
                        mbc: None,
                        attack: None,
                        evidence: vec![Evidence {
                            method: "import".to_string(),
                            source: "tree-sitter-python".to_string(),
                            value: module.to_string(),
                            location: Some(format!("line:{}", node.start_position().row + 1)),
                        }],
                    });
                }
            }
        }
    }

    fn check_obfuscation(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        if let Ok(text) = node.utf8_text(source) {
            // Detect base64 + eval pattern (common obfuscation)
            if (text.contains("base64") || text.contains("b64decode"))
                && (text.contains("eval") || text.contains("exec"))
                && !report
                    .findings
                    .iter()
                    .any(|c| c.id == "anti-analysis/obfuscation/base64-eval")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/obfuscation/base64-eval".to_string(),
                    desc: "Base64 decode followed by eval (obfuscation)".to_string(),
                    conf: 0.95,
                    crit: Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "pattern".to_string(),
                        source: "tree-sitter-python".to_string(),
                        value: "base64+eval".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }

            // Detect hex string construction
            if text.contains("\\x")
                && text.matches("\\x").count() > 5
                && !report
                    .findings
                    .iter()
                    .any(|c| c.id == "anti-analysis/obfuscation/hex")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/obfuscation/hex".to_string(),
                    desc: "Hex-encoded strings".to_string(),
                    conf: 0.9,
                    crit: crate::types::Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "pattern".to_string(),
                        source: "tree-sitter-python".to_string(),
                        value: "hex_encoding".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }

            // Detect string obfuscation via join
            if text.contains(".join(")
                && (text.contains("chr(") || text.contains("ord("))
                && !report
                    .findings
                    .iter()
                    .any(|c| c.id == "anti-analysis/obfuscation/string-construct")
            {
                report.findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/obfuscation/string-construct".to_string(),
                    desc: "Constructs strings via chr/ord".to_string(),
                    conf: 0.9,
                    crit: crate::types::Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "pattern".to_string(),
                        source: "tree-sitter-python".to_string(),
                        value: "chr_join_pattern".to_string(),
                        location: Some(format!("line:{}", node.start_position().row + 1)),
                    }],
                });
            }
        }
    }

    fn analyze_env_var_access(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        if let Ok(text) = node.utf8_text(source) {
            let line_num = node.start_position().row + 1;

            // Special handling for subscript nodes (os.environ['VAR'])
            if node.kind() == "subscript" && text.contains("os.environ") {
                // Extract variable name using simple parsing
                // Look for os.environ['VAR'] or os.environ["VAR"]
                let var_name_opt = if let Some(start) = text.find("os.environ[") {
                    let after_bracket = &text[start + 11..]; // Skip "os.environ["
                    if let Some(quote_pos) = after_bracket.find(&['\'', '"'][..]) {
                        let quote_char = after_bracket.chars().nth(quote_pos).unwrap();
                        let after_quote = &after_bracket[quote_pos + 1..];
                        after_quote
                            .find(quote_char)
                            .map(|end_quote| after_quote[..end_quote].to_string())
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(var_name) = var_name_opt {
                    let category = self.classify_env_var(&var_name);

                    report.env_vars.push(crate::types::EnvVarInfo {
                        name: var_name.clone(),
                        access_type: crate::types::EnvVarAccessType::Read,
                        source: format!("line:{}", line_num),
                        referenced_by_traits: Vec::new(),
                        category,
                        evidence: vec![crate::types::Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-python".to_string(),
                            value: format!("os.environ['{}']", var_name),
                            location: Some(format!("line:{}", line_num)),
                        }],
                    });

                    // Add trait for environ usage
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: "env/api/environ".to_string(),
                        desc: "Accesses os.environ dictionary".to_string(),
                        conf: 1.0,
                        evidence: vec![crate::types::Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-python".to_string(),
                            value: format!("os.environ['{}']", var_name),
                            location: Some(format!("line:{}", line_num)),
                        }],
                        crit: crate::types::Criticality::Suspicious,
                        mbc: None,
                        attack: None,
                    });
                }
                return;
            }

            // Detect os.getenv() calls
            if text.contains("os.getenv") || text.contains("os.environ.get") {
                if let Some(var_name) = self.extract_env_var_name(text, "getenv") {
                    let category = self.classify_env_var(&var_name);

                    report.env_vars.push(crate::types::EnvVarInfo {
                        name: var_name.clone(),
                        access_type: crate::types::EnvVarAccessType::Read,
                        source: format!("line:{}", line_num),
                        referenced_by_traits: Vec::new(),
                        category,
                        evidence: vec![crate::types::Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-python".to_string(),
                            value: text.to_string(),
                            location: Some(format!("line:{}", line_num)),
                        }],
                    });

                    // Add trait for getenv usage
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: "env/api/getenv".to_string(),
                        desc: "Reads environment variable".to_string(),
                        conf: 1.0,
                        evidence: vec![crate::types::Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-python".to_string(),
                            value: format!("os.getenv('{}')", var_name),
                            location: Some(format!("line:{}", line_num)),
                        }],
                        crit: crate::types::Criticality::Suspicious,
                        mbc: None,
                        attack: None,
                    });
                }
            }

            // Detect os.environ[] direct access
            if text.contains("os.environ[") {
                if let Some(var_name) = self.extract_env_var_from_bracket(text) {
                    let category = self.classify_env_var(&var_name);

                    report.env_vars.push(crate::types::EnvVarInfo {
                        name: var_name.clone(),
                        access_type: crate::types::EnvVarAccessType::Read,
                        source: format!("line:{}", line_num),
                        referenced_by_traits: Vec::new(),
                        category,
                        evidence: vec![crate::types::Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-python".to_string(),
                            value: text.to_string(),
                            location: Some(format!("line:{}", line_num)),
                        }],
                    });

                    // Add trait for environ usage
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: "env/api/environ".to_string(),
                        desc: "Accesses os.environ dictionary".to_string(),
                        conf: 1.0,
                        evidence: vec![crate::types::Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-python".to_string(),
                            value: format!("os.environ['{}'", var_name),
                            location: Some(format!("line:{}", line_num)),
                        }],
                        crit: crate::types::Criticality::Suspicious,
                        mbc: None,
                        attack: None,
                    });
                }
            }

            // Detect os.putenv() calls (write)
            if text.contains("os.putenv") {
                if let Some(var_name) = self.extract_env_var_name(text, "putenv") {
                    let category = self.classify_env_var(&var_name);

                    report.env_vars.push(crate::types::EnvVarInfo {
                        name: var_name.clone(),
                        access_type: crate::types::EnvVarAccessType::Write,
                        source: format!("line:{}", line_num),
                        referenced_by_traits: Vec::new(),
                        category,
                        evidence: vec![crate::types::Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-python".to_string(),
                            value: text.to_string(),
                            location: Some(format!("line:{}", line_num)),
                        }],
                    });

                    // Add trait for setenv usage
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: "env/api/setenv".to_string(),
                        desc: "Modifies environment variable".to_string(),
                        conf: 1.0,
                        evidence: vec![crate::types::Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-python".to_string(),
                            value: format!("os.putenv('{}')", var_name),
                            location: Some(format!("line:{}", line_num)),
                        }],
                        crit: crate::types::Criticality::Suspicious,
                        mbc: None,
                        attack: None,
                    });
                }
            }

            // Detect os.unsetenv() calls (delete)
            if text.contains("os.unsetenv") {
                if let Some(var_name) = self.extract_env_var_name(text, "unsetenv") {
                    let category = self.classify_env_var(&var_name);

                    report.env_vars.push(crate::types::EnvVarInfo {
                        name: var_name.clone(),
                        access_type: crate::types::EnvVarAccessType::Delete,
                        source: format!("line:{}", line_num),
                        referenced_by_traits: Vec::new(),
                        category,
                        evidence: vec![crate::types::Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-python".to_string(),
                            value: text.to_string(),
                            location: Some(format!("line:{}", line_num)),
                        }],
                    });

                    // Add trait for unsetenv usage
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        id: "env/api/unsetenv".to_string(),
                        desc: "Deletes environment variable".to_string(),
                        conf: 1.0,
                        evidence: vec![crate::types::Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter-python".to_string(),
                            value: format!("os.unsetenv('{}')", var_name),
                            location: Some(format!("line:{}", line_num)),
                        }],
                        crit: crate::types::Criticality::Suspicious,
                        mbc: None,
                        attack: None,
                    });
                }
            }
        }
    }

    fn extract_env_var_name(&self, text: &str, func_name: &str) -> Option<String> {
        // Parse: os.getenv("VAR_NAME") or os.putenv("VAR_NAME", ...)
        let pattern = format!("{}(", func_name);
        if let Some(start) = text.find(&pattern) {
            let after_paren = &text[start + pattern.len()..];
            // Find the first string literal (between quotes)
            if let Some(quote_start) = after_paren.find(&['\'', '"'][..]) {
                let quote_char = after_paren.chars().nth(quote_start).unwrap();
                let after_quote = &after_paren[quote_start + 1..];
                if let Some(quote_end) = after_quote.find(quote_char) {
                    return Some(after_quote[..quote_end].to_string());
                }
            }
        }
        None
    }

    fn extract_env_var_from_bracket(&self, text: &str) -> Option<String> {
        // Parse: os.environ["VAR_NAME"] or os.environ['VAR_NAME']
        if let Some(bracket_start) = text.find("environ[") {
            let after_bracket = &text[bracket_start + 8..];
            if let Some(quote_start) = after_bracket.find(&['\'', '"'][..]) {
                let quote_char = after_bracket.chars().nth(quote_start).unwrap();
                let after_quote = &after_bracket[quote_start + 1..];
                if let Some(quote_end) = after_quote.find(quote_char) {
                    return Some(after_quote[..quote_end].to_string());
                }
            }
        }
        None
    }

    fn classify_env_var(&self, name: &str) -> crate::types::EnvVarCategory {
        use crate::types::EnvVarCategory;

        let upper_name = name.to_uppercase();

        if upper_name == "PATH" || upper_name == "PYTHONPATH" || upper_name == "LD_LIBRARY_PATH" {
            EnvVarCategory::Path
        } else if upper_name == "HOME"
            || upper_name == "USER"
            || upper_name == "USERNAME"
            || upper_name == "USERPROFILE"
        {
            EnvVarCategory::User
        } else if upper_name.contains("TOKEN")
            || upper_name.contains("KEY")
            || upper_name.contains("SECRET")
            || upper_name.contains("PASSWORD")
            || upper_name.starts_with("AWS_")
        {
            EnvVarCategory::Credential
        } else if upper_name == "LD_PRELOAD" || upper_name == "DYLD_INSERT_LIBRARIES" {
            EnvVarCategory::Injection
        } else if upper_name == "DISPLAY" {
            EnvVarCategory::Display
        } else if upper_name == "TEMP" || upper_name == "TMP" || upper_name == "TMPDIR" {
            EnvVarCategory::Temp
        } else if upper_name.starts_with("SSH_") {
            EnvVarCategory::System
        } else {
            EnvVarCategory::Other
        }
    }

    fn extract_functions(
        &self,
        root: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        let mut cursor = root.walk();

        loop {
            let node = cursor.node();

            if node.kind() == "function_definition" {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(func_name) = name_node.utf8_text(source) {
                        report.functions.push(Function {
                            name: func_name.to_string(),
                            offset: Some(format!("line:{}", node.start_position().row + 1)),
                            size: Some((node.end_byte() - node.start_byte()) as u64),
                            complexity: None,
                            calls: Vec::new(),
                            source: "tree-sitter-python".to_string(),
                            control_flow: None,
                            instruction_analysis: None,
                            register_usage: None,
                            constants: Vec::new(),
                            properties: None,
                            call_patterns: None,
                            nesting: None,
                            signature: None,
                        });
                    }
                }
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

impl Default for PythonAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for PythonAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let bytes = fs::read(file_path).context("Failed to read Python script")?;
        let content = String::from_utf8_lossy(&bytes);

        self.analyze_script(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            ext == "py"
        } else if let Ok(data) = fs::read(file_path) {
            data.starts_with(b"#!/usr/bin/env python") || data.starts_with(b"#!/usr/bin/python")
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn analyze_python_code(code: &str) -> AnalysisReport {
        let analyzer = PythonAnalyzer::new();
        let path = PathBuf::from("test.py");
        analyzer.analyze_script(&path, code).unwrap()
    }

    #[test]
    fn test_detect_eval() {
        let code = r#"
x = eval("1+1")
"#;
        let report = analyze_python_code(code);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "exec/script/eval" && c.desc.contains("Evaluates")));
    }

    #[test]
    fn test_detect_exec() {
        let code = r#"
exec("print('hello')")
"#;
        let report = analyze_python_code(code);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "exec/script/eval" && c.desc.contains("Executes")));
    }

    #[test]
    fn test_detect_compile() {
        let code = r#"
code = compile("x = 1", "<string>", "exec")
"#;
        let report = analyze_python_code(code);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "exec/script/eval" && c.desc.contains("Compiles")));
    }

    #[test]
    fn test_detect_subprocess() {
        let code = r#"
import subprocess
subprocess.call(['ls', '-la'])
"#;
        let report = analyze_python_code(code);

        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_os_system() {
        let code = r#"
import os
os.system('ls')
"#;
        let report = analyze_python_code(code);

        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_http_requests() {
        let code = r#"
import requests
r = requests.get('https://example.com')
"#;
        let report = analyze_python_code(code);

        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
    }

    #[test]
    fn test_detect_socket() {
        let code = r#"
import socket
s = socket.socket()
"#;
        let report = analyze_python_code(code);

        assert!(report.findings.iter().any(|c| c.id == "net/socket/create"));
    }

    #[test]
    fn test_detect_file_write() {
        let code = r#"
with open('test.txt', 'w') as f:
    f.write('data')
"#;
        let report = analyze_python_code(code);

        assert!(report.findings.iter().any(|c| c.id == "fs/write"));
    }

    // Note: fs/file/delete detection moved to traits/fs/file/delete/python.yaml

    #[test]
    fn test_detect_base64_decode() {
        let code = r#"
import base64
data = base64.b64decode('aGVsbG8=')
"#;
        let report = analyze_python_code(code);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/base64"));
    }

    #[test]
    fn test_detect_base64_eval_obfuscation() {
        let code = r#"
import base64
result = eval(base64.b64decode('cHJpbnQoImhlbGxvIik='))
"#;
        let report = analyze_python_code(code);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/base64-eval"));
        assert_eq!(
            report
                .findings
                .iter()
                .find(|c| c.id == "anti-analysis/obfuscation/base64-eval")
                .unwrap()
                .conf,
            0.95
        );
    }

    #[test]
    fn test_detect_hex_obfuscation() {
        let code = r#"
data = b'\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64'
"#;
        let report = analyze_python_code(code);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/hex"));
    }

    #[test]
    fn test_detect_dynamic_import() {
        let code = r#"
module = __import__('os')
"#;
        let report = analyze_python_code(code);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/dynamic-import"));
    }

    #[test]
    fn test_detect_subprocess_import() {
        let code = r#"
import subprocess
"#;
        let report = analyze_python_code(code);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "exec/command/shell" && c.conf == 0.7));
    }

    #[test]
    fn test_detect_pickle_import() {
        let code = r#"
import pickle
"#;
        let report = analyze_python_code(code);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/pickle"));
    }

    #[test]
    fn test_detect_ctypes_import() {
        let code = r#"
import ctypes
"#;
        let report = analyze_python_code(code);

        assert!(report.findings.iter().any(|c| c.id == "exec/dylib/load"));
    }

    #[test]
    fn test_extract_functions() {
        let code = r#"
def hello():
    pass

def world():
    return 42
"#;
        let report = analyze_python_code(code);

        assert_eq!(report.functions.len(), 2);
        assert!(report.functions.iter().any(|f| f.name == "hello"));
        assert!(report.functions.iter().any(|f| f.name == "world"));
        assert_eq!(report.functions[0].source, "tree-sitter-python");
    }

    #[test]
    fn test_structural_feature() {
        let code = "print('hello')";
        let report = analyze_python_code(code);

        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/python"));
    }

    #[test]
    fn test_multiple_capabilities() {
        let code = r#"
import subprocess
import socket
import requests

subprocess.call(['ls'])
s = socket.socket()
requests.get('http://example.com')
"#;
        let report = analyze_python_code(code);

        assert!(report.findings.len() >= 3);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
        assert!(report.findings.iter().any(|c| c.id == "net/socket/create"));
        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
    }

    #[test]
    fn test_can_analyze_py_extension() {
        let analyzer = PythonAnalyzer::new();
        let path = PathBuf::from("test.py");

        assert!(analyzer.can_analyze(&path));
    }

    #[test]
    fn test_cannot_analyze_other_extension() {
        let analyzer = PythonAnalyzer::new();
        let path = PathBuf::from("test.txt");

        assert!(!analyzer.can_analyze(&path));
    }
}
