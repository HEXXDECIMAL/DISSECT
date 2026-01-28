#[cfg(test)]
mod tests {
    use crate::analyzers::{python::PythonAnalyzer, Analyzer};
    use crate::types::AnalysisReport;
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
