//! Test suite for JavaScript analyzer
//!
//! Tests cover:
//! - Basic capability detection (exec, fs, network)
//! - Obfuscation detection (base64+eval, hex encoding)
//! - Dynamic code execution (eval, Function constructor)
//! - Function extraction
//! - Structural features

#[cfg(test)]
mod tests {
    
    use crate::types::AnalysisReport;
    use std::path::Path;

    use super::super::JavaScriptAnalyzer;

    fn analyze_js_code(code: &str) -> AnalysisReport {
        let analyzer = JavaScriptAnalyzer::new();
        analyzer.analyze_script(Path::new("test.js"), code).unwrap()
    }

    #[test]
    fn test_simple_script() {
        let script = r#"
            const fs = require('fs');
            const { exec } = require('child_process');

            exec('rm -rf /tmp/test', (error, stdout, stderr) => {
                console.log(stdout);
            });

            fs.writeFileSync('/tmp/malicious.txt', 'payload');
        "#;

        let report = analyze_js_code(script);

        // Should detect exec and fs imports
        assert!(!report.findings.is_empty());

        // Should detect shell execution
        assert!(report
            .findings
            .iter()
            .any(|c| c.id.contains("exec/command")));

        // Should detect file write
        assert!(report.findings.iter().any(|c| c.id.contains("fs/write")));
    }

    #[test]
    fn test_obfuscated_script() {
        let script = r#"
            const payload = Buffer.from('Y3VybCBldmlsLmNvbQ==', 'base64').toString();
            eval(payload);
        "#;

        let report = analyze_js_code(script);

        // Should detect base64 + eval obfuscation
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/base64-eval"));
    }

    #[test]
    fn test_detect_eval() {
        let code = "eval('console.log(\"hello\")');";
        let report = analyze_js_code(code);

        assert!(report.findings.iter().any(|c| c.id == "exec/script/eval"));
    }

    #[test]
    fn test_detect_function_constructor() {
        let code = "const fn = Function('return 1+1');";
        let report = analyze_js_code(code);

        assert!(report.findings.iter().any(|c| c.id == "exec/script/eval"));
    }

    #[test]
    fn test_detect_exec() {
        let code = "const { exec } = require('child_process'); exec('ls -la');";
        let report = analyze_js_code(code);

        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_spawn() {
        let code = "const { spawn } = require('child_process'); spawn('sh', ['-c', 'ls']);";
        let report = analyze_js_code(code);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "exec/command/direct"));
    }

    #[test]
    fn test_detect_fs_write() {
        let code = "const fs = require('fs'); fs.writeFileSync('test.txt', 'data');";
        let report = analyze_js_code(code);

        assert!(report.findings.iter().any(|c| c.id == "fs/write"));
    }

    // Note: fs/file/delete detection moved to traits/fs/file/delete/javascript.yaml

    #[test]
    fn test_detect_fs_chmod() {
        let code = "const fs = require('fs'); fs.chmodSync('script.sh', 0o755);";
        let report = analyze_js_code(code);

        assert!(report.findings.iter().any(|c| c.id == "fs/permissions"));
    }

    #[test]
    fn test_detect_http_request() {
        let code = "const https = require('https'); https.request('https://example.com', cb);";
        let report = analyze_js_code(code);

        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
    }

    #[test]
    fn test_detect_net_connect() {
        let code = "const net = require('net'); net.connect(4444, 'example.com');";
        let report = analyze_js_code(code);

        assert!(report.findings.iter().any(|c| c.id == "net/socket/connect"));
    }

    #[test]
    fn test_detect_net_server() {
        let code = "const net = require('net'); net.createServer((socket) => {});";
        let report = analyze_js_code(code);

        assert!(report.findings.iter().any(|c| c.id == "net/socket/listen"));
    }

    #[test]
    fn test_detect_buffer_base64() {
        let code = "const data = Buffer.from('aGVsbG8=', 'base64');";
        let report = analyze_js_code(code);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/base64"));
    }

    #[test]
    fn test_detect_atob() {
        let code = "const decoded = atob('aGVsbG8=');";
        let report = analyze_js_code(code);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/base64"));
    }

    #[test]
    fn test_detect_dynamic_require() {
        let code = "const moduleName = 'fs'; const fs = require(moduleName);";
        let report = analyze_js_code(code);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/dynamic-import"));
    }

    #[test]
    fn test_structural_feature() {
        let code = "console.log('hello');";
        let report = analyze_js_code(code);

        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/javascript"));
    }

    #[test]
    fn test_extract_functions() {
        let code = r#"
function hello() {
    return 'world';
}

const goodbye = () => {
    console.log('bye');
};
"#;
        let report = analyze_js_code(code);

        assert!(!report.functions.is_empty());
        assert!(report.functions.iter().any(|f| f.name == "hello"));
    }

    #[test]
    fn test_multiple_capabilities() {
        let code = r#"
const fs = require('fs');
const { exec } = require('child_process');
const https = require('https');

exec('whoami');
fs.writeFileSync('/tmp/data', 'test');
https.request('https://evil.com');
"#;
        let report = analyze_js_code(code);

        assert!(report.findings.len() >= 3);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
        assert!(report.findings.iter().any(|c| c.id == "fs/write"));
        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
    }
}
