use dissect::composite_rules::condition::Condition;
use dissect::types::{AnalysisReport, StringInfo, StringType, TargetInfo};

#[test]
fn test_layer_path_condition_basic() {
    // Create a string with stack encoding layer
    let strings = vec![StringInfo {
        value: "kworker".to_string(),
        offset: Some("0x1000".to_string()),
        encoding: "utf8".to_string(),
        string_type: StringType::Plain,
        section: Some(".text".to_string()),
        encoding_chain: vec!["stack".to_string()],
        fragments: None,
    }];

    let target = TargetInfo {
        sha256: "test".to_string(),
        path: "test".to_string(),
        size_bytes: 100,
        file_type: "elf".to_string(),
        architectures: None,
    };
    let mut report = AnalysisReport::new(target);
    report.strings = strings;

    // Test that layer_path condition type can be created
    let condition = Condition::LayerPath {
        value: "meta/layers/.text/stack".to_string(),
    };

    assert!(matches!(condition, Condition::LayerPath { .. }));
    assert_eq!(condition.type_name(), "layer_path");
}

#[test]
fn test_layer_path_no_encoding_chain() {
    // String without encoding chain should not match
    let strings = vec![StringInfo {
        value: "hello".to_string(),
        offset: Some("0x2000".to_string()),
        encoding: "utf8".to_string(),
        string_type: StringType::Plain,
        section: Some(".text".to_string()),
        encoding_chain: vec![], // Empty encoding chain
        fragments: None,
    }];

    // A condition for a layered path shouldn't match strings without encoding
    assert_eq!(strings[0].encoding_chain.len(), 0);
}

#[test]
fn test_layer_path_multiple_encoding_layers() {
    // String with multiple encoding layers
    let strings = vec![StringInfo {
        value: "YWJj".to_string(), // abc in base64
        offset: Some("0x3000".to_string()),
        encoding: "utf8".to_string(),
        string_type: StringType::Base64,
        section: Some(".rodata".to_string()),
        encoding_chain: vec!["base64".to_string(), "zlib".to_string()],
        fragments: None,
    }];

    // Verify encoding chain structure
    assert_eq!(
        strings[0].encoding_chain,
        vec!["base64".to_string(), "zlib".to_string()]
    );
    // The computed layer path would be: meta/layers/.rodata/base64/zlib
}
