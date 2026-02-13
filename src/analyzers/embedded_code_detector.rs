//! Embedded Code Detector
//!
//! Analyzes strings extracted by stng to detect and analyze embedded code (both plain and encoded).
//! Detects Python, JavaScript, Shell, and PHP code in strings and re-analyzes them with full
//! AST parsing and capability detection.

use crate::analyzers::{unified::UnifiedSourceAnalyzer, FileType};
use crate::capabilities::CapabilityMapper;
use crate::types::binary::StringInfo;
use crate::types::file_analysis::{encode_decoded_path, FileAnalysis};
use crate::types::Evidence;
use crate::types::{Criticality, Finding};
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;

/// Maximum nesting depth for decoded strings (prevent infinite recursion)
const MAX_DECODE_DEPTH: usize = 3;

/// Maximum size for individual decoded string (10MB)
const MAX_DECODED_SIZE: usize = 10 * 1024 * 1024;

/// Maximum total decoded bytes per file (50MB)
const MAX_TOTAL_DECODED: usize = 50 * 1024 * 1024;

/// Minimum size for plain strings to analyze (reduce false positives)
const MIN_PLAIN_SIZE: usize = 50;

/// Minimum size for encoded strings to analyze (can be smaller)
const MIN_ENCODED_SIZE: usize = 20;

/// Maximum number of strings to analyze per file
const MAX_STRINGS_TO_ANALYZE: usize = 100;

/// Maximum entropy for code (compressed data has entropy > 7.5)
const MAX_CODE_ENTROPY: f64 = 7.5;

/// Detect if a string contains code worth analyzing
///
/// Uses fast heuristics to identify Python, JavaScript, Shell, or PHP code.
/// Returns Some(FileType) if code is detected, None otherwise.
pub fn detect_language(value: &str, is_encoded: bool) -> Option<FileType> {
    // Size checks
    let min_size = if is_encoded {
        MIN_ENCODED_SIZE
    } else {
        MIN_PLAIN_SIZE
    };

    if value.len() < min_size || value.len() > MAX_DECODED_SIZE {
        return None;
    }

    // Check entropy (skip compressed/encrypted data)
    if calculate_entropy(value.as_bytes()) > MAX_CODE_ENTROPY {
        return None;
    }

    // Pattern threshold (stricter for plain strings)
    let min_matches = if is_encoded { 2 } else { 3 };

    // PHP detection (check first - <?php is most distinctive marker)
    if detect_php(value) {
        return Some(FileType::Php);
    }

    // JavaScript detection (check before Python - JS code often has eval() which matches Python)
    if detect_javascript(value, min_matches) {
        return Some(FileType::JavaScript);
    }

    // Python detection
    if detect_python(value, min_matches) {
        return Some(FileType::Python);
    }

    // Shell detection
    if detect_shell(value, min_matches) {
        return Some(FileType::Shell);
    }

    None
}

/// Detect Python code patterns
fn detect_python(value: &str, min_matches: usize) -> bool {
    let patterns = [
        r"\bimport\s+\w+",
        r"\bfrom\s+\w+\s+import\b",
        r"\bdef\s+\w+\s*\(",
        r"\bclass\s+\w+",
        r"\bexec\s*\(",
        r"\beval\s*\(",
        r"\bsys\.",
        r"\bos\.",
        r#"__name__\s*==\s*['"]__main__['"]"#,
    ];

    let mut matches = 0;
    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(value) {
                matches += 1;
                if matches >= min_matches {
                    return true;
                }
            }
        }
    }

    false
}

/// Detect JavaScript code patterns
fn detect_javascript(value: &str, min_matches: usize) -> bool {
    let patterns = [
        r"\bfunction\s+\w+\s*\(",
        r"\bconst\s+\w+\s*=",
        r"\blet\s+\w+\s*=",
        r"\bvar\s+\w+\s*=",
        r#"\brequire\s*\(['"]"#,
        r"\beval\s*\(",
        r"\bdocument\.",
        r"\bwindow\.",
        r"=>\s*\{",
        r"\bconsole\.log\s*\(",
    ];

    let mut matches = 0;
    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(value) {
                matches += 1;
                if matches >= min_matches {
                    return true;
                }
            }
        }
    }

    false
}

/// Detect Shell script patterns
fn detect_shell(value: &str, min_matches: usize) -> bool {
    // Shebang is strong indicator
    if value.starts_with("#!/bin/bash") || value.starts_with("#!/bin/sh") {
        return true;
    }

    let patterns = [
        r"\b(echo|curl|wget|chmod|chown|chgrp)\s+",
        r"\|\s*\b(grep|sh|bash|python|php|node|base64|sed|awk)\b",
        r"\$\{?\w+\}?",
        r"\bif\s*\[\s*",
        r"\bfor\s+\w+\s+in\b",
        r"\bexport\s+\w+=",
        r"\b(python|php|perl|ruby)\s+-e\s+",
        r"2>&1",
        r">/dev/null",
        r"\b(sudo|doas)\s+",
        r"&\s*/dev/null",
        r"\bnohup\s+",
    ];

    let mut matches = 0;
    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(value) {
                matches += 1;
                if matches >= min_matches {
                    return true;
                }
            }
        }
    }

    false
}

/// Detect PHP code patterns
fn detect_php(value: &str) -> bool {
    // PHP has very distinctive opening tags - require them for reliable detection
    if value.contains("<?php") || value.contains("<?=") {
        return true;
    }

    // Only use fallback patterns if we see PHP-specific patterns (multiple matches required)
    let patterns = [
        r"\$\w+\s*=",                              // PHP variables always start with $
        r"\beval\s*\(\s*base64_decode",            // Common PHP obfuscation
        r"function\s+\w+\s*\([^)]*\)\s*\{[^}]*\$", // PHP function with $ variable
    ];

    let mut matches = 0;
    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(value) {
                matches += 1;
                if matches >= 2 {
                    return true;
                }
            }
        }
    }

    false
}

/// Calculate Shannon entropy of data
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Convert FileType to language name string
fn lang_name(file_type: &FileType) -> &'static str {
    match file_type {
        FileType::Python => "python",
        FileType::JavaScript => "javascript",
        FileType::Shell => "shell",
        FileType::Php => "php",
        _ => "unknown",
    }
}

/// Generate automatic language detection trait (auto-generated, no YAML needed like meta/sign)
fn generate_language_trait(
    detected_lang: &FileType,
    encoding_chain: &[String],
    offset: u64,
) -> Finding {
    let (trait_id, criticality) = if encoding_chain.is_empty() {
        // Plain embedded code - notable
        (
            format!("meta/lang/embedded::{}", lang_name(detected_lang)),
            Criticality::Notable,
        )
    } else {
        // Encoded code - suspicious (obfuscation attempt)
        let encoding = &encoding_chain[0];
        (
            format!(
                "meta/lang/encoded/{}::{}",
                encoding,
                lang_name(detected_lang)
            ),
            Criticality::Suspicious,
        )
    };

    let description = format!(
        "{} code {} in string",
        lang_name(detected_lang),
        if encoding_chain.is_empty() {
            "embedded"
        } else {
            "encoded"
        }
    );

    Finding {
        id: trait_id,
        kind: crate::types::FindingKind::Capability,
        desc: description,
        conf: 1.0,
        crit: criticality,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![Evidence {
            method: "embedded-code-detection".to_string(),
            source: "string-analysis".to_string(),
            value: format!(
                "Detected {} at offset {:#x}",
                lang_name(detected_lang),
                offset
            ),
            location: Some(format!("{:#x}", offset)),
        }],
        source_file: None,
    }
}

/// Result of analyzing an embedded string
pub enum EmbeddedAnalysisResult {
    /// Encoded code - becomes a separate layer (FileAnalysis)
    EncodedLayer(Box<FileAnalysis>),
    /// Plain embedded code - findings added to parent
    PlainEmbedded(Vec<Finding>),
}

/// Analyze a string detected as code
pub fn analyze_embedded_string(
    parent_path: &str,
    string_info: &StringInfo,
    _string_index: usize,
    capability_mapper: &Arc<CapabilityMapper>,
    current_depth: usize,
) -> Result<EmbeddedAnalysisResult> {
    // Check depth limit
    if current_depth >= MAX_DECODE_DEPTH {
        anyhow::bail!("Maximum decode depth {} exceeded", MAX_DECODE_DEPTH);
    }

    // Detect language
    let is_encoded = !string_info.encoding_chain.is_empty();
    let file_type = detect_language(&string_info.value, is_encoded)
        .context("No language detected in string")?;

    let offset = string_info.offset.unwrap_or(0);

    // Create virtual path
    let virtual_path = if is_encoded {
        encode_decoded_path(parent_path, &string_info.encoding_chain, offset as usize)
    } else {
        format!("{}##plain@{:#x}", parent_path, offset)
    };

    // Create analyzer for detected language
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&file_type)
        .context("Failed to create analyzer for language")?
        .with_capability_mapper_arc(capability_mapper.clone());

    // Analyze in-memory
    let mut report = analyzer
        .analyze_source(Path::new(&virtual_path), &string_info.value)
        .context("Failed to analyze embedded code")?;

    // Generate language detection trait (auto-generated, no YAML needed)
    let lang_trait = generate_language_trait(&file_type, &string_info.encoding_chain, offset);

    if is_encoded {
        // Encoded code - create a separate layer
        report.findings.push(lang_trait);

        let mut file_entry = report.to_file_analysis(0, true);
        file_entry.path = virtual_path.clone();
        file_entry.depth = (current_depth + 1) as u32;
        file_entry.encoding = Some(string_info.encoding_chain.clone());

        // Prefix evidence locations
        for finding in &mut file_entry.findings {
            for evidence in &mut finding.evidence {
                evidence.location = Some(format!(
                    "decoded:{}:{}",
                    virtual_path,
                    evidence.location.as_deref().unwrap_or("unknown")
                ));
            }
        }

        file_entry.compute_summary();
        Ok(EmbeddedAnalysisResult::EncodedLayer(Box::new(file_entry)))
    } else {
        // Plain embedded code - return findings for parent
        let mut findings = report.findings;
        findings.push(lang_trait);

        // Prefix evidence locations to indicate they came from embedded code
        for finding in &mut findings {
            for evidence in &mut finding.evidence {
                evidence.location = Some(format!(
                    "embedded@{:#x}:{}",
                    offset,
                    evidence.location.as_deref().unwrap_or("unknown")
                ));
            }
        }

        Ok(EmbeddedAnalysisResult::PlainEmbedded(findings))
    }
}

/// Process all strings from a file, analyzing detected code
/// Returns (encoded_layers, plain_findings):
/// - encoded_layers: FileAnalysis entries for encoded code (true layers)
/// - plain_findings: Findings for plain embedded code (added to parent)
pub fn process_all_strings(
    parent_path: &str,
    strings: &[StringInfo],
    capability_mapper: &Arc<CapabilityMapper>,
    current_depth: usize,
) -> (Vec<FileAnalysis>, Vec<Finding>) {
    let mut encoded_layers = Vec::new();
    let mut plain_findings = Vec::new();
    let mut total_analyzed = 0;
    let mut total_bytes = 0;

    for (idx, string_info) in strings.iter().enumerate() {
        // Check limits
        if total_analyzed >= MAX_STRINGS_TO_ANALYZE {
            break;
        }

        if total_bytes >= MAX_TOTAL_DECODED {
            break;
        }

        // Try to analyze this string
        match analyze_embedded_string(
            parent_path,
            string_info,
            idx,
            capability_mapper,
            current_depth,
        ) {
            Ok(EmbeddedAnalysisResult::EncodedLayer(file_analysis)) => {
                total_bytes += string_info.value.len();
                total_analyzed += 1;
                encoded_layers.push(*file_analysis);
            }
            Ok(EmbeddedAnalysisResult::PlainEmbedded(findings)) => {
                total_bytes += string_info.value.len();
                total_analyzed += 1;
                plain_findings.extend(findings);
            }
            Err(_) => {
                // Not code or analysis failed - skip silently
                continue;
            }
        }
    }

    (encoded_layers, plain_findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_python() {
        // Make string > MIN_PLAIN_SIZE (50 bytes) for plain detection
        let code = "import os\nimport sys\ndef main():\n    os.system('ls -la')\n    sys.exit(0)";
        assert_eq!(detect_language(code, false), Some(FileType::Python));
    }

    #[test]
    fn test_detect_javascript() {
        // Make string > MIN_PLAIN_SIZE (50 bytes) for plain detection
        let code =
            "function test() {\n  const x = require('fs');\n  eval(x);\n  console.log('done');\n}";
        assert_eq!(detect_language(code, false), Some(FileType::JavaScript));
    }

    #[test]
    fn test_detect_shell() {
        // Make string > MIN_PLAIN_SIZE (50 bytes) for plain detection
        let code =
            "#!/bin/bash\necho 'hello world'\ncurl http://example.com/payload\nsh -c 'payload'";
        assert_eq!(detect_language(code, false), Some(FileType::Shell));
    }

    #[test]
    fn test_detect_php() {
        // Make string > MIN_PLAIN_SIZE (50 bytes) for plain detection
        let code = "<?php eval(base64_decode('test')); echo 'malware'; ?>";
        assert_eq!(detect_language(code, false), Some(FileType::Php));
    }

    #[test]
    fn test_reject_plain_text() {
        let text = "This is just some regular text without code.";
        assert_eq!(detect_language(text, false), None);
    }

    #[test]
    fn test_reject_too_small() {
        let code = "import os"; // Less than MIN_PLAIN_SIZE
        assert_eq!(detect_language(code, false), None);
    }

    #[test]
    fn test_encoded_lower_threshold() {
        let code = "import os\ndef main():\n    pass"; // Only 1 match
        assert_eq!(detect_language(code, true), Some(FileType::Python));
    }

    #[test]
    fn test_entropy_calculation() {
        let data = b"aaaaaaaaaa";
        let entropy = calculate_entropy(data);
        assert!(entropy < 1.0); // Low entropy

        // Use more varied data for higher entropy test
        let varied = b"abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        let entropy = calculate_entropy(varied);
        assert!(entropy > 3.0); // Higher entropy (many unique bytes)
    }
}
