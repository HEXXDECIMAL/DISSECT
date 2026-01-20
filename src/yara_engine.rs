use crate::capabilities::CapabilityMapper;
use crate::types::{Evidence, YaraMatch, MatchedString};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::fs;
use walkdir::WalkDir;
use yara_x;

/// YARA-X engine for pattern-based detection
pub struct YaraEngine {
    rules: Option<yara_x::Rules>,
    capability_mapper: CapabilityMapper,
}

impl YaraEngine {
    /// Create a new YARA engine without rules loaded
    pub fn new() -> Self {
        Self {
            rules: None,
            capability_mapper: CapabilityMapper::new(),
        }
    }

    /// Load YARA rules from malcontent rules directory
    pub fn load_malcontent_rules(&mut self) -> Result<usize> {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        let rules_path = PathBuf::from(home).join("src/malcontent/rules");

        if !rules_path.exists() {
            anyhow::bail!("Malcontent rules not found at {}", rules_path.display());
        }

        self.load_rules_from_directory(&rules_path)
    }

    /// Load YARA rules from a directory (recursively)
    pub fn load_rules_from_directory(&mut self, dir: &Path) -> Result<usize> {
        let mut compiler = yara_x::Compiler::new();
        let mut count = 0;

        // Walk directory and compile all .yar and .yara files
        for entry in WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "yar" || ext == "yara" {
                        match self.compile_rule_file(&mut compiler, path) {
                            Ok(_) => count += 1,
                            Err(e) => {
                                eprintln!("Warning: Failed to compile {}: {}", path.display(), e);
                            }
                        }
                    }
                }
            }
        }

        if count == 0 {
            anyhow::bail!("No YARA rules found in {}", dir.display());
        }

        self.rules = Some(compiler.build());
        Ok(count)
    }

    /// Load a single YARA rule file
    pub fn load_rule_file(&mut self, path: &Path) -> Result<()> {
        let mut compiler = yara_x::Compiler::new();
        self.compile_rule_file(&mut compiler, path)?;
        self.rules = Some(compiler.build());
        Ok(())
    }

    /// Compile a single rule file into the compiler
    fn compile_rule_file(&self, compiler: &mut yara_x::Compiler, path: &Path) -> Result<()> {
        let source = fs::read_to_string(path)
            .context(format!("Failed to read rule file: {}", path.display()))?;

        // Extract namespace from path and set it
        let namespace = self.extract_namespace(path);
        compiler.new_namespace(&namespace);

        compiler
            .add_source(source.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to compile rule {}: {:?}", path.display(), e))?;

        Ok(())
    }

    /// Extract namespace from file path
    fn extract_namespace(&self, path: &Path) -> String {
        // Get the path relative to rules directory
        let path_str = path.to_string_lossy();

        // Find "rules/" in the path
        if let Some(idx) = path_str.find("rules/") {
            let relative = &path_str[idx + 6..]; // Skip "rules/"

            // Remove filename and extension
            if let Some(parent) = Path::new(relative).parent() {
                return parent.to_string_lossy().replace('/', ".");
            }
        }

        "default".to_string()
    }

    /// Scan a file with loaded YARA rules
    pub fn scan_file(&self, file_path: &Path) -> Result<Vec<YaraMatch>> {
        let rules = self.rules.as_ref()
            .context("No YARA rules loaded")?;

        let data = fs::read(file_path)
            .context(format!("Failed to read file: {}", file_path.display()))?;

        self.scan_bytes(&data)
    }

    /// Scan byte data with loaded YARA rules
    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        let rules = self.rules.as_ref()
            .context("No YARA rules loaded")?;

        let mut scanner = yara_x::Scanner::new(rules);
        let scan_results = scanner.scan(data)
            .map_err(|e| anyhow::anyhow!("YARA scan failed: {:?}", e))?;

        let mut matches = Vec::new();

        for matching_rule in scan_results.matching_rules() {
            let rule_name = matching_rule.identifier().to_string();
            let namespace = matching_rule.namespace().to_string();

            // Extract metadata - iterate through key-value pairs
            let mut description = String::new();
            let mut severity = "medium".to_string();

            for (key, value) in matching_rule.metadata() {
                match key {
                    "description" => {
                        description = format!("{:?}", value).trim_matches('"').to_string();
                    }
                    "risk" => {
                        severity = format!("{:?}", value).trim_matches('"').to_string();
                    }
                    _ => {}
                }
            }

            // Extract matched strings/patterns
            let mut matched_strings = Vec::new();
            for pattern in matching_rule.patterns() {
                for m in pattern.matches() {
                    let range = m.range();
                    let match_len = range.end - range.start;

                    let value = if match_len <= 100 {
                        String::from_utf8_lossy(&data[range.clone()]).to_string()
                    } else {
                        format!("<{} bytes>", match_len)
                    };

                    matched_strings.push(MatchedString {
                        identifier: pattern.identifier().to_string(),
                        offset: range.start as u64,
                        value,
                    });
                }
            }

            matches.push(YaraMatch {
                rule: rule_name,
                namespace: namespace.clone(),
                severity,
                description,
                matched_strings,
            });
        }

        Ok(matches)
    }

    /// Check if rules are loaded
    pub fn is_loaded(&self) -> bool {
        self.rules.is_some()
    }

    /// Map YARA match to capability evidence
    pub fn yara_match_to_evidence(&self, yara_match: &YaraMatch) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        for matched_str in &yara_match.matched_strings {
            evidence.push(Evidence {
                method: "yara".to_string(),
                source: "yara-x".to_string(),
                value: format!("{}:{}", yara_match.rule, matched_str.identifier),
                location: Some(format!("offset:0x{:x}", matched_str.offset)),
            });
        }

        // If no specific strings matched, add general evidence
        if evidence.is_empty() {
            evidence.push(Evidence {
                method: "yara".to_string(),
                source: "yara-x".to_string(),
                value: yara_match.rule.clone(),
                location: Some(yara_match.namespace.clone()),
            });
        }

        evidence
    }
}

impl Default for YaraEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_simple_rule() {
        let rule = r#"
rule test_rule {
    meta:
        description = "Test rule"
        risk = "low"
    strings:
        $test = "TESTPATTERN"
    condition:
        $test
}
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(rule.as_bytes()).unwrap();

        let mut engine = YaraEngine::new();
        engine.load_rule_file(temp_file.path()).unwrap();

        let test_data = b"This contains TESTPATTERN in the data";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule, "test_rule");
        assert!(!matches[0].matched_strings.is_empty());
    }

    #[test]
    fn test_no_match() {
        let rule = r#"
rule test_rule {
    strings:
        $test = "NOTFOUND"
    condition:
        $test
}
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(rule.as_bytes()).unwrap();

        let mut engine = YaraEngine::new();
        engine.load_rule_file(temp_file.path()).unwrap();

        let test_data = b"This does not contain the pattern";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 0);
    }
}
