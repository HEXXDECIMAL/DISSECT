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
    /// Namespaces that are from third-party rules (marked as high criticality)
    third_party_namespaces: Vec<String>,
}

impl YaraEngine {
    /// Create a new YARA engine without rules loaded
    pub fn new() -> Self {
        Self {
            rules: None,
            capability_mapper: CapabilityMapper::new(),
            third_party_namespaces: Vec::new(),
        }
    }

    /// Load all YARA rules (built-in from traits/ + optionally third-party from third_party/yara)
    pub fn load_all_rules(&mut self, enable_third_party: bool) -> Result<(usize, usize)> {
        let mut compiler = yara_x::Compiler::new();
        let mut builtin_count = 0;
        let mut third_party_count = 0;

        // 1. Load built-in YARA rules from traits/ directory
        let traits_dir = Path::new("traits");
        if traits_dir.exists() {
            match self.load_rules_into_compiler(&mut compiler, traits_dir, "traits") {
                Ok(count) => {
                    builtin_count = count;
                    if count > 0 {
                        eprintln!("✅ Loaded {} built-in YARA rules from traits/", count);
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  No built-in YARA rules found: {}", e);
                }
            }
        }

        // 2. Optionally load third-party YARA rules from third_party/yara
        if enable_third_party {
            let third_party_dir = Path::new("third_party/yara");
            if third_party_dir.exists() {
                match self.load_rules_into_compiler(&mut compiler, third_party_dir, "third_party") {
                    Ok(count) => {
                        third_party_count = count;
                        if count > 0 {
                            eprintln!("✅ Loaded {} third-party YARA rules from third_party/yara (high criticality)", count);
                        }
                    }
                    Err(e) => {
                        eprintln!("⚠️  Failed to load third-party YARA rules: {}", e);
                    }
                }
            } else {
                eprintln!("⚠️  third_party/yara directory not found");
            }
        }

        if builtin_count + third_party_count == 0 {
            // Don't fail if no rules - just return empty
            return Ok((0, 0));
        }

        self.rules = Some(compiler.build());
        Ok((builtin_count, third_party_count))
    }

    /// Load YARA rules from a directory into a compiler
    fn load_rules_into_compiler(&mut self, compiler: &mut yara_x::Compiler, dir: &Path, namespace_prefix: &str) -> Result<usize> {
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
                        match self.compile_rule_file_into(compiler, path, namespace_prefix) {
                            Ok(_) => count += 1,
                            Err(e) => {
                                eprintln!("⚠️  Failed to compile {}: {}", path.display(), e);
                            }
                        }
                    }
                }
            }
        }

        if count == 0 {
            anyhow::bail!("No YARA rules found in {}", dir.display());
        }

        Ok(count)
    }

    /// Compile a single rule file into the compiler with namespace
    fn compile_rule_file_into(&mut self, compiler: &mut yara_x::Compiler, path: &Path, namespace_prefix: &str) -> Result<()> {
        let source = fs::read_to_string(path)
            .context(format!("Failed to read rule file: {}", path.display()))?;

        // Extract namespace from path and set it
        let namespace = self.extract_namespace_with_prefix(path, namespace_prefix);
        compiler.new_namespace(&namespace);

        // Track third-party namespaces
        if namespace_prefix == "third_party" {
            self.third_party_namespaces.push(namespace.clone());
        }

        compiler
            .add_source(source.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to compile rule {}: {:?}", path.display(), e))?;

        Ok(())
    }

    /// Extract namespace from file path with prefix
    fn extract_namespace_with_prefix(&self, path: &Path, prefix: &str) -> String {
        let path_str = path.to_string_lossy();

        // Find the base directory (traits/ or third_party/)
        let search_str = if prefix == "third_party" { "third_party/yara/" } else { "traits/" };

        if let Some(idx) = path_str.find(search_str) {
            let relative = &path_str[idx + search_str.len()..];

            // Remove filename and extension
            if let Some(parent) = Path::new(relative).parent() {
                let namespace_path = parent.to_string_lossy().replace('/', ".");
                return if namespace_path.is_empty() {
                    prefix.to_string()
                } else {
                    format!("{}.{}", prefix, namespace_path)
                };
            }
        }

        prefix.to_string()
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
            let mut severity = "none".to_string();  // Default to none - rules should explicitly set severity
            let mut capability_flag = false;
            let mut mbc_code: Option<String> = None;
            let mut attack_code: Option<String> = None;

            // Extract severity from YARA rule tags (e.g., "rule name: low")
            for tag in matching_rule.tags() {
                let tag_name = tag.identifier();
                if tag_name == "none" || tag_name == "low" || tag_name == "medium" || tag_name == "high" {
                    severity = tag_name.to_string();
                    break;
                }
            }

            // Check if this is a third-party rule - mark as high criticality
            let is_third_party = self.third_party_namespaces.iter().any(|ns| namespace.starts_with(ns));
            if is_third_party {
                severity = "high".to_string();
            }

            for (key, value) in matching_rule.metadata() {
                // Extract string value from MetaValue (strips String("...") wrapper from debug output)
                let value_str = {
                    let debug_str = format!("{:?}", value);
                    if debug_str.starts_with("String(\"") && debug_str.ends_with("\")") {
                        debug_str[8..debug_str.len()-2].to_string()
                    } else {
                        debug_str.trim_matches('"').to_string()
                    }
                };

                match key {
                    "description" => {
                        description = value_str;
                    }
                    "risk" => {
                        // Don't override high criticality for third-party rules
                        if !is_third_party {
                            severity = value_str;
                        }
                    }
                    "capability" => {
                        capability_flag = value_str.to_lowercase() == "true" || value_str == "1";
                    }
                    "mbc" => {
                        mbc_code = Some(value_str);
                    }
                    "attack" => {
                        attack_code = Some(value_str);
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

            // Infer capability from metadata:
            // 1. Explicit: capability = "true"
            // 2. Inferred: mbc or attack present
            let is_capability = capability_flag || mbc_code.is_some() || attack_code.is_some();

            matches.push(YaraMatch {
                rule: rule_name,
                namespace: namespace.clone(),
                severity,
                description,
                matched_strings,
                is_capability,
                mbc: mbc_code,
                attack: attack_code,
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
