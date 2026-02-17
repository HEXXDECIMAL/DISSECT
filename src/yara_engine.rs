//! YARA rule engine integration.
//!
//! This module provides YARA pattern matching for malware detection.
//! It loads and compiles YARA rules from:
//! - Built-in rules (traits/yara/)
//! - Third-party rules (if enabled)
//!
//! Rules are compiled once at startup for performance.

use crate::capabilities::CapabilityMapper;
use crate::types::{Evidence, MatchedString, YaraMatch};
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// YARA-X engine for pattern-based detection
#[derive(Debug)]
pub(crate) struct YaraEngine {
    rules: Option<yara_x::Rules>,
    capability_mapper: CapabilityMapper,
    /// Namespaces that are from third-party rules (marked as suspicious)
    third_party_namespaces: Vec<String>,
}

impl YaraEngine {
    /// Create a new YARA engine without rules loaded
    #[must_use] 
    pub(crate) fn new() -> Self {
        Self {
            rules: None,
            capability_mapper: CapabilityMapper::new(),
            third_party_namespaces: Vec::new(),
        }
    }

    /// Create a new YARA engine with a pre-existing capability mapper (avoids duplicate loading)
    #[must_use] 
    pub(crate) fn new_with_mapper(capability_mapper: CapabilityMapper) -> Self {
        Self {
            rules: None,
            capability_mapper,
            third_party_namespaces: Vec::new(),
        }
    }

    /// Set the capability mapper (useful for injecting after parallel loading)
    pub(crate) fn set_capability_mapper(&mut self, capability_mapper: CapabilityMapper) {
        self.capability_mapper = capability_mapper;
    }

    /// Load all YARA rules (built-in from traits/ + optionally third-party from third_party/yara)
    /// Uses cache if available and valid
    pub(crate) fn load_all_rules(&mut self, enable_third_party: bool) -> Result<(usize, usize)> {
        let _span = tracing::info_span!("load_yara_rules").entered();
        tracing::info!("Loading YARA rules");
        // Try to load from cache
        if let Ok(cache_path) = crate::cache::yara_cache_path(enable_third_party) {
            if cache_path.exists() {
                tracing::debug!("Attempting to load from cache");
                let _t_cache = std::time::Instant::now();
                match self.load_from_cache(&cache_path) {
                    Ok((builtin, third_party)) => {
                        tracing::info!(
                            "Loaded {} built-in + {} third-party YARA rules from cache",
                            builtin,
                            third_party
                        );
                        eprintln!(
                            "✅ Loaded {} built-in + {} third-party YARA rules from cache",
                            builtin, third_party
                        );
                        return Ok((builtin, third_party));
                    },
                    Err(e) => {
                        tracing::warn!("Cache load failed: {}, recompiling from source", e);
                        eprintln!("⚠️  Cache load failed ({}), recompiling...", e);
                    },
                }
            } else {
                tracing::debug!("No cache found, compiling from source");
            }
        }

        // Cache miss or invalid - compile from source
        tracing::info!("Compiling YARA rules from source");
        let mut compiler = yara_x::Compiler::new();
        let mut builtin_count = 0;
        let mut third_party_count = 0;

        // 1. Load built-in YARA rules from traits directory
        let traits_dir = crate::cache::traits_path();
        if traits_dir.exists() {
            tracing::debug!("Loading built-in YARA rules from {}", traits_dir.display());
            match self.load_rules_into_compiler(&mut compiler, &traits_dir, "traits") {
                Ok(count) => {
                    builtin_count = count;
                    if count > 0 {
                        eprintln!(
                            "✅ Loaded {} built-in YARA rules from {}",
                            count,
                            traits_dir.display()
                        );
                    }
                },
                Err(e) => {
                    // Only warn if this is an actual error, not just "no rules found"
                    let err_str = e.to_string();
                    if !err_str.contains("No YARA rules found") {
                        eprintln!(
                            "⚠️  Failed to load YARA rules from {}: {}",
                            traits_dir.display(),
                            e
                        );
                    }
                },
            }
        }

        // 2. Optionally load third-party YARA rules from third_party/yara
        if enable_third_party {
            let third_party_dir = Path::new("third_party/yara");
            if third_party_dir.exists() {
                tracing::debug!("Loading third-party YARA rules");
                match self.load_rules_into_compiler(&mut compiler, third_party_dir, "third_party") {
                    Ok(count) => {
                        third_party_count = count;
                        if count > 0 {
                            eprintln!("✅ Loaded {} third-party YARA rules from third_party/yara (suspicious)", count);
                        }
                    },
                    Err(e) => {
                        eprintln!("⚠️  Failed to load third-party YARA rules: {}", e);
                    },
                }
            } else {
                eprintln!("⚠️  third_party/yara directory not found");
            }
        }

        if builtin_count + third_party_count == 0 {
            // Don't fail if no rules - just return empty
            tracing::info!("No YARA rules found");
            return Ok((0, 0));
        }

        let _t_build = std::time::Instant::now();
        tracing::info!("Compiling {} YARA rules", builtin_count + third_party_count);
        self.rules = Some(compiler.build());
        tracing::debug!("YARA compilation complete");

        // Save to cache for next time
        tracing::debug!("Saving compiled rules to cache");
        if let Ok(cache_path) = crate::cache::yara_cache_path(enable_third_party) {
            if let Err(e) = self.save_to_cache(&cache_path, builtin_count, third_party_count) {
                eprintln!("⚠️  Failed to save cache: {}", e);
            } else {
                eprintln!("✅ Saved YARA rules to cache");
                // Clean up old caches
                let _ = crate::cache::cleanup_old_caches(&cache_path);
            }
        }

        Ok((builtin_count, third_party_count))
    }

    /// Load YARA rules from a directory into a compiler
    fn load_rules_into_compiler<'a>(
        &mut self,
        compiler: &mut yara_x::Compiler<'a>,
        dir: &Path,
        namespace_prefix: &str,
    ) -> Result<usize> {
        // First, collect all YARA rule file paths
        tracing::trace!("Scanning {} for YARA rule files", dir.display());
        let rule_files: Vec<PathBuf> = WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                let path = entry.path();
                path.is_file()
                    && path.extension().map(|ext| ext == "yar" || ext == "yara").unwrap_or(false)
            })
            .map(|entry| entry.path().to_path_buf())
            .collect();

        if rule_files.is_empty() {
            anyhow::bail!("No YARA rules found in {}", dir.display());
        }

        tracing::debug!("Found {} YARA rule files", rule_files.len());
        // Read all files in parallel (I/O bound operation)
        let _t_read = std::time::Instant::now();
        tracing::trace!("Reading YARA rule files");
        let sources: Vec<_> = rule_files
            .par_iter()
            .filter_map(|path| {
                let bytes = fs::read(path).ok()?;
                let source = String::from_utf8_lossy(&bytes).into_owned();
                Some((path.clone(), source))
            })
            .collect();

        tracing::debug!("Read {} rule files", sources.len());

        // Use a single namespace per source (builtin vs third_party)
        let namespace = namespace_prefix.to_string();
        compiler.new_namespace(&namespace);

        // Track third-party namespace
        if namespace_prefix == "third_party" {
            self.third_party_namespaces.push(namespace.clone());
        }

        // Compile all sources (separate calls for better error reporting)
        let _t_compile = std::time::Instant::now();
        tracing::debug!("Compiling {} YARA rule sources", sources.len());
        let mut count = 0;
        for (path, source) in sources {
            tracing::trace!("Compiling {}", path.display());
            match compiler.add_source(source.as_bytes()) {
                Ok(_) => count += 1,
                Err(e) => {
                    tracing::warn!("Failed to compile {}: {:?}", path.display(), e);
                    eprintln!("⚠️  Failed to compile {}: {:?}", path.display(), e);
                },
            }
        }
        tracing::debug!("Successfully compiled {} YARA rules", count);

        if count == 0 {
            anyhow::bail!("Failed to compile any YARA rules from {}", dir.display());
        }

        Ok(count)
    }

    /// Extract namespace from file path with prefix
    #[allow(dead_code)] // Used by tests
    fn extract_namespace_with_prefix(&self, path: &Path, prefix: &str) -> String {
        let path_str = path.to_string_lossy();

        // Find the base directory (traits/ or third_party/)
        let search_str = if prefix == "third_party" {
            "third_party/yara/"
        } else {
            "traits/"
        };

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

    /// Normalize a filetype string for use as a cache suffix
    /// Simplifies types like "application/x-sh" to "sh"
    #[allow(dead_code)] // Used by tests
    fn normalize_filetype_for_cache(filetype: &str) -> &str {
        // Remove MIME type prefixes
        if let Some(suffix) = filetype.strip_prefix("application/x-") {
            return suffix;
        }
        if let Some(suffix) = filetype.strip_prefix("text/x-") {
            return suffix;
        }
        // Return as-is for simple types
        filetype
    }

    /// Check if a YARA rule matches the given file types
    /// Parses the metadata section for "filetype" or "filetypes" fields
    #[allow(dead_code)] // Used by tests
    fn rule_matches_filetypes(source: &str, filter_types: &[&str]) -> bool {
        // If no metadata section, include the rule (no type restriction)
        if !source.contains("meta:") {
            return true;
        }

        // Simple text-based parsing for filetype metadata
        // Look for: filetype = "value" or filetypes = "value1,value2"
        for line in source.lines() {
            let trimmed = line.trim();

            // Single filetype
            if trimmed.starts_with("filetype") && trimmed.contains('=') {
                if let Some(value_part) = trimmed.split('=').nth(1) {
                    let value =
                        value_part.trim().trim_matches('"').trim_matches('\'').to_lowercase();

                    // Check if any filter type matches
                    for filter_type in filter_types {
                        if value == filter_type.to_lowercase() {
                            return true;
                        }
                    }
                }
            }

            // Multiple filetypes (comma-separated)
            if trimmed.starts_with("filetypes") && trimmed.contains('=') {
                if let Some(value_part) = trimmed.split('=').nth(1) {
                    let value = value_part.trim().trim_matches('"').trim_matches('\'');

                    // Split by comma and check each type
                    for rule_type in value.split(',') {
                        let rule_type = rule_type.trim().to_lowercase();
                        for filter_type in filter_types {
                            if rule_type == filter_type.to_lowercase() {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        // No matching filetype found, exclude the rule
        false
    }

/// Scan a file with loaded YARA rules
    pub(crate) fn scan_file(&self, file_path: &Path) -> Result<Vec<YaraMatch>> {
        let _rules = self.rules.as_ref().context("No YARA rules loaded")?;

        let data =
            fs::read(file_path).context(format!("Failed to read file: {}", file_path.display()))?;

        self.scan_bytes(&data)
    }

    /// Scan byte data with loaded YARA rules
    /// Optionally filter results by file type
    pub(crate) fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        self.scan_bytes_filtered(data, None)
    }

    /// Scan byte data with optional file type filtering
    pub(crate) fn scan_bytes_filtered(
        &self,
        data: &[u8],
        file_type_filter: Option<&[&str]>,
    ) -> Result<Vec<YaraMatch>> {
        let rules = self.rules.as_ref().context("No YARA rules loaded")?;

        let mut scanner = yara_x::Scanner::new(rules);
        let scan_results =
            scanner.scan(data).map_err(|e| anyhow::anyhow!("YARA scan failed: {:?}", e))?;

        let mut matches = Vec::new();
        let debug = std::env::var("DISSECT_DEBUG").is_ok();

        for matching_rule in scan_results.matching_rules() {
            let rule_name = matching_rule.identifier().to_string();
            let namespace = matching_rule.namespace().to_string();

            // Extract metadata - iterate through key-value pairs
            let mut description = String::new();
            let mut severity = "none".to_string(); // Default to none - rules should explicitly set severity
            let mut capability_flag = false;
            let mut mbc_code: Option<String> = None;
            let mut attack_code: Option<String> = None;
            let mut rule_filetypes: Vec<String> = Vec::new();

            // Extract severity from YARA rule tags (e.g., "rule name: low")
            for tag in matching_rule.tags() {
                let tag_name = tag.identifier();
                if tag_name == "none"
                    || tag_name == "low"
                    || tag_name == "medium"
                    || tag_name == "high"
                {
                    severity = tag_name.to_string();
                    break;
                }
            }

            // Check if this is a third-party rule - mark as suspicious
            let is_third_party =
                self.third_party_namespaces.iter().any(|ns| namespace.starts_with(ns));
            if is_third_party {
                severity = "medium".to_string();
            }

            for (key, value) in matching_rule.metadata() {
                // Extract string value from MetaValue (strips String("...") wrapper from debug output)
                let value_str = {
                    let debug_str = format!("{:?}", value);
                    if debug_str.starts_with("String(\"") && debug_str.ends_with("\")") {
                        debug_str[8..debug_str.len() - 2].to_string()
                    } else {
                        debug_str.trim_matches('"').to_string()
                    }
                };

                match key {
                    "description" => {
                        description = value_str;
                    },
                    "risk" => {
                        // Don't override suspicious criticality for third-party rules
                        if !is_third_party {
                            severity = value_str;
                        }
                    },
                    "capability" => {
                        capability_flag = value_str.to_lowercase() == "true" || value_str == "1";
                    },
                    "mbc" => {
                        mbc_code = Some(value_str);
                    },
                    "attack" => {
                        attack_code = Some(value_str);
                    },
                    "filetype" | "filetypes" => {
                        // Parse comma-separated file types
                        rule_filetypes =
                            value_str.split(',').map(|s| s.trim().to_lowercase()).collect();
                    },
                    _ => {},
                }
            }

            // Apply file type filtering if specified
            if let Some(filter_types) = file_type_filter {
                // If rule has filetype constraints and none match our filter, mark as filtered
                if !rule_filetypes.is_empty() {
                    let matches_filter = rule_filetypes.iter().any(|rule_type| {
                        filter_types
                            .iter()
                            .any(|filter_type| rule_type == &filter_type.to_lowercase())
                    });

                    if !matches_filter {
                        severity = "filtered".to_string();
                        if debug {
                            eprintln!(
                                "  [DEBUG] Filtered rule '{}' (types: {:?}, expected: {:?})",
                                rule_name, rule_filetypes, filter_types
                            );
                        }
                    }
                }
                // If rule has no filetype constraint, include it (applies to all files)
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
                desc: description,
                matched_strings,
                is_capability,
                mbc: mbc_code,
                attack: attack_code,
            });
        }

        Ok(matches)
    }

    /// Check if rules are loaded
    #[must_use] 
    pub(crate) fn is_loaded(&self) -> bool {
        self.rules.is_some()
    }

    /// Map YARA match to capability evidence
    #[must_use] 
    pub(crate) fn yara_match_to_evidence(&self, yara_match: &YaraMatch) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        for matched_str in &yara_match.matched_strings {
            // Use actual matched value if printable, otherwise use identifier
            let is_printable = matched_str
                .value
                .bytes()
                .all(|b| (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\t');
            let evidence_value = if is_printable && !matched_str.value.is_empty() {
                matched_str.value.clone()
            } else {
                matched_str.identifier.clone()
            };

            evidence.push(Evidence {
                method: "yara".to_string(),
                source: "yara-x".to_string(),
                value: evidence_value,
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

    /// Map YARA namespace to capability ID
    /// Returns the capability ID if the namespace maps to a known capability
    #[must_use] 
    pub(crate) fn namespace_to_capability(&self, namespace: &str) -> Option<String> {
        // YARA namespace format: exec.cmd, anti-static.obfuscation, etc.
        // Convert to capability ID: exec/command, anti-analysis/obfuscation
        let parts: Vec<&str> = namespace.split('.').collect();

        match parts.as_slice() {
            ["exec", "cmd"] => Some("exec/command/shell".to_string()),
            ["exec", "program"] => Some("exec/command/direct".to_string()),
            ["exec", "shell"] => Some("exec/command/shell".to_string()),
            ["net", sub] => Some(format!("net/{}", sub)),
            ["crypto", sub] => Some(format!("crypto/{}", sub)),
            ["fs", sub] => Some(format!("fs/{}", sub)),
            ["anti-static", "obfuscation"] => Some("anti-analysis/obfuscation".to_string()),
            ["process", sub] => Some(format!("process/{}", sub)),
            ["credential", sub] => Some(format!("credential/{}", sub)),
            // For third-party rules, use the namespace directly as the capability
            _ if !namespace.is_empty() => Some(namespace.replace('.', "/")),
            _ => None,
        }
    }

    /// Scan a file and return both YARA matches and derived findings
    /// This is the main entry point for universal YARA scanning
    pub(crate) fn scan_file_to_findings(
        &self,
        file_path: &Path,
        file_type_filter: Option<&[&str]>,
    ) -> Result<(Vec<YaraMatch>, Vec<crate::types::Finding>)> {
        use crate::types::{Criticality, Finding, FindingKind};

        let data =
            fs::read(file_path).context(format!("Failed to read file: {}", file_path.display()))?;

        let matches = self.scan_bytes_filtered(&data, file_type_filter)?;
        let mut findings = Vec::new();

        for yara_match in &matches {
            // Map namespace to capability ID
            let capability_id = self.namespace_to_capability(&yara_match.namespace);

            if let Some(cap_id) = capability_id {
                let evidence = self.yara_match_to_evidence(yara_match);

                // Determine criticality from severity
                let criticality = match yara_match.severity.as_str() {
                    "high" => Criticality::Hostile,
                    "medium" => Criticality::Suspicious,
                    "low" => Criticality::Notable,
                    _ => Criticality::Inert,
                };

                findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: cap_id,
                    desc: yara_match.desc.clone(),
                    conf: 0.9, // YARA matches are high confidence
                    crit: criticality,
                    mbc: yara_match.mbc.clone(),
                    attack: yara_match.attack.clone(),
                    evidence,
                    source_file: None,
                });
            }
        }

        Ok((matches, findings))
    }

    /// Save compiled YARA rules to cache
    fn save_to_cache(
        &self,
        cache_path: &Path,
        builtin_count: usize,
        third_party_count: usize,
    ) -> Result<()> {
        let rules = self.rules.as_ref().context("No rules to cache")?;

        // Serialize the rules using the YARA-X serialization
        let serialized = rules.serialize().context("Failed to serialize YARA rules")?;

        // Create a cache structure with metadata
        let cache_data = CacheData {
            builtin_count,
            third_party_count,
            third_party_namespaces: self.third_party_namespaces.clone(),
            rules_data: serialized,
        };

        // Serialize to file
        let encoded = bincode::serialize(&cache_data).context("Failed to encode cache data")?;

        fs::write(cache_path, encoded).context("Failed to write cache file")?;

        Ok(())
    }

    /// Load compiled YARA rules from cache
    fn load_from_cache(&mut self, cache_path: &Path) -> Result<(usize, usize)> {
        let _t_read = std::time::Instant::now();
        let data = fs::read(cache_path).context("Failed to read cache file")?;

        let _t_bincode = std::time::Instant::now();
        let cache_data: CacheData =
            bincode::deserialize(&data).context("Failed to decode cache data")?;

        // Deserialize the YARA rules
        let _t_yara = std::time::Instant::now();
        let rules = yara_x::Rules::deserialize(&cache_data.rules_data)
            .context("Failed to deserialize YARA rules")?;

        self.rules = Some(rules);
        self.third_party_namespaces = cache_data.third_party_namespaces;

        Ok((cache_data.builtin_count, cache_data.third_party_count))
    }
}

/// Cache data structure
#[derive(serde::Serialize, serde::Deserialize)]
struct CacheData {
    builtin_count: usize,
    third_party_count: usize,
    third_party_namespaces: Vec<String>,
    rules_data: Vec<u8>,
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

    #[test]
    fn test_new() {
        let engine = YaraEngine::new();
        assert!(!engine.is_loaded());
        assert_eq!(engine.third_party_namespaces.len(), 0);
    }

    #[test]
    fn test_default() {
        let engine = YaraEngine::default();
        assert!(!engine.is_loaded());
    }

    #[test]
    fn test_is_loaded() {
        let mut engine = YaraEngine::new();
        assert!(!engine.is_loaded());

        // Load a simple rule
        let rule = r#"rule test { strings: $a = "test" condition: $a }"#;
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(rule.as_bytes()).unwrap();
        engine.load_rule_file(temp_file.path()).unwrap();

        assert!(engine.is_loaded());
    }

    #[test]
    fn test_scan_without_rules() {
        let engine = YaraEngine::new();
        let result = engine.scan_bytes(b"test data");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No YARA rules loaded"));
    }

    #[test]
    fn test_extract_namespace() {
        let engine = YaraEngine::new();
        let path = Path::new("/path/to/rules/exec/shell/test.yar");
        let namespace = engine.extract_namespace(path);
        assert_eq!(namespace, "exec.shell");
    }

    #[test]
    fn test_extract_namespace_no_subdirs() {
        let engine = YaraEngine::new();
        let path = Path::new("/path/to/rules/test.yar");
        let namespace = engine.extract_namespace(path);
        // When a file is directly in rules/, parent returns "" not "default"
        assert_eq!(namespace, "");
    }

    #[test]
    fn test_extract_namespace_with_prefix() {
        let engine = YaraEngine::new();
        let path = Path::new("/path/to/traits/exec/shell/test.yar");
        let namespace = engine.extract_namespace_with_prefix(path, "traits");
        assert_eq!(namespace, "traits.exec.shell");
    }

    #[test]
    fn test_extract_namespace_with_prefix_third_party() {
        let engine = YaraEngine::new();
        let path = Path::new("/path/to/third_party/yara/malware/test.yar");
        let namespace = engine.extract_namespace_with_prefix(path, "third_party");
        assert_eq!(namespace, "third_party.malware");
    }

    #[test]
    fn test_extract_namespace_with_prefix_no_subdirs() {
        let engine = YaraEngine::new();
        let path = Path::new("/path/to/traits/test.yar");
        let namespace = engine.extract_namespace_with_prefix(path, "traits");
        assert_eq!(namespace, "traits");
    }

    #[test]
    fn test_rule_with_metadata() {
        let rule = r#"
rule test_rule {
    meta:
        description = "Test description"
        risk = "high"
        capability = "true"
        mbc = "B0001"
        attack = "T1059"
    strings:
        $test = "PATTERN"
    condition:
        $test
}
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(rule.as_bytes()).unwrap();

        let mut engine = YaraEngine::new();
        engine.load_rule_file(temp_file.path()).unwrap();

        let test_data = b"This contains PATTERN in the data";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].desc, "Test description");
        assert_eq!(matches[0].severity, "high");
        assert!(matches[0].is_capability);
        assert_eq!(matches[0].mbc, Some("B0001".to_string()));
        assert_eq!(matches[0].attack, Some("T1059".to_string()));
    }

    #[test]
    fn test_rule_with_tags() {
        let rule = r#"
rule test_rule : medium {
    strings:
        $test = "TAGGED"
    condition:
        $test
}
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(rule.as_bytes()).unwrap();

        let mut engine = YaraEngine::new();
        engine.load_rule_file(temp_file.path()).unwrap();

        let test_data = b"TAGGED data";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].severity, "medium");
    }

    #[test]
    fn test_yara_match_to_evidence() {
        let engine = YaraEngine::new();

        let yara_match = YaraMatch {
            rule: "test_rule".to_string(),
            namespace: "test.namespace".to_string(),
            severity: "high".to_string(),
            desc: "Test".to_string(),
            matched_strings: vec![MatchedString {
                identifier: "$pattern".to_string(),
                offset: 0x1000,
                value: "test".to_string(),
            }],
            is_capability: false,
            mbc: None,
            attack: None,
        };

        let evidence = engine.yara_match_to_evidence(&yara_match);

        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].method, "yara");
        assert_eq!(evidence[0].source, "yara-x");
        assert_eq!(evidence[0].value, "test"); // Uses actual matched value
        assert_eq!(evidence[0].location, Some("offset:0x1000".to_string()));
    }

    #[test]
    fn test_yara_match_to_evidence_no_strings() {
        let engine = YaraEngine::new();

        let yara_match = YaraMatch {
            rule: "test_rule".to_string(),
            namespace: "test.namespace".to_string(),
            severity: "high".to_string(),
            desc: "Test".to_string(),
            matched_strings: vec![],
            is_capability: false,
            mbc: None,
            attack: None,
        };

        let evidence = engine.yara_match_to_evidence(&yara_match);

        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].value, "test_rule");
        assert_eq!(evidence[0].location, Some("test.namespace".to_string()));
    }

    #[test]
    fn test_multiple_patterns() {
        let rule = r#"
rule test_rule {
    strings:
        $a = "FIRST"
        $b = "SECOND"
    condition:
        any of them
}
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(rule.as_bytes()).unwrap();

        let mut engine = YaraEngine::new();
        engine.load_rule_file(temp_file.path()).unwrap();

        let test_data = b"FIRST and SECOND patterns";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched_strings.len(), 2);
    }

    #[test]
    fn test_long_match_truncation() {
        let rule = r#"
rule test_rule {
    strings:
        $long = /A{200}/
    condition:
        $long
}
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(rule.as_bytes()).unwrap();

        let mut engine = YaraEngine::new();
        engine.load_rule_file(temp_file.path()).unwrap();

        let test_data = vec![b'A'; 200];
        let matches = engine.scan_bytes(&test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert!(matches[0].matched_strings[0].value.contains("200 bytes"));
    }

    #[test]
    fn test_capability_inference_from_mbc() {
        let rule = r#"
rule test_rule {
    meta:
        mbc = "B0015.001"
    strings:
        $test = "TEST"
    condition:
        $test
}
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(rule.as_bytes()).unwrap();

        let mut engine = YaraEngine::new();
        engine.load_rule_file(temp_file.path()).unwrap();

        let test_data = b"TEST";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert!(matches[0].is_capability); // Inferred from MBC presence
    }

    #[test]
    fn test_capability_inference_from_attack() {
        let rule = r#"
rule test_rule {
    meta:
        attack = "T1059.004"
    strings:
        $test = "TEST"
    condition:
        $test
}
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(rule.as_bytes()).unwrap();

        let mut engine = YaraEngine::new();
        engine.load_rule_file(temp_file.path()).unwrap();

        let test_data = b"TEST";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert!(matches[0].is_capability); // Inferred from ATT&CK presence
    }
}
