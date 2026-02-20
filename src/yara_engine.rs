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
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// YARA-X engine for pattern-based detection
#[derive(Debug)]
pub(crate) struct YaraEngine {
    rules: Option<yara_x::Rules>,
    capability_mapper: CapabilityMapper,
    /// Namespaces compiled into the combined engine from inline trait YARA conditions.
    /// Used to split scan results: inline matches (keyed here) go to trait evaluation;
    /// all other matches are returned as regular YARA findings.
    compiled_inline_namespaces: Vec<String>,
}

impl YaraEngine {
    /// Create a new YARA engine without rules loaded
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            rules: None,
            capability_mapper: CapabilityMapper::new(),
            compiled_inline_namespaces: Vec::new(),
        }
    }

    /// Create a new YARA engine with a pre-existing capability mapper (avoids duplicate loading)
    #[must_use]
    pub(crate) fn new_with_mapper(capability_mapper: CapabilityMapper) -> Self {
        Self { rules: None, capability_mapper, compiled_inline_namespaces: Vec::new() }
    }

    /// Set the capability mapper (useful for injecting after parallel loading)
    pub(crate) fn set_capability_mapper(&mut self, capability_mapper: CapabilityMapper) {
        self.capability_mapper = capability_mapper;
    }

    /// Load all YARA rules (built-in from traits/ + optionally third-party from third_party/)
    /// Uses cache if available and valid
    pub(crate) fn load_all_rules(&mut self, enable_third_party: bool) -> (usize, usize) {
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
                        return (builtin, third_party);
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

        // 0. Load inline YARA from trait YAML files into the combined compiler.
        //    These are `type: yara` conditions in .yaml trait definitions.
        //    By compiling them here, a single JIT pass covers both inline and third-party rules.
        let traits_dir = crate::cache::traits_path();
        if traits_dir.exists() {
            self.compiled_inline_namespaces =
                Self::load_inline_trait_rules(&mut compiler, &traits_dir);
            if !self.compiled_inline_namespaces.is_empty() {
                tracing::debug!(
                    "Loaded {} inline YARA rules from trait YAML files",
                    self.compiled_inline_namespaces.len()
                );
            }
        }

        // 1. Load built-in YARA rules from traits directory
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

        // 2. Optionally load third-party YARA rules from third_party/ with per-vendor namespaces
        if enable_third_party {
            let third_party_dir = Path::new("third_party");
            if third_party_dir.exists() {
                tracing::debug!("Loading third-party YARA rules");
                let count = self.load_third_party_rules(&mut compiler, third_party_dir);
                third_party_count = count;
                if count > 0 {
                    tracing::info!("Loaded {} third-party YARA rules from third_party/", count);
                }
            } else {
                tracing::warn!("third_party/ directory not found");
            }
        }

        if builtin_count + third_party_count == 0 {
            // Don't fail if no rules - just return empty
            tracing::info!("No YARA rules found");
            return (0, 0);
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

        (builtin_count, third_party_count)
    }

    /// Parse trait YAML files and add all `type: yara` conditions to the compiler.
    ///
    /// Each rule is added under namespace `inline.{trait_id}` so that scan results
    /// can be mapped back to the originating trait during evaluation.
    /// Returns the list of namespaces successfully added.
    fn load_inline_trait_rules<'a>(
        compiler: &mut yara_x::Compiler<'a>,
        traits_dir: &Path,
    ) -> Vec<String> {
        let mut namespaces = Vec::new();

        let yaml_files: Vec<PathBuf> = WalkDir::new(traits_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                let p = e.path();
                p.is_file()
                    && p.extension()
                        .map(|ext| ext == "yaml" || ext == "yml")
                        .unwrap_or(false)
            })
            .map(|e| e.path().to_path_buf())
            .collect();

        for path in &yaml_files {
            let Ok(content) = fs::read_to_string(path) else { continue };
            let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&content) else { continue };

            // YAML files may have a top-level `traits:` list or be a bare list
            let items = match &doc {
                serde_yaml::Value::Mapping(m) => m
                    .get("traits")
                    .and_then(|v| v.as_sequence())
                    .map(Vec::as_slice),
                serde_yaml::Value::Sequence(s) => Some(s.as_slice()),
                _ => None,
            };

            let Some(items) = items else { continue };

            for item in items {
                let Some(id) = item.get("id").and_then(|v| v.as_str()) else { continue };
                let Some(if_cond) = item.get("if") else { continue };

                // Only handle `type: yara` conditions
                if if_cond.get("type").and_then(|v| v.as_str()) != Some("yara") {
                    continue;
                }

                let Some(source) = if_cond.get("source").and_then(|v| v.as_str()) else {
                    continue
                };

                let ns = format!("inline.{}", id);
                compiler.new_namespace(&ns);
                match compiler.add_source(source.as_bytes()) {
                    Ok(_) => {
                        tracing::trace!("Loaded inline YARA rule for trait {}", id);
                        namespaces.push(ns);
                    },
                    Err(e) => {
                        tracing::warn!("Failed to compile inline YARA for trait {}: {:?}", id, e);
                    },
                }
            }
        }

        namespaces
    }

    /// Scan binary data and split results into regular YARA matches and inline trait results.
    ///
    /// Regular matches (non-`inline.*` namespaces) are returned as `Vec<YaraMatch>` for
    /// inclusion in the analysis report. Inline matches are returned as a
    /// `HashMap<String, Vec<Evidence>>` keyed by namespace (`"inline.{trait_id}"`), for use
    /// by trait evaluation via `EvaluationContext::inline_yara_results`.
    pub(crate) fn scan_bytes_with_inline(
        &self,
        data: &[u8],
        file_type_filter: Option<&[&str]>,
    ) -> Result<(Vec<YaraMatch>, HashMap<String, Vec<Evidence>>)> {
        use std::time::Duration;

        let rules = self.rules.as_ref().context("No YARA rules loaded")?;
        let inline_ns_set: std::collections::HashSet<&str> =
            self.compiled_inline_namespaces.iter().map(String::as_str).collect();

        let mut scanner = yara_x::Scanner::new(rules);
        scanner.set_timeout(Duration::from_secs(30));
        let scan_results =
            scanner.scan(data).map_err(|e| anyhow::anyhow!("YARA scan failed: {:?}", e))?;

        struct RawRule {
            name: String,
            namespace: String,
            tags: Vec<String>,
            metadata: Vec<(String, String)>,
            patterns: Vec<(String, Vec<(usize, usize)>)>,
        }

        let raw_rules: Vec<RawRule> = scan_results
            .matching_rules()
            .map(|rule| RawRule {
                name: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
                metadata: rule
                    .metadata()
                    .map(|(k, v)| (k.to_string(), format!("{:?}", v)))
                    .collect(),
                patterns: rule
                    .patterns()
                    .map(|pat| {
                        let ranges =
                            pat.matches().map(|m| (m.range().start, m.range().end)).collect();
                        (pat.identifier().to_string(), ranges)
                    })
                    .collect(),
            })
            .collect();

        drop(scan_results);

        // Warn on slow rules
        const SLOW_RULE_THRESHOLD: Duration = Duration::from_millis(500);
        for profiling_data in scanner.most_expensive_rules(20) {
            let total = profiling_data.condition_exec_time + profiling_data.pattern_matching_time;
            if total >= SLOW_RULE_THRESHOLD {
                tracing::warn!(
                    namespace = %profiling_data.namespace,
                    rule = %profiling_data.rule,
                    total_ms = total.as_millis(),
                    "Slow YARA rule ({}ms): {}::{} — consider disabling",
                    total.as_millis(),
                    profiling_data.namespace,
                    profiling_data.rule,
                );
            }
        }

        let mut yara_matches = Vec::new();
        let mut inline_results: HashMap<String, Vec<Evidence>> = HashMap::new();

        for raw in raw_rules {
            // Inline namespace: collect evidence for trait evaluation, not YARA output
            if inline_ns_set.contains(raw.namespace.as_str()) {
                let evidence = raw
                    .patterns
                    .iter()
                    .flat_map(|(_pattern_id, ranges)| {
                        ranges.iter().map(|(start, end)| {
                            let match_len = end - start;
                            let value = if match_len <= 100 {
                                String::from_utf8_lossy(&data[*start..*end]).to_string()
                            } else {
                                format!("<{} bytes>", match_len)
                            };
                            Evidence {
                                method: "yara".to_string(),
                                source: "yara-x".to_string(),
                                value,
                                location: Some(format!("offset:0x{:x}", start)),
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                // Even if empty (condition match without string patterns), record the hit
                inline_results.entry(raw.namespace).or_default().extend(evidence);
                continue;
            }

            // Regular match: build YaraMatch
            let yara_match = self.build_yara_match(raw.name, raw.namespace, &raw.tags,
                &raw.metadata, &raw.patterns, data, file_type_filter);
            if let Some(m) = yara_match {
                yara_matches.push(m);
            }
        }

        Ok((yara_matches, inline_results))
    }

    /// Load YARA rules from a directory into a compiler, skipping individual files that fail to compile
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

        compiler.new_namespace(namespace_prefix);

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

    /// Load third-party YARA rules with per-vendor namespaces (3p.{vendor}[.{subdir}])
    fn load_third_party_rules<'a>(
        &mut self,
        compiler: &mut yara_x::Compiler<'a>,
        dir: &Path,
    ) -> usize {
        // Collect all YARA files grouped by their directory (namespace boundary)
        let mut files_by_dir: std::collections::BTreeMap<PathBuf, Vec<PathBuf>> =
            std::collections::BTreeMap::new();

        for entry in WalkDir::new(dir).follow_links(false).into_iter().filter_map(std::result::Result::ok) {
            let path = entry.path();
            if path.is_file()
                && path.extension().map(|e| e == "yar" || e == "yara").unwrap_or(false)
            {
                let dir_path = path.parent().unwrap_or(path).to_path_buf();
                files_by_dir.entry(dir_path).or_default().push(path.to_path_buf());
            }
        }

        let mut total = 0;
        for (dir_path, rule_files) in &files_by_dir {
            // Derive namespace from directory path relative to third_party/
            let namespace = dir_path
                .strip_prefix(dir)
                .ok()
                .and_then(|rel| rel.to_str())
                .map(|s| {
                    let parts: Vec<&str> =
                        s.split(std::path::MAIN_SEPARATOR).filter(|p| !p.is_empty()).collect();
                    format!("3p.{}", parts.join("."))
                })
                .unwrap_or_else(|| "3p".to_string());

            compiler.new_namespace(&namespace);

            let sources: Vec<_> = rule_files
                .par_iter()
                .filter_map(|path| fs::read(path).ok().map(|b| (path.clone(), b)))
                .collect();

            for (path, bytes) in sources {
                let source = String::from_utf8_lossy(&bytes);
                match compiler.add_source(source.as_bytes()) {
                    Ok(_) => total += 1,
                    Err(e) => tracing::warn!("{}: {}", path.display(), e),
                }
            }
        }

        total
    }

    /// Extract namespace from file path with prefix
    #[allow(dead_code)] // Used by tests
    fn extract_namespace_with_prefix(&self, path: &Path, prefix: &str) -> String {
        let path_str = path.to_string_lossy();

        // Find the base directory (traits/ or third_party/)
        let search_str = if prefix == "third_party" {
            "third_party/"
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

    /// Scan byte data with optional file type filtering.
    /// Inline YARA results (namespace `inline.*`) are silently discarded; use
    /// `scan_bytes_with_inline` when you need them for trait evaluation.
    pub(crate) fn scan_bytes_filtered(
        &self,
        data: &[u8],
        file_type_filter: Option<&[&str]>,
    ) -> Result<Vec<YaraMatch>> {
        let (matches, _inline) = self.scan_bytes_with_inline(data, file_type_filter)?;
        Ok(matches)
    }

    /// Build a `YaraMatch` from raw match data collected during scanning.
    /// Returns `None` if the rule is an inline trait rule (those go into `inline_results`).
    #[allow(clippy::too_many_arguments)]
    fn build_yara_match(
        &self,
        rule_name: String,
        namespace: String,
        tags: &[String],
        metadata: &[(String, String)],
        patterns: &[(String, Vec<(usize, usize)>)],
        data: &[u8],
        file_type_filter: Option<&[&str]>,
    ) -> Option<YaraMatch> {
        let mut description = String::new();
        let mut severity = "none".to_string();
        let mut capability_flag = false;
        let mut mbc_code: Option<String> = None;
        let mut attack_code: Option<String> = None;
        let mut rule_filetypes: Vec<String> = Vec::new();
        let mut os_meta: Option<String> = None;

        for tag_name in tags {
            if matches!(tag_name.as_str(), "none" | "low" | "medium" | "high") {
                severity = tag_name.clone();
                break;
            }
        }

        let is_third_party = namespace.starts_with("3p.");
        if is_third_party {
            severity = "medium".to_string();
        }

        for (key, value_str) in metadata {
            let value_str = if value_str.starts_with("String(\"") && value_str.ends_with("\")") {
                value_str[8..value_str.len() - 2].to_string()
            } else {
                value_str.trim_matches('"').to_string()
            };

            match key.as_str() {
                "description" => description = value_str,
                "risk" => {
                    if !is_third_party {
                        severity = value_str;
                    }
                },
                "capability" => {
                    capability_flag = value_str.to_lowercase() == "true" || value_str == "1";
                },
                "mbc" => mbc_code = Some(value_str),
                "attack" => attack_code = Some(value_str),
                "filetype" | "filetypes" => {
                    rule_filetypes =
                        value_str.split(',').map(|s| s.trim().to_lowercase()).collect();
                },
                "os" => os_meta = Some(value_str.to_lowercase()),
                _ => {},
            }
        }

        if is_third_party && rule_filetypes.is_empty() {
            let inferred =
                crate::third_party_yara::infer_filetypes(&rule_name, os_meta.as_deref());
            rule_filetypes = inferred.iter().map(std::string::ToString::to_string).collect();
        }

        if let Some(filter_types) = file_type_filter {
            if !rule_filetypes.is_empty() {
                let matches_filter = rule_filetypes
                    .iter()
                    .any(|rule_type| filter_types.iter().any(|ft| rule_type == &ft.to_lowercase()));
                if !matches_filter {
                    tracing::warn!(
                        rule = %rule_name,
                        rule_targets = ?rule_filetypes,
                        scanning = ?filter_types,
                        "YARA rule filtered: targets {:?}, not applicable to {:?}",
                        rule_filetypes,
                        filter_types,
                    );
                    return None;
                }
            }
        }

        let mut matched_strings = Vec::new();
        for (pattern_id, ranges) in patterns {
            for (start, end) in ranges {
                let match_len = end - start;
                let value = if match_len <= 100 {
                    String::from_utf8_lossy(&data[*start..*end]).to_string()
                } else {
                    format!("<{} bytes>", match_len)
                };
                matched_strings.push(MatchedString {
                    identifier: pattern_id.clone(),
                    offset: *start as u64,
                    value,
                });
            }
        }

        let is_capability = capability_flag || mbc_code.is_some() || attack_code.is_some();
        let trait_id = if is_third_party {
            Some(crate::third_party_yara::derive_trait_id(
                &namespace,
                &rule_name,
                os_meta.as_deref(),
            ))
        } else {
            None
        };

        Some(YaraMatch {
            rule: rule_name,
            namespace,
            severity,
            desc: description,
            matched_strings,
            is_capability,
            mbc: mbc_code,
            attack: attack_code,
            trait_id,
        })
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
        // Convert to capability ID: execution/command, anti-analysis/obfuscation
        let parts: Vec<&str> = namespace.split('.').collect();

        match parts.as_slice() {
            ["exec", "cmd"] | ["exec", "shell"] => Some("execution/command/shell".to_string()),
            ["exec", "program"] => Some("execution/command/direct".to_string()),
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
            // Skip filtered matches
            if yara_match.severity == "filtered" {
                continue;
            }

            // Use derived trait_id for third-party rules, otherwise map namespace to capability
            let finding_id = yara_match
                .trait_id
                .clone()
                .or_else(|| self.namespace_to_capability(&yara_match.namespace));

            if let Some(cap_id) = finding_id {
                let evidence = self.yara_match_to_evidence(yara_match);

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
                    conf: 0.9,
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

        let cache_data = CacheData {
            builtin_count,
            third_party_count,
            rules_data: serialized,
            inline_namespaces: self.compiled_inline_namespaces.clone(),
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
        self.compiled_inline_namespaces = cache_data.inline_namespaces;
        Ok((cache_data.builtin_count, cache_data.third_party_count))
    }
}

/// Cache data structure
#[derive(serde::Serialize, serde::Deserialize)]
struct CacheData {
    builtin_count: usize,
    third_party_count: usize,
    rules_data: Vec<u8>,
    /// Inline YARA namespaces compiled from trait YAML files.
    /// Stored so the engine can split scan results correctly on cache load.
    #[serde(default)]
    inline_namespaces: Vec<String>,
}

impl Default for YaraEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl YaraEngine {
    /// Compile YARA rules from source text. For tests only.
    fn load_rule_source(&mut self, source: &str) -> Result<()> {
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(source.as_bytes()).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        self.rules = Some(compiler.build());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let mut engine = YaraEngine::new();
        engine.load_rule_source(rule).unwrap();

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

        let mut engine = YaraEngine::new();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"This does not contain the pattern";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_new() {
        let engine = YaraEngine::new();
        assert!(!engine.is_loaded());
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

        engine.load_rule_source(r#"rule test { strings: $a = "test" condition: $a }"#).unwrap();

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
    fn test_extract_namespace_with_prefix() {
        let engine = YaraEngine::new_with_mapper(CapabilityMapper::empty());
        let path = Path::new("/path/to/traits/execution/shell/test.yar");
        let namespace = engine.extract_namespace_with_prefix(path, "traits");
        assert_eq!(namespace, "traits.execution.shell");
    }

    #[test]
    fn test_extract_namespace_with_prefix_third_party() {
        let engine = YaraEngine::new_with_mapper(CapabilityMapper::empty());
        let path = Path::new("/path/to/third_party/malware/test.yar");
        let namespace = engine.extract_namespace_with_prefix(path, "third_party");
        assert_eq!(namespace, "third_party.malware");
    }

    #[test]
    fn test_extract_namespace_with_prefix_no_subdirs() {
        let engine = YaraEngine::new_with_mapper(CapabilityMapper::empty());
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

        let mut engine = YaraEngine::new();
        engine.load_rule_source(rule).unwrap();

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

        let mut engine = YaraEngine::new();
        engine.load_rule_source(rule).unwrap();

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
            trait_id: None,
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
            trait_id: None,
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

        let mut engine = YaraEngine::new();
        engine.load_rule_source(rule).unwrap();

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

        let mut engine = YaraEngine::new();
        engine.load_rule_source(rule).unwrap();

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

        let mut engine = YaraEngine::new();
        engine.load_rule_source(rule).unwrap();

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

        let mut engine = YaraEngine::new();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"TEST";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert!(matches[0].is_capability); // Inferred from ATT&CK presence
    }
}
