use crate::composite_rules::{
    CompositeTrait, Condition, EvaluationContext, FileType as RuleFileType, Platform,
    TraitDefinition,
};
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
use aho_corasick::AhoCorasick;
use anyhow::{Context, Result};
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Index of trait indices by file type for fast lookup.
/// Maps FileType -> Vec of indices into trait_definitions.
#[derive(Clone, Default)]
struct TraitIndex {
    /// Traits that apply to each specific file type
    by_file_type: FxHashMap<RuleFileType, Vec<usize>>,
    /// Traits that apply to all file types (Platform::All)
    universal: Vec<usize>,
}

impl TraitIndex {
    fn new() -> Self {
        Self {
            by_file_type: FxHashMap::default(),
            universal: Vec::new(),
        }
    }

    /// Build index from trait definitions
    fn build(traits: &[TraitDefinition]) -> Self {
        let mut index = Self::new();

        for (i, trait_def) in traits.iter().enumerate() {
            let has_all = trait_def.r#for.contains(&RuleFileType::All);

            if has_all {
                // Trait applies to all file types
                index.universal.push(i);
            } else {
                // Trait applies to specific file types
                for ft in &trait_def.r#for {
                    index.by_file_type.entry(ft.clone()).or_default().push(i);
                }
            }
        }

        index
    }

    /// Get trait indices applicable to a given file type
    fn get_applicable(&self, file_type: &RuleFileType) -> impl Iterator<Item = usize> + '_ {
        // Universal traits + specific file type traits
        let specific = self
            .by_file_type
            .get(file_type)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);

        self.universal
            .iter()
            .copied()
            .chain(specific.iter().copied())
    }

    /// Get count of applicable traits for a file type
    #[allow(dead_code)]
    fn applicable_count(&self, file_type: &RuleFileType) -> usize {
        let specific_count = self
            .by_file_type
            .get(file_type)
            .map(|v: &Vec<usize>| v.len())
            .unwrap_or(0);
        self.universal.len() + specific_count
    }
}

/// Index for fast batched string matching using Aho-Corasick.
/// Pre-computes an automaton from all exact string patterns in traits,
/// enabling single-pass matching across thousands of patterns.
#[derive(Clone)]
struct StringMatchIndex {
    /// Aho-Corasick automaton for all exact string patterns (case-sensitive)
    automaton: Option<AhoCorasick>,
    /// Maps pattern index -> trait indices that use this pattern
    pattern_to_traits: Vec<Vec<usize>>,
    /// Total number of traits with exact string patterns
    total_patterns: usize,
}

impl Default for StringMatchIndex {
    fn default() -> Self {
        Self {
            automaton: None,
            pattern_to_traits: Vec::new(),
            total_patterns: 0,
        }
    }
}

impl StringMatchIndex {
    /// Build the string match index from trait definitions.
    /// Extracts all exact string patterns (case-sensitive only) and builds an AC automaton.
    fn build(traits: &[TraitDefinition]) -> Self {
        let mut patterns: Vec<String> = Vec::new();
        let mut pattern_to_traits: Vec<Vec<usize>> = Vec::new();
        let mut pattern_map: FxHashMap<String, usize> = FxHashMap::default();

        for (trait_idx, trait_def) in traits.iter().enumerate() {
            // Extract exact string pattern if present
            if let Condition::String {
                exact: Some(ref exact_str),
                case_insensitive: false,
                ..
            } = trait_def.r#if
            {
                // Check if we already have this pattern
                if let Some(&pattern_idx) = pattern_map.get(exact_str) {
                    pattern_to_traits[pattern_idx].push(trait_idx);
                } else {
                    // New pattern
                    let pattern_idx = patterns.len();
                    pattern_map.insert(exact_str.clone(), pattern_idx);
                    patterns.push(exact_str.clone());
                    pattern_to_traits.push(vec![trait_idx]);
                }
            }
        }

        let total_patterns = patterns.len();

        // Build Aho-Corasick automaton if we have patterns
        let automaton = if !patterns.is_empty() {
            AhoCorasick::builder()
                .ascii_case_insensitive(false)
                .build(&patterns)
                .ok()
        } else {
            None
        };

        Self {
            automaton,
            pattern_to_traits,
            total_patterns,
        }
    }

    /// Find all trait indices whose exact string patterns match in the given text.
    /// Returns a set of trait indices that could potentially match.
    fn find_matching_traits(&self, text: &str) -> FxHashSet<usize> {
        let mut matching_traits = FxHashSet::default();

        if let Some(ref ac) = self.automaton {
            for mat in ac.find_iter(text) {
                let pattern_idx = mat.pattern().as_usize();
                if let Some(trait_indices) = self.pattern_to_traits.get(pattern_idx) {
                    for &trait_idx in trait_indices {
                        matching_traits.insert(trait_idx);
                    }
                }
            }
        }

        matching_traits
    }

    /// Find matching traits in binary data (for extracted strings).
    fn find_matching_traits_in_strings<'a, I>(&self, strings: I) -> FxHashSet<usize>
    where
        I: Iterator<Item = &'a str>,
    {
        let mut matching_traits = FxHashSet::default();

        if let Some(ref ac) = self.automaton {
            for s in strings {
                for mat in ac.find_iter(s) {
                    let pattern_idx = mat.pattern().as_usize();
                    if let Some(trait_indices) = self.pattern_to_traits.get(pattern_idx) {
                        for &trait_idx in trait_indices {
                            matching_traits.insert(trait_idx);
                        }
                    }
                }
            }
        }

        matching_traits
    }

    /// Returns true if the index has patterns to match
    fn has_patterns(&self) -> bool {
        self.total_patterns > 0
    }
}

/// Maps symbols (function names, library calls) to capability IDs
/// Also supports trait definitions and composite rules that combine traits
#[derive(Clone)]
pub struct CapabilityMapper {
    symbol_map: HashMap<String, TraitInfo>,
    trait_definitions: Vec<TraitDefinition>,
    composite_rules: Vec<CompositeTrait>,
    /// Index for fast trait lookup by file type
    trait_index: TraitIndex,
    /// Index for fast batched string matching
    string_match_index: StringMatchIndex,
}

#[derive(Clone)]
struct TraitInfo {
    id: String,
    desc: String,
    conf: f32,
}

/// File-level defaults that apply to all traits in a file
#[derive(Debug, Deserialize, Default, Clone)]
struct TraitDefaults {
    #[serde(default, alias = "for", alias = "file_types")]
    r#for: Option<Vec<String>>,
    #[serde(default)]
    platforms: Option<Vec<String>>,
    #[serde(default, alias = "criticality")]
    crit: Option<String>,
    #[serde(default, alias = "confidence")]
    conf: Option<f32>,
    #[serde(default)]
    mbc: Option<String>,
    #[serde(default)]
    attack: Option<String>,
}

/// Raw trait definition for parsing (fields can be absent to inherit defaults)
#[derive(Debug, Deserialize)]
struct RawTraitDefinition {
    id: String,
    #[serde(alias = "description")]
    desc: String,
    #[serde(default, alias = "confidence")]
    conf: Option<f32>,
    #[serde(default, alias = "criticality")]
    crit: Option<String>,
    #[serde(default)]
    mbc: Option<String>,
    #[serde(default)]
    attack: Option<String>,
    #[serde(default)]
    platforms: Option<Vec<String>>,
    #[serde(default, alias = "for", alias = "files")]
    file_types: Option<Vec<String>>,
    #[serde(alias = "if")]
    condition: crate::composite_rules::Condition,
}

/// Raw composite rule for parsing (fields can be absent to inherit defaults)
#[derive(Debug, Deserialize)]
struct RawCompositeRule {
    #[serde(alias = "capability")]
    id: String,
    #[serde(alias = "description")]
    desc: String,
    #[serde(default, alias = "confidence")]
    conf: Option<f32>,
    #[serde(default, alias = "criticality")]
    crit: Option<String>,
    #[serde(default)]
    mbc: Option<String>,
    #[serde(default)]
    attack: Option<String>,
    #[serde(default)]
    platforms: Option<Vec<String>>,
    #[serde(default, alias = "for", alias = "files")]
    file_types: Option<Vec<String>>,
    // Boolean operators
    #[serde(default, alias = "requires_all")]
    all: Option<Vec<crate::composite_rules::Condition>>,
    #[serde(default, alias = "requires_any", alias = "conditions")]
    any: Option<Vec<crate::composite_rules::Condition>>,
    #[serde(default, alias = "requires_count")]
    count: Option<usize>,
    #[serde(default)]
    min_count: Option<usize>,
    #[serde(default)]
    max_count: Option<usize>,
    #[serde(default, alias = "requires_none")]
    none: Option<Vec<crate::composite_rules::Condition>>,
    // Single condition (for simple composite rules)
    #[serde(default, alias = "if")]
    condition: Option<crate::composite_rules::Condition>,
}

/// YAML file structure
#[derive(Debug, Deserialize)]
struct TraitMappings {
    #[serde(default)]
    defaults: TraitDefaults,

    #[serde(default)]
    symbols: Vec<SymbolMapping>,

    #[serde(default)]
    simple_rules: Vec<SimpleRule>,

    #[serde(default)]
    traits: Vec<RawTraitDefinition>,

    #[serde(default, alias = "capabilities")]
    composite_rules: Vec<RawCompositeRule>,
}

#[derive(Debug, Deserialize)]
struct SimpleRule {
    symbol: String,
    capability: String,
    #[serde(alias = "description")]
    desc: String,
    #[serde(alias = "confidence")]
    conf: f32,
    #[serde(default)]
    platforms: Vec<String>,
    #[serde(default, alias = "for")]
    file_types: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SymbolMapping {
    symbol: String,
    capability: String,
    #[serde(alias = "description")]
    desc: String,
    #[serde(alias = "confidence")]
    conf: f32,
}

/// Check if a string value is the special "none" keyword to unset a default
#[allow(dead_code)]
fn is_unset(value: &Option<String>) -> bool {
    value
        .as_ref()
        .map(|v| v.eq_ignore_ascii_case("none"))
        .unwrap_or(false)
}

/// Apply default for Option<String> fields, supporting "none" to unset
/// - If raw is Some("none"), return None (explicit unset)
/// - If raw is Some(value), return Some(value)
/// - If raw is None, return default
fn apply_string_default(raw: Option<String>, default: &Option<String>) -> Option<String> {
    match &raw {
        Some(v) if v.eq_ignore_ascii_case("none") => None,
        Some(_) => raw,
        None => default.clone(),
    }
}

/// Apply default for Vec<String> fields (file_types, platforms), supporting "none" to unset
/// - If raw contains "none", return empty/default behavior
/// - If raw is Some with values, use those
/// - If raw is None, use default
fn apply_vec_default(
    raw: Option<Vec<String>>,
    default: &Option<Vec<String>>,
) -> Option<Vec<String>> {
    match &raw {
        Some(v) if v.iter().any(|s| s.eq_ignore_ascii_case("none")) => None,
        Some(_) => raw,
        None => default.clone(),
    }
}

/// Convert a raw trait definition to a final TraitDefinition, applying file-level defaults
fn apply_trait_defaults(raw: RawTraitDefinition, defaults: &TraitDefaults) -> TraitDefinition {
    // Parse file_types: use trait-specific if present (unless "none"), else defaults, else [All]
    let file_types = apply_vec_default(raw.file_types, &defaults.r#for)
        .map(|types| parse_file_types(&types))
        .unwrap_or_else(|| vec![RuleFileType::All]);

    // Parse platforms: use trait-specific if present (unless "none"), else defaults, else [All]
    let platforms = apply_vec_default(raw.platforms, &defaults.platforms)
        .map(|plats| parse_platforms(&plats))
        .unwrap_or_else(|| vec![Platform::All]);

    // Parse criticality: "none" means Inert
    let mut criticality = match &raw.crit {
        Some(v) if v.eq_ignore_ascii_case("none") => Criticality::Inert,
        Some(v) => parse_criticality(v),
        None => defaults
            .crit
            .as_deref()
            .map(parse_criticality)
            .unwrap_or(Criticality::Inert),
    };

    // Stricter validation for HOSTILE traits: atomic traits cannot be HOSTILE
    if criticality == Criticality::Hostile {
        eprintln!(
            "⚠️  WARNING: Trait '{}' is atomic but marked HOSTILE. Downgrading to SUSPICIOUS.",
            raw.id
        );
        criticality = Criticality::Suspicious;
    }

    // Additional strictness for SUSPICIOUS/HOSTILE traits
    if criticality >= Criticality::Suspicious {
        if raw.desc.len() < 15 {
            eprintln!(
                "⚠️  WARNING: Trait '{}' has an overly short description for its criticality.",
                raw.id
            );
        }
    }

    TraitDefinition {
        id: raw.id,
        desc: raw.desc,
        conf: raw.conf.or(defaults.conf).unwrap_or(1.0),
        crit: criticality,
        mbc: apply_string_default(raw.mbc, &defaults.mbc),
        attack: apply_string_default(raw.attack, &defaults.attack),
        platforms,
        r#for: file_types,
        r#if: raw.condition,
    }
}

fn parse_file_types(types: &[String]) -> Vec<RuleFileType> {
    types
        .iter()
        .filter_map(|ft| {
            // Handle "*" separately (exact match), then lowercase for the rest
            if ft == "*" {
                return Some(RuleFileType::All);
            }
            match ft.to_lowercase().as_str() {
                "all" => Some(RuleFileType::All),
                "elf" => Some(RuleFileType::Elf),
                "macho" => Some(RuleFileType::Macho),
                "pe" => Some(RuleFileType::Pe),
                "dylib" => Some(RuleFileType::Dylib),
                "so" => Some(RuleFileType::So),
                "dll" => Some(RuleFileType::Dll),
                "shell" | "shellscript" => Some(RuleFileType::Shell),
                "batch" | "bat" | "cmd" => Some(RuleFileType::Batch),
                "python" => Some(RuleFileType::Python),
                "javascript" | "js" => Some(RuleFileType::JavaScript),
                "typescript" | "ts" => Some(RuleFileType::TypeScript),
                "java" => Some(RuleFileType::Java),
                "class" => Some(RuleFileType::Class),
                "c" => Some(RuleFileType::C),
                "rust" => Some(RuleFileType::Rust),
                "go" => Some(RuleFileType::Go),
                "ruby" => Some(RuleFileType::Ruby),
                "php" => Some(RuleFileType::Php),
                "csharp" | "cs" => Some(RuleFileType::CSharp),
                "packagejson" | "package.json" => Some(RuleFileType::PackageJson),
                _ => None,
            }
        })
        .collect()
}

fn parse_platforms(platforms: &[String]) -> Vec<Platform> {
    platforms
        .iter()
        .filter_map(|p| match p.to_lowercase().as_str() {
            "all" => Some(Platform::All),
            "linux" => Some(Platform::Linux),
            "macos" => Some(Platform::MacOS),
            "windows" => Some(Platform::Windows),
            "unix" => Some(Platform::Unix),
            "android" => Some(Platform::Android),
            "ios" => Some(Platform::Ios),
            _ => None,
        })
        .collect()
}

fn parse_criticality(s: &str) -> Criticality {
    match s.to_lowercase().as_str() {
        "inert" => Criticality::Inert,
        "notable" => Criticality::Notable,
        "suspicious" => Criticality::Suspicious,
        "hostile" | "malicious" => Criticality::Hostile,
        _ => Criticality::Inert,
    }
}

/// Convert a raw composite rule to a final CompositeTrait, applying file-level defaults
fn apply_composite_defaults(raw: RawCompositeRule, defaults: &TraitDefaults) -> CompositeTrait {
    // Parse file_types: use rule-specific if present (unless "none"), else defaults, else [All]
    let file_types = apply_vec_default(raw.file_types, &defaults.r#for)
        .map(|types| parse_file_types(&types))
        .unwrap_or_else(|| vec![RuleFileType::All]);

    // Parse platforms: use rule-specific if present (unless "none"), else defaults, else [All]
    let platforms = apply_vec_default(raw.platforms, &defaults.platforms)
        .map(|plats| parse_platforms(&plats))
        .unwrap_or_else(|| vec![Platform::All]);

    // Parse criticality: "none" means Inert
    let mut criticality = match &raw.crit {
        Some(v) if v.eq_ignore_ascii_case("none") => Criticality::Inert,
        Some(v) => parse_criticality(v),
        None => defaults
            .crit
            .as_deref()
            .map(parse_criticality)
            .unwrap_or(Criticality::Inert),
    };

    // Stricter validation for HOSTILE traits: composite traits must have at least 3 conditions and a file_type filter
    if criticality == Criticality::Hostile {
        let mut condition_count = 0;
        if let Some(ref c) = raw.all {
            condition_count += c.len();
        }
        if let Some(ref c) = raw.any {
            condition_count += c.len();
        }
        if let Some(ref c) = raw.any {
            condition_count += c.len();
        }
        if let Some(ref c) = raw.none {
            condition_count += c.len();
        }
        if raw.condition.is_some() {
            condition_count += 1;
        }

        let has_file_type_filter = !file_types.contains(&RuleFileType::All);

        if condition_count < 3 || !has_file_type_filter {
            eprintln!(
                "⚠️  WARNING: Composite trait '{}' is marked HOSTILE but does not meet strictness requirements. Downgrading to SUSPICIOUS.",
                raw.id
            );
            criticality = Criticality::Suspicious;
        }
    }

    // Additional strictness for SUSPICIOUS/HOSTILE composite rules
    if criticality >= Criticality::Suspicious {
        if raw.desc.len() < 15 {
            eprintln!(
                "⚠️  WARNING: Composite trait '{}' has an overly short description for its criticality.",
                raw.id
            );
        }
        if criticality >= Criticality::Hostile
            && raw.mbc.is_none()
            && raw.attack.is_none()
            && defaults.mbc.is_none()
            && defaults.attack.is_none()
        {
            eprintln!(
                "⚠️  WARNING: Composite trait '{}' is marked {:?} but lacks an MBC or MITRE ATT&CK mapping.",
                raw.id, criticality
            );
        }
    }

    // Handle single condition by converting to requires_all
    let requires_all = raw.all.or_else(|| raw.condition.map(|c| vec![c]));

    CompositeTrait {
        id: raw.id,
        desc: raw.desc,
        conf: raw.conf.or(defaults.conf).unwrap_or(1.0),
        crit: criticality,
        mbc: apply_string_default(raw.mbc, &defaults.mbc),
        attack: apply_string_default(raw.attack, &defaults.attack),
        platforms,
        r#for: file_types,
        all: requires_all,
        any: raw.any,
        count: raw.count,
        min_count: raw.min_count,
        max_count: raw.max_count,
        none: raw.none,
    }
}

impl CapabilityMapper {
    /// Create an empty capability mapper for testing
    pub fn empty() -> Self {
        Self {
            symbol_map: HashMap::new(),
            trait_definitions: Vec::new(),
            composite_rules: Vec::new(),
            trait_index: TraitIndex::new(),
            string_match_index: StringMatchIndex::default(),
        }
    }

    pub fn new() -> Self {
        let debug = std::env::var("DISSECT_DEBUG").is_ok();

        // Try to load from capabilities directory, fall back to single file
        // YAML parse errors or invalid trait configurations are fatal
        match Self::from_directory("traits") {
            Ok(mapper) => {
                eprintln!("✅ Loaded capabilities from traits/ directory");
                eprintln!("   {} symbol mappings", mapper.symbol_map.len());
                eprintln!("   {} trait definitions", mapper.trait_definitions.len());
                eprintln!("   {} composite rules", mapper.composite_rules.len());
                return mapper;
            }
            Err(e) => {
                // Check if this is a YAML parse error or invalid configuration
                // These are fatal and should exit immediately with clear error message
                let error_chain = format!("{:#}", e);
                if error_chain.contains("Failed to parse YAML")
                    || error_chain.contains("invalid condition")
                {
                    eprintln!("\n❌ FATAL: Invalid trait configuration file\n");
                    // Print the full error chain which includes file path and line info
                    for (i, cause) in e.chain().enumerate() {
                        if i == 0 {
                            eprintln!("   Error: {}", cause);
                        } else {
                            eprintln!("   Caused by: {}", cause);
                        }
                    }
                    eprintln!();
                    std::process::exit(1);
                }
                if debug {
                    eprintln!("⚠️  Failed to load from traits/ directory: {:#}", e);
                }
            }
        }

        match Self::from_yaml("capabilities.yaml") {
            Ok(mapper) => {
                eprintln!("✅ Loaded capabilities from capabilities.yaml");
                eprintln!("   {} symbol mappings", mapper.symbol_map.len());
                return mapper;
            }
            Err(e) => {
                // Check if this is a YAML parse error - fatal
                let error_chain = format!("{:#}", e);
                if error_chain.contains("Failed to parse") {
                    eprintln!("\n❌ FATAL: Invalid capabilities.yaml file\n");
                    for (i, cause) in e.chain().enumerate() {
                        if i == 0 {
                            eprintln!("   Error: {}", cause);
                        } else {
                            eprintln!("   Caused by: {}", cause);
                        }
                    }
                    eprintln!();
                    std::process::exit(1);
                }
                if debug {
                    eprintln!("⚠️  Failed to load from capabilities.yaml: {:#}", e);
                }
            }
        }

        eprintln!("❌ ERROR: Failed to load capabilities from any source");
        eprintln!("   Tried: traits/ directory, capabilities.yaml");
        eprintln!("   Set DISSECT_DEBUG=1 for detailed errors");
        eprintln!("   Creating empty capability mapper - NO DETECTIONS WILL WORK");

        Self::empty()
    }

    /// Load capability mappings from directory of YAML files (recursively)
    pub fn from_directory<P: AsRef<Path>>(dir_path: P) -> Result<Self> {
        let debug = std::env::var("DISSECT_DEBUG").is_ok();
        let timing = std::env::var("DISSECT_TIMING").is_ok();
        let dir_path = dir_path.as_ref();
        let t_start = std::time::Instant::now();

        if debug {
            eprintln!("🔍 Loading capabilities from: {}", dir_path.display());
        }

        // First, collect all YAML file paths
        let yaml_files: Vec<_> = walkdir::WalkDir::new(dir_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|entry| {
                let path = entry.path();
                if !path.is_file() || !path.extension().map(|e| e == "yaml").unwrap_or(false) {
                    return false;
                }
                let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
                !filename.to_lowercase().contains("readme") && !filename.starts_with("EXAMPLE")
            })
            .map(|entry| entry.path().to_path_buf())
            .collect();

        if yaml_files.is_empty() {
            anyhow::bail!("No YAML files found in {}", dir_path.display());
        }

        if timing {
            eprintln!(
                "[TIMING] Collected {} YAML files: {:?}",
                yaml_files.len(),
                t_start.elapsed()
            );
        }
        let t_parse = std::time::Instant::now();

        // Load all YAML files in parallel, preserving path for prefix calculation
        let results: Vec<_> = yaml_files
            .par_iter()
            .map(|path| {
                if debug {
                    eprintln!("   📄 Loading: {}", path.display());
                }

                let bytes = fs::read(path).with_context(|| format!("Failed to read {:?}", path))?;
                let content = String::from_utf8_lossy(&bytes);

                let mappings: TraitMappings = serde_yaml::from_str(&content)
                    .with_context(|| format!("Failed to parse YAML in {:?}", path))?;

                Ok::<_, anyhow::Error>((path.clone(), mappings))
            })
            .collect();

        if timing {
            eprintln!("[TIMING] Parsed YAML files: {:?}", t_parse.elapsed());
        }
        let t_merge = std::time::Instant::now();

        // Merge all results
        let mut symbol_map = HashMap::new();
        let mut trait_definitions = Vec::new();
        let mut composite_rules = Vec::new();
        let mut rule_source_files: HashMap<String, String> = HashMap::new(); // rule_id -> file_path
        let mut files_processed = 0;

        for result in results {
            let (path, mappings) = result?;
            files_processed += 1;

            // Calculate the prefix from the directory path relative to traits/
            // e.g., traits/credential/java/traits.yaml -> credential/java
            let trait_prefix = path
                .strip_prefix(dir_path)
                .ok()
                .and_then(|p| p.parent())
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .filter(|s| !s.is_empty());

            let before_symbols = symbol_map.len();
            let before_traits = trait_definitions.len();
            let before_composites = composite_rules.len();

            // Merge symbols
            for mapping in mappings.symbols {
                symbol_map.insert(
                    mapping.symbol.clone(),
                    TraitInfo {
                        id: mapping.capability,
                        desc: mapping.desc,
                        conf: mapping.conf,
                    },
                );
            }

            // Merge simple_rules
            for rule in mappings.simple_rules {
                // If rule has platform or file_type constraints, convert to composite rule
                if !rule.platforms.is_empty() || !rule.file_types.is_empty() {
                    let composite = simple_rule_to_composite_rule(rule);
                    composite_rules.push(composite);
                } else {
                    // No constraints - add to symbol map for fast lookup
                    symbol_map.insert(
                        rule.symbol.clone(),
                        TraitInfo {
                            id: rule.capability,
                            desc: rule.desc,
                            conf: rule.conf,
                        },
                    );
                }
            }

            // Merge trait definitions with auto-prefixed IDs, applying file-level defaults
            let traits_count = mappings.traits.len();
            for raw_trait in mappings.traits {
                // Convert raw trait to final trait, applying file-level defaults
                let mut trait_def = apply_trait_defaults(raw_trait, &mappings.defaults);

                // Auto-prefix trait ID if it doesn't already have the path prefix
                if let Some(ref prefix) = trait_prefix {
                    if !trait_def.id.starts_with(prefix) && !trait_def.id.contains('/') {
                        trait_def.id = format!("{}/{}", prefix, trait_def.id);
                    }
                }
                // Validate YARA/AST conditions at load time
                trait_def.r#if.validate().with_context(|| {
                    format!(
                        "invalid condition in trait '{}' from {:?}",
                        trait_def.id, path
                    )
                })?;
                // Warn about greedy regex patterns
                if let Some(warning) = trait_def.r#if.check_greedy_patterns() {
                    eprintln!(
                        "warning: trait '{}' in {:?}: {}",
                        trait_def.id, path, warning
                    );
                }
                trait_definitions.push(trait_def);
            }

            // Extract symbol mappings from trait definitions with symbol conditions
            for trait_def in
                &trait_definitions[trait_definitions.len().saturating_sub(traits_count)..]
            {
                // Check if this trait has a symbol condition
                if let crate::composite_rules::Condition::Symbol {
                    pattern,
                    platforms: _,
                } = &trait_def.r#if
                {
                    // Check if there are no platform constraints, or add anyway for lookup
                    // (platform filtering will happen later during evaluation)

                    // For each pattern (may contain "|" for alternatives)
                    for symbol_pattern in pattern.split('|') {
                        let symbol = symbol_pattern.trim().to_string();

                        // Only add if not already present (first match wins)
                        symbol_map.entry(symbol).or_insert_with(|| TraitInfo {
                            id: trait_def.id.clone(),
                            desc: trait_def.desc.clone(),
                            conf: trait_def.conf,
                        });
                    }
                }
            }

            // Merge composite_rules with auto-prefixed IDs, applying file-level defaults
            for raw_rule in mappings.composite_rules {
                // Convert raw rule to final rule, applying file-level defaults
                let mut rule = apply_composite_defaults(raw_rule, &mappings.defaults);

                // Auto-prefix composite rule ID if it doesn't already have the path prefix
                if let Some(ref prefix) = trait_prefix {
                    if !rule.id.starts_with(prefix) && !rule.id.contains('/') {
                        rule.id = format!("{}/{}", prefix, rule.id);
                    }
                }
                // Track source file for error reporting
                rule_source_files.insert(rule.id.clone(), path.display().to_string());
                composite_rules.push(rule);
            }

            if debug {
                eprintln!(
                    "      +{} symbols, +{} traits, +{} composite rules",
                    symbol_map.len() - before_symbols,
                    trait_definitions.len() - before_traits,
                    composite_rules.len() - before_composites
                );
            }
        }

        if debug {
            eprintln!("   ✅ Processed {} YAML files", files_processed);
        }

        if timing {
            eprintln!("[TIMING] Merged results: {:?}", t_merge.elapsed());
        }
        let t_yara = std::time::Instant::now();

        // Pre-compile all YARA rules for faster evaluation (parallelized)
        let yara_count_traits = trait_definitions
            .iter()
            .filter(|t| matches!(t.r#if, crate::composite_rules::Condition::Yara { .. }))
            .count();

        // Use rayon's par_iter_mut for parallel YARA compilation
        trait_definitions.par_iter_mut().for_each(|t| {
            if matches!(t.r#if, crate::composite_rules::Condition::Yara { .. }) {
                t.compile_yara();
            }
        });

        let yara_count_composite = composite_rules.len();
        composite_rules.par_iter_mut().for_each(|r| {
            r.compile_yara();
        });

        if debug && (yara_count_traits > 0 || yara_count_composite > 0) {
            eprintln!(
                "   ⚡ Pre-compiled YARA rules in {} traits, {} composite rules",
                yara_count_traits, yara_count_composite
            );
        }

        if timing {
            eprintln!("[TIMING] Pre-compiled YARA: {:?}", t_yara.elapsed());
        }
        let t_validate = std::time::Instant::now();

        // Validate trait references in composite rules
        // Cross-directory references (containing '/') must match an existing directory prefix
        // Include both trait definition prefixes AND composite rule prefixes (rules can reference rules)
        let mut known_prefixes: std::collections::HashSet<String> = trait_definitions
            .iter()
            .filter_map(|t| {
                // Extract the directory prefix from trait IDs (everything before the last '/')
                t.id.rfind('/').map(|idx| t.id[..idx].to_string())
            })
            .collect();

        // Also add composite rule prefixes (composite rules can reference other composite rules)
        for rule in &composite_rules {
            if let Some(idx) = rule.id.rfind('/') {
                known_prefixes.insert(rule.id[..idx].to_string());
            }
        }

        let mut invalid_refs = Vec::new();
        for rule in &composite_rules {
            let trait_refs = collect_trait_refs_from_rule(rule);
            for (ref_id, rule_id) in trait_refs {
                // Only validate cross-directory references (those with slashes)
                if ref_id.contains('/') {
                    // Check if this matches any known prefix
                    let matches_prefix = known_prefixes
                        .iter()
                        .any(|prefix| prefix.starts_with(&ref_id) || ref_id.starts_with(prefix));
                    if !matches_prefix {
                        let source_file = rule_source_files
                            .get(&rule_id)
                            .map(|s| s.as_str())
                            .unwrap_or("unknown");
                        invalid_refs.push((rule_id.clone(), ref_id, source_file.to_string()));
                    }
                }
            }
        }

        if !invalid_refs.is_empty() {
            eprintln!(
                "\n⚠️  WARNING: {} invalid trait references found in composite rules",
                invalid_refs.len()
            );
            if debug {
                for (rule_id, ref_id, source_file) in &invalid_refs {
                    // Try to find line number by searching the file
                    let line_hint = find_line_number(source_file, ref_id);
                    if let Some(line) = line_hint {
                        eprintln!(
                            "   {}:{}: Rule '{}' references unknown path: '{}'",
                            source_file, line, rule_id, ref_id
                        );
                    } else {
                        eprintln!(
                            "   {}: Rule '{}' references unknown path: '{}'",
                            source_file, rule_id, ref_id
                        );
                    }
                }
                eprintln!("\n   Cross-directory references must use directory paths (e.g., 'discovery/system')");
                eprintln!("   that match existing trait directories, not exact trait IDs.\n");
            } else {
                eprintln!("   Set DISSECT_DEBUG=1 to see details\n");
            }
        }

        // Validate that composite rules only contain trait references (not inline primitives)
        // Strict mode is the default - composite rules must only reference traits
        // Set DISSECT_ALLOW_INLINE_PRIMITIVES=1 to temporarily allow inline primitives
        let allow_inline = std::env::var("DISSECT_ALLOW_INLINE_PRIMITIVES").is_ok();
        if !allow_inline {
            let mut inline_errors = Vec::new();
            for rule in &composite_rules {
                let source = rule_source_files
                    .get(&rule.id)
                    .map(|s| s.as_str())
                    .unwrap_or("unknown");
                inline_errors.extend(validate_composite_trait_only(rule, source));
            }

            if !inline_errors.is_empty() {
                eprintln!(
                    "\n❌ FATAL: {} composite rules have inline primitives\n",
                    inline_errors.len()
                );
                for err in &inline_errors {
                    eprintln!("   {}", err);
                }
                eprintln!("\n   Composite rules must only reference traits (type: trait).");
                eprintln!(
                    "   Convert inline conditions (string, symbol, yara, etc.) to atomic traits."
                );
                eprintln!(
                    "   Set DISSECT_ALLOW_INLINE_PRIMITIVES=1 to temporarily bypass this check.\n"
                );
                std::process::exit(1);
            }
        }

        if timing {
            eprintln!("[TIMING] Validated refs: {:?}", t_validate.elapsed());
            eprintln!("[TIMING] Total from_directory: {:?}", t_start.elapsed());
        }

        // Build trait index for fast lookup by file type
        let trait_index = TraitIndex::build(&trait_definitions);

        // Build string match index for batched AC matching
        let t_string_index = std::time::Instant::now();
        let string_match_index = StringMatchIndex::build(&trait_definitions);
        if timing {
            eprintln!(
                "[TIMING] Built string index ({} patterns): {:?}",
                string_match_index.total_patterns,
                t_string_index.elapsed()
            );
        }

        Ok(Self {
            symbol_map,
            trait_definitions,
            composite_rules,
            trait_index,
            string_match_index,
        })
    }

    /// Load capability mappings from YAML file
    pub fn from_yaml<P: AsRef<Path>>(path: P) -> Result<Self> {
        let bytes = fs::read(path.as_ref()).context("Failed to read capabilities YAML file")?;
        let content = String::from_utf8_lossy(&bytes);

        let mappings: TraitMappings =
            serde_yaml::from_str(&content).context("Failed to parse capabilities YAML")?;

        let mut symbol_map = HashMap::new();

        // Load legacy "symbols" format
        for mapping in mappings.symbols {
            symbol_map.insert(
                mapping.symbol.clone(),
                TraitInfo {
                    id: mapping.capability,
                    desc: mapping.desc,
                    conf: mapping.conf,
                },
            );
        }

        // Load "simple_rules" format
        for rule in mappings.simple_rules {
            symbol_map.insert(
                rule.symbol.clone(),
                TraitInfo {
                    id: rule.capability,
                    desc: rule.desc,
                    conf: rule.conf,
                },
            );
        }

        // Convert raw traits to final traits with defaults applied
        let trait_definitions: Vec<TraitDefinition> = mappings
            .traits
            .into_iter()
            .map(|raw| apply_trait_defaults(raw, &mappings.defaults))
            .collect();

        // Convert raw composite rules to final rules with defaults applied
        let composite_rules: Vec<CompositeTrait> = mappings
            .composite_rules
            .into_iter()
            .map(|raw| apply_composite_defaults(raw, &mappings.defaults))
            .collect();

        // Build trait index for fast lookup by file type
        let trait_index = TraitIndex::build(&trait_definitions);

        // Build string match index for batched AC matching
        let string_match_index = StringMatchIndex::build(&trait_definitions);

        Ok(Self {
            symbol_map,
            trait_definitions,
            composite_rules,
            trait_index,
            string_match_index,
        })
    }

    /// Look up a symbol and return its capability finding if known
    pub fn lookup(&self, symbol: &str, source: &str) -> Option<Finding> {
        // Strip common prefixes for matching
        let clean_symbol = symbol
            .trim_start_matches('_') // C symbols often have leading underscore
            .trim_start_matches("__"); // Some have double underscore

        if let Some(info) = self.symbol_map.get(clean_symbol) {
            return Some(Finding {
                id: info.id.clone(),
                kind: FindingKind::Capability,
                desc: info.desc.clone(),
                conf: info.conf,
                crit: Criticality::Inert,
                mbc: None,
                attack: None,
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "symbol".to_string(),
                    source: source.to_string(),
                    value: symbol.to_string(),
                    location: None,
                }],
            });
        }

        None
    }

    /// Map YARA rule path to capability ID
    /// Example: "rules/exec/cmd/cmd.yara" → "exec/command/shell"
    pub fn yara_rule_to_capability(&self, rule_path: &str) -> Option<String> {
        // Extract the path components after "rules/"
        let path = rule_path.strip_prefix("rules/").unwrap_or(rule_path);

        // Map directory structure to capability IDs
        // This follows the malcontent rule structure
        let parts: Vec<&str> = path.split('/').collect();

        if parts.is_empty() {
            return None;
        }

        // Build capability ID from path components
        // Example: exec/cmd/cmd.yara → exec/command/shell
        match (parts.first(), parts.get(1)) {
            (Some(&"exec"), Some(&"cmd")) => Some("exec/command/shell".to_string()),
            (Some(&"exec"), Some(&"program")) => Some("exec/command/direct".to_string()),
            (Some(&"exec"), Some(&"shell")) => Some("exec/command/shell".to_string()),
            (Some(&"net"), Some(&"ftp")) => Some("net/ftp/client".to_string()),
            (Some(&"net"), Some(&"http")) => Some("net/http/client".to_string()),
            (Some(&"crypto"), sub) => Some(format!("crypto/{}", sub.unwrap_or(&"generic"))),
            (Some(&"anti-static"), Some(&"obfuscation")) => {
                // Get the specific obfuscation type
                if let Some(&obf_type) = parts.get(2) {
                    let type_clean = obf_type.trim_end_matches(".yara");
                    Some(format!("anti-analysis/obfuscation/{}", type_clean))
                } else {
                    Some("anti-analysis/obfuscation".to_string())
                }
            }
            (Some(&"fs"), sub) => Some(format!("fs/{}", sub.unwrap_or(&"generic"))),
            (Some(category), sub) => Some(format!("{}/{}", category, sub.unwrap_or(&"generic"))),
            _ => None,
        }
    }

    /// Get the number of loaded symbol mappings
    pub fn mapping_count(&self) -> usize {
        self.symbol_map.len()
    }

    /// Get the number of loaded composite rules
    pub fn composite_rules_count(&self) -> usize {
        self.composite_rules.len()
    }

    /// Get the number of loaded trait definitions
    pub fn trait_definitions_count(&self) -> usize {
        self.trait_definitions.len()
    }

    /// Evaluate trait definitions against an analysis report
    /// Returns findings detected from trait definitions
    pub fn evaluate_traits(&self, report: &AnalysisReport, binary_data: &[u8]) -> Vec<Finding> {
        let timing = std::env::var("DISSECT_TIMING").is_ok();

        // Determine platform and file type from report
        let platform = self.detect_platform(&report.target.file_type);
        let file_type = self.detect_file_type(&report.target.file_type);

        let ctx = EvaluationContext {
            report,
            binary_data,
            file_type: file_type.clone(),
            platform,
            additional_findings: None,
        };

        // Use trait index to only evaluate applicable traits
        // This dramatically reduces work for specific file types
        let applicable_indices: Vec<usize> = self.trait_index.get_applicable(&file_type).collect();

        // Pre-filter using batched Aho-Corasick string matching
        // This identifies which traits could possibly match based on their exact string patterns
        let t_prematch = std::time::Instant::now();
        let string_matched_traits: FxHashSet<usize> = if self.string_match_index.has_patterns() {
            // Search in extracted strings first
            let mut matched = self
                .string_match_index
                .find_matching_traits_in_strings(report.strings.iter().map(|s| s.value.as_str()));

            // Also search in raw binary data (for source files)
            if let Ok(content) = std::str::from_utf8(binary_data) {
                matched.extend(self.string_match_index.find_matching_traits(content));
            }

            matched
        } else {
            FxHashSet::default()
        };

        if timing {
            eprintln!(
                "[TIMING] String pre-match: {:?} ({} traits matched)",
                t_prematch.elapsed(),
                string_matched_traits.len()
            );
        }

        // Evaluate only applicable traits in parallel
        // Skip traits with exact string patterns that didn't match in pre-filter
        let t_eval = std::time::Instant::now();
        let all_findings: Vec<Finding> = applicable_indices
            .par_iter()
            .filter_map(|&idx| {
                // Check if this trait was excluded by string pre-filter
                // Traits with no exact string pattern (or with regex) are always evaluated
                let trait_def = &self.trait_definitions[idx];
                let has_exact_string = matches!(
                    trait_def.r#if,
                    Condition::String {
                        exact: Some(_),
                        case_insensitive: false,
                        ..
                    }
                );

                // If trait has an exact string pattern and it wasn't matched, skip it
                if has_exact_string && !string_matched_traits.contains(&idx) {
                    return None;
                }

                trait_def.evaluate(&ctx)
            })
            .collect();

        if timing {
            eprintln!("[TIMING] Trait evaluation: {:?}", t_eval.elapsed());
        }

        // Deduplicate findings (keep first occurrence of each ID)
        let mut seen = std::collections::HashSet::new();
        all_findings
            .into_iter()
            .filter(|f| seen.insert(f.id.clone()))
            .collect()
    }

    /// Evaluate composite rules against an analysis report
    /// Returns additional findings detected by composite rules
    pub fn evaluate_composite_rules(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
    ) -> Vec<Finding> {
        // Determine platform and file type from report
        let platform = self.detect_platform(&report.target.file_type);
        let file_type = self.detect_file_type(&report.target.file_type);

        // Iterative evaluation to support composite rules referencing other composites
        // On each iteration, newly matched composites become available for subsequent evaluations
        let mut all_findings: Vec<Finding> = Vec::new();
        let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

        // Track which composite IDs have already matched (including original findings)
        for finding in &report.findings {
            seen_ids.insert(finding.id.clone());
        }

        // Maximum iterations to prevent infinite loops (should converge quickly)
        const MAX_ITERATIONS: usize = 10;

        for _ in 0..MAX_ITERATIONS {
            let ctx = EvaluationContext {
                report,
                binary_data,
                file_type: file_type.clone(),
                platform: platform.clone(),
                additional_findings: if all_findings.is_empty() {
                    None
                } else {
                    Some(&all_findings)
                },
            };

            // Evaluate composite rules in parallel
            let new_findings: Vec<Finding> = self
                .composite_rules
                .par_iter()
                .filter_map(|rule| rule.evaluate(&ctx))
                .filter(|f| !seen_ids.contains(&f.id))
                .collect();

            if new_findings.is_empty() {
                // Fixed point reached - no new composites found
                break;
            }

            // Add new findings to the accumulated set
            for finding in new_findings {
                seen_ids.insert(finding.id.clone());
                all_findings.push(finding);
            }
        }

        all_findings
    }

    /// Detect platform from file type string
    fn detect_platform(&self, file_type: &str) -> Platform {
        match file_type.to_lowercase().as_str() {
            "elf" | "so" => Platform::Linux,
            "macho" | "dylib" => Platform::MacOS,
            "pe" | "dll" | "exe" => Platform::Windows,
            _ => Platform::All,
        }
    }

    /// Detect file type from file type string
    fn detect_file_type(&self, file_type: &str) -> RuleFileType {
        match file_type.to_lowercase().as_str() {
            "elf" => RuleFileType::Elf,
            "macho" => RuleFileType::Macho,
            "pe" | "exe" => RuleFileType::Pe,
            "dylib" => RuleFileType::Dylib,
            "so" => RuleFileType::So,
            "dll" => RuleFileType::Dll,
            "shell" | "shellscript" | "shell_script" => RuleFileType::Shell,
            "batch" | "bat" | "cmd" => RuleFileType::Batch,
            "python" | "python_script" => RuleFileType::Python,
            "javascript" | "js" => RuleFileType::JavaScript,
            "typescript" | "ts" => RuleFileType::TypeScript,
            "c" | "h" => RuleFileType::C,
            "rust" | "rs" => RuleFileType::Rust,
            "go" => RuleFileType::Go,
            "java" => RuleFileType::Java,
            "class" => RuleFileType::Class,
            "ruby" | "rb" => RuleFileType::Ruby,
            "php" => RuleFileType::Php,
            "csharp" | "cs" => RuleFileType::CSharp,
            "lua" => RuleFileType::Lua,
            "perl" | "pl" => RuleFileType::Perl,
            "powershell" | "ps1" => RuleFileType::PowerShell,
            "swift" => RuleFileType::Swift,
            "objectivec" | "objc" | "m" => RuleFileType::ObjectiveC,
            "groovy" | "gradle" => RuleFileType::Groovy,
            "scala" | "sc" => RuleFileType::Scala,
            "zig" => RuleFileType::Zig,
            "elixir" | "ex" | "exs" => RuleFileType::Elixir,
            "package.json" | "packagejson" => RuleFileType::PackageJson,
            "applescript" | "scpt" => RuleFileType::AppleScript,
            _ => RuleFileType::All,
        }
    }
}

/// Convert a simple rule with constraints into a composite rule
fn simple_rule_to_composite_rule(rule: SimpleRule) -> CompositeTrait {
    use crate::composite_rules::{Condition, FileType as RuleFileType, Platform};

    // Parse platforms
    let platforms = if rule.platforms.is_empty() {
        vec![Platform::All]
    } else {
        rule.platforms
            .iter()
            .filter_map(|p| match p.to_lowercase().as_str() {
                "all" => Some(Platform::All),
                "linux" => Some(Platform::Linux),
                "macos" => Some(Platform::MacOS),
                "windows" => Some(Platform::Windows),
                "unix" => Some(Platform::Unix),
                "android" => Some(Platform::Android),
                "ios" => Some(Platform::Ios),
                _ => None,
            })
            .collect()
    };

    // Parse file types
    let file_types = if rule.file_types.is_empty() {
        vec![RuleFileType::All]
    } else {
        rule.file_types
            .iter()
            .filter_map(|ft| match ft.to_lowercase().as_str() {
                "all" => Some(RuleFileType::All),
                "elf" => Some(RuleFileType::Elf),
                "macho" => Some(RuleFileType::Macho),
                "pe" => Some(RuleFileType::Pe),
                "dylib" => Some(RuleFileType::Dylib),
                "so" => Some(RuleFileType::So),
                "dll" => Some(RuleFileType::Dll),
                "shell" | "shellscript" => Some(RuleFileType::Shell),
                "batch" | "bat" | "cmd" => Some(RuleFileType::Batch),
                "python" => Some(RuleFileType::Python),
                "javascript" | "js" => Some(RuleFileType::JavaScript),
                "typescript" | "ts" => Some(RuleFileType::TypeScript),
                "java" => Some(RuleFileType::Java),
                "class" => Some(RuleFileType::Class),
                "c" => Some(RuleFileType::C),
                "rust" => Some(RuleFileType::Rust),
                "go" => Some(RuleFileType::Go),
                "ruby" => Some(RuleFileType::Ruby),
                "php" => Some(RuleFileType::Php),
                "csharp" | "cs" => Some(RuleFileType::CSharp),
                "lua" => Some(RuleFileType::Lua),
                "perl" | "pl" => Some(RuleFileType::Perl),
                "powershell" | "ps1" => Some(RuleFileType::PowerShell),
                "swift" => Some(RuleFileType::Swift),
                "objectivec" | "objc" | "m" => Some(RuleFileType::ObjectiveC),
                "groovy" | "gradle" => Some(RuleFileType::Groovy),
                "scala" | "sc" => Some(RuleFileType::Scala),
                "zig" => Some(RuleFileType::Zig),
                "elixir" | "ex" | "exs" => Some(RuleFileType::Elixir),
                "packagejson" | "package.json" => Some(RuleFileType::PackageJson),
                "applescript" | "scpt" => Some(RuleFileType::AppleScript),
                _ => None,
            })
            .collect()
    };

    // Create a composite trait with a single symbol condition
    CompositeTrait {
        id: rule.capability,
        desc: rule.desc,
        conf: rule.conf,
        crit: Criticality::Inert,
        mbc: None,
        attack: None,
        platforms,
        r#for: file_types,
        all: Some(vec![Condition::Symbol {
            pattern: rule.symbol,
            platforms: None,
        }]),
        any: None,
        count: None,
        min_count: None,
        max_count: None,
        none: None,
    }
}

/// Try to find the line number where a string appears in a file
fn find_line_number(file_path: &str, search_str: &str) -> Option<usize> {
    let content = std::fs::read_to_string(file_path).ok()?;
    for (line_num, line) in content.lines().enumerate() {
        if line.contains(search_str) {
            return Some(line_num + 1); // 1-indexed
        }
    }
    None
}

/// Validate that all conditions in a composite rule are trait references only.
/// Composite rules should combine traits, not contain inline primitives.
fn validate_composite_trait_only(rule: &CompositeTrait, source_file: &str) -> Vec<String> {
    use crate::composite_rules::Condition;

    let mut errors = Vec::new();

    fn check_conditions(
        conditions: &[Condition],
        rule_id: &str,
        field_name: &str,
        source_file: &str,
        errors: &mut Vec<String>,
    ) {
        for cond in conditions {
            if !cond.is_trait_reference() {
                errors.push(format!(
                    "{}: Composite rule '{}' has inline '{}' in {}. Convert to a trait.",
                    source_file,
                    rule_id,
                    cond.type_name(),
                    field_name
                ));
            }
        }
    }

    if let Some(ref c) = rule.all {
        check_conditions(c, &rule.id, "all", source_file, &mut errors);
    }
    if let Some(ref c) = rule.any {
        check_conditions(c, &rule.id, "any", source_file, &mut errors);
    }
    if let Some(ref c) = rule.none {
        check_conditions(c, &rule.id, "none", source_file, &mut errors);
    }

    errors
}

/// Collect all trait reference IDs from a composite rule's conditions
fn collect_trait_refs_from_rule(rule: &CompositeTrait) -> Vec<(String, String)> {
    use crate::composite_rules::Condition;

    let mut refs = Vec::new();

    fn collect_from_conditions(
        conditions: &[Condition],
        rule_id: &str,
        refs: &mut Vec<(String, String)>,
    ) {
        for cond in conditions {
            if let Condition::Trait { id } = cond {
                refs.push((id.clone(), rule_id.to_string()));
            }
        }
    }

    if let Some(ref conditions) = rule.all {
        collect_from_conditions(conditions, &rule.id, &mut refs);
    }
    if let Some(ref conditions) = rule.any {
        collect_from_conditions(conditions, &rule.id, &mut refs);
    }
    if let Some(ref conditions) = rule.none {
        collect_from_conditions(conditions, &rule.id, &mut refs);
    }

    refs
}

impl Default for CapabilityMapper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_mapper() {
        let mapper = CapabilityMapper::empty();

        // Should have no mappings
        assert_eq!(mapper.mapping_count(), 0);
        assert_eq!(mapper.trait_definitions.len(), 0);
        assert_eq!(mapper.composite_rules.len(), 0);

        // Lookup should return None
        assert!(mapper.lookup("socket", "test").is_none());
    }

    #[test]
    fn test_yaml_loading() {
        // Test loading from embedded capabilities
        let mapper = CapabilityMapper::new();

        // Should be able to create mapper (may or may not load mappings depending on environment)
        let count = mapper.mapping_count();
        println!("Loaded {} symbol mappings", count);
        // Test passes if mapper was created successfully
        let _ = count;
    }

    #[test]
    fn test_yara_rule_mapping() {
        let mapper = CapabilityMapper::new();

        assert_eq!(
            mapper.yara_rule_to_capability("rules/exec/cmd/cmd.yara"),
            Some("exec/command/shell".to_string())
        );

        assert_eq!(
            mapper.yara_rule_to_capability("rules/anti-static/obfuscation/bitwise.yara"),
            Some("anti-analysis/obfuscation/bitwise".to_string())
        );
    }

    #[test]
    fn test_mapping_count() {
        let mapper = CapabilityMapper::new();
        let count = mapper.mapping_count();

        // Mapper should be created successfully (count depends on environment)
        let _ = count;
    }

    #[test]
    fn test_lookup_nonexistent() {
        let mapper = CapabilityMapper::empty();
        let capability = mapper.lookup("nonexistent_func", "test");
        assert!(capability.is_none());
    }

    #[test]
    fn test_yara_rule_path_parsing() {
        let mapper = CapabilityMapper::new();

        // Test various path formats
        assert!(mapper
            .yara_rule_to_capability("rules/exec/shell.yara")
            .is_some());
    }

    #[test]
    fn test_empty_mapper_counts() {
        let mapper = CapabilityMapper::empty();
        assert_eq!(mapper.mapping_count(), 0);
        assert_eq!(mapper.composite_rules_count(), 0);
        assert_eq!(mapper.trait_definitions_count(), 0);
    }

    #[test]
    fn test_new_loads_symbols() {
        let mapper = CapabilityMapper::new();

        // Should create mapper successfully (loading depends on environment)
        let _ = mapper.mapping_count();
    }

    #[test]
    fn test_composite_rules_count() {
        let mapper = CapabilityMapper::new();
        let count = mapper.composite_rules_count();

        // May or may not have composite rules depending on traits/ directory
        let _ = count;
    }

    #[test]
    fn test_trait_definitions_count() {
        let mapper = CapabilityMapper::new();
        let count = mapper.trait_definitions_count();

        // May or may not have trait definitions depending on traits/ directory
        let _ = count;
    }

    // ==================== Defaults and Unset Tests ====================

    #[test]
    fn test_is_unset() {
        assert!(is_unset(&Some("none".to_string())));
        assert!(is_unset(&Some("NONE".to_string())));
        assert!(is_unset(&Some("None".to_string())));
        assert!(!is_unset(&Some("other".to_string())));
        assert!(!is_unset(&None));
    }

    #[test]
    fn test_apply_string_default_uses_default_when_raw_is_none() {
        let default = Some("T1234".to_string());
        let result = apply_string_default(None, &default);
        assert_eq!(result, Some("T1234".to_string()));
    }

    #[test]
    fn test_apply_string_default_uses_raw_when_present() {
        let default = Some("T1234".to_string());
        let result = apply_string_default(Some("T5678".to_string()), &default);
        assert_eq!(result, Some("T5678".to_string()));
    }

    #[test]
    fn test_apply_string_default_unset_with_none_keyword() {
        let default = Some("T1234".to_string());
        let result = apply_string_default(Some("none".to_string()), &default);
        assert_eq!(result, None);
    }

    #[test]
    fn test_apply_string_default_unset_case_insensitive() {
        let default = Some("T1234".to_string());
        assert_eq!(
            apply_string_default(Some("NONE".to_string()), &default),
            None
        );
        assert_eq!(
            apply_string_default(Some("None".to_string()), &default),
            None
        );
        assert_eq!(
            apply_string_default(Some("nOnE".to_string()), &default),
            None
        );
    }

    #[test]
    fn test_apply_string_default_no_default() {
        let result = apply_string_default(None, &None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_apply_vec_default_uses_default_when_raw_is_none() {
        let default = Some(vec!["elf".to_string(), "macho".to_string()]);
        let result = apply_vec_default(None, &default);
        assert_eq!(result, Some(vec!["elf".to_string(), "macho".to_string()]));
    }

    #[test]
    fn test_apply_vec_default_uses_raw_when_present() {
        let default = Some(vec!["elf".to_string()]);
        let result = apply_vec_default(Some(vec!["pe".to_string()]), &default);
        assert_eq!(result, Some(vec!["pe".to_string()]));
    }

    #[test]
    fn test_apply_vec_default_unset_with_none_keyword() {
        let default = Some(vec!["elf".to_string(), "macho".to_string()]);
        let result = apply_vec_default(Some(vec!["none".to_string()]), &default);
        assert_eq!(result, None);
    }

    #[test]
    fn test_apply_trait_defaults_applies_all_defaults() {
        use crate::composite_rules::Condition;

        let defaults = TraitDefaults {
            r#for: Some(vec!["php".to_string()]),
            platforms: Some(vec!["linux".to_string()]),
            crit: Some("suspicious".to_string()),
            conf: Some(0.85),
            mbc: Some("B0001".to_string()),
            attack: Some("T1059".to_string()),
        };

        let raw = RawTraitDefinition {
            id: "test/trait".to_string(),
            desc: "Test trait".to_string(),
            conf: None,
            crit: None,
            mbc: None,
            attack: None,
            platforms: None,
            file_types: None,
            condition: Condition::String {
                exact: Some("test".to_string()),
                regex: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            },
        };

        let result = apply_trait_defaults(raw, &defaults);

        assert_eq!(result.conf, 0.85);
        assert_eq!(result.crit, Criticality::Suspicious);
        assert_eq!(result.mbc, Some("B0001".to_string()));
        assert_eq!(result.attack, Some("T1059".to_string()));
        assert_eq!(result.platforms, vec![Platform::Linux]);
        assert_eq!(result.r#for, vec![RuleFileType::Php]);
    }

    #[test]
    fn test_apply_trait_defaults_trait_overrides_defaults() {
        use crate::composite_rules::Condition;

        let defaults = TraitDefaults {
            r#for: Some(vec!["php".to_string()]),
            platforms: Some(vec!["linux".to_string()]),
            crit: Some("suspicious".to_string()),
            conf: Some(0.85),
            mbc: Some("B0001".to_string()),
            attack: Some("T1059".to_string()),
        };

        let raw = RawTraitDefinition {
            id: "test/trait".to_string(),
            desc: "Test trait".to_string(),
            conf: Some(0.99),
            crit: Some("hostile".to_string()),
            mbc: Some("B0002".to_string()),
            attack: Some("T1234".to_string()),
            platforms: Some(vec!["windows".to_string()]),
            file_types: Some(vec!["pe".to_string()]),
            condition: Condition::String {
                exact: Some("test".to_string()),
                regex: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            },
        };

        let result = apply_trait_defaults(raw, &defaults);

        assert_eq!(result.conf, 0.99);
        // Atomic traits cannot be HOSTILE, so they get downgraded to SUSPICIOUS
        assert_eq!(result.crit, Criticality::Suspicious);
        assert_eq!(result.mbc, Some("B0002".to_string()));
        assert_eq!(result.attack, Some("T1234".to_string()));
        assert_eq!(result.platforms, vec![Platform::Windows]);
        assert_eq!(result.r#for, vec![RuleFileType::Pe]);
    }

    #[test]
    fn test_apply_trait_defaults_unset_mbc_with_none() {
        use crate::composite_rules::Condition;

        let defaults = TraitDefaults {
            r#for: None,
            platforms: None,
            crit: None,
            conf: None,
            mbc: Some("B0001".to_string()),
            attack: Some("T1059".to_string()),
        };

        let raw = RawTraitDefinition {
            id: "test/trait".to_string(),
            desc: "Test trait".to_string(),
            conf: None,
            crit: None,
            mbc: Some("none".to_string()), // Explicitly unset
            attack: None,                  // Use default
            platforms: None,
            file_types: None,
            condition: Condition::String {
                exact: Some("test".to_string()),
                regex: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            },
        };

        let result = apply_trait_defaults(raw, &defaults);

        assert_eq!(result.mbc, None); // Unset despite default
        assert_eq!(result.attack, Some("T1059".to_string())); // Default applied
    }

    #[test]
    fn test_apply_trait_defaults_unset_attack_with_none() {
        use crate::composite_rules::Condition;

        let defaults = TraitDefaults {
            r#for: None,
            platforms: None,
            crit: None,
            conf: None,
            mbc: Some("B0001".to_string()),
            attack: Some("T1059".to_string()),
        };

        let raw = RawTraitDefinition {
            id: "test/trait".to_string(),
            desc: "Test trait".to_string(),
            conf: None,
            crit: None,
            mbc: None,                        // Use default
            attack: Some("NONE".to_string()), // Explicitly unset (uppercase)
            platforms: None,
            file_types: None,
            condition: Condition::String {
                exact: Some("test".to_string()),
                regex: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            },
        };

        let result = apply_trait_defaults(raw, &defaults);

        assert_eq!(result.mbc, Some("B0001".to_string())); // Default applied
        assert_eq!(result.attack, None); // Unset despite default
    }

    #[test]
    fn test_apply_trait_defaults_unset_file_types_with_none() {
        use crate::composite_rules::Condition;

        let defaults = TraitDefaults {
            r#for: Some(vec!["php".to_string()]),
            platforms: None,
            crit: None,
            conf: None,
            mbc: None,
            attack: None,
        };

        let raw = RawTraitDefinition {
            id: "test/trait".to_string(),
            desc: "Test trait".to_string(),
            conf: None,
            crit: None,
            mbc: None,
            attack: None,
            platforms: None,
            file_types: Some(vec!["none".to_string()]), // Explicitly unset
            condition: Condition::String {
                exact: Some("test".to_string()),
                regex: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            },
        };

        let result = apply_trait_defaults(raw, &defaults);

        // When unset, file_types defaults to [All]
        assert_eq!(result.r#for, vec![RuleFileType::All]);
    }

    #[test]
    fn test_apply_composite_defaults_applies_all_defaults() {
        use crate::composite_rules::Condition;

        let defaults = TraitDefaults {
            r#for: Some(vec!["elf".to_string(), "macho".to_string()]),
            platforms: Some(vec!["linux".to_string(), "macos".to_string()]),
            crit: Some("notable".to_string()),
            conf: Some(0.75),
            mbc: Some("B0030".to_string()),
            attack: Some("T1071.001".to_string()),
        };

        let raw = RawCompositeRule {
            id: "test/rule".to_string(),
            desc: "Test rule".to_string(),
            conf: None,
            crit: None,
            mbc: None,
            attack: None,
            platforms: None,
            file_types: None,
            all: None,
            any: None,
            count: None,
            min_count: None,
            max_count: None,
            none: None,
            condition: Some(Condition::String {
                exact: Some("test".to_string()),
                regex: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            }),
        };

        let result = apply_composite_defaults(raw, &defaults);

        assert_eq!(result.conf, 0.75);
        assert_eq!(result.crit, Criticality::Notable);
        assert_eq!(result.mbc, Some("B0030".to_string()));
        assert_eq!(result.attack, Some("T1071.001".to_string()));
        assert_eq!(result.platforms, vec![Platform::Linux, Platform::MacOS]);
        assert_eq!(
            result.r#for,
            vec![RuleFileType::Elf, RuleFileType::Macho]
        );
    }

    #[test]
    fn test_apply_composite_defaults_unset_with_none() {
        use crate::composite_rules::Condition;

        let defaults = TraitDefaults {
            r#for: Some(vec!["elf".to_string()]),
            platforms: Some(vec!["linux".to_string()]),
            crit: Some("suspicious".to_string()),
            conf: Some(0.9),
            mbc: Some("B0030".to_string()),
            attack: Some("T1071".to_string()),
        };

        let raw = RawCompositeRule {
            id: "test/rule".to_string(),
            desc: "Test rule".to_string(),
            conf: None,
            crit: None,
            mbc: Some("none".to_string()),             // Unset
            attack: Some("none".to_string()),          // Unset
            platforms: Some(vec!["none".to_string()]), // Unset
            file_types: None,                          // Use default
            all: None,
            any: None,
            count: None,
            min_count: None,
            max_count: None,
            none: None,
            condition: Some(Condition::String {
                exact: Some("test".to_string()),
                regex: None,
                case_insensitive: false,
                exclude_patterns: None,
                min_count: 1,
                search_raw: false,
            }),
        };

        let result = apply_composite_defaults(raw, &defaults);

        assert_eq!(result.mbc, None);
        assert_eq!(result.attack, None);
        assert_eq!(result.platforms, vec![Platform::All]); // Fallback when unset
        assert_eq!(result.r#for, vec![RuleFileType::Elf]); // Default applied
    }

    #[test]
    fn test_yaml_with_defaults_and_unset() {
        let yaml = r#"
defaults:
  file_types: [php]
  mbc: "B0001"
  attack: "T1059"
  criticality: suspicious

traits:
  - id: test/uses-defaults
    description: "Uses all defaults"
    condition:
      type: string
      exact: "test1"

  - id: test/overrides-some
    description: "Overrides some defaults"
    mbc: "B0002"
    criticality: notable
    condition:
      type: string
      exact: "test2"

  - id: test/unsets-mbc
    description: "Unsets mbc"
    mbc: none
    condition:
      type: string
      exact: "test3"

  - id: test/unsets-attack
    description: "Unsets attack"
    attack: NONE
    condition:
      type: string
      exact: "test4"
"#;

        let mappings: TraitMappings = serde_yaml::from_str(yaml).expect("Failed to parse YAML");

        assert_eq!(mappings.traits.len(), 4);

        // Apply defaults and verify
        let t1 = apply_trait_defaults(
            mappings.traits.into_iter().next().unwrap(),
            &mappings.defaults,
        );
        assert_eq!(t1.mbc, Some("B0001".to_string()));
        assert_eq!(t1.attack, Some("T1059".to_string()));
        assert_eq!(t1.crit, Criticality::Suspicious);
        assert_eq!(t1.r#for, vec![RuleFileType::Php]);
    }

    #[test]
    fn test_yaml_composite_rules_with_defaults() {
        let yaml = r#"
defaults:
  file_types: [elf, macho, pe]
  attack: "T1071.001"
  criticality: notable

composite_rules:
  - id: test/uses-defaults
    description: "Uses all defaults"
    confidence: 0.5
    condition:
      type: string
      exact: "HTTP/1.1"

  - id: test/unsets-attack
    description: "Unsets attack"
    confidence: 0.6
    attack: none
    condition:
      type: string
      exact: "GET /"
"#;

        let mappings: TraitMappings = serde_yaml::from_str(yaml).expect("Failed to parse YAML");

        assert_eq!(mappings.composite_rules.len(), 2);

        let rules: Vec<_> = mappings
            .composite_rules
            .into_iter()
            .map(|r| apply_composite_defaults(r, &mappings.defaults))
            .collect();

        // First rule uses defaults
        assert_eq!(rules[0].attack, Some("T1071.001".to_string()));
        assert_eq!(rules[0].crit, Criticality::Notable);
        assert_eq!(
            rules[0].r#for,
            vec![RuleFileType::Elf, RuleFileType::Macho, RuleFileType::Pe]
        );

        // Second rule unsets attack
        assert_eq!(rules[1].attack, None);
        assert_eq!(rules[1].crit, Criticality::Notable); // Still uses default
    }

    // ==================== Iterative Composite Evaluation Tests ====================

    use crate::composite_rules::Condition;
    use crate::types::{AnalysisReport, Finding, FindingKind, TargetInfo};

    /// Helper to create a minimal analysis report for testing
    fn test_report_with_findings(findings: Vec<Finding>) -> AnalysisReport {
        let mut report = AnalysisReport::new(TargetInfo {
            path: "/test/file".to_string(),
            file_type: "elf".to_string(),
            size_bytes: 1000,
            sha256: "abc123".to_string(),
            architectures: None,
        });
        report.findings = findings;
        report
    }

    /// Helper to create a test finding
    fn test_finding(id: &str) -> Finding {
        Finding {
            id: id.to_string(),
            kind: FindingKind::Capability,
            desc: format!("Test finding {}", id),
            conf: 0.9,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![],
        }
    }

    #[test]
    fn test_iterative_eval_single_pass() {
        // Test that simple composites work in a single pass
        let mapper = CapabilityMapper::empty();
        let report = test_report_with_findings(vec![test_finding("atomic/trait-a")]);
        let findings = mapper.evaluate_composite_rules(&report, &[]);
        assert!(findings.is_empty()); // Empty mapper returns no findings
    }

    #[test]
    fn test_iterative_eval_max_iterations_protection() {
        // Test that MAX_ITERATIONS limit prevents infinite loops
        let report = test_report_with_findings(vec![]);
        let mapper = CapabilityMapper::empty();

        let start = std::time::Instant::now();
        let _ = mapper.evaluate_composite_rules(&report, &[]);
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_secs() < 1,
            "Evaluation took too long: {:?}",
            elapsed
        );
    }

    #[test]
    fn test_composite_referencing_atomic_trait() {
        use crate::composite_rules::CompositeTrait;

        let composite = CompositeTrait {
            id: "test/composite".to_string(),
            desc: "Test composite".to_string(),
            conf: 0.9,
            crit: Criticality::Suspicious,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            all: Some(vec![Condition::Trait {
                id: "test/atomic-trait".to_string(),
            }]),
            any: None,
            count: None,
            min_count: None,
            max_count: None,
            none: None,
        };

        let report = test_report_with_findings(vec![test_finding("test/atomic-trait")]);
        let mut mapper = CapabilityMapper::empty();
        mapper.composite_rules.push(composite);

        let findings = mapper.evaluate_composite_rules(&report, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "test/composite");
    }

    #[test]
    fn test_composite_of_composites_two_levels() {
        // Level 1: atomic-trait -> Level 2: composite-a -> Level 3: composite-b
        use crate::composite_rules::CompositeTrait;

        let composite_a = CompositeTrait {
            id: "test/composite-a".to_string(),
            desc: "First level".to_string(),
            conf: 0.9,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            all: Some(vec![Condition::Trait {
                id: "test/atomic-trait".to_string(),
            }]),
            any: None,
            count: None,
            min_count: None,
            max_count: None,
            none: None,
        };

        let composite_b = CompositeTrait {
            id: "test/composite-b".to_string(),
            desc: "Second level".to_string(),
            conf: 0.95,
            crit: Criticality::Suspicious,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            all: Some(vec![Condition::Trait {
                id: "test/composite-a".to_string(),
            }]),
            any: None,
            count: None,
            min_count: None,
            max_count: None,
            none: None,
        };

        let report = test_report_with_findings(vec![test_finding("test/atomic-trait")]);
        let mut mapper = CapabilityMapper::empty();
        mapper.composite_rules.push(composite_a);
        mapper.composite_rules.push(composite_b);

        let findings = mapper.evaluate_composite_rules(&report, &[]);

        // Both composites should be found due to iterative evaluation
        assert_eq!(findings.len(), 2);
        let ids: Vec<_> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"test/composite-a"), "Missing composite-a");
        assert!(ids.contains(&"test/composite-b"), "Missing composite-b");
    }

    #[test]
    fn test_composite_three_level_chain() {
        // Test 3-level chain: atomic -> A -> B -> C
        use crate::composite_rules::CompositeTrait;

        let make_composite = |id: &str, requires: &str| CompositeTrait {
            id: id.to_string(),
            desc: format!("Composite {}", id),
            conf: 0.9,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            all: Some(vec![Condition::Trait {
                id: requires.to_string(),
            }]),
            any: None,
            count: None,
            min_count: None,
            max_count: None,
            none: None,
        };

        let report = test_report_with_findings(vec![test_finding("level/zero")]);
        let mut mapper = CapabilityMapper::empty();
        mapper
            .composite_rules
            .push(make_composite("level/one", "level/zero"));
        mapper
            .composite_rules
            .push(make_composite("level/two", "level/one"));
        mapper
            .composite_rules
            .push(make_composite("level/three", "level/two"));

        let findings = mapper.evaluate_composite_rules(&report, &[]);

        assert_eq!(findings.len(), 3);
        let ids: Vec<_> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"level/one"));
        assert!(ids.contains(&"level/two"));
        assert!(ids.contains(&"level/three"));
    }

    #[test]
    fn test_composite_circular_dependency_handled() {
        // Test that circular dependencies don't cause infinite loops
        use crate::composite_rules::CompositeTrait;

        let composite_a = CompositeTrait {
            id: "circular/a".to_string(),
            desc: "Circular A".to_string(),
            conf: 0.9,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            all: Some(vec![Condition::Trait {
                id: "circular/b".to_string(),
            }]),
            any: None,
            count: None,
            min_count: None,
            max_count: None,
            none: None,
        };

        let composite_b = CompositeTrait {
            id: "circular/b".to_string(),
            desc: "Circular B".to_string(),
            conf: 0.9,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            all: Some(vec![Condition::Trait {
                id: "circular/a".to_string(),
            }]),
            any: None,
            count: None,
            min_count: None,
            max_count: None,
            none: None,
        };

        let report = test_report_with_findings(vec![]);
        let mut mapper = CapabilityMapper::empty();
        mapper.composite_rules.push(composite_a);
        mapper.composite_rules.push(composite_b);

        let start = std::time::Instant::now();
        let findings = mapper.evaluate_composite_rules(&report, &[]);
        let elapsed = start.elapsed();

        assert!(elapsed.as_millis() < 100, "Took too long: {:?}", elapsed);
        assert!(findings.is_empty(), "Circular deps shouldn't match");
    }

    #[test]
    fn test_composite_prefix_matching_in_chain() {
        // Test prefix matching works in composite chains
        use crate::composite_rules::CompositeTrait;

        let composite = CompositeTrait {
            id: "test/uses-discovery".to_string(),
            desc: "Uses discovery".to_string(),
            conf: 0.9,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            all: Some(vec![Condition::Trait {
                id: "discovery/system".to_string(), // Prefix match
            }]),
            any: None,
            count: None,
            min_count: None,
            max_count: None,
            none: None,
        };

        // Report has specific trait under discovery/system/
        let report = test_report_with_findings(vec![test_finding("discovery/system/hostname")]);
        let mut mapper = CapabilityMapper::empty();
        mapper.composite_rules.push(composite);

        let findings = mapper.evaluate_composite_rules(&report, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "test/uses-discovery");
    }

    #[test]
    fn test_composite_requires_count_in_chain() {
        use crate::composite_rules::CompositeTrait;

        let composite = CompositeTrait {
            id: "test/needs-two".to_string(),
            desc: "Needs 2 of 3".to_string(),
            conf: 0.9,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            all: None,
            any: Some(vec![
                Condition::Trait {
                    id: "feat/a".to_string(),
                },
                Condition::Trait {
                    id: "feat/b".to_string(),
                },
                Condition::Trait {
                    id: "feat/c".to_string(),
                },
            ]),
            count: Some(2),
            min_count: None,
            max_count: None,
            none: None,
        };

        let report =
            test_report_with_findings(vec![test_finding("feat/a"), test_finding("feat/c")]);
        let mut mapper = CapabilityMapper::empty();
        mapper.composite_rules.push(composite);

        let findings = mapper.evaluate_composite_rules(&report, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "test/needs-two");
    }
}
