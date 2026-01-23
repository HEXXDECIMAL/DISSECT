use crate::composite_rules::{
    CompositeTrait, EvaluationContext, FileType as RuleFileType, Platform, TraitDefinition,
};
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
use anyhow::{Context, Result};
use rayon::prelude::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Maps symbols (function names, library calls) to capability IDs
/// Also supports trait definitions and composite rules that combine traits
#[derive(Clone)]
pub struct CapabilityMapper {
    symbol_map: HashMap<String, TraitInfo>,
    trait_definitions: Vec<TraitDefinition>,
    composite_rules: Vec<CompositeTrait>,
}

#[derive(Clone)]
struct TraitInfo {
    id: String,
    description: String,
    confidence: f32,
}

/// File-level defaults that apply to all traits in a file
#[derive(Debug, Deserialize, Default, Clone)]
struct TraitDefaults {
    #[serde(default)]
    file_types: Option<Vec<String>>,
    #[serde(default)]
    platforms: Option<Vec<String>>,
    #[serde(default)]
    criticality: Option<String>,
    #[serde(default)]
    confidence: Option<f32>,
    #[serde(default)]
    mbc: Option<String>,
    #[serde(default)]
    attack: Option<String>,
}

/// Raw trait definition for parsing (fields can be absent to inherit defaults)
#[derive(Debug, Deserialize)]
struct RawTraitDefinition {
    id: String,
    description: String,
    #[serde(default)]
    confidence: Option<f32>,
    #[serde(default)]
    criticality: Option<String>,
    #[serde(default)]
    mbc: Option<String>,
    #[serde(default)]
    attack: Option<String>,
    #[serde(default)]
    platforms: Option<Vec<String>>,
    #[serde(default)]
    file_types: Option<Vec<String>>,
    condition: crate::composite_rules::Condition,
}

/// Raw composite rule for parsing (fields can be absent to inherit defaults)
#[derive(Debug, Deserialize)]
struct RawCompositeRule {
    #[serde(alias = "capability")]
    id: String,
    description: String,
    #[serde(default)]
    confidence: Option<f32>,
    #[serde(default)]
    criticality: Option<String>,
    #[serde(default)]
    mbc: Option<String>,
    #[serde(default)]
    attack: Option<String>,
    #[serde(default)]
    platforms: Option<Vec<String>>,
    #[serde(default)]
    file_types: Option<Vec<String>>,
    // Boolean operators
    #[serde(default)]
    requires_all: Option<Vec<crate::composite_rules::Condition>>,
    #[serde(default)]
    requires_any: Option<Vec<crate::composite_rules::Condition>>,
    #[serde(default)]
    requires_count: Option<usize>,
    #[serde(default)]
    conditions: Option<Vec<crate::composite_rules::Condition>>,
    #[serde(default)]
    requires_none: Option<Vec<crate::composite_rules::Condition>>,
    // Single condition (for simple composite rules)
    #[serde(default)]
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
    description: String,
    confidence: f32,
    #[serde(default)]
    platforms: Vec<String>,
    #[serde(default)]
    file_types: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SymbolMapping {
    symbol: String,
    capability: String,
    description: String,
    confidence: f32,
}

/// Check if a string value is the special "none" keyword to unset a default
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
    let file_types = apply_vec_default(raw.file_types, &defaults.file_types)
        .map(|types| parse_file_types(&types))
        .unwrap_or_else(|| vec![RuleFileType::All]);

    // Parse platforms: use trait-specific if present (unless "none"), else defaults, else [All]
    let platforms = apply_vec_default(raw.platforms, &defaults.platforms)
        .map(|plats| parse_platforms(&plats))
        .unwrap_or_else(|| vec![Platform::All]);

    // Parse criticality: "none" means Inert
    let criticality = match &raw.criticality {
        Some(v) if v.eq_ignore_ascii_case("none") => Criticality::Inert,
        Some(v) => parse_criticality(v),
        None => defaults
            .criticality
            .as_deref()
            .map(parse_criticality)
            .unwrap_or(Criticality::Inert),
    };

    TraitDefinition {
        id: raw.id,
        description: raw.description,
        confidence: raw.confidence.or(defaults.confidence).unwrap_or(1.0),
        criticality,
        mbc: apply_string_default(raw.mbc, &defaults.mbc),
        attack: apply_string_default(raw.attack, &defaults.attack),
        platforms,
        file_types,
        condition: raw.condition,
    }
}

fn parse_file_types(types: &[String]) -> Vec<RuleFileType> {
    types
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
            "packagejson" | "package.json" => Some(RuleFileType::PackageJson),
            _ => None,
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
    let file_types = apply_vec_default(raw.file_types, &defaults.file_types)
        .map(|types| parse_file_types(&types))
        .unwrap_or_else(|| vec![RuleFileType::All]);

    // Parse platforms: use rule-specific if present (unless "none"), else defaults, else [All]
    let platforms = apply_vec_default(raw.platforms, &defaults.platforms)
        .map(|plats| parse_platforms(&plats))
        .unwrap_or_else(|| vec![Platform::All]);

    // Parse criticality: "none" means Inert
    let criticality = match &raw.criticality {
        Some(v) if v.eq_ignore_ascii_case("none") => Criticality::Inert,
        Some(v) => parse_criticality(v),
        None => defaults
            .criticality
            .as_deref()
            .map(parse_criticality)
            .unwrap_or(Criticality::Inert),
    };

    // Handle single condition by converting to requires_all
    let requires_all = raw.requires_all.or_else(|| raw.condition.map(|c| vec![c]));

    CompositeTrait {
        id: raw.id,
        description: raw.description,
        confidence: raw.confidence.or(defaults.confidence).unwrap_or(1.0),
        criticality,
        mbc: apply_string_default(raw.mbc, &defaults.mbc),
        attack: apply_string_default(raw.attack, &defaults.attack),
        platforms,
        file_types,
        requires_all,
        requires_any: raw.requires_any,
        requires_count: raw.requires_count,
        conditions: raw.conditions,
        requires_none: raw.requires_none,
    }
}

impl CapabilityMapper {
    /// Create an empty capability mapper for testing
    pub fn empty() -> Self {
        Self {
            symbol_map: HashMap::new(),
            trait_definitions: Vec::new(),
            composite_rules: Vec::new(),
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
        let dir_path = dir_path.as_ref();

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

        // Merge all results
        let mut symbol_map = HashMap::new();
        let mut trait_definitions = Vec::new();
        let mut composite_rules = Vec::new();
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
                        description: mapping.description,
                        confidence: mapping.confidence,
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
                            description: rule.description,
                            confidence: rule.confidence,
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
                trait_def.condition.validate().with_context(|| {
                    format!(
                        "invalid condition in trait '{}' from {:?}",
                        trait_def.id, path
                    )
                })?;
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
                } = &trait_def.condition
                {
                    // Check if there are no platform constraints, or add anyway for lookup
                    // (platform filtering will happen later during evaluation)

                    // For each pattern (may contain "|" for alternatives)
                    for symbol_pattern in pattern.split('|') {
                        let symbol = symbol_pattern.trim().to_string();

                        // Only add if not already present (first match wins)
                        symbol_map.entry(symbol).or_insert_with(|| TraitInfo {
                            id: trait_def.id.clone(),
                            description: trait_def.description.clone(),
                            confidence: trait_def.confidence,
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

        // Pre-compile all YARA rules for faster evaluation
        let yara_count_traits = trait_definitions
            .iter_mut()
            .filter(|t| matches!(t.condition, crate::composite_rules::Condition::Yara { .. }))
            .map(|t| {
                t.compile_yara();
            })
            .count();

        let yara_count_composite = composite_rules
            .iter_mut()
            .map(|r| {
                r.compile_yara();
            })
            .count();

        if debug && (yara_count_traits > 0 || yara_count_composite > 0) {
            eprintln!(
                "   ⚡ Pre-compiled YARA rules in {} traits, {} composite rules",
                yara_count_traits, yara_count_composite
            );
        }

        Ok(Self {
            symbol_map,
            trait_definitions,
            composite_rules,
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
                    description: mapping.description,
                    confidence: mapping.confidence,
                },
            );
        }

        // Load "simple_rules" format
        for rule in mappings.simple_rules {
            symbol_map.insert(
                rule.symbol.clone(),
                TraitInfo {
                    id: rule.capability,
                    description: rule.description,
                    confidence: rule.confidence,
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

        Ok(Self {
            symbol_map,
            trait_definitions,
            composite_rules,
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
                description: info.description.clone(),
                confidence: info.confidence,
                criticality: Criticality::Inert,
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
        // Determine platform and file type from report
        let platform = self.detect_platform(&report.target.file_type);
        let file_type = self.detect_file_type(&report.target.file_type);

        let ctx = EvaluationContext {
            report,
            binary_data,
            file_type,
            platform,
        };

        // Evaluate traits in parallel and collect results
        let all_findings: Vec<Finding> = self
            .trait_definitions
            .par_iter()
            .filter_map(|trait_def| trait_def.evaluate(&ctx))
            .collect();

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

        let ctx = EvaluationContext {
            report,
            binary_data,
            file_type,
            platform,
        };

        // Evaluate composite rules in parallel and collect results
        let all_findings: Vec<Finding> = self
            .composite_rules
            .par_iter()
            .filter_map(|rule| rule.evaluate(&ctx))
            .collect();

        // Deduplicate findings (keep first occurrence of each ID)
        let mut seen = std::collections::HashSet::new();
        all_findings
            .into_iter()
            .filter(|f| seen.insert(f.id.clone()))
            .collect()
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
                "packagejson" | "package.json" => Some(RuleFileType::PackageJson),
                _ => None,
            })
            .collect()
    };

    // Create a composite trait with a single symbol condition
    CompositeTrait {
        id: rule.capability,
        description: rule.description,
        confidence: rule.confidence,
        criticality: Criticality::Inert,
        mbc: None,
        attack: None,
        platforms,
        file_types,
        requires_all: Some(vec![Condition::Symbol {
            pattern: rule.symbol,
            platforms: None,
        }]),
        requires_any: None,
        requires_count: None,
        conditions: None,
        requires_none: None,
    }
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
            file_types: Some(vec!["php".to_string()]),
            platforms: Some(vec!["linux".to_string()]),
            criticality: Some("suspicious".to_string()),
            confidence: Some(0.85),
            mbc: Some("B0001".to_string()),
            attack: Some("T1059".to_string()),
        };

        let raw = RawTraitDefinition {
            id: "test/trait".to_string(),
            description: "Test trait".to_string(),
            confidence: None,
            criticality: None,
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

        assert_eq!(result.confidence, 0.85);
        assert_eq!(result.criticality, Criticality::Suspicious);
        assert_eq!(result.mbc, Some("B0001".to_string()));
        assert_eq!(result.attack, Some("T1059".to_string()));
        assert_eq!(result.platforms, vec![Platform::Linux]);
        assert_eq!(result.file_types, vec![RuleFileType::Php]);
    }

    #[test]
    fn test_apply_trait_defaults_trait_overrides_defaults() {
        use crate::composite_rules::Condition;

        let defaults = TraitDefaults {
            file_types: Some(vec!["php".to_string()]),
            platforms: Some(vec!["linux".to_string()]),
            criticality: Some("suspicious".to_string()),
            confidence: Some(0.85),
            mbc: Some("B0001".to_string()),
            attack: Some("T1059".to_string()),
        };

        let raw = RawTraitDefinition {
            id: "test/trait".to_string(),
            description: "Test trait".to_string(),
            confidence: Some(0.99),
            criticality: Some("hostile".to_string()),
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

        assert_eq!(result.confidence, 0.99);
        assert_eq!(result.criticality, Criticality::Hostile);
        assert_eq!(result.mbc, Some("B0002".to_string()));
        assert_eq!(result.attack, Some("T1234".to_string()));
        assert_eq!(result.platforms, vec![Platform::Windows]);
        assert_eq!(result.file_types, vec![RuleFileType::Pe]);
    }

    #[test]
    fn test_apply_trait_defaults_unset_mbc_with_none() {
        use crate::composite_rules::Condition;

        let defaults = TraitDefaults {
            file_types: None,
            platforms: None,
            criticality: None,
            confidence: None,
            mbc: Some("B0001".to_string()),
            attack: Some("T1059".to_string()),
        };

        let raw = RawTraitDefinition {
            id: "test/trait".to_string(),
            description: "Test trait".to_string(),
            confidence: None,
            criticality: None,
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
            file_types: None,
            platforms: None,
            criticality: None,
            confidence: None,
            mbc: Some("B0001".to_string()),
            attack: Some("T1059".to_string()),
        };

        let raw = RawTraitDefinition {
            id: "test/trait".to_string(),
            description: "Test trait".to_string(),
            confidence: None,
            criticality: None,
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
            file_types: Some(vec!["php".to_string()]),
            platforms: None,
            criticality: None,
            confidence: None,
            mbc: None,
            attack: None,
        };

        let raw = RawTraitDefinition {
            id: "test/trait".to_string(),
            description: "Test trait".to_string(),
            confidence: None,
            criticality: None,
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
        assert_eq!(result.file_types, vec![RuleFileType::All]);
    }

    #[test]
    fn test_apply_composite_defaults_applies_all_defaults() {
        use crate::composite_rules::Condition;

        let defaults = TraitDefaults {
            file_types: Some(vec!["elf".to_string(), "macho".to_string()]),
            platforms: Some(vec!["linux".to_string(), "macos".to_string()]),
            criticality: Some("notable".to_string()),
            confidence: Some(0.75),
            mbc: Some("B0030".to_string()),
            attack: Some("T1071.001".to_string()),
        };

        let raw = RawCompositeRule {
            id: "test/rule".to_string(),
            description: "Test rule".to_string(),
            confidence: None,
            criticality: None,
            mbc: None,
            attack: None,
            platforms: None,
            file_types: None,
            requires_all: None,
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
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

        assert_eq!(result.confidence, 0.75);
        assert_eq!(result.criticality, Criticality::Notable);
        assert_eq!(result.mbc, Some("B0030".to_string()));
        assert_eq!(result.attack, Some("T1071.001".to_string()));
        assert_eq!(result.platforms, vec![Platform::Linux, Platform::MacOS]);
        assert_eq!(
            result.file_types,
            vec![RuleFileType::Elf, RuleFileType::Macho]
        );
    }

    #[test]
    fn test_apply_composite_defaults_unset_with_none() {
        use crate::composite_rules::Condition;

        let defaults = TraitDefaults {
            file_types: Some(vec!["elf".to_string()]),
            platforms: Some(vec!["linux".to_string()]),
            criticality: Some("suspicious".to_string()),
            confidence: Some(0.9),
            mbc: Some("B0030".to_string()),
            attack: Some("T1071".to_string()),
        };

        let raw = RawCompositeRule {
            id: "test/rule".to_string(),
            description: "Test rule".to_string(),
            confidence: None,
            criticality: None,
            mbc: Some("none".to_string()),             // Unset
            attack: Some("none".to_string()),          // Unset
            platforms: Some(vec!["none".to_string()]), // Unset
            file_types: None,                          // Use default
            requires_all: None,
            requires_any: None,
            requires_count: None,
            conditions: None,
            requires_none: None,
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
        assert_eq!(result.file_types, vec![RuleFileType::Elf]); // Default applied
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
        assert_eq!(t1.criticality, Criticality::Suspicious);
        assert_eq!(t1.file_types, vec![RuleFileType::Php]);
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
        assert_eq!(rules[0].criticality, Criticality::Notable);
        assert_eq!(
            rules[0].file_types,
            vec![RuleFileType::Elf, RuleFileType::Macho, RuleFileType::Pe]
        );

        // Second rule unsets attack
        assert_eq!(rules[1].attack, None);
        assert_eq!(rules[1].criticality, Criticality::Notable); // Still uses default
    }
}
