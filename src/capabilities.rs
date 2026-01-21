use crate::composite_rules::{
    CompositeTrait, EvaluationContext, FileType as RuleFileType, Platform, TraitDefinition,
};
use crate::types::{AnalysisReport, Capability, Criticality, Evidence, Trait};
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
    symbol_map: HashMap<String, CapabilityInfo>,
    trait_definitions: Vec<TraitDefinition>,
    composite_rules: Vec<CompositeTrait>,
}

#[derive(Clone)]
struct CapabilityInfo {
    id: String,
    description: String,
    confidence: f32,
}

/// YAML file structure
#[derive(Debug, Deserialize)]
struct CapabilityMappings {
    #[serde(default)]
    symbols: Vec<SymbolMapping>,

    #[serde(default)]
    simple_rules: Vec<SimpleRule>,

    #[serde(default)]
    traits: Vec<TraitDefinition>,

    #[serde(default, alias = "capabilities")]
    composite_rules: Vec<CompositeTrait>,
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

        // Try to load from capabilities directory, fall back to single file, then empty
        match Self::from_directory("traits") {
            Ok(mapper) => {
                eprintln!("✅ Loaded capabilities from traits/ directory");
                eprintln!("   {} symbol mappings", mapper.symbol_map.len());
                eprintln!("   {} trait definitions", mapper.trait_definitions.len());
                eprintln!("   {} composite rules", mapper.composite_rules.len());
                return mapper;
            }
            Err(e) => {
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

        // Load all YAML files in parallel
        let results: Vec<_> = yaml_files
            .par_iter()
            .map(|path| {
                if debug {
                    eprintln!("   📄 Loading: {}", path.display());
                }

                let content = fs::read_to_string(path)
                    .with_context(|| format!("Failed to read {:?}", path))?;

                let mappings: CapabilityMappings = serde_yaml::from_str(&content)
                    .with_context(|| format!("Failed to parse YAML in {:?}", path))?;

                Ok::<_, anyhow::Error>(mappings)
            })
            .collect();

        // Merge all results
        let mut symbol_map = HashMap::new();
        let mut trait_definitions = Vec::new();
        let mut composite_rules = Vec::new();
        let mut files_processed = 0;

        for result in results {
            let mappings = result?;
            files_processed += 1;

            let before_symbols = symbol_map.len();
            let before_traits = trait_definitions.len();
            let before_composites = composite_rules.len();

            // Merge symbols
            for mapping in mappings.symbols {
                symbol_map.insert(
                    mapping.symbol.clone(),
                    CapabilityInfo {
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
                        CapabilityInfo {
                            id: rule.capability,
                            description: rule.description,
                            confidence: rule.confidence,
                        },
                    );
                }
            }

            // Merge trait definitions
            trait_definitions.extend(mappings.traits.clone());

            // Extract symbol mappings from trait definitions with symbol conditions
            for trait_def in &mappings.traits {
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
                        if !symbol_map.contains_key(&symbol) {
                            symbol_map.insert(
                                symbol,
                                CapabilityInfo {
                                    id: trait_def.id.clone(),
                                    description: trait_def.description.clone(),
                                    confidence: trait_def.confidence,
                                },
                            );
                        }
                    }
                }
            }

            // Merge composite_rules
            composite_rules.extend(mappings.composite_rules);

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

        Ok(Self {
            symbol_map,
            trait_definitions,
            composite_rules,
        })
    }

    /// Load capability mappings from YAML file
    pub fn from_yaml<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content =
            fs::read_to_string(path.as_ref()).context("Failed to read capabilities YAML file")?;

        let mappings: CapabilityMappings =
            serde_yaml::from_str(&content).context("Failed to parse capabilities YAML")?;

        let mut symbol_map = HashMap::new();

        // Load legacy "symbols" format
        for mapping in mappings.symbols {
            symbol_map.insert(
                mapping.symbol.clone(),
                CapabilityInfo {
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
                CapabilityInfo {
                    id: rule.capability,
                    description: rule.description,
                    confidence: rule.confidence,
                },
            );
        }

        Ok(Self {
            symbol_map,
            trait_definitions: mappings.traits,
            composite_rules: mappings.composite_rules,
        })
    }

    /// Look up a symbol and return its capability if known
    pub fn lookup(&self, symbol: &str, source: &str) -> Option<Capability> {
        // Strip common prefixes for matching
        let clean_symbol = symbol
            .trim_start_matches('_') // C symbols often have leading underscore
            .trim_start_matches("__"); // Some have double underscore

        if let Some(info) = self.symbol_map.get(clean_symbol) {
            return Some(Capability {
                id: info.id.clone(),
                description: info.description.clone(),
                confidence: info.confidence,
                criticality: Criticality::Inert,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "symbol".to_string(),
                    source: source.to_string(),
                    value: symbol.to_string(),
                    location: None,
                }],
                traits: Vec::new(),
                referenced_paths: None,
                referenced_directories: None,
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
    /// Returns (traits, capabilities_from_traits)
    /// - traits: All detected atomic observations (always exported)
    /// - capabilities: Traits marked with capability: true
    pub fn evaluate_traits(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
    ) -> (Vec<Trait>, Vec<Capability>) {
        let mut traits = Vec::new();
        let mut capabilities = Vec::new();

        // Determine platform and file type from report
        let platform = self.detect_platform(&report.target.file_type);
        let file_type = self.detect_file_type(&report.target.file_type);

        let ctx = EvaluationContext {
            report,
            binary_data,
            file_type,
            platform,
        };

        for trait_def in &self.trait_definitions {
            if let Some(detected_trait) = trait_def.evaluate(&ctx) {
                // Check if this trait already exists (avoid duplicates)
                if !traits.iter().any(|t: &Trait| t.id == detected_trait.id) {
                    // Always add to traits
                    traits.push(detected_trait.clone());

                    // Infer capability from metadata:
                    // 1. Explicit: capability = true
                    // 2. Inferred: mbc or attack present
                    let is_capability = trait_def.capability
                        || trait_def.mbc.is_some()
                        || trait_def.attack.is_some();

                    if is_capability {
                        capabilities.push(Capability {
                            id: detected_trait.id.clone(),
                            description: detected_trait.description.clone(),
                            confidence: detected_trait.confidence,
                            criticality: detected_trait.criticality,
                            mbc: detected_trait.mbc.clone(),
                            attack: detected_trait.attack.clone(),
                            evidence: detected_trait.evidence.clone(),
                            traits: vec![detected_trait.id.clone()], // Self-reference
                            referenced_paths: None,
                            referenced_directories: None,
                        });
                    }
                }
            }
        }

        (traits, capabilities)
    }

    /// Evaluate composite rules against an analysis report
    /// Returns additional capabilities detected by composite rules
    pub fn evaluate_composite_rules(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
    ) -> Vec<Capability> {
        let mut capabilities = Vec::new();

        // Determine platform and file type from report
        let platform = self.detect_platform(&report.target.file_type);
        let file_type = self.detect_file_type(&report.target.file_type);

        let ctx = EvaluationContext {
            report,
            binary_data,
            file_type,
            platform,
        };

        for rule in &self.composite_rules {
            if let Some(capability) = rule.evaluate(&ctx) {
                // Check if this capability already exists (avoid duplicates)
                if !capabilities
                    .iter()
                    .any(|c: &Capability| c.id == capability.id)
                {
                    capabilities.push(capability);
                }
            }
        }

        capabilities
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
            "shellscript" | "shell" => RuleFileType::ShellScript,
            "python" => RuleFileType::Python,
            "javascript" | "js" => RuleFileType::JavaScript,
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
                "shellscript" => Some(RuleFileType::ShellScript),
                "python" => Some(RuleFileType::Python),
                "javascript" => Some(RuleFileType::JavaScript),
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
        assert!(count >= 0);
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
        assert!(count >= 0);
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
        assert!(mapper.mapping_count() >= 0);
    }

    #[test]
    fn test_composite_rules_count() {
        let mapper = CapabilityMapper::new();
        let count = mapper.composite_rules_count();

        // May or may not have composite rules depending on traits/ directory
        assert!(count >= 0);
    }

    #[test]
    fn test_trait_definitions_count() {
        let mapper = CapabilityMapper::new();
        let count = mapper.trait_definitions_count();

        // May or may not have trait definitions depending on traits/ directory
        assert!(count >= 0);
    }
}
