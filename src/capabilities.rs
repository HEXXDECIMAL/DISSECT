use crate::types::{Capability, Evidence};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Maps symbols (function names, library calls) to capability IDs
pub struct CapabilityMapper {
    symbol_map: HashMap<String, CapabilityInfo>,
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
    symbols: Vec<SymbolMapping>,
}

#[derive(Debug, Deserialize)]
struct SymbolMapping {
    symbol: String,
    capability: String,
    description: String,
    confidence: f32,
}

impl CapabilityMapper {
    pub fn new() -> Self {
        // Try to load from YAML, fall back to empty if not found
        Self::from_yaml("capabilities.yaml").unwrap_or_else(|e| {
            eprintln!("Warning: Failed to load capabilities.yaml: {}", e);
            eprintln!("Creating empty capability mapper");
            Self {
                symbol_map: HashMap::new(),
            }
        })
    }

    /// Load capability mappings from YAML file
    pub fn from_yaml<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .context("Failed to read capabilities YAML file")?;

        let mappings: CapabilityMappings = serde_yaml::from_str(&content)
            .context("Failed to parse capabilities YAML")?;

        let mut symbol_map = HashMap::new();
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

        Ok(Self { symbol_map })
    }

    /// Look up a symbol and return its capability if known
    pub fn lookup(&self, symbol: &str, source: &str) -> Option<Capability> {
        // Strip common prefixes for matching
        let clean_symbol = symbol
            .trim_start_matches('_')  // C symbols often have leading underscore
            .trim_start_matches("__"); // Some have double underscore

        if let Some(info) = self.symbol_map.get(clean_symbol) {
            return Some(Capability {
                id: info.id.clone(),
                description: info.description.clone(),
                confidence: info.confidence,
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
    fn test_yaml_loading() {
        // Test loading from the YAML file
        let mapper = CapabilityMapper::from_yaml("capabilities.yaml");

        // Should successfully load
        assert!(mapper.is_ok());

        let mapper = mapper.unwrap();

        // Should have loaded many mappings
        assert!(mapper.mapping_count() > 50);

        println!("Loaded {} symbol mappings", mapper.mapping_count());
    }

    #[test]
    fn test_symbol_lookup() {
        let mapper = CapabilityMapper::from_yaml("capabilities.yaml").unwrap();

        // Test direct match
        let cap = mapper.lookup("system", "goblin").unwrap();
        assert_eq!(cap.id, "exec/command/shell");
        assert_eq!(cap.confidence, 1.0);

        // Test with leading underscore
        let cap = mapper.lookup("_system", "goblin").unwrap();
        assert_eq!(cap.id, "exec/command/shell");

        // Test unknown symbol
        assert!(mapper.lookup("unknown_function", "goblin").is_none());
    }

    #[test]
    fn test_network_symbols() {
        let mapper = CapabilityMapper::from_yaml("capabilities.yaml").unwrap();

        let cap = mapper.lookup("socket", "goblin").unwrap();
        assert_eq!(cap.id, "net/socket/create");

        let cap = mapper.lookup("connect", "goblin").unwrap();
        assert_eq!(cap.id, "net/socket/connect");
    }

    #[test]
    fn test_crypto_symbols() {
        let mapper = CapabilityMapper::from_yaml("capabilities.yaml").unwrap();

        let cap = mapper.lookup("MD5", "goblin").unwrap();
        assert_eq!(cap.id, "crypto/hash/md5");

        let cap = mapper.lookup("AES_encrypt", "goblin").unwrap();
        assert_eq!(cap.id, "crypto/encrypt/aes");
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
}
