use crate::error::{DivineError, Result};
use std::path::Path;
use tracing::{info, warn};
use yara_x::{Compiler, Rules, SourceCode};

pub struct RuleLoader<'a> {
    compiler: Compiler<'a>,
}

impl<'a> Default for RuleLoader<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> RuleLoader<'a> {
    pub fn new() -> Self {
        Self { compiler: Compiler::new() }
    }

    pub fn add_rule_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();
        let rule_content = std::fs::read_to_string(path)
            .map_err(|e| DivineError::rule_loading(format!("Failed to read YARA rule file {}: {e}", path.display())))?;

        self.compiler
            .add_source(SourceCode::from(rule_content.as_str()))
            .map_err(|e| DivineError::yara_compilation(format!("Failed to compile YARA rule from {}: {e}", path.display())))?;

        Ok(())
    }

    pub fn add_rule_directory<P: AsRef<Path>>(&mut self, dir_path: P) -> Result<usize> {
        let dir_path = dir_path.as_ref();
        let mut rule_count = 0;

        for entry in std::fs::read_dir(dir_path)
            .map_err(|e| DivineError::rule_loading(format!("Failed to read rule directory {}: {e}", dir_path.display())))?
        {
            let entry = entry.map_err(|e| DivineError::rule_loading(format!("Failed to read directory entry: {e}")))?;
            let path = entry.path();

            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "yara" || ext == "yar" {
                        self.add_rule_file(&path)?;
                        rule_count += 1;
                    }
                }
            } else if path.is_dir() {
                rule_count += self.add_rule_directory(&path)?;
            }
        }

        Ok(rule_count)
    }

    pub fn add_rule_string(&mut self, rule_content: &str) -> Result<()> {
        self.compiler.add_source(SourceCode::from(rule_content)).map_err(|e| DivineError::yara_compilation(format!("Failed to compile YARA rule from string: {e}")))?;
        Ok(())
    }

    pub fn build(self) -> Result<Rules> {
        Ok(self.compiler.build())
    }

    pub fn load_malcontent_rules() -> Result<Rules> {
        let malcontent_rules_path = "../../malcontent/rules";

        if !Path::new(malcontent_rules_path).exists() {
            warn!("Malcontent rules directory not found at {}, falling back to embedded rules", malcontent_rules_path);
            return Self::load_embedded_rules();
        }

        // For now, just compile directly - caching YARA Rules is complex
        // TODO: Implement proper caching when YARA-X supports it
        info!("Loading malcontent rules from {}", malcontent_rules_path);
        let mut loader = Self::new();
        let count = loader.add_rule_directory(malcontent_rules_path)?;
        info!("Loaded {} rule files from malcontent", count);

        loader.build()
    }
}

// Generated at compile time by build.rs
include!(concat!(env!("OUT_DIR"), "/embedded_rules.rs"));
