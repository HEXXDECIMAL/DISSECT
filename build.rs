use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn find_rule_files_recursive(dir: &Path, base_path: &Path) -> Vec<PathBuf> {
    let mut rule_files = Vec::new();
    
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            
            if path.is_dir() {
                // Recursively search subdirectories
                rule_files.extend(find_rule_files_recursive(&path, base_path));
            } else if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "yar" || ext == "yara" {
                        // Store the relative path from the canonical base path
                        let canonical_base = fs::canonicalize(base_path).unwrap_or_else(|_| base_path.to_path_buf());
                        if let Ok(relative_path) = path.strip_prefix(&canonical_base) {
                            rule_files.push(relative_path.to_path_buf());
                        } else if let Ok(relative_path) = path.strip_prefix(base_path) {
                            rule_files.push(relative_path.to_path_buf());
                        }
                    }
                }
            }
        }
    }
    
    rule_files
}

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    
    // Get current working directory and build absolute path to rules
    let cwd = env::current_dir().expect("Failed to get current directory");
    let rules_dir = cwd.join("src/rules");
    
    let generated_code = if rules_dir.exists() || rules_dir.symlink_metadata().is_ok() {
        // Handle symlinks by canonicalizing the path
        let actual_rules_dir = if let Ok(canonical) = fs::canonicalize(&rules_dir) {
            canonical
        } else {
            rules_dir.clone()
        };
        
        // Recursively find all .yar/.yara files
        let rule_files = find_rule_files_recursive(&actual_rules_dir, &rules_dir);
        
        if rule_files.is_empty() {
            println!("cargo:warning=No YARA rule files found in src/rules/");
            // Generate fallback
            String::from("    pub fn load_embedded_rules() -> Result<Rules> {\n        let mut loader = Self::new();\n        \n        loader.add_rule_string(r#\"\nrule BasicSuspicious {\n    meta:\n        description = \"Basic suspicious pattern detection\"\n        author = \"Divine Security Scanner\"\n        risk_score = 1\n        \n    strings:\n        $exec = \"exec(\" nocase\n        $system = \"system(\" nocase\n        \n    condition:\n        any of them\n}\n\"#)?;\n        \n        loader.build()\n    }")
        } else {
            // Create a temporary directory structure that mirrors the rules and copy files there
            let temp_rules_dir = Path::new(&out_dir).join("temp_rules");
            fs::create_dir_all(&temp_rules_dir).unwrap();
            
            // Generate the rule loading code for all found files
            let mut rule_loading_code = Vec::new();
            for file in &rule_files {
                let source_path = actual_rules_dir.join(file);
                let dest_path = temp_rules_dir.join(file);
                
                // Create parent directories
                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent).unwrap();
                }
                
                // Copy the file
                if let Err(e) = fs::copy(&source_path, &dest_path) {
                    println!("cargo:warning=Failed to copy {}: {}", source_path.display(), e);
                    continue;
                }
                
                let file_str = file.to_string_lossy().replace('\\', "/");
                rule_loading_code.push(format!("        loader.add_rule_string(include_str!(concat!(env!(\"OUT_DIR\"), \"/temp_rules/{}\")))?;", file_str));
            }
            let rule_loading_code = rule_loading_code.join("\n");
                
                
            format!(
                "impl<'a> RuleLoader<'a> {{\n    pub fn load_embedded_rules() -> Result<Rules> {{\n        let mut loader = Self::new();\n        \n{}\n        \n        loader.build()\n    }}\n}}", 
                rule_loading_code
            )
        }
    } else {
        println!("cargo:warning=src/rules directory not found, using fallback rules");
        // Generate fallback if no rules directory
        String::from("impl<'a> RuleLoader<'a> {\n    pub fn load_embedded_rules() -> Result<Rules> {\n        let mut loader = Self::new();\n        \n        loader.add_rule_string(r#\"\nrule BasicSuspicious {\n    meta:\n        description = \"Basic suspicious pattern detection\"\n        author = \"Divine Security Scanner\"\n        risk_score = 1\n        \n    strings:\n        $exec = \"exec(\" nocase\n        $system = \"system(\" nocase\n        \n    condition:\n        any of them\n}\n\"#)?;\n        \n        loader.build()\n    }\n}")
    };
    
    let output_path = Path::new(&out_dir).join("embedded_rules.rs");
    fs::write(output_path, generated_code).unwrap();
    
    // Tell cargo to rerun if rule files change
    println!("cargo:rerun-if-changed=src/rules");
    
    // Also watch for changes in the symlinked directory itself
    if rules_dir.exists() {
        if let Ok(canonical_path) = fs::canonicalize(rules_dir) {
            println!("cargo:rerun-if-changed={}", canonical_path.display());
        }
    }
}