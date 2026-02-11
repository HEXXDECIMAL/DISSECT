//! Core types for composite rules: Platform and FileType enums.

use serde::{Deserialize, Serialize};

/// Platform specifier for trait targeting
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    All,
    Linux,
    MacOS,
    Windows,
    Unix,
    Android,
    Ios,
}

/// File type specifier for rule targeting
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum FileType {
    All,
    // Binary formats
    Elf,
    Macho,
    Pe,
    Dylib,
    So,
    Dll,
    Class, // Java bytecode
    // Source code formats
    Shell,
    Batch,
    Python,
    JavaScript,
    TypeScript,
    Rust,
    Java,
    Ruby,
    C,
    Cpp,
    Go,
    Php,
    CSharp,
    Lua,
    Perl,
    PowerShell,
    Swift,
    ObjectiveC,
    Groovy,
    Scala,
    Zig,
    Elixir,
    AppleScript,
    Vbs,
    Html,
    // Manifest/config formats
    PackageJson,    // npm package.json
    ChromeManifest, // Chrome extension manifest.json
    CargoToml,      // Rust Cargo.toml
    PyProjectToml,  // Python pyproject.toml
    GithubActions,  // GitHub Actions workflow YAML
    ComposerJson,   // PHP composer.json
    PkgInfo,        // Python package metadata
    Plist,          // Apple Property List
    Rtf,            // Rich Text Format
    // Archive/installer formats (not extractable by DISSECT)
    Ipa, // iOS App Package
    // Generic formats
    Text, // Plain text files
    // Image formats
    Jpeg,
    Png,
}

impl FileType {
    /// Returns true if this file type is source code (not a compiled binary)
    pub fn is_source_code(&self) -> bool {
        matches!(
            self,
            FileType::Shell
                | FileType::Batch
                | FileType::Python
                | FileType::JavaScript
                | FileType::TypeScript
                | FileType::Rust
                | FileType::Java
                | FileType::Ruby
                | FileType::C
                | FileType::Cpp
                | FileType::Go
                | FileType::CSharp
                | FileType::Php
                | FileType::Lua
                | FileType::Perl
                | FileType::PowerShell
                | FileType::Swift
                | FileType::ObjectiveC
                | FileType::Groovy
                | FileType::Scala
                | FileType::Zig
                | FileType::Elixir
                | FileType::AppleScript
                | FileType::Vbs
                | FileType::Html
        )
    }

    /// Returns a list of all concrete file types (excluding All)
    pub fn all_concrete_variants() -> Vec<FileType> {
        vec![
            // Binary formats
            FileType::Elf,
            FileType::Macho,
            FileType::Pe,
            FileType::Dylib,
            FileType::So,
            FileType::Dll,
            FileType::Class,
            // Source code formats
            FileType::Shell,
            FileType::Batch,
            FileType::Python,
            FileType::JavaScript,
            FileType::TypeScript,
            FileType::Rust,
            FileType::Java,
            FileType::Ruby,
            FileType::C,
            FileType::Cpp,
            FileType::Go,
            FileType::Php,
            FileType::CSharp,
            FileType::Lua,
            FileType::Perl,
            FileType::PowerShell,
            FileType::Swift,
            FileType::ObjectiveC,
            FileType::Groovy,
            FileType::Scala,
            FileType::Zig,
            FileType::Elixir,
            FileType::AppleScript,
            FileType::Vbs,
            FileType::Html,
            // Manifest/config formats
            FileType::PackageJson,
            FileType::ChromeManifest,
            FileType::CargoToml,
            FileType::PyProjectToml,
            FileType::GithubActions,
            FileType::ComposerJson,
            FileType::PkgInfo,
            FileType::Plist,
            FileType::Rtf,
            // Archive/installer formats
            FileType::Ipa,
            // Generic formats
            FileType::Text,
            // Image formats
            FileType::Jpeg,
            FileType::Png,
        ]
    }
}

/// Default platforms for rules (all platforms)
pub fn default_platforms() -> Vec<Platform> {
    vec![Platform::All]
}

/// Default file types for rules (all file types)
pub fn default_file_types() -> Vec<FileType> {
    vec![FileType::All]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== FileType::is_source_code Tests ====================

    #[test]
    fn test_is_source_code_true_for_shell() {
        assert!(FileType::Shell.is_source_code());
    }

    #[test]
    fn test_is_source_code_true_for_python() {
        assert!(FileType::Python.is_source_code());
    }

    #[test]
    fn test_is_source_code_true_for_javascript() {
        assert!(FileType::JavaScript.is_source_code());
    }

    #[test]
    fn test_is_source_code_true_for_rust() {
        assert!(FileType::Rust.is_source_code());
    }

    #[test]
    fn test_is_source_code_true_for_go() {
        assert!(FileType::Go.is_source_code());
    }

    #[test]
    fn test_is_source_code_true_for_applescript() {
        assert!(FileType::AppleScript.is_source_code());
    }

    #[test]
    fn test_is_source_code_false_for_elf() {
        assert!(!FileType::Elf.is_source_code());
    }

    #[test]
    fn test_is_source_code_false_for_macho() {
        assert!(!FileType::Macho.is_source_code());
    }

    #[test]
    fn test_is_source_code_false_for_pe() {
        assert!(!FileType::Pe.is_source_code());
    }

    #[test]
    fn test_is_source_code_false_for_all() {
        assert!(!FileType::All.is_source_code());
    }

    #[test]
    fn test_is_source_code_false_for_package_json() {
        assert!(!FileType::PackageJson.is_source_code());
    }

    #[test]
    fn test_is_source_code_false_for_plist() {
        assert!(!FileType::Plist.is_source_code());
    }

    #[test]
    fn test_is_source_code_false_for_jpeg() {
        assert!(!FileType::Jpeg.is_source_code());
    }

    // ==================== FileType::all_concrete_variants Tests ====================

    #[test]
    fn test_all_concrete_variants_excludes_all() {
        let variants = FileType::all_concrete_variants();
        assert!(!variants.contains(&FileType::All));
    }

    #[test]
    fn test_all_concrete_variants_includes_elf() {
        let variants = FileType::all_concrete_variants();
        assert!(variants.contains(&FileType::Elf));
    }

    #[test]
    fn test_all_concrete_variants_includes_python() {
        let variants = FileType::all_concrete_variants();
        assert!(variants.contains(&FileType::Python));
    }

    #[test]
    fn test_all_concrete_variants_includes_package_json() {
        let variants = FileType::all_concrete_variants();
        assert!(variants.contains(&FileType::PackageJson));
    }

    #[test]
    fn test_all_concrete_variants_includes_jpeg() {
        let variants = FileType::all_concrete_variants();
        assert!(variants.contains(&FileType::Jpeg));
    }

    #[test]
    fn test_all_concrete_variants_count() {
        let variants = FileType::all_concrete_variants();
        // Should have all variants except All
        assert!(variants.len() > 30); // At least 30+ variants
    }

    // ==================== default_platforms Tests ====================

    #[test]
    fn test_default_platforms_returns_all() {
        let platforms = default_platforms();
        assert_eq!(platforms.len(), 1);
        assert_eq!(platforms[0], Platform::All);
    }

    // ==================== default_file_types Tests ====================

    #[test]
    fn test_default_file_types_returns_all() {
        let file_types = default_file_types();
        assert_eq!(file_types.len(), 1);
        assert_eq!(file_types[0], FileType::All);
    }

    // ==================== Platform Equality Tests ====================

    #[test]
    fn test_platform_equality() {
        assert_eq!(Platform::Linux, Platform::Linux);
        assert_ne!(Platform::Linux, Platform::Windows);
    }

    // ==================== FileType Comparison Tests ====================

    #[test]
    fn test_file_type_equality() {
        assert_eq!(FileType::Elf, FileType::Elf);
        assert_ne!(FileType::Elf, FileType::Macho);
    }

    #[test]
    fn test_file_type_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FileType::Elf);
        set.insert(FileType::Macho);
        set.insert(FileType::Elf); // Duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_file_type_ord() {
        // FileType derives Ord, so we can compare
        // Just verify it doesn't panic
        let _ = FileType::Elf < FileType::Macho;
    }
}
