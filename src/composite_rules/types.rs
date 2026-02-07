//! Core types for composite rules: Platform and FileType enums.

use serde::Deserialize;

/// Platform specifier for trait targeting
#[derive(Debug, Clone, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
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
    // Manifest/config formats
    PackageJson,    // npm package.json
    ChromeManifest, // Chrome extension manifest.json
    CargoToml,      // Rust Cargo.toml
    PyProjectToml,  // Python pyproject.toml
    GithubActions,  // GitHub Actions workflow YAML
    ComposerJson,   // PHP composer.json
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
        )
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
