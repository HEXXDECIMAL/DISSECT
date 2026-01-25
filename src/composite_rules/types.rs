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
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FileType {
    All,
    Elf,
    Macho,
    Pe,
    Dylib,
    So,
    Dll,
    Shell,
    Batch,
    Python,
    JavaScript,
    TypeScript,
    Rust,
    Java,
    Class,
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
    PackageJson,
    AppleScript,
}

/// Default platforms for rules (all platforms)
pub fn default_platforms() -> Vec<Platform> {
    vec![Platform::All]
}

/// Default file types for rules (all file types)
pub fn default_file_types() -> Vec<FileType> {
    vec![FileType::All]
}
