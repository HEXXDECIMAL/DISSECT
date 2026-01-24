pub mod applescript;
pub mod archive;
pub mod c;
pub mod csharp;

// Universal metrics analyzers
pub mod comment_metrics;
pub mod function_metrics;
pub mod identifier_metrics;
pub mod string_metrics;
pub mod text_metrics;

pub mod elf;
pub mod go;
pub mod java;
pub mod java_class;
pub mod javascript;
pub mod lua;
pub mod macho;
pub mod package_json;
pub mod pe;
pub mod perl;
pub mod php;
pub mod powershell;
pub mod python;
pub mod ruby;
pub mod rust;
pub mod shell;
pub mod typescript;
pub mod vsix_manifest;

use crate::types::AnalysisReport;
use anyhow::Result;
use std::path::Path;

/// Trait for file analyzers
pub trait Analyzer {
    /// Analyze a file and return a report
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport>;

    /// Check if this analyzer can handle the given file
    fn can_analyze(&self, file_path: &Path) -> bool;
}

/// Detect file type and route to appropriate analyzer
pub fn detect_file_type(file_path: &Path) -> Result<FileType> {
    let file_data = std::fs::read(file_path)?;

    if file_data.len() < 4 {
        return Ok(FileType::Unknown);
    }

    // Check for compiled AppleScript magic bytes "Fasd"
    if file_data.starts_with(b"Fasd") {
        return Ok(FileType::AppleScript);
    }

    // Check for Java class files BEFORE Mach-O (both use 0xCAFEBABE)
    if is_java_class(&file_data) {
        return Ok(FileType::JavaClass);
    }

    // Check for JAR files (ZIP with .jar extension) - check extension first
    let path_str = file_path.to_string_lossy().to_lowercase();
    if path_str.ends_with(".jar") || path_str.ends_with(".war") || path_str.ends_with(".ear") {
        // Verify it's a ZIP file (PK signature)
        if file_data.starts_with(b"PK") {
            return Ok(FileType::Jar);
        }
    }

    // Check for Mach-O magic bytes
    if is_macho(&file_data) {
        return Ok(FileType::MachO);
    }

    // Check for ELF magic bytes
    if file_data.starts_with(b"\x7fELF") {
        return Ok(FileType::Elf);
    }

    // Check for PE magic bytes
    if file_data.starts_with(b"MZ") {
        return Ok(FileType::Pe);
    }

    // Check for shell script shebang (various shells)
    if file_data.starts_with(b"#!/bin/sh")
        || file_data.starts_with(b"#!/bin/bash")
        || file_data.starts_with(b"#!/bin/zsh")
        || file_data.starts_with(b"#!/bin/dash")
        || file_data.starts_with(b"#!/usr/bin/env sh")
        || file_data.starts_with(b"#!/usr/bin/env bash")
        || file_data.starts_with(b"#!/usr/bin/env zsh")
        || file_data.starts_with(b"#!/usr/bin/env dash")
    {
        return Ok(FileType::Shell);
    }

    // Check for Python script shebang
    if file_data.starts_with(b"#!/usr/bin/env python")
        || file_data.starts_with(b"#!/usr/bin/python")
        || file_data.starts_with(b"#!/usr/bin/env python3")
        || file_data.starts_with(b"#!/usr/bin/python3")
    {
        return Ok(FileType::Python);
    }

    // Check for Node.js/JavaScript shebang
    if file_data.starts_with(b"#!/usr/bin/env node") || file_data.starts_with(b"#!/usr/bin/node") {
        return Ok(FileType::JavaScript);
    }

    // Check for Ruby shebang
    if file_data.starts_with(b"#!/usr/bin/env ruby") || file_data.starts_with(b"#!/usr/bin/ruby") {
        return Ok(FileType::Ruby);
    }

    // Check for Perl shebang
    if file_data.starts_with(b"#!/usr/bin/env perl")
        || file_data.starts_with(b"#!/usr/bin/perl")
        || file_data.starts_with(b"#!/usr/local/bin/perl")
    {
        return Ok(FileType::Perl);
    }

    // Check for PHP opening tag or shebang
    if file_data.starts_with(b"<?php")
        || file_data.starts_with(b"#!/usr/bin/env php")
        || file_data.starts_with(b"#!/usr/bin/php")
    {
        return Ok(FileType::Php);
    }

    // Check for Lua shebang
    if file_data.starts_with(b"#!/usr/bin/lua")
        || file_data.starts_with(b"#!/usr/bin/env lua")
        || file_data.starts_with(b"#!/usr/local/bin/lua")
    {
        return Ok(FileType::Lua);
    }

    // Check for package.json (npm manifest)
    if let Some(file_name) = file_path.file_name() {
        let name = file_name.to_string_lossy().to_lowercase();
        if name == "package.json" {
            return Ok(FileType::PackageJson);
        }
        if name == "extension.vsixmanifest" || name.ends_with(".vsixmanifest") {
            return Ok(FileType::VsixManifest);
        }
        // Debian/Ubuntu package maintainer scripts (often lack shebang)
        let name = file_name.to_string_lossy().to_lowercase();
        if name.contains("postinst")
            || name.contains("preinst")
            || name.contains("postrm")
            || name.contains("prerm")
        {
            return Ok(FileType::Shell);
        }
    }

    // Heuristic shell detection for files without shebang
    // Look for common shell patterns in first few lines
    if looks_like_shell(&file_data) {
        return Ok(FileType::Shell);
    }

    // Check for archives by file extension (need to check path, not just extension)
    let path_str = file_path.to_string_lossy().to_lowercase();
    if path_str.ends_with(".zip")
        || path_str.ends_with(".tar")
        || path_str.ends_with(".tar.gz")
        || path_str.ends_with(".tgz")
        || path_str.ends_with(".tar.bz2")
        || path_str.ends_with(".tbz2")
        || path_str.ends_with(".tar.xz")
        || path_str.ends_with(".txz")
        || path_str.ends_with(".xz")
        || path_str.ends_with(".gz")
        || path_str.ends_with(".bz2")
    {
        return Ok(FileType::Archive);
    }

    if let Some(ext) = file_path.extension() {
        let ext_str = ext.to_str().unwrap_or("");
        if ext_str == "sh" {
            return Ok(FileType::Shell);
        }
        if ext_str == "py" {
            return Ok(FileType::Python);
        }
        if matches!(ext_str, "js" | "mjs" | "cjs") {
            return Ok(FileType::JavaScript);
        }
        if matches!(ext_str, "ts" | "tsx" | "mts" | "cts") {
            return Ok(FileType::TypeScript);
        }
        if ext_str == "go" {
            return Ok(FileType::Go);
        }
        if ext_str == "rs" {
            return Ok(FileType::Rust);
        }
        if ext_str == "java" {
            return Ok(FileType::Java);
        }
        if ext_str == "rb" {
            return Ok(FileType::Ruby);
        }
        if ext_str == "php" {
            return Ok(FileType::Php);
        }
        if matches!(ext_str, "pl" | "pm" | "t") {
            return Ok(FileType::Perl);
        }
        if matches!(ext_str, "ps1" | "psm1" | "psd1") {
            return Ok(FileType::PowerShell);
        }
        if matches!(ext_str, "bat" | "cmd") {
            return Ok(FileType::Batch);
        }
        if ext_str == "c" || ext_str == "h" {
            return Ok(FileType::C);
        }
        if ext_str == "lua" {
            return Ok(FileType::Lua);
        }
        if ext_str == "cs" {
            return Ok(FileType::CSharp);
        }
        if ext_str == "scpt" || ext_str == "applescript" {
            return Ok(FileType::AppleScript);
        }
    }

    Ok(FileType::Unknown)
}

/// Check if data is a Java class file
/// Java class files start with 0xCAFEBABE followed by minor/major version
fn is_java_class(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }

    // Java class magic: CA FE BA BE
    if data[0] != 0xCA || data[1] != 0xFE || data[2] != 0xBA || data[3] != 0xBE {
        return false;
    }

    // Check major version (bytes 6-7, big-endian)
    // Java 1.0 = 45, Java 1.1 = 45, Java 1.2 = 46, ... Java 21 = 65
    // Mach-O fat binaries have nfat_arch in bytes 4-7 which is typically < 10
    let major_version = u16::from_be_bytes([data[6], data[7]]);

    // Valid Java class major versions are 45-70 (covering Java 1.0 through future versions)
    // Mach-O fat headers have small values (number of architectures) in this position
    (45..=70).contains(&major_version)
}

fn is_macho(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    // Mach-O magic numbers (excluding 0xcafebabe which is handled by is_java_class first)
    let magic = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

    // For 0xcafebabe (fat binary), we only match if is_java_class returned false
    if magic == 0xcafebabe || magic == 0xbebafeca {
        // This is a fat binary (not a Java class since is_java_class is called first)
        return true;
    }

    matches!(magic, 0xfeedface | 0xcefaedfe | 0xfeedfacf | 0xcffaedfe)
}

fn looks_like_shell(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(data);
    let first_lines: String = s.lines().take(5).collect::<Vec<_>>().join("\n");

    first_lines.contains("export ")
        || first_lines.contains("alias ")
        || first_lines.contains("set -e")
        || first_lines.contains("if [")
        || first_lines.contains("case $")
}

#[derive(Debug, PartialEq)]
pub enum FileType {
    MachO,
    Elf,
    Pe,
    Shell,
    Batch, // Windows batch files (.bat, .cmd)
    Python,
    JavaScript,
    TypeScript,
    Go,
    Rust,
    Java,      // .java source files
    JavaClass, // .class bytecode files
    Jar,       // .jar/.war/.ear archives
    Ruby,
    Php,
    Perl,
    Lua,
    CSharp,
    PowerShell,
    C,
    PackageJson,  // npm package.json manifest
    VsixManifest, // VSCode extension.vsixmanifest
    Archive,
    AppleScript,
    Unknown,
}

impl FileType {
    /// Returns true if this file type represents executable code (binaries, scripts, etc.)
    /// as opposed to data files (images, documents, etc.)
    pub fn is_program(&self) -> bool {
        match self {
            FileType::MachO
            | FileType::Elf
            | FileType::Pe
            | FileType::Shell
            | FileType::Batch
            | FileType::Python
            | FileType::JavaScript
            | FileType::TypeScript
            | FileType::Go
            | FileType::Rust
            | FileType::Java
            | FileType::JavaClass
            | FileType::Jar
            | FileType::Ruby
            | FileType::Php
            | FileType::Perl
            | FileType::Lua
            | FileType::CSharp
            | FileType::PowerShell
            | FileType::C
            | FileType::PackageJson
            | FileType::VsixManifest
            | FileType::AppleScript
            | FileType::Unknown => true, // Treat unknown as potential program for YARA scanning
            FileType::Archive => false,
        }
    }

    /// Get YARA rule filetypes that are relevant for this file type
    /// Returns a list of filetype identifiers to match against YARA metadata
    pub fn yara_filetypes(&self) -> Vec<&'static str> {
        match self {
            FileType::MachO => vec!["macho", "elf", "so"],
            FileType::Elf => vec!["elf", "so", "ko"],
            FileType::Pe => vec!["pe", "exe", "dll", "bat", "ps1"],
            FileType::Shell => {
                vec!["sh", "bash", "zsh", "application/x-sh", "application/x-zsh"]
            }
            FileType::Batch => vec!["bat", "cmd", "batch"],
            FileType::Python => vec!["py", "pyc"],
            FileType::JavaScript => vec!["js", "mjs", "cjs", "ts"],
            FileType::TypeScript => vec!["ts", "tsx", "mts", "cts", "js"],
            FileType::Go => vec!["go"],
            FileType::Rust => vec!["rs"],
            FileType::Java => vec!["java"],
            FileType::JavaClass => vec!["class", "java"],
            FileType::Jar => vec!["jar", "war", "ear", "class", "java"],
            FileType::Ruby => vec!["rb"],
            FileType::Php => vec!["php"],
            FileType::Perl => vec!["pl", "pm"],
            FileType::Lua => vec!["lua"],
            FileType::CSharp => vec!["cs", "csharp"],
            FileType::PowerShell => vec!["ps1", "psm1", "psd1"],
            FileType::C => vec!["c", "h", "hh"],
            FileType::PackageJson => vec!["json", "package.json", "npm"],
            FileType::VsixManifest => vec!["xml", "vsix", "vscode"],
            FileType::Archive => vec!["zip", "tar", "gz"],
            FileType::AppleScript => vec!["scpt", "applescript"],
            FileType::Unknown => vec![], // No filtering for unknown types
        }
    }
}
