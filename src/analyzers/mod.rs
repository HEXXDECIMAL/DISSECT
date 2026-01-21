pub mod archive;
pub mod c;
pub mod elf;
pub mod go;
pub mod java;
pub mod javascript;
pub mod macho;
pub mod pe;
// pub mod php;  // TODO: Fix compilation errors
pub mod python;
pub mod ruby;
pub mod rust;
pub mod shell;
pub mod typescript;

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
        return Ok(FileType::ShellScript);
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

    // Check for PHP opening tag or shebang
    if file_data.starts_with(b"<?php")
        || file_data.starts_with(b"#!/usr/bin/env php")
        || file_data.starts_with(b"#!/usr/bin/php")
    {
        return Ok(FileType::Php);
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
    {
        return Ok(FileType::Archive);
    }

    if let Some(ext) = file_path.extension() {
        let ext_str = ext.to_str().unwrap_or("");
        if ext_str == "sh" {
            return Ok(FileType::ShellScript);
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
        if ext_str == "c" || ext_str == "h" {
            return Ok(FileType::C);
        }
    }

    Ok(FileType::Unknown)
}

fn is_macho(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    // Mach-O magic numbers
    let magic = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    matches!(
        magic,
        0xfeedface | 0xcefaedfe | 0xfeedfacf | 0xcffaedfe | 0xcafebabe | 0xbebafeca
    )
}

#[derive(Debug, PartialEq)]
pub enum FileType {
    MachO,
    Elf,
    Pe,
    ShellScript,
    Python,
    JavaScript,
    TypeScript,
    Go,
    Rust,
    Java,
    Ruby,
    Php,
    C,
    Archive,
    Unknown,
}

impl FileType {
    /// Get YARA rule filetypes that are relevant for this file type
    /// Returns a list of filetype identifiers to match against YARA metadata
    pub fn yara_filetypes(&self) -> Vec<&'static str> {
        match self {
            FileType::MachO => vec!["macho", "elf", "so"],
            FileType::Elf => vec!["elf", "so", "ko"],
            FileType::Pe => vec!["pe", "exe", "dll", "bat", "ps1"],
            FileType::ShellScript => {
                vec!["sh", "bash", "zsh", "application/x-sh", "application/x-zsh"]
            }
            FileType::Python => vec!["py", "pyc"],
            FileType::JavaScript => vec!["js", "mjs", "cjs", "ts"],
            FileType::TypeScript => vec!["ts", "tsx", "mts", "cts", "js"],
            FileType::Go => vec!["go"],
            FileType::Rust => vec!["rs"],
            FileType::Java => vec!["java"],
            FileType::Ruby => vec!["rb"],
            FileType::Php => vec!["php"],
            FileType::C => vec!["c", "h", "hh"],
            FileType::Archive => vec!["zip", "tar", "gz"],
            FileType::Unknown => vec![], // No filtering for unknown types
        }
    }
}
