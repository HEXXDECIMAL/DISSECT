pub mod archive;
pub mod elf;
pub mod javascript;
pub mod macho;
pub mod pe;
pub mod python;
pub mod shell;

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

    // Check for shell script shebang
    if file_data.starts_with(b"#!/bin/sh") || file_data.starts_with(b"#!/bin/bash") {
        return Ok(FileType::ShellScript);
    }

    // Check for Python script shebang or extension
    if file_data.starts_with(b"#!/usr/bin/env python") || file_data.starts_with(b"#!/usr/bin/python") {
        return Ok(FileType::Python);
    }

    // Check for archives by file extension (need to check path, not just extension)
    let path_str = file_path.to_string_lossy().to_lowercase();
    if path_str.ends_with(".zip") ||
       path_str.ends_with(".tar") ||
       path_str.ends_with(".tar.gz") ||
       path_str.ends_with(".tgz") ||
       path_str.ends_with(".tar.bz2") ||
       path_str.ends_with(".tbz2") ||
       path_str.ends_with(".tar.xz") ||
       path_str.ends_with(".txz") {
        return Ok(FileType::Archive);
    }

    if let Some(ext) = file_path.extension() {
        let ext_str = ext.to_str().unwrap_or("");
        if ext_str == "py" {
            return Ok(FileType::Python);
        }
        if matches!(ext_str, "js" | "mjs" | "cjs") {
            return Ok(FileType::JavaScript);
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
    Archive,
    Unknown,
}
