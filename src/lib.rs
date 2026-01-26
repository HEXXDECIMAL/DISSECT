//! DISSECT - Deep static analysis library for extracting features from binaries and source code.
//!
//! This library provides APIs for analyzing files and extracting security-relevant
//! features including capabilities, traits, and behavioral indicators.
//!
//! # Example
//!
//! ```no_run
//! use dissect::{analyze_file, AnalysisOptions};
//!
//! let options = AnalysisOptions::default();
//! let report = analyze_file("suspicious.py", &options).unwrap();
//!
//! for finding in &report.findings {
//!     println!("{}: {} ({:?})", finding.id, finding.desc, finding.crit);
//! }
//! ```

mod amos_cipher;
mod archive_utils;
mod cache;
mod constant_decoder;
mod entropy;
mod radare2;
mod strings;
mod syscall_names;
mod upx;

// Public modules
pub mod analyzers;
pub mod capabilities;
pub mod cli;
pub mod composite_rules;
pub mod diff;
pub mod env_mapper;
pub mod output;
pub mod path_mapper;
pub mod trait_mapper;
pub mod types;
pub mod yara_engine;

// Re-export commonly used types at crate root
pub use analyzers::{detect_file_type, Analyzer, FileType};
pub use capabilities::CapabilityMapper;
pub use diff::DiffAnalyzer;
pub use types::{
    AnalysisReport, BinaryProperties, Criticality, DiffReport, Evidence, Finding, FindingKind,
    Metrics, ModifiedFileAnalysis, SourceCodeMetrics, StringInfo, TargetInfo, TextMetrics, Trait,
    TraitKind,
};

use anyhow::Result;
use std::path::Path;

/// Options for file analysis
#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    /// Enable third-party YARA rules
    pub enable_third_party_yara: bool,
    /// Passwords to try for encrypted ZIP files
    pub zip_passwords: Vec<String>,
    /// Disable YARA scanning
    pub disable_yara: bool,
    /// Disable radare2 analysis
    pub disable_radare2: bool,
    /// Disable UPX unpacking
    pub disable_upx: bool,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            enable_third_party_yara: false,
            zip_passwords: cli::DEFAULT_ZIP_PASSWORDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            disable_yara: false,
            disable_radare2: false,
            disable_upx: false,
        }
    }
}

/// Analyze a single file and return a detailed report.
///
/// This is the main entry point for analyzing files programmatically.
///
/// # Arguments
///
/// * `path` - Path to the file to analyze
/// * `options` - Analysis options
///
/// # Returns
///
/// An `AnalysisReport` containing all extracted features, findings, and metrics.
pub fn analyze_file<P: AsRef<Path>>(path: P, options: &AnalysisOptions) -> Result<AnalysisReport> {
    let path = path.as_ref();

    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", path.display());
    }

    if path.is_dir() {
        anyhow::bail!(
            "Path is a directory, use analyze_directory instead: {}",
            path.display()
        );
    }

    // Apply global disables
    if options.disable_radare2 {
        radare2::disable_radare2();
    }
    if options.disable_upx {
        upx::disable_upx();
    }

    // Detect file type
    let file_type = detect_file_type(path)?;

    // Load capability mapper
    let capability_mapper = CapabilityMapper::new();

    // Load YARA rules if not disabled
    let mut yara_engine = if options.disable_yara {
        None
    } else {
        let empty_mapper = CapabilityMapper::empty();
        let mut engine = yara_engine::YaraEngine::new_with_mapper(empty_mapper);
        let (builtin_count, third_party_count) =
            engine.load_all_rules(options.enable_third_party_yara)?;
        engine.set_capability_mapper(capability_mapper.clone());
        if builtin_count + third_party_count > 0 {
            Some(engine)
        } else {
            None
        }
    };

    // Route to appropriate analyzer
    let mut report = match file_type {
        FileType::MachO => {
            let mut analyzer = analyzers::macho::MachOAnalyzer::new()
                .with_capability_mapper(capability_mapper.clone());
            if let Some(engine) = yara_engine.take() {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::Elf => {
            let mut analyzer = analyzers::elf::ElfAnalyzer::new()
                .with_capability_mapper(capability_mapper.clone());
            if let Some(engine) = yara_engine.take() {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::Pe => {
            let mut analyzer =
                analyzers::pe::PEAnalyzer::new().with_capability_mapper(capability_mapper.clone());
            if let Some(engine) = yara_engine.take() {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::Shell | FileType::Batch => {
            let analyzer = analyzers::shell::ShellAnalyzer::new()
                .with_capability_mapper(capability_mapper.clone());
            analyzer.analyze(path)?
        }
        FileType::Python => {
            let analyzer = analyzers::python::PythonAnalyzer::new()
                .with_capability_mapper(capability_mapper.clone());
            analyzer.analyze(path)?
        }
        FileType::JavaScript => {
            let analyzer = analyzers::javascript::JavaScriptAnalyzer::new()
                .with_capability_mapper(capability_mapper.clone());
            analyzer.analyze(path)?
        }
        FileType::Go => {
            let analyzer =
                analyzers::go::GoAnalyzer::new().with_capability_mapper(capability_mapper.clone());
            analyzer.analyze(path)?
        }
        FileType::Rust => {
            let analyzer = analyzers::rust::RustAnalyzer::new()
                .with_capability_mapper(capability_mapper.clone());
            analyzer.analyze(path)?
        }
        FileType::Java => {
            let analyzer = analyzers::java::JavaAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::JavaClass => {
            let analyzer = analyzers::java_class::JavaClassAnalyzer::new()
                .with_capability_mapper(capability_mapper.clone());
            analyzer.analyze(path)?
        }
        FileType::Jar | FileType::Archive => {
            let mut analyzer = analyzers::archive::ArchiveAnalyzer::new()
                .with_capability_mapper(capability_mapper.clone())
                .with_zip_passwords(options.zip_passwords.clone());
            if let Some(engine) = yara_engine.take() {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::Ruby => {
            let analyzer = analyzers::ruby::RubyAnalyzer::new()
                .with_capability_mapper(capability_mapper.clone());
            analyzer.analyze(path)?
        }
        FileType::TypeScript => {
            let analyzer = analyzers::typescript::TypeScriptAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::Php => {
            let analyzer = analyzers::php::PhpAnalyzer::new()
                .with_capability_mapper(capability_mapper.clone());
            analyzer.analyze(path)?
        }
        FileType::C => {
            let analyzer =
                analyzers::c::CAnalyzer::new().with_capability_mapper(capability_mapper.clone());
            analyzer.analyze(path)?
        }
        FileType::Perl => {
            let analyzer = analyzers::perl::PerlAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::Lua => {
            let analyzer = analyzers::lua::LuaAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::PowerShell => {
            let analyzer = analyzers::powershell::PowerShellAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::CSharp => {
            let analyzer = analyzers::csharp::CSharpAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::PackageJson => {
            let analyzer = analyzers::package_json::PackageJsonAnalyzer::new()
                .with_capability_mapper(capability_mapper.clone());
            analyzer.analyze(path)?
        }
        FileType::VsixManifest => {
            let analyzer = analyzers::vsix_manifest::VsixManifestAnalyzer::new()
                .with_capability_mapper(capability_mapper.clone());
            analyzer.analyze(path)?
        }
        FileType::Swift
        | FileType::ObjectiveC
        | FileType::Groovy
        | FileType::Scala
        | FileType::Zig
        | FileType::Elixir
        | FileType::AppleScript => analyze_generic_source(path, &file_type)?,
        FileType::Unknown => {
            anyhow::bail!("Unsupported file type: {:?}", file_type);
        }
    };

    // Run YARA for file types that didn't handle it internally
    if let Some(ref engine) = yara_engine {
        if file_type.is_program() && engine.is_loaded() {
            let file_types = file_type.yara_filetypes();
            let filter = if file_types.is_empty() {
                None
            } else {
                Some(file_types.as_slice())
            };

            if let Ok((matches, findings)) = engine.scan_file_to_findings(path, filter) {
                report.yara_matches = matches;
                for finding in findings {
                    if !report.findings.iter().any(|f| f.id == finding.id) {
                        report.findings.push(finding);
                    }
                }
                if !report.metadata.tools_used.contains(&"yara-x".to_string()) {
                    report.metadata.tools_used.push("yara-x".to_string());
                }
            }
        }
    }

    Ok(report)
}

/// Analyze source code files for languages with AST support but no dedicated analyzer.
fn analyze_generic_source(path: &Path, file_type: &FileType) -> Result<AnalysisReport> {
    use analyzers::symbol_extraction;
    use sha2::{Digest, Sha256};
    use std::fs;

    let start = std::time::Instant::now();
    let content = fs::read_to_string(path)?;

    let file_type_str = format!("{:?}", file_type).to_lowercase();
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let sha256 = format!("{:x}", hasher.finalize());

    let target = TargetInfo {
        path: path.display().to_string(),
        file_type: file_type_str.clone(),
        size_bytes: content.len() as u64,
        sha256,
        architectures: None,
    };

    let mut report = AnalysisReport::new(target);

    report.structure.push(types::StructuralFeature {
        id: format!("source/language/{}", file_type_str),
        desc: format!("{} source code", file_type_str),
        evidence: vec![Evidence {
            method: "parser".to_string(),
            source: "tree-sitter".to_string(),
            value: file_type_str.clone(),
            location: Some("AST".to_string()),
        }],
    });

    if let Some((lang, call_types)) = symbol_extraction::get_language_config(file_type) {
        symbol_extraction::extract_symbols(&content, lang, &call_types, &mut report);
    }

    path_mapper::analyze_and_link_paths(&mut report);
    env_mapper::analyze_and_link_env_vars(&mut report);

    report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
    report.metadata.tools_used = vec!["tree-sitter".to_string()];

    Ok(report)
}

/// Analyze multiple files in a directory.
///
/// Returns a vector of analysis reports, one for each analyzed file.
pub fn analyze_directory<P: AsRef<Path>>(
    path: P,
    options: &AnalysisOptions,
) -> Result<Vec<AnalysisReport>> {
    use rayon::prelude::*;
    use walkdir::WalkDir;

    let path = path.as_ref();
    if !path.is_dir() {
        anyhow::bail!("Path is not a directory: {}", path.display());
    }

    // Apply global disables
    if options.disable_radare2 {
        radare2::disable_radare2();
    }
    if options.disable_upx {
        upx::disable_upx();
    }

    // Collect all files
    let files: Vec<_> = WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let file_name = e.file_name().to_string_lossy();
            !file_name.starts_with(".git")
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| !archive_utils::is_archive(e.path()))
        .map(|e| e.path().to_path_buf())
        .collect();

    // Analyze in parallel
    let reports: Vec<_> = files
        .par_iter()
        .filter_map(|file_path| analyze_file(file_path, options).ok())
        .collect();

    Ok(reports)
}

/// Compare two file versions for supply chain attack detection.
///
/// This is useful for detecting malicious changes between package versions.
pub fn diff_files<P: AsRef<Path>>(old_path: P, new_path: P) -> Result<DiffReport> {
    let analyzer = DiffAnalyzer::new(old_path, new_path);
    analyzer.analyze()
}
