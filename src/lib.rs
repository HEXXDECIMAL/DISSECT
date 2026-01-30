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
pub mod decoders;
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
/// Creates a new CapabilityMapper for each call - for batch processing,
/// use `analyze_file_with_mapper` instead.
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
    let capability_mapper = CapabilityMapper::new();
    analyze_file_with_mapper(path, options, &capability_mapper)
}

/// Analyze a single file using a pre-loaded CapabilityMapper.
///
/// Use this for batch processing to avoid reloading capabilities for each file.
///
/// # Arguments
///
/// * `path` - Path to the file to analyze
/// * `options` - Analysis options
/// * `capability_mapper` - Pre-loaded capability mapper
///
/// # Returns
///
/// An `AnalysisReport` containing all extracted features, findings, and metrics.
pub fn analyze_file_with_mapper<P: AsRef<Path>>(
    path: P,
    options: &AnalysisOptions,
    capability_mapper: &CapabilityMapper,
) -> Result<AnalysisReport> {
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
        // All source code languages use the unified analyzer (or generic fallback)
        _ => {
            if let Some(analyzer) =
                analyzers::analyzer_for_file_type(&file_type, Some(capability_mapper.clone()))
            {
                analyzer.analyze(path)?
            } else {
                anyhow::bail!("Unsupported file type: {:?}", file_type);
            }
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
