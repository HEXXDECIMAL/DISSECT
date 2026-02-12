//! DISSECT - Deep Inspection of Suspicious Software for Evaluation and Classification of Threats
//!
//! DISSECT is a comprehensive malware analysis tool that performs deep static analysis
//! of binaries, scripts, and archives to identify malicious behavior patterns and capabilities.
//!
//! # Architecture
//!
//! - **Analyzers**: Format-specific analysis engines (ELF, PE, MachO, scripts, archives)
//! - **Capabilities**: Trait-based capability detection from YAML rules
//! - **Composite Rules**: Boolean logic for combining multiple indicators
//! - **YARA Integration**: Pattern matching with community and custom rules
//! - **Radare2/Rizin**: Binary analysis and disassembly
//!
//! # Usage
//!
//! ```text
//! dissect <file> [options]
//! dissect diff <file1> <file2>  # Compare two versions
//! ```
//!
//! # Output
//!
//! Analysis results are output as JSON containing:
//! - Detected capabilities and traits
//! - Findings with criticality levels
//! - Binary metrics and code structure
//! - YARA matches and syscalls
//! - Archive contents (if applicable)

#![allow(dead_code)]

mod amos_cipher;
mod analyzers;
mod archive_utils;
mod cache;
mod capabilities;
mod cli;
mod composite_rules;
mod constant_decoder;
mod diff;
mod entropy;
mod env_mapper;
mod extractors;
mod ip_validator;
mod output;
mod path_mapper;
mod radare2;
mod rtf;
mod syscall_names;
// mod radare2_extended;  // Removed: integrated into radare2.rs
mod strings;
mod test_rules;
mod trait_mapper;
mod types;
mod upx;
mod yara_engine;

use crate::radare2::Radare2Analyzer;
use analyzers::{
    archive::ArchiveAnalyzer, detect_file_type, elf::ElfAnalyzer, macho::MachOAnalyzer,
    pe::PEAnalyzer, Analyzer, FileType,
};
use anyhow::{Context, Result};
use clap::Parser;
use crossbeam_channel::bounded;
use rayon::prelude::*;
use serde::Serialize;
use std::fs;
use std::io::BufRead;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing_subscriber::EnvFilter;
use yara_engine::YaraEngine;

/// Read paths from stdin, one per line.
/// Filters out empty lines and comments (lines starting with #).
fn read_paths_from_stdin() -> Vec<String> {
    let stdin = std::io::stdin();
    let reader = stdin.lock();
    reader
        .lines()
        .map_while(Result::ok)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

/// Expand paths, replacing "-" with paths read from stdin.
fn expand_paths(paths: Vec<String>) -> Vec<String> {
    let mut expanded = Vec::new();
    let mut stdin_read = false;

    for path in paths {
        if path == "-" {
            if !stdin_read {
                let stdin_paths = read_paths_from_stdin();
                eprintln!("Read {} paths from stdin", stdin_paths.len());
                expanded.extend(stdin_paths);
                stdin_read = true;
            }
            // If "-" appears multiple times, only read stdin once
        } else {
            expanded.push(path);
        }
    }

    expanded
}

/// Check if a report's highest criticality matches any of the error_if levels
/// If so, exit with error
fn check_criticality_error(
    report: &types::AnalysisReport,
    error_if_levels: Option<&[types::Criticality]>,
) -> Result<()> {
    if let Some(levels) = error_if_levels {
        if let Some(highest_crit) = report.highest_criticality() {
            if levels.contains(&highest_crit) {
                anyhow::bail!(
                    "File '{}' has highest criticality {:?} which matches --error-if criteria",
                    report.target.path,
                    highest_crit
                );
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    // Parse args early to get verbose flag for logging initialization
    let args = cli::Args::parse();

    // Initialize tracing/logging
    // Use RUST_LOG env var if set, otherwise use verbose flag
    // Examples: RUST_LOG=debug, RUST_LOG=dissect=trace, RUST_LOG=dissect::analyzers::archive=trace
    let env_filter = if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else if args.verbose {
        // Use trace level for verbose mode to see all instrumentation
        EnvFilter::new("dissect=trace")
    } else {
        // By default, only show warnings and errors
        EnvFilter::new("dissect=warn")
    };

    // Set up logging with optional file output
    if let Some(ref log_file) = args.log_file {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use std::fs::OpenOptions;
        use std::sync::{Arc, Mutex};

        // Create or append to log file
        let file = Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_file)
                .unwrap_or_else(|e| {
                    eprintln!("Failed to open log file {}: {}", log_file, e);
                    std::process::exit(1);
                })
        ));

        eprintln!("Logging to: {}", log_file);

        // Create a MakeWriter implementation for our file
        use tracing_subscriber::fmt::MakeWriter;
        struct LogFile(Arc<Mutex<std::fs::File>>);
        impl<'a> MakeWriter<'a> for LogFile {
            type Writer = LogFileWriter;
            fn make_writer(&'a self) -> Self::Writer {
                LogFileWriter(self.0.clone())
            }
        }
        struct LogFileWriter(Arc<Mutex<std::fs::File>>);
        impl std::io::Write for LogFileWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let mut file = self.0.lock().unwrap();
                let result = file.write(buf);
                // Flush after every write to ensure logs survive OOM kills
                // This has a performance cost but is critical for debugging crashes
                let _ = file.flush();
                result
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.0.lock().unwrap().flush()
            }
        }

        // Create layers for both stderr and file
        let stderr_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_line_number(true)
            .with_writer(std::io::stderr);

        let file_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_line_number(true)
            .with_ansi(false) // No color codes in file
            .with_writer(LogFile(file));

        tracing_subscriber::registry()
            .with(env_filter)
            .with(stderr_layer)
            .with(file_layer)
            .init();
    } else {
        // No log file, just stderr
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_thread_ids(false)
            .with_line_number(true)
            .with_writer(std::io::stderr)
            .init();
    }

    // Log command line and initialization
    tracing::info!("dissect started: {}", std::env::args().collect::<Vec<_>>().join(" "));
    tracing::trace!("Logging initialized (verbose={})", args.verbose);

    // Configure rayon thread pool with larger stack size to handle deeply nested ASTs
    // (e.g., minified JavaScript, malicious files with extreme nesting)
    // Default is ~2MB which can overflow on files with 1000+ nesting levels
    rayon::ThreadPoolBuilder::new()
        .stack_size(8 * 1024 * 1024) // 8MB per thread
        .build_global()
        .ok(); // Ignore error if pool already initialized (e.g., in tests)

    // Get disabled components
    let disabled = args.disabled_components();

    // Apply custom traits directory if specified (must be before any trait loading)
    if let Some(ref traits_dir) = args.traits_dir {
        std::env::set_var("DISSECT_TRAITS_PATH", traits_dir);
    }

    // Apply global disables for radare2 and upx
    if disabled.radare2 {
        radare2::disable_radare2();
    }
    if disabled.upx {
        upx::disable_upx();
    }

    // Print banner to stderr (status info never goes to stdout)
    eprintln!(
        "DISSECT v{} • Deep static analysis tool\n",
        env!("CARGO_PKG_VERSION")
    );

    let format = args.format();

    // Collect zip passwords (default + custom, unless disabled)
    let zip_passwords: Vec<String> = if args.no_zip_passwords {
        Vec::new()
    } else {
        let mut passwords: Vec<String> = cli::DEFAULT_ZIP_PASSWORDS
            .iter()
            .map(|s| s.to_string())
            .collect();
        passwords.extend(args.zip_passwords.clone());
        passwords
    };

    // Determine third_party_yara setting (can come from top-level or subcommand)
    // Third-party YARA is opt-in (disabled by default), but can also be disabled via --disable
    let enable_third_party_global = args.third_party_yara && !disabled.third_party;

    // Collect error_if levels for criticality checking
    let error_if_levels = args.error_if_levels();

    // Create extraction config if --extract-dir is specified
    let sample_extraction = args.extract_dir.as_ref().map(|dir| {
        let path = std::path::PathBuf::from(dir);
        // Ensure directory exists
        if let Err(e) = std::fs::create_dir_all(&path) {
            eprintln!("Warning: could not create extract directory {}: {}", dir, e);
        }
        types::SampleExtractionConfig::new(path)
    });

    // Parse platforms once before match (avoids borrow issues in match arms)
    let platforms = args.platforms();

    // Convert max_file_mem from MB to bytes
    let max_memory_file_size = args.max_file_mem * 1024 * 1024;

    // Start periodic memory logging if verbose mode is enabled
    let _memory_logger = if args.verbose {
        use dissect::memory_tracker;
        Some(memory_tracker::start_periodic_logging(
            std::time::Duration::from_secs(10),
        ))
    } else {
        None
    };

    let result = match args.command {
        Some(cli::Command::Analyze {
            targets,
            third_party_yara: cmd_third_party,
        }) => {
            let enable_third_party =
                (enable_third_party_global || cmd_third_party) && !disabled.third_party;
            let expanded = expand_paths(targets);
            if expanded.is_empty() {
                anyhow::bail!("No valid paths found (stdin was empty or contained only comments)");
            }
            let path = Path::new(&expanded[0]);
            if expanded.len() == 1 && !path.exists() {
                // Single nonexistent path - error
                anyhow::bail!("Path does not exist: {}", expanded[0]);
            } else if expanded.len() == 1 && path.is_file() {
                // Single file - use detailed analyze
                analyze_file(
                    &expanded[0],
                    enable_third_party,
                    &format,
                    &zip_passwords,
                    &disabled,
                    error_if_levels.as_deref(),
                    args.verbose,
                    args.all_files,
                    sample_extraction.as_ref(),
                    platforms.clone(),
                    args.min_hostile_precision,
                    args.min_suspicious_precision,
                    max_memory_file_size,
                    args.validate,
                )?
            } else {
                // Multiple targets or directory - use scan
                scan_paths(
                    expanded,
                    enable_third_party,
                    &format,
                    &zip_passwords,
                    &disabled,
                    error_if_levels.as_deref(),
                    args.verbose,
                    args.all_files,
                    sample_extraction.as_ref(),
                    platforms.clone(),
                    args.min_hostile_precision,
                    args.min_suspicious_precision,
                    max_memory_file_size,
                    args.validate,
                )?
            }
        }
        Some(cli::Command::Scan {
            paths,
            third_party_yara: cmd_third_party,
        }) => scan_paths(
            expand_paths(paths),
            (enable_third_party_global || cmd_third_party) && !disabled.third_party,
            &format,
            &zip_passwords,
            &disabled,
            error_if_levels.as_deref(),
            args.verbose,
            args.all_files,
            sample_extraction.as_ref(),
            platforms.clone(),
            args.min_hostile_precision,
            args.min_suspicious_precision,
            max_memory_file_size,
            args.validate,
        )?,
        Some(cli::Command::Diff { old, new }) => diff_analysis(&old, &new, &format)?,
        Some(cli::Command::Strings { target, min_length }) => {
            extract_strings(&target, min_length, &format)?
        }
        Some(cli::Command::Symbols { target }) => extract_symbols(&target, &format)?,
        Some(cli::Command::Sections { target }) => extract_sections(&target, &format)?,
        Some(cli::Command::Metrics { target }) => extract_metrics(&target, &format, &disabled)?,
        Some(cli::Command::TestRules { target, rules }) => test_rules_debug(
            &target,
            &rules,
            &disabled,
            platforms.clone(),
            args.min_hostile_precision,
            args.min_suspicious_precision,
        )?,
        Some(cli::Command::TestMatch {
            target,
            r#type,
            method,
            pattern,
            kv_path,
            file_type,
            count_min,
            count_max,
            per_kb_min,
            per_kb_max,
            case_insensitive,
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            external_ip,
            encoding,
            entropy_min,
            entropy_max,
            length_min,
            length_max,
            value_min,
            value_max,
            min_size,
            max_size,
        }) => test_match_debug(
            &target,
            r#type,
            method,
            pattern.as_deref(),
            kv_path.as_deref(),
            file_type,
            count_min,
            count_max,
            per_kb_min,
            per_kb_max,
            case_insensitive,
            section.as_deref(),
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            external_ip,
            encoding.as_deref(),
            entropy_min,
            entropy_max,
            length_min,
            length_max,
            value_min,
            value_max,
            min_size,
            max_size,
            &disabled,
            platforms.clone(),
            args.min_hostile_precision,
            args.min_suspicious_precision,
        )?,
        None => {
            // No subcommand - use paths from top-level args
            if args.paths.is_empty() {
                anyhow::bail!("No paths specified. Usage: dissect <path>... or dissect <command>");
            }
            let expanded = expand_paths(args.paths);
            if expanded.is_empty() {
                anyhow::bail!("No valid paths found (stdin was empty or contained only comments)");
            }
            scan_paths(
                expanded,
                enable_third_party_global,
                &format,
                &zip_passwords,
                &disabled,
                error_if_levels.as_deref(),
                args.verbose,
                args.all_files,
                sample_extraction.as_ref(),
                platforms.clone(),
                args.min_hostile_precision,
                args.min_suspicious_precision,
                max_memory_file_size,
                args.validate,
            )?
        }
    };

    // Output results
    if let Some(output_path) = args.output {
        fs::write(&output_path, &result)
            .context(format!("Failed to write output to {}", output_path))?;
        eprintln!("Results written to: {}", output_path);
    } else {
        // Results go to stdout
        print!("{}", result);
    }

    // Log final memory statistics if verbose
    if args.verbose {
        use dissect::memory_tracker;
        memory_tracker::global_tracker().log_stats();
        let total_files = memory_tracker::global_tracker().files_processed();
        let peak_rss = memory_tracker::global_tracker().peak_rss();
        tracing::info!(
            total_files = total_files,
            peak_rss_gb = peak_rss / 1024 / 1024 / 1024,
            "Analysis complete"
        );
    }

    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn analyze_file(
    target: &str,
    enable_third_party_yara: bool,
    format: &cli::OutputFormat,
    zip_passwords: &[String],
    disabled: &cli::DisabledComponents,
    error_if_levels: Option<&[types::Criticality]>,
    verbose: bool,
    all_files: bool,
    sample_extraction: Option<&types::SampleExtractionConfig>,
    platforms: Vec<composite_rules::Platform>,
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
    max_memory_file_size: u64,
    enable_full_validation: bool,
) -> Result<String> {
    let _start = std::time::Instant::now();
    let path = Path::new(target);

    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", target);
    }

    // If target is a directory, scan it recursively
    if path.is_dir() {
        return scan_paths(
            vec![target.to_string()],
            enable_third_party_yara,
            format,
            zip_passwords,
            disabled,
            error_if_levels,
            verbose,
            all_files,
            sample_extraction,
            platforms,
            min_hostile_precision,
            min_suspicious_precision,
            max_memory_file_size,
            enable_full_validation,
        );
    }

    // Status messages go to stderr
    eprintln!("Analyzing: {}", target);
    tracing::info!("Starting analysis of {}", target);

    // Detect file type first (fast - just reads magic bytes)
    tracing::debug!("Detecting file type");
    let file_type = detect_file_type(path)?;
    eprintln!("Detected file type: {:?}", file_type);
    tracing::info!("File type: {:?}", file_type);

    // Load capability mapper
    let _t1 = std::time::Instant::now();
    tracing::info!("Loading capability mapper (trait definitions)");
    let capability_mapper = crate::capabilities::CapabilityMapper::new_with_precision_thresholds(
        min_hostile_precision,
        min_suspicious_precision,
        enable_full_validation,
    )
    .with_platforms(platforms.clone());
    tracing::info!("Capability mapper loaded");

    // Load YARA rules (unless YARA is disabled)
    let mut yara_engine = if disabled.yara {
        tracing::info!("YARA scanning disabled");
        eprintln!("[INFO] YARA scanning disabled");
        None
    } else {
        let _t_yara_start = std::time::Instant::now();
        tracing::info!("Initializing YARA engine");
        let empty_mapper = crate::capabilities::CapabilityMapper::empty();
        let mut engine = YaraEngine::new_with_mapper(empty_mapper);
        let (builtin_count, third_party_count) = engine.load_all_rules(enable_third_party_yara)?;
        tracing::info!(
            "YARA engine loaded with {} rules",
            builtin_count + third_party_count
        );
        engine.set_capability_mapper(capability_mapper.clone());
        if builtin_count + third_party_count > 0 {
            Some(engine)
        } else {
            None
        }
    };

    // Route to appropriate analyzer
    // Binary analyzers (MachO, Elf, Pe, Archive, Jar) handle YARA internally with specialized filtering
    // All other analyzers get YARA scanning applied universally after analysis
    let _t3 = std::time::Instant::now();
    let mut report = match file_type {
        FileType::MachO => {
            let mut analyzer =
                MachOAnalyzer::new().with_capability_mapper(capability_mapper.clone());
            if let Some(engine) = yara_engine.take() {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::Elf => {
            let mut analyzer = ElfAnalyzer::new().with_capability_mapper(capability_mapper.clone());
            if let Some(engine) = yara_engine.take() {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::Pe => {
            let mut analyzer = PEAnalyzer::new().with_capability_mapper(capability_mapper.clone());
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
        FileType::Jar => {
            // JAR files are analyzed like archives but with Java-specific handling
            let mut analyzer = ArchiveAnalyzer::new()
                .with_capability_mapper(capability_mapper.clone())
                .with_zip_passwords(zip_passwords.to_vec())
                .with_max_memory_file_size(max_memory_file_size);
            if let Some(engine) = yara_engine.take() {
                analyzer = analyzer.with_yara(engine);
            }
            if let Some(config) = sample_extraction {
                analyzer = analyzer.with_sample_extraction(config.clone());
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
        FileType::Archive => {
            let mut analyzer = ArchiveAnalyzer::new()
                .with_capability_mapper(capability_mapper.clone())
                .with_zip_passwords(zip_passwords.to_vec())
                .with_max_memory_file_size(max_memory_file_size);
            if let Some(engine) = yara_engine.take() {
                analyzer = analyzer.with_yara(engine);
            }
            if let Some(config) = sample_extraction {
                analyzer = analyzer.with_sample_extraction(config.clone());
            }
            // Use streaming for JSONL format to emit files as they're analyzed
            if matches!(format, cli::OutputFormat::Jsonl) {
                analyzer.analyze_streaming(path, |file_analysis| {
                    if let Ok(line) = output::format_jsonl_line(file_analysis) {
                        println!("{}", line);
                    }
                })?
            } else {
                analyzer.analyze(path)?
            }
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

    // Run YARA universally for file types that didn't handle it internally
    // This ensures all program files get scanned with YARA rules
    if let Some(ref engine) = yara_engine {
        if file_type.is_program() && engine.is_loaded() {
            let file_types = file_type.yara_filetypes();
            let filter = if file_types.is_empty() {
                None
            } else {
                Some(file_types.as_slice())
            };

            match engine.scan_file_to_findings(path, filter) {
                Ok((matches, findings)) => {
                    // Add YARA matches to report
                    report.yara_matches = matches;

                    // Add findings that don't already exist
                    for finding in findings {
                        if !report.findings.iter().any(|f| f.id == finding.id) {
                            report.findings.push(finding);
                        }
                    }

                    // Mark that we used YARA
                    if !report.metadata.tools_used.contains(&"yara-x".to_string()) {
                        report.metadata.tools_used.push("yara-x".to_string());
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  YARA scan failed: {}", e);
                }
            }
        }
    }

    // Check if report's criticality matches --error-if criteria
    check_criticality_error(&report, error_if_levels)?;

    // Free excess capacity in all Vec fields to reduce memory footprint
    report.shrink_to_fit();

    // Convert to v2 schema (flat files array) and filter based on verbosity
    report.convert_to_v2(verbose);

    // Format output based on requested format
    let _t4 = std::time::Instant::now();

    match format {
        cli::OutputFormat::Jsonl => output::format_jsonl(&report),
        cli::OutputFormat::Terminal => output::format_terminal(&report),
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_paths(
    paths: Vec<String>,
    enable_third_party_yara: bool,
    format: &cli::OutputFormat,
    zip_passwords: &[String],
    disabled: &cli::DisabledComponents,
    error_if_levels: Option<&[types::Criticality]>,
    verbose: bool,
    include_all_files: bool,
    sample_extraction: Option<&types::SampleExtractionConfig>,
    platforms: Vec<composite_rules::Platform>,
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
    max_memory_file_size: u64,
    enable_full_validation: bool,
) -> Result<String> {
    use walkdir::WalkDir;

    // Load capability mapper once and share across all threads
    let capability_mapper = Arc::new(
        crate::capabilities::CapabilityMapper::new_with_precision_thresholds(
            min_hostile_precision,
            min_suspicious_precision,
            enable_full_validation,
        )
        .with_platforms(platforms.clone()),
    );

    // Pre-load YARA engine once and share across all threads
    let shared_yara_engine: Option<Arc<YaraEngine>> = if disabled.yara {
        None
    } else {
        let mut engine = YaraEngine::new_with_mapper((*capability_mapper).clone());
        match engine.load_all_rules(enable_third_party_yara) {
            Ok((builtin, third_party)) if builtin + third_party > 0 => Some(Arc::new(engine)),
            _ => None,
        }
    };

    // Collect all files from paths (expanding directories recursively)
    // Pre-allocate with reasonable capacity to reduce reallocations
    let mut all_files = Vec::with_capacity(1000);
    let mut archives_found = Vec::with_capacity(100);

    for path_str in &paths {
        let path = Path::new(path_str);

        if path.is_file() {
            // Check if it's an archive
            if archive_utils::is_archive(path) {
                archives_found.push(path_str.clone());
            } else {
                all_files.push(path_str.clone());
            }
        } else if path.is_dir() {
            // Recursively walk directory
            for entry in WalkDir::new(path)
                .follow_links(false) // Skip symlinks to avoid infinite loops
                .into_iter()
                .filter_entry(|e| {
                    // Skip .git directories
                    let file_name = e.file_name().to_string_lossy();
                    !file_name.starts_with(".git")
                })
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    let file_path = entry.path().to_string_lossy().to_string();

                    // Check if it's an archive
                    if archive_utils::is_archive(entry.path()) {
                        archives_found.push(file_path);
                    } else {
                        // Skip unknown file types unless --all-files is set
                        if !include_all_files {
                            let file_type =
                                detect_file_type(entry.path()).unwrap_or(FileType::Unknown);
                            if !file_type.is_program() {
                                continue;
                            }
                        }
                        all_files.push(file_path);
                    }
                }
            }
        }
    }

    // Track --error-if failures to stop processing early
    let error_if_triggered = Arc::new(AtomicBool::new(false));
    let error_if_message: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    // Process regular files in parallel using try_for_each for early termination
    let files_result: Result<(), ()> = all_files.par_iter().try_for_each(|path_str| {
        // Check if another thread already triggered --error-if
        if error_if_triggered.load(Ordering::Relaxed) {
            return Err(());
        }

        match analyze_file_with_shared_mapper(
            path_str,
            &capability_mapper,
            shared_yara_engine.as_ref(),
            zip_passwords,
            disabled,
            error_if_levels,
            verbose,
            sample_extraction,
            max_memory_file_size,
        ) {
            Ok(json) => {
                match format {
                    cli::OutputFormat::Terminal => {
                        // For terminal format, show immediate output above progress bar
                        match output::parse_jsonl(&json) {
                            Ok(report) => match output::format_terminal(&report) {
                                Ok(formatted) => {
                                    print!("{}", formatted);
                                }
                                Err(e) => {
                                    eprintln!("Error formatting report for {}: {}", path_str, e);
                                }
                            },
                            Err(e) => {
                                eprintln!("Error parsing JSON for {}: {}", path_str, e);
                            }
                        }
                    }
                    cli::OutputFormat::Jsonl => {
                        // For JSONL, stream each file immediately
                        match output::parse_jsonl(&json) {
                            Ok(report) => {
                                for file in &report.files {
                                    if let Ok(line) = output::format_jsonl_line(file) {
                                        println!("{}", line);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Error parsing JSON for {}: {}", path_str, e);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                // Check if this is an --error-if failure - stop processing
                if err_str.contains("--error-if") {
                    error_if_triggered.store(true, Ordering::Relaxed);
                    eprintln!("✗ {}: {}", path_str, e);
                    let mut msg = error_if_message.lock().unwrap();
                    if msg.is_none() {
                        *msg = Some(err_str);
                    }
                    return Err(()); // Short-circuit parallel iteration
                }

                eprintln!("✗ {}: {}", path_str, e);
            }
        }

        Ok(())
    });

    // Process archives with limited concurrency to prevent OOM
    // Use a semaphore pattern: bounded channel with N tokens
    const MAX_CONCURRENT_ARCHIVES: usize = 3;
    let (archive_sem_tx, archive_sem_rx) = bounded(MAX_CONCURRENT_ARCHIVES);
    for _ in 0..MAX_CONCURRENT_ARCHIVES {
        archive_sem_tx.send(()).unwrap();
    }

    // Process archives in parallel (skip if files already triggered --error-if)
    let archives_result: Result<(), ()> = if files_result.is_ok() {
        archives_found.par_iter().try_for_each(|path_str| {
            // Acquire semaphore token (blocks if MAX_CONCURRENT_ARCHIVES already processing)
            let _token = archive_sem_rx.recv().ok();

            // Process archive (wrapped to ensure token is returned)
            let result = (|| -> Result<(), ()> {
                // Check if another thread already triggered --error-if
                if error_if_triggered.load(Ordering::Relaxed) {
                    return Err(());
                }

                // For JSONL format, use true streaming analysis for archives
                if matches!(format, cli::OutputFormat::Jsonl) {
                    match analyze_archive_streaming_jsonl(
                        path_str,
                        &capability_mapper,
                        shared_yara_engine.as_ref(),
                        zip_passwords,
                        sample_extraction,
                        max_memory_file_size,
                    ) {
                        Ok(()) => {
                            // Files were already streamed via callback
                        }
                        Err(e) => {
                            eprintln!("✗ {}: {}", path_str, e);
                        }
                    }
                    return Ok(());
                }

                match analyze_file_with_shared_mapper(
                    path_str,
                    &capability_mapper,
                    shared_yara_engine.as_ref(),
                    zip_passwords,
                    disabled,
                    error_if_levels,
                    verbose,
                    sample_extraction,
                    max_memory_file_size,
                ) {
                    Ok(json) => {
                        match format {
                            cli::OutputFormat::Terminal => {
                                // For terminal format, show immediate output above progress bar
                                match output::parse_jsonl(&json) {
                                    Ok(report) => match output::format_terminal(&report) {
                                        Ok(formatted) => {
                                            print!("{}", formatted);
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "Error formatting report for {}: {}",
                                                path_str, e
                                            );
                                        }
                                    },
                                    Err(e) => {
                                        eprintln!("DEBUG: JSON parse error: {}", e);
                                        eprintln!(
                                            "DEBUG: JSON preview: {}",
                                            &json[..json.len().min(500)]
                                        );
                                        eprintln!("Error parsing JSON for {}: {}", path_str, e);
                                    }
                                }
                            }
                            cli::OutputFormat::Jsonl => {
                                // Should not reach here - JSONL uses streaming path above
                                unreachable!("JSONL should use streaming path");
                            }
                        }
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        // Check if this is an --error-if failure - stop processing
                        if err_str.contains("--error-if") {
                            error_if_triggered.store(true, Ordering::Relaxed);
                            eprintln!("✗ {}: {}", path_str, e);
                            let mut msg = error_if_message.lock().unwrap();
                            if msg.is_none() {
                                *msg = Some(err_str);
                            }
                            return Err(()); // Short-circuit parallel iteration
                        }

                        eprintln!("✗ {}: {}", path_str, e);
                    }
                }

                Ok(())
            })();

            // Return token to semaphore
            let _ = _token;
            archive_sem_tx.send(()).ok();

            result
        })
    } else {
        Err(()) // Skip archives if files already failed
    };

    // If --error-if was triggered, return the error
    if files_result.is_err() || archives_result.is_err() {
        if let Some(msg) = error_if_message.lock().unwrap().take() {
            anyhow::bail!(msg);
        }
    }

    // Format based on output type
    match format {
        cli::OutputFormat::Jsonl => {
            // JSONL already streamed files above via analyze_archive_streaming_jsonl
            // Don't emit a summary - the individual file lines were already printed
            Ok(String::new())
        }
        cli::OutputFormat::Terminal => Ok(String::new()),
    }
}

#[allow(clippy::too_many_arguments)]
fn analyze_file_with_shared_mapper(
    target: &str,
    capability_mapper: &Arc<crate::capabilities::CapabilityMapper>,
    shared_yara_engine: Option<&Arc<YaraEngine>>,
    zip_passwords: &[String],
    _disabled: &cli::DisabledComponents,
    error_if_levels: Option<&[types::Criticality]>,
    verbose: bool,
    sample_extraction: Option<&types::SampleExtractionConfig>,
    max_memory_file_size: u64,
) -> Result<String> {
    // Log BEFORE processing to ensure we capture what file causes OOM crashes
    tracing::info!("Starting analysis of file: {}", target);

    let _t_start = std::time::Instant::now();
    let path = Path::new(target);

    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }
    let _t_detect = std::time::Instant::now();

    // Detect file type
    tracing::debug!("Detecting file type for: {}", target);
    let file_type = detect_file_type(path)?;
    tracing::debug!("Detected file type: {:?} for: {}", file_type, target);

    // Get file size for memory tracking
    let file_size = std::fs::metadata(path)?.len();

    // Log memory state before processing
    if verbose {
        use dissect::memory_tracker;
        memory_tracker::log_before_file_processing(target, file_size);
    }

    // Read file for mismatch check and payload extraction
    let file_data_wrapper = dissect::file_io::read_file_smart(path)?;
    let file_data = file_data_wrapper.as_slice();

    // Track file read for memory monitoring
    if verbose {
        use dissect::memory_tracker;
        memory_tracker::global_tracker().record_file_read(file_size, target);
    }

    // Check for extension/content mismatch
    let mismatch = analyzers::check_extension_content_mismatch(path, file_data);

    // Check for encoded payloads (hex, base64, etc.)
    let encoded_payloads = extractors::encoded_payload::extract_encoded_payloads(file_data);

    let _t_analyze = std::time::Instant::now();

    // Route to appropriate analyzer
    // Binary analyzers (MachO, Elf, Pe, Archive, Jar) handle YARA internally with specialized filtering
    // All other analyzers get YARA scanning applied universally after analysis
    let mut report = match file_type {
        FileType::MachO => {
            let mut analyzer =
                MachOAnalyzer::new().with_capability_mapper_arc(capability_mapper.clone());
            if let Some(engine) = shared_yara_engine {
                analyzer = analyzer.with_yara_arc(engine.clone());
            }
            analyzer.analyze(path)?
        }
        FileType::Elf => {
            let mut analyzer =
                ElfAnalyzer::new().with_capability_mapper_arc(capability_mapper.clone());
            if let Some(engine) = shared_yara_engine {
                analyzer = analyzer.with_yara_arc(engine.clone());
            }
            analyzer.analyze(path)?
        }
        FileType::Pe => {
            let mut analyzer =
                PEAnalyzer::new().with_capability_mapper_arc(capability_mapper.clone());
            if let Some(engine) = shared_yara_engine {
                analyzer = analyzer.with_yara_arc(engine.clone());
            }
            analyzer.analyze(path)?
        }
        FileType::JavaClass => {
            let analyzer = analyzers::java_class::JavaClassAnalyzer::new()
                .with_capability_mapper_arc(capability_mapper.clone());
            analyzer.analyze(path)?
        }
        FileType::Jar => {
            // JAR files are analyzed like archives but with Java-specific handling
            let mut analyzer = ArchiveAnalyzer::new()
                .with_capability_mapper_arc(capability_mapper.clone())
                .with_zip_passwords(zip_passwords.to_vec())
                .with_max_memory_file_size(max_memory_file_size);
            if let Some(engine) = shared_yara_engine {
                analyzer = analyzer.with_yara_arc(engine.clone());
            }
            if let Some(config) = sample_extraction {
                analyzer = analyzer.with_sample_extraction(config.clone());
            }
            analyzer.analyze(path)?
        }
        FileType::PackageJson => {
            let analyzer = analyzers::package_json::PackageJsonAnalyzer::new()
                .with_capability_mapper_arc(capability_mapper.clone());
            analyzer.analyze(path)?
        }
        FileType::VsixManifest => {
            let analyzer = analyzers::vsix_manifest::VsixManifestAnalyzer::new()
                .with_capability_mapper_arc(capability_mapper.clone());
            analyzer.analyze(path)?
        }
        FileType::AppleScript => {
            let analyzer = analyzers::applescript::AppleScriptAnalyzer::new()
                .with_capability_mapper_arc(capability_mapper.clone());
            analyzer.analyze(path)?
        }
        FileType::Archive => {
            let mut analyzer = ArchiveAnalyzer::new()
                .with_capability_mapper_arc(capability_mapper.clone())
                .with_zip_passwords(zip_passwords.to_vec())
                .with_max_memory_file_size(max_memory_file_size);
            if let Some(engine) = shared_yara_engine {
                analyzer = analyzer.with_yara_arc(engine.clone());
            }
            if let Some(config) = sample_extraction {
                analyzer = analyzer.with_sample_extraction(config.clone());
            }
            analyzer.analyze(path)?
        }
        // All source code languages use the unified analyzer (or generic fallback)
        _ => {
            if let Some(analyzer) =
                analyzers::analyzer_for_file_type_arc(&file_type, Some(capability_mapper.clone()))
            {
                analyzer.analyze(path)?
            } else {
                anyhow::bail!("Unsupported file type: {:?}", file_type);
            }
        }
    };

    // Add finding for extension/content mismatch if detected
    if let Some((expected, actual)) = mismatch {
        report.findings.push(types::Finding {
            id: "meta/file-extension-mismatch".to_string(),
            kind: types::FindingKind::Indicator,
            desc: format!(
                "File extension claims {} but content is {}",
                expected, actual
            ),
            conf: 1.0,
            crit: types::Criticality::Hostile,
            mbc: None,
            attack: Some("T1036.005".to_string()), // Masquerading: Match Legitimate Name or Location
            trait_refs: vec![],
            evidence: vec![types::Evidence {
                method: "magic-byte".to_string(),
                source: "dissect".to_string(),
                value: format!("expected={}, actual={}", expected, actual),
                location: None,
            }],
        
            source_file: None,
        });
    }

    // Add findings for encoded payloads
    for payload in encoded_payloads {
        report.findings.push(types::Finding {
            id: format!("meta/encoded-payload/{}", payload.encoding_chain.join("-")),
            kind: types::FindingKind::Structural,
            desc: format!(
                "Encoded payload detected: {}",
                payload.encoding_chain.join(" → ")
            ),
            conf: 0.9,
            crit: types::Criticality::Suspicious,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![types::Evidence {
                method: "pattern".to_string(),
                source: "dissect".to_string(),
                value: format!(
                    "encoding={}, type={:?}, preview={}",
                    payload.encoding_chain.join(", "),
                    payload.detected_type,
                    payload.preview
                ),
                location: Some(format!("offset:{}", payload.original_offset)),
            }],
        
            source_file: None,
        });

        // TODO: Recursively analyze decoded payloads
        // This is currently only done in lib.rs::analyze_file_with_mapper
        // Consider refactoring to share this logic between CLI and library paths
    }

    // Run YARA universally for file types that didn't handle it internally
    // This ensures all program files get scanned with YARA rules
    if let Some(engine) = shared_yara_engine {
        if file_type.is_program() && engine.is_loaded() {
            let file_types = file_type.yara_filetypes();
            let filter = if file_types.is_empty() {
                None
            } else {
                Some(file_types.as_slice())
            };

            match engine.scan_file_to_findings(path, filter) {
                Ok((matches, findings)) => {
                    // Add YARA matches to report
                    report.yara_matches = matches;

                    // Add findings that don't already exist
                    for finding in findings {
                        if !report.findings.iter().any(|f| f.id == finding.id) {
                            report.findings.push(finding);
                        }
                    }

                    // Mark that we used YARA
                    if !report.metadata.tools_used.contains(&"yara-x".to_string()) {
                        report.metadata.tools_used.push("yara-x".to_string());
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  YARA scan failed: {}", e);
                }
            }
        }
    }

    // Check if report's criticality matches --error-if criteria
    check_criticality_error(&report, error_if_levels)?;

    // Free excess capacity in all Vec fields to reduce memory footprint
    report.shrink_to_fit();

    // Convert to v2 schema (flat files array) and filter based on verbosity
    report.convert_to_v2(verbose);

    // Log memory state after processing
    if verbose {
        use dissect::memory_tracker;
        memory_tracker::log_after_file_processing(
            target,
            file_size,
            _t_start.elapsed(),
        );
    }

    // Output as JSONL format for parallel scanning
    output::format_jsonl(&report)
}

/// Analyze an archive with streaming JSONL output.
///
/// This function uses the streaming archive analyzer to emit results as they
/// become available, rather than waiting for the entire archive to be processed.
fn analyze_archive_streaming_jsonl(
    target: &str,
    capability_mapper: &Arc<crate::capabilities::CapabilityMapper>,
    shared_yara_engine: Option<&Arc<YaraEngine>>,
    zip_passwords: &[String],
    sample_extraction: Option<&types::SampleExtractionConfig>,
    max_memory_file_size: u64,
) -> Result<()> {
    let path = Path::new(target);
    let archive_path = target.to_string();

    let mut analyzer = ArchiveAnalyzer::new()
        .with_capability_mapper_arc(capability_mapper.clone())
        .with_zip_passwords(zip_passwords.to_vec())
        .with_max_memory_file_size(max_memory_file_size);

    if let Some(engine) = shared_yara_engine {
        analyzer = analyzer.with_yara_arc(engine.clone());
    }
    if let Some(config) = sample_extraction {
        analyzer = analyzer.with_sample_extraction(config.clone());
    }

    // Use streaming analysis - each file is emitted as a JSONL line via the callback
    // Prefix the archive path to each file's path so consumers can group by archive
    let report = analyzer.analyze_streaming(path, |file_analysis| {
        let mut fa = file_analysis.clone();
        fa.path = types::file_analysis::encode_archive_path(&archive_path, &fa.path);
        if let Ok(line) = output::format_jsonl_line(&fa) {
            println!("{}", line);
        }
    })?;

    // After all member files are emitted, emit an archive-level entry
    // This signals archive completion and provides aggregate risk for consumers
    // Format: same as file entries but path has no "!!" (no parent)

    // Get aggregates from summary (computed incrementally during streaming)
    let mut max_risk = report
        .summary
        .as_ref()
        .and_then(|s| s.max_risk)
        .unwrap_or(types::Criticality::Inert);
    let mut counts = report
        .summary
        .as_ref()
        .map(|s| s.counts.clone())
        .unwrap_or_default();

    // Include archive-level findings (zip-bomb, path traversal, etc.)
    for finding in &report.findings {
        if finding.crit > max_risk {
            max_risk = finding.crit;
        }
        match finding.crit {
            types::Criticality::Hostile => counts.hostile += 1,
            types::Criticality::Suspicious => counts.suspicious += 1,
            types::Criticality::Notable => counts.notable += 1,
            _ => {}
        }
    }

    // Create archive-level FileAnalysis entry
    let archive_entry = types::FileAnalysis {
        id: 0,
        path: archive_path,
        parent_id: None, // No parent - this IS the archive
        depth: 0,
        file_type: report.target.file_type,
        sha256: report.target.sha256,
        size: report.target.size_bytes,
        risk: if max_risk > types::Criticality::Inert {
            Some(max_risk)
        } else {
            None
        },
        counts: Some(counts),
        encoding: None,
        findings: report.findings,
        traits: Vec::new(),
        structure: report.structure,
        functions: Vec::new(),
        strings: Vec::new(),
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        yara_matches: Vec::new(),
        syscalls: Vec::new(),
        binary_properties: None,
        source_code_metrics: None,
        metrics: None,
        paths: Vec::new(),
        directories: Vec::new(),
        env_vars: Vec::new(),
        extracted_path: None,
    };

    if let Ok(line) = output::format_jsonl_line(&archive_entry) {
        println!("{}", line);
    }

    Ok(())
}

fn diff_analysis(old: &str, new: &str, format: &cli::OutputFormat) -> Result<String> {
    let diff_analyzer = diff::DiffAnalyzer::new(old, new);

    match format {
        cli::OutputFormat::Jsonl => {
            // Use full diff for JSONL - comprehensive ML-ready output
            let report = diff_analyzer.analyze_full()?;
            Ok(serde_json::to_string_pretty(&report)?)
        }
        cli::OutputFormat::Terminal => {
            // Use simple diff for terminal display
            let report = diff_analyzer.analyze()?;
            Ok(diff::format_diff_terminal(&report))
        }
    }
}

fn extract_strings(target: &str, min_length: usize, format: &cli::OutputFormat) -> Result<String> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    let data = fs::read(path)?;

    // For source code files with AST support, extract strings via AST parsing
    if let Ok(file_type) = detect_file_type(path) {
        if file_type.is_source_code() {
            return extract_strings_from_ast(path, &file_type, min_length, format);
        }
    }

    let mut imports = std::collections::HashSet::new();
    let mut import_libraries = std::collections::HashMap::new();
    let mut exports = std::collections::HashSet::new();
    let mut functions = std::collections::HashSet::new();

    // Try to extract symbols if it's a binary file
    if let Ok(file_type) = detect_file_type(path) {
        match file_type {
            FileType::Elf | FileType::MachO | FileType::Pe => {
                // macOS specific optimization: use nm -u -m for highly accurate import library mappings
                #[cfg(target_os = "macos")]
                {
                    if file_type == FileType::MachO {
                        if let Ok(nm_output) = std::process::Command::new("nm")
                            .args(["-u", "-m", path.to_str().unwrap()])
                            .output()
                        {
                            let nm_str = String::from_utf8_lossy(&nm_output.stdout);
                            for line in nm_str.lines() {
                                let trimmed = line.trim();
                                if let Some(sym_start) = trimmed.find("external ") {
                                    let sym_part = &trimmed[sym_start + 9..];
                                    if let Some(lib_start) = sym_part.find(" (from ") {
                                        let mut sym = sym_part[..lib_start].trim().to_string();
                                        // Strip leading underscore for consistency
                                        if sym.starts_with('_') {
                                            sym = sym[1..].to_string();
                                        }
                                        let lib_part = &sym_part[lib_start + 7..];
                                        let lib = lib_part.trim_end_matches(')').to_string();
                                        imports.insert(sym.clone());
                                        import_libraries.insert(sym, lib);
                                    }
                                }
                            }
                        }
                    }
                }

                // Use radare2 directly for fast symbol/function extraction in ONE batch
                if Radare2Analyzer::is_available() {
                    let r2 = Radare2Analyzer::new();
                    if let Ok((r2_imports, _, r2_symbols)) = r2.extract_all_symbols(path) {
                        for imp in r2_imports {
                            let name = imp.name.trim_start_matches('_');
                            imports.insert(name.to_string());
                            if let Some(lib) = imp.lib_name {
                                import_libraries.insert(name.to_string(), lib);
                            }
                        }
                        for sym in r2_symbols {
                            if sym.name.starts_with("imp.") || sym.name.starts_with("sym.imp.") {
                                let clean = sym
                                    .name
                                    .trim_start_matches("sym.imp.")
                                    .trim_start_matches("imp.")
                                    .trim_start_matches('_');
                                imports.insert(clean.to_string());
                            } else if sym.symbol_type == "FUNC"
                                || sym.symbol_type == "func"
                                || sym.name.starts_with("fcn.")
                            {
                                let name = sym.name.trim_start_matches('_').to_string();
                                // Exports are GLOBAL in MachO symbols
                                if sym.symbol_type == "FUNC"
                                    && (sym.name.starts_with("__mh_") || !sym.name.starts_with('_'))
                                {
                                    exports.insert(name.clone());
                                }
                                if !imports.contains(&name) && !exports.contains(&name) {
                                    functions.insert(name);
                                }
                            }
                        }
                    }
                } else {
                    // Fallback to minimal goblin analysis
                    let capability_mapper = crate::capabilities::CapabilityMapper::empty();
                    let report = match file_type {
                        FileType::Elf => ElfAnalyzer::new()
                            .with_capability_mapper(capability_mapper)
                            .analyze(path)?,
                        FileType::MachO => MachOAnalyzer::new()
                            .with_capability_mapper(capability_mapper)
                            .analyze(path)?,
                        FileType::Pe => PEAnalyzer::new()
                            .with_capability_mapper(capability_mapper)
                            .analyze(path)?,
                        _ => unreachable!(),
                    };

                    for import in report.imports {
                        imports.insert(import.symbol.clone());
                        if let Some(lib) = import.library {
                            import_libraries.insert(import.symbol, lib);
                        }
                    }
                    for export in report.exports {
                        exports.insert(export.symbol);
                    }
                    for func in report.functions {
                        if func.name.starts_with("sym.imp.") {
                            let clean = func.name.trim_start_matches("sym.imp.");
                            imports.insert(clean.to_string());
                        } else if !imports.contains(&func.name) && !exports.contains(&func.name) {
                            functions.insert(func.name);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let extractor = strings::StringExtractor::new()
        .with_min_length(min_length)
        .with_imports(imports)
        .with_import_libraries(import_libraries)
        .with_exports(exports)
        .with_functions(functions);

    let strings = extractor.extract_smart(&data);

    match format {
        cli::OutputFormat::Jsonl => Ok(serde_json::to_string_pretty(&strings)?),
        cli::OutputFormat::Terminal => {
            let mut output = String::new();

            // Sort strings by offset to show them in file order
            let mut strings = strings;
            strings.sort_by_key(|s| s.offset);

            let mut current_section: Option<&str> = None;

            for s in &strings {
                let section = s.section.as_deref();

                // Print section header when section changes
                if section != current_section {
                    if current_section.is_some() {
                        output.push('\n');
                    }
                    let section_name = section.unwrap_or("(unknown)");
                    output.push_str(&format!("── {} ──\n", section_name));
                    current_section = section;
                }

                let offset = s
                    .offset
                    .map(|o| format!("{}", o))
                    .unwrap_or_else(|| "-".to_string());

                // Use stng-style type labels
                let stype_str = match s.string_type {
                    crate::types::StringType::Import => "import",
                    crate::types::StringType::Export => "export",
                    crate::types::StringType::Function => "func",
                    crate::types::StringType::StackString => "stack",
                    crate::types::StringType::Url => "url",
                    crate::types::StringType::Ip => "ip",
                    crate::types::StringType::Email => "email",
                    crate::types::StringType::Path => "path",
                    crate::types::StringType::Base64 => "base64",
                    crate::types::StringType::ShellCmd => "shell",
                    _ => "-",
                };

                // Format encoding chain as a separate column
                let encoding_str = if s.encoding_chain.is_empty() {
                    "-".to_string()
                } else {
                    s.encoding_chain.join("+")
                };

                // Escape control characters for display
                let mut val_display = s
                    .value
                    .replace('\n', "\\n")
                    .replace('\r', "\\r")
                    .replace('\t', "\\t");

                if s.string_type == crate::types::StringType::Base64 {
                    use base64::{engine::general_purpose, Engine as _};

                    if let Ok(decoded) = general_purpose::STANDARD.decode(s.value.trim()) {
                        if !decoded.is_empty()
                            && decoded.iter().all(|&b| {
                                (0x20..=0x7e).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t'
                            })
                        {
                            if let Ok(decoded_str) = String::from_utf8(decoded) {
                                let escaped = decoded_str
                                    .replace('\n', "\\n")
                                    .replace('\r', "\\r")
                                    .replace('\t', "\\t");

                                val_display = format!("{}  [{}]", val_display, escaped);
                            }
                        }
                    }
                }

                output.push_str(&format!(
                    "{:>10} {:<12} {:<10} {}\n",
                    offset, stype_str, encoding_str, val_display
                ));
            }
            Ok(output)
        }
    }
}

/// Extract strings from source code files using AST parsing.
/// This ensures consistency with how strings are matched in trait evaluation.
fn extract_strings_from_ast(
    path: &Path,
    file_type: &FileType,
    min_length: usize,
    format: &cli::OutputFormat,
) -> Result<String> {
    // Analyze the file to extract strings via AST using unified analyzer
    let report = if let Some(analyzer) = analyzers::analyzer_for_file_type(file_type, None) {
        analyzer.analyze(path)?
    } else {
        anyhow::bail!("Unsupported file type for AST extraction: {:?}", file_type);
    };

    // Filter strings by min_length
    let filtered_strings: Vec<_> = report
        .strings
        .into_iter()
        .filter(|s| s.value.len() >= min_length)
        .collect();

    match format {
        cli::OutputFormat::Jsonl => Ok(serde_json::to_string_pretty(&filtered_strings)?),
        cli::OutputFormat::Terminal => {
            let mut output = String::new();
            output.push_str(&format!(
                "Extracted {} strings from {} (AST-based)\n\n",
                filtered_strings.len(),
                path.display()
            ));
            output.push_str(&format!("{:<10} {:<14} {}\n", "OFFSET", "TYPE", "VALUE"));
            output.push_str(&format!("{:-<10} {:-<14} {:-<20}\n", "", "", ""));
            for s in filtered_strings {
                let offset = s
                    .offset
                    .map(|o| format!("{:#x}", o))
                    .unwrap_or_else(|| "unknown".to_string());
                let stype_str = format!("{:?}", s.string_type);
                output.push_str(&format!("{:<10} {:<14} {}\n", offset, stype_str, s.value));
            }
            Ok(output)
        }
    }
}

#[derive(Debug, Serialize)]
struct SectionInfo {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    size: u64,
    entropy: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    permissions: Option<String>,
}

#[derive(Debug, Serialize)]
struct SymbolInfo {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    library: Option<String>,
    symbol_type: String,
    source: String,
}

fn extract_symbols(target: &str, format: &cli::OutputFormat) -> Result<String> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    let mut symbols: Vec<SymbolInfo> = Vec::new();

    // Detect file type
    if let Ok(file_type) = detect_file_type(path) {
        match file_type {
            FileType::Elf | FileType::MachO | FileType::Pe => {
                // Binary file - extract symbols with addresses

                // Use radare2 for comprehensive symbol extraction
                if Radare2Analyzer::is_available() {
                    let r2 = Radare2Analyzer::new();
                    if let Ok((r2_imports, r2_exports, r2_symbols)) = r2.extract_all_symbols(path) {
                        // Add imports
                        for imp in r2_imports {
                            symbols.push(SymbolInfo {
                                name: imp.name.trim_start_matches('_').to_string(),
                                address: None,
                                library: imp.lib_name,
                                symbol_type: "import".to_string(),
                                source: "radare2".to_string(),
                            });
                        }

                        // Add exports
                        for exp in r2_exports {
                            symbols.push(SymbolInfo {
                                name: exp.name.trim_start_matches('_').to_string(),
                                address: Some(format!("0x{:x}", exp.vaddr)),
                                library: None,
                                symbol_type: "export".to_string(),
                                source: "radare2".to_string(),
                            });
                        }

                        // Add other symbols (functions, etc.)
                        for sym in r2_symbols {
                            let sym_type = if sym.symbol_type == "FUNC" || sym.symbol_type == "func"
                            {
                                "function"
                            } else {
                                &sym.symbol_type
                            };

                            let clean_name = sym.name.trim_start_matches('_').to_string();

                            // Skip if already added as import or export
                            let already_added = symbols.iter().any(|s| s.name == clean_name);
                            if !already_added {
                                symbols.push(SymbolInfo {
                                    name: clean_name,
                                    address: Some(format!("0x{:x}", sym.vaddr)),
                                    library: None,
                                    symbol_type: sym_type.to_lowercase(),
                                    source: "radare2".to_string(),
                                });
                            }
                        }
                    }
                } else {
                    // Fallback to goblin-based analysis
                    let capability_mapper = crate::capabilities::CapabilityMapper::empty();
                    let report = match file_type {
                        FileType::Elf => ElfAnalyzer::new()
                            .with_capability_mapper(capability_mapper)
                            .analyze(path)?,
                        FileType::MachO => MachOAnalyzer::new()
                            .with_capability_mapper(capability_mapper)
                            .analyze(path)?,
                        FileType::Pe => PEAnalyzer::new()
                            .with_capability_mapper(capability_mapper)
                            .analyze(path)?,
                        _ => unreachable!(),
                    };

                    // Add imports
                    for import in report.imports {
                        symbols.push(SymbolInfo {
                            name: import.symbol.clone(),
                            address: None,
                            library: import.library,
                            symbol_type: "import".to_string(),
                            source: import.source,
                        });
                    }

                    // Add exports
                    for export in report.exports {
                        symbols.push(SymbolInfo {
                            name: export.symbol,
                            address: export.offset,
                            library: None,
                            symbol_type: "export".to_string(),
                            source: export.source,
                        });
                    }

                    // Add functions
                    for func in report.functions {
                        symbols.push(SymbolInfo {
                            name: func.name,
                            address: func.offset,
                            library: None,
                            symbol_type: "function".to_string(),
                            source: func.source,
                        });
                    }
                }
            }
            _ => {
                // Source file or script - analyze for symbols using unified analyzer
                let report =
                    if let Some(analyzer) = analyzers::analyzer_for_file_type(&file_type, None) {
                        analyzer.analyze(path)?
                    } else {
                        anyhow::bail!(
                            "Unsupported file type for symbol extraction: {:?}",
                            file_type
                        );
                    };

                // Add imports (function calls from source code)
                for import in report.imports {
                    symbols.push(SymbolInfo {
                        name: import.symbol.clone(),
                        address: None,
                        library: import.library,
                        symbol_type: "import".to_string(),
                        source: import.source,
                    });
                }

                // Add exports (defined functions)
                for export in report.exports {
                    symbols.push(SymbolInfo {
                        name: export.symbol,
                        address: export.offset,
                        library: None,
                        symbol_type: "export".to_string(),
                        source: export.source,
                    });
                }

                // Add functions
                for func in report.functions {
                    symbols.push(SymbolInfo {
                        name: func.name,
                        address: func.offset,
                        library: None,
                        symbol_type: "function".to_string(),
                        source: func.source,
                    });
                }
            }
        }
    } else {
        anyhow::bail!("Unable to detect file type for: {}", target);
    }

    // Sort symbols by address (if available), then by name
    symbols.sort_by(|a, b| {
        match (&a.address, &b.address) {
            (Some(addr_a), Some(addr_b)) => {
                // Parse hex addresses for proper numeric sorting
                let parse_addr =
                    |s: &str| -> u64 { s.trim_start_matches("0x").parse::<u64>().unwrap_or(0) };
                let num_a = parse_addr(addr_a);
                let num_b = parse_addr(addr_b);
                num_a.cmp(&num_b)
            }
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.name.cmp(&b.name),
        }
    });

    // Format output
    match format {
        cli::OutputFormat::Jsonl => Ok(serde_json::to_string_pretty(&symbols)?),
        cli::OutputFormat::Terminal => {
            let mut output = String::new();
            output.push_str(&format!(
                "Extracted {} symbols from {}\n\n",
                symbols.len(),
                target
            ));
            output.push_str(&format!(
                "{:<18} {:<12} {:<20} {}\n",
                "ADDRESS", "TYPE", "LIBRARY", "NAME"
            ));
            output.push_str(&format!(
                "{:-<18} {:-<12} {:-<20} {:-<30}\n",
                "", "", "", ""
            ));

            for sym in symbols {
                let addr = sym.address.unwrap_or_else(|| "-".to_string());
                let lib = sym.library.as_deref().unwrap_or("-");
                output.push_str(&format!(
                    "{:<18} {:<12} {:<20} {}\n",
                    addr, sym.symbol_type, lib, sym.name
                ));
            }

            Ok(output)
        }
    }
}

fn extract_sections(target: &str, format: &cli::OutputFormat) -> Result<String> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    let mut sections: Vec<SectionInfo> = Vec::new();

    // Detect file type
    if let Ok(file_type) = detect_file_type(path) {
        match file_type {
            FileType::Elf | FileType::MachO | FileType::Pe => {
                // Binary file - extract sections with addresses
                let capability_mapper = crate::capabilities::CapabilityMapper::empty();
                let report = match file_type {
                    FileType::Elf => ElfAnalyzer::new()
                        .with_capability_mapper(capability_mapper)
                        .analyze(path)?,
                    FileType::MachO => MachOAnalyzer::new()
                        .with_capability_mapper(capability_mapper)
                        .analyze(path)?,
                    FileType::Pe => PEAnalyzer::new()
                        .with_capability_mapper(capability_mapper)
                        .analyze(path)?,
                    _ => unreachable!(),
                };

                // Convert sections to output format
                for section in report.sections {
                    sections.push(SectionInfo {
                        name: section.name,
                        address: section.address.map(|addr| format!("0x{:x}", addr)),
                        size: section.size,
                        entropy: section.entropy,
                        permissions: section.permissions,
                    });
                }
            }
            _ => {
                anyhow::bail!(
                    "Unsupported file type for section extraction: {:?}. Only ELF, PE, and Mach-O binaries are supported.",
                    file_type
                );
            }
        }
    } else {
        anyhow::bail!("Unable to detect file type for: {}", target);
    }

    // Sort sections by address (if available), then by name
    sections.sort_by(|a, b| {
        match (&a.address, &b.address) {
            (Some(addr_a), Some(addr_b)) => {
                // Parse hex addresses for proper numeric sorting
                let parse_addr =
                    |s: &str| -> u64 { s.trim_start_matches("0x").parse::<u64>().unwrap_or(0) };
                let num_a = parse_addr(addr_a);
                let num_b = parse_addr(addr_b);
                num_a.cmp(&num_b)
            }
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.name.cmp(&b.name),
        }
    });

    // Format output
    match format {
        cli::OutputFormat::Jsonl => Ok(serde_json::to_string_pretty(&sections)?),
        cli::OutputFormat::Terminal => {
            let mut output = String::new();
            output.push_str(&format!(
                "Extracted {} sections from {}\n\n",
                sections.len(),
                target
            ));
            output.push_str(&format!(
                "{:<18} {:<30} {:<12} {:<10} {}\n",
                "ADDRESS", "NAME", "SIZE", "ENTROPY", "PERMISSIONS"
            ));
            output.push_str(&format!(
                "{:-<18} {:-<30} {:-<12} {:-<10} {:-<15}\n",
                "", "", "", "", ""
            ));

            for section in sections {
                let addr = section.address.unwrap_or_else(|| "-".to_string());
                let perms = section.permissions.as_deref().unwrap_or("-");
                output.push_str(&format!(
                    "{:<18} {:<30} {:<12} {:<10.2} {}\n",
                    addr, section.name, section.size, section.entropy, perms
                ));
            }

            Ok(output)
        }
    }
}

/// Extract computed metrics from a file
fn extract_metrics(
    target: &str,
    format: &cli::OutputFormat,
    _disabled: &cli::DisabledComponents,
) -> Result<String> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    // Detect file type
    let file_type = detect_file_type(path)?;

    // Create capability mapper (needed for analysis)
    let capability_mapper = crate::capabilities::CapabilityMapper::empty();

    // Analyze the file to compute metrics
    // Note: For metrics extraction, we use the empty capability mapper and rely on the
    // analyzers to compute metrics. Radare2 analysis can be slow, but it's controlled
    // by the --disable flag (already in disabled)
    let report = match file_type {
        FileType::Elf => {
            ElfAnalyzer::new()
                .with_capability_mapper(capability_mapper)
                .analyze(path)?
        }
        FileType::MachO => {
            MachOAnalyzer::new()
                .with_capability_mapper(capability_mapper)
                .analyze(path)?
        }
        FileType::Pe => {
            PEAnalyzer::new()
                .with_capability_mapper(capability_mapper)
                .analyze(path)?
        }
        _ => {
            // Use the generic analyzer for source code
            if let Some(analyzer) = analyzers::analyzer_for_file_type(&file_type, None) {
                analyzer.analyze(path)?
            } else {
                anyhow::bail!("Unsupported file type for metrics extraction: {:?}", file_type);
            }
        }
    };

    // Extract metrics from report and update binary metrics with report data
    let mut metrics = report.metrics.clone().ok_or_else(|| {
        anyhow::anyhow!("No metrics computed for file (file type may not support metrics)")
    })?;

    // Update binary metrics with counts from the report (these aren't populated by radare2)
    if let Some(ref mut binary) = metrics.binary {
        binary.import_count = report.imports.len() as u32;
        binary.export_count = report.exports.len() as u32;
        binary.string_count = report.strings.len() as u32;

        // Calculate string entropy metrics
        if !report.strings.is_empty() {
            use crate::entropy::calculate_entropy;
            let entropies: Vec<f64> = report.strings.iter()
                .map(|s| calculate_entropy(s.value.as_bytes()))
                .collect();

            let total_entropy: f64 = entropies.iter().sum();
            binary.avg_string_entropy = (total_entropy / entropies.len() as f64) as f32;
            binary.high_entropy_strings = entropies.iter().filter(|&&e| e > 6.0).count() as u32;
        }

        // Calculate binary entropy from sections if not already populated
        if binary.overall_entropy == 0.0 && !report.sections.is_empty() {
            use crate::entropy::calculate_entropy;

            let mut entropies = Vec::new();
            let mut code_entropies = Vec::new();
            let mut data_entropies = Vec::new();

            for section in &report.sections {
                let entropy = section.entropy as f32;
                entropies.push(entropy);

                // Track code vs data section entropy
                let name_lower = section.name.to_lowercase();
                let is_executable = section.permissions.as_ref()
                    .map(|p| p.contains('x'))
                    .unwrap_or(false);

                if name_lower.contains("text") || name_lower.contains("code") || is_executable {
                    code_entropies.push(entropy);
                } else if name_lower.contains("data") || name_lower.contains("rodata") {
                    data_entropies.push(entropy);
                }

                if entropy > 7.5 {
                    binary.high_entropy_regions += 1;
                }
            }

            if !entropies.is_empty() {
                binary.overall_entropy = entropies.iter().sum::<f32>() / entropies.len() as f32;

                let mean = binary.overall_entropy;
                let variance: f32 = entropies.iter()
                    .map(|e| (e - mean).powi(2))
                    .sum::<f32>() / entropies.len() as f32;
                binary.entropy_variance = variance.sqrt();
            }

            if !code_entropies.is_empty() {
                binary.code_entropy = code_entropies.iter().sum::<f32>() / code_entropies.len() as f32;
            }

            if !data_entropies.is_empty() {
                binary.data_entropy = data_entropies.iter().sum::<f32>() / data_entropies.len() as f32;
            }

            // If still zero, calculate from raw file data as fallback
            if binary.overall_entropy == 0.0 {
                let data = std::fs::read(path)?;
                binary.overall_entropy = calculate_entropy(&data) as f32;
            }
        }
    }

    // Format output
    match format {
        cli::OutputFormat::Jsonl => Ok(serde_json::to_string_pretty(&metrics)?),
        cli::OutputFormat::Terminal => {
            let mut output = String::new();
            output.push_str(&format!("Metrics for: {}\n", target));
            output.push_str(&format!("File type: {:?}\n\n", file_type));
            output.push_str("# Field paths for use in rules (type: metrics, field: <path>)\n\n");

            // Text metrics
            if let Some(text) = &metrics.text {
                output.push_str("## Text Metrics\n");
                output.push_str(&format!("text.char_entropy: {:.2}\n", text.char_entropy));
                output.push_str(&format!("text.avg_line_length: {:.1}\n", text.avg_line_length));
                output.push_str(&format!("text.max_line_length: {}\n", text.max_line_length));
                output.push_str(&format!("text.line_length_stddev: {:.1}\n", text.line_length_stddev));
                output.push_str(&format!("text.empty_line_ratio: {:.2}\n", text.empty_line_ratio));
                output.push_str(&format!("text.whitespace_ratio: {:.2}\n", text.whitespace_ratio));
                output.push_str(&format!("text.digit_ratio: {:.2}\n\n", text.digit_ratio));
            }

            // Identifier metrics
            if let Some(ident) = &metrics.identifiers {
                output.push_str("## Identifier Metrics\n");
                output.push_str(&format!("identifiers.total: {}\n", ident.total));
                output.push_str(&format!("identifiers.unique: {}\n", ident.unique));
                output.push_str(&format!("identifiers.reuse_ratio: {:.2}\n", ident.reuse_ratio));
                output.push_str(&format!("identifiers.avg_length: {:.1}\n", ident.avg_length));
                output.push_str(&format!("identifiers.avg_entropy: {:.2}\n", ident.avg_entropy));
                output.push_str(&format!("identifiers.high_entropy_ratio: {:.2}\n", ident.high_entropy_ratio));
                output.push_str(&format!("identifiers.single_char_count: {}\n", ident.single_char_count));
                output.push_str(&format!("identifiers.numeric_suffix_count: {}\n\n", ident.numeric_suffix_count));
            }

            // String metrics
            if let Some(strings) = &metrics.strings {
                output.push_str("## String Metrics\n");
                output.push_str(&format!("strings.total: {}\n", strings.total));
                output.push_str(&format!("strings.avg_entropy: {:.2}\n", strings.avg_entropy));
                output.push_str(&format!("strings.entropy_stddev: {:.2}\n", strings.entropy_stddev));
                output.push_str(&format!("strings.avg_length: {:.1}\n\n", strings.avg_length));
            }

            // Comment metrics
            if let Some(comments) = &metrics.comments {
                output.push_str("## Comment Metrics\n");
                output.push_str(&format!("comments.total: {}\n", comments.total));
                output.push_str(&format!("comments.to_code_ratio: {:.2}\n\n", comments.to_code_ratio));
            }

            // Function metrics
            if let Some(funcs) = &metrics.functions {
                output.push_str("## Function Metrics\n");
                output.push_str(&format!("functions.total: {}\n", funcs.total));
                output.push_str(&format!("functions.anonymous: {}\n", funcs.anonymous));
                output.push_str(&format!("functions.async_count: {}\n", funcs.async_count));
                output.push_str(&format!("functions.avg_length_lines: {:.1}\n", funcs.avg_length_lines));
                output.push_str(&format!("functions.max_length_lines: {}\n", funcs.max_length_lines));
                output.push_str(&format!("functions.length_stddev: {:.1}\n", funcs.length_stddev));
                output.push_str(&format!("functions.over_100_lines: {}\n", funcs.over_100_lines));
                output.push_str(&format!("functions.over_500_lines: {}\n", funcs.over_500_lines));
                output.push_str(&format!("functions.one_liners: {}\n", funcs.one_liners));
                output.push_str(&format!("functions.avg_params: {:.1}\n", funcs.avg_params));
                output.push_str(&format!("functions.max_params: {}\n", funcs.max_params));
                output.push_str(&format!("functions.many_params_count: {}\n", funcs.many_params_count));
                output.push_str(&format!("functions.max_nesting_depth: {}\n\n", funcs.max_nesting_depth));
            }

            // Binary metrics
            if let Some(binary) = &metrics.binary {
                output.push_str("## Binary Metrics\n");
                output.push_str(&format!("binary.overall_entropy: {:.2}\n", binary.overall_entropy));
                output.push_str(&format!("binary.code_entropy: {:.2}\n", binary.code_entropy));
                output.push_str(&format!("binary.data_entropy: {:.2}\n", binary.data_entropy));
                output.push_str(&format!("binary.entropy_variance: {:.2}\n", binary.entropy_variance));
                output.push_str(&format!("binary.high_entropy_regions: {}\n", binary.high_entropy_regions));
                output.push_str(&format!("binary.section_count: {}\n", binary.section_count));
                output.push_str(&format!("binary.executable_sections: {}\n", binary.executable_sections));
                output.push_str(&format!("binary.writable_sections: {}\n", binary.writable_sections));
                output.push_str(&format!("binary.wx_sections: {}\n", binary.wx_sections));
                output.push_str(&format!("binary.import_count: {}\n", binary.import_count));
                output.push_str(&format!("binary.export_count: {}\n", binary.export_count));
                output.push_str(&format!("binary.string_count: {}\n", binary.string_count));
                output.push_str(&format!("binary.avg_string_entropy: {:.2}\n", binary.avg_string_entropy));
                output.push_str(&format!("binary.high_entropy_strings: {}\n", binary.high_entropy_strings));
                output.push_str(&format!("binary.function_count: {}\n", binary.function_count));
                output.push_str(&format!("binary.avg_function_size: {:.1}\n", binary.avg_function_size));
                output.push_str(&format!("binary.avg_complexity: {:.1}\n", binary.avg_complexity));
                output.push_str(&format!("binary.max_complexity: {}\n", binary.max_complexity));
                output.push_str(&format!("binary.high_complexity_functions: {}\n", binary.high_complexity_functions));
                output.push_str(&format!("binary.total_basic_blocks: {}\n", binary.total_basic_blocks));
                output.push_str(&format!("binary.indirect_calls: {}\n", binary.indirect_calls));
                output.push_str(&format!("binary.indirect_jumps: {}\n", binary.indirect_jumps));
                if binary.has_overlay {
                    output.push_str(&format!("binary.overlay_size: {}\n", binary.overlay_size));
                    output.push_str(&format!("binary.overlay_entropy: {:.2}\n", binary.overlay_entropy));
                }
                output.push('\n');
            }

            // ELF-specific metrics
            if let Some(elf) = &metrics.elf {
                output.push_str("## ELF Metrics\n");
                output.push_str(&format!("elf.stripped: {}\n", elf.stripped));
                output.push_str(&format!("elf.nx_enabled: {}\n", elf.nx_enabled));
                output.push_str(&format!("elf.pie_enabled: {}\n", elf.pie_enabled));
                output.push_str(&format!("elf.stack_canary: {}\n", elf.stack_canary));
                if let Some(relro) = &elf.relro {
                    output.push_str(&format!("elf.relro: {}\n", relro));
                }
                output.push_str(&format!("elf.needed_libs: {}\n", elf.needed_libs));
                output.push_str(&format!("elf.rpath_set: {}\n", elf.rpath_set));
                output.push_str(&format!("elf.runpath_set: {}\n\n", elf.runpath_set));
            }

            // PE-specific metrics
            if let Some(pe) = &metrics.pe {
                output.push_str("## PE Metrics\n");
                output.push_str(&format!("pe.is_dotnet: {}\n", pe.is_dotnet));
                output.push_str(&format!("pe.has_signature: {}\n", pe.has_signature));
                output.push_str(&format!("pe.timestamp_anomaly: {}\n", pe.timestamp_anomaly));
                output.push_str(&format!("pe.rich_header_present: {}\n", pe.rich_header_present));
                output.push_str(&format!("pe.resource_count: {}\n", pe.resource_count));
                output.push_str(&format!("pe.rsrc_size: {}\n", pe.rsrc_size));
                output.push_str(&format!("pe.rsrc_entropy: {:.2}\n", pe.rsrc_entropy));
                output.push_str(&format!("pe.tls_callbacks: {}\n", pe.tls_callbacks));
                output.push_str(&format!("pe.suspicious_import_combo: {}\n\n", pe.suspicious_import_combo));
            }

            // Mach-O specific metrics
            if let Some(macho) = &metrics.macho {
                output.push_str("## Mach-O Metrics\n");
                output.push_str(&format!("macho.is_universal: {}\n", macho.is_universal));
                output.push_str(&format!("macho.slice_count: {}\n", macho.slice_count));
                output.push_str(&format!("macho.has_code_signature: {}\n", macho.has_code_signature));
                output.push_str(&format!("macho.hardened_runtime: {}\n", macho.hardened_runtime));
                output.push_str(&format!("macho.has_entitlements: {}\n", macho.has_entitlements));
                output.push_str(&format!("macho.dylib_count: {}\n", macho.dylib_count));
                output.push_str(&format!("macho.rpath_count: {}\n\n", macho.rpath_count));
            }

            // Language-specific metrics
            if let Some(py) = &metrics.python {
                output.push_str("## Python Metrics\n");
                output.push_str(&format!("python.eval_count: {}\n", py.eval_count));
                output.push_str(&format!("python.exec_count: {}\n", py.exec_count));
                output.push_str(&format!("python.decorator_count: {}\n", py.decorator_count));
                output.push_str(&format!("python.lambda_count: {}\n", py.lambda_count));
                output.push_str(&format!("python.comprehension_depth_max: {}\n", py.comprehension_depth_max));
                output.push_str(&format!("python.base64_calls: {}\n\n", py.base64_calls));
            }

            if let Some(js) = &metrics.javascript {
                output.push_str("## JavaScript Metrics\n");
                output.push_str(&format!("javascript.eval_count: {}\n", js.eval_count));
                output.push_str(&format!("javascript.arrow_function_count: {}\n", js.arrow_function_count));
                output.push_str(&format!("javascript.iife_count: {}\n", js.iife_count));
                output.push_str(&format!("javascript.from_char_code_count: {}\n", js.from_char_code_count));
                output.push_str(&format!("javascript.atob_btoa_count: {}\n", js.atob_btoa_count));
                output.push_str(&format!("javascript.innerhtml_writes: {}\n\n", js.innerhtml_writes));
            }

            if let Some(go) = &metrics.go_metrics {
                output.push_str("## Go Metrics\n");
                output.push_str(&format!("go_metrics.unsafe_usage: {}\n", go.unsafe_usage));
                output.push_str(&format!("go_metrics.reflect_usage: {}\n", go.reflect_usage));
                output.push_str(&format!("go_metrics.cgo_usage: {}\n", go.cgo_usage));
                output.push_str(&format!("go_metrics.exec_command_count: {}\n", go.exec_command_count));
                output.push_str(&format!("go_metrics.http_usage: {}\n", go.http_usage));
                output.push_str(&format!("go_metrics.syscall_direct: {}\n\n", go.syscall_direct));
            }

            if let Some(shell) = &metrics.shell {
                output.push_str("## Shell Metrics\n");
                output.push_str(&format!("shell.eval_count: {}\n", shell.eval_count));
                output.push_str(&format!("shell.exec_count: {}\n", shell.exec_count));
                output.push_str(&format!("shell.pipe_count: {}\n", shell.pipe_count));
                output.push_str(&format!("shell.pipe_depth_max: {}\n", shell.pipe_depth_max));
                output.push_str(&format!("shell.background_jobs: {}\n", shell.background_jobs));
                output.push_str(&format!("shell.curl_wget_count: {}\n", shell.curl_wget_count));
                output.push_str(&format!("shell.base64_decode_count: {}\n\n", shell.base64_decode_count));
            }

            Ok(output)
        }
    }
}

/// Debug rule evaluation - shows exactly why rules match or fail
fn test_rules_debug(
    target: &str,
    rules: &str,
    _disabled: &cli::DisabledComponents,
    platforms: Vec<composite_rules::Platform>,
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
) -> Result<String> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    eprintln!("Analyzing: {}", target);

    // Parse rule IDs, stripping trailing slashes
    let rule_ids: Vec<String> = rules
        .split(',')
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .collect();
    eprintln!("Debugging {} rule(s): {:?}", rule_ids.len(), rule_ids);

    // Detect file type
    let file_type = detect_file_type(path)?;
    eprintln!("Detected file type: {:?}", file_type);

    // Load capability mapper with full validation (test-rules is a developer command)
    let capability_mapper = crate::capabilities::CapabilityMapper::new_with_precision_thresholds(
        min_hostile_precision,
        min_suspicious_precision,
        true, // Always enable full validation for test-rules
    )
    .with_platforms(platforms.clone());

    // Read file data
    let binary_data = fs::read(path)?;

    // Create a basic report by analyzing the file
    let mut report = create_analysis_report(path, &file_type, &binary_data, &capability_mapper)?;

    // Evaluate traits first to populate findings
    capability_mapper.evaluate_and_merge_findings(&mut report, &binary_data, None);

    // Create debugger and debug each rule
    // Pass platforms from CLI for consistency with production evaluation
    let debugger = test_rules::RuleDebugger::new(
        &capability_mapper,
        &report,
        &binary_data,
        &capability_mapper.composite_rules,
        capability_mapper.trait_definitions(),
        platforms,
    );

    let mut results = Vec::new();
    for rule_id in &rule_ids {
        // First try exact match
        if let Some(result) = debugger.debug_rule(rule_id) {
            results.push(result);
        } else {
            // Check if this is a directory prefix - find all rules under it
            let rules_in_dir = find_rules_in_directory(&capability_mapper, rule_id);
            if !rules_in_dir.is_empty() {
                eprintln!(
                    "Warning: Rule '{}' not found, but found {} rules in directory:",
                    rule_id,
                    rules_in_dir.len()
                );
                for r in &rules_in_dir {
                    eprintln!("    - {}", r);
                }
                // Debug each rule in the directory
                for sub_rule_id in &rules_in_dir {
                    if let Some(result) = debugger.debug_rule(sub_rule_id) {
                        results.push(result);
                    }
                }
            } else {
                eprintln!("Warning: Rule '{}' not found", rule_id);
                // Search for similar rules
                let similar = find_similar_rules(&capability_mapper, rule_id);
                if !similar.is_empty() {
                    eprintln!("  Did you mean one of:");
                    for s in similar.iter().take(5) {
                        eprintln!("    - {}", s);
                    }
                }
            }
        }
    }

    // Format and return output
    Ok(test_rules::format_debug_output(&results))
}

/// Convert CLI file type enum to internal FileType
fn cli_file_type_to_internal(ft: cli::DetectFileType) -> FileType {
    match ft {
        cli::DetectFileType::Elf => FileType::Elf,
        cli::DetectFileType::Pe => FileType::Pe,
        cli::DetectFileType::Macho => FileType::MachO,
        cli::DetectFileType::JavaScript => FileType::JavaScript,
        cli::DetectFileType::Python => FileType::Python,
        cli::DetectFileType::Go => FileType::Go,
        cli::DetectFileType::Shell => FileType::Shell,
        cli::DetectFileType::Raw => FileType::Unknown,
    }
}

/// Helper function to extract metric value from a field path
fn get_metric_value(metrics: &types::Metrics, field: &str) -> Option<f64> {
    // Parse field path and get value
    match field {
        // Text metrics
        "text.char_entropy" => metrics.text.as_ref().map(|t| t.char_entropy as f64),
        "text.line_length_stddev" => metrics.text.as_ref().map(|t| t.line_length_stddev as f64),
        "text.avg_line_length" => metrics.text.as_ref().map(|t| t.avg_line_length as f64),
        "text.max_line_length" => metrics.text.as_ref().map(|t| t.max_line_length as f64),
        "text.empty_line_ratio" => metrics.text.as_ref().map(|t| t.empty_line_ratio as f64),
        "text.whitespace_ratio" => metrics.text.as_ref().map(|t| t.whitespace_ratio as f64),
        "text.digit_ratio" => metrics.text.as_ref().map(|t| t.digit_ratio as f64),

        // Identifier metrics
        "identifiers.total" => metrics.identifiers.as_ref().map(|i| i.total as f64),
        "identifiers.unique" => metrics.identifiers.as_ref().map(|i| i.unique as f64),
        "identifiers.reuse_ratio" => metrics.identifiers.as_ref().map(|i| i.reuse_ratio as f64),
        "identifiers.avg_length" => metrics.identifiers.as_ref().map(|i| i.avg_length as f64),
        "identifiers.avg_entropy" => metrics.identifiers.as_ref().map(|i| i.avg_entropy as f64),
        "identifiers.high_entropy_ratio" => metrics.identifiers.as_ref().map(|i| i.high_entropy_ratio as f64),
        "identifiers.single_char_count" => metrics.identifiers.as_ref().map(|i| i.single_char_count as f64),

        // String metrics
        "strings.total" => metrics.strings.as_ref().map(|s| s.total as f64),
        "strings.avg_entropy" => metrics.strings.as_ref().map(|s| s.avg_entropy as f64),
        "strings.entropy_stddev" => metrics.strings.as_ref().map(|s| s.entropy_stddev as f64),
        "strings.avg_length" => metrics.strings.as_ref().map(|s| s.avg_length as f64),

        // Comment metrics
        "comments.total" => metrics.comments.as_ref().map(|c| c.total as f64),
        "comments.to_code_ratio" => metrics.comments.as_ref().map(|c| c.to_code_ratio as f64),

        // Function metrics
        "functions.total" => metrics.functions.as_ref().map(|f| f.total as f64),
        "functions.anonymous" => metrics.functions.as_ref().map(|f| f.anonymous as f64),
        "functions.avg_length_lines" => metrics.functions.as_ref().map(|f| f.avg_length_lines as f64),
        "functions.max_length_lines" => metrics.functions.as_ref().map(|f| f.max_length_lines as f64),
        "functions.avg_params" => metrics.functions.as_ref().map(|f| f.avg_params as f64),
        "functions.max_params" => metrics.functions.as_ref().map(|f| f.max_params as f64),
        "functions.max_nesting_depth" => metrics.functions.as_ref().map(|f| f.max_nesting_depth as f64),

        // Binary metrics
        "binary.overall_entropy" => metrics.binary.as_ref().map(|b| b.overall_entropy as f64),
        "binary.code_entropy" => metrics.binary.as_ref().map(|b| b.code_entropy as f64),
        "binary.data_entropy" => metrics.binary.as_ref().map(|b| b.data_entropy as f64),
        "binary.section_count" => metrics.binary.as_ref().map(|b| b.section_count as f64),
        "binary.import_count" => metrics.binary.as_ref().map(|b| b.import_count as f64),
        "binary.export_count" => metrics.binary.as_ref().map(|b| b.export_count as f64),
        "binary.function_count" => metrics.binary.as_ref().map(|b| b.function_count as f64),
        "binary.avg_function_size" => metrics.binary.as_ref().map(|b| b.avg_function_size as f64),
        "binary.avg_complexity" => metrics.binary.as_ref().map(|b| b.avg_complexity as f64),
        "binary.max_complexity" => metrics.binary.as_ref().map(|b| b.max_complexity as f64),
        "binary.indirect_calls" => metrics.binary.as_ref().map(|b| b.indirect_calls as f64),
        "binary.indirect_jumps" => metrics.binary.as_ref().map(|b| b.indirect_jumps as f64),

        // Python metrics
        "python.eval_count" => metrics.python.as_ref().map(|p| p.eval_count as f64),
        "python.exec_count" => metrics.python.as_ref().map(|p| p.exec_count as f64),
        "python.decorator_count" => metrics.python.as_ref().map(|p| p.decorator_count as f64),
        "python.lambda_count" => metrics.python.as_ref().map(|p| p.lambda_count as f64),
        "python.comprehension_depth_max" => metrics.python.as_ref().map(|p| p.comprehension_depth_max as f64),
        "python.base64_calls" => metrics.python.as_ref().map(|p| p.base64_calls as f64),

        // JavaScript metrics
        "javascript.eval_count" => metrics.javascript.as_ref().map(|j| j.eval_count as f64),
        "javascript.arrow_function_count" => metrics.javascript.as_ref().map(|j| j.arrow_function_count as f64),
        "javascript.iife_count" => metrics.javascript.as_ref().map(|j| j.iife_count as f64),
        "javascript.from_char_code_count" => metrics.javascript.as_ref().map(|j| j.from_char_code_count as f64),
        "javascript.atob_btoa_count" => metrics.javascript.as_ref().map(|j| j.atob_btoa_count as f64),
        "javascript.innerhtml_writes" => metrics.javascript.as_ref().map(|j| j.innerhtml_writes as f64),

        // Go metrics
        "go_metrics.unsafe_usage" => metrics.go_metrics.as_ref().map(|g| g.unsafe_usage as f64),
        "go_metrics.reflect_usage" => metrics.go_metrics.as_ref().map(|g| g.reflect_usage as f64),
        "go_metrics.cgo_usage" => metrics.go_metrics.as_ref().map(|g| g.cgo_usage as f64),
        "go_metrics.exec_command_count" => metrics.go_metrics.as_ref().map(|g| g.exec_command_count as f64),
        "go_metrics.http_usage" => metrics.go_metrics.as_ref().map(|g| g.http_usage as f64),
        "go_metrics.syscall_direct" => metrics.go_metrics.as_ref().map(|g| g.syscall_direct as f64),

        // Shell metrics
        "shell.eval_count" => metrics.shell.as_ref().map(|s| s.eval_count as f64),
        "shell.exec_count" => metrics.shell.as_ref().map(|s| s.exec_count as f64),
        "shell.pipe_count" => metrics.shell.as_ref().map(|s| s.pipe_count as f64),
        "shell.pipe_depth_max" => metrics.shell.as_ref().map(|s| s.pipe_depth_max as f64),
        "shell.background_jobs" => metrics.shell.as_ref().map(|s| s.background_jobs as f64),
        "shell.curl_wget_count" => metrics.shell.as_ref().map(|s| s.curl_wget_count as f64),
        "shell.base64_decode_count" => metrics.shell.as_ref().map(|s| s.base64_decode_count as f64),

        _ => None,
    }
}

/// Test pattern matching against a file with alternative suggestions
#[allow(clippy::too_many_arguments)]
fn test_match_debug(
    target: &str,
    search_type: cli::SearchType,
    method: cli::MatchMethod,
    pattern: Option<&str>,
    kv_path: Option<&str>,
    file_type_override: Option<cli::DetectFileType>,
    count_min: usize,
    count_max: Option<usize>,
    per_kb_min: Option<f64>,
    per_kb_max: Option<f64>,
    case_insensitive: bool,
    section: Option<&str>,
    offset: Option<i64>,
    offset_range: Option<(i64, Option<i64>)>,
    section_offset: Option<i64>,
    section_offset_range: Option<(i64, Option<i64>)>,
    external_ip: bool,
    encoding: Option<&str>,
    entropy_min: Option<f64>,
    entropy_max: Option<f64>,
    length_min: Option<u64>,
    length_max: Option<u64>,
    value_min: Option<f64>,
    value_max: Option<f64>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    _disabled: &cli::DisabledComponents,
    platforms: Vec<composite_rules::Platform>,
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
) -> Result<String> {
    // Validate arguments based on search type
    if search_type == cli::SearchType::Kv {
        if kv_path.is_none() {
            anyhow::bail!("--kv-path is required for kv searches");
        }
    } else if search_type == cli::SearchType::Section {
        // Section searches don't require pattern (can search by length or entropy alone)
        let has_constraints = count_min > 1 || count_max.is_some() || length_min.is_some() || length_max.is_some() || entropy_min.is_some() || entropy_max.is_some();
        if pattern.is_none() && !has_constraints {
            anyhow::bail!("--pattern is required for section searches unless using size/entropy constraints (--count-min/max, --length-min/max, --entropy-min/max)");
        }
    } else if search_type == cli::SearchType::Metrics {
        if pattern.is_none() {
            anyhow::bail!("--pattern is required for metrics searches (use field path like 'binary.avg_complexity')");
        }
        if value_min.is_none() && value_max.is_none() {
            anyhow::bail!("At least one of --value-min or --value-max is required for metrics searches");
        }
    } else if pattern.is_none() {
        anyhow::bail!("--pattern is required for {:?} searches", search_type);
    }

    // Validate location constraints
    if offset.is_some() && offset_range.is_some() {
        anyhow::bail!("--offset and --offset-range are mutually exclusive");
    }
    if section_offset.is_some() && section_offset_range.is_some() {
        anyhow::bail!("--section-offset and --section-offset-range are mutually exclusive");
    }
    if (section_offset.is_some() || section_offset_range.is_some()) && section.is_none() {
        anyhow::bail!("--section-offset and --section-offset-range require --section");
    }

    let pattern = pattern.unwrap_or("");
    use crate::test_rules::{find_matching_strings, find_matching_symbols, RuleDebugger};
    use colored::Colorize;

    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    // Use specified file type or auto-detect
    let file_type = if let Some(ft) = file_type_override {
        cli_file_type_to_internal(ft)
    } else {
        detect_file_type(path)?
    };

    // Load capability mapper with full validation (test-match is a developer command)
    let capability_mapper = crate::capabilities::CapabilityMapper::new_with_precision_thresholds(
        min_hostile_precision,
        min_suspicious_precision,
        true, // Always enable full validation for test-match
    )
    .with_platforms(platforms.clone());

    // Read file data
    let binary_data = fs::read(path)?;

    // Create a basic report by analyzing the file
    let report = create_analysis_report(path, &file_type, &binary_data, &capability_mapper)?;

    // Create debugger to access search functions
    let debugger = RuleDebugger::new(
        &capability_mapper,
        &report,
        &binary_data,
        &capability_mapper.composite_rules,
        capability_mapper.trait_definitions(),
        platforms.clone(),
    );
    let context_info = debugger.context_info();

    // Create section map for location constraint resolution
    let section_map = composite_rules::SectionMap::from_binary(&binary_data);

    // Resolve effective byte range from location constraints
    // Returns (start, end, effective_size) where effective_size is used for density calculations
    let resolve_effective_range = |section: Option<&str>,
                                   offset: Option<i64>,
                                   offset_range: Option<(i64, Option<i64>)>,
                                   section_offset: Option<i64>,
                                   section_offset_range: Option<(i64, Option<i64>)>|
     -> Result<(usize, usize), String> {
        let file_size = binary_data.len();

        if let Some(sec) = section {
            if let Some(bounds) = section_map.bounds(sec) {
                let sec_start = bounds.0 as usize;
                let sec_end = bounds.1 as usize;
                let sec_size = sec_end - sec_start;

                if let Some(sec_off) = section_offset {
                    let abs_off = if sec_off >= 0 {
                        sec_start + sec_off as usize
                    } else {
                        sec_end.saturating_sub((-sec_off) as usize)
                    };
                    Ok((abs_off, abs_off.saturating_add(1).min(sec_end)))
                } else if let Some((start, end_opt)) = section_offset_range {
                    let rel_start = if start >= 0 {
                        start as usize
                    } else {
                        sec_size.saturating_sub((-start) as usize)
                    };
                    let rel_end = end_opt
                        .map(|e| {
                            if e >= 0 {
                                e as usize
                            } else {
                                sec_size.saturating_sub((-e) as usize)
                            }
                        })
                        .unwrap_or(sec_size);
                    Ok((
                        (sec_start + rel_start).min(sec_end),
                        (sec_start + rel_end).min(sec_end),
                    ))
                } else {
                    Ok((sec_start, sec_end))
                }
            } else {
                Err(format!("Section '{}' not found", sec))
            }
        } else if let Some(off) = offset {
            let abs_off = if off >= 0 {
                off as usize
            } else {
                file_size.saturating_sub((-off) as usize)
            };
            Ok((abs_off, abs_off.saturating_add(1).min(file_size)))
        } else if let Some((start, end_opt)) = offset_range {
            let abs_start = if start >= 0 {
                start as usize
            } else {
                file_size.saturating_sub((-start) as usize)
            };
            let abs_end = end_opt
                .map(|e| {
                    if e >= 0 {
                        e as usize
                    } else {
                        file_size.saturating_sub((-e) as usize)
                    }
                })
                .unwrap_or(file_size);
            Ok((abs_start.min(file_size), abs_end.min(file_size)))
        } else {
            Ok((0, file_size))
        }
    };

    // Check if any location constraints are specified
    let has_location_constraints = section.is_some()
        || offset.is_some()
        || offset_range.is_some()
        || section_offset.is_some()
        || section_offset_range.is_some();

    // Perform the requested search
    let (matched, _match_count, mut output): (bool, usize, String) = match search_type {
        cli::SearchType::String => {
            // Resolve effective range for filtering strings by offset
            let effective_range = resolve_effective_range(
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            );

            let (range_start, range_end) = match effective_range {
                Ok((s, e)) => (s, e),
                Err(msg) => {
                    let mut out = String::new();
                    out.push_str("Search: strings\n");
                    out.push_str(&format!("Pattern: {}\n", pattern));
                    out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                    out.push_str(&format!("{}\n", msg));
                    if section_map.has_sections() {
                        out.push_str(&format!(
                            "Available sections: {}\n",
                            section_map.section_names().join(", ")
                        ));
                    }
                    return Ok(out);
                }
            };

            // Filter strings by offset range if location constraints are specified
            let filtered_strings: Vec<&types::StringInfo> = if has_location_constraints {
                report
                    .strings
                    .iter()
                    .filter(|s| {
                        if let Some(off) = s.offset {
                            let off = off as usize;
                            off >= range_start && off < range_end
                        } else {
                            false // Skip strings without offset info
                        }
                    })
                    .collect()
            } else {
                report.strings.iter().collect()
            };

            let strings: Vec<&str> = filtered_strings.iter().map(|s| s.value.as_str()).collect();

            let exact = if method == cli::MatchMethod::Exact {
                Some(pattern.to_string())
            } else {
                None
            };
            let contains = if method == cli::MatchMethod::Contains {
                Some(pattern.to_string())
            } else {
                None
            };
            let regex = if method == cli::MatchMethod::Regex {
                Some(pattern.to_string())
            } else {
                None
            };
            let word = if method == cli::MatchMethod::Word {
                Some(pattern.to_string())
            } else {
                None
            };

            let matched_strings =
                find_matching_strings(&strings, &exact, &contains, &regex, &word, case_insensitive);

            // Filter by external IP if required
            let matched_strings: Vec<&str> = if external_ip {
                matched_strings
                    .into_iter()
                    .filter(|s| ip_validator::contains_external_ip(s))
                    .collect()
            } else {
                matched_strings
            };
            let match_count = matched_strings.len();

            // Use effective range size for density calculations when location constraints apply
            let effective_size = if has_location_constraints {
                range_end.saturating_sub(range_start)
            } else {
                binary_data.len()
            };
            let effective_size_kb = effective_size as f64 / 1024.0;
            let density = if effective_size_kb > 0.0 {
                match_count as f64 / effective_size_kb
            } else {
                0.0
            };

            // Check all constraints
            let count_min_ok = match_count >= count_min;
            let count_max_ok = count_max.is_none_or(|max| match_count <= max);
            let per_kb_min_ok = per_kb_min.is_none_or(|min| density >= min);
            let per_kb_max_ok = per_kb_max.is_none_or(|max| density <= max);
            let matched = count_min_ok && count_max_ok && per_kb_min_ok && per_kb_max_ok;

            let mut out = String::new();
            out.push_str("Search: strings\n");
            out.push_str(&format!("  count_min: {}", count_min));
            if let Some(max) = count_max {
                out.push_str(&format!(", count_max: {}", max));
            }
            if let Some(min) = per_kb_min {
                out.push_str(&format!(", per_kb_min: {:.2}", min));
            }
            if let Some(max) = per_kb_max {
                out.push_str(&format!(", per_kb_max: {:.2}", max));
            }
            if external_ip {
                out.push_str(", external_ip: true");
            }
            out.push('\n');
            out.push_str(&format!("Pattern: {}\n", pattern));

            // Show location constraints if specified
            if has_location_constraints {
                out.push_str(&format!(
                    "Search range: [{:#x}, {:#x}) of {} bytes\n",
                    range_start,
                    range_end,
                    binary_data.len()
                ));
            }

            out.push_str(&format!(
                "Context: file_type={:?}, strings={} (filtered from {})\n",
                file_type,
                filtered_strings.len(),
                report.strings.len()
            ));

            if matched {
                out.push_str(&format!(
                    "\n{} ({} matches, {:.3}/KB in search range)\n",
                    "MATCHED".green().bold(),
                    match_count,
                    density
                ));
                let display_count = match_count.min(10);
                for s in matched_strings.iter().take(display_count) {
                    out.push_str(&format!("  \"{}\"\n", s));
                }
                if match_count > display_count {
                    out.push_str(&format!("  ... and {} more\n", match_count - display_count));
                }
            } else {
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                out.push_str(&format!(
                    "Found {} matches ({:.3}/KB in search range)\n",
                    match_count, density
                ));
                // Show which constraints failed
                if !count_min_ok {
                    out.push_str(&format!(
                        "  count_min: {} < {} (FAILED)\n",
                        match_count, count_min
                    ));
                }
                if !count_max_ok {
                    out.push_str(&format!(
                        "  count_max: {} > {} (FAILED)\n",
                        match_count,
                        count_max.unwrap()
                    ));
                }
                if !per_kb_min_ok {
                    out.push_str(&format!(
                        "  per_kb_min: {:.3} < {:.3} (FAILED)\n",
                        density,
                        per_kb_min.unwrap()
                    ));
                }
                if !per_kb_max_ok {
                    out.push_str(&format!(
                        "  per_kb_max: {:.3} > {:.3} (FAILED)\n",
                        density,
                        per_kb_max.unwrap()
                    ));
                }
            }

            (matched, match_count, out)
        }
        cli::SearchType::Symbol => {
            let symbols: Vec<&str> = report
                .imports
                .iter()
                .map(|i| i.symbol.as_str())
                .chain(report.exports.iter().map(|e| e.symbol.as_str()))
                .chain(report.functions.iter().map(|f| f.name.as_str()))
                .collect();

            let exact = if method == cli::MatchMethod::Exact {
                Some(pattern.to_string())
            } else {
                None
            };
            let regex = if method == cli::MatchMethod::Regex {
                Some(pattern.to_string())
            } else {
                None
            };

            let matched_symbols =
                find_matching_symbols(&symbols, &exact, &None, &regex, case_insensitive);
            let matched = !matched_symbols.is_empty();

            let mut out = String::new();
            out.push_str("Search: symbols\n");
            if case_insensitive {
                out.push_str("  case_insensitive: true\n");
            }
            out.push_str(&format!("Pattern: {}\n", pattern));
            out.push_str(&format!(
                "Context: file_type={:?}, strings={}, symbols={}\n",
                file_type, context_info.string_count, context_info.symbol_count
            ));

            if matched {
                out.push_str(&format!(
                    "\n{} ({} matches)\n",
                    "MATCHED".green().bold(),
                    matched_symbols.len()
                ));
                let display_count = matched_symbols.len().min(10);
                for s in matched_symbols.iter().take(display_count) {
                    out.push_str(&format!("  \"{}\"\n", s));
                }
                if matched_symbols.len() > display_count {
                    out.push_str(&format!(
                        "  ... and {} more\n",
                        matched_symbols.len() - display_count
                    ));
                }
            } else {
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                out.push_str(&format!(
                    "Total symbols: {} ({} imports, {} exports)\n",
                    symbols.len(),
                    report.imports.len(),
                    report.exports.len()
                ));
            }

            (matched, matched_symbols.len(), out)
        }
        cli::SearchType::Raw => {
            // Resolve effective range for content search
            let effective_range = resolve_effective_range(
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            );

            let (range_start, range_end) = match effective_range {
                Ok((s, e)) => (s, e),
                Err(msg) => {
                    let mut out = String::new();
                    out.push_str("Search: content\n");
                    out.push_str(&format!("Pattern: {}\n", pattern));
                    out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                    out.push_str(&format!("{}\n", msg));
                    if section_map.has_sections() {
                        out.push_str(&format!(
                            "Available sections: {}\n",
                            section_map.section_names().join(", ")
                        ));
                    }
                    return Ok(out);
                }
            };

            // Slice binary data to effective range
            let search_data = &binary_data[range_start..range_end];
            let content = String::from_utf8_lossy(search_data);

            // Count all matches for density calculation
            // When external_ip is set, only count matches that contain external IPs
            let match_count = match method {
                // Exact: entire content slice must equal the pattern
                cli::MatchMethod::Exact => {
                    let matched = &*content == pattern;
                    if matched && external_ip {
                        if ip_validator::contains_external_ip(pattern) {
                            1
                        } else {
                            0
                        }
                    } else if matched {
                        1
                    } else {
                        0
                    }
                }
                cli::MatchMethod::Contains => {
                    if external_ip {
                        // For external_ip, we need to check context around each match
                        let mut count = 0;
                        let mut start = 0;
                        while let Some(pos) = content[start..].find(pattern) {
                            let abs_pos = start + pos;
                            // Get context around match to check for IP
                            let context_start = abs_pos.saturating_sub(50);
                            let context_end = (abs_pos + pattern.len() + 50).min(content.len());
                            let context = &content[context_start..context_end];
                            if ip_validator::contains_external_ip(context) {
                                count += 1;
                            }
                            start = abs_pos + 1;
                        }
                        count
                    } else {
                        content.matches(pattern).count()
                    }
                }
                cli::MatchMethod::Regex => regex::Regex::new(pattern)
                    .map(|re| {
                        if external_ip {
                            re.find_iter(&content)
                                .filter(|m| ip_validator::contains_external_ip(m.as_str()))
                                .count()
                        } else {
                            re.find_iter(&content).count()
                        }
                    })
                    .unwrap_or(0),
                cli::MatchMethod::Word => {
                    let word_pattern = format!(r"\b{}\b", regex::escape(pattern));
                    regex::Regex::new(&word_pattern)
                        .map(|re| {
                            if external_ip {
                                re.find_iter(&content)
                                    .filter(|m| ip_validator::contains_external_ip(m.as_str()))
                                    .count()
                            } else {
                                re.find_iter(&content).count()
                            }
                        })
                        .unwrap_or(0)
                }
            };

            // Use effective range size for density calculations
            let effective_size = range_end.saturating_sub(range_start);
            let effective_size_kb = effective_size as f64 / 1024.0;
            let density = if effective_size_kb > 0.0 {
                match_count as f64 / effective_size_kb
            } else {
                0.0
            };

            // Check all constraints
            let count_min_ok = match_count >= count_min;
            let count_max_ok = count_max.is_none_or(|max| match_count <= max);
            let per_kb_min_ok = per_kb_min.is_none_or(|min| density >= min);
            let per_kb_max_ok = per_kb_max.is_none_or(|max| density <= max);
            let matched = count_min_ok && count_max_ok && per_kb_min_ok && per_kb_max_ok;

            let mut out = String::new();
            out.push_str("Search: content\n");
            out.push_str(&format!("  count_min: {}", count_min));
            if let Some(max) = count_max {
                out.push_str(&format!(", count_max: {}", max));
            }
            if let Some(min) = per_kb_min {
                out.push_str(&format!(", per_kb_min: {:.2}", min));
            }
            if let Some(max) = per_kb_max {
                out.push_str(&format!(", per_kb_max: {:.2}", max));
            }
            if external_ip {
                out.push_str(", external_ip: true");
            }
            out.push('\n');
            out.push_str(&format!("Pattern: {}\n", pattern));

            // Show location constraints if specified
            if has_location_constraints {
                out.push_str(&format!(
                    "Search range: [{:#x}, {:#x}) of {} bytes\n",
                    range_start,
                    range_end,
                    binary_data.len()
                ));
            }

            out.push_str(&format!(
                "Context: file_type={:?}, search_size={} bytes\n",
                file_type, effective_size
            ));

            if matched {
                out.push_str(&format!(
                    "\n{} ({} matches, {:.3}/KB in search range)\n",
                    "MATCHED".green().bold(),
                    match_count,
                    density
                ));
            } else {
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                out.push_str(&format!(
                    "Found {} matches ({:.3}/KB in search range)\n",
                    match_count, density
                ));
                // Show which constraints failed
                if !count_min_ok {
                    out.push_str(&format!(
                        "  count_min: {} < {} (FAILED)\n",
                        match_count, count_min
                    ));
                }
                if !count_max_ok {
                    out.push_str(&format!(
                        "  count_max: {} > {} (FAILED)\n",
                        match_count,
                        count_max.unwrap()
                    ));
                }
                if !per_kb_min_ok {
                    out.push_str(&format!(
                        "  per_kb_min: {:.3} < {:.3} (FAILED)\n",
                        density,
                        per_kb_min.unwrap()
                    ));
                }
                if !per_kb_max_ok {
                    out.push_str(&format!(
                        "  per_kb_max: {:.3} > {:.3} (FAILED)\n",
                        density,
                        per_kb_max.unwrap()
                    ));
                }
            }

            (matched, match_count, out)
        }
        cli::SearchType::Kv => {
            let kv_path_str = kv_path.unwrap(); // Safe: validated above

            // Build the kv condition
            let exact = if method == cli::MatchMethod::Exact && !pattern.is_empty() {
                Some(pattern.to_string())
            } else {
                None
            };
            let substr = if method == cli::MatchMethod::Contains && !pattern.is_empty() {
                Some(pattern.to_string())
            } else {
                None
            };
            let regex_str = if method == cli::MatchMethod::Regex && !pattern.is_empty() {
                Some(pattern.to_string())
            } else {
                None
            };
            let compiled_regex = regex_str.as_ref().and_then(|r| regex::Regex::new(r).ok());

            let condition = composite_rules::Condition::Kv {
                path: kv_path_str.to_string(),
                exact: exact.clone(),
                substr: substr.clone(),
                regex: regex_str.clone(),
                case_insensitive,
                compiled_regex,
            };

            // Use the actual kv evaluator
            let evidence = composite_rules::evaluators::evaluate_kv(&condition, &binary_data, path);
            let _matched = evidence.is_some();

            let mut out = String::new();
            out.push_str("Search: kv (structured data)\n");
            out.push_str(&format!("Path: {}\n", kv_path_str));
            if !pattern.is_empty() {
                out.push_str(&format!(
                    "Pattern: {} ({})\n",
                    pattern,
                    format!("{:?}", method).to_lowercase()
                ));
            } else {
                out.push_str("Pattern: (existence check)\n");
            }
            out.push_str(&format!(
                "Context: file_type={:?}, file_size={} bytes\n",
                file_type,
                binary_data.len()
            ));

            if let Some(ev) = evidence {
                out.push_str(&format!("\n{}\n", "MATCHED".green().bold()));
                out.push_str(&format!("  Value: {}\n", ev.value));
                if let Some(loc) = &ev.location {
                    out.push_str(&format!("  Location: {}\n", loc));
                }
                (true, 1, out)
            } else {
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));

                // Try to parse and show available keys
                if let Ok(content) = std::str::from_utf8(&binary_data) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
                        if let Some(obj) = json.as_object() {
                            let keys: Vec<_> = obj.keys().take(15).collect();
                            out.push_str(&format!("Available top-level keys: {:?}\n", keys));
                        }
                    } else if let Ok(yaml) = serde_yaml::from_str::<serde_json::Value>(content) {
                        if let Some(obj) = yaml.as_object() {
                            let keys: Vec<_> = obj.keys().take(15).collect();
                            out.push_str(&format!("Available top-level keys: {:?}\n", keys));
                        }
                    }
                }

                (false, 0, out)
            }
        }
        cli::SearchType::Hex => {
            use composite_rules::evaluators::eval_hex;
            use composite_rules::SectionMap;

            // Create section map for location constraints
            let section_map = SectionMap::from_binary(&binary_data);

            // Resolve effective search range and convert to offset/offset_range for eval_hex
            let (effective_start, effective_end, _resolved_offset, _resolved_offset_range) =
                if let Some(sec) = section {
                    if let Some(bounds) = section_map.bounds(sec) {
                        // Apply section-relative offsets if specified
                        if let Some(sec_off) = section_offset {
                            let abs_off = if sec_off >= 0 {
                                bounds.0 + sec_off as u64
                            } else {
                                bounds.1.saturating_sub((-sec_off) as u64)
                            };
                            (
                                abs_off as usize,
                                (abs_off + 1) as usize,
                                Some(abs_off as i64),
                                None,
                            )
                        } else if let Some((start, end_opt)) = section_offset_range {
                            let section_size = bounds.1 - bounds.0;
                            let rel_start = if start >= 0 {
                                start as u64
                            } else {
                                section_size.saturating_sub((-start) as u64)
                            };
                            let rel_end = end_opt
                                .map(|e| {
                                    if e >= 0 {
                                        e as u64
                                    } else {
                                        section_size.saturating_sub((-e) as u64)
                                    }
                                })
                                .unwrap_or(section_size);
                            let abs_start = (bounds.0 + rel_start) as usize;
                            let abs_end = (bounds.0 + rel_end).min(bounds.1) as usize;
                            (
                                abs_start,
                                abs_end,
                                None,
                                Some((abs_start as i64, Some(abs_end as i64))),
                            )
                        } else {
                            // Entire section
                            (
                                bounds.0 as usize,
                                bounds.1 as usize,
                                None,
                                Some((bounds.0 as i64, Some(bounds.1 as i64))),
                            )
                        }
                    } else {
                        let mut out = String::new();
                        out.push_str("Search: hex\n");
                        out.push_str(&format!("Pattern: {}\n", pattern));
                        out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                        out.push_str(&format!("Section '{}' not found in binary\n", sec));
                        if section_map.has_sections() {
                            out.push_str(&format!(
                                "Available sections: {}\n",
                                section_map.section_names().join(", ")
                            ));
                        }
                        return Ok(out);
                    }
                } else if let Some(off) = offset {
                    let file_size = binary_data.len();
                    let abs_off = if off >= 0 {
                        off as usize
                    } else {
                        file_size.saturating_sub((-off) as usize)
                    };
                    (abs_off, abs_off + 1, offset, None)
                } else if let Some((start, end_opt)) = offset_range {
                    let file_size = binary_data.len();
                    let abs_start = if start >= 0 {
                        start as usize
                    } else {
                        file_size.saturating_sub((-start) as usize)
                    };
                    let abs_end = end_opt
                        .map(|e| {
                            if e >= 0 {
                                e as usize
                            } else {
                                file_size.saturating_sub((-e) as usize)
                            }
                        })
                        .unwrap_or(file_size);
                    (abs_start, abs_end.min(file_size), None, offset_range)
                } else {
                    (0, binary_data.len(), None, None)
                };

            // Create evaluation context
            let ctx = composite_rules::EvaluationContext::new(
                &report,
                &binary_data,
                composite_rules::FileType::All,
                platforms.clone(),
                None,
                None,
            );

            // Evaluate hex pattern with resolved location constraints
            let result = eval_hex(
                pattern,
                &composite_rules::evaluators::ContentLocationParams {
                    section: section.map(|s| s.to_string()),
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                },
                &ctx,
            );

            let match_count = result.evidence.len();
            let effective_size = effective_end.saturating_sub(effective_start);
            let effective_size_kb = effective_size as f64 / 1024.0;
            let density = if effective_size_kb > 0.0 {
                match_count as f64 / effective_size_kb
            } else {
                0.0
            };

            let mut out = String::new();
            out.push_str("Search: hex\n");
            out.push_str(&format!("Pattern: {}\n", pattern));

            // Show location constraints
            if let Some(sec) = section {
                out.push_str(&format!("Section: {}\n", sec));
            }
            if let Some(off) = offset {
                out.push_str(&format!("Offset: {:#x}\n", off));
            }
            if let Some((start, end_opt)) = offset_range {
                if let Some(end) = end_opt {
                    out.push_str(&format!("Offset range: [{:#x}, {:#x})\n", start, end));
                } else {
                    out.push_str(&format!("Offset range: [{:#x}, end)\n", start));
                }
            }

            out.push_str(&format!(
                "Context: file_type={:?}, file_size={} bytes",
                file_type,
                binary_data.len()
            ));
            if effective_size != binary_data.len() {
                out.push_str(&format!(
                    ", search_range=[{:#x},{:#x}) ({} bytes)",
                    effective_start, effective_end, effective_size
                ));
            }
            if section_map.has_sections() {
                out.push_str(&format!(", sections={}", section_map.section_names().len()));
            }
            out.push('\n');

            if result.matched {
                out.push_str(&format!(
                    "\n{} ({} matches, {:.3}/KB)\n",
                    "MATCHED".green().bold(),
                    match_count,
                    density
                ));
                let display_count = match_count.min(10);
                for ev in result.evidence.iter().take(display_count) {
                    out.push_str(&format!(
                        "  {} @ {}\n",
                        ev.value,
                        ev.location.as_deref().unwrap_or("?")
                    ));
                }
                if match_count > display_count {
                    out.push_str(&format!("  ... and {} more\n", match_count - display_count));
                }
            } else {
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                out.push_str(&format!(
                    "Found {} matches ({:.3}/KB)\n",
                    match_count, density
                ));

                // Show available sections as suggestion
                if section_map.has_sections() && section.is_none() {
                    out.push_str(&format!(
                        "\nBinary has sections: {} - try --section for targeted search\n",
                        section_map.section_names().join(", ")
                    ));
                }
            }

            (result.matched, match_count, out)
        }
        cli::SearchType::Encoded => {
            // Search in encoded/decoded strings with optional encoding filter
            // Parse encoding parameter: single ("base64"), multiple ("base64,hex"), or None (all)
            let encoding_filter: Option<Vec<String>> =
                encoding.map(|enc_str| enc_str.split(',').map(|s| s.trim().to_string()).collect());

            // Filter strings by encoding_chain
            let encoded_strings: Vec<&str> = report
                .strings
                .iter()
                .filter(|s| {
                    if s.encoding_chain.is_empty() {
                        return false; // Not an encoded string
                    }
                    match &encoding_filter {
                        None => true, // No filter: accept all encoded strings
                        Some(filters) => {
                            // Accept if ANY filter matches (OR logic)
                            filters.iter().any(|enc| s.encoding_chain.contains(enc))
                        }
                    }
                })
                .map(|s| s.value.as_str())
                .collect();

            let exact = if method == cli::MatchMethod::Exact {
                Some(pattern.to_string())
            } else {
                None
            };
            let contains = if method == cli::MatchMethod::Contains {
                Some(pattern.to_string())
            } else {
                None
            };
            let regex = if method == cli::MatchMethod::Regex {
                Some(pattern.to_string())
            } else {
                None
            };
            let word = if method == cli::MatchMethod::Word {
                Some(pattern.to_string())
            } else {
                None
            };

            let matched_strings = find_matching_strings(
                &encoded_strings,
                &exact,
                &contains,
                &regex,
                &word,
                case_insensitive,
            );

            // Filter by external IP if required
            let matched_strings: Vec<&str> = if external_ip {
                matched_strings
                    .into_iter()
                    .filter(|s| ip_validator::contains_external_ip(s))
                    .collect()
            } else {
                matched_strings
            };
            let match_count = matched_strings.len();

            let file_size_kb = binary_data.len() as f64 / 1024.0;
            let density = if file_size_kb > 0.0 {
                match_count as f64 / file_size_kb
            } else {
                0.0
            };

            let count_min_ok = match_count >= count_min;
            let count_max_ok = count_max.is_none_or(|max| match_count <= max);
            let per_kb_min_ok = per_kb_min.is_none_or(|min| density >= min);
            let per_kb_max_ok = per_kb_max.is_none_or(|max| density <= max);
            let matched = count_min_ok && count_max_ok && per_kb_min_ok && per_kb_max_ok;

            let mut out = String::new();
            if let Some(ref filters) = encoding_filter {
                out.push_str(&format!("Search: encoded ({})\n", filters.join(", ")));
            } else {
                out.push_str("Search: encoded (all encodings)\n");
            }
            out.push_str(&format!("  count_min: {}", count_min));
            if let Some(max) = count_max {
                out.push_str(&format!(", count_max: {}", max));
            }
            if let Some(min) = per_kb_min {
                out.push_str(&format!(", per_kb_min: {:.2}", min));
            }
            if let Some(max) = per_kb_max {
                out.push_str(&format!(", per_kb_max: {:.2}", max));
            }
            if external_ip {
                out.push_str(", external_ip: true");
            }
            out.push('\n');
            out.push_str(&format!("Pattern: {}\n", pattern));
            out.push_str(&format!(
                "Context: file_type={:?}, encoded_strings={} (from {} total strings)\n",
                file_type,
                encoded_strings.len(),
                report.strings.len()
            ));

            if matched {
                out.push_str(&format!(
                    "\n{} ({} matches, {:.3}/KB)\n",
                    "MATCHED".green().bold(),
                    match_count,
                    density
                ));
                let display_count = match_count.min(10);
                for s in matched_strings.iter().take(display_count) {
                    out.push_str(&format!("  \"{}\"\n", s));
                }
                if match_count > display_count {
                    out.push_str(&format!("  ... and {} more\n", match_count - display_count));
                }
            } else {
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                out.push_str(&format!(
                    "Found {} matches ({:.3}/KB)\n",
                    match_count, density
                ));
                if encoded_strings.is_empty() {
                    out.push_str("  No encoded strings found in this file\n");
                    if encoding_filter.is_some() {
                        out.push_str(
                            "  💡 Try removing --encoding to search all encoded strings\n",
                        );
                    }
                    out.push_str("  💡 Try `--type string` or `--type raw` instead\n");
                }
            }

            (matched, match_count, out)
        }
        cli::SearchType::Section => {
            // Search for sections by name, size, and/or entropy
            // count_min/count_max = number of matching sections
            // length_min/length_max = size of each section in bytes
            let sections: Vec<&types::Section> = report.sections.iter().collect();

            // Helper function to check if a section name matches the pattern
            let name_matches = |section_name: &str| -> bool {
                if pattern.is_empty() {
                    return true; // No pattern = match all names
                }

                let name = if case_insensitive {
                    section_name.to_lowercase()
                } else {
                    section_name.to_string()
                };
                let pat = if case_insensitive {
                    pattern.to_lowercase()
                } else {
                    pattern.to_string()
                };

                match method {
                    cli::MatchMethod::Exact => name == pat,
                    cli::MatchMethod::Contains => name.contains(&pat),
                    cli::MatchMethod::Regex => {
                        if let Ok(re) = regex::Regex::new(&pat) {
                            re.is_match(&name)
                        } else {
                            false
                        }
                    }
                    cli::MatchMethod::Word => {
                        // Word boundary match
                        let word_pattern = format!(r"\b{}\b", regex::escape(&pat));
                        if let Ok(re) = regex::Regex::new(&word_pattern) {
                            re.is_match(&name)
                        } else {
                            false
                        }
                    }
                }
            };

            // Filter sections by name pattern, length constraints, and entropy
            let matched_sections: Vec<&types::Section> = sections
                .into_iter()
                .filter(|sec| {
                    // Check name match
                    if !name_matches(&sec.name) {
                        return false;
                    }

                    // Check length constraints
                    if let Some(min) = length_min {
                        if sec.size < min {
                            return false;
                        }
                    }
                    if let Some(max) = length_max {
                        if sec.size > max {
                            return false;
                        }
                    }

                    // Check entropy constraints
                    if let Some(min) = entropy_min {
                        if sec.entropy < min {
                            return false;
                        }
                    }
                    if let Some(max) = entropy_max {
                        if sec.entropy > max {
                            return false;
                        }
                    }

                    true
                })
                .collect();

            let match_count = matched_sections.len();

            // Check count constraints (number of matching sections)
            let count_ok = match_count >= count_min && count_max.is_none_or(|max| match_count <= max);
            let matched = count_ok;

            let mut out = String::new();
            out.push_str("Search: sections\n");
            let mut constraints = Vec::new();
            if count_min > 1 {
                constraints.push(format!("count_min: {}", count_min));
            }
            if let Some(max) = count_max {
                constraints.push(format!("count_max: {}", max));
            }
            if let Some(min) = length_min {
                constraints.push(format!("length_min: {}", min));
            }
            if let Some(max) = length_max {
                constraints.push(format!("length_max: {}", max));
            }
            if let Some(min) = entropy_min {
                constraints.push(format!("entropy_min: {:.2}", min));
            }
            if let Some(max) = entropy_max {
                constraints.push(format!("entropy_max: {:.2}", max));
            }
            if !constraints.is_empty() {
                out.push_str(&format!("  {}\n", constraints.join(", ")));
            }
            if !pattern.is_empty() {
                out.push_str(&format!("Pattern: {}\n", pattern));
            }
            out.push_str(&format!(
                "Context: file_type={:?}, total_sections={}\n",
                file_type,
                report.sections.len()
            ));

            if matched {
                out.push_str(&format!(
                    "\n{} ({} sections matched)\n",
                    "MATCHED".green().bold(),
                    match_count
                ));
                for sec in matched_sections.iter().take(10) {
                    let addr_str = sec.address.map(|a| format!("0x{:x}", a)).unwrap_or_else(|| "-".to_string());
                    out.push_str(&format!(
                        "  {} (addr: {}, size: {}, entropy: {:.2})\n",
                        sec.name, addr_str, sec.size, sec.entropy
                    ));
                }
                if match_count > 10 {
                    out.push_str(&format!("  ... and {} more\n", match_count - 10));
                }
            } else {
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                if report.sections.is_empty() {
                    out.push_str("  No sections found (not a binary file?)\n");
                    out.push_str("  💡 Section search only works on ELF, PE, and Mach-O binaries\n");
                } else {
                    out.push_str(&format!("Found 0 matching sections (out of {} total)\n", report.sections.len()));
                    if !pattern.is_empty() {
                        out.push_str(&format!("  Available sections: {}\n",
                            report.sections.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")));
                    }
                }
            }

            (matched, match_count, out)
        }
        cli::SearchType::Metrics => {
            // Test metrics conditions using eval_metrics
            let field = pattern;

            let mut out = String::new();
            out.push_str("Search: metrics\n");
            out.push_str(&format!("Field: {}\n", field));
            if let Some(min) = value_min {
                out.push_str(&format!("Min value: {}\n", min));
            }
            if let Some(max) = value_max {
                out.push_str(&format!("Max value: {}\n", max));
            }
            if let Some(min) = min_size {
                out.push_str(&format!("Min file size: {} bytes\n", min));
            }
            if let Some(max) = max_size {
                out.push_str(&format!("Max file size: {} bytes\n", max));
            }

            // Create evaluation context
            let ctx = composite_rules::EvaluationContext::new(
                &report,
                &binary_data,
                composite_rules::FileType::All, // FileType doesn't matter for metrics
                platforms,
                None, // No additional findings
                None, // No cached AST
            );

            // Use eval_metrics from the composite_rules module
            let result = composite_rules::evaluators::eval_metrics(
                field,
                value_min,
                value_max,
                min_size,
                max_size,
                &ctx,
            );

            let matched = result.matched;
            let match_count = if matched { 1 } else { 0 };

            if matched {
                out.push_str(&format!("\n{}\n", "MATCHED".green().bold()));

                // Try to extract and display the actual metric value
                if let Some(metrics) = &report.metrics {
                    let value = get_metric_value(metrics, field);
                    if let Some(val) = value {
                        out.push_str(&format!("  Current value: {:.2}\n", val));
                    }
                }

                out.push_str(&format!("  File size: {} bytes\n", report.target.size_bytes));

                if !result.warnings.is_empty() {
                    out.push_str("\n  Warnings:\n");
                    for warning in &result.warnings {
                        out.push_str(&format!("    - {:?}\n", warning));
                    }
                }
            } else {
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));

                // Show current value for debugging
                if let Some(metrics) = &report.metrics {
                    let value = get_metric_value(metrics, field);
                    if let Some(val) = value {
                        out.push_str(&format!("  Current value: {:.2}\n", val));
                        if let Some(min) = value_min {
                            if val < min {
                                out.push_str(&format!("  ❌ Value {:.2} is below minimum {:.2}\n", val, min));
                            }
                        }
                        if let Some(max) = value_max {
                            if val > max {
                                out.push_str(&format!("  ❌ Value {:.2} exceeds maximum {:.2}\n", val, max));
                            }
                        }
                    } else {
                        out.push_str(&format!("  Metric field '{}' not found or not applicable to this file type\n", field));
                    }
                } else {
                    out.push_str("  No metrics available for this file\n");
                }

                // Show file size constraint failures
                let file_size = report.target.size_bytes;
                if let Some(min) = min_size {
                    if file_size < min {
                        out.push_str(&format!("  ❌ File size {} bytes is below minimum {} bytes\n", file_size, min));
                    }
                }
                if let Some(max) = max_size {
                    if file_size > max {
                        out.push_str(&format!("  ❌ File size {} bytes exceeds maximum {} bytes\n", file_size, max));
                    }
                }
            }

            (matched, match_count, out)
        }
    };

    // If not matched, provide suggestions
    if !matched {
        output.push_str("\nSuggestions:\n");

        // Check alternative search types
        match search_type {
            cli::SearchType::String => {
                // Check if pattern exists in symbols
                let symbols: Vec<&str> = report
                    .imports
                    .iter()
                    .map(|i| i.symbol.as_str())
                    .chain(report.exports.iter().map(|e| e.symbol.as_str()))
                    .chain(report.functions.iter().map(|f| f.name.as_str()))
                    .collect();
                let exact = if method == cli::MatchMethod::Exact {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let regex = if method == cli::MatchMethod::Regex {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let symbol_matches = find_matching_symbols(&symbols, &exact, &None, &regex, false);
                if !symbol_matches.is_empty() {
                    output.push_str(&format!(
                        "  💡 Found in symbols ({} matches) - try `--type symbol`\n",
                        symbol_matches.len()
                    ));
                }

                // Check if pattern exists in content
                let content = String::from_utf8_lossy(&binary_data);
                let content_matched = match method {
                    cli::MatchMethod::Exact => content.contains(pattern),
                    cli::MatchMethod::Contains => content.contains(pattern),
                    cli::MatchMethod::Regex => {
                        regex::Regex::new(pattern).is_ok_and(|re| re.is_match(&content))
                    }
                    cli::MatchMethod::Word => {
                        let word_pattern = format!(r"\b{}\b", regex::escape(pattern));
                        regex::Regex::new(&word_pattern).is_ok_and(|re| re.is_match(&content))
                    }
                };
                if content_matched {
                    output.push_str("  💡 Found in content - try `--type raw`\n");
                }
            }
            cli::SearchType::Symbol => {
                // Check if pattern exists in strings (try exact first, then contains)
                let strings: Vec<&str> = report.strings.iter().map(|s| s.value.as_str()).collect();
                let exact = if method == cli::MatchMethod::Exact {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let contains = if method == cli::MatchMethod::Contains {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let regex = if method == cli::MatchMethod::Regex {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let word = if method == cli::MatchMethod::Word {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let string_matches = find_matching_strings(
                    &strings,
                    &exact,
                    &contains,
                    &regex,
                    &word,
                    case_insensitive,
                );
                if !string_matches.is_empty() {
                    output.push_str(&format!(
                        "  💡 Found in strings ({} matches) - try `--type string`\n",
                        string_matches.len()
                    ));
                } else if method == cli::MatchMethod::Exact {
                    // Also try contains for exact searches
                    let contains_matches = find_matching_strings(
                        &strings,
                        &None,
                        &Some(pattern.to_string()),
                        &None,
                        &None,
                        case_insensitive,
                    );
                    if !contains_matches.is_empty() {
                        output.push_str(&format!(
                            "  💡 Found in strings ({} substring matches) - try `--type string --method contains`\n",
                            contains_matches.len()
                        ));
                    }
                }

                // Check if pattern exists in content
                let content = String::from_utf8_lossy(&binary_data);
                let content_matched = match method {
                    cli::MatchMethod::Exact => content.contains(pattern),
                    cli::MatchMethod::Contains => content.contains(pattern),
                    cli::MatchMethod::Regex => {
                        regex::Regex::new(pattern).is_ok_and(|re| re.is_match(&content))
                    }
                    cli::MatchMethod::Word => {
                        let word_pattern = format!(r"\b{}\b", regex::escape(pattern));
                        regex::Regex::new(&word_pattern).is_ok_and(|re| re.is_match(&content))
                    }
                };
                if content_matched {
                    output.push_str("  💡 Found in content - try `--type raw`\n");
                }
            }
            cli::SearchType::Raw => {
                // Check if pattern exists in strings
                let strings: Vec<&str> = report.strings.iter().map(|s| s.value.as_str()).collect();
                let exact = if method == cli::MatchMethod::Exact {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let contains = if method == cli::MatchMethod::Contains {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let regex = if method == cli::MatchMethod::Regex {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let word = if method == cli::MatchMethod::Word {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let string_matches = find_matching_strings(
                    &strings,
                    &exact,
                    &contains,
                    &regex,
                    &word,
                    case_insensitive,
                );
                if !string_matches.is_empty() {
                    output.push_str(&format!(
                        "  💡 Found in strings ({} matches) - try `--type string`\n",
                        string_matches.len()
                    ));
                }

                // Check if pattern exists in symbols
                let symbols: Vec<&str> = report
                    .imports
                    .iter()
                    .map(|i| i.symbol.as_str())
                    .chain(report.exports.iter().map(|e| e.symbol.as_str()))
                    .chain(report.functions.iter().map(|f| f.name.as_str()))
                    .collect();
                let symbol_matches = find_matching_symbols(&symbols, &exact, &None, &regex, false);
                if !symbol_matches.is_empty() {
                    output.push_str(&format!(
                        "  💡 Found in symbols ({} matches) - try `--type symbol`\n",
                        symbol_matches.len()
                    ));
                }
            }
            cli::SearchType::Kv => {
                // No cross-search suggestions for kv - it's a different paradigm
                output.push_str("  💡 Check that the path exists in the file structure\n");
                output.push_str("  💡 Try without a pattern for existence check\n");
            }
            cli::SearchType::Hex => {
                // Suggest content search as alternative
                output.push_str("  💡 Try --type raw for string-based search\n");
                output.push_str("  💡 Ensure hex pattern has correct format: \"7F 45 4C 46\"\n");
                output
                    .push_str("  💡 Try --offset or --offset-range to target specific locations\n");
            }
            cli::SearchType::Encoded => {
                output.push_str(
                    "  💡 Encoded search looks for decoded strings (base64, hex, xor, etc.)\n",
                );
                output.push_str("  💡 Use --encoding to filter by type: --encoding base64\n");
                output.push_str("  💡 Try `--type string` for regular strings\n");
                output.push_str("  💡 Try `--type raw` for raw content search\n");
            }
            cli::SearchType::Section => {
                output.push_str("  💡 Section search matches binary section metadata\n");
                if pattern.is_empty() && entropy_min.is_none() && entropy_max.is_none() && length_min.is_none() && length_max.is_none() && count_min <= 1 && count_max.is_none() {
                    output.push_str("  💡 Specify --pattern for name matching\n");
                    output.push_str("  💡 Use --entropy-min/--entropy-max for entropy constraints\n");
                    output.push_str("  💡 Use --length-min/--length-max for section size constraints\n");
                    output.push_str("  💡 Use --count-min/--count-max for number of matching sections\n");
                }
                if !report.sections.is_empty() {
                    output.push_str(&format!("  Available sections: {}\n",
                        report.sections.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")));
                }
            }
            cli::SearchType::Metrics => {
                output.push_str("  💡 Metrics search tests computed file metrics against thresholds\n");
                output.push_str("  💡 Use --pattern for field path (e.g., 'binary.avg_complexity')\n");
                output.push_str("  💡 Use --value-min/--value-max for thresholds\n");
                output.push_str("  💡 Use --min-size/--max-size for file size constraints\n");
                if let Some(metrics) = &report.metrics {
                    output.push_str("\n  Available metric fields:\n");
                    if metrics.binary.is_some() {
                        output.push_str("    binary.overall_entropy, binary.avg_complexity, binary.import_count, ...\n");
                    }
                    if metrics.text.is_some() {
                        output.push_str("    text.char_entropy, text.avg_line_length, ...\n");
                    }
                    if metrics.functions.is_some() {
                        output.push_str("    functions.total, functions.avg_params, functions.max_nesting_depth, ...\n");
                    }
                    if metrics.identifiers.is_some() {
                        output.push_str("    identifiers.avg_entropy, identifiers.reuse_ratio, ...\n");
                    }
                    output.push_str("  Run `dissect metrics <file>` to see all available fields\n");
                } else {
                    output.push_str("  ⚠️  No metrics available for this file type\n");
                }
            }
        }

        // Suggest alternative match methods
        output.push_str("\n  Try different match methods:\n");
        match method {
            cli::MatchMethod::Exact => {
                output.push_str("    --method contains (substring match)\n");
                output.push_str("    --method regex (pattern match)\n");
            }
            cli::MatchMethod::Contains => {
                output.push_str("    --method exact (exact match)\n");
                output.push_str("    --method regex (pattern match)\n");
            }
            cli::MatchMethod::Regex => {
                output.push_str("    --method contains (substring match)\n");
                output.push_str("    --method exact (exact match)\n");
            }
            cli::MatchMethod::Word => {
                output.push_str("    --method contains (substring match)\n");
                output.push_str("    --method regex (pattern match)\n");
            }
        }

        // Check if pattern would match with different file types
        output.push_str("\n  File type analysis:\n");
        output.push_str(&format!("    Current file type: {:?}\n", file_type));

        // Try analyzing as different file types
        let alternative_types = vec![
            ("ELF", FileType::Elf),
            ("PE", FileType::Pe),
            ("Mach-O", FileType::MachO),
            ("JavaScript", FileType::JavaScript),
            ("Python", FileType::Python),
            ("Go", FileType::Go),
        ];

        for (type_name, alt_type) in alternative_types {
            if alt_type != file_type {
                // Try to create a report with alternative file type
                if let Ok(alt_report) =
                    create_analysis_report(path, &alt_type, &binary_data, &capability_mapper)
                {
                    let alt_debugger = RuleDebugger::new(
                        &capability_mapper,
                        &alt_report,
                        &binary_data,
                        &capability_mapper.composite_rules,
                        capability_mapper.trait_definitions(),
                        vec![composite_rules::Platform::All], // Check all platforms for alt file types
                    );
                    let alt_context = alt_debugger.context_info();

                    // Quick check if search would work with this type
                    let would_match = match search_type {
                        cli::SearchType::String => {
                            let strings: Vec<&str> = alt_report
                                .strings
                                .iter()
                                .map(|s| s.value.as_str())
                                .collect();
                            let exact = if method == cli::MatchMethod::Exact {
                                Some(pattern.to_string())
                            } else {
                                None
                            };
                            let contains = if method == cli::MatchMethod::Contains {
                                Some(pattern.to_string())
                            } else {
                                None
                            };
                            let regex = if method == cli::MatchMethod::Regex {
                                Some(pattern.to_string())
                            } else {
                                None
                            };
                            let word = if method == cli::MatchMethod::Word {
                                Some(pattern.to_string())
                            } else {
                                None
                            };
                            let matches = find_matching_strings(
                                &strings,
                                &exact,
                                &contains,
                                &regex,
                                &word,
                                case_insensitive,
                            );
                            !matches.is_empty()
                        }
                        cli::SearchType::Symbol => {
                            let symbols: Vec<&str> = alt_report
                                .imports
                                .iter()
                                .map(|i| i.symbol.as_str())
                                .chain(alt_report.exports.iter().map(|e| e.symbol.as_str()))
                                .chain(alt_report.functions.iter().map(|f| f.name.as_str()))
                                .collect();
                            let exact = if method == cli::MatchMethod::Exact {
                                Some(pattern.to_string())
                            } else {
                                None
                            };
                            let regex = if method == cli::MatchMethod::Regex {
                                Some(pattern.to_string())
                            } else {
                                None
                            };
                            let matches =
                                find_matching_symbols(&symbols, &exact, &None, &regex, false);
                            !matches.is_empty()
                        }
                        cli::SearchType::Raw => {
                            let content = String::from_utf8_lossy(&binary_data);
                            match method {
                                cli::MatchMethod::Exact => content.contains(pattern),
                                cli::MatchMethod::Contains => content.contains(pattern),
                                cli::MatchMethod::Regex => {
                                    regex::Regex::new(pattern).is_ok_and(|re| re.is_match(&content))
                                }
                                cli::MatchMethod::Word => {
                                    let word_pattern = format!(r"\b{}\b", regex::escape(pattern));
                                    regex::Regex::new(&word_pattern)
                                        .is_ok_and(|re| re.is_match(&content))
                                }
                            }
                        }
                        cli::SearchType::Kv => {
                            // kv searches don't benefit from file type changes
                            false
                        }
                        cli::SearchType::Hex => {
                            // hex searches don't benefit from file type changes
                            false
                        }
                        cli::SearchType::Encoded => {
                            // encoded string searches depend on string extraction
                            false
                        }
                        cli::SearchType::Section => {
                            // Section searches are binary-specific
                            false
                        }
                        cli::SearchType::Metrics => {
                            // Metrics searches depend on metrics availability for the file type
                            false
                        }
                    };

                    if would_match {
                        output.push_str(&format!(
                            "    💡 Would match if file type was: {} (strings: {}, symbols: {})\n",
                            type_name, alt_context.string_count, alt_context.symbol_count
                        ));
                    }
                }
            }
        }
    }

    Ok(output)
}

/// Create a basic analysis report for the file
fn create_analysis_report(
    path: &Path,
    file_type: &FileType,
    binary_data: &[u8],
    capability_mapper: &crate::capabilities::CapabilityMapper,
) -> Result<types::AnalysisReport> {
    use sha2::{Digest, Sha256};

    // Route to appropriate analyzer to get a full report
    let report = if let Some(analyzer) =
        analyzers::analyzer_for_file_type(file_type, Some(capability_mapper.clone()))
    {
        analyzer.analyze(path)?
    } else {
        // Fallback: create minimal report for unsupported types
        let mut hasher = Sha256::new();
        hasher.update(binary_data);
        let sha256 = format!("{:x}", hasher.finalize());

        let target = types::TargetInfo {
            path: path.display().to_string(),
            file_type: format!("{:?}", file_type).to_lowercase(),
            size_bytes: binary_data.len() as u64,
            sha256,
            architectures: None,
        };

        types::AnalysisReport::new(target)
    };

    Ok(report)
}

/// Find similar rule IDs for suggestions
fn find_similar_rules(mapper: &crate::capabilities::CapabilityMapper, query: &str) -> Vec<String> {
    let query_lower = query.to_lowercase();
    let mut matches: Vec<(String, usize)> = Vec::new();

    // Check composite rules
    for rule in &mapper.composite_rules {
        let id_lower = rule.id.to_lowercase();
        if id_lower.contains(&query_lower) || query_lower.contains(&id_lower) {
            let score = strsim::levenshtein(&query_lower, &id_lower);
            matches.push((rule.id.clone(), score));
        } else {
            let score = strsim::levenshtein(&query_lower, &id_lower);
            if score < 15 {
                matches.push((rule.id.clone(), score));
            }
        }
    }

    // Check trait definitions
    for trait_def in mapper.trait_definitions() {
        let id_lower = trait_def.id.to_lowercase();
        if id_lower.contains(&query_lower) || query_lower.contains(&id_lower) {
            let score = strsim::levenshtein(&query_lower, &id_lower);
            matches.push((trait_def.id.clone(), score));
        } else {
            let score = strsim::levenshtein(&query_lower, &id_lower);
            if score < 15 {
                matches.push((trait_def.id.clone(), score));
            }
        }
    }

    // Sort by similarity score
    matches.sort_by_key(|(_, score)| *score);
    matches.into_iter().map(|(id, _)| id).collect()
}

/// Find all rules (traits and composites) that are in a given directory prefix
fn find_rules_in_directory(
    mapper: &crate::capabilities::CapabilityMapper,
    directory: &str,
) -> Vec<String> {
    let prefix = format!("{}/", directory);
    let mut rules = Vec::new();

    // Check trait definitions
    for trait_def in mapper.trait_definitions() {
        if trait_def.id.starts_with(&prefix) {
            rules.push(trait_def.id.clone());
        }
    }

    // Check composite rules
    for rule in &mapper.composite_rules {
        if rule.id.starts_with(&prefix) {
            rules.push(rule.id.clone());
        }
    }

    // Sort alphabetically
    rules.sort();
    rules.dedup();
    rules
}
