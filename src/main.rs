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
mod output;
mod path_mapper;
mod radare2;
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
use rayon::prelude::*;
use serde::Serialize;
use std::fs;
use std::io::{BufRead, IsTerminal};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::debug;
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
        EnvFilter::new("dissect=debug")
    } else {
        EnvFilter::new("dissect=info")
    };

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_line_number(true)
        .with_writer(std::io::stderr)
        .init();

    debug!("Logging initialized (verbose={})", args.verbose);

    // Configure rayon thread pool with larger stack size to handle deeply nested ASTs
    // (e.g., minified JavaScript, malicious files with extreme nesting)
    // Default is ~2MB which can overflow on files with 1000+ nesting levels
    rayon::ThreadPoolBuilder::new()
        .stack_size(8 * 1024 * 1024) // 8MB per thread
        .build_global()
        .ok(); // Ignore error if pool already initialized (e.g., in tests)

    // Get disabled components
    let disabled = args.disabled_components();

    // Apply global disables for radare2 and upx
    if disabled.radare2 {
        radare2::disable_radare2();
    }
    if disabled.upx {
        upx::disable_upx();
    }

    // Print banner to stderr (status info never goes to stdout)
    eprintln!("DISSECT v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("Deep static analysis tool\n");
    if disabled.any_disabled() {
        eprintln!(
            "Disabled components: {}",
            disabled.disabled_names().join(", ")
        );
    }

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
        )?,
        Some(cli::Command::Diff { old, new }) => diff_analysis(&old, &new, &format)?,
        Some(cli::Command::Strings { target, min_length }) => {
            extract_strings(&target, min_length, &format)?
        }
        Some(cli::Command::Symbols { target }) => extract_symbols(&target, &format)?,
        Some(cli::Command::TestRules { target, rules }) => {
            test_rules_debug(&target, &rules, &disabled)?
        }
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

    Ok(())
}
fn analyze_file(
    target: &str,
    enable_third_party_yara: bool,
    format: &cli::OutputFormat,
    zip_passwords: &[String],
    disabled: &cli::DisabledComponents,
    error_if_levels: Option<&[types::Criticality]>,
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
        );
    }

    // Status messages go to stderr
    eprintln!("Analyzing: {}", target);

    // Detect file type first (fast - just reads magic bytes)
    let file_type = detect_file_type(path)?;
    eprintln!("Detected file type: {:?}", file_type);

    // Load capability mapper
    let t1 = std::time::Instant::now();
    let capability_mapper = crate::capabilities::CapabilityMapper::new();
    eprintln!("[TIMING] CapabilityMapper::new(): {:?}", t1.elapsed());

    // Load YARA rules (unless YARA is disabled)
    let mut yara_engine = if disabled.yara {
        eprintln!("[INFO] YARA scanning disabled");
        None
    } else {
        let t_yara_start = std::time::Instant::now();
        let empty_mapper = crate::capabilities::CapabilityMapper::empty();
        let mut engine = YaraEngine::new_with_mapper(empty_mapper);
        let (builtin_count, third_party_count) = engine.load_all_rules(enable_third_party_yara)?;
        eprintln!("[TIMING] YaraEngine load: {:?}", t_yara_start.elapsed());
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
    let t3 = std::time::Instant::now();
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
                .with_zip_passwords(zip_passwords.to_vec());
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
        FileType::Archive => {
            let mut analyzer = ArchiveAnalyzer::new()
                .with_capability_mapper(capability_mapper.clone())
                .with_zip_passwords(zip_passwords.to_vec());
            if let Some(engine) = yara_engine.take() {
                analyzer = analyzer.with_yara(engine);
            }
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

    eprintln!("[TIMING] Analysis: {:?}", t3.elapsed());

    // Check if report's criticality matches --error-if criteria
    check_criticality_error(&report, error_if_levels)?;

    // Format output based on requested format
    let t4 = std::time::Instant::now();
    let result = match format {
        cli::OutputFormat::Json => output::format_json(&report),
        cli::OutputFormat::Terminal => output::format_terminal(&report),
    };
    eprintln!("[TIMING] Output format: {:?}", t4.elapsed());

    result
}

fn scan_paths(
    paths: Vec<String>,
    enable_third_party_yara: bool,
    format: &cli::OutputFormat,
    zip_passwords: &[String],
    disabled: &cli::DisabledComponents,
    error_if_levels: Option<&[types::Criticality]>,
) -> Result<String> {
    use indicatif::{ProgressBar, ProgressStyle};
    use walkdir::WalkDir;

    eprintln!("Scanning {} path(s)...\n", paths.len());

    // Load capability mapper once and share across all threads
    let capability_mapper = Arc::new(crate::capabilities::CapabilityMapper::new());

    // Collect all files from paths (expanding directories recursively)
    let mut all_files = Vec::new();
    let mut archives_found = Vec::new();

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
                        all_files.push(file_path);
                    }
                }
            }
        }
    }

    eprintln!(
        "Found {} files and {} archives to analyze\n",
        all_files.len(),
        archives_found.len()
    );

    // Create progress bar for terminal output only when stdout is a TTY
    let total_items = all_files.len() + archives_found.len();
    let is_tty = std::io::stdout().is_terminal();
    let pb = if matches!(format, cli::OutputFormat::Terminal) && is_tty {
        let bar = ProgressBar::new(total_items as u64);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("█▓▒░ "),
        );
        Some(Arc::new(bar))
    } else {
        None
    };

    // Use Mutex to safely collect results from parallel threads
    let all_reports = Arc::new(Mutex::new(Vec::new()));

    // Process regular files in parallel
    all_files.par_iter().for_each(|path_str| {
        let path = Path::new(&path_str);

        if let Some(ref bar) = pb {
            bar.set_message(format!(
                "Analyzing {}",
                path.file_name().unwrap_or_default().to_string_lossy()
            ));
        }

        match analyze_file_with_shared_mapper(
            path_str,
            enable_third_party_yara,
            &capability_mapper,
            zip_passwords,
            disabled,
            error_if_levels,
        ) {
            Ok(json) => {
                // For terminal format, show immediate output above progress bar
                if matches!(format, cli::OutputFormat::Terminal) {
                    // Parse JSON and format as terminal output
                    match serde_json::from_str::<crate::types::AnalysisReport>(&json) {
                        Ok(report) => match output::format_terminal(&report) {
                            Ok(formatted) => {
                                if let Some(ref bar) = pb {
                                    bar.println(formatted);
                                } else {
                                    print!("{}", formatted);
                                }
                            }
                            Err(e) => {
                                let msg =
                                    format!("Error formatting report for {}: {}", path_str, e);
                                if let Some(ref bar) = pb {
                                    bar.println(msg);
                                } else {
                                    eprintln!("{}", msg);
                                }
                            }
                        },
                        Err(e) => {
                            let msg = format!("Error parsing JSON for {}: {}", path_str, e);
                            if let Some(ref bar) = pb {
                                bar.println(msg);
                            } else {
                                eprintln!("{}", msg);
                            }
                        }
                    }
                } else {
                    // For JSON format, collect for array output at end
                    all_reports.lock().unwrap().push(json);
                }
            }
            Err(e) => {
                if pb.is_none() {
                    eprintln!("✗ {}: {}", path_str, e);
                } else {
                    // Show error but keep progress bar
                    if let Some(ref bar) = pb {
                        bar.println(format!("✗ {}: {}", path_str, e));
                    }
                }
            }
        }

        if let Some(ref bar) = pb {
            bar.inc(1);
        }
    });

    // Process archives in parallel
    archives_found.par_iter().for_each(|path_str| {
        let path = Path::new(&path_str);

        if let Some(ref bar) = pb {
            bar.set_message(format!(
                "Extracting {}",
                path.file_name().unwrap_or_default().to_string_lossy()
            ));
        }

        match analyze_file_with_shared_mapper(
            path_str,
            enable_third_party_yara,
            &capability_mapper,
            zip_passwords,
            disabled,
            error_if_levels,
        ) {
            Ok(json) => {
                // For terminal format, show immediate output above progress bar
                if matches!(format, cli::OutputFormat::Terminal) {
                    // Parse JSON and format as terminal output
                    match serde_json::from_str::<crate::types::AnalysisReport>(&json) {
                        Ok(report) => match output::format_terminal(&report) {
                            Ok(formatted) => {
                                if let Some(ref bar) = pb {
                                    bar.println(formatted);
                                } else {
                                    print!("{}", formatted);
                                }
                            }
                            Err(e) => {
                                let msg =
                                    format!("Error formatting report for {}: {}", path_str, e);
                                if let Some(ref bar) = pb {
                                    bar.println(msg);
                                } else {
                                    eprintln!("{}", msg);
                                }
                            }
                        },
                        Err(e) => {
                            eprintln!("DEBUG: JSON parse error: {}", e);
                            eprintln!("DEBUG: JSON preview: {}", &json[..json.len().min(500)]);
                            let msg = format!("Error parsing JSON for {}: {}", path_str, e);
                            if let Some(ref bar) = pb {
                                bar.println(msg.clone());
                            }
                            eprintln!("{}", msg);
                        }
                    }
                } else {
                    // For JSON format, collect for array output at end
                    all_reports.lock().unwrap().push(json);
                }
            }
            Err(e) => {
                if pb.is_none() {
                    eprintln!("✗ {}: {}", path_str, e);
                } else {
                    // Show error but keep progress bar
                    if let Some(ref bar) = pb {
                        bar.println(format!("✗ {}: {}", path_str, e));
                    }
                }
            }
        }

        if let Some(ref bar) = pb {
            bar.inc(1);
        }
    });

    if let Some(ref bar) = pb {
        bar.finish_with_message("Scan complete");
    }

    // Extract results from Arc<Mutex<>>
    let reports = Arc::try_unwrap(all_reports)
        .map(|mutex| mutex.into_inner().unwrap())
        .unwrap_or_else(|arc| arc.lock().unwrap().clone());

    // Format based on output type
    match format {
        cli::OutputFormat::Json => Ok(format!(
            "[
{}
]",
            reports.join(",\n")
        )),
        cli::OutputFormat::Terminal => {
            // For terminal, show summary
            let mut output = String::new();
            output.push_str("\n📊 Scan Summary\n");
            output.push_str(&format!("  Files analyzed: {}\n", all_files.len()));
            output.push_str(&format!("  Archives analyzed: {}\n", archives_found.len()));
            output.push_str(&format!("  Total reports: {}\n", reports.len()));
            output.push_str("  Analysis complete\n\n");
            Ok(output)
        }
    }
}

fn analyze_file_with_shared_mapper(
    target: &str,
    enable_third_party_yara: bool,
    capability_mapper: &Arc<crate::capabilities::CapabilityMapper>,
    zip_passwords: &[String],
    disabled: &cli::DisabledComponents,
    error_if_levels: Option<&[types::Criticality]>,
) -> Result<String> {
    let timing = std::env::var("DISSECT_TIMING").is_ok();
    let t_start = std::time::Instant::now();
    let path = Path::new(target);

    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    let t_yara = std::time::Instant::now();
    // Load YARA rules (unless YARA is disabled)
    let mut yara_engine = if disabled.yara {
        None
    } else {
        let mut engine = YaraEngine::new_with_mapper((**capability_mapper).clone());
        let (builtin_count, third_party_count) = engine.load_all_rules(enable_third_party_yara)?;
        if builtin_count + third_party_count > 0 {
            Some(engine)
        } else {
            None
        }
    };

    if timing {
        eprintln!("[TIMING] YARA engine setup: {:?}", t_yara.elapsed());
    }
    let t_detect = std::time::Instant::now();

    // Detect file type
    let file_type = detect_file_type(path)?;

    if timing {
        eprintln!("[TIMING] File type detection: {:?}", t_detect.elapsed());
    }
    let t_analyze = std::time::Instant::now();

    // Route to appropriate analyzer
    // Binary analyzers (MachO, Elf, Pe, Archive, Jar) handle YARA internally with specialized filtering
    // All other analyzers get YARA scanning applied universally after analysis
    let mut report = match file_type {
        FileType::MachO => {
            let mut analyzer =
                MachOAnalyzer::new().with_capability_mapper((**capability_mapper).clone());
            if let Some(engine) = yara_engine.take() {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::Elf => {
            let mut analyzer =
                ElfAnalyzer::new().with_capability_mapper((**capability_mapper).clone());
            if let Some(engine) = yara_engine.take() {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::Pe => {
            let mut analyzer =
                PEAnalyzer::new().with_capability_mapper((**capability_mapper).clone());
            if let Some(engine) = yara_engine.take() {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::JavaClass => {
            let analyzer = analyzers::java_class::JavaClassAnalyzer::new()
                .with_capability_mapper((**capability_mapper).clone());
            analyzer.analyze(path)?
        }
        FileType::Jar => {
            // JAR files are analyzed like archives but with Java-specific handling
            let mut analyzer = ArchiveAnalyzer::new()
                .with_capability_mapper((**capability_mapper).clone())
                .with_zip_passwords(zip_passwords.to_vec());
            if let Some(engine) = yara_engine.take() {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::PackageJson => {
            let analyzer = analyzers::package_json::PackageJsonAnalyzer::new()
                .with_capability_mapper((**capability_mapper).clone());
            analyzer.analyze(path)?
        }
        FileType::VsixManifest => {
            let analyzer = analyzers::vsix_manifest::VsixManifestAnalyzer::new()
                .with_capability_mapper((**capability_mapper).clone());
            analyzer.analyze(path)?
        }
        FileType::AppleScript => {
            let analyzer = analyzers::applescript::AppleScriptAnalyzer::new()
                .with_capability_mapper((**capability_mapper).clone());
            analyzer.analyze(path)?
        }
        FileType::Archive => {
            let mut analyzer = ArchiveAnalyzer::new()
                .with_capability_mapper((**capability_mapper).clone())
                .with_zip_passwords(zip_passwords.to_vec());
            if let Some(engine) = yara_engine.take() {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        // All source code languages use the unified analyzer (or generic fallback)
        _ => {
            if let Some(analyzer) =
                analyzers::analyzer_for_file_type(&file_type, Some((**capability_mapper).clone()))
            {
                analyzer.analyze(path)?
            } else {
                anyhow::bail!("Unsupported file type: {:?}", file_type);
            }
        }
    };

    if timing {
        eprintln!("[TIMING] Analysis: {:?}", t_analyze.elapsed());
    }

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

    if timing {
        eprintln!(
            "[TIMING] Total analyze_file_with_shared_mapper: {:?}",
            t_start.elapsed()
        );
    }

    // Check if report's criticality matches --error-if criteria
    check_criticality_error(&report, error_if_levels)?;

    // Always output JSON for parallel scanning
    output::format_json(&report)
}

fn diff_analysis(old: &str, new: &str, format: &cli::OutputFormat) -> Result<String> {
    let diff_analyzer = diff::DiffAnalyzer::new(old, new);

    match format {
        cli::OutputFormat::Json => {
            // Use full diff for JSON - comprehensive ML-ready output
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
                                        let sym = sym_part[..lib_start].trim().to_string();
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
                            imports.insert(imp.name.clone());
                            if let Some(lib) = imp.lib_name {
                                import_libraries.insert(imp.name, lib);
                            }
                        }
                        for sym in r2_symbols {
                            if sym.name.starts_with("imp.") || sym.name.starts_with("sym.imp.") {
                                let clean = sym
                                    .name
                                    .trim_start_matches("sym.imp.")
                                    .trim_start_matches("imp.");
                                imports.insert(clean.to_string());
                            } else if sym.symbol_type == "FUNC"
                                || sym.symbol_type == "func"
                                || sym.name.starts_with("fcn.")
                            {
                                let name = sym.name.clone();
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
        cli::OutputFormat::Json => Ok(serde_json::to_string_pretty(&strings)?),
        cli::OutputFormat::Terminal => {
            let mut output = String::new();
            output.push_str(&format!(
                "Extracted {} strings from {}\n\n",
                strings.len(),
                target
            ));
            output.push_str(&format!("{:<10} {:<14} {}\n", "OFFSET", "TYPE", "VALUE"));
            output.push_str(&format!("{:-<10} {:-<14} {:-<20}\n", "", "", ""));
            for s in strings {
                let offset = s.offset.unwrap_or_else(|| "unknown".to_string());

                let stype_str = if s.string_type == crate::types::StringType::Import {
                    "@unknown".to_string()
                } else {
                    format!("{:?}", s.string_type)
                };

                let mut val_display = s.value.clone();

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
                    "{:<10} {:<14} {}\n",
                    offset, stype_str, val_display
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
    use analyzers::Analyzer;

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
        cli::OutputFormat::Json => Ok(serde_json::to_string_pretty(&filtered_strings)?),
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
                let offset = s.offset.unwrap_or_else(|| "unknown".to_string());
                let stype_str = format!("{:?}", s.string_type);
                output.push_str(&format!("{:<10} {:<14} {}\n", offset, stype_str, s.value));
            }
            Ok(output)
        }
    }
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
                                name: imp.name.clone(),
                                address: None,
                                library: imp.lib_name,
                                symbol_type: "import".to_string(),
                                source: "radare2".to_string(),
                            });
                        }

                        // Add exports
                        for exp in r2_exports {
                            symbols.push(SymbolInfo {
                                name: exp.name,
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

                            // Skip if already added as import or export
                            let already_added = symbols.iter().any(|s| s.name == sym.name);
                            if !already_added {
                                symbols.push(SymbolInfo {
                                    name: sym.name,
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
        cli::OutputFormat::Json => Ok(serde_json::to_string_pretty(&symbols)?),
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

/// Debug rule evaluation - shows exactly why rules match or fail
fn test_rules_debug(
    target: &str,
    rules: &str,
    _disabled: &cli::DisabledComponents,
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

    // Load capability mapper
    let capability_mapper = crate::capabilities::CapabilityMapper::new();

    // Read file data
    let binary_data = fs::read(path)?;

    // Create a basic report by analyzing the file
    let mut report = create_analysis_report(path, &file_type, &binary_data, &capability_mapper)?;

    // Evaluate traits first to populate findings
    capability_mapper.evaluate_and_merge_findings(&mut report, &binary_data, None);

    // Create debugger and debug each rule
    let debugger = test_rules::RuleDebugger::new(&capability_mapper, &report, &binary_data);

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
