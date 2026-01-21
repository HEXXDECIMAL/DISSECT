#![allow(dead_code)]

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
// mod radare2_extended;  // Removed: integrated into radare2.rs
mod strings;
mod trait_mapper;
mod types;
mod yara_engine;

use analyzers::{
    archive::ArchiveAnalyzer, detect_file_type, elf::ElfAnalyzer, javascript::JavaScriptAnalyzer,
    macho::MachOAnalyzer, pe::PEAnalyzer, Analyzer, FileType,
};
use anyhow::{Context, Result};
use clap::Parser;
use rayon::prelude::*;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use yara_engine::YaraEngine;

fn main() -> Result<()> {
    let args = cli::Args::parse();

    // Print banner to stderr if JSON mode, stdout otherwise
    match args.format {
        cli::OutputFormat::Json => {
            eprintln!("DISSECT v{}", env!("CARGO_PKG_VERSION"));
            eprintln!("Deep static analysis tool\n");
        }
        cli::OutputFormat::Terminal => {
            println!("DISSECT v{}", env!("CARGO_PKG_VERSION"));
            println!("Deep static analysis tool\n");
        }
    }

    let result = match args.command {
        cli::Command::Analyze {
            target,
            third_party_yara,
        } => analyze_file(&target, third_party_yara, &args.format)?,
        cli::Command::Scan {
            paths,
            third_party_yara,
        } => scan_paths(paths, third_party_yara, &args.format)?,
        cli::Command::Diff { old, new } => diff_analysis(&old, &new)?,
    };

    // Output results
    if let Some(output_path) = args.output {
        fs::write(&output_path, &result)
            .context(format!("Failed to write output to {}", output_path))?;
        println!("Results written to: {}", output_path);
    } else {
        // For terminal output, don't include the newlines from analyze functions
        print!("{}", result);
    }

    Ok(())
}

fn analyze_file(
    target: &str,
    enable_third_party_yara: bool,
    format: &cli::OutputFormat,
) -> Result<String> {
    let _start = std::time::Instant::now();
    let path = Path::new(target);

    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", target);
    }

    // If target is a directory, scan it recursively
    if path.is_dir() {
        return scan_paths(vec![target.to_string()], enable_third_party_yara, format);
    }

    // Print to stderr in JSON mode
    match format {
        cli::OutputFormat::Json => eprintln!("Analyzing: {}", target),
        cli::OutputFormat::Terminal => println!("Analyzing: {}", target),
    }

    // Detect file type first (fast - just reads magic bytes)
    let file_type = detect_file_type(path)?;
    match format {
        cli::OutputFormat::Json => eprintln!("Detected file type: {:?}", file_type),
        cli::OutputFormat::Terminal => println!("Detected file type: {:?}", file_type),
    }

    // Start loading YARA rules in background immediately (most expensive operation)
    // Use empty mapper to avoid duplicate YAML loading - we'll inject the real one later
    let t_yara_start = std::time::Instant::now();
    let yara_handle = std::thread::spawn(move || {
        let empty_mapper = crate::capabilities::CapabilityMapper::empty();
        let mut engine = YaraEngine::new_with_mapper(empty_mapper);
        let result = engine.load_all_rules(enable_third_party_yara);
        (engine, result)
    });

    // While YARA loads in background, do other setup work in parallel
    // Load capability mapper
    let t1 = std::time::Instant::now();
    let capability_mapper = crate::capabilities::CapabilityMapper::new();
    eprintln!("[TIMING] CapabilityMapper::new(): {:?}", t1.elapsed());

    // Wait for YARA engine to finish loading
    let (mut yara_engine_loaded, yara_result) = yara_handle
        .join()
        .map_err(|_| anyhow::anyhow!("YARA loading thread panicked"))?;

    let (builtin_count, third_party_count) = yara_result?;
    eprintln!(
        "[TIMING] YaraEngine load (parallel): {:?}",
        t_yara_start.elapsed()
    );

    // Inject CapabilityMapper into the loaded YARA engine
    yara_engine_loaded.set_capability_mapper(capability_mapper.clone());

    let yara_engine = if builtin_count + third_party_count > 0 {
        Some(yara_engine_loaded)
    } else {
        None
    };

    // Route to appropriate analyzer
    let t3 = std::time::Instant::now();
    let report = match file_type {
        FileType::MachO => {
            let mut analyzer =
                MachOAnalyzer::new().with_capability_mapper(capability_mapper.clone());
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::Elf => {
            let mut analyzer = ElfAnalyzer::new().with_capability_mapper(capability_mapper.clone());
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::Pe => {
            let mut analyzer = PEAnalyzer::new().with_capability_mapper(capability_mapper.clone());
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::ShellScript => {
            let analyzer = analyzers::shell::ShellAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::Python => {
            let analyzer = analyzers::python::PythonAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::JavaScript => {
            let analyzer =
                JavaScriptAnalyzer::new().with_capability_mapper(capability_mapper.clone());
            analyzer.analyze(path)?
        }
        FileType::Go => {
            let analyzer = analyzers::go::GoAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::Rust => {
            let analyzer = analyzers::rust::RustAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::Java => {
            let analyzer = analyzers::java::JavaAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::Ruby => {
            let analyzer =
                analyzers::ruby::RubyAnalyzer::new().with_capability_mapper(capability_mapper);
            analyzer.analyze(path)?
        }
        FileType::C => {
            let analyzer = analyzers::c::CAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::Archive => {
            let analyzer = ArchiveAnalyzer::new();
            analyzer.analyze(path)?
        }
        _ => {
            anyhow::bail!("Unsupported file type: {:?}", file_type);
        }
    };
    eprintln!("[TIMING] Analysis: {:?}", t3.elapsed());

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
) -> Result<String> {
    use indicatif::{ProgressBar, ProgressStyle};
    use walkdir::WalkDir;

    println!("Scanning {} path(s)...\n", paths.len());

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

    println!(
        "Found {} files and {} archives to analyze\n",
        all_files.len(),
        archives_found.len()
    );

    // Create progress bar for terminal output (indicatif is thread-safe)
    let total_items = all_files.len() + archives_found.len();
    let pb = if matches!(format, cli::OutputFormat::Terminal) {
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

        match analyze_file_with_shared_mapper(path_str, enable_third_party_yara, &capability_mapper)
        {
            Ok(json) => {
                eprintln!(
                    "DEBUG: Analyzed file {}, JSON length: {}",
                    path_str,
                    json.len()
                );
                // For terminal format, show immediate output above progress bar
                if matches!(format, cli::OutputFormat::Terminal) {
                    eprintln!("DEBUG: Terminal format, parsing JSON...");
                    // Parse JSON and format as terminal output
                    let parse_result = serde_json::from_str::<crate::types::AnalysisReport>(&json);
                    eprintln!(
                        "DEBUG: Parse result: {}",
                        if parse_result.is_ok() { "Ok" } else { "Err" }
                    );
                    match parse_result {
                        Ok(report) => {
                            eprintln!("DEBUG: Parsed JSON successfully, formatting...");
                            match output::format_terminal(&report) {
                                Ok(formatted) => {
                                    eprintln!(
                                        "DEBUG: Formatted successfully, length: {}",
                                        formatted.len()
                                    );
                                    // Print directly to test
                                    eprintln!("{}", formatted);
                                    if let Some(ref bar) = pb {
                                        eprintln!("DEBUG: Calling bar.println()");
                                        bar.println(formatted.clone());
                                        eprintln!("DEBUG: bar.println() returned");
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
                            }
                        }
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

    // Process archives in parallel
    archives_found.par_iter().for_each(|path_str| {
        let path = Path::new(&path_str);

        if let Some(ref bar) = pb {
            bar.set_message(format!(
                "Extracting {}",
                path.file_name().unwrap_or_default().to_string_lossy()
            ));
        }

        match analyze_file_with_shared_mapper(path_str, enable_third_party_yara, &capability_mapper)
        {
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
        cli::OutputFormat::Json => Ok(format!("[\n{}\n]", reports.join(",\n"))),
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
) -> Result<String> {
    let path = Path::new(target);

    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    // Each thread creates its own YaraEngine with the shared CapabilityMapper
    let yara_engine = {
        let mut engine = YaraEngine::new_with_mapper((**capability_mapper).clone());
        let (builtin_count, third_party_count) = engine.load_all_rules(enable_third_party_yara)?;

        if builtin_count + third_party_count > 0 {
            Some(engine)
        } else {
            None
        }
    };

    // Detect file type
    let file_type = detect_file_type(path)?;

    // Route to appropriate analyzer
    let report = match file_type {
        FileType::MachO => {
            let mut analyzer =
                MachOAnalyzer::new().with_capability_mapper((**capability_mapper).clone());
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::Elf => {
            let mut analyzer =
                ElfAnalyzer::new().with_capability_mapper((**capability_mapper).clone());
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::Pe => {
            let mut analyzer =
                PEAnalyzer::new().with_capability_mapper((**capability_mapper).clone());
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::ShellScript => {
            let analyzer = analyzers::shell::ShellAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::Python => {
            let analyzer = analyzers::python::PythonAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::JavaScript => {
            let analyzer =
                JavaScriptAnalyzer::new().with_capability_mapper((**capability_mapper).clone());
            analyzer.analyze(path)?
        }
        FileType::Go => {
            let analyzer = analyzers::go::GoAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::Rust => {
            let analyzer = analyzers::rust::RustAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::Java => {
            let analyzer = analyzers::java::JavaAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::Ruby => {
            let analyzer = analyzers::ruby::RubyAnalyzer::new()
                .with_capability_mapper((**capability_mapper).clone());
            analyzer.analyze(path)?
        }
        FileType::C => {
            let analyzer = analyzers::c::CAnalyzer::new();
            analyzer.analyze(path)?
        }
        FileType::Archive => {
            let analyzer = ArchiveAnalyzer::new();
            analyzer.analyze(path)?
        }
        _ => {
            anyhow::bail!("Unsupported file type: {:?}", file_type);
        }
    };

    // Always output JSON for parallel scanning
    output::format_json(&report)
}

fn diff_analysis(old: &str, new: &str) -> Result<String> {
    let diff_analyzer = diff::DiffAnalyzer::new(old, new);
    let report = diff_analyzer.analyze()?;

    // Format as terminal output
    Ok(diff::format_diff_terminal(&report))
}
