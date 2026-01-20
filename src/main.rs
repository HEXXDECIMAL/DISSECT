mod analyzers;
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

use analyzers::{archive::ArchiveAnalyzer, detect_file_type, elf::ElfAnalyzer, javascript::JavaScriptAnalyzer, macho::MachOAnalyzer, pe::PEAnalyzer, Analyzer, FileType};
use anyhow::{Context, Result};
use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};
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
        cli::Command::Analyze { target, yara, yara_rules } => {
            analyze_file(&target, yara, yara_rules.as_deref(), &args.format)?
        }
        cli::Command::Scan { paths, yara, yara_rules } => {
            scan_paths(paths, yara, yara_rules.as_deref(), &args.format)?
        }
        cli::Command::Diff { old, new } => {
            diff_analysis(&old, &new)?
        }
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

fn analyze_file(target: &str, use_yara: bool, yara_rules_dir: Option<&str>, format: &cli::OutputFormat) -> Result<String> {
    let path = Path::new(target);

    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    // Print to stderr in JSON mode
    match format {
        cli::OutputFormat::Json => eprintln!("Analyzing: {}", target),
        cli::OutputFormat::Terminal => println!("Analyzing: {}", target),
    }

    // Load YARA rules if requested
    let yara_engine = if use_yara {
        use indicatif::{ProgressBar, ProgressStyle};

        let mut engine = YaraEngine::new();

        // Create spinner for YARA loading (terminal mode only)
        let spinner = if matches!(format, cli::OutputFormat::Terminal) {
            let sp = ProgressBar::new_spinner();
            sp.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap()
            );
            Some(sp)
        } else {
            None
        };

        if let Some(rules_dir) = yara_rules_dir {
            match format {
                cli::OutputFormat::Json => {
                    eprintln!("Loading YARA rules from: {}", rules_dir);
                    let count = engine.load_rules_from_directory(Path::new(rules_dir))?;
                    eprintln!("Loaded {} YARA rules", count);
                }
                cli::OutputFormat::Terminal => {
                    if let Some(ref sp) = spinner {
                        sp.set_message(format!("Loading YARA rules from: {}", rules_dir));
                        sp.enable_steady_tick(std::time::Duration::from_millis(100));
                    }
                    let count = engine.load_rules_from_directory(Path::new(rules_dir))?;
                    if let Some(ref sp) = spinner {
                        sp.finish_with_message(format!("Loaded {} YARA rules", count));
                    }
                }
            }
        } else {
            match format {
                cli::OutputFormat::Json => {
                    eprintln!("Loading YARA rules from malcontent...");
                    let count = engine.load_malcontent_rules()?;
                    eprintln!("Loaded {} YARA rules", count);
                }
                cli::OutputFormat::Terminal => {
                    if let Some(ref sp) = spinner {
                        sp.set_message("Loading YARA rules from malcontent...");
                        sp.enable_steady_tick(std::time::Duration::from_millis(100));
                    }
                    let count = engine.load_malcontent_rules()?;
                    if let Some(ref sp) = spinner {
                        sp.finish_with_message(format!("Loaded {} YARA rules", count));
                    }
                }
            }
        }

        Some(engine)
    } else {
        None
    };

    // Detect file type
    let file_type = detect_file_type(path)?;
    match format {
        cli::OutputFormat::Json => eprintln!("Detected file type: {:?}", file_type),
        cli::OutputFormat::Terminal => println!("Detected file type: {:?}", file_type),
    }

    // Route to appropriate analyzer
    let report = match file_type {
        FileType::MachO => {
            let mut analyzer = MachOAnalyzer::new();
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::Elf => {
            let mut analyzer = ElfAnalyzer::new();
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara(engine);
            }
            analyzer.analyze(path)?
        }
        FileType::Pe => {
            let mut analyzer = PEAnalyzer::new();
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
            let analyzer = JavaScriptAnalyzer::new();
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
            let analyzer = analyzers::ruby::RubyAnalyzer::new();
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

    // Format output based on requested format
    match format {
        cli::OutputFormat::Json => output::format_json(&report),
        cli::OutputFormat::Terminal => output::format_terminal(&report),
    }
}

fn scan_paths(paths: Vec<String>, use_yara: bool, yara_rules_dir: Option<&str>, format: &cli::OutputFormat) -> Result<String> {
    use indicatif::{ProgressBar, ProgressStyle};

    println!("Scanning {} path(s)...\n", paths.len());

    let mut all_reports = Vec::new();

    // Create progress bar for terminal output
    let pb = if matches!(format, cli::OutputFormat::Terminal) {
        let bar = ProgressBar::new(paths.len() as u64);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("█▓▒░ ")
        );
        Some(bar)
    } else {
        None
    };

    for (idx, path_str) in paths.iter().enumerate() {
        let path = Path::new(&path_str);

        if let Some(ref bar) = pb {
            bar.set_message(format!("Analyzing {}", path.file_name().unwrap_or_default().to_string_lossy()));
        }

        if path.is_file() {
            match analyze_file(path_str, use_yara, yara_rules_dir, &cli::OutputFormat::Json) {
                Ok(json) => {
                    if pb.is_none() {
                        println!("✓ {}", path_str);
                    }
                    all_reports.push(json);
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
        } else if path.is_dir() {
            // TODO: Implement recursive directory scanning
            if pb.is_none() {
                println!("Directory scanning not yet implemented: {}", path_str);
            }
        }

        if let Some(ref bar) = pb {
            bar.inc(1);
        }
    }

    if let Some(ref bar) = pb {
        bar.finish_with_message("Scan complete");
    }

    // Format based on output type
    match format {
        cli::OutputFormat::Json => Ok(format!("[\n{}\n]", all_reports.join(",\n"))),
        cli::OutputFormat::Terminal => {
            // For terminal, show summary
            let mut output = String::new();
            output.push_str(&format!("\n📊 Scan Summary\n"));
            output.push_str(&format!("  Files analyzed: {}\n", all_reports.len()));
            output.push_str(&format!("  Analysis complete\n\n"));
            Ok(output)
        }
    }
}

fn diff_analysis(old: &str, new: &str) -> Result<String> {
    let diff_analyzer = diff::DiffAnalyzer::new(old, new);
    let report = diff_analyzer.analyze()?;

    // Format as terminal output
    Ok(diff::format_diff_terminal(&report))
}
