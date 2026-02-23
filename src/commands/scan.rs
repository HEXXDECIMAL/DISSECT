//! Multi-file scanning command.
//!
//! This module provides the `scan` command functionality, which performs parallel
//! analysis of multiple files and directories. It handles both regular files and
//! archives with intelligent concurrency management.
//!
//! # Features
//!
//! - **Parallel Processing**: Uses rayon for concurrent file analysis
//! - **Archive Support**: Detects and processes archives with streaming output
//! - **Format-Specific Output**: Terminal and JSONL output formats
//! - **Path Expansion**: Recursively expands directories and handles stdin input
//! - **Error Propagation**: Supports --error-if for early termination
//! - **Concurrency Control**: Limits concurrent archive processing to prevent OOM
//!
//! # Architecture
//!
//! The scan command operates in several phases:
//!
//! 1. **Initialization**: Loads YARA rules in background while capability mapper initializes
//! 2. **Path Expansion**: Recursively walks directories, filters files, separates archives
//! 3. **File Processing**: Analyzes regular files in parallel with rayon
//! 4. **Archive Processing**: Analyzes archives with bounded concurrency (max 3 concurrent)
//! 5. **Output**: Streams results in JSONL or formats for terminal display
//!
//! # Concurrency Strategy
//!
//! - Regular files: Unlimited parallelism via rayon
//! - Archives: Limited to 3 concurrent to prevent memory exhaustion
//! - Uses semaphore pattern (bounded channel) for archive throttling
//!
//! # Error Handling
//!
//! - Supports --error-if flag to halt processing when criticality threshold is met
//! - Uses atomic flag for cross-thread early termination coordination
//! - Preserves first error message for reporting

use crate::analyzers::{detect_file_type, FileType};
use crate::archive_utils;
use crate::cli;
use crate::composite_rules;
use crate::output;
use crate::types;
use crate::yara_engine::YaraEngine;
use anyhow::Result;
use crossbeam_channel::bounded;
use rayon::prelude::*;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;

/// Number of files to process before clearing thread-local caches.
/// This helps prevent memory growth during long-running scans.
/// Set DISSECT_CACHE_CLEAR_INTERVAL env var to override (0 to disable).
fn cache_clear_interval() -> usize {
    std::env::var("DISSECT_CACHE_CLEAR_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100)
}

/// Run the scan command to analyze multiple files and directories.
///
/// This function performs parallel analysis of multiple files, handling both regular
/// files and archives. It supports various output formats and error-if conditions.
///
/// # Parameters
///
/// - `paths`: List of file/directory paths to scan (may include "-" for stdin)
/// - `enable_third_party`: Whether to load third-party YARA rules
/// - `format`: Output format (Terminal or JSONL)
/// - `zip_passwords`: Passwords to try for encrypted archives
/// - `disabled`: Components to disable during analysis
/// - `error_if_levels`: Criticality levels that should trigger early termination
/// - `verbose`: Enable verbose logging
/// - `include_all_files`: Include non-program files (otherwise filtered by type)
/// - `sample_extraction`: Configuration for extracting samples during analysis
/// - `platforms`: Target platforms for capability detection
/// - `min_hostile_precision`: Minimum precision threshold for hostile findings
/// - `min_suspicious_precision`: Minimum precision threshold for suspicious findings
/// - `max_memory_file_size`: Maximum file size to load into memory
/// - `enable_full_validation`: Enable full YAML validation during rule loading
///
/// # Returns
///
/// Returns an empty string on success (output is streamed during processing).
/// Returns an error if --error-if condition is triggered or other failures occur.
///
/// # Architecture
///
/// The function uses a two-phase approach:
/// 1. Initialize engines (YARA in background, capability mapper in foreground)
/// 2. Expand paths (walk directories, separate files from archives)
/// 3. Process files in parallel (unlimited concurrency)
/// 4. Process archives with bounded concurrency (max 3 concurrent)
#[allow(clippy::too_many_arguments)]
pub(crate) fn run(
    paths: &[String],
    enable_third_party: bool,
    format: &cli::OutputFormat,
    zip_passwords: &[String],
    disabled: &cli::DisabledComponents,
    error_if_levels: Option<&[types::Criticality]>,
    verbose: bool,
    include_all_files: bool,
    sample_extraction: Option<&types::SampleExtractionConfig>,
    platforms: &[composite_rules::Platform],
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
    max_memory_file_size: u64,
    enable_full_validation: bool,
) -> Result<String> {
    // Kick off YARA loading on a background thread immediately — it's the slowest
    // initialization step (wasmtime JIT) and is independent of capability loading.
    let yara_disabled = disabled.yara;
    let yara_handle: Option<std::thread::JoinHandle<(YaraEngine, usize, usize)>> = if yara_disabled
    {
        None
    } else {
        Some(std::thread::spawn(move || {
            let empty_mapper = crate::capabilities::CapabilityMapper::empty();
            let mut engine = YaraEngine::new_with_mapper(empty_mapper);
            let (builtin, third_party) = engine.load_all_rules(enable_third_party);
            (engine, builtin, third_party)
        }))
    };

    // Load capability mapper while YARA compiles in the background.
    let capability_mapper = Arc::new(
        crate::capabilities::CapabilityMapper::new_with_precision_thresholds(
            min_hostile_precision,
            min_suspicious_precision,
            enable_full_validation,
        )
        .with_platforms(platforms.to_vec()),
    );

    // Join YARA thread now that the mapper is ready.
    // NOTE: set_capability_mapper removed - field is unused in YaraEngine
    let shared_yara_engine: Option<Arc<YaraEngine>> = if let Some(handle) = yara_handle {
        let (engine, builtin, third_party) = handle
            .join()
            .unwrap_or_else(|e| std::panic::resume_unwind(e));
        if builtin + third_party > 0 {
            Some(Arc::new(engine))
        } else {
            None
        }
    } else {
        None
    };

    // Collect all files from paths (expanding directories recursively)
    // Pre-allocate with reasonable capacity to reduce reallocations
    let mut all_files = Vec::with_capacity(1000);
    let mut archives_found = Vec::with_capacity(100);

    for path_str in paths {
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
                .filter_map(std::result::Result::ok)
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

    // File counter for periodic cache clearing to prevent memory growth
    let files_processed = AtomicUsize::new(0);
    let clear_interval = cache_clear_interval();

    // Process regular files in parallel using try_for_each for early termination
    let files_result: Result<(), ()> = all_files.par_iter().try_for_each(|path_str| {
        // Check if another thread already triggered --error-if
        if error_if_triggered.load(Ordering::Relaxed) {
            return Err(());
        }

        // Periodically clear thread-local caches to prevent memory buildup
        // This is especially important for long-running scans with many files
        if clear_interval > 0 {
            let count = files_processed.fetch_add(1, Ordering::Relaxed);
            if count > 0 && count % clear_interval == 0 {
                crate::composite_rules::evaluators::clear_thread_local_caches();
                tracing::debug!("Cleared thread-local caches after {} files", count);
            }
        }

        match super::analyze_file_with_shared_mapper(
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
                            Ok(report) => {
                                print!("{}", output::format_terminal(&report));
                            }
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
                    let mut msg = error_if_message
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let _ = archive_sem_tx.send(());
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
                    match super::analyze_archive_streaming_jsonl(
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

                match super::analyze_file_with_shared_mapper(
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
                                    Ok(report) => {
                                        print!("{}", output::format_terminal(&report));
                                    }
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
                                tracing::warn!("Unexpected JSONL format in terminal output path");
                            }
                        }
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        // Check if this is an --error-if failure - stop processing
                        if err_str.contains("--error-if") {
                            error_if_triggered.store(true, Ordering::Relaxed);
                            eprintln!("✗ {}: {}", path_str, e);
                            let mut msg = error_if_message
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        if let Some(msg) = error_if_message
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
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
