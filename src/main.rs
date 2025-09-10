use clap::Parser;
use divine::cli::{Cli, Commands, OutputFormat};
use divine::error::Result;
use divine::report::{Behavior, Report, RiskLevel};
use divine::rules::RuleLoader;
use divine::scanner::Scanner;
use divine::{archive, FileReport};
use std::fs;
use std::path::Path;
use std::time::Instant;
use tracing::{error, info, warn};

struct FileReportTable {
    path: String,
    risk: String,
    behaviors: usize,
    size: String,
}

impl From<&FileReport> for FileReportTable {
    fn from(fr: &FileReport) -> Self {
        let risk = match fr.risk_level {
            RiskLevel::Low => "LOW".to_string(),
            RiskLevel::Medium => "MED".to_string(),
            RiskLevel::High => "HIGH".to_string(),
            RiskLevel::Critical => "CRIT".to_string(),
        };

        let size = if fr.size < 1024 {
            format!("{}B", fr.size)
        } else if fr.size < 1024 * 1024 {
            format!("{:.1}KB", fr.size as f64 / 1024.0)
        } else {
            format!("{:.1}MB", fr.size as f64 / (1024.0 * 1024.0))
        };

        Self { path: fr.path.clone(), risk, behaviors: fr.behaviors.len(), size }
    }
}

fn load_rules(rules_path: Option<&str>) -> Result<yara_x::Rules> {
    let mut loader = RuleLoader::new();

    if let Some(path) = rules_path {
        let path = Path::new(path);
        if path.is_file() {
            loader.add_rule_file(path).map_err(|e| divine::error::DivineError::yara_compilation(format!("Failed to load rule file: {e}")))?
        } else if path.is_dir() {
            let count = loader.add_rule_directory(path).map_err(|e| divine::error::DivineError::yara_compilation(format!("Failed to load rule directory: {e}")))?;
            info!("Loaded {} YARA rules from {}", count, path.display());
        } else {
            return Err(divine::error::DivineError::path_not_found(path));
        }
    } else {
        info!("Loading YARA rules...");
        return RuleLoader::load_malcontent_rules();
    }

    loader.build()
}

fn format_output(report: &Report, format: &OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|e| divine::error::DivineError::serialization(format!("Failed to serialize to JSON: {e}"))),
        OutputFormat::Brief => {
            let mut output = String::new();
            for file in &report.files {
                if file.skipped.is_none() && !file.behaviors.is_empty() {
                    output.push_str(&format!(
                        "{} [{}] {}\n",
                        file.path,
                        file.risk_level.as_str().to_uppercase(),
                        file.behaviors.len()
                    ));
                }
            }
            Ok(output)
        }
        OutputFormat::Terminal => {
            let mut output = String::new();

            // Check if this is detailed analysis (single file)
            let is_detailed_analysis = report.files.len() == 1;

            if is_detailed_analysis {
                // Malcontent-style analysis view
                if let Some(file) = report.files.first() {
                    output.push_str(&format!("🔎 Scanning \"{}\"\n", file.path));

                    if file.behaviors.is_empty() {
                        output.push_str(&format!("├─ ✅ {} [CLEAN]\n", file.path));
                        output.push_str("│     No suspicious behaviors detected\n");
                    } else {
                        // Determine file risk level icon and color
                        let (risk_icon, risk_text) = match file.risk_level {
                            RiskLevel::Low => ("🔵", file.risk_level.as_str().to_uppercase()),
                            RiskLevel::Medium => ("🟡", file.risk_level.as_str().to_uppercase()),
                            RiskLevel::High => ("🟠", file.risk_level.as_str().to_uppercase()),
                            RiskLevel::Critical => ("🔴", file.risk_level.as_str().to_uppercase()),
                        };

                        output.push_str(&format!("├─ {} {} [{}]\n", risk_icon, file.path, risk_text));

                        // Group behaviors by category
                        use std::collections::HashMap;
                        let mut categories: HashMap<String, Vec<&Behavior>> = HashMap::new();

                        for behavior in &file.behaviors {
                            let category = infer_category(&behavior.rule_name);
                            categories.entry(category).or_default().push(behavior);
                        }

                        // Sort categories alphabetically like malcontent
                        let mut sorted_categories: Vec<_> = categories.into_iter().collect();
                        sorted_categories.sort_by_key(|(k, _)| k.clone());

                        for (category, behaviors) in sorted_categories {
                            let max_risk = behaviors
                                .iter()
                                .map(|b| b.risk_level.as_str().to_uppercase())
                                .max()
                                .unwrap_or_else(|| "LOW".to_string());
                            output.push_str(&format!("│     ≡ {} [{}]\n", category, max_risk));

                            for behavior in behaviors {
                                let risk_icon = match behavior.risk_level {
                                    RiskLevel::Low => "🔵",
                                    RiskLevel::Medium => "🟡",
                                    RiskLevel::High => "🟠",
                                    RiskLevel::Critical => "🔴",
                                };

                                let display_name = format_rule_name(&behavior.rule_name);
                                output.push_str(&format!(
                                    "│       {} {} — {}",
                                    risk_icon,
                                    display_name,
                                    behavior.description
                                ));

                                // Show author attribution except for "Divine Team"
                                if let Some(author) = &behavior.rule_author {
                                    if author != "Divine Team" {
                                        output.push_str(&format!(", by {author}"));
                                    }
                                }

                                if !behavior.match_strings.is_empty() {
                                    output.push_str(": ");
                                    let matches_display = behavior
                                        .match_strings
                                        .iter()
                                        .map(|m| m.trim())
                                        .filter(|s| !s.is_empty())
                                        .collect::<Vec<_>>()
                                        .join(", ");

                                    output.push_str(&matches_display);
                                }

                                output.push('\n');
                            }
                        }
                    }
                    output.push_str("│\n");
                }
            } else {
                // Standard scan report view for multiple files
                output.push_str("📊 Divine Scan Report ");
                output.push_str(&format!("({}ms)\n\n", report.scan_duration_ms));

                output.push_str(&format!("Files scanned: {}\n", report.total_files_scanned));
                output.push_str(&format!("Files skipped: {}\n", report.total_files_skipped));
                output.push_str(&format!("Malicious files: {}\n", report.malicious_files));
                output.push_str(&format!("Suspicious files: {}\n\n", report.suspicious_files));

                let findings: Vec<&FileReport> =
                    report.files.iter().filter(|f| f.skipped.is_none() && !f.behaviors.is_empty()).collect();

                if !findings.is_empty() {
                    // Simple table formatting instead of tabled
                    output.push_str(&format!("{:<50} {:<8} {:<10} {}\n", "PATH", "RISK", "BEHAVIORS", "SIZE"));
                    output.push_str(&format!("{}", "-".repeat(80)));
                    output.push('\n');
                    
                    for file in &findings {
                        let table_row: FileReportTable = (*file).into();
                        output.push_str(&format!(
                            "{:<50} {:<8} {:<10} {}\n",
                            table_row.path,
                            table_row.risk,
                            table_row.behaviors,
                            table_row.size
                        ));
                    }
                    output.push('\n');

                    for file in &findings {
                        if file.risk_level >= RiskLevel::High {
                            output.push_str(&format!(
                                "\n🔍 {} Details for {}\n",
                                if file.risk_level == RiskLevel::Critical { "Critical" } else { "High Risk" },
                                file.path
                            ));

                            for behavior in &file.behaviors {
                                output.push_str(&format!(
                                    "  • {} [{}]\n",
                                    behavior.description,
                                    behavior.risk_level.as_str().to_uppercase()
                                ));
                                if !behavior.match_strings.is_empty() {
                                    for match_str in behavior.match_strings.iter().take(3) {
                                        output.push_str(&format!(
                                            "    → {}\n",
                                            match_str
                                        ));
                                    }
                                    if behavior.match_strings.len() > 3 {
                                        output.push_str(&format!(
                                            "    ... and {} more matches\n",
                                            behavior.match_strings.len() - 3
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Ok(output)
        }
    }
}

fn scan_paths(paths: Vec<String>, scanner: &Scanner, archives: bool) -> Result<Report> {
    let start_time = Instant::now();
    let mut report = Report::new();

    for path_str in paths {
        let path = Path::new(&path_str);

        if !path.exists() {
            warn!("Path does not exist: {}", path_str);
            continue;
        }

        if path.is_file() {
            // Check if file is an archive (inlined for simplicity)
            let is_archive = if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let path_str = path.to_string_lossy().to_lowercase();
                matches!(ext.to_lowercase().as_str(), "zip" | "tar" | "gz") || path_str.ends_with(".tar.gz")
            } else {
                false
            };
            if archives && is_archive {
                info!("Extracting archive: {}", path_str);
                let mut extractor = archive::ArchiveExtractor::new()?;

                let extracted_files = extractor.extract_archive(path)?;

                for extracted_path in extracted_files {
                    match scanner.scan_file(&extracted_path) {
                        Ok(file_report) => report.add_file(file_report),
                        Err(e) => {
                            error!("Failed to scan {}: {}", extracted_path, e);
                            report.add_file(FileReport::with_skipped(extracted_path, format!("Scan error: {}", e)));
                        }
                    }
                }
            } else {
                match scanner.scan_file(path) {
                    Ok(file_report) => report.add_file(file_report),
                    Err(e) => {
                        error!("Failed to scan {}: {}", path_str, e);
                        report.add_file(FileReport::with_skipped(path_str, format!("Scan error: {}", e)));
                    }
                }
            }
        } else if path.is_dir() {
            info!("Scanning directory: {}", path_str);
            match scanner.scan_directory(path) {
                Ok(file_reports) => {
                    for file_report in file_reports {
                        report.add_file(file_report);
                    }
                }
                Err(e) => {
                    error!("Failed to scan directory {}: {}", path_str, e);
                }
            }
        }
    }

    report.scan_duration_ms = start_time.elapsed().as_millis() as u64;
    Ok(report)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    // Setup logging inline for simplicity
    let level = if cli.verbose { tracing::Level::DEBUG } else { tracing::Level::INFO };
    tracing_subscriber::fmt().with_max_level(level).with_target(false).without_time().init();

    let result = match cli.command {
        Commands::Scan { paths, rules, archives } => {
            if paths.is_empty() {
                return Err(divine::error::DivineError::invalid_input("No paths specified for scanning"));
            }

            info!("Loading YARA rules...");
            let yara_rules = load_rules(rules.as_deref())?;

            let scanner = Scanner::builder()
                .min_risk(cli.min_risk)
                .include_data_files(cli.include_data_files)
                .build(yara_rules)?;

            info!("Starting scan of {} path(s)...", paths.len());
            let report = scan_paths(paths, &scanner, archives)?;

            if report.has_findings() {
                info!("🚨 Found {} malicious and {} suspicious files", report.malicious_files, report.suspicious_files);
            } else {
                info!("✅ No malicious content detected");
            }

            format_output(&report, &cli.format)?
        }

        Commands::Analyze { path, rules } => {
            let path = Path::new(&path);
            if !path.exists() {
                return Err(divine::error::DivineError::path_not_found(path));
            }

            info!("Loading YARA rules...");
            let yara_rules = load_rules(rules.as_deref())?;

            let scanner = Scanner::builder()
                .min_risk(RiskLevel::Low) // Show all findings for analysis
                .include_data_files(true)
                .build(yara_rules)?;

            info!("Analyzing: {}", path.display());
            let start_time = Instant::now();

            let file_report = scanner.scan_file(path)?;
            let duration = start_time.elapsed().as_millis() as u64;

            let mut report = Report::new();
            report.add_file(file_report);
            report.scan_duration_ms = duration;

            format_output(&report, &cli.format)?
        }
    };

    if let Some(output_file) = cli.output {
        fs::write(&output_file, &result).map_err(|e| divine::error::DivineError::io(format!("Failed to write output to {output_file}: {e}")))?;
        info!("Results written to {}", output_file);
    } else {
        print!("{}", result);
    }

    Ok(())
}

fn format_rule_name(rule_name: &str) -> String {
    // Map rule names to their actual malcontent file path structure
    match rule_name {
        // OS rules
        "getenv" => "os/env/get".to_string(),
        "env_get" => "os/env/get".to_string(),

        // Filesystem rules
        "fts" => "fs/directory/traverse".to_string(),
        "directory_traverse" => "fs/directory/traverse".to_string(),
        "readlink" => "fs/link_read".to_string(),
        "link_read" => "fs/link_read".to_string(),

        // Network rules
        "http" => "net/http".to_string(),
        "http_url" => "net/url/embedded".to_string(),
        "https_url" => "net/url/embedded".to_string(),
        "hardcoded_urls" => "net/url/embedded".to_string(),

        // Crypto rules
        "rc4" => "crypto/rc4".to_string(),

        // Execution rules
        "shell_TERM" => "os/terminal".to_string(),

        // Generic fallback patterns
        _ => {
            // For unknown rules, try some common patterns
            let rule_lower = rule_name.to_lowercase();
            if rule_lower.contains("inject") || rule_lower.contains("process") {
                format!("process/{}", rule_name)
            } else if rule_lower.contains("debug") || rule_lower.contains("anti") {
                format!("evasion/{}", rule_name)
            } else if rule_lower.contains("crypto") || rule_lower.contains("encrypt") {
                format!("crypto/{}", rule_name)
            } else if rule_lower.contains("network") || rule_lower.contains("http") {
                format!("net/{}", rule_name)
            } else if rule_lower.contains("file") || rule_lower.contains("dir") {
                format!("fs/{}", rule_name)
            } else if rule_lower.contains("obfusc") {
                format!("evasion/{}", rule_name)
            } else {
                rule_name.to_string()
            }
        }
    }
}

fn infer_category(rule_name: &str) -> String {
    let rule_lower = rule_name.to_lowercase();

    // Match malcontent's exact categories
    match rule_name {
        "hardcoded_urls" => "command & control".to_string(),
        "rc4" => "cryptography".to_string(),
        "shell_TERM" => "execution".to_string(),
        "directory_traverse" => "filesystem".to_string(),
        "link_read" => "filesystem".to_string(),
        "http_url" | "https_url" => "networking".to_string(),
        "env_get" => "operating-system".to_string(),
        _ => {
            // Fallback to pattern matching for other rules
            if rule_lower.contains("network")
                || rule_lower.contains("connect")
                || rule_lower.contains("socket")
                || rule_lower.contains("http")
            {
                "networking".to_string()
            } else if rule_lower.contains("crypto")
                || rule_lower.contains("encrypt")
                || rule_lower.contains("decrypt")
                || rule_lower.contains("hash")
                || rule_lower.contains("rc4")
            {
                "cryptography".to_string()
            } else if rule_lower.contains("process")
                || rule_lower.contains("inject")
                || rule_lower.contains("exec")
                || rule_lower.contains("shell")
                || rule_lower.contains("term")
            {
                "execution".to_string()
            } else if rule_lower.contains("file")
                || rule_lower.contains("dir")
                || rule_lower.contains("path")
                || rule_lower.contains("fs")
                || rule_lower.contains("fts")
            {
                "filesystem".to_string()
            } else if rule_lower.contains("registry")
                || rule_lower.contains("persist")
                || rule_lower.contains("service")
            {
                "persistence".to_string()
            } else if rule_lower.contains("debug") || rule_lower.contains("anti") || rule_lower.contains("evasion") {
                "anti-analysis".to_string()
            } else if rule_lower.contains("obfusc") || rule_lower.contains("pack") || rule_lower.contains("upx") {
                "obfuscation".to_string()
            } else if rule_lower.contains("c2")
                || rule_lower.contains("command")
                || rule_lower.contains("control")
                || rule_lower.contains("exfil")
                || rule_lower.contains("url")
            {
                "command & control".to_string()
            } else if rule_lower.contains("env") || rule_lower.contains("system") || rule_lower.contains("os") {
                "operating-system".to_string()
            } else if rule_lower.contains("malware") || rule_lower.contains("trojan") || rule_lower.contains("virus") {
                "malware".to_string()
            } else {
                "suspicious".to_string()
            }
        }
    }
}
