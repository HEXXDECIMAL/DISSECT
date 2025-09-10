use crate::config::{validation, ScanConfig};
use crate::error::{DivineError, Result};
use crate::report::{Behavior, FileReport, RiskLevel};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::Instant;
use tracing::{debug, info, warn};
use walkdir::WalkDir;
use yara_x::{Rules, Scanner as YaraScanner};

/// High-performance malware scanner using YARA rules
#[derive(Debug)]
pub struct Scanner {
    rules: Rules,
    config: ScanConfig,
}

#[derive(Debug)]
pub struct ScanResult {
    pub file_report: FileReport,
    pub error: Option<String>,
}

/// Builder for configuring and creating Scanner instances
#[derive(Debug)]
pub struct ScannerBuilder {
    config: ScanConfig,
}

impl ScannerBuilder {
    /// Create a new scanner builder with default configuration
    pub fn new() -> Self {
        Self { config: ScanConfig::default() }
    }

    /// Set the minimum risk level to report
    #[must_use]
    pub fn min_risk(mut self, min_risk: RiskLevel) -> Self {
        self.config.min_risk = min_risk;
        self
    }

    /// Enable or disable scanning of data files (non-executables)
    #[must_use]
    pub fn include_data_files(mut self, include_data_files: bool) -> Self {
        self.config.include_data_files = include_data_files;
        self
    }

    /// Set maximum file size to scan
    #[must_use]
    pub fn max_file_size(mut self, max_file_size: u64) -> Self {
        self.config.max_file_size = max_file_size;
        self
    }

    /// Set maximum number of concurrent file scanning operations
    #[must_use]
    pub fn max_concurrent_files(mut self, max_concurrent: usize) -> Self {
        self.config.max_concurrent_files = max_concurrent;
        self
    }

    /// Set whether to follow symbolic links
    #[must_use]
    pub fn follow_symlinks(mut self, follow: bool) -> Self {
        self.config.follow_symlinks = follow;
        self
    }

    /// Set whether to scan hidden files (dotfiles)
    #[must_use]
    pub fn scan_hidden_files(mut self, scan_hidden: bool) -> Self {
        self.config.scan_hidden_files = scan_hidden;
        self
    }

    /// Use a high-security configuration preset
    #[must_use]
    pub fn high_security(mut self) -> Self {
        self.config = ScanConfig::high_security();
        self
    }

    /// Use a high-performance configuration preset
    #[must_use]
    pub fn high_performance(mut self) -> Self {
        self.config = ScanConfig::high_performance();
        self
    }

    /// Set a custom configuration (validates the config)
    pub fn config(mut self, config: ScanConfig) -> Result<Self> {
        config.validate()?;
        self.config = config;
        Ok(self)
    }

    /// Build the scanner with the specified YARA rules
    pub fn build(self, rules: Rules) -> Result<Scanner> {
        self.config.validate()?;
        Ok(Scanner { rules, config: self.config })
    }
}

impl Default for ScannerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    /// Create a scanner builder for fluent configuration
    #[must_use]
    pub fn builder() -> ScannerBuilder {
        ScannerBuilder::new()
    }

    /// Create a new scanner with default configuration
    pub fn new(rules: Rules) -> Result<Self> {
        Self::builder().build(rules)
    }

    /// Create a scanner with a custom configuration
    pub fn with_config(rules: Rules, config: ScanConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { rules, config })
    }

    /// Get the scanner's configuration
    #[must_use]
    pub const fn config(&self) -> &ScanConfig {
        &self.config
    }

    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<FileReport> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy().to_string();

        debug!("Starting scan of file: {}", path_str);

        // Validate path for security
        validation::validate_path(path)?;

        if !path.exists() {
            warn!("File not found: {}", path_str);
            return Err(DivineError::path_not_found(path));
        }

        let metadata = fs::metadata(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                warn!("Permission denied accessing file: {}", path_str);
                DivineError::permission_denied(path)
            } else {
                warn!("Failed to read metadata for {}: {}", path_str, e);
                DivineError::Io(e)
            }
        })?;

        // Check file size limits
        if let Err(e) = validation::validate_file_size(metadata.len(), self.config.max_file_size) {
            info!(
                "Skipping oversized file {}: {} bytes (limit: {})",
                path_str,
                metadata.len(),
                self.config.max_file_size
            );
            return Err(e);
        }

        if metadata.len() == 0 {
            debug!("Skipping zero-sized file: {}", path_str);
            return Ok(FileReport::with_skipped(path_str, "Zero-sized file".to_string()));
        }

        let mime_type = mime_guess::from_path(path).first_or_text_plain().to_string();

        if !self.config.include_data_files && !Self::is_program_file(&mime_type) {
            debug!("Skipping data file: {} (type: {})", path_str, mime_type);
            return Ok(FileReport::with_skipped(path_str, "Data file or non-program".to_string()));
        }

        debug!("Reading file: {} ({} bytes, type: {})", path_str, metadata.len(), mime_type);
        let file_contents = fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                warn!("Permission denied reading file: {}", path_str);
                DivineError::permission_denied(path)
            } else {
                warn!("Failed to read file {}: {}", path_str, e);
                DivineError::Io(e)
            }
        })?;

        let sha256 = hex::encode(Sha256::digest(&file_contents));

        let mut file_report = FileReport::new(path_str.clone(), sha256, metadata.len(), mime_type);

        let start_time = Instant::now();
        let mut yara_scanner = YaraScanner::new(&self.rules);
        let scan_results = yara_scanner.scan(&file_contents).map_err(|e| {
            warn!("YARA scan failed for {}: {}", path_str, e);
            DivineError::yara_scan(path_str.clone(), e.to_string())
        })?;

        let scan_duration = start_time.elapsed();
        debug!("YARA scan completed for {} in {:?}", path_str, scan_duration);

        let matching_rules: Vec<_> = scan_results.matching_rules().collect();
        if !matching_rules.is_empty() {
            info!("Found {} matching rules for {}", matching_rules.len(), path_str);
        }

        for matching_rule in matching_rules {
            let rule_name = matching_rule.identifier().to_string();
            let risk_score = Self::extract_risk_score(&matching_rule);

            debug!("Processing rule match: {} (risk: {})", rule_name, risk_score);

            // Extract description from metadata or use rule name
            let description =
                Self::extract_description(&matching_rule).unwrap_or_else(|| format!("Matched rule: {rule_name}"));

            // Extract matched strings
            let match_strings = Self::extract_match_strings(&matching_rule, &file_contents);
            debug!("Extracted {} match strings for rule {}", match_strings.len(), rule_name);

            let mut behavior = Behavior::new(rule_name.clone(), rule_name.clone(), description, risk_score);
            behavior.match_strings = match_strings;

            // Extract metadata safely with logging
            if let Some(author) = Self::extract_metadata(&matching_rule, "author") {
                behavior.rule_author = Some(author);
            }
            if let Some(url) = Self::extract_metadata(&matching_rule, "url") {
                behavior.rule_url = Some(url);
            }
            if let Some(reference) = Self::extract_metadata(&matching_rule, "reference") {
                behavior.reference_url = Some(reference);
            }

            if behavior.risk_level >= self.config.min_risk {
                debug!("Adding behavior for rule {} (risk: {})", rule_name, behavior.risk_level.as_str());
                file_report.add_behavior(behavior);
            } else {
                debug!(
                    "Filtered out rule {} (risk {} < min {})",
                    rule_name,
                    behavior.risk_level.as_str(),
                    self.config.min_risk.as_str()
                );
            }
        }

        debug!("Scan completed for {}: {} behaviors detected", path_str, file_report.behaviors.len());

        Ok(file_report)
    }

    pub fn scan_directory<P: AsRef<Path>>(&self, dir_path: P) -> Result<Vec<FileReport>> {
        let dir_path = dir_path.as_ref();
        let mut results = Vec::new();
        let mut files_processed = 0;
        let mut files_skipped = 0;

        info!("Starting directory scan: {}", dir_path.display());

        let walker = WalkDir::new(dir_path).follow_links(self.config.follow_symlinks).into_iter();

        for entry in walker {
            match entry {
                Ok(entry) => {
                    if entry.file_type().is_file() {
                        // Skip hidden files unless configured to scan them
                        if !self.config.scan_hidden_files {
                            if let Some(filename) = entry.file_name().to_str() {
                                if filename.starts_with('.') {
                                    debug!("Skipping hidden file: {}", entry.path().display());
                                    files_skipped += 1;
                                    continue;
                                }
                            }
                        }

                        files_processed += 1;
                        match self.scan_file(entry.path()) {
                            Ok(report) => {
                                debug!("Successfully scanned: {}", entry.path().display());
                                results.push(report);
                            }
                            Err(e) => {
                                // Graceful degradation - continue scanning even if individual files fail
                                let path_str = entry.path().to_string_lossy().to_string();
                                if e.is_recoverable() {
                                    debug!("Recoverable error scanning {}: {}", path_str, e);
                                } else {
                                    warn!("Non-recoverable error scanning {}: {}", path_str, e);
                                    if e.is_security_related() {
                                        // Still continue but log security issues prominently
                                        warn!("Security-related error in {}: {}", path_str, e);
                                    }
                                }
                                results.push(FileReport::with_skipped(path_str, format!("Scan error: {e}")));
                                files_skipped += 1;
                            }
                        }
                    }
                }
                Err(e) => {
                    // Graceful degradation for directory traversal errors
                    warn!("Failed to access directory entry: {}", e);
                    files_skipped += 1;
                    // Continue scanning other entries
                }
            }
        }

        info!("Directory scan completed: {} files processed, {} skipped", files_processed, files_skipped);
        Ok(results)
    }

    fn is_program_file(mime_type: &str) -> bool {
        matches!(
            mime_type,
            "application/x-executable"
                | "application/x-sharedlib"
                | "application/x-object"
                | "application/x-dosexec"
                | "application/x-elf"
                | "application/x-mach-binary"
                | "text/x-shellscript"
                | "text/x-python"
                | "text/x-perl"
                | "text/x-ruby"
                | "text/x-php"
                | "application/javascript"
                | "text/x-go"
                | "text/x-c"
                | "text/x-c++"
                | "text/x-java-source"
        ) || mime_type.starts_with("text/")
            && (mime_type.contains("script") || mime_type.contains("source") || mime_type.contains("program"))
    }

    fn extract_risk_score(matching_rule: &yara_x::Rule) -> i32 {
        for (key, value) in matching_rule.metadata() {
            if key == "risk_score" {
                match value {
                    yara_x::MetaValue::String(s) => {
                        if let Ok(score) = s.parse::<i32>() {
                            return score;
                        }
                    }
                    yara_x::MetaValue::Integer(i) => {
                        return i32::try_from(i).unwrap_or(i32::MAX);
                    }
                    _ => {}
                }
            }
        }

        let rule_name = matching_rule.identifier();
        match rule_name {
            id if id.contains("critical") || id.contains("malware") => 4,
            id if id.contains("suspicious") || id.contains("high") => 3,
            id if id.contains("medium") => 2,
            _ => 1,
        }
    }

    fn extract_description(matching_rule: &yara_x::Rule) -> Option<String> {
        for (key, value) in matching_rule.metadata() {
            if key == "description" {
                if let yara_x::MetaValue::String(s) = value {
                    return Some(s.to_string());
                }
            }
        }
        None
    }

    fn extract_metadata(matching_rule: &yara_x::Rule, meta_key: &str) -> Option<String> {
        for (key, value) in matching_rule.metadata() {
            if key == meta_key {
                if let yara_x::MetaValue::String(s) = value {
                    return Some(s.to_string());
                }
            }
        }
        None
    }

    fn extract_match_strings(matching_rule: &yara_x::Rule, file_contents: &[u8]) -> Vec<String> {
        const MAX_MATCH_LENGTH: usize = 50;
        const MAX_HEX_BYTES: usize = 25;
        const MAX_MATCHES: usize = 10;

        let mut unique_matches = std::collections::HashSet::with_capacity(MAX_MATCHES);

        for pattern in matching_rule.patterns() {
            if unique_matches.len() >= MAX_MATCHES {
                break; // Early exit for performance
            }

            for m in pattern.matches() {
                let range = m.range();
                if range.start >= file_contents.len() || range.end > file_contents.len() {
                    continue;
                }

                let matched_bytes = &file_contents[range];
                let match_str = std::str::from_utf8(matched_bytes).map_or_else(
                    |_| {
                        // Handle binary data with hex representation
                        let bytes_to_show = matched_bytes.len().min(MAX_HEX_BYTES);
                        let mut hex_str = String::with_capacity(bytes_to_show * 3);
                        for (i, &byte) in matched_bytes[..bytes_to_show].iter().enumerate() {
                            if i > 0 {
                                hex_str.push(' ');
                            }
                            use std::fmt::Write;
                            let _ = write!(hex_str, "{byte:02x}");
                        }
                        if matched_bytes.len() > MAX_HEX_BYTES {
                            hex_str.push_str(" ...");
                        }
                        hex_str
                    },
                    |s| {
                        // Handle UTF-8 text efficiently
                        if s.len() > MAX_MATCH_LENGTH {
                            format!("{}...", &s[..MAX_MATCH_LENGTH])
                        } else {
                            s.chars().map(|c| if c.is_control() { '.' } else { c }).collect()
                        }
                    },
                );

                unique_matches.insert(match_str);
                if unique_matches.len() >= MAX_MATCHES {
                    break;
                }
            }
        }

        // Convert to sorted vector for consistent output
        let mut matches: Vec<String> = unique_matches.into_iter().collect();
        matches.sort_unstable(); // Faster than sort() for strings
        matches
    }
}
