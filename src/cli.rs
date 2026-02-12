//! Command-line interface definitions and parsing.
//!
//! This module defines the CLI structure using clap, including:
//! - Main command arguments
//! - Subcommands (diff, etc.)
//! - Component disable flags
//! - Output formatting options
//!
//! # Component Control
//!
//! DISSECT supports disabling expensive analysis components:
//! - `--disable yara` - Skip YARA pattern matching
//! - `--disable radare2` - Skip binary disassembly
//! - `--disable upx` - Skip UPX unpacking attempts
//! - `--disable third-party` - Skip third-party YARA rules

use clap::{Parser, Subcommand};

/// Parse comma-separated platforms string into a vector of Platform values
/// Returns vec![Platform::All] if input is empty or "all"
pub fn parse_platforms(s: &str) -> Vec<crate::composite_rules::Platform> {
    use crate::composite_rules::Platform;

    if s.is_empty() {
        return vec![Platform::All];
    }

    let platforms: Vec<Platform> = s
        .split(',')
        .map(|p| p.trim().to_lowercase())
        .filter(|p| !p.is_empty())
        .filter_map(|p| match p.as_str() {
            "all" => Some(Platform::All),
            "linux" => Some(Platform::Linux),
            "macos" | "darwin" => Some(Platform::MacOS),
            "windows" | "win" => Some(Platform::Windows),
            "unix" => Some(Platform::Unix),
            "android" => Some(Platform::Android),
            "ios" => Some(Platform::Ios),
            unknown => {
                eprintln!("⚠️  Unknown platform '{}', ignoring", unknown);
                None
            }
        })
        .collect();

    if platforms.is_empty() || platforms.contains(&Platform::All) {
        vec![Platform::All]
    } else {
        platforms
    }
}

/// Default passwords to try for encrypted zip files (common malware sample passwords)
pub const DEFAULT_ZIP_PASSWORDS: &[&str] =
    &["infected", "infect3d", "malware", "virus", "password"];

/// Components that can be disabled via --disable flag
pub const DISABLEABLE_COMPONENTS: &[&str] = &["yara", "radare2", "upx", "third-party"];

/// Default components to disable (for faster testing)
pub const DEFAULT_DISABLED: &[&str] = &["third-party"];

/// Tracks which components are disabled
#[derive(Debug, Clone, Default)]
pub struct DisabledComponents {
    pub yara: bool,
    pub radare2: bool,
    pub upx: bool,
    pub third_party: bool,
}

impl DisabledComponents {
    /// Parse comma-separated list of components to disable
    pub fn parse(s: &str) -> Self {
        let mut disabled = Self::default();
        for component in s.split(',').map(|c| c.trim().to_lowercase()) {
            match component.as_str() {
                "yara" => disabled.yara = true,
                "radare2" => disabled.radare2 = true,
                "upx" => disabled.upx = true,
                "third-party" => disabled.third_party = true,
                _ => {} // Ignore unknown components
            }
        }
        disabled
    }

    /// Create from a list of component names
    pub fn from_list(components: &[&str]) -> Self {
        let mut disabled = Self::default();
        for component in components {
            match *component {
                "yara" => disabled.yara = true,
                "radare2" => disabled.radare2 = true,
                "upx" => disabled.upx = true,
                "third-party" => disabled.third_party = true,
                _ => {}
            }
        }
        disabled
    }

    /// Check if any components are disabled
    pub fn any_disabled(&self) -> bool {
        self.yara || self.radare2 || self.upx || self.third_party
    }

    /// Get list of disabled component names
    pub fn disabled_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.yara {
            names.push("yara");
        }
        if self.radare2 {
            names.push("radare2");
        }
        if self.upx {
            names.push("upx");
        }
        if self.third_party {
            names.push("third-party");
        }
        names
    }
}

#[derive(Parser, Debug)]
#[command(name = "dissect")]
#[command(
    about = "Deep static analysis tool for extracting features from binaries and source code"
)]
#[command(version)]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Files or directories to analyze (when no subcommand is specified)
    #[arg(value_name = "PATH")]
    pub paths: Vec<String>,

    /// Output as JSONL (machine-readable, streaming). Shorthand for --format jsonl.
    #[arg(long)]
    pub json: bool,

    /// Output format: terminal (default), json, or jsonl (streaming)
    #[arg(long, value_enum)]
    pub format: Option<OutputFormat>,

    /// Write output to file
    #[arg(short, long)]
    pub output: Option<String>,

    /// Verbose logging
    #[arg(short, long)]
    pub verbose: bool,

    /// Write logs to file (in addition to stderr)
    #[arg(long, value_name = "FILE")]
    pub log_file: Option<String>,

    /// Enable full trait validation (expensive, ~60s+). Enabled by default.
    /// Use --validate=false to disable. Can also set DISSECT_VALIDATE=0 to disable.
    #[arg(long, default_value_t = true)]
    pub validate: bool,

    /// Additional password to try for encrypted zip files (can be specified multiple times)
    #[arg(long = "zip-password", value_name = "PASSWORD")]
    pub zip_passwords: Vec<String>,

    /// Disable automatic password guessing for encrypted zip files
    #[arg(long)]
    pub no_zip_passwords: bool,

    /// Enable third-party YARA rules (from third_party/yara directory)
    #[arg(long)]
    pub third_party_yara: bool,

    /// Disable specific components (comma-separated: yara,radare2,upx,third-party)
    /// Default: third-party is disabled for faster analysis
    #[arg(long, value_name = "COMPONENTS", default_value = "third-party")]
    pub disable: String,

    /// Enable all components (overrides --disable default)
    #[arg(long)]
    pub enable_all: bool,

    /// Exit with error if top-level file has highest trait criticality matching these levels
    /// (comma-separated: filtered,inert,notable,suspicious,hostile)
    /// Example: --error-if=suspicious,hostile (for sweeping known-good data)
    /// Example: --error-if=inert,notable (for sweeping known-bad data for weak detections)
    #[arg(long, value_name = "LEVELS")]
    pub error_if: Option<String>,

    /// Include all files in directory scans, even unknown types
    /// By default, only recognized code/binary files are analyzed
    #[arg(long)]
    pub all_files: bool,

    /// Filter rules by target platform(s) (comma-separated, default: all)
    /// Examples: --platforms linux,macos or --platforms windows
    /// Valid values: all, linux, macos, windows, unix, android, ios
    #[arg(long, value_name = "PLATFORMS", default_value = "all")]
    pub platforms: String,

    /// Directory to extract all analyzed files for external tools or review.
    /// Files are written to <dir>/<sha256>/<original-path> preserving structure.
    /// When set, disables in-memory extraction (all files written to disk).
    #[arg(long, value_name = "DIR")]
    pub extract_dir: Option<String>,

    /// Custom traits directory (overrides DISSECT_TRAITS_PATH env var and default "traits")
    #[arg(long, value_name = "DIR")]
    pub traits_dir: Option<String>,

    /// Minimum recursive precision required for HOSTILE composite traits.
    /// Rules below this threshold are downgraded to SUSPICIOUS.
    #[arg(long, default_value_t = 3.5)]
    pub min_hostile_precision: f32,

    /// Minimum recursive precision required for SUSPICIOUS composite traits.
    /// Rules below this threshold are downgraded to NOTABLE.
    #[arg(long, default_value_t = 1.5)]
    pub min_suspicious_precision: f32,

    /// Maximum file size (in MB) to keep in memory during archive analysis.
    /// Files larger than this are written to temp files. Default: 100 MB.
    #[arg(long, value_name = "MB", default_value_t = 100)]
    pub max_file_mem: u64,
}

impl Args {
    /// Get the disabled components based on --disable and --enable-all flags
    pub fn disabled_components(&self) -> DisabledComponents {
        if self.enable_all {
            DisabledComponents::default()
        } else {
            DisabledComponents::parse(&self.disable)
        }
    }

    /// Get the output format based on --json and --format flags
    pub fn format(&self) -> OutputFormat {
        // --format takes precedence over --json
        if let Some(format) = self.format {
            return format;
        }
        if self.json {
            OutputFormat::Jsonl
        } else {
            OutputFormat::Terminal
        }
    }

    /// Parse --error-if flag into a set of criticality levels
    pub fn error_if_levels(&self) -> Option<Vec<crate::types::Criticality>> {
        self.error_if.as_ref().map(|s| {
            s.split(',')
                .map(|level| parse_criticality_level(level.trim()))
                .collect()
        })
    }

    /// Parse --platforms flag into a vector of Platform values
    pub fn platforms(&self) -> Vec<crate::composite_rules::Platform> {
        parse_platforms(&self.platforms)
    }
}

/// Parse a criticality level string (case-insensitive)
fn parse_criticality_level(s: &str) -> crate::types::Criticality {
    match s.to_lowercase().as_str() {
        "filtered" => crate::types::Criticality::Filtered,
        "inert" => crate::types::Criticality::Inert,
        "notable" => crate::types::Criticality::Notable,
        "suspicious" => crate::types::Criticality::Suspicious,
        "hostile" | "malicious" => crate::types::Criticality::Hostile,
        _ => {
            eprintln!("⚠️  Unknown criticality level '{}', treating as 'inert'", s);
            crate::types::Criticality::Inert
        }
    }
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Analyze files or directories in detail
    Analyze {
        /// Target files or directories to analyze
        #[arg(required = true)]
        targets: Vec<String>,

        /// Enable third-party YARA rules (from third_party/yara directory)
        #[arg(long)]
        third_party_yara: bool,
    },

    /// Scan multiple files or directories
    Scan {
        /// Paths to scan (files or directories)
        #[arg(required = true)]
        paths: Vec<String>,

        /// Enable third-party YARA rules (from third_party/yara directory)
        #[arg(long)]
        third_party_yara: bool,
    },

    /// Compare two versions (diff mode) for supply chain attack detection
    Diff {
        /// Old/baseline version (file or directory)
        old: String,

        /// New/target version (file or directory)
        new: String,
    },

    /// Extract language-specific strings from a binary
    Strings {
        /// Target binary file
        #[arg(required = true)]
        target: String,

        /// Minimum string length
        #[arg(short, long, default_value = "4")]
        min_length: usize,
    },

    /// Extract symbols (imports, exports, functions) from a binary or source file
    Symbols {
        /// Target file (binary or source)
        #[arg(required = true)]
        target: String,
    },

    /// Extract section information (name, address, size, entropy) from a binary
    Sections {
        /// Target binary file
        #[arg(required = true)]
        target: String,
    },

    /// Debug rule evaluation - trace through how rules match or fail
    TestRules {
        /// Target file to analyze
        #[arg(required = true)]
        target: String,

        /// Comma-separated list of rule/trait IDs to debug
        /// (e.g., "lateral/supply-chain/npm/obfuscated-trojan,anti-static/obfuscation/code-metrics")
        #[arg(short, long, value_name = "RULE_IDS")]
        rules: String,
    },

    /// Test pattern matching against a file
    TestMatch {
        /// Target file to analyze
        #[arg(required = true)]
        target: String,

        /// Type of search to perform (string, symbol, raw, kv, hex, encoded)
        #[arg(short, long, value_enum, default_value = "string")]
        r#type: SearchType,

        /// Match method: exact, contains, regex, or word
        #[arg(short, long, value_enum, default_value = "contains")]
        method: MatchMethod,

        /// Pattern to search for (for kv: the value to match, or omit for existence check)
        #[arg(short, long)]
        pattern: Option<String>,

        /// Path expression for kv searches (e.g., "scripts.postinstall", "permissions[*]")
        #[arg(long)]
        kv_path: Option<String>,

        /// File type to use for analysis (auto-detected if not specified)
        #[arg(short, long, value_enum)]
        file_type: Option<DetectFileType>,

        /// Minimum number of matches required (for string/raw/encoded searches)
        #[arg(long, default_value = "1")]
        count_min: usize,

        /// Maximum number of matches allowed (for string/raw/encoded searches)
        #[arg(long)]
        count_max: Option<usize>,

        /// Minimum matches per kilobyte (density floor)
        #[arg(long)]
        per_kb_min: Option<f64>,

        /// Maximum matches per kilobyte (density ceiling)
        #[arg(long)]
        per_kb_max: Option<f64>,

        /// Case-insensitive matching
        #[arg(short, long)]
        case_insensitive: bool,

        /// Restrict search to named section (e.g., "text", ".data", "__TEXT,__text")
        #[arg(long)]
        section: Option<String>,

        /// Search only at exact file offset (hex or decimal, negative = from end)
        #[arg(long)]
        offset: Option<i64>,

        /// Search within byte range [start,end) - use "start," for open-ended (e.g., "0,4096" or "-1024,")
        #[arg(long, value_parser = parse_offset_range)]
        offset_range: Option<(i64, Option<i64>)>,

        /// Section-relative offset (requires --section)
        #[arg(long)]
        section_offset: Option<i64>,

        /// Section-relative byte range [start,end) (requires --section)
        #[arg(long, value_parser = parse_offset_range)]
        section_offset_range: Option<(i64, Option<i64>)>,

        /// Filter by encoding method(s) for 'encoded' search type
        /// Examples: "base64", "xor,hex", "xor+base64"
        /// Use comma for OR, plus for chain sequence
        #[arg(long)]
        encoding: Option<String>,

        /// Require matches to contain a valid external IP (not private/loopback/reserved)
        #[arg(long)]
        external_ip: bool,

        /// Minimum entropy for section searches (0.0-8.0)
        #[arg(long)]
        entropy_min: Option<f64>,

        /// Maximum entropy for section searches (0.0-8.0)
        #[arg(long)]
        entropy_max: Option<f64>,

        /// Minimum section length in bytes (for section searches)
        #[arg(long)]
        length_min: Option<u64>,

        /// Maximum section length in bytes (for section searches)
        #[arg(long)]
        length_max: Option<u64>,
    },
}

/// Parse an offset range like "0,4096" or "-1024," into (start, Option<end>)
fn parse_offset_range(s: &str) -> Result<(i64, Option<i64>), String> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 2 {
        return Err("offset_range must be 'start,end' or 'start,' for open-ended".to_string());
    }
    let start: i64 = parts[0]
        .trim()
        .parse()
        .map_err(|_| format!("invalid start offset: {}", parts[0]))?;
    let end = if parts[1].trim().is_empty() {
        None
    } else {
        Some(
            parts[1]
                .trim()
                .parse()
                .map_err(|_| format!("invalid end offset: {}", parts[1]))?,
        )
    };
    Ok((start, end))
}

#[derive(Debug, Clone, clap::ValueEnum, PartialEq)]
pub enum SearchType {
    /// Search in extracted strings
    String,
    /// Search in symbols (imports/exports)
    Symbol,
    /// Search in raw file content
    Raw,
    /// Search in structured data (JSON/YAML/TOML manifests)
    Kv,
    /// Search for hex byte patterns
    Hex,
    /// Search in decoded strings (base64, xor, hex, url, etc.) - optionally filter by encoding
    Encoded,
    /// Search for sections by name (supports entropy/size constraints via count_min/max and per_kb_min/max)
    Section,
}

#[derive(Debug, Clone, clap::ValueEnum, PartialEq)]
pub enum MatchMethod {
    /// Exact match
    Exact,
    /// Contains substring
    Contains,
    /// Regular expression match
    Regex,
    /// Whole word match
    Word,
}

#[derive(Debug, Clone, clap::ValueEnum, PartialEq)]
pub enum DetectFileType {
    /// ELF binary
    Elf,
    /// PE/Windows executable
    Pe,
    /// Mach-O binary
    Macho,
    /// JavaScript source
    JavaScript,
    /// Python source
    Python,
    /// Go source
    Go,
    /// Shell script
    Shell,
    /// Raw/binary content
    Raw,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, PartialEq)]
pub enum OutputFormat {
    /// JSONL output (newline-delimited JSON) for streaming
    Jsonl,
    /// Human-readable terminal output
    Terminal,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_paths_without_subcommand() {
        let args = Args::try_parse_from(["dissect", "file1.bin", "file2.bin", "dir1"]).unwrap();

        assert!(args.command.is_none());
        assert_eq!(args.paths, vec!["file1.bin", "file2.bin", "dir1"]);
    }

    #[test]
    fn test_parse_single_path_without_subcommand() {
        let args = Args::try_parse_from(["dissect", "file.bin"]).unwrap();

        assert!(args.command.is_none());
        assert_eq!(args.paths, vec!["file.bin"]);
    }

    #[test]
    fn test_parse_analyze_command() {
        let args = Args::try_parse_from(["dissect", "analyze", "file.bin"]).unwrap();

        assert!(matches!(args.command, Some(Command::Analyze { .. })));
        if let Some(Command::Analyze {
            targets,
            third_party_yara,
        }) = args.command
        {
            assert_eq!(targets, vec!["file.bin"]);
            assert!(!third_party_yara); // Third-party YARA disabled by default
        }
    }

    #[test]
    fn test_parse_analyze_multiple_targets() {
        let args =
            Args::try_parse_from(["dissect", "analyze", "file1.bin", "file2.bin", "dir1"]).unwrap();

        if let Some(Command::Analyze {
            targets,
            third_party_yara,
        }) = args.command
        {
            assert_eq!(targets, vec!["file1.bin", "file2.bin", "dir1"]);
            assert!(!third_party_yara); // Third-party YARA disabled by default
        }
    }

    #[test]
    fn test_parse_analyze_with_third_party_yara() {
        let args =
            Args::try_parse_from(["dissect", "analyze", "file.bin", "--third-party-yara"]).unwrap();

        if let Some(Command::Analyze {
            targets,
            third_party_yara,
        }) = args.command
        {
            assert_eq!(targets, vec!["file.bin"]);
            assert!(third_party_yara); // Third-party YARA explicitly enabled
        }
    }

    #[test]
    fn test_parse_scan_command() {
        let args = Args::try_parse_from(["dissect", "scan", "dir1", "dir2"]).unwrap();

        assert!(matches!(args.command, Some(Command::Scan { .. })));
        if let Some(Command::Scan {
            paths,
            third_party_yara,
        }) = args.command
        {
            assert_eq!(paths, vec!["dir1", "dir2"]);
            assert!(!third_party_yara); // Third-party YARA disabled by default
        }
    }

    #[test]
    fn test_parse_scan_with_third_party_yara() {
        let args = Args::try_parse_from(["dissect", "scan", "dir1", "--third-party-yara"]).unwrap();

        if let Some(Command::Scan {
            paths,
            third_party_yara,
        }) = args.command
        {
            assert_eq!(paths, vec!["dir1"]);
            assert!(third_party_yara); // Third-party YARA explicitly enabled
        }
    }

    #[test]
    fn test_parse_diff_command() {
        let args = Args::try_parse_from(["dissect", "diff", "old.bin", "new.bin"]).unwrap();

        assert!(matches!(args.command, Some(Command::Diff { .. })));
        if let Some(Command::Diff { old, new }) = args.command {
            assert_eq!(old, "old.bin");
            assert_eq!(new, "new.bin");
        }
    }

    #[test]
    fn test_parse_strings_command() {
        let args = Args::try_parse_from(["dissect", "strings", "file.bin"]).unwrap();

        assert!(matches!(args.command, Some(Command::Strings { .. })));
        if let Some(Command::Strings { target, min_length }) = args.command {
            assert_eq!(target, "file.bin");
            assert_eq!(min_length, 4); // Default value
        }
    }

    #[test]
    fn test_parse_strings_command_with_min_length() {
        let args = Args::try_parse_from(["dissect", "strings", "file.bin", "-m", "10"]).unwrap();

        if let Some(Command::Strings { target, min_length }) = args.command {
            assert_eq!(target, "file.bin");
            assert_eq!(min_length, 10);
        }
    }

    #[test]
    fn test_parse_symbols_command() {
        let args = Args::try_parse_from(["dissect", "symbols", "file.bin"]).unwrap();

        assert!(matches!(args.command, Some(Command::Symbols { .. })));
        if let Some(Command::Symbols { target }) = args.command {
            assert_eq!(target, "file.bin");
        }
    }

    #[test]
    fn test_parse_json_flag() {
        let args = Args::try_parse_from(["dissect", "--json", "file.bin"]).unwrap();
        assert!(args.json);
        assert!(matches!(args.format(), OutputFormat::Jsonl));
    }

    #[test]
    fn test_parse_no_json_flag() {
        let args = Args::try_parse_from(["dissect", "file.bin"]).unwrap();
        assert!(!args.json);
        assert!(matches!(args.format(), OutputFormat::Terminal));
    }

    #[test]
    fn test_parse_output_file() {
        let args = Args::try_parse_from(["dissect", "-o", "results.json", "file.bin"]).unwrap();
        assert_eq!(args.output, Some("results.json".to_string()));
    }

    #[test]
    fn test_parse_verbose() {
        let args = Args::try_parse_from(["dissect", "-v", "file.bin"]).unwrap();
        assert!(args.verbose);
    }

    #[test]
    fn test_parse_no_verbose() {
        let args = Args::try_parse_from(["dissect", "file.bin"]).unwrap();
        assert!(!args.verbose);
    }

    #[test]
    fn test_parse_all_options_together() {
        let args = Args::try_parse_from([
            "dissect",
            "--json",
            "-o",
            "output.json",
            "-v",
            "--third-party-yara",
            "file1.bin",
            "file2.bin",
        ])
        .unwrap();

        assert!(args.json);
        assert!(matches!(args.format(), OutputFormat::Jsonl));
        assert_eq!(args.output, Some("output.json".to_string()));
        assert!(args.verbose);
        assert!(args.third_party_yara); // Third-party YARA explicitly enabled
        assert_eq!(args.paths, vec!["file1.bin", "file2.bin"]);
    }

    #[test]
    fn test_parse_scan_no_paths_fails() {
        let result = Args::try_parse_from(["dissect", "scan"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_no_args_succeeds_with_empty_paths() {
        // Running without args is now valid (will show help or error at runtime)
        let result = Args::try_parse_from(["dissect"]);
        assert!(result.is_ok());
        assert!(result.unwrap().paths.is_empty());
    }

    #[test]
    fn test_precision_threshold_defaults() {
        let args = Args::try_parse_from(["dissect", "file.bin"]).unwrap();
        assert_eq!(args.min_hostile_precision, 4.0);
        assert_eq!(args.min_suspicious_precision, 1.5);
    }

    #[test]
    fn test_precision_threshold_flags() {
        let args = Args::try_parse_from([
            "dissect",
            "--min-hostile-precision",
            "5.5",
            "--min-suspicious-precision",
            "2.7",
            "file.bin",
        ])
        .unwrap();
        assert_eq!(args.min_hostile_precision, 5.5);
        assert_eq!(args.min_suspicious_precision, 2.7);
    }

    #[test]
    fn test_parse_global_third_party_yara() {
        let args = Args::try_parse_from(["dissect", "--third-party-yara", "file.bin"]).unwrap();
        assert!(args.third_party_yara); // Third-party YARA explicitly enabled
        assert_eq!(args.paths, vec!["file.bin"]);
    }

    #[test]
    fn test_third_party_yara_disabled_by_default() {
        let args = Args::try_parse_from(["dissect", "file.bin"]).unwrap();
        assert!(!args.third_party_yara); // Third-party YARA disabled by default
    }

    #[test]
    fn test_output_format_clone() {
        let format = OutputFormat::Jsonl;
        let cloned = format;
        assert!(matches!(cloned, OutputFormat::Jsonl));
    }

    #[test]
    fn test_output_format_debug() {
        let format = OutputFormat::Terminal;
        let debug_str = format!("{:?}", format);
        assert!(debug_str.contains("Terminal"));
    }

    #[test]
    fn test_parse_zip_password_single() {
        let args =
            Args::try_parse_from(["dissect", "--zip-password", "secret", "analyze", "file.zip"])
                .unwrap();
        assert_eq!(args.zip_passwords, vec!["secret"]);
        assert!(!args.no_zip_passwords);
    }

    #[test]
    fn test_parse_zip_password_multiple() {
        let args = Args::try_parse_from([
            "dissect",
            "--zip-password",
            "pass1",
            "--zip-password",
            "pass2",
            "--zip-password",
            "pass3",
            "analyze",
            "file.zip",
        ])
        .unwrap();
        assert_eq!(args.zip_passwords, vec!["pass1", "pass2", "pass3"]);
    }

    #[test]
    fn test_parse_no_zip_passwords() {
        let args =
            Args::try_parse_from(["dissect", "--no-zip-passwords", "analyze", "file.zip"]).unwrap();
        assert!(args.no_zip_passwords);
        assert!(args.zip_passwords.is_empty());
    }

    #[test]
    fn test_parse_zip_password_default_empty() {
        let args = Args::try_parse_from(["dissect", "analyze", "file.zip"]).unwrap();
        assert!(args.zip_passwords.is_empty());
        assert!(!args.no_zip_passwords);
    }

    #[test]
    fn test_default_zip_passwords_content() {
        // Verify the default passwords are what we expect
        assert!(DEFAULT_ZIP_PASSWORDS.contains(&"infected"));
        assert!(DEFAULT_ZIP_PASSWORDS.contains(&"infect3d"));
        assert!(DEFAULT_ZIP_PASSWORDS.contains(&"malware"));
        assert!(DEFAULT_ZIP_PASSWORDS.contains(&"virus"));
        assert!(DEFAULT_ZIP_PASSWORDS.contains(&"password"));
        assert_eq!(DEFAULT_ZIP_PASSWORDS.len(), 5);
    }

    #[test]
    fn test_disabled_components_default() {
        let args = Args::try_parse_from(["dissect", "file.bin"]).unwrap();
        let disabled = args.disabled_components();
        // third-party is disabled by default
        assert!(disabled.third_party);
        assert!(!disabled.yara);
        assert!(!disabled.radare2);
        assert!(!disabled.upx);
    }

    #[test]
    fn test_disabled_components_custom() {
        let args =
            Args::try_parse_from(["dissect", "--disable", "yara,radare2", "file.bin"]).unwrap();
        let disabled = args.disabled_components();
        assert!(disabled.yara);
        assert!(disabled.radare2);
        assert!(!disabled.upx);
        assert!(!disabled.third_party);
    }

    #[test]
    fn test_disabled_components_all() {
        let args = Args::try_parse_from([
            "dissect",
            "--disable",
            "yara,radare2,upx,third-party",
            "file.bin",
        ])
        .unwrap();
        let disabled = args.disabled_components();
        assert!(disabled.yara);
        assert!(disabled.radare2);
        assert!(disabled.upx);
        assert!(disabled.third_party);
    }

    #[test]
    fn test_enable_all_overrides_disable() {
        let args = Args::try_parse_from(["dissect", "--enable-all", "file.bin"]).unwrap();
        let disabled = args.disabled_components();
        // --enable-all should override the default --disable=third-party
        assert!(!disabled.third_party);
        assert!(!disabled.yara);
        assert!(!disabled.radare2);
        assert!(!disabled.upx);
    }

    #[test]
    fn test_disabled_components_from_str() {
        let disabled = DisabledComponents::parse("yara,upx");
        assert!(disabled.yara);
        assert!(disabled.upx);
        assert!(!disabled.radare2);
        assert!(!disabled.third_party);
    }

    #[test]
    fn test_disabled_components_from_str_with_spaces() {
        let disabled = DisabledComponents::parse("yara, radare2 , upx");
        assert!(disabled.yara);
        assert!(disabled.radare2);
        assert!(disabled.upx);
        assert!(!disabled.third_party);
    }

    #[test]
    fn test_disabled_components_from_str_ignores_unknown() {
        let disabled = DisabledComponents::parse("yara,unknown,radare2");
        assert!(disabled.yara);
        assert!(disabled.radare2);
        assert!(!disabled.upx);
        assert!(!disabled.third_party);
    }

    #[test]
    fn test_disabled_components_any_disabled() {
        let disabled = DisabledComponents::default();
        assert!(!disabled.any_disabled());

        let disabled = DisabledComponents::parse("yara");
        assert!(disabled.any_disabled());
    }

    #[test]
    fn test_disabled_components_disabled_names() {
        let disabled = DisabledComponents::parse("yara,upx");
        let names = disabled.disabled_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"yara"));
        assert!(names.contains(&"upx"));
    }

    #[test]
    fn test_disable_empty_string() {
        let args = Args::try_parse_from(["dissect", "--disable", "", "file.bin"]).unwrap();
        let disabled = args.disabled_components();
        // Empty string means nothing disabled
        assert!(!disabled.yara);
        assert!(!disabled.radare2);
        assert!(!disabled.upx);
        assert!(!disabled.third_party);
    }

    #[test]
    fn test_error_if_single_level() {
        let args =
            Args::try_parse_from(["dissect", "--error-if", "suspicious", "file.bin"]).unwrap();
        let levels = args.error_if_levels().unwrap();
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0], crate::types::Criticality::Suspicious);
    }

    #[test]
    fn test_error_if_multiple_levels() {
        let args =
            Args::try_parse_from(["dissect", "--error-if", "suspicious,hostile", "file.bin"])
                .unwrap();
        let levels = args.error_if_levels().unwrap();
        assert_eq!(levels.len(), 2);
        assert!(levels.contains(&crate::types::Criticality::Suspicious));
        assert!(levels.contains(&crate::types::Criticality::Hostile));
    }

    #[test]
    fn test_error_if_all_levels() {
        let args = Args::try_parse_from([
            "dissect",
            "--error-if",
            "filtered,inert,notable,suspicious,hostile",
            "file.bin",
        ])
        .unwrap();
        let levels = args.error_if_levels().unwrap();
        assert_eq!(levels.len(), 5);
        assert!(levels.contains(&crate::types::Criticality::Filtered));
        assert!(levels.contains(&crate::types::Criticality::Inert));
        assert!(levels.contains(&crate::types::Criticality::Notable));
        assert!(levels.contains(&crate::types::Criticality::Suspicious));
        assert!(levels.contains(&crate::types::Criticality::Hostile));
    }

    #[test]
    fn test_error_if_with_spaces() {
        let args = Args::try_parse_from([
            "dissect",
            "--error-if",
            "suspicious, hostile , notable",
            "file.bin",
        ])
        .unwrap();
        let levels = args.error_if_levels().unwrap();
        assert_eq!(levels.len(), 3);
        assert!(levels.contains(&crate::types::Criticality::Suspicious));
        assert!(levels.contains(&crate::types::Criticality::Hostile));
        assert!(levels.contains(&crate::types::Criticality::Notable));
    }

    #[test]
    fn test_error_if_none() {
        let args = Args::try_parse_from(["dissect", "file.bin"]).unwrap();
        assert!(args.error_if_levels().is_none());
    }

    #[test]
    fn test_error_if_case_insensitive() {
        let args = Args::try_parse_from([
            "dissect",
            "--error-if",
            "SUSPICIOUS,Hostile,NoTabLe",
            "file.bin",
        ])
        .unwrap();
        let levels = args.error_if_levels().unwrap();
        assert_eq!(levels.len(), 3);
        assert!(levels.contains(&crate::types::Criticality::Suspicious));
        assert!(levels.contains(&crate::types::Criticality::Hostile));
        assert!(levels.contains(&crate::types::Criticality::Notable));
    }

    // Platform parsing tests
    #[test]
    fn test_parse_platforms_default() {
        use crate::composite_rules::Platform;
        let platforms = parse_platforms("all");
        assert_eq!(platforms, vec![Platform::All]);
    }

    #[test]
    fn test_parse_platforms_empty() {
        use crate::composite_rules::Platform;
        let platforms = parse_platforms("");
        assert_eq!(platforms, vec![Platform::All]);
    }

    #[test]
    fn test_parse_platforms_single() {
        use crate::composite_rules::Platform;
        assert_eq!(parse_platforms("linux"), vec![Platform::Linux]);
        assert_eq!(parse_platforms("macos"), vec![Platform::MacOS]);
        assert_eq!(parse_platforms("darwin"), vec![Platform::MacOS]);
        assert_eq!(parse_platforms("windows"), vec![Platform::Windows]);
        assert_eq!(parse_platforms("win"), vec![Platform::Windows]);
        assert_eq!(parse_platforms("unix"), vec![Platform::Unix]);
        assert_eq!(parse_platforms("android"), vec![Platform::Android]);
        assert_eq!(parse_platforms("ios"), vec![Platform::Ios]);
    }

    #[test]
    fn test_parse_platforms_multiple() {
        use crate::composite_rules::Platform;
        let platforms = parse_platforms("linux,macos");
        assert_eq!(platforms.len(), 2);
        assert!(platforms.contains(&Platform::Linux));
        assert!(platforms.contains(&Platform::MacOS));
    }

    #[test]
    fn test_parse_platforms_with_spaces() {
        use crate::composite_rules::Platform;
        let platforms = parse_platforms(" linux , macos , windows ");
        assert_eq!(platforms.len(), 3);
        assert!(platforms.contains(&Platform::Linux));
        assert!(platforms.contains(&Platform::MacOS));
        assert!(platforms.contains(&Platform::Windows));
    }

    #[test]
    fn test_parse_platforms_case_insensitive() {
        use crate::composite_rules::Platform;
        assert_eq!(parse_platforms("LINUX"), vec![Platform::Linux]);
        assert_eq!(parse_platforms("MacOS"), vec![Platform::MacOS]);
        assert_eq!(parse_platforms("Windows"), vec![Platform::Windows]);
    }

    #[test]
    fn test_parse_platforms_all_overrides() {
        use crate::composite_rules::Platform;
        // If "all" is in the list, it should return just [All]
        let platforms = parse_platforms("linux,all,macos");
        assert_eq!(platforms, vec![Platform::All]);
    }

    #[test]
    fn test_parse_platforms_unknown_ignored() {
        use crate::composite_rules::Platform;
        let platforms = parse_platforms("linux,freebsd,macos");
        // freebsd should be ignored, only linux and macos
        assert_eq!(platforms.len(), 2);
        assert!(platforms.contains(&Platform::Linux));
        assert!(platforms.contains(&Platform::MacOS));
    }

    #[test]
    fn test_platforms_cli_flag() {
        let args =
            Args::try_parse_from(["dissect", "--platforms", "linux,macos", "file.bin"]).unwrap();
        assert_eq!(args.platforms, "linux,macos");
    }

    #[test]
    fn test_platforms_default_value() {
        let args = Args::try_parse_from(["dissect", "file.bin"]).unwrap();
        assert_eq!(args.platforms, "all");
    }
}
