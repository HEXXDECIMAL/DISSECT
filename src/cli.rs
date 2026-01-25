use clap::{Parser, Subcommand};

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
    pub fn from_str(s: &str) -> Self {
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

    /// Output as JSON (machine-readable)
    #[arg(long)]
    pub json: bool,

    /// Write output to file
    #[arg(short, long)]
    pub output: Option<String>,

    /// Verbose logging
    #[arg(short, long)]
    pub verbose: bool,

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
}

impl Args {
    /// Get the disabled components based on --disable and --enable-all flags
    pub fn disabled_components(&self) -> DisabledComponents {
        if self.enable_all {
            DisabledComponents::default()
        } else {
            DisabledComponents::from_str(&self.disable)
        }
    }

    /// Get the output format based on --json flag
    pub fn format(&self) -> OutputFormat {
        if self.json {
            OutputFormat::Json
        } else {
            OutputFormat::Terminal
        }
    }
}

#[derive(Subcommand, Debug)]
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
}

#[derive(Debug, Clone, clap::ValueEnum, PartialEq)]
pub enum OutputFormat {
    /// JSON output for machine consumption
    Json,
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
    fn test_parse_json_flag() {
        let args = Args::try_parse_from(["dissect", "--json", "file.bin"]).unwrap();
        assert!(args.json);
        assert!(matches!(args.format(), OutputFormat::Json));
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
        assert!(matches!(args.format(), OutputFormat::Json));
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
        let format = OutputFormat::Json;
        let cloned = format.clone();
        assert!(matches!(cloned, OutputFormat::Json));
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
        let disabled = DisabledComponents::from_str("yara,upx");
        assert!(disabled.yara);
        assert!(disabled.upx);
        assert!(!disabled.radare2);
        assert!(!disabled.third_party);
    }

    #[test]
    fn test_disabled_components_from_str_with_spaces() {
        let disabled = DisabledComponents::from_str("yara, radare2 , upx");
        assert!(disabled.yara);
        assert!(disabled.radare2);
        assert!(disabled.upx);
        assert!(!disabled.third_party);
    }

    #[test]
    fn test_disabled_components_from_str_ignores_unknown() {
        let disabled = DisabledComponents::from_str("yara,unknown,radare2");
        assert!(disabled.yara);
        assert!(disabled.radare2);
        assert!(!disabled.upx);
        assert!(!disabled.third_party);
    }

    #[test]
    fn test_disabled_components_any_disabled() {
        let disabled = DisabledComponents::default();
        assert!(!disabled.any_disabled());

        let disabled = DisabledComponents::from_str("yara");
        assert!(disabled.any_disabled());
    }

    #[test]
    fn test_disabled_components_disabled_names() {
        let disabled = DisabledComponents::from_str("yara,upx");
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
}
