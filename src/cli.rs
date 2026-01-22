use clap::{Parser, Subcommand};

/// Default passwords to try for encrypted zip files (common malware sample passwords)
pub const DEFAULT_ZIP_PASSWORDS: &[&str] =
    &["infected", "infect3d", "malware", "virus", "password"];

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

    /// Output format (json, terminal)
    #[arg(short, long, default_value = "terminal")]
    pub format: OutputFormat,

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
}

#[derive(Debug, Clone, clap::ValueEnum)]
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
    fn test_parse_format_json() {
        let args = Args::try_parse_from(["dissect", "-f", "json", "file.bin"]).unwrap();
        assert!(matches!(args.format, OutputFormat::Json));
    }

    #[test]
    fn test_parse_format_terminal() {
        let args = Args::try_parse_from(["dissect", "-f", "terminal", "file.bin"]).unwrap();
        assert!(matches!(args.format, OutputFormat::Terminal));
    }

    #[test]
    fn test_parse_format_default() {
        let args = Args::try_parse_from(["dissect", "file.bin"]).unwrap();
        assert!(matches!(args.format, OutputFormat::Terminal));
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
            "-f",
            "json",
            "-o",
            "output.json",
            "-v",
            "--third-party-yara",
            "file1.bin",
            "file2.bin",
        ])
        .unwrap();

        assert!(matches!(args.format, OutputFormat::Json));
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
    fn test_parse_invalid_format_fails() {
        let result = Args::try_parse_from(["dissect", "-f", "xml", "file.bin"]);
        assert!(result.is_err());
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
}
