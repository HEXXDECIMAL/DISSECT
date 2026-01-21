use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "dissect")]
#[command(
    about = "Deep static analysis tool for extracting features from binaries and source code"
)]
#[command(version)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,

    /// Output format (json, terminal)
    #[arg(short, long, default_value = "terminal")]
    pub format: OutputFormat,

    /// Write output to file
    #[arg(short, long)]
    pub output: Option<String>,

    /// Verbose logging
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Analyze a single file in detail
    Analyze {
        /// Target file to analyze
        target: String,

        /// Enable third-party YARA rules from third_party/yara (suspicious criticality)
        #[arg(long)]
        third_party_yara: bool,
    },

    /// Scan multiple files or directories
    Scan {
        /// Paths to scan (files or directories)
        #[arg(required = true)]
        paths: Vec<String>,

        /// Enable third-party YARA rules from third_party/yara (suspicious criticality)
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
    fn test_parse_analyze_command() {
        let args = Args::try_parse_from(["dissect", "analyze", "file.bin"]).unwrap();

        assert!(matches!(args.command, Command::Analyze { .. }));
        if let Command::Analyze {
            target,
            third_party_yara,
        } = args.command
        {
            assert_eq!(target, "file.bin");
            assert_eq!(third_party_yara, false);
        }
    }

    #[test]
    fn test_parse_analyze_with_third_party_yara() {
        let args =
            Args::try_parse_from(["dissect", "analyze", "file.bin", "--third-party-yara"]).unwrap();

        if let Command::Analyze {
            target,
            third_party_yara,
        } = args.command
        {
            assert_eq!(target, "file.bin");
            assert_eq!(third_party_yara, true);
        }
    }

    #[test]
    fn test_parse_scan_command() {
        let args = Args::try_parse_from(["dissect", "scan", "dir1", "dir2"]).unwrap();

        assert!(matches!(args.command, Command::Scan { .. }));
        if let Command::Scan {
            paths,
            third_party_yara,
        } = args.command
        {
            assert_eq!(paths, vec!["dir1", "dir2"]);
            assert_eq!(third_party_yara, false);
        }
    }

    #[test]
    fn test_parse_scan_with_third_party_yara() {
        let args = Args::try_parse_from(["dissect", "scan", "dir1", "--third-party-yara"]).unwrap();

        if let Command::Scan {
            paths,
            third_party_yara,
        } = args.command
        {
            assert_eq!(paths, vec!["dir1"]);
            assert_eq!(third_party_yara, true);
        }
    }

    #[test]
    fn test_parse_diff_command() {
        let args = Args::try_parse_from(["dissect", "diff", "old.bin", "new.bin"]).unwrap();

        assert!(matches!(args.command, Command::Diff { .. }));
        if let Command::Diff { old, new } = args.command {
            assert_eq!(old, "old.bin");
            assert_eq!(new, "new.bin");
        }
    }

    #[test]
    fn test_parse_format_json() {
        let args = Args::try_parse_from(["dissect", "-f", "json", "analyze", "file.bin"]).unwrap();
        assert!(matches!(args.format, OutputFormat::Json));
    }

    #[test]
    fn test_parse_format_terminal() {
        let args =
            Args::try_parse_from(["dissect", "-f", "terminal", "analyze", "file.bin"]).unwrap();
        assert!(matches!(args.format, OutputFormat::Terminal));
    }

    #[test]
    fn test_parse_format_default() {
        let args = Args::try_parse_from(["dissect", "analyze", "file.bin"]).unwrap();
        assert!(matches!(args.format, OutputFormat::Terminal));
    }

    #[test]
    fn test_parse_output_file() {
        let args =
            Args::try_parse_from(["dissect", "-o", "results.json", "analyze", "file.bin"]).unwrap();
        assert_eq!(args.output, Some("results.json".to_string()));
    }

    #[test]
    fn test_parse_verbose() {
        let args = Args::try_parse_from(["dissect", "-v", "analyze", "file.bin"]).unwrap();
        assert_eq!(args.verbose, true);
    }

    #[test]
    fn test_parse_no_verbose() {
        let args = Args::try_parse_from(["dissect", "analyze", "file.bin"]).unwrap();
        assert_eq!(args.verbose, false);
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
            "analyze",
            "malware.bin",
            "--third-party-yara",
        ])
        .unwrap();

        assert!(matches!(args.format, OutputFormat::Json));
        assert_eq!(args.output, Some("output.json".to_string()));
        assert_eq!(args.verbose, true);

        if let Command::Analyze {
            target,
            third_party_yara,
        } = args.command
        {
            assert_eq!(target, "malware.bin");
            assert_eq!(third_party_yara, true);
        }
    }

    #[test]
    fn test_parse_scan_no_paths_fails() {
        let result = Args::try_parse_from(["dissect", "scan"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_command_fails() {
        let result = Args::try_parse_from(["dissect"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_format_fails() {
        let result = Args::try_parse_from(["dissect", "-f", "xml", "analyze", "file.bin"]);
        assert!(result.is_err());
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
}
