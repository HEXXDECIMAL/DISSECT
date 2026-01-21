use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "dissect")]
#[command(about = "Deep static analysis tool for extracting features from binaries and source code")]
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

        /// Enable third-party YARA rules from third_party/yara (high criticality)
        #[arg(long)]
        third_party_yara: bool,
    },

    /// Scan multiple files or directories
    Scan {
        /// Paths to scan (files or directories)
        #[arg(required = true)]
        paths: Vec<String>,

        /// Enable third-party YARA rules from third_party/yara (high criticality)
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
