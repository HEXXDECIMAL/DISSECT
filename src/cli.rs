use crate::report::RiskLevel;
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "divine")]
#[command(about = "Rust port of malcontent - malware detection using YARA rules")]
#[command(version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[arg(long, value_enum, default_value_t = OutputFormat::Terminal, global = true)]
    pub format: OutputFormat,

    #[arg(long, default_value_t = RiskLevel::Low, global = true)]
    pub min_risk: RiskLevel,

    #[arg(long, global = true)]
    pub include_data_files: bool,

    #[arg(short = 'j', long, default_value_t = num_cpus::get(), global = true)]
    pub jobs: usize,

    #[arg(short, long, global = true)]
    pub output: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    Scan {
        #[arg(help = "Paths to scan")]
        paths: Vec<String>,

        #[arg(long, help = "Rule file or directory")]
        rules: Option<String>,

        #[arg(long, help = "Scan archive contents")]
        archives: bool,
    },

    Analyze {
        #[arg(help = "Path to analyze")]
        path: String,

        #[arg(long, help = "Rule file or directory")]
        rules: Option<String>,
    },
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
    Brief,
}

impl std::str::FromStr for RiskLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" | "1" => Ok(Self::Low),
            "medium" | "2" => Ok(Self::Medium),
            "high" | "3" => Ok(Self::High),
            "critical" | "4" => Ok(Self::Critical),
            _ => Err(format!("Invalid risk level: {s}")),
        }
    }
}

mod num_cpus {
    pub fn get() -> usize {
        std::thread::available_parallelism().map(std::num::NonZero::get).unwrap_or(1)
    }
}
