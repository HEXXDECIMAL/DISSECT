use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl RiskLevel {
    pub fn from_score(score: i32) -> Self {
        match score {
            0..=1 => RiskLevel::Low,
            2 => RiskLevel::Medium,
            3 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Behavior {
    pub id: String,
    pub rule_name: String,
    pub description: String,
    pub risk_score: i32,
    pub risk_level: RiskLevel,
    pub match_strings: Vec<String>,
    pub rule_author: Option<String>,
    pub rule_url: Option<String>,
    pub reference_url: Option<String>,
}

impl Behavior {
    pub fn new(id: String, rule_name: String, description: String, risk_score: i32) -> Self {
        Self {
            id,
            rule_name,
            description,
            risk_level: RiskLevel::from_score(risk_score),
            risk_score,
            match_strings: Vec::new(),
            rule_author: None,
            rule_url: None,
            reference_url: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileReport {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub mime_type: String,
    pub behaviors: Vec<Behavior>,
    pub risk_score: i32,
    pub risk_level: RiskLevel,
    pub skipped: Option<String>,
    pub meta: HashMap<String, String>,
}

impl FileReport {
    pub fn new(path: String, sha256: String, size: u64, mime_type: String) -> Self {
        Self {
            path,
            sha256,
            size,
            mime_type,
            behaviors: Vec::new(),
            risk_score: 0,
            risk_level: RiskLevel::Low,
            skipped: None,
            meta: HashMap::new(),
        }
    }

    pub fn with_skipped(path: String, reason: String) -> Self {
        Self {
            path,
            sha256: String::new(),
            size: 0,
            mime_type: String::new(),
            behaviors: Vec::new(),
            risk_score: 0,
            risk_level: RiskLevel::Low,
            skipped: Some(reason),
            meta: HashMap::new(),
        }
    }

    pub fn add_behavior(&mut self, behavior: Behavior) {
        self.risk_score = self.risk_score.max(behavior.risk_score);
        self.risk_level = RiskLevel::from_score(self.risk_score);
        self.behaviors.push(behavior);
    }

    pub fn is_malicious(&self) -> bool {
        self.risk_level >= RiskLevel::Critical
    }

    pub fn is_suspicious(&self) -> bool {
        self.risk_level >= RiskLevel::High
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub files: Vec<FileReport>,
    pub total_files_scanned: usize,
    pub total_files_skipped: usize,
    pub malicious_files: usize,
    pub suspicious_files: usize,
    pub scan_duration_ms: u64,
}

impl Report {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_file(&mut self, file_report: FileReport) {
        if file_report.skipped.is_some() {
            self.total_files_skipped += 1;
        } else {
            self.total_files_scanned += 1;
            if file_report.is_malicious() {
                self.malicious_files += 1;
            } else if file_report.is_suspicious() {
                self.suspicious_files += 1;
            }
        }
        self.files.push(file_report);
    }

    pub fn has_findings(&self) -> bool {
        self.malicious_files > 0 || self.suspicious_files > 0
    }

    pub fn highest_risk_level(&self) -> RiskLevel {
        self.files.iter().filter(|f| f.skipped.is_none()).map(|f| f.risk_level).max().unwrap_or(RiskLevel::Low)
    }
}
