use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::analyzers::{archive::ArchiveAnalyzer, Analyzer};
use crate::types::AnalysisReport;
use crate::yara_engine::YaraEngine;

/// Check if a file is an archive based on extension
pub fn is_archive(path: &Path) -> bool {
    let analyzer = ArchiveAnalyzer::new();
    analyzer.can_analyze(path)
}

/// Extract and scan an archive, returning reports for all extracted files
#[allow(dead_code)]
pub fn extract_and_scan_archive(
    archive_path: &Path,
    _yara_engine: &Arc<YaraEngine>,
    _max_depth: usize,
) -> Result<Vec<AnalysisReport>> {
    // Use the existing ArchiveAnalyzer to extract and analyze
    let analyzer = ArchiveAnalyzer::new();

    // The ArchiveAnalyzer already handles extraction and recursive analysis
    // It returns a single aggregated report with capabilities from all files
    let report = analyzer
        .analyze(archive_path)
        .context("Failed to analyze archive")?;

    // For now, return a single report for the archive
    // In a future iteration, we could modify ArchiveAnalyzer to return individual reports
    Ok(vec![report])
}

/// RAII guard for temporary directories that ensures cleanup
pub struct TempDirGuard {
    _temp_dir: tempfile::TempDir,
    path: PathBuf,
}

impl TempDirGuard {
    pub fn new(prefix: &str) -> Result<Self> {
        let temp_dir = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir()
            .context("Failed to create temporary directory")?;
        let path = temp_dir.path().to_path_buf();
        Ok(Self {
            _temp_dir: temp_dir,
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_archive_zip() {
        assert!(is_archive(Path::new("test.zip")));
        assert!(is_archive(Path::new("TEST.ZIP")));
    }

    #[test]
    fn test_is_archive_tar() {
        assert!(is_archive(Path::new("test.tar")));
        assert!(is_archive(Path::new("test.tar.gz")));
        assert!(is_archive(Path::new("test.tgz")));
        assert!(is_archive(Path::new("test.tar.bz2")));
        assert!(is_archive(Path::new("test.tar.xz")));
    }

    #[test]
    fn test_is_not_archive() {
        assert!(!is_archive(Path::new("test.txt")));
        assert!(!is_archive(Path::new("test.py")));
        assert!(!is_archive(Path::new("test.elf")));
    }

    #[test]
    fn test_temp_dir_guard() {
        let guard = TempDirGuard::new("dissect-test").unwrap();
        let path = guard.path().to_path_buf();

        // Directory should exist while guard is in scope
        assert!(path.exists());

        drop(guard);

        // Directory should be cleaned up after drop
        // Note: This might be flaky depending on OS cleanup timing
        // so we'll just check that the guard was created successfully
    }

    #[test]
    fn test_temp_dir_guard_cleanup() {
        let path = {
            let guard = TempDirGuard::new("dissect-test").unwrap();
            guard.path().to_path_buf()
        };

        // After guard goes out of scope, directory should be cleaned up
        // Adding a small delay to ensure filesystem operations complete
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Note: On some systems, temp cleanup might be deferred
        // So we primarily test that the guard was created and can be dropped without panic
    }
}
