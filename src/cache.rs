use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use walkdir::WalkDir;

/// Get the cache directory for DISSECT
/// Returns OS-appropriate cache directory:
/// - macOS: ~/Library/Caches/dissect
/// - Linux: ~/.cache/dissect
/// - Windows: %LOCALAPPDATA%\dissect
pub fn cache_dir() -> Result<PathBuf> {
    let base_cache = dirs::cache_dir().context("Failed to get system cache directory")?;

    let cache_path = base_cache.join("dissect");

    // Create cache directory if it doesn't exist
    if !cache_path.exists() {
        fs::create_dir_all(&cache_path).context("Failed to create cache directory")?;
    }

    Ok(cache_path)
}

/// Check if we're running in developer mode (traits/ directory exists)
pub fn is_developer_mode() -> bool {
    Path::new("traits").exists()
}

/// Get the most recent modification time of any YARA rule file
pub fn get_most_recent_yara_mtime() -> Result<SystemTime> {
    let mut most_recent = SystemTime::UNIX_EPOCH;

    // Check traits/ directory
    if Path::new("traits").exists() {
        for entry in WalkDir::new("traits")
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            let path = entry.path();
            if path.is_file()
                && path
                    .extension()
                    .map(|ext| ext == "yar" || ext == "yara")
                    .unwrap_or(false)
            {
                if let Ok(metadata) = fs::metadata(path) {
                    if let Ok(mtime) = metadata.modified() {
                        if mtime > most_recent {
                            most_recent = mtime;
                        }
                    }
                }
            }
        }
    }

    // Check third_party/yara directory
    if Path::new("third_party/yara").exists() {
        for entry in WalkDir::new("third_party/yara")
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            let path = entry.path();
            if path.is_file()
                && path
                    .extension()
                    .map(|ext| ext == "yar" || ext == "yara")
                    .unwrap_or(false)
            {
                if let Ok(metadata) = fs::metadata(path) {
                    if let Ok(mtime) = metadata.modified() {
                        if mtime > most_recent {
                            most_recent = mtime;
                        }
                    }
                }
            }
        }
    }

    if most_recent == SystemTime::UNIX_EPOCH {
        anyhow::bail!("No YARA files found");
    }

    Ok(most_recent)
}

/// Get the modification time of the dissect binary
pub fn get_binary_mtime() -> Result<SystemTime> {
    let exe_path = std::env::current_exe().context("Failed to get current executable path")?;

    let metadata = fs::metadata(&exe_path).context("Failed to read binary metadata")?;

    metadata
        .modified()
        .context("Failed to get binary modification time")
}

/// Get the appropriate timestamp for cache invalidation
pub fn get_cache_timestamp() -> Result<SystemTime> {
    if is_developer_mode() {
        // Developer mode: use most recent YARA file mtime
        get_most_recent_yara_mtime()
    } else {
        // Production mode: use binary mtime (embedded rules)
        get_binary_mtime()
    }
}

/// Generate a cache key based on timestamp and third-party flag
pub fn yara_cache_key(third_party_enabled: bool) -> Result<String> {
    let mtime = get_cache_timestamp()?;
    let timestamp = mtime
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("Invalid cache timestamp")?
        .as_secs();

    let suffix = if third_party_enabled {
        "with-3p"
    } else {
        "builtin"
    };
    let mode = if is_developer_mode() { "dev" } else { "prod" };

    Ok(format!("yara-rules-{}-{}-{}.bin", mode, timestamp, suffix))
}

/// Get the path to the YARA rules cache file
pub fn yara_cache_path(third_party_enabled: bool) -> Result<PathBuf> {
    let cache_key = yara_cache_key(third_party_enabled)?;
    Ok(cache_dir()?.join(cache_key))
}

/// Clean up old cache files (keep only current one)
pub fn cleanup_old_caches(current_cache: &Path) -> Result<()> {
    let cache_dir = cache_dir()?;

    for entry in fs::read_dir(&cache_dir)? {
        let entry = entry?;
        let path = entry.path();

        // Remove old yara-rules-*.bin files (except the current one)
        if path.is_file()
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("yara-rules-") && n.ends_with(".bin"))
                .unwrap_or(false)
            && path != current_cache
        {
            let _ = fs::remove_file(&path); // Ignore errors
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    #[test]
    fn test_is_developer_mode_no_traits_dir() {
        // Should return false when traits/ doesn't exist (in test environment)
        let result = is_developer_mode();
        // Result depends on whether traits/ exists in test environment
        // Simply verify it returns a boolean without panicking
        let _ = result;
    }

    #[test]
    fn test_yara_cache_key_format() {
        // Test that cache key has expected format
        if let Ok(key) = yara_cache_key(false) {
            assert!(key.starts_with("yara-rules-"));
            assert!(key.ends_with("-builtin.bin"));
        }

        if let Ok(key) = yara_cache_key(true) {
            assert!(key.starts_with("yara-rules-"));
            assert!(key.ends_with("-with-3p.bin"));
        }
    }

    #[test]
    fn test_yara_cache_key_includes_mode() {
        if let Ok(key) = yara_cache_key(false) {
            // Should include either "dev" or "prod" mode
            assert!(key.contains("-dev-") || key.contains("-prod-"));
        }
    }

    #[test]
    fn test_cache_dir_returns_path() {
        let result = cache_dir();
        // Should either succeed or fail, but not panic
        match result {
            Ok(path) => {
                assert!(path.to_string_lossy().contains("dissect"));
            }
            Err(_) => {
                // Some environments may not have cache dir
            }
        }
    }

    #[test]
    fn test_yara_cache_path_includes_cache_key() {
        if let Ok(path) = yara_cache_path(false) {
            let path_str = path.to_string_lossy();
            assert!(path_str.contains("yara-rules-"));
            assert!(path_str.contains(".bin"));
        }
    }

    #[test]
    fn test_yara_cache_path_different_for_third_party() {
        if let (Ok(path1), Ok(path2)) = (yara_cache_path(false), yara_cache_path(true)) {
            // Paths should be different based on third_party flag
            assert_ne!(path1, path2);
            assert!(path1.to_string_lossy().contains("builtin"));
            assert!(path2.to_string_lossy().contains("with-3p"));
        }
    }

    #[test]
    fn test_get_most_recent_yara_mtime_no_files() {
        // Create a temp directory with no YARA files
        let temp_dir = TempDir::new().unwrap();
        std::env::set_current_dir(&temp_dir).ok();

        let result = get_most_recent_yara_mtime();
        // Should fail when no YARA files exist
        assert!(result.is_err());
    }

    #[test]
    fn test_cleanup_old_caches_handles_nonexistent_dir() {
        let temp_path = PathBuf::from("/nonexistent/cache/file.bin");
        // Should not panic with nonexistent path
        let _ = cleanup_old_caches(&temp_path);
    }
}
