//! Archive extraction guards for bomb protection.
//!
//! This module provides safety mechanisms to prevent archive bomb attacks,
//! including excessive file counts, decompression bombs (zip bombs), and
//! path traversal attacks (zip slip).

use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

// =============================================================================
// Archive Bomb Protection Constants
// =============================================================================

/// Maximum size of a single decompressed file (100 MB)
pub(crate) const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Maximum total extraction size (1 GB)
pub(crate) const MAX_TOTAL_SIZE: u64 = 1024 * 1024 * 1024;

/// Maximum number of files to extract
pub(crate) const MAX_FILE_COUNT: usize = 10_000;

/// Maximum compression ratio before considering it suspicious (100:1)
pub(crate) const MAX_COMPRESSION_RATIO: u64 = 100;

/// Reasons an archive may be considered hostile
#[derive(Debug, Clone)]
pub enum HostileArchiveReason {
    PathTraversal(String),
    ZipBomb { compressed: u64, uncompressed: u64 },
    ExcessiveFileCount(usize),
    ExcessiveTotalSize(u64),
    ExcessiveFileSize { file: String, size: u64 },
    SymlinkEscape(String),
    MalformedEntry(String),
    ExtractionError(String),
}

/// Tracks extraction limits and detects hostile patterns
pub(crate) struct ExtractionGuard {
    total_bytes: AtomicU64,
    file_count: AtomicUsize,
    hostile_reasons: Mutex<Vec<HostileArchiveReason>>,
}

impl ExtractionGuard {
    pub(crate) fn new() -> Self {
        Self {
            total_bytes: AtomicU64::new(0),
            file_count: AtomicUsize::new(0),
            hostile_reasons: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn add_hostile_reason(&self, reason: HostileArchiveReason) {
        if let Ok(mut reasons) = self.hostile_reasons.lock() {
            reasons.push(reason);
        }
    }

    pub(crate) fn take_reasons(&self) -> Vec<HostileArchiveReason> {
        self.hostile_reasons
            .lock()
            .map(|mut r| std::mem::take(&mut *r))
            .unwrap_or_default()
    }

    /// Check if we can extract another file, returns false if limits exceeded
    pub(crate) fn check_file_count(&self) -> bool {
        let count = self.file_count.fetch_add(1, Ordering::Relaxed) + 1;
        if count > MAX_FILE_COUNT {
            self.add_hostile_reason(HostileArchiveReason::ExcessiveFileCount(count));
            return false;
        }
        true
    }

    /// Check and track bytes, returns false if limits exceeded
    pub(crate) fn check_bytes(&self, bytes: u64, file_name: &str) -> bool {
        // Check single file size
        if bytes > MAX_FILE_SIZE {
            self.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                file: file_name.to_string(),
                size: bytes,
            });
            return false;
        }

        // Check total size
        let total = self.total_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if total > MAX_TOTAL_SIZE {
            self.add_hostile_reason(HostileArchiveReason::ExcessiveTotalSize(total));
            return false;
        }
        true
    }

    /// Check compression ratio for zip bomb detection
    pub(crate) fn check_compression_ratio(&self, compressed: u64, uncompressed: u64) -> bool {
        if compressed > 0 && uncompressed / compressed > MAX_COMPRESSION_RATIO {
            self.add_hostile_reason(HostileArchiveReason::ZipBomb {
                compressed,
                uncompressed,
            });
            return false;
        }
        true
    }
}

/// Sanitize archive entry path to prevent path traversal attacks (zip slip)
pub(crate) fn sanitize_entry_path(entry_name: &str, dest_dir: &Path) -> Option<PathBuf> {
    let path = Path::new(entry_name);

    // Reject absolute paths
    if path.is_absolute() {
        return None;
    }

    // Build path component by component, rejecting dangerous ones
    let mut result = dest_dir.to_path_buf();
    for component in path.components() {
        match component {
            Component::Normal(c) => result.push(c),
            Component::CurDir => {}, // Skip "."
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                // Reject "..", drive prefixes, and root
                return None;
            },
        }
    }

    // Final check: ensure result is still under dest_dir
    if !result.starts_with(dest_dir) {
        return None;
    }

    Some(result)
}

/// Size-limited reader that stops after a maximum number of bytes
pub(crate) struct LimitedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R: Read> LimitedReader<R> {
    pub(crate) fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::other("size limit exceeded"));
        }
        let max_read = buf.len().min(self.remaining as usize);
        let n = self.inner.read(&mut buf[..max_read])?;
        self.remaining = self.remaining.saturating_sub(n as u64);
        Ok(n)
    }
}
