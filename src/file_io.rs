//! Efficient file I/O utilities with memory optimization.
//!
//! Provides smart file reading that uses memory-mapping for large files
//! to reduce memory usage and improve performance.

use anyhow::Result;
use memmap2::Mmap;
use std::fs::File;
use std::path::Path;

/// Threshold for using memory-mapping instead of loading into memory.
/// Files larger than this will be memory-mapped (zero-copy).
const MMAP_THRESHOLD: u64 = 10 * 1024 * 1024; // 10 MB

/// File data that can be either memory-mapped or owned.
pub enum FileData {
    /// Memory-mapped file (zero-copy, for large files)
    Mapped(Mmap),
    /// Owned data (for small files)
    Owned(Vec<u8>),
}

impl FileData {
    /// Get the data as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        match self {
            FileData::Mapped(mmap) => mmap,
            FileData::Owned(vec) => vec,
        }
    }

    /// Get the length of the data
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Check if the data is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AsRef<[u8]> for FileData {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// Read a file efficiently, using memory-mapping for large files.
///
/// For files larger than 10MB, this uses memory-mapping (zero-copy).
/// For smaller files, it reads into memory for better cache locality.
///
/// # Arguments
///
/// * `path` - Path to the file to read
///
/// # Returns
///
/// A `FileData` that can be used as a byte slice
pub fn read_file_smart(path: &Path) -> Result<FileData> {
    let metadata = std::fs::metadata(path)?;
    let file_size = metadata.len();

    if file_size > MMAP_THRESHOLD {
        // Large file: use memory-mapping (zero-copy)
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        tracing::debug!(
            "Memory-mapped large file ({:.2} MB): {}",
            file_size as f64 / 1024.0 / 1024.0,
            path.display()
        );
        Ok(FileData::Mapped(mmap))
    } else {
        // Small file: read into memory for better cache locality
        let data = std::fs::read(path)?;
        Ok(FileData::Owned(data))
    }
}

/// Read a file into an owned Vec<u8>.
///
/// This is a convenience wrapper that always returns owned data.
/// Use `read_file_smart` if you want automatic memory-mapping for large files.
pub fn read_file_to_vec(path: &Path) -> Result<Vec<u8>> {
    Ok(std::fs::read(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_small_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"test data").unwrap();
        temp_file.flush().unwrap();

        let data = read_file_smart(temp_file.path()).unwrap();
        assert_eq!(data.as_slice(), b"test data");
        assert_eq!(data.len(), 9);
        assert!(!data.is_empty());

        // Small file should be owned
        assert!(matches!(data, FileData::Owned(_)));
    }

    #[test]
    fn test_read_large_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let large_data = vec![0u8; 20 * 1024 * 1024]; // 20 MB
        temp_file.write_all(&large_data).unwrap();
        temp_file.flush().unwrap();

        let data = read_file_smart(temp_file.path()).unwrap();
        assert_eq!(data.len(), 20 * 1024 * 1024);

        // Large file should be memory-mapped
        assert!(matches!(data, FileData::Mapped(_)));
    }

    #[test]
    fn test_as_ref_trait() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"test").unwrap();
        temp_file.flush().unwrap();

        let data = read_file_smart(temp_file.path()).unwrap();
        let slice: &[u8] = data.as_ref();
        assert_eq!(slice, b"test");
    }
}
