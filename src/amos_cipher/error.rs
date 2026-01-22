//! AMOS cipher error types.

use thiserror::Error;

/// Errors that can occur during AMOS cipher detection and decryption.
#[derive(Debug, Error)]
pub enum AMOSError {
    #[error("failed to parse Mach-O binary: {0}")]
    MachOParseError(String),

    #[error("section not found: {0}")]
    SectionNotFound(String),

    #[error("invalid section: {0}")]
    InvalidSection(String),

    #[error("insufficient data: {0}")]
    InsufficientData(String),

    #[error("invalid alignment for table extraction")]
    InvalidAlignment,

    #[error("could not determine table size")]
    TableSizeUnknown,

    #[error("invalid format: {0}")]
    InvalidFormat(String),

    #[error("no architecture found in fat binary")]
    NoArchitecture,

    #[error("payload too large: {payload_size} > table size {table_size}")]
    PayloadTooLarge {
        payload_size: usize,
        table_size: usize,
    },

    #[error("table index out of bounds: {index} >= {table_size}")]
    IndexOutOfBounds { index: usize, table_size: usize },

    #[error("custom Base64 decode error: {0}")]
    Base64DecodeError(String),

    #[error("hex decode error: {0}")]
    HexDecodeError(String),

    #[error("PRNG seed not found")]
    SeedNotFound,

    #[error("decryption produced garbage output")]
    DecryptionFailed,

    #[error("no AMOS cipher detected in binary")]
    NotAMOSEncrypted,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("goblin parse error: {0}")]
    GoblinError(#[from] goblin::error::Error),
}
