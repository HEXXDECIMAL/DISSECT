use thiserror::Error;

#[derive(Debug, Error)]
pub enum RtfError {
    #[error("Invalid RTF header: expected '{{\\rtf' prefix")]
    InvalidHeader,

    #[error("Excessive nesting depth: {depth} (max: {max})")]
    ExcessiveNesting { depth: usize, max: usize },

    #[error("Too many embedded objects: {count} (max: {max})")]
    TooManyObjects { count: usize, max: usize },

    #[error("File too large: {size} bytes (max: {max} bytes)")]
    FileTooLarge { size: usize, max: usize },

    #[error("Hex decoding failed at position {position}: {reason}")]
    HexDecodeError { position: usize, reason: String },

    #[error("Invalid OLE header")]
    InvalidOleHeader,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid UTF-8: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("Empty file")]
    EmptyFile,

    #[error("RTF parsing error: {0}")]
    ParseError(String),
}

pub type Result<T> = std::result::Result<T, RtfError>;
