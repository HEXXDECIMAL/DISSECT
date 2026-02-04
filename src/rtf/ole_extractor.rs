use crate::rtf::error::{Result, RtfError};
use crate::rtf::types::OleHeader;

/// OLE compound document magic bytes (8 bytes)
const OLE_MAGIC: &[u8; 8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";

/// Check if a byte sequence starts with an OLE header
pub fn is_ole_header(data: &[u8]) -> bool {
    data.len() >= 8 && &data[0..8] == OLE_MAGIC
}

/// Extract and validate an OLE header from binary data
pub fn extract_header(data: &[u8]) -> Result<OleHeader> {
    if data.len() < 8 {
        return Err(RtfError::InvalidOleHeader);
    }

    let mut magic = [0u8; 8];
    magic.copy_from_slice(&data[0..8]);

    if magic != *OLE_MAGIC {
        return Err(RtfError::InvalidOleHeader);
    }

    Ok(OleHeader {
        magic,
        is_obfuscated: false,
    })
}

/// Check if hex data has obfuscation (whitespace between hex digits)
pub fn detect_hex_obfuscation(rtf_data: &str) -> bool {
    // Count transitions from hex digit to whitespace and back
    // If we find patterns like "D 0 C F", it's obfuscated
    let bytes = rtf_data.as_bytes();
    let mut found_whitespace_between_hex = false;

    for (i, &b) in bytes.iter().enumerate() {
        let is_hex = is_hex_digit(b);
        let is_ws = is_whitespace(b);

        if is_hex && i > 0 && is_whitespace(bytes[i - 1]) {
            found_whitespace_between_hex = true;
        } else if is_ws && found_whitespace_between_hex {
            // Reset if we hit another non-hex character
            if i + 1 < bytes.len() && is_hex_digit(bytes[i + 1]) {
                return true;
            }
        }
    }

    false
}

/// Find all potential OLE headers in a byte buffer
pub fn find_ole_headers(data: &[u8]) -> Vec<(usize, OleHeader)> {
    let mut headers = Vec::new();

    for i in 0..data.len().saturating_sub(7) {
        if is_ole_header(&data[i..]) {
            if let Ok(header) = extract_header(&data[i..]) {
                headers.push((i, header));
            }
        }
    }

    headers
}

fn is_hex_digit(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn is_whitespace(b: u8) -> bool {
    b == b' ' || b == b'\t' || b == b'\n' || b == b'\r'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ole_header() {
        let data = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1other";
        assert!(is_ole_header(data));
    }

    #[test]
    fn test_is_not_ole_header() {
        let data = b"notaheader";
        assert!(!is_ole_header(data));
    }

    #[test]
    fn test_extract_header() {
        let data = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";
        let header = extract_header(data).unwrap();
        assert_eq!(header.magic, *OLE_MAGIC);
        assert!(!header.is_obfuscated);
    }

    #[test]
    fn test_extract_header_short() {
        let data = b"\xD0\xCF";
        assert!(extract_header(data).is_err());
    }

    #[test]
    fn test_detect_hex_obfuscation_no_spaces() {
        assert!(!detect_hex_obfuscation("D0CF11E0"));
    }

    #[test]
    fn test_detect_hex_obfuscation_with_spaces() {
        assert!(detect_hex_obfuscation("D 0 C F 1 1 E 0"));
    }

    #[test]
    fn test_find_ole_headers() {
        let mut data = vec![0u8; 100];
        data[10..18].copy_from_slice(OLE_MAGIC);
        data[50..58].copy_from_slice(OLE_MAGIC);

        let headers = find_ole_headers(&data);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, 10);
        assert_eq!(headers[1].0, 50);
    }
}
