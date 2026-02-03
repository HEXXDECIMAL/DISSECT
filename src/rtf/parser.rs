use crate::rtf::error::{RtfError, Result};
use crate::rtf::hex_decoder::decode_hex_tolerant;
use crate::rtf::ole_extractor;
use crate::rtf::types::*;
use regex::Regex;

/// RTF parser with anti-bomb protections and minimal dependencies
pub struct RtfParser {
    max_depth: usize,
    max_objects: usize,
    max_file_size: usize,
}

impl RtfParser {
    pub fn new() -> Self {
        Self {
            max_depth: 100,
            max_objects: 50,
            max_file_size: 10 * 1024 * 1024, // 10MB
        }
    }

    pub fn with_limits(max_depth: usize, max_objects: usize) -> Self {
        Self {
            max_depth,
            max_objects,
            max_file_size: 10 * 1024 * 1024,
        }
    }

    pub fn with_max_file_size(mut self, size: usize) -> Self {
        self.max_file_size = size;
        self
    }

    /// Parse RTF data and extract document structure
    pub fn parse(&self, data: &[u8]) -> Result<RtfDocument> {
        if data.is_empty() {
            return Err(RtfError::EmptyFile);
        }

        if data.len() > self.max_file_size {
            return Err(RtfError::FileTooLarge {
                size: data.len(),
                max: self.max_file_size,
            });
        }

        // Validate RTF header
        if !data.starts_with(b"{\\rtf") {
            return Err(RtfError::InvalidHeader);
        }

        let text = String::from_utf8_lossy(data);

        // Extract control words
        let control_words = self.extract_control_words(&text)?;

        // Check for objupdate directive (suspicious)
        let has_objupdate = control_words.iter().any(|cw| cw.name == "objupdate");

        // Extract embedded objects
        let embedded_objects = self.extract_ole_objects(&text)?;

        if embedded_objects.len() > self.max_objects {
            return Err(RtfError::TooManyObjects {
                count: embedded_objects.len(),
                max: self.max_objects,
            });
        }

        // Calculate nesting depth
        let max_nesting_depth = self.calculate_nesting_depth(&text)?;

        let header = RtfHeader {
            version: self.extract_version(&control_words),
            charset: self.extract_charset(&control_words),
            offset: 0,
        };

        let metadata = DocumentMetadata {
            file_size: data.len(),
            object_count: embedded_objects.len(),
            max_nesting_depth,
            has_objupdate,
            detected_charset: self.extract_charset(&control_words),
        };

        Ok(RtfDocument {
            header,
            control_words,
            embedded_objects,
            metadata,
        })
    }

    /// Extract control words from RTF text
    fn extract_control_words(&self, text: &str) -> Result<Vec<ControlWord>> {
        let mut words = Vec::new();
        let re = Regex::new(r"\\([a-zA-Z]+)(-?\d*)").expect("regex should compile");

        for (i, m) in re.find_iter(text).enumerate() {
            if i > 10000 {
                // Sanity check - prevent excessive parsing
                break;
            }

            let caps = re.captures(m.as_str()).unwrap();
            let name = caps.get(1).unwrap().as_str().to_string();
            let param = caps.get(2).map(|p| p.as_str()).and_then(|s| s.parse().ok());

            words.push(ControlWord {
                name,
                parameter: param,
                offset: m.start(),
            });
        }

        Ok(words)
    }

    /// Extract embedded OLE objects
    fn extract_ole_objects(&self, text: &str) -> Result<Vec<OleObject>> {
        let mut objects = Vec::new();

        // Find all \object...{\object directives
        // Look for patterns like: {\object\objemb...{\*\objdata ...}}
        let re = Regex::new(r"\{\\object[^}]*\}")
            .expect("object regex should compile");

        for m in re.find_iter(text) {
            let object_str = m.as_str();

            // Try to extract objdata (hex-encoded OLE data)
            if let Some((class_name, objdata)) = self.extract_objdata(object_str) {
                let mut flags = Vec::new();

                // Check for OLE header
                let ole_header = if let Ok(header) = ole_extractor::extract_header(&objdata) {
                    flags.push(SuspiciousFlag::ObfuscatedOleHeader);
                    Some(header)
                } else {
                    None
                };

                // Check for obfuscation in hex encoding
                if let Some(hex_start) = object_str.find("objdata") {
                    if detect_hex_obfuscation(&object_str[hex_start..]) {
                        flags.push(SuspiciousFlag::ObfuscatedOleHeader);
                    }
                }

                // Check for UNC paths
                if let Some(unc_path) = extract_unc_path(object_str) {
                    flags.push(SuspiciousFlag::UncPath(unc_path));
                }

                // Check for objupdate
                if object_str.contains("\\objupdate") {
                    flags.push(SuspiciousFlag::ObjUpdateDirective);
                }

                // Check for WebDAV paths
                if object_str.contains("davwwwroot") || object_str.contains("DavWWWRoot") {
                    flags.push(SuspiciousFlag::WebdavPath);
                }

                objects.push(OleObject {
                    class_name,
                    objdata,
                    ole_header,
                    offset: m.start(),
                    suspicious_flags: flags,
                });
            }
        }

        Ok(objects)
    }

    /// Extract objdata hex string from object directive
    fn extract_objdata(&self, object_str: &str) -> Option<(String, Vec<u8>)> {
        // Extract class name (e.g., "Word.Document.8")
        let class_re = Regex::new(r#"\\objclass\s+"([^"]+)"?"#)
            .expect("class regex should compile");
        let class_name = class_re
            .captures(object_str)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        // Extract hex data from {\*\objdata ...}
        let data_re = Regex::new(r"\{\\?\*?\\objdata\s+([0-9A-Fa-f\s]+)\}")
            .expect("objdata regex should compile");

        if let Some(caps) = data_re.captures(object_str) {
            let hex_str = caps.get(1).map(|m| m.as_str())?;
            if let Ok(decoded) = decode_hex_tolerant(hex_str) {
                return Some((class_name, decoded));
            }
        }

        None
    }

    /// Calculate maximum nesting depth to detect zip bombs
    fn calculate_nesting_depth(&self, text: &str) -> Result<usize> {
        let mut max_depth = 0;
        let mut current_depth = 0;

        for ch in text.chars() {
            match ch {
                '{' => {
                    current_depth += 1;
                    if current_depth > max_depth {
                        max_depth = current_depth;
                    }
                    if current_depth > self.max_depth {
                        return Err(RtfError::ExcessiveNesting {
                            depth: current_depth,
                            max: self.max_depth,
                        });
                    }
                }
                '}' => {
                    if current_depth > 0 {
                        current_depth -= 1;
                    }
                }
                _ => {}
            }
        }

        Ok(max_depth)
    }

    /// Extract RTF version from control words
    fn extract_version(&self, words: &[ControlWord]) -> u32 {
        words
            .iter()
            .find(|w| w.name == "rtf")
            .and_then(|w| w.parameter)
            .unwrap_or(0) as u32
    }

    /// Extract charset from control words
    fn extract_charset(&self, words: &[ControlWord]) -> Option<String> {
        words
            .iter()
            .find(|w| w.name == "charset")
            .and_then(|w| {
                w.parameter.map(|p| match p {
                    0 => "ANSI".to_string(),
                    1 => "Default".to_string(),
                    2 => "Symbol".to_string(),
                    238 => "Eastern European".to_string(),
                    _ => format!("Unknown({})", p),
                })
            })
    }
}

impl Default for RtfParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract UNC path from RTF control sequences
fn extract_unc_path(text: &str) -> Option<String> {
    // Look for \\server@SSL\path patterns
    let re = Regex::new(r"\\\\([^\s\\]+)@SSL\\([^\s}]+)")
        .expect("unc regex should compile");

    if let Some(caps) = re.captures(text) {
        let server = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let path = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        return Some(format!("\\\\{}@SSL\\{}", server, path));
    }

    None
}

/// Detect hex obfuscation (whitespace between hex digits)
fn detect_hex_obfuscation(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut prev_was_hex = false;
    let mut found_spacing = false;

    for &b in bytes {
        let is_hex = matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F');
        let is_ws = matches!(b, b' ' | b'\t' | b'\n' | b'\r');

        if is_hex {
            if prev_was_hex && found_spacing {
                return true;
            }
            prev_was_hex = true;
            found_spacing = false;
        } else if is_ws && prev_was_hex {
            found_spacing = true;
        } else if !is_ws {
            prev_was_hex = false;
            found_spacing = false;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_rtf() {
        let data = b"{\\rtf1\\ansi\\ansicpg1252}";
        let parser = RtfParser::new();
        let doc = parser.parse(data).unwrap();
        assert_eq!(doc.header.version, 1);
    }

    #[test]
    fn test_parse_empty_file() {
        let parser = RtfParser::new();
        assert!(parser.parse(b"").is_err());
    }

    #[test]
    fn test_parse_invalid_header() {
        let parser = RtfParser::new();
        assert!(parser.parse(b"not rtf").is_err());
    }

    #[test]
    fn test_excessive_nesting() {
        let bomb = format!("{{\\rtf1{}", "{".repeat(101));
        let parser = RtfParser::new();
        assert!(matches!(parser.parse(bomb.as_bytes()), Err(RtfError::ExcessiveNesting { .. })));
    }

    #[test]
    fn test_extract_control_words() {
        let parser = RtfParser::new();
        let words = parser
            .extract_control_words("{\\rtf1\\ansi\\deff0}")
            .unwrap();
        assert!(words.iter().any(|w| w.name == "rtf"));
        assert!(words.iter().any(|w| w.name == "ansi"));
    }
}
