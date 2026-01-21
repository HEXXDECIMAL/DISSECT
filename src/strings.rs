use crate::types::{StringInfo, StringType};
use regex::Regex;

/// Extract and classify strings from binary data
pub struct StringExtractor {
    min_length: usize,
    url_regex: Regex,
    ip_regex: Regex,
    email_regex: Regex,
    base64_regex: Regex,
}

impl StringExtractor {
    pub fn new() -> Self {
        Self {
            min_length: 4,
            url_regex: Regex::new(r"(?i)(https?|ftp)://[^\s<>]+").unwrap(),
            ip_regex: Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap(),
            email_regex: Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap(),
            base64_regex: Regex::new(r"^[A-Za-z0-9+/]{20,}={0,2}$").unwrap(),
        }
    }

    /// Extract all strings from binary data
    pub fn extract(&self, data: &[u8], section_name: Option<String>) -> Vec<StringInfo> {
        let mut strings = Vec::new();
        let mut current_string = Vec::new();
        let mut string_offset = 0;

        for (i, &byte) in data.iter().enumerate() {
            if byte.is_ascii() && !byte.is_ascii_control() || byte == b' ' || byte == b'\t' {
                if current_string.is_empty() {
                    string_offset = i;
                }
                current_string.push(byte);
            } else {
                if current_string.len() >= self.min_length {
                    if let Ok(s) = String::from_utf8(current_string.clone()) {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() {
                            strings.push(self.classify_string(
                                trimmed.to_string(),
                                string_offset,
                                section_name.clone(),
                            ));
                        }
                    }
                }
                current_string.clear();
            }
        }

        // Handle last string if present
        if current_string.len() >= self.min_length {
            if let Ok(s) = String::from_utf8(current_string) {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    strings.push(self.classify_string(
                        trimmed.to_string(),
                        string_offset,
                        section_name,
                    ));
                }
            }
        }

        strings
    }

    /// Classify a string by type
    fn classify_string(&self, value: String, offset: usize, section: Option<String>) -> StringInfo {
        let string_type = if self.url_regex.is_match(&value) {
            StringType::Url
        } else if self.ip_regex.is_match(&value) {
            StringType::Ip
        } else if self.email_regex.is_match(&value) {
            StringType::Email
        } else if self.is_path(&value) {
            StringType::Path
        } else if value.len() > 20 && self.base64_regex.is_match(&value) {
            StringType::Base64
        } else {
            StringType::Plain
        };

        StringInfo {
            value,
            offset: Some(format!("{:#x}", offset)),
            encoding: "utf8".to_string(),
            string_type,
            section,
        }
    }

    /// Classify a string's type without creating a StringInfo object
    pub fn classify_string_type(&self, value: &str) -> StringType {
        if self.url_regex.is_match(value) {
            StringType::Url
        } else if self.ip_regex.is_match(value) {
            StringType::Ip
        } else if self.email_regex.is_match(value) {
            StringType::Email
        } else if self.is_path(value) {
            StringType::Path
        } else if value.len() > 20 && self.base64_regex.is_match(value) {
            StringType::Base64
        } else {
            StringType::Plain
        }
    }

    /// Check if string looks like a file path
    fn is_path(&self, s: &str) -> bool {
        // Unix paths
        if s.starts_with('/') && s.contains('/') {
            return true;
        }

        // Windows paths
        if s.len() > 3 && s.chars().nth(1) == Some(':') && s.chars().nth(2) == Some('\\') {
            return true;
        }

        // Relative paths with directory separators
        if (s.contains('/') || s.contains('\\')) && !s.contains(' ') {
            // Check for common path patterns
            if s.contains("/bin/")
                || s.contains("/usr/")
                || s.contains("/etc/")
                || s.contains("/tmp/")
                || s.contains("/var/")
                || s.contains(r"C:\")
                || s.contains("Program")
            {
                return true;
            }
        }

        false
    }
}

impl Default for StringExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_extraction() {
        let data = b"Hello World http://example.com /usr/bin/ls";
        let extractor = StringExtractor::new();
        let strings = extractor.extract(data, None);

        assert!(!strings.is_empty());
    }

    #[test]
    fn test_url_detection() {
        let data = b"Check out https://example.com for more info";
        let extractor = StringExtractor::new();
        let strings = extractor.extract(data, None);

        let url_string = strings
            .iter()
            .find(|s| matches!(s.string_type, StringType::Url));
        assert!(url_string.is_some());
    }

    #[test]
    fn test_path_detection() {
        let extractor = StringExtractor::new();

        assert!(extractor.is_path("/usr/bin/ls"));
        assert!(extractor.is_path("/etc/passwd"));
        assert!(extractor.is_path(r"C:\Windows\System32"));
        assert!(!extractor.is_path("hello world"));
    }

    #[test]
    fn test_ip_detection() {
        let data = b"Connect to 192.168.1.1 for server";
        let extractor = StringExtractor::new();
        let strings = extractor.extract(data, None);

        let ip_string = strings
            .iter()
            .find(|s| matches!(s.string_type, StringType::Ip));
        assert!(ip_string.is_some());
    }

    #[test]
    fn test_email_detection() {
        let data = b"Contact us at admin@example.com";
        let extractor = StringExtractor::new();
        let strings = extractor.extract(data, None);

        let email_string = strings
            .iter()
            .find(|s| matches!(s.string_type, StringType::Email));
        assert!(email_string.is_some());
    }

    #[test]
    fn test_base64_detection() {
        let data = b"SGVsbG8gV29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZw==";
        let extractor = StringExtractor::new();
        let strings = extractor.extract(data, None);

        // Base64 needs to be > 20 chars
        assert!(strings
            .iter()
            .any(|s| matches!(s.string_type, StringType::Base64)));
    }

    #[test]
    fn test_min_length_filter() {
        let data = b"ab  Hello World";
        let extractor = StringExtractor::new();
        let strings = extractor.extract(data, None);

        // "ab" should be filtered (< 4 chars), "Hello World" should be kept
        assert!(!strings.iter().any(|s| s.value == "ab"));
        assert!(strings.iter().any(|s| s.value.contains("Hello World")));
    }

    #[test]
    fn test_control_characters_filtered() {
        let data = b"Hello\x00\x01World";
        let extractor = StringExtractor::new();
        let strings = extractor.extract(data, None);

        // Should extract "Hello" and "World" separately
        assert!(strings.len() >= 2);
    }

    #[test]
    fn test_section_name_preserved() {
        let data = b"test string";
        let extractor = StringExtractor::new();
        let strings = extractor.extract(data, Some(".text".to_string()));

        assert!(strings
            .iter()
            .any(|s| s.section == Some(".text".to_string())));
    }

    #[test]
    fn test_offset_recorded() {
        let data = b"start test string end";
        let extractor = StringExtractor::new();
        let strings = extractor.extract(data, None);

        // Offset should be recorded for each string
        assert!(strings.iter().all(|s| s.offset.is_some()));
    }

    #[test]
    fn test_classify_string_type() {
        let extractor = StringExtractor::new();

        assert_eq!(
            extractor.classify_string_type("https://example.com"),
            StringType::Url
        );
        assert_eq!(
            extractor.classify_string_type("192.168.1.1"),
            StringType::Ip
        );
        assert_eq!(
            extractor.classify_string_type("user@example.com"),
            StringType::Email
        );
        assert_eq!(
            extractor.classify_string_type("/usr/bin/bash"),
            StringType::Path
        );
        assert_eq!(
            extractor.classify_string_type("plain text"),
            StringType::Plain
        );
    }

    #[test]
    fn test_windows_path_detection() {
        let extractor = StringExtractor::new();

        assert!(extractor.is_path(r"C:\Windows\System32\cmd.exe"));
        assert!(extractor.is_path(r"D:\Program Files\App"));
    }

    #[test]
    fn test_relative_path_detection() {
        let extractor = StringExtractor::new();

        assert!(extractor.is_path("/bin/sh"));
        assert!(extractor.is_path("/usr/local/bin"));
        assert!(!extractor.is_path("just/text"));
        assert!(!extractor.is_path("not a path"));
    }

    #[test]
    fn test_default() {
        let extractor = StringExtractor::default();
        assert_eq!(extractor.min_length, 4);
    }

    #[test]
    fn test_trimmed_strings() {
        let data = b"  spaced  ";
        let extractor = StringExtractor::new();
        let strings = extractor.extract(data, None);

        // Should trim whitespace
        if let Some(s) = strings.first() {
            assert_eq!(s.value.trim(), s.value);
        }
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        let extractor = StringExtractor::new();
        let strings = extractor.extract(data, None);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_binary_data_only() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0xFF];
        let extractor = StringExtractor::new();
        let strings = extractor.extract(&data, None);

        // No printable strings should be found
        assert!(strings.is_empty());
    }
}
