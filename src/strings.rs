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

        let url_string = strings.iter().find(|s| matches!(s.string_type, StringType::Url));
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

        let ip_string = strings.iter().find(|s| matches!(s.string_type, StringType::Ip));
        assert!(ip_string.is_some());
    }
}
