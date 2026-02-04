//! String extraction from binaries.
//!
//! This module extracts human-readable strings from binary files,
//! classifying them as URLs, IPs, file paths, or generic strings.
//!
//! Useful for quick triage and finding embedded indicators.

use crate::radare2::R2String;
use crate::types::{StringInfo, StringType};
use goblin::elf::Elf;
use goblin::mach::MachO;
use goblin::pe::PE;
use regex::Regex;
use rustc_hash::FxHashSet;
use std::collections::{HashMap, HashSet};
use stng::{ExtractOptions, ExtractedString, StringKind, StringMethod};

/// Detect encoding layers in a string and populate layer metadata
fn detect_layers(mut info: StringInfo) -> StringInfo {
    // Stack strings are already tracked via stng_method_to_string(),  so don't add here
    // Just detect additional encoding layers in the actual string content

    // Detect encoding layers based on string content
    if is_likely_base64(&info.value) {
        info.encoding_chain.push("base64".to_string());
    }

    if is_likely_hex(&info.value) {
        info.encoding_chain.push("hex".to_string());
    }

    info
}

/// Check if a string looks like base64-encoded data
fn is_likely_base64(s: &str) -> bool {
    // Base64 strings are alphanumeric + /+ and optional padding
    // Must be reasonably long (> 16 chars) and have high base64 character ratio
    if s.len() < 16 {
        return false;
    }

    let base64_chars = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();

    // If >= 80% base64 characters, likely encoded
    (base64_chars as f32 / s.len() as f32) >= 0.8
}

/// Check if a string looks like hex-encoded data
fn is_likely_hex(s: &str) -> bool {
    // Hex strings are [0-9a-fA-F]+, must be even length and >= 32 chars
    if s.len() < 32 || s.len() % 2 != 0 {
        return false;
    }

    s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Convert stng StringMethod to a string for encoding_chain tracking
/// Only tracks actual string construction/encoding methods, not extraction sources
fn stng_method_to_string(method: StringMethod) -> String {
    match method {
        // String construction methods - worth tracking
        StringMethod::StackString => "stack",
        StringMethod::XorDecode => "xor",
        StringMethod::WideString => "wide",

        // Extraction sources - not worth tracking (all strings are equally valid)
        StringMethod::R2String
        | StringMethod::R2Symbol
        | StringMethod::RawScan
        | StringMethod::InstructionPattern
        | StringMethod::Structure
        | StringMethod::Heuristic
        | StringMethod::CodeSignature => return String::new(),

        // Future variants from stng
        _ => return String::new(),
    }
    .to_string()
}

/// Extract and classify strings from binary data
pub struct StringExtractor {
    min_length: usize,
    url_regex: Regex,
    ip_regex: Regex,
    version_ip_regex: Regex,
    email_regex: Regex,
    base64_regex: Regex,
    // Unified map for O(1) classification: normalized_name -> (Type, Optional Library)
    symbol_map: HashMap<String, (StringType, Option<String>)>,
}

impl StringExtractor {
    pub fn new() -> Self {
        Self {
            min_length: 4,
            url_regex: Regex::new(r"(?i)(https?|ftp)://[^\s<>]{1,2048}").unwrap(),
            // Basic IP pattern for initial detection
            ip_regex: Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap(),
            // Pattern to detect version strings that look like IPs (e.g., Chrome/100.0.0.0)
            version_ip_regex: Regex::new(r"(?i)(?:Chrome|Safari|Firefox|Edge|Opera|Chromium|Version|AppleWebKit|KHTML|Gecko|Trident|OPR|Mobile|MSIE|rv:|v)/\d+\.\d+\.\d+\.\d+").unwrap(),
            email_regex: Regex::new(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}").unwrap(),
            base64_regex: Regex::new(r"^[A-Za-z0-9+/]{16,65536}={0,2}$").unwrap(),
            symbol_map: HashMap::new(),
        }
    }

    fn normalize_symbol(sym: &str) -> String {
        sym.trim_start_matches("sym.imp.")
            .trim_start_matches("sym.")
            .trim_start_matches("fcn.")
            .trim_start_matches('_')
            .to_string()
    }

    #[allow(dead_code)]
    pub fn with_min_length(mut self, min_length: usize) -> Self {
        self.min_length = min_length;
        self
    }

    #[allow(dead_code)]
    pub fn with_symbols(mut self, functions: HashSet<String>) -> Self {
        for func in &functions {
            let normalized = Self::normalize_symbol(func);
            self.symbol_map
                .entry(normalized)
                .or_insert((StringType::Function, None));
        }
        self
    }

    #[allow(dead_code)]
    pub fn with_functions(mut self, functions: HashSet<String>) -> Self {
        for func in &functions {
            let normalized = Self::normalize_symbol(func);
            self.symbol_map
                .entry(normalized)
                .or_insert((StringType::Function, None));
        }
        self
    }

    #[allow(dead_code)]
    pub fn with_imports(mut self, imports: HashSet<String>) -> Self {
        for imp in &imports {
            let normalized = Self::normalize_symbol(imp);
            self.symbol_map
                .insert(normalized, (StringType::Import, None));
        }
        self
    }

    #[allow(dead_code)]
    pub fn with_import_libraries(mut self, import_libraries: HashMap<String, String>) -> Self {
        // Update existing imports in symbol_map with library info
        for (imp, lib) in import_libraries {
            let normalized = Self::normalize_symbol(&imp);
            self.symbol_map
                .insert(normalized, (StringType::Import, Some(lib)));
        }
        self
    }

    #[allow(dead_code)]
    pub fn with_exports(mut self, exports: HashSet<String>) -> Self {
        for exp in &exports {
            let normalized = Self::normalize_symbol(exp);
            self.symbol_map
                .insert(normalized, (StringType::Export, None));
        }
        self
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
                    if let Ok(s) = String::from_utf8(std::mem::take(&mut current_string)) {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() {
                            strings.push(self.classify_string(
                                trimmed.to_owned(),
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
                        trimmed.to_owned(),
                        string_offset,
                        section_name,
                    ));
                }
            }
        }

        strings
    }

    /// Extract strings using language-aware analysis for Go/Rust binaries.
    ///
    /// This method provides better results for Go and Rust binaries by using
    /// structure-based extraction that understands how these languages store
    /// strings. For other binary types, it falls back to basic extraction.
    ///
    /// The method:
    /// 1. Attempts language-aware extraction for Go/Rust binaries
    /// 2. Falls back to basic ASCII extraction for other binaries
    /// 3. Merges results from both methods, deduplicating by value
    pub fn extract_smart(&self, data: &[u8]) -> Vec<StringInfo> {
        // Build stng options with garbage filtering enabled
        let opts = ExtractOptions::new(self.min_length)
            .with_garbage_filter(true)
            .with_xor(None);

        // Run both extractions in parallel
        let (lang_strings, basic_strings) = rayon::join(
            || stng::extract_strings_with_options(data, &opts),
            || self.extract(data, None),
        );

        // Pre-size based on expected string count (roughly 1 string per 20 bytes)
        let estimated_count = data.len() / 20;
        // Use FxHashSet for faster hashing (non-cryptographic, ~10x faster than SipHash)
        let mut seen: FxHashSet<String> =
            FxHashSet::with_capacity_and_hasher(estimated_count, Default::default());
        let mut strings = Vec::with_capacity(estimated_count);

        for es in lang_strings {
            if !seen.contains(&es.value) {
                seen.insert(es.value.clone());
                strings.push(self.convert_extracted_string(es));
            }
        }

        for s in basic_strings {
            if !seen.contains(&s.value) {
                seen.insert(s.value.clone());
                strings.push(s);
            }
        }

        strings
    }

    /// Extract strings using language-aware analysis with optional r2 strings.
    ///
    /// This method accepts optional r2 strings if the caller has already run radare2.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw binary data
    /// * `r2_strings` - Optional pre-extracted radare2 strings
    pub fn extract_smart_with_r2(
        &self,
        data: &[u8],
        r2_strings: Option<Vec<R2String>>,
    ) -> Vec<StringInfo> {
        // Convert r2 strings to stng format if provided
        let stng_r2 = r2_strings.map(|r2s| r2_to_stng(r2s, self.min_length));

        // Build stng options with garbage filtering, XOR detection, and optional r2 strings
        let mut opts = ExtractOptions::new(self.min_length)
            .with_garbage_filter(true)
            .with_xor(None);
        if let Some(r2) = stng_r2 {
            opts = opts.with_r2_strings(r2);
        }

        // Run both extractions in parallel
        let (lang_strings, basic_strings) = rayon::join(
            || stng::extract_strings_with_options(data, &opts),
            || self.extract(data, None),
        );

        // Pre-size based on expected string count
        let estimated_count = data.len() / 20;
        let mut seen: FxHashSet<String> =
            FxHashSet::with_capacity_and_hasher(estimated_count, Default::default());
        let mut strings = Vec::with_capacity(estimated_count);

        for es in lang_strings {
            if !seen.contains(&es.value) {
                seen.insert(es.value.clone());
                strings.push(self.convert_extracted_string(es));
            }
        }

        for s in basic_strings {
            if !seen.contains(&s.value) {
                seen.insert(s.value.clone());
                strings.push(s);
            }
        }

        strings
    }

    /// Check if the binary is a Go binary (useful for conditional processing)
    #[allow(dead_code)]
    pub fn is_go_binary(&self, data: &[u8]) -> bool {
        stng::is_go_binary(data)
    }

    /// Extract strings from a pre-parsed Mach-O binary with optional r2 strings.
    ///
    /// DEPRECATED: This method doesn't find all special string types (e.g., StackStrings).
    /// Use `extract_smart_with_r2` instead for comprehensive extraction.
    ///
    /// This avoids re-parsing the binary in stng since DISSECT already parsed it.
    #[allow(dead_code)]
    pub fn extract_from_macho(
        &self,
        macho: &MachO,
        data: &[u8],
        r2_strings: Option<Vec<R2String>>,
    ) -> Vec<StringInfo> {
        let stng_r2 = r2_strings.map(|r2s| r2_to_stng(r2s, self.min_length));
        let mut opts = ExtractOptions::new(self.min_length)
            .with_garbage_filter(true)
            .with_xor(None);
        if let Some(r2) = stng_r2 {
            opts = opts.with_r2_strings(r2);
        }

        let (lang_strings, basic_strings) = rayon::join(
            || stng::extract_from_macho(macho, data, &opts),
            || self.extract(data, None),
        );

        self.merge_strings(lang_strings, basic_strings, data.len())
    }

    /// Extract strings from a pre-parsed ELF binary with optional r2 strings.
    ///
    /// DEPRECATED: This method doesn't find all special string types (e.g., StackStrings).
    /// Use `extract_smart_with_r2` instead for comprehensive extraction.
    ///
    /// This avoids re-parsing the binary in stng since DISSECT already parsed it.
    #[allow(dead_code)]
    pub fn extract_from_elf(
        &self,
        elf: &Elf,
        data: &[u8],
        r2_strings: Option<Vec<R2String>>,
    ) -> Vec<StringInfo> {
        let stng_r2 = r2_strings.map(|r2s| r2_to_stng(r2s, self.min_length));
        let mut opts = ExtractOptions::new(self.min_length)
            .with_garbage_filter(true)
            .with_xor(None);
        if let Some(r2) = stng_r2 {
            opts = opts.with_r2_strings(r2);
        }

        let (lang_strings, basic_strings) = rayon::join(
            || stng::extract_from_elf(elf, data, &opts),
            || self.extract(data, None),
        );

        self.merge_strings(lang_strings, basic_strings, data.len())
    }

    /// Extract strings from a pre-parsed PE binary with optional r2 strings.
    ///
    /// DEPRECATED: This method doesn't find all special string types (e.g., StackStrings).
    /// Use `extract_smart_with_r2` instead for comprehensive extraction.
    ///
    /// This avoids re-parsing the binary in stng since DISSECT already parsed it.
    #[allow(dead_code)]
    pub fn extract_from_pe(
        &self,
        pe: &PE,
        data: &[u8],
        r2_strings: Option<Vec<R2String>>,
    ) -> Vec<StringInfo> {
        let stng_r2 = r2_strings.map(|r2s| r2_to_stng(r2s, self.min_length));
        let mut opts = ExtractOptions::new(self.min_length)
            .with_garbage_filter(true)
            .with_xor(None);
        if let Some(r2) = stng_r2 {
            opts = opts.with_r2_strings(r2);
        }

        let (lang_strings, basic_strings) = rayon::join(
            || stng::extract_from_pe(pe, data, &opts),
            || self.extract(data, None),
        );

        self.merge_strings(lang_strings, basic_strings, data.len())
    }

    /// Merge language-aware strings with basic extraction, deduplicating by value.
    #[allow(dead_code)]
    fn merge_strings(
        &self,
        lang_strings: Vec<ExtractedString>,
        basic_strings: Vec<StringInfo>,
        data_len: usize,
    ) -> Vec<StringInfo> {
        let estimated_count = data_len / 20;
        let mut seen: FxHashSet<String> =
            FxHashSet::with_capacity_and_hasher(estimated_count, Default::default());
        let mut strings = Vec::with_capacity(estimated_count);

        for es in lang_strings {
            if !seen.contains(&es.value) {
                seen.insert(es.value.clone());
                strings.push(self.convert_extracted_string(es));
            }
        }

        for s in basic_strings {
            if !seen.contains(&s.value) {
                seen.insert(s.value.clone());
                strings.push(s);
            }
        }

        strings
    }

    /// Convert an ExtractedString from stng to StringInfo
    fn convert_extracted_string(&self, es: ExtractedString) -> StringInfo {
        // Use stng's kind if it's an import/export, otherwise classify ourselves
        let string_type = match es.kind {
            StringKind::Import => StringType::Import,
            StringKind::Export => StringType::Export,
            StringKind::FuncName => StringType::Function,
            _ => self.classify_string_type(&es.value),
        };

        // Detect if this is a stack string
        let final_string_type = if es.method == StringMethod::StackString {
            StringType::StackString
        } else {
            string_type
        };

        let mut info = StringInfo {
            value: es.value,
            offset: Some(format!("{:#x}", es.data_offset)),
            encoding: "utf8".to_string(),
            string_type: final_string_type,
            section: es.section,
            encoding_chain: Vec::new(),
            // Note: fragments from stng are StringFragment, not String - skip for now
            fragments: None,
        };

        // Track the stng method as an encoding layer if it's a special string construction
        // This captures: StackString, InetNtoa, InetAton, etc.
        let method_str = stng_method_to_string(es.method);
        if !method_str.is_empty() {
            info.encoding_chain.push(method_str);
        }

        // Detect any additional encoding layers (base64, hex, etc.)
        info = detect_layers(info);
        info
    }

    /// Classify a string by type
    fn classify_string(&self, value: String, offset: usize, section: Option<String>) -> StringInfo {
        let normalized = Self::normalize_symbol(&value);

        let (stype, _lib_info) = match self.symbol_map.get(&normalized) {
            Some((t, l)) => (*t, l.clone()),
            None => {
                let t = if self.url_regex.is_match(&value) {
                    StringType::Url
                } else if self.is_real_ip(&value) {
                    StringType::Ip
                } else if self.email_regex.is_match(&value) {
                    StringType::Email
                } else if self.is_path(&value) {
                    StringType::Path
                } else if value.len() >= 16 && self.base64_regex.is_match(&value) {
                    StringType::Base64
                } else {
                    StringType::Plain
                };
                (t, None)
            }
        };

        let mut info = StringInfo {
            value,
            offset: Some(format!("{:#x}", offset)),
            encoding: "utf8".to_string(),
            string_type: stype,
            section,
            encoding_chain: Vec::new(),
            fragments: None,
        };

        // Detect any encoding layers
        info = detect_layers(info);
        info
    }
    /// Classify a string's type without creating a StringInfo object
    pub fn classify_string_type(&self, value: &str) -> StringType {
        let normalized = Self::normalize_symbol(value);
        if let Some((stype, _)) = self.symbol_map.get(&normalized) {
            return *stype;
        }

        if self.url_regex.is_match(value) {
            StringType::Url
        } else if self.is_real_ip(value) {
            StringType::Ip
        } else if self.email_regex.is_match(value) {
            StringType::Email
        } else if self.is_path(value) {
            StringType::Path
        } else if value.len() >= 16 && self.base64_regex.is_match(value) {
            StringType::Base64
        } else {
            StringType::Plain
        }
    }

    #[allow(dead_code)]
    fn find_symbol_type(&self, value: &str) -> Option<StringType> {
        let normalized = Self::normalize_symbol(value);
        self.symbol_map.get(&normalized).map(|(t, _)| *t)
    }

    #[allow(dead_code)]
    fn get_import_library(&self, value: &str) -> Option<String> {
        let normalized = Self::normalize_symbol(value);
        self.symbol_map
            .get(&normalized)
            .and_then(|(_, l)| l.clone())
    }

    #[allow(dead_code)]
    fn matches_symbol_set(&self, _set: &HashSet<String>, value: &str) -> bool {
        let normalized = Self::normalize_symbol(value);
        self.symbol_map.contains_key(&normalized)
    }

    /// Check if string contains a real IP address (not a version string)
    fn is_real_ip(&self, s: &str) -> bool {
        // Must contain IP-like pattern
        if !self.ip_regex.is_match(s) {
            return false;
        }
        // Exclude version strings like "Chrome/100.0.0.0", "Safari/537.36.0.0"
        if self.version_ip_regex.is_match(s) {
            return false;
        }
        // Validate that IP octets are in valid range (0-255)
        if let Some(caps) = self.ip_regex.find(s) {
            let ip_str = caps.as_str();
            let octets: Vec<&str> = ip_str.split('.').collect();
            if octets.len() == 4 {
                for octet in octets {
                    if let Ok(val) = octet.parse::<u32>() {
                        if val > 255 {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                return true;
            }
        }
        false
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

/// Convert radare2 strings to stng format
fn r2_to_stng(r2_strings: Vec<R2String>, min_length: usize) -> Vec<ExtractedString> {
    r2_strings
        .into_iter()
        .filter(|s| s.string.len() >= min_length)
        .map(|s| ExtractedString {
            value: s.string,
            data_offset: s.paddr,
            section: None,
            method: StringMethod::R2String,
            kind: StringKind::Const,
            library: None,
            fragments: None,
        })
        .collect()
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
    fn test_ip_excludes_version_strings() {
        let extractor = StringExtractor::new();

        // Version strings should NOT be detected as IPs
        assert!(
            !extractor.is_real_ip("Chrome/100.0.0.0"),
            "Chrome version should not be IP"
        );
        assert!(
            !extractor.is_real_ip("Safari/537.36.0.0"),
            "Safari version should not be IP"
        );
        assert!(
            !extractor.is_real_ip("AppleWebKit/537.36.0.0"),
            "AppleWebKit version should not be IP"
        );
        assert!(
            !extractor.is_real_ip("Mozilla/5.0 Chrome/100.0.0.0 Safari/537.36"),
            "UA string with version should not be IP"
        );
        assert!(
            !extractor.is_real_ip("Firefox/115.0.0.0"),
            "Firefox version should not be IP"
        );

        // Real IPs should be detected
        assert!(
            extractor.is_real_ip("192.168.1.1"),
            "Private IP should be IP"
        );
        assert!(extractor.is_real_ip("10.0.0.1"), "Private IP should be IP");
        assert!(
            extractor.is_real_ip("8.8.8.8"),
            "Public DNS IP should be IP"
        );
        assert!(
            extractor.is_real_ip("Connect to 192.168.1.1 now"),
            "IP in sentence should be IP"
        );
    }

    #[test]
    fn test_ip_validates_octets() {
        let extractor = StringExtractor::new();

        // Invalid octets (> 255) should not be detected as IPs
        assert!(
            !extractor.is_real_ip("300.168.1.1"),
            "Invalid octet should not be IP"
        );
        assert!(
            !extractor.is_real_ip("192.300.1.1"),
            "Invalid octet should not be IP"
        );
        assert!(
            !extractor.is_real_ip("192.168.1.300"),
            "Invalid octet should not be IP"
        );

        // Valid edge cases
        assert!(
            extractor.is_real_ip("255.255.255.255"),
            "Max IP should be IP"
        );
        assert!(extractor.is_real_ip("0.0.0.0"), "Zero IP should be IP");
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

    #[test]
    fn test_extract_smart_basic() {
        // Basic test with non-Go/Rust data - should fall back to basic extraction
        let data = b"Hello World http://example.com /usr/bin/ls";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data);

        assert!(!strings.is_empty());
        // Should find URL
        assert!(strings
            .iter()
            .any(|s| matches!(s.string_type, StringType::Url)));
    }

    #[test]
    fn test_extract_smart_empty() {
        let data = b"";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_smart_deduplication() {
        // Test that duplicate strings are removed
        let data = b"test string\0test string\0test string";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data);

        // Should not have duplicate values
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        let unique: HashSet<&str> = values.iter().cloned().collect();
        assert_eq!(values.len(), unique.len());
    }

    #[test]
    fn test_is_go_binary_false_for_plain_data() {
        let data = b"Hello World";
        let extractor = StringExtractor::new();

        // Plain data should not be detected as Go
        assert!(!extractor.is_go_binary(data));
    }

    #[test]
    fn test_extract_smart_with_go_binary() {
        // Test with actual Go binary if available
        let path = "tests/fixtures/lang_strings/go_darwin_arm64";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let extractor = StringExtractor::new();

        let strings = extractor.extract_smart(&data);

        // Should find strings from both lang_strings and basic extraction
        assert!(!strings.is_empty());

        // Go binaries should have DISSECT_CONST_MARKER from lang_strings
        assert!(
            strings.iter().any(|s| s.value.contains("DISSECT")),
            "Should find DISSECT markers in Go binary"
        );
    }

    #[test]
    fn test_extract_smart_with_rust_binary() {
        // Test with actual Rust binary if available
        let path = "tests/fixtures/lang_strings/rust_native";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let extractor = StringExtractor::new();

        let strings = extractor.extract_smart(&data);

        // Should find strings
        assert!(!strings.is_empty());

        // Rust binaries should have stdlib paths
        assert!(
            strings.iter().any(|s| s.value.contains("library/std")),
            "Should find stdlib paths in Rust binary"
        );
    }
}
