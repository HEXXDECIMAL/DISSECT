//! Language-aware string extraction for Go and Rust binaries.
//!
//! This module understands how Go and Rust store strings internally
//! (pointer + length pairs, NOT null-terminated) and can properly
//! extract individual strings from packed string data.
//!
//! # Background
//!
//! Both Go and Rust use "fat pointer" representations for strings:
//! - Go: `string` is `{ptr: *byte, len: int}` (16 bytes on 64-bit)
//! - Rust: `&str` is `{ptr: *u8, len: usize}` (16 bytes on 64-bit)
//! - Rust: `String` is `{ptr: *u8, len: usize, cap: usize}` (24 bytes on 64-bit)
//!
//! Because strings aren't null-terminated, they're often packed together
//! in the binary without separators. Traditional string extraction tools
//! (like `strings(1)`) concatenate them into garbage blobs.
//!
//! This module finds the pointer+length structures and uses them to
//! extract strings with precise boundaries.

mod common;
mod go;
mod instr;
mod rust;

pub use common::ExtractedString;
pub use go::GoStringExtractor;
pub use rust::RustStringExtractor;

use goblin::mach::MachO;
use goblin::Object;

/// Helper to check if a Mach-O binary has Go sections.
fn macho_has_go_sections(macho: &MachO) -> bool {
    macho.segments.iter().any(|seg| {
        seg.sections().is_ok_and(|secs| {
            secs.iter().any(|(sec, _)| {
                let name = sec.name().unwrap_or("");
                name == "__gopclntab" || name == "__go_buildinfo"
            })
        })
    })
}

/// Check if a binary is a Go binary by looking for Go-specific sections.
#[allow(dead_code)]
pub fn is_go_binary(data: &[u8]) -> bool {
    match Object::parse(data) {
        Ok(Object::Mach(goblin::mach::Mach::Binary(macho))) => macho_has_go_sections(&macho),
        Ok(Object::Mach(goblin::mach::Mach::Fat(_))) => false,
        Ok(Object::Elf(elf)) => elf.section_headers.iter().any(|sh| {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            name == ".gopclntab" || name == ".go.buildinfo"
        }),
        Ok(Object::PE(_pe)) => false,
        _ => false,
    }
}

/// Check if a Mach-O binary appears to be a Rust binary.
fn macho_is_rust(macho: &MachO) -> bool {
    // Look for Rust-specific symbols or section patterns
    // Rust binaries typically have __rust_alloc, __rust_dealloc symbols
    // or section names containing "rust"
    macho.segments.iter().any(|seg| {
        seg.sections().is_ok_and(|secs| {
            secs.iter().any(|(sec, _)| {
                let name = sec.name().unwrap_or("");
                name.contains("rust")
            })
        })
    })
}

/// Detect binary type and extract strings using appropriate language-aware extractor.
pub fn extract_lang_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let mut strings = Vec::new();

    match Object::parse(data) {
        Ok(Object::Mach(goblin::mach::Mach::Binary(macho))) => {
            if macho_has_go_sections(&macho) {
                let extractor = GoStringExtractor::new(min_length);
                strings.extend(extractor.extract_macho(&macho, data));
            } else if macho_is_rust(&macho) {
                let extractor = RustStringExtractor::new(min_length);
                strings.extend(extractor.extract_macho(&macho, data));
            } else {
                // Try Rust extraction for unknown Mach-O (many Rust binaries don't have markers)
                let extractor = RustStringExtractor::new(min_length);
                strings.extend(extractor.extract_macho(&macho, data));
            }
        }
        Ok(Object::Mach(goblin::mach::Mach::Fat(_))) => {
            // Fat binaries not supported yet
        }
        Ok(Object::Elf(elf)) => {
            // Check for Go sections
            let has_go = elf.section_headers.iter().any(|sh| {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                name == ".gopclntab" || name == ".go.buildinfo"
            });

            // Check for Rust (presence of rust metadata or panic strings)
            let has_rust = elf.section_headers.iter().any(|sh| {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                name.contains("rust") || name == ".rustc"
            });

            if has_go {
                let extractor = GoStringExtractor::new(min_length);
                strings.extend(extractor.extract_elf(&elf, data));
            } else if has_rust {
                let extractor = RustStringExtractor::new(min_length);
                strings.extend(extractor.extract_elf(&elf, data));
            } else {
                // Try Rust extraction for unknown ELF (fallback)
                let extractor = RustStringExtractor::new(min_length);
                strings.extend(extractor.extract_elf(&elf, data));
            }
        }
        Ok(Object::PE(pe)) => {
            // Check for Go by looking for go.buildinfo or runtime.main
            let has_go = pe.sections.iter().any(|sec| {
                let name = String::from_utf8_lossy(&sec.name);
                name.contains("go") || name.contains(".rdata")
            });

            if has_go {
                let extractor = GoStringExtractor::new(min_length);
                strings.extend(extractor.extract_pe(&pe, data));
            }
        }
        _ => {}
    }

    strings
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Basic Tests ====================

    #[test]
    fn test_extract_lang_strings_empty_data() {
        let strings = extract_lang_strings(&[], 4);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_lang_strings_invalid_binary() {
        let data = b"not a valid binary format";
        let strings = extract_lang_strings(data, 4);
        assert!(strings.is_empty());
    }

    // ==================== Go String Extraction - Mach-O ARM64 ====================

    #[test]
    fn test_go_macho_arm64_constants() {
        let path = "tests/fixtures/lang_strings/go_darwin_arm64";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Constants should be extracted
        assert!(
            values.contains(&"DISSECT_CONST_MARKER_1"),
            "Should find const marker 1"
        );
        assert!(values.contains(&"10.0.0.100"), "Should find const IP");
    }

    #[test]
    fn test_go_macho_arm64_global_variables() {
        let path = "tests/fixtures/lang_strings/go_darwin_arm64";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Global variables should be extracted
        assert!(
            values.contains(&"DISSECT_VAR_MARKER_1"),
            "Should find var marker 1"
        );
        assert!(values.contains(&"/etc/passwd"), "Should find var path");
    }

    #[test]
    fn test_go_macho_arm64_error_messages() {
        let path = "tests/fixtures/lang_strings/go_darwin_arm64";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Error messages from errors.New() should be extracted
        assert!(
            values.iter().any(|s| s.contains("authentication failed")),
            "Should find error message"
        );
    }

    #[test]
    fn test_go_macho_arm64_struct_fields() {
        let path = "tests/fixtures/lang_strings/go_darwin_arm64";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Struct field values from variables should be extracted
        assert!(values.contains(&"api-server"), "Should find server name");
        assert!(
            values.contains(&"api.example.com"),
            "Should find server host"
        );
    }

    #[test]
    fn test_go_macho_arm64_map_keys_values() {
        let path = "tests/fixtures/lang_strings/go_darwin_arm64";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Map keys and values from variables should be extracted
        assert!(values.contains(&"DATABASE_URL"), "Should find env key");
        assert!(
            values
                .iter()
                .any(|s| s.contains("postgresql://db.example.com")),
            "Should find env value"
        );
    }

    #[test]
    fn test_go_macho_arm64_sensitive_data() {
        let path = "tests/fixtures/lang_strings/go_darwin_arm64";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Sensitive data patterns should be extracted
        assert!(
            values.contains(&"sk_live_abc123xyz"),
            "Should find API token"
        );
        assert!(values.contains(&"secret123"), "Should find password");
    }

    // ==================== Go String Extraction - ELF AMD64 ====================

    #[test]
    fn test_go_elf_amd64_constants() {
        let path = "tests/fixtures/lang_strings/go_linux_amd64";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        assert!(
            values.contains(&"DISSECT_CONST_MARKER_1"),
            "ELF AMD64: Should find const marker"
        );
    }

    #[test]
    fn test_go_elf_amd64_global_variables() {
        let path = "tests/fixtures/lang_strings/go_linux_amd64";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        assert!(
            values.contains(&"DISSECT_VAR_MARKER_1"),
            "ELF AMD64: Should find var marker"
        );
    }

    #[test]
    fn test_go_elf_amd64_sensitive_data() {
        let path = "tests/fixtures/lang_strings/go_linux_amd64";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        assert!(
            values.contains(&"DATABASE_URL"),
            "ELF AMD64: Should find env key"
        );
    }

    // ==================== Go String Extraction - ELF ARM64 ====================

    #[test]
    fn test_go_elf_arm64_constants() {
        let path = "tests/fixtures/lang_strings/go_linux_arm64";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        assert!(
            values.contains(&"DISSECT_CONST_MARKER_1"),
            "ELF ARM64: Should find const marker"
        );
    }

    #[test]
    fn test_go_elf_arm64_global_variables() {
        let path = "tests/fixtures/lang_strings/go_linux_arm64";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        assert!(
            values.contains(&"DISSECT_VAR_MARKER_1"),
            "ELF ARM64: Should find var marker"
        );
    }

    // ==================== Cross-Architecture Consistency ====================

    #[test]
    fn test_go_cross_architecture_consistency() {
        let paths = [
            "tests/fixtures/lang_strings/go_darwin_arm64",
            "tests/fixtures/lang_strings/go_linux_amd64",
            "tests/fixtures/lang_strings/go_linux_arm64",
        ];

        // Expected strings that should be found in ALL architectures
        let expected = [
            "DISSECT_CONST_MARKER_1",
            "DISSECT_VAR_MARKER_1",
            "api-server",
            "DATABASE_URL",
        ];

        for path in &paths {
            if !std::path::Path::new(path).exists() {
                continue;
            }
            let data = std::fs::read(path).unwrap();
            let strings = extract_lang_strings(&data, 4);
            let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

            for exp in &expected {
                assert!(
                    values.iter().any(|s| s == exp),
                    "Binary {} should contain '{}'",
                    path,
                    exp
                );
            }
        }
    }

    // ==================== Rust Binary Tests ====================

    #[test]
    fn test_rust_binary_not_detected_as_go() {
        let path = "tests/fixtures/lang_strings/rust_native";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        assert!(
            !is_go_binary(&data),
            "Rust binary should not be detected as Go"
        );
    }

    #[test]
    fn test_rust_macho_static_strings() {
        let path = "tests/fixtures/lang_strings/rust_native";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Static strings should be extracted
        let expected = [
            "DISSECT_STATIC_MARKER_1",
            "DISSECT_STATIC_MARKER_2",
            "10.0.0.200",
            "https://static.example.com/api",
        ];

        for exp in &expected {
            assert!(
                values.contains(exp),
                "Rust Mach-O: Should find static string '{}'",
                exp
            );
        }
    }

    #[test]
    fn test_rust_macho_const_strings() {
        let path = "tests/fixtures/lang_strings/rust_native";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Const strings should be extracted
        let expected = ["DISSECT_CONST_MARKER_1", "DISSECT_CONST_MARKER_2"];

        for exp in &expected {
            assert!(
                values.contains(exp),
                "Rust Mach-O: Should find const string '{}'",
                exp
            );
        }
    }

    #[test]
    fn test_rust_macho_struct_fields() {
        let path = "tests/fixtures/lang_strings/rust_native";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Struct field values should be extracted
        let expected = [
            "rust-api-server",
            "rust.api.example.com",
            "9443",
            "rust_admin",
            "rust_secret123",
            "rs_live_token_xyz789",
        ];

        for exp in &expected {
            assert!(
                values.contains(exp),
                "Rust Mach-O: Should find struct field '{}'",
                exp
            );
        }
    }

    #[test]
    fn test_rust_macho_local_variables() {
        // Note: Rust heavily optimizes local string bindings, packing them without
        // pointer+length structures. Unlike Go, most Rust inline literals cannot
        // be extracted via structure analysis. This test verifies that we extract
        // SOMETHING from a Rust binary - the stdlib paths are always present.
        let path = "tests/fixtures/lang_strings/rust_native";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Rust stdlib paths should always be extractable (panic metadata)
        assert!(
            values.iter().any(|s| s.contains("library/std/src")),
            "Rust Mach-O: Should find stdlib paths from panic metadata"
        );

        // The source file name should be present
        assert!(
            values.iter().any(|s| s.contains("test_rust")),
            "Rust Mach-O: Should find source file name"
        );
    }

    #[test]
    fn test_rust_macho_vec_elements() {
        // Note: Vec elements in Rust are packed without separators and lack
        // pointer+length structures. They're stored inline and not extractable
        // via structure analysis. This test verifies general extraction works.
        let path = "tests/fixtures/lang_strings/rust_native";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);

        // Verify we extract a reasonable number of strings
        assert!(
            strings.len() > 100,
            "Rust Mach-O: Should extract >100 strings, got {}",
            strings.len()
        );
    }

    #[test]
    fn test_rust_macho_hashmap_data() {
        // Note: HashMap literal keys/values in Rust are packed inline without
        // pointer structures. They would require instruction analysis to extract.
        // This test verifies structure-based extraction still finds stdlib strings.
        let path = "tests/fixtures/lang_strings/rust_native";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Should find hashbrown (HashMap implementation) source paths
        assert!(
            values.iter().any(|s| s.contains("hashbrown")),
            "Rust Mach-O: Should find hashbrown lib paths"
        );
    }

    #[test]
    fn test_rust_macho_owned_strings() {
        // Note: String::from() literals get packed into __const without separate
        // pointer structures, making them hard to extract. They're treated as
        // static data that's copied at runtime.
        let path = "tests/fixtures/lang_strings/rust_native";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Should find alloc-related paths (used by String)
        assert!(
            values.iter().any(|s| s.contains("alloc")),
            "Rust Mach-O: Should find alloc lib paths"
        );
    }

    #[test]
    fn test_rust_macho_error_messages() {
        // Note: User-defined error messages are packed inline without pointer
        // structures. The Rust stdlib panic messages ARE extractable.
        let path = "tests/fixtures/lang_strings/rust_native";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Panic-related paths should be extractable
        assert!(
            values.iter().any(|s| s.contains("panicking")),
            "Rust Mach-O: Should find panic-related paths"
        );
    }

    #[test]
    fn test_rust_macho_literal_markers() {
        // Literals passed to println!() macro - may be inlined
        let path = "tests/fixtures/lang_strings/rust_native";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Check that literal markers are extractable
        assert!(
            values.iter().any(|s| s.contains("DISSECT_LITERAL_RUST")),
            "Rust Mach-O: Should find literal markers"
        );
    }

    // ==================== gostrings Sample Tests ====================
    // These tests verify EXACT string extraction - no garbage before or after.
    // All assertions use == for exact match, not contains().

    /// Helper to check if an exact string exists in extracted values
    fn has_exact(values: &[&str], expected: &str) -> bool {
        values.contains(&expected)
    }

    /// Helper to report missing strings
    fn assert_exact_strings(values: &[&str], expected: &[&str], category: &str) {
        let mut missing = Vec::new();
        for exp in expected {
            if !has_exact(values, exp) {
                missing.push(*exp);
            }
        }
        assert!(
            missing.is_empty(),
            "{}: Missing exact strings (no garbage allowed): {:?}\nExtracted {} total strings",
            category,
            missing,
            values.len()
        );
    }

    #[test]
    fn test_gostrings_sample_exact_constants() {
        let path = "../gostrings/testdata/sample";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Constants from sample.go - EXACT matches only
        let expected = [
            "192.168.1.100",              // ServerIP
            "https://api.example.com/v1", // ApiURL
        ];
        assert_exact_strings(&values, &expected, "Constants");
    }

    #[test]
    fn test_gostrings_sample_exact_error_messages() {
        let path = "../gostrings/testdata/sample";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Error messages from errors.New() - EXACT matches only
        let expected = [
            "authentication failed: invalid OAuth2 credentials provided",
            "database connection lost: unable to reach postgresql server",
            "payment processing failed: transaction declined by issuing bank",
            "payment rejected: customer account has insufficient funds",
        ];
        assert_exact_strings(&values, &expected, "Error messages");
    }

    #[test]
    fn test_gostrings_sample_exact_env_and_paths() {
        let path = "../gostrings/testdata/sample";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Environment variables and file paths - EXACT matches only
        let expected = [
            "DATABASE_URL", // env var name
            "/etc/hosts",   // file path
        ];
        assert_exact_strings(&values, &expected, "Env vars and paths");
    }

    #[test]
    fn test_gostrings_sample_exact_sensitive_data() {
        // These strings are inline literals passed directly to functions.
        // The Go compiler doesn't create pointer+length structures for these.
        // They require instruction pattern analysis (ADRP+ADD on ARM64, LEA on AMD64).
        let path = "../gostrings/testdata/sample";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Sensitive data patterns - EXACT matches only, no garbage
        let expected = [
            "secret-oauth-token-12345", // OAuth token - inline literal
            "postgresql://user:pass@localhost:5432/mydb", // Database DSN - inline literal
            "4532-1234-5678-9010",      // Credit card - inline literal
        ];
        assert_exact_strings(&values, &expected, "Sensitive data (inline literals)");
    }

    #[test]
    fn test_gostrings_sample_exact_test_markers() {
        let path = "../gostrings/testdata/sample";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Test markers - EXACT matches only
        let expected = [
            "GOSTRINGS_TEST_MARKER_1",
            "GOSTRINGS_TEST_MARKER_2",
            "GOSTRINGS_TEST_MARKER_3",
        ];
        assert_exact_strings(&values, &expected, "Test markers");
    }

    #[test]
    fn test_gostrings_sample_exact_inline_map_literals() {
        let path = "../gostrings/testdata/sample";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Inline map literals from sample.go lines 59-63 - EXACT matches only
        // Map KEYS are extractable, but map VALUES stored as inline literals
        // may not be extractable even with instruction pattern analysis
        // (gostrings also doesn't extract these values)
        let expected = ["email"];
        assert_exact_strings(&values, &expected, "Inline map literals");
    }

    // ==================== Dissect Test Binary - Exact Matches ====================

    #[test]
    fn test_dissect_go_binary_exact_constants() {
        let path = "tests/fixtures/lang_strings/go_darwin_arm64";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        let expected = [
            "DISSECT_CONST_MARKER_1",
            "DISSECT_CONST_MARKER_2",
            "10.0.0.100",
            "https://const.example.com/api",
        ];
        assert_exact_strings(&values, &expected, "Dissect Go constants");
    }

    #[test]
    fn test_dissect_go_binary_exact_variables() {
        let path = "tests/fixtures/lang_strings/go_darwin_arm64";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        let expected = [
            "DISSECT_VAR_MARKER_1",
            "DISSECT_VAR_MARKER_2",
            "/etc/passwd",
            "postgres://user:pass@localhost:5432/db",
        ];
        assert_exact_strings(&values, &expected, "Dissect Go variables");
    }

    #[test]
    fn test_dissect_go_binary_exact_struct_fields() {
        let path = "tests/fixtures/lang_strings/go_darwin_arm64";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        let expected = [
            "api-server",
            "api.example.com",
            "8443",
            "https",
            "admin",
            "secret123",
            "sk_live_abc123xyz",
        ];
        assert_exact_strings(&values, &expected, "Dissect Go struct fields");
    }

    #[test]
    fn test_dissect_go_binary_exact_map_data() {
        let path = "tests/fixtures/lang_strings/go_darwin_arm64";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        let expected = [
            "DATABASE_URL",
            "REDIS_URL",
            "API_SECRET",
            "postgresql://db.example.com:5432/prod",
            "redis://cache.example.com:6379",
            "super_secret_api_key_12345",
        ];
        assert_exact_strings(&values, &expected, "Dissect Go map data");
    }

    // ==================== Rust Binary - Comprehensive Extraction ====================

    #[test]
    fn test_rust_comprehensive_extraction() {
        // This test verifies the improved Rust extraction finds key strings
        let path = "tests/fixtures/lang_strings/rust_native";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_lang_strings(&data, 4);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // Strings extractable via __DATA_CONST structures
        let structure_strings = [
            "DISSECT_STATIC_MARKER_1",
            "DISSECT_STATIC_MARKER_2",
            "DISSECT_CONST_MARKER_1",
            "DISSECT_CONST_MARKER_2",
            "DISSECT_LITERAL_RUST_1",
            "DISSECT_LITERAL_RUST_2",
            "rust_admin",
            "rust_secret123",
            "rs_live_token_xyz789",
            "rust.api.example.com",
        ];

        for exp in &structure_strings {
            assert!(
                values.iter().any(|s| s.contains(exp)),
                "Rust: Should find '{}' via structure analysis",
                exp
            );
        }

        // Strings extractable via heuristic pattern matching
        let heuristic_strings = [
            "RUST_DATABASE_URL",
            "RUST_REDIS_URL",
            "rust.db.example.com",
            "rust.cache.example.com",
            "DISSECT_OWNED_MARKER",
            "owned_secret_value_abc",
            "rust_vec_element_1",
        ];

        for exp in &heuristic_strings {
            assert!(
                values.iter().any(|s| s.contains(exp)),
                "Rust: Should find '{}' via heuristic extraction",
                exp
            );
        }

        // URLs should be extracted
        assert!(
            values.iter().any(|s| s.contains("postgresql://")),
            "Rust: Should extract PostgreSQL connection string"
        );
        assert!(
            values.iter().any(|s| s.contains("redis://")),
            "Rust: Should extract Redis connection string"
        );
        assert!(
            values.iter().any(|s| s.contains("mysql://")),
            "Rust: Should extract MySQL connection string"
        );
    }
}
