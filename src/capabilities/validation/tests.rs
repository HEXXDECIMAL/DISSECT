//! Tests for validation module.
//!
//! Tests are organized by submodule to match the module structure.

#[cfg(test)]
mod precision_tests {
    // Precision calculation tests would go here
    // Tests from original validation.rs lines ~3312-4200
}

#[cfg(test)]
mod duplicate_tests {
    use super::super::duplicates::*;
    use super::super::helpers::extract_tier;
    use crate::composite_rules::{Condition, ConditionWithFilters, FileType, Platform, TraitDefinition};
    use std::path::PathBuf;

    // ========================================================================
    // Test Helpers
    // ========================================================================

    /// Create a minimal trait definition for testing
    fn create_test_trait(
        id: &str,
        condition: Condition,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test trait".to_string(),
            r#if: ConditionWithFilters {
                condition,
                size_min: None,
                size_max: None,
                count_min: None,
                count_max: None,
                per_kb_min: None,
                per_kb_max: None,
            },
            r#for: for_types,
            platforms: vec![Platform::All],
            not: None,
            unless: None,
            defined_in: PathBuf::from(file_path),
            precision: None,
        }
    }

    /// Create a string exact trait
    fn create_string_exact(
        id: &str,
        pattern: &str,
        case_insensitive: bool,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::String {
                exact: Some(pattern.to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive,
                exclude_patterns: None,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            for_types,
            file_path,
        )
    }

    /// Create a string substr trait
    fn create_string_substr(
        id: &str,
        pattern: &str,
        case_insensitive: bool,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::String {
                exact: None,
                substr: Some(pattern.to_string()),
                regex: None,
                word: None,
                case_insensitive,
                exclude_patterns: None,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            for_types,
            file_path,
        )
    }

    /// Create a string regex trait
    fn create_string_regex(
        id: &str,
        pattern: &str,
        case_insensitive: bool,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::String {
                exact: None,
                substr: None,
                regex: Some(pattern.to_string()),
                word: None,
                case_insensitive,
                exclude_patterns: None,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                compiled_excludes: Vec::new(),
            },
            for_types,
            file_path,
        )
    }

    /// Create a symbol exact trait
    fn create_symbol_exact(
        id: &str,
        pattern: &str,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::Symbol {
                exact: Some(pattern.to_string()),
                substr: None,
                regex: None,
                platforms: None,
                compiled_regex: None,
            },
            for_types,
            file_path,
        )
    }

    /// Create a raw regex trait
    fn create_raw_regex(
        id: &str,
        pattern: &str,
        case_insensitive: bool,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::Raw {
                exact: None,
                substr: None,
                regex: Some(pattern.to_string()),
                word: None,
                case_insensitive,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
            },
            for_types,
            file_path,
        )
    }

    // ========================================================================
    // Phase 1: Hex Escape Normalization Tests
    // ========================================================================

    #[test]
    fn test_hex_escape_single_byte() {
        assert_eq!(decode_hex_escapes("\\x27"), "'");
        assert_eq!(decode_hex_escapes("\\x00"), "\0");
        assert_eq!(decode_hex_escapes("\\x41"), "A");
        assert_eq!(decode_hex_escapes("\\x7f"), "\x7f");
    }

    #[test]
    fn test_hex_escape_in_string() {
        assert_eq!(decode_hex_escapes("test\\x27string"), "test'string");
        assert_eq!(decode_hex_escapes("\\x48ello"), "Hello");
        assert_eq!(decode_hex_escapes("foo\\x20bar"), "foo bar");
    }

    #[test]
    fn test_hex_escape_multiple() {
        assert_eq!(decode_hex_escapes("\\x41\\x42\\x43"), "ABC");
        assert_eq!(decode_hex_escapes("\\x27\\x22"), "'\"");
    }

    #[test]
    fn test_hex_escape_invalid_kept_as_is() {
        // Invalid hex (only 1 digit)
        assert_eq!(decode_hex_escapes("\\x2"), "\\x2");
        // Invalid hex (non-hex chars)
        assert_eq!(decode_hex_escapes("\\xZZ"), "\\xZZ");
        // Other escape sequences preserved
        assert_eq!(decode_hex_escapes("\\n"), "\\n");
        assert_eq!(decode_hex_escapes("\\t"), "\\t");
    }

    #[test]
    fn test_hex_escape_duplicate_detection() {
        let trait1 = create_string_exact(
            "test::a",
            "\\x27",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let trait2 = create_string_exact(
            "test::b",
            "'",
            false,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Duplicate"));
        assert!(warnings[0].contains("test::a"));
        assert!(warnings[0].contains("test::b"));
    }

    #[test]
    fn test_hex_escape_real_example() {
        // Real pattern from codebase: [\"\x27] vs [\"']
        let trait1 = create_string_regex(
            "test::a",
            "[\\\"\\x27]",
            false,
            vec![FileType::Python],
            "file1.yaml",
        );
        let trait2 = create_string_regex(
            "test::b",
            "[\\\"\\'']",
            false,
            vec![FileType::Python],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Duplicate"));
    }

    // ========================================================================
    // Phase 2: Containment Detection Tests
    // ========================================================================

    #[test]
    fn test_exact_contained_by_substr() {
        let exact = create_string_exact(
            "test::exact",
            "/dev/kmem",
            false,
            vec![FileType::Elf],
            "file1.yaml",
        );
        let substr = create_string_substr(
            "test::substr",
            "/dev/kmem",
            false,
            vec![FileType::Elf],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_exact_contained_by_substr(&[exact, substr], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("REDUNDANT"));
        assert!(warnings[0].contains("exact pattern"));
        assert!(warnings[0].contains("/dev/kmem"));
    }

    #[test]
    fn test_exact_not_contained_different_strings() {
        let exact = create_string_exact(
            "test::exact",
            "os.rename",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let substr = create_string_substr(
            "test::substr",
            "os.rename ",  // trailing space
            false,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_exact_contained_by_substr(&[exact, substr], &mut warnings);

        // No redundancy because strings differ (trailing space)
        assert_eq!(warnings.len(), 0);
    }

    // ========================================================================
    // Phase 3: Case-Insensitive Overlap Tests
    // ========================================================================

    #[test]
    fn test_case_insensitive_subsumes_case_sensitive() {
        let case_sensitive = create_string_exact(
            "test::sensitive",
            "PASSWORD",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let case_insensitive = create_string_exact(
            "test::insensitive",
            "password",
            true,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_case_insensitive_overlaps(&[case_sensitive, case_insensitive], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("CASE SUBSUMPTION"));
    }

    #[test]
    fn test_both_case_insensitive_differ_in_case() {
        let trait1 = create_string_exact(
            "test::a",
            "GetProcAddress",
            true,
            vec![FileType::All],
            "file1.yaml",
        );
        let trait2 = create_string_exact(
            "test::b",
            "getprocaddress",
            true,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_case_insensitive_overlaps(&[trait1, trait2], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("DUPLICATE (case only)"));
    }

    #[test]
    fn test_both_case_sensitive_different_case_ok() {
        let trait1 = create_string_exact(
            "test::a",
            "GetProcAddress",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let trait2 = create_string_exact(
            "test::b",
            "GETPROCADDRESS",
            false,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_case_insensitive_overlaps(&[trait1, trait2], &mut warnings);

        // No warning - both case-sensitive, different case = different patterns
        assert_eq!(warnings.len(), 0);
    }

    // ========================================================================
    // Phase 4: Regex Containment Tests
    // ========================================================================

    #[test]
    fn test_regex_exact_match_cross_type() {
        let symbol_exact = create_symbol_exact(
            "test::symbol",
            "GetProcAddress",
            vec![FileType::Pe],
            "file1.yaml",
        );
        let raw_regex = create_raw_regex(
            "test::raw",
            "GetProcAddress",
            false,
            vec![FileType::Pe],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_regex_contains_literal(&[symbol_exact, raw_regex], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("REGEX vs LITERAL DUPLICATE"));
        assert!(warnings[0].contains("cross-type"));
    }

    #[test]
    fn test_regex_contains_literal() {
        let exact = create_string_exact(
            "test::exact",
            "foo",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let regex = create_string_regex(
            "test::regex",
            "foo.*",
            false,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_regex_contains_literal(&[exact, regex], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("REGEX CONTAINS LITERAL"));
    }

    #[test]
    fn test_regex_doesnt_match_no_warning() {
        let exact = create_string_exact(
            "test::exact",
            "bar",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let regex = create_string_regex(
            "test::regex",
            "foo.*",
            false,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_regex_contains_literal(&[exact, regex], &mut warnings);

        // No warning - regex doesn't match literal
        assert_eq!(warnings.len(), 0);
    }

    // ========================================================================
    // Phase 5: Regex Alternative Subset Tests
    // ========================================================================

    #[test]
    fn test_regex_alternative_subset() {
        let regex1 = create_string_regex(
            "test::subset",
            "(read|write)",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let regex2 = create_string_regex(
            "test::superset",
            "(read|write|execute)",
            false,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_regex_alternative_subsets(&[regex1, regex2], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("REGEX ALTERNATIVE SUBSET"));
    }

    #[test]
    fn test_regex_case_insensitive_subsumption() {
        let case_sensitive = create_string_regex(
            "test::sensitive",
            "(password|secret)",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let case_insensitive = create_string_regex(
            "test::insensitive",
            "(PASSWORD|SECRET)",
            true,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_regex_alternative_subsets(&[case_sensitive, case_insensitive], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("REGEX CASE SUBSUMPTION"));
    }

    // ========================================================================
    // Phase 6: Tier Violation Tests
    // ========================================================================

    #[test]
    fn test_tier_violation_detection() {
        let micro = create_symbol_exact(
            "micro-behaviors/fs/file/delete::unlink",
            "unlink",
            vec![FileType::Elf],
            "traits/micro-behaviors/fs/file/delete.yaml",
        );
        let objective = create_symbol_exact(
            "objectives/anti-forensics/cleanup::artifact",
            "unlink",
            vec![FileType::Elf],
            "traits/objectives/anti-forensics/cleanup.yaml",
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[micro, objective], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("TIER VIOLATION"));
        assert!(warnings[0].contains("objectives/ should REFERENCE micro-behaviors/"));
    }

    #[test]
    fn test_no_tier_violation_same_tier() {
        let trait1 = create_symbol_exact(
            "micro-behaviors/fs/file/delete::unlink",
            "unlink",
            vec![FileType::Elf],
            "traits/micro-behaviors/fs/file/delete.yaml",
        );
        let trait2 = create_symbol_exact(
            "micro-behaviors/fs/file/remove::rm",
            "unlink",
            vec![FileType::Elf],
            "traits/micro-behaviors/fs/file/remove.yaml",
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2], &mut warnings);

        assert_eq!(warnings.len(), 1);
        // Should NOT contain TIER VIOLATION (both in micro-behaviors)
        assert!(!warnings[0].contains("TIER VIOLATION"));
    }

    // ========================================================================
    // File Type Overlap Tests
    // ========================================================================

    #[test]
    fn test_filetype_overlap_all_vs_specific() {
        let trait1 = create_string_exact(
            "test::a",
            "test",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let trait2 = create_string_exact(
            "test::b",
            "test",
            false,
            vec![FileType::Elf],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2], &mut warnings);

        // Should detect overlap (All overlaps with everything)
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn test_filetype_no_overlap_disjoint() {
        let trait1 = create_string_exact(
            "test::a",
            "test",
            false,
            vec![FileType::Elf],
            "file1.yaml",
        );
        let trait2 = create_string_exact(
            "test::b",
            "test",
            false,
            vec![FileType::Pe],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2], &mut warnings);

        // No overlap - disjoint file types
        assert_eq!(warnings.len(), 0);
    }

    // ========================================================================
    // Helper Function Tests
    // ========================================================================

    #[test]
    fn test_extract_tier() {
        assert_eq!(extract_tier("micro-behaviors/fs/file/delete::unlink"), Some("micro-behaviors"));
        assert_eq!(extract_tier("objectives/collection/metadata::home-env"), Some("objectives"));
        assert_eq!(extract_tier("well-known/malware/rat::geacon"), Some("well-known"));
        assert_eq!(extract_tier("metadata/format/extension::exe"), Some("metadata"));

        // Invalid formats
        assert_eq!(extract_tier("invalid-id"), None);
        assert_eq!(extract_tier(""), None);
    }
}

#[cfg(test)]
mod composite_tests {
    // Composite validation tests would go here
    // Tests from original validation.rs lines ~4800-5200
}

#[cfg(test)]
mod pattern_tests {
    // Pattern quality tests would go here
    // Tests from original validation.rs lines ~5200-5600
}

#[cfg(test)]
mod taxonomy_tests {
    // Taxonomy validation tests would go here
    // Tests from original validation.rs lines ~5600-5900
}

#[cfg(test)]
mod constraint_tests {
    // Constraint validation tests would go here
    // Tests from original validation.rs lines ~5900-6194
}
