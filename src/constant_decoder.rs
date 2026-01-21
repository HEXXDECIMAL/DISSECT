use crate::types::DecodedValue;
use std::net::Ipv4Addr;

/// Decode embedded constants into possible interpretations
pub struct ConstantDecoder;

impl ConstantDecoder {
    /// Decode a 64-bit constant into possible values
    pub fn decode_qword(value: u64) -> Vec<DecodedValue> {
        let mut decoded = Vec::new();

        // Try IPv4 address (both big and little endian)
        decoded.extend(Self::try_ipv4_from_qword(value));

        // Try port number
        decoded.extend(Self::try_port_from_qword(value));

        // Try timestamp
        decoded.extend(Self::try_timestamp(value));

        decoded
    }

    /// Decode a 32-bit constant
    pub fn decode_dword(value: u32) -> Vec<DecodedValue> {
        let mut decoded = Vec::new();

        // Try IPv4 address
        decoded.extend(Self::try_ipv4(value));

        // Try port
        if value <= 65535 {
            decoded.push(DecodedValue {
                value_type: "port".to_string(),
                decoded_value: value.to_string(),
                confidence: 0.6,
            });
        }

        // Try timestamp
        decoded.extend(Self::try_timestamp(value as u64));

        decoded
    }

    /// Try to interpret as IPv4 address from qword (could be embedded with port)
    fn try_ipv4_from_qword(value: u64) -> Vec<DecodedValue> {
        let mut results = Vec::new();

        // Try lower 32 bits as IPv4
        let lower_32 = (value & 0xFFFFFFFF) as u32;
        results.extend(Self::try_ipv4(lower_32));

        // Try upper 32 bits as IPv4
        let upper_32 = (value >> 32) as u32;
        results.extend(Self::try_ipv4(upper_32));

        // Check if it could be IPv4:port (various encodings)
        // Format: 0x00000000_PPPP_IIII (port in upper word, IP in lower dword)
        if value >> 48 == 0 {
            let port = ((value >> 32) & 0xFFFF) as u16;
            let ip = (value & 0xFFFFFFFF) as u32;

            let ipv4 = Ipv4Addr::from(ip.to_be_bytes());
            if Self::is_interesting_ip(&ipv4) && port > 0 {
                results.push(DecodedValue {
                    value_type: "ip_port".to_string(),
                    decoded_value: format!("{}:{}", ipv4, port),
                    confidence: 0.8,
                });
            }
        }

        results
    }

    /// Try to interpret as IPv4 address
    fn try_ipv4(value: u32) -> Vec<DecodedValue> {
        let mut results = Vec::new();

        // Big endian
        let ipv4_be = Ipv4Addr::from(value.to_be_bytes());
        if Self::is_interesting_ip(&ipv4_be) {
            results.push(DecodedValue {
                value_type: "ip_address".to_string(),
                decoded_value: ipv4_be.to_string(),
                confidence: 0.7,
            });
        }

        // Little endian
        let ipv4_le = Ipv4Addr::from(value.to_le_bytes());
        if Self::is_interesting_ip(&ipv4_le) && ipv4_le != ipv4_be {
            results.push(DecodedValue {
                value_type: "ip_address".to_string(),
                decoded_value: ipv4_le.to_string(),
                confidence: 0.7,
            });
        }

        results
    }

    /// Check if IP address is interesting (not obviously invalid)
    fn is_interesting_ip(ip: &Ipv4Addr) -> bool {
        let octets = ip.octets();

        // Reject all zeros
        if octets.iter().all(|&x| x == 0) {
            return false;
        }

        // Reject all 0xFF
        if octets.iter().all(|&x| x == 0xFF) {
            return false;
        }

        // Accept if at least one octet is in typical range
        true
    }

    /// Try to interpret as port number (qword)
    fn try_port_from_qword(value: u64) -> Vec<DecodedValue> {
        let mut results = Vec::new();

        // Lower 16 bits
        let lower_16 = (value & 0xFFFF) as u16;
        if Self::is_interesting_port(lower_16) {
            results.push(DecodedValue {
                value_type: "port".to_string(),
                decoded_value: lower_16.to_string(),
                confidence: 0.5,
            });
        }

        // Next 16 bits
        let next_16 = ((value >> 16) & 0xFFFF) as u16;
        if Self::is_interesting_port(next_16) && next_16 != lower_16 {
            results.push(DecodedValue {
                value_type: "port".to_string(),
                decoded_value: next_16.to_string(),
                confidence: 0.5,
            });
        }

        results
    }

    /// Check if port number is interesting
    fn is_interesting_port(port: u16) -> bool {
        // Common port ranges
        matches!(port,
            20..=23 |    // FTP, SSH, Telnet
            25 |         // SMTP
            53 |         // DNS
            80 | 443 |   // HTTP/HTTPS
            110 | 143 |  // POP3/IMAP
            194 |        // IRC
            445 |        // SMB
            1024..=65535 // User ports
        )
    }

    /// Try to interpret as Unix timestamp
    fn try_timestamp(value: u64) -> Vec<DecodedValue> {
        let mut results = Vec::new();

        // Unix timestamp range: roughly 2000-2040
        let year_2000 = 946684800_u64;
        let year_2040 = 2208988800_u64;

        if (year_2000..year_2040).contains(&value) {
            if let Some(datetime) = chrono::DateTime::from_timestamp(value as i64, 0) {
                results.push(DecodedValue {
                    value_type: "timestamp".to_string(),
                    decoded_value: datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                    confidence: 0.6,
                });
            }
        }

        results
    }

    /// Decode a string that might be an encoded IP/URL
    pub fn decode_string(s: &str) -> Vec<DecodedValue> {
        let mut results = Vec::new();

        // Check for hex-encoded IP
        if s.len() == 8 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(bytes) = hex::decode(s) {
                if bytes.len() == 4 {
                    let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                    results.push(DecodedValue {
                        value_type: "ip_address".to_string(),
                        decoded_value: ip.to_string(),
                        confidence: 0.8,
                    });
                }
            }
        }

        // Check for base64-encoded data
        if s.len() >= 8
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        {
            if let Ok(decoded) = BASE64.decode(s) {
                if let Ok(utf8) = String::from_utf8(decoded.clone()) {
                    if utf8
                        .chars()
                        .all(|c| c.is_ascii_graphic() || c.is_whitespace())
                    {
                        results.push(DecodedValue {
                            value_type: "base64_decoded".to_string(),
                            decoded_value: utf8,
                            confidence: 0.7,
                        });
                    }
                }
            }
        }

        results
    }

    /// Extract constants from disassembly line
    pub fn extract_from_instruction(instruction: &str) -> Vec<(u64, String)> {
        let mut constants = Vec::new();

        // Match hex constants in various formats
        // 0x1234, 0x12345678, etc.
        let hex_pattern = regex::Regex::new(r"0x([0-9a-fA-F]+)").unwrap();

        for cap in hex_pattern.captures_iter(instruction) {
            if let Some(hex_str) = cap.get(1) {
                if let Ok(value) = u64::from_str_radix(hex_str.as_str(), 16) {
                    // Only capture interesting constants (not tiny values like offsets)
                    if value > 0xFFFF || Self::is_interesting_port(value as u16) {
                        let const_type = match hex_str.as_str().len() {
                            1..=2 => "byte",
                            3..=4 => "word",
                            5..=8 => "dword",
                            _ => "qword",
                        };
                        constants.push((value, const_type.to_string()));
                    }
                }
            }
        }

        constants
    }
}

// Use external crates for encoding/decoding
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_dword_ip_address() {
        // 192.168.1.1 in network byte order
        let value = 0xC0A80101_u32;
        let decoded = ConstantDecoder::decode_dword(value);

        assert!(decoded.iter().any(|d| d.value_type == "ip_address"));
    }

    #[test]
    fn test_decode_dword_port() {
        // Common HTTP port
        let value = 80_u32;
        let decoded = ConstantDecoder::decode_dword(value);

        assert!(decoded
            .iter()
            .any(|d| d.value_type == "port" && d.decoded_value == "80"));
    }

    #[test]
    fn test_decode_dword_port_too_large() {
        // Value exceeds max port number
        let value = 70000_u32;
        let decoded = ConstantDecoder::decode_dword(value);

        // Should not decode as port
        let has_port = decoded.iter().any(|d| d.value_type == "port");
        assert!(!has_port);
    }

    #[test]
    fn test_decode_qword_ip_address() {
        // IPv4 in lower 32 bits
        let value = 0x00000000C0A80101_u64; // 192.168.1.1
        let decoded = ConstantDecoder::decode_qword(value);

        assert!(decoded.iter().any(|d| d.value_type == "ip_address"));
    }

    #[test]
    fn test_decode_qword_port() {
        // Common HTTPS port
        let value = 443_u64;
        let decoded = ConstantDecoder::decode_qword(value);

        assert!(decoded
            .iter()
            .any(|d| d.value_type == "port" && d.decoded_value == "443"));
    }

    #[test]
    fn test_decode_qword_timestamp() {
        // Unix timestamp for 2020-01-01 00:00:00 UTC
        let value = 1577836800_u64;
        let decoded = ConstantDecoder::decode_qword(value);

        assert!(decoded.iter().any(|d| d.value_type == "timestamp"));

        let timestamp_entry = decoded
            .iter()
            .find(|d| d.value_type == "timestamp")
            .unwrap();
        assert!(timestamp_entry.decoded_value.contains("2020-01-01"));
    }

    #[test]
    fn test_is_interesting_ip_valid() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        assert!(ConstantDecoder::is_interesting_ip(&ip));

        let ip = Ipv4Addr::new(8, 8, 8, 8);
        assert!(ConstantDecoder::is_interesting_ip(&ip));
    }

    #[test]
    fn test_is_interesting_ip_invalid_all_zeros() {
        let ip = Ipv4Addr::new(0, 0, 0, 0);
        assert!(!ConstantDecoder::is_interesting_ip(&ip));
    }

    #[test]
    fn test_is_interesting_ip_invalid_all_ff() {
        let ip = Ipv4Addr::new(255, 255, 255, 255);
        assert!(!ConstantDecoder::is_interesting_ip(&ip));
    }

    #[test]
    fn test_is_interesting_port_common_ports() {
        assert!(ConstantDecoder::is_interesting_port(22)); // SSH
        assert!(ConstantDecoder::is_interesting_port(80)); // HTTP
        assert!(ConstantDecoder::is_interesting_port(443)); // HTTPS
        assert!(ConstantDecoder::is_interesting_port(3306)); // MySQL
        assert!(ConstantDecoder::is_interesting_port(8080)); // Alt HTTP
    }

    #[test]
    fn test_is_interesting_port_invalid() {
        assert!(!ConstantDecoder::is_interesting_port(0));
        assert!(!ConstantDecoder::is_interesting_port(1));
        assert!(!ConstantDecoder::is_interesting_port(10));
    }

    #[test]
    fn test_decode_string_hex_ip() {
        // "c0a80101" = 192.168.1.1 in hex
        let result = ConstantDecoder::decode_string("c0a80101");

        assert!(result
            .iter()
            .any(|d| d.value_type == "ip_address" && d.decoded_value == "192.168.1.1"));
    }

    #[test]
    fn test_decode_string_base64() {
        // "SGVsbG8gV29ybGQ=" = "Hello World" in base64
        let result = ConstantDecoder::decode_string("SGVsbG8gV29ybGQ=");

        assert!(result
            .iter()
            .any(|d| d.value_type == "base64_decoded" && d.decoded_value == "Hello World"));
    }

    #[test]
    fn test_decode_string_invalid_hex() {
        // Invalid hex (contains 'z')
        let result = ConstantDecoder::decode_string("c0a8010z");

        assert!(result.is_empty());
    }

    #[test]
    fn test_decode_string_wrong_length() {
        // Wrong length for hex IP (should be 8 chars)
        let result = ConstantDecoder::decode_string("c0a801");

        // Should not decode as IP
        assert!(!result.iter().any(|d| d.value_type == "ip_address"));
    }

    #[test]
    fn test_extract_from_instruction() {
        let instruction = "mov eax, 0x12345678";
        let constants = ConstantDecoder::extract_from_instruction(instruction);

        assert_eq!(constants.len(), 1);
        assert_eq!(constants[0].0, 0x12345678);
        assert_eq!(constants[0].1, "dword");
    }

    #[test]
    fn test_extract_from_instruction_multiple() {
        let instruction = "add rax, 0x1000; mov rbx, 0xdeadbeef";
        let constants = ConstantDecoder::extract_from_instruction(instruction);

        assert!(constants.len() >= 1);
        assert!(constants.iter().any(|(v, _)| *v == 0xdeadbeef));
    }

    #[test]
    fn test_extract_from_instruction_small_values_filtered() {
        // Small values (< 0xFFFF) should be filtered unless they're interesting ports
        let instruction = "mov eax, 0x10";
        let constants = ConstantDecoder::extract_from_instruction(instruction);

        // 0x10 (16) is not an interesting port, should be filtered
        assert!(constants.is_empty());
    }

    #[test]
    fn test_extract_from_instruction_port() {
        // Port 80 should be kept even though it's small
        let instruction = "mov dx, 0x50"; // 0x50 = 80
        let constants = ConstantDecoder::extract_from_instruction(instruction);

        assert!(constants.iter().any(|(v, _)| *v == 0x50));
    }

    #[test]
    fn test_decode_qword_ip_port_combo() {
        // Test IP:port encoding (port in upper word, IP in lower dword)
        // Format: 0x0000PPPP_IIII_IIII
        // Port 443 (0x01BB) and IP 127.0.0.1 (0x7F000001)
        let value = 0x000001BB7F000001_u64;
        let decoded = ConstantDecoder::decode_qword(value);

        // Should decode the IP:port combination
        assert!(decoded.iter().any(|d| d.value_type == "ip_port"));
    }

    #[test]
    fn test_timestamp_range_validation() {
        // Valid timestamp (2020)
        let value = 1577836800_u64;
        let decoded = ConstantDecoder::decode_qword(value);
        assert!(decoded.iter().any(|d| d.value_type == "timestamp"));

        // Too old (before 2000)
        let value = 900000000_u64;
        let decoded = ConstantDecoder::decode_qword(value);
        assert!(!decoded.iter().any(|d| d.value_type == "timestamp"));

        // Too new (after 2040)
        let value = 3000000000_u64;
        let decoded = ConstantDecoder::decode_qword(value);
        assert!(!decoded.iter().any(|d| d.value_type == "timestamp"));
    }
}
