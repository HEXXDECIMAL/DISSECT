//! Mach-O code signature parser for extracting signature types, team IDs, and entitlements
//!
//! Parses the SuperBlob structure from LC_CODE_SIGNATURE load command to extract:
//! - Signature type (adhoc, developer-id, platform, app-store)
//! - Team identifier from CMS certificate
//! - Entitlements from XML plist blob

use anyhow::{anyhow, Result};
use roxmltree::Document;
use std::collections::HashMap;

/// Signature types extracted from code signature
#[derive(Debug, Clone)]
pub enum SignatureType {
    Adhoc,
    DeveloperID,
    AppStore,
    Platform,
    Unknown,
}

impl SignatureType {
    pub fn as_str(&self) -> &str {
        match self {
            SignatureType::Adhoc => "adhoc",
            SignatureType::DeveloperID => "developer-id",
            SignatureType::AppStore => "app-store",
            SignatureType::Platform => "platform",
            SignatureType::Unknown => "unknown",
        }
    }
}

/// Entitlement values (simplified from full plist support)
#[derive(Debug, Clone)]
pub enum EntitlementValue {
    Boolean(bool),
    String(String),
    Array(Vec<String>),
}

/// Parsed code signature information
#[derive(Debug, Clone)]
pub struct CodeSignature {
    pub signature_type: SignatureType,
    pub team_id: Option<String>,
    pub authorities: Vec<String>,
    pub entitlements: HashMap<String, EntitlementValue>,
    pub is_notarized: bool,
    pub has_hardened_runtime: bool,
    pub identifier: Option<String>,
}

// Magic numbers for Mach-O code signature blobs
const SUPERBLOB_MAGIC: u32 = 0xFADE0CC0;
const CODE_DIRECTORY_MAGIC: u32 = 0xFADE0C02;
const ENTITLEMENTS_BLOB_MAGIC: u32 = 0xFADE7171;
#[allow(dead_code)]
const REQUIREMENTS_MAGIC: u32 = 0xFADE0C01;
const CMS_SIGNATURE_MAGIC: u32 = 0xFADE0B01;

/// Parse code signature from binary data
pub fn parse_code_signature(data: &[u8], cs_offset: u32, cs_size: u32) -> Result<CodeSignature> {
    let offset = cs_offset as usize;
    let size = cs_size as usize;

    if offset + size > data.len() {
        return Err(anyhow!("Code signature offset/size out of bounds"));
    }

    let cs_data = &data[offset..offset + size];

    // Parse superblob to get individual blobs
    let blobs = parse_superblob(cs_data)?;

    // Extract entitlements from blob if present
    let entitlements = if let Some(ent_data) = blobs.get(&ENTITLEMENTS_BLOB_MAGIC) {
        parse_entitlements_blob(ent_data).unwrap_or_default()
    } else {
        HashMap::new()
    };

    // Extract team ID and signature type from CMS blob
    let (team_id, signature_type, authorities) =
        if let Some(cms_data) = blobs.get(&CMS_SIGNATURE_MAGIC) {
            extract_certificate_info(cms_data)
        } else {
            (None, SignatureType::Unknown, vec![])
        };

    // Check for hardened runtime flag in code directory
    let has_hardened_runtime = if let Some(cd_data) = blobs.get(&CODE_DIRECTORY_MAGIC) {
        check_hardened_runtime_flag(cd_data)
    } else {
        false
    };

    // Extract identifier from code directory
    let identifier = if let Some(cd_data) = blobs.get(&CODE_DIRECTORY_MAGIC) {
        extract_identifier(cd_data)
    } else {
        None
    };

    // Determine if notarized (would need notarization ticket blob, for now just check for strictness)
    let is_notarized = !entitlements.is_empty() && has_hardened_runtime;

    Ok(CodeSignature {
        signature_type,
        team_id,
        authorities,
        entitlements,
        is_notarized,
        has_hardened_runtime,
        identifier,
    })
}

/// Parse superblob structure and extract individual blobs
fn parse_superblob(data: &[u8]) -> Result<HashMap<u32, Vec<u8>>> {
    if data.len() < 8 {
        return Err(anyhow!("Superblob too small"));
    }

    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic != SUPERBLOB_MAGIC {
        return Err(anyhow!("Invalid superblob magic: 0x{:x}", magic));
    }

    let _total_length = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    if data.len() < (12 + count as usize * 8) {
        return Err(anyhow!("Superblob index out of bounds"));
    }

    let mut blobs = HashMap::new();

    for i in 0..count as usize {
        let idx_offset = 12 + i * 8;
        let _blob_slot = u32::from_be_bytes([
            data[idx_offset],
            data[idx_offset + 1],
            data[idx_offset + 2],
            data[idx_offset + 3],
        ]);
        let blob_offset = u32::from_be_bytes([
            data[idx_offset + 4],
            data[idx_offset + 5],
            data[idx_offset + 6],
            data[idx_offset + 7],
        ]) as usize;

        if blob_offset + 8 > data.len() {
            continue;
        }

        // Read actual blob magic (not the slot index!)
        let blob_magic = u32::from_be_bytes([
            data[blob_offset],
            data[blob_offset + 1],
            data[blob_offset + 2],
            data[blob_offset + 3],
        ]);
        let blob_size = u32::from_be_bytes([
            data[blob_offset + 4],
            data[blob_offset + 5],
            data[blob_offset + 6],
            data[blob_offset + 7],
        ]) as usize;

        if blob_offset + blob_size > data.len() {
            continue;
        }


        // Store blob data (skip 8-byte header)
        let blob_data = &data[blob_offset + 8..blob_offset + blob_size];
        blobs.insert(blob_magic, blob_data.to_vec());
    }

    Ok(blobs)
}

/// Parse entitlements blob (XML plist format)
fn parse_entitlements_blob(data: &[u8]) -> Result<HashMap<String, EntitlementValue>> {
    if data.len() < 8 {
        return Err(anyhow!("Entitlements blob too small"));
    }

    // Skip the 8-byte blob header (magic + size already consumed by caller)
    let plist_data = &data[8..];

    // Parse as XML plist
    let plist_str = std::str::from_utf8(plist_data)?;
    let doc = Document::parse(plist_str)?;
    let mut entitlements = HashMap::new();

    // Navigate plist structure: plist -> dict -> key/value pairs
    if let Some(root) = doc.root().first_element_child() {
        if root.tag_name().name() == "dict" {
            let mut current_key: Option<String> = None;

            for child in root.children() {
                if !child.is_element() {
                    continue;
                }

                let tag_name = child.tag_name().name();
                match tag_name {
                    "key" => {
                        current_key = child.text().map(|s| s.to_string());
                    }
                    "true" => {
                        if let Some(key) = current_key.take() {
                            entitlements.insert(key, EntitlementValue::Boolean(true));
                        }
                    }
                    "false" => {
                        if let Some(key) = current_key.take() {
                            entitlements.insert(key, EntitlementValue::Boolean(false));
                        }
                    }
                    "string" => {
                        if let Some(key) = current_key.take() {
                            if let Some(text) = child.text() {
                                entitlements
                                    .insert(key, EntitlementValue::String(text.to_string()));
                            }
                        }
                    }
                    "array" => {
                        if let Some(key) = current_key.take() {
                            let mut array_values = Vec::new();
                            for array_child in child.children() {
                                if array_child.is_element()
                                    && array_child.tag_name().name() == "string"
                                {
                                    if let Some(text) = array_child.text() {
                                        array_values.push(text.to_string());
                                    }
                                }
                            }
                            entitlements.insert(key, EntitlementValue::Array(array_values));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(entitlements)
}

/// Extract team ID and signature type from CMS blob
fn extract_certificate_info(cms_data: &[u8]) -> (Option<String>, SignatureType, Vec<String>) {
    let mut team_id = None;
    let mut authorities = Vec::new();
    let mut signature_type = SignatureType::Unknown;

    // Look for DER-encoded patterns in certificate
    // This is a simplified approach - full PKCS#7 parsing would be complex

    // Search for OU field (Organizational Unit) which typically contains team ID
    // DER tag for OU is 0x55 0x04 0x0B
    if let Some(team) = extract_der_string(cms_data, &[0x55, 0x04, 0x0B]) {
        team_id = Some(team.trim().to_string());
    }

    // Search for CN (Common Name) for signer information
    // DER tag for CN is 0x55 0x04 0x03
    if let Some(cn) = extract_der_string(cms_data, &[0x55, 0x04, 0x03]) {
        authorities.push(cn.trim().to_string());

        // Determine signature type from CN
        if cn.contains("Developer ID Application") {
            signature_type = SignatureType::DeveloperID;
        } else if cn.contains("Developer ID Installer") {
            signature_type = SignatureType::DeveloperID;
        } else if cn.contains("Mac Developer") || cn.contains("iPhone Developer") {
            signature_type = SignatureType::Platform;
        } else if cn.contains("3rd Party Mac Developer") {
            signature_type = SignatureType::Platform;
        } else if cn.contains("Apple") {
            signature_type = SignatureType::Platform;
        }
    }

    // If no valid signature type found from certificate, assume adhoc
    if matches!(signature_type, SignatureType::Unknown) && team_id.is_none() {
        signature_type = SignatureType::Adhoc;
    }

    (team_id, signature_type, authorities)
}

/// Extract DER-encoded string from certificate data
/// Looks for pattern: tag_bytes [length] [string_data]
fn extract_der_string(data: &[u8], tag: &[u8]) -> Option<String> {
    for i in 0..data.len().saturating_sub(tag.len()) {
        if &data[i..i + tag.len()] == tag {
            // Found tag, next byte should be length
            let len_pos = i + tag.len();
            if len_pos >= data.len() {
                continue;
            }

            let length = data[len_pos] as usize;
            let str_pos = len_pos + 1;

            if str_pos + length > data.len() {
                continue;
            }

            // Try to parse as UTF-8 string
            if let Ok(s) = std::str::from_utf8(&data[str_pos..str_pos + length]) {
                // Verify it looks like a valid string (printable ASCII mostly)
                if s.chars()
                    .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

/// Check for hardened runtime flag in code directory
fn check_hardened_runtime_flag(cd_data: &[u8]) -> bool {
    if cd_data.len() < 36 {
        return false;
    }

    // Code directory flags are at offset 32
    // Hardened runtime flag is 0x00010000
    let flags = u32::from_be_bytes([cd_data[32], cd_data[33], cd_data[34], cd_data[35]]);
    (flags & 0x00010000) != 0
}

/// Extract identifier string from code directory
fn extract_identifier(cd_data: &[u8]) -> Option<String> {
    if cd_data.len() < 16 {
        return None;
    }

    // Code directory structure (8-byte blob header already skipped by caller):
    // offset 0: version (4 bytes)
    // offset 4: flags (4 bytes)
    // offset 8: hash_offset (4 bytes)
    // offset 12: ident_offset (4 bytes)
    let ident_offset = u32::from_be_bytes([cd_data[12], cd_data[13], cd_data[14], cd_data[15]]);
    let ident_offset = ident_offset as usize;

    if ident_offset >= cd_data.len() {
        return None;
    }

    // Find null-terminated string starting from ident_offset
    let ident_data = &cd_data[ident_offset..];

    // Search backwards from ident_offset to find the start of the identifier
    // (usually preceded by null byte or hash data)
    let mut start_offset = ident_offset;
    if ident_offset > 0 {
        // Search backwards for a null byte or start of printable ASCII
        for i in (0..ident_offset).rev() {
            if cd_data[i] == 0 {
                start_offset = i + 1;
                break;
            }
            // Also break if we find something that's definitely not part of identifier
            if !cd_data[i].is_ascii_graphic() && cd_data[i] != b'.' {
                start_offset = i + 1;
                break;
            }
        }
    }

    // Find null terminator from ident_offset
    if let Some(null_pos) = ident_data.iter().position(|&b| b == 0) {
        let end_offset = ident_offset + null_pos;
        if let Ok(ident_str) = std::str::from_utf8(&cd_data[start_offset..end_offset]) {
            if !ident_str.is_empty() {
                return Some(ident_str.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_type_str() {
        assert_eq!(SignatureType::Adhoc.as_str(), "adhoc");
        assert_eq!(SignatureType::DeveloperID.as_str(), "developer-id");
        assert_eq!(SignatureType::Platform.as_str(), "platform");
    }
}
