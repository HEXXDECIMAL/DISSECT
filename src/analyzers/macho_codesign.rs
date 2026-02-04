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
/// Note: blob header (magic + size) has already been skipped by caller
fn parse_entitlements_blob(data: &[u8]) -> Result<HashMap<String, EntitlementValue>> {
    if data.is_empty() {
        return Err(anyhow!("Entitlements blob empty"));
    }

    // Data has already had the 8-byte blob header (magic + size) removed by caller
    let plist_data = data;

    // Parse as XML plist
    let plist_str = match std::str::from_utf8(plist_data) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("Failed to convert plist to UTF-8: {}", e);
            return Err(anyhow!("Failed to convert plist to UTF-8: {}", e));
        }
    };

    // roxmltree doesn't support DTDs, so strip the DOCTYPE declaration
    let plist_str_no_dtd = if let Some(plist_start) = plist_str.find("<plist") {
        plist_str[plist_start..].to_string()
    } else {
        plist_str.to_string()
    };

    tracing::debug!(
        "parse_entitlements_blob: stripped plist_str length {}",
        plist_str_no_dtd.len()
    );
    let doc = match Document::parse(&plist_str_no_dtd) {
        Ok(d) => d,
        Err(e) => {
            tracing::debug!("Failed to parse XML: {}", e);
            return Err(anyhow!("Failed to parse plist XML: {}", e));
        }
    };
    let mut entitlements = HashMap::new();

    tracing::debug!("parse_entitlements_blob: XML parsed successfully");

    // Navigate plist structure: plist -> dict -> key/value pairs
    // First check the root
    let root_elem = doc.root();
    tracing::debug!("Root element tag: {}", root_elem.tag_name().name());

    if let Some(first_elem) = root_elem.first_element_child() {
        tracing::debug!("Found first element: {}", first_elem.tag_name().name());

        // If it's a plist element, get its dict child; otherwise use it directly
        let dict_elem = if first_elem.tag_name().name() == "plist" {
            first_elem.first_element_child()
        } else {
            Some(first_elem)
        };

        if let Some(root) = dict_elem {
            tracing::debug!("Processing dict element: {}", root.tag_name().name());
            if root.tag_name().name() == "dict" {
                tracing::debug!("Root is dict, parsing entitlements");
            let mut current_key: Option<String> = None;
            let mut key_count = 0;

            for child in root.children() {
                if !child.is_element() {
                    continue;
                }

                let tag_name = child.tag_name().name();
                tracing::debug!("Processing element: {}", tag_name);

                match tag_name {
                    "key" => {
                        current_key = child.text().map(|s| s.to_string());
                        tracing::debug!("Found key: {:?}", current_key);
                    }
                    "true" => {
                        if let Some(key) = current_key.take() {
                            tracing::debug!("Adding boolean entitlement: {} = true", key);
                            entitlements.insert(key, EntitlementValue::Boolean(true));
                            key_count += 1;
                        }
                    }
                    "false" => {
                        if let Some(key) = current_key.take() {
                            tracing::debug!("Adding boolean entitlement: {} = false", key);
                            entitlements.insert(key, EntitlementValue::Boolean(false));
                            key_count += 1;
                        }
                    }
                    "string" => {
                        if let Some(key) = current_key.take() {
                            if let Some(text) = child.text() {
                                tracing::debug!("Adding string entitlement: {} = {}", key, text);
                                entitlements
                                    .insert(key, EntitlementValue::String(text.to_string()));
                                key_count += 1;
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
                            tracing::debug!("Adding array entitlement: {} with {} values", key, array_values.len());
                            entitlements.insert(key, EntitlementValue::Array(array_values));
                            key_count += 1;
                        }
                    }
                    _ => {
                        tracing::debug!("Skipping unexpected element: {}", tag_name);
                    }
                }
            }
                tracing::debug!("Parsed dict with {} entitlements", key_count);
            } else {
                tracing::debug!("First element is not dict: {}", root.tag_name().name());
            }
        } else {
            tracing::debug!("No dict element found in plist");
        }
    } else {
        tracing::debug!("No root element found");
    }

    tracing::debug!("parse_entitlements_blob: extracted {} entitlements", entitlements.len());
    Ok(entitlements)
}

/// Extract team ID and signature type from CMS blob
fn extract_certificate_info(cms_data: &[u8]) -> (Option<String>, SignatureType, Vec<String>) {
    let mut team_id = None;
    let mut authorities = Vec::new();
    let mut signature_type = SignatureType::Unknown;


    // Look for DER-encoded patterns in certificate
    // This is a simplified approach - full PKCS#7 parsing would be complex

    // Find all CN and OU values, then pick the one that looks like the leaf cert
    let mut all_cns = Vec::new();
    let mut all_ous = Vec::new();

    // Extract all OU fields
    for i in 0..cms_data.len().saturating_sub(5) {
        if &cms_data[i..i + 3] == &[0x55, 0x04, 0x0B] {
            if let Some(ou) = extract_der_string(&cms_data[i..], &[0x55, 0x04, 0x0B]) {
                all_ous.push(ou);
            }
        }
    }

    // Extract all CN fields
    for i in 0..cms_data.len().saturating_sub(5) {
        if &cms_data[i..i + 3] == &[0x55, 0x04, 0x03] {
            if let Some(cn) = extract_der_string(&cms_data[i..], &[0x55, 0x04, 0x03]) {
                all_cns.push(cn);
            }
        }
    }


    // Pick the CN that has "Developer ID" or "Mac Developer" (leaf cert, not intermediate)
    for cn in &all_cns {
        if cn.contains("Developer ID Application: ")
            || cn.contains("Developer ID Installer: ")
            || cn.contains("Mac Developer: ")
            || cn.contains("iPhone Developer: ")
            || cn.contains("3rd Party Mac Developer: ")
        {
            let cn_trimmed = cn.trim().to_string();
            authorities.push(cn_trimmed.clone());

            // Determine signature type from CN
            if cn.contains("Developer ID Application") {
                signature_type = SignatureType::DeveloperID;
            } else if cn.contains("Developer ID Installer") {
                signature_type = SignatureType::DeveloperID;
            } else if cn.contains("Mac Developer") || cn.contains("iPhone Developer") {
                signature_type = SignatureType::Platform;
            } else if cn.contains("3rd Party Mac Developer") {
                signature_type = SignatureType::Platform;
            }
            break;
        }
    }

    // Pick the OU that looks like a team ID (alphanumeric, 10-11 chars)
    for ou in &all_ous {
        let ou_trimmed = ou.trim();
        // Team IDs are typically 10 alphanumeric characters
        if ou_trimmed.len() >= 8
            && ou_trimmed.len() <= 12
            && ou_trimmed.chars().all(|c| c.is_ascii_alphanumeric())
        {
            team_id = Some(ou_trimmed.to_string());
            break;
        }
    }

    // If no developer/platform cert found, check if we have Apple Root CA or other CAs
    if matches!(signature_type, SignatureType::Unknown) {
        // Check if any CN has "Apple" in it
        for cn in &all_cns {
            if cn.contains("Apple") && (cn.contains("Root") || cn.contains("Code")) {
                signature_type = SignatureType::Platform;
                if authorities.is_empty() {
                    authorities.push(cn.trim().to_string());
                }
                break;
            }
        }
    }

    // If still no signature type and no team ID, assume adhoc
    if matches!(signature_type, SignatureType::Unknown) && team_id.is_none() {
        signature_type = SignatureType::Adhoc;
    }

    (team_id, signature_type, authorities)
}

/// Extract DER-encoded string from certificate data
/// After OID tag, there's a string type byte (0x0C UTF8String, 0x13 PrintableString, etc),
/// then length, then data
fn extract_der_string(data: &[u8], tag: &[u8]) -> Option<String> {
    for i in 0..data.len().saturating_sub(tag.len() + 2) {
        if &data[i..i + tag.len()] == tag {
            // Found OID tag, next byte should be string type (0x0C, 0x13, 0x16, etc)
            let type_pos = i + tag.len();
            if type_pos >= data.len() {
                continue;
            }

            let string_type = data[type_pos];
            // Valid ASN.1 string types
            if ![0x0C, 0x13, 0x16, 0x1A, 0x1B, 0x1C].contains(&string_type) {
                continue;
            }

            let len_pos = type_pos + 1;
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
