//! Risk assessment for differential analysis.
//!
//! Categorizes capability changes by risk level (high, medium, low) to prioritize
//! review of suspicious changes.

/// Check if a capability ID indicates high risk
pub(super) fn is_high_risk_id(id: &str) -> bool {
    id.starts_with("exec/")
        || id.starts_with("anti-analysis/")
        || id.starts_with("privesc/")
        || id.starts_with("privilege/")
        || id.starts_with("persistence/")
        || id.starts_with("injection/")
        || id.starts_with("c2/")
        || id.starts_with("exfil/")
        || id.starts_with("data/secret")
}

/// Check if a capability ID indicates medium risk
pub(super) fn is_medium_risk_id(id: &str) -> bool {
    id.starts_with("net/")
        || id.starts_with("credential/")
        || id.starts_with("registry/")
        || id.starts_with("service/")
        || id.starts_with("evasion/")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== High Risk Tests ====================

    #[test]
    fn test_high_risk_exec() {
        assert!(is_high_risk_id("exec/shell"));
        assert!(is_high_risk_id("exec/process/spawn"));
    }

    #[test]
    fn test_high_risk_anti_analysis() {
        assert!(is_high_risk_id("anti-analysis/vm/detect"));
        assert!(is_high_risk_id("anti-analysis/debug/check"));
    }

    #[test]
    fn test_high_risk_privesc() {
        assert!(is_high_risk_id("privesc/local"));
        assert!(is_high_risk_id("privilege/escalation"));
    }

    #[test]
    fn test_high_risk_persistence() {
        assert!(is_high_risk_id("persistence/registry"));
        assert!(is_high_risk_id("persistence/cron"));
    }

    #[test]
    fn test_high_risk_injection() {
        assert!(is_high_risk_id("injection/process"));
        assert!(is_high_risk_id("injection/dll"));
    }

    #[test]
    fn test_high_risk_c2() {
        assert!(is_high_risk_id("c2/beacon"));
        assert!(is_high_risk_id("c2/channel"));
    }

    #[test]
    fn test_high_risk_exfil() {
        assert!(is_high_risk_id("exfil/data"));
        assert!(is_high_risk_id("exfil/network"));
    }

    #[test]
    fn test_high_risk_data_secret() {
        assert!(is_high_risk_id("data/secret/api-key"));
        assert!(is_high_risk_id("data/secrets"));
    }

    // ==================== Medium Risk Tests ====================

    #[test]
    fn test_medium_risk_net() {
        assert!(is_medium_risk_id("net/socket"));
        assert!(is_medium_risk_id("net/http/client"));
    }

    #[test]
    fn test_medium_risk_credential() {
        assert!(is_medium_risk_id("credential/access"));
        assert!(is_medium_risk_id("credential/dump"));
    }

    #[test]
    fn test_medium_risk_registry() {
        assert!(is_medium_risk_id("registry/read"));
        assert!(is_medium_risk_id("registry/write"));
    }

    #[test]
    fn test_medium_risk_service() {
        assert!(is_medium_risk_id("service/install"));
        assert!(is_medium_risk_id("service/control"));
    }

    #[test]
    fn test_medium_risk_evasion() {
        assert!(is_medium_risk_id("evasion/obfuscation"));
        assert!(is_medium_risk_id("evasion/packing"));
    }

    // ==================== Low Risk (neither high nor medium) Tests ====================

    #[test]
    fn test_low_risk_file() {
        assert!(!is_high_risk_id("file/read"));
        assert!(!is_medium_risk_id("file/read"));
    }

    #[test]
    fn test_low_risk_logging() {
        assert!(!is_high_risk_id("logging/output"));
        assert!(!is_medium_risk_id("logging/output"));
    }

    #[test]
    fn test_low_risk_data_non_secret() {
        // "data/config" is low risk, "data/secret" is high risk
        assert!(!is_high_risk_id("data/config"));
        assert!(!is_medium_risk_id("data/config"));
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_empty_string() {
        assert!(!is_high_risk_id(""));
        assert!(!is_medium_risk_id(""));
    }

    #[test]
    fn test_partial_match_not_prefix() {
        // Should not match "execution" because it doesn't start with "exec/"
        assert!(!is_high_risk_id("execution/shell"));
        // Should not match "network" because it doesn't start with "net/"
        assert!(!is_medium_risk_id("network/socket"));
    }

    #[test]
    fn test_case_sensitive() {
        // These should not match due to case sensitivity
        assert!(!is_high_risk_id("EXEC/shell"));
        assert!(!is_medium_risk_id("NET/socket"));
    }
}
