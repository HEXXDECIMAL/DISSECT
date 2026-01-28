//! Risk assessment for differential analysis.
//!
//! Categorizes capability changes by risk level (high, medium, low) to prioritize
//! review of suspicious changes.

use crate::types::Finding;

/// Check if a capability is high risk based on its ID
#[allow(dead_code)]
pub(super) fn is_high_risk(capability: &Finding) -> bool {
    is_high_risk_id(&capability.id)
}

/// Check if a capability ID indicates high risk
#[allow(dead_code)]
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

/// Check if a capability is medium risk based on its ID
#[allow(dead_code)]
pub(super) fn is_medium_risk(capability: &Finding) -> bool {
    is_medium_risk_id(&capability.id)
}

/// Check if a capability ID indicates medium risk
#[allow(dead_code)]
pub(super) fn is_medium_risk_id(id: &str) -> bool {
    id.starts_with("net/")
        || id.starts_with("credential/")
        || id.starts_with("registry/")
        || id.starts_with("service/")
        || id.starts_with("evasion/")
}
