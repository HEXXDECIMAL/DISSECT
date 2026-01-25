//! TraitDefinition evaluation logic
//!
//! Handles evaluation of atomic trait definitions.

use super::evaluators::eval_condition;
use super::types::{EvaluationContext, FileType, Platform, TraitDefinition};
use crate::types::{Finding, FindingKind};

impl TraitDefinition {
    /// Evaluate this trait definition against the analysis context
    pub fn evaluate(&self, ctx: &EvaluationContext) -> Option<Finding> {
        if !self.matches_target(ctx) {
            return None;
        }

        let result = eval_condition(&self.condition, ctx);

        if result.matched {
            Some(Finding {
                id: self.id.clone(),
                kind: FindingKind::Capability,
                desc: self.description.clone(),
                conf: self.conf,
                crit: self.criticality,
                mbc: self.mbc.clone(),
                attack: self.attack.clone(),
                trait_refs: vec![],
                evidence: result.evidence,
            })
        } else {
            None
        }
    }

    fn matches_target(&self, ctx: &EvaluationContext) -> bool {
        let platform_match = self.platforms.contains(&Platform::All)
            || ctx.platform == Platform::All
            || self.platforms.contains(&ctx.platform);

        let file_type_match = self.file_types.contains(&FileType::All)
            || ctx.file_type == FileType::All
            || self.file_types.contains(&ctx.file_type);

        platform_match && file_type_match
    }
}
