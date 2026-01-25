//! CompositeTrait evaluation logic
//!
//! Handles evaluation of composite rules with boolean operators and proximity constraints.

use super::evaluators::eval_condition;
use super::types::{
    CompositeTrait, Condition, ConditionResult, EvaluationContext, FileType, Platform, ScopeLevel,
};
use crate::types::{Evidence, Finding, FindingKind, SourceSpan};

impl CompositeTrait {
    /// Evaluate this rule against the analysis context
    pub fn evaluate(&self, ctx: &EvaluationContext) -> Option<Finding> {
        if !self.matches_target(ctx) {
            return None;
        }

        let result = if let Some(ref conditions) = self.requires_all {
            self.eval_requires_all(conditions, ctx)
        } else if let Some(ref conditions) = self.requires_any {
            self.eval_requires_any(conditions, ctx)
        } else if let Some(count) = self.requires_count {
            if let Some(ref conditions) = self.conditions {
                self.eval_requires_count(conditions, count, ctx)
            } else {
                return None;
            }
        } else if let Some(ref conditions) = self.requires_none {
            self.eval_requires_none(conditions, ctx)
        } else {
            return None;
        };

        if !result.matched {
            return None;
        }

        if !self.check_proximity_constraints(&result.evidence, ctx) {
            return None;
        }

        Some(Finding {
            id: self.id.clone(),
            kind: FindingKind::Capability,
            desc: self.description.clone(),
            conf: self.conf,
            crit: self.criticality,
            mbc: self.mbc.clone(),
            attack: self.attack.clone(),
            trait_refs: result.traits,
            evidence: result.evidence,
        })
    }

    fn check_proximity_constraints(&self, evidence: &[Evidence], ctx: &EvaluationContext) -> bool {
        let spans: Vec<&SourceSpan> = evidence.iter().filter_map(|e| e.span.as_ref()).collect();

        if spans.is_empty() {
            return true;
        }

        if let Some(max_lines) = self.near_lines {
            if !self.check_line_proximity(&spans, max_lines) {
                return false;
            }
        }

        if let Some(max_bytes) = self.near {
            if !self.check_byte_proximity(&spans, max_bytes) {
                return false;
            }
        }

        if let Some(ref container_trait_id) = self.within {
            if !self.check_within_constraint(&spans, container_trait_id, ctx) {
                return false;
            }
        }

        if self.scope != ScopeLevel::None {
            let scope_lines = match self.scope {
                ScopeLevel::Block => 20,
                ScopeLevel::Method => 50,
                ScopeLevel::Class => 500,
                ScopeLevel::None => return true,
            };
            if !self.check_line_proximity(&spans, scope_lines) {
                return false;
            }
        }

        true
    }

    fn check_line_proximity(&self, spans: &[&SourceSpan], max_lines: u32) -> bool {
        if spans.len() < 2 {
            return true;
        }

        let min_line = spans.iter().map(|s| s.start_line).min().unwrap_or(0);
        let max_line = spans.iter().map(|s| s.end_line).max().unwrap_or(0);

        max_line.saturating_sub(min_line) <= max_lines
    }

    fn check_byte_proximity(&self, spans: &[&SourceSpan], max_bytes: u32) -> bool {
        if spans.len() < 2 {
            return true;
        }

        let min_byte = spans.iter().map(|s| s.start_byte).min().unwrap_or(0);
        let max_byte = spans.iter().map(|s| s.end_byte).max().unwrap_or(0);

        max_byte.saturating_sub(min_byte) <= max_bytes
    }

    fn check_within_constraint(
        &self,
        spans: &[&SourceSpan],
        container_trait_id: &str,
        ctx: &EvaluationContext,
    ) -> bool {
        let container_spans: Vec<&SourceSpan> = ctx
            .report
            .findings
            .iter()
            .filter(|f| {
                f.id == container_trait_id || f.id.ends_with(&format!("/{}", container_trait_id))
            })
            .flat_map(|f| f.evidence.iter())
            .filter_map(|e| e.span.as_ref())
            .collect();

        if container_spans.is_empty() {
            return false;
        }

        for span in spans {
            let contained = container_spans
                .iter()
                .any(|container| container.contains(span));
            if !contained {
                return false;
            }
        }

        true
    }

    fn matches_target(&self, ctx: &EvaluationContext) -> bool {
        let platform_match = self.platforms.contains(&Platform::All)
            || ctx.platform == Platform::All
            || self.platforms.contains(&ctx.platform);

        let file_type_match = self.file_types.contains(&FileType::All)
            || ctx.file_type == FileType::All
            || self.file_types.contains(&ctx.file_type);

        if !platform_match || !file_type_match {
            return false;
        }

        // Check file size constraints
        let size = ctx.report.target.size_bytes;
        if let Some(min) = self.min_size {
            if size < min {
                return false;
            }
        }
        if let Some(max) = self.max_size {
            if size > max {
                return false;
            }
        }

        true
    }

    fn eval_requires_all(
        &self,
        any: &[Condition],
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        let mut all_evidence = Vec::new();
        let mut all_traits = Vec::new();

        for condition in conditions {
            let result = eval_condition(condition, ctx);
            if !result.matched {
                return ConditionResult::no_match();
            }
            all_evidence.extend(result.evidence);
            all_traits.extend(result.traits);
        }

        ConditionResult::matched_with_traits(all_evidence, all_traits)
    }

    fn eval_requires_any(
        &self,
        any: &[Condition],
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        for condition in conditions {
            let result = eval_condition(condition, ctx);
            if result.matched {
                return result;
            }
        }

        ConditionResult::no_match()
    }

    fn eval_requires_count(
        &self,
        any: &[Condition],
        count: usize,
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        let mut matched_count = 0;
        let mut all_evidence = Vec::new();
        let mut all_traits = Vec::new();

        for condition in conditions {
            let result = eval_condition(condition, ctx);
            if result.matched {
                matched_count += 1;
                all_evidence.extend(result.evidence);
                all_traits.extend(result.traits);
            }
        }

        if matched_count >= count {
            ConditionResult::matched_with_traits(all_evidence, all_traits)
        } else {
            ConditionResult::no_match()
        }
    }

    fn eval_requires_none(
        &self,
        any: &[Condition],
        ctx: &EvaluationContext,
    ) -> ConditionResult {
        for condition in conditions {
            let result = eval_condition(condition, ctx);
            if result.matched {
                return ConditionResult::no_match();
            }
        }

        ConditionResult::matched_with(vec![Evidence {
            method: "exclusion".to_string(),
            source: "composite_rule".to_string(),
            value: "negative_conditions_not_found".to_string(),
            location: None,
            span: None, analysis_layer: None,
                    analysis_layer: None,
        }])
    }
}
