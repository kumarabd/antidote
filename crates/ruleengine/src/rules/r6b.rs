//! R6B: MANY_UNKNOWN_DOMAINS

use antidote_core::{Flag, Label, Severity};
use crate::state::SessionState;
use crate::RuleEngine;

pub fn check(engine: &RuleEngine, session: &mut SessionState) -> Vec<Flag> {
    let mut flags = Vec::new();
    let unknown_domain_count = session.evidence.unknown_domains.len() as u64;
    let th = engine.config().thresholds.unknown_domains_high;
    if unknown_domain_count >= th && session.can_trigger_rule("R6B") {
        session.record_rule_hit("R6B");
        flags.push(Flag::new(
            session.session_id.clone(),
            "R6B".to_string(),
            Severity::High,
            20,
            Label::UnknownEndpoint,
            serde_json::json!({
                "unknown_domains_count": unknown_domain_count,
                "threshold": th
            }),
            format!("Many unknown domains contacted: {}", unknown_domain_count),
        ));
    }
    flags
}
