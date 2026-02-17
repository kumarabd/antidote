//! R11: SUSPICIOUS_DOMAIN_CLUSTER - many unknown domains in short window

use antidote_core::{Flag, Label, Severity};
use crate::state::SessionState;
use crate::RuleEngine;

pub fn check(engine: &RuleEngine, session: &mut SessionState) -> Vec<Flag> {
    let mut flags = Vec::new();
    let recent_unknown = session.unknown_domain_contacts.len() as u64;
    let th = engine.config().thresholds.unknown_domains_cluster;
    let window = engine.config().time_windows.unknown_domains_window_seconds;
    if recent_unknown >= th && session.can_trigger_rule("R11") {
        session.record_rule_hit("R11");
        flags.push(Flag::new(
            session.session_id.clone(),
            "R11".to_string(),
            Severity::High,
            22,
            Label::UnknownEndpoint,
            serde_json::json!({
                "unknown_domains_in_window": recent_unknown,
                "window_seconds": window
            }),
            format!(
                "Suspicious domain cluster: {} unknown domains in {}s",
                recent_unknown, window
            ),
        ));
    }
    flags
}
