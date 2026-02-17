//! R4: UNKNOWN_DOMAIN_CONTACT

use antidote_core::{Event, Flag, Label, Severity};
use crate::state::SessionState;
use crate::RuleEngine;

pub fn check(engine: &RuleEngine, event: &Event, session: &mut SessionState) -> Vec<Flag> {
    let mut flags = Vec::new();
    if let Some(domain) = event.payload.get("domain").and_then(|v| v.as_str()) {
        if !engine.is_known_domain(domain) && session.can_trigger_rule("R4") {
            session.record_rule_hit("R4");
            session.evidence.add_unknown_domain(domain.to_string());
            flags.push(Flag::new(
                session.session_id.clone(),
                "R4".to_string(),
                Severity::Med,
                10,
                Label::UnknownEndpoint,
                serde_json::json!({
                    "domain": domain,
                    "event_id": event.id
                }),
                format!("Unknown domain contacted: {}", domain),
            ));
        }
    }
    flags
}
