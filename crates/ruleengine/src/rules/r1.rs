//! R1: SENSITIVE_FILE_WRITE

use antidote_core::{Event, Flag, Label, Severity};
use crate::state::SessionState;
use crate::RuleEngine;

pub fn check(engine: &RuleEngine, event: &Event, session: &mut SessionState) -> Vec<Flag> {
    let mut flags = Vec::new();
    if let Some(path) = event.payload.get("path").and_then(|v| v.as_str()) {
        if engine.is_sensitive_path(path) && session.can_trigger_rule("R1") {
            session.record_rule_hit("R1");
            session.evidence.add_sensitive_path(path.to_string());
            flags.push(Flag::new(
                session.session_id.clone(),
                "R1".to_string(),
                Severity::Crit,
                30,
                Label::ConfigTampering,
                serde_json::json!({
                    "path": path,
                    "event_id": event.id
                }),
                format!("Sensitive file write detected: {}", path),
            ));
        }
    }
    flags
}
