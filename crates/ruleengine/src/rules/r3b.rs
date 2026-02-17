//! R3B: BULK_DELETE_PROGRESSIVE (flag at 5 files)

use antidote_core::{Event, Flag, Label, Severity};
use crate::state::SessionState;
use crate::RuleEngine;

pub fn check(_engine: &RuleEngine, event: &Event, session: &mut SessionState) -> Vec<Flag> {
    let mut flags = Vec::new();
    if session.counts.files_deleted == 5 && session.can_trigger_rule("R3B") {
        session.record_rule_hit("R3B");
        if let Some(path) = event.payload.get("path").and_then(|v| v.as_str()) {
            session.evidence.add_deleted_path(path.to_string());
        }
        flags.push(Flag::new(
            session.session_id.clone(),
            "R3B".to_string(),
            Severity::Med,
            10,
            Label::DestructiveAction,
            serde_json::json!({
                "files_deleted": session.counts.files_deleted,
                "event_id": event.id
            }),
            format!(
                "Progressive bulk delete detected: {} files",
                session.counts.files_deleted
            ),
        ));
    }
    flags
}
