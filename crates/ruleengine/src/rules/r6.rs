//! R6: BULK_DELETE (at threshold)

use antidote_core::{Flag, Label, Severity};
use crate::state::SessionState;
use crate::RuleEngine;

pub fn check(engine: &RuleEngine, session: &mut SessionState) -> Vec<Flag> {
    let mut flags = Vec::new();
    let th = engine.config().thresholds.bulk_delete;
    if session.counts.files_deleted >= th && session.can_trigger_rule("R6") {
        session.record_rule_hit("R6");
        flags.push(Flag::new(
            session.session_id.clone(),
            "R6".to_string(),
            Severity::Crit,
            40,
            Label::DestructiveAction,
            serde_json::json!({
                "files_deleted": session.counts.files_deleted,
                "threshold": th
            }),
            format!("Bulk delete detected: {} files", session.counts.files_deleted),
        ));
    }
    flags
}
