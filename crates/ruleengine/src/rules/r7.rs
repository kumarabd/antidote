//! R7: BULK_WRITE

use antidote_core::{Flag, Label, Severity};
use crate::state::SessionState;
use crate::RuleEngine;

pub fn check(engine: &RuleEngine, session: &mut SessionState) -> Vec<Flag> {
    let mut flags = Vec::new();
    let th = engine.config().thresholds.bulk_write;
    if session.counts.files_written >= th && session.can_trigger_rule("R7") {
        session.record_rule_hit("R7");
        flags.push(Flag::new(
            session.session_id.clone(),
            "R7".to_string(),
            Severity::Med,
            12,
            Label::BulkTraversal,
            serde_json::json!({
                "files_written": session.counts.files_written,
                "threshold": th
            }),
            format!("Bulk write detected: {} files", session.counts.files_written),
        ));
    }
    flags
}
