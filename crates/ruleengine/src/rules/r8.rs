//! R8: EXCESSIVE_COMMANDS

use antidote_core::{Flag, Label, Severity};
use crate::state::SessionState;
use crate::RuleEngine;

pub fn check(engine: &RuleEngine, session: &mut SessionState) -> Vec<Flag> {
    let mut flags = Vec::new();
    let th = engine.config().thresholds.cmds_high;
    if session.counts.cmds >= th && session.can_trigger_rule("R8") {
        session.record_rule_hit("R8");
        flags.push(Flag::new(
            session.session_id.clone(),
            "R8".to_string(),
            Severity::Med,
            10,
            Label::ExecutionRisk,
            serde_json::json!({
                "cmds": session.counts.cmds,
                "threshold": th
            }),
            format!("Excessive commands detected: {} commands", session.counts.cmds),
        ));
    }
    flags
}
