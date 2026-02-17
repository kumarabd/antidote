//! R5: HIGH_EGRESS (medium and high thresholds)

use antidote_core::{Flag, Label, Severity};
use crate::state::SessionState;
use crate::RuleEngine;

pub fn check(engine: &RuleEngine, session: &mut SessionState) -> Vec<Flag> {
    let mut flags = Vec::new();
    let egress_mb = session.counts.bytes_out as f64 / 1_000_000.0;
    let th = &engine.config().thresholds;

    if egress_mb > th.egress_mb_high && session.can_trigger_rule("R5") {
        session.record_rule_hit("R5");
        flags.push(Flag::new(
            session.session_id.clone(),
            "R5".to_string(),
            Severity::High,
            20,
            Label::SuspiciousEgress,
            serde_json::json!({
                "egress_mb": egress_mb,
                "threshold": th.egress_mb_high
            }),
            format!("High egress detected: {:.2} MB", egress_mb),
        ));
    } else if egress_mb > th.egress_mb_medium && session.can_trigger_rule("R5") {
        session.record_rule_hit("R5");
        flags.push(Flag::new(
            session.session_id.clone(),
            "R5".to_string(),
            Severity::Med,
            8,
            Label::SuspiciousEgress,
            serde_json::json!({
                "egress_mb": egress_mb,
                "threshold": th.egress_mb_medium
            }),
            format!("Medium egress detected: {:.2} MB", egress_mb),
        ));
    }
    flags
}
