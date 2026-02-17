//! R12: DATA_EXFIL_SUSPECTED - unknown domain + high egress + sensitive write

use antidote_core::{Flag, Label, Severity};
use crate::state::SessionState;
use crate::RuleEngine;

pub fn check(engine: &RuleEngine, session: &mut SessionState) -> Vec<Flag> {
    let mut flags = Vec::new();
    let egress_mb = (session.counts.bytes_out as f64) / (1024.0 * 1024.0);
    let th = engine.config().thresholds.exfil_egress_mb;
    if egress_mb >= th
        && !session.evidence.unknown_domains.is_empty()
        && !session.evidence.sensitive_paths.is_empty()
        && session.can_trigger_rule("R12")
    {
        session.record_rule_hit("R12");
        session.labels.insert(Label::SuspiciousEgress);
        flags.push(Flag::new(
            session.session_id.clone(),
            "R12".to_string(),
            Severity::High,
            30,
            Label::SuspiciousEgress,
            serde_json::json!({
                "egress_mb": egress_mb,
                "unknown_domains": session.evidence.unknown_domains.len(),
                "sensitive_paths": session.evidence.sensitive_paths.len()
            }),
            format!(
                "Data exfiltration suspected: {:.2}MB to {} unknown domains after sensitive writes",
                egress_mb,
                session.evidence.unknown_domains.len()
            ),
        ));
    }
    flags
}
