//! Cross-session risk history and escalation

use antidote_core::{Flag, Label, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;

use crate::{ESCALATION_COUNT_THRESHOLD, ESCALATION_DAYS};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskHistoryEntry {
    pub app: String,
    pub rule_id: String,
    pub first_seen: OffsetDateTime,
    pub last_seen: OffsetDateTime,
    pub count: u32,
}

/// Check if we should emit ESCALATING_PATTERN (same HIGH rule >= 3 in 7 days).
/// history: (rule_id, count) for this app in last 7 days where severity was High.
pub fn check_escalation(
    session_id: &str,
    _app: &str,
    high_rule_counts: &[(String, u32)],
) -> Option<Flag> {
    for (rule_id, count) in high_rule_counts {
        if *count >= ESCALATION_COUNT_THRESHOLD {
            return Some(Flag::new(
                session_id.to_string(),
                "ESCALATING_PATTERN".to_string(),
                Severity::High,
                15,
                Label::RepeatedRisk,
                json!({
                    "rule_id": rule_id,
                    "count": count,
                    "window_days": ESCALATION_DAYS
                }),
                format!(
                    "Escalating pattern: {} triggered {} times in last {} days",
                    rule_id, count, ESCALATION_DAYS
                ),
            ));
        }
    }
    None
}
