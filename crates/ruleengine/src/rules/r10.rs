//! R10: CONFIG_PERSISTENCE - repeated shell profile/launch agent modifications

use antidote_core::{Flag, Label, Severity};
use crate::state::SessionState;
use crate::RuleEngine;

pub fn check(engine: &RuleEngine, session: &mut SessionState) -> Vec<Flag> {
    let mut flags = Vec::new();
    let th = engine.config().thresholds.sensitive_burst as usize;
    if session.sensitive_writes.len() >= th && session.can_trigger_rule("R10") {
        let shell_profile_count = session
            .sensitive_writes
            .iter()
            .filter(|(path, _)| {
                path.contains(".zshrc")
                    || path.contains(".bashrc")
                    || path.contains(".profile")
                    || path.contains("LaunchAgents")
            })
            .count();
        if shell_profile_count >= 2 {
            session.record_rule_hit("R10");
            flags.push(Flag::new(
                session.session_id.clone(),
                "R10".to_string(),
                Severity::Crit,
                40,
                Label::PersistenceModification,
                serde_json::json!({
                    "profile_modifications": shell_profile_count
                }),
                format!(
                    "Config persistence detected: {} profile/agent modifications",
                    shell_profile_count
                ),
            ));
        }
    }
    flags
}
