//! R9: REPO_SECRETS_HUNTING - many file writes with secret-like names

use antidote_core::{Flag, Label, Severity};
use crate::state::SessionState;
use crate::RuleEngine;

pub fn check(_engine: &RuleEngine, session: &mut SessionState) -> Vec<Flag> {
    let mut flags = Vec::new();
    if session.counts.files_written >= 10 && session.can_trigger_rule("R9") {
        let secret_like_count = session.evidence.sensitive_paths.len();
        if secret_like_count >= 3 {
            session.record_rule_hit("R9");
            flags.push(Flag::new(
                session.session_id.clone(),
                "R9".to_string(),
                Severity::High,
                25,
                Label::SensitiveAccess,
                serde_json::json!({
                    "files_written": session.counts.files_written,
                    "sensitive_paths": secret_like_count
                }),
                format!(
                    "Secrets hunting detected: {} sensitive files in {} writes",
                    secret_like_count, session.counts.files_written
                ),
            ));
        }
    }
    flags
}
