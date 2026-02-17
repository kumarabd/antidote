//! R2: SHELL_PROFILE_WRITE

use antidote_core::{Event, Flag, Label, Severity};
use crate::state::SessionState;
use crate::RuleEngine;

const SHELL_PROFILES: &[&str] = &["~/.zshrc", "~/.bashrc", "~/.profile"];

pub fn check(_engine: &RuleEngine, event: &Event, session: &mut SessionState) -> Vec<Flag> {
    let mut flags = Vec::new();
    if let Some(path) = event.payload.get("path").and_then(|v| v.as_str()) {
        let expanded_path = if path.starts_with("~/") {
            let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
            path.replacen("~", &home, 1)
        } else {
            path.to_string()
        };

        let is_shell_profile = SHELL_PROFILES.iter().any(|&p| {
            let expanded = if p.starts_with("~/") {
                let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
                p.replacen("~", &home, 1)
            } else {
                p.to_string()
            };
            expanded_path == expanded || expanded_path.ends_with(&expanded)
        });

        if is_shell_profile && session.can_trigger_rule("R2") {
            session.record_rule_hit("R2");
            flags.push(Flag::new(
                session.session_id.clone(),
                "R2".to_string(),
                Severity::Crit,
                35,
                Label::PersistenceModification,
                serde_json::json!({
                    "path": path,
                    "event_id": event.id
                }),
                format!("Shell profile modification detected: {}", path),
            ));
        }
    }
    flags
}
