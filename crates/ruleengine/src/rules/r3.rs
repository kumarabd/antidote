//! R3: DANGEROUS_COMMAND

use antidote_core::{Event, Flag, Label, Severity};
use crate::state::SessionState;
use crate::RuleEngine;

pub fn check(engine: &RuleEngine, event: &Event, session: &mut SessionState) -> Vec<Flag> {
    let mut flags = Vec::new();
    if let Some(argv_json) = event.payload.get("argv").and_then(|v| v.as_array()) {
        let argv: Vec<String> = argv_json
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        if engine.is_dangerous_command(&argv) && session.can_trigger_rule("R3") {
            session.record_rule_hit("R3");
            let cmd_str = argv.join(" ");
            session.evidence.add_dangerous_command(cmd_str.clone());
            flags.push(Flag::new(
                session.session_id.clone(),
                "R3".to_string(),
                Severity::High,
                25,
                Label::ExecutionRisk,
                serde_json::json!({
                    "argv": argv,
                    "event_id": event.id
                }),
                format!("Dangerous command detected: {}", cmd_str),
            ));
        }
    }
    flags
}
