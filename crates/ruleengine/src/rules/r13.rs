//! R13: TOOLCHAIN_INSTALL_SPIKE + BENIGN_INDEXING (labels only, no flags for R13)

use antidote_core::Label;
use crate::state::SessionState;
use crate::RuleEngine;

pub fn check(engine: &RuleEngine, session: &mut SessionState) {
    // R13: TOOLCHAIN_INSTALL_SPIKE
    let is_registry_domain = session.evidence.unknown_domains.iter().any(|d| {
        d.contains("npmjs.org") || d.contains("pypi.org") || d.contains("registry.npmjs.org")
    }) || engine.config().known_domains.iter().any(|d| {
        session
            .evidence
            .unknown_domains
            .iter()
            .any(|ud| ud.contains(d))
    });
    if is_registry_domain && session.counts.files_written >= 50 && session.can_trigger_rule("R13") {
        let benign_write_count = session
            .evidence
            .sensitive_paths
            .iter()
            .filter(|p| engine.is_benign_path(p))
            .count();
        if benign_write_count == 0 && session.counts.files_written >= 100 {
            session.record_rule_hit("R13");
            session.labels.insert(Label::LikelyDepInstall);
        }
    }

    // BENIGN_INDEXING
    if session.counts.files_written >= 50
        && session.evidence.unknown_domains.is_empty()
        && session.evidence.sensitive_paths.is_empty()
        && !session.labels.contains(&Label::LikelyDepInstall)
    {
        session.labels.insert(Label::BenignIndexing);
    }
}
