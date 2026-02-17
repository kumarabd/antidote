//! Session state tracked by the rule engine

use antidote_core::{Counts, Evidence, Flag, Label, RiskSummary, Severity};
use std::collections::{HashMap, HashSet};
use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub struct SessionState {
    pub session_id: String,
    pub app: String,
    pub counts: Counts,
    pub flags: Vec<Flag>,
    pub labels: HashSet<Label>,
    pub evidence: Evidence,
    /// Track rule hit counts to enforce caps
    rule_hits: HashMap<String, u32>,
    /// Track event timestamps for time-window rules (Phase 3)
    pub event_timestamps: Vec<OffsetDateTime>,
    /// Track sensitive file writes with timestamps
    pub sensitive_writes: Vec<(String, OffsetDateTime)>,
    /// Track unknown domain contacts with timestamps
    pub unknown_domain_contacts: Vec<(String, OffsetDateTime)>,
}

impl SessionState {
    pub fn new(session_id: String, app: String) -> Self {
        Self {
            session_id,
            app,
            counts: Counts::default(),
            flags: Vec::new(),
            labels: HashSet::new(),
            evidence: Evidence::default(),
            rule_hits: HashMap::new(),
            event_timestamps: Vec::new(),
            sensitive_writes: Vec::new(),
            unknown_domain_contacts: Vec::new(),
        }
    }

    /// Check if a rule has hit its cap (max 3 hits per rule)
    pub(crate) fn can_trigger_rule(&self, rule_id: &str) -> bool {
        self.rule_hits.get(rule_id).copied().unwrap_or(0) < 3
    }

    /// Record a rule hit
    pub(crate) fn record_rule_hit(&mut self, rule_id: &str) {
        *self.rule_hits.entry(rule_id.to_string()).or_insert(0) += 1;
    }

    /// Calculate risk summary from flags (Phase 3: with synergy bonuses and dampening)
    pub fn calculate_risk(&self) -> RiskSummary {
        let unique_weights: HashSet<i32> = self.flags.iter().map(|f| f.weight).collect();
        let mut score: i32 = unique_weights.iter().sum();

        let has_exfil_suspected = self.labels.contains(&Label::SuspiciousEgress)
            && !self.evidence.unknown_domains.is_empty()
            && !self.evidence.sensitive_paths.is_empty();
        if has_exfil_suspected {
            score += 15;
        }

        let has_benign_install = self.labels.contains(&Label::LikelyDepInstall);
        let has_high_sev = self
            .flags
            .iter()
            .any(|f| matches!(f.severity, Severity::High | Severity::Crit));
        if has_benign_install && !has_high_sev {
            score = (score - 10).max(0);
        }

        RiskSummary::new(score)
    }
}
