//! Core types for Antidote AI Activity Monitor

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Event types that can be monitored
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    Heartbeat,
    ProcStart,
    ProcExit,
    Tick,
    FileWrite,
    FileCreate,
    FileDelete,
    FileRename,
    FileRead,      // Phase 4: from audit logs
    NetHttp,
    NetConnect,    // Phase 4: from audit logs
    CmdExec,
    ProcSpawn,
}

/// Severity levels for flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Med,
    High,
    Crit,
}

/// Risk bucket classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskBucket {
    Low,
    Medium,
    High,
}

/// Labels for categorizing suspicious activity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Label {
    SensitiveAccess,
    UnknownEndpoint,
    SuspiciousEgress,
    DestructiveAction,
    ExecutionRisk,
    PersistenceModification,
    ConfigTampering,
    BulkTraversal,
    PrivilegeEscalation,
    // Phase 3: Benign labels (reduce false positives)
    BenignIndexing,
    LikelyDepInstall,
    // Phase 5: Behavioral
    BehavioralAnomaly,
    RepeatedRisk,
    // Phase 6: Enforcement
    EnforcementBlocked,
    SafeModeViolation,
    EmergencyFreeze,
}

/// An event captured by the monitor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    pub session_id: String,
    pub event_type: EventType,
    pub payload: serde_json::Value,
    /// Phase 6: True if this event represents an enforcement action (block, freeze, etc.)
    #[serde(default)]
    pub enforcement_action: bool,
}

impl Event {
    /// Create a new event
    pub fn new(
        session_id: String,
        event_type: EventType,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            ts: OffsetDateTime::now_utc(),
            session_id,
            event_type,
            payload,
            enforcement_action: false,
        }
    }
}

/// Counts of various event types in a session
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Counts {
    pub files_written: u64,
    pub files_deleted: u64,
    pub files_read: u64,      // Phase 4: from audit logs
    pub cmds: u64,
    pub domains: u64,
    pub bytes_out: u64,
    pub events_total: u64,
}

/// Risk summary for a session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSummary {
    pub score: i32,
    pub bucket: RiskBucket,
}

impl RiskSummary {
    /// Calculate risk bucket from score
    pub fn from_score(score: i32) -> Self {
        let bucket = match score {
            0..=30 => RiskBucket::Low,
            31..=60 => RiskBucket::Medium,
            _ => RiskBucket::High,
        };
        Self { score, bucket }
    }

    /// Create a new risk summary with clamped score
    pub fn new(score: i32) -> Self {
        let clamped = score.clamp(0, 100);
        Self::from_score(clamped)
    }
}

/// A flag raised by the rule engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flag {
    pub id: Uuid,
    pub session_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    pub rule_id: String,
    pub severity: Severity,
    pub weight: i32,
    pub label: Label,
    pub evidence: serde_json::Value,
    pub message: String,
}

impl Flag {
    /// Create a new flag
    pub fn new(
        session_id: String,
        rule_id: String,
        severity: Severity,
        weight: i32,
        label: Label,
        evidence: serde_json::Value,
        message: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            ts: OffsetDateTime::now_utc(),
            session_id,
            rule_id,
            severity,
            weight,
            label,
            evidence,
            message,
        }
    }
}

/// Evidence collected during a session
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Evidence {
    pub sensitive_paths: Vec<String>,
    pub unknown_domains: Vec<String>,
    pub dangerous_commands: Vec<String>,
}

impl Evidence {
    /// Add a sensitive path (capped at 10)
    pub fn add_sensitive_path(&mut self, path: String) {
        if !self.sensitive_paths.contains(&path) && self.sensitive_paths.len() < 10 {
            self.sensitive_paths.push(path);
        }
    }

    /// Add an unknown domain (capped at 10)
    pub fn add_unknown_domain(&mut self, domain: String) {
        if !self.unknown_domains.contains(&domain) && self.unknown_domains.len() < 10 {
            self.unknown_domains.push(domain);
        }
    }

    /// Add a dangerous command (capped at 5)
    pub fn add_dangerous_command(&mut self, cmd: String) {
        if !self.dangerous_commands.contains(&cmd) && self.dangerous_commands.len() < 5 {
            self.dangerous_commands.push(cmd);
        }
    }

    /// Add a deleted file path (capped at 10, for destructive action evidence)
    pub fn add_deleted_path(&mut self, path: String) {
        // Store in sensitive_paths for now (we can add a separate field later)
        if !self.sensitive_paths.contains(&path) && self.sensitive_paths.len() < 10 {
            self.sensitive_paths.push(path);
        }
    }
}

/// Telemetry confidence level (Phase 4)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TelemetryConfidence {
    #[default]
    Low,   // Only process polling + debug events
    Med,   // Proxy + FS watcher active
    High,  // Audit collector active
}

/// Summary of a monitoring session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub app: String,
    pub root_pid: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub start_ts: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub end_ts: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub last_event_ts: OffsetDateTime,
    pub counts: Counts,
    pub risk: RiskSummary,
    pub labels: Vec<Label>,
    pub evidence: Evidence,
    /// Observed watched roots for this session (paths that saw events)
    #[serde(default)]
    pub observed_roots: Vec<String>,
    /// Telemetry confidence level (Phase 4)
    #[serde(default)]
    pub telemetry_confidence: TelemetryConfidence,
    /// Number of events dropped due to rate limiting (Phase 4)
    #[serde(default)]
    pub dropped_events: u64,
    /// Count of unique PIDs that participated in this session (Phase 4)
    #[serde(default)]
    pub participant_pids_count: u32,
    /// Phase 5: Drift index 0..100 (how much session deviates from app baseline)
    #[serde(default)]
    pub drift_index: Option<u8>,
    /// Phase 5: Human-readable baseline comparison (e.g. "3.2x more egress than typical")
    #[serde(default)]
    pub baseline_comparison_summary: Option<String>,
    /// Phase 6: Number of enforcement actions (blocks, kills) in this session
    #[serde(default)]
    pub enforcement_actions_count: u32,
    /// Phase 6: True if session was force-terminated by emergency freeze
    #[serde(default)]
    pub forced_terminated: bool,
}

impl SessionSummary {
    /// Create a new session summary
    pub fn new(session_id: String, app: String, root_pid: i32) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            session_id,
            app,
            root_pid,
            start_ts: now,
            end_ts: None,
            last_event_ts: now,
            counts: Counts::default(),
            risk: RiskSummary::new(0),
            labels: Vec::new(),
            evidence: Evidence::default(),
            observed_roots: Vec::new(),
            telemetry_confidence: TelemetryConfidence::Low,
            dropped_events: 0,
            participant_pids_count: 0,
            drift_index: None,
            baseline_comparison_summary: None,
            enforcement_actions_count: 0,
            forced_terminated: false,
        }
    }
}

/// Payload structures for events (helpers for serialization)
pub mod payloads {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ProcPayload {
        pub pid: i32,
        pub ppid: i32,
        pub name: String,
        pub exe: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NetPayload {
        pub domain: String,
        pub bytes_out: u64,
        pub bytes_in: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CmdPayload {
        pub argv: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FilePayload {
        pub path: String,
        pub bytes: Option<u64>,
    }

    /// Audit event payload (Phase 4)
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuditPayload {
        pub pid: Option<i32>,
        pub ppid: Option<i32>,
        pub uid: Option<u32>,
        pub exe: Option<String>,
        pub path: Option<String>,
        pub remote_addr: Option<String>,
        pub remote_port: Option<u16>,
    }
}

/// Phase 6: Enforcement configuration (opt-in, safe by default)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementConfig {
    pub enabled: bool,
    pub block_unknown_domains: bool,
    pub block_high_egress: bool,
    pub block_dangerous_commands: bool,
    pub auto_freeze_high_risk: bool,
    /// Per-connection egress threshold in bytes (when block_high_egress is true)
    #[serde(default = "default_egress_threshold")]
    pub egress_threshold_bytes: u64,
}

fn default_egress_threshold() -> u64 {
    50 * 1024 * 1024 // 50 MiB
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            block_unknown_domains: false,
            block_high_egress: false,
            block_dangerous_commands: false,
            auto_freeze_high_risk: false,
            egress_threshold_bytes: default_egress_threshold(),
        }
    }
}

/// Phase 6: Safe mode (restricted runtime)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeModeConfig {
    pub enabled: bool,
    pub allowed_domains: Vec<String>,
    pub allowed_roots: Vec<String>,
}

impl Default for SafeModeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_domains: vec![
                "api.openai.com".to_string(),
                "api.anthropic.com".to_string(),
            ],
            allowed_roots: vec![],
        }
    }
}

#[cfg(test)]
mod enforcement_tests {
    use super::{EnforcementConfig, SafeModeConfig};

    #[test]
    fn test_enforcement_disabled_by_default() {
        let c = EnforcementConfig::default();
        assert!(!c.enabled);
        assert!(!c.block_unknown_domains);
        assert!(!c.block_dangerous_commands);
    }

    #[test]
    fn test_safe_mode_default() {
        let s = SafeModeConfig::default();
        assert!(!s.enabled);
        assert!(s.allowed_domains.contains(&"api.openai.com".to_string()));
    }
}
