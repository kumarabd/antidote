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
    /// Step 4: Why this event was attributed to this session (e.g. "pid", "root_match", "foreground").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution_reason: Option<String>,
    /// Step 4: Attribution confidence 0..100 (higher = more confident).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution_confidence: Option<u8>,
    /// Step 7: Explainability details (heat scores, etc.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution_details_json: Option<serde_json::Value>,
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
            attribution_reason: None,
            attribution_confidence: None,
            attribution_details_json: None,
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

/// Step 4: Confidence that the current focus session is correct
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FocusConfidence {
    High,
    Medium,
    #[default]
    Low,
}

/// Step 4: Current foreground context (app, pid, workspace roots, session_id, confidence)
/// Step 7: workspace_confidence from resolver (High/Medium/Low) for attribution downgrade.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForegroundContext {
    pub app: Option<String>,
    pub pid: Option<i32>,
    pub workspace_roots: Vec<String>,
    pub session_id: Option<String>,
    pub confidence: FocusConfidence,
    /// Step 7: Workspace resolver confidence (for attribution downgrade)
    #[serde(default)]
    pub workspace_confidence: FocusConfidence,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
}

impl Default for ForegroundContext {
    fn default() -> Self {
        Self {
            app: None,
            pid: None,
            workspace_roots: Vec::new(),
            session_id: None,
            confidence: FocusConfidence::Low,
            workspace_confidence: FocusConfidence::Low,
            observed_at: OffsetDateTime::UNIX_EPOCH,
        }
    }
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
    /// Step 5: Computed summary JSON on finalize (duration, writes, reads, net, etc.)
    #[serde(default)]
    pub summary_json: Option<String>,
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
                summary_json: None,
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

// ---------------------------------------------------------------------------
// Step 4: Attribution (session_id + reason + confidence for events)
// ---------------------------------------------------------------------------

/// Result of attributing an event to a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionResult {
    pub session_id: String,
    pub reason: String,
    pub confidence: u8,
    /// Step 7: Optional explainability details (heat scores, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details_json: Option<serde_json::Value>,
}

/// Snapshot of context for attribution (built from FocusManager + SessionManager + watched_roots).
/// Step 7: session_heat, recent_session_window_seconds for heat-based tie break.
#[derive(Debug, Clone)]
pub struct AttributionContext {
    pub foreground: ForegroundContext,
    pub watched_roots: Vec<String>,
    pub active_sessions: Vec<SessionSummary>,
    pub session_roots: std::collections::HashMap<String, Vec<String>>,
    pub pid_to_session: std::collections::HashMap<i32, String>,
    /// Step 7: session_id -> heat score for tie-breaking
    pub session_heat: std::collections::HashMap<String, u32>,
    /// Step 7: seconds for "recent" session window (network events)
    pub recent_session_window_seconds: u64,
}

impl AttributionContext {
    pub fn from_parts(
        foreground: ForegroundContext,
        watched_roots: Vec<String>,
        active_sessions: Vec<SessionSummary>,
        session_roots: std::collections::HashMap<String, Vec<String>>,
        session_heat: std::collections::HashMap<String, u32>,
        recent_session_window_seconds: u64,
    ) -> Self {
        let pid_to_session = active_sessions
            .iter()
            .filter(|s| s.root_pid != 0)
            .map(|s| (s.root_pid, s.session_id.clone()))
            .collect();
        Self {
            foreground,
            watched_roots,
            active_sessions,
            session_roots,
            pid_to_session,
            session_heat,
            recent_session_window_seconds,
        }
    }

    /// Step 7: Build with custom pid_to_session (merged with session-based pids).
    pub fn from_parts_with_pid_override(
        foreground: ForegroundContext,
        watched_roots: Vec<String>,
        active_sessions: Vec<SessionSummary>,
        session_roots: std::collections::HashMap<String, Vec<String>>,
        mut pid_to_session: std::collections::HashMap<i32, String>,
        session_heat: std::collections::HashMap<String, u32>,
        recent_session_window_seconds: u64,
    ) -> Self {
        for s in &active_sessions {
            if s.root_pid != 0 {
                pid_to_session.entry(s.root_pid).or_insert_with(|| s.session_id.clone());
            }
        }
        Self {
            foreground,
            watched_roots,
            active_sessions,
            session_roots,
            pid_to_session,
            session_heat,
            recent_session_window_seconds,
        }
    }
}

/// Deterministic attribution: file, network, command. Used by pipeline and debug/simulate.
pub fn attribute_event(event: &Event, ctx: &AttributionContext) -> AttributionResult {
    if matches!(
        event.event_type,
        EventType::FileWrite | EventType::FileCreate | EventType::FileDelete
            | EventType::FileRename | EventType::FileRead
    ) {
        attribute_file_event(event, ctx)
    } else if matches!(event.event_type, EventType::NetHttp | EventType::NetConnect) {
        attribute_network_event(ctx)
    } else if event.event_type == EventType::CmdExec {
        attribute_command_event(event, ctx)
    } else if event.event_type == EventType::ProcStart || event.event_type == EventType::ProcExit {
        attribute_proc_event(event, ctx)
    } else {
        fallback_attribution(ctx)
    }
}

fn attribute_file_event(event: &Event, ctx: &AttributionContext) -> AttributionResult {
    let path = event.payload.get("path").and_then(|v| v.as_str());
    let pid: Option<i32> = event.payload.get("pid").and_then(|v| v.as_i64()).map(|v| v as i32);

    if let Some(pid) = pid {
        if let Some(sid) = ctx.pid_to_session.get(&pid) {
            return with_confidence(
                AttributionResult {
                    session_id: sid.clone(),
                    reason: "pid".to_string(),
                    confidence: 90,
                    details_json: None,
                },
                &ctx.foreground,
            );
        }
    }

    let path = match path {
        Some(p) => p,
        None => return fallback_attribution(ctx),
    };

    let candidate_sessions = sessions_containing_path(ctx, path);
    if candidate_sessions.is_empty() {
        if let Some(ref fg) = ctx.foreground.session_id {
            let under_fg = ctx
                .foreground
                .workspace_roots
                .iter()
                .any(|r| path.starts_with(r));
            if under_fg {
                return with_confidence(
                    AttributionResult {
                        session_id: fg.clone(),
                        reason: "fallback_foreground_workspace".to_string(),
                        confidence: 50,
                        details_json: None,
                    },
                    &ctx.foreground,
                );
            }
        }
        return AttributionResult {
            session_id: "background".to_string(),
            reason: "fallback_background".to_string(),
            confidence: 0,
            details_json: None,
        };
    }

    if candidate_sessions.len() == 1 {
        return with_confidence(
            AttributionResult {
                session_id: candidate_sessions[0].clone(),
                reason: "root_match".to_string(),
                confidence: 85,
                details_json: None,
            },
            &ctx.foreground,
        );
    }

    if let Some(ref fg) = ctx.foreground.session_id {
        if candidate_sessions.contains(fg) {
            return with_confidence(
                AttributionResult {
                    session_id: fg.clone(),
                    reason: "foreground".to_string(),
                    confidence: 75,
                    details_json: None,
                },
                &ctx.foreground,
            );
        }
    }

    let chosen = pick_by_heat_recent_oldest(ctx, &candidate_sessions);
    let heat_scores: std::collections::HashMap<String, u32> = candidate_sessions
        .iter()
        .filter_map(|sid| ctx.session_heat.get(sid).map(|h| (sid.clone(), *h)))
        .collect();
    let details = if heat_scores.is_empty() {
        None
    } else {
        Some(serde_json::json!({ "heat_scores": heat_scores }))
    };
    with_confidence(
        AttributionResult {
            session_id: chosen.unwrap_or_else(|| "background".to_string()),
            reason: "heat".to_string(),
            confidence: 60,
            details_json: details,
        },
        &ctx.foreground,
    )
}

fn pick_by_heat_recent_oldest(
    ctx: &AttributionContext,
    candidates: &[String],
) -> Option<String> {
    let mut scored: Vec<(String, u32, time::OffsetDateTime, time::OffsetDateTime)> = candidates
        .iter()
        .filter_map(|sid| {
            ctx.active_sessions
                .iter()
                .find(|s| s.session_id == *sid)
                .map(|s| {
                    let heat = ctx.session_heat.get(sid).copied().unwrap_or(0);
                    (sid.clone(), heat, s.last_event_ts, s.start_ts)
                })
        })
        .collect();
    scored.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then(b.2.cmp(&a.2))
            .then(a.3.cmp(&b.3))
    });
    scored.into_iter().next().map(|(sid, _, _, _)| sid)
}

fn with_confidence(mut r: AttributionResult, fg: &ForegroundContext) -> AttributionResult {
    let downgrade = match fg.workspace_confidence {
        FocusConfidence::High => 0,
        FocusConfidence::Medium => 10,
        FocusConfidence::Low => 20,
    };
    r.confidence = r.confidence.saturating_sub(downgrade);
    r
}

fn sessions_containing_path(ctx: &AttributionContext, path: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (sid, roots) in &ctx.session_roots {
        if roots.iter().any(|r| path.starts_with(r.as_str())) {
            out.push(sid.clone());
        }
    }
    out
}

fn attribute_network_event(ctx: &AttributionContext) -> AttributionResult {
    let now = time::OffsetDateTime::now_utc();
    if let Some(ref sid) = ctx.foreground.session_id {
        let is_supported = ctx
            .foreground
            .app
            .as_ref()
            .map(|a| a.eq_ignore_ascii_case("Cursor") || a.eq_ignore_ascii_case("VSCode"))
            .unwrap_or(false);
        if is_supported {
            return with_confidence(
                AttributionResult {
                    session_id: sid.clone(),
                    reason: "foreground".to_string(),
                    confidence: 70,
                    details_json: None,
                },
                &ctx.foreground,
            );
        }
    }

    let window_secs = ctx.recent_session_window_seconds.max(60) as i64;
    let cutoff = now - time::Duration::seconds(window_secs);
    let recent: Vec<_> = ctx
        .active_sessions
        .iter()
        .filter(|s| s.end_ts.is_none() && s.last_event_ts >= cutoff)
        .collect();

    if recent.len() == 1 {
        return with_confidence(
            AttributionResult {
                session_id: recent[0].session_id.clone(),
                reason: "recent_session".to_string(),
                confidence: 50,
                details_json: None,
            },
            &ctx.foreground,
        );
    }
    if recent.len() > 1 {
        let candidates: Vec<String> = recent.iter().map(|s| s.session_id.clone()).collect();
        let chosen = pick_by_heat_recent_oldest(ctx, &candidates);
        if let Some(sid) = chosen {
            let heat_scores: std::collections::HashMap<String, u32> = candidates
                .iter()
                .filter_map(|s| ctx.session_heat.get(s).map(|h| (s.clone(), *h)))
                .collect();
            return with_confidence(
                AttributionResult {
                    session_id: sid,
                    reason: "heat".to_string(),
                    confidence: 40,
                    details_json: Some(serde_json::json!({ "heat_scores": heat_scores })),
                },
                &ctx.foreground,
            );
        }
    }

    AttributionResult {
        session_id: "background".to_string(),
        reason: "fallback_background".to_string(),
        confidence: 0,
        details_json: None,
    }
}

fn attribute_command_event(event: &Event, ctx: &AttributionContext) -> AttributionResult {
    let pid: Option<i32> = event.payload.get("pid").and_then(|v| v.as_i64()).map(|v| v as i32);
    if let Some(pid) = pid {
        if let Some(sid) = ctx.pid_to_session.get(&pid) {
            return with_confidence(
                AttributionResult {
                    session_id: sid.clone(),
                    reason: "pid".to_string(),
                    confidence: 90,
                    details_json: None,
                },
                &ctx.foreground,
            );
        }
    }
    attribute_network_event(ctx)
}

fn attribute_proc_event(event: &Event, ctx: &AttributionContext) -> AttributionResult {
    let pid: Option<i32> = event.payload.get("pid").and_then(|v| v.as_i64()).map(|v| v as i32);
    if let Some(pid) = pid {
        if let Some(sid) = ctx.pid_to_session.get(&pid) {
            return AttributionResult {
                session_id: sid.clone(),
                reason: "pid".to_string(),
                confidence: 90,
                details_json: None,
            };
        }
    }
    fallback_attribution(ctx)
}

fn fallback_attribution(ctx: &AttributionContext) -> AttributionResult {
    if let Some(ref sid) = ctx.foreground.session_id {
        return with_confidence(
            AttributionResult {
                session_id: sid.clone(),
                reason: "foreground".to_string(),
                confidence: 60,
                details_json: None,
            },
            &ctx.foreground,
        );
    }
    let best = ctx
        .active_sessions
        .iter()
        .filter(|s| s.end_ts.is_none())
        .max_by_key(|s| s.last_event_ts)
        .map(|s| s.session_id.clone());
    AttributionResult {
        session_id: best.unwrap_or_else(|| "background".to_string()),
        reason: "recent_session".to_string(),
        confidence: 30,
        details_json: None,
    }
}

/// Step 6: Trait for reading dropped event count (rate limiting).
pub trait DropMetrics: Send + Sync {
    fn get_dropped(&self) -> u64;
}

/// Step 7: Provider for attribution debug snapshot (heat, PID cache, stabilization).
pub trait AttributionDebugProvider: Send + Sync {
    fn get_snapshot(
        self: std::sync::Arc<Self>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = serde_json::Value> + Send>>;
}

/// Step 8: Provider for telemetry integrity metrics (attribution quality, root coverage, pipeline).
/// Health, capabilities, confidence, and warnings are built by the API from its state.
pub trait TelemetryIntegrityProvider: Send + Sync {
    fn get_attribution_quality(
        self: std::sync::Arc<Self>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = serde_json::Value> + Send>>;
    fn get_root_coverage(
        self: std::sync::Arc<Self>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = serde_json::Value> + Send>>;
    fn get_pipeline(
        self: std::sync::Arc<Self>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = serde_json::Value> + Send>>;
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

#[cfg(test)]
mod attribution_tests {
    use super::*;
    use time::OffsetDateTime;

    fn mk_session(id: &str, app: &str, root_pid: i32, roots: Vec<&str>) -> SessionSummary {
        let now = OffsetDateTime::now_utc();
        let mut s = SessionSummary::new(id.to_string(), app.to_string(), root_pid);
        s.observed_roots = roots.into_iter().map(String::from).collect();
        s.last_event_ts = now;
        s
    }

    fn mk_event(ty: EventType, path: Option<&str>, pid: Option<i32>) -> Event {
        let mut payload = serde_json::json!({});
        if let Some(p) = path {
            payload["path"] = serde_json::json!(p);
        }
        if let Some(p) = pid {
            payload["pid"] = serde_json::json!(p);
        }
        Event {
            id: uuid::Uuid::new_v4(),
            ts: OffsetDateTime::now_utc(),
            session_id: "pending".to_string(),
            event_type: ty,
            payload,
            enforcement_action: false,
            attribution_reason: None,
            attribution_confidence: None,
            attribution_details_json: None,
        }
    }

    fn mk_ctx(
        foreground: ForegroundContext,
        session_roots: Vec<(&str, Vec<&str>)>,
        pids: Vec<(i32, &str)>,
    ) -> AttributionContext {
        let now = OffsetDateTime::now_utc();
        let active_sessions: Vec<SessionSummary> = session_roots
            .iter()
            .map(|(id, roots)| {
                let mut s = SessionSummary::new(id.to_string(), "Cursor".to_string(), 0);
                s.observed_roots = roots.iter().map(|r| (*r).to_string()).collect();
                s.last_event_ts = now;
                s
            })
            .collect();
        let pid_to_session: std::collections::HashMap<i32, String> =
            pids.into_iter().map(|(p, s)| (p, s.to_string())).collect();
        let session_roots_map: std::collections::HashMap<String, Vec<String>> = session_roots
            .into_iter()
            .map(|(id, roots)| (id.to_string(), roots.into_iter().map(String::from).collect()))
            .collect();
        AttributionContext {
            foreground,
            watched_roots: vec![],
            active_sessions: active_sessions.clone(),
            session_roots: session_roots_map,
            pid_to_session,
            session_heat: std::collections::HashMap::new(),
            recent_session_window_seconds: 300,
        }
    }

    #[test]
    fn test_root_match_single_session() {
        let ctx = mk_ctx(
            ForegroundContext::default(),
            vec![("s1", vec!["/tmp/proj1"])],
            vec![],
        );
        let event = mk_event(EventType::FileWrite, Some("/tmp/proj1/src/main.rs"), None);
        let r = attribute_event(&event, &ctx);
        assert_eq!(r.session_id, "s1");
        assert_eq!(r.reason, "root_match");
        assert!(r.confidence >= 80);
    }

    #[test]
    fn test_foreground_tie_break() {
        let mut fg = ForegroundContext::default();
        fg.session_id = Some("s1".to_string());
        let ctx = mk_ctx(
            fg,
            vec![("s1", vec!["/tmp/a"]), ("s2", vec!["/tmp/a"])],
            vec![],
        );
        let event = mk_event(EventType::FileWrite, Some("/tmp/a/file.rs"), None);
        let r = attribute_event(&event, &ctx);
        assert_eq!(r.session_id, "s1");
        assert_eq!(r.reason, "foreground_tie_break");
    }

    #[test]
    fn test_network_foreground() {
        let mut fg = ForegroundContext::default();
        fg.session_id = Some("cursor-session".to_string());
        fg.app = Some("Cursor".to_string());
        let ctx = mk_ctx(fg, vec![("cursor-session", vec!["/x"])], vec![]);
        let event = Event {
            id: uuid::Uuid::new_v4(),
            ts: OffsetDateTime::now_utc(),
            session_id: "pending".to_string(),
            event_type: EventType::NetHttp,
            payload: serde_json::json!({ "domain": "example.com" }),
            enforcement_action: false,
            attribution_reason: None,
            attribution_confidence: None,
            attribution_details_json: None,
        };
        let r = attribute_event(&event, &ctx);
        assert_eq!(r.session_id, "cursor-session");
        assert_eq!(r.reason, "foreground");
    }

    #[test]
    fn test_pid_attribution() {
        let ctx = mk_ctx(
            ForegroundContext::default(),
            vec![("s1", vec!["/tmp"])],
            vec![(12345, "s1")],
        );
        let event = mk_event(EventType::FileWrite, Some("/other/path"), Some(12345));
        let r = attribute_event(&event, &ctx);
        assert_eq!(r.session_id, "s1");
        assert_eq!(r.reason, "pid");
        assert!(r.confidence >= 85);
    }

    #[test]
    fn test_fallback_background() {
        let ctx = mk_ctx(ForegroundContext::default(), vec![], vec![]);
        let event = mk_event(EventType::FileWrite, Some("/unknown/path"), None);
        let r = attribute_event(&event, &ctx);
        assert_eq!(r.session_id, "background");
        assert_eq!(r.reason, "fallback_background");
        assert_eq!(r.confidence, 0);
    }
}
