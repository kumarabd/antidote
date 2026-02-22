//! Storage layer for Antidote using SQLite

use antidote_core::{
    Counts, Evidence, Event, EventType, Flag, Label, RiskBucket, RiskSummary, SessionSummary, Severity,
};
use anyhow::{Context, Result};
use serde_json;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Row, SqlitePool};
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

/// Parse session timestamp (Rfc3339); on failure use UNIX_EPOCH so legacy Display-formatted rows don't 500.
fn parse_session_ts(s: &str) -> OffsetDateTime {
    OffsetDateTime::parse(s, &Rfc3339).unwrap_or_else(|_| OffsetDateTime::UNIX_EPOCH)
}

/// Storage handle for database operations
pub struct Storage {
    pool: SqlitePool,
}

impl Storage {
    /// Initialize storage and apply migrations
    pub async fn init(db_url: &str) -> Result<Self> {
        let connect_url = if db_url.starts_with("sqlite:") {
            let path_str = db_url.strip_prefix("sqlite:").unwrap().trim_start_matches("./");
            let path = Path::new(path_str);
            let absolute: PathBuf = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir().context("Failed to get current directory")?
                    .join(path_str)
            };
            let parent = absolute.parent().context("Database path has no parent")?;
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create database directory: {}", parent.display()))?;
            // Use canonical path so SQLite gets a stable absolute path (helps on symlinks and URL parsing)
            let canonical_parent = std::fs::canonicalize(parent)
                .with_context(|| format!("Failed to canonicalize database directory: {}", parent.display()))?;
            let db_path = canonical_parent.join(absolute.file_name().context("Database path has no file name")?);
            // sqlx expects sqlite:///absolute/path (three slashes total)
            let url = format!("sqlite://{}", db_path.display());
            url
        } else {
            db_url.to_string()
        };

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&connect_url)
            .await
            .with_context(|| format!("Failed to connect to database: {}. Ensure the path exists and is writable.", connect_url))?;

        // Apply migrations manually (embed SQL to avoid path issues)
        // SQLite doesn't support multiple statements in one execute, so we split them
        let migrations = [
            include_str!("../migrations/0001_init.sql"),
            include_str!("../migrations/0002_session_fields.sql"),
            include_str!("../migrations/0003_roots_and_retention.sql"),
            include_str!("../migrations/0004_observed_roots.sql"),
            include_str!("../migrations/0005_audit_fields.sql"),
            include_str!("../migrations/0006_behavioral.sql"),
            include_str!("../migrations/0007_enforcement.sql"),
            include_str!("../migrations/0008_autoroot.sql"),
            include_str!("../migrations/0009_attribution.sql"),
            include_str!("../migrations/0010_sessions_lifecycle.sql"),
            include_str!("../migrations/0011_coalesced_events.sql"),
            include_str!("../migrations/0012_attribution_details.sql"),
        ];

        for (i, migration_sql) in migrations.iter().enumerate() {
            for chunk in migration_sql.split(';') {
                // Strip leading comment lines only; keep SQL that may follow (e.g. "-- Comment\nCREATE TABLE...")
                let statement_owned: String = chunk
                    .trim()
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("--"))
                    .collect::<Vec<_>>()
                    .join("\n");
                let statement = statement_owned.trim();
                if statement.is_empty() {
                    continue;
                }
                if let Err(e) = sqlx::query(statement).execute(&pool).await {
                    let msg = e.to_string();
                    // Ignore "already exists" / "duplicate column" from re-running migrations
                    if msg.contains("already exists")
                        || msg.contains("duplicate column name")
                        || msg.contains("Duplicate column")
                    {
                        continue;
                    }
                    anyhow::bail!(
                        "Migration {} failed on statement: {} ... Error: {}",
                        i + 1,
                        &statement[..statement.len().min(80)],
                        e
                    );
                }
            }
        }

        Ok(Self { pool })
    }

    /// Upsert a session summary
    pub async fn upsert_session_summary(&self, summary: &SessionSummary) -> Result<()> {
        let labels_json = serde_json::to_string(&summary.labels)?;
        let counts_json = serde_json::to_string(&summary.counts)?;
        let evidence_json = serde_json::to_string(&summary.evidence)?;
        let observed_roots_json = serde_json::to_string(&summary.observed_roots)?;
        let risk_bucket = match summary.risk.bucket {
            RiskBucket::Low => "low",
            RiskBucket::Medium => "medium",
            RiskBucket::High => "high",
        };

        let telemetry_confidence = match summary.telemetry_confidence {
            antidote_core::TelemetryConfidence::Low => "LOW",
            antidote_core::TelemetryConfidence::Med => "MED",
            antidote_core::TelemetryConfidence::High => "HIGH",
        };

        let drift_index_i: Option<i64> = summary.drift_index.map(|u| u as i64);
        let baseline_comp: Option<&str> = summary.baseline_comparison_summary.as_deref();
        let enforcement_actions: i64 = summary.enforcement_actions_count as i64;
        let forced_term: i64 = if summary.forced_terminated { 1 } else { 0 };

        sqlx::query(
            r#"
            INSERT INTO sessions (
                session_id, app, root_pid, start_ts, end_ts, last_event_ts,
                risk_score, risk_bucket, labels_json, counts_json, evidence_json, observed_roots_json,
                telemetry_confidence, dropped_events, participant_pids_count, drift_index, baseline_comparison_summary,
                enforcement_actions_count, forced_terminated, summary_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                app = excluded.app,
                end_ts = excluded.end_ts,
                last_event_ts = excluded.last_event_ts,
                risk_score = excluded.risk_score,
                risk_bucket = excluded.risk_bucket,
                labels_json = excluded.labels_json,
                counts_json = excluded.counts_json,
                evidence_json = excluded.evidence_json,
                observed_roots_json = excluded.observed_roots_json,
                telemetry_confidence = excluded.telemetry_confidence,
                dropped_events = excluded.dropped_events,
                participant_pids_count = excluded.participant_pids_count,
                drift_index = excluded.drift_index,
                baseline_comparison_summary = excluded.baseline_comparison_summary,
                enforcement_actions_count = excluded.enforcement_actions_count,
                forced_terminated = excluded.forced_terminated,
                summary_json = excluded.summary_json,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&summary.session_id)
        .bind(&summary.app)
        .bind(summary.root_pid)
        .bind(
            summary
                .start_ts
                .format(&Rfc3339)
                .map_err(|e| anyhow::anyhow!("format start_ts: {}", e))?
                .to_string(),
        )
        .bind(
            summary
                .end_ts
                .as_ref()
                .and_then(|ts| ts.format(&Rfc3339).ok().map(|f| f.to_string())),
        )
        .bind(
            summary
                .last_event_ts
                .format(&Rfc3339)
                .map_err(|e| anyhow::anyhow!("format last_event_ts: {}", e))?
                .to_string(),
        )
        .bind(summary.risk.score)
        .bind(risk_bucket)
        .bind(&labels_json)
        .bind(&counts_json)
        .bind(&evidence_json)
        .bind(&observed_roots_json)
        .bind(telemetry_confidence)
        .bind(summary.dropped_events as i64)
        .bind(summary.participant_pids_count as i64)
        .bind(drift_index_i)
        .bind(baseline_comp)
        .bind(enforcement_actions)
        .bind(forced_term)
        .bind(summary.summary_json.as_deref())
        .bind(
            OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .map_err(|e| anyhow::anyhow!("format updated_at: {}", e))?
                .to_string(),
        )
        .execute(&self.pool)
        .await
        .context("Failed to upsert session")?;

        Ok(())
    }

    /// Step 5: Finalize a session - compute summary JSON and update row
    pub async fn finalize_session(
        &self,
        session_id: &str,
        ended_at: OffsetDateTime,
    ) -> Result<SessionSummary> {
        let mut summary = self
            .get_session(session_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Session not found: {}", session_id))?;

        summary.end_ts = Some(ended_at);
        let start_ts = summary.start_ts;
        let duration_secs = (ended_at - start_ts).whole_seconds();
        let summary_json_val = serde_json::json!({
            "duration_seconds": duration_secs,
            "file_writes": summary.counts.files_written,
            "file_reads": summary.counts.files_read,
            "network_calls": summary.counts.domains,
            "total_egress_bytes": summary.counts.bytes_out,
            "risk_score": summary.risk.score,
            "drift_score": summary.drift_index.unwrap_or(0) as f64,
            "event_count": summary.counts.events_total,
        });
        summary.summary_json = Some(serde_json::to_string(&summary_json_val)?);

        self.upsert_session_summary(&summary).await?;
        Ok(summary)
    }

    /// Insert an event
    pub async fn insert_event(&self, event: &Event) -> Result<()> {
        let payload_json = serde_json::to_string(&event.payload)?;
        let event_type = match event.event_type {
            EventType::Heartbeat => "HEARTBEAT",
            EventType::ProcStart => "PROC_START",
            EventType::ProcExit => "PROC_EXIT",
            EventType::Tick => "TICK",
            EventType::FileWrite => "FILE_WRITE",
            EventType::FileCreate => "FILE_CREATE",
            EventType::FileDelete => "FILE_DELETE",
            EventType::FileRename => "FILE_RENAME",
            EventType::FileRead => "FILE_READ",
            EventType::NetHttp => "NET_HTTP",
            EventType::NetConnect => "NET_CONNECT",
            EventType::CmdExec => "CMD_EXEC",
            EventType::ProcSpawn => "PROC_SPAWN",
        };

        // Extract pid and ppid from payload (Phase 4)
        let pid: Option<i32> = event.payload.get("pid").and_then(|v| v.as_i64()).map(|v| v as i32);
        let ppid: Option<i32> = event.payload.get("ppid").and_then(|v| v.as_i64()).map(|v| v as i32);

        let enforcement_action = if event.enforcement_action { 1i32 } else { 0i32 };
        let attributed_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|e| anyhow::anyhow!("format ts: {}", e))?
            .to_string();
        let attribution_confidence: Option<i32> = event.attribution_confidence.map(|c| c as i32);
        let repeat_count: i32 = event.payload.get("repeat_count").and_then(|v| v.as_u64()).unwrap_or(1) as i32;
        let coalesced_duration_ms: Option<i64> = event.payload.get("coalesced_duration_ms").and_then(|v| v.as_u64()).map(|u| u as i64);
        let attribution_details_json: Option<String> = event
            .attribution_details_json
            .as_ref()
            .and_then(|v| serde_json::to_string(v).ok());
        sqlx::query(
            r#"
            INSERT INTO events (id, session_id, ts, event_type, payload_json, pid, ppid, enforcement_action, attribution_reason, attribution_confidence, attributed_at, repeat_count, coalesced_duration_ms, attribution_details_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(event.id.to_string())
        .bind(&event.session_id)
        .bind(event.ts.to_string())
        .bind(event_type)
        .bind(&payload_json)
        .bind(pid)
        .bind(ppid)
        .bind(enforcement_action)
        .bind(event.attribution_reason.as_deref())
        .bind(attribution_confidence)
        .bind(&attributed_at)
        .bind(repeat_count)
        .bind(coalesced_duration_ms)
        .bind(attribution_details_json.as_deref())
        .execute(&self.pool)
        .await
        .context("Failed to insert event")?;

        Ok(())
    }

    /// Insert multiple flags
    pub async fn insert_flags(&self, flags: &[Flag]) -> Result<()> {
        for flag in flags {
            let evidence_json = serde_json::to_string(&flag.evidence)?;
            let severity = match flag.severity {
                Severity::Low => "low",
                Severity::Med => "med",
                Severity::High => "high",
                Severity::Crit => "crit",
            };
            let label = match flag.label {
                Label::SensitiveAccess => "SENSITIVE_ACCESS",
                Label::UnknownEndpoint => "UNKNOWN_ENDPOINT",
                Label::SuspiciousEgress => "SUSPICIOUS_EGRESS",
                Label::DestructiveAction => "DESTRUCTIVE_ACTION",
                Label::ExecutionRisk => "EXECUTION_RISK",
                Label::PersistenceModification => "PERSISTENCE_MODIFICATION",
                Label::ConfigTampering => "CONFIG_TAMPERING",
                Label::BulkTraversal => "BULK_TRAVERSAL",
                Label::PrivilegeEscalation => "PRIVILEGE_ESCALATION",
                Label::BenignIndexing => "BENIGN_INDEXING",
                Label::LikelyDepInstall => "LIKELY_DEP_INSTALL",
                Label::BehavioralAnomaly => "BEHAVIORAL_ANOMALY",
                Label::RepeatedRisk => "REPEATED_RISK",
                Label::EnforcementBlocked => "ENFORCEMENT_BLOCKED",
                Label::SafeModeViolation => "SAFE_MODE_VIOLATION",
                Label::EmergencyFreeze => "EMERGENCY_FREEZE",
            };

            sqlx::query(
                r#"
                INSERT INTO flags (
                    id, session_id, ts, rule_id, severity, weight,
                    label, evidence_json, message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(flag.id.to_string())
            .bind(&flag.session_id)
            .bind(
                flag.ts
                    .format(&Rfc3339)
                    .map_err(|e| anyhow::anyhow!("format flag ts: {}", e))?
                    .to_string(),
            )
            .bind(&flag.rule_id)
            .bind(severity)
            .bind(flag.weight)
            .bind(label)
            .bind(&evidence_json)
            .bind(&flag.message)
            .execute(&self.pool)
            .await
            .context("Failed to insert flag")?;
        }

        Ok(())
    }

    /// List sessions with pagination and optional time filters
    pub async fn list_sessions(
        &self,
        limit: Option<u32>,
        offset: Option<u32>,
        since: Option<&str>,
        until: Option<&str>,
    ) -> Result<Vec<SessionSummary>> {
        let limit = limit.unwrap_or(100) as i64;
        let offset = offset.unwrap_or(0) as i64;

        // Build query with optional time filters
        let mut query = r#"
            SELECT
                session_id, app, root_pid, start_ts, end_ts, last_event_ts,
                risk_score, risk_bucket, labels_json, counts_json, evidence_json, observed_roots_json,
                telemetry_confidence, dropped_events, participant_pids_count,
                drift_index, baseline_comparison_summary, enforcement_actions_count, forced_terminated, summary_json
            FROM sessions
            WHERE 1=1
        "#.to_string();

        if since.is_some() {
            query.push_str(" AND start_ts >= ?");
        }
        if until.is_some() {
            query.push_str(" AND start_ts <= ?");
        }

        query.push_str(" ORDER BY start_ts DESC LIMIT ? OFFSET ?");

        let mut query_builder = sqlx::query(&query);
        if let Some(since) = since {
            query_builder = query_builder.bind(since);
        }
        if let Some(until) = until {
            query_builder = query_builder.bind(until);
        }
        query_builder = query_builder.bind(limit).bind(offset);

        let rows = query_builder
            .fetch_all(&self.pool)
            .await
            .context("Failed to list sessions")?;

        let mut sessions = Vec::new();
        for row in rows {
            let session_id: String = row.get("session_id");
            let app: String = row.get("app");
            let root_pid: i32 = row.get("root_pid");
            let start_ts: String = row.get("start_ts");
            let end_ts: Option<String> = row.get("end_ts");
            let last_event_ts: String = row.get("last_event_ts");
            let risk_score: i32 = row.get("risk_score");
            let risk_bucket: String = row.get("risk_bucket");
            let labels_json: String = row.get("labels_json");
            let counts_json: String = row.get("counts_json");
            let evidence_json: String = row.get("evidence_json");
            let observed_roots_json: String = row.try_get::<String, &str>("observed_roots_json").unwrap_or_else(|_| "[]".to_string());

            let labels: Vec<String> = serde_json::from_str(&labels_json)?;
            let labels: Vec<Label> = labels
                .iter()
                .filter_map(|s| match s.as_str() {
                    "SENSITIVE_ACCESS" => Some(Label::SensitiveAccess),
                    "UNKNOWN_ENDPOINT" => Some(Label::UnknownEndpoint),
                    "SUSPICIOUS_EGRESS" => Some(Label::SuspiciousEgress),
                    "DESTRUCTIVE_ACTION" => Some(Label::DestructiveAction),
                    "EXECUTION_RISK" => Some(Label::ExecutionRisk),
                    "PERSISTENCE_MODIFICATION" => Some(Label::PersistenceModification),
                    "CONFIG_TAMPERING" => Some(Label::ConfigTampering),
                    "BULK_TRAVERSAL" => Some(Label::BulkTraversal),
                    "PRIVILEGE_ESCALATION" => Some(Label::PrivilegeEscalation),
                    "BENIGN_INDEXING" => Some(Label::BenignIndexing),
                    "LIKELY_DEP_INSTALL" => Some(Label::LikelyDepInstall),
                    "BEHAVIORAL_ANOMALY" => Some(Label::BehavioralAnomaly),
                    "REPEATED_RISK" => Some(Label::RepeatedRisk),
                    "ENFORCEMENT_BLOCKED" => Some(Label::EnforcementBlocked),
                    "SAFE_MODE_VIOLATION" => Some(Label::SafeModeViolation),
                    "EMERGENCY_FREEZE" => Some(Label::EmergencyFreeze),
                    _ => None,
                })
                .collect();

            let counts: Counts = serde_json::from_str(&counts_json)?;
            let evidence: Evidence = serde_json::from_str(&evidence_json)
                .unwrap_or_else(|_| Evidence::default());
            let observed_roots: Vec<String> = serde_json::from_str(&observed_roots_json)
                .unwrap_or_else(|_| Vec::new());
            let telemetry_confidence_str: String = row.get("telemetry_confidence");
            let telemetry_confidence = match telemetry_confidence_str.as_str() {
                "HIGH" => antidote_core::TelemetryConfidence::High,
                "MED" => antidote_core::TelemetryConfidence::Med,
                _ => antidote_core::TelemetryConfidence::Low,
            };
            let dropped_events: i64 = row.get("dropped_events");
            let participant_pids_count: i64 = row.get("participant_pids_count");
            let drift_index: Option<i64> = row.try_get("drift_index").ok();
            let baseline_comparison_summary: Option<String> = row.try_get("baseline_comparison_summary").ok();
            let enforcement_actions_count: i64 = row.try_get("enforcement_actions_count").unwrap_or(0);
            let forced_terminated: i64 = row.try_get("forced_terminated").unwrap_or(0);
            let summary_json: Option<String> = row.try_get("summary_json").ok();

            let risk_bucket = match risk_bucket.as_str() {
                "low" => RiskBucket::Low,
                "medium" => RiskBucket::Medium,
                "high" => RiskBucket::High,
                _ => RiskBucket::Low,
            };

            let start_ts = parse_session_ts(&start_ts);
            let end_ts = end_ts
                .as_ref()
                .and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok());
            let last_event_ts = parse_session_ts(&last_event_ts);

            sessions.push(SessionSummary {
                session_id,
                app,
                root_pid,
                start_ts,
                end_ts,
                last_event_ts,
                counts,
                risk: RiskSummary {
                    score: risk_score,
                    bucket: risk_bucket,
                },
                labels,
                evidence,
                observed_roots,
                telemetry_confidence,
                dropped_events: dropped_events as u64,
                participant_pids_count: participant_pids_count as u32,
                drift_index: drift_index.map(|i| i.clamp(0, 255) as u8),
                baseline_comparison_summary,
                enforcement_actions_count: enforcement_actions_count.max(0) as u32,
                forced_terminated: forced_terminated != 0,
                summary_json,
            });
        }

        Ok(sessions)
    }

    /// Step 5: Get active session by root_pid (for daemon restart / reuse)
    pub async fn get_session_by_pid(&self, root_pid: i32) -> Result<Option<SessionSummary>> {
        let row = sqlx::query(
            r#"
            SELECT session_id FROM sessions
            WHERE root_pid = ? AND end_ts IS NULL
            ORDER BY start_ts DESC LIMIT 1
            "#,
        )
        .bind(root_pid)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to get session by pid")?;

        if let Some(row) = row {
            let session_id: String = row.get("session_id");
            self.get_session(&session_id).await
        } else {
            Ok(None)
        }
    }

    /// Get a specific session
    pub async fn get_session(&self, session_id: &str) -> Result<Option<SessionSummary>> {
        let row = sqlx::query(
            r#"
            SELECT
                session_id, app, root_pid, start_ts, end_ts, last_event_ts,
                risk_score, risk_bucket, labels_json, counts_json, evidence_json, observed_roots_json,
                telemetry_confidence, dropped_events, participant_pids_count,
                drift_index, baseline_comparison_summary, enforcement_actions_count, forced_terminated, summary_json
            FROM sessions
            WHERE session_id = ?
            "#,
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to get session")?;

        if let Some(row) = row {
            let session_id: String = row.get("session_id");
            let app: String = row.get("app");
            let root_pid: i32 = row.get("root_pid");
            let start_ts: String = row.get("start_ts");
            let end_ts: Option<String> = row.get("end_ts");
            let last_event_ts: String = row.get("last_event_ts");
            let risk_score: i32 = row.get("risk_score");
            let risk_bucket: String = row.get("risk_bucket");
            let labels_json: String = row.get("labels_json");
            let counts_json: String = row.get("counts_json");
            let evidence_json: String = row.get("evidence_json");
            let observed_roots_json: String = row.try_get::<String, &str>("observed_roots_json").unwrap_or_else(|_| "[]".to_string());

            let labels: Vec<String> = serde_json::from_str(&labels_json)?;
            let labels: Vec<Label> = labels
                .iter()
                .filter_map(|s| match s.as_str() {
                    "SENSITIVE_ACCESS" => Some(Label::SensitiveAccess),
                    "UNKNOWN_ENDPOINT" => Some(Label::UnknownEndpoint),
                    "SUSPICIOUS_EGRESS" => Some(Label::SuspiciousEgress),
                    "DESTRUCTIVE_ACTION" => Some(Label::DestructiveAction),
                    "EXECUTION_RISK" => Some(Label::ExecutionRisk),
                    "PERSISTENCE_MODIFICATION" => Some(Label::PersistenceModification),
                    "CONFIG_TAMPERING" => Some(Label::ConfigTampering),
                    "BULK_TRAVERSAL" => Some(Label::BulkTraversal),
                    "PRIVILEGE_ESCALATION" => Some(Label::PrivilegeEscalation),
                    "BENIGN_INDEXING" => Some(Label::BenignIndexing),
                    "LIKELY_DEP_INSTALL" => Some(Label::LikelyDepInstall),
                    "BEHAVIORAL_ANOMALY" => Some(Label::BehavioralAnomaly),
                    "REPEATED_RISK" => Some(Label::RepeatedRisk),
                    "ENFORCEMENT_BLOCKED" => Some(Label::EnforcementBlocked),
                    "SAFE_MODE_VIOLATION" => Some(Label::SafeModeViolation),
                    "EMERGENCY_FREEZE" => Some(Label::EmergencyFreeze),
                    _ => None,
                })
                .collect();

            let counts: Counts = serde_json::from_str(&counts_json)?;
            let evidence: Evidence = serde_json::from_str(&evidence_json)
                .unwrap_or_else(|_| Evidence::default());
            let observed_roots: Vec<String> = serde_json::from_str(&observed_roots_json)
                .unwrap_or_else(|_| Vec::new());
            let telemetry_confidence_str: String = row.get("telemetry_confidence");
            let telemetry_confidence = match telemetry_confidence_str.as_str() {
                "HIGH" => antidote_core::TelemetryConfidence::High,
                "MED" => antidote_core::TelemetryConfidence::Med,
                _ => antidote_core::TelemetryConfidence::Low,
            };
            let dropped_events: i64 = row.get("dropped_events");
            let participant_pids_count: i64 = row.get("participant_pids_count");
            let drift_index: Option<i64> = row.try_get("drift_index").ok();
            let baseline_comparison_summary: Option<String> = row.try_get("baseline_comparison_summary").ok();
            let enforcement_actions_count: i64 = row.try_get("enforcement_actions_count").unwrap_or(0);
            let forced_terminated: i64 = row.try_get("forced_terminated").unwrap_or(0);
            let summary_json: Option<String> = row.try_get("summary_json").ok();

            let risk_bucket = match risk_bucket.as_str() {
                "low" => RiskBucket::Low,
                "medium" => RiskBucket::Medium,
                "high" => RiskBucket::High,
                _ => RiskBucket::Low,
            };

            let start_ts = parse_session_ts(&start_ts);
            let end_ts = end_ts
                .as_ref()
                .and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok());
            let last_event_ts = parse_session_ts(&last_event_ts);

            Ok(Some(SessionSummary {
                session_id,
                app,
                root_pid,
                start_ts,
                end_ts,
                last_event_ts,
                counts,
                risk: RiskSummary {
                    score: risk_score,
                    bucket: risk_bucket,
                },
                labels,
                evidence,
                observed_roots,
                telemetry_confidence,
                dropped_events: dropped_events as u64,
                participant_pids_count: participant_pids_count as u32,
                drift_index: drift_index.map(|i| i.clamp(0, 255) as u8),
                baseline_comparison_summary,
                enforcement_actions_count: enforcement_actions_count.max(0) as u32,
                forced_terminated: forced_terminated != 0,
                summary_json,
            }))
        } else {
            Ok(None)
        }
    }

    /// List events for a session
    pub async fn list_events(
        &self,
        session_id: &str,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<Event>> {
        let limit = limit.unwrap_or(100) as i64;
        let offset = offset.unwrap_or(0) as i64;

        let rows = sqlx::query(
            r#"
            SELECT id, session_id, ts, event_type, payload_json, enforcement_action, attribution_reason, attribution_confidence, attribution_details_json
            FROM events
            WHERE session_id = ?
            ORDER BY ts DESC
            LIMIT ? OFFSET ?
            "#,
        )
        .bind(session_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list events")?;

        let mut events = Vec::new();
        for row in rows {
            let id_str: String = row.get("id");
            let session_id_str: String = row.get("session_id");
            let ts_str: String = row.get("ts");
            let event_type_str: String = row.get("event_type");
            let payload_json: String = row.get("payload_json");
            let enforcement_action: i64 = row.try_get("enforcement_action").unwrap_or(0);
            let attribution_reason: Option<String> = row.try_get("attribution_reason").ok();
            let attribution_confidence: Option<u8> = row
                .try_get::<Option<i64>, _>("attribution_confidence")
                .ok()
                .flatten()
                .and_then(|c| u8::try_from(c).ok());
            let attribution_details_json: Option<serde_json::Value> = row
                .try_get::<Option<String>, _>("attribution_details_json")
                .ok()
                .flatten()
                .and_then(|s| serde_json::from_str(&s).ok());

            let id = Uuid::parse_str(&id_str).context("Invalid event ID")?;
            let ts = parse_session_ts(&ts_str);
            let event_type = match event_type_str.as_str() {
                "HEARTBEAT" => EventType::Heartbeat,
                "PROC_START" => EventType::ProcStart,
                "PROC_EXIT" => EventType::ProcExit,
                "TICK" => EventType::Tick,
                "FILE_WRITE" => EventType::FileWrite,
                "FILE_CREATE" => EventType::FileCreate,
                "FILE_DELETE" => EventType::FileDelete,
                "FILE_RENAME" => EventType::FileRename,
                "FILE_READ" => EventType::FileRead,
                "NET_HTTP" => EventType::NetHttp,
                "NET_CONNECT" => EventType::NetConnect,
                "CMD_EXEC" => EventType::CmdExec,
                "PROC_SPAWN" => EventType::ProcSpawn,
                _ => EventType::Heartbeat,
            };
            let payload: serde_json::Value = serde_json::from_str(&payload_json)
                .unwrap_or_else(|_| serde_json::json!({}));

            events.push(Event {
                id,
                ts,
                session_id: session_id_str,
                event_type,
                payload,
                enforcement_action: enforcement_action != 0,
                attribution_reason,
                attribution_confidence,
                attribution_details_json,
            });
        }

        Ok(events)
    }

    /// List flags for a session
    pub async fn list_flags(
        &self,
        session_id: &str,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<Flag>> {
        let limit = limit.unwrap_or(100) as i64;
        let offset = offset.unwrap_or(0) as i64;

        let rows = sqlx::query(
            r#"
            SELECT
                id, session_id, ts, rule_id, severity, weight,
                label, evidence_json, message
            FROM flags
            WHERE session_id = ?
            ORDER BY ts DESC
            LIMIT ? OFFSET ?
            "#,
        )
        .bind(session_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .context("Failed to list flags")?;

        let mut flags = Vec::new();
        for row in rows {
            let id_str: String = row.get("id");
            let session_id_str: String = row.get("session_id");
            let ts_str: String = row.get("ts");
            let rule_id_str: String = row.get("rule_id");
            let severity_str: String = row.get("severity");
            let weight_val: i32 = row.get("weight");
            let label_str: String = row.get("label");
            let evidence_json: String = row.get("evidence_json");
            let message_str: String = row.get("message");

            let id = Uuid::parse_str(&id_str).context("Invalid flag ID")?;
            let ts = parse_session_ts(&ts_str); // Rfc3339 with fallback for legacy Display format
            let severity = match severity_str.as_str() {
                "low" => Severity::Low,
                "med" => Severity::Med,
                "high" => Severity::High,
                "crit" => Severity::Crit,
                _ => Severity::Low,
            };
            let label = match label_str.as_str() {
                "SENSITIVE_ACCESS" => Label::SensitiveAccess,
                "UNKNOWN_ENDPOINT" => Label::UnknownEndpoint,
                "SUSPICIOUS_EGRESS" => Label::SuspiciousEgress,
                "DESTRUCTIVE_ACTION" => Label::DestructiveAction,
                "EXECUTION_RISK" => Label::ExecutionRisk,
                "PERSISTENCE_MODIFICATION" => Label::PersistenceModification,
                "CONFIG_TAMPERING" => Label::ConfigTampering,
                "BULK_TRAVERSAL" => Label::BulkTraversal,
                "PRIVILEGE_ESCALATION" => Label::PrivilegeEscalation,
                "BENIGN_INDEXING" => Label::BenignIndexing,
                "LIKELY_DEP_INSTALL" => Label::LikelyDepInstall,
                "BEHAVIORAL_ANOMALY" => Label::BehavioralAnomaly,
                "REPEATED_RISK" => Label::RepeatedRisk,
                "ENFORCEMENT_BLOCKED" => Label::EnforcementBlocked,
                "SAFE_MODE_VIOLATION" => Label::SafeModeViolation,
                "EMERGENCY_FREEZE" => Label::EmergencyFreeze,
                _ => Label::ExecutionRisk,
            };
            let evidence: serde_json::Value = serde_json::from_str(&evidence_json)?;

            flags.push(Flag {
                id,
                ts,
                session_id: session_id_str,
                rule_id: rule_id_str,
                severity,
                weight: weight_val,
                label,
                evidence,
                message: message_str,
            });
        }

        Ok(flags)
    }

    /// Watched root management
    pub async fn add_watched_root(&self, path: &str) -> Result<i64> {
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|e| anyhow::anyhow!("format timestamp: {}", e))?
            .to_string();
        sqlx::query(
            r#"
            INSERT INTO watched_roots (path, enabled, added_ts, source, pinned, updated_ts)
            VALUES (?, 1, ?, 'user', 0, ?)
            "#,
        )
        .bind(path)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await
        .context("Failed to add watched root")?;

        // Get the inserted ID
        let row = sqlx::query(
            "SELECT id FROM watched_roots WHERE path = ? ORDER BY id DESC LIMIT 1"
        )
        .bind(path)
        .fetch_one(&self.pool)
        .await
        .context("Failed to get inserted root ID")?;
        Ok(row.get("id"))
    }

    pub async fn list_watched_roots(&self) -> Result<Vec<WatchedRoot>> {
        let rows = sqlx::query(
            r#"
            SELECT id, path, source, pinned, enabled, last_seen_ts, added_ts, updated_ts
            FROM watched_roots
            ORDER BY added_ts DESC
            "#
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to list watched roots")?;

        let mut roots = Vec::new();
        for row in rows {
            let id: i64 = row.get("id");
            let path: String = row.get("path");
            let source_str: String = row.try_get("source").unwrap_or_else(|_| "user".to_string());
            let source = if source_str.to_lowercase() == "auto" {
                RootSource::Auto
            } else {
                RootSource::User
            };
            let pinned: i64 = row.try_get("pinned").unwrap_or(0);
            let enabled: i64 = row.get("enabled");
            let last_seen_ts: Option<String> = row.try_get("last_seen_ts").ok();
            let added_ts: String = row.get("added_ts");
            let updated_ts: Option<String> = row.try_get("updated_ts").ok();

            let added_ts = OffsetDateTime::parse(&added_ts, &Rfc3339)
                .unwrap_or_else(|_| OffsetDateTime::now_utc());
            let last_seen_ts = last_seen_ts
                .and_then(|s| OffsetDateTime::parse(&s, &Rfc3339).ok());
            let updated_ts = updated_ts
                .and_then(|s| OffsetDateTime::parse(&s, &Rfc3339).ok())
                .unwrap_or(added_ts);

            roots.push(WatchedRoot {
                id,
                path,
                source,
                pinned: pinned != 0,
                enabled: enabled != 0,
                last_seen_ts,
                added_ts,
                updated_ts,
            });
        }
        Ok(roots)
    }

    pub async fn get_enabled_roots(&self) -> Result<Vec<String>> {
        let rows = sqlx::query(
            r#"
            SELECT path
            FROM watched_roots
            WHERE enabled = 1
            ORDER BY added_ts DESC
            "#
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to get enabled roots")?;

        Ok(rows.into_iter().map(|r| r.get::<String, _>("path")).collect())
    }

    pub async fn delete_watched_root(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM watched_roots WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to delete watched root")?;
        Ok(())
    }

    pub async fn set_watched_root_enabled(&self, id: i64, enabled: bool) -> Result<()> {
        let enabled_val = if enabled { 1 } else { 0 };
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|e| anyhow::anyhow!("format timestamp: {}", e))?
            .to_string();
        sqlx::query("UPDATE watched_roots SET enabled = ?, updated_ts = ? WHERE id = ?")
            .bind(enabled_val)
            .bind(&now)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update watched root")?;
        Ok(())
    }

    /// Get a watched root by exact path (normalized).
    pub async fn get_watched_root_by_path(&self, path: &str) -> Result<Option<WatchedRoot>> {
        let row = sqlx::query(
            r#"
            SELECT id, path, source, pinned, enabled, last_seen_ts, added_ts, updated_ts
            FROM watched_roots
            WHERE path = ?
            "#
        )
        .bind(path)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to get watched root by path")?;
        let row = match row {
            Some(r) => r,
            None => return Ok(None),
        };
        let id: i64 = row.get("id");
        let path: String = row.get("path");
        let source_str: String = row.get("source");
        let source = if source_str.to_lowercase() == "auto" {
            RootSource::Auto
        } else {
            RootSource::User
        };
        let pinned: i64 = row.get("pinned");
        let enabled: i64 = row.get("enabled");
        let last_seen_ts: Option<String> = row.try_get("last_seen_ts").ok();
        let added_ts: String = row.get("added_ts");
        let updated_ts: Option<String> = row.try_get("updated_ts").ok();
        let added_ts = OffsetDateTime::parse(&added_ts, &Rfc3339)
            .unwrap_or_else(|_| OffsetDateTime::now_utc());
        let last_seen_ts = last_seen_ts.and_then(|s| OffsetDateTime::parse(&s, &Rfc3339).ok());
        let updated_ts = updated_ts
            .and_then(|s| OffsetDateTime::parse(&s, &Rfc3339).ok())
            .unwrap_or(added_ts);
        Ok(Some(WatchedRoot {
            id,
            path,
            source,
            pinned: pinned != 0,
            enabled: enabled != 0,
            last_seen_ts,
            added_ts,
            updated_ts,
        }))
    }

    /// Upsert an auto root: insert if new, or update last_seen_ts (and optionally enabled) if exists.
    /// Does not change source from 'user' to 'auto'. Does not enable a user-disabled root.
    pub async fn upsert_auto_root(&self, path: &str) -> Result<()> {
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|e| anyhow::anyhow!("format timestamp: {}", e))?
            .to_string();
        let existing = self.get_watched_root_by_path(path).await?;
        match existing {
            Some(ref r) => {
                if r.source == RootSource::User {
                    return Ok(());
                }
                sqlx::query(
                    "UPDATE watched_roots SET last_seen_ts = ?, updated_ts = ?, enabled = 1 WHERE path = ? AND source = 'auto'",
                )
                .bind(&now)
                .bind(&now)
                .bind(path)
                .execute(&self.pool)
                .await
                .context("Failed to update auto root")?;
            }
            None => {
                sqlx::query(
                    r#"
                    INSERT INTO watched_roots (path, enabled, added_ts, source, pinned, last_seen_ts, updated_ts)
                    VALUES (?, 1, ?, 'auto', 0, ?, ?)
                    "#,
                )
                .bind(path)
                .bind(&now)
                .bind(&now)
                .bind(&now)
                .execute(&self.pool)
                .await
                .context("Failed to insert auto root")?;
            }
        }
        Ok(())
    }

    /// Disable stale auto roots not seen for longer than the given cutoff (and not pinned).
    pub async fn disable_stale_auto_roots(&self, cutoff_ts: &str) -> Result<u64> {
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|e| anyhow::anyhow!("format timestamp: {}", e))?
            .to_string();
        let result = sqlx::query(
            "UPDATE watched_roots SET enabled = 0, updated_ts = ? WHERE source = 'auto' AND pinned = 0 AND enabled = 1 AND (last_seen_ts IS NULL OR last_seen_ts < ?)",
        )
        .bind(&now)
        .bind(cutoff_ts)
        .execute(&self.pool)
        .await
        .context("Failed to disable stale auto roots")?;
        Ok(result.rows_affected())
    }

    /// Count enabled auto roots (source='auto', pinned=0, enabled=1).
    pub async fn count_enabled_auto_roots(&self) -> Result<i64> {
        let row = sqlx::query(
            "SELECT COUNT(*) as c FROM watched_roots WHERE source = 'auto' AND pinned = 0 AND enabled = 1",
        )
        .fetch_one(&self.pool)
        .await
        .context("Failed to count enabled auto roots")?;
        Ok(row.get::<i64, _>("c"))
    }

    /// Get enabled auto roots ordered by last_seen_ts ascending (oldest first) for cap enforcement.
    pub async fn get_enabled_auto_roots_oldest_first(&self) -> Result<Vec<(i64, String)>> {
        let rows = sqlx::query(
            r#"
            SELECT id, path FROM watched_roots
            WHERE source = 'auto' AND pinned = 0 AND enabled = 1
            ORDER BY COALESCE(last_seen_ts, '1970-01-01') ASC, id ASC
            "#
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to list enabled auto roots")?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get("id"), r.get("path")))
            .collect())
    }

    /// Phase 5: App baselines (behavioral)
    pub async fn get_app_baseline(&self, app: &str) -> Result<Option<AppBaselineRow>> {
        let row = sqlx::query_as::<_, AppBaselineRow>(
            "SELECT app, session_count, avg_files_written, avg_files_deleted, avg_bytes_out, avg_unknown_domains, avg_cmds, var_files_written, var_bytes_out, var_unknown_domains, var_cmds, last_updated FROM app_baselines WHERE app = ?",
        )
        .bind(app)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to get app baseline")?;
        Ok(row)
    }

    pub async fn upsert_app_baseline(&self, row: &AppBaselineRow) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO app_baselines (app, session_count, avg_files_written, avg_files_deleted, avg_bytes_out, avg_unknown_domains, avg_cmds, var_files_written, var_bytes_out, var_unknown_domains, var_cmds, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(app) DO UPDATE SET
                session_count = excluded.session_count,
                avg_files_written = excluded.avg_files_written,
                avg_files_deleted = excluded.avg_files_deleted,
                avg_bytes_out = excluded.avg_bytes_out,
                avg_unknown_domains = excluded.avg_unknown_domains,
                avg_cmds = excluded.avg_cmds,
                var_files_written = excluded.var_files_written,
                var_bytes_out = excluded.var_bytes_out,
                var_unknown_domains = excluded.var_unknown_domains,
                var_cmds = excluded.var_cmds,
                last_updated = excluded.last_updated
            "#,
        )
        .bind(&row.app)
        .bind(row.session_count as i64)
        .bind(row.avg_files_written)
        .bind(row.avg_files_deleted)
        .bind(row.avg_bytes_out)
        .bind(row.avg_unknown_domains)
        .bind(row.avg_cmds)
        .bind(row.var_files_written)
        .bind(row.var_bytes_out)
        .bind(row.var_unknown_domains)
        .bind(row.var_cmds)
        .bind(&row.last_updated)
        .execute(&self.pool)
        .await
        .context("Failed to upsert app baseline")?;
        Ok(())
    }

    pub async fn get_all_baselines(&self) -> Result<Vec<AppBaselineRow>> {
        let rows = sqlx::query_as::<_, AppBaselineRow>(
            "SELECT app, session_count, avg_files_written, avg_files_deleted, avg_bytes_out, avg_unknown_domains, avg_cmds, var_files_written, var_bytes_out, var_unknown_domains, var_cmds, last_updated FROM app_baselines",
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to list baselines")?;
        Ok(rows)
    }

    /// Phase 5: Risk history (cross-session escalation)
    pub async fn record_risk_history(&self, app: &str, rule_id: &str, ts: OffsetDateTime) -> Result<()> {
        let ts_str = ts
            .format(&Rfc3339)
            .map_err(|e| anyhow::anyhow!("format ts: {}", e))?
            .to_string();
        sqlx::query(
            r#"
            INSERT INTO risk_history (app, rule_id, first_seen, last_seen, count)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(app, rule_id) DO UPDATE SET
                last_seen = excluded.last_seen,
                count = count + 1
            "#,
        )
        .bind(app)
        .bind(rule_id)
        .bind(&ts_str)
        .bind(&ts_str)
        .execute(&self.pool)
        .await
        .context("Failed to record risk history")?;
        Ok(())
    }

    /// Returns (rule_id, count) for app in last n days. Used for escalation.
    pub async fn get_risk_history_last_n_days(
        &self,
        app: &str,
        days: i64,
    ) -> Result<Vec<(String, u32)>> {
        let cutoff = OffsetDateTime::now_utc() - time::Duration::days(days);
        let cutoff_str = cutoff
            .format(&Rfc3339)
            .map_err(|e| anyhow::anyhow!("format cutoff: {}", e))?
            .to_string();
        let rows = sqlx::query(
            "SELECT rule_id, count FROM risk_history WHERE app = ? AND last_seen >= ?",
        )
        .bind(app)
        .bind(&cutoff_str)
        .fetch_all(&self.pool)
        .await
        .context("Failed to get risk history")?;
        let out: Vec<(String, u32)> = rows
            .into_iter()
            .map(|r| {
                let rule_id: String = r.get("rule_id");
                let count: i64 = r.get("count");
                (rule_id, count.max(0) as u32)
            })
            .collect();
        Ok(out)
    }

    pub async fn prune_risk_history_older_than(&self, cutoff_ts: OffsetDateTime) -> Result<u64> {
        let cutoff_str = cutoff_ts
            .format(&Rfc3339)
            .map_err(|e| anyhow::anyhow!("format cutoff: {}", e))?
            .to_string();
        let result = sqlx::query("DELETE FROM risk_history WHERE last_seen < ?")
            .bind(&cutoff_str)
            .execute(&self.pool)
            .await
            .context("Failed to prune risk history")?;
        Ok(result.rows_affected())
    }

    /// All risk history entries with last_seen >= cutoff (for insights).
    pub async fn get_risk_history_since(
        &self,
        cutoff_ts: OffsetDateTime,
    ) -> Result<Vec<(String, String, u32)>> {
        let cutoff_str = cutoff_ts
            .format(&Rfc3339)
            .map_err(|e| anyhow::anyhow!("format cutoff: {}", e))?
            .to_string();
        let rows = sqlx::query("SELECT app, rule_id, count FROM risk_history WHERE last_seen >= ?")
            .bind(&cutoff_str)
            .fetch_all(&self.pool)
            .await
            .context("Failed to get risk history")?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let app: String = r.get("app");
                let rule_id: String = r.get("rule_id");
                let count: i64 = r.get("count");
                (app, rule_id, count.max(0) as u32)
            })
            .collect())
    }

    /// Retention/pruning functions
    pub async fn prune_events_older_than(&self, cutoff_ts: OffsetDateTime) -> Result<u64> {
        let cutoff_str = cutoff_ts.to_string();
        let result = sqlx::query("DELETE FROM events WHERE ts < ?")
            .bind(&cutoff_str)
            .execute(&self.pool)
            .await
            .context("Failed to prune events")?;
        Ok(result.rows_affected())
    }

    pub async fn prune_flags_older_than(&self, cutoff_ts: OffsetDateTime) -> Result<u64> {
        let cutoff_str = cutoff_ts
            .format(&Rfc3339)
            .map_err(|e| anyhow::anyhow!("format cutoff: {}", e))?
            .to_string();
        let result = sqlx::query("DELETE FROM flags WHERE ts < ?")
            .bind(&cutoff_str)
            .execute(&self.pool)
            .await
            .context("Failed to prune flags")?;
        Ok(result.rows_affected())
    }
}

/// Phase 5: App baseline row (DB representation)
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct AppBaselineRow {
    pub app: String,
    pub session_count: i64,
    pub avg_files_written: f64,
    pub avg_files_deleted: f64,
    pub avg_bytes_out: f64,
    pub avg_unknown_domains: f64,
    pub avg_cmds: f64,
    pub var_files_written: f64,
    pub var_bytes_out: f64,
    pub var_unknown_domains: f64,
    pub var_cmds: f64,
    pub last_updated: String,
}

/// Source of a watched root (user-added or auto-detected).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RootSource {
    User,
    Auto,
}

impl RootSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            RootSource::User => "user",
            RootSource::Auto => "auto",
        }
    }
}

/// Watched root representation
#[derive(Debug, Clone, serde::Serialize)]
pub struct WatchedRoot {
    pub id: i64,
    pub path: String,
    pub source: RootSource,
    pub pinned: bool,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_ts: Option<OffsetDateTime>,
    pub added_ts: OffsetDateTime,
    pub updated_ts: OffsetDateTime,
}
