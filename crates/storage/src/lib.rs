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

        sqlx::query(
            r#"
            INSERT INTO sessions (
                session_id, app, root_pid, start_ts, end_ts, last_event_ts,
                risk_score, risk_bucket, labels_json, counts_json, evidence_json, observed_roots_json,
                telemetry_confidence, dropped_events, participant_pids_count, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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

        sqlx::query(
            r#"
            INSERT INTO events (id, session_id, ts, event_type, payload_json, pid, ppid)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(event.id.to_string())
        .bind(&event.session_id)
        .bind(event.ts.to_string())
        .bind(event_type)
        .bind(&payload_json)
        .bind(pid)
        .bind(ppid)
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
                telemetry_confidence, dropped_events, participant_pids_count
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
            });
        }

        Ok(sessions)
    }

    /// Get a specific session
    pub async fn get_session(&self, session_id: &str) -> Result<Option<SessionSummary>> {
        let row = sqlx::query(
            r#"
            SELECT
                session_id, app, root_pid, start_ts, end_ts, last_event_ts,
                risk_score, risk_bucket, labels_json, counts_json, evidence_json, observed_roots_json,
                telemetry_confidence, dropped_events, participant_pids_count
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
            SELECT id, session_id, ts, event_type, payload_json
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

            let id = Uuid::parse_str(&id_str).context("Invalid event ID")?;
            let ts = OffsetDateTime::parse(
                &ts_str,
                &time::format_description::well_known::Rfc3339,
            )
            .context("Failed to parse event timestamp")?;
            let event_type = match event_type_str.as_str() {
                "HEARTBEAT" => EventType::Heartbeat,
                "FILE_WRITE" => EventType::FileWrite,
                "FILE_DELETE" => EventType::FileDelete,
                "NET_HTTP" => EventType::NetHttp,
                "CMD_EXEC" => EventType::CmdExec,
                "PROC_SPAWN" => EventType::ProcSpawn,
                _ => EventType::Heartbeat,
            };
            let payload: serde_json::Value = serde_json::from_str(&payload_json)?;

            events.push(Event {
                id,
                ts,
                session_id: session_id_str,
                event_type,
                payload,
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
            INSERT INTO watched_roots (path, enabled, added_ts)
            VALUES (?, 1, ?)
            "#,
        )
        .bind(path)
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
            SELECT id, path, enabled, added_ts
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
            let enabled: i64 = row.get("enabled");
            let added_ts: String = row.get("added_ts");

            let added_ts = OffsetDateTime::parse(&added_ts, &Rfc3339)
                .unwrap_or_else(|_| OffsetDateTime::now_utc()); // fallback if stored with pre-Rfc3339 format

            roots.push(WatchedRoot {
                id,
                path,
                enabled: enabled != 0,
                added_ts,
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
        sqlx::query("UPDATE watched_roots SET enabled = ? WHERE id = ?")
            .bind(enabled_val)
            .bind(id)
            .execute(&self.pool)
            .await
            .context("Failed to update watched root")?;
        Ok(())
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

/// Watched root representation
#[derive(Debug, Clone, serde::Serialize)]
pub struct WatchedRoot {
    pub id: i64,
    pub path: String,
    pub enabled: bool,
    pub added_ts: OffsetDateTime,
}
