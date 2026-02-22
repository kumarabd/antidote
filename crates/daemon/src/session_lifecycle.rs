//! Step 5: Session lifecycle automation - create on AppStarted, end on AppExited, idle rotation.

use anyhow::Result;
use std::future::Future;
use std::pin::Pin;

#[cfg(target_os = "macos")]
use antidote_collectors::{AppEvent, AppKind};
use antidote_core::{Counts, SessionSummary};
use antidote_session::SessionManager;
use antidote_storage::Storage;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tracing::{info, warn};

/// Callback invoked when a session is finalized (for baseline, anomaly, etc.)
pub type OnFinalizeCallback = Arc<
    dyn Fn(SessionSummary) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync,
>;

/// Step 5: Manages session lifecycle from AppEvents (macOS) and idle rotation.
pub struct SessionLifecycleManager {
    session_manager: Arc<SessionManager>,
    storage: Arc<Storage>,
    idle_timeout_minutes: u64,
    on_finalize: Option<OnFinalizeCallback>,
}

impl SessionLifecycleManager {
    pub fn new(
        session_manager: Arc<SessionManager>,
        storage: Arc<Storage>,
        idle_timeout_minutes: u64,
    ) -> Self {
        Self {
            session_manager,
            storage,
            idle_timeout_minutes,
            on_finalize: None,
        }
    }

    pub fn with_on_finalize(mut self, cb: OnFinalizeCallback) -> Self {
        self.on_finalize = Some(cb);
        self
    }

    #[cfg(target_os = "macos")]
    pub async fn handle_app_event(&self, ev: AppEvent) {
        match ev {
            AppEvent::Started { app, pid, process_name, .. } => self.handle_started(app, pid, process_name.as_deref()).await,
            AppEvent::Exited { app, pid, .. } => self.handle_exited(app, pid).await,
            AppEvent::ScanComplete { .. } => {}
        }
    }

    #[cfg(target_os = "macos")]
    async fn handle_started(&self, app: AppKind, pid: i32, process_name: Option<&str>) {
        // Cursor/VSCode: only create sessions for renderer processes (one per window), not main process
        if matches!(app, AppKind::Cursor | AppKind::VSCode) {
            let name_lower = process_name.unwrap_or("").to_lowercase();
            let is_main = name_lower == "cursor"
                || name_lower == "code"
                || name_lower == "visual studio code";
            if is_main {
                return;
            }
        }
        let app_str = app.as_display_str().to_string();

        if self.session_manager.get_session_for_pid(pid).await.is_some() {
            return;
        }

        if let Ok(Some(existing)) = self.storage.get_session_by_pid(pid).await {
            if existing.end_ts.is_none() {
                self.session_manager
                    .register_session_from_app(existing.session_id, existing.app, pid)
                    .await;
                return;
            }
        }

        let session_id = uuid::Uuid::new_v4().to_string();
        let now = OffsetDateTime::now_utc();
        let summary = SessionSummary {
            session_id: session_id.clone(),
            app: app_str.clone(),
            root_pid: pid,
            start_ts: now,
            end_ts: None,
            last_event_ts: now,
            counts: Counts::default(),
            risk: antidote_core::RiskSummary::new(0),
            labels: Vec::new(),
            evidence: antidote_core::Evidence::default(),
            observed_roots: Vec::new(),
            telemetry_confidence: antidote_core::TelemetryConfidence::Low,
            dropped_events: 0,
            participant_pids_count: 0,
            drift_index: None,
            baseline_comparison_summary: None,
            enforcement_actions_count: 0,
            forced_terminated: false,
            summary_json: None,
        };

        if let Err(e) = self.storage.upsert_session_summary(&summary).await {
            warn!("Failed to insert session: {}", e);
            return;
        }

        self.session_manager
            .register_session_from_app(session_id.clone(), app_str, pid)
            .await;

        info!("Session started: {} for {} pid={}", session_id, app.as_display_str(), pid);
    }

    #[cfg(target_os = "macos")]
    async fn handle_exited(&self, _app: AppKind, pid: i32) {
        let Some(session_id) = self.session_manager.end_session_for_pid(pid).await else {
            return;
        };

        let now = OffsetDateTime::now_utc();
        if let Err(e) = self.finalize_session(&session_id, now).await {
            warn!("Failed to finalize session {}: {}", session_id, e);
        }
        info!("Session ended: {}", session_id);
    }

    pub async fn finalize_session(&self, session_id: &str, ended_at: OffsetDateTime) -> Result<SessionSummary> {
        let summary = self.storage.finalize_session(session_id, ended_at).await?;
        info!(
            "Session finalized: id={}, duration={}s, writes={}, net={}",
            session_id,
            summary.counts.events_total,
            summary.counts.files_written,
            summary.counts.domains
        );
        if let Some(ref cb) = self.on_finalize {
            let s = summary.clone();
            tokio::spawn((cb)(s));
        }
        Ok(summary)
    }

    pub async fn run_idle_rotation(&self) -> Vec<SessionSummary> {
        let mut finalized = Vec::new();
        let active = self.session_manager.get_active_sessions_with_roots().await;
        let now = OffsetDateTime::now_utc();
        let timeout = Duration::from_secs(self.idle_timeout_minutes * 60);

        for (summary, _roots) in active {
            if summary.end_ts.is_some() {
                continue;
            }
            if summary.counts.events_total == 0 {
                continue;
            }
            let elapsed = now - summary.last_event_ts;
            if elapsed <= timeout {
                continue;
            }

            let session_id = summary.session_id.clone();
            let app = summary.app.clone();
            let root_pid = summary.root_pid;

            let _ = self.session_manager.end_session_for_pid(root_pid).await;
            match self.finalize_session(&session_id, now).await {
                Ok(s) => finalized.push(s),
                Err(e) => warn!("Failed to finalize idle session {}: {}", session_id, e),
            }

            let new_id = uuid::Uuid::new_v4().to_string();
            let new_summary = SessionSummary {
                session_id: new_id.clone(),
                app: app.clone(),
                root_pid,
                start_ts: now,
                end_ts: None,
                last_event_ts: now,
                counts: Counts::default(),
                risk: antidote_core::RiskSummary::new(0),
                labels: Vec::new(),
                evidence: antidote_core::Evidence::default(),
                observed_roots: Vec::new(),
                telemetry_confidence: antidote_core::TelemetryConfidence::Low,
                dropped_events: 0,
                participant_pids_count: 0,
                drift_index: None,
                baseline_comparison_summary: None,
                enforcement_actions_count: 0,
                forced_terminated: false,
                summary_json: None,
            };

            if self.storage.upsert_session_summary(&new_summary).await.is_ok() {
                self.session_manager
                    .register_session_from_app(new_id.clone(), app, root_pid)
                    .await;
                info!("Idle rotation: ended {}, started {}", session_id, new_id);
            }
        }
        finalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db_url() -> String {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("antidote_test_{}.db", std::process::id()));
        format!("sqlite:{}", path.display())
    }

    #[tokio::test]
    async fn test_session_creation_no_duplicate() {
        let storage = Arc::new(
            Storage::init(&temp_db_url())
                .await
                .expect("init"),
        );
        let session_manager = Arc::new(SessionManager::new(
            vec!["Cursor".to_string()],
            20,
        ));
        let lifecycle = SessionLifecycleManager::new(
            session_manager.clone(),
            storage.clone(),
            20,
        );

        #[cfg(target_os = "macos")]
        {
            lifecycle
                .handle_app_event(antidote_collectors::AppEvent::Started {
                    app: antidote_collectors::AppKind::Cursor,
                    pid: 12345,
                    process_name: Some("Cursor Helper (Renderer)".to_string()),
                    bundle_id: None,
                    started_at: time::OffsetDateTime::now_utc(),
                })
                .await;

            let active = session_manager.get_active_sessions().await;
            assert_eq!(active.len(), 1);
            assert_eq!(active[0].root_pid, 12345);
            assert_eq!(active[0].app, "Cursor");

            lifecycle
                .handle_app_event(antidote_collectors::AppEvent::Started {
                    app: antidote_collectors::AppKind::Cursor,
                    pid: 12345,
                    process_name: Some("Cursor Helper (Renderer)".to_string()),
                    bundle_id: None,
                    started_at: time::OffsetDateTime::now_utc(),
                })
                .await;

            let active2 = session_manager.get_active_sessions().await;
            assert_eq!(active2.len(), 1);
        }
    }

    #[tokio::test]
    async fn test_cursor_main_process_no_session() {
        let storage = Arc::new(
            Storage::init(&temp_db_url())
                .await
                .expect("init"),
        );
        let session_manager = Arc::new(SessionManager::new(
            vec!["Cursor".to_string()],
            20,
        ));
        let lifecycle = SessionLifecycleManager::new(
            session_manager.clone(),
            storage.clone(),
            20,
        );

        #[cfg(target_os = "macos")]
        {
            lifecycle
                .handle_app_event(antidote_collectors::AppEvent::Started {
                    app: antidote_collectors::AppKind::Cursor,
                    pid: 11111,
                    process_name: Some("Cursor".to_string()),
                    bundle_id: None,
                    started_at: time::OffsetDateTime::now_utc(),
                })
                .await;

            let active = session_manager.get_active_sessions().await;
            assert_eq!(active.len(), 0, "main Cursor process should not create a session");
        }
    }

    #[tokio::test]
    async fn test_session_end_on_exit() {
        let storage = Arc::new(
            Storage::init(&temp_db_url())
                .await
                .expect("init"),
        );
        let session_manager = Arc::new(SessionManager::new(
            vec!["Cursor".to_string()],
            20,
        ));
        let lifecycle = SessionLifecycleManager::new(
            session_manager.clone(),
            storage.clone(),
            20,
        );

        #[cfg(target_os = "macos")]
        {
            lifecycle
                .handle_app_event(antidote_collectors::AppEvent::Started {
                    app: antidote_collectors::AppKind::Cursor,
                    pid: 99999,
                    process_name: Some("Cursor Helper (Renderer)".to_string()),
                    bundle_id: None,
                    started_at: time::OffsetDateTime::now_utc(),
                })
                .await;

            let sid = session_manager.get_session_for_pid(99999).await.unwrap();

            lifecycle
                .handle_app_event(antidote_collectors::AppEvent::Exited {
                    app: antidote_collectors::AppKind::Cursor,
                    pid: 99999,
                    exited_at: time::OffsetDateTime::now_utc(),
                })
                .await;

            assert!(session_manager.get_session_for_pid(99999).await.is_none());
            let s = storage.get_session(&sid).await.unwrap().unwrap();
            assert!(s.end_ts.is_some());
            assert!(s.summary_json.is_some());
        }
    }
}
