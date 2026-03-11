//! FocusManager: maps foreground app to ForegroundContext (session_id, workspace_roots, confidence).
//! Step 7: Configurable stabilization window; optionally uses AttributionState for stabilization.

#[cfg(target_os = "macos")]
use antidote_collectors::{app_kind_from_name, ForegroundApp, WorkspaceResolverState};
use antidote_core::{ForegroundContext, FocusConfidence};
use antidote_session::SessionManager;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::RwLock;

use crate::attribution_state::AttributionState;

/// FocusManager: polls foreground state and resolves to session_id + roots.
pub struct FocusManager {
    #[cfg(target_os = "macos")]
    foreground_state: Arc<RwLock<Option<ForegroundApp>>>,
    #[cfg(target_os = "macos")]
    workspace_state: Option<Arc<RwLock<WorkspaceResolverState>>>,
    session_manager: Arc<SessionManager>,
    context: Arc<RwLock<ForegroundContext>>,
    /// Step 7: Optional AttributionState for stabilization (candidate/committed flow)
    attribution_state: Option<Arc<AttributionState>>,
    /// Fallback: last (app_name, pid) we saw; used when attribution_state is None
    last_seen: Arc<RwLock<Option<(String, Option<i32>)>>>,
    last_switch_at: Arc<RwLock<OffsetDateTime>>,
}

impl FocusManager {
    #[cfg(target_os = "macos")]
    pub fn new(
        foreground_state: Arc<RwLock<Option<ForegroundApp>>>,
        workspace_state: Option<Arc<RwLock<WorkspaceResolverState>>>,
        session_manager: Arc<SessionManager>,
        attribution_state: Option<Arc<AttributionState>>,
    ) -> Self {
        Self {
            foreground_state,
            workspace_state,
            session_manager,
            context: Arc::new(RwLock::new(ForegroundContext::default())),
            attribution_state,
            last_seen: Arc::new(RwLock::new(None)),
            last_switch_at: Arc::new(RwLock::new(OffsetDateTime::UNIX_EPOCH)),
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn new(_: (), _: (), session_manager: Arc<SessionManager>, _: Option<Arc<AttributionState>>) -> Self {
        Self {
            session_manager,
            context: Arc::new(RwLock::new(ForegroundContext::default())),
            attribution_state: None,
            last_seen: Arc::new(RwLock::new(None)),
            last_switch_at: Arc::new(RwLock::new(OffsetDateTime::UNIX_EPOCH)),
        }
    }

    pub fn context(&self) -> Arc<RwLock<ForegroundContext>> {
        Arc::clone(&self.context)
    }

    #[cfg(target_os = "macos")]
    pub async fn run(
        self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) {
        let mut ticker = tokio::time::interval(Duration::from_millis(500));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    self.tick().await;
                }
                _ = shutdown_rx.recv() => break,
            }
        }
    }

    #[cfg(target_os = "macos")]
    async fn tick(&self) {
        let app = self.foreground_state.read().await.clone();
        let Some(ref fg) = app else {
            *self.context.write().await = ForegroundContext::default();
            return;
        };

        let now = OffsetDateTime::now_utc();
        let app_name = fg.name.clone();
        let pid = fg.pid;

        if let Some(ref attr) = self.attribution_state {
            let committed = attr.record_foreground_candidate(app_name, pid, now).await;
            if !committed {
                return;
            }
        } else {
            let key = (app_name.clone(), pid);
            let mut last = self.last_seen.write().await;
            if last.as_ref() != Some(&key) {
                let mut last_switch = self.last_switch_at.write().await;
                *last_switch = now;
                *last = Some(key);
            }
            drop(last);
            let last_switch = *self.last_switch_at.read().await;
            let elapsed_ms = (now - last_switch).whole_milliseconds();
            if elapsed_ms < 700 {
                return;
            }
        }

        let app_kind = app_kind_from_name(&fg.name);
        let app_str = app_kind.as_ref().map(|k| k.as_display_str().to_string());

        let session_id = self.resolve_session_id(app_kind.clone(), fg.pid).await;

        // Workspace roots are decoupled from sessions; use all roots from resolver (Cursor windows)
        let workspace_roots = if let Some(ref ws) = &self.workspace_state {
            let state = ws.read().await;
            state
                .items
                .iter()
                .flat_map(|i| i.roots.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect()
        } else {
            Vec::new()
        };
        let confidence = self.compute_confidence(
            app_kind.is_some(),
            session_id.is_some(),
            !workspace_roots.is_empty(),
        );

        *self.context.write().await = ForegroundContext {
            app: app_str,
            pid: fg.pid,
            workspace_roots,
            session_id,
            confidence,
            workspace_confidence: confidence,
            observed_at: now,
        };
    }

    fn compute_confidence(
        &self,
        app_recognized: bool,
        session_found: bool,
        has_roots: bool,
    ) -> FocusConfidence {
        if app_recognized && session_found && has_roots {
            FocusConfidence::High
        } else if app_recognized && session_found {
            FocusConfidence::Medium
        } else {
            FocusConfidence::Low
        }
    }

    #[cfg(target_os = "macos")]
    async fn resolve_session_id(
        &self,
        app_kind: Option<antidote_collectors::AppKind>,
        pid: Option<i32>,
    ) -> Option<String> {
        use antidote_collectors::AppKind;
        if app_kind.is_none() {
            return None;
        }
        let app_kind = app_kind.unwrap();

        if let Some(pid) = pid {
            if let Some(sid) = self.session_manager.get_session_for_pid(pid).await {
                return Some(sid);
            }
            if matches!(app_kind, AppKind::Cursor) {
                let sid = self.session_manager.ensure_cursor_session(pid).await;
                return Some(sid);
            }
        }

        let active = self.session_manager.get_active_sessions().await;
        let cutoff = OffsetDateTime::now_utc() - time::Duration::minutes(15);
        let matching: Vec<_> = active
            .into_iter()
            .filter(|s| {
                s.end_ts.is_none()
                    && s.last_event_ts >= cutoff
                    && app_name_matches(&s.app, &app_kind)
            })
            .collect();
        matching
            .into_iter()
            .max_by_key(|s| s.last_event_ts)
            .map(|s| s.session_id)
    }
}

fn app_name_matches(app: &str, kind: &antidote_collectors::AppKind) -> bool {
    let a = app.to_lowercase();
    match kind {
        antidote_collectors::AppKind::Cursor => a == "cursor",
        antidote_collectors::AppKind::VSCode => a.contains("code") || a.contains("vscode"),
        antidote_collectors::AppKind::Claude => a.contains("claude"),
        antidote_collectors::AppKind::Unknown(_) => false,
    }
}

#[cfg(not(target_os = "macos"))]
impl FocusManager {
    pub async fn run(
        self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) {
        let _ = shutdown_rx.recv().await;
    }
}
