//! Session management for Antidote

use antidote_core::{Event, EventType, SessionSummary};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Session state tracked by the manager
#[derive(Debug, Clone)]
pub struct SessionState {
    pub summary: SessionSummary,
    pub last_event_ts: time::OffsetDateTime,
    /// Candidate roots (watched roots at session start)
    pub candidate_roots: Vec<String>,
    /// Observed roots (roots that saw events)
    pub observed_roots: std::collections::HashSet<String>,
}

impl SessionState {
    pub fn new(session_id: String, app: String, root_pid: i32) -> Self {
        let now = time::OffsetDateTime::now_utc();
        Self {
            summary: SessionSummary::new(session_id, app, root_pid),
            last_event_ts: now,
            candidate_roots: Vec::new(),
            observed_roots: std::collections::HashSet::new(),
        }
    }

    pub fn with_candidate_roots(mut self, roots: Vec<String>) -> Self {
        self.candidate_roots = roots;
        self
    }

    pub fn add_observed_root(&mut self, root: String) {
        self.observed_roots.insert(root);
        // Update summary
        self.summary.observed_roots = self.observed_roots.iter().cloned().collect();
    }

    pub fn update_last_event(&mut self) {
        self.last_event_ts = time::OffsetDateTime::now_utc();
        self.summary.last_event_ts = self.last_event_ts;
    }

    pub fn end(&mut self) {
        self.summary.end_ts = Some(time::OffsetDateTime::now_utc());
    }

    /// Phase 6: Mark session as force-terminated (emergency freeze)
    pub fn force_terminate(&mut self) {
        let now = time::OffsetDateTime::now_utc();
        self.summary.end_ts = Some(now);
        self.summary.last_event_ts = now;
        self.summary.forced_terminated = true;
    }

    pub fn is_active(&self) -> bool {
        self.summary.end_ts.is_none()
    }
}

/// Session manager that handles session lifecycle
pub struct SessionManager {
    /// Mapping from root_pid to session_id
    pid_to_session: Arc<RwLock<HashMap<i32, String>>>,
    /// Mapping from session_id to SessionState
    sessions: Arc<RwLock<HashMap<String, SessionState>>>,
    /// Watch process names
    watch_names: Vec<String>,
    /// Idle timeout in minutes
    idle_timeout_minutes: u64,
    /// Foreground session ID (manually set or inferred)
    foreground_session: Arc<RwLock<Option<String>>>,
    /// Last time foreground session was updated
    foreground_updated: Arc<RwLock<Option<time::OffsetDateTime>>>,
    /// Process names for which we skip ProcStart session creation (e.g. on macOS, app detector owns these)
    skip_proc_start_creation_for: Vec<String>,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(watch_names: Vec<String>, idle_timeout_minutes: u64) -> Self {
        Self {
            pid_to_session: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            watch_names,
            idle_timeout_minutes,
            foreground_session: Arc::new(RwLock::new(None)),
            foreground_updated: Arc::new(RwLock::new(None)),
            skip_proc_start_creation_for: Vec::new(),
        }
    }

    /// On macOS with app detector: skip ProcStart session creation for these process names.
    /// SessionLifecycleManager creates them from AppEvent instead. Prevents duplicate sessions.
    pub fn with_skip_proc_start_creation(mut self, process_names: Vec<String>) -> Self {
        self.skip_proc_start_creation_for = process_names;
        self
    }

    /// Set the foreground session (manual focus)
    pub async fn set_foreground_session(&self, session_id: String) -> bool {
        // Verify session exists and is active
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&session_id) {
            if session.is_active() {
                drop(sessions);
                *self.foreground_session.write().await = Some(session_id.clone());
                *self.foreground_updated.write().await = Some(time::OffsetDateTime::now_utc());
                info!("Set foreground session to {}", session_id);
                return true;
            }
        }
        false
    }

    /// Get the current foreground session
    pub async fn get_foreground_session(&self) -> Option<String> {
        self.foreground_session.read().await.clone()
    }

    /// Get foreground session info (ID and last update time)
    pub async fn get_foreground_info(&self) -> Option<(String, time::OffsetDateTime)> {
        let session_id = self.foreground_session.read().await.clone()?;
        let updated = self.foreground_updated.read().await.clone()?;
        Some((session_id, updated))
    }

    /// Update foreground session based on most recent activity (fallback heuristic)
    pub async fn update_foreground_from_activity(&self) {
        let sessions = self.sessions.read().await;
        let mut active_sessions: Vec<(&String, &SessionState)> = sessions
            .iter()
            .filter(|(_, s)| s.is_active())
            .collect();
        active_sessions.sort_by(|a, b| b.1.last_event_ts.cmp(&a.1.last_event_ts));

        let session_id_clone = active_sessions.first().map(|(id, _)| (*id).clone());
        drop(sessions);

        if let Some(session_id_clone) = session_id_clone {
            let mut fg = self.foreground_session.write().await;
            if fg.as_ref() != Some(&session_id_clone) {
                *fg = Some(session_id_clone.clone());
                *self.foreground_updated.write().await = Some(time::OffsetDateTime::now_utc());
                debug!("Updated foreground session to {} (most recent activity)", session_id_clone);
            }
        }
    }

    /// Handle a ProcStart event
    pub async fn handle_proc_start(&self, event: &Event, candidate_roots: Option<Vec<String>>) -> Option<String> {
        let payload = event.payload.clone();
        let pid = payload.get("pid")?.as_i64()? as i32;
        let name = payload.get("name")?.as_str()?.to_string();

        // Check if we should create a session for this process
        if !self.should_watch(&name) {
            return None;
        }
        // Only create sessions for main processes; helpers (Code Helper, Cursor Helper, etc.) would spawn many sessions
        if !Self::is_main_process(&name) {
            return None;
        }

        // Check if we already have a session for this pid (e.g. from SessionLifecycleManager)
        let pid_to_session = self.pid_to_session.read().await;
        if let Some(session_id) = pid_to_session.get(&pid) {
            debug!("Session already exists for pid={}, session_id={}", pid, session_id);
            return Some(session_id.clone());
        }
        drop(pid_to_session);

        // Skip creation for processes owned by app detector (macOS) — SessionLifecycleManager creates them
        let name_lower = name.to_lowercase();
        if self
            .skip_proc_start_creation_for
            .iter()
            .any(|n| name_lower == n.to_lowercase())
        {
            debug!("Skipping ProcStart session creation for {} (app detector owns)", name);
            return None;
        }

        // Create new session
        let app = self.infer_app(&name);
        let session_id = uuid::Uuid::new_v4().to_string();

        // Create session state with candidate roots
        let mut session_state = SessionState::new(session_id.clone(), app.clone(), pid);
        if let Some(roots) = candidate_roots {
            session_state.candidate_roots = roots;
        }

        // Store mappings
        {
            let mut pid_map = self.pid_to_session.write().await;
            pid_map.insert(pid, session_id.clone());
        }

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session_state);
        }

        info!(
            "Created session session_id={}, app={}, root_pid={}",
            session_id, app, pid
        );

        Some(session_id)
    }

    /// Handle a ProcExit event
    pub async fn handle_proc_exit(&self, event: &Event) -> Option<String> {
        let payload = event.payload.clone();
        let pid = payload.get("pid")?.as_i64()? as i32;

        let session_id = {
            let mut pid_map = self.pid_to_session.write().await;
            pid_map.remove(&pid)?
        };

        // End the session
        {
            let mut sessions = self.sessions.write().await;
            if let Some(session) = sessions.get_mut(&session_id) {
                session.end();
                info!("Ended session session_id={} due to process exit pid={}", session_id, pid);
            }
        }

        Some(session_id)
    }

    /// Get or assign session for an event
    pub async fn get_or_assign_session(&self, event: &Event, candidate_roots: Option<Vec<String>>) -> Option<String> {
        // For ProcStart/ProcExit, handle specially
        match event.event_type {
            EventType::ProcStart => return self.handle_proc_start(event, candidate_roots).await,
            EventType::ProcExit => return self.handle_proc_exit(event).await,
            _ => {}
        }

        // For other events, try to find the most recent active session
        let sessions = self.sessions.read().await;
        let mut active_sessions: Vec<(&String, &SessionState)> = sessions
            .iter()
            .filter(|(_, s)| s.is_active())
            .collect();
        active_sessions.sort_by(|a, b| b.1.last_event_ts.cmp(&a.1.last_event_ts));

        active_sessions.first().map(|(id, _)| (*id).clone())
    }

    /// Update session with an event
    pub async fn update_session(&self, session_id: &str, _event: &Event) -> bool {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            if !session.is_active() {
                warn!("Attempted to update ended session {}", session_id);
                return false;
            }
            session.update_last_event();
            true
        } else {
            false
        }
    }

    /// Get session summary
    pub async fn get_session(&self, session_id: &str) -> Option<SessionSummary> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).map(|s| {
            let mut summary = s.summary.clone();
            // Update observed_roots from state
            summary.observed_roots = s.observed_roots.iter().cloned().collect();
            summary
        })
    }

    /// Get candidate and observed roots for a session (for UI display). Returns None if session not in manager.
    pub async fn get_session_roots(&self, session_id: &str) -> Option<(Vec<String>, Vec<String>)> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).map(|s| {
            (
                s.candidate_roots.clone(),
                s.observed_roots.iter().cloned().collect(),
            )
        })
    }

    /// Add an observed root to a session
    pub async fn add_observed_root(&self, session_id: &str, root: String) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.add_observed_root(root);
        }
    }

    /// Get sessions that have a watched root matching a path (candidate or observed roots)
    pub async fn get_sessions_for_path(&self, path: &str) -> Vec<String> {
        let sessions = self.sessions.read().await;
        let mut matching = Vec::new();
        for (session_id, session) in sessions.iter() {
            if !session.is_active() {
                continue;
            }
            let under_candidate = session.candidate_roots.iter().any(|root| path.starts_with(root));
            let under_observed = session.observed_roots.iter().any(|root| path.starts_with(root));
            if under_candidate || under_observed {
                matching.push(session_id.clone());
            }
        }
        matching
    }

    /// Get session_id for a pid if known (from ProcStart mapping)
    pub async fn get_session_for_pid(&self, pid: i32) -> Option<String> {
        self.pid_to_session.read().await.get(&pid).cloned()
    }

    /// Step 5: End and unregister session for pid (from AppEvent::Exited). Returns session_id if found.
    pub async fn end_session_for_pid(&self, pid: i32) -> Option<String> {
        let session_id = self.pid_to_session.write().await.remove(&pid)?;
        let mut sessions = self.sessions.write().await;
        if let Some(s) = sessions.get_mut(&session_id) {
            s.end();
        }
        Some(session_id)
    }

    /// Step 5: Register a session created by SessionLifecycleManager (from AppEvent::Started).
    /// Inserts into in-memory registry; caller must persist to DB.
    pub async fn register_session_from_app(&self, session_id: String, app: String, root_pid: i32) {
        let state = SessionState::new(session_id.clone(), app, root_pid);
        {
            let mut pid_map = self.pid_to_session.write().await;
            pid_map.insert(root_pid, session_id.clone());
        }
        self.sessions.write().await.insert(session_id, state);
    }

    /// Ensure a Cursor session exists for this pid; create lightweight one if not. Returns session_id.
    pub async fn ensure_cursor_session(&self, pid: i32) -> String {
        if let Some(sid) = self.pid_to_session.read().await.get(&pid) {
            return sid.clone();
        }
        let session_id = uuid::Uuid::new_v4().to_string();
        let app = "Cursor".to_string();
        {
            let mut pid_map = self.pid_to_session.write().await;
            pid_map.insert(pid, session_id.clone());
        }
        let state = SessionState::new(session_id.clone(), app, pid);
        self.sessions.write().await.insert(session_id.clone(), state);
        session_id
    }

    /// Get all active sessions
    pub async fn get_active_sessions(&self) -> Vec<SessionSummary> {
        let sessions = self.sessions.read().await;
        sessions
            .values()
            .filter(|s| s.is_active())
            .map(|s| s.summary.clone())
            .collect()
    }

    /// Active sessions with combined roots (candidate + observed) for attribution.
    pub async fn get_active_sessions_with_roots(&self) -> Vec<(SessionSummary, Vec<String>)> {
        let sessions = self.sessions.read().await;
        sessions
            .values()
            .filter(|s| s.is_active())
            .map(|s| {
                let mut roots: Vec<String> = s.candidate_roots.iter().cloned().collect();
                for r in &s.observed_roots {
                    if !roots.contains(r) {
                        roots.push(r.clone());
                    }
                }
                (s.summary.clone(), roots)
            })
            .collect()
    }

    /// Phase 6: Force-end sessions (e.g. emergency freeze). Marks each as ended and forced_terminated.
    pub async fn force_end_sessions(&self, session_ids: &[String]) {
        let mut sessions = self.sessions.write().await;
        for id in session_ids {
            if let Some(s) = sessions.get_mut(id) {
                s.force_terminate();
            }
        }
        let mut pid_map = self.pid_to_session.write().await;
        for id in session_ids {
            pid_map.retain(|_, sid| sid != id);
        }
    }

    /// Get all sessions (active and ended)
    pub async fn get_all_sessions(&self) -> Vec<SessionSummary> {
        let sessions = self.sessions.read().await;
        sessions.values().map(|s| s.summary.clone()).collect()
    }

    /// Check for idle sessions and end them
    pub async fn check_idle_timeout(&self) -> Vec<String> {
        let now = time::OffsetDateTime::now_utc();
        let timeout = Duration::from_secs(self.idle_timeout_minutes * 60);
        let mut ended = Vec::new();

        let mut sessions = self.sessions.write().await;
        for (session_id, session) in sessions.iter_mut() {
            if session.is_active() {
                let elapsed = now - session.last_event_ts;
                if elapsed > timeout {
                    session.end();
                    ended.push(session_id.clone());
                    info!("Ended idle session session_id={}", session_id);
                }
            }
        }

        // Clean up pid mappings for ended sessions
        if !ended.is_empty() {
            let mut pid_map = self.pid_to_session.write().await;
            pid_map.retain(|_, session_id| !ended.contains(session_id));
        }

        ended
    }

    /// Processes that get sessions: renderers for Cursor/VSCode (one per window), main for Claude.
    fn is_main_process(name: &str) -> bool {
        let n = name.to_lowercase();
        n == "cursor helper (renderer)"
            || n == "code helper (renderer)"
            || n == "code - renderer"
            || n == "claude"
    }

    fn should_watch(&self, name: &str) -> bool {
        self.watch_names.iter().any(|w| name.contains(w))
    }

    fn infer_app(&self, name: &str) -> String {
        if name.contains("Cursor") {
            "Cursor".to_string()
        } else if name.contains("Code") || name.contains("Visual Studio Code") {
            "VSCode".to_string()
        } else if name.contains("Claude") {
            "Claude".to_string()
        } else {
            "Unknown".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SessionManager;

    #[tokio::test]
    async fn test_force_end_sessions_empty() {
        let m = SessionManager::new(vec!["Cursor".to_string()], 7);
        m.force_end_sessions(&[]).await;
    }

    #[tokio::test]
    async fn test_force_end_sessions_nonexistent() {
        let m = SessionManager::new(vec!["Cursor".to_string()], 7);
        m.force_end_sessions(&["nonexistent".to_string()]).await;
    }
}
