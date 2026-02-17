//! Event pipeline worker

use antidote_core::{Event, EventType, Flag, Label, Severity, EnforcementConfig, SafeModeConfig};
use antidote_ruleengine::{RuleEngine, SessionState};
use antidote_session::SessionManager;
use antidote_storage::Storage;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Pipeline worker that processes events through the system
pub struct PipelineWorker {
    storage: Arc<Storage>,
    rule_engine: Arc<RuleEngine>,
    session_manager: Arc<SessionManager>,
    event_rx: mpsc::UnboundedReceiver<Event>,
    /// In-memory session states (keyed by session_id)
    session_states: HashMap<String, SessionState>,
    /// Watched roots cache (for path matching)
    watched_roots: Arc<tokio::sync::RwLock<Vec<String>>>,
    /// Phase 6: Enforcement config (for command blocking)
    enforcement: Arc<tokio::sync::RwLock<EnforcementConfig>>,
    /// Phase 6: Safe mode config (allowed_roots, domain allowlist in proxy)
    safe_mode: Arc<tokio::sync::RwLock<SafeModeConfig>>,
}

impl PipelineWorker {
    /// Phase 6: Send SIGTERM to process (never panics)
    async fn kill_pid_sigterm(pid: i32) {
        #[cfg(unix)]
        {
            use std::process::Stdio;
            if let Ok(mut child) = tokio::process::Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    child.wait(),
                )
                .await;
            } else {
                warn!("Failed to spawn kill for pid {}", pid);
            }
        }
        #[cfg(not(unix))]
        let _ = pid;
    }

    pub fn new(
        storage: Arc<Storage>,
        rule_engine: Arc<RuleEngine>,
        session_manager: Arc<SessionManager>,
        event_rx: mpsc::UnboundedReceiver<Event>,
        enforcement: Arc<tokio::sync::RwLock<EnforcementConfig>>,
        safe_mode: Arc<tokio::sync::RwLock<SafeModeConfig>>,
    ) -> Self {
        Self {
            storage,
            rule_engine,
            session_manager,
            event_rx,
            session_states: HashMap::new(),
            watched_roots: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            enforcement,
            safe_mode,
        }
    }

    /// Update watched roots cache
    pub async fn update_watched_roots(&self, roots: Vec<String>) {
        *self.watched_roots.write().await = roots;
    }

    pub async fn run(mut self) {
        info!("Pipeline worker started");

        // Initialize watched roots cache
        if let Ok(roots) = self.storage.get_enabled_roots().await {
            self.update_watched_roots(roots).await;
        }

        // Batch processing
        let mut event_batch = Vec::new();
        let mut last_flush = std::time::Instant::now();
        let batch_interval = std::time::Duration::from_secs(2);
        let batch_size = 100;

        loop {
            tokio::select! {
                event_opt = self.event_rx.recv() => {
                    if let Some(mut event) = event_opt {
                        // Get or assign session for this event using heuristics
                        let session_id = self.resolve_session_id(&event).await;
                        event.session_id = session_id.clone();

                        event_batch.push((session_id, event));

                        // Flush if batch is full or interval elapsed
                        if event_batch.len() >= batch_size || last_flush.elapsed() >= batch_interval {
                            self.flush_batch(&mut event_batch).await;
                            last_flush = std::time::Instant::now();
                        }
                    } else {
                        // Channel closed, flush remaining and exit
                        self.flush_batch(&mut event_batch).await;
                        break;
                    }
                }
                _ = tokio::time::sleep(batch_interval) => {
                    // Periodic flush
                    if !event_batch.is_empty() {
                        self.flush_batch(&mut event_batch).await;
                        last_flush = std::time::Instant::now();
                    }
                }
            }
        }

        info!("Pipeline worker stopped");
    }

    /// Resolve session ID using improved heuristics (Phase 3 + Phase 4 pid-based)
    async fn resolve_session_id(&self, event: &Event) -> String {
        // Phase 4: If event has pid, try pid-based attribution first
        if let Some(_pid) = event.payload.get("pid").and_then(|v| v.as_i64()).map(|v| v as i32) {
            // TODO: Query process tree index from audit collector if available
            // For now, fall through to Phase 3 heuristics
        }

        // For ProcStart, get candidate roots and pass to session manager
        if event.event_type == EventType::ProcStart {
            let candidate_roots = self.storage.get_enabled_roots().await.ok();
            if let Some(id) = self.session_manager.get_or_assign_session(event, candidate_roots).await {
                // Update foreground session on new process start
                self.session_manager.update_foreground_from_activity().await;
                return id;
            }
        }

        // For ProcExit, use session manager
        if event.event_type == EventType::ProcExit {
            if let Some(id) = self.session_manager.get_or_assign_session(event, None).await {
                return id;
            }
        }

        // For FS events (including FileRead from Phase 4): attribute to session whose roots include the event path
        if matches!(event.event_type, EventType::FileWrite | EventType::FileCreate | EventType::FileDelete | EventType::FileRename | EventType::FileRead) {
            if let Some(path) = event.payload.get("path").and_then(|v| v.as_str()) {
                let matching_sessions = self.session_manager.get_sessions_for_path(path).await;
                
                if !matching_sessions.is_empty() {
                    // Multiple matches: use foreground session as tiebreaker
                    let fg_session = self.session_manager.get_foreground_session().await;
                    if let Some(fg) = fg_session {
                        if matching_sessions.contains(&fg) {
                            debug!("Attributed FS event to foreground session {}", fg);
                            return fg;
                        }
                    }
                    // Use first matching session (most recently created)
                    let session_id = matching_sessions[0].clone();
                    debug!("Attributed FS event to session {} (path under root)", session_id);
                    // Track observed root
                    if let Some(root) = self.find_root_for_path(path).await {
                        self.session_manager.add_observed_root(&session_id, root.clone()).await;
                        debug!("Tracked observed root {} for session {}", root, session_id);
                    }
                    return session_id;
                }
            }
        }

        // For Net events: attribute to foreground session
        if matches!(event.event_type, EventType::NetHttp | EventType::NetConnect) {
            let fg_session = self.session_manager.get_foreground_session().await;
            if let Some(fg) = fg_session {
                debug!("Attributed Net event to foreground session {}", fg);
                return fg;
            }
        }

        // Fallback: most recently active session
        let active_sessions = self.session_manager.get_active_sessions().await;
        if active_sessions.is_empty() {
            return "background".to_string();
        }

        let session_id = active_sessions
            .iter()
            .max_by_key(|s| s.last_event_ts)
            .map(|s| s.session_id.clone())
            .unwrap_or_else(|| "background".to_string());
        
        // Update foreground session based on activity
        self.session_manager.update_foreground_from_activity().await;
        session_id
    }

    /// Find which watched root a path belongs to (helper)
    async fn find_root_for_path(&self, path: &str) -> Option<String> {
        let roots = self.watched_roots.read().await;
        // Find the longest matching root (most specific)
        roots.iter()
            .filter(|root| path.starts_with(root.as_str()))
            .max_by_key(|root| root.len())
            .cloned()
    }

    /// Flush a batch of events
    async fn flush_batch(&mut self, batch: &mut Vec<(String, Event)>) {
        if batch.is_empty() {
            return;
        }

        let batch_size = batch.len();
        debug!("Flushing batch of {} events", batch_size);

        // Process each event in the batch
        for (session_id, event) in batch.drain(..) {
            self.process_event(&session_id, event).await;
        }
    }

    /// Process a single event
    async fn process_event(&mut self, session_id: &str, event: Event) {
        // Update session last_event_ts (skip for background session)
        if session_id != "background" {
            if !self.session_manager.update_session(session_id, &event).await {
                warn!("Session {} not found or ended, skipping event", session_id);
                return;
            }
        }

        // Get or create session state for rule evaluation
        let session_info = if session_id != "background" {
            self.session_manager.get_session(session_id).await
        } else {
            None
        };
        let app = session_info
            .as_ref()
            .map(|s| s.app.clone())
            .unwrap_or_else(|| "Background".to_string());

        // Handle Tick events specially (broadcast to all active sessions)
        if event.event_type == EventType::Tick {
            // Evaluate aggregate rules for all active sessions
            let active_sessions: Vec<String> = self
                .session_states
                .keys()
                .cloned()
                .collect();

            for active_id in active_sessions {
                let (flags, state_clone) = if let Some(state) = self.session_states.get_mut(&active_id) {
                    let tick_event = Event {
                        id: uuid::Uuid::new_v4(),
                        ts: time::OffsetDateTime::now_utc(),
                        session_id: active_id.clone(),
                        event_type: EventType::Tick,
                        payload: serde_json::json!({}),
                        enforcement_action: false,
                    };
                    let flags = self.rule_engine.evaluate_event(&tick_event, state);
                    (flags, state.clone())
                } else {
                    continue;
                };
                self.persist_flags(&active_id, &state_clone.app, &flags).await;
                self.update_session_summary(&active_id, &state_clone).await;
            }
            return;
        }

        // Evaluate event with rule engine, then release the map borrow by cloning state
        let (flags, state_clone) = {
            let session_state = self
                .session_states
                .entry(session_id.to_string())
                .or_insert_with(|| SessionState::new(session_id.to_string(), app.clone()));
            let flags = self.rule_engine.evaluate_event(&event, session_state);
            (flags, session_state.clone())
        };

        let app = session_info
            .as_ref()
            .map(|s| s.app.clone())
            .unwrap_or_else(|| "Background".to_string());

        // Phase 6: Safe mode - reject file writes outside allowed_roots
        if matches!(
            event.event_type,
            EventType::FileWrite | EventType::FileCreate | EventType::FileDelete
        ) {
            let safe = self.safe_mode.read().await;
            if safe.enabled && !safe.allowed_roots.is_empty() {
                if let Some(path) = event.payload.get("path").and_then(|v| v.as_str()) {
                    let under_allowed = safe
                        .allowed_roots
                        .iter()
                        .any(|root| path.starts_with(root.as_str()));
                    if !under_allowed {
                        drop(safe);
                        let flag = Flag::new(
                            session_id.to_string(),
                            "SAFE_MODE_VIOLATION".to_string(),
                            antidote_core::Severity::High,
                            20,
                            Label::SafeModeViolation,
                            serde_json::json!({ "path": path }),
                            format!("Safe mode: write outside allowed roots: {}", path),
                        );
                        self.persist_flags(session_id, &app, &[flag]).await;
                        // Still persist event and continue (optionally kill - skip for now)
                    }
                }
            }
        }

        // Ensure session row exists before inserting events (FK: events.session_id -> sessions.session_id)
        self.update_session_summary(session_id, &state_clone).await;

        // Persist event
        if let Err(e) = self.storage.insert_event(&event).await {
            error!("Failed to insert event: {}", e);
        }

        // Persist flags if any (and record risk history for high/crit for Phase 5 escalation)
        if !flags.is_empty() {
            self.persist_flags(session_id, &app, &flags).await;
        }

        // Phase 6: Dangerous command blocking (when enforcement enabled and audit provided PID)
        if event.event_type == EventType::CmdExec
            && flags.iter().any(|f| f.rule_id == "R3")
        {
            let enf = self.enforcement.read().await;
            if enf.enabled && enf.block_dangerous_commands {
                if let Some(pid) = event.payload.get("pid").and_then(|v| v.as_i64()).map(|p| p as i32) {
                    drop(enf);
                    Self::kill_pid_sigterm(pid).await;
                    let block_flag = Flag::new(
                        session_id.to_string(),
                        "BLOCKED_COMMAND".to_string(),
                        antidote_core::Severity::High,
                        20,
                        Label::EnforcementBlocked,
                        event.payload.clone(),
                        format!("Blocked dangerous command (pid {})", pid),
                    );
                    self.persist_flags(session_id, &app, &[block_flag]).await;
                }
            }
        }

        // Clean up ended sessions from in-memory state
        if session_id != "background" {
            if let Some(session) = self.session_manager.get_session(session_id).await {
                if session.end_ts.is_some() {
                    self.session_states.remove(session_id);
                    debug!("Removed ended session {} from in-memory state", session_id);
                }
            }
        }
    }

    async fn persist_flags(&self, session_id: &str, app: &str, flags: &[antidote_core::Flag]) {
        if !flags.is_empty() {
            if let Err(e) = self.storage.insert_flags(flags).await {
                error!("Failed to insert flags for session {}: {}", session_id, e);
            }
            for flag in flags {
                if matches!(flag.severity, Severity::High | Severity::Crit) {
                    if let Err(e) = self.storage.record_risk_history(app, &flag.rule_id, flag.ts).await {
                        error!("Failed to record risk history: {}", e);
                    }
                }
            }
        }
    }

    async fn update_session_summary(&self, session_id: &str, session_state: &SessionState) {
        // For background session, create a minimal summary
        if session_id == "background" {
            let summary = antidote_core::SessionSummary {
                session_id: "background".to_string(),
                app: "Background".to_string(),
                root_pid: 0,
                start_ts: time::OffsetDateTime::now_utc(),
                end_ts: None,
                last_event_ts: time::OffsetDateTime::now_utc(),
                counts: session_state.counts.clone(),
                risk: session_state.calculate_risk(),
                labels: session_state.labels.iter().copied().collect(),
                evidence: session_state.evidence.clone(),
                observed_roots: Vec::new(),
                telemetry_confidence: antidote_core::TelemetryConfidence::default(),
                dropped_events: 0,
                participant_pids_count: 0,
                drift_index: None,
                baseline_comparison_summary: None,
                enforcement_actions_count: 0,
                forced_terminated: false,
            };

            if let Err(e) = self.storage.upsert_session_summary(&summary).await {
                error!("Failed to upsert background session summary: {}", e);
            }
            return;
        }

        // Get session from manager to get root_pid and timestamps
        let session = match self.session_manager.get_session(session_id).await {
            Some(s) => s,
            None => {
                warn!("Session {} not found in manager", session_id);
                return;
            }
        };

        let risk = session_state.calculate_risk();
        let summary = antidote_core::SessionSummary {
            session_id: session.session_id.clone(),
            app: session.app.clone(),
            root_pid: session.root_pid,
            start_ts: session.start_ts,
            end_ts: session.end_ts,
            last_event_ts: session.last_event_ts,
            counts: session_state.counts.clone(),
            risk,
            labels: session_state.labels.iter().copied().collect(),
            evidence: session_state.evidence.clone(),
            observed_roots: session.observed_roots.clone(),
            telemetry_confidence: session.telemetry_confidence,
            dropped_events: session.dropped_events,
            participant_pids_count: session.participant_pids_count,
            drift_index: session.drift_index,
            baseline_comparison_summary: session.baseline_comparison_summary.clone(),
            enforcement_actions_count: session.enforcement_actions_count,
            forced_terminated: session.forced_terminated,
        };

        if let Err(e) = self.storage.upsert_session_summary(&summary).await {
            error!("Failed to upsert session summary for {}: {}", session_id, e);
        }
    }
}
