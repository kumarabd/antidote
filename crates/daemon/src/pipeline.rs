//! Event pipeline worker

use antidote_core::{Event, EventType, Flag, Label, Severity, EnforcementConfig, SafeModeConfig};
use antidote_ruleengine::{RuleEngine, SessionState};
use antidote_session::SessionManager;
use antidote_storage::Storage;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use crate::rate_limiter::{RateLimiter, EventDropMetrics};

use antidote_core::ForegroundContext;
use crate::attribution_engine::{self, build_attribution_context};
use crate::attribution_state::AttributionState;
use crate::telemetry_integrity::TelemetryIntegrityState;
use time::OffsetDateTime;

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
    /// Step 4: Focus context for attribution (optional; default used if None)
    focus_context: Option<Arc<tokio::sync::RwLock<ForegroundContext>>>,
    /// Step 6: Rate limiter and drop metrics
    rate_limiter: Option<Arc<RateLimiter>>,
    drop_metrics: Option<Arc<EventDropMetrics>>,
    /// Step 7: Attribution state (heat, PID cache, stabilization)
    attribution_state: Option<Arc<AttributionState>>,
    /// Step 7: Recent session window for network events (seconds)
    recent_session_window_seconds: u64,
    /// Step 8: Telemetry integrity (attribution quality, root coverage, pipeline)
    telemetry_integrity: Option<Arc<TelemetryIntegrityState>>,
}

impl PipelineWorker {
    pub fn new(
        storage: Arc<Storage>,
        rule_engine: Arc<RuleEngine>,
        session_manager: Arc<SessionManager>,
        event_rx: mpsc::UnboundedReceiver<Event>,
        enforcement: Arc<tokio::sync::RwLock<EnforcementConfig>>,
        safe_mode: Arc<tokio::sync::RwLock<SafeModeConfig>>,
        watched_roots: Arc<tokio::sync::RwLock<Vec<String>>>,
        focus_context: Option<Arc<tokio::sync::RwLock<ForegroundContext>>>,
        rate_limiter: Option<Arc<RateLimiter>>,
        drop_metrics: Option<Arc<EventDropMetrics>>,
        attribution_state: Option<Arc<AttributionState>>,
        recent_session_window_seconds: u64,
        telemetry_integrity: Option<Arc<TelemetryIntegrityState>>,
    ) -> Self {
        Self {
            storage,
            rule_engine,
            session_manager,
            event_rx,
            session_states: HashMap::new(),
            watched_roots,
            enforcement,
            safe_mode,
            focus_context,
            rate_limiter,
            drop_metrics,
            attribution_state,
            recent_session_window_seconds,
            telemetry_integrity,
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
                        if let Some(ref ti) = &self.telemetry_integrity {
                            ti.record_event_received();
                        }
                        // Step 6: Rate limit - drop if over threshold
                        if let (Some(ref limiter), Some(ref metrics)) = (&self.rate_limiter, &self.drop_metrics) {
                            if !limiter.allow() {
                                metrics.record_drop();
                                if let Some(ref ti) = &self.telemetry_integrity {
                                    ti.record_event_dropped();
                                }
                                continue;
                            }
                        }
                        // Step 4: ProcStart — ensure session exists before attribution
                        if event.event_type == EventType::ProcStart {
                            let roots = self.storage.get_enabled_roots().await.ok();
                            let _ = self.session_manager.get_or_assign_session(&event, roots).await;
                            self.session_manager.update_foreground_from_activity().await;
                        }
                        let focus = match &self.focus_context {
                            Some(c) => c.read().await.clone(),
                            None => ForegroundContext::default(),
                        };
                        let roots = self.watched_roots.read().await.clone();
                        let ctx = build_attribution_context(
                            focus,
                            self.session_manager.clone(),
                            roots,
                            self.attribution_state.clone(),
                            self.recent_session_window_seconds,
                        )
                        .await;
                        let attr = attribution_engine::attribute(&event, &ctx);
                        event.attribution_reason = Some(attr.reason);
                        event.attribution_confidence = Some(attr.confidence);
                        event.attribution_details_json = attr.details_json.clone();

                        if let Some(ref state) = &self.attribution_state {
                            let now = OffsetDateTime::now_utc();
                            state
                                .record_attribution(
                                    &attr.session_id,
                                    matches!(
                                        event.event_type,
                                        antidote_core::EventType::FileWrite
                                            | antidote_core::EventType::FileCreate
                                            | antidote_core::EventType::FileDelete
                                            | antidote_core::EventType::FileRename
                                            | antidote_core::EventType::FileRead
                                    ),
                                    matches!(
                                        event.event_type,
                                        antidote_core::EventType::NetHttp | antidote_core::EventType::NetConnect
                                    ),
                                    now,
                                )
                                .await;
                            if event.attribution_reason.as_deref() == Some("pid") {
                                if let Some(pid) = event.payload.get("pid").and_then(|v| v.as_i64()).map(|p| p as i32) {
                                    state.insert_pid_session(pid, attr.session_id.clone(), now).await;
                                }
                            }
                        }

                        event_batch.push((attr.session_id, event));

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
    async fn process_event(&mut self, session_id: &str, mut event: Event) {
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
                        root_id: None,
                        event_type: EventType::Tick,
                        payload: serde_json::json!({}),
                        enforcement_action: false,
                        attribution_reason: None,
                        attribution_confidence: None,
                        attribution_details_json: None,
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

        // Step 4: Track observed root for file events (for future path attribution)
        if session_id != "background"
            && matches!(
                event.event_type,
                EventType::FileWrite | EventType::FileCreate | EventType::FileDelete
                    | EventType::FileRename | EventType::FileRead
            )
        {
            if let Some(path) = event.payload.get("path").and_then(|v| v.as_str()) {
                if let Some(root) = self.find_root_for_path(path).await {
                    self.session_manager.add_observed_root(session_id, root).await;
                }
            }
        }

        // Update session summary for attribution/counts (sessions are independent; events are not associated)
        self.update_session_summary(session_id, &state_clone).await;

        // Set root_id for file events (primary association: watcher is per-root)
        if event.root_id.is_none()
            && matches!(
                event.event_type,
                EventType::FileWrite | EventType::FileCreate | EventType::FileDelete
                    | EventType::FileRename | EventType::FileRead
            )
        {
            if let Some(path) = event.payload.get("path").and_then(|v| v.as_str()) {
                if let Some(root_path) = self.find_root_for_path(path).await {
                    if let Ok(Some(wr)) = self.storage.get_watched_root_by_path(&root_path).await {
                        event.root_id = Some(wr.id);
                    }
                }
            }
        }

        // Persist event
        if let Err(e) = self.storage.insert_event(&event).await {
            error!("Failed to insert event: {}", e);
        } else if let Some(ref ti) = &self.telemetry_integrity {
            let confidence = event.attribution_confidence.unwrap_or(0);
            let is_file = matches!(
                event.event_type,
                EventType::FileWrite
                    | EventType::FileCreate
                    | EventType::FileDelete
                    | EventType::FileRename
                    | EventType::FileRead
            );
            let coalesced = event
                .payload
                .get("repeat_count")
                .and_then(|v| v.as_u64())
                .map(|n| n > 1)
                .unwrap_or(false);
            ti.record_event_stored(
                confidence,
                session_id,
                is_file,
                session_id == "background",
                coalesced,
            );
        }

        // Persist flags if any (and record risk history for high/crit for Phase 5 escalation)
        if !flags.is_empty() {
            self.persist_flags(session_id, &app, &flags).await;
        }

        // Phase 6: Dangerous command detection (observation only; never kills processes)
        if event.event_type == EventType::CmdExec
            && flags.iter().any(|f| f.rule_id == "R3")
        {
            let enf = self.enforcement.read().await;
            if enf.enabled && enf.block_dangerous_commands {
                if let Some(pid) = event.payload.get("pid").and_then(|v| v.as_i64()) {
                    drop(enf);
                    let block_flag = Flag::new(
                        session_id.to_string(),
                        "BLOCKED_COMMAND".to_string(),
                        antidote_core::Severity::High,
                        20,
                        Label::EnforcementBlocked,
                        event.payload.clone(),
                        format!("Detected dangerous command (pid {})", pid),
                    );
                    self.persist_flags(session_id, &app, &[block_flag]).await;
                }
            }
        }

        // Clean up ended sessions from in-memory state and attribution PID cache
        if session_id != "background" {
            if let Some(session) = self.session_manager.get_session(session_id).await {
                if session.end_ts.is_some() {
                    self.session_states.remove(session_id);
                    if let Some(ref state) = &self.attribution_state {
                        state.remove_session_pids(session_id).await;
                    }
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
                summary_json: None,
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
            summary_json: session.summary_json.clone(),
        };

        if let Err(e) = self.storage.upsert_session_summary(&summary).await {
            error!("Failed to upsert session summary for {}: {}", session_id, e);
        }
    }
}
