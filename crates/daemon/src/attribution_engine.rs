//! Build AttributionContext and call core attribution (used by pipeline and optionally API simulate).
//! Step 7: Integrates SessionHeat, PID cache, recent_session_window.

use crate::attribution_state::AttributionState;
use antidote_core::{attribute_event, AttributionContext, AttributionResult, Event, ForegroundContext};
use antidote_session::SessionManager;
use std::collections::HashMap;
use std::sync::Arc;
use time::OffsetDateTime;

/// Run attribution: returns session_id, reason, confidence.
pub fn attribute(event: &Event, ctx: &AttributionContext) -> AttributionResult {
    attribute_event(event, ctx)
}

/// Build AttributionContext from current state (for pipeline and debug simulate).
pub async fn build_attribution_context(
    focus: ForegroundContext,
    session_manager: Arc<SessionManager>,
    watched_roots: Vec<String>,
    attribution_state: Option<Arc<AttributionState>>,
    recent_session_window_seconds: u64,
) -> AttributionContext {
    let with_roots = session_manager.get_active_sessions_with_roots().await;
    let active_sessions: Vec<_> = with_roots.iter().map(|(s, _)| s.clone()).collect();
    let session_roots: HashMap<String, Vec<String>> = with_roots
        .into_iter()
        .map(|(s, roots)| (s.session_id, roots))
        .collect();

    let mut pid_to_session: HashMap<i32, String> = active_sessions
        .iter()
        .filter(|s| s.root_pid != 0)
        .map(|s| (s.root_pid, s.session_id.clone()))
        .collect();

    if let Some(ref state) = attribution_state {
        let now = OffsetDateTime::now_utc();
        let heat = state.get_all_heat_scores(now).await;
        let snap = state.debug_snapshot(now).await;
        for (pid, sid) in snap.pid_to_session {
            pid_to_session.entry(pid).or_insert(sid);
        }
        return AttributionContext::from_parts_with_pid_override(
            focus,
            watched_roots,
            active_sessions,
            session_roots,
            pid_to_session,
            heat,
            recent_session_window_seconds,
        );
    }

    AttributionContext::from_parts(
        focus,
        watched_roots,
        active_sessions,
        session_roots,
        HashMap::new(),
        recent_session_window_seconds,
    )
}
