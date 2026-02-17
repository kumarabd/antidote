//! HTTP API for Antidote

use antidote_core::{Event, EventType, Flag, SessionSummary};
use antidote_session::SessionManager;
use antidote_storage::{Storage, WatchedRoot};
#[cfg(target_os = "macos")]
use antidote_collectors::AuditCollector;
use anyhow::Result;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
pub struct ApiState {
    pub storage: Arc<Storage>,
    pub session_manager: Option<Arc<antidote_session::SessionManager>>,
    pub proxy_enabled: bool,
    pub proxy_listen_addr: String,
}

/// Health check response
#[derive(Serialize)]
pub struct HealthResponse {
    pub ok: bool,
}

/// Request to emit a debug event
#[derive(Deserialize)]
pub struct EmitEventRequest {
    pub session_id: String,
    pub event_type: String,
    pub payload: serde_json::Value,
}

/// Response for emit event
#[derive(Serialize)]
pub struct EmitEventResponse {
    pub accepted: bool,
}

/// Query parameters for list endpoints
#[derive(Deserialize)]
pub struct ListParams {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub since: Option<String>,
    pub until: Option<String>,
}

/// Create the API router
pub fn create_router(
    storage: Arc<Storage>,
    session_manager: Option<Arc<SessionManager>>,
    proxy_enabled: bool,
    proxy_listen_addr: String,
) -> Router {
    let state = ApiState {
        storage,
        session_manager,
        proxy_enabled,
        proxy_listen_addr,
    };

    Router::new()
        .route("/health", get(health_handler))
        .route("/sessions", get(list_sessions_handler))
        .route("/sessions/:id", get(get_session_handler))
        .route("/sessions/:id/summary", get(get_session_summary_handler))
        .route("/sessions/:id/events", get(list_events_handler))
        .route("/sessions/:id/flags", get(list_flags_handler))
        .route("/roots", get(list_roots_handler))
        .route("/roots", post(add_root_handler))
        .route("/roots/:id", axum::routing::delete(delete_root_handler))
        .route("/roots/:id/enable", post(enable_root_handler))
        .route("/proxy/status", get(proxy_status_handler))
        .route("/debug/emit", post(emit_event_handler))
        .route("/debug/sessions/active", get(list_active_sessions_handler))
        .route("/debug/focus", get(get_focus_handler))
        .route("/debug/focus", post(set_focus_handler))
        .route("/debug/db", get(db_health_handler))
        .route("/debug/prune", post(prune_handler))
        .route("/capabilities", get(capabilities_handler))
        .route("/ui", get(ui_redirect_handler))
        .route("/ui/", get(ui_index_handler))
        .route("/ui/*path", get(ui_static_handler))
        .with_state(state)
}

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse { ok: true })
}

async fn list_sessions_handler(
    State(state): State<ApiState>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<SessionSummary>>, StatusCode> {
    let sessions = state
        .storage
        .list_sessions(
            params.limit,
            params.offset,
            params.since.as_deref(),
            params.until.as_deref(),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(sessions))
}

async fn get_session_handler(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
) -> Result<Json<SessionSummary>, StatusCode> {
    let session = state
        .storage
        .get_session(&session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(session))
}

async fn get_session_summary_handler(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
) -> Result<Json<SessionSummary>, StatusCode> {
    let session = state
        .storage
        .get_session(&session_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(session))
}

async fn list_active_sessions_handler(
    State(state): State<ApiState>,
) -> Result<Json<Vec<SessionSummary>>, StatusCode> {
    if let Some(manager) = &state.session_manager {
        let sessions = manager.get_active_sessions().await;
        Ok(Json(sessions))
    } else {
        // Fallback: return sessions with no end_ts from storage
        let all_sessions = state
            .storage
            .list_sessions(None, None, None, None)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let active: Vec<SessionSummary> = all_sessions
            .into_iter()
            .filter(|s| s.end_ts.is_none())
            .collect();
        Ok(Json(active))
    }
}

async fn list_events_handler(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<Event>>, StatusCode> {
    let events = state
        .storage
        .list_events(&session_id, params.limit, params.offset)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(events))
}

async fn list_flags_handler(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<Flag>>, StatusCode> {
    let flags = state
        .storage
        .list_flags(&session_id, params.limit, params.offset)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(flags))
}

async fn emit_event_handler(
    State(state): State<ApiState>,
    Json(req): Json<EmitEventRequest>,
) -> Result<Json<EmitEventResponse>, StatusCode> {
    // Parse event type
    let event_type = match req.event_type.as_str() {
        "HEARTBEAT" => EventType::Heartbeat,
        "PROC_START" => EventType::ProcStart,
        "PROC_EXIT" => EventType::ProcExit,
        "TICK" => EventType::Tick,
        "FILE_WRITE" => EventType::FileWrite,
        "FILE_CREATE" => EventType::FileCreate,
        "FILE_DELETE" => EventType::FileDelete,
        "FILE_RENAME" => EventType::FileRename,
        "NET_HTTP" => EventType::NetHttp,
        "CMD_EXEC" => EventType::CmdExec,
        "PROC_SPAWN" => EventType::ProcSpawn,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let event = Event::new(req.session_id, event_type, req.payload);

    // Store the event
    state
        .storage
        .insert_event(&event)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(EmitEventResponse { accepted: true }))
}

/// Request to add a watched root
#[derive(Deserialize)]
pub struct AddRootRequest {
    pub path: String,
}

/// Request to enable/disable a root
#[derive(Deserialize)]
pub struct EnableRootRequest {
    pub enabled: bool,
}

/// Proxy status response
#[derive(Serialize)]
pub struct ProxyStatusResponse {
    pub enabled: bool,
    pub listen_addr: String,
    pub instructions: String,
}

async fn list_roots_handler(
    State(state): State<ApiState>,
) -> Result<Json<Vec<WatchedRoot>>, StatusCode> {
    let roots = state
        .storage
        .list_watched_roots()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(roots))
}

async fn add_root_handler(
    State(state): State<ApiState>,
    Json(req): Json<AddRootRequest>,
) -> Result<Json<WatchedRoot>, StatusCode> {
    let id = state
        .storage
        .add_watched_root(&req.path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Fetch the created root
    let roots = state
        .storage
        .list_watched_roots()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let root = roots
        .into_iter()
        .find(|r| r.id == id)
        .ok_or(StatusCode::NOT_FOUND)?;
    
    Ok(Json(root))
}

async fn delete_root_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    state
        .storage
        .delete_watched_root(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn enable_root_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
    Json(req): Json<EnableRootRequest>,
) -> Result<StatusCode, StatusCode> {
    state
        .storage
        .set_watched_root_enabled(id, req.enabled)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn proxy_status_handler(
    State(state): State<ApiState>,
) -> Result<Json<ProxyStatusResponse>, StatusCode> {
    Ok(Json(ProxyStatusResponse {
        enabled: state.proxy_enabled,
        listen_addr: state.proxy_listen_addr.clone(),
        instructions: format!(
            "Set system HTTP proxy to {}",
            state.proxy_listen_addr
        ),
    }))
}

/// Request to set foreground session
#[derive(Deserialize)]
pub struct SetFocusRequest {
    pub session_id: String,
}

/// Response for focus info
#[derive(Serialize)]
pub struct FocusResponse {
    pub session_id: Option<String>,
    pub last_updated: Option<String>,
}

/// DB health response
#[derive(Serialize)]
pub struct DbHealthResponse {
    pub ok: bool,
    pub message: String,
}

async fn get_focus_handler(
    State(state): State<ApiState>,
) -> Result<Json<FocusResponse>, StatusCode> {
    if let Some(session_manager) = &state.session_manager {
        if let Some((session_id, updated)) = session_manager.get_foreground_info().await {
            Ok(Json(FocusResponse {
                session_id: Some(session_id),
                last_updated: Some(updated.to_string()),
            }))
        } else {
            Ok(Json(FocusResponse {
                session_id: None,
                last_updated: None,
            }))
        }
    } else {
        Ok(Json(FocusResponse {
            session_id: None,
            last_updated: None,
        }))
    }
}

async fn set_focus_handler(
    State(state): State<ApiState>,
    Json(req): Json<SetFocusRequest>,
) -> Result<StatusCode, StatusCode> {
    if let Some(session_manager) = &state.session_manager {
        if session_manager.set_foreground_session(req.session_id).await {
            Ok(StatusCode::NO_CONTENT)
        } else {
            Err(StatusCode::NOT_FOUND)
        }
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

async fn db_health_handler(
    State(state): State<ApiState>,
) -> Result<Json<DbHealthResponse>, StatusCode> {
    // Simple health check: try to list sessions
    match state.storage.list_sessions(None, None, None, None).await {
        Ok(_) => Ok(Json(DbHealthResponse {
            ok: true,
            message: "Database is healthy".to_string(),
        })),
        Err(e) => Ok(Json(DbHealthResponse {
            ok: false,
            message: format!("Database error: {}", e),
        })),
    }
}

async fn prune_handler(
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    use time::{Duration, OffsetDateTime};
    let cutoff = OffsetDateTime::now_utc() - Duration::days(7);
    let events_pruned = state.storage.prune_events_older_than(cutoff).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let flags_pruned = state.storage.prune_flags_older_than(cutoff).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({
        "events_pruned": events_pruned,
        "flags_pruned": flags_pruned
    })))
}

async fn ui_redirect_handler() -> axum::response::Redirect {
    axum::response::Redirect::permanent("/ui/")
}

async fn ui_index_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../static/index.html"))
}

async fn ui_static_handler(
    Path(_path): Path<String>,
) -> Result<axum::response::Response, StatusCode> {
    // For Phase 3, we only serve index.html
    // In a real implementation, you'd serve CSS/JS files here
    Err(StatusCode::NOT_FOUND)
}

/// Capabilities response (Phase 4)
#[derive(Serialize)]
pub struct CapabilitiesResponse {
    pub audit_collector_active: bool,
    pub proxy_active: bool,
    pub fs_watcher_active: bool,
    pub telemetry_confidence: String,
}

async fn capabilities_handler(
    State(_state): State<ApiState>,
) -> Result<Json<CapabilitiesResponse>, StatusCode> {
    // Check if audit collector is available (Phase 4)
    #[cfg(target_os = "macos")]
    let audit_active = AuditCollector::check_availability();
    #[cfg(not(target_os = "macos"))]
    let audit_active = false;

    // For now, assume proxy and fs_watcher are always available if configured
    // In a real implementation, these would be tracked in ApiState
    let proxy_active = true; // TODO: Track actual state
    let fs_watcher_active = true; // TODO: Track actual state

    let telemetry_confidence = if audit_active {
        "HIGH"
    } else if proxy_active && fs_watcher_active {
        "MED"
    } else {
        "LOW"
    };

    Ok(Json(CapabilitiesResponse {
        audit_collector_active: audit_active,
        proxy_active,
        fs_watcher_active,
        telemetry_confidence: telemetry_confidence.to_string(),
    }))
}
