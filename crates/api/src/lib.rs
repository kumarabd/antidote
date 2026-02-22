//! HTTP API for Antidote

use antidote_core::{
    attribute_event, AttributionContext, AttributionResult, Event, EventType, EnforcementConfig,
    Flag, ForegroundContext, SafeModeConfig, SessionSummary,
};
use antidote_session::SessionManager;
use antidote_storage::{AppBaselineRow, Storage, WatchedRoot};
#[cfg(target_os = "macos")]
use antidote_collectors::AuditCollector;
use anyhow::Result;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::services::ServeDir;

#[derive(Clone)]
pub struct ApiState {
    pub storage: Arc<Storage>,
    pub session_manager: Option<Arc<antidote_session::SessionManager>>,
    pub proxy_enabled: bool,
    pub proxy_listen_addr: String,
    /// Phase 6: Enforcement config (shared with proxy/daemon)
    pub enforcement: Arc<tokio::sync::RwLock<EnforcementConfig>>,
    /// Phase 6: Safe mode config
    pub safe_mode: Arc<tokio::sync::RwLock<SafeModeConfig>>,
    /// Phase 6: True when emergency freeze is active
    pub frozen: Arc<tokio::sync::RwLock<bool>>,
    /// Phase 6: Signal daemon to run freeze (kill sessions). None if not provided.
    pub freeze_tx: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    /// App detector state (macOS only); used by GET /debug/apps
    #[cfg(target_os = "macos")]
    pub app_detector_state: Option<Arc<tokio::sync::RwLock<antidote_collectors::AppDetectorState>>>,
    /// Workspace resolver state (macOS only); used by GET /debug/workspaces
    #[cfg(target_os = "macos")]
    pub workspace_resolver_state: Option<Arc<tokio::sync::RwLock<antidote_collectors::WorkspaceResolverState>>>,
    /// FS watcher manager for GET /debug/watchers
    pub fs_watcher: Option<Arc<tokio::sync::RwLock<antidote_collectors::FsWatcherManager>>>,
    /// Step 4: Foreground app state (macOS only); GET /debug/foreground
    #[cfg(target_os = "macos")]
    pub foreground_state: Option<Arc<tokio::sync::RwLock<Option<antidote_collectors::ForegroundApp>>>>,
    /// Step 4: Focus context (session_id, roots, confidence); GET /debug/focus
    #[cfg(target_os = "macos")]
    pub focus_context: Option<Arc<tokio::sync::RwLock<antidote_core::ForegroundContext>>>,
    /// Step 6: Optional drop metrics for /debug/zero_config_health
    pub drop_metrics: Option<Arc<dyn antidote_core::DropMetrics>>,
    /// Step 7: Attribution debug snapshot provider for GET /debug/attribution/state
    pub attribution_debug: Option<Arc<dyn antidote_core::AttributionDebugProvider>>,
    /// Step 8: Telemetry integrity provider (attribution quality, root coverage, pipeline)
    pub telemetry_integrity: Option<Arc<dyn antidote_core::TelemetryIntegrityProvider>>,
    /// Path to built UI dist (ui/dist). If set and exists, SPA is served from here.
    pub ui_dist: Option<PathBuf>,
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

/// Create the API router. On macOS, pass `app_detector_state`, `workspace_resolver_state`, `foreground_state`, `focus_context` for debug endpoints.
fn default_ui_dist() -> Option<PathBuf> {
    std::env::current_dir()
        .ok()
        .map(|p| p.join("ui").join("dist"))
        .filter(|p| p.exists())
}

#[cfg(target_os = "macos")]
pub fn create_router(
    storage: Arc<Storage>,
    session_manager: Option<Arc<SessionManager>>,
    proxy_enabled: bool,
    proxy_listen_addr: String,
    enforcement: Arc<tokio::sync::RwLock<EnforcementConfig>>,
    safe_mode: Arc<tokio::sync::RwLock<SafeModeConfig>>,
    frozen: Arc<tokio::sync::RwLock<bool>>,
    freeze_tx: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    app_detector_state: Option<Arc<tokio::sync::RwLock<antidote_collectors::AppDetectorState>>>,
    workspace_resolver_state: Option<Arc<tokio::sync::RwLock<antidote_collectors::WorkspaceResolverState>>>,
    fs_watcher: Option<Arc<tokio::sync::RwLock<antidote_collectors::FsWatcherManager>>>,
    foreground_state: Option<Arc<tokio::sync::RwLock<Option<antidote_collectors::ForegroundApp>>>>,
    focus_context: Option<Arc<tokio::sync::RwLock<antidote_core::ForegroundContext>>>,
    drop_metrics: Option<Arc<dyn antidote_core::DropMetrics>>,
    attribution_debug: Option<Arc<dyn antidote_core::AttributionDebugProvider>>,
    telemetry_integrity: Option<Arc<dyn antidote_core::TelemetryIntegrityProvider>>,
) -> Router {
    let state = ApiState {
        storage,
        session_manager,
        proxy_enabled,
        proxy_listen_addr,
        enforcement,
        safe_mode,
        frozen,
        freeze_tx,
        app_detector_state,
        workspace_resolver_state,
        fs_watcher,
        foreground_state,
        focus_context,
        drop_metrics,
        attribution_debug,
        telemetry_integrity,
        ui_dist: default_ui_dist(),
    };
    create_router_routes(state)
}

/// Create the API router (non-macOS: no app detector).
#[cfg(not(target_os = "macos"))]
pub fn create_router(
    storage: Arc<Storage>,
    session_manager: Option<Arc<SessionManager>>,
    proxy_enabled: bool,
    proxy_listen_addr: String,
    enforcement: Arc<tokio::sync::RwLock<EnforcementConfig>>,
    safe_mode: Arc<tokio::sync::RwLock<SafeModeConfig>>,
    frozen: Arc<tokio::sync::RwLock<bool>>,
    freeze_tx: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    fs_watcher: Option<Arc<tokio::sync::RwLock<antidote_collectors::FsWatcherManager>>>,
    drop_metrics: Option<Arc<dyn antidote_core::DropMetrics>>,
    attribution_debug: Option<Arc<dyn antidote_core::AttributionDebugProvider>>,
    telemetry_integrity: Option<Arc<dyn antidote_core::TelemetryIntegrityProvider>>,
) -> Router {
    let state = ApiState {
        storage,
        session_manager,
        proxy_enabled,
        proxy_listen_addr,
        enforcement,
        safe_mode,
        frozen,
        freeze_tx,
        fs_watcher,
        drop_metrics,
        attribution_debug,
        telemetry_integrity,
        ui_dist: default_ui_dist(),
    };
    create_router_routes(state)
}

#[cfg(target_os = "macos")]
fn create_router_routes(state: ApiState) -> Router {
    let mut router = Router::new()
        .route("/health", get(health_handler))
        .route("/debug/apps", get(debug_apps_handler))
        .route("/debug/workspaces", get(debug_workspaces_handler))
        .route("/debug/workspaces/:app", get(debug_workspaces_by_app_handler))
        .route("/debug/roots", get(debug_roots_handler))
        .route("/debug/watchers", get(debug_watchers_handler))
        .route("/debug/zero_config_status", get(debug_zero_config_status_handler))
        .route("/debug/zero_config_health", get(debug_zero_config_health_handler))
        .route("/debug/confidence", get(debug_confidence_handler))
        .route("/debug/foreground", get(debug_foreground_handler))
        .route("/debug/attribution/simulate", get(debug_attribution_simulate_handler))
        .route("/debug/attribution/state", get(debug_attribution_state_handler))
        .route("/debug/attribution/quality", get(debug_attribution_quality_handler))
        .route("/debug/capabilities", get(debug_capabilities_handler))
        .route("/debug/health", get(debug_health_handler))
        .route("/debug/root_coverage", get(debug_root_coverage_handler))
        .route("/debug/warnings", get(debug_warnings_handler))
        .route("/debug/pipeline", get(debug_pipeline_handler))
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
        .route("/debug/sessions/all", get(debug_sessions_all_handler))
        .route("/debug/focus", get(get_focus_handler_macos))
        .route("/debug/focus", post(set_focus_handler))
        .route("/debug/db", get(db_health_handler))
        .route("/debug/prune", post(prune_handler))
        .route("/capabilities", get(capabilities_handler))
        .route("/ui/state", get(ui_state_handler))
        .route("/ui/sessions/:id", get(ui_session_handler))
        .route("/ui", get(ui_redirect_handler))
        .route("/ui/", get(ui_index_handler))
        .route("/ui/insights", get(ui_insights_handler))
        .route("/ui/security", get(ui_security_handler));
    if let Some(ref ui_dist) = state.ui_dist {
        let assets = ui_dist.join("assets");
        if assets.exists() {
            router = router.nest_service(
                "/ui/assets",
                ServeDir::new(assets),
            );
        }
    }
    router
        .route("/ui/*path", get(ui_static_handler))
        .route("/baselines", get(baselines_handler))
        .route("/insights", get(insights_handler))
        .route("/enforcement", get(enforcement_get_handler).post(enforcement_post_handler))
        .route("/emergency/freeze", post(emergency_freeze_handler))
        .route("/emergency/unfreeze", post(emergency_unfreeze_handler))
        .with_state(state)
}

#[cfg(not(target_os = "macos"))]
fn create_router_routes(state: ApiState) -> Router {
    let mut router = Router::new()
        .route("/health", get(health_handler))
        .route("/debug/roots", get(debug_roots_handler))
        .route("/debug/watchers", get(debug_watchers_handler))
        .route("/debug/zero_config_health", get(debug_zero_config_health_handler))
        .route("/debug/confidence", get(debug_confidence_handler))
        .route("/debug/attribution/quality", get(debug_attribution_quality_handler))
        .route("/debug/capabilities", get(debug_capabilities_handler))
        .route("/debug/health", get(debug_health_handler))
        .route("/debug/root_coverage", get(debug_root_coverage_handler))
        .route("/debug/warnings", get(debug_warnings_handler))
        .route("/debug/pipeline", get(debug_pipeline_handler))
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
        .route("/debug/sessions/all", get(debug_sessions_all_handler))
        .route("/debug/focus", get(get_focus_handler))
        .route("/debug/focus", post(set_focus_handler))
        .route("/debug/db", get(db_health_handler))
        .route("/debug/prune", post(prune_handler))
        .route("/debug/attribution/simulate", get(debug_attribution_simulate_handler))
        .route("/debug/attribution/state", get(debug_attribution_state_handler))
        .route("/capabilities", get(capabilities_handler))
        .route("/ui/state", get(ui_state_handler))
        .route("/ui/sessions/:id", get(ui_session_handler))
        .route("/ui", get(ui_redirect_handler))
        .route("/ui/", get(ui_index_handler))
        .route("/ui/insights", get(ui_insights_handler))
        .route("/ui/security", get(ui_security_handler));
    if let Some(ref ui_dist) = state.ui_dist {
        let assets = ui_dist.join("assets");
        if assets.exists() {
            router = router.nest_service(
                "/ui/assets",
                ServeDir::new(assets),
            );
        }
    }
    router
        .route("/ui/*path", get(ui_static_handler))
        .route("/baselines", get(baselines_handler))
        .route("/insights", get(insights_handler))
        .route("/enforcement", get(enforcement_get_handler).post(enforcement_post_handler))
        .route("/emergency/freeze", post(emergency_freeze_handler))
        .route("/emergency/unfreeze", post(emergency_unfreeze_handler))
        .with_state(state)
}

#[cfg(target_os = "macos")]
async fn debug_foreground_handler(
    State(state): State<ApiState>,
) -> Result<Json<Option<antidote_collectors::ForegroundApp>>, StatusCode> {
    let Some(ref guard) = state.foreground_state else {
        return Ok(Json(None));
    };
    let app = guard.read().await.clone();
    Ok(Json(app))
}

#[cfg(target_os = "macos")]
async fn get_focus_handler_macos(
    State(state): State<ApiState>,
) -> Result<Json<antidote_core::ForegroundContext>, StatusCode> {
    if let Some(ref ctx) = state.focus_context {
        let f = ctx.read().await.clone();
        return Ok(Json(f));
    }
    Ok(Json(antidote_core::ForegroundContext::default()))
}

#[derive(Deserialize)]
struct SimulateParams {
    path: Option<String>,
    domain: Option<String>,
}

async fn debug_attribution_simulate_handler(
    State(state): State<ApiState>,
    Query(params): Query<SimulateParams>,
) -> Result<Json<AttributionResult>, StatusCode> {
    let session_manager = state
        .session_manager
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let watched_roots = state
        .storage
        .get_enabled_roots()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let with_roots = session_manager.get_active_sessions_with_roots().await;
    let active_sessions: Vec<SessionSummary> = with_roots.iter().map(|(s, _)| s.clone()).collect();
    let session_roots: std::collections::HashMap<String, Vec<String>> = with_roots
        .into_iter()
        .map(|(s, roots)| (s.session_id, roots))
        .collect();
    let focus = ForegroundContext::default();
    let ctx = AttributionContext::from_parts(
        focus,
        watched_roots,
        active_sessions,
        session_roots,
        std::collections::HashMap::new(),
        300,
    );

    let event = if let Some(path) = params.path {
        Event {
            id: uuid::Uuid::new_v4(),
            ts: time::OffsetDateTime::now_utc(),
            session_id: "pending".to_string(),
            event_type: EventType::FileWrite,
            payload: serde_json::json!({ "path": path }),
            enforcement_action: false,
            attribution_reason: None,
            attribution_confidence: None,
            attribution_details_json: None,
        }
    } else if let Some(domain) = params.domain {
        Event {
            id: uuid::Uuid::new_v4(),
            ts: time::OffsetDateTime::now_utc(),
            session_id: "pending".to_string(),
            event_type: EventType::NetHttp,
            payload: serde_json::json!({ "domain": domain }),
            enforcement_action: false,
            attribution_reason: None,
            attribution_confidence: None,
            attribution_details_json: None,
        }
    } else {
        return Err(StatusCode::BAD_REQUEST);
    };

    let result = attribute_event(&event, &ctx);
    Ok(Json(result))
}

async fn debug_attribution_state_handler(
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let Some(ref provider) = state.attribution_debug else {
        return Ok(Json(serde_json::json!({
            "available": false,
            "message": "Attribution debug not configured"
        })));
    };
    let snapshot = provider.clone().get_snapshot().await;
    Ok(Json(snapshot))
}

#[derive(Serialize)]
struct DebugCapabilitiesResponse {
    fs_watcher_active: bool,
    proxy_active: bool,
    workspace_resolution_active: bool,
    foreground_detection_active: bool,
    attribution_engine_active: bool,
    session_lifecycle_active: bool,
    root_policy_active: bool,
    retention_job_active: bool,
}

async fn debug_capabilities_handler(
    State(state): State<ApiState>,
) -> Result<Json<DebugCapabilitiesResponse>, StatusCode> {
    let fs_watcher_active = match &state.fs_watcher {
        Some(w) => !w.read().await.watcher_status().is_empty(),
        None => false,
    };
    #[cfg(target_os = "macos")]
    let (workspace_resolution_active, foreground_detection_active) = (
        state.workspace_resolver_state.is_some(),
        state.foreground_state.is_some(),
    );
    #[cfg(not(target_os = "macos"))]
    let (workspace_resolution_active, foreground_detection_active) = (false, false);
    Ok(Json(DebugCapabilitiesResponse {
        fs_watcher_active,
        proxy_active: state.proxy_enabled,
        workspace_resolution_active,
        foreground_detection_active,
        attribution_engine_active: state.attribution_debug.is_some(),
        session_lifecycle_active: workspace_resolution_active,
        root_policy_active: true,
        retention_job_active: true,
    }))
}

async fn debug_attribution_quality_handler(
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let Some(ref provider) = state.telemetry_integrity else {
        return Ok(Json(serde_json::json!({
            "available": false,
            "message": "Telemetry integrity not configured"
        })));
    };
    let snapshot = provider.clone().get_attribution_quality().await;
    Ok(Json(snapshot))
}

async fn debug_root_coverage_handler(
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let Some(ref provider) = state.telemetry_integrity else {
        return Ok(Json(serde_json::json!({
            "available": false,
            "message": "Telemetry integrity not configured"
        })));
    };
    let snapshot = provider.clone().get_root_coverage().await;
    Ok(Json(snapshot))
}

async fn debug_pipeline_handler(
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let Some(ref provider) = state.telemetry_integrity else {
        return Ok(Json(serde_json::json!({
            "available": false,
            "message": "Telemetry integrity not configured"
        })));
    };
    let snapshot = provider.clone().get_pipeline().await;
    Ok(Json(snapshot))
}

#[derive(Serialize)]
struct DebugHealthComponent {
    name: String,
    healthy: bool,
    last_tick: Option<String>,
    error_count_last_hour: u32,
    running: bool,
}

#[derive(Serialize)]
struct DebugHealthResponse {
    components: Vec<DebugHealthComponent>,
    system_healthy: bool,
}

async fn debug_health_handler(
    State(state): State<ApiState>,
) -> Result<Json<DebugHealthResponse>, StatusCode> {
    let now = time::OffsetDateTime::now_utc();
    let poller_threshold_secs: i64 = 15;
    let mut components = Vec::new();

    #[cfg(target_os = "macos")]
    {
        if let Some(ref guard) = state.app_detector_state {
            let s = guard.read().await;
            let last = s.last_scan_ts;
            let healthy = last
                .map(|t| (now - t).whole_seconds() <= poller_threshold_secs)
                .unwrap_or(false);
            components.push(DebugHealthComponent {
                name: "AppDetector".to_string(),
                healthy,
                last_tick: last.map(|t| t.to_string()),
                error_count_last_hour: 0,
                running: true,
            });
        }
        if let Some(ref guard) = state.workspace_resolver_state {
            let s = guard.read().await;
            let last = s.last_run_at;
            let healthy = last
                .map(|t| (now - t).whole_seconds() <= poller_threshold_secs)
                .unwrap_or(false);
            components.push(DebugHealthComponent {
                name: "WorkspaceResolver".to_string(),
                healthy,
                last_tick: last.map(|t| t.to_string()),
                error_count_last_hour: 0,
                running: true,
            });
        }
    }

    if let Some(ref w) = state.fs_watcher {
        let watchers = w.read().await.watcher_status();
        components.push(DebugHealthComponent {
            name: "FsWatcherManager".to_string(),
            healthy: !watchers.is_empty(),
            last_tick: None,
            error_count_last_hour: 0,
            running: true,
        });
    }
    components.push(DebugHealthComponent {
        name: "AttributionEngine".to_string(),
        healthy: state.attribution_debug.is_some(),
        last_tick: None,
        error_count_last_hour: 0,
        running: true,
    });
    components.push(DebugHealthComponent {
        name: "SessionLifecycle".to_string(),
        healthy: true,
        last_tick: None,
        error_count_last_hour: 0,
        running: true,
    });
    components.push(DebugHealthComponent {
        name: "RetentionJob".to_string(),
        healthy: true,
        last_tick: None,
        error_count_last_hour: 0,
        running: true,
    });

    let system_healthy = components.iter().all(|c| c.healthy);
    Ok(Json(DebugHealthResponse {
        components,
        system_healthy,
    }))
}

#[derive(Serialize)]
struct DebugWarning {
    code: String,
    severity: String,
    message: Option<String>,
}

#[derive(Serialize)]
struct DebugWarningsResponse {
    warnings: Vec<DebugWarning>,
}

async fn debug_warnings_handler(
    State(state): State<ApiState>,
) -> Result<Json<DebugWarningsResponse>, StatusCode> {
    let mut warnings = Vec::new();
    #[cfg(target_os = "macos")]
    {
        let cursor_running = if let Some(ref g) = state.app_detector_state {
            let s = g.read().await;
            s.instances
                .iter()
                .any(|i| format!("{:?}", i.app).to_lowercase().contains("cursor"))
        } else {
            false
        };
        let workspace_detected = if let Some(ref g) = state.workspace_resolver_state {
            let s = g.read().await;
            !s.items.is_empty()
        } else {
            false
        };
        if cursor_running && !workspace_detected {
            warnings.push(DebugWarning {
                code: "WORKSPACE_MISSING".to_string(),
                severity: "medium".to_string(),
                message: Some("Workspace resolution inactive".to_string()),
            });
        }
    }
    Ok(Json(DebugWarningsResponse { warnings }))
}

// ---------------------------------------------------------------------------
// UI view model endpoints
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct UIStateParams {
    recent_limit: Option<u32>,
}

#[derive(Deserialize)]
struct UISessionParams {
    events_limit: Option<u32>,
}

fn trust_from_risk_and_warnings(risk_score: i32, has_high: bool, has_medium: bool) -> &'static str {
    if risk_score >= 70 || has_high {
        "Risky"
    } else if risk_score >= 30 || has_medium {
        "NeedsReview"
    } else {
        "Trusted"
    }
}

fn session_row_from_summary(s: &SessionSummary, flags: &[Flag]) -> UISessionRow {
    let has_high = flags.iter().any(|f| matches!(f.severity, antidote_core::Severity::High | antidote_core::Severity::Crit));
    let has_medium = flags.iter().any(|f| f.severity == antidote_core::Severity::Med);
    let trust = trust_from_risk_and_warnings(s.risk.score, has_high, has_medium);
    UISessionRow {
        id: s.session_id.clone(),
        app: s.app.clone(),
        started_at: s.start_ts.to_string(),
        last_active_ts: Some(s.last_event_ts.to_string()),
        ended_at: s.end_ts.as_ref().map(|t| t.to_string()),
        trust: trust.to_string(),
        risk_score: s.risk.score,
        drift_score: s.drift_index.unwrap_or(0) as i32,
        event_count: s.counts.events_total,
        duration_seconds: s.end_ts.map(|e| (e - s.start_ts).whole_seconds() as u64),
        summary_json: s.summary_json.as_ref().and_then(|j| serde_json::from_str(j).ok()),
    }
}

#[derive(Serialize)]
struct UISessionRow {
    id: String,
    app: String,
    started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_active_ts: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ended_at: Option<String>,
    trust: String,
    risk_score: i32,
    drift_score: i32,
    event_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary_json: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct UIWarning {
    code: String,
    severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Serialize)]
struct UIGlobalState {
    trust: String,
    confidence: String,
    health: String,
    reasons: Vec<String>,
    warnings: Vec<UIWarning>,
}

#[derive(Serialize)]
struct UIStateResponse {
    version: String,
    now: String,
    global: UIGlobalState,
    active_sessions: Vec<UISessionRow>,
    recent_sessions: Vec<UISessionRow>,
}

#[derive(Serialize)]
struct UITopFinding {
    label: String,
    severity: String,
    count: u32,
    examples: Vec<String>,
}

#[derive(Serialize)]
struct UITouchedFile {
    path: String,
    op: String,
    count: u32,
}

#[derive(Serialize)]
struct UIDomainContact {
    domain: String,
    count: u32,
    egress_bytes: u64,
}

#[derive(Serialize)]
struct UIRecentEvent {
    ts: String,
    kind: String,
    summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    attribution_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence: Option<String>,
}

#[derive(Serialize)]
struct UISessionDiagnostics {
    telemetry_confidence: String,
    attribution_quality: f64,
    root_coverage: f64,
}

#[derive(Serialize)]
struct UISessionResponse {
    session: UISessionRow,
    top_findings: Vec<UITopFinding>,
    touched_files: Vec<UITouchedFile>,
    domains: Vec<UIDomainContact>,
    recent_events: Vec<UIRecentEvent>,
    diagnostics: UISessionDiagnostics,
}

async fn ui_state_handler(
    State(state): State<ApiState>,
    Query(params): Query<UIStateParams>,
) -> Result<Json<UIStateResponse>, StatusCode> {
    let now = time::OffsetDateTime::now_utc();
    let recent_limit = params.recent_limit.unwrap_or(10).min(50);

    let all_sessions = state
        .storage
        .list_sessions(Some(100), None, None, None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let active_sessions: Vec<SessionSummary> = if let Some(ref mgr) = state.session_manager {
        mgr.get_active_sessions().await
    } else {
        all_sessions
            .iter()
            .filter(|s| s.end_ts.is_none())
            .cloned()
            .collect()
    };

    let mut recent = all_sessions
        .into_iter()
        .filter(|s| s.end_ts.is_some())
        .take(recent_limit as usize)
        .collect::<Vec<_>>();
    recent.sort_by(|a, b| b.start_ts.cmp(&a.start_ts));

    let mut warnings = Vec::new();
    let wr = state.storage.list_watched_roots().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let watchers = match &state.fs_watcher {
        Some(w) => w.read().await.watcher_status(),
        None => vec![],
    };
    let fs_active = !watchers.is_empty();
    let health = if fs_active { "Healthy" } else { "Degraded" };
    let confidence = if fs_active { "High" } else { "Medium" };
    let reasons: Vec<String> = if !fs_active {
        vec!["fs_watcher_inactive".to_string()]
    } else {
        vec![]
    };

    #[cfg(target_os = "macos")]
    {
        let cursor_running = if let Some(ref g) = state.app_detector_state {
            let s = g.read().await;
            s.instances
                .iter()
                .any(|i| format!("{:?}", i.app).to_lowercase().contains("cursor"))
        } else {
            false
        };
        let workspace_detected = if let Some(ref g) = state.workspace_resolver_state {
            let s = g.read().await;
            !s.items.is_empty()
        } else {
            false
        };
        if cursor_running && !workspace_detected {
            warnings.push(UIWarning {
                code: "WORKSPACE_MISSING".to_string(),
                severity: "medium".to_string(),
                message: Some("Workspace resolution inactive".to_string()),
            });
        }
    }

    let has_high_warn = warnings.iter().any(|w| w.severity == "high");
    let has_medium_warn = warnings.iter().any(|w| w.severity == "medium");
    let global_trust = if has_high_warn {
        "Risky"
    } else if has_medium_warn {
        "NeedsReview"
    } else {
        "Trusted"
    };

    let mut active_rows = Vec::new();
    for s in &active_sessions {
        let flags = state.storage.list_flags(&s.session_id, Some(10), None).await.unwrap_or_default();
        active_rows.push(session_row_from_summary(s, &flags));
    }

    let mut recent_rows = Vec::new();
    for s in &recent {
        let flags = state.storage.list_flags(&s.session_id, Some(10), None).await.unwrap_or_default();
        recent_rows.push(session_row_from_summary(s, &flags));
    }

    let _ = wr; // roots available for future use
    Ok(Json(UIStateResponse {
        version: "0.1.0".to_string(),
        now: now.to_string(),
        global: UIGlobalState {
            trust: global_trust.to_string(),
            confidence: confidence.to_string(),
            health: health.to_string(),
            reasons,
            warnings,
        },
        active_sessions: active_rows,
        recent_sessions: recent_rows,
    }))
}

async fn ui_session_handler(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
    Query(params): Query<UISessionParams>,
) -> Result<Json<UISessionResponse>, StatusCode> {
    let events_limit = params.events_limit.unwrap_or(20).min(100);

    let session = state
        .storage
        .get_session(&session_id)
        .await
        .map_err(|e| {
            tracing::error!("ui_session get_session failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    let flags = state
        .storage
        .list_flags(&session_id, Some(50), None)
        .await
        .map_err(|e| {
            tracing::error!("ui_session list_flags failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let events = state
        .storage
        .list_events(&session_id, Some(events_limit), None)
        .await
        .map_err(|e| {
            tracing::error!("ui_session list_events failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let session_row = session_row_from_summary(&session, &flags);

    let mut findings: HashMap<String, (String, Vec<String>, u32)> = HashMap::new();
    for f in &flags {
        let sev = match f.severity {
            antidote_core::Severity::Crit => "high",
            antidote_core::Severity::High => "high",
            antidote_core::Severity::Med => "medium",
            antidote_core::Severity::Low => "low",
        };
        let label = format!("{:?}", f.label);
        let entry = findings.entry(label.clone()).or_insert((sev.to_string(), Vec::new(), 0));
        entry.2 += 1;
        if entry.1.len() < 3 {
            entry.1.push(f.message.clone());
        }
    }
    let top_findings: Vec<UITopFinding> = findings
        .into_iter()
        .map(|(label, (severity, examples, count))| UITopFinding {
            label,
            severity,
            count,
            examples,
        })
        .collect();

    let mut path_counts: HashMap<(String, &'static str), u32> = HashMap::new();
    for e in &events {
        let (op, path) = match e.event_type {
            EventType::FileRead => ("read", e.payload.get("path").and_then(|v| v.as_str())),
            EventType::FileWrite | EventType::FileCreate | EventType::FileRename => {
                ("write", e.payload.get("path").and_then(|v| v.as_str()))
            }
            EventType::FileDelete => ("delete", e.payload.get("path").and_then(|v| v.as_str())),
            _ => continue,
        };
        if let Some(p) = path {
            *path_counts.entry((p.to_string(), op)).or_insert(0) += 1;
        }
    }
    let mut touched_files: Vec<UITouchedFile> = path_counts
        .into_iter()
        .map(|((path, op), count)| UITouchedFile {
            path,
            op: op.to_string(),
            count,
        })
        .collect();
    touched_files.sort_by(|a, b| b.count.cmp(&a.count));
    touched_files.truncate(20);

    let mut domain_counts: HashMap<String, (u32, u64)> = HashMap::new();
    for e in &events {
        if matches!(e.event_type, EventType::NetHttp | EventType::NetConnect) {
            if let Some(d) = e.payload.get("domain").and_then(|v| v.as_str()) {
                let bytes = e.payload.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                let ent = domain_counts.entry(d.to_string()).or_insert((0, 0));
                ent.0 += 1;
                ent.1 += bytes;
            }
        }
    }
    let mut domains: Vec<UIDomainContact> = domain_counts
        .into_iter()
        .map(|(domain, (count, egress_bytes))| UIDomainContact {
            domain,
            count,
            egress_bytes,
        })
        .collect();
    domains.sort_by(|a, b| b.count.cmp(&a.count));
    domains.truncate(20);

    let recent_events: Vec<UIRecentEvent> = events
        .iter()
        .map(|e| {
            let kind = match e.event_type {
                EventType::FileRead | EventType::FileWrite | EventType::FileCreate
                | EventType::FileDelete | EventType::FileRename => "fs",
                EventType::NetHttp | EventType::NetConnect => "net",
                EventType::CmdExec | EventType::ProcSpawn => "cmd",
                _ => "flag",
            };
            let summary = e
                .payload
                .get("path")
                .or(e.payload.get("domain"))
                .map(|v| v.to_string())
                .unwrap_or_else(|| format!("{:?}", e.event_type));
            UIRecentEvent {
                ts: e.ts.to_string(),
                kind: kind.to_string(),
                summary,
                attribution_reason: e.attribution_reason.clone(),
                confidence: e.attribution_confidence.map(|c| format!("{}", c)),
            }
        })
        .collect();

    let (tel_conf, attr_qual, root_cov) = match &state.telemetry_integrity {
        Some(p) => {
            let aq = p.clone().get_attribution_quality().await;
            let rc = p.clone().get_root_coverage().await;
            let tc = aq.get("quality_score").and_then(|x| x.as_f64()).unwrap_or(1.0);
            let rc_val = rc.get("root_coverage_ratio").and_then(|x| x.as_f64()).unwrap_or(1.0);
            ("High".to_string(), tc, rc_val)
        }
        None => ("Medium".to_string(), 1.0, 1.0),
    };

    Ok(Json(UISessionResponse {
        session: session_row,
        top_findings,
        touched_files,
        domains,
        recent_events,
        diagnostics: UISessionDiagnostics {
            telemetry_confidence: tel_conf,
            attribution_quality: attr_qual,
            root_coverage: root_cov,
        },
    }))
}

#[cfg(target_os = "macos")]
#[derive(Serialize)]
struct DebugAppsResponse {
    detected: Vec<DebugAppDto>,
    last_scan_ts: Option<String>,
}

#[cfg(target_os = "macos")]
#[derive(Serialize)]
struct DebugAppDto {
    app: antidote_collectors::AppKind,
    pid: i32,
    bundle_id: Option<String>,
    started_at: String,
}

#[cfg(target_os = "macos")]
async fn debug_apps_handler(
    State(state): State<ApiState>,
) -> Result<Json<DebugAppsResponse>, StatusCode> {
    let Some(ref guard) = state.app_detector_state else {
        return Ok(Json(DebugAppsResponse {
            detected: vec![],
            last_scan_ts: None,
        }));
    };
    let s = guard.read().await;
    let detected: Vec<DebugAppDto> = s
        .instances
        .iter()
        .map(|i| DebugAppDto {
            app: i.app.clone(),
            pid: i.pid,
            bundle_id: i.bundle_id.clone(),
            started_at: i
                .started_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
                .to_string(),
        })
        .collect();
    let last_scan_ts = s
        .last_scan_ts
        .map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default().to_string());
    Ok(Json(DebugAppsResponse {
        detected,
        last_scan_ts,
    }))
}

#[cfg(target_os = "macos")]
#[derive(Serialize)]
struct DebugWorkspacesResponse {
    items: Vec<DebugWorkspaceItemDto>,
    last_run_at: Option<String>,
    last_error: Option<String>,
}

#[cfg(target_os = "macos")]
#[derive(Serialize)]
struct DebugWorkspaceItemDto {
    app: antidote_collectors::AppKind,
    pid: i32,
    roots: Vec<String>,
    confidence: antidote_collectors::Confidence,
    #[serde(rename = "source_tier")]
    source: antidote_collectors::SourceTier,
    observed_at: String,
}

#[cfg(target_os = "macos")]
async fn debug_workspaces_handler(
    State(state): State<ApiState>,
) -> Result<Json<DebugWorkspacesResponse>, StatusCode> {
    let Some(ref guard) = state.workspace_resolver_state else {
        return Ok(Json(DebugWorkspacesResponse {
            items: vec![],
            last_run_at: None,
            last_error: None,
        }));
    };
    let s = guard.read().await;
    let items: Vec<DebugWorkspaceItemDto> = s
        .items
        .iter()
        .map(|i| DebugWorkspaceItemDto {
            app: i.app.clone(),
            pid: i.pid,
            roots: i.roots.clone(),
            confidence: i.confidence,
            source: i.source,
            observed_at: i
                .observed_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
                .to_string(),
        })
        .collect();
    let last_run_at = s
        .last_run_at
        .map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default().to_string());
    Ok(Json(DebugWorkspacesResponse {
        items,
        last_run_at,
        last_error: s.last_error.clone(),
    }))
}

#[cfg(target_os = "macos")]
async fn debug_workspaces_by_app_handler(
    State(state): State<ApiState>,
    Path(app_name): Path<String>,
) -> Result<Json<DebugWorkspacesResponse>, StatusCode> {
    let Some(ref guard) = state.workspace_resolver_state else {
        return Ok(Json(DebugWorkspacesResponse {
            items: vec![],
            last_run_at: None,
            last_error: None,
        }));
    };
    let s = guard.read().await;
    let app_lower = app_name.to_lowercase();
    let items: Vec<DebugWorkspaceItemDto> = s
        .items
        .iter()
        .filter(|i| i.app.as_display_str().to_lowercase() == app_lower)
        .map(|i| DebugWorkspaceItemDto {
            app: i.app.clone(),
            pid: i.pid,
            roots: i.roots.clone(),
            confidence: i.confidence,
            source: i.source,
            observed_at: i
                .observed_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
                .to_string(),
        })
        .collect();
    let last_run_at = s
        .last_run_at
        .map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default().to_string());
    Ok(Json(DebugWorkspacesResponse {
        items,
        last_run_at,
        last_error: s.last_error.clone(),
    }))
}

async fn debug_roots_handler(
    State(state): State<ApiState>,
) -> Result<Json<Vec<WatchedRoot>>, StatusCode> {
    let roots = state
        .storage
        .list_watched_roots()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(roots))
}

async fn debug_watchers_handler(
    State(state): State<ApiState>,
) -> Result<Json<Vec<antidote_collectors::WatcherStatus>>, StatusCode> {
    let watchers = match &state.fs_watcher {
        Some(w) => w.read().await.watcher_status(),
        None => vec![],
    };
    Ok(Json(watchers))
}

#[cfg(target_os = "macos")]
#[derive(Serialize)]
struct ZeroConfigStatusResponse {
    apps: DebugAppsResponse,
    workspaces: DebugWorkspacesResponse,
    roots: Vec<WatchedRoot>,
    watchers: Vec<antidote_collectors::WatcherStatus>,
    global_confidence: String,
    system_health: String,
    root_count: usize,
    attribution_quality: f64,
    warnings: Vec<DebugWarning>,
    event_rate_last_1min: u64,
    dropped_events_last_1min: u64,
}

#[cfg(target_os = "macos")]
async fn debug_zero_config_status_handler(
    State(state): State<ApiState>,
) -> Result<Json<ZeroConfigStatusResponse>, StatusCode> {
    let apps = match &state.app_detector_state {
        Some(guard) => {
            let s = guard.read().await;
            let detected: Vec<DebugAppDto> = s
                .instances
                .iter()
                .map(|i| DebugAppDto {
                    app: i.app.clone(),
                    pid: i.pid,
                    bundle_id: i.bundle_id.clone(),
                    started_at: i
                        .started_at
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default()
                        .to_string(),
                })
                .collect();
            let last_scan_ts = s
                .last_scan_ts
                .map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default().to_string());
            DebugAppsResponse {
                detected,
                last_scan_ts,
            }
        }
        None => DebugAppsResponse {
            detected: vec![],
            last_scan_ts: None,
        },
    };
    let workspaces = match &state.workspace_resolver_state {
        Some(guard) => {
            let s = guard.read().await;
            let items: Vec<DebugWorkspaceItemDto> = s
                .items
                .iter()
                .map(|i| DebugWorkspaceItemDto {
                    app: i.app.clone(),
                    pid: i.pid,
                    roots: i.roots.clone(),
                    confidence: i.confidence,
                    source: i.source,
                    observed_at: i
                        .observed_at
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default()
                        .to_string(),
                })
                .collect();
            let last_run_at = s
                .last_run_at
                .map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default().to_string());
            DebugWorkspacesResponse {
                items,
                last_run_at,
                last_error: s.last_error.clone(),
            }
        }
        None => DebugWorkspacesResponse {
            items: vec![],
            last_run_at: None,
            last_error: None,
        },
    };
    let roots = state
        .storage
        .list_watched_roots()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let watchers = match &state.fs_watcher {
        Some(w) => w.read().await.watcher_status(),
        None => vec![],
    };
    let fs_active = !watchers.is_empty();
    let ws_high = workspaces
        .items
        .iter()
        .any(|i| format!("{:?}", i.confidence) == "High");
    let (global_confidence, _reasons): (String, Vec<String>) = if !fs_active {
        ("Low".to_string(), vec![])
    } else if !ws_high && !workspaces.items.is_empty() {
        ("Medium".to_string(), vec![])
    } else if !state.proxy_enabled {
        ("Medium".to_string(), vec![])
    } else {
        ("High".to_string(), vec![])
    };
    let system_health = if fs_active { "Healthy" } else { "Degraded" }.to_string();
    let mut warn_list = Vec::new();
    if !workspaces.items.is_empty() && apps.detected.is_empty() {
        warn_list.push(DebugWarning {
            code: "NO_ACTIVITY_CAPTURED".to_string(),
            severity: "medium".to_string(),
            message: Some("No activity captured".to_string()),
        });
    }
    let attribution_quality = match &state.telemetry_integrity {
        Some(p) => {
            let v = p.clone().get_attribution_quality().await;
            v.get("quality_score")
                .and_then(|x| x.as_f64())
                .unwrap_or(1.0)
        }
        None => 1.0,
    };
    let dropped = state.drop_metrics.as_ref().map(|m| m.get_dropped()).unwrap_or(0);
    Ok(Json(ZeroConfigStatusResponse {
        apps,
        workspaces,
        roots: roots.clone(),
        watchers,
        global_confidence,
        system_health,
        root_count: roots.len(),
        attribution_quality,
        warnings: warn_list,
        event_rate_last_1min: 0,
        dropped_events_last_1min: dropped,
    }))
}

#[derive(Serialize)]
struct ZeroConfigHealthResponse {
    active_apps: serde_json::Value,
    current_foreground: serde_json::Value,
    resolved_workspaces: serde_json::Value,
    watched_roots: Vec<WatchedRoot>,
    watcher_status: Vec<antidote_collectors::WatcherStatus>,
    event_drops: u64,
    retention_events_days: u64,
    retention_run_every_minutes: u64,
    global_confidence: String,
    confidence_reasons: Vec<String>,
}

async fn debug_zero_config_health_handler(
    State(state): State<ApiState>,
) -> Result<Json<ZeroConfigHealthResponse>, StatusCode> {
    #[cfg(target_os = "macos")]
    let active_apps = match &state.app_detector_state {
        Some(guard) => {
            let s = guard.read().await;
            serde_json::json!({
                "detected": s.instances.iter().map(|i| serde_json::json!({
                    "app": i.app,
                    "pid": i.pid,
                })).collect::<Vec<_>>(),
                "last_scan_ts": s.last_scan_ts.map(|t| t.to_string()),
            })
        }
        None => serde_json::json!({ "detected": [], "last_scan_ts": null }),
    };
    #[cfg(not(target_os = "macos"))]
    let active_apps = serde_json::json!({ "detected": [], "last_scan_ts": null });

    #[cfg(target_os = "macos")]
    let current_foreground = match &state.foreground_state {
        Some(guard) => {
            let app = guard.read().await.clone();
            serde_json::json!(app)
        }
        None => serde_json::json!(null),
    };
    #[cfg(not(target_os = "macos"))]
    let current_foreground = serde_json::json!(null);

    #[cfg(target_os = "macos")]
    let resolved_workspaces = match &state.workspace_resolver_state {
        Some(guard) => {
            let s = guard.read().await;
            serde_json::json!({
                "items": s.items,
                "last_run_at": s.last_run_at.map(|t| t.to_string()),
                "last_error": s.last_error,
            })
        }
        None => serde_json::json!({ "items": [], "last_run_at": null, "last_error": null }),
    };
    #[cfg(not(target_os = "macos"))]
    let resolved_workspaces = serde_json::json!({ "items": [], "last_run_at": null, "last_error": null });
    let roots = state.storage.list_watched_roots().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let watchers = match &state.fs_watcher {
        Some(w) => w.read().await.watcher_status(),
        None => vec![],
    };
    let event_drops = state.drop_metrics.as_ref().map(|m| m.get_dropped()).unwrap_or(0);
    Ok(Json(ZeroConfigHealthResponse {
        active_apps,
        current_foreground,
        resolved_workspaces,
        watched_roots: roots,
        watcher_status: watchers,
        event_drops,
        retention_events_days: 7,
        retention_run_every_minutes: 60,
        global_confidence: "Medium".to_string(),
        confidence_reasons: vec![],
    }))
}

#[derive(Serialize)]
struct ConfidenceResponse {
    global: String,
    global_reasons: Vec<String>,
    per_session: Vec<PerSessionConfidenceDto>,
}

#[derive(Serialize)]
struct PerSessionConfidenceDto {
    session_id: String,
    confidence: String,
    reasons: Vec<String>,
}

#[derive(Serialize)]
struct PerAppConfidence {
    app: String,
    confidence: String,
}

async fn debug_confidence_handler(
    State(state): State<ApiState>,
) -> Result<Json<ConfidenceResponse>, StatusCode> {
    let mut reasons = Vec::new();
    let fs_active = match &state.fs_watcher {
        Some(w) => !w.read().await.watcher_status().is_empty(),
        None => false,
    };
    let proxy_active = state.proxy_enabled;

    let (global, _per_app): (String, Vec<PerAppConfidence>) = if fs_active && proxy_active {
        #[cfg(target_os = "macos")]
        {
            let audit_active = antidote_collectors::AuditCollector::check_availability();
            if audit_active {
                (String::from("High"), vec![])
            } else {
                reasons.push("workspace_confidence_low".to_string());
                (String::from("Medium"), vec![])
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            reasons.push("no_audit_collector".to_string());
            (String::from("Medium"), vec![])
        }
    } else {
        if !fs_active {
            reasons.push("no_fs_watcher".to_string());
        }
        if !proxy_active {
            reasons.push("proxy_disabled".to_string());
        }
        (String::from("Low"), vec![])
    };

    let per_session = vec![]; // TODO: build from active sessions
    Ok(Json(ConfidenceResponse {
        global,
        global_reasons: reasons,
        per_session,
    }))
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

#[derive(Serialize)]
struct ActiveSessionDto {
    id: String,
    app: String,
    pid: i32,
    started_at: String,
    last_active_ts: String,
    event_count: u64,
}

#[derive(Serialize)]
struct ActiveSessionsResponse {
    active: Vec<ActiveSessionDto>,
}

async fn list_active_sessions_handler(
    State(state): State<ApiState>,
) -> Result<Json<ActiveSessionsResponse>, StatusCode> {
    let sessions = if let Some(manager) = &state.session_manager {
        manager.get_active_sessions().await
    } else {
        let all_sessions = state
            .storage
            .list_sessions(None, None, None, None)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        all_sessions
            .into_iter()
            .filter(|s| s.end_ts.is_none())
            .collect()
    };
    let active: Vec<ActiveSessionDto> = sessions
        .into_iter()
        .map(|s| ActiveSessionDto {
            id: s.session_id,
            app: s.app,
            pid: s.root_pid,
            started_at: s.start_ts.to_string(),
            last_active_ts: s.last_event_ts.to_string(),
            event_count: s.counts.events_total,
        })
        .collect();
    Ok(Json(ActiveSessionsResponse { active }))
}

#[derive(Deserialize)]
struct SessionsAllParams {
    limit: Option<u32>,
}

async fn debug_sessions_all_handler(
    State(state): State<ApiState>,
    Query(params): Query<SessionsAllParams>,
) -> Result<Json<Vec<SessionSummary>>, StatusCode> {
    let limit = params.limit.unwrap_or(10);
    state
        .storage
        .list_sessions(Some(limit), None, None, None)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
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

#[cfg(not(target_os = "macos"))]
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

const UI_NOT_BUILT_HTML: &str = r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Antidote</title></head>
<body style="font-family:system-ui;padding:2rem;max-width:600px;">
<h1>UI not built</h1>
<p>Run: <code>cd ui && npm install && npm run build</code></p>
</body></html>"#;

async fn ui_index_handler(
    State(state): State<ApiState>,
) -> impl IntoResponse {
    if let Some(ref ui_dist) = state.ui_dist {
        let index_path = ui_dist.join("index.html");
        if index_path.exists() {
            if let Ok(html) = tokio::fs::read_to_string(&index_path).await {
                return Html(html).into_response();
            }
        }
    }
    Html(UI_NOT_BUILT_HTML).into_response()
}

async fn ui_insights_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../static/insights.html"))
}

async fn baselines_handler(
    State(state): State<ApiState>,
) -> Result<Json<Vec<AppBaselineRow>>, StatusCode> {
    let baselines = state
        .storage
        .get_all_baselines()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(baselines))
}

#[derive(Serialize)]
pub struct InsightsResponse {
    pub baselines: Vec<AppBaselineRow>,
    pub risk_trend_7d: Vec<DayRisk>,
    pub top_repeated_risk: Vec<RiskPattern>,
    pub sessions_with_drift: Vec<SessionDriftSummary>,
}

#[derive(Serialize)]
pub struct DayRisk {
    pub date: String,
    pub session_count: u32,
    pub avg_risk_score: f64,
}

#[derive(Serialize)]
pub struct RiskPattern {
    pub app: String,
    pub rule_id: String,
    pub count: u32,
}

#[derive(Serialize)]
pub struct SessionDriftSummary {
    pub session_id: String,
    pub app: String,
    pub drift_index: Option<u8>,
    pub risk_score: i32,
}

async fn insights_handler(
    State(state): State<ApiState>,
) -> Result<Json<InsightsResponse>, StatusCode> {
    let cutoff = time::OffsetDateTime::now_utc() - time::Duration::days(7);
    let cutoff_str = cutoff
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
        .to_string();

    let baselines = state
        .storage
        .get_all_baselines()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let sessions = state
        .storage
        .list_sessions(Some(500), None, Some(&cutoff_str), None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut by_date: std::collections::HashMap<String, (u32, i64)> = std::collections::HashMap::new();
    for s in &sessions {
        let date = s.start_ts.date().to_string();
        let e = by_date.entry(date).or_insert((0, 0));
        e.0 += 1;
        e.1 += s.risk.score as i64;
    }
    let mut risk_trend_7d: Vec<DayRisk> = by_date
        .into_iter()
        .map(|(date, (session_count, total_score))| DayRisk {
            date,
            session_count,
            avg_risk_score: if session_count > 0 {
                total_score as f64 / session_count as f64
            } else {
                0.0
            },
        })
        .collect();
    risk_trend_7d.sort_by(|a, b| a.date.cmp(&b.date));

    let risk_since = state
        .storage
        .get_risk_history_since(cutoff)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut top_repeated_risk: Vec<RiskPattern> = risk_since
        .into_iter()
        .map(|(app, rule_id, count)| RiskPattern { app, rule_id, count })
        .collect();
    top_repeated_risk.sort_by(|a, b| b.count.cmp(&a.count));

    let sessions_with_drift: Vec<SessionDriftSummary> = sessions
        .iter()
        .filter(|s| s.drift_index.is_some())
        .map(|s| SessionDriftSummary {
            session_id: s.session_id.clone(),
            app: s.app.clone(),
            drift_index: s.drift_index,
            risk_score: s.risk.score,
        })
        .collect();

    Ok(Json(InsightsResponse {
        baselines,
        risk_trend_7d,
        top_repeated_risk,
        sessions_with_drift,
    }))
}

// --- Phase 6: Enforcement & Emergency ---

#[derive(Serialize)]
pub struct EnforcementGetResponse {
    #[serde(flatten)]
    pub config: EnforcementConfig,
    pub frozen: bool,
    pub safe_mode: SafeModeConfig,
}

async fn enforcement_get_handler(
    State(state): State<ApiState>,
) -> Result<Json<EnforcementGetResponse>, StatusCode> {
    let config = state.enforcement.read().await.clone();
    let frozen = *state.frozen.read().await;
    let safe_mode = state.safe_mode.read().await.clone();
    Ok(Json(EnforcementGetResponse {
        config,
        frozen,
        safe_mode,
    }))
}

#[derive(Deserialize)]
struct EnforcementPostBody {
    enabled: Option<bool>,
    block_unknown_domains: Option<bool>,
    block_high_egress: Option<bool>,
    block_dangerous_commands: Option<bool>,
    auto_freeze_high_risk: Option<bool>,
    egress_threshold_bytes: Option<u64>,
    safe_mode_enabled: Option<bool>,
}

async fn enforcement_post_handler(
    State(state): State<ApiState>,
    Json(body): Json<EnforcementPostBody>,
) -> Result<Json<EnforcementGetResponse>, StatusCode> {
    let mut config = state.enforcement.write().await;
    if let Some(v) = body.enabled {
        config.enabled = v;
    }
    if let Some(v) = body.block_unknown_domains {
        config.block_unknown_domains = v;
    }
    if let Some(v) = body.block_high_egress {
        config.block_high_egress = v;
    }
    if let Some(v) = body.block_dangerous_commands {
        config.block_dangerous_commands = v;
    }
    if let Some(v) = body.auto_freeze_high_risk {
        config.auto_freeze_high_risk = v;
    }
    if let Some(v) = body.egress_threshold_bytes {
        config.egress_threshold_bytes = v;
    }
    let config_out = config.clone();
    drop(config);
    if let Some(v) = body.safe_mode_enabled {
        let mut safe = state.safe_mode.write().await;
        safe.enabled = v;
    }
    let frozen = *state.frozen.read().await;
    let safe_mode = state.safe_mode.read().await.clone();
    Ok(Json(EnforcementGetResponse {
        config: config_out,
        frozen,
        safe_mode,
    }))
}

async fn emergency_freeze_handler(
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    *state.frozen.write().await = true;
    if let Some(ref tx) = state.freeze_tx {
        let _ = tx.send(());
    }
    Ok(Json(serde_json::json!({ "frozen": true })))
}

async fn emergency_unfreeze_handler(
    State(state): State<ApiState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    *state.frozen.write().await = false;
    Ok(Json(serde_json::json!({ "frozen": false })))
}

async fn ui_security_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../static/security.html"))
}

async fn ui_static_handler(
    State(state): State<ApiState>,
    Path(path): Path<String>,
) -> impl IntoResponse {
    if path.starts_with("assets/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Some(ref ui_dist) = state.ui_dist {
        let index_path = ui_dist.join("index.html");
        if index_path.exists() {
            if let Ok(html) = tokio::fs::read_to_string(&index_path).await {
                return Html(html).into_response();
            }
        }
    }
    Html(UI_NOT_BUILT_HTML).into_response()
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
