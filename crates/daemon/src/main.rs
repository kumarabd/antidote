//! Antidote daemon - main entry point

mod attribution_engine;
mod attribution_state;
mod auto_root_manager;
mod telemetry_integrity;
mod file_event_coalescer;
mod focus_manager;
mod ignore_filters;
mod pipeline;
mod rate_limiter;
mod root_policy;
mod session_lifecycle;
// mod watcher_supervisor; // P0: wired when watcher supervisor integrated with API

use antidote_api::create_router;
use antidote_behavior;
use antidote_collectors::{FsWatcherManager, FsWatcherOptions, ProcessPoller, ProxyServer};
#[cfg(target_os = "macos")]
use antidote_collectors::{
    AppDetectorState, AppEvent, AppDetector, ForegroundPoller, MacAppDetector,
    spawn_foreground_activate_observer, WorkspaceResolver, WorkspaceResolverConfig,
    WorkspaceResolverState,
};
use antidote_core::{
    Event, EventType, Flag, Label, SessionSummary, Severity,
    EnforcementConfig, SafeModeConfig,
};
use antidote_ruleengine::RuleEngine;
use antidote_session::SessionManager;
use antidote_storage::{AppBaselineRow, Storage};
use anyhow::{Context, Result};
use futures::stream::StreamExt;
use pipeline::PipelineWorker;
use std::collections::HashMap;
use time::format_description::well_known::Rfc3339;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tracing::{info, warn};

/// Unified handle for daemon tasks: some return Result (e.g. API server), others run until cancelled ().
enum TaskHandle {
    WithResult(tokio::task::JoinHandle<Result<(), anyhow::Error>>),
    Unit(tokio::task::JoinHandle<()>),
}

impl TaskHandle {
    fn abort(&self) {
        match self {
            TaskHandle::WithResult(h) => h.abort(),
            TaskHandle::Unit(h) => h.abort(),
        }
    }
}

async fn await_task_handle(handle: TaskHandle) {
    match handle {
        TaskHandle::WithResult(h) => {
            match h.await {
                Ok(Err(e)) => warn!("API task error: {}", e),
                Err(e) => warn!("API task panicked: {}", e),
                _ => {}
            }
        }
        TaskHandle::Unit(h) => {
            let _ = h.await;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FsConfig {
    debounce_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProxyConfig {
    enabled: bool,
    listen_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RetentionConfig {
    days: u64,
    #[serde(default = "default_events_days")]
    events_days: u64,
    #[serde(default = "default_sessions_days")]
    sessions_days: u64,
    #[serde(default = "default_run_every_minutes")]
    run_every_minutes: u64,
}

fn default_events_days() -> u64 {
    7
}
fn default_sessions_days() -> u64 {
    90
}
fn default_run_every_minutes() -> u64 {
    60
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppDetectorConfig {
    enabled: bool,
    poll_interval_ms: u64,
}

impl Default for AppDetectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_ms: 60_000, // 60s reconciliation; NSWorkspace observer provides event-driven launch/terminate
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkspaceResolverConfigDaemon {
    enabled: bool,
    poll_interval_ms: u64,
    max_roots_per_app: usize,
    dev_dir_candidates: Vec<String>,
    lsof_fallback_enabled: bool,
    lsof_min_interval_ms: u64,
}

impl Default for WorkspaceResolverConfigDaemon {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval_ms: 30_000, // 30s fallback; FSEvents on storage dirs provides event-driven wake
            max_roots_per_app: 5,
            dev_dir_candidates: vec![
                "~/code".to_string(),
                "~/dev".to_string(),
                "~/projects".to_string(),
                "~/workspace".to_string(),
                "~/Documents".to_string(),
            ],
            lsof_fallback_enabled: true,
            lsof_min_interval_ms: 30000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AutoRootConfigDaemon {
    enabled: bool,
    max_auto_roots: usize,
    stale_disable_days: u32,
    #[serde(default = "default_apply_debounce_ms")]
    apply_debounce_ms: u64,
}

fn default_apply_debounce_ms() -> u64 {
    300
}

impl Default for AutoRootConfigDaemon {
    fn default() -> Self {
        Self {
            enabled: true,
            max_auto_roots: 20,
            stale_disable_days: 14,
            apply_debounce_ms: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileEventsConfig {
    #[serde(default = "default_coalesce_window_ms")]
    coalesce_window_ms: u64,
    /// Use PollWatcher instead of FSEvents (fallback). Fixes missed events for "unowned" paths on macOS (e.g. /tmp).
    #[serde(default)]
    use_poll_watcher: Option<bool>,
    /// Poll interval in ms when use_poll_watcher is enabled. Default 1000.
    #[serde(default = "default_poll_interval_ms")]
    poll_interval_ms: u64,
}

fn default_coalesce_window_ms() -> u64 {
    800
}

fn default_poll_interval_ms() -> u64 {
    1000
}

impl Default for FileEventsConfig {
    fn default() -> Self {
        Self {
            coalesce_window_ms: 800,
            use_poll_watcher: None,
            poll_interval_ms: 1000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FocusConfig {
    #[serde(default = "default_stabilization_ms")]
    stabilization_ms: u64,
}

fn default_stabilization_ms() -> u64 {
    1000
}

impl Default for FocusConfig {
    fn default() -> Self {
        Self {
            stabilization_ms: 1000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttributionConfig {
    #[serde(default = "default_recent_session_window_seconds")]
    recent_session_window_seconds: u64,
}

fn default_recent_session_window_seconds() -> u64 {
    300
}

impl Default for AttributionConfig {
    fn default() -> Self {
        Self {
            recent_session_window_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PipelineConfig {
    /// Tick interval for aggregate rule evaluation (Phase 3: 10s per design).
    #[serde(default = "default_tick_interval_secs")]
    tick_interval_secs: u64,
}

fn default_tick_interval_secs() -> u64 {
    10
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            tick_interval_secs: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LimitsConfig {
    #[serde(default = "default_max_events_per_second")]
    max_events_per_second: u32,
}

fn default_max_events_per_second() -> u32 {
    200
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_events_per_second: 200,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    db_url: String,
    listen_addr: String,
    rules_path: String,
    watch_processes: Vec<String>,
    poll_interval_secs: u64,
    idle_timeout_minutes: u64,
    fs: FsConfig,
    proxy: ProxyConfig,
    retention: RetentionConfig,
    #[serde(default)]
    app_detector: AppDetectorConfig,
    #[serde(default)]
    workspace_resolver: WorkspaceResolverConfigDaemon,
    #[serde(default)]
    auto_roots: AutoRootConfigDaemon,
    #[serde(default)]
    file_events: FileEventsConfig,
    #[serde(default)]
    pipeline: PipelineConfig, // Phase 3: tick_interval_secs for aggregate rules
    #[serde(default)]
    limits: LimitsConfig,
    #[serde(default)]
    focus: FocusConfig,
    #[serde(default)]
    attribution: AttributionConfig,
    #[serde(default)]
    enforcement: EnforcementConfig,
    #[serde(default)]
    safe_mode: SafeModeConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db_url: "sqlite:monitor.db".to_string(),
            listen_addr: "127.0.0.1:17845".to_string(),
            rules_path: "./rules/rules.yaml".to_string(),
            watch_processes: vec!["Cursor".to_string(), "Code".to_string(), "Claude".to_string()],
            poll_interval_secs: 2,
            idle_timeout_minutes: 20,
            fs: FsConfig { debounce_ms: 1000 },
            proxy: ProxyConfig {
                enabled: true,
                listen_addr: "127.0.0.1:17846".to_string(),
            },
            retention: RetentionConfig {
                days: 7,
                events_days: 7,
                sessions_days: 90,
                run_every_minutes: 60,
            },
            app_detector: AppDetectorConfig::default(),
            workspace_resolver: WorkspaceResolverConfigDaemon::default(),
            auto_roots: AutoRootConfigDaemon::default(),
            file_events: FileEventsConfig::default(),
            pipeline: PipelineConfig::default(),
            limits: LimitsConfig::default(),
            focus: FocusConfig::default(),
            attribution: AttributionConfig::default(),
            enforcement: EnforcementConfig::default(),
            safe_mode: SafeModeConfig::default(),
        }
    }
}

/// Step 5: Post-finalize processing (baseline, anomaly, escalation, drift)
async fn process_finalized_session(
    storage: &Storage,
    baselines: &tokio::sync::RwLock<std::collections::HashMap<String, antidote_behavior::AppBaseline>>,
    mut summary: antidote_core::SessionSummary,
) {
    let now = time::OffsetDateTime::now_utc();
    if summary.end_ts.is_none() {
        summary.end_ts = Some(now);
    }
    let current = baselines.read().await.get(&summary.app).cloned();
    let new_baseline = antidote_behavior::update_baseline_ema(
        current.as_ref(),
        &summary.app,
        &summary.counts,
        antidote_behavior::DEFAULT_EMA_ALPHA,
        now,
    );
    let row = AppBaselineRow {
        app: new_baseline.app.clone(),
        session_count: new_baseline.session_count as i64,
        avg_files_written: new_baseline.avg_files_written,
        avg_files_deleted: new_baseline.avg_files_deleted,
        avg_bytes_out: new_baseline.avg_bytes_out,
        avg_unknown_domains: new_baseline.avg_unknown_domains,
        avg_cmds: new_baseline.avg_cmds,
        var_files_written: new_baseline.var_files_written,
        var_bytes_out: new_baseline.var_bytes_out,
        var_unknown_domains: new_baseline.var_unknown_domains,
        var_cmds: new_baseline.var_cmds,
        last_updated: new_baseline.last_updated.format(&time::format_description::well_known::Rfc3339).unwrap_or_default().to_string(),
    };
    let _ = storage.upsert_app_baseline(&row).await;
    baselines.write().await.insert(summary.app.clone(), new_baseline.clone());

    let baseline_guard = baselines.read().await;
    let baseline_ref = baseline_guard.get(&summary.app);
    let anomaly_flags = antidote_behavior::detect_anomalies(
        &summary.session_id,
        &summary.app,
        &summary.counts,
        &summary.evidence,
        baseline_ref,
        &antidote_behavior::AnomalyConfig::default(),
    );
    let risk_counts = storage
        .get_risk_history_last_n_days(&summary.app, antidote_behavior::ESCALATION_DAYS)
        .await
        .unwrap_or_default();
    let escalation_flag = antidote_behavior::check_escalation(&summary.session_id, &summary.app, &risk_counts);
    let mut all_new_flags = anomaly_flags;
    if let Some(f) = escalation_flag {
        all_new_flags.push(f);
    }
    for flag in &all_new_flags {
        let _ = storage.insert_flags(&[flag.clone()]).await;
        if matches!(flag.severity, Severity::High | Severity::Crit) {
            let _ = storage.record_risk_history(&summary.app, &flag.rule_id, flag.ts).await;
        }
    }

    let drift_index = antidote_behavior::compute_drift_index(
        &summary,
        baseline_ref,
        &std::collections::HashSet::new(),
        &std::collections::HashSet::new(),
        0.0,
    );
    let baseline_comp = antidote_behavior::build_baseline_comparison_summary(&summary, baseline_ref);
    summary.drift_index = Some(drift_index);
    summary.baseline_comparison_summary = baseline_comp;

    let _ = storage.upsert_session_summary(&summary).await;
}

/// Phase 6: Run emergency freeze - kill active session processes and mark sessions forced_terminated
async fn run_emergency_freeze(
    storage: &Storage,
    session_manager: &SessionManager,
) {
    let active = session_manager.get_active_sessions().await;
    let now = time::OffsetDateTime::now_utc();
    let session_ids: Vec<String> = active.iter().map(|s| s.session_id.clone()).collect();
    let pids: Vec<i32> = active.iter().map(|s| s.root_pid).filter(|&p| p != 0).collect();

    for pid in pids {
        #[cfg(unix)]
        {
            use std::process::Stdio;
            match tokio::process::Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(mut child) => {
                    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
                }
                Err(e) => {
                    warn!("Failed to kill pid {}: {}", pid, e);
                }
            }
        }
        #[cfg(not(unix))]
        let _ = pid;
    }

    session_manager.force_end_sessions(&session_ids).await;

    for session_id in &session_ids {
        if let Ok(Some(mut summary)) = storage.get_session(session_id).await {
            summary.end_ts = Some(now);
            summary.forced_terminated = true;
            summary.enforcement_actions_count = summary.enforcement_actions_count.saturating_add(1);
            let _ = storage.upsert_session_summary(&summary).await;
        }
        let flag = Flag::new(
            session_id.clone(),
            "EMERGENCY_FREEZE".to_string(),
            Severity::High,
            20,
            Label::EmergencyFreeze,
            serde_json::json!({ "forced_termination": true }),
            "Session force-terminated by emergency freeze".to_string(),
        );
        let _ = storage.insert_flags(&[flag]).await;
    }
    info!("Emergency freeze completed: {} sessions force-terminated", session_ids.len());
}

/// A3: Finalize orphan sessions (ended_at NULL but pid no longer running).
async fn finalize_orphan_sessions(
    storage: &Storage,
    baseline_cache: &Arc<RwLock<HashMap<String, antidote_behavior::AppBaseline>>>,
) {
    let sessions = storage.list_sessions(Some(500), None, None, None).await;
    let Ok(sessions) = sessions else { return };
    let now = time::OffsetDateTime::now_utc();
    for s in sessions {
        if s.end_ts.is_some() {
            continue;
        }
        if s.root_pid == 0 {
            continue;
        }
        #[cfg(unix)]
        {
            let running = unsafe { libc::kill(s.root_pid, 0) == 0 };
            if !running {
                if let Ok(summary) = storage.finalize_session(&s.session_id, now).await {
                    process_finalized_session(storage, baseline_cache, summary).await;
                    info!("Finalized orphan session {} (pid {} not running)", s.session_id, s.root_pid);
                }
            }
        }
        #[cfg(not(unix))]
        let _ = s;
    }
}
/// Uses signal-hook-tokio on Unix (reliable under cargo run / subprocess); ctrl_c on Windows.
async fn wait_for_shutdown_signal() -> Result<(), anyhow::Error> {
    #[cfg(unix)]
    {
        use signal_hook::consts::signal::{SIGINT, SIGTERM};
        use signal_hook_tokio::Signals;
        let mut signals = Signals::new(&[SIGINT, SIGTERM]).context("Failed to register signal handlers")?;
        // First signal (Ctrl+C or SIGTERM) triggers shutdown
        let _ = signals.next().await;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("Failed to listen for shutdown signal")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing. Set RUST_LOG for level (e.g. RUST_LOG=debug or RUST_LOG=antidote_daemon=debug)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "antidote=info".into()),
        )
        .init();

    info!("Starting Antidote daemon (Phase 2)");

    // Load config
    let config = Config::default();
    info!(
        "Config: db_url={}, listen_addr={}, rules_path={}, watch_processes={:?}",
        config.db_url, config.listen_addr, config.rules_path, config.watch_processes
    );

    // A3: DB resilience - check integrity before init, recover if corrupt
    let db_recovered = antidote_storage::try_recover_db(&config.db_url)
        .await
        .context("DB recovery failed")?;
    if db_recovered {
        warn!("DB was corrupt and recovered; old file moved to .corrupt.<ts>");
    }

    // Initialize storage
    let storage = Arc::new(
        Storage::init(&config.db_url)
            .await
            .context("Failed to initialize storage")?,
    );
    info!("Storage initialized");

    // Phase 5: Load behavioral baselines into memory
    let baseline_cache: Arc<RwLock<HashMap<String, antidote_behavior::AppBaseline>>> =
        Arc::new(RwLock::new(HashMap::new()));
    if let Ok(rows) = storage.get_all_baselines().await {
        let time = time::OffsetDateTime::now_utc();
        for row in rows {
            let last_updated = time::OffsetDateTime::parse(&row.last_updated, &Rfc3339)
                .unwrap_or(time);
            let b = antidote_behavior::AppBaseline {
                app: row.app.clone(),
                session_count: row.session_count.max(0) as u64,
                avg_files_written: row.avg_files_written,
                avg_files_deleted: row.avg_files_deleted,
                avg_bytes_out: row.avg_bytes_out,
                avg_unknown_domains: row.avg_unknown_domains,
                avg_cmds: row.avg_cmds,
                var_files_written: row.var_files_written,
                var_bytes_out: row.var_bytes_out,
                var_unknown_domains: row.var_unknown_domains,
                var_cmds: row.var_cmds,
                last_updated,
            };
            baseline_cache.write().await.insert(row.app, b);
        }
        info!("Loaded {} app baselines", baseline_cache.read().await.len());
    }

    // A3: Orphan session finalization
    finalize_orphan_sessions(&storage, &baseline_cache).await;

    // Load rule engine
    let rule_engine = Arc::new(
        RuleEngine::load_from_file(&config.rules_path)
            .context("Failed to load rules")?,
    );
    info!("Rules engine loaded");

    // Create session manager
    let session_manager = Arc::new(SessionManager::new(
        config.watch_processes.clone(),
        config.idle_timeout_minutes,
    ));
    info!("Session manager initialized");

    // Create event channels: raw -> coalescer (ignore + coalesce) -> pipeline
    let (raw_tx, raw_rx) = mpsc::unbounded_channel::<Event>();
    let (event_tx, event_rx) = mpsc::unbounded_channel::<Event>();

    // Step 6: Rate limiter and drop metrics (for pipeline and debug endpoints)
    let drop_metrics = Arc::new(rate_limiter::EventDropMetrics::default());
    let rate_limiter = Arc::new(rate_limiter::RateLimiter::new(config.limits.max_events_per_second));

    // Phase 6: Enforcement state (shared with API and proxy)
    let enforcement_state: Arc<RwLock<EnforcementConfig>> =
        Arc::new(RwLock::new(config.enforcement.clone()));
    let safe_mode_state: Arc<RwLock<SafeModeConfig>> =
        Arc::new(RwLock::new(config.safe_mode.clone()));
    let frozen_state: Arc<RwLock<bool>> = Arc::new(RwLock::new(false));
    let (freeze_tx, mut freeze_rx) = mpsc::unbounded_channel::<()>();
    let (flag_tx, mut flag_rx) = mpsc::unbounded_channel::<Flag>();

    // Ensure "enforcement" session exists for proxy-originated flags (FK)
    {
        let enforcement_session = SessionSummary::new(
            "enforcement".to_string(),
            "System".to_string(),
            0,
        );
        let _ = storage.upsert_session_summary(&enforcement_session).await;
    }

    // Initialize FS watcher manager (sends to raw_tx; coalescer filters and forwards to pipeline)
    // Default: FSEvents (native). Set file_events.use_poll_watcher: true for PollWatcher fallback (e.g. /tmp, unowned paths).
    let use_poll = config.file_events.use_poll_watcher.unwrap_or(false);
    let fs_opts = FsWatcherOptions {
        use_poll_watcher: use_poll,
        poll_interval_ms: config.file_events.poll_interval_ms,
    };
    let fs_watcher = Arc::new(RwLock::new(FsWatcherManager::new_with_options(raw_tx.clone(), fs_opts)));
    
    // Load and start watching enabled roots; shared cache for pipeline and AutoRootManager
    let enabled_roots = storage.get_enabled_roots().await
        .context("Failed to load watched roots")?;
    let watched_roots_cache = Arc::new(RwLock::new(enabled_roots.clone()));
    {
        let mut watcher = fs_watcher.write().await;
        watcher.reconcile_watches(&enabled_roots);
    }
    info!("FS watcher initialized with {} roots", enabled_roots.len());

    // Shutdown signal for graceful server exit (API server never exits otherwise)
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let mut shutdown_rx = shutdown_tx.subscribe();

    // Step 5: Session lifecycle manager (macOS: creates on AppStarted, ends on AppExited, idle rotation)
    #[cfg(target_os = "macos")]
    let (lifecycle, app_detector_lifecycle) = {
        let lifecycle_storage = storage.clone();
        let lifecycle_baselines = baseline_cache.clone();
        let lc = Arc::new(
            session_lifecycle::SessionLifecycleManager::new(
                session_manager.clone(),
                storage.clone(),
                config.idle_timeout_minutes,
            )
            .with_on_finalize(Arc::new(move |summary| {
                let st = lifecycle_storage.clone();
                let bl = lifecycle_baselines.clone();
                Box::pin(async move {
                    process_finalized_session(&*st, &bl, summary).await;
                })
            })),
        );
        (Some(lc.clone()), Some(lc))
    };
    #[cfg(not(target_os = "macos"))]
    let (lifecycle, app_detector_lifecycle) = (None as Option<Arc<session_lifecycle::SessionLifecycleManager>>, None);

    // App detector (macOS only): lifecycle events for Cursor/VSCode/Claude
    #[cfg(target_os = "macos")]
    let (app_detector_state, app_detector_handle) = {
        if !config.app_detector.enabled {
            (None, None)
        } else {
            let state = Arc::new(RwLock::new(AppDetectorState::default()));
            let (app_event_tx, mut app_event_rx) = mpsc::channel::<AppEvent>(64);
            let detector = MacAppDetector::new(config.app_detector.poll_interval_ms);
            let mut detector_handle = detector.start(app_event_tx.clone());
            let shutdown_rx_ns = shutdown_tx.subscribe();
            let _nsworkspace_handle =
                antidote_collectors::spawn_nsworkspace_observer(app_event_tx, shutdown_rx_ns);
            let consumer_state = state.clone();
            let consumer_lifecycle = app_detector_lifecycle.clone().unwrap();
            let consumer_handle = tokio::spawn(async move {
                let mut by_pid: std::collections::HashMap<i32, antidote_collectors::AppInstance> = std::collections::HashMap::new();
                while let Some(ev) = app_event_rx.recv().await {
                    consumer_lifecycle.handle_app_event(ev.clone()).await;
                    match ev {
                        AppEvent::Started { app, pid, process_name: _, bundle_id, started_at } => {
                            info!("App started: {} pid={}", app.as_display_str(), pid);
                            let instance = antidote_collectors::AppInstance::new(app, pid, bundle_id, started_at);
                            by_pid.insert(pid, instance);
                        }
                        AppEvent::Exited { app, pid, exited_at: _ } => {
                            info!("App exited: {} pid={}", app.as_display_str(), pid);
                            by_pid.remove(&pid);
                        }
                        AppEvent::ScanComplete { at } => {
                            let instances: Vec<_> = by_pid.values().cloned().collect();
                            let mut s = consumer_state.write().await;
                            s.instances = instances;
                            s.last_scan_ts = Some(at);
                        }
                    }
                }
            });
            let mut shutdown_rx_app = shutdown_tx.subscribe();
            let join_both = tokio::spawn(async move {
                tokio::select! {
                    _ = shutdown_rx_app.recv() => {
                        detector_handle.abort();
                        let _ = detector_handle.await;
                    }
                    _ = &mut detector_handle => {}
                }
                let _ = consumer_handle.await;
            });
            (Some(state), Some(join_both))
        }
    };
    #[cfg(not(target_os = "macos"))]
    let app_detector_handle: Option<tokio::task::JoinHandle<()>> = None;

    // Workspace resolver (macOS only): infers workspace roots; event-driven via storage FSEvents
    #[cfg(target_os = "macos")]
    let (workspace_resolver_state, workspace_resolver_handle, workspace_event_rx) = {
        if !config.workspace_resolver.enabled || app_detector_state.is_none() {
            (None, None, None)
        } else {
            let state = Arc::new(RwLock::new(WorkspaceResolverState::default()));
            let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel::<antidote_collectors::WorkspaceEvent>();
            let (wake_tx, wake_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
            let shutdown_rx_watcher = shutdown_tx.subscribe();
            let _storage_watcher_handle =
                antidote_collectors::spawn_storage_watcher(wake_tx, shutdown_rx_watcher);
            let resolver_config = WorkspaceResolverConfig {
                poll_interval_ms: config.workspace_resolver.poll_interval_ms,
                max_roots_per_app: config.workspace_resolver.max_roots_per_app,
                dev_dir_candidates: config.workspace_resolver.dev_dir_candidates.clone(),
                lsof_fallback_enabled: config.workspace_resolver.lsof_fallback_enabled,
                lsof_min_interval_ms: config.workspace_resolver.lsof_min_interval_ms,
            };
            let resolver = WorkspaceResolver::new(resolver_config, state.clone(), Some(event_tx));
            let app_state = app_detector_state.clone().unwrap();
            let shutdown_rx_ws = shutdown_tx.subscribe();
            let handle = tokio::spawn(async move {
                resolver.run(app_state, shutdown_rx_ws, wake_rx).await;
            });
            (Some(state), Some(handle), Some(event_rx))
        }
    };
    #[cfg(not(target_os = "macos"))]
    let workspace_resolver_handle: Option<tokio::task::JoinHandle<()>> = None;

    // AutoRootManager (macOS only): consumes WorkspaceEvent, upserts auto roots, reconciles watchers
    #[cfg(target_os = "macos")]
    let auto_root_manager_handle = {
        if config.auto_roots.enabled && workspace_event_rx.is_some() {
            let event_rx = workspace_event_rx.unwrap();
            let manager = Arc::new(auto_root_manager::AutoRootManager::new(
                auto_root_manager::AutoRootConfig {
                    enabled: config.auto_roots.enabled,
                    max_auto_roots: config.auto_roots.max_auto_roots,
                    stale_disable_days: config.auto_roots.stale_disable_days,
                    apply_debounce_ms: config.auto_roots.apply_debounce_ms,
                },
                storage.clone(),
                fs_watcher.clone(),
                watched_roots_cache.clone(),
            ));
            let shutdown_rx_arm = shutdown_tx.subscribe();
            Some(tokio::spawn(async move {
                manager.run(event_rx, shutdown_rx_arm).await;
            }))
        } else {
            None
        }
    };
    #[cfg(not(target_os = "macos"))]
    let auto_root_manager_handle: Option<tokio::task::JoinHandle<()>> = None;

    // Step 8: Telemetry integrity (capabilities, confidence, health, attribution quality, etc.)
    let telemetry_integrity = Arc::new(telemetry_integrity::TelemetryIntegrityState::new());

    // Step 7: Attribution state (heat, PID cache, stabilization)
    let attribution_state = Arc::new(attribution_state::AttributionState::new(
        config.focus.stabilization_ms,
        10, // PID cache TTL minutes
    ));

    // Step 4: Foreground poller + FocusManager (macOS only)
    #[cfg(target_os = "macos")]
    let (foreground_state, focus_context) = {
        let (fg_activate_tx, fg_activate_rx) = tokio::sync::mpsc::unbounded_channel();
        let shutdown_rx_activate = shutdown_tx.subscribe();
        let _foreground_activate_handle =
            spawn_foreground_activate_observer(fg_activate_tx, shutdown_rx_activate);

        let poller = ForegroundPoller::new(30_000); // 30s reconciliation; activate observer is primary
        let fg_state = poller.state();
        let shutdown_rx_fg = shutdown_tx.subscribe();
        let _foreground_poller_handle = tokio::spawn(async move {
            poller.run(shutdown_rx_fg, Some(fg_activate_rx)).await;
        });
        let ws_state = workspace_resolver_state.clone();
        let focus_mgr = focus_manager::FocusManager::new(
            fg_state.clone(),
            ws_state,
            session_manager.clone(),
            Some(attribution_state.clone()),
        );
        let focus_ctx = focus_mgr.context();
        let shutdown_rx_focus = shutdown_tx.subscribe();
        let _focus_manager_handle = tokio::spawn(async move {
            focus_mgr.run(shutdown_rx_focus).await;
        });
        (Some(fg_state), Some(focus_ctx))
    };
    #[cfg(not(target_os = "macos"))]
    let (foreground_state, focus_context) = (None, None);

    // Start API server with graceful shutdown
    let api_storage = storage.clone();
    let api_session_manager = session_manager.clone();
    let api_addr = config.listen_addr.clone();
    let proxy_enabled = config.proxy.enabled;
    let proxy_listen_addr = config.proxy.listen_addr.clone();
    let api_enforcement = enforcement_state.clone();
    let api_safe_mode = safe_mode_state.clone();
    let api_frozen = frozen_state.clone();
    let api_freeze_tx = freeze_tx.clone();
    let api_attribution_state = attribution_state.clone();
    let api_telemetry_integrity = telemetry_integrity.clone();
    #[cfg(target_os = "macos")]
    let api_app_detector_state = app_detector_state.clone();
    #[cfg(target_os = "macos")]
    let api_workspace_resolver_state = workspace_resolver_state.clone();
    #[cfg(target_os = "macos")]
    let api_foreground_state = foreground_state.clone();
    #[cfg(target_os = "macos")]
    let api_focus_context = focus_context.clone();
    let api_fs_watcher = fs_watcher.clone();
    let api_drop_metrics = drop_metrics.clone();
    let api_pipeline_tx = event_tx.clone();
    let api_handle = tokio::spawn(async move {
        #[cfg(target_os = "macos")]
        let router = create_router(
            api_storage,
            Some(api_session_manager),
            proxy_enabled,
            proxy_listen_addr,
            api_enforcement,
            api_safe_mode,
            api_frozen,
            Some(api_freeze_tx),
            api_app_detector_state,
            api_workspace_resolver_state,
            Some(api_fs_watcher),
            api_foreground_state,
            api_focus_context,
            Some(api_drop_metrics),
            Some(api_attribution_state),
            Some(api_telemetry_integrity),
            Some(api_pipeline_tx),
        );
        #[cfg(not(target_os = "macos"))]
        let router = create_router(
            api_storage,
            Some(api_session_manager),
            proxy_enabled,
            proxy_listen_addr,
            api_enforcement,
            api_safe_mode,
            api_frozen,
            Some(api_freeze_tx),
            Some(api_fs_watcher),
            Some(api_drop_metrics),
            Some(api_attribution_state),
            Some(api_telemetry_integrity),
            Some(api_pipeline_tx),
        );
        let listener = TcpListener::bind(&api_addr)
            .await
            .context("Failed to bind to address")?;
        info!("Starting API server on {}", api_addr);
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.recv().await;
            })
            .await
            .context("API server error")
    });

    // Start process poller (select with shutdown so it exits on Ctrl+C even when idle)
    let poller_tx = raw_tx.clone();
    let mut poller = ProcessPoller::new(
        config.watch_processes.clone(),
        poller_tx,
        Duration::from_secs(config.poll_interval_secs),
    );
    let mut shutdown_rx_poller = shutdown_tx.subscribe();
    let poller_handle = tokio::spawn(async move {
        tokio::select! {
            _ = poller.run() => {}
            _ = shutdown_rx_poller.recv() => {}
        }
    });

    // Start tick emitter (Phase 3: configurable interval, default 10s for aggregate rules)
    let tick_interval_secs = config.pipeline.tick_interval_secs;
    let tick_tx = raw_tx.clone();
    let mut shutdown_rx_tick = shutdown_tx.subscribe();
    let tick_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(tick_interval_secs));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let event = Event {
                        id: uuid::Uuid::new_v4(),
                        ts: time::OffsetDateTime::now_utc(),
                        session_id: "broadcast".to_string(),
                        event_type: EventType::Tick,
                        payload: serde_json::json!({}),
                        enforcement_action: false,
                        attribution_reason: None,
                        attribution_confidence: None,
                        attribution_details_json: None,
                    };
                    if tick_tx.send(event).is_err() {
                        break;
                    }
                }
                _ = shutdown_rx_tick.recv() => break,
            }
        }
    });

    // Step 6: Coalescer task (ignore filter + coalesce file events)
    let coalesce_window = config.file_events.coalesce_window_ms;
    let coalescer_handle = tokio::spawn(file_event_coalescer::coalescer_task(
        raw_rx,
        event_tx.clone(),
        coalesce_window,
    ));

    // Step 7: Periodic PID cache eviction
    let eviction_attr = attribution_state.clone();
    let mut shutdown_rx_evict = shutdown_tx.subscribe();
    let _eviction_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    eviction_attr.evict_stale_pids(time::OffsetDateTime::now_utc()).await;
                }
                _ = shutdown_rx_evict.recv() => break,
            }
        }
    });

    // Start pipeline worker (shares watched_roots_cache with AutoRootManager; focus_context for attribution)
    let pipeline_focus = focus_context.clone();
    let pipeline = PipelineWorker::new(
        storage.clone(),
        rule_engine.clone(),
        session_manager.clone(),
        event_rx,
        enforcement_state.clone(),
        safe_mode_state.clone(),
        watched_roots_cache.clone(),
        pipeline_focus,
        Some(rate_limiter.clone()),
        Some(drop_metrics.clone()),
        Some(attribution_state.clone()),
        config.attribution.recent_session_window_seconds,
        Some(telemetry_integrity.clone()),
    );
    let pipeline_handle = tokio::spawn(async move {
        pipeline.run().await;
    });

    // Phase 6: Spawn task to consume proxy-originated flags and persist
    let flag_storage = storage.clone();
    let flag_handle = tokio::spawn(async move {
        while let Some(flag) = flag_rx.recv().await {
            if let Err(e) = flag_storage.insert_flags(&[flag]).await {
                warn!("Failed to persist proxy flag: {}", e);
            }
        }
    });

    // Phase 6: Spawn freeze task (kill active sessions when freeze is triggered)
    let freeze_storage = storage.clone();
    let freeze_session_manager = session_manager.clone();
    let mut shutdown_rx_freeze = shutdown_tx.subscribe();
    let freeze_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = freeze_rx.recv() => {
                    run_emergency_freeze(&freeze_storage, &freeze_session_manager).await;
                }
                _ = shutdown_rx_freeze.recv() => break,
            }
        }
    });

    // Start proxy server (if enabled; select with shutdown so it stops accepting)
    let proxy_handle = if config.proxy.enabled {
        let proxy_addr = config.proxy.listen_addr.parse()
            .context("Invalid proxy listen address")?;
        let known_domains = rule_engine.known_domains().to_vec();
        let proxy = ProxyServer::new(proxy_addr, raw_tx.clone())
            .with_enforcement(
                known_domains,
                enforcement_state.clone(),
                safe_mode_state.clone(),
                frozen_state.clone(),
                Some(flag_tx.clone()),
            );
        let mut shutdown_rx_proxy = shutdown_tx.subscribe();
        Some(tokio::spawn(async move {
            tokio::select! {
                result = proxy.run() => {
                    if let Err(e) = result {
                        warn!("Proxy server error: {}", e);
                    }
                }
                _ = shutdown_rx_proxy.recv() => {}
            }
        }))
    } else {
        None
    };

    // Start idle timeout checker + Phase 5 behavioral (baseline update, anomaly, escalation, drift)
    let idle_manager = session_manager.clone();
    let idle_storage = storage.clone();
    let idle_baselines = baseline_cache.clone();
    let idle_lifecycle = lifecycle.clone();
    let mut shutdown_rx_idle = shutdown_tx.subscribe();
    let idle_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let to_process: Vec<SessionSummary> = if let Some(ref lc) = idle_lifecycle {
                        lc.run_idle_rotation().await
                    } else {
                        let ended = idle_manager.check_idle_timeout().await;
                        let mut out = Vec::new();
                        for session_id in ended {
                            let from_storage = idle_storage.get_session(&session_id).await.ok().flatten();
                            let summary_opt = if from_storage.is_some() {
                                from_storage
                            } else {
                                idle_manager.get_session(&session_id).await
                            };
                            if let Some(mut s) = summary_opt {
                                if s.end_ts.is_none() {
                                    s.end_ts = Some(time::OffsetDateTime::now_utc());
                                }
                                out.push(s);
                            }
                        }
                        out
                    };
                    for summary in to_process {
                        process_finalized_session(&*idle_storage, &idle_baselines, summary).await;
                    }
                }
                _ = shutdown_rx_idle.recv() => break,
            }
        }
    });

    // Start retention/pruning task (listens for shutdown so it can exit)
    let retention_storage = storage.clone();
    let events_retention_days = config.retention.events_days;
    let run_every_minutes = config.retention.run_every_minutes;
    let mut shutdown_rx_retention = shutdown_tx.subscribe();
    let retention_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(run_every_minutes * 60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let cutoff = time::OffsetDateTime::now_utc() - time::Duration::days(events_retention_days as i64);
                    if let Err(e) = retention_storage.prune_events_older_than(cutoff).await {
                        warn!("Failed to prune events: {}", e);
                    }
                    if let Err(e) = retention_storage.prune_flags_older_than(cutoff).await {
                        warn!("Failed to prune flags: {}", e);
                    }
                    if let Err(e) = retention_storage.prune_risk_history_older_than(cutoff).await {
                        warn!("Failed to prune risk history: {}", e);
                    }
                    info!("Retention pruning completed (cutoff: {})", cutoff);
                }
                _ = shutdown_rx_retention.recv() => break,
            }
        }
    });

    // Wait for shutdown signal (SIGINT on Unix = Ctrl+C; also SIGTERM on Unix)
    info!("Daemon running. Press Ctrl+C to shutdown.");
    wait_for_shutdown_signal().await?;

    info!("Shutdown signal received, shutting down...");

    const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(8);

    info!("Signaling all tasks to stop...");
    let _ = shutdown_tx.send(());

    info!("Closing event and control channels (pipeline, freeze, flags)...");
    drop(raw_tx);
    drop(event_tx);
    drop(freeze_tx);
    drop(flag_tx);

    let mut task_list: Vec<(&'static str, TaskHandle)> = vec![
        ("API server", TaskHandle::WithResult(api_handle)),
        ("process poller", TaskHandle::Unit(poller_handle)),
        ("tick emitter", TaskHandle::Unit(tick_handle)),
        ("coalescer", TaskHandle::Unit(coalescer_handle)),
        ("pipeline worker", TaskHandle::Unit(pipeline_handle)),
        ("idle/baseline task", TaskHandle::Unit(idle_handle)),
        ("retention pruner", TaskHandle::Unit(retention_handle)),
        ("flag consumer", TaskHandle::Unit(flag_handle)),
        ("freeze handler", TaskHandle::Unit(freeze_handle)),
    ];
    if let Some(proxy_h) = proxy_handle {
        task_list.push(("proxy server", TaskHandle::Unit(proxy_h)));
    }
    if let Some(app_detector_h) = app_detector_handle {
        task_list.push(("app detector", TaskHandle::Unit(app_detector_h)));
    }
    #[cfg(target_os = "macos")]
    if let Some(ws_h) = workspace_resolver_handle {
        task_list.push(("workspace resolver", TaskHandle::Unit(ws_h)));
    }
    #[cfg(target_os = "macos")]
    if let Some(arm_h) = auto_root_manager_handle {
        task_list.push(("auto root manager", TaskHandle::Unit(arm_h)));
    }

    let tasks = Arc::new(Mutex::new(task_list));
    let tasks_clone = Arc::clone(&tasks);
    // When timeout hits, we may be in the middle of awaiting one task (e.g. pipeline worker).
    // Track it so we can abort it too.
    let current_awaiting: Arc<Mutex<Option<(&'static str, TaskHandle)>>> = Arc::new(Mutex::new(None));
    let current_awaiting_clone = Arc::clone(&current_awaiting);

    let join_all = async move {
        loop {
            let next = {
                let mut guard = tasks_clone.lock().await;
                if guard.is_empty() {
                    None
                } else {
                    Some(guard.remove(0))
                }
            };
            let Some((name, handle)) = next else { break };
            info!("  Waiting for {}...", name);
            *current_awaiting_clone.lock().await = Some((name, handle));
            let (name, handle) = current_awaiting_clone.lock().await.take().unwrap();
            await_task_handle(handle).await;
            info!("  {} stopped.", name);
        }
    };

    info!("Waiting for tasks to finish (timeout {}s)...", SHUTDOWN_TIMEOUT.as_secs());
    if tokio::time::timeout(SHUTDOWN_TIMEOUT, join_all).await.is_err() {
        info!(
            "Shutdown timeout ({}s) reached, forcing remaining tasks to stop.",
            SHUTDOWN_TIMEOUT.as_secs()
        );
        // Abort the task we were waiting on when the timeout hit (e.g. pipeline worker)
        if let Some((name, handle)) = current_awaiting.lock().await.take() {
            info!("  Aborting {}...", name);
            handle.abort();
            await_task_handle(handle).await;
            info!("  {} stopped (forced).", name);
        }
        // Abort any tasks still in the list (not yet started waiting on)
        let remaining = {
            let mut guard = tasks.lock().await;
            guard.drain(..).collect::<Vec<_>>()
        };
        for (name, handle) in remaining {
            info!("  Aborting {}...", name);
            handle.abort();
            await_task_handle(handle).await;
            info!("  {} stopped (forced).", name);
        }
    }

    info!("Shutdown complete.");
    Ok(())
}
