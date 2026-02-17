//! Antidote daemon - main entry point

mod pipeline;

use antidote_api::create_router;
use antidote_behavior;
use antidote_collectors::{FsWatcherManager, ProcessPoller, ProxyServer};
use antidote_core::{
    Event, EventType, Flag, Label, SessionSummary, Severity,
    EnforcementConfig, SafeModeConfig,
};
use antidote_ruleengine::RuleEngine;
use antidote_session::SessionManager;
use antidote_storage::{AppBaselineRow, Storage};
use anyhow::{Context, Result};
use pipeline::PipelineWorker;
use std::collections::HashMap;
use time::format_description::well_known::Rfc3339;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{info, warn};

/// Unified handle for daemon tasks: some return Result (e.g. API server), others run until cancelled ().
enum TaskHandle {
    WithResult(tokio::task::JoinHandle<Result<(), anyhow::Error>>),
    Unit(tokio::task::JoinHandle<()>),
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
    enforcement: EnforcementConfig,
    #[serde(default)]
    safe_mode: SafeModeConfig,
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db_url: "sqlite:monitor.db".to_string(),
            listen_addr: "127.0.0.1:17845".to_string(),
            rules_path: "./rules/rules.yaml".to_string(),
            watch_processes: vec!["Cursor".to_string(), "Code".to_string(), "Claude".to_string()],
            poll_interval_secs: 2,
            idle_timeout_minutes: 7,
            fs: FsConfig { debounce_ms: 1000 },
            proxy: ProxyConfig {
                enabled: true,
                listen_addr: "127.0.0.1:17846".to_string(),
            },
            retention: RetentionConfig { days: 7 },
            enforcement: EnforcementConfig::default(),
            safe_mode: SafeModeConfig::default(),
        }
    }
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

    // Create event channel
    let (event_tx, event_rx) = mpsc::unbounded_channel::<Event>();

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

    // Initialize FS watcher manager
    let fs_watcher = Arc::new(RwLock::new(FsWatcherManager::new(event_tx.clone())));
    
    // Load and start watching enabled roots
    let enabled_roots = storage.get_enabled_roots().await
        .context("Failed to load watched roots")?;
    {
        let mut watcher = fs_watcher.write().await;
        for root_path in &enabled_roots {
            if let Err(e) = watcher.add_root(PathBuf::from(root_path)) {
                warn!("Failed to watch root {}: {}", root_path, e);
            }
        }
    }
    info!("FS watcher initialized with {} roots", enabled_roots.len());

    // Shutdown signal for graceful server exit (API server never exits otherwise)
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let mut shutdown_rx = shutdown_tx.subscribe();

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
    let api_handle = tokio::spawn(async move {
        let router = create_router(
            api_storage,
            Some(api_session_manager),
            proxy_enabled,
            proxy_listen_addr,
            api_enforcement,
            api_safe_mode,
            api_frozen,
            Some(api_freeze_tx),
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
    let poller_tx = event_tx.clone();
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

    // Start tick emitter (select with shutdown so it exits immediately)
    let tick_tx = event_tx.clone();
    let mut shutdown_rx_tick = shutdown_tx.subscribe();
    let tick_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
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
                    };
                    if tick_tx.send(event).is_err() {
                        break;
                    }
                }
                _ = shutdown_rx_tick.recv() => break,
            }
        }
    });

    // Start pipeline worker
    let pipeline = PipelineWorker::new(
        storage.clone(),
        rule_engine.clone(),
        session_manager.clone(),
        event_rx,
        enforcement_state.clone(),
        safe_mode_state.clone(),
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
        let proxy = ProxyServer::new(proxy_addr, event_tx.clone())
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
    let mut shutdown_rx_idle = shutdown_tx.subscribe();
    let idle_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let ended = idle_manager.check_idle_timeout().await;
                    for session_id in ended {
                        // Prefer summary from storage (has latest counts from pipeline)
                        let mut summary_opt = idle_storage.get_session(&session_id).await.ok().flatten();
                        if summary_opt.is_none() {
                            summary_opt = idle_manager.get_session(&session_id).await;
                        }
                        let mut summary = match summary_opt {
                            Some(s) => s,
                            None => continue,
                        };
                        let now = time::OffsetDateTime::now_utc();
                        if summary.end_ts.is_none() {
                            summary.end_ts = Some(now);
                        }

                        // Phase 5: Update baseline (EMA)
                        let current = idle_baselines.read().await.get(&summary.app).cloned();
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
                            last_updated: new_baseline.last_updated.format(&Rfc3339).unwrap_or_default().to_string(),
                        };
                        let _ = idle_storage.upsert_app_baseline(&row).await;
                        idle_baselines.write().await.insert(summary.app.clone(), new_baseline.clone());

                        // Anomaly detection (keep read guard alive for baseline_ref uses below)
                        let baseline_guard = idle_baselines.read().await;
                        let baseline_ref = baseline_guard.get(&summary.app);
                        let anomaly_flags = antidote_behavior::detect_anomalies(
                            &summary.session_id,
                            &summary.app,
                            &summary.counts,
                            &summary.evidence,
                            baseline_ref,
                            &antidote_behavior::AnomalyConfig::default(),
                        );
                        // Escalation (risk history already recorded when flags were created)
                        let risk_counts = idle_storage
                            .get_risk_history_last_n_days(&summary.app, antidote_behavior::ESCALATION_DAYS)
                            .await
                            .unwrap_or_default();
                        let escalation_flag = antidote_behavior::check_escalation(
                            &summary.session_id,
                            &summary.app,
                            &risk_counts,
                        );
                        let mut all_new_flags = anomaly_flags;
                        if let Some(f) = escalation_flag {
                            all_new_flags.push(f);
                        }
                        for flag in &all_new_flags {
                            let _ = idle_storage.insert_flags(&[flag.clone()]).await;
                            if matches!(flag.severity, Severity::High | Severity::Crit) {
                                let _ = idle_storage.record_risk_history(&summary.app, &flag.rule_id, flag.ts).await;
                            }
                        }

                        // Drift index (simplified: no historical sets here)
                        let drift_index = antidote_behavior::compute_drift_index(
                            &summary,
                            baseline_ref,
                            &std::collections::HashSet::new(),
                            &std::collections::HashSet::new(),
                            0.0,
                        );
                        let baseline_comp =
                            antidote_behavior::build_baseline_comparison_summary(&summary, baseline_ref);
                        summary.drift_index = Some(drift_index);
                        summary.baseline_comparison_summary = baseline_comp;

                        if let Err(e) = idle_storage.upsert_session_summary(&summary).await {
                            warn!("Failed to persist ended session {}: {}", session_id, e);
                        }
                    }
                }
                _ = shutdown_rx_idle.recv() => break,
            }
        }
    });

    // Start retention/pruning task (listens for shutdown so it can exit)
    let retention_storage = storage.clone();
    let retention_days = config.retention.days;
    let mut shutdown_rx_retention = shutdown_tx.subscribe();
    let retention_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(86400)); // Daily
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let cutoff = time::OffsetDateTime::now_utc() - time::Duration::days(retention_days as i64);
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

    // Wait for shutdown signal
    info!("Daemon running. Press Ctrl+C to shutdown.");
    signal::ctrl_c()
        .await
        .context("Failed to listen for shutdown signal")?;

    info!("Shutdown signal received, shutting down...");

    // Signal API server to stop accepting new connections and drain
    let _ = shutdown_tx.send(());

    // Close event channel so pipeline, poller, tick, proxy exit
    drop(event_tx);
    drop(freeze_tx);
    drop(flag_tx);

    // Wait for tasks to complete
    let mut handles: Vec<TaskHandle> = vec![
        TaskHandle::WithResult(api_handle),
        TaskHandle::Unit(poller_handle),
        TaskHandle::Unit(tick_handle),
        TaskHandle::Unit(pipeline_handle),
        TaskHandle::Unit(idle_handle),
        TaskHandle::Unit(retention_handle),
        TaskHandle::Unit(flag_handle),
        TaskHandle::Unit(freeze_handle),
    ];
    if let Some(proxy_h) = proxy_handle {
        handles.push(TaskHandle::Unit(proxy_h));
    }
    for handle in handles {
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

    info!("Shutdown complete");
    Ok(())
}
