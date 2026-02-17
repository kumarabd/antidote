//! Antidote daemon - main entry point

mod pipeline;

use antidote_api::create_router;
use antidote_collectors::{FsWatcherManager, ProcessPoller, ProxyServer};
use antidote_core::{Event, EventType};
use antidote_rules::RuleEngine;
use antidote_session::SessionManager;
use antidote_storage::Storage;
use anyhow::{Context, Result};
use pipeline::PipelineWorker;
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
        }
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

    // Initialize storage
    let storage = Arc::new(
        Storage::init(&config.db_url)
            .await
            .context("Failed to initialize storage")?,
    );
    info!("Storage initialized");

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
    let api_handle = tokio::spawn(async move {
        let router = create_router(
            api_storage,
            Some(api_session_manager),
            proxy_enabled,
            proxy_listen_addr,
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
    );
    let pipeline_handle = tokio::spawn(async move {
        pipeline.run().await;
    });

    // Start proxy server (if enabled; select with shutdown so it stops accepting)
    let proxy_handle = if config.proxy.enabled {
        let proxy_addr = config.proxy.listen_addr.parse()
            .context("Invalid proxy listen address")?;
        let proxy = ProxyServer::new(proxy_addr, event_tx.clone());
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

    // Start idle timeout checker (listens for shutdown so it can exit)
    let idle_manager = session_manager.clone();
    let idle_storage = storage.clone();
    let mut shutdown_rx_idle = shutdown_tx.subscribe();
    let idle_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let ended = idle_manager.check_idle_timeout().await;
                    for session_id in ended {
                        if let Some(summary) = idle_manager.get_session(&session_id).await {
                            if let Err(e) = idle_storage.upsert_session_summary(&summary).await {
                                warn!("Failed to persist ended session {}: {}", session_id, e);
                            }
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

    // Wait for tasks to complete
    let mut handles: Vec<TaskHandle> = vec![
        TaskHandle::WithResult(api_handle),
        TaskHandle::Unit(poller_handle),
        TaskHandle::Unit(tick_handle),
        TaskHandle::Unit(pipeline_handle),
        TaskHandle::Unit(idle_handle),
        TaskHandle::Unit(retention_handle),
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
