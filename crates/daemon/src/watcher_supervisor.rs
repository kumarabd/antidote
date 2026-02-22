//! FS Watcher self-heal: supervises watchers, restarts on stale heartbeats.

use antidote_collectors::{FsWatcherManager, WatcherStatus};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Per-root watcher health for /debug/watchers
#[derive(Debug, Clone, serde::Serialize)]
pub struct WatcherHealth {
    pub root: String,
    pub running: bool,
    pub last_heartbeat_ts: Option<String>,
    pub restart_count: u32,
    pub last_error: Option<String>,
}

/// Heartbeat tracker: root path -> (last_heartbeat_ts, last_error)
pub type HeartbeatMap = Arc<RwLock<HashMap<String, (OffsetDateTime, Option<String>)>>>;

pub fn new_heartbeat_map() -> HeartbeatMap {
    Arc::new(RwLock::new(HashMap::new()))
}

/// FSWatcherSupervisor wraps FsWatcherManager and periodically restarts stale watchers.
pub struct FSWatcherSupervisor {
    inner: Arc<RwLock<FsWatcherManager>>,
    heartbeats: HeartbeatMap,
    restart_counts: Arc<RwLock<HashMap<String, u32>>>,
    last_errors: Arc<RwLock<HashMap<String, String>>>,
    stale_threshold_secs: u64,
    min_backoff_secs: u64,
    max_backoff_secs: u64,
}

impl FSWatcherSupervisor {
    pub fn new(inner: Arc<RwLock<FsWatcherManager>>, heartbeats: HeartbeatMap) -> Self {
        Self {
            inner,
            heartbeats,
            restart_counts: Arc::new(RwLock::new(HashMap::new())),
            last_errors: Arc::new(RwLock::new(HashMap::new())),
            stale_threshold_secs: 60,
            min_backoff_secs: 1,
            max_backoff_secs: 30,
        }
    }

    /// Record heartbeat for a root (called from heartbeat receiver task).
    pub async fn record_heartbeat(&self, root: PathBuf) {
        let key = root.to_string_lossy().to_string();
        let mut h = self.heartbeats.write().await;
        h.insert(key, (OffsetDateTime::now_utc(), None));
    }

    /// Record error for a root.
    pub async fn record_error(&self, root: &str, err: &str) {
        let mut e = self.last_errors.write().await;
        e.insert(root.to_string(), err.to_string());
    }

    /// Reconcile watches and restart one stale root per cycle if needed.
    pub async fn reconcile_and_heal(&self, desired_roots: &[String]) {
        let mut inner = self.inner.write().await;
        inner.reconcile_watches(desired_roots);

        let mut heartbeats = self.heartbeats.write().await;
        let restarts = self.restart_counts.read().await;
        let now = OffsetDateTime::now_utc();
        let stale_secs = self.stale_threshold_secs as i64;

        for root in desired_roots {
            let path = PathBuf::from(root);
            let canonical = match path.canonicalize() {
                Ok(p) => p,
                Err(_) => path,
            };
            if !canonical.exists() {
                continue;
            }
            let key = canonical.to_string_lossy().to_string();

            let should_restart = heartbeats
                .get(&key)
                .map(|(ts, _)| (now - *ts).whole_seconds() > stale_secs)
                .unwrap_or(true);

            if should_restart {
                let count = restarts.get(&key).copied().unwrap_or(0);
                let backoff_secs = (self.min_backoff_secs * 2_u64.pow(count))
                    .min(self.max_backoff_secs);

                drop(heartbeats);
                drop(restarts);

                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;

                let mut inner = self.inner.write().await;
                if let Err(e) = inner.remove_root(&canonical) {
                    warn!("Failed to remove stale root {:?}: {}", canonical, e);
                    self.record_error(&key, &e.to_string()).await;
                } else if let Err(e) = inner.add_root(canonical.clone()) {
                    self.record_error(&key, &e.to_string()).await;
                    warn!("Failed to restart watcher for {:?}: {}", canonical, e);
                } else {
                    info!("Restarted watcher for {:?} (restart #{}", canonical, count + 1);
                    let mut restarts = self.restart_counts.write().await;
                    *restarts.entry(key.clone()).or_insert(0) += 1;
                    let mut h = self.heartbeats.write().await;
                    h.insert(key, (OffsetDateTime::now_utc(), None));
                }
                return;
            }
        }
    }

    /// Get watcher status for /debug/watchers with health info.
    pub async fn watcher_status_with_health(&self) -> Vec<WatcherHealth> {
        use time::format_description::well_known::Rfc3339;
        let inner = self.inner.read().await;
        let statuses = inner.watcher_status();
        let heartbeats = self.heartbeats.read().await;
        let restarts = self.restart_counts.read().await;
        let errors = self.last_errors.read().await;

        statuses
            .into_iter()
            .map(|s: WatcherStatus| {
                let last_ts = heartbeats
                    .get(&s.path)
                    .and_then(|(ts, _)| ts.format(&Rfc3339).ok());
                WatcherHealth {
                    root: s.path.clone(),
                    running: s.status == "running",
                    last_heartbeat_ts: last_ts,
                    restart_count: restarts.get(&s.path).copied().unwrap_or(0),
                    last_error: errors.get(&s.path).cloned(),
                }
            })
            .collect()
    }

    /// Simple status for backward compat.
    pub async fn watcher_status(&self) -> Vec<WatcherStatus> {
        let inner = self.inner.read().await;
        inner.watcher_status()
    }
}
