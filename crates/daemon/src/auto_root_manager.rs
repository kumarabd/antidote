//! Auto-root manager: consumes WorkspaceEvent, upserts roots as source=auto,
//! reconciles stale/cap, and drives FSWatcherManager + watched_roots cache.
//! Event-driven: apply on sight with short debounce; handle RootsRemoved to disable.

#[cfg(target_os = "macos")]
use antidote_collectors::WorkspaceEvent;
use antidote_storage::Storage;
use crate::root_policy;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};


/// Config for auto-root behavior
#[derive(Clone)]
pub struct AutoRootConfig {
    #[allow(dead_code)]
    pub enabled: bool,
    pub max_auto_roots: usize,
    pub stale_disable_days: u32,
    /// Short debounce to coalesce rapid bursts (ms). Event-driven: apply on sight.
    pub apply_debounce_ms: u64,
}

impl Default for AutoRootConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_auto_roots: 20,
            stale_disable_days: 14,
            apply_debounce_ms: 300,
        }
    }
}

pub struct AutoRootManager {
    config: AutoRootConfig,
    storage: Arc<Storage>,
    fs_watcher: Arc<RwLock<antidote_collectors::FsWatcherManager>>,
    watched_roots_cache: Arc<tokio::sync::RwLock<Vec<String>>>,
}

impl AutoRootManager {
    pub fn new(
        config: AutoRootConfig,
        storage: Arc<Storage>,
        fs_watcher: Arc<RwLock<antidote_collectors::FsWatcherManager>>,
        watched_roots_cache: Arc<tokio::sync::RwLock<Vec<String>>>,
    ) -> Self {
        Self {
            config,
            storage,
            fs_watcher,
            watched_roots_cache,
        }
    }

    /// Apply pending roots to DB (upsert auto), then reconcile stale/cap, then sync watchers and cache.
    pub async fn apply_and_reconcile(&self, roots: Vec<String>) -> Result<(), anyhow::Error> {
        let now = OffsetDateTime::now_utc();
        let _now_str = now
            .format(&Rfc3339)
            .map_err(|e| anyhow::anyhow!("format ts: {}", e))?
            .to_string();

        for path in &roots {
            match root_policy::evaluate_root(path) {
                root_policy::RootDecision::Accept { normalized_root, reason: _ } => {
                    let normalized = normalized_root.to_string_lossy().to_string();
                    if let Err(e) = self.storage.upsert_auto_root(&normalized).await {
                        warn!("upsert_auto_root {}: {}", normalized, e);
                    }
                }
                root_policy::RootDecision::Reject { reason } => {
                    debug!("Root rejected: {} - {}", path, reason);
                }
            }
        }

        if !roots.is_empty() {
            info!("Auto-root manager applying {} roots: {:?}", roots.len(), roots);
        }
        let cutoff = now - time::Duration::days(self.config.stale_disable_days as i64);
        let cutoff_str = cutoff
            .format(&Rfc3339)
            .map_err(|e| anyhow::anyhow!("format cutoff: {}", e))?
            .to_string();
        self.reconcile(cutoff_str.as_str()).await
    }

    /// Stale disable + cap enforcement + sync watchers and cache.
    pub async fn reconcile(&self, cutoff_ts: &str) -> Result<(), anyhow::Error> {
        if let Err(e) = self.storage.disable_stale_auto_roots(cutoff_ts).await {
            warn!("disable_stale_auto_roots: {}", e);
        }

        let count = self.storage.count_enabled_auto_roots().await?;
        let max = self.config.max_auto_roots as i64;
        if count > max {
            let oldest = self.storage.get_enabled_auto_roots_oldest_first().await?;
            let to_disable = (count - max) as usize;
            for (id, _) in oldest.into_iter().take(to_disable) {
                self.storage.set_watched_root_enabled(id, false).await?;
            }
        }

        let enabled = self.storage.get_enabled_roots().await?;
        if !enabled.is_empty() {
            info!("FS watcher reconciled: {} roots enabled", enabled.len());
        }
        {
            let mut watcher = self.fs_watcher.write().await;
            watcher.reconcile_watches(&enabled);
        }
        *self.watched_roots_cache.write().await = enabled.clone();
        Ok(())
    }

    /// Run the manager: consume WorkspaceEvent, debounce, apply on sight, handle RootsRemoved.
    #[cfg(target_os = "macos")]
    pub async fn run(
        self: Arc<Self>,
        mut event_rx: mpsc::UnboundedReceiver<WorkspaceEvent>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) {
        let debounce = Duration::from_millis(self.config.apply_debounce_ms);
        // Roots to apply (accumulated since last debounce)
        let mut pending_roots: HashSet<String> = HashSet::new();
        let mut dirty = false;
        let mut debounce_deadline: Option<tokio::time::Instant> = None;
        // Track which roots each (app, pid) contributes for RootsRemoved
        let mut roots_by_app_pid: HashMap<(String, i32), HashSet<String>> = HashMap::new();

        loop {
            let sleep_fut = async {
                if let Some(deadline) = debounce_deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await
                }
            };

            tokio::select! {
                ev = event_rx.recv() => {
                    match ev {
                        Some(WorkspaceEvent::Updated { app, pid, roots, .. }) => {
                            let key = (app.as_display_str().to_string(), pid);
                            let accepted: HashSet<String> = roots
                                .into_iter()
                                .filter_map(|r| {
                                    if let root_policy::RootDecision::Accept { normalized_root, .. } =
                                        root_policy::evaluate_root(&r)
                                    {
                                        Some(normalized_root.to_string_lossy().to_string())
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            roots_by_app_pid.insert(key, accepted.clone());
                            for n in &accepted {
                                pending_roots.insert(n.clone());
                            }
                            dirty = true;
                            if debounce_deadline.is_none() {
                                debounce_deadline = Some(tokio::time::Instant::now() + debounce);
                            }
                        }
                        Some(WorkspaceEvent::RootsRemoved { app, pid, roots }) => {
                            let key = (app.as_display_str().to_string(), pid);
                            roots_by_app_pid.remove(&key);
                            let still_referenced: HashSet<String> = roots_by_app_pid
                                .values()
                                .flat_map(|s| s.iter().cloned())
                                .collect();
                            for r in roots {
                                if let root_policy::RootDecision::Accept { normalized_root, .. } =
                                    root_policy::evaluate_root(&r)
                                {
                                    let n = normalized_root.to_string_lossy().to_string();
                                    if !still_referenced.contains(&n) {
                                        if let Err(e) = self.disable_auto_root_if_unreferenced(&n).await {
                                            warn!("disable_auto_root {}: {}", n, e);
                                        }
                                    }
                                }
                            }
                            let cutoff = OffsetDateTime::now_utc()
                                - time::Duration::days(self.config.stale_disable_days as i64);
                            if let Ok(s) = cutoff.format(&Rfc3339) {
                                let _ = self.reconcile(&s.to_string()).await;
                            }
                        }
                        None => break,
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("AutoRootManager shutting down");
                    break;
                }
                _ = sleep_fut => {
                    debounce_deadline = None;
                    if dirty {
                        let to_apply: Vec<String> = pending_roots.drain().collect();
                        if !to_apply.is_empty() {
                            if let Err(e) = self.apply_and_reconcile(to_apply).await {
                                warn!("apply_and_reconcile: {}", e);
                            }
                        }
                        dirty = false;
                    }
                }
            }
        }
    }

    /// Disable an auto root if it exists and is not pinned.
    async fn disable_auto_root_if_unreferenced(&self, path: &str) -> Result<(), anyhow::Error> {
        if let Some(r) = self.storage.get_watched_root_by_path(path).await? {
            if r.source == antidote_storage::RootSource::Auto && !r.pinned {
                self.storage.set_watched_root_enabled(r.id, false).await?;
                info!("Auto root disabled (no longer referenced): {}", path);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::root_policy;
    use std::path::Path;

    #[test]
    fn normalize_path_expands_tilde() {
        if std::env::var_os("HOME").is_some() {
            let n = root_policy::normalize_path("~/foo");
            assert!(n.is_some());
            assert!(n.unwrap().to_string_lossy().contains("foo"));
        }
    }

    #[test]
    fn root_policy_accepts_git_repo() {
        let tmp = std::env::temp_dir();
        let with_git = tmp.join("test_repo_autoroot_git");
        let _ = std::fs::create_dir_all(with_git.join(".git"));
        let decision = root_policy::evaluate_root(with_git.to_str().unwrap());
        let _ = std::fs::remove_dir_all(with_git);
        match decision {
            root_policy::RootDecision::Accept { .. } => {}
            root_policy::RootDecision::Reject { reason } => panic!("Expected accept: {}", reason),
        }
    }

    #[test]
    fn root_policy_rejects_home() {
        if let Some(home) = std::env::var_os("HOME") {
            let home_str = home.to_string_lossy().to_string();
            let decision = root_policy::evaluate_root(&home_str);
            match decision {
                root_policy::RootDecision::Reject { .. } => {}
                root_policy::RootDecision::Accept { .. } => {
                    assert!(
                        Path::new(&home_str).join(".git").exists()
                            || Path::new(&home_str).join("Cargo.toml").exists()
                    );
                }
            }
        }
    }
}
