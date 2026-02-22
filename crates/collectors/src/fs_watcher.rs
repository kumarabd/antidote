//! File system watcher for macOS

use antidote_core::{payloads::FilePayload, Event, EventType};
use anyhow::{Context, Result};
use notify::{
    event::RenameMode,
    Config, EventKind, PollWatcher, RecommendedWatcher, RecursiveMode, Watcher,
};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Options for FS watcher backend. PollWatcher is more reliable for paths like /tmp on macOS
/// where FSEvents may miss events for "unowned" files.
#[derive(Debug, Clone)]
pub struct FsWatcherOptions {
    /// Use PollWatcher instead of platform-native (FSEvents on macOS). Fixes missed events.
    pub use_poll_watcher: bool,
    /// Poll interval in ms when use_poll_watcher is true. Default 1000.
    pub poll_interval_ms: u64,
}

impl Default for FsWatcherOptions {
    fn default() -> Self {
        Self {
            use_poll_watcher: false,
            poll_interval_ms: 1000,
        }
    }
}

/// Inner watcher: either platform-native or PollWatcher.
enum WatcherImpl {
    Recommended(RecommendedWatcher),
    Poll(PollWatcher),
}

impl WatcherImpl {
    fn watch(&mut self, path: &Path, mode: RecursiveMode) -> Result<()> {
        match self {
            WatcherImpl::Recommended(w) => w.watch(path, mode).map_err(anyhow::Error::from),
            WatcherImpl::Poll(w) => w.watch(path, mode).map_err(anyhow::Error::from),
        }
    }
    fn unwatch(&mut self, path: &Path) -> Result<()> {
        match self {
            WatcherImpl::Recommended(w) => w.unwatch(path).map_err(anyhow::Error::from),
            WatcherImpl::Poll(w) => w.unwatch(path).map_err(anyhow::Error::from),
        }
    }
}

/// File system watcher manager
pub struct FsWatcherManager {
    event_tx: mpsc::UnboundedSender<Event>,
    watchers: HashMap<PathBuf, WatcherImpl>,
    options: FsWatcherOptions,
    /// Optional channel to emit heartbeat (root path) on each event for supervisor.
    heartbeat_tx: Option<mpsc::UnboundedSender<PathBuf>>,
}

impl FsWatcherManager {
    pub fn new(event_tx: mpsc::UnboundedSender<Event>) -> Self {
        Self::new_with_options(event_tx, FsWatcherOptions::default())
    }

    pub fn new_with_options(event_tx: mpsc::UnboundedSender<Event>, options: FsWatcherOptions) -> Self {
        Self {
            event_tx,
            watchers: HashMap::new(),
            options,
            heartbeat_tx: None,
        }
    }

    /// Set heartbeat sender for watcher self-heal (emits root path on each event).
    pub fn with_heartbeat_tx(mut self, tx: mpsc::UnboundedSender<PathBuf>) -> Self {
        self.heartbeat_tx = Some(tx);
        self
    }

    /// Add a watch root
    pub fn add_root(&mut self, root: PathBuf) -> Result<()> {
        let root_canonical = root.canonicalize()
            .with_context(|| format!("Failed to canonicalize root: {:?}", root))?;

        if self.watchers.contains_key(&root_canonical) {
            warn!("Root already watched: {:?}", root_canonical);
            return Ok(());
        }

        info!("Adding FS watch root: {:?} (backend={})", root_canonical,
            if self.options.use_poll_watcher { "PollWatcher" } else { "native" });

        let mut watcher = if self.options.use_poll_watcher {
            let event_tx = self.event_tx.clone();
            let root_clone = root_canonical.clone();
            let heartbeat_tx = self.heartbeat_tx.clone();
            let config = Config::default()
                .with_poll_interval(Duration::from_millis(self.options.poll_interval_ms));
            let w = PollWatcher::new(
                move |res: Result<notify::Event, notify::Error>| {
                    handle_fs_event(res, &event_tx, &root_clone, heartbeat_tx.as_ref());
                },
                config,
            )
                .with_context(|| "Failed to create PollWatcher")?;
            WatcherImpl::Poll(w)
        } else {
            let event_tx = self.event_tx.clone();
            let root_clone = root_canonical.clone();
            let heartbeat_tx = self.heartbeat_tx.clone();
            let w = notify::recommended_watcher(
                move |res: Result<notify::Event, notify::Error>| {
                    handle_fs_event(res, &event_tx, &root_clone, heartbeat_tx.as_ref());
                },
            )
                .with_context(|| "Failed to create FS watcher")?;
            WatcherImpl::Recommended(w)
        };

        watcher.watch(&root_canonical, RecursiveMode::Recursive)
            .with_context(|| format!("Failed to watch root: {:?}", root_canonical))?;
        self.watchers.insert(root_canonical.clone(), watcher);
        info!("Successfully watching root: {:?}", root_canonical);

        Ok(())
    }

    /// Remove a watch root
    pub fn remove_root(&mut self, root: &Path) -> Result<()> {
        let root_canonical = root.canonicalize()
            .with_context(|| format!("Failed to canonicalize root: {:?}", root))?;

        if let Some(mut watcher) = self.watchers.remove(&root_canonical) {
            watcher.unwatch(&root_canonical)
                .with_context(|| format!("Failed to unwatch root: {:?}", root_canonical))?;
            info!("Removed FS watch root: {:?}", root_canonical);
        }

        Ok(())
    }

    /// Get all watched roots
    pub fn watched_roots(&self) -> Vec<PathBuf> {
        self.watchers.keys().cloned().collect()
    }

    /// Reconcile watchers to match the desired set of enabled root paths.
    /// Adds watchers for new paths, removes watchers for paths no longer desired.
    /// Logs errors but does not panic; continues with remaining roots.
    pub fn reconcile_watches(&mut self, desired_roots: &[String]) {
        let desired_set: HashSet<PathBuf> = desired_roots
            .iter()
            .filter_map(|p| {
                let path = PathBuf::from(p);
                path.canonicalize().ok().or_else(|| Some(path))
            })
            .filter(|p| p.exists())
            .collect();
        let current: Vec<PathBuf> = self.watchers.keys().cloned().collect();
        let current_set: HashSet<PathBuf> = current.iter().cloned().collect();
        let to_add: Vec<PathBuf> = desired_set.difference(&current_set).cloned().collect();
        let to_remove: Vec<PathBuf> = current_set.difference(&desired_set).cloned().collect();
        for root in to_remove {
            if let Some(mut watcher) = self.watchers.remove(&root) {
                if let Err(e) = watcher.unwatch(&root) {
                    warn!("Failed to unwatch {:?}: {}", root, e);
                } else {
                    info!("Removed FS watch root: {:?}", root);
                }
            }
        }
        for root in to_add {
            if let Err(e) = self.add_root(root.clone()) {
                warn!("Failed to add watch {:?}: {}", root, e);
            }
        }
    }

    /// Return current watcher status for debug: path -> status (running).
    pub fn watcher_status(&self) -> Vec<WatcherStatus> {
        self.watchers
            .keys()
            .map(|p| WatcherStatus {
                path: p.to_string_lossy().to_string(),
                status: "running".to_string(),
            })
            .collect()
    }
}

/// Shared logic for processing FS events from either watcher backend.
fn handle_fs_event(
    res: Result<notify::Event, notify::Error>,
    event_tx: &mpsc::UnboundedSender<Event>,
    root: &Path,
    heartbeat_tx: Option<&mpsc::UnboundedSender<PathBuf>>,
) {
    match res {
        Ok(event) => {
            for (path_idx, path) in event.paths.iter().enumerate() {
                let path_canonical = match path.canonicalize() {
                    Ok(p) => p,
                    Err(_) => path.clone(),
                };

                // Only emit for paths under our watched root (ignore e.g. Trash destination)
                if !path_canonical.starts_with(root) {
                    continue;
                }

                let event_type = match &event.kind {
                    EventKind::Create(_) => EventType::FileCreate,
                    EventKind::Modify(ref m) => {
                        if let notify::event::ModifyKind::Name(rename_mode) = m {
                            match rename_mode {
                                RenameMode::From => EventType::FileDelete,
                                RenameMode::To => EventType::FileCreate,
                                RenameMode::Both => {
                                    if path_idx == 0 {
                                        EventType::FileDelete
                                    } else {
                                        EventType::FileCreate
                                    }
                                }
                                _ => EventType::FileRename,
                            }
                        } else {
                            EventType::FileWrite
                        }
                    }
                    EventKind::Remove(_) => EventType::FileDelete,
                    _ => continue,
                };

                let rel_path = path_canonical
                    .strip_prefix(root)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| path_canonical.to_string_lossy().to_string());

                let mut payload = serde_json::to_value(FilePayload {
                    path: path_canonical.to_string_lossy().to_string(),
                    bytes: None,
                })
                .unwrap_or_else(|_| serde_json::json!({}));

                if let Some(payload_obj) = payload.as_object_mut() {
                    payload_obj.insert("rel_path".to_string(), serde_json::Value::String(rel_path));
                }

                let ev = Event {
                    id: Uuid::new_v4(),
                    ts: OffsetDateTime::now_utc(),
                    session_id: "pending".to_string(),
                    event_type,
                    payload,
                    enforcement_action: false,
                    attribution_reason: None,
                    attribution_confidence: None,
                    attribution_details_json: None,
                };

                if event_tx.send(ev).is_err() {
                    warn!("Event channel closed");
                }
                if let Some(tx) = heartbeat_tx {
                    let _ = tx.send(root.to_path_buf());
                }
            }
        }
        Err(e) => {
            error!("FS watcher error: {}", e);
        }
    }
}

/// Per-watcher status for debug endpoint
#[derive(Debug, Clone, serde::Serialize)]
pub struct WatcherStatus {
    pub path: String,
    pub status: String,
}
