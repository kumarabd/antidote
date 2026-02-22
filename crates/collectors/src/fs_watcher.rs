//! File system watcher for macOS

use antidote_core::{payloads::FilePayload, Event, EventType};
use anyhow::{Context, Result};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

/// File system watcher manager
pub struct FsWatcherManager {
    event_tx: mpsc::UnboundedSender<Event>,
    watchers: HashMap<PathBuf, RecommendedWatcher>,
}

impl FsWatcherManager {
    pub fn new(event_tx: mpsc::UnboundedSender<Event>) -> Self {
        Self {
            event_tx,
            watchers: HashMap::new(),
        }
    }

    /// Add a watch root
    pub fn add_root(&mut self, root: PathBuf) -> Result<()> {
        let root_canonical = root.canonicalize()
            .with_context(|| format!("Failed to canonicalize root: {:?}", root))?;

        if self.watchers.contains_key(&root_canonical) {
            warn!("Root already watched: {:?}", root_canonical);
            return Ok(());
        }

        info!("Adding FS watch root: {:?}", root_canonical);

        let event_tx = self.event_tx.clone();
        let root_clone = root_canonical.clone();

        let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            match res {
                Ok(event) => {
                    for path in &event.paths {
                        let path_canonical = match path.canonicalize() {
                            Ok(p) => p,
                            Err(_) => path.clone(),
                        };

                        // Determine event type
                        let event_type = match &event.kind {
                            EventKind::Create(_) => EventType::FileCreate,
                            EventKind::Modify(ref m) => {
                                // Check if it's a rename (name change) or data modification
                                if let notify::event::ModifyKind::Name(_) = m {
                                    EventType::FileRename
                                } else {
                                    EventType::FileWrite
                                }
                            },
                            EventKind::Remove(_) => EventType::FileDelete,
                            _ => continue,
                        };

                        // Compute relative path
                        let rel_path = path_canonical
                            .strip_prefix(&root_clone)
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|_| path_canonical.to_string_lossy().to_string());

                        let mut payload = serde_json::to_value(FilePayload {
                            path: path_canonical.to_string_lossy().to_string(),
                            bytes: None,
                        })
                        .unwrap_or_else(|_| serde_json::json!({}));

                        // Add relative path to payload
                        if let Some(payload_obj) = payload.as_object_mut() {
                            payload_obj.insert("rel_path".to_string(), serde_json::Value::String(rel_path));
                        }

                        let event = Event {
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

                        if event_tx.send(event).is_err() {
                            warn!("Event channel closed");
                        }
                    }
                }
                Err(e) => {
                    error!("FS watcher error: {}", e);
                }
            }
        })
        .with_context(|| "Failed to create FS watcher")?;

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

/// Per-watcher status for debug endpoint
#[derive(Debug, Clone, serde::Serialize)]
pub struct WatcherStatus {
    pub path: String,
    pub status: String,
}
