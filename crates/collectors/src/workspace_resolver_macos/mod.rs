//! macOS workspace root resolver. Discovers roots from tool-specific storage (e.g. Cursor),
//! independent of sessions. Roots are associated with a source_id (e.g. cursor:ws:{hash})
//! for lifecycle/cleanup.

mod cursor_discovery;

use crate::app_detector_macos::AppKind;
use notify::{RecursiveMode, Watcher};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Workspace update event emitted when roots change.
/// Uses source_id (e.g. cursor:ws:{hash}) - decoupled from sessions.
#[derive(Debug, Clone)]
pub enum WorkspaceEvent {
    Updated {
        source_id: String,
        app: AppKind,
        roots: Vec<String>,
        observed_at: OffsetDateTime,
    },
    /// Emitted when roots are no longer present for a source.
    RootsRemoved {
        source_id: String,
        roots: Vec<String>,
    },
}

/// Per-source workspace state for debug and downstream.
#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceState {
    pub source_id: String,
    pub app: AppKind,
    pub roots: Vec<String>,
    pub observed_at: OffsetDateTime,
}

/// Full resolver state: current items + last run metadata.
#[derive(Debug, Clone, Default, Serialize)]
pub struct WorkspaceResolverState {
    pub items: Vec<WorkspaceState>,
    pub last_run_at: Option<OffsetDateTime>,
    pub last_error: Option<String>,
}

// ---------------------------------------------------------------------------
// Injectable traits (for tests)
// ---------------------------------------------------------------------------

/// Read files and list dirs (injectable for tests).
pub trait FileReader: Send + Sync {
    fn read_file(&self, path: &str) -> Option<String>;
    #[allow(dead_code)]
    fn read_dir_entries(&self, path: &str) -> Vec<String>;
    fn path_exists(&self, path: &str) -> bool;
}

/// Run external commands (injectable for tests).
#[async_trait::async_trait]
pub trait CommandRunner: Send + Sync {
    async fn run_lsof(&self, pid: i32) -> Result<String, String>;
    async fn run_git_rev_parse_show_toplevel(&self, dir: &str) -> Result<String, String>;
}

/// Default filesystem reader.
pub struct StdFileReader;

impl FileReader for StdFileReader {
    fn read_file(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    fn read_dir_entries(&self, path: &str) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(path) else { return vec![] };
        entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect()
    }

    fn path_exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }
}

/// Default command runner (macOS: lsof, git). Kept for potential lsof-based discovery.
#[allow(dead_code)]
pub struct StdCommandRunner;

#[async_trait::async_trait]
impl CommandRunner for StdCommandRunner {
    async fn run_lsof(&self, pid: i32) -> Result<String, String> {
        let out = tokio::process::Command::new("lsof")
            .args(["-p", &pid.to_string(), "-Fn"])
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).to_string())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).to_string())
        }
    }

    async fn run_git_rev_parse_show_toplevel(&self, dir: &str) -> Result<String, String> {
        let out = tokio::process::Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .current_dir(dir)
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            Ok(s)
        } else {
            Err(String::from_utf8_lossy(&out.stderr).to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// Root discovery (lsof-based - kept for potential future use)
// ---------------------------------------------------------------------------

/// Noise patterns to exclude from lsof paths (avoids .cursor, node_modules, etc.).
const PATH_NOISE: &[&str] = &[
    "/Library/",
    ".framework/",
    ".cursor",
    ".vscode",
    "node_modules",
    "/.git/",
];

fn is_noise_path(path: &str) -> bool {
    PATH_NOISE.iter().any(|p| path.contains(p))
}

/// Parse lsof -Fn output: lines starting with 'n' are path names.
/// Returns paths under /Users/ excluding noise.
pub fn parse_lsof_output(lsof_out: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for line in lsof_out.lines() {
        let line = line.trim();
        if line.starts_with('n') && line.len() > 1 {
            let path = line[1..].trim();
            if path.starts_with("/Users/") && !is_noise_path(path) {
                paths.push(path.to_string());
            }
        }
    }
    paths
}

/// Discover workspace roots for a process. Uses lsof. Kept for potential future use.
#[allow(dead_code)]
pub async fn discover_roots_for_pid<F: FileReader, R: CommandRunner>(
    reader: &F,
    runner: &R,
    pid: i32,
    max_roots: usize,
) -> Vec<String> {
    let out = match runner.run_lsof(pid).await {
        Ok(s) => s,
        Err(e) => {
            debug!("Workspace discovery: lsof failed for pid={}: {}", pid, e);
            return vec![];
        }
    };
    let paths = parse_lsof_output(&out);
    if paths.is_empty() {
        return vec![];
    }
    let mut dir_counts: HashMap<String, usize> = HashMap::new();
    for p in &paths {
        if let Some(parent) = std::path::Path::new(p).parent() {
            let dir = parent.to_string_lossy().to_string();
            *dir_counts.entry(dir).or_insert(0) += 1;
        }
    }
    let mut by_count: Vec<_> = dir_counts.into_iter().collect();
    by_count.sort_by(|a, b| b.1.cmp(&a.1));
    let candidates: Vec<_> = by_count
        .into_iter()
        .take((max_roots * 3).max(20))
        .map(|(dir, _)| dir)
        .collect();
    let mut roots: HashSet<String> = HashSet::new();
    for dir in candidates {
        if let Ok(root) = runner.run_git_rev_parse_show_toplevel(&dir).await {
            let root = root.trim().to_string();
            if reader.path_exists(&root) {
                roots.insert(root);
                if roots.len() >= max_roots {
                    break;
                }
            }
        } else {
            let path = PathBuf::from(&dir);
            if path.join("Cargo.toml").exists() || path.join("package.json").exists() {
                if reader.path_exists(&dir) {
                    roots.insert(dir);
                    if roots.len() >= max_roots {
                        break;
                    }
                }
            }
        }
    }
    let mut out: Vec<String> = roots.into_iter().collect();
    out.sort();
    out.dedup();
    out.into_iter().take(max_roots).collect()
}

#[allow(dead_code)]
fn dominant_dir_from_paths(paths: &[String]) -> Option<String> {
    let mut dir_counts: HashMap<String, usize> = HashMap::new();
    for p in paths {
        if let Some(parent) = std::path::Path::new(p).parent() {
            let dir = parent.to_string_lossy().to_string();
            *dir_counts.entry(dir).or_insert(0) += 1;
        }
    }
    dir_counts
        .into_iter()
        .max_by_key(|(_, c)| *c)
        .map(|(dir, _)| dir)
}

pub(super) fn extract_paths_from_json(json: &str) -> Vec<String> {
    let mut out = Vec::new();
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(x) => x,
        Err(_) => return out,
    };
    fn visit(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, val) in m {
                    let kl = k.to_lowercase();
                    if (kl == "folderuri" || kl == "path" || kl == "folder") && val.is_string() {
                        if let Some(s) = val.as_str() {
                            let decoded = if s.starts_with("file://") {
                                s.strip_prefix("file://")
                                    .map(|p| p.replace("%20", " ").replace("%2F", "/"))
                                    .unwrap_or_default()
                            } else if s.starts_with('/') {
                                s.to_string()
                            } else if s.starts_with("~/") {
                                std::env::var_os("HOME")
                                    .map(|h| format!("{}/{}", h.to_string_lossy(), s.trim_start_matches("~/")))
                                    .unwrap_or_default()
                            } else {
                                continue;
                            };
                            if !decoded.is_empty() && std::path::Path::new(&decoded).exists() {
                                out.push(decoded);
                            }
                        }
                    }
                    if kl == "folders" {
                        visit(val, out);
                    }
                    if kl.contains("workspace") || kl.contains("recent") || kl == "entries" {
                        visit(val, out);
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    visit(item, out);
                }
            }
            _ => {}
        }
    }
    visit(&v, &mut out);
    out
}

// ---------------------------------------------------------------------------
// Config and storage watcher
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct WorkspaceResolverConfig {
    pub poll_interval_ms: u64,
    pub max_roots_per_source: usize,
    pub wake_debounce_secs: u64,
}

impl Default for WorkspaceResolverConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 30_000,
            max_roots_per_source: 10,
            wake_debounce_secs: 30,
        }
    }
}

/// Directories to watch for workspace changes (FSEvents).
fn workspace_storage_watch_dirs() -> Vec<PathBuf> {
    let home = std::env::var_os("HOME")
        .and_then(|h| h.into_string().ok())
        .unwrap_or_default();
    if home.is_empty() {
        return vec![];
    }
    let mut out = Vec::new();
    for app in ["Cursor", "Code"] {
        let base = PathBuf::from(&home).join("Library/Application Support").join(app);
        if base.exists() {
            out.push(base);
        }
    }
    out
}

/// Watches Cursor storage dirs with FSEvents; sends wake signals to trigger resolver.
pub fn spawn_storage_watcher(
    wake_tx: mpsc::UnboundedSender<()>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    let dirs = workspace_storage_watch_dirs();
    if dirs.is_empty() {
        return tokio::spawn(async move {
            let _ = shutdown_rx.recv().await;
        });
    }
    tokio::spawn(async move {
        let mut w = match notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            if res.is_ok() {
                let _ = wake_tx.send(());
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!("Workspace storage watcher failed to create: {}", e);
                return;
            }
        };
        for dir in &dirs {
            if let Err(e) = w.watch(dir, RecursiveMode::Recursive) {
                warn!("Failed to watch {:?}: {}", dir, e);
            } else {
                debug!("Watching workspace storage: {:?}", dir);
            }
        }
        info!("Workspace storage watcher active ({} dirs)", dirs.len());
        let _ = shutdown_rx.recv().await;
    })
}

/// Workspace resolver: discovers roots via Cursor storage (decoupled from sessions).
pub struct WorkspaceResolver {
    config: WorkspaceResolverConfig,
    state: Arc<RwLock<WorkspaceResolverState>>,
    event_tx: Option<mpsc::UnboundedSender<WorkspaceEvent>>,
}

impl WorkspaceResolver {
    pub fn new(
        config: WorkspaceResolverConfig,
        state: Arc<RwLock<WorkspaceResolverState>>,
        event_tx: Option<mpsc::UnboundedSender<WorkspaceEvent>>,
    ) -> Self {
        Self {
            config,
            state,
            event_tx,
        }
    }

    /// Run the resolver. Uses Cursor-specific discovery (storage.json + workspace.json).
    pub async fn run(
        &self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        mut wake_rx: mpsc::UnboundedReceiver<()>,
    ) {
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut ticker = tokio::time::interval(Duration::from_millis(self.config.poll_interval_ms));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let reader = StdFileReader;
        let mut last_discovery = tokio::time::Instant::now() - Duration::from_secs(60);
        let debounce = Duration::from_secs(self.config.wake_debounce_secs);

        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = shutdown_rx.recv() => {
                    info!("Workspace resolver shutting down");
                    return;
                }
                _ = wake_rx.recv() => {
                    while wake_rx.try_recv().is_ok() {}
                    if last_discovery.elapsed() < debounce {
                        continue;
                    }
                }
            }

            // Cursor-specific discovery: storage.json → active windows, workspace.json → roots
            let windows = cursor_discovery::discover_cursor_roots(&reader);
            let max = self.config.max_roots_per_source;

            let prev_items = {
                let s = self.state.read().await;
                s.items.clone()
            };

            let mut new_items = Vec::new();
            for w in &windows {
                let roots: Vec<String> = w.roots.iter().cloned().take(max).collect();
                if roots.is_empty() {
                    continue;
                }
                let observed_at = OffsetDateTime::now_utc();
                new_items.push(WorkspaceState {
                    source_id: w.source_id.clone(),
                    app: AppKind::Cursor,
                    roots: roots.clone(),
                    observed_at,
                });

                let prev = prev_items.iter().find(|i| i.source_id == w.source_id).map(|i| i.roots.clone());
                let prev_set: HashSet<_> = prev.unwrap_or_default().into_iter().collect();
                let new_set: HashSet<_> = roots.iter().cloned().collect();
                if prev_set != new_set {
                    info!("Workspace updated: source_id={} roots={:?}", w.source_id, roots);
                    if let Some(ref tx) = self.event_tx {
                        let _ = tx.send(WorkspaceEvent::Updated {
                            source_id: w.source_id.clone(),
                            app: AppKind::Cursor,
                            roots,
                            observed_at,
                        });
                    }
                }
            }

            last_discovery = tokio::time::Instant::now();

            let new_source_ids: HashSet<_> = new_items.iter().map(|i| i.source_id.as_str()).collect();
            for old in &prev_items {
                if !old.roots.is_empty() && !new_source_ids.contains(old.source_id.as_str()) {
                    info!("Workspace roots removed: source_id={} roots={:?}", old.source_id, old.roots);
                    if let Some(ref tx) = self.event_tx {
                        let _ = tx.send(WorkspaceEvent::RootsRemoved {
                            source_id: old.source_id.clone(),
                            roots: old.roots.clone(),
                        });
                    }
                }
            }

            {
                let mut s = self.state.write().await;
                s.items = new_items;
                s.last_run_at = Some(OffsetDateTime::now_utc());
                s.last_error = None;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lsof_output_filters_noise() {
        let out = "p123\nn/Users/joe/proj/src/main.rs\nn/Users/joe/proj/node_modules/x/file.js\nn/usr/lib/libc.dylib\n";
        let paths = parse_lsof_output(out);
        assert_eq!(paths.len(), 1);
        assert!(paths.contains(&"/Users/joe/proj/src/main.rs".to_string()));
    }

    #[test]
    fn parse_lsof_output_valid_paths() {
        let out = "p123\nn/Users/joe/proj/src/main.rs\nn/Users/joe/proj/src/lib.rs\nn/usr/lib/libc.dylib\n";
        let paths = parse_lsof_output(out);
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&"/Users/joe/proj/src/main.rs".to_string()));
        assert!(paths.contains(&"/Users/joe/proj/src/lib.rs".to_string()));
    }

    #[test]
    fn extract_paths_from_json_folder_uri() {
        let json = r#"{"folderUri":"file:///tmp"}"#;
        let roots = extract_paths_from_json(json);
        if std::path::Path::new("/tmp").exists() {
            assert!(!roots.is_empty());
            assert!(roots[0].contains("tmp"));
        }
    }

    #[test]
    fn extract_paths_from_json_entries_array() {
        let json = r#"{"entries":[{"folderUri":"file:///tmp/a"},{"folderUri":"file:///tmp/b"}]}"#;
        let roots = extract_paths_from_json(json);
        if std::path::Path::new("/tmp/a").exists() && std::path::Path::new("/tmp/b").exists() {
            assert_eq!(roots.len(), 2);
            assert!(roots.contains(&"/tmp/a".to_string()));
            assert!(roots.contains(&"/tmp/b".to_string()));
        }
    }

    #[test]
    fn parse_lsof_output_dominant_dir() {
        let out = "p123\nn/Users/joe/proj/src/main.rs\nn/Users/joe/proj/src/lib.rs\nn/usr/lib/libc.dylib\n";
        let paths = parse_lsof_output(out);
        assert_eq!(paths.len(), 2);
        let dir = dominant_dir_from_paths(&paths);
        assert_eq!(dir.as_deref(), Some("/Users/joe/proj/src"));
    }
}
