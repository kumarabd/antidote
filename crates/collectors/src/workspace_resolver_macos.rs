//! macOS workspace root resolver (Cursor/VSCode). Infers workspace roots from
//! app storage JSON, window title, or lsof. Emits WorkspaceEvent::Updated for downstream use.

use crate::app_detector_macos::{AppDetectorState, AppKind};
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

/// Confidence level for resolved workspace roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Source tier that produced the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceTier {
    Tier1,
    Tier2,
    Tier3,
}

/// Workspace update event emitted when roots change.
#[derive(Debug, Clone)]
pub enum WorkspaceEvent {
    Updated {
        app: AppKind,
        pid: i32,
        roots: Vec<String>,
        confidence: Confidence,
        observed_at: OffsetDateTime,
    },
    /// Emitted when roots are no longer present for a (app, pid) (window closed, folder removed).
    RootsRemoved {
        app: AppKind,
        pid: i32,
        roots: Vec<String>,
    },
}

/// Per-(app, pid) workspace state for debug and downstream.
#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceState {
    pub app: AppKind,
    pub pid: i32,
    pub roots: Vec<String>,
    pub confidence: Confidence,
    #[serde(rename = "source_tier")]
    pub source: SourceTier,
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
    async fn run_osascript(&self, script: &str) -> Result<String, String>;
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

/// Default command runner (macOS: osascript, lsof, git).
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

    async fn run_osascript(&self, script: &str) -> Result<String, String> {
        let out = tokio::process::Command::new("osascript")
            .args(["-e", script])
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
// URI and path helpers
// ---------------------------------------------------------------------------

/// Parse file:// URI (and vscode-file://vscode-app/...) to absolute path.
/// Percent-decodes path. Returns None if not a file URI or invalid.
pub fn file_uri_to_path(uri: &str) -> Option<String> {
    let uri = uri.trim();
    let path_str = if uri.starts_with("file://") {
        uri.strip_prefix("file://")?
    } else if uri.contains("file://") {
        // vscode-file://vscode-app/... or similar: take after last "file://"
        uri.rsplit_once("file://")?.1
    } else {
        return None;
    };
    // Percent-decode
    let decoded = percent_decode(path_str);
    // Normalize: remove trailing slash, ensure absolute
    let path = PathBuf::from(&decoded);
    let path = path.canonicalize().ok().or_else(|| Some(path))?;
    path.to_str().map(|s| s.to_string())
}

fn percent_decode(s: &str) -> String {
    let mut out = String::new();
    let mut i = 0;
    let b = s.as_bytes();
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                out.push(char::from(h * 16 + l));
                i += 3;
                continue;
            }
        }
        if b[i] == b'+' {
            out.push(' ');
        } else {
            out.push(b[i] as char);
        }
        i += 1;
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Expand ~ to home dir.
pub fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home)
                .join(path.strip_prefix("~/").unwrap_or(path))
                .to_string_lossy()
                .to_string();
        }
    } else if path == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home).to_string_lossy().to_string();
        }
    }
    path.to_string()
}

// ---------------------------------------------------------------------------
// Tier 1: Cursor/VSCode JSON storage
// ---------------------------------------------------------------------------

/// Extract workspace paths from a JSON string (storage.json, recentlyOpened, etc.).
/// Looks for folderUri, fileUri, path, workspace paths in common structures.
pub fn extract_roots_from_json(json_str: &str, limit: usize) -> Vec<String> {
    let mut roots: Vec<String> = Vec::new();
    let v: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(x) => x,
        Err(_) => return roots,
    };
    extract_roots_from_value(&v, &mut roots);
    roots.sort();
    roots.dedup();
    roots.into_iter().take(limit).collect()
}

fn extract_roots_from_value(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, val) in m {
                let key_lower = k.to_lowercase();
                // Single path/URI fields
                if (key_lower == "folderuri" || key_lower == "fileuri" || key_lower == "path" || key_lower == "folder")
                    && val.is_string()
                {
                    if let Some(s) = val.as_str() {
                        if let Some(path) = path_from_str(s) {
                            if std::path::Path::new(&path).exists() {
                                out.push(path);
                            }
                        }
                    }
                }
                // Multi-root workspace: "folders" array of {path, folder, folderUri, ...}
                if key_lower == "folders" {
                    if let Some(arr) = val.as_array() {
                        for item in arr {
                            if let Some(obj) = item.as_object() {
                                for (fk, fv) in obj {
                                    let fk_lower = fk.to_lowercase();
                                    if (fk_lower == "path" || fk_lower == "folder" || fk_lower == "folderuri" || fk_lower == "uri")
                                        && fv.is_string()
                                    {
                                        if let Some(s) = fv.as_str() {
                                            if let Some(path) = path_from_str(s) {
                                                if std::path::Path::new(&path).exists() {
                                                    out.push(path);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if key_lower.contains("workspace") || key_lower.contains("recent") || key_lower == "entries" {
                    extract_roots_from_value(val, out);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                extract_roots_from_value(item, out);
            }
        }
        _ => {}
    }
}

fn path_from_str(s: &str) -> Option<String> {
    file_uri_to_path(s).or_else(|| {
        if s.starts_with('/') || s.starts_with("file:") {
            file_uri_to_path(s)
        } else {
            Some(expand_tilde(s))
        }
    })
}

/// Candidate JSON paths for Cursor and VSCode (under Application Support).
fn cursor_storage_candidates() -> Vec<String> {
    let home = std::env::var_os("HOME").map(|h| h.to_string_lossy().to_string()).unwrap_or_default();
    if home.is_empty() {
        return vec![];
    }
    let base = format!("{}/Library/Application Support/Cursor", home);
    let mut out = Vec::new();
    for sub in ["User", "User/globalStorage", ""] {
        let dir = if sub.is_empty() { base.clone() } else { format!("{}/{}", base, sub) };
        for name in ["storage.json", "recentlyOpened.json", "state.json"] {
            out.push(format!("{}/{}", dir, name));
        }
    }
    // workspaceStorage: each subdir has workspace.json with folder(s) for that workspace
    let ws_storage = format!("{}/User/workspaceStorage", base);
    if let Ok(entries) = std::fs::read_dir(&ws_storage) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.push(p.join("workspace.json").to_string_lossy().to_string());
            }
        }
    }
    // Recursive glob under Cursor
    if let Ok(entries) = std::fs::read_dir(&base) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                for name in ["storage.json", "recentlyOpened.json", "state.json"] {
                    out.push(p.join(name).to_string_lossy().to_string());
                }
            }
        }
    }
    out
}

fn vscode_storage_candidates() -> Vec<String> {
    let home = std::env::var_os("HOME").map(|h| h.to_string_lossy().to_string()).unwrap_or_default();
    if home.is_empty() {
        return vec![];
    }
    let base = format!("{}/Library/Application Support/Code", home);
    let mut out = vec![
        format!("{}/User/globalStorage/storage.json", base),
        format!("{}/storage.json", base),
    ];
    // workspaceStorage: each subdir has workspace.json with folder(s) for that workspace
    let ws_storage = format!("{}/User/workspaceStorage", base);
    if let Ok(entries) = std::fs::read_dir(&ws_storage) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.push(p.join("workspace.json").to_string_lossy().to_string());
            }
        }
    }
    out
}

/// Directories to watch for workspace changes (FSEvents). When these change, resolver re-runs.
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

pub fn resolve_tier1<F: FileReader>(
    reader: &F,
    app: AppKind,
    _pid: i32,
    max_roots: usize,
) -> (Vec<String>, SourceTier) {
    let candidates = match app {
        AppKind::Cursor => cursor_storage_candidates(),
        AppKind::VSCode => vscode_storage_candidates()
            .into_iter()
            .filter(|p| p.ends_with(".json"))
            .collect(),
        _ => return (vec![], SourceTier::Tier1),
    };
    let mut all_roots = Vec::new();
    for path in candidates {
        if let Some(s) = reader.read_file(&path) {
            let roots = extract_roots_from_json(&s, max_roots);
            for r in roots {
                if reader.path_exists(&r) {
                    all_roots.push(r);
                }
            }
        }
    }
    all_roots.sort();
    all_roots.dedup();
    let roots: Vec<String> = all_roots.into_iter().take(max_roots).collect();
    if roots.is_empty() {
        (roots, SourceTier::Tier1)
    } else {
        (roots, SourceTier::Tier1)
    }
}

// ---------------------------------------------------------------------------
// Tier 2: Foreground window title + folder name resolution
// ---------------------------------------------------------------------------

/// Get frontmost application name (macOS AppleScript).
pub async fn get_frontmost_app_name<R: CommandRunner>(runner: &R) -> String {
    let script = r#"tell application "System Events" to get name of first application process whose frontmost is true"#;
    runner.run_osascript(script).await.unwrap_or_default()
}

/// Get frontmost window title (best-effort).
pub async fn get_frontmost_window_title<R: CommandRunner>(runner: &R) -> String {
    let script = r#"tell application "System Events"
    set frontApp to first application process whose frontmost is true
    try
        return name of front window of frontApp
    on error
        return ""
    end try
end tell"#;
    runner.run_osascript(script).await.unwrap_or_default()
}

/// Parse window title like "main.rs — foo — Cursor" or "foo — Cursor" to folder name "foo".
pub fn parse_folder_from_window_title(title: &str, app_name: &str) -> Option<String> {
    let title = title.trim();
    if title.is_empty() {
        return None;
    }
    // Split by " — " or " - "
    let parts: Vec<&str> = title
        .split(" — ")
        .flat_map(|s| s.split(" - "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    // Remove app name from end
    let parts: Vec<&str> = parts
        .into_iter()
        .filter(|s| !s.eq_ignore_ascii_case(app_name))
        .collect();
    // Prefer a segment that looks like a folder (no extension, or single segment)
    if parts.len() == 1 {
        return Some(parts[0].to_string());
    }
    if parts.len() >= 2 {
        // Often "file — folder — app"; folder is second-to-last or middle
        return Some(parts[parts.len() - 1].to_string());
    }
    None
}

/// Resolve folder name to a single path by scanning candidate dirs.
pub fn resolve_folder_name_to_path<F: FileReader>(
    reader: &F,
    folder_name: &str,
    dev_dir_candidates: &[String],
) -> Option<String> {
    let folder_name = folder_name.trim();
    if folder_name.is_empty() {
        return None;
    }
    for dir in dev_dir_candidates {
        let expanded = expand_tilde(dir);
        let candidate = format!("{}/{}", expanded.trim_end_matches('/'), folder_name);
        if reader.path_exists(&candidate) {
            return Some(candidate);
        }
    }
    None
}

pub async fn resolve_tier2<F: FileReader, R: CommandRunner>(
    reader: &F,
    runner: &R,
    _app: AppKind,
    app_name_for_title: &str,
    dev_dir_candidates: &[String],
) -> (Vec<String>, SourceTier) {
    let app_name = get_frontmost_app_name(runner).await;
    if !app_name.to_lowercase().contains(&app_name_for_title.to_lowercase()) {
        return (vec![], SourceTier::Tier2);
    }
    let title = get_frontmost_window_title(runner).await;
    let folder = match parse_folder_from_window_title(&title, &app_name) {
        Some(f) => f,
        None => return (vec![], SourceTier::Tier2),
    };
    match resolve_folder_name_to_path(reader, &folder, dev_dir_candidates) {
        Some(path) => (vec![path], SourceTier::Tier2),
        None => (vec![], SourceTier::Tier2),
    }
}

// ---------------------------------------------------------------------------
// Tier 3: lsof + git root (throttled)
// ---------------------------------------------------------------------------

/// Parse lsof -Fn output: lines starting with 'n' are path names. Return paths under /Users.
pub fn parse_lsof_output(lsof_out: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for line in lsof_out.lines() {
        let line = line.trim();
        if line.starts_with('n') && line.len() > 1 {
            let path = line[1..].trim();
            if path.starts_with("/Users/") && !path.contains("/Library/") && !path.contains(".framework/") {
                paths.push(path.to_string());
            }
        }
    }
    paths
}

/// Pick top directory by frequency, then optionally promote to git root.
pub fn dominant_dir_from_paths(paths: &[String]) -> Option<String> {
    if paths.is_empty() {
        return None;
    }
    let mut dir_counts: HashMap<String, usize> = HashMap::new();
    for p in paths {
        if let Some(parent) = std::path::Path::new(p).parent() {
            let dir = parent.to_string_lossy().to_string();
            *dir_counts.entry(dir).or_insert(0) += 1;
        }
    }
    let mut by_count: Vec<_> = dir_counts.into_iter().collect();
    by_count.sort_by(|a, b| b.1.cmp(&a.1));
    by_count.into_iter().next().map(|(dir, _)| dir)
}

pub async fn resolve_tier3<F: FileReader, R: CommandRunner>(
    reader: &F,
    runner: &R,
    pid: i32,
) -> (Vec<String>, SourceTier) {
    let out = match runner.run_lsof(pid).await {
        Ok(s) => s,
        Err(_) => return (vec![], SourceTier::Tier3),
    };
    let paths = parse_lsof_output(&out);
    let Some(dir) = dominant_dir_from_paths(&paths) else {
        return (vec![], SourceTier::Tier3);
    };
    if let Ok(root) = runner.run_git_rev_parse_show_toplevel(&dir).await {
        let root = root.trim().to_string();
        if reader.path_exists(&root) {
            return (vec![root], SourceTier::Tier3);
        }
    }
    if reader.path_exists(&dir) {
        (vec![dir], SourceTier::Tier3)
    } else {
        (vec![], SourceTier::Tier3)
    }
}

// ---------------------------------------------------------------------------
// Resolver config and main loop
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct WorkspaceResolverConfig {
    pub poll_interval_ms: u64,
    pub max_roots_per_app: usize,
    pub dev_dir_candidates: Vec<String>,
    pub lsof_fallback_enabled: bool,
    pub lsof_min_interval_ms: u64,
}

impl Default for WorkspaceResolverConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 30_000, // 30s fallback; FSEvents on storage dirs provides event-driven wake
            max_roots_per_app: 5,
            dev_dir_candidates: vec![
                "~/code".into(),
                "~/dev".into(),
                "~/projects".into(),
                "~/workspace".into(),
                "~/Documents".into(),
            ],
            lsof_fallback_enabled: true,
            lsof_min_interval_ms: 30000,
        }
    }
}

/// Key for workspace state map: (AppKind, pid). We use (String, i32) for serialization.
fn app_pid_key(app: &AppKind, pid: i32) -> (String, i32) {
    (app.as_display_str().to_string(), pid)
}

/// Watches Cursor/VSCode storage dirs with FSEvents; sends wake signals to trigger resolver.
/// Spawn this task; it runs until shutdown. Pass the receiver to resolver.run() as wake_rx.
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
        info!(
            "Workspace storage watcher active ({} dirs), event-driven mode",
            dirs.len()
        );
        // Keep watcher alive until shutdown
        let _ = shutdown_rx.recv().await;
    })
}

/// Workspace resolver: polls app state and resolves roots per Cursor/VSCode instance.
pub struct WorkspaceResolver {
    config: WorkspaceResolverConfig,
    state: Arc<RwLock<WorkspaceResolverState>>,
    event_tx: Option<mpsc::UnboundedSender<WorkspaceEvent>>,
    last_lsof_per_pid: Arc<RwLock<HashMap<i32, OffsetDateTime>>>,
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
            last_lsof_per_pid: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Run resolution for one (app, pid). Returns (roots, confidence, source).
    async fn resolve_one(
        &self,
        app: AppKind,
        pid: i32,
    ) -> (Vec<String>, Confidence, SourceTier) {
        let reader = StdFileReader;
        let runner = StdCommandRunner;

        // Tier 1
        let (roots1, src1) = tokio::task::spawn_blocking({
            let reader = StdFileReader;
            let app = app.clone();
            let max = self.config.max_roots_per_app;
            move || resolve_tier1(&reader, app, pid, max)
        })
        .await
        .unwrap_or((vec![], SourceTier::Tier1));

        if !roots1.is_empty() {
            return (roots1, Confidence::High, src1);
        }

        // Tier 2
        let app_name = app.as_display_str();
        let (roots2, src2) =
            resolve_tier2(&reader, &runner, app.clone(), app_name, &self.config.dev_dir_candidates).await;
        if !roots2.is_empty() {
            return (roots2, Confidence::Medium, src2);
        }

        // Tier 3 (throttled)
        if self.config.lsof_fallback_enabled {
            let now = OffsetDateTime::now_utc();
            let min_ms = self.config.lsof_min_interval_ms as i64;
            let ok = {
                let last = self.last_lsof_per_pid.write().await;
                let last_ts = last.get(&pid).copied();
                match last_ts {
                    Some(ts) => (now - ts).whole_milliseconds() >= min_ms as i128,
                    None => true,
                }
            };
            if ok {
                if let Ok(mut last) = self.last_lsof_per_pid.try_write() {
                    last.insert(pid, now);
                }
                let (roots3, src3) = tokio::time::timeout(
                    Duration::from_secs(5),
                    resolve_tier3(&reader, &runner, pid),
                )
                .await
                .unwrap_or((vec![], SourceTier::Tier3));
                if !roots3.is_empty() {
                    return (roots3, Confidence::Low, src3);
                }
            }
        }

        (vec![], Confidence::High, SourceTier::Tier1)
    }

    /// Run the resolver. Pass wake_rx from spawn_storage_watcher for event-driven re-resolution
    /// when Cursor/VSCode storage files change; otherwise pass a channel that never receives.
    pub async fn run(
        &self,
        app_state: Arc<RwLock<AppDetectorState>>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        mut wake_rx: mpsc::UnboundedReceiver<()>,
    ) {
        let mut ticker = tokio::time::interval(Duration::from_millis(self.config.poll_interval_ms));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = shutdown_rx.recv() => {
                    info!("Workspace resolver shutting down");
                    return;
                }
                _ = wake_rx.recv() => {
                    debug!("Workspace storage changed, re-resolving");
                }
            }

            let instances = {
                let s = app_state.read().await;
                s.instances.clone()
            };

            let prev_items = {
                let s = self.state.read().await;
                s.items.clone()
            };

            // Only Cursor and VSCode for v1
            let relevant: Vec<_> = instances
                .into_iter()
                .filter(|i| matches!(i.app, AppKind::Cursor | AppKind::VSCode))
                .collect();

            let mut new_items = Vec::new();
            let last_error = None::<String>;

            for inst in relevant {
                let (roots, confidence, source) = self.resolve_one(inst.app.clone(), inst.pid).await;
                let observed_at = OffsetDateTime::now_utc();
                if roots.is_empty() {
                    continue;
                }

                let state_entry = WorkspaceState {
                    app: inst.app.clone(),
                    pid: inst.pid,
                    roots: roots.clone(),
                    confidence,
                    source,
                    observed_at,
                };
                new_items.push(state_entry);

                // Emit only when roots changed (compare with current state)
                let key = app_pid_key(&inst.app, inst.pid);
                let prev = {
                    let s = self.state.read().await;
                    s.items
                        .iter()
                        .find(|i| (i.app.as_display_str().to_string(), i.pid) == key)
                        .map(|i| i.roots.clone())
                };
                let prev_set: HashSet<_> = prev.unwrap_or_default().into_iter().collect();
                let new_set: HashSet<_> = roots.iter().cloned().collect();
                if prev_set != new_set {
                    info!(
                        "Workspace updated: {} pid={} roots={:?} confidence={:?}",
                        inst.app.as_display_str(),
                        inst.pid,
                        roots,
                        confidence
                    );
                    if let Some(ref tx) = self.event_tx {
                        let _ = tx.send(WorkspaceEvent::Updated {
                            app: inst.app,
                            pid: inst.pid,
                            roots,
                            confidence,
                            observed_at,
                        });
                    }
                }
            }

            // Emit RootsRemoved for (app, pid) that had roots before but are now gone or empty
            let new_keys: HashSet<_> = new_items.iter().map(|i| app_pid_key(&i.app, i.pid)).collect();
            for old in &prev_items {
                let key = app_pid_key(&old.app, old.pid);
                if !old.roots.is_empty() && !new_keys.contains(&key) {
                    info!(
                        "Workspace roots removed: {} pid={} roots={:?}",
                        old.app.as_display_str(),
                        old.pid,
                        old.roots
                    );
                    if let Some(ref tx) = self.event_tx {
                        let _ = tx.send(WorkspaceEvent::RootsRemoved {
                            app: old.app.clone(),
                            pid: old.pid,
                            roots: old.roots.clone(),
                        });
                    }
                }
            }

            {
                let mut s = self.state.write().await;
                s.items = new_items;
                s.last_run_at = Some(OffsetDateTime::now_utc());
                s.last_error = last_error;
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
    fn file_uri_to_path_basic() {
        assert_eq!(
            file_uri_to_path("file:///Users/me/code/foo"),
            Some("/Users/me/code/foo".to_string())
        );
    }

    #[test]
    fn file_uri_to_path_percent_decode() {
        assert_eq!(
            file_uri_to_path("file:///Users/me/foo%20bar"),
            Some("/Users/me/foo bar".to_string())
        );
    }

    #[test]
    fn file_uri_to_path_invalid_returns_none() {
        assert!(file_uri_to_path("http://example.com").is_none());
        assert!(file_uri_to_path("not-a-uri").is_none());
    }

    #[test]
    fn extract_roots_from_json_folder_uri() {
        let json = r#"{"folderUri":"file:///tmp"}"#;
        let roots = extract_roots_from_json(json, 5);
        // /tmp exists on Unix; parsing should yield /tmp (or canonical form)
        if std::path::Path::new("/tmp").exists() {
            assert!(!roots.is_empty());
            assert!(roots[0].contains("tmp"));
        }
    }

    #[test]
    fn extract_roots_from_json_entries_array() {
        let json = r#"{"entries":[{"folderUri":"file:///tmp/a"},{"folderUri":"file:///tmp/b"}]}"#;
        let roots = extract_roots_from_json(json, 5);
        if std::path::Path::new("/tmp/a").exists() && std::path::Path::new("/tmp/b").exists() {
            assert_eq!(roots.len(), 2);
            assert!(roots.contains(&"/tmp/a".to_string()));
            assert!(roots.contains(&"/tmp/b".to_string()));
        }
    }

    #[test]
    fn parse_folder_from_window_title() {
        assert_eq!(
            parse_folder_from_window_title("main.rs — foo — Cursor", "Cursor"),
            Some("foo".to_string())
        );
        assert_eq!(
            parse_folder_from_window_title("foo — Cursor", "Cursor"),
            Some("foo".to_string())
        );
        assert_eq!(
            parse_folder_from_window_title("single", "Cursor"),
            Some("single".to_string())
        );
    }

    struct MockFileReader {
        existing: std::collections::HashSet<String>,
    }
    impl FileReader for MockFileReader {
        fn read_file(&self, _path: &str) -> Option<String> {
            None
        }
        fn read_dir_entries(&self, _path: &str) -> Vec<String> {
            vec![]
        }
        fn path_exists(&self, path: &str) -> bool {
            self.existing.contains(path)
        }
    }

    #[test]
    fn resolve_folder_name_to_path_mock() {
        let reader = MockFileReader {
            existing: ["/Users/me/code/foo".to_string()].into_iter().collect(),
        };
        let candidates = vec!["/Users/me/code".to_string(), "/Users/me/dev".to_string()];
        assert_eq!(
            resolve_folder_name_to_path(&reader, "foo", &candidates),
            Some("/Users/me/code/foo".to_string())
        );
        assert_eq!(resolve_folder_name_to_path(&reader, "nonexistent", &candidates), None);
    }

    #[test]
    fn parse_lsof_output_dominant_dir() {
        let out = "p123\nn/Users/joe/proj/src/main.rs\nn/Users/joe/proj/src/lib.rs\nn/usr/lib/libc.dylib\n";
        let paths = parse_lsof_output(out);
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&"/Users/joe/proj/src/main.rs".to_string()));
        let dir = dominant_dir_from_paths(&paths);
        assert_eq!(dir.as_deref(), Some("/Users/joe/proj/src"));
    }
}
