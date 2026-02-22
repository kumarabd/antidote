//! macOS foreground (frontmost) app detection for attribution.

use crate::app_detector_macos::AppKind;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tracing::debug;

/// Frontmost application snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct ForegroundApp {
    pub name: String,
    pub pid: Option<i32>,
    pub bundle_id: Option<String>,
    pub observed_at: OffsetDateTime,
}

/// Polls frontmost app every interval and stores in shared state.
pub struct ForegroundPoller {
    interval_ms: u64,
    state: Arc<RwLock<Option<ForegroundApp>>>,
}

impl ForegroundPoller {
    pub fn new(interval_ms: u64) -> Self {
        Self {
            interval_ms,
            state: Arc::new(RwLock::new(None)),
        }
    }

    pub fn state(&self) -> Arc<RwLock<Option<ForegroundApp>>> {
        Arc::clone(&self.state)
    }

    /// Runs the poller. If `activate_rx` is Some, receives event-driven foreground updates
    /// from NSWorkspace activate observer; poll is reconciliation-only (e.g. 30s).
    pub async fn run(
        self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        mut activate_rx: Option<tokio::sync::mpsc::UnboundedReceiver<ForegroundApp>>,
    ) {
        let mut ticker = tokio::time::interval(Duration::from_millis(self.interval_ms));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Initial poll on startup (design: "poll on daemon start to get initial state")
        let app = Self::poll_once().await;
        if let Some(ref a) = app {
            debug!("Foreground app (initial): {} pid={:?}", a.name, a.pid);
        }
        *self.state.write().await = app;

        loop {
            if let Some(ref mut rx) = activate_rx {
                tokio::select! {
                    _ = ticker.tick() => {
                        let app = Self::poll_once().await;
                        if let Some(ref a) = app {
                            debug!("Foreground app (poll): {} pid={:?}", a.name, a.pid);
                        }
                        *self.state.write().await = app;
                    }
                    Some(app) = rx.recv() => {
                        debug!("Foreground app (activate): {} pid={:?}", app.name, app.pid);
                        *self.state.write().await = Some(app);
                    }
                    _ = shutdown_rx.recv() => break,
                }
            } else {
                tokio::select! {
                    _ = ticker.tick() => {
                        let app = Self::poll_once().await;
                        if let Some(ref a) = app {
                            debug!("Foreground app (poll): {} pid={:?}", a.name, a.pid);
                        }
                        *self.state.write().await = app;
                    }
                    _ = shutdown_rx.recv() => break,
                }
            }
        }
    }

    async fn poll_once() -> Option<ForegroundApp> {
        let name = run_osascript(
            r#"tell application "System Events" to get name of first application process whose frontmost is true"#,
        )
        .await?;
        let name = name.trim().to_string();
        if name.is_empty() {
            return None;
        }
        let pid: Option<i32> = run_osascript(
            r#"tell application "System Events" to get unix id of first application process whose frontmost is true"#,
        )
        .await
        .and_then(|s| s.trim().parse().ok());
        let bundle_id = bundle_id_for_app(&name).await;
        Some(ForegroundApp {
            name,
            pid,
            bundle_id,
            observed_at: OffsetDateTime::now_utc(),
        })
    }
}

async fn run_osascript(script: &str) -> Option<String> {
    let out = tokio::process::Command::new("osascript")
        .args(["-e", script])
        .output()
        .await
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
}

/// Best-effort bundle id from app name (v1: map known apps).
async fn bundle_id_for_app(name: &str) -> Option<String> {
    let id = match name.to_lowercase().as_str() {
        "cursor" => Some("com.todesktop.230313mzl4w4u92"),
        "code" | "visual studio code" => Some("com.microsoft.VSCode"),
        "claude" => Some("com.anthropic.claude"),
        _ => None,
    };
    id.map(String::from)
}

/// Map foreground app name to AppKind.
pub fn app_kind_from_name(name: &str) -> Option<AppKind> {
    let n = name.to_lowercase();
    if n == "cursor" {
        Some(AppKind::Cursor)
    } else if n.contains("code") || n.contains("visual studio") {
        Some(AppKind::VSCode)
    } else if n.contains("claude") {
        Some(AppKind::Claude)
    } else {
        None
    }
}
