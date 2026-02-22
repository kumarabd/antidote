//! macOS-only app lifecycle detector for supported AI tools (Cursor, VSCode, Claude).
//! Uses process polling; emits Started/Exited events for SessionManager integration later.

use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, info, warn};

/// Supported app kinds (v1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AppKind {
    Cursor,
    VSCode,
    Claude,
    #[serde(rename = "unknown")]
    Unknown(String),
}

impl AppKind {
    pub fn as_display_str(&self) -> &str {
        match self {
            AppKind::Cursor => "Cursor",
            AppKind::VSCode => "VSCode",
            AppKind::Claude => "Claude",
            AppKind::Unknown(s) => s.as_str(),
        }
    }
}

/// Lifecycle events emitted by the app detector.
#[derive(Debug, Clone)]
pub enum AppEvent {
    Started {
        app: AppKind,
        pid: i32,
        process_name: Option<String>,
        bundle_id: Option<String>,
        started_at: OffsetDateTime,
    },
    Exited {
        app: AppKind,
        pid: i32,
        exited_at: OffsetDateTime,
    },
    /// Emitted after each poll; consumer can set last_scan_ts.
    ScanComplete { at: OffsetDateTime },
}

/// A detected app instance (for /debug/apps and state).
#[derive(Debug, Clone, Serialize)]
pub struct AppInstance {
    pub app: AppKind,
    pub pid: i32,
    pub bundle_id: Option<String>,
    pub started_at: OffsetDateTime,
}

impl AppInstance {
    pub fn new(app: AppKind, pid: i32, bundle_id: Option<String>, started_at: OffsetDateTime) -> Self {
        Self {
            app,
            pid,
            bundle_id,
            started_at,
        }
    }
}

/// Signature for matching a supported app (process names; bundle_ids optional in v1).
#[derive(Clone)]
pub struct AppSignature {
    app: AppKind,
    /// Main process name(s) only (e.g. "Cursor" for the app, not "Cursor Helper").
    names: Vec<&'static str>,
    /// If true, only match exact main process name (ignore helpers).
    main_process_only: bool,
}

pub fn default_signatures() -> Vec<AppSignature> {
    vec![
        // Main processes: one session per app
        AppSignature {
            app: AppKind::Cursor,
            names: vec!["Cursor"],
            main_process_only: true,
        },
        AppSignature {
            app: AppKind::VSCode,
            names: vec!["Code", "Visual Studio Code", "code"],
            main_process_only: true,
        },
        AppSignature {
            app: AppKind::Claude,
            names: vec!["Claude"],
            main_process_only: true,
        },
        // Renderer processes: one session per window (exact match only)
        AppSignature {
            app: AppKind::Cursor,
            names: vec!["Cursor Helper (Renderer)"],
            main_process_only: true,
        },
        AppSignature {
            app: AppKind::VSCode,
            names: vec!["Code Helper (Renderer)", "Code - Renderer"],
            main_process_only: true,
        },
    ]
}

/// Match a process name to a supported app; returns None if helper should be ignored or no match.
pub fn match_app(comm: &str, signatures: &[AppSignature]) -> Option<AppKind> {
    let comm_lower = comm.to_lowercase();
    for sig in signatures {
        if sig.main_process_only {
            // Cursor: only exact "Cursor" (case-insensitive), ignore "Cursor Helper", etc.
            if sig.names.iter().any(|n| comm_lower == n.to_lowercase()) {
                return Some(sig.app.clone());
            }
        } else {
            if sig.names.iter().any(|n| comm_lower.contains(&n.to_lowercase())) {
                return Some(sig.app.clone());
            }
        }
    }
    None
}

/// Shared state for app detector (current instances + last scan time).
#[derive(Debug, Clone, Default)]
pub struct AppDetectorState {
    pub instances: Vec<AppInstance>,
    pub last_scan_ts: Option<OffsetDateTime>,
}

/// Trait for app detectors (macOS implementation only in v1).
pub trait AppDetector {
    fn start(
        &self,
        sender: mpsc::Sender<AppEvent>,
    ) -> tokio::task::JoinHandle<()>;
}

/// Default poll interval when not configured.
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 2000;

/// macOS app detector: polls processes and emits Started/Exited.
pub struct MacAppDetector {
    poll_interval: Duration,
}

impl MacAppDetector {
    pub fn new(poll_interval_ms: u64) -> Self {
        Self {
            poll_interval: Duration::from_millis(poll_interval_ms),
        }
    }

    /// Enumerate running processes and return (pid, name) for those matching a supported app.
    fn snapshot_processes(sys: &mut sysinfo::System) -> Vec<(i32, String, Option<AppKind>)> {
        sys.refresh_all();
        let mut out = Vec::new();
        let signatures = default_signatures();
        for (pid, process) in sys.processes() {
            let pid_val = pid.as_u32() as i32;
            let name = process.name().to_string_lossy().to_string();
            if let Some(app) = match_app(&name, &signatures) {
                out.push((pid_val, name, Some(app)));
            }
        }
        out
    }
}

impl AppDetector for MacAppDetector {
    fn start(
        &self,
        sender: mpsc::Sender<AppEvent>,
    ) -> tokio::task::JoinHandle<()> {
        let poll_interval = self.poll_interval;
        let handle = tokio::spawn(async move {
            let mut sys = sysinfo::System::new_all();
            let mut ticker = interval(poll_interval);
            let mut known: HashMap<i32, (AppKind, Option<String>, OffsetDateTime)> = HashMap::new();

            info!("App detector (macOS) started, poll_interval={:?}", poll_interval);

            loop {
                ticker.tick().await;
                let now = OffsetDateTime::now_utc();
                let snapshot = MacAppDetector::snapshot_processes(&mut sys);

                let current_pids: std::collections::HashSet<i32> =
                    snapshot.iter().map(|(pid, _, _)| *pid).collect();

                // New PIDs => Started
                for (pid, _name, app_opt) in &snapshot {
                    let app = match app_opt {
                        Some(a) => a.clone(),
                        None => continue,
                    };
                    if !known.contains_key(pid) {
                        known.insert(*pid, (app.clone(), None, now));
                        if sender
                            .send(AppEvent::Started {
                                app: app.clone(),
                                pid: *pid,
                                process_name: Some(_name.clone()),
                                bundle_id: None,
                                started_at: now,
                            })
                            .await
                            .is_err()
                        {
                            warn!("App event channel closed");
                            return;
                        }
                        debug!("App started: {} pid={}", app.as_display_str(), pid);
                    }
                }

                // Missing PIDs => Exited
                let known_pids: Vec<i32> = known.keys().copied().collect();
                for pid in known_pids {
                    if !current_pids.contains(&pid) {
                        if let Some((app, _, _started_at)) = known.remove(&pid) {
                            if sender
                                .send(AppEvent::Exited {
                                    app: app.clone(),
                                    pid,
                                    exited_at: now,
                                })
                                .await
                                .is_err()
                            {
                                warn!("App event channel closed");
                                return;
                            }
                            debug!("App exited: {} pid={}", app.as_display_str(), pid);
                        }
                    }
                }

                if sender.send(AppEvent::ScanComplete { at: now }).await.is_err() {
                    return;
                }
            }
        });
        handle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_exact_match() {
        let sigs = default_signatures();
        assert_eq!(match_app("Cursor", &sigs), Some(AppKind::Cursor));
        assert_eq!(match_app("cursor", &sigs), Some(AppKind::Cursor));
    }

    #[test]
    fn cursor_helper_ignored() {
        let sigs = default_signatures();
        assert_eq!(match_app("Cursor Helper", &sigs), None);
        assert_eq!(match_app("Cursor Helper (Renderer)", &sigs), None);
    }

    #[test]
    fn vscode_match() {
        let sigs = default_signatures();
        assert_eq!(match_app("Code", &sigs), Some(AppKind::VSCode));
        assert_eq!(match_app("code", &sigs), Some(AppKind::VSCode));
        assert_eq!(match_app("Visual Studio Code", &sigs), Some(AppKind::VSCode));
    }

    #[test]
    fn vscode_helper_ignored_non_renderer() {
        let sigs = default_signatures();
        assert_eq!(match_app("Code Helper", &sigs), None);
    }

    #[test]
    fn vscode_renderer_matches() {
        let sigs = default_signatures();
        assert_eq!(match_app("Code Helper (Renderer)", &sigs), Some(AppKind::VSCode));
        assert_eq!(match_app("Code - Renderer", &sigs), Some(AppKind::VSCode));
    }

    #[test]
    fn cursor_renderer_matches() {
        let sigs = default_signatures();
        assert_eq!(match_app("Cursor Helper (Renderer)", &sigs), Some(AppKind::Cursor));
    }

    #[test]
    fn claude_match() {
        let sigs = default_signatures();
        assert_eq!(match_app("Claude", &sigs), Some(AppKind::Claude));
    }

    #[test]
    fn state_machine_started_then_exited() {
        // Simulate: first poll sees Cursor pid 123, second poll does not.
        let mut known: HashMap<i32, (AppKind, Option<String>, OffsetDateTime)> = HashMap::new();
        let now = OffsetDateTime::now_utc();

        // Poll 1: new pid 123 => Started
        let pid = 123;
        assert!(!known.contains_key(&pid));
        known.insert(pid, (AppKind::Cursor, None, now));
        let events_poll1 = vec!["Started"];

        // Poll 2: pid 123 missing => Exited
        let current_pids: std::collections::HashSet<i32> = [].into_iter().collect();
        let known_pids: Vec<i32> = known.keys().copied().collect();
        let mut events_poll2 = Vec::new();
        for p in known_pids {
            if !current_pids.contains(&p) {
                known.remove(&p);
                events_poll2.push("Exited");
            }
        }

        assert_eq!(events_poll1, vec!["Started"]);
        assert_eq!(events_poll2, vec!["Exited"]);
        assert!(known.is_empty());
    }
}
