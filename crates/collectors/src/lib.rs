//! Event collectors for Antidote

mod fs_watcher;
mod proxy;
#[cfg(target_os = "macos")]
mod app_detector_macos;
#[cfg(target_os = "macos")]
mod nsworkspace_observer_macos;
#[cfg(target_os = "macos")]
mod audit_macos;
#[cfg(target_os = "macos")]
mod workspace_resolver_macos;
#[cfg(target_os = "macos")]
mod foreground_macos;

pub use fs_watcher::{FsWatcherManager, FsWatcherOptions, WatcherStatus};
pub use proxy::ProxyServer;
#[cfg(target_os = "macos")]
pub use app_detector_macos::{
    AppDetector, AppDetectorState, AppEvent, AppInstance, AppKind, MacAppDetector,
    DEFAULT_POLL_INTERVAL_MS,
};
#[cfg(target_os = "macos")]
pub use nsworkspace_observer_macos::{spawn_foreground_activate_observer, spawn_nsworkspace_observer};
#[cfg(target_os = "macos")]
pub use audit_macos::AuditCollector;
#[cfg(target_os = "macos")]
pub use workspace_resolver_macos::{
    spawn_storage_watcher, WorkspaceEvent, WorkspaceResolver,
    WorkspaceResolverConfig, WorkspaceResolverState, WorkspaceState,
};
#[cfg(target_os = "macos")]
pub use foreground_macos::{ForegroundApp, ForegroundPoller, app_kind_from_name};

use antidote_core::{payloads::ProcPayload, Event, EventType};
use std::collections::HashMap;
use std::time::Duration;
use sysinfo::System;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Process information tracked by the poller
#[derive(Debug, Clone)]
struct ProcessInfo {
    ppid: i32,
    name: String,
    exe: Option<String>,
    #[allow(dead_code)] // Reserved for age-based cleanup or diagnostics
    first_seen_ts: OffsetDateTime,
}

/// Process poller that monitors running processes
pub struct ProcessPoller {
    watch_names: Vec<String>,
    seen_pids: HashMap<i32, ProcessInfo>,
    event_tx: mpsc::UnboundedSender<Event>,
    poll_interval: Duration,
}

impl ProcessPoller {
    /// Create a new process poller
    pub fn new(
        watch_names: Vec<String>,
        event_tx: mpsc::UnboundedSender<Event>,
        poll_interval: Duration,
    ) -> Self {
        Self {
            watch_names,
            seen_pids: HashMap::new(),
            event_tx,
            poll_interval,
        }
    }

    /// Run the poller (blocking async task)
    pub async fn run(&mut self) {
        let mut sys = System::new_all();
        let mut ticker = interval(self.poll_interval);

        info!("Process poller started, watching: {:?}", self.watch_names);

        loop {
            ticker.tick().await;
            sys.refresh_all();

            // Check for new processes
            for (pid, process) in sys.processes() {
                let pid_val = pid.as_u32() as i32;
                let name = process.name().to_string_lossy().to_string();
                let ppid = process.parent().map(|p| p.as_u32() as i32).unwrap_or(0);
                let exe = process.exe().and_then(|p| p.to_str().map(|s| s.to_string()));

                // Check if we should watch this process
                if self.should_watch(&name, ppid) && Self::is_main_process(&name) {
                    if !self.seen_pids.contains_key(&pid_val) {
                        // New process - emit ProcStart
                        let info = ProcessInfo {
                            ppid,
                            name: name.clone(),
                            exe: exe.clone(),
                            first_seen_ts: OffsetDateTime::now_utc(),
                        };
                        self.seen_pids.insert(pid_val, info.clone());

                        let payload = serde_json::to_value(ProcPayload {
                            pid: pid_val,
                            ppid,
                            name,
                            exe,
                        })
                        .unwrap_or_else(|_| serde_json::json!({}));

                        // For ProcStart, we don't have a session_id yet - use "pending"
                        let event = Event {
                            id: Uuid::new_v4(),
                            ts: OffsetDateTime::now_utc(),
                            root_id: None,
                            event_type: EventType::ProcStart,
                            payload,
                            enforcement_action: false,
                            attribution_reason: None,
                            attribution_confidence: None,
                            attribution_details_json: None,
                        };

                        if self.event_tx.send(event).is_err() {
                            warn!("Event channel closed, stopping poller");
                            return;
                        }

                        debug!("Emitted ProcStart for pid={}, name={}", pid_val, info.name);
                    }
                }
            }

            // Check for exited processes
            let current_pids: Vec<i32> = sys
                .processes()
                .keys()
                .map(|pid| pid.as_u32() as i32)
                .collect();

            let exited_pids: Vec<i32> = self
                .seen_pids
                .keys()
                .filter(|pid| !current_pids.contains(pid))
                .copied()
                .collect();

            for pid in exited_pids {
                if let Some(info) = self.seen_pids.remove(&pid) {
                    let payload = serde_json::to_value(ProcPayload {
                        pid,
                        ppid: info.ppid,
                        name: info.name.clone(),
                        exe: info.exe,
                    })
                    .unwrap_or_else(|_| serde_json::json!({}));

                    let event = Event {
                        id: uuid::Uuid::new_v4(),
                        ts: OffsetDateTime::now_utc(),
                        root_id: None,
                        event_type: EventType::ProcExit,
                        payload,
                        enforcement_action: false,
                        attribution_reason: None,
                        attribution_confidence: None,
                        attribution_details_json: None,
                    };

                    if self.event_tx.send(event).is_err() {
                        warn!("Event channel closed, stopping poller");
                        return;
                    }

                    debug!("Emitted ProcExit for pid={}, name={}", pid, info.name);
                }
            }
        }
    }

    /// Processes that get sessions: renderers for Cursor/VSCode (one per window), main for Claude.
    /// We skip Cursor/Code main process to avoid duplicate sessions (main + N renderers).
    fn is_main_process(name: &str) -> bool {
        let n = name.to_lowercase();
        // Cursor/VSCode: only renderers (one session per window)
        n == "cursor helper (renderer)"
            || n == "code helper (renderer)"
            || n == "code - renderer"
            // Claude: main process (no multi-window renderer model)
            || n == "claude"
    }

    /// Determine if we should watch a process
    fn should_watch(&self, name: &str, ppid: i32) -> bool {
        // Direct match on watch list
        if self.watch_names.iter().any(|w| name.contains(w)) {
            return true;
        }

        // For node/python, check if parent is watched
        if name == "node" || name == "python" || name == "python3" {
            // Check if parent is in seen_pids (indicating it's a child of watched process)
            return self.seen_pids.contains_key(&ppid);
        }

        false
    }
}
