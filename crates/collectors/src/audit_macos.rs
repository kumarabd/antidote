//! macOS audit log collector using OpenBSM/praudit
//! Phase 4: Process-level telemetry without kernel extensions

use antidote_core::{Event, EventType};
use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Process tree entry for attribution
#[derive(Debug, Clone)]
struct ProcessEntry {
    #[allow(dead_code)] // Key is the map key; kept for debugging/serialization
    pid: i32,
    ppid: i32,
    #[allow(dead_code)] // Reserved for evidence or display
    exe: Option<String>,
    session_id: Option<String>,
    start_ts: OffsetDateTime,
}

/// Process tree index for session attribution
#[derive(Debug, Clone)]
pub struct ProcessTree {
    /// Mapping from pid to process entry
    processes: HashMap<i32, ProcessEntry>,
    /// Watch process names (to filter events)
    watch_names: Vec<String>,
    /// Watched roots (to filter file events)
    watched_roots: Vec<String>,
}

impl ProcessTree {
    pub fn new(watch_names: Vec<String>) -> Self {
        Self {
            processes: HashMap::new(),
            watch_names,
            watched_roots: Vec::new(),
        }
    }

    pub fn update_watched_roots(&mut self, roots: Vec<String>) {
        self.watched_roots = roots;
    }

    /// Register a process execution
    pub fn register_exec(&mut self, pid: i32, ppid: i32, exe: Option<String>, session_id: Option<String>) {
        self.processes.insert(pid, ProcessEntry {
            pid,
            ppid,
            exe: exe.clone(),
            session_id,
            start_ts: OffsetDateTime::now_utc(),
        });
        // Clean up old entries (older than 1 hour)
        let cutoff = OffsetDateTime::now_utc() - time::Duration::hours(1);
        self.processes.retain(|_, entry| entry.start_ts >= cutoff);
    }

    /// Find session ID for a pid (walk up process tree if needed)
    pub fn find_session_for_pid(&self, pid: i32) -> Option<String> {
        let mut current_pid = pid;
        let mut visited = std::collections::HashSet::new();
        
        for _ in 0..100 { // Max depth
            if visited.contains(&current_pid) {
                break; // Cycle detected
            }
            visited.insert(current_pid);

            if let Some(entry) = self.processes.get(&current_pid) {
                if let Some(ref session_id) = entry.session_id {
                    return Some(session_id.clone());
                }
                // Walk up to parent
                current_pid = entry.ppid;
            } else {
                break;
            }
        }
        None
    }

    /// Check if a process name should be watched
    pub fn should_watch(&self, name: &str) -> bool {
        self.watch_names.iter().any(|w| name.contains(w))
    }

    /// Check if a path is under a watched root
    pub fn is_watched_path(&self, path: &str) -> bool {
        self.watched_roots.iter().any(|root| path.starts_with(root))
    }
}

/// Audit collector that reads from praudit
pub struct AuditCollector {
    event_tx: tokio::sync::mpsc::UnboundedSender<Event>,
    process_tree: Arc<RwLock<ProcessTree>>,
    enabled: bool,
}

impl AuditCollector {
    /// Create a new audit collector
    pub fn new(
        event_tx: tokio::sync::mpsc::UnboundedSender<Event>,
        watch_names: Vec<String>,
    ) -> Self {
        Self {
            event_tx,
            process_tree: Arc::new(RwLock::new(ProcessTree::new(watch_names))),
            enabled: false,
        }
    }

    /// Check if audit is available (praudit exists and we have permissions)
    pub fn check_availability() -> bool {
        // Check if praudit exists
        let output = Command::new("which")
            .arg("praudit")
            .output();
        
        if output.is_err() {
            return false;
        }

        // Try to read audit pipe (requires root or audit access)
        // For now, we'll assume it's available if praudit exists
        // In practice, this should check /dev/auditpipe access
        true
    }

    /// Update watched roots
    pub async fn update_watched_roots(&self, roots: Vec<String>) {
        let mut tree = self.process_tree.write().await;
        tree.update_watched_roots(roots);
    }

    /// Link a pid to a session (called when session is created)
    pub async fn link_pid_to_session(&self, pid: i32, session_id: String) {
        // Find the process entry and update it
        let mut tree = self.process_tree.write().await;
        if let Some(entry) = tree.processes.get_mut(&pid) {
            entry.session_id = Some(session_id);
        }
    }

    /// Run the audit collector
    pub async fn run(&mut self) -> Result<()> {
        // Check availability
        if !Self::check_availability() {
            warn!("Audit collector not available (praudit not found or no permissions)");
            return Ok(());
        }

        info!("Starting audit collector (reading from audit pipe)");

        // Spawn praudit to read from audit pipe
        // Note: This requires root or audit access
        let mut child = TokioCommand::new("praudit")
            .arg("-l")  // Line format
            .arg("/dev/auditpipe")  // Read from audit pipe
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn praudit. Run with sudo for audit telemetry.")?;

        self.enabled = true;
        info!("Audit collector enabled");

        let stdout = child.stdout.take()
            .context("Failed to capture praudit stdout")?;
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();

        // Regex patterns for parsing audit records
        let exec_pattern = Regex::new(r#"execve\(.*?\)"#).unwrap();
        let file_open_pattern = Regex::new(r#"open\(.*?\)"#).unwrap();
        let connect_pattern = Regex::new(r#"connect\(.*?\)"#).unwrap();
        let pid_pattern = Regex::new(r#"pid\s+(\d+)"#).unwrap();
        let ppid_pattern = Regex::new(r#"ppid\s+(\d+)"#).unwrap();
        let path_pattern = Regex::new(r#"path\s+"([^"]+)""#).unwrap();
        let exe_pattern = Regex::new(r#"executable\s+"([^"]+)""#).unwrap();
        let addr_pattern = Regex::new(r#"addr\s+([^\s]+)"#).unwrap();

        while let Some(line) = lines.next_line().await? {
            if let Err(e) = self.process_audit_line(
                &line,
                &exec_pattern,
                &file_open_pattern,
                &connect_pattern,
                &pid_pattern,
                &ppid_pattern,
                &path_pattern,
                &exe_pattern,
                &addr_pattern,
            ).await {
                debug!("Failed to process audit line: {}: {}", e, line);
            }
        }

        // Child process exited
        let status = child.wait().await?;
        if !status.success() {
            warn!("praudit exited with status: {:?}", status);
        }

        Ok(())
    }

    async fn process_audit_line(
        &self,
        line: &str,
        exec_pattern: &Regex,
        file_open_pattern: &Regex,
        connect_pattern: &Regex,
        pid_pattern: &Regex,
        ppid_pattern: &Regex,
        path_pattern: &Regex,
        exe_pattern: &Regex,
        addr_pattern: &Regex,
    ) -> Result<()> {
        // Extract pid and ppid
        let pid: Option<i32> = pid_pattern.captures(line)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse().ok());
        let ppid: Option<i32> = ppid_pattern.captures(line)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse().ok());

        // Check if this is an execve event
        if exec_pattern.is_match(line) {
            let exe = exe_pattern.captures(line)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string());

            if let Some(pid_val) = pid {
                let ppid_val = ppid.unwrap_or(0);
                
                // Check if we should watch this process
                let tree = self.process_tree.read().await;
                let should_watch = exe.as_ref()
                    .map(|e| {
                        let name = std::path::Path::new(e)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("");
                        tree.should_watch(name)
                    })
                    .unwrap_or(false);
                let session_id = if should_watch {
                    tree.find_session_for_pid(ppid_val)
                } else {
                    None
                };
                drop(tree);

                if should_watch {
                    // Register in process tree
                    {
                        let mut tree = self.process_tree.write().await;
                        tree.register_exec(pid_val, ppid_val, exe.clone(), session_id);
                    }

                    // Emit CmdExec event
                    let event = Event::new(
                        EventType::CmdExec,
                        serde_json::json!({
                            "pid": pid_val,
                            "ppid": ppid_val,
                            "exe": exe,
                        }),
                    );
                    if self.event_tx.send(event).is_err() {
                        return Err(anyhow::anyhow!("Event channel closed"));
                    }
                }
            }
        }
        // Check if this is a file open event
        else if file_open_pattern.is_match(line) {
            if let Some(pid_val) = pid {
                let path = path_pattern.captures(line)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string());

                if let Some(path_val) = path {
                    let tree = self.process_tree.read().await;
                    let is_watched = tree.is_watched_path(&path_val);
                    let session_id = tree.find_session_for_pid(pid_val);

                    // Only emit if path is under watched root or process is watched
                    if is_watched || session_id.is_some() {
                        // Determine if this is a read or write
                        // For simplicity, we'll emit FileRead (audit doesn't distinguish well)
                        // In practice, you'd check the open flags
                        let event_type = if line.contains("O_WRONLY") || line.contains("O_RDWR") {
                            EventType::FileWrite
                        } else {
                            EventType::FileRead
                        };

                        let event = Event::new(
                            event_type,
                            serde_json::json!({
                                "pid": pid_val,
                                "ppid": ppid,
                                "path": path_val,
                            }),
                        );
                        if self.event_tx.send(event).is_err() {
                            return Err(anyhow::anyhow!("Event channel closed"));
                        }
                    }
                }
            }
        }
        // Check if this is a connect event
        else if connect_pattern.is_match(line) {
            if let Some(pid_val) = pid {
                let addr = addr_pattern.captures(line)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string());

                if let Some(addr_val) = addr {
                    let tree = self.process_tree.read().await;
                    let session_id = tree.find_session_for_pid(pid_val);

                    if session_id.is_some() {
                        // Parse address (could be IP:port or domain)
                        let (domain, port) = if addr_val.contains(':') {
                            let parts: Vec<&str> = addr_val.split(':').collect();
                            (parts[0].to_string(), parts.get(1).and_then(|p| p.parse::<u16>().ok()))
                        } else {
                            (addr_val, None)
                        };

                        let event = Event::new(
                            EventType::NetConnect,
                            serde_json::json!({
                                "pid": pid_val,
                                "ppid": ppid,
                                "domain": domain,
                                "port": port,
                            }),
                        );
                        if self.event_tx.send(event).is_err() {
                            return Err(anyhow::anyhow!("Event channel closed"));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if collector is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}
