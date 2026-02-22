//! Local HTTP proxy for network telemetry and Phase 6 enforcement

use antidote_core::{
    payloads::NetPayload, Event, EventType, EnforcementConfig, Flag, Label, SafeModeConfig,
    Severity,
};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Helper: domain matches allowlist (exact or subdomain)
fn is_domain_allowed(domain: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|a| domain == a.as_str() || domain.ends_with(&format!(".{}", a.as_str())))
}

#[cfg(test)]
mod tests {
    use super::is_domain_allowed;

    #[test]
    fn test_domain_blocking_unknown_rejected() {
        let allowed = vec!["api.openai.com".to_string(), "github.com".to_string()];
        assert!(!is_domain_allowed("evil.com", &allowed));
        assert!(!is_domain_allowed("api.evil.com", &allowed));
        assert!(is_domain_allowed("api.openai.com", &allowed));
        assert!(is_domain_allowed("sub.api.openai.com", &allowed));
    }

    #[test]
    fn test_safe_mode_rejects_non_allowed_domain() {
        let allowed = vec!["api.anthropic.com".to_string()];
        assert!(!is_domain_allowed("other.com", &allowed));
        assert!(is_domain_allowed("api.anthropic.com", &allowed));
    }
}

/// HTTP proxy server with optional Phase 6 enforcement
pub struct ProxyServer {
    listen_addr: SocketAddr,
    event_tx: mpsc::UnboundedSender<Event>,
    /// Phase 6: known domains (from rules); used when block_unknown_domains
    known_domains: Vec<String>,
    enforcement: Arc<RwLock<EnforcementConfig>>,
    safe_mode: Arc<RwLock<SafeModeConfig>>,
    frozen: Arc<RwLock<bool>>,
    /// Channel to emit enforcement flags (proxy cannot persist; daemon subscribes and persists)
    flag_tx: Option<mpsc::UnboundedSender<Flag>>,
}

impl ProxyServer {
    pub fn new(listen_addr: SocketAddr, event_tx: mpsc::UnboundedSender<Event>) -> Self {
        Self {
            listen_addr,
            event_tx,
            known_domains: Vec::new(),
            enforcement: Arc::new(RwLock::new(EnforcementConfig::default())),
            safe_mode: Arc::new(RwLock::new(SafeModeConfig::default())),
            frozen: Arc::new(RwLock::new(false)),
            flag_tx: None,
        }
    }

    /// Phase 6: Builder with enforcement
    pub fn with_enforcement(
        self,
        known_domains: Vec<String>,
        enforcement: Arc<RwLock<EnforcementConfig>>,
        safe_mode: Arc<RwLock<SafeModeConfig>>,
        frozen: Arc<RwLock<bool>>,
        flag_tx: Option<mpsc::UnboundedSender<Flag>>,
    ) -> Self {
        Self {
            known_domains,
            enforcement,
            safe_mode,
            frozen,
            flag_tx,
            ..self
        }
    }

    /// Start the proxy server
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.listen_addr)
            .await
            .with_context(|| format!("Failed to bind proxy to {}", self.listen_addr))?;

        info!("Proxy server listening on {}", self.listen_addr);

        let event_tx = self.event_tx.clone();
        let known_domains = self.known_domains.clone();
        let enforcement = self.enforcement.clone();
        let safe_mode = self.safe_mode.clone();
        let frozen = self.frozen.clone();
        let flag_tx = self.flag_tx.clone();

        loop {
            match listener.accept().await {
                Ok((mut stream, addr)) => {
                    if *frozen.read().await {
                        debug!("Rejecting connection from {} (frozen)", addr);
                        let _ = stream.shutdown().await;
                        continue;
                    }
                    debug!("New proxy connection from {}", addr);
                    let event_tx = event_tx.clone();
                    let known_domains = known_domains.clone();
                    let enforcement = enforcement.clone();
                    let safe_mode = safe_mode.clone();
                    let flag_tx = flag_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(
                            stream,
                            addr,
                            event_tx,
                            known_domains,
                            enforcement,
                            safe_mode,
                            flag_tx,
                        )
                        .await
                        {
                            error!("Connection handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
    }

    async fn handle_connection(
        mut stream: TcpStream,
        _addr: SocketAddr,
        event_tx: mpsc::UnboundedSender<Event>,
        known_domains: Vec<String>,
        enforcement: Arc<RwLock<EnforcementConfig>>,
        safe_mode: Arc<RwLock<SafeModeConfig>>,
        flag_tx: Option<mpsc::UnboundedSender<Flag>>,
    ) -> Result<()> {
        let mut buffer = [0u8; 4096];
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            return Ok(());
        }

        let request_str = String::from_utf8_lossy(&buffer[..n.min(1024)]);
        let domain = if request_str.starts_with("CONNECT") {
            let parts: Vec<&str> = request_str.split_whitespace().collect();
            if parts.len() >= 2 {
                parts[1].split(':').next().unwrap_or("unknown").to_string()
            } else {
                "unknown".to_string()
            }
        } else if let Some(host_line) = request_str.lines().find(|l| l.to_lowercase().starts_with("host:")) {
            host_line
                .split(':')
                .nth(1)
                .map(|s| s.trim().split(':').next().unwrap_or("unknown").to_string())
                .unwrap_or_else(|| "unknown".to_string())
        } else {
            "unknown".to_string()
        };

        let enf = enforcement.read().await;
        let safe = safe_mode.read().await;

        // Phase 6: Safe mode - only allowed domains
        if safe.enabled {
            if !is_domain_allowed(&domain, &safe.allowed_domains) {
                warn!("Safe mode: blocking domain {}", domain);
                let _ = stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                let flag = Flag::new(
                    "enforcement".to_string(),
                    "SAFE_MODE_VIOLATION".to_string(),
                    Severity::High,
                    20,
                    Label::SafeModeViolation,
                    serde_json::json!({ "domain": domain }),
                    format!("Safe mode: domain {} not in allowed list", domain),
                );
                if let Some(ref tx) = flag_tx {
                    let _ = tx.send(flag);
                }
                return Ok(());
            }
        }

        // Phase 6: Enforcement - block unknown domains
        if enf.enabled && enf.block_unknown_domains {
            let known = is_domain_allowed(&domain, &known_domains);
            if !known {
                warn!("Enforcement: blocking unknown domain {}", domain);
                let _ = stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                let flag = Flag::new(
                    "enforcement".to_string(),
                    "BLOCKED_DOMAIN".to_string(),
                    Severity::Med,
                    12,
                    Label::EnforcementBlocked,
                    serde_json::json!({ "domain": domain }),
                    format!("Blocked unknown domain: {}", domain),
                );
                if let Some(ref tx) = flag_tx {
                    let _ = tx.send(flag);
                }
                return Ok(());
            }
        }

        // Emit telemetry event
        let payload = serde_json::to_value(NetPayload {
            domain: domain.clone(),
            bytes_in: 0,
            bytes_out: 0,
        })
        .unwrap_or_else(|_| serde_json::json!({}));

        let event = Event {
            id: Uuid::new_v4(),
            ts: OffsetDateTime::now_utc(),
            session_id: "pending".to_string(),
            event_type: EventType::NetHttp,
            payload,
            enforcement_action: false,
            attribution_reason: None,
            attribution_confidence: None,
            attribution_details_json: None,
        };

        let _ = event_tx.send(event);
        debug!("Emitted NetHttp event for domain: {}", domain);

        if request_str.starts_with("CONNECT") {
            let _ = stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
        }

        Ok(())
    }
}
