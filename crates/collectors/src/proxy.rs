//! Local HTTP proxy for network telemetry

use antidote_core::{payloads::NetPayload, Event, EventType};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use uuid::Uuid;

/// HTTP proxy server
pub struct ProxyServer {
    listen_addr: SocketAddr,
    event_tx: mpsc::UnboundedSender<Event>,
}

impl ProxyServer {
    pub fn new(listen_addr: SocketAddr, event_tx: mpsc::UnboundedSender<Event>) -> Self {
        Self {
            listen_addr,
            event_tx,
        }
    }

    /// Start the proxy server
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.listen_addr)
            .await
            .with_context(|| format!("Failed to bind proxy to {}", self.listen_addr))?;

        info!("Proxy server listening on {}", self.listen_addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("New proxy connection from {}", addr);
                    let event_tx = self.event_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, addr, event_tx).await {
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
    ) -> Result<()> {
        // Read first line to determine if it's HTTP or CONNECT
        let mut buffer = [0u8; 4096];
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            return Ok(());
        }

        let request_str = String::from_utf8_lossy(&buffer[..n.min(1024)]);
        let domain = if request_str.starts_with("CONNECT") {
            // Extract domain from CONNECT request: CONNECT host:port HTTP/1.1
            let parts: Vec<&str> = request_str.split_whitespace().collect();
            if parts.len() >= 2 {
                parts[1].split(':').next().unwrap_or("unknown").to_string()
            } else {
                "unknown".to_string()
            }
        } else if let Some(host_line) = request_str.lines().find(|l| l.to_lowercase().starts_with("host:")) {
            // Extract domain from Host header
            host_line
                .split(':')
                .nth(1)
                .map(|s| s.trim().split(':').next().unwrap_or("unknown").to_string())
                .unwrap_or_else(|| "unknown".to_string())
        } else {
            "unknown".to_string()
        };

        // Emit event (simplified - in production would count bytes)
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
        };

        let _ = event_tx.send(event);
        debug!("Emitted NetHttp event for domain: {}", domain);

        // For CONNECT, respond with 200 Connection Established
        if request_str.starts_with("CONNECT") {
            let _ = stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
        }

        Ok(())
    }
}
