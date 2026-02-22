//! Step 6: Coalesce rapid file writes into single events with repeat_count.
//! Also applies ignore filter (node_modules, .git, etc.) before coalescing.
//!
//! Phase 3: Event-triggered debounce flush — no fixed ticker. Sleep until earliest
//! pending goes stale; each new event recalculates. Batch size threshold flushes early.

use crate::ignore_filters;
use antidote_core::{Event, EventType};
use std::collections::HashMap;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::mpsc;

/// Key for coalescing: (normalized_path, event_type). Session is "pending" at coalescer input.
#[derive(Hash, Eq, PartialEq, Clone)]
struct CoalesceKey {
    path: String,
    event_type: EventType,
}

/// Pending coalesced event state.
struct PendingEvent {
    first_ts: OffsetDateTime,
    last_ts: OffsetDateTime,
    repeat_count: u32,
    last_event: Event,
}

/// Coalesces file events within a time window.
pub struct FileEventCoalescer {
    window: Duration,
    pending: HashMap<CoalesceKey, PendingEvent>,
}

impl FileEventCoalescer {
    pub fn new(coalesce_window_ms: u64) -> Self {
        Self {
            window: Duration::from_millis(coalesce_window_ms),
            pending: HashMap::new(),
        }
    }

    /// Process an incoming event. Returns events to emit (0, 1, or more).
    pub fn process(&mut self, event: Event, now: OffsetDateTime) -> Vec<Event> {
        let path = event
            .payload
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !path.is_empty() && ignore_filters::should_ignore_path(path) {
            return vec![];
        }

        let is_coalesceable = matches!(
            event.event_type,
            EventType::FileWrite | EventType::FileCreate | EventType::FileDelete
        );
        if !is_coalesceable {
            return vec![event];
        }
        let path = path.to_string();
        if path.is_empty() {
            return vec![event];
        }

        // Emit sensitive paths immediately (no coalescing) so .env, .pem etc. are detected promptly
        if ignore_filters::is_sensitive_path(&path) {
            return vec![event];
        }

        let key = CoalesceKey {
            path: path.clone(),
            event_type: event.event_type,
        };

        let window_ms = self.window.as_millis() as i128;
        let mut to_emit = Vec::new();
        if let Some(pending) = self.pending.get_mut(&key) {
            let elapsed_ms = (now - pending.first_ts).whole_milliseconds();
            if elapsed_ms <= window_ms && elapsed_ms >= 0 {
                pending.last_ts = now;
                pending.repeat_count += 1;
                pending.last_event = event.clone();
                return vec![];
            }
            let p = self.pending.remove(&key).unwrap();
            let mut emitted = p.last_event;
            emitted.payload["repeat_count"] = serde_json::json!(p.repeat_count);
            let dur_ms = (p.last_ts - p.first_ts).whole_milliseconds().max(0) as u64;
            emitted.payload["coalesced_duration_ms"] = serde_json::json!(dur_ms);
            to_emit.push(emitted);
        }

        self.pending.insert(
            key,
            PendingEvent {
                first_ts: now,
                last_ts: now,
                repeat_count: 1,
                last_event: event,
            },
        );
        to_emit
    }

    /// Earliest time at which any pending event becomes stale. None if no pending.
    pub fn earliest_stale_time(&self) -> Option<OffsetDateTime> {
        self.pending
            .values()
            .map(|p| p.first_ts + time::Duration::milliseconds(self.window.as_millis() as i64))
            .min()
    }

    /// Number of pending coalesce keys.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Flush pending events that have exceeded the window. Call when deadline reached or batch full.
    pub fn flush_stale(&mut self, now: OffsetDateTime) -> Vec<Event> {
        let mut out = Vec::new();
        let mut stale_keys = Vec::new();
        for (key, p) in &self.pending {
            let elapsed_ms = (now - p.first_ts).whole_milliseconds();
            if elapsed_ms >= self.window.as_millis() as i128 {
                stale_keys.push(key.clone());
            }
        }
        for key in stale_keys {
            if let Some(p) = self.pending.remove(&key) {
                let mut ev = p.last_event;
                ev.payload["repeat_count"] = serde_json::json!(p.repeat_count);
                let dur_ms = (p.last_ts - p.first_ts).whole_milliseconds().max(0) as u64;
                ev.payload["coalesced_duration_ms"] = serde_json::json!(dur_ms);
                out.push(ev);
            }
        }
        out
    }
}

/// Batch size threshold: flush immediately when this many pending keys (design: 50).
const FLUSH_BATCH_THRESHOLD: usize = 50;

/// Task that receives events, coalesces file events, and forwards to output channel.
/// Event-triggered flush: sleep until earliest pending goes stale; each new event
/// recalculates. No fixed ticker.
pub async fn coalescer_task(
    mut rx: mpsc::UnboundedReceiver<Event>,
    tx: mpsc::UnboundedSender<Event>,
    coalesce_window_ms: u64,
) {
    let mut coalescer = FileEventCoalescer::new(coalesce_window_ms);

    loop {
        let sleep_fut = async {
            if let Some(stale_at) = coalescer.earliest_stale_time() {
                let now = time::OffsetDateTime::now_utc();
                let wait_ms = (stale_at - now).whole_milliseconds().max(0) as u64;
                tokio::time::sleep(Duration::from_millis(wait_ms)).await;
            } else {
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(event) => {
                        let now = time::OffsetDateTime::now_utc();
                        for emitted in coalescer.process(event, now) {
                            if tx.send(emitted).is_err() {
                                break;
                            }
                        }
                        // Batch threshold: flush early if too many pending
                        if coalescer.pending_len() >= FLUSH_BATCH_THRESHOLD {
                            for ev in coalescer.flush_stale(now) {
                                if tx.send(ev).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    None => break,
                }
            }
            _ = sleep_fut => {
                let now = time::OffsetDateTime::now_utc();
                for ev in coalescer.flush_stale(now) {
                    if tx.send(ev).is_err() {
                        break;
                    }
                }
            }
        }
    }
    let now = time::OffsetDateTime::now_utc();
    for ev in coalescer.flush_stale(now) {
        let _ = tx.send(ev);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesce_rapid_writes() {
        let mut c = FileEventCoalescer::new(800);
        let now = OffsetDateTime::now_utc();
        let path = "/tmp/foo.rs";

        let mut events = Vec::new();
        for _ in 0..10 {
            let ev = Event {
                id: uuid::Uuid::new_v4(),
                ts: now,
                session_id: "pending".to_string(),
                event_type: EventType::FileWrite,
                payload: serde_json::json!({ "path": path }),
                enforcement_action: false,
                attribution_reason: None,
                attribution_confidence: None,
                attribution_details_json: None,
            };
            events.extend(c.process(ev, now));
        }
        assert_eq!(events.len(), 0);

        let flushed = c.flush_stale(now + time::Duration::milliseconds(900));
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].payload.get("repeat_count").and_then(|v| v.as_u64()), Some(10));
        assert!(flushed[0].payload.get("coalesced_duration_ms").is_some());
    }
}
