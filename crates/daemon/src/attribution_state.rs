//! Step 7: Attribution stabilization state - heat scores, PID cache, stabilization.

use antidote_core::AttributionDebugProvider;
use serde::Serialize;
use std::collections::HashMap;
use time::OffsetDateTime;
use tokio::sync::RwLock;

/// Per-session heat: rolling activity for tie-breaking.
#[derive(Debug, Clone, Serialize)]
pub struct SessionHeat {
    pub event_count_last_30s: u32,
    pub file_events_last_30s: u32,
    pub network_events_last_30s: u32,
    pub last_event_ts: OffsetDateTime,
}

impl Default for SessionHeat {
    fn default() -> Self {
        Self {
            event_count_last_30s: 0,
            file_events_last_30s: 0,
            network_events_last_30s: 0,
            last_event_ts: OffsetDateTime::UNIX_EPOCH,
        }
    }
}

impl SessionHeat {
    /// Compute heat score for tie-breaking.
    /// heat = (file_events * 2) + (network_events * 1) + recency_bonus
    pub fn score(&self, now: OffsetDateTime) -> u32 {
        let base = (self.file_events_last_30s * 2) + (self.network_events_last_30s);
        let recency_bonus = {
            let elapsed_secs = (now - self.last_event_ts).whole_seconds();
            if elapsed_secs < 5 {
                5
            } else if elapsed_secs < 15 {
                2
            } else {
                0
            }
        };
        base + recency_bonus
    }
}

/// Entry in PID cache with TTL.
#[derive(Debug, Clone)]
struct PidCacheEntry {
    session_id: String,
    last_seen: OffsetDateTime,
}

/// Shared attribution state: heat, PID cache, stabilization.
pub struct AttributionState {
    /// session_id -> heat (updated on each attributed event)
    heat: RwLock<HashMap<String, SessionHeat>>,
    /// pid -> (session_id, last_seen) for TTL eviction
    pid_cache: RwLock<HashMap<i32, PidCacheEntry>>,
    /// How long before PID cache entry expires (seconds)
    pid_cache_ttl_secs: i64,
    /// Current candidate foreground (not yet stabilized)
    candidate_foreground: RwLock<Option<(String, Option<i32>, OffsetDateTime)>>,
    /// Last committed foreground (app_name, pid)
    last_committed: RwLock<Option<(String, Option<i32>)>>,
    /// Config: stabilization window in ms
    stabilization_ms: u64,
}

impl AttributionState {
    pub fn new(stabilization_ms: u64, pid_cache_ttl_minutes: u64) -> Self {
        Self {
            heat: RwLock::new(HashMap::new()),
            pid_cache: RwLock::new(HashMap::new()),
            pid_cache_ttl_secs: pid_cache_ttl_minutes as i64 * 60,
            candidate_foreground: RwLock::new(None),
            last_committed: RwLock::new(None),
            stabilization_ms,
        }
    }

    /// Record a candidate foreground change. Returns true if committed (stabilized).
    pub async fn record_foreground_candidate(
        &self,
        app_name: String,
        pid: Option<i32>,
        now: OffsetDateTime,
    ) -> bool {
        let key = (app_name.clone(), pid);
        let mut candidate = self.candidate_foreground.write().await;
        let mut last = self.last_committed.write().await;

        if last.as_ref() == Some(&key) {
            return true;
        }

        if candidate.as_ref().map(|(a, p, _)| (a.as_str(), *p)) != Some((app_name.as_str(), pid)) {
            *candidate = Some((app_name, pid, now));
        }

        let (_, _, since) = candidate.as_ref().unwrap();
        let elapsed_ms = (now - *since).whole_milliseconds();
        if elapsed_ms >= self.stabilization_ms as i128 {
            *last = candidate.as_ref().map(|(a, p, _)| (a.clone(), *p));
            *candidate = None;
            return true;
        }
        false
    }

    /// Get last committed foreground (for stabilization: keep previous during window).
    #[allow(dead_code)] // used in tests
    pub async fn get_last_committed(&self) -> Option<(String, Option<i32>)> {
        self.last_committed.read().await.clone()
    }

    /// Update heat for a session after attribution.
    pub async fn record_attribution(
        &self,
        session_id: &str,
        is_file_event: bool,
        is_network_event: bool,
        now: OffsetDateTime,
    ) {
        let cutoff = now - time::Duration::seconds(30);
        let mut heat_map = self.heat.write().await;
        let entry = heat_map.entry(session_id.to_string()).or_default();

        // Decay: reset counts if last_event is old (simple approach: we overwrite)
        if entry.last_event_ts < cutoff {
            entry.event_count_last_30s = 0;
            entry.file_events_last_30s = 0;
            entry.network_events_last_30s = 0;
        }

        entry.event_count_last_30s = entry.event_count_last_30s.saturating_add(1);
        if is_file_event {
            entry.file_events_last_30s = entry.file_events_last_30s.saturating_add(1);
        }
        if is_network_event {
            entry.network_events_last_30s = entry.network_events_last_30s.saturating_add(1);
        }
        entry.last_event_ts = now;
    }

    /// Get heat score for a session (0 if unknown).
    #[allow(dead_code)] // used in tests
    pub async fn get_heat_score(&self, session_id: &str, now: OffsetDateTime) -> u32 {
        let heat_map = self.heat.read().await;
        heat_map
            .get(session_id)
            .map(|h| h.score(now))
            .unwrap_or(0)
    }

    /// Get all heat scores for tie-breaking.
    pub async fn get_all_heat_scores(&self, now: OffsetDateTime) -> HashMap<String, u32> {
        let heat_map = self.heat.read().await;
        heat_map
            .iter()
            .map(|(sid, h)| (sid.clone(), h.score(now)))
            .collect()
    }

    /// Insert PID -> session mapping (from audit/cmd attribution).
    pub async fn insert_pid_session(&self, pid: i32, session_id: String, now: OffsetDateTime) {
        let mut cache = self.pid_cache.write().await;
        cache.insert(
            pid,
            PidCacheEntry {
                session_id,
                last_seen: now,
            },
        );
    }

    /// Lookup session by PID. Evicts stale entries.
    #[allow(dead_code)] // used in tests
    pub async fn get_session_for_pid(&self, pid: i32, now: OffsetDateTime) -> Option<String> {
        let mut cache = self.pid_cache.write().await;
        let entry = cache.get(&pid)?;
        let elapsed = (now - entry.last_seen).whole_seconds();
        if elapsed > self.pid_cache_ttl_secs {
            cache.remove(&pid);
            return None;
        }
        Some(entry.session_id.clone())
    }

    /// Remove PID when session ends.
    #[allow(dead_code)] // used in tests
    pub async fn remove_pid(&self, pid: i32) {
        self.pid_cache.write().await.remove(&pid);
    }

    /// Remove all PIDs mapping to a session (when session ends).
    pub async fn remove_session_pids(&self, session_id: &str) {
        let mut cache = self.pid_cache.write().await;
        cache.retain(|_, e| e.session_id != session_id);
    }

    /// Update last_seen for PID (on attributed event).
    #[allow(dead_code)] // used in tests
    pub async fn touch_pid(&self, pid: i32, now: OffsetDateTime) {
        if let Some(entry) = self.pid_cache.write().await.get_mut(&pid) {
            entry.last_seen = now;
        }
    }

    /// Evict stale PID entries. Call periodically.
    pub async fn evict_stale_pids(&self, now: OffsetDateTime) {
        let mut cache = self.pid_cache.write().await;
        cache.retain(|_, e| (now - e.last_seen).whole_seconds() <= self.pid_cache_ttl_secs);
    }

    /// Clear heat for ended session.
    #[allow(dead_code)] // used in tests
    pub async fn remove_session_heat(&self, session_id: &str) {
        self.heat.write().await.remove(session_id);
    }

    /// Snapshot for debug endpoint.
    pub async fn debug_snapshot(&self, now: OffsetDateTime) -> AttributionStateSnapshot {
        let heat_map = self.heat.read().await;
        let heat_scores: HashMap<String, u32> = heat_map
            .iter()
            .map(|(k, v)| (k.clone(), v.score(now)))
            .collect();
        let heat_details: HashMap<String, SessionHeat> = heat_map
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let pid_cache = self.pid_cache.read().await;
        let pid_to_session: HashMap<i32, String> = pid_cache
            .iter()
            .filter(|(_, e)| (now - e.last_seen).whole_seconds() <= self.pid_cache_ttl_secs)
            .map(|(k, v)| (*k, v.session_id.clone()))
            .collect();

        let candidate = self.candidate_foreground.read().await.clone();
        let last_committed = self.last_committed.read().await.clone();

        AttributionStateSnapshot {
            heat_scores,
            heat_details,
            pid_to_session,
            candidate_foreground: candidate.map(|(a, p, t)| CandidateForeground {
                app: a,
                pid: p,
                since: t.to_string(),
            }),
            last_committed,
            stabilization_ms: self.stabilization_ms,
            pid_cache_ttl_secs: self.pid_cache_ttl_secs,
        }
    }
}

impl AttributionDebugProvider for AttributionState {
    fn get_snapshot(
        self: std::sync::Arc<Self>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = serde_json::Value> + Send>> {
        Box::pin(async move {
            let now = OffsetDateTime::now_utc();
            let snap = self.debug_snapshot(now).await;
            serde_json::to_value(snap).unwrap_or_else(|_| serde_json::json!({}))
        })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AttributionStateSnapshot {
    pub heat_scores: HashMap<String, u32>,
    pub heat_details: HashMap<String, SessionHeat>,
    pub pid_to_session: HashMap<i32, String>,
    pub candidate_foreground: Option<CandidateForeground>,
    pub last_committed: Option<(String, Option<i32>)>,
    pub stabilization_ms: u64,
    pub pid_cache_ttl_secs: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CandidateForeground {
    pub app: String,
    pub pid: Option<i32>,
    pub since: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_foreground_stabilization_quick_change_does_not_commit() {
        let state = AttributionState::new(100, 10);
        let t0 = OffsetDateTime::now_utc();
        state.record_foreground_candidate("AppA".to_string(), Some(1), t0).await;
        let t1 = t0 + time::Duration::milliseconds(150);
        assert!(state.record_foreground_candidate("AppA".to_string(), Some(1), t1).await);
        let t2 = t1 + time::Duration::milliseconds(10);
        state.record_foreground_candidate("AppB".to_string(), Some(2), t2).await;
        let t3 = t2 + time::Duration::milliseconds(10);
        state.record_foreground_candidate("AppA".to_string(), Some(1), t3).await;
        let committed = state.get_last_committed().await;
        assert_eq!(committed, Some(("AppA".to_string(), Some(1))));
    }

    #[tokio::test]
    async fn test_foreground_stabilization_sustained_change_commits() {
        let state = AttributionState::new(50, 10);
        let t0 = OffsetDateTime::now_utc();
        state.record_foreground_candidate("AppA".to_string(), Some(1), t0).await;
        let t1 = t0 + time::Duration::milliseconds(60);
        assert!(state.record_foreground_candidate("AppA".to_string(), Some(1), t1).await);
        let t2 = t1 + time::Duration::milliseconds(60);
        assert!(state.record_foreground_candidate("AppB".to_string(), Some(2), t2).await);
        let committed = state.get_last_committed().await;
        assert_eq!(committed, Some(("AppB".to_string(), Some(2))));
    }

    #[tokio::test]
    async fn test_heat_scoring_file_events_increase_heat() {
        let state = AttributionState::new(1000, 10);
        let now = OffsetDateTime::now_utc();
        state.record_attribution("s1", true, false, now).await;
        state.record_attribution("s1", true, false, now).await;
        let score = state.get_heat_score("s1", now).await;
        assert!(score >= 4 + 5);
    }

    #[tokio::test]
    async fn test_heat_recency_bonus() {
        let state = AttributionState::new(1000, 10);
        let now = OffsetDateTime::now_utc();
        state.record_attribution("s1", true, false, now).await;
        let score_5s = state.get_heat_score("s1", now + time::Duration::seconds(2)).await;
        let score_20s = state.get_heat_score("s1", now + time::Duration::seconds(20)).await;
        assert!(score_5s > score_20s);
    }

    #[tokio::test]
    async fn test_pid_cache_insert_and_lookup() {
        let state = AttributionState::new(1000, 10);
        let now = OffsetDateTime::now_utc();
        state.insert_pid_session(12345, "session-a".to_string(), now).await;
        let sid = state.get_session_for_pid(12345, now).await;
        assert_eq!(sid, Some("session-a".to_string()));
    }

    #[tokio::test]
    async fn test_pid_cache_remove_session() {
        let state = AttributionState::new(1000, 10);
        let now = OffsetDateTime::now_utc();
        state.insert_pid_session(1, "s1".to_string(), now).await;
        state.insert_pid_session(2, "s1".to_string(), now).await;
        state.insert_pid_session(3, "s2".to_string(), now).await;
        state.remove_session_pids("s1").await;
        assert!(state.get_session_for_pid(1, now).await.is_none());
        assert!(state.get_session_for_pid(2, now).await.is_none());
        assert_eq!(state.get_session_for_pid(3, now).await, Some("s2".to_string()));
    }
}
