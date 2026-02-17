//! Phase 5: Behavioral baseline engine, anomaly detection, risk memory, drift index.
//! All deterministic and local; no AI/LLM.

mod baseline;
mod anomaly;
mod risk_memory;
mod drift;

pub use baseline::{AppBaseline, BaselineStore};
pub use anomaly::{detect_anomalies, AnomalyConfig};
pub use risk_memory::{check_escalation, RiskHistoryEntry};
pub use drift::{compute_drift_index, build_baseline_comparison_summary, DriftBucket};

use antidote_core::Counts;
use time::OffsetDateTime;

/// Default EMA alpha (0.2 = slow adaptation)
pub const DEFAULT_EMA_ALPHA: f64 = 0.2;

/// Epsilon below which we treat variance as zero (no anomaly)
pub const VARIANCE_EPSILON: f64 = 0.01;

/// Minimum session count before we run anomaly detection (conservative)
pub const MIN_SESSIONS_FOR_ANOMALY: u64 = 5;

/// Z-score thresholds: trigger anomaly if current > avg + k * std_dev
pub const Z_FILES_WRITTEN: f64 = 3.0;
pub const Z_BYTES_OUT: f64 = 3.0;
pub const Z_UNKNOWN_DOMAINS: f64 = 2.0;
pub const Z_CMDS: f64 = 3.0;

/// Escalation: same HIGH severity rule >= this many times in 7 days
pub const ESCALATION_COUNT_THRESHOLD: u32 = 3;
pub const ESCALATION_DAYS: i64 = 7;

/// Update baseline with EMA when a session ends. Returns new baseline.
pub fn update_baseline_ema(
    current: Option<&AppBaseline>,
    app: &str,
    counts: &Counts,
    alpha: f64,
    now: OffsetDateTime,
) -> AppBaseline {
    let session_count = current.map(|b| b.session_count).unwrap_or(0) + 1;

    let (avg_fw, var_fw) = ema_mean_var(
        current.map(|b| (b.avg_files_written, b.var_files_written)),
        counts.files_written as f64,
        alpha,
    );
    let (avg_fd, _) = ema_mean_var(
        current.map(|b| (b.avg_files_deleted, 0.0)),
        counts.files_deleted as f64,
        alpha,
    );
    let (avg_bo, var_bo) = ema_mean_var(
        current.map(|b| (b.avg_bytes_out, b.var_bytes_out)),
        counts.bytes_out as f64,
        alpha,
    );
    let (avg_ud, var_ud) = ema_mean_var(
        current.map(|b| (b.avg_unknown_domains, b.var_unknown_domains)),
        counts.domains as f64,
        alpha,
    );
    let (avg_cmds, var_cmds) = ema_mean_var(
        current.map(|b| (b.avg_cmds, b.var_cmds)),
        counts.cmds as f64,
        alpha,
    );

    AppBaseline {
        app: app.to_string(),
        session_count,
        avg_files_written: avg_fw,
        avg_files_deleted: avg_fd,
        avg_bytes_out: avg_bo,
        avg_unknown_domains: avg_ud,
        avg_cmds,
        var_files_written: var_fw,
        var_bytes_out: var_bo,
        var_unknown_domains: var_ud,
        var_cmds,
        last_updated: now,
    }
}

/// Exponential moving average for mean and variance (Welford-style one-pass compatible with EMA).
/// Returns (new_mean, new_variance). Variance uses EMA of squared deviation.
fn ema_mean_var(
    old: Option<(f64, f64)>,
    value: f64,
    alpha: f64,
) -> (f64, f64) {
    let (old_avg, old_var) = old.unwrap_or((value, 0.0));
    let new_avg = alpha * value + (1.0 - alpha) * old_avg;
    let sq_dev = (value - new_avg) * (value - new_avg);
    let new_var = alpha * sq_dev + (1.0 - alpha) * old_var;
    (new_avg, new_var.max(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use antidote_core::Counts;
    use crate::anomaly::{detect_anomalies, AnomalyConfig};
    use crate::risk_memory::check_escalation;
    use crate::drift::compute_drift_index;
    use antidote_core::{Evidence, RiskBucket, RiskSummary};
    use std::collections::HashSet;

    #[test]
    fn test_ema_baseline_update() {
        let counts = Counts {
            files_written: 100,
            files_deleted: 2,
            files_read: 0,
            cmds: 10,
            domains: 3,
            bytes_out: 50_000,
            events_total: 200,
        };
        let b = update_baseline_ema(None, "Cursor", &counts, 0.2, time::OffsetDateTime::now_utc());
        assert_eq!(b.session_count, 1);
        assert!((b.avg_files_written - 100.0).abs() < 0.01);
        assert!((b.avg_bytes_out - 50_000.0).abs() < 0.01);

        let counts2 = Counts {
            files_written: 50,
            ..counts
        };
        let b2 = update_baseline_ema(Some(&b), "Cursor", &counts2, 0.2, time::OffsetDateTime::now_utc());
        assert_eq!(b2.session_count, 2);
        assert!(b2.avg_files_written < 100.0 && b2.avg_files_written > 50.0);
    }

    #[test]
    fn test_drift_bucket() {
        assert_eq!(DriftBucket::from_index(0).as_str(), "Normal");
        assert_eq!(DriftBucket::from_index(30).as_str(), "Normal");
        assert_eq!(DriftBucket::from_index(31).as_str(), "Elevated");
        assert_eq!(DriftBucket::from_index(60).as_str(), "Elevated");
        assert_eq!(DriftBucket::from_index(61).as_str(), "Significant");
        assert_eq!(DriftBucket::from_index(100).as_str(), "Significant");
    }

    #[test]
    fn test_z_score_anomaly_detection() {
        let now = time::OffsetDateTime::now_utc();
        let baseline = AppBaseline {
            app: "Cursor".to_string(),
            session_count: 10,
            avg_files_written: 20.0,
            avg_files_deleted: 0.0,
            avg_bytes_out: 1000.0,
            avg_unknown_domains: 2.0,
            avg_cmds: 5.0,
            var_files_written: 25.0,
            var_bytes_out: 100_000.0,
            var_unknown_domains: 1.0,
            var_cmds: 4.0,
            last_updated: now,
        };
        let counts = Counts {
            files_written: 100,
            files_deleted: 0,
            files_read: 0,
            cmds: 20,
            domains: 10,
            bytes_out: 50_000,
            events_total: 200,
        };
        let evidence = Evidence {
            unknown_domains: vec!["x.com".to_string(); 10],
            sensitive_paths: vec![],
            dangerous_commands: vec![],
        };
        let config = AnomalyConfig::default();
        let flags = detect_anomalies("s1", "Cursor", &counts, &evidence, Some(&baseline), &config);
        assert!(!flags.is_empty());
        let rule_ids: Vec<_> = flags.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rule_ids.contains(&"ANOMALOUS_FILE_ACTIVITY"));
        assert!(rule_ids.contains(&"ANOMALOUS_EGRESS"));
        assert!(rule_ids.contains(&"ANOMALOUS_DOMAIN_PATTERN"));
        assert!(rule_ids.contains(&"ANOMALOUS_COMMAND_PATTERN"));
    }

    #[test]
    fn test_min_sessions_conservative() {
        let now = time::OffsetDateTime::now_utc();
        let baseline = AppBaseline {
            app: "Cursor".to_string(),
            session_count: 3,
            avg_files_written: 20.0,
            avg_files_deleted: 0.0,
            avg_bytes_out: 1000.0,
            avg_unknown_domains: 2.0,
            avg_cmds: 5.0,
            var_files_written: 100.0,
            var_bytes_out: 50_000.0,
            var_unknown_domains: 4.0,
            var_cmds: 9.0,
            last_updated: now,
        };
        let counts = Counts {
            files_written: 500,
            files_deleted: 0,
            files_read: 0,
            cmds: 100,
            domains: 20,
            bytes_out: 100_000,
            events_total: 200,
        };
        let evidence = Evidence {
            unknown_domains: vec!["x.com".to_string(); 10],
            sensitive_paths: vec![],
            dangerous_commands: vec![],
        };
        let config = AnomalyConfig::default();
        let flags = detect_anomalies("s1", "Cursor", &counts, &evidence, Some(&baseline), &config);
        assert!(flags.is_empty(), "anomaly should be conservative when session_count < 5");
    }

    #[test]
    fn test_zero_variance_no_anomaly() {
        let now = time::OffsetDateTime::now_utc();
        let baseline = AppBaseline {
            app: "Cursor".to_string(),
            session_count: 10,
            avg_files_written: 20.0,
            avg_files_deleted: 0.0,
            avg_bytes_out: 1000.0,
            avg_unknown_domains: 0.0,
            avg_cmds: 5.0,
            var_files_written: 0.0,
            var_bytes_out: 0.0,
            var_unknown_domains: 0.0,
            var_cmds: 0.0,
            last_updated: now,
        };
        let counts = Counts {
            files_written: 1000,
            files_deleted: 0,
            files_read: 0,
            cmds: 100,
            domains: 50,
            bytes_out: 1_000_000,
            events_total: 200,
        };
        let evidence = Evidence {
            unknown_domains: vec!["a.com".to_string(); 50],
            sensitive_paths: vec![],
            dangerous_commands: vec![],
        };
        let config = AnomalyConfig::default();
        let flags = detect_anomalies("s1", "Cursor", &counts, &evidence, Some(&baseline), &config);
        assert!(flags.is_empty(), "zero variance should skip anomaly detection");
    }

    #[test]
    fn test_escalation_after_repeated_flags() {
        let high_rule_counts = vec![
            ("SUSPICIOUS_EGRESS".to_string(), 2),
        ];
        assert!(check_escalation("s1", "Cursor", &high_rule_counts).is_none());

        let high_rule_counts_3 = vec![
            ("SUSPICIOUS_EGRESS".to_string(), 3),
        ];
        let flag = check_escalation("s1", "Cursor", &high_rule_counts_3);
        assert!(flag.is_some());
        let f = flag.unwrap();
        assert_eq!(f.rule_id, "ESCALATING_PATTERN");
        assert!(f.score <= 100);
    }

    #[test]
    fn test_drift_index_bounds() {
        let now = time::OffsetDateTime::now_utc();
        let summary = SessionSummary {
            session_id: "s1".to_string(),
            app: "Cursor".to_string(),
            root_pid: 1,
            start_ts: now,
            end_ts: None,
            last_event_ts: now,
            counts: Counts {
                files_written: 100,
                files_deleted: 0,
                files_read: 0,
                cmds: 10,
                domains: 5,
                bytes_out: 10_000,
                events_total: 200,
            },
            risk: RiskSummary {
                score: 50,
                bucket: RiskBucket::Medium,
            },
            labels: vec![],
            evidence: Evidence::default(),
            observed_roots: vec![],
            telemetry_confidence: antidote_core::TelemetryConfidence::Med,
            dropped_events: 0,
            participant_pids_count: 1,
            drift_index: None,
            baseline_comparison_summary: None,
        };
        let empty: HashSet<String> = HashSet::new();
        for _ in 0..20 {
            let idx = compute_drift_index(&summary, None, &empty, &empty, 0.0);
            assert!(idx <= 100, "drift index must be <= 100, got {}", idx);
        }
        let baseline = AppBaseline {
            app: "Cursor".to_string(),
            session_count: 10,
            avg_files_written: 20.0,
            avg_files_deleted: 0.0,
            avg_bytes_out: 1000.0,
            avg_unknown_domains: 2.0,
            avg_cmds: 5.0,
            var_files_written: 100.0,
            var_bytes_out: 50_000.0,
            var_unknown_domains: 4.0,
            var_cmds: 9.0,
            last_updated: now,
        };
        let idx = compute_drift_index(&summary, Some(&baseline), &empty, &empty, 0.0);
        assert!(idx <= 100, "drift index must be <= 100, got {}", idx);
    }

    #[test]
    fn test_baseline_persistence_reload() {
        use crate::BaselineStore;
        use std::collections::HashMap;
        struct HashMapStore(HashMap<String, AppBaseline>);
        impl BaselineStore for HashMapStore {
            fn get(&self, app: &str) -> Option<AppBaseline> {
                self.0.get(app).cloned()
            }
            fn set(&mut self, baseline: AppBaseline) {
                self.0.insert(baseline.app.clone(), baseline);
            }
            fn all(&self) -> Vec<AppBaseline> {
                self.0.values().cloned().collect()
            }
        }
        let now = time::OffsetDateTime::now_utc();
        let counts = Counts {
            files_written: 10,
            files_deleted: 0,
            files_read: 0,
            cmds: 2,
            domains: 1,
            bytes_out: 500,
            events_total: 50,
        };
        let baseline = update_baseline_ema(None, "Cursor", &counts, 0.2, now);
        let mut store = HashMapStore(HashMap::new());
        store.set(baseline.clone());
        let loaded = store.get("Cursor").expect("should load baseline");
        assert_eq!(loaded.app, baseline.app);
        assert_eq!(loaded.session_count, baseline.session_count);
        assert!((loaded.avg_files_written - baseline.avg_files_written).abs() < 0.01);
        let all = store.all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].app, "Cursor");
    }
}
