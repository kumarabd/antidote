//! Statistical anomaly detection (z-score) on session end

use antidote_core::{Counts, Evidence, Flag, Label, Severity};
use serde_json::json;

use crate::{AppBaseline, VARIANCE_EPSILON, Z_BYTES_OUT, Z_CMDS, Z_FILES_WRITTEN, Z_UNKNOWN_DOMAINS, MIN_SESSIONS_FOR_ANOMALY};

#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    pub variance_epsilon: f64,
    pub z_files_written: f64,
    pub z_bytes_out: f64,
    pub z_unknown_domains: f64,
    pub z_cmds: f64,
    pub min_sessions: u64,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            variance_epsilon: VARIANCE_EPSILON,
            z_files_written: Z_FILES_WRITTEN,
            z_bytes_out: Z_BYTES_OUT,
            z_unknown_domains: Z_UNKNOWN_DOMAINS,
            z_cmds: Z_CMDS,
            min_sessions: MIN_SESSIONS_FOR_ANOMALY,
        }
    }
}

/// Detect anomalies vs baseline. Returns new flags. No panic on zero variance.
pub fn detect_anomalies(
    session_id: &str,
    _app: &str,
    counts: &Counts,
    evidence: &Evidence,
    baseline: Option<&AppBaseline>,
    config: &AnomalyConfig,
) -> Vec<Flag> {
    let mut flags = Vec::new();
    let Some(b) = baseline else { return flags };
    if b.session_count < config.min_sessions {
        return flags;
    }

    let _now = time::OffsetDateTime::now_utc();

    // files_written > avg + 3*std_dev
    let std_fw = b.std_dev_files_written();
    if std_fw >= config.variance_epsilon {
        let threshold = b.avg_files_written + config.z_files_written * std_fw;
        if counts.files_written as f64 > threshold {
            flags.push(Flag::new(
                session_id.to_string(),
                "ANOMALOUS_FILE_ACTIVITY".to_string(),
                Severity::Med,
                12,
                Label::BehavioralAnomaly,
                json!({
                    "files_written": counts.files_written,
                    "avg": b.avg_files_written,
                    "std_dev": std_fw,
                    "threshold": threshold
                }),
                format!(
                    "Anomalous file activity: {} writes (baseline avg {:.1})",
                    counts.files_written, b.avg_files_written
                ),
            ));
        }
    }

    // bytes_out > avg + 3*std_dev
    let std_bo = b.std_dev_bytes_out();
    if std_bo >= config.variance_epsilon {
        let threshold = b.avg_bytes_out + config.z_bytes_out * std_bo;
        if counts.bytes_out as f64 > threshold {
            flags.push(Flag::new(
                session_id.to_string(),
                "ANOMALOUS_EGRESS".to_string(),
                Severity::High,
                20,
                Label::BehavioralAnomaly,
                json!({
                    "bytes_out": counts.bytes_out,
                    "avg": b.avg_bytes_out,
                    "std_dev": std_bo,
                    "threshold": threshold
                }),
                format!(
                    "Anomalous egress: {} bytes (baseline avg {:.0})",
                    counts.bytes_out, b.avg_bytes_out
                ),
            ));
        }
    }

    // unknown_domains (evidence.unknown_domains.len()) > avg + 2*std_dev
    let unknown_count = evidence.unknown_domains.len() as f64;
    let std_ud = b.std_dev_unknown_domains();
    if std_ud >= config.variance_epsilon {
        let threshold = b.avg_unknown_domains + config.z_unknown_domains * std_ud;
        if unknown_count > threshold {
            flags.push(Flag::new(
                session_id.to_string(),
                "ANOMALOUS_DOMAIN_PATTERN".to_string(),
                Severity::High,
                20,
                Label::BehavioralAnomaly,
                json!({
                    "unknown_domains": unknown_count,
                    "avg": b.avg_unknown_domains,
                    "std_dev": std_ud,
                    "threshold": threshold
                }),
                format!(
                    "Anomalous domain pattern: {} unknown domains (baseline avg {:.1})",
                    evidence.unknown_domains.len(),
                    b.avg_unknown_domains
                ),
            ));
        }
    }

    // cmds > avg + 3*std_dev
    let std_cmds = b.std_dev_cmds();
    if std_cmds >= config.variance_epsilon {
        let threshold = b.avg_cmds + config.z_cmds * std_cmds;
        if counts.cmds as f64 > threshold {
            flags.push(Flag::new(
                session_id.to_string(),
                "ANOMALOUS_COMMAND_PATTERN".to_string(),
                Severity::Med,
                12,
                Label::BehavioralAnomaly,
                json!({
                    "cmds": counts.cmds,
                    "avg": b.avg_cmds,
                    "std_dev": std_cmds,
                    "threshold": threshold
                }),
                format!(
                    "Anomalous command pattern: {} commands (baseline avg {:.1})",
                    counts.cmds, b.avg_cmds
                ),
            ));
        }
    }

    flags
}
