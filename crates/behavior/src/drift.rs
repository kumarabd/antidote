//! Drift index and baseline comparison summary

use antidote_core::SessionSummary;
use std::collections::HashSet;

use crate::{AppBaseline, VARIANCE_EPSILON};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftBucket {
    Normal,
    Elevated,
    Significant,
}

impl DriftBucket {
    pub fn from_index(index: u8) -> Self {
        match index {
            0..=30 => DriftBucket::Normal,
            31..=60 => DriftBucket::Elevated,
            _ => DriftBucket::Significant,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            DriftBucket::Normal => "Normal",
            DriftBucket::Elevated => "Elevated",
            DriftBucket::Significant => "Significant",
        }
    }
}

/// Compute weighted z-scores and other factors, normalize to 0..100.
/// Safe for zero variance (treat as 0 contribution).
pub fn compute_drift_index(
    summary: &SessionSummary,
    baseline: Option<&AppBaseline>,
    all_historical_domains: &HashSet<String>,
    all_historical_sensitive_paths: &HashSet<String>,
    avg_risk_score: f64,
) -> u8 {
    let mut raw: f64 = 0.0;

    if let Some(b) = baseline {
        let eps = VARIANCE_EPSILON;

        // Weighted z-scores (cap each at ~3 so one metric doesn't dominate)
        let z_fw = if b.var_files_written >= eps {
            let z = (summary.counts.files_written as f64 - b.avg_files_written)
                / b.std_dev_files_written();
            z.clamp(0.0, 3.0)
        } else {
            0.0
        };
        let z_bo = if b.var_bytes_out >= eps {
            let z = (summary.counts.bytes_out as f64 - b.avg_bytes_out) / b.std_dev_bytes_out();
            z.clamp(0.0, 3.0)
        } else {
            0.0
        };
        let z_ud = if b.var_unknown_domains >= eps {
            let n = summary.evidence.unknown_domains.len() as f64;
            let z = (n - b.avg_unknown_domains) / b.std_dev_unknown_domains();
            z.clamp(0.0, 3.0)
        } else {
            0.0
        };
        let z_cmds = if b.var_cmds >= eps {
            let z = (summary.counts.cmds as f64 - b.avg_cmds) / b.std_dev_cmds();
            z.clamp(0.0, 3.0)
        } else {
            0.0
        };
        raw += (z_fw + z_bo + z_ud + z_cmds) * 5.0; // scale to ~0-60
    }

    // New domains not seen before
    let new_domains = summary
        .evidence
        .unknown_domains
        .iter()
        .filter(|d| !all_historical_domains.contains(*d))
        .count();
    raw += new_domains as f64 * 3.0;

    // New sensitive paths not seen before
    let new_paths = summary
        .evidence
        .sensitive_paths
        .iter()
        .filter(|p| !all_historical_sensitive_paths.contains(*p))
        .count();
    raw += new_paths as f64 * 3.0;

    // Difference from avg risk score (0-100 scale)
    let score_diff = (summary.risk.score as f64 - avg_risk_score).abs();
    raw += score_diff * 0.2;

    // Normalize to 0..100 (empirical cap)
    let index = (raw.min(100.0).max(0.0)).round() as u8;
    index.min(100)
}

/// Human-readable baseline comparison (e.g. "3.2x more egress than your typical Cursor session").
pub fn build_baseline_comparison_summary(
    summary: &SessionSummary,
    baseline: Option<&AppBaseline>,
) -> Option<String> {
    let b = baseline?;
    let mut parts = Vec::new();

    if b.avg_bytes_out > 0.0 && summary.counts.bytes_out > 0 {
        let ratio = summary.counts.bytes_out as f64 / b.avg_bytes_out;
        if ratio > 1.2 {
            parts.push(format!(
                "{:.1}x more egress than your typical {} session",
                ratio, summary.app
            ));
        } else if ratio < 0.8 {
            parts.push(format!(
                "{:.1}x less egress than your typical {} session",
                1.0 / ratio, summary.app
            ));
        }
    }
    if b.avg_files_written > 0.0 && summary.counts.files_written > 0 {
        let ratio = summary.counts.files_written as f64 / b.avg_files_written;
        if ratio > 1.5 {
            parts.push(format!(
                "{:.1}x more file writes than typical",
                ratio
            ));
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join(". "))
}
