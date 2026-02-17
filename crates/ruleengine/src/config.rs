//! Rules configuration loaded from YAML

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    pub known_domains: Vec<String>,
    pub sensitive_path_globs: Vec<String>,
    #[serde(default)]
    pub benign_path_globs: Vec<String>,
    #[serde(default)]
    pub time_windows: TimeWindows,
    pub thresholds: Thresholds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindows {
    #[serde(default = "default_unknown_domains_window")]
    pub unknown_domains_window_seconds: u64,
    #[serde(default = "default_sensitive_burst_window")]
    pub sensitive_burst_window_seconds: u64,
}

fn default_unknown_domains_window() -> u64 { 120 }
fn default_sensitive_burst_window() -> u64 { 60 }

impl Default for TimeWindows {
    fn default() -> Self {
        Self {
            unknown_domains_window_seconds: 120,
            sensitive_burst_window_seconds: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thresholds {
    pub egress_mb_medium: f64,
    pub egress_mb_high: f64,
    pub bulk_delete: u64,
    pub bulk_write: u64,
    pub cmds_high: u64,
    pub unknown_domains_high: u64,
    #[serde(default = "default_unknown_domains_cluster")]
    pub unknown_domains_cluster: u64,
    #[serde(default = "default_sensitive_burst")]
    pub sensitive_burst: u64,
    #[serde(default = "default_exfil_egress_mb")]
    pub exfil_egress_mb: f64,
}

fn default_unknown_domains_cluster() -> u64 { 3 }
fn default_sensitive_burst() -> u64 { 3 }
fn default_exfil_egress_mb() -> f64 { 5.0 }

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            known_domains: vec![],
            sensitive_path_globs: vec![],
            benign_path_globs: vec![],
            time_windows: TimeWindows::default(),
            thresholds: Thresholds {
                egress_mb_medium: 1.0,
                egress_mb_high: 10.0,
                bulk_delete: 20,
                bulk_write: 100,
                cmds_high: 30,
                unknown_domains_high: 3,
                unknown_domains_cluster: 3,
                sensitive_burst: 3,
                exfil_egress_mb: 5.0,
            },
        }
    }
}
