//! App baseline (EMA) and storage trait

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppBaseline {
    pub app: String,
    pub session_count: u64,
    pub avg_files_written: f64,
    pub avg_files_deleted: f64,
    pub avg_bytes_out: f64,
    pub avg_unknown_domains: f64,
    pub avg_cmds: f64,
    pub var_files_written: f64,
    pub var_bytes_out: f64,
    pub var_unknown_domains: f64,
    pub var_cmds: f64,
    #[serde(with = "time::serde::rfc3339")]
    pub last_updated: OffsetDateTime,
}

impl AppBaseline {
    pub fn std_dev_files_written(&self) -> f64 {
        self.var_files_written.max(0.0).sqrt()
    }
    pub fn std_dev_bytes_out(&self) -> f64 {
        self.var_bytes_out.max(0.0).sqrt()
    }
    pub fn std_dev_unknown_domains(&self) -> f64 {
        self.var_unknown_domains.max(0.0).sqrt()
    }
    pub fn std_dev_cmds(&self) -> f64 {
        self.var_cmds.max(0.0).sqrt()
    }
}

/// In-memory or DB-backed baseline storage (trait for testing; concrete impl in daemon uses storage)
pub trait BaselineStore: Send + Sync {
    fn get(&self, app: &str) -> Option<AppBaseline>;
    fn set(&mut self, baseline: AppBaseline);
    fn all(&self) -> Vec<AppBaseline>;
}
