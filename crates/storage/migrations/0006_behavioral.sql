-- Phase 5: Behavioral baseline and risk memory

CREATE TABLE IF NOT EXISTS app_baselines (
    app TEXT PRIMARY KEY,
    session_count INTEGER NOT NULL DEFAULT 0,
    avg_files_written REAL NOT NULL DEFAULT 0,
    avg_files_deleted REAL NOT NULL DEFAULT 0,
    avg_bytes_out REAL NOT NULL DEFAULT 0,
    avg_unknown_domains REAL NOT NULL DEFAULT 0,
    avg_cmds REAL NOT NULL DEFAULT 0,
    var_files_written REAL NOT NULL DEFAULT 0,
    var_bytes_out REAL NOT NULL DEFAULT 0,
    var_unknown_domains REAL NOT NULL DEFAULT 0,
    var_cmds REAL NOT NULL DEFAULT 0,
    last_updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    UNIQUE(app, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_risk_history_app_rule ON risk_history(app, rule_id);
CREATE INDEX IF NOT EXISTS idx_risk_history_last_seen ON risk_history(last_seen);

ALTER TABLE sessions ADD COLUMN drift_index INTEGER;
ALTER TABLE sessions ADD COLUMN baseline_comparison_summary TEXT;
