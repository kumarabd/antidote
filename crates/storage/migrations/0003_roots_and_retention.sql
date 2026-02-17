-- Watched roots table
CREATE TABLE IF NOT EXISTS watched_roots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT UNIQUE NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    added_ts TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_watched_roots_enabled ON watched_roots(enabled);

-- Add indexes for retention pruning
CREATE INDEX IF NOT EXISTS idx_events_ts_retention ON events(ts);
CREATE INDEX IF NOT EXISTS idx_flags_ts_retention ON flags(ts);
