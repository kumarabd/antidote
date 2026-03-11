-- Remove session association from events; sessions are independent entities
-- Recreate table without session_id (SQLite doesn't support DROP COLUMN in older versions)
CREATE TABLE IF NOT EXISTS events_new (
    id TEXT PRIMARY KEY,
    root_id INTEGER REFERENCES watched_roots(id),
    ts TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    pid INTEGER,
    ppid INTEGER,
    enforcement_action INTEGER NOT NULL DEFAULT 0,
    attribution_reason TEXT,
    attribution_confidence INTEGER,
    attributed_at TEXT,
    repeat_count INTEGER DEFAULT 1,
    coalesced_duration_ms INTEGER,
    attribution_details_json TEXT
);

INSERT INTO events_new (id, root_id, ts, event_type, payload_json, pid, ppid, enforcement_action, attribution_reason, attribution_confidence, attributed_at, repeat_count, coalesced_duration_ms, attribution_details_json)
SELECT id, root_id, ts, event_type, payload_json, pid, ppid, enforcement_action, attribution_reason, attribution_confidence, attributed_at, repeat_count, coalesced_duration_ms, attribution_details_json FROM events;

DROP TABLE events;
ALTER TABLE events_new RENAME TO events;

CREATE INDEX IF NOT EXISTS idx_events_root_id ON events(root_id);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_root_ts ON events(root_id, ts);
