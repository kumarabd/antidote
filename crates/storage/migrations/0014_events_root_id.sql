-- Associate events with roots (watcher is per-root; root is primary association)
ALTER TABLE events ADD COLUMN root_id INTEGER REFERENCES watched_roots(id);
CREATE INDEX IF NOT EXISTS idx_events_root_id ON events(root_id);
