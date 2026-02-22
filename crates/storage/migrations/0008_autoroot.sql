-- Auto-root fields and indexes for zero-config workspace watching
ALTER TABLE watched_roots ADD COLUMN source TEXT NOT NULL DEFAULT 'user';
ALTER TABLE watched_roots ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0;
ALTER TABLE watched_roots ADD COLUMN last_seen_ts TEXT;
ALTER TABLE watched_roots ADD COLUMN updated_ts TEXT;

-- Backfill updated_ts from added_ts for existing rows
UPDATE watched_roots SET updated_ts = added_ts WHERE updated_ts IS NULL;

CREATE INDEX IF NOT EXISTS idx_roots_source_last_seen ON watched_roots(source, last_seen_ts);
