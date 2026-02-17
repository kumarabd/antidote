-- Add Phase 1 fields to sessions table
ALTER TABLE sessions ADD COLUMN root_pid INTEGER;
ALTER TABLE sessions ADD COLUMN last_event_ts TEXT;

-- Update existing rows to have default values
UPDATE sessions SET root_pid = 0 WHERE root_pid IS NULL;
UPDATE sessions SET last_event_ts = start_ts WHERE last_event_ts IS NULL;

-- Create composite index for time-based queries
CREATE INDEX IF NOT EXISTS idx_events_session_ts ON events(session_id, ts);
CREATE INDEX IF NOT EXISTS idx_flags_session_ts ON flags(session_id, ts);
