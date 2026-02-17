-- Phase 4: Add audit telemetry fields

-- Add pid/ppid to events table
ALTER TABLE events ADD COLUMN pid INTEGER;
ALTER TABLE events ADD COLUMN ppid INTEGER;

CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid);

-- Add telemetry fields to sessions table
ALTER TABLE sessions ADD COLUMN telemetry_confidence TEXT DEFAULT 'LOW';
ALTER TABLE sessions ADD COLUMN dropped_events INTEGER DEFAULT 0;
ALTER TABLE sessions ADD COLUMN participant_pids_count INTEGER DEFAULT 0;
