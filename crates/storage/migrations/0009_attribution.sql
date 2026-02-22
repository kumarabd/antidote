-- Attribution metadata for events (Step 4: FocusManager)
ALTER TABLE events ADD COLUMN attribution_reason TEXT;
ALTER TABLE events ADD COLUMN attribution_confidence INTEGER;
ALTER TABLE events ADD COLUMN attributed_at TEXT;

CREATE INDEX IF NOT EXISTS idx_events_attribution ON events(attribution_reason);
