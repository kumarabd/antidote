-- Step 6: Coalesced file event fields
ALTER TABLE events ADD COLUMN repeat_count INTEGER DEFAULT 1;
ALTER TABLE events ADD COLUMN coalesced_duration_ms INTEGER;
