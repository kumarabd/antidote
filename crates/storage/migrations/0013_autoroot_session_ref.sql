-- Link auto roots to the session (app:pid) they came from for session-based cleanup.
-- User roots have NULL session_ref. Only auto roots from working sessions get this.
ALTER TABLE watched_roots ADD COLUMN session_ref TEXT;

CREATE INDEX IF NOT EXISTS idx_roots_session_ref ON watched_roots(session_ref) WHERE session_ref IS NOT NULL;
